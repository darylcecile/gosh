package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/darylcecile/gosh"
)

func run(t *testing.T, sh *gosh.Shell, script string, opts ...gosh.RunOption) gosh.Result {
	t.Helper()
	res, err := sh.Run(context.Background(), script, opts...)
	if err != nil {
		t.Fatalf("host error: %v", err)
	}
	return res
}

func readVFS(t *testing.T, sh *gosh.Shell, name string) string {
	t.Helper()
	f, err := sh.FS().Open(name, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func existsVFS(sh *gosh.Shell, name string) bool {
	_, err := sh.FS().Stat(name)
	return err == nil
}

func TestGzipGunzipRoundTripStdin(t *testing.T) {
	sh := gosh.New(gosh.WithCommands(Commands()...))
	res := run(t, sh, `gzip -c | gunzip -c`, gosh.RunStdin("hello from stdin\n"))
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
	if res.Stdout != "hello from stdin\n" {
		t.Fatalf("stdout=%q", res.Stdout)
	}
}

func TestGzipGunzipRoundTripFile(t *testing.T) {
	sh := gosh.New(gosh.WithCommands(Commands()...), gosh.WithFiles(map[string]string{"/home/user/file.txt": "file contents\n"}))
	res := run(t, sh, `gzip file.txt && gunzip file.txt.gz`)
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
	if got := readVFS(t, sh, "/home/user/file.txt"); got != "file contents\n" {
		t.Fatalf("file=%q", got)
	}
	if existsVFS(sh, "/home/user/file.txt.gz") {
		t.Fatalf("gzip file should have been removed by gunzip")
	}
}

func TestZcat(t *testing.T) {
	sh := gosh.New(gosh.WithCommands(Commands()...), gosh.WithFiles(map[string]string{"/home/user/file.txt": "zcat contents\n"}))
	res := run(t, sh, `gzip -k file.txt && zcat file.txt.gz`)
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
	if res.Stdout != "zcat contents\n" {
		t.Fatalf("stdout=%q", res.Stdout)
	}
}

func TestTarCreateListExtractRoundTrip(t *testing.T) {
	sh := gosh.New(gosh.WithCommands(Commands()...), gosh.WithFiles(map[string]string{
		"/home/user/src/a.txt":     "alpha",
		"/home/user/src/dir/b.txt": "bravo",
	}))
	res := run(t, sh, `tar -cf pack.tar src && tar -tf pack.tar && tar -xf pack.tar -C out`)
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
	for _, want := range []string{"src", "src/a.txt", "src/dir", "src/dir/b.txt"} {
		if !strings.Contains(res.Stdout, want+"\n") {
			t.Fatalf("list output %q missing %q", res.Stdout, want)
		}
	}
	if got := readVFS(t, sh, "/home/user/out/src/a.txt"); got != "alpha" {
		t.Fatalf("a.txt=%q", got)
	}
	if got := readVFS(t, sh, "/home/user/out/src/dir/b.txt"); got != "bravo" {
		t.Fatalf("b.txt=%q", got)
	}
}

func TestTarGzipCreateExtract(t *testing.T) {
	sh := gosh.New(gosh.WithCommands(Commands()...), gosh.WithFiles(map[string]string{"/home/user/src/a.txt": "alpha"}))
	res := run(t, sh, `tar -czf pack.tgz src && tar -xzf pack.tgz -C out`)
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
	if got := readVFS(t, sh, "/home/user/out/src/a.txt"); got != "alpha" {
		t.Fatalf("a.txt=%q", got)
	}
}

func TestTarCAndStripComponents(t *testing.T) {
	sh := gosh.New(gosh.WithCommands(Commands()...), gosh.WithFiles(map[string]string{"/home/user/root/nested/a.txt": "alpha"}))
	res := run(t, sh, `tar -cf pack.tar -C /home/user root && tar -xf pack.tar -C out --strip-components 1`)
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
	if got := readVFS(t, sh, "/home/user/out/nested/a.txt"); got != "alpha" {
		t.Fatalf("stripped file=%q", got)
	}
}

func makeTar(t *testing.T, entries ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, hdr := range entries {
		data := []byte(nil)
		if hdr.Typeflag == tar.TypeReg || hdr.Typeflag == 0 {
			data = bytes.Repeat([]byte("x"), int(hdr.Size))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if len(data) > 0 {
			if _, err := tw.Write(data); err != nil {
				t.Fatalf("write data: %v", err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

func TestTarExtractRejectsTraversal(t *testing.T) {
	stream := makeTar(t, &tar.Header{Name: "../evil", Mode: 0o644, Size: 4})
	sh := gosh.New(gosh.WithCommands(Commands()...))
	res := run(t, sh, `tar -xf - -C out`, gosh.RunStdin(bytes.NewReader(stream)))
	if res.ExitCode == 0 {
		t.Fatalf("expected non-zero exit")
	}
	if existsVFS(sh, "/home/user/evil") {
		t.Fatalf("traversal created /home/user/evil")
	}
}

func TestTarExtractRejectsAbsolutePath(t *testing.T) {
	stream := makeTar(t, &tar.Header{Name: "/abs/evil", Mode: 0o644, Size: 4})
	sh := gosh.New(gosh.WithCommands(Commands()...))
	res := run(t, sh, `tar -xf - -C out`, gosh.RunStdin(bytes.NewReader(stream)))
	if res.ExitCode == 0 {
		t.Fatalf("expected non-zero exit")
	}
	if existsVFS(sh, "/abs/evil") {
		t.Fatalf("absolute path entry was created")
	}
}

func TestTarExtractRejectsEscapingSymlink(t *testing.T) {
	stream := makeTar(t, &tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "../evil", Mode: 0o777})
	sh := gosh.New(gosh.WithCommands(Commands()...))
	res := run(t, sh, `tar -xf - -C out`, gosh.RunStdin(bytes.NewReader(stream)))
	if res.ExitCode == 0 {
		t.Fatalf("expected non-zero exit")
	}
	if existsVFS(sh, "/home/user/out/link") {
		t.Fatalf("escaping symlink was created")
	}
}

func TestTarExtractionBombTripsCap(t *testing.T) {
	stream := makeTar(t, &tar.Header{Name: "large", Mode: 0o644, Size: 128})
	sh := gosh.New(gosh.WithCommands(Commands()...), gosh.WithLimits(gosh.Limits{MaxFileBytes: 32, MaxTotalFSBytes: 64}))
	res := run(t, sh, `tar -xf - -C out`, gosh.RunStdin(bytes.NewReader(stream)))
	if res.ExitCode == 0 {
		t.Fatalf("expected non-zero exit")
	}
	if existsVFS(sh, "/home/user/out/large") {
		t.Fatalf("bomb wrote capped file")
	}
}

func TestGzipDecompressionBombTripsCap(t *testing.T) {
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(bytes.Repeat([]byte("x"), 128)); err != nil {
		t.Fatalf("write gzip: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	sh := gosh.New(gosh.WithCommands(Commands()...), gosh.WithLimits(gosh.Limits{MaxFileBytes: 32, MaxTotalFSBytes: 64}))
	res := run(t, sh, `gunzip -c`, gosh.RunStdin(bytes.NewReader(compressed.Bytes())))
	if res.ExitCode == 0 {
		t.Fatalf("expected non-zero exit")
	}
	if len(res.Stdout) > 32 {
		t.Fatalf("wrote beyond cap: %d bytes", len(res.Stdout))
	}
}
