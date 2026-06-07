package fileops

import (
	"context"
	"strings"
	"testing"

	"github.com/darylcecile/gosh"
)

func newShell(files map[string]string) *gosh.Shell {
	return gosh.New(gosh.WithCommands(Commands()...), gosh.WithFiles(files))
}

func run(t *testing.T, sh *gosh.Shell, script string, opts ...gosh.RunOption) gosh.Result {
	t.Helper()
	res, err := sh.Run(context.Background(), script, opts...)
	if err != nil {
		t.Fatalf("Run(%q) host error: %v", script, err)
	}
	return res
}

func requireExit(t *testing.T, res gosh.Result, code int) {
	t.Helper()
	if res.ExitCode != code {
		t.Fatalf("exit code = %d, want %d\nstdout=%q\nstderr=%q", res.ExitCode, code, res.Stdout, res.Stderr)
	}
}

func TestCatFilesNumberingAndPipe(t *testing.T) {
	sh := newShell(map[string]string{"/a.txt": "a\nb\n", "/b.txt": "c\n"})
	res := run(t, sh, "cat -n /a.txt /b.txt")
	requireExit(t, res, 0)
	want := "     1\ta\n     2\tb\n     3\tc\n"
	if res.Stdout != want {
		t.Fatalf("stdout = %q, want %q", res.Stdout, want)
	}

	res = run(t, sh, "echo hi | cat")
	requireExit(t, res, 0)
	if res.Stdout != "hi\n" {
		t.Fatalf("pipe stdout = %q", res.Stdout)
	}
}

func TestMissingFileExitCode(t *testing.T) {
	res := run(t, newShell(nil), "cat /missing")
	requireExit(t, res, 1)
	if !strings.Contains(res.Stderr, "cat: /missing:") {
		t.Fatalf("stderr = %q", res.Stderr)
	}
}

func TestMkdirCpMvRmRmdir(t *testing.T) {
	sh := newShell(map[string]string{"/src/a.txt": "alpha", "/src/sub/b.txt": "beta"})
	res := run(t, sh, "mkdir -p -m 700 /dst && cp -rp /src /dst && mv /dst/src/a.txt /dst/src/renamed.txt && cat /dst/src/renamed.txt /dst/src/sub/b.txt")
	requireExit(t, res, 0)
	if res.Stdout != "alphabeta" {
		t.Fatalf("stdout = %q", res.Stdout)
	}

	res = run(t, sh, "rm /dst/src/renamed.txt && rmdir /dst/src/sub")
	requireExit(t, res, 1)
	if !strings.Contains(res.Stderr, "directory not empty") {
		t.Fatalf("stderr = %q", res.Stderr)
	}

	res = run(t, sh, "rm -r /dst/src/sub && rmdir /dst/src")
	requireExit(t, res, 0)
}

func TestLsStatAndTreeShape(t *testing.T) {
	sh := newShell(map[string]string{"/dir/a.txt": "a", "/dir/.hidden": "h", "/dir/sub/b.txt": "bb"})
	res := run(t, sh, "ls -1 /dir")
	requireExit(t, res, 0)
	if res.Stdout != "a.txt\nsub\n" {
		t.Fatalf("ls stdout = %q", res.Stdout)
	}

	res = run(t, sh, "ls -la /dir")
	requireExit(t, res, 0)
	for _, want := range []string{".hidden", "a.txt", "sub", "2000-01-01 00:00"} {
		if !strings.Contains(res.Stdout, want) {
			t.Fatalf("ls -la missing %q in %q", want, res.Stdout)
		}
	}

	res = run(t, sh, "stat /dir/a.txt")
	requireExit(t, res, 0)
	for _, want := range []string{"/dir/a.txt: size=1", "mode=-rw-r--r--", "mtime=2000-01-01 00:00:00 UTC"} {
		if !strings.Contains(res.Stdout, want) {
			t.Fatalf("stat missing %q in %q", want, res.Stdout)
		}
	}

	res = run(t, sh, "tree /dir")
	requireExit(t, res, 0)
	for _, want := range []string{"/dir", "├── a.txt", "└── sub", "    └── b.txt", "2 directories, 2 files"} {
		if !strings.Contains(res.Stdout, want) {
			t.Fatalf("tree missing %q in %q", want, res.Stdout)
		}
	}
}

func TestLinksReadlinkTouchAndFile(t *testing.T) {
	sh := newShell(map[string]string{"/text.txt": "hello\n", "/utf.txt": "héllo\n", "/bin.dat": string([]byte{0, 1, 2})})
	res := run(t, sh, "ln /text.txt /hard.txt && ln -s text.txt /sym.txt && readlink /sym.txt && cat /hard.txt")
	requireExit(t, res, 0)
	if res.Stdout != "text.txt\nhello\n" {
		t.Fatalf("stdout = %q", res.Stdout)
	}

	res = run(t, sh, "touch /new.txt && touch -c /nope && file /new.txt /text.txt /utf.txt /bin.dat")
	requireExit(t, res, 0)
	for _, want := range []string{"/new.txt: empty", "/text.txt: ASCII text", "/utf.txt: UTF-8 text", "/bin.dat: data"} {
		if !strings.Contains(res.Stdout, want) {
			t.Fatalf("file output missing %q in %q", want, res.Stdout)
		}
	}

	res = run(t, sh, "cat /nope")
	requireExit(t, res, 1)
}

func TestRecursiveLsAndDirAsEntry(t *testing.T) {
	sh := newShell(map[string]string{"/d/a": "a", "/d/s/b": "b"})
	res := run(t, sh, "ls -R /d")
	requireExit(t, res, 0)
	for _, want := range []string{"/d:", "a", "s", "/d/s:", "b"} {
		if !strings.Contains(res.Stdout, want) {
			t.Fatalf("ls -R missing %q in %q", want, res.Stdout)
		}
	}
	res = run(t, sh, "ls -d /d")
	requireExit(t, res, 0)
	if res.Stdout != "/d\n" {
		t.Fatalf("ls -d stdout = %q", res.Stdout)
	}
}
