package hardening_test

import (
	"archive/tar"
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/darylcecile/gosh"
	"github.com/darylcecile/gosh/std"
)

// TestNetworkMetadataRangesBlocked attacks the SSRF defense end-to-end through
// std.Shell, confirming cloud-metadata and special-purpose IP ranges are refused
// by default even when explicitly allow-listed, and no connection is made (S22).
func TestNetworkMetadataRangesBlocked(t *testing.T) {
	hosts := []struct{ name, host string }{
		{"alibaba metadata", "100.100.100.200"},
		{"oracle metadata", "192.0.0.192"},
		{"cgnat shared", "100.64.0.1"},
		{"benchmarking", "198.18.0.1"},
		{"reserved", "240.0.0.1"},
		{"6to4 anycast", "192.88.99.1"},
		{"nat64 loopback", "[64:ff9b::7f00:1]"},
	}
	for _, h := range hosts {
		t.Run(h.name, func(t *testing.T) {
			origin := "http://" + h.host
			sh := hardenedShell(gosh.WithNetwork(gosh.NetworkPolicy{AllowedOrigins: []string{origin}}))
			got := runScript(t, sh, "curl "+origin+"/latest/meta-data/")
			assertBlocked(t, got, "curl "+origin)
			if !strings.Contains(got.stderr, "forbidden private IP") {
				t.Fatalf("want SSRF refusal for %s, stderr=%q", origin, got.stderr)
			}
		})
	}
}

// tarLinkBytes builds a tar archive containing a single hardlink (TypeLink) entry.
func tarLinkBytes(t testing.TB, name, linkname string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeLink, Name: name, Linkname: linkname, Mode: 0o644}); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

// TestTarHardlinkThroughSymlinkRefused confirms a tar hardlink whose source path
// traverses a pre-existing symlink cannot link to an inode outside the -C
// extraction destination (S4). Regression for the FS.Link symlink-follow gap.
func TestTarHardlinkThroughSymlinkRefused(t *testing.T) {
	base := gosh.NewInMemoryFS(gosh.NewVirtualClock(gosh.Epoch), 1<<20, 1<<20)
	mustMkdir(t, base, "/home/user")
	mustMkdir(t, base, "/out")
	mustMkdir(t, base, "/secret")
	writeFS(t, base, "/secret/data", "TOPSECRET\n")
	// Pre-existing symlink inside the extraction dest pointing OUTSIDE it.
	if err := base.Symlink("/secret", "/out/escape"); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// Hardlink entry whose source traverses /out/escape -> /secret.
	writeFS(t, base, "/evil.tar", string(tarLinkBytes(t, "pwned", "escape/data")))

	sh := std.Shell(gosh.WithFS(base))
	got := runScript(t, sh, "tar -xf /evil.tar -C /out; cat /out/pwned")
	if strings.Contains(got.stdout, "TOPSECRET") {
		t.Fatalf("hardlink escaped extraction dest via symlink: stdout=%q stderr=%q", got.stdout, got.stderr)
	}
	if !strings.Contains(got.stderr, "symlink") {
		t.Fatalf("want refusal mentioning symlink, stderr=%q", got.stderr)
	}
}

func mustMkdir(t testing.TB, fsys gosh.FileSystem, dir string) {
	t.Helper()
	if err := fsys.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func writeFS(t testing.TB, fsys gosh.FileSystem, name, content string) {
	t.Helper()
	f, err := fsys.Open(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
}
