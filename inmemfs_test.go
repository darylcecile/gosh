package gosh_test

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/darylcecile/gosh"
)

func newFS(t *testing.T) *gosh.InMemoryFS {
	t.Helper()
	return gosh.NewInMemoryFS(gosh.NewVirtualClock(gosh.Epoch), 1<<20, 4<<20)
}

func writeFile(t *testing.T, fsys gosh.FileSystem, name, content string) {
	t.Helper()
	f, err := fsys.Open(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	if _, err := io.WriteString(f, content); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
}

func TestVFSReadWrite(t *testing.T) {
	fsys := newFS(t)
	if err := fsys.MkdirAll("/a/b", 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, fsys, "/a/b/c.txt", "hello")
	f, err := fsys.Open("/a/b/c.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, _ := io.ReadAll(f)
	if string(b) != "hello" {
		t.Fatalf("content=%q", b)
	}
}

func TestVFSPathTraversalConfined(t *testing.T) {
	fsys := newFS(t)
	// A path that tries to climb above the root resolves back inside it.
	if _, err := fsys.Stat("/../../../../etc/passwd"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected not-exist (confined), got %v", err)
	}
	// Create a file and reach it via a traversal-laden path.
	writeFile(t, fsys, "/secret.txt", "x")
	if _, err := fsys.Stat("/a/../b/../secret.txt"); err != nil {
		t.Fatalf("clean traversal within root should resolve: %v", err)
	}
}

func TestVFSSymlinkConfinement(t *testing.T) {
	fsys := newFS(t)
	// A symlink pointing outside the root is clamped back inside it.
	if err := fsys.Symlink("../../../../etc/passwd", "/escape"); err != nil {
		t.Fatal(err)
	}
	if _, err := fsys.Stat("/escape"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlink escape should resolve to a non-existent VFS path, got %v", err)
	}
}

func TestVFSSymlinkLoopErrors(t *testing.T) {
	fsys := newFS(t)
	if err := fsys.Symlink("/b", "/a"); err != nil {
		t.Fatal(err)
	}
	if err := fsys.Symlink("/a", "/b"); err != nil {
		t.Fatal(err)
	}
	_, err := fsys.Stat("/a")
	if err == nil {
		t.Fatalf("expected ELOOP-style error, got nil")
	}
	if !strings.Contains(err.Error(), "symbolic links") {
		t.Fatalf("expected symlink-loop error, got %v", err)
	}
}

func TestVFSSymlinkFollow(t *testing.T) {
	fsys := newFS(t)
	writeFile(t, fsys, "/real.txt", "data")
	if err := fsys.Symlink("/real.txt", "/link"); err != nil {
		t.Fatal(err)
	}
	// Stat follows; Lstat does not.
	fi, err := fsys.Stat("/link")
	if err != nil || fi.IsDir() {
		t.Fatalf("stat link: %v", err)
	}
	li, err := fsys.Lstat("/link")
	if err != nil {
		t.Fatal(err)
	}
	if li.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("lstat should report a symlink, mode=%v", li.Mode())
	}
	target, err := fsys.Readlink("/link")
	if err != nil || target != "/real.txt" {
		t.Fatalf("readlink=%q err=%v", target, err)
	}
}

func TestVFSHardlink(t *testing.T) {
	fsys := newFS(t)
	writeFile(t, fsys, "/a.txt", "shared")
	if err := fsys.Link("/a.txt", "/b.txt"); err != nil {
		t.Fatal(err)
	}
	// Both names see the same content.
	f, _ := fsys.Open("/b.txt", os.O_RDONLY, 0)
	b, _ := io.ReadAll(f)
	f.Close()
	if string(b) != "shared" {
		t.Fatalf("hardlink content=%q", b)
	}
}

func TestVFSPerFileSizeCap(t *testing.T) {
	fsys := gosh.NewInMemoryFS(gosh.NewVirtualClock(gosh.Epoch), 8, 1<<20)
	f, err := fsys.Open("/big.txt", os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte("0123456789")) // 10 bytes > 8 cap
	var le *gosh.LimitError
	if !errors.As(err, &le) || le.Kind != gosh.LimitFileBytes {
		t.Fatalf("want file-bytes LimitError, got %v", err)
	}
}

func TestVFSTotalSizeCap(t *testing.T) {
	fsys := gosh.NewInMemoryFS(gosh.NewVirtualClock(gosh.Epoch), 1<<20, 12)
	writeFile(t, fsys, "/a.txt", "12345678") // 8 bytes ok
	f, err := fsys.Open("/b.txt", os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte("12345678")) // would bring total to 16 > 12
	var le *gosh.LimitError
	if !errors.As(err, &le) || le.Kind != gosh.LimitTotalFSBytes {
		t.Fatalf("want total-fs LimitError, got %v", err)
	}
}

func TestVFSRemoveFreesBytes(t *testing.T) {
	fsys := gosh.NewInMemoryFS(gosh.NewVirtualClock(gosh.Epoch), 1<<20, 16)
	writeFile(t, fsys, "/a.txt", "12345678")
	if err := fsys.Remove("/a.txt"); err != nil {
		t.Fatal(err)
	}
	// After removal the budget is reclaimed; a new 8-byte file fits.
	writeFile(t, fsys, "/b.txt", "12345678")
}

func TestVFSReadDirSorted(t *testing.T) {
	fsys := newFS(t)
	writeFile(t, fsys, "/z.txt", "")
	writeFile(t, fsys, "/a.txt", "")
	writeFile(t, fsys, "/m.txt", "")
	entries, err := fsys.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	got := strings.Join(names, ",")
	if got != "a.txt,m.txt,z.txt" {
		t.Fatalf("readdir order=%q", got)
	}
}

func TestVFSRename(t *testing.T) {
	fsys := newFS(t)
	writeFile(t, fsys, "/old.txt", "v")
	if err := fsys.Rename("/old.txt", "/new.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := fsys.Stat("/old.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old should be gone")
	}
	if _, err := fsys.Stat("/new.txt"); err != nil {
		t.Fatalf("new should exist: %v", err)
	}
}
