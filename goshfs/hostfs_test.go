package goshfs_test

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/darylcecile/gosh"
	"github.com/darylcecile/gosh/goshfs"
)

func mountTemp(t *testing.T) (string, gosh.FileSystem) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hi from host"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "nested.txt"), []byte("nested"), 0o644); err != nil {
		t.Fatal(err)
	}
	hfs, err := goshfs.NewHostReadOnlyFS(root)
	if err != nil {
		t.Fatalf("NewHostReadOnlyFS: %v", err)
	}
	return root, hfs
}

func readAllFile(t *testing.T, hfs gosh.FileSystem, name string) string {
	t.Helper()
	f, err := hfs.Open(name, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("Open(%s): %v", name, err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("ReadAll(%s): %v", name, err)
	}
	return string(b)
}

func TestHostReadOnlyFS_ReadsWithinRoot(t *testing.T) {
	_, hfs := mountTemp(t)
	if got := readAllFile(t, hfs, "/hello.txt"); got != "hi from host" {
		t.Fatalf("got %q", got)
	}
	if got := readAllFile(t, hfs, "/sub/nested.txt"); got != "nested" {
		t.Fatalf("got %q", got)
	}
}

func TestHostReadOnlyFS_DeniesWrite(t *testing.T) {
	_, hfs := mountTemp(t)
	_, err := hfs.Open("/hello.txt", os.O_WRONLY, 0)
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("expected permission error, got %v", err)
	}
	if err := hfs.Mkdir("/newdir", 0o755); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Mkdir expected permission, got %v", err)
	}
	if err := hfs.Remove("/hello.txt"); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Remove expected permission, got %v", err)
	}
	if err := hfs.Rename("/hello.txt", "/x"); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Rename expected permission, got %v", err)
	}
	if err := hfs.Symlink("/hello.txt", "/x"); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Symlink expected permission, got %v", err)
	}
	if err := hfs.Chmod("/hello.txt", 0o600); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Chmod expected permission, got %v", err)
	}
}

func TestHostReadOnlyFS_DeniesWriteViaOpenFlag(t *testing.T) {
	_, hfs := mountTemp(t)
	f, err := hfs.Open("/hello.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("x")); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("file Write expected permission, got %v", err)
	}
	if err := f.Truncate(0); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("file Truncate expected permission, got %v", err)
	}
}

func TestHostReadOnlyFS_SymlinkEscapeDenied(t *testing.T) {
	root := t.TempDir()
	secretDir := t.TempDir()
	secret := filepath.Join(secretDir, "secret.txt")
	if err := os.WriteFile(secret, []byte("TOP SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A symlink inside root pointing OUTSIDE root.
	if err := os.Symlink(secret, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	// A symlink to a directory outside root, to test path traversal through it.
	if err := os.Symlink(secretDir, filepath.Join(root, "escapedir")); err != nil {
		t.Fatal(err)
	}
	hfs, err := goshfs.NewHostReadOnlyFS(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hfs.Open("/escape", os.O_RDONLY, 0); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("escape Open expected ErrNotExist, got %v", err)
	}
	if _, err := hfs.Stat("/escape"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("escape Stat expected ErrNotExist, got %v", err)
	}
	if _, err := hfs.Open("/escapedir/secret.txt", os.O_RDONLY, 0); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("escapedir traversal expected ErrNotExist, got %v", err)
	}
	if _, err := hfs.ReadDir("/escapedir"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("escapedir ReadDir expected ErrNotExist, got %v", err)
	}
}

func TestHostReadOnlyFS_SymlinkWithinRootAllowed(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "real.txt"), []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "real.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	hfs, err := goshfs.NewHostReadOnlyFS(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := readAllFile(t, hfs, "/link.txt"); got != "inside" {
		t.Fatalf("symlink within root: got %q", got)
	}
	target, err := hfs.Readlink("/link.txt")
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if target != "/real.txt" {
		t.Fatalf("Readlink virtualized target = %q, want /real.txt", target)
	}
}

func TestHostReadOnlyFS_ReadlinkEscapeDenied(t *testing.T) {
	root := t.TempDir()
	secretDir := t.TempDir()
	if err := os.Symlink(secretDir, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	hfs, err := goshfs.NewHostReadOnlyFS(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hfs.Readlink("/escape"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("escaping Readlink expected ErrNotExist, got %v", err)
	}
}

func TestHostReadOnlyFS_TraversalRejected(t *testing.T) {
	_, hfs := mountTemp(t)
	// validateName rejects ".." outright.
	if _, err := hfs.Open("/../etc/passwd", os.O_RDONLY, 0); err == nil {
		t.Fatal("expected traversal to be rejected")
	}
}

func TestHostReadOnlyFS_ReadDir(t *testing.T) {
	_, hfs := mountTemp(t)
	entries, err := hfs.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name()] = true
	}
	if !names["hello.txt"] || !names["sub"] {
		t.Fatalf("ReadDir missing entries: %v", names)
	}
}

func TestHostReadOnlyFS_OverlayWritesDiscarded(t *testing.T) {
	root, hfs := mountTemp(t)
	upper := gosh.NewInMemoryFS(gosh.NewVirtualClock(gosh.Epoch), 1<<20, 1<<24)
	overlay := goshfs.NewOverlayFS(hfs, upper)

	// Read falls through to host.
	if got := readAllFile(t, overlay, "/hello.txt"); got != "hi from host" {
		t.Fatalf("overlay read: got %q", got)
	}
	// Write lands in the in-memory upper.
	f, err := overlay.Open("/hello.txt", os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("overlay write open: %v", err)
	}
	if _, err := io.WriteString(f, "overwritten in memory"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if got := readAllFile(t, overlay, "/hello.txt"); got != "overwritten in memory" {
		t.Fatalf("overlay post-write read: got %q", got)
	}
	// Host file on disk is untouched.
	onDisk, err := os.ReadFile(filepath.Join(root, "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != "hi from host" {
		t.Fatalf("host disk mutated: %q", onDisk)
	}
}

func TestNewHostReadOnlyFS_RejectsNonDir(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := goshfs.NewHostReadOnlyFS(file); err == nil {
		t.Fatal("expected error mounting a non-directory")
	}
}
