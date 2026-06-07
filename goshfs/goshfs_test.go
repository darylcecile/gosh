package goshfs

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"reflect"
	"testing"

	"github.com/darylcecile/gosh"
)

func newFS() gosh.FileSystem { return gosh.NewInMemoryFS(nil, 0, 0) }

func writeFile(t *testing.T, fsys gosh.FileSystem, name, contents string) {
	t.Helper()
	f, err := fsys.Open(name, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	if _, err := f.Write([]byte(contents)); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
}

func readFile(t *testing.T, fsys gosh.FileSystem, name string) string {
	t.Helper()
	f, err := fsys.Open(name, os.O_RDONLY, 0)
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

func names(entries []fs.DirEntry) []string {
	out := make([]string, 0, len(entries))
	for _, ent := range entries {
		out = append(out, ent.Name())
	}
	return out
}

func TestReadOnlyFS(t *testing.T) {
	inner := newFS()
	if err := inner.Mkdir("/dir", 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, inner, "/dir/file", "hello")
	ro := NewReadOnlyFS(inner)

	if got := readFile(t, ro, "/dir/file"); got != "hello" {
		t.Fatalf("read = %q", got)
	}
	if _, err := ro.ReadDir("/dir"); err != nil {
		t.Fatalf("readdir: %v", err)
	}

	mutations := []struct {
		name string
		fn   func() error
	}{
		{"open-write", func() error { _, err := ro.Open("/dir/file", os.O_WRONLY, 0); return err }},
		{"open-create", func() error { _, err := ro.Open("/new", os.O_CREATE|os.O_RDWR, 0o644); return err }},
		{"mkdir", func() error { return ro.Mkdir("/x", 0o755) }},
		{"mkdirall", func() error { return ro.MkdirAll("/x/y", 0o755) }},
		{"remove", func() error { return ro.Remove("/dir/file") }},
		{"removeall", func() error { return ro.RemoveAll("/dir") }},
		{"rename", func() error { return ro.Rename("/dir/file", "/dir/other") }},
		{"symlink", func() error { return ro.Symlink("/dir/file", "/dir/link") }},
		{"link", func() error { return ro.Link("/dir/file", "/dir/hard") }},
		{"chmod", func() error { return ro.Chmod("/dir/file", 0o600) }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(); !errors.Is(err, fs.ErrPermission) {
				t.Fatalf("got %v, want permission", err)
			}
		})
	}
}

func TestOverlayFS(t *testing.T) {
	lower, upper := newFS(), newFS()
	if err := lower.Mkdir("/dir", 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, lower, "/dir/a", "lower-a")
	writeFile(t, lower, "/dir/b", "lower-b")
	writeFile(t, upper, "/dir", "shadow-file")
	over := NewOverlayFS(lower, upper)
	if got := readFile(t, over, "/dir"); got != "shadow-file" {
		t.Fatalf("upper shadow read = %q", got)
	}

	lower2, upper2 := newFS(), newFS()
	if err := lower2.Mkdir("/dir", 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, lower2, "/dir/a", "lower-a")
	writeFile(t, lower2, "/dir/b", "lower-b")
	if err := upper2.Mkdir("/dir", 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, upper2, "/dir/c", "upper-c")
	over = NewOverlayFS(lower2, upper2)

	writeFile(t, over, "/dir/a", "changed")
	if got := readFile(t, lower2, "/dir/a"); got != "lower-a" {
		t.Fatalf("lower changed after copy-up: %q", got)
	}
	if got := readFile(t, upper2, "/dir/a"); got != "changed" {
		t.Fatalf("upper copy-up = %q", got)
	}
	if err := over.Remove("/dir/b"); err != nil {
		t.Fatalf("remove lower file: %v", err)
	}
	if _, err := over.Stat("/dir/b"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stat whiteout = %v, want not exist", err)
	}
	ents, err := over.ReadDir("/dir")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if got, want := names(ents), []string{"a", "c"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("merged names = %v, want %v", got, want)
	}

	if err := over.Chmod("/dir/a", 0o600); err != nil {
		t.Fatalf("chmod copied file: %v", err)
	}
	if mode := statMode(t, upper2, "/dir/a"); mode != 0o600 {
		t.Fatalf("upper mode = %v", mode)
	}
}

func statMode(t *testing.T, fsys gosh.FileSystem, name string) fs.FileMode {
	t.Helper()
	info, err := fsys.Stat(name)
	if err != nil {
		t.Fatalf("stat %s: %v", name, err)
	}
	return info.Mode().Perm()
}

func TestMountableFS(t *testing.T) {
	root, mnt, mnt2 := newFS(), newFS(), newFS()
	writeFile(t, root, "/root", "root")
	writeFile(t, mnt, "/file", "mount")
	writeFile(t, mnt2, "/file", "mount2")

	fsys := NewMountableFS(root)
	m, ok := fsys.(*MountableFS)
	if !ok {
		t.Fatalf("constructor returned %T", fsys)
	}
	if err := m.Mount("/mnt", mnt); err != nil {
		t.Fatalf("mount: %v", err)
	}
	if err := m.Mount("/other", mnt2); err != nil {
		t.Fatalf("mount2: %v", err)
	}
	if err := m.Mount("/mnt/sub", newFS()); err == nil {
		t.Fatalf("overlapping mount succeeded")
	}

	if got := readFile(t, fsys, "/mnt/file"); got != "mount" {
		t.Fatalf("mounted read = %q", got)
	}
	if got := readFile(t, fsys, "/root"); got != "root" {
		t.Fatalf("root read = %q", got)
	}
	ents, err := fsys.ReadDir("/")
	if err != nil {
		t.Fatalf("root readdir: %v", err)
	}
	if got, want := names(ents), []string{"mnt", "other", "root"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("root entries = %v, want %v", got, want)
	}
	writeFile(t, fsys, "/mnt/new", "new")
	if got := readFile(t, mnt, "/new"); got != "new" {
		t.Fatalf("translated write = %q", got)
	}
	if err := fsys.Rename("/mnt/new", "/other/new"); !errors.Is(err, errCrossFilesystem) {
		t.Fatalf("cross mount rename = %v", err)
	}
	m.Unmount("/mnt")
	if _, err := fsys.Stat("/mnt/file"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("after unmount stat = %v", err)
	}
}

func TestTraversalCorpus(t *testing.T) {
	cases := []string{"/a/../../etc/x", "/mnt/../../../secret", `\\unc\share`, `C:\win`, "/mnt/../secret", "/clean/./x"}
	adapters := []struct {
		name string
		fsys gosh.FileSystem
	}{
		{"readonly", NewReadOnlyFS(newFS())},
		{"readwrite", NewReadWriteFS(newFS())},
		{"overlay", NewOverlayFS(newFS(), newFS())},
	}
	mountRoot := newFS()
	mounted := newFS()
	mountable := NewMountableFS(mountRoot)
	if err := mountable.(*MountableFS).Mount("/mnt", mounted); err != nil {
		t.Fatal(err)
	}
	adapters = append(adapters, struct {
		name string
		fsys gosh.FileSystem
	}{"mountable", mountable})

	for _, adapter := range adapters {
		for _, hostile := range cases {
			t.Run(adapter.name+":"+hostile, func(t *testing.T) {
				if _, err := adapter.fsys.Stat(hostile); err == nil {
					t.Fatalf("Stat(%q) succeeded", hostile)
				}
				if _, err := adapter.fsys.Open(hostile, os.O_CREATE|os.O_RDWR, 0o644); err == nil {
					t.Fatalf("Open(%q) succeeded", hostile)
				}
			})
		}
	}
	if _, err := mounted.Stat("/secret"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("mounted namespace escaped: %v", err)
	}
	if _, err := mountRoot.Stat("/secret"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("root namespace escaped: %v", err)
	}
	if err := mountable.(*MountableFS).Symlink("/secret", "/mnt/link"); err == nil {
		t.Fatalf("cross-namespace absolute symlink target accepted")
	}
	if err := mountable.(*MountableFS).Symlink("../secret", "/mnt/link"); err == nil {
		t.Fatalf("traversing relative symlink target accepted")
	}
}

// TestOverlayFSRenameOverLowerFile is a regression test: renaming an upper file
// onto a path that exists only in the lower layer must leave the destination
// readable with the moved content (the upper file shadows the lower). A previous
// bug re-added a whiteout on the destination after the rename, making it vanish.
func TestOverlayFSRenameOverLowerFile(t *testing.T) {
lower, upper := newFS(), newFS()
writeFile(t, lower, "/target", "lower-original")
over := NewOverlayFS(lower, upper)

// Create a new file in the upper, then rename it onto the lower-backed path.
writeFile(t, over, "/src", "moved-content")
if err := over.Rename("/src", "/target"); err != nil {
t.Fatalf("rename: %v", err)
}
if got := readFile(t, over, "/target"); got != "moved-content" {
t.Fatalf("after rename-over-lower, /target = %q, want %q", got, "moved-content")
}
if _, err := over.Stat("/src"); !errors.Is(err, fs.ErrNotExist) {
t.Fatalf("source should be gone after rename, got err=%v", err)
}
// The lower layer must be untouched.
if got := readFile(t, lower, "/target"); got != "lower-original" {
t.Fatalf("lower mutated: %q", got)
}
}

// TestOverlayFSRenameOverLowerThenRemove verifies the destination can still be
// deleted afterwards, restoring nothing (the lower stays masked).
func TestOverlayFSRenameOverLowerThenRemove(t *testing.T) {
lower, upper := newFS(), newFS()
writeFile(t, lower, "/target", "lower-original")
over := NewOverlayFS(lower, upper)
writeFile(t, over, "/src", "moved")
if err := over.Rename("/src", "/target"); err != nil {
t.Fatal(err)
}
if err := over.Remove("/target"); err != nil {
t.Fatalf("remove after rename: %v", err)
}
if _, err := over.Stat("/target"); !errors.Is(err, fs.ErrNotExist) {
t.Fatalf("target should be gone, got %v", err)
}
}
