// Command overlay-cwd demonstrates "overlay-over-cwd": a real host directory is
// mounted read-only as the lower layer, and an in-memory upper layer captures
// every write. Scripts can read the real files on disk, but their writes are
// confined to memory and discarded when the process exits — the host directory
// is never modified. This is the same mechanism the `gosh --root DIR` CLI flag
// uses.
//
// Run it with: go run ./examples/overlay-cwd
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/darylcecile/gosh"
	"github.com/darylcecile/gosh/goshfs"
	"github.com/darylcecile/gosh/std"
)

func main() {
	// Create a throwaway host directory to stand in for a real project tree.
	root, err := os.MkdirTemp("", "gosh-overlay-cwd-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(root)
	mustWriteHost(filepath.Join(root, "README.md"), "# Real project\nThis lives on host disk.\n")
	mustWriteHost(filepath.Join(root, "VERSION"), "1.0.0\n")

	// Lower layer: the real directory, read-only and symlink-confined.
	lower, err := goshfs.NewHostReadOnlyFS(root)
	if err != nil {
		panic(err)
	}
	// Upper layer: in-memory scratch that captures (and discards) all writes.
	upper := gosh.NewInMemoryFS(gosh.NewVirtualClock(gosh.Epoch), 1<<20, 1<<24)
	overlay := goshfs.NewOverlayFS(lower, upper)

	// Start the shell at "/" (the mount point) so the host tree is visible there.
	sh := std.Shell(gosh.WithFS(overlay), gosh.WithCwd("/"))

	res, err := sh.Run(context.Background(), `
		echo "== files served from host disk =="
		ls
		echo
		echo "== read a real file =="
		cat README.md
		echo "== edit it (write goes to the in-memory upper layer) =="
		sed 's/Real/Edited/' README.md > README.md.tmp
		mv README.md.tmp README.md
		cat README.md
	`)
	if err != nil {
		fmt.Println("run error:", err)
		return
	}
	fmt.Print(res.Stdout)

	// The host file on disk was never touched.
	fmt.Println("== host README.md on disk is still pristine ==")
	data, _ := os.ReadFile(filepath.Join(root, "README.md"))
	fmt.Print(string(data))
}

func mustWriteHost(path, contents string) {
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		panic(err)
	}
}
