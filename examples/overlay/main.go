// Command overlay demonstrates a copy-on-write overlay: a read-only lower layer
// holds the original files, and all writes land in a throwaway upper layer. The
// lower layer is never modified, so each run starts from the same base and the
// script's changes can be inspected or discarded.
//
// Run it with: go run ./examples/overlay
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/darylcecile/gosh"
	"github.com/darylcecile/gosh/goshfs"
	"github.com/darylcecile/gosh/std"
)

func main() {
	// Lower layer: the pristine base, mounted read-only.
	lower := gosh.NewInMemoryFS(gosh.NewVirtualClock(gosh.Epoch), 1<<20, 1<<24)
	_ = lower.MkdirAll("/home/user", 0o755)
	writeFile(lower, "/home/user/config.txt", "mode=production\n")

	// Upper layer: writable scratch that captures every change.
	upper := gosh.NewInMemoryFS(gosh.NewVirtualClock(gosh.Epoch), 1<<20, 1<<24)

	overlay := goshfs.NewOverlayFS(goshfs.NewReadOnlyFS(lower), upper)
	sh := std.Shell(gosh.WithFS(overlay))

	res, _ := sh.Run(context.Background(), `
		echo "== original =="
		cat /home/user/config.txt
		echo "mode=debug" > /home/user/config.txt
		echo "scratch" > /home/user/new.txt
		echo "== after edit (served from upper layer) =="
		cat /home/user/config.txt
		cat /home/user/new.txt
	`)
	fmt.Print(res.Stdout)

	// The lower layer is untouched: a fresh overlay would see the original.
	fmt.Println("== lower layer still pristine ==")
	fmt.Print(readFile(lower, "/home/user/config.txt"))
}

func writeFile(fsys gosh.FileSystem, name, contents string) {
	f, err := fsys.Open(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		panic(err)
	}
	if _, err := f.Write([]byte(contents)); err != nil {
		panic(err)
	}
	_ = f.Close()
}

func readFile(fsys gosh.FileSystem, name string) string {
	f, err := fsys.Open(name, os.O_RDONLY, 0)
	if err != nil {
		return "<missing>"
	}
	defer f.Close()
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	return string(buf[:n])
}
