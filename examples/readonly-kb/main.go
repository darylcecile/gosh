// Command readonly-kb demonstrates mounting a read-only "knowledge base" into
// the sandbox: the script can read the seeded files but every write is rejected,
// so model-generated scripts cannot tamper with the reference material.
//
// Run it with: go run ./examples/readonly-kb
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
	// Build a base in-memory FS, seed it, then wrap it read-only.
	base := gosh.NewInMemoryFS(gosh.NewVirtualClock(gosh.Epoch), 1<<20, 1<<24)
	_ = base.MkdirAll("/kb", 0o755)
	writeFile(base, "/kb/policies.md", "# Refund policy\nRefunds within 30 days.\n")
	writeFile(base, "/kb/faq.md", "Q: Is it sandboxed?\nA: Yes.\n")

	sh := std.Shell(gosh.WithFS(goshfs.NewReadOnlyFS(base)))

	res, _ := sh.Run(context.Background(), `
		echo "== files =="
		ls /kb
		echo "== refund line =="
		grep -i refund /kb/policies.md
		echo "== attempting a write (should fail) =="
		echo "tampered" > /kb/policies.md && echo "WROTE (bad!)" || echo "write correctly rejected"
	`)
	fmt.Print(res.Stdout)
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
