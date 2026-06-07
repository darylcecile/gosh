// Command customcommand demonstrates registering a custom gosh command that
// composes with the standard command set in pipes and redirections.
//
// Run it with: go run ./examples/customcommand
package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/darylcecile/gosh"
	"github.com/darylcecile/gosh/std"
)

func main() {
	// A custom command is trusted Go code. Use only the cc.* accessors so it
	// stays inside the sandbox (no os, net/http, or time.Now).
	shout := gosh.CommandFunc("shout", func(ctx context.Context, cc *gosh.CommandContext) int {
		if cc.WantsHelp() {
			cc.PrintHelp("shout [text...]", "Print arguments in upper case.")
			return 0
		}
		fmt.Fprintln(cc.Stdout, strings.ToUpper(strings.Join(cc.Args, " ")))
		return 0
	})

	sh := std.Shell(gosh.WithCommands(shout))

	res, err := sh.Run(context.Background(), `
		shout hello world | tr ' ' '_'
		echo '{"who":"gosh"}' | jq -r .who
	`)
	if err != nil {
		panic(err)
	}
	fmt.Print(res.Stdout)
	fmt.Println("exit:", res.ExitCode)
}
