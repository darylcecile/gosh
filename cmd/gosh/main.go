// Package main implements the gosh command-line sandbox runner.
package main

import (
	"os"
)

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
