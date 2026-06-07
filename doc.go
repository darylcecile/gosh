// Package gosh is a sandboxed, in-memory Bash interpreter for Go, built for AI
// agents. It executes untrusted, model-generated Bash inside a fully
// virtualized environment: no real process is ever spawned and no real file is
// ever touched unless the host explicitly opts in.
//
// # Quick start
//
//	sh := gosh.New() // secure defaults: in-memory FS, no network, no exec, limits on
//	res, err := sh.Run(ctx, `echo "hi" > f.txt && cat f.txt`,
//	    gosh.RunStdin(""))
//	// res.Stdout, res.ExitCode; err is non-nil only for host-level failures.
//
// New returns a Shell with a default-deny posture (G3): an empty in-memory
// filesystem, no host environment inheritance (S23), a deterministic UTC
// virtual clock (S24), all resource governors enabled at DefaultLimits, no
// network egress, and registry-only command execution. The underlying parser
// and interpreter are mvdan.cc/sh/v3, whose defaults (which inherit os.Environ
// and the real filesystem/exec) are inverted via an internal fail-closed runner
// constructor (S1).
//
// # Host error vs script exit
//
// Run returns a Result and a Go error. The error is for HOST-level failures
// only — a resource limit (LimitError), context cancellation (CanceledError), a
// parse failure (ParseError), an unsupported construct (UnsupportedError), or an
// internal failure (InternalError). A script that simply exits non-zero yields
// Result.ExitCode != 0 and a nil error (D2). All host errors are matchable via
// errors.As / errors.Is (D7).
//
// # Extending gosh
//
// Custom commands implement the Command interface (or use CommandFunc) and are
// registered with WithCommands. Command-group packages live in separate
// packages that import this one; each exposes a Commands() []gosh.Command
// constructor. A command reads and writes ONLY through its CommandContext —
// cc.FS(), cc.Stdin/Stdout/Stderr, cc.Env, cc.Cwd(), cc.Clock(), and
// cc.Governor() — never via the real os or net packages.
//
//	WARNING: a custom command is arbitrary trusted Go code. CommandContext
//	OFFERS a capability-scoped, governed path, but cannot FORCE a misbehaving
//	plugin to stay in bounds. gosh sandboxes the script, not third-party Go
//	extensions; treat command authors as part of your trusted computing base.
//
// # Concurrency
//
// A single *Shell is intended for one agent/session and is cheap to construct.
// Run serializes calls with an internal mutex, so concurrent use cannot corrupt
// state, but it provides no parallelism (D9).
package gosh
