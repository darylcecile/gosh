package gosh

import (
	"context"
	"fmt"
	"io"
	"path"
	"sort"
)

// Command is the interface every built-in coreutil and host-provided custom
// command implements. Implementations are trusted Go code (see the E2 warning
// in the package docs): they receive only capability-scoped handles through
// CommandContext and SHOULD confine all I/O to those handles, but gosh cannot
// force a misbehaving command to stay in bounds.
type Command interface {
	// Name is the command's primary invocation name (e.g. "cat").
	Name() string
	// Run executes the command and returns its exit code. A non-zero code
	// indicates failure but is NOT a host-level error; commands report all
	// user-facing problems by writing to CommandContext.Stderr and returning a
	// non-zero code. ctx carries cancellation/deadline.
	Run(ctx context.Context, cc *CommandContext) int
}

// commandFunc adapts a plain function to the Command interface.
type commandFunc struct {
	name string
	fn   func(ctx context.Context, cc *CommandContext) int
}

func (c commandFunc) Name() string { return c.name }
func (c commandFunc) Run(ctx context.Context, cc *CommandContext) int {
	return c.fn(ctx, cc)
}

// CommandFunc builds a Command from a name and a function. It is the ergonomic
// path for simple commands and host extensions:
//
//	gosh.CommandFunc("hello", func(ctx context.Context, cc *gosh.CommandContext) int {
//	    fmt.Fprintln(cc.Stdout, "hello", strings.Join(cc.Args, " "))
//	    return 0
//	})
func CommandFunc(name string, fn func(ctx context.Context, cc *CommandContext) int) Command {
	return commandFunc{name: name, fn: fn}
}

// EnvAccessor exposes the environment visible to a command. Get/All read the
// current values; Set updates the command's local view (used by sub-commands it
// invokes via Exec) and, like a real process, does NOT propagate back to the
// parent shell.
type EnvAccessor interface {
	// Get returns the value of key and whether it was set.
	Get(key string) (string, bool)
	// Set assigns key=value in the command-local environment.
	Set(key, value string)
	// All returns a copy of the full environment as a map.
	All() map[string]string
}

// mapEnv is the default EnvAccessor backed by a map.
type mapEnv struct{ m map[string]string }

func (e *mapEnv) Get(key string) (string, bool) { v, ok := e.m[key]; return v, ok }
func (e *mapEnv) Set(key, value string)         { e.m[key] = value }
func (e *mapEnv) All() map[string]string {
	out := make(map[string]string, len(e.m))
	for k, v := range e.m {
		out[k] = v
	}
	return out
}

// Sorted returns env keys in sorted order, a convenience for commands such as
// env/printenv that must emit deterministic output.
func (e *mapEnv) sortedKeys() []string {
	keys := make([]string, 0, len(e.m))
	for k := range e.m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// CommandContext is the capability-scoped execution context handed to a
// Command. It is the ONLY sanctioned way for a command to perform I/O: read the
// filesystem via FS, read/write standard streams, inspect the environment and
// working directory, compose with other commands via Exec, read time via Clock,
// and observe resource limits via Governor. Commands must never reach for the
// real os/net packages.
type CommandContext struct {
	// Name is the command's invocation name (arg0).
	Name string
	// Args holds the arguments WITHOUT the command name. For `grep -i foo`,
	// Name is "grep" and Args is ["-i", "foo"].
	Args []string
	// Stdin is the command's standard input.
	Stdin io.Reader
	// Stdout is the command's standard output.
	Stdout io.Writer
	// Stderr is the command's standard error.
	Stderr io.Writer

	// Env is the command-local environment accessor.
	Env EnvAccessor

	cwd      string
	fsys     FileSystem
	clock    Clock
	governor *Governor
	network  NetworkPolicy
	exec     func(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, cwd string) int
}

// Network returns the egress policy in force for this run. Network-aware
// commands (e.g. curl) consult it to decide whether they may run at all
// (NetworkPolicy.Enabled) and to validate each request against the configured
// origin/method/path allow-lists and SSRF defenses (S17–S22). The zero value is
// a deny-all policy.
func (cc *CommandContext) Network() NetworkPolicy { return cc.network }

// Cwd returns the command's current working directory as an absolute, cleaned
// POSIX path.
func (cc *CommandContext) Cwd() string { return cc.cwd }

// FS returns the filesystem the command must use for all storage access.
func (cc *CommandContext) FS() FileSystem { return cc.fsys }

// Clock returns the injected clock; time-reading commands MUST use it instead
// of time.Now so runs stay deterministic (S24).
func (cc *CommandContext) Clock() Clock { return cc.clock }

// Governor returns the run's resource governor. Stream-processing commands
// should call Governor().StreamTick once per record to honor the
// MaxStreamIterations cap (S13).
func (cc *CommandContext) Governor() *Governor { return cc.governor }

// ResolvePath converts a possibly-relative path argument into the absolute,
// cleaned POSIX path expected by FileSystem methods. Relative paths are joined
// against Cwd. This is the canonical helper every file-touching command should
// use before calling cc.FS().
func (cc *CommandContext) ResolvePath(p string) string {
	if p == "" {
		return cleanAbs(cc.cwd)
	}
	if path.IsAbs(p) {
		return cleanAbs(p)
	}
	return cleanAbs(path.Join(cc.cwd, p))
}

// Exec runs another command (builtin coreutil or custom) in the same world,
// sharing this command's FS, environment, working directory, and standard
// streams. It returns the sub-command's exit code, enabling composition (for
// example an xargs-like command driving others). The shared resource governor
// continues to apply.
func (cc *CommandContext) Exec(ctx context.Context, args ...string) int {
	if len(args) == 0 {
		return 0
	}
	if cc.exec == nil {
		fmt.Fprintf(cc.Stderr, "gosh: %s: command not found\n", args[0])
		return 127
	}
	return cc.exec(ctx, args, cc.Stdin, cc.Stdout, cc.Stderr, cc.cwd)
}

// BoundedWrite writes p to w but never more than the run's remaining output
// budget, accounting the bytes against MaxOutputBytes (S12). It returns the
// number of bytes actually written. Commands that emit large output should
// route writes through their Stdout/Stderr (already bounded by the engine);
// this helper is for commands building their own writers.
func (cc *CommandContext) BoundedWrite(w io.Writer, p []byte) (int, error) {
	if cc.governor == nil {
		return w.Write(p)
	}
	allowed := cc.governor.accountOutput(len(p))
	if allowed <= 0 {
		return 0, nil
	}
	return w.Write(p[:allowed])
}

// PrintHelp writes a standard, consistently formatted help block to Stdout and
// returns 0. usage is a one-line synopsis (e.g. "cat [FILE]...") and desc is a
// short description. It gives every command a uniform `--help` rendering.
func (cc *CommandContext) PrintHelp(usage, desc string) int {
	fmt.Fprintf(cc.Stdout, "Usage: %s\n\n%s\n", usage, desc)
	return 0
}

// WantsHelp reports whether the command's arguments request help (-h or
// --help), so commands can early-return PrintHelp.
func (cc *CommandContext) WantsHelp() bool {
	for _, a := range cc.Args {
		if a == "--help" || a == "-h" {
			return true
		}
		if a == "--" {
			break
		}
	}
	return false
}
