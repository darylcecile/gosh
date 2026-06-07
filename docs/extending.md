# Extending gosh

`gosh` is built to be extended. You can add commands, swap the filesystem
backing, and compose the bundled command set with your own — all against a small,
stable API.

> ⚠️ **Extensions are trusted Go code.** `gosh` sandboxes the *script*, not your Go
> command. A command that calls `os.Getenv`, opens a real file, or dials the
> network with `net/http` punches a hole straight through the sandbox. Treat
> command authors as part of your trusted computing base, and always use the
> sandbox-safe `cc.*` accessors below instead of host APIs.

## Writing a command

A command implements the `Command` interface:

```go
type Command interface {
	Name() string
	Run(ctx context.Context, cc *CommandContext) int // returns the exit code
}
```

The easiest way is `gosh.CommandFunc`, which wraps a closure:

```go
package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/darylcecile/gosh"
	"github.com/darylcecile/gosh/std"
)

func main() {
	shout := gosh.CommandFunc("shout", func(ctx context.Context, cc *gosh.CommandContext) int {
		if cc.WantsHelp() {
			cc.PrintHelp("shout [text...]", "Print arguments in upper case.")
			return 0
		}
		fmt.Fprintln(cc.Stdout, strings.ToUpper(strings.Join(cc.Args, " ")))
		return 0
	})

	sh := std.Shell(gosh.WithCommands(shout))
	res, _ := sh.Run(context.Background(), `shout hello world`)
	fmt.Print(res.Stdout) // HELLO WORLD
}
```

Your command composes with everything else — pipes, redirects, command
substitution, `xargs`, `find`:

```sh
shout hi | tr ' ' '_' > /home/user/out.txt
```

## The CommandContext

`CommandContext` is the only surface a command should use to interact with the
world. Key members:

| Member | Use |
|---|---|
| `cc.Name` | the invoked command name |
| `cc.Args` | arguments **excluding** the command name (like `os.Args[1:]`) |
| `cc.Stdin` / `cc.Stdout` / `cc.Stderr` | sandbox-wired I/O streams |
| `cc.Env` | `EnvAccessor` with `Get`, `Set`, `All` over the run's environment |
| `cc.Cwd()` | current working directory (virtual) |
| `cc.FS()` | the virtual `FileSystem` — read/write files inside the sandbox |
| `cc.ResolvePath(p)` | resolve `p` against `cc.Cwd()`, confined to the virtual root |
| `cc.Clock()` | the virtual clock — use instead of `time.Now()` |
| `cc.Governor()` | the resource governor — account work so limits stay enforced |
| `cc.Network()` | the active `NetworkPolicy` (gate egress on `cc.Network().Enabled()`) |
| `cc.Exec(ctx, args...)` | re-enter the dispatcher to run another registered command |
| `cc.BoundedWrite(...)` | write while respecting the output-byte limit |
| `cc.PrintHelp(usage, desc)` | standard `--help` output |
| `cc.WantsHelp()` | true if `-h`/`--help` was passed |

### Reading and writing the VFS

```go
import (
	"io"
	"os"
)

f, err := cc.FS().Open(cc.ResolvePath("input.txt"), os.O_RDONLY, 0)
if err != nil {
	fmt.Fprintln(cc.Stderr, cc.Name+": "+err.Error())
	return 1
}
data, _ := io.ReadAll(f)
f.Close()

// ... transform data into result ...

out, err := cc.FS().Open(cc.ResolvePath("output.txt"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
if err != nil {
	fmt.Fprintln(cc.Stderr, cc.Name+": "+err.Error())
	return 1
}
out.Write([]byte(result))
out.Close()
```

Always go through `cc.ResolvePath` so relative paths honor the script's cwd and
stay confined — never join paths against a host directory.

### Honoring limits

Long loops should account their work against the governor so resource caps keep
holding inside your command. `StreamTick` returns a `*LimitError` (nil when
under budget) when `MaxStreamIterations` is exceeded:

```go
for _, line := range lines {
	if e := cc.Governor().StreamTick(); e != nil {
		fmt.Fprintln(cc.Stderr, cc.Name+": "+e.Error())
		return 1
	}
	// ... process line ...
}
```

Use `cc.BoundedWrite` (or write through `cc.Stdout`, which is already bounded) so
a runaway command cannot blow past `MaxOutputBytes`.

### Gating on the network policy

If your command performs egress, refuse cleanly when networking is disabled — the
same convention the built-in `curl` follows:

```go
if !cc.Network().Enabled() {
	fmt.Fprintln(cc.Stderr, cc.Name+": networking is disabled")
	return 127
}
```

…and route the actual request through the audited egress path rather than rolling
your own `net/http` client, or you bypass the SSRF/allow-list guarantees.

## Composing command sets

- `gosh.WithCommands(cmds...)` registers commands; later registrations override
  earlier same-named ones, so you can **replace** a bundled command with your own.
- `std.Commands()` returns the full bundled set as `[]gosh.Command` if you want to
  filter or wrap it.
- `std.WithStandard()` is the option that registers the bundle; `std.Shell(opts...)`
  is `gosh.New(opts..., std.WithStandard())`.

```go
// Full bundle plus a custom command, with a hardened `curl` of your own:
sh := std.Shell(
	gosh.WithCommands(myShout, myHardenedCurl), // myHardenedCurl shadows the default
)
```

## Filesystem adapters

`gosh.FileSystem` is an interface, so you can back the sandbox with anything. The
[`goshfs`](https://pkg.go.dev/github.com/darylcecile/gosh/goshfs) package provides
ready-made, confinement-preserving adapters:

| Constructor | Behavior |
|---|---|
| `goshfs.NewReadOnlyFS(inner)` | rejects all writes |
| `goshfs.NewReadWriteFS(inner)` | explicit read-write wrapper |
| `goshfs.NewOverlayFS(lower, upper)` | copy-on-write; reads fall through to `lower`, writes go to `upper` |
| `goshfs.NewMountableFS(root)` | mount multiple filesystems at subpaths, each confined |
| `goshfs.NewHostReadOnlyFS(dir)` | mount a **real host directory** read-only, symlink-confined (the one bridge to host disk; opt-in, host-trusted) |

```go
base := gosh.NewInMemoryFS(gosh.NewVirtualClock(gosh.Epoch), 64<<20, 256<<20)
_ = base.MkdirAll("/seed", 0o755)
ro := goshfs.NewReadOnlyFS(base)

sh := std.Shell(gosh.WithFS(ro)) // scripts can read /seed but cannot modify it
```

### Overlay-over-cwd: read real files, discard writes

`goshfs.NewHostReadOnlyFS(dir)` is the only adapter that reads real host disk. It
canonicalizes `dir`, serves files only from within it, resolves every path
through the OS, and rejects (as "not exist") anything whose resolved location —
including via symlinks — escapes the root. It denies all writes. Compose it as the
lower layer of an overlay so scripts can "write" into a discarded in-memory upper
without ever touching host disk (this is exactly what `gosh -root DIR` does):

```go
lower, err := goshfs.NewHostReadOnlyFS("/path/to/project")
if err != nil {
    return err
}
upper := gosh.NewInMemoryFS(gosh.NewVirtualClock(gosh.Epoch), 64<<20, 256<<20)
sh := std.Shell(
    gosh.WithFS(goshfs.NewOverlayFS(lower, upper)),
    gosh.WithCwd("/"), // mount point is visible at the starting directory
)
```

**Security:** this bridges the sandbox to host disk, so it is opt-in and
host-trusted. It assumes the mounted tree is not concurrently mutated by other
host processes during the run and contains no attacker-controlled hardlinks
escaping the root. See `THREAT_MODEL.md` §5.10. A runnable demo lives in
[`examples/overlay-cwd`](../examples/overlay-cwd).

To implement a backend from scratch, satisfy the `gosh.FileSystem` interface and
**preserve traversal confinement** — every adapter must clamp `..` and symlinks to
its root. Reuse the `goshfs` adapters where possible rather than reimplementing the
confinement logic.

## Checklist for a safe extension

- [ ] Uses only `cc.*` accessors — no `os`, `net/http`, `time.Now`, or host I/O.
- [ ] Resolves every path with `cc.ResolvePath` and reads/writes via `cc.FS()`.
- [ ] Accounts loops/streams against `cc.Governor()`.
- [ ] Writes through `cc.Stdout`/`cc.BoundedWrite` (respects `MaxOutputBytes`).
- [ ] Supports `cc.WantsHelp()` / `cc.PrintHelp`.
- [ ] If it does egress, gates on `cc.Network().Enabled()` and respects the policy.
- [ ] Returns a meaningful exit code (`0` success, non-zero failure).
