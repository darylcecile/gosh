# gosh

A sandboxed, in-memory **Bash interpreter for Go**, built for AI agents.

`gosh` runs untrusted, model-generated shell scripts inside a fully virtualized
environment built on [`mvdan.cc/sh`](https://pkg.go.dev/mvdan.cc/sh/v3). **No real
process is ever spawned and no real file is ever touched** unless you explicitly
opt in. It ships ~70 sandboxed coreutils (`cat`, `ls`, `grep`, `sed`, `awk`,
`jq`, `tar`, `curl`, …), deterministic time, hard resource limits, and a small,
stable API for embedding and extension.

```go
sh := std.Shell()                       // secure defaults, full command set
res, _ := sh.Run(ctx, `echo "hi $USER" | tr a-z A-Z`)
fmt.Print(res.Stdout)                    // HI
```

> **Why?** AI agents need a shell. Giving a model a real shell is a remote-code-
> execution hazard. `gosh` gives it a *believable* shell whose every capability —
> filesystem, network, time, CPU/memory budget — is a host decision, fails
> closed, and is covered by an adversarial test + fuzz suite. See
> [`THREAT_MODEL.md`](./THREAT_MODEL.md).

---

## Install

```sh
go get github.com/darylcecile/gosh
```

Requires Go 1.25+. Two import surfaces:

- `github.com/darylcecile/gosh` — the core engine, types, and options.
- `github.com/darylcecile/gosh/std` — the bundled command set (`std.Shell`, `std.Commands`, `std.WithStandard`).

The core package has **zero commands** by default; you choose what to register.
`std` is the batteries-included bundle.

---

## Quick start

### Run a script

```go
package main

import (
	"context"
	"fmt"

	"github.com/darylcecile/gosh/std"
)

func main() {
	sh := std.Shell() // in-memory FS, no network, no host exec, all limits on
	res, err := sh.Run(context.Background(), `
		seq 1 5 | paste -sd,        # 1,2,3,4,5
		echo '{"a":1,"b":2}' | jq .b
	`)
	if err != nil {
		panic(err) // host-level failure (limit/parse/cancel/unsupported)
	}
	fmt.Print(res.Stdout)
	fmt.Println("exit:", res.ExitCode)
}
```

### Error model

`Run` returns `(Result, error)`:

- A script that **exits non-zero** yields `res.ExitCode != 0` and a **nil** error —
  that is normal shell behavior, not a host failure.
- The `error` is reserved for **host-level** failures and is always one of the
  typed errors `*LimitError`, `*CanceledError`, `*ParseError`,
  `*UnsupportedError`, `*InternalError` — all matchable with `errors.As`/`errors.Is`.

```go
res, err := sh.Run(ctx, script)
var limit *gosh.LimitError
switch {
case errors.As(err, &limit):
	log.Printf("script hit a resource cap: %s", limit.Kind)
case err != nil:
	log.Printf("host failure: %v", err)
case res.ExitCode != 0:
	log.Printf("script failed: %s", res.Stderr)
}
```

---

## Secure defaults

`std.Shell()` (and `gosh.New()`) start from a fail-closed baseline. Everything
dangerous is **off** until you opt in:

| Capability | Default | Opt-in |
|---|---|---|
| Filesystem | empty in-memory VFS, persists across `Run`s | `WithFiles`, `WithFS`, `WithEphemeralFS` |
| Host environment | **not** inherited; only `HOME` seeded | `WithEnv`, `RunEnv` |
| Working dir / `$HOME` | `/home/user` | `WithCwd`, `RunCwd` |
| Clock | deterministic UTC `VirtualClock` from `2000-01-01T00:00:00Z` | `WithClock` |
| Network | none (egress commands return 127) | `WithNetwork` |
| Process execution | registry-only; unknown command → exit 127, **never** `os/exec` | `WithCommands` |
| Builtins | deny-by-default; `eval`/`source`/`exec`/job-control denied | `WithAllowedBuiltins`, `WithBuiltinPolicy` |
| Resource limits | all on at `DefaultLimits()` | `WithLimits` |

Because the clock and FS are virtual and the environment is empty, **runs are
deterministic and reproducible** by default — the same script yields the same
output (`date` returns `2000-01-01`, etc.) until you opt into a real clock.

---

## Configure the sandbox

Options are passed to `std.Shell(...)` / `gosh.New(...)`:

```go
sh := std.Shell(
	gosh.WithFiles(map[string]string{
		"/home/user/input.txt": "alpha\nbeta\ngamma\n",
	}),
	gosh.WithEnv(map[string]string{"GREETING": "hello"}),
	gosh.WithLimits(gosh.Limits{
		MaxCommands:    5_000,   // any field left zero keeps its secure default
		MaxOutputBytes: 1 << 20, // 1 MiB
	}),
)
```

`WithLimits` uses **zero-means-default** per field: a partial `Limits{}` only
overrides the fields you set, so you can never accidentally disable a guard by
omission. See [`docs/security.md`](./docs/security.md) for the full limit table
and the network/FS sandboxing guides.

### Per-run overrides

A single `*Shell` is reusable. Each `Run` resets env/functions/positional
params (the FS persists), and accepts per-call `RunOption`s:

```go
res, _ := sh.Run(ctx, `cat; echo "args: $@"`,
	gosh.RunStdin("piped input\n"),
	gosh.RunArgs("one", "two"),
	gosh.RunEnv(map[string]string{"EXTRA": "1"}),
	gosh.RunStdout(&buf),
)
```

> A `*Shell` is **not** safe for concurrent `Run` calls. The model is one
> `*Shell` per agent/session (construction is cheap). `Run` serializes internally
> so concurrent misuse cannot corrupt state, but you should not rely on it for
> parallelism.

---

## What's included

~70 sandboxed commands across file ops, text processing, encoding/data,
archives, and network. Highlights: `cat cp mv rm mkdir ls ln stat find tree`,
`grep cut tr sort uniq wc head tail sed awk`, `base64 md5sum sha256sum jq yq csv`,
`gzip gunzip tar zcat`, and `curl` (deny-by-default egress). Full reference:
[`docs/commands.md`](./docs/commands.md).

Coreutils aim for GNU-compatible behavior but are reimplemented in pure Go —
some legacy flag forms differ (e.g. use `head -n 2`, not `head -2`). `echo`,
`printf`, `test`, and `[` are shell builtins, not registry commands.

---

## Extending with custom commands

A command is anything implementing `Command` (`Name() string` and
`Run(ctx, *CommandContext) int`). The `CommandFunc` helper wraps a closure:

```go
shout := gosh.CommandFunc("shout", func(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		cc.PrintHelp("shout [text...]", "Print arguments in upper case.")
		return 0
	}
	fmt.Fprintln(cc.Stdout, strings.ToUpper(strings.Join(cc.Args, " ")))
	return 0
})

sh := std.Shell(gosh.WithCommands(shout))
sh.Run(ctx, `shout hello world | tr ' ' '_'`)
```

`CommandContext` gives you sandbox-safe access to stdio, args, env, the virtual
filesystem (`cc.FS()`, `cc.ResolvePath()`), the virtual clock (`cc.Clock()`),
the resource governor (`cc.Governor()`), the network policy (`cc.Network()`), and
re-entrant dispatch (`cc.Exec()`). See [`docs/extending.md`](./docs/extending.md).

> ⚠️ **A custom command is trusted Go code.** `gosh` sandboxes the *script*, not
> your Go extensions. If your command reads `os.Getenv`, dials the network with
> `net/http`, or touches the real disk, you have punched a hole in the sandbox.
> Treat command authors as part of your trusted computing base, and use the
> provided `cc.*` accessors instead of host APIs.

---

## Command line

A reference CLI is included:

```sh
go install github.com/darylcecile/gosh/cmd/gosh@latest

echo 'echo hi | tr a-z A-Z' | gosh        # read script from stdin
gosh -c 'seq 3 | paste -sd+'              # inline script
```

Flags cover cwd, resource caps, and network opt-in (`--max-output-bytes`,
`--max-commands`, `--allow-private-ips`, `--dangerously-allow-full-internet`).
See [`docs/cli.md`](./docs/cli.md).

---

## Model Context Protocol (MCP)

`goshmcp` exposes the sandbox as an MCP stdio server with a single `bash` tool,
so an MCP-capable agent can run shell scripts safely:

```go
srv := goshmcp.NewServer(goshmcp.WithPersistentFS(true))
srv.ServeStdio(ctx, os.Stdin, os.Stdout)
```

See [`docs/mcp.md`](./docs/mcp.md).

---

## Documentation

- [`docs/getting-started.md`](./docs/getting-started.md) — embed the library, step by step
- [`docs/commands.md`](./docs/commands.md) — full command reference (~70 commands)
- [`docs/security.md`](./docs/security.md) — sandbox configuration: limits, network, filesystem
- [`docs/extending.md`](./docs/extending.md) — write custom commands and filesystem adapters
- [`docs/cli.md`](./docs/cli.md) — `cmd/gosh` CLI reference
- [`docs/mcp.md`](./docs/mcp.md) — MCP server reference
- [`examples/`](./examples) — runnable programs: custom command, read-only knowledge base, in-memory overlay, and overlay-over-cwd
- [`THREAT_MODEL.md`](./THREAT_MODEL.md) — security model, guarantees, and residual risks
- [`PRD.md`](./PRD.md) / [`FEATURES.md`](./FEATURES.md) — product requirements & feature checklist

---

## License

[Dazza Public License 1.0](./LICENSE) — © 2026 Daryl Cecile. You may use,
modify, and distribute the library (including in closed-source applications);
distributed modifications of the library itself must stay under this license
with source available. See [`LICENSE`](./LICENSE) for the full text.
