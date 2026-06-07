# Getting started

This guide walks through embedding `gosh` in a Go program from the simplest
possible run to a fully configured agent sandbox.

## 1. Install

```sh
go get github.com/darylcecile/gosh
```

Two packages matter:

- `github.com/darylcecile/gosh` — the engine, types, and `With*` options. It
  registers **no commands** on its own.
- `github.com/darylcecile/gosh/std` — the bundled ~70-command coreutil set plus
  the convenience constructors `std.Shell`, `std.Commands`, and `std.WithStandard`.

## 2. Your first run

```go
package main

import (
	"context"
	"fmt"

	"github.com/darylcecile/gosh/std"
)

func main() {
	sh := std.Shell()
	res, err := sh.Run(context.Background(), `echo "hello world" | tr a-z A-Z`)
	if err != nil {
		panic(err)
	}
	fmt.Print(res.Stdout) // HELLO WORLD
}
```

`std.Shell(opts...)` is sugar for `gosh.New(append(opts, std.WithStandard())...)`.
If you want the engine with your *own* command set instead of the bundle, use
`gosh.New(gosh.WithCommands(...))` directly.

## 3. The Result and error model

```go
res, err := sh.Run(ctx, script)
```

- `res.Stdout`, `res.Stderr` — captured output (also streamable; see step 6).
- `res.ExitCode` — the script's exit status. **Non-zero is not an error** — it is
  how shells report a failed command.
- `res.Metadata` — auxiliary info such as commands executed and whether output
  was truncated.
- `err` — **only** non-nil for host-level failures, and always one of the typed
  errors:

| Error | Meaning |
|---|---|
| `*ParseError` | the script is not valid shell |
| `*UnsupportedError` | a rejected construct (background `&`, process substitution, coproc) |
| `*LimitError` | a resource governor tripped (`.Kind` names which one) |
| `*CanceledError` | the `context.Context` was cancelled or its deadline passed |
| `*InternalError` | a recovered internal fault (e.g. recovered stack overflow) |

```go
import "errors"

var le *gosh.LimitError
if errors.As(err, &le) {
	log.Printf("hit limit: %s (cap %d)", le.Kind, le.Limit)
}
```

## 4. Give the script some files

The default filesystem is an **empty in-memory VFS**. Seed it with `WithFiles`,
or mount something richer (see [security.md](./security.md) and
[extending.md](./extending.md)).

```go
sh := std.Shell(gosh.WithFiles(map[string]string{
	"/home/user/data.csv": "name,age\nada,36\nalan,41\n",
}))
res, _ := sh.Run(ctx, `csv --col name /home/user/data.csv | sort`)
```

The VFS **persists across `Run` calls** on the same `*Shell` (so an agent can
build up state turn by turn). Pass `gosh.WithEphemeralFS()` if you want a fresh
filesystem snapshot restored before every run instead.

## 5. Set a budget

Every run is bounded by `DefaultLimits()`. Override individual caps; any field
left zero keeps its secure default:

```go
sh := std.Shell(gosh.WithLimits(gosh.Limits{
	MaxCommands:    2_000,
	MaxOutputBytes: 512 << 10, // 512 KiB
	MaxLoopIterations: 100_000,
}))
```

A script that exceeds a cap stops immediately with a `*LimitError`. See the full
table in [security.md](./security.md).

## 6. Stream output and feed stdin

By default output is captured into `res.Stdout`/`res.Stderr`. For long-running or
large output, stream to your own writers and feed stdin per run:

```go
var out bytes.Buffer
res, _ := sh.Run(ctx, `cat | wc -l`,
	gosh.RunStdin("a\nb\nc\n"),
	gosh.RunStdout(&out),
	gosh.RunArgs("extra", "positional", "args"), // become $1 $2 $3 / $@
)
```

`RunStdin` accepts a `string`, `[]byte`, or `io.Reader`.

## 7. Enable network deliberately

Network commands are present in the standard bundle, but they refuse to run until
you provide an explicit allow-list. Keep the policy narrow: exact origins, optional
path prefixes, and only the HTTP methods the script needs.

```go
sh := std.Shell(gosh.WithNetwork(gosh.NetworkPolicy{
	AllowedOrigins:      []string{"https://api.example.com"},
	AllowedPathPrefixes: []string{"/v1/"},
	AllowedMethods:      []string{"GET"},
	MaxResponseBytes:    4 << 20,
	MaxRedirects:        3,
}))

res, _ := sh.Run(ctx, `curl https://api.example.com/v1/status`)
```

By default, gosh still refuses private, loopback, link-local, cloud-metadata, and
other special-use IP ranges even when their origin is allow-listed. Host proxy
environment variables are ignored. Only use `AllowPrivateIPs` for a trusted
internal test service, and avoid `DangerouslyAllowFullInternet` for untrusted
scripts.

## 8. Reuse the shell

A `*Shell` owns one VFS and is meant to be **reused** across an agent session.
Env, shell functions, and positional parameters reset each `Run`; the filesystem
carries over. A `*Shell` is **not** safe for concurrent `Run` calls — use one per
session (they are cheap to build). `Run` serializes internally so accidental
concurrency cannot corrupt state, but don't rely on it for parallelism.

## Next steps

- Lock down or open up capabilities: [security.md](./security.md)
- Add your own commands or filesystem backends: [extending.md](./extending.md)
- Browse the command set: [commands.md](./commands.md)
- Run it from a terminal or wire it to an agent: [cli.md](./cli.md), [mcp.md](./mcp.md)
