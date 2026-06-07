# Model Context Protocol server (`goshmcp`)

`goshmcp` exposes the gosh sandbox as a [Model Context Protocol](https://modelcontextprotocol.io)
stdio server with a single tool, `bash`, so any MCP-capable agent can run shell
scripts without ever touching your host. It speaks JSON-RPC 2.0 over stdin/stdout
and implements the `initialize`, `tools/list`, and `tools/call` methods.

`goshmcp` is a **library** — you wrap it in a tiny `main` so you control the
sandbox policy.

## A minimal server

```go
package main

import (
	"context"
	"os"

	"github.com/darylcecile/gosh/goshmcp"
)

func main() {
	srv := goshmcp.NewServer(
		goshmcp.WithPersistentFS(true), // keep the VFS across tool calls in this process
	)
	if err := srv.ServeStdio(context.Background(), os.Stdin, os.Stdout); err != nil {
		os.Exit(1)
	}
}
```

Build it and point your MCP client at the binary:

```sh
go build -o gosh-mcp ./path/to/your/main
```

## The `bash` tool

```
name: bash
description: Execute a Bash script inside a secure in-memory sandbox
             (no host filesystem or process access; network deny-by-default).
```

Input schema:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `script` | string | yes | the Bash script to execute |
| `stdin` | string | no | standard input for the script |
| `cwd` | string | no | virtual working directory for this run |
| `args` | string[] | no | positional parameters (`$1`, `$2`, …) |

The result is returned as MCP text content containing the script's exit code and
its stdout/stderr (a formatted `exitCode:` / `stdout:` / `stderr:` block);
`isError` is set for **host-level** failures (limit/parse/cancel/unsupported),
not for ordinary non-zero script exits.

## Configuring the sandbox

Pass any core `gosh` options through `WithShellOptions` to apply limits, seed
files, set an environment, or enable a network allow-list for every tool call:

```go
srv := goshmcp.NewServer(
	goshmcp.WithPersistentFS(true),
	goshmcp.WithShellOptions(
		gosh.WithLimits(gosh.Limits{MaxCommands: 5_000, MaxOutputBytes: 1 << 20}),
		gosh.WithFiles(map[string]string{
			"/home/user/README.md": "seeded content\n",
		}),
		gosh.WithNetwork(gosh.NetworkPolicy{
			AllowedOrigins: []string{"https://api.example.com"},
			AllowedMethods: []string{"GET"},
		}),
	),
)
```

All the secure defaults and opt-ins from [security.md](./security.md) apply
exactly as they do for the embedded library — the MCP layer only adds the
JSON-RPC transport.

### Persistent vs. fresh filesystem

- `WithPersistentFS(true)` — one shell (and one VFS) is reused for the lifetime of
  the process, so files an agent writes in one `bash` call are visible in the
  next. Good for an interactive session.
- `WithPersistentFS(false)` (default) — each tool call gets a fresh sandbox, so
  calls cannot accumulate state. Good for stateless, one-shot execution.

## Driving it directly

You can also call the handler in-process (e.g. to embed in a larger server)
without the stdio transport:

```go
res, err := srv.HandleToolCall(ctx, "bash", json.RawMessage(`{"script":"echo hi"}`))
// res.Content[0].Text contains the formatted run result (exit code + stdout/stderr).
// res.IsError reflects host-level failures.
```

## Security notes

- The server **never** spawns host processes or reads host env/files; it inherits
  every guarantee in [`THREAT_MODEL.md`](../THREAT_MODEL.md).
- Network stays deny-by-default. Only enable egress (and only specific origins)
  via `WithShellOptions(gosh.WithNetwork(...))`, and never enable the
  `Dangerously*`/`AllowPrivateIPs` escape hatches for untrusted agents.
- The single tool is intentionally narrow (`bash` only); there is no file-write or
  exec tool that bypasses the sandbox.
