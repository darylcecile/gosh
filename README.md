# gosh

A sandboxed, in-memory Bash interpreter for Go, built for AI agents.

`gosh` executes untrusted, model-generated Bash inside a fully virtualized
environment built on [`mvdan.cc/sh`](https://pkg.go.dev/mvdan.cc/sh/v3). No real
process is ever spawned and no real file is ever touched unless the host
explicitly opts in. See [`PRD.md`](./PRD.md) and [`FEATURES.md`](./FEATURES.md)
for the full product and security requirements.

> **Status:** core foundation. The shell engine, in-memory filesystem, resource
> governors, typed errors, clock, and extension interfaces are implemented and
> tested. Coreutil command groups (`cat`, `ls`, `grep`, …) are built in separate
> `commands/<group>` packages against the stable interfaces here.

## Quick start

```go
sh := gosh.New() // secure defaults: in-memory FS, no network, no exec, limits on
res, err := sh.Run(ctx, `name=world; echo "hello $name"`)
// res.Stdout == "hello world\n"; err is non-nil only for host-level failures.
```

Register commands (coreutils or your own) and compose them in pipes/redirects:

```go
sh := gosh.New(gosh.WithCommands(myCommands...))
res, _ := sh.Run(ctx, `echo hi | mycmd > /home/user/out.txt`)
```

A script that exits non-zero yields `res.ExitCode != 0` with a **nil** error.
The returned `error` is reserved for host-level failures — `*LimitError`,
`*CanceledError`, `*ParseError`, `*UnsupportedError`, `*InternalError` — all
matchable via `errors.As`/`errors.Is`.

## Defaults (D11)

| Capability | Default | Opt-in |
|---|---|---|
| Filesystem | empty in-memory (`InMemoryFS`), persists across `Run`s | `WithFiles`, `WithFS`, `WithEphemeralFS` |
| Host environment | **not** inherited; only `HOME`/`PWD` seeded | `WithEnv`, `RunEnv` |
| Working dir / `$HOME` | `/home/user` | `WithCwd`, `RunCwd` |
| Clock | deterministic UTC `VirtualClock` from `2000-01-01T00:00:00Z` | `WithClock` (`SystemClock`, `FixedClock`) |
| Network | none (egress commands absent) | `WithNetwork` |
| Process execution | registry-only; unknown command → exit 127, never `os/exec` | `WithCommands` |
| Builtins | deny-by-default admission; safe shell-control allowed | `WithAllowedBuiltins`, `WithBuiltinPolicy` |
| Resource limits | all on at `DefaultLimits()` | `WithLimits` |

## Security posture

- **Fail-closed runner (S1):** every `mvdan/sh` option is set explicitly so no
  default leaks `os.Environ` or the real FS/exec.
- **Admission before exec (S2):** a `CallHandler` gates *every* command,
  including builtins; `eval`, `source`, `command`, `builtin`, job control, and
  host-touching builtins are denied by default.
- **Construct rejection (S2a):** background `&`, process substitution, and
  coprocs are rejected with a typed `*UnsupportedError` before any statement
  runs.
- **Confined VFS (S4/S5/S7):** path traversal is clamped to the virtual root,
  symlink loops error out, and per-file/total size caps bound memory.
- **Governors (S8–S14a):** command count, loop iterations, output bytes,
  stream iterations, and pre-exec/expansion bounds, each surfacing a typed
  `*LimitError` naming the limit.

> A custom command is **trusted Go code**. `gosh` sandboxes the script, not your
> Go extensions; treat command authors as part of your trusted computing base.
