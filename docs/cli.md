# Command-line interface (`cmd/gosh`)

`cmd/gosh` is a reference CLI that runs Bash scripts inside the gosh sandbox using
the bundled `std` command set. Like the library, it **never executes host
processes, never inherits host environment variables, and denies network egress
by default**.

## Install

```sh
go install github.com/darylcecile/gosh/cmd/gosh@latest
```

Or build from a checkout:

```sh
go build -o gosh ./cmd/gosh
```

## Usage

```
gosh [FLAGS] -c 'SCRIPT' [ARG...]      # inline script
gosh [FLAGS] SCRIPT_FILE [ARG...]      # script from a file
gosh [FLAGS] < SCRIPT                  # script from stdin
gosh [FLAGS]                           # REPL when stdin is a TTY
```

Script sources are mutually exclusive, in priority order: `-c`, then
`SCRIPT_FILE`, then stdin. Any trailing `ARG...` become the script's positional
parameters (`$1`, `$2`, … `$@`). The process exit code mirrors the script's exit
code.

```sh
echo 'echo hi | tr a-z A-Z' | gosh         # HI
gosh -c 'seq 3 | paste -sd+'               # 1+2+3
gosh -c 'echo "first arg is $1"' alpha      # first arg is alpha
gosh script.sh one two                      # run a file with positional args
```

## Flags

| Flag | Description |
|---|---|
| `-c STRING` | run an inline Bash script |
| `-cwd PATH` | initial virtual working directory (defaults to `/` when `-root` is set, else `/home/user`) |
| `-root HOSTDIR` | mount `HOSTDIR` as a **read-only** overlay lower layer: scripts read real files, but writes land in a discarded in-memory layer and never touch host disk. Use `-root .` for overlay-over-cwd |
| `-e`, `-errexit` | exit on the first command failure (prepends `set -e`) |
| `-no-network` | assert no network egress (the default); errors if combined with network-enabling flags |
| `-env KEY=VAL` | seed an environment variable (repeatable) |
| `-file HOSTPATH:VPATH` | load a **trusted** host file into the VFS at `VPATH` (repeatable) |
| `-max-output-bytes N` | cap cumulative stdout+stderr bytes |
| `-max-commands N` | cap simple commands per run |
| `-timeout DURATION` | wall-clock timeout, e.g. `2s`, `1m` |
| `-allow-origin ORIGIN` | allow an exact network origin, e.g. `https://example.com` (repeatable) |
| `-allow-method METHOD` | allow an HTTP method (repeatable; default `GET`,`HEAD`) |
| `-allow-private-ips` | allow network commands to reach private/loopback IPs (SSRF protection is on by default) |
| `-dangerously-allow-full-internet` | **DANGEROUS:** unrestricted network egress |
| `-json` | emit a single JSON object `{stdout,stderr,exitCode}` instead of streaming output |
| `-version` | print version and exit |
| `-help` | print help and exit |

Flags left unset keep the library's secure defaults (see
[security.md](./security.md)). `--mount` is reserved but **not implemented** by
this CLI; use `--file` to seed trusted host files into the virtual filesystem.

## Seeding files

```sh
gosh -file ./report.csv:/home/user/report.csv -c 'wc -l /home/user/report.csv'
```

`-file` copies the host file's **contents** into the in-memory VFS — the script
operates on the copy and cannot reach back to the real path. Only seed files you
are willing to expose to the (untrusted) script.

## Overlay-over-cwd (mounting a real directory read-only)

`-root DIR` mounts a real host directory as a **read-only lower layer** with an
in-memory **upper layer** that captures every write. Scripts can read the real
files on disk, but their writes are confined to memory and discarded when the
process exits — the host directory is never modified:

```sh
# Let an agent inspect (but never mutate) the current project tree:
gosh -root . -c 'ls; grep -rl TODO .'

# Writes appear to succeed inside the run, but host disk stays pristine:
gosh -root . -c 'echo CHANGED > README.md; cat README.md'   # prints CHANGED
cat README.md                                                # unchanged on disk
```

When `-root` is set, the virtual working directory defaults to `/` (the mount
point) so the mounted tree is visible immediately. `-file` entries are still
honored and are seeded into the writable upper layer.

**Security:** the mount is symlink-confined — any path resolving outside `DIR`
(including via symlinks) reads as "file does not exist". It is read-only and
opt-in by you, the operator. Do **not** point `-root` at a directory that
untrusted host processes can modify during the run, or one containing
attacker-controlled hardlinks; see [security.md](./security.md) and
`THREAT_MODEL.md` §5.10 for the full residual-risk discussion.

## Enabling the network

Network commands (`curl`, `html2md`) refuse to run until you allow-list origins:

```sh
gosh -allow-origin https://api.github.com \
     -allow-method GET \
     -c 'curl https://api.github.com/zen'
```

SSRF protection (no private/loopback/metadata IPs) stays on unless you pass
`-allow-private-ips`, and `-dangerously-allow-full-internet` removes both the
allow-list and the SSRF defense. **Never** pass those for untrusted scripts.

## Structured (JSON) output

For programmatic callers and agent tooling, `-json` captures the run and prints a
single JSON object instead of streaming raw output:

```sh
gosh --json -c 'echo out; echo oops 1>&2; exit 3'
# {"stdout":"out\n","stderr":"oops\n","exitCode":3}
```

A non-zero script exit is reported in `exitCode` (not an error). Host-level
failures (limits, parse errors, cancellation) set `exitCode` to `2` and append the
`gosh:`-prefixed reason to `stderr`, so a single parse of the object tells you
both what the script produced and whether the host aborted it.

## Determinism

Without `-timeout`/network flags, runs are deterministic: the virtual clock means
`date` and timestamps are reproducible, and there is no host state to leak. This
makes the CLI handy for reproducible scripting and for testing agent-generated
shell snippets in isolation.
