# Security & sandbox configuration

`gosh` is designed to run **untrusted, model-generated** scripts. Every
capability fails closed and is a deliberate host opt-in. This page is the
configuration reference; for the guarantees, attacker model, and residual risks,
read [`THREAT_MODEL.md`](../THREAT_MODEL.md).

## The baseline

`gosh.New()` / `std.Shell()` start from a fail-closed posture:

- **No host process execution, ever.** Unknown commands return exit `127`; the
  engine never calls `os/exec`. This is enforced by an import-discipline test —
  only the audited `commands/netcmd` egress boundary may import `net`, and
  nothing may import `os/exec`.
- **No host filesystem.** The default FS is an empty in-memory VFS, confined to a
  virtual root with path-traversal clamping and symlink-loop detection.
- **No host environment.** Only `HOME` is seeded; `os.Environ()` is never read.
- **No network.** Egress commands refuse to run until `WithNetwork`.
- **Deterministic clock.** A virtual UTC clock from `2000-01-01T00:00:00Z`.
- **Deny-by-default builtins.** `eval`, `source`/`.`, `exec`, `command`,
  `builtin`, job control, and host-touching builtins are rejected before they run.
- **Rejected constructs.** Background `&`, process substitution `<(...)`, and
  coprocesses are rejected with a typed `*UnsupportedError` before any statement
  executes.
- **All resource governors on.**

You weaken this posture only by passing explicit options. The rest of this page
covers each lever.

## Resource limits

All limits are on by default (`DefaultLimits()`); override with `WithLimits`.
**Zero means "keep the default"** for each field, so partial structs are safe.

```go
sh := std.Shell(gosh.WithLimits(gosh.Limits{
	MaxCommands:    5_000,
	MaxOutputBytes: 1 << 20,
}))
```

| Field | Default | Bounds |
|---|---|---|
| `MaxCommands` | 100,000 | total simple commands per run |
| `MaxLoopIterations` | 1,000,000 | iterations per loop call-site |
| `MaxCallDepth` | 1,000 | shell function recursion (best-effort¹) |
| `MaxOutputBytes` | 32 MiB | cumulative stdout+stderr |
| `MaxStreamIterations` | 10,000,000 | per-command stream/record iterations |
| `MaxMemoryBytes` | 256 MiB | best-effort VFS + buffer ceiling¹ |
| `MaxScriptBytes` | 1 MiB | script rejected **before** parsing if larger |
| `MaxASTNodes` | 250,000 | parsed syntax-tree node count |
| `MaxASTDepth` | 500 | syntax-tree nesting depth |
| `MaxArgvBytes` | 1 MiB | total argv bytes for one command |
| `MaxExpandedWords` | 100,000 | words from a single expansion (also bounds glob blow-up) |
| `MaxPipelineLength` | 256 | stages in one pipeline |
| `MaxCmdSubstDepth` | 64 | command-substitution nesting |
| `MaxFileBytes` | 64 MiB | one file in the VFS |
| `MaxTotalFSBytes` | 256 MiB | all files in the VFS |

Exceeding any cap aborts the run with a `*LimitError` whose `.Kind` names the
limit. Always pair `Run` with a `context.Context` deadline as the outer wall-clock
bound:

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
res, err := sh.Run(ctx, script) // *CanceledError on deadline
```

> ¹ `MaxCallDepth` and `MaxMemoryBytes` are **best-effort** — the underlying
> interpreter exposes no precise return-depth hook, so very deep recursion is
> primarily bounded by `MaxCommands`/`MaxLoopIterations`, and a stack-overflow
> panic is recovered into an `*InternalError` rather than crashing the host. See
> the threat model for details.

## Filesystem

The default empty VFS persists across runs on the same `*Shell`. Options:

- `WithFiles(map[path]contents)` — seed the in-memory VFS.
- `WithEphemeralFS()` — snapshot the FS and restore it before **every** run, so
  scripts cannot accumulate state across turns.
- `WithFS(fsys)` — supply any `gosh.FileSystem` implementation, including the
  adapters in [`goshfs`](./extending.md#filesystem-adapters):
  - `goshfs.NewReadOnlyFS(inner)` — block all writes.
  - `goshfs.NewReadWriteFS(inner)` — explicit read-write wrapper.
  - `goshfs.NewOverlayFS(lower, upper)` — copy-on-write: reads fall through to
    `lower`, writes land in `upper`, leaving `lower` untouched.
  - `goshfs.NewMountableFS(root)` — mount multiple filesystems at subpaths, each
    confined to its mount point.
  - `goshfs.NewHostReadOnlyFS(dir)` — mount a **real host directory** read-only
    and symlink-confined (overlay-over-cwd). This is the one adapter that touches
    host disk: opt-in, host-trusted, writes denied. Pair it with `NewOverlayFS`
    to discard script writes into memory. See `THREAT_MODEL.md` §5.10.

All adapters preserve traversal confinement — a script cannot escape the virtual
root or a mount boundary via `..` or symlinks.

> **Mounting real host directories is possible but dangerous.** If you back the
> VFS with the real disk, the sandbox is only as strong as that backing FS. Prefer
> a read-only or overlay wrapper and mount the narrowest subtree the task needs.

## Network

Network is fully off by default. Enable it with a `NetworkPolicy` that explicitly
allow-lists what the script may reach:

```go
sh := std.Shell(gosh.WithNetwork(gosh.NetworkPolicy{
	AllowedOrigins:      []string{"https://api.example.com"},
	AllowedPathPrefixes: []string{"/v1/"},          // optional path narrowing
	AllowedMethods:      []string{"GET"},           // default: GET, HEAD
	MaxResponseBytes:    4 << 20,                    // decompression-bomb cap
	MaxRedirects:        3,                          // each hop re-validated
	CredentialTransforms: []func(*http.Request){     // host-side secret injection
		func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) },
	},
}))
```

Guarantees enforced at the egress boundary:

- **Origin allow-list.** Empty list = nothing reachable. Each request's
  scheme/host/port must match exactly.
- **Optional path narrowing.** `AllowedPathPrefixes` matches the escaped URL path
  (for example `/v1/`). When prefixes are configured, gosh rejects `..` path
  segments and encoded separators/dot segments (`%2e`, `%2f`, `%5c`) before the
  prefix check so `/v1/../admin` or `/v1%2fadmin` cannot satisfy a narrower
  allow-list.
- **SSRF + DNS-rebinding defense (secure by default).** Connections to private,
  loopback, link-local, unspecified, multicast, cloud-metadata, and special-use
  ranges are refused. This includes `169.254.169.254`, `fd00:ec2::254`, CGNAT
  (`100.64.0.0/10`, including Alibaba metadata), IETF protocol assignments
  (`192.0.0.0/24`, including Oracle metadata), benchmarking (`198.18.0.0/15`),
  6to4 anycast (`192.88.99.0/24`), reserved IPv4 (`240.0.0.0/4`), and related
  IPv6 special ranges. NAT64 well-known-prefix and 6to4 addresses are decoded
  and their embedded IPv4 is checked too.
- **DNS rebinding resistance.** Hostnames are resolved inside the policy transport;
  every resolved IP is checked, then the transport dials the checked IP directly.
  The same validation runs on every redirect hop.
- **No ambient host proxy.** `HTTP_PROXY` / `HTTPS_PROXY` from the host
  environment are ignored. Network traffic and injected credentials only follow
  explicit `NetworkPolicy`, never ambient proxy configuration.
- **Credential isolation.** `CredentialTransforms` run **outside** the sandbox at
  the egress boundary. Injected secrets are never visible to the script and
  override any script-supplied header of the same name.
- **Response caps & redirect caps** bound memory and redirect chains.
- **Safe remote filenames.** `curl -O` treats the URL-derived filename as a single
  basename. Decoded `/`, `\`, NUL, `.`, and `..` are refused so a URL or redirect
  cannot choose `../target` as the output path.

SSRF protection is ON for any policy that is not `DangerouslyAllowFullInternet`,
regardless of how the policy was built. If you need to reach a trusted internal
test service, set both a narrow `AllowedOrigins` entry and `AllowPrivateIPs: true`;
do not use `DangerouslyAllowFullInternet` for that case.

Two narrow, loudly-named escape hatches — **never enable for untrusted scripts**:

| Field | Effect |
|---|---|
| `AllowPrivateIPs` | opt **out** of the SSRF defense only (e.g. to reach a trusted intranet/test host). Origin allow-list still applies. |
| `DangerouslyAllowFullInternet` | disables **both** the origin allow-list **and** the SSRF defense — unrestricted egress. |

Residual network caveat: gosh recognizes the NAT64 well-known prefix
(`64:ff9b::/96`) and 6to4 (`2002::/16`) for embedded-IPv4 checks. If your
environment routes a private, network-specific NAT64 prefix from ordinary global
IPv6 space, avoid allow-listing that prefix for untrusted scripts or enforce the
translation boundary outside gosh.

## Builtins

Shell-control builtins are admitted by a deny-by-default policy. Safe control
flow (`if`, `for`, `while`, `echo`, `printf`, `test`, variable/param handling) is
allowed; anything that could break isolation (`eval`, `source`, `exec`, job
control, host-touching builtins) is denied. Adjust with:

- `WithAllowedBuiltins(names...)` — extend the allow-list.
- `WithDeniedBuiltins(names...)` — further restrict.
- `WithBuiltinPolicy(p)` — replace the policy wholesale.

> Loosening builtin admission can reintroduce code-execution paths (`eval`,
> `source`). Only do so for trusted input.

## Determinism

With the default virtual clock and empty environment, runs are reproducible:
`date`, file mtimes, and `sleep` all operate on virtual time (`sleep` advances the
clock instantly rather than blocking). Pass `WithClock(gosh.SystemClock{})` (or a
`FixedClock`) only when you genuinely need real or pinned wall-clock time.

## Verifying the guarantees

The repository's `hardening/` package drives the **fully assembled** system
through the public API with adversarial scripts (host-exec escapes, FS/symlink
escapes, resource exhaustion, network/SSRF, archive bombs, awk/sed isolation) plus
`FuzzRunScript` and `FuzzInMemoryFSPaths` fuzz targets. Run them:

```sh
go test ./hardening/...
go test ./... -race
```
