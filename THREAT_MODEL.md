# gosh Threat Model

## 1. Purpose and scope

`gosh` is a Go library for running Bash scripts inside an in-process, virtualized environment for AI agents. Its security objective is to make **untrusted script text** useful while preventing it from directly reaching host process execution, the host filesystem, ambient host environment, or unrestricted network egress. This model is grounded in the implementation, especially `shell.go`, `engine.go`, `policy.go`, `fs.go`, `inmemfs.go`, `limits.go`, `network.go`, `commands/*`, `goshfs/*`, and `internal/importcheck`.

`gosh` is a logic and denial-of-service sandbox for scripts. It is **not** an OS sandbox, container, cgroup, seccomp profile, VM, kernel boundary, or protection against a hostile embedding application. The package docs and PRD are explicit that the host integrator is trusted (`PRD.md` E2; `doc.go`; `command.go`). Custom Go `Command` implementations and host-supplied `NetworkPolicy.CredentialTransforms` run as trusted Go code. They can import `os`, `net`, spawn goroutines, ignore limits, or disclose secrets if the host writes them that way; `gosh` confines scripts, not trusted extensions.

The reference shape follows `vercel-labs/just-bash`'s threat-model structure, but the mitigations below are specific to this Go implementation. Unlike `just-bash`, `gosh` does not need JavaScript eval/prototype defenses; its critical escape class is instead accidentally allowing `mvdan.cc/sh` defaults, shell builtins, custom commands, filesystem adapters, or network commands to cross the host boundary (`PRD.md` §§2, 6, 11; `engine.go`).

## 2. Trust boundaries and actors

### Actors

| Actor | Trust | Capability | Goal |
|---|---:|---|---|
| Untrusted script author / AI agent | None | Controls Bash source, argv, stdin-derived strings, expansions, redirections, functions, loops, and command substitutions. | Escape the sandbox, read/write host state, spawn host commands, exfiltrate secrets, or exhaust resources. |
| Malicious data source | None | Controls file contents, stdin, archive members, JSON/YAML/TOML/CSV, HTML, or HTTP responses that scripts process. | Trigger parser/decoder bugs, path traversal, decompression bombs, regex/stream blowups, or credential leaks. |
| Trusted host embedding `gosh` | Trusted | Constructs `Shell`, registers commands, selects FS/network/clock/limits, supplies env/files/stdin and receives output/snapshots. | Provides capabilities intentionally. If malicious or buggy, it can bypass the sandbox by design (`PRD.md` NG4/E2; `command.go`). |
| Trusted command/FS/network extension author | Trusted | Implements Go code behind `Command`, `FileSystem`, or credential transforms. | Part of the TCB; must honor `CommandContext` and documented contracts. |
| Dependency/runtime attacker | Out of runtime scope | Exploits Go runtime, stdlib, `mvdan.cc/sh`, goawk, gojq, YAML/TOML, x/net/html, etc. | Bypass in-process checks or crash/exfiltrate from the host process. Mitigated by dependency discipline, tests, and OS defense in depth, not eliminated. |

### Data flow

```
trusted host
  ├─ config: limits, env, cwd, seed files, FS, clock, commands, NetworkPolicy
  ├─ per-run inputs: script text, argv, stdin
  ▼
gosh.Shell.Run
  ├─ mvdan/sh parser + pre-exec AST validation (`shell.go`, `engine.go`)
  ├─ secure runner: explicit env, VFS handlers, capped stdio, CallHandler, registry-only ExecHandler (`engine.go`)
  ├─ registered commands via capability-scoped CommandContext (`command.go`)
  ├─ virtual FS: InMemoryFS or host-supplied FileSystem (`fs.go`, `inmemfs.go`, `goshfs/goshfs.go`)
  └─ optional network commands gated by NetworkPolicy (`network.go`, `commands/netcmd/netcmd.go`)
  ▼
trusted host receives Result{Stdout, Stderr, ExitCode, Metadata}, typed host error, and optional FS snapshot
```

The script boundary is crossed only through explicit host inputs. Outputs are bounded stdout/stderr, exit status, metadata, and virtual filesystem state (`shell.go`, `engine.go`, `limits.go`). Network is denied unless the host configures policy and registers/uses network-aware commands (`network.go`, `commands/netcmd/netcmd.go`, `std/std.go`).

## 3. Assets to protect

- **Host filesystem and paths**: no direct read/write of real files; script-visible errors should use virtual paths (`engine.go`, `fs.go`, `inmemfs.go`, `goshfs/goshfs.go`, `errors.go`).
- **Host process execution**: no native binary execution, `os/exec`, job control, signals, or builtin bypass (`policy.go`, `engine.go`, `internal/importcheck/importcheck_test.go`).
- **Host network and SSRF targets**: no ambient network; optional egress must enforce method/origin/path/redirect/private-IP policy (`network.go`, `commands/netcmd/netcmd.go`).
- **Secrets and ambient environment**: no `os.Environ` inheritance; credential injection happens host-side and should not be script-readable (`shell.go`, `engine.go`, `commands/netcmd/netcmd.go`).
- **Host CPU, memory, time, and availability**: context cancellation and cooperative governors bound common runaway scripts and data processors (`shell.go`, `engine.go`, `limits.go`, command packages).
- **Determinism and host-state non-disclosure**: default virtual UTC clock and sorted deterministic outputs reduce host time/timezone/order leakage (`clock.go`, `shell.go`, `inmemfs.go`).

## 4. Security requirements: threats, mitigations, and status

| Req | Threat | Concrete mitigation in code | Status |
|---|---|---|---|
| S1 | `mvdan/sh` default runner could inherit host env, filesystem, stdio, or `os/exec`. | `newSecureRunner` sets `interp.Env`, `Dir`, `Params`, `StdIO`, VFS `OpenHandler`/`StatHandler`/`ReadDirHandler2`, `CallHandler`, and registry-only `ExecHandlers` explicitly (`engine.go`). `New` uses secure defaults (`shell.go`). | Enforced. |
| S2 | Dangerous builtins bypass `ExecHandler` and execute before registry policy. | `CallHandler` consults `BuiltinPolicy` for every command; denied builtins are rewritten to NUL-prefixed sentinels and rejected by `execMiddleware` (`engine.go`, `policy.go`). Denied by default: `eval`, `source`, `.`, `exec`, `command`, `builtin`, `enable`, `trap`, `alias`, `unalias`, job-control builtins, `kill`, `history`, `hash`, completion, `times`, `ulimit`, `caller`, `umask`, etc. | Enforced by admission policy; host can weaken with `WithAllowedBuiltins`/custom policy (`shell.go`, `policy.go`). |
| S2a | Unsupported shell features could touch host paths, processes, FIFOs, or job control. | `validateAST` rejects background jobs, coprocs/disown, and process substitution before execution (`engine.go`). | Enforced for implemented checks. Gap: PRD also mentions redirects to special FD/host paths; current AST validation does not visibly inspect redirect targets, relying instead on VFS handlers. |
| S2b | Unknown external commands might fall through to `os/exec`. | `execMiddleware` never calls the next `mvdan/sh` exec handler; it dispatches only `rs.registry` and returns 127 for unknown commands (`engine.go`). `CommandContext.Exec` recurses through the same registry (`command.go`, `engine.go`). | Enforced for shell execution. Trusted custom commands can still do anything in Go. |
| S3 | Script reads/writes host disk by default. | `New` creates `InMemoryFS`; `fsAdapter` routes all interpreter FS operations to the configured `FileSystem` (`shell.go`, `engine.go`, `fs.go`, `inmemfs.go`). | Enforced by default. Host-supplied FS is trusted. |
| S4 | Path traversal or symlink targets escape virtual root/mount. | Shell paths are made absolute/clean with `absFromCtx`, `ResolvePath`, and `cleanAbs`; `InMemoryFS` resolves symlinks inside its root; archive extraction checks `safeArchivePath`, `safeSymlinkTarget`, and rejects writing or hardlinking through pre-existing symlink path components (so a hardlink source cannot follow a symlink out of the `-C` destination); `curl -O` treats the URL-derived remote name as a single basename and refuses decoded separators, NUL, or dot-directory names; `goshfs` validates mount paths, rejects `..`, Windows drive/UNC forms, and cross-mount symlinks/links (`engine.go`, `command.go`, `inmemfs.go`, `commands/archive/archive.go`, `commands/netcmd/netcmd.go`, `goshfs/goshfs.go`). | Enforced for built-in VFS/adapters. Custom FS implementations must honor the `FileSystem` contract (`fs.go`). |
| S5 | Symlink cycles or long chains hang resolution. | `InMemoryFS.resolve` caps symlink hops at 40 and returns an ELOOP-style error (`inmemfs.go`). | Enforced in `InMemoryFS`; custom FS must provide equivalent safety. |
| S6 | Real filesystem adapters accidentally write host disk or follow host symlinks. | Core default has no host backing. `goshfs.NewReadOnlyFS` rejects writes; `OverlayFS` copies writes into an upper FS; `MountableFS` confines paths by prefix and rejects cross-filesystem rename/link (`goshfs/goshfs.go`). | Partly enforced by provided adapters. Discrepancy: PRD says a true `ReadWriteFS` is deferred, but code exposes `NewReadWriteFS` as a pass-through wrapper over any `FileSystem` (`goshfs/goshfs.go`). If the host wraps a real FS backend, that backend is trusted and must be confined. |
| S7 | In-memory files consume unbounded host memory. | `InMemoryFS` enforces `MaxFileBytes` and `MaxTotalFSBytes` on `Write` and `Truncate`; archive extraction reuses these limits/fallback caps (`limits.go`, `inmemfs.go`, `commands/archive/archive.go`). | Enforced for `InMemoryFS` writes and archive extraction. Not a process-wide memory cap. |
| S8 | Infinite or long-running scripts ignore host deadlines. | `Run` accepts `context.Context`; `renderRunError` maps cancellation/deadlines to `CanceledError`; commands call `ctx.Err`/use context-aware interpreters where implemented (`shell.go`, `engine.go`, command packages). | Best-effort/cooperative; cancellation happens at interpreter/command check points. |
| S9 | Runaway scripts execute unlimited commands. | `Governor.countCommand` increments at `CallHandler` and sub-command dispatch; returns `LimitCommands` (`engine.go`, `limits.go`). | Enforced for commands passing through shell/`CommandContext.Exec`. Custom Go code can ignore it. |
| S10 | Infinite loops run forever. | `Governor.countCommand` tracks executions by source offset and enforces `MaxLoopIterations` (`engine.go`, `limits.go`). | Enforced for command-bearing loop bodies; pure expansion/interpreter work is covered by other limits only. |
| S11 | Function recursion overflows stack or consumes CPU. | `MaxCallDepth` exists, but comments state enforcement is best-effort because `mvdan/sh` exposes no function-return hook; recursion is mainly stopped by command/loop limits, and panics are recovered by `runGuarded` (`limits.go`, `shell.go`, `security_test.go`). | Best-effort; no direct call-depth counter found. |
| S12 | Unbounded stdout/stderr exhaust memory or logs. | `cappedWriter` accounts combined stdout/stderr via `Governor.accountOutput`, truncates excess, and surfaces `LimitOutputBytes` after run (`engine.go`, `limits.go`, `shell.go`). | Enforced for engine stdio; custom commands must write through provided writers or `BoundedWrite`. |
| S13 | Stream/regex/data commands process unlimited records. | `Governor.StreamTick` enforces `MaxStreamIterations`; text, data, file, nav/env, awk, and sed commands call it in loops (`limits.go`, `commands/textproc/textproc.go`, `commands/textlang/awk.go`, `commands/textlang/sed.go`, `commands/datacmd/datacmd.go`, `commands/fileops/helpers.go`). | Enforced where commands call `StreamTick`; cooperative for custom commands. |
| S14 | Overall memory growth exhausts host process. | `Limits.MaxMemoryBytes` is defined as advisory; hard enforcement exists for output and VFS file/total bytes, but Go has no per-goroutine/process heap cap in this code (`limits.go`, `inmemfs.go`, `engine.go`). | Best-effort / incomplete. Use OS memory limits for hostile workloads. |
| S14a | Pre-exec/expansion blowups: huge scripts, ASTs, argv, word expansion, glob matches, pipelines, command substitution. | `Run` rejects oversized scripts; `validateAST` caps AST nodes/depth, pipeline length, command-substitution depth; `checkArgvBounds` caps argv bytes and expanded word count — and since globs expand into words, `MaxExpandedWords` also bounds glob match counts (`shell.go`, `engine.go`, `limits.go`). | Enforced. Glob-match counts are bounded via `MaxExpandedWords` rather than a separate knob. |
| S15 | Catastrophic-backtracking ReDoS. | Built-in text commands use Go `regexp`/RE2; sed uses `regexp.Compile`; awk variable validation uses `regexp.MustCompile`; stream caps add a second bound (`commands/textproc/textproc.go`, `commands/textlang/sed.go`, `commands/textlang/awk.go`, `limits.go`). | Enforced for built-in regex users. Third-party parsers remain TCB. |
| S16 | Malformed scripts or interpreter bugs panic/crash host. | Parser errors become `ParseError`; `runGuarded` recovers panics into `InternalError`; `renderRunError` normalizes supported error classes (`shell.go`, `engine.go`, `errors.go`). | Enforced for panics during `Runner.Run`. Panics outside guarded paths or in trusted custom commands may still affect host unless recovered by the host. |
| S17 | Network commands provide ambient internet access. | `NetworkPolicy` zero value is disabled; `curl`/`html2md` check `cc.Network().Enabled()` and return 127-like failure when disabled; `std` notes network commands refuse unless configured (`network.go`, `commands/netcmd/netcmd.go`, `std/std.go`). | Enforced at command runtime. Commands may still be registered but inert when policy is disabled. |
| S18 | Egress to arbitrary origins/paths. | `parseAndValidateURL` accepts only `http`/`https`, exact normalized origin match, and optional path-prefix match unless `DangerouslyAllowFullInternet` is set; when path prefixes are configured, encoded separators (`%2e`/`%2f`/`%5c`) and `..` segments are rejected so a prefix cannot be satisfied via traversal (`commands/netcmd/netcmd.go`, `network.go`). | Enforced when network command is used. Dangerous full-internet flag bypasses origin allow-list by design. |
| S19 | Unsafe HTTP methods mutate services. | `methodAllowed` defaults to GET/HEAD and checks configured methods (`network.go`, `commands/netcmd/netcmd.go`). | Enforced. Host can opt into broader methods. |
| S20 | Redirects bypass allow-list or leak credentials cross-origin. | `doPolicyRequest` disables automatic redirects, revalidates each hop, caps redirect count, and deletes `Authorization` when the origin changes (`commands/netcmd/netcmd.go`). | Partly enforced. Credential transforms run after the cross-origin deletion and can re-add secrets if host code chooses to; transforms are trusted. |
| S21 | Scripts steal or override egress credentials. | `CredentialTransforms` are host-side functions applied at request time after script headers/basic auth; tests show a transform using `Header.Set` overrides a script header (`network.go`, `commands/netcmd/netcmd.go`, `commands/netcmd/netcmd_test.go`). | Enforced only if host transforms are written safely. Transforms are trusted code and can leak/re-add secrets. |
| S22 | SSRF to loopback/private/link-local/cloud metadata or DNS rebinding. | `parseAndValidateURL` rejects literal forbidden IPs, and a custom `DialContext` resolves hostnames, rejects every forbidden resolved IP, and dials the checked IP (defeating DNS rebinding); this is **on by default** whenever the policy is not `DangerouslyAllowFullInternet`. `forbiddenIP` covers loopback/private/link-local/unspecified/multicast plus special-purpose and cloud ranges (CGNAT `100.64/10`, IETF protocol `192.0.0/24`, benchmarking `198.18/15`, 6to4-anycast `192.88.99/24`, reserved `240/4`, etc.) and extracts the embedded IPv4 from NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`) addresses to re-check it. Ambient `HTTP(S)_PROXY` is disabled unconditionally (`Proxy = nil`) so egress and any injected credentials never route through host proxy config, and the dial-time IP check cannot be bypassed by a proxy that reaches the real target. Response size/timeouts are capped by `MaxResponseBytes`, `--max-time`, and context (`commands/netcmd/netcmd.go`). | Enforced, secure-by-default. Reaching private IPs requires an explicit `AllowPrivateIPs` opt-in. |
| S23 | Script inherits host environment/secrets. | `New` seeds only `HOME`; `WithEnv`/`RunEnv` are explicit; `newSecureRunner` passes exactly `rs.envPairs` rather than `os.Environ` (`shell.go`, `engine.go`). | Enforced. Host-provided env is trusted input. |
| S24 | Host wall-clock/timezone leaks and nondeterminism. | Default clock is `VirtualClock` at fixed UTC `Epoch`; `Clock` abstraction and `CommandContext.Clock` direct commands to use injected time; `SystemClock` is opt-in and documented as nondeterministic (`clock.go`, `shell.go`, `command.go`). | Enforced by default for commands that use `Clock`. Custom commands may use real time. |
| S25 | Errors leak host paths, stacks, or addresses. | FS adapter rewrites `fs.PathError` paths to virtual paths; parser uses virtual filename `script`; typed errors avoid stacks (`engine.go`, `shell.go`, `errors.go`). | Mostly enforced for core paths. Trusted custom FS/commands and third-party errors must avoid leaking host details. |
| S26 | Optional runtimes (Python/JS/SQLite/WASM) expand attack surface. | No bundled optional runtimes were found; standard command set contains Go command groups only (`std/std.go`). | N/A currently. If added, treat as new TCB with separate limits. |
| S27 | First-party imports accidentally introduce `os/exec` or raw network. | `internal/importcheck` walks first-party packages and bans direct `os/exec` everywhere and `net` except audited `commands/netcmd` egress package; `os/exec` remains banned even there (`internal/importcheck/doc.go`, `internal/importcheck/importcheck_test.go`). | Enforced by tests, not by compiler in production. Third-party dependencies are out of scope. |

## 5. Specific attack scenarios and mitigations

### 5.1 Arbitrary host command execution

Attack: a script tries `eval`, `source`, `.`, `exec`, `command eval`, `builtin eval`, command substitution, or an unknown command name that might fall through to a real binary.

Mitigation: dangerous builtins are denied at `CallHandler` before `mvdan/sh` can run them (`policy.go`, `engine.go`). `command` and `builtin` are explicitly denied because they can dispatch builtins directly and bypass admission (`policy.go`; `security_test.go`). Command substitution is allowed as shell syntax, but commands inside it still traverse the same `CallHandler` and registry-only `ExecHandler` (`engine.go`). Unknown external commands return 127 and the middleware never calls `mvdan/sh`'s next/default exec handler (`engine.go`). First-party code is tested not to import `os/exec` (`internal/importcheck/importcheck_test.go`).

Residual caveat: a trusted custom `Command` can call `os/exec`; the sandbox does not and cannot prevent arbitrary trusted Go code from doing so (`PRD.md` E2; `command.go`; `doc.go`).

### 5.2 Path traversal and symlink escape on the VFS

Attack: a script uses `../../etc/passwd`, absolute host-looking paths, symlink chains, hard links, mounts, or archive entries to escape the virtual root.

Mitigation: the interpreter resolves relative paths against virtual cwd and cleans them before calling the `FileSystem` (`engine.go`). `InMemoryFS.cleanAbs` collapses traversal at `/`, and symlink resolution converts absolute and relative symlink targets back into cleaned virtual paths with a hop limit (`inmemfs.go`). `goshfs` adapters reject non-clean paths, `..`, Windows drive paths, UNC paths, cross-mount links/renames, and cross-mount absolute symlink targets (`goshfs/goshfs.go`). Archive extraction separately rejects unsafe names, absolute paths, backslashes, Windows drive paths, symlink targets outside destination, and writes through pre-existing symlinks (`commands/archive/archive.go`).

Residual caveat: `FileSystem` is an interface; a host-provided implementation that follows host symlinks or maps `/` to a sensitive real root is trusted and can break confinement (`fs.go`).

### 5.3 Decompression bombs and archive traversal

Attack: a tiny gzip/tar expands to enormous data, contains many entries, or writes `../outside`, `/absolute`, `C:\...`, symlink-to-outside, or hard-link-to-outside paths.

Mitigation: gzip decompression and tar extraction use `readAllLimited`/`copyLimited` with per-entry and total caps derived from `Limits` or conservative fallbacks; tar caps entry count; extraction checks paths through `invalidArchivePath`, `safeArchivePath`, `safeSymlinkTarget`, and `rejectExistingSymlinkPath` (`commands/archive/archive.go`). Writes then go through the governed VFS, which enforces per-file/total caps (`inmemfs.go`).

Residual caveat: archive creation can buffer the archive in memory (`commands/archive/archive.go`); overall process heap is not kernel-limited by `gosh`.

### 5.4 SSRF and cloud metadata through `curl`

Attack: a script issues `curl http://169.254.169.254/`, targets loopback/private services, relies on DNS rebinding, or follows a redirect to a forbidden origin.

Mitigation: network commands fail when `NetworkPolicy.Enabled()` is false (`network.go`, `commands/netcmd/netcmd.go`). URL validation restricts scheme, method, exact origin, and optional path prefixes; redirects are manually handled and each hop is revalidated; max redirects and response bytes are capped (`commands/netcmd/netcmd.go`). By default (unless `DangerouslyAllowFullInternet`), literal private IPs are rejected and the custom dialer resolves all IPs, rejects private/loopback/link-local/unspecified/multicast/cloud-metadata and special-purpose addresses (CGNAT, IETF-protocol, benchmarking, 6to4-anycast, reserved ranges, and the IPv4 embedded in NAT64 well-known-prefix/6to4 addresses), then dials a checked IP rather than letting the transport re-resolve unchecked. Ambient `HTTP(S)_PROXY` is disabled unconditionally (`Proxy = nil`), so egress and any `CredentialTransform`-injected credentials are never routed through host-environment proxy config, and a proxy cannot reach an internal target on the script's behalf after the dial-time check passes for the proxy itself (`commands/netcmd/netcmd.go`).

Residual caveat: the embedded-IPv4 recheck only recognizes the NAT64 well-known prefix (`64:ff9b::/96`) and 6to4 (`2002::/16`); an operator who routes a *network-specific* RFC 6052 NAT64 prefix from ordinary global IPv6 space and allows it to translate to private IPv4 could still smuggle an internal target. Hosts in such environments should keep `AllowPrivateIPs` off and avoid allow-listing provider-specific NAT64 origins.

Secure-by-default: private-IP denial is automatic once network is enabled. Hosts that genuinely need to reach an internal/loopback service must explicitly set `AllowPrivateIPs: true`; merely configuring `AllowedOrigins` keeps SSRF protection on (`network.go`, `commands/netcmd/netcmd.go`).

### 5.5 Credential exfiltration via request headers and redirects

Attack: a script supplies its own `Authorization`/token header, tries to read host credentials from env, or uses redirects to forward credentials to another origin.

Mitigation: host credentials should be injected only through `CredentialTransforms`, after script-supplied headers are copied; a transform using `Header.Set` overrides a script-supplied value (`commands/netcmd/netcmd.go`, `commands/netcmd/netcmd_test.go`). Host env is not inherited (`shell.go`, `engine.go`). On cross-origin redirect, `Authorization` is removed before transforms run (`commands/netcmd/netcmd.go`).

Residual caveat: credential transforms are trusted Go callbacks. If a transform uses `Header.Add`, writes secrets to logs, or re-adds credentials after a cross-origin redirect, `gosh` cannot prevent it (`network.go`, `commands/netcmd/netcmd.go`).

### 5.6 Resource exhaustion and infinite loops

Attack: `while true`, recursive functions, huge output, huge scripts, nested ASTs, long pipelines, deep command substitutions, massive VFS writes, or streaming data processors.

Mitigation: command and loop counts are enforced in `Governor.countCommand`; output is capped by `cappedWriter`; script size and AST shape are rejected before execution; argv/expanded word counts are bounded per command; VFS writes enforce per-file and total FS caps; stream commands call `StreamTick`; context cancellation is propagated (`shell.go`, `engine.go`, `limits.go`, `inmemfs.go`, command packages).

Residual caveat: `MaxCallDepth` and `MaxMemoryBytes` are best-effort rather than hard guarantees in the current code (`limits.go`). Run `gosh` inside OS-level CPU/memory limits for hostile multi-tenant use.

### 5.7 Nondeterminism and time leakage

Attack: a script observes host wall-clock time, timezone, or real sleeping behavior to infer host state or make tests flaky.

Mitigation: default `VirtualClock` starts at fixed UTC `Epoch` and advances only through virtual `Sleep`; `SystemClock` is opt-in and documented as leaking real time (`clock.go`, `shell.go`). Commands are expected to use `CommandContext.Clock` (`command.go`).

Residual caveat: trusted custom commands can call `time.Now` directly.

### 5.8 AWK `system()`, pipes, `getline`, and file reads/writes

Attack: an AWK program calls `system("sh")`, uses command pipes, or reads/writes files through goawk outside the VFS.

Mitigation: `commands/textlang/awk.go` pre-reads file operands through `cc.FS()`, passes no goawk file args, clears AWK environment, and sets `NoExec`, `NoFileReads`, and `NoFileWrites` in `goawk/interp.Config`. Record processing is counted through `StreamTick`.

Residual caveat: goawk itself is a third-party dependency in the TCB.

### 5.9 Importing `os/exec` or raw `net`

Attack: a future first-party command accidentally imports `os/exec` or raw `net` and exposes host execution/network outside the audited boundary.

Mitigation: `internal/importcheck` tests every first-party package and rejects `os/exec` everywhere and `net` everywhere except `commands/netcmd`, the audited egress boundary (`internal/importcheck/doc.go`, `internal/importcheck/importcheck_test.go`).

Residual caveat: this is a test-time guard, not a Go compiler rule; it also does not constrain third-party dependencies or external custom commands.

### 5.10 Host directory mounts via `goshfs.NewHostReadOnlyFS` (overlay-over-cwd)

Attack: an operator mounts a real host directory as the lower layer of an overlay (the `gosh --root DIR` CLI flag, or `goshfs.NewHostReadOnlyFS`), and a script tries to escape the mounted subtree to read arbitrary host files via `..`, symlinks, or absolute paths.

Mitigation: `NewHostReadOnlyFS` canonicalizes `root` with `filepath.EvalSymlinks` once, then for every access maps the virtual path under `root`, fully resolves symlinks, and rejects (as `fs.ErrNotExist`) any path whose resolved real location escapes `root` (`filepath.Rel`-based containment). It is read-only: every mutation and every write-flagged `Open` returns `fs.ErrPermission`, and it is additionally wrapped in `NewReadOnlyFS` for defense in depth. Composed under `OverlayFS`, all script writes are captured in a discarded in-memory upper layer, so host disk is never modified (`goshfs/hostfs.go`, `cmd/gosh/run.go`).

Residual caveat: the adapter resolves-then-opens in two steps, so it assumes the mounted tree is **not concurrently mutated by an untrusted host process** during execution (the sandboxed script itself can never write host disk, so it cannot win this race). It also cannot detect **hardlinks** inside `root` that point to inodes outside `root`, and directory listings (`ReadDir`/`Lstat`) reveal the *names* of escaping symlinks even though their contents stay unreadable. Operators must not mount directories writable by untrusted host processes or containing attacker-controlled hardlinks (`goshfs/hostfs.go`).

## 6. Residual risks and assumptions

1. **In-process execution is not kernel isolation.** A Go runtime bug, panic outside guarded paths, extreme allocation, scheduler starvation, or unsafe dependency bug can affect the host process. Use containers, seccomp, cgroups, macOS sandboxing, gVisor, Firecracker, or another OS boundary for defense in depth and hostile multi-tenant workloads (`PRD.md` NG5/S14/S6.8; `limits.go`).
2. **Trusted extensions are fully trusted.** Custom `Command`s, custom `FileSystem`s, and credential transforms can bypass script confinement. Treat them as part of the TCB, review them like privileged code, and prefer `CommandContext` capabilities (`PRD.md` E2; `command.go`; `fs.go`; `network.go`).
3. **Memory limits are best-effort.** `MaxFileBytes`, `MaxTotalFSBytes`, and `MaxOutputBytes` are concrete, but `MaxMemoryBytes` is advisory and not a hard heap limit. Some commands buffer whole inputs/archives/responses within configured or fallback caps (`limits.go`, `inmemfs.go`, `commands/archive/archive.go`, `commands/netcmd/netcmd.go`).
4. **Call depth is best-effort.** The code documents that `MaxCallDepth` is not directly enforced because the interpreter lacks a function-return hook; recursion relies mostly on command/loop limits and panic recovery (`limits.go`, `shell.go`).
5. **Best-effort resource bounds.** `MaxCallDepth` and `MaxMemoryBytes` are best-effort (mvdan/sh exposes no return-depth hook; stack-overflow is recovered into an `InternalError`). `goshfs` also exposes a `NewReadWriteFS` pass-through that the PRD originally staged for later; it is a thin wrapper and safe. Run under OS-level isolation for hostile multi-tenant use (`limits.go`, `goshfs/goshfs.go`).
6. **Dependency and runtime vulnerabilities remain.** The TCB includes Go, `mvdan.cc/sh`, goawk, gojq, YAML/TOML parsers, `golang.org/x/net/html`, compression/archive parsers, and the standard library. Keep dependencies patched, run `go test`, `govulncheck`, fuzzing where available, and review parser/decoder changes (`go.mod`, `commands/datacmd/datacmd.go`, `commands/textlang/awk.go`, `commands/netcmd/netcmd.go`, `commands/archive/archive.go`).
7. **Network policy is only as safe as host configuration.** `DangerouslyAllowFullInternet` disables the origin allow-list and the SSRF defense; broad allowed origins/methods/path prefixes or an explicit `AllowPrivateIPs` opt-in weaken SSRF defenses (`network.go`, `commands/netcmd/netcmd.go`).
8. **Side channels are out of scope.** Timing, cache, Spectre-class, memory-pressure, and same-process observation side channels are not eliminated by an in-process interpreter.
9. **Script-visible error hygiene depends on all trusted code.** Core errors are virtualized and typed, but custom commands/FS implementations and third-party libraries may include host details unless wrapped carefully (`engine.go`, `errors.go`).
10. **Host directory mounts are operator-gated and confined but not race-proof.** `goshfs.NewHostReadOnlyFS` (and `gosh --root`) confine reads to a symlink-resolved root and discard all writes into an in-memory overlay, but assume the mounted tree is not concurrently mutated by untrusted host processes and contains no attacker-controlled hardlinks escaping the root (`goshfs/hostfs.go`; §5.10).

## 7. Reporting security issues

Please report suspected sandbox escapes, host filesystem/process/network access, SSRF bypasses, credential leaks, decompression/resource-exhaustion bypasses, or dependency vulnerabilities privately to the repository owner/maintainer rather than opening a public proof-of-concept issue. Include the `gosh` version/commit, a minimal script or input, host configuration (`WithCommands`, `WithFS`, `WithNetwork`, limits), observed behavior, and expected boundary.
