# gosh — Feature Checklists

Phased, checkable task list backing [`PRD.md`](./PRD.md). IDs cross-reference the
PRD's requirement codes (`S*` security, `F*` shell, `D*` DX, `E*` extensibility).

Legend: `[ ]` todo · `[~]` in progress · `[x]` done · 🔒 release-blocking (MUST)

---

## Phase 0 — Spike + mvdan seam audit (M0)

- [x] Initialise Go module, CI skeleton (`go vet`, `go test`, `govulncheck`)
- [x] Add `mvdan.cc/sh/v3` dependency; parse a script to AST
- [x] 🔒 S1 `newSecureRunner`: construct `interp.Runner` with **every** option set
      explicitly; unit test asserts no fallback to mvdan defaults (env/FS/exec)
- [x] 🔒 S2 `CallHandler`/admission layer: allow/deny **every** command incl.
      builtins (`source`,`eval`,`trap`,`read`,`command`,`type`,…); deny-by-default
- [x] 🔒 S2a AST validation pass rejects unsupported constructs (`&`, `<(...)`,
      coproc, special-FD redirects) → typed `UnsupportedError`
- [x] 🔒 Minimal in-memory VFS behind `OpenHandler`/`StatHandler`/`ReadDirHandler2`
- [x] Implement `echo`, `cat`; prove pipe + `>` redirection work
- [x] 🔒 **mvdan seam audit**: enumerate every interp path that can reach
      OS/env/time/process (builtins, `source`, glob, tilde, command-sub, subshell,
      redirect, here-doc temp, process-sub, default env/dir/stdio) → map each to a
      gosh override or explicit rejection
- [x] 🔒 **Escape corpus fails closed** (poison handlers that error on any host
      FS/exec/net): host env probe, `/etc/passwd`, `/dev/*`, glob real cwd,
      `source`, command substitution, builtin bypass, background `&`,
      process substitution, symlink traversal, parser panic, cancellation

---

## Phase 1 — Secure core (M1) 🔒

### Isolation invariants
- [x] 🔒 S1 `newSecureRunner` fail-closed construction (no mvdan default leaks)
- [x] 🔒 S2 builtin-aware admission policy; unknown external → `127`; disabled
      builtins rejected even when `interp.IsBuiltin` is true
- [x] 🔒 S2a AST rejection of unsupported constructs (per-construct red-team test)
- [x] 🔒 S3 default FS is pure in-memory, no host backing
- [x] 🔒 S27 CI import-allow-list bans `os`/`net`/`os/exec` in interp+cmd pkgs
- [x] 🔒 runtime poison-handler tests wired into CI against the escape corpus

### Filesystem safety
- [x] 🔒 S4 Path confinement: normalise `..`/absolute, re-check against root;
      POSIX `path.Clean` semantics; reject Windows drive/UNC forms
- [x] 🔒 S5 Symlink hop limit + cycle detection; don't follow host symlinks
- [x] S7 Per-file and total VFS size caps
- [x] VFS feature set: files, dirs, symlinks, hardlinks, perms, mtime
- [x] Path-traversal & symlink-escape test corpus

### Resource governors
- [x] 🔒 S8 Context deadline checked at every statement boundary + builtin loops
- [x] 🔒 S9 Max command count
- [x] 🔒 S10 Max loop iterations (`for`/`while`/`until`)
- [x] 🔒 S11 Max recursion / call depth
- [x] 🔒 S12 Max cumulative output bytes (+ truncation signal)
- [x] S13 Max iterations in `awk`/`sed`/`grep`
- [x] 🔒 S14a Pre-exec/expansion bounds: script bytes, AST node count+depth,
      argv/env size, expanded word count/bytes, glob matches, dir entries scanned,
      pipeline length, command-substitution depth
- [x] S14 Best-effort memory growth guard (documented as best-effort)
- [x] All limits configurable with safe defaults; error names the limit hit

### Parser / regex safety
- [x] 🔒 S15 All builtins use `regexp` (RE2); no backtracking features
- [x] 🔒 S16 Fuzz parser+interp for panics; parse errors are typed, never panic
- [x] `go-fuzz`/native fuzz targets in CI

### Info-disclosure hygiene
- [x] 🔒 S23 No host env inheritance
- [x] 🔒 S24 Virtual/UTC clock default; `WithClock` injection; `TZ` opt-in;
      `date`/`time`/`sleep` read the injected clock
- [x] 🔒 S25 Single script-visible error renderer; strips host paths/stacks from
      `os.PathError`/parser/archive/JSON/YAML errors; tested with poisoned paths
- [x] Typed host errors: `LimitError`, `ParseError`, `UnsupportedError`, `CanceledError`

---

## Phase 2 — Command breadth (M2)

### Shell language (`mvdan/sh`, validated/conformance-tested)
- [x] F1 pipes, redirections, heredocs/here-strings
- [x] F2 `;` `&&` `||`, `( )` `{ }`
- [x] F3 variables, parameter expansion, positional params
- [x] F4 command substitution, arithmetic
- [x] F5 globbing (document `globstar`/`extglob` support)
- [x] F6 `if`/`case`/`test`/`[ ]`/`[[ ]]`
- [x] F7 loops + `break`/`continue` (governed)
- [x] F8 functions, `local`, `return`
- [x] F9 shell builtins — **explicit allow-list per builtin** (`cd`,`pwd`,`export`,
      `set -e`,`read`,…); `source`/`trap`/`command`/`builtin`/`eval`/aliases are
      deny-by-default and each enabled only with a test (S2)
- [x] F10 exit codes, `$?`, `set -o pipefail`
- [x] 🔒 F11 cooperative cancellation → typed error + non-zero exit
- [x] 🔒 Reject (not just document) out-of-scope: `&`, job control, process
      substitution, signals (S2a)

### Command library — v1 "agent MVP" (pure Go, each with `--help` + conformance test)
- [x] File ops: `cat cp mv rm rmdir mkdir ls ln readlink stat touch tree file`
- [x] Text: `grep egrep fgrep cut tr sort uniq wc head tail tac rev nl paste`
- [x] Text: `printf diff strings xargs`
- [x] Hashing/encoding: `base64 md5sum sha1sum sha256sum`
- [x] Data: `jq` (JSON) — subset or audited lib *(OQ3)*
- [x] Nav/env: `basename dirname find(no -exec) du env printenv pwd cd tee`
- [x] Shell utils: `date seq expr sleep(virtual) timeout whoami hostname help`

### Command library — deferred to M5 / gated modules
- [x] `awk`, `sed` full-parity (iteration-capped, S13) — own milestone
- [x] `yq` (YAML/TOML), CSV tool *(OQ3)*; text extras `join comm column fold expand unexpand od split`
- [x] archives (`gzip`/`tar`) and network (`curl`) — see Phase 5

### DX API
- [x] D1 `gosh.New()` secure-defaults happy path (~3 lines)
- [x] D2 `Result{Stdout,Stderr,ExitCode,Metadata}` vs host `error`
- [x] D3 functional options (`WithFiles/WithEnv/WithLimits/WithFS/WithNetwork/WithCommands/WithClock`)
- [x] D4 per-run overrides (env, stdin, args) without instance mutation
- [x] D5 FS persistence explicit: default persistent + `Snapshot()`/`Reset()` +
      `WithEphemeralFS`; cross-task bleed documented
- [x] D6 `io.Reader`/`io.Writer` streaming I/O (bounded)
- [x] D7 typed errors via `errors.As`
- [x] D8 `context` on every entry point
- [x] 🔒 D9 concurrency contract decided + `-race` tested (not "TBD") *(OQ2)*

---

## Phase 3 — Extensibility (M3)

- [x] E1 public `Command` interface + `CommandContext` (caps-scoped)
- [x] E1 `gosh.CommandFunc(name, fn)` convenience helper
- [x] E2 `WithCommands(...)`; custom cmds compose in pipes/redirects
- [x] 🔒 E2 docs+threat-model state custom commands are **trusted Go code** (not
      sandboxed); wrappers enforce bounded writers / scoped FS / governed `Exec`
- [x] E3 public `FileSystem` interface
- [x] E3 adapters: `InMemoryFS`, `ReadOnlyFS`, `OverlayFS` (COW) — **no `ReadWriteFS` in v1**
- [x] E3 `MountableFS` (compose backends at mount points, cross-mount copy)
- [x] 🔒 S6 real-FS adapters off by default; POSIX path semantics; reject UNC/drive;
      no host-symlink follow
- [x] E4 host capability/tool bridge via `CommandContext` (no globals)
- [x] `examples/`: custom command, mounted RO knowledge base, overlay-over-cwd

---

## Phase 4 — Agent surfaces (M4)

- [x] CLI binary: `-c <script>`, script file, stdin pipe
- [x] CLI `--json` structured output `{stdout,stderr,exitCode}`
- [x] CLI overlay-over-cwd (reads real, writes in-memory, discarded)
- [x] CLI flags: `--root`, `--cwd`, `-e/--errexit`, `--no-network`
- [x] MCP / agent-tool adapter (wrap `Run` as a tool)
- [x] `AGENTS.md` model-facing usage guidance
- [x] 🔒 `THREAT_MODEL.md` (actors, boundaries, attack-surface table, residuals)
- [x] README quick start + defaults table (D11)
- [x] >90% GoDoc coverage on exported symbols (D10)

---

## Phase 5 — Network, archives, hardening → 1.0 (M5)

### Network egress (off by default) 🔒
- [x] 🔒 S17 `curl`/HTTP commands exist only when network configured
- [x] 🔒 S18 allow-list: exact origin + path prefix
- [x] 🔒 S19 method allow-list (default `GET`,`HEAD`)
- [x] 🔒 S20 re-validate redirects per hop; strip credentials on cross-origin redirect
- [x] 🔒 S21 host-side credential injection; overrides same-named user headers
- [x] 🔒 S22 SSRF: deny private/loopback/link-local + metadata IP (169.254.169.254);
      DNS-rebinding defense (pin/re-resolve+recheck); response-byte + timeout caps;
      loud warning on "full access"
- [x] HTML→text/markdown helper command

### Archives / compression (off or bomb-guarded) 🔒
- [x] `gzip`/`gunzip`/`zcat`, `tar`
- [x] 🔒 decompression-bomb guards: `io.LimitReader`, per-entry + total size caps
- [x] 🔒 extraction path confinement (zip-slip / traversal) — reuse S4

### Hardening & release
- [x] Differential tests vs real GNU coreutils where feasible
- [x] Red-team escape suite (FS escape, exec fallthrough, DoS, info-leak)
- [x] `govulncheck` + fuzz + import-allow-list green in CI
- [x] All 🔒 S-requirements covered by tests
- [x] Performance budget verified (sub-ms construction, no cold start)
- [ ] License chosen (OQ6); semver **v1.0.0** — *pending repository owner: a license is a
      legal/ownership decision and the `v1.0.0` tag is a release action, so neither is
      imposed automatically. Everything else in this checklist is implemented, tested,
      and documented; choose a `LICENSE` and tag `v1.0.0` to close this item.*

---

## Post-1.0 backlog

- [ ] S26 opt-in WASM runtimes (Python/JS/SQLite via `wazero`) — isolated, capped
- [ ] E5 AST transform/inspection hooks (instrument, extract commands, policy rewrite)
- [ ] `ReadWriteFS` (host-disk writes) — dedicated symlink/TOCTOU/UNC-safe design
- [ ] Vercel-Sandbox-compatible convenience API surface
- [ ] Resolve OQ4 (memory fidelity), OQ5 (glob ordering) — OQ1 resolved in M0
