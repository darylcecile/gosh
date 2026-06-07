# gosh — Feature Checklists

Phased, checkable task list backing [`PRD.md`](./PRD.md). IDs cross-reference the
PRD's requirement codes (`S*` security, `F*` shell, `D*` DX, `E*` extensibility).

Legend: `[ ]` todo · `[~]` in progress · `[x]` done · 🔒 release-blocking (MUST)

---

## Phase 0 — Spike + mvdan seam audit (M0)

- [ ] Initialise Go module, CI skeleton (`go vet`, `go test`, `govulncheck`)
- [ ] Add `mvdan.cc/sh/v3` dependency; parse a script to AST
- [ ] 🔒 S1 `newSecureRunner`: construct `interp.Runner` with **every** option set
      explicitly; unit test asserts no fallback to mvdan defaults (env/FS/exec)
- [ ] 🔒 S2 `CallHandler`/admission layer: allow/deny **every** command incl.
      builtins (`source`,`eval`,`trap`,`read`,`command`,`type`,…); deny-by-default
- [ ] 🔒 S2a AST validation pass rejects unsupported constructs (`&`, `<(...)`,
      coproc, special-FD redirects) → typed `UnsupportedError`
- [ ] 🔒 Minimal in-memory VFS behind `OpenHandler`/`StatHandler`/`ReadDirHandler2`
- [ ] Implement `echo`, `cat`; prove pipe + `>` redirection work
- [ ] 🔒 **mvdan seam audit**: enumerate every interp path that can reach
      OS/env/time/process (builtins, `source`, glob, tilde, command-sub, subshell,
      redirect, here-doc temp, process-sub, default env/dir/stdio) → map each to a
      gosh override or explicit rejection
- [ ] 🔒 **Escape corpus fails closed** (poison handlers that error on any host
      FS/exec/net): host env probe, `/etc/passwd`, `/dev/*`, glob real cwd,
      `source`, command substitution, builtin bypass, background `&`,
      process substitution, symlink traversal, parser panic, cancellation

---

## Phase 1 — Secure core (M1) 🔒

### Isolation invariants
- [ ] 🔒 S1 `newSecureRunner` fail-closed construction (no mvdan default leaks)
- [ ] 🔒 S2 builtin-aware admission policy; unknown external → `127`; disabled
      builtins rejected even when `interp.IsBuiltin` is true
- [ ] 🔒 S2a AST rejection of unsupported constructs (per-construct red-team test)
- [ ] 🔒 S3 default FS is pure in-memory, no host backing
- [ ] 🔒 S27 CI import-allow-list bans `os`/`net`/`os/exec` in interp+cmd pkgs
- [ ] 🔒 runtime poison-handler tests wired into CI against the escape corpus

### Filesystem safety
- [ ] 🔒 S4 Path confinement: normalise `..`/absolute, re-check against root;
      POSIX `path.Clean` semantics; reject Windows drive/UNC forms
- [ ] 🔒 S5 Symlink hop limit + cycle detection; don't follow host symlinks
- [ ] S7 Per-file and total VFS size caps
- [ ] VFS feature set: files, dirs, symlinks, hardlinks, perms, mtime
- [ ] Path-traversal & symlink-escape test corpus

### Resource governors
- [ ] 🔒 S8 Context deadline checked at every statement boundary + builtin loops
- [ ] 🔒 S9 Max command count
- [ ] 🔒 S10 Max loop iterations (`for`/`while`/`until`)
- [ ] 🔒 S11 Max recursion / call depth
- [ ] 🔒 S12 Max cumulative output bytes (+ truncation signal)
- [ ] S13 Max iterations in `awk`/`sed`/`grep`
- [ ] 🔒 S14a Pre-exec/expansion bounds: script bytes, AST node count+depth,
      argv/env size, expanded word count/bytes, glob matches, dir entries scanned,
      pipeline length, command-substitution depth
- [ ] S14 Best-effort memory growth guard (documented as best-effort)
- [ ] All limits configurable with safe defaults; error names the limit hit

### Parser / regex safety
- [ ] 🔒 S15 All builtins use `regexp` (RE2); no backtracking features
- [ ] 🔒 S16 Fuzz parser+interp for panics; parse errors are typed, never panic
- [ ] `go-fuzz`/native fuzz targets in CI

### Info-disclosure hygiene
- [ ] 🔒 S23 No host env inheritance
- [ ] 🔒 S24 Virtual/UTC clock default; `WithClock` injection; `TZ` opt-in;
      `date`/`time`/`sleep` read the injected clock
- [ ] 🔒 S25 Single script-visible error renderer; strips host paths/stacks from
      `os.PathError`/parser/archive/JSON/YAML errors; tested with poisoned paths
- [ ] Typed host errors: `LimitError`, `ParseError`, `UnsupportedError`, `CanceledError`

---

## Phase 2 — Command breadth (M2)

### Shell language (`mvdan/sh`, validated/conformance-tested)
- [ ] F1 pipes, redirections, heredocs/here-strings
- [ ] F2 `;` `&&` `||`, `( )` `{ }`
- [ ] F3 variables, parameter expansion, positional params
- [ ] F4 command substitution, arithmetic
- [ ] F5 globbing (document `globstar`/`extglob` support)
- [ ] F6 `if`/`case`/`test`/`[ ]`/`[[ ]]`
- [ ] F7 loops + `break`/`continue` (governed)
- [ ] F8 functions, `local`, `return`
- [ ] F9 shell builtins — **explicit allow-list per builtin** (`cd`,`pwd`,`export`,
      `set -e`,`read`,…); `source`/`trap`/`command`/`builtin`/`eval`/aliases are
      deny-by-default and each enabled only with a test (S2)
- [ ] F10 exit codes, `$?`, `set -o pipefail`
- [ ] 🔒 F11 cooperative cancellation → typed error + non-zero exit
- [ ] 🔒 Reject (not just document) out-of-scope: `&`, job control, process
      substitution, signals (S2a)

### Command library — v1 "agent MVP" (pure Go, each with `--help` + conformance test)
- [ ] File ops: `cat cp mv rm rmdir mkdir ls ln readlink stat touch tree file`
- [ ] Text: `grep egrep fgrep cut tr sort uniq wc head tail tac rev nl paste`
- [ ] Text: `printf diff strings xargs`
- [ ] Hashing/encoding: `base64 md5sum sha1sum sha256sum`
- [ ] Data: `jq` (JSON) — subset or audited lib *(OQ3)*
- [ ] Nav/env: `basename dirname find(no -exec) du env printenv pwd cd tee`
- [ ] Shell utils: `date seq expr sleep(virtual) timeout whoami hostname help`

### Command library — deferred to M5 / gated modules
- [ ] `awk`, `sed` full-parity (iteration-capped, S13) — own milestone
- [ ] `yq` (YAML/TOML), CSV tool *(OQ3)*; text extras `join comm column fold expand unexpand od split`
- [ ] archives (`gzip`/`tar`) and network (`curl`) — see Phase 5

### DX API
- [ ] D1 `gosh.New()` secure-defaults happy path (~3 lines)
- [ ] D2 `Result{Stdout,Stderr,ExitCode,Metadata}` vs host `error`
- [ ] D3 functional options (`WithFiles/WithEnv/WithLimits/WithFS/WithNetwork/WithCommands/WithClock`)
- [ ] D4 per-run overrides (env, stdin, args) without instance mutation
- [ ] D5 FS persistence explicit: default persistent + `Snapshot()`/`Reset()` +
      `WithEphemeralFS`; cross-task bleed documented
- [ ] D6 `io.Reader`/`io.Writer` streaming I/O (bounded)
- [ ] D7 typed errors via `errors.As`
- [ ] D8 `context` on every entry point
- [ ] 🔒 D9 concurrency contract decided + `-race` tested (not "TBD") *(OQ2)*

---

## Phase 3 — Extensibility (M3)

- [ ] E1 public `Command` interface + `CommandContext` (caps-scoped)
- [ ] E1 `gosh.CommandFunc(name, fn)` convenience helper
- [ ] E2 `WithCommands(...)`; custom cmds compose in pipes/redirects
- [ ] 🔒 E2 docs+threat-model state custom commands are **trusted Go code** (not
      sandboxed); wrappers enforce bounded writers / scoped FS / governed `Exec`
- [ ] E3 public `FileSystem` interface
- [ ] E3 adapters: `InMemoryFS`, `ReadOnlyFS`, `OverlayFS` (COW) — **no `ReadWriteFS` in v1**
- [ ] E3 `MountableFS` (compose backends at mount points, cross-mount copy)
- [ ] 🔒 S6 real-FS adapters off by default; POSIX path semantics; reject UNC/drive;
      no host-symlink follow
- [ ] E4 host capability/tool bridge via `CommandContext` (no globals)
- [ ] `examples/`: custom command, mounted RO knowledge base, overlay-over-cwd

---

## Phase 4 — Agent surfaces (M4)

- [ ] CLI binary: `-c <script>`, script file, stdin pipe
- [ ] CLI `--json` structured output `{stdout,stderr,exitCode}`
- [ ] CLI overlay-over-cwd (reads real, writes in-memory, discarded)
- [ ] CLI flags: `--root`, `--cwd`, `-e/--errexit`, `--no-network`
- [ ] MCP / agent-tool adapter (wrap `Run` as a tool)
- [ ] `AGENTS.md` model-facing usage guidance
- [ ] 🔒 `THREAT_MODEL.md` (actors, boundaries, attack-surface table, residuals)
- [ ] README quick start + defaults table (D11)
- [ ] >90% GoDoc coverage on exported symbols (D10)

---

## Phase 5 — Network, archives, hardening → 1.0 (M5)

### Network egress (off by default) 🔒
- [ ] 🔒 S17 `curl`/HTTP commands exist only when network configured
- [ ] 🔒 S18 allow-list: exact origin + path prefix
- [ ] 🔒 S19 method allow-list (default `GET`,`HEAD`)
- [ ] 🔒 S20 re-validate redirects per hop; strip credentials on cross-origin redirect
- [ ] 🔒 S21 host-side credential injection; overrides same-named user headers
- [ ] 🔒 S22 SSRF: deny private/loopback/link-local + metadata IP (169.254.169.254);
      DNS-rebinding defense (pin/re-resolve+recheck); response-byte + timeout caps;
      loud warning on "full access"
- [ ] HTML→text/markdown helper command

### Archives / compression (off or bomb-guarded) 🔒
- [ ] `gzip`/`gunzip`/`zcat`, `tar`
- [ ] 🔒 decompression-bomb guards: `io.LimitReader`, per-entry + total size caps
- [ ] 🔒 extraction path confinement (zip-slip / traversal) — reuse S4

### Hardening & release
- [ ] Differential tests vs real GNU coreutils where feasible
- [ ] Red-team escape suite (FS escape, exec fallthrough, DoS, info-leak)
- [ ] `govulncheck` + fuzz + import-allow-list green in CI
- [ ] All 🔒 S-requirements covered by tests
- [ ] Performance budget verified (sub-ms construction, no cold start)
- [ ] License chosen (OQ6); semver **v1.0.0**

---

## Post-1.0 backlog

- [ ] S26 opt-in WASM runtimes (Python/JS/SQLite via `wazero`) — isolated, capped
- [ ] E5 AST transform/inspection hooks (instrument, extract commands, policy rewrite)
- [ ] `ReadWriteFS` (host-disk writes) — dedicated symlink/TOCTOU/UNC-safe design
- [ ] Vercel-Sandbox-compatible convenience API surface
- [ ] Resolve OQ4 (memory fidelity), OQ5 (glob ordering) — OQ1 resolved in M0
