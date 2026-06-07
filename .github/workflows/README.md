# GitHub Actions for gosh

This directory contains four pieces of automation.

## `ci.yml` — continuous integration

`go vet`, `go test -race`, import-discipline, fuzz smoke, and `govulncheck` on
every push to `main` and every pull request. See the file for details.

## `release.yml` — automated releases

Runs on every push to `main` (and via manual `workflow_dispatch`). It reads the
semver string from the repo-root [`VERSION`](../../VERSION) file, runs
`go build ./...` and `go test ./...` as a release gate (a broken build never
ships), and then — **only if a `v<VERSION>` tag does not already exist** — it:

1. cross-compiles the `gosh` CLI for `linux/{amd64,arm64}`,
   `darwin/{amd64,arm64}`, and `windows/amd64` (the version string is baked in
   via `-ldflags -X main.version`),
2. packages each binary (`.tar.gz`, or `.zip` for Windows) plus a
   `SHA256SUMS.txt`, and
3. creates a GitHub release tagged `v<VERSION>` at the merge commit with
   auto-generated notes and the binaries attached.

The release tag is also what `go install github.com/darylcecile/gosh/cmd/gosh@v<VERSION>`
and `go get` resolve for module consumers. Because the job is a no-op when the
tag already exists, it is safe to run on every merge.

**To cut a release:** bump the `VERSION` file (e.g. `1.0.0` → `1.1.0`) in a PR;
merging it to `main` publishes the release. Major bumps to `2.0.0`+ are rejected
until the module path is migrated to `.../gosh/v2` per Go's
[semantic import versioning](https://go.dev/ref/mod#major-version-suffixes). It
needs only the built-in `GITHUB_TOKEN` (`contents: write`); if a release run
fails after the tag is created, delete the `v<VERSION>` tag and re-run via
`workflow_dispatch`.

## Agentic workflows (GitHub Agentic Workflows / `gh aw`)

Two AI-agent workflows authored with [GitHub Agentic Workflows](https://github.github.com/gh-aw/).
Each is a markdown file (the **source of truth**) compiled to a `*.lock.yml`
file (what Actions actually runs). **Edit the `.md`, never the `.lock.yml`.**

| Source (`.md`) | Compiled (`.lock.yml`) | Trigger | What it does |
|---|---|---|---|
| `issue-triage.md` | `issue-triage.lock.yml` | issue `opened` / `reopened` | Reads the issue, applies labels, flags duplicates, posts a triage report, closes obvious spam. Read-only + sanitized safe-outputs. |
| `issue-fix.md` | `issue-fix.lock.yml` | a maintainer adds the **`agent-fix`** label to an issue | Reads the issue, makes a minimal change, runs the Go test suite, and opens a **draft** PR for review. Never merges; only touches Go/docs files. |

Both run the **`copilot`** engine, with read-only repository permissions; every
write goes through gh-aw's sanitized `safe-outputs` path, and untrusted issue
text is treated as data (prompt-injection hardened).

### Setup required before these run

1. **Add a repository secret `COPILOT_GITHUB_TOKEN`** — a fine-grained PAT with
   the **"Copilot Requests"** permission (the engine authenticates with it). For
   `issue-fix`, the built-in `GITHUB_TOKEN` (with the `contents`/`pull-requests`
   write that the safe-output grants) is used to open the PR.
2. **Create the `agent-fix` label** in the repo (any colour). Because adding a
   label requires triage/write access, this label is the authorization gate for
   the fix workflow — only trusted collaborators can invoke it.
3. Make sure **Copilot is enabled** for the repository/organization and that
   Actions is allowed to call it.

### Regenerating the lock files

The committed `*.lock.yml` files were compiled against
[`github/gh-aw@v0.78.3`](https://github.com/github/gh-aw) (the `setup` action is
pinned to that tag). To change behaviour, edit the `.md` frontmatter and
recompile with the official extension:

```bash
gh extension install github/gh-aw   # one time
gh aw compile                       # regenerates *.lock.yml from *.md
```

Editing only the markdown **body** (the instructions) does not require
recompilation; editing the **frontmatter** does.

### Notes & limitations

- PRs opened by `issue-fix` are created with `GITHUB_TOKEN`, so they do **not**
  automatically trigger the `ci.yml` checks (a GitHub safeguard against workflow
  loops). Re-run CI by pushing to the branch or closing/reopening the PR.
- `issue-fix` is intentionally scoped: the safe-output restricts its patch to
  `**/*.go`, `go.mod`, `go.sum`, `docs/**/*.md`, and `README.md`, and it is told
  never to introduce `os/exec`/`net` (enforced by `internal/importcheck`).
- These workflows consume Copilot premium requests when they run.
