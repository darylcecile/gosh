# Using the gosh sandbox (guidance for AI agents)

You are running shell scripts inside **gosh**, a sandboxed, in-memory Bash
interpreter. This is **not** a real shell on a real machine. Read this so you use
it effectively and don't waste turns on operations that cannot work here.

## What this environment is

- A virtualized Bash interpreter with an **in-memory filesystem**. Files you
  create persist for the session but never touch a real disk.
- A curated set of ~70 coreutils (`cat`, `ls`, `grep`, `sed`, `awk`, `jq`, `tar`,
  …). See the command list below.
- Deterministic by default: the clock starts at `2000-01-01T00:00:00Z`, so `date`
  and timestamps are reproducible, and `sleep` returns instantly.

## Hard limits — do not attempt these

- **No host programs.** Only the built-in commands exist. Anything else
  (`python`, `node`, `/bin/sh`, `git`, `npm`, custom binaries) returns
  `command not found` (exit 127). Do not try to install or invoke external tools.
- **No host filesystem.** You cannot read real paths like `/etc/passwd`, the host
  home directory, or project files unless they were explicitly seeded into the
  virtual filesystem. Start from `/home/user`.
- **No environment secrets.** The environment is empty except `HOME`. Do not
  expect host env vars.
- **Network is usually off.** `curl` and friends fail unless the host has
  allow-listed specific origins. Assume offline unless told otherwise.
- **Disabled shell features.** `eval`, `source`/`.`, `exec`, `command`, job
  control (`&`, `fg`, `bg`), process substitution `<(...)`, and coprocesses are
  rejected. Write straightforward scripts without them.
- **Resource budgets are enforced.** Excessive commands, loop iterations, output,
  or file sizes abort the run with a "limit exceeded" error. Keep work bounded;
  avoid infinite loops and unbounded output.

## What works well

- Pipes, redirects, here-docs, `&&`/`||`/`;`, subshells `( )`, command
  substitution `$(...)`, arithmetic `$(( ))`, globbing, `if`/`case`/`for`/`while`,
  functions, and `test`/`[ ]`/`[[ ]]`.
- Text wrangling: `grep sed awk cut tr sort uniq wc head tail paste join nl
  column fold split`.
- Data: `jq` (JSON), `yq` (YAML), `csv`, `base64`, `md5sum`/`sha256sum`.
- Files: `cat cp mv rm mkdir ls ln stat find tree du`, archives `tar gzip gunzip`.

## Tips

- Use GNU long forms: `head -n 2`, not `head -2`.
- `echo`, `printf`, `test`, `[`, `cd`, `pwd` are shell builtins — you cannot pass
  them to `xargs`/`find -exec` (which only run registry commands like `cat`).
- Write intermediate files under `/home/user`; they persist across commands in the
  same session.
- If a command "isn't found", it genuinely does not exist here — choose a
  different approach using the available commands rather than retrying.
- Prefer one well-formed script over many tiny calls; the interpreter handles
  multi-line scripts, pipelines, and control flow in a single run.

## Full command list

```
File:    cat cp mv rm rmdir mkdir ls ln readlink stat touch tree file
Text:    grep egrep fgrep cut tr sort uniq wc head tail tac rev nl paste join
         comm column fold expand unexpand diff od strings xargs split
Lang:    awk sed
Nav/env: basename dirname find du env printenv tee seq expr sleep timeout date
         whoami hostname
Data:    base64 md5sum sha1sum sha256sum jq yq csv
Archive: gzip gunzip zcat tar
Network: curl html2md htmlmd   (only when the host enables egress)
Meta:    help   (run `help` for an index, or `<cmd> --help`)
```
