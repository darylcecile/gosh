# Command reference

`gosh` ships a reimplemented, pure-Go coreutil set — **no command ever shells out
to the host**. Register the full bundle with `std.Shell()` / `std.WithStandard()`,
or hand-pick groups with `gosh.WithCommands(...)`.

```go
import "github.com/darylcecile/gosh/std"

sh := std.Shell()                       // all commands below
all := std.Commands()                   // []gosh.Command — the full set
```

## Compatibility notes

- Behavior targets GNU coreutils, but is an independent reimplementation. Some
  **legacy flag forms differ** — e.g. use `head -n 2` / `tail -n 5`, not `head -2`.
- `echo`, `printf`, `test`, `[`, `cd`, `pwd`, `read`, and other shell-control
  words are **interpreter builtins**, not registry commands, so they are not in
  the list below and cannot be invoked via `xargs`/`find -exec`.
- Network commands (`curl`, `html2md`/`htmlmd`) are always registered but return
  exit `127` ("command not found"-style refusal) until you pass `WithNetwork`.
- Run any command with `--help` for its usage, or use the built-in `help`
  command (registered by `std`) for an index:

  ```sh
  help            # list all commands
  help jq sort    # usage for specific commands
  ```

## File operations (`commands/fileops`)

| Command | Purpose |
|---|---|
| `cat` | concatenate and print files |
| `cp` | copy files/directories |
| `mv` | move/rename |
| `rm` | remove files (guards against removing `/`) |
| `rmdir` | remove empty directories |
| `mkdir` | create directories (`-p`) |
| `ls` | list directory contents |
| `ln` | create hard/symbolic links |
| `readlink` | print a symlink target |
| `stat` | file metadata |
| `touch` | create/update timestamps |
| `tree` | recursive directory tree |
| `file` | classify file contents |

## Text processing (`commands/textproc`)

| Command | Purpose |
|---|---|
| `grep` / `egrep` / `fgrep` | search text with patterns |
| `cut` | extract columns/fields |
| `tr` | translate/delete characters |
| `sort` | sort lines |
| `uniq` | collapse/count adjacent duplicates |
| `wc` | count lines/words/bytes |
| `head` / `tail` | first/last lines (`-n N`) |
| `tac` | reverse line order |
| `rev` | reverse characters per line |
| `nl` | number lines |
| `paste` | merge lines of files |
| `join` | relational join on a field |
| `comm` | compare two sorted files |
| `column` | columnate lists |
| `fold` | wrap long lines |
| `expand` / `unexpand` | tabs ↔ spaces |
| `diff` | line differences |
| `od` | octal/hex dump |
| `strings` | printable strings from data |
| `split` | split a file into fixed-size pieces (by lines or bytes) written to the VFS |
| `xargs` | build commands from stdin (dispatches **registry** commands only) |

## Text languages (`commands/textlang`)

| Command | Purpose |
|---|---|
| `awk` | pattern-action language (powered by [goawk](https://github.com/benhoyt/goawk), isolated: no host exec, no host file access) |
| `sed` | stream editor |

## Navigation & environment (`commands/navenv`)

| Command | Purpose |
|---|---|
| `basename` / `dirname` | path components |
| `find` | walk and filter the VFS |
| `du` | disk usage within the VFS |
| `env` / `printenv` | print environment |
| `tee` | duplicate stdin to files + stdout |
| `seq` | numeric sequences |
| `expr` | evaluate expressions |
| `sleep` | advance the **virtual** clock (no real wall-clock wait) |
| `timeout` | bound a command's duration |
| `date` | format the virtual clock |
| `whoami` / `hostname` | fixed sandbox identity |

## Encoding & data (`commands/datacmd`)

| Command | Purpose |
|---|---|
| `base64` | encode/decode (`-d`) |
| `md5sum` / `sha1sum` / `sha256sum` | checksums |
| `jq` | JSON query/transform (powered by [gojq](https://github.com/itchyny/gojq)) |
| `yq` | YAML query/transform |
| `csv` | CSV field extraction/manipulation |

## Archives & compression (`commands/archive`)

| Command | Purpose |
|---|---|
| `gzip` / `gunzip` / `zcat` | gzip (de)compression |
| `tar` | tar archives, with traversal and decompression-bomb guards |

Archive extraction is bounded: per-entry and total-size caps derived from your
`Limits`, an entry-count ceiling, and rejection of absolute/`..` paths.

## Network (`commands/netcmd`)

| Command | Purpose |
|---|---|
| `curl` | HTTP(S) client — **deny-by-default**, origin allow-list, SSRF-protected |
| `html2md` / `htmlmd` | fetch and convert HTML to Markdown |

Network commands enforce the `NetworkPolicy` you supply via `WithNetwork`: only
allow-listed origins, a method allow-list (GET/HEAD by default), redirect re-
validation, response-size caps, and dial-time private/loopback/metadata-IP
blocking (SSRF + DNS-rebinding defense). See [security.md](./security.md#network).
