// Package std aggregates every built-in gosh command group into a single,
// ready-to-register standard library and adds a registry-aware help command.
//
// It is the ergonomic entry point for hosts that want "batteries included":
//
//	sh := std.Shell(gosh.WithFiles(map[string]string{"/in.txt": "hello\n"}))
//	res, err := sh.Run(ctx, "grep -n hello /in.txt", gosh.RunStdout(os.Stdout))
//
// Equivalently, callers may register the set onto a shell they configure
// themselves:
//
//	sh := gosh.New(std.WithStandard(), gosh.WithLimits(myLimits))
//
// The aggregated set is deny-by-default safe: the network commands (curl,
// html2md) are always present but refuse to run unless an egress NetworkPolicy
// is configured via gosh.WithNetwork (S17). Filesystem adapters live in the
// separate goshfs package because they are wrappers around the FileSystem
// interface rather than commands.
package std

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/darylcecile/gosh"
	"github.com/darylcecile/gosh/commands/archive"
	"github.com/darylcecile/gosh/commands/datacmd"
	"github.com/darylcecile/gosh/commands/fileops"
	"github.com/darylcecile/gosh/commands/navenv"
	"github.com/darylcecile/gosh/commands/netcmd"
	"github.com/darylcecile/gosh/commands/textlang"
	"github.com/darylcecile/gosh/commands/textproc"
)

// groups returns the concatenation of every command group's commands, in a
// stable, documented order. Later groups win on the rare chance two groups
// register the same name (none do today); the core registry has identical
// last-wins semantics.
func groups() []gosh.Command {
	var all []gosh.Command
	all = append(all, fileops.Commands()...)
	all = append(all, textproc.Commands()...)
	all = append(all, textlang.Commands()...)
	all = append(all, navenv.Commands()...)
	all = append(all, datacmd.Commands()...)
	all = append(all, archive.Commands()...)
	all = append(all, netcmd.Commands()...)
	return all
}

// Commands returns the full standard command set plus a help command that lists
// the available commands and forwards `help NAME` to `NAME --help`. The result
// is suitable for gosh.WithCommands.
func Commands() []gosh.Command {
	base := groups()

	seen := make(map[string]struct{}, len(base)+1)
	names := make([]string, 0, len(base)+1)
	for _, c := range base {
		if _, dup := seen[c.Name()]; dup {
			continue
		}
		seen[c.Name()] = struct{}{}
		names = append(names, c.Name())
	}
	names = append(names, "help")
	sort.Strings(names)

	return append(base, helpCommand(names))
}

// WithStandard is a gosh.Option that registers the entire standard command set
// (plus help) onto a shell. It is the most concise way to opt in:
//
//	sh := gosh.New(std.WithStandard())
func WithStandard() gosh.Option {
	return gosh.WithCommands(Commands()...)
}

// Shell constructs a gosh.Shell with the standard command set pre-registered,
// followed by any caller-supplied options (which can override defaults such as
// limits, network policy, the initial filesystem, or additional custom
// commands).
func Shell(opts ...gosh.Option) *gosh.Shell {
	all := make([]gosh.Option, 0, len(opts)+1)
	all = append(all, WithStandard())
	all = append(all, opts...)
	return gosh.New(all...)
}

// helpCommand builds the help command from the known set of command names.
func helpCommand(names []string) gosh.Command {
	const usage = "help [COMMAND]"
	const desc = "List available commands, or show help for COMMAND."
	return gosh.CommandFunc("help", func(ctx context.Context, cc *gosh.CommandContext) int {
		// `help --help` / `help -h` describes help itself.
		if cc.WantsHelp() {
			return cc.PrintHelp(usage, desc)
		}
		// `help NAME` forwards to that command's own --help.
		args := cc.Args
		if len(args) > 0 {
			return cc.Exec(ctx, args[0], "--help")
		}
		fmt.Fprintln(cc.Stdout, "Available commands:")
		fmt.Fprintln(cc.Stdout)
		printColumns(cc, names)
		fmt.Fprintln(cc.Stdout)
		fmt.Fprintln(cc.Stdout, "Run 'help COMMAND' for details on a specific command.")
		return 0
	})
}

// printColumns renders the command names in a tidy multi-column grid.
func printColumns(cc *gosh.CommandContext, names []string) {
	const cols = 6
	tw := tabwriter.NewWriter(cc.Stdout, 0, 0, 2, ' ', 0)
	for i := 0; i < len(names); i += cols {
		end := i + cols
		if end > len(names) {
			end = len(names)
		}
		fmt.Fprintln(tw, "  "+strings.Join(names[i:end], "\t"))
	}
	tw.Flush()
}
