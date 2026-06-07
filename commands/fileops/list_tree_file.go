package fileops

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/darylcecile/gosh"
)

func lsCommand() gosh.Command {
	return gosh.CommandFunc("ls", func(ctx context.Context, cc *gosh.CommandContext) int {
		if cc.WantsHelp() {
			return cc.PrintHelp("ls [-la1Rd] [FILE]...", "List directory contents.")
		}
		opts := lsOptions{}
		var args []string
		for _, a := range cc.Args {
			if strings.HasPrefix(a, "-") && a != "-" {
				for _, r := range a[1:] {
					switch r {
					case 'l':
						opts.long = true
					case 'a':
						opts.all = true
					case '1':
						opts.one = true
					case 'R':
						opts.recursive = true
					case 'd':
						opts.dirAsEntry = true
					default:
						return usageError(cc, "unsupported option "+string(r))
					}
				}
			} else {
				args = append(args, a)
			}
		}
		if len(args) == 0 {
			args = []string{"."}
		}
		for i, a := range args {
			if i > 0 {
				fmt.Fprintln(cc.Stdout)
			}
			if err := listPath(ctx, cc, a, opts, len(args) > 1 || opts.recursive); err != nil {
				return commandError(cc, "%s: %v", a, err)
			}
		}
		return 0
	})
}

type lsOptions struct{ long, all, one, recursive, dirAsEntry bool }

func listPath(ctx context.Context, cc *gosh.CommandContext, arg string, opts lsOptions, header bool) error {
	info, abs, err := lstatPath(cc, arg)
	if err != nil {
		return err
	}
	if opts.dirAsEntry || !info.IsDir() {
		return printEntry(ctx, cc, printablePath(arg, abs), abs, info, opts.long)
	}
	return listDir(ctx, cc, printablePath(arg, abs), abs, opts, header)
}

func listDir(ctx context.Context, cc *gosh.CommandContext, label, abs string, opts lsOptions, header bool) error {
	if header {
		fmt.Fprintf(cc.Stdout, "%s:\n", label)
	}
	entries, err := sortedDirEntries(cc, abs, opts.all)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := tick(ctx, cc); err != nil {
			return err
		}
		entryAbs := path.Join(abs, e.Name())
		info, err := cc.FS().Lstat(entryAbs)
		if err != nil {
			return err
		}
		if err := printEntry(ctx, cc, e.Name(), entryAbs, info, opts.long); err != nil {
			return err
		}
	}
	if opts.recursive {
		for _, e := range entries {
			if err := tick(ctx, cc); err != nil {
				return err
			}
			entryAbs := path.Join(abs, e.Name())
			info, err := cc.FS().Stat(entryAbs)
			if err != nil {
				return err
			}
			if info.IsDir() {
				fmt.Fprintln(cc.Stdout)
				if err := listDir(ctx, cc, path.Join(label, e.Name()), entryAbs, opts, true); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func printEntry(ctx context.Context, cc *gosh.CommandContext, name, abs string, info fs.FileInfo, long bool) error {
	if err := tick(ctx, cc); err != nil {
		return err
	}
	if !long {
		fmt.Fprintln(cc.Stdout, name)
		return nil
	}
	fmt.Fprintf(cc.Stdout, "%s %8d %s %s\n", info.Mode().String(), info.Size(), info.ModTime().UTC().Format("2006-01-02 15:04"), name)
	return nil
}

func treeCommand() gosh.Command {
	return gosh.CommandFunc("tree", func(ctx context.Context, cc *gosh.CommandContext) int {
		if cc.WantsHelp() {
			return cc.PrintHelp("tree [DIRECTORY]...", "Print a recursive directory tree.")
		}
		args := cc.Args
		if len(args) == 0 {
			args = []string{"."}
		}
		counts := &treeCounts{}
		for i, a := range args {
			if i > 0 {
				fmt.Fprintln(cc.Stdout)
			}
			info, abs, err := statPath(cc, a)
			if err != nil {
				return commandError(cc, "%s: %v", a, err)
			}
			fmt.Fprintln(cc.Stdout, printablePath(a, abs))
			if info.IsDir() {
				counts.dirs++
				if err := treeWalk(ctx, cc, abs, "", counts); err != nil {
					return writeLimitErr(cc, err)
				}
			} else {
				counts.files++
			}
		}
		fmt.Fprintf(cc.Stdout, "\n%d directories, %d files\n", counts.dirs, counts.files)
		return 0
	})
}

type treeCounts struct{ dirs, files int }

func treeWalk(ctx context.Context, cc *gosh.CommandContext, abs, prefix string, counts *treeCounts) error {
	entries, err := sortedDirEntries(cc, abs, false)
	if err != nil {
		return err
	}
	for i, e := range entries {
		if err := tick(ctx, cc); err != nil {
			return err
		}
		last := i == len(entries)-1
		connector := "├── "
		nextPrefix := prefix + "│   "
		if last {
			connector = "└── "
			nextPrefix = prefix + "    "
		}
		entryAbs := path.Join(abs, e.Name())
		info, err := cc.FS().Stat(entryAbs)
		if err != nil {
			return err
		}
		fmt.Fprintf(cc.Stdout, "%s%s%s\n", prefix, connector, e.Name())
		if info.IsDir() {
			counts.dirs++
			if err := treeWalk(ctx, cc, entryAbs, nextPrefix, counts); err != nil {
				return err
			}
		} else {
			counts.files++
		}
	}
	return nil
}

func fileCommand() gosh.Command {
	return gosh.CommandFunc("file", func(ctx context.Context, cc *gosh.CommandContext) int {
		if cc.WantsHelp() {
			return cc.PrintHelp("file FILE...", "Classify files as empty, text, UTF-8 text, or data.")
		}
		if len(cc.Args) == 0 {
			return usageError(cc, "missing operand")
		}
		for _, p := range cc.Args {
			if err := tick(ctx, cc); err != nil {
				return writeLimitErr(cc, err)
			}
			abs := cc.ResolvePath(p)
			info, err := cc.FS().Stat(abs)
			if err != nil {
				return commandError(cc, "%s: %v", p, err)
			}
			kind := "data"
			if info.IsDir() {
				kind = "directory"
			} else {
				f, err := cc.FS().Open(abs, os.O_RDONLY, 0)
				if err != nil {
					return commandError(cc, "%s: %v", p, err)
				}
				data, rerr := io.ReadAll(f)
				_ = f.Close()
				if rerr != nil {
					return commandError(cc, "%s: %v", p, rerr)
				}
				kind = isTextKind(data, true)
			}
			fmt.Fprintf(cc.Stdout, "%s: %s\n", p, kind)
		}
		return 0
	})
}
