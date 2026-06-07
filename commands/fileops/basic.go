package fileops

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/darylcecile/gosh"
)

func catCommand() gosh.Command {
	return gosh.CommandFunc("cat", func(ctx context.Context, cc *gosh.CommandContext) int {
		if cc.WantsHelp() {
			return cc.PrintHelp("cat [-n] [FILE]...", "Concatenate files to standard output. Use - for standard input.")
		}
		number := false
		files := make([]string, 0, len(cc.Args))
		for _, a := range cc.Args {
			if a == "-n" {
				number = true
				continue
			}
			if strings.HasPrefix(a, "-") && a != "-" {
				return usageError(cc, "unsupported option "+a)
			}
			files = append(files, a)
		}
		if len(files) == 0 {
			files = []string{"-"}
		}
		lineNo := 1
		for _, name := range files {
			var r io.Reader
			var closeFn func() error
			if name == "-" {
				r = cc.Stdin
			} else {
				f, err := cc.FS().Open(cc.ResolvePath(name), os.O_RDONLY, 0)
				if err != nil {
					return commandError(cc, "%s: %v", name, err)
				}
				r = f
				closeFn = f.Close
			}
			br := bufio.NewReader(r)
			for {
				if err := tick(ctx, cc); err != nil {
					if closeFn != nil {
						_ = closeFn()
					}
					return writeLimitErr(cc, err)
				}
				line, err := br.ReadString('\n')
				if len(line) > 0 {
					if number {
						fmt.Fprintf(cc.Stdout, "%6d\t", lineNo)
						lineNo++
					}
					fmt.Fprint(cc.Stdout, line)
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					if closeFn != nil {
						_ = closeFn()
					}
					return commandError(cc, "%s: %v", name, err)
				}
			}
			if closeFn != nil {
				_ = closeFn()
			}
		}
		return 0
	})
}

func mkdirCommand() gosh.Command {
	return gosh.CommandFunc("mkdir", func(ctx context.Context, cc *gosh.CommandContext) int {
		if cc.WantsHelp() {
			return cc.PrintHelp("mkdir [-p] [-m MODE] DIRECTORY...", "Create directories.")
		}
		parents := false
		mode := defaultDirMode
		var dirs []string
		for i := 0; i < len(cc.Args); i++ {
			a := cc.Args[i]
			switch {
			case a == "-p":
				parents = true
			case a == "-m":
				i++
				if i >= len(cc.Args) {
					return usageError(cc, "missing mode")
				}
				m, err := parseMode(cc.Args[i])
				if err != nil {
					return usageError(cc, "invalid mode")
				}
				mode = m
			case strings.HasPrefix(a, "-m") && len(a) > 2:
				m, err := parseMode(a[2:])
				if err != nil {
					return usageError(cc, "invalid mode")
				}
				mode = m
			case strings.HasPrefix(a, "-"):
				return usageError(cc, "unsupported option "+a)
			default:
				dirs = append(dirs, a)
			}
		}
		if len(dirs) == 0 {
			return usageError(cc, "missing operand")
		}
		for _, d := range dirs {
			if err := tick(ctx, cc); err != nil {
				return writeLimitErr(cc, err)
			}
			abs := cc.ResolvePath(d)
			var err error
			if parents {
				err = cc.FS().MkdirAll(abs, mode)
			} else {
				err = cc.FS().Mkdir(abs, mode)
			}
			if err != nil {
				return commandError(cc, "%s: %v", d, err)
			}
		}
		return 0
	})
}

func rmCommand() gosh.Command {
	return gosh.CommandFunc("rm", func(ctx context.Context, cc *gosh.CommandContext) int {
		if cc.WantsHelp() {
			return cc.PrintHelp("rm [-f] [-r|-R] FILE...", "Remove files or directories.")
		}
		force, recursive := false, false
		var files []string
		for _, a := range cc.Args {
			if a == "--" {
				continue
			}
			if strings.HasPrefix(a, "-") && a != "-" {
				for _, r := range a[1:] {
					switch r {
					case 'f':
						force = true
					case 'r', 'R':
						recursive = true
					default:
						return usageError(cc, "unsupported option "+string(r))
					}
				}
			} else {
				files = append(files, a)
			}
		}
		if len(files) == 0 {
			if force {
				return 0
			}
			return usageError(cc, "missing operand")
		}
		for _, p := range files {
			if err := tick(ctx, cc); err != nil {
				return writeLimitErr(cc, err)
			}
			abs := cc.ResolvePath(p)
			if abs == "/" || abs == cc.Cwd() {
				return commandError(cc, "refusing to remove %s", p)
			}
			_, err := cc.FS().Lstat(abs)
			if err != nil {
				if force {
					continue
				}
				return commandError(cc, "%s: %v", p, err)
			}
			if recursive {
				err = cc.FS().RemoveAll(abs)
			} else {
				err = cc.FS().Remove(abs)
			}
			if err != nil {
				if force {
					continue
				}
				return commandError(cc, "%s: %v", p, err)
			}
		}
		return 0
	})
}

func rmdirCommand() gosh.Command {
	return gosh.CommandFunc("rmdir", func(ctx context.Context, cc *gosh.CommandContext) int {
		if cc.WantsHelp() {
			return cc.PrintHelp("rmdir DIRECTORY...", "Remove empty directories.")
		}
		if len(cc.Args) == 0 {
			return usageError(cc, "missing operand")
		}
		for _, d := range cc.Args {
			if err := tick(ctx, cc); err != nil {
				return writeLimitErr(cc, err)
			}
			abs := cc.ResolvePath(d)
			info, err := cc.FS().Stat(abs)
			if err != nil {
				return commandError(cc, "%s: %v", d, err)
			}
			if !info.IsDir() {
				return commandError(cc, "%s: not a directory", d)
			}
			if err := cc.FS().Remove(abs); err != nil {
				return commandError(cc, "%s: %v", d, err)
			}
		}
		return 0
	})
}

func touchCommand() gosh.Command {
	return gosh.CommandFunc("touch", func(ctx context.Context, cc *gosh.CommandContext) int {
		if cc.WantsHelp() {
			return cc.PrintHelp("touch [-c] FILE...", "Create files or update their modification time.")
		}
		noCreate := false
		var files []string
		for _, a := range cc.Args {
			if a == "-c" {
				noCreate = true
			} else if strings.HasPrefix(a, "-") {
				return usageError(cc, "unsupported option "+a)
			} else {
				files = append(files, a)
			}
		}
		if len(files) == 0 {
			return usageError(cc, "missing operand")
		}
		for _, p := range files {
			if err := tick(ctx, cc); err != nil {
				return writeLimitErr(cc, err)
			}
			abs := cc.ResolvePath(p)
			_, statErr := cc.FS().Stat(abs)
			if statErr != nil && noCreate {
				continue
			}
			f, err := cc.FS().Open(abs, os.O_WRONLY|os.O_CREATE|os.O_APPEND, defaultFileMode)
			if err != nil {
				return commandError(cc, "%s: %v", p, err)
			}
			_, err = f.Write(nil)
			cerr := f.Close()
			if err != nil {
				return commandError(cc, "%s: %v", p, err)
			}
			if cerr != nil {
				return commandError(cc, "%s: %v", p, cerr)
			}
		}
		return 0
	})
}

func statCommand() gosh.Command {
	return gosh.CommandFunc("stat", func(ctx context.Context, cc *gosh.CommandContext) int {
		if cc.WantsHelp() {
			return cc.PrintHelp("stat FILE...", "Display file size, mode, and modification time.")
		}
		if len(cc.Args) == 0 {
			return usageError(cc, "missing operand")
		}
		for _, p := range cc.Args {
			if err := tick(ctx, cc); err != nil {
				return writeLimitErr(cc, err)
			}
			info, abs, err := lstatPath(cc, p)
			if err != nil {
				return commandError(cc, "%s: %v", p, err)
			}
			fmt.Fprintf(cc.Stdout, "%s: size=%d mode=%s mtime=%s\n", printablePath(p, abs), info.Size(), info.Mode().String(), info.ModTime().UTC().Format("2006-01-02 15:04:05 UTC"))
		}
		return 0
	})
}

func readlinkCommand() gosh.Command {
	return gosh.CommandFunc("readlink", func(ctx context.Context, cc *gosh.CommandContext) int {
		if cc.WantsHelp() {
			return cc.PrintHelp("readlink [-f] FILE...", "Print symbolic link targets.")
		}
		canonical := false
		var files []string
		for _, a := range cc.Args {
			if a == "-f" {
				canonical = true
			} else if strings.HasPrefix(a, "-") {
				return usageError(cc, "unsupported option "+a)
			} else {
				files = append(files, a)
			}
		}
		if len(files) == 0 {
			return usageError(cc, "missing operand")
		}
		for _, p := range files {
			if err := tick(ctx, cc); err != nil {
				return writeLimitErr(cc, err)
			}
			abs := cc.ResolvePath(p)
			target, err := cc.FS().Readlink(abs)
			if err != nil {
				if canonical {
					if _, statErr := cc.FS().Stat(abs); statErr != nil {
						return commandError(cc, "%s: %v", p, err)
					}
					fmt.Fprintln(cc.Stdout, abs)
					continue
				}
				return commandError(cc, "%s: %v", p, err)
			}
			if canonical && !path.IsAbs(target) {
				target = path.Clean(path.Join(path.Dir(abs), target))
			}
			fmt.Fprintln(cc.Stdout, target)
		}
		return 0
	})
}
