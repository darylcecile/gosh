package fileops

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/darylcecile/gosh"
)

func cpCommand() gosh.Command {
	return gosh.CommandFunc("cp", func(ctx context.Context, cc *gosh.CommandContext) int {
		if cc.WantsHelp() {
			return cc.PrintHelp("cp [-r|-R] [-p] SOURCE... DEST", "Copy files and directories.")
		}
		recursive, preserve := false, false
		var args []string
		for _, a := range cc.Args {
			if strings.HasPrefix(a, "-") && a != "-" {
				for _, r := range a[1:] {
					switch r {
					case 'r', 'R':
						recursive = true
					case 'p':
						preserve = true
					default:
						return usageError(cc, "unsupported option "+string(r))
					}
				}
			} else {
				args = append(args, a)
			}
		}
		if len(args) < 2 {
			return usageError(cc, "missing operand")
		}
		destArg := args[len(args)-1]
		sources := args[:len(args)-1]
		destInfo, destAbs, destErr := statPath(cc, destArg)
		multi := len(sources) > 1
		if multi && (destErr != nil || !destInfo.IsDir()) {
			return commandError(cc, "%s: not a directory", destArg)
		}
		for _, srcArg := range sources {
			if err := tick(ctx, cc); err != nil {
				return writeLimitErr(cc, err)
			}
			_, srcAbs, err := statPath(cc, srcArg)
			if err != nil {
				return commandError(cc, "%s: %v", srcArg, err)
			}
			outAbs := destAbs
			if destErr == nil && destInfo.IsDir() {
				outAbs = path.Join(destAbs, path.Base(srcAbs))
			}
			if err := copyPath(ctx, cc, srcAbs, outAbs, recursive, preserve); err != nil {
				return commandError(cc, "%s: %v", srcArg, err)
			}
		}
		return 0
	})
}

func copyPath(ctx context.Context, cc *gosh.CommandContext, srcAbs, dstAbs string, recursive, preserve bool) error {
	info, err := cc.FS().Stat(srcAbs)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if !recursive {
			return fmt.Errorf("omitting directory")
		}
		mode := defaultDirMode
		if preserve {
			mode = info.Mode() & fs.ModePerm
		}
		if err := cc.FS().MkdirAll(dstAbs, mode); err != nil {
			return err
		}
		entries, err := cc.FS().ReadDir(srcAbs)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := tick(ctx, cc); err != nil {
				return err
			}
			if err := copyPath(ctx, cc, path.Join(srcAbs, e.Name()), path.Join(dstAbs, e.Name()), recursive, preserve); err != nil {
				return err
			}
		}
		if preserve {
			_ = cc.FS().Chmod(dstAbs, info.Mode()&fs.ModePerm)
		}
		return nil
	}
	mode := defaultFileMode
	if preserve {
		mode = info.Mode() & fs.ModePerm
	}
	in, err := cc.FS().Open(srcAbs, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := cc.FS().Open(dstAbs, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if err := copyStream(ctx, cc, out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if preserve {
		_ = cc.FS().Chmod(dstAbs, info.Mode()&fs.ModePerm)
	}
	return nil
}

func mvCommand() gosh.Command {
	return gosh.CommandFunc("mv", func(ctx context.Context, cc *gosh.CommandContext) int {
		if cc.WantsHelp() {
			return cc.PrintHelp("mv SOURCE... DEST", "Move or rename files and directories.")
		}
		if len(cc.Args) < 2 {
			return usageError(cc, "missing operand")
		}
		destArg := cc.Args[len(cc.Args)-1]
		sources := cc.Args[:len(cc.Args)-1]
		destInfo, destAbs, destErr := statPath(cc, destArg)
		if len(sources) > 1 && (destErr != nil || !destInfo.IsDir()) {
			return commandError(cc, "%s: not a directory", destArg)
		}
		for _, srcArg := range sources {
			if err := tick(ctx, cc); err != nil {
				return writeLimitErr(cc, err)
			}
			_, srcAbs, err := lstatPath(cc, srcArg)
			if err != nil {
				return commandError(cc, "%s: %v", srcArg, err)
			}
			outAbs := destAbs
			if destErr == nil && destInfo.IsDir() {
				outAbs = path.Join(destAbs, path.Base(srcAbs))
			}
			if err := cc.FS().Rename(srcAbs, outAbs); err != nil {
				return commandError(cc, "%s: %v", srcArg, err)
			}
		}
		return 0
	})
}

func lnCommand() gosh.Command {
	return gosh.CommandFunc("ln", func(ctx context.Context, cc *gosh.CommandContext) int {
		if cc.WantsHelp() {
			return cc.PrintHelp("ln [-s] [-f] TARGET LINK_NAME", "Create hard or symbolic links.")
		}
		sym, force := false, false
		var args []string
		for _, a := range cc.Args {
			if strings.HasPrefix(a, "-") && a != "-" {
				for _, r := range a[1:] {
					switch r {
					case 's':
						sym = true
					case 'f':
						force = true
					default:
						return usageError(cc, "unsupported option "+string(r))
					}
				}
			} else {
				args = append(args, a)
			}
		}
		if len(args) != 2 {
			return usageError(cc, "TARGET and LINK_NAME required")
		}
		targetArg, linkArg := args[0], args[1]
		linkAbs := cc.ResolvePath(linkArg)
		if force {
			_ = cc.FS().Remove(linkAbs)
		}
		var err error
		if sym {
			err = cc.FS().Symlink(targetArg, linkAbs)
		} else {
			err = cc.FS().Link(cc.ResolvePath(targetArg), linkAbs)
		}
		if err != nil {
			return commandError(cc, "%s: %v", linkArg, err)
		}
		return 0
	})
}
