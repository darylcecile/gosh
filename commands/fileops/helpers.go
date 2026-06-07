package fileops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/darylcecile/gosh"
)

const defaultFileMode fs.FileMode = 0o644
const defaultDirMode fs.FileMode = 0o755

func commandError(cc *gosh.CommandContext, format string, args ...any) int {
	fmt.Fprintf(cc.Stderr, "%s: %s\n", cc.Name, fmt.Sprintf(format, args...))
	return 1
}

func usageError(cc *gosh.CommandContext, msg string) int {
	if msg != "" {
		fmt.Fprintf(cc.Stderr, "%s: %s\n", cc.Name, msg)
	}
	return 2
}

func tick(ctx context.Context, cc *gosh.CommandContext) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if gov := cc.Governor(); gov != nil {
		if err := gov.StreamTick(); err != nil {
			return err
		}
	}
	return nil
}

func writeLimitErr(cc *gosh.CommandContext, err error) int {
	fmt.Fprintf(cc.Stderr, "%s: %v\n", cc.Name, err)
	return 1
}

func parseMode(s string) (fs.FileMode, error) {
	if s == "" {
		return 0, errors.New("empty mode")
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, err
	}
	return fs.FileMode(v) & fs.ModePerm, nil
}

func isDir(cc *gosh.CommandContext, p string) bool {
	info, err := cc.FS().Stat(cc.ResolvePath(p))
	return err == nil && info.IsDir()
}

func statPath(cc *gosh.CommandContext, p string) (fs.FileInfo, string, error) {
	abs := cc.ResolvePath(p)
	info, err := cc.FS().Stat(abs)
	return info, abs, err
}

func lstatPath(cc *gosh.CommandContext, p string) (fs.FileInfo, string, error) {
	abs := cc.ResolvePath(p)
	info, err := cc.FS().Lstat(abs)
	return info, abs, err
}

func sortedDirEntries(cc *gosh.CommandContext, abs string, all bool) ([]fs.DirEntry, error) {
	entries, err := cc.FS().ReadDir(abs)
	if err != nil {
		return nil, err
	}
	out := make([]fs.DirEntry, 0, len(entries))
	for _, e := range entries {
		if !all && strings.HasPrefix(e.Name(), ".") {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

func copyStream(ctx context.Context, cc *gosh.CommandContext, dst io.Writer, src io.Reader) error {
	buf := make([]byte, 32*1024)
	for {
		if err := tick(ctx, cc); err != nil {
			return err
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

func baseName(p string) string {
	clean := path.Clean(p)
	if clean == "/" || clean == "." {
		return strings.TrimPrefix(clean, "/")
	}
	return path.Base(clean)
}

func printablePath(input, abs string) string {
	if input == "" {
		return abs
	}
	return input
}

func isTextKind(data []byte, all bool) string {
	if len(data) == 0 && all {
		return "empty"
	}
	if len(data) == 0 {
		return "empty"
	}
	ascii := true
	for _, b := range data {
		if b == 0 {
			return "data"
		}
		if b >= 0x80 {
			ascii = false
		}
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' && b != '\f' && b != '\b' {
			return "data"
		}
	}
	if ascii {
		return "ASCII text"
	}
	if utf8.Valid(data) {
		return "UTF-8 text"
	}
	return "data"
}
