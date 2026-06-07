// Package archive provides gzip and tar commands for gosh.
package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"
	"unicode"

	"github.com/darylcecile/gosh"
)

const (
	fallbackPerEntryBytes = int64(256 << 20) // 256 MiB
	fallbackTotalBytes    = int64(1 << 30)   // 1 GiB
	maxArchiveEntries     = int64(100_000)
)

// Commands returns the archive command group: gzip, gunzip, zcat, and tar.
func Commands() []gosh.Command {
	return []gosh.Command{
		gosh.CommandFunc("gzip", runGzip),
		gosh.CommandFunc("gunzip", runGunzip),
		gosh.CommandFunc("zcat", runZcat),
		gosh.CommandFunc("tar", runTar),
	}
}

func archiveLimits(cc *gosh.CommandContext) (perEntry, total int64) {
	perEntry, total = fallbackPerEntryBytes, fallbackTotalBytes
	if cc != nil && cc.Governor() != nil {
		lim := cc.Governor().Limits()
		if lim.MaxFileBytes > 0 {
			perEntry = lim.MaxFileBytes
		}
		if lim.MaxTotalFSBytes > 0 {
			total = lim.MaxTotalFSBytes
		}
	}
	if total < perEntry {
		total = perEntry
	}
	return perEntry, total
}

func commandError(cc *gosh.CommandContext, format string, args ...any) {
	fmt.Fprintf(cc.Stderr, "%s: %s\n", cc.Name, fmt.Sprintf(format, args...))
}

type gzipOptions struct {
	decompress bool
	keep       bool
	stdout     bool
	level      int
	files      []string
}

func runGunzip(ctx context.Context, cc *gosh.CommandContext) int {
	args := append([]string{"-d"}, cc.Args...)
	clone := *cc
	clone.Name = "gunzip"
	clone.Args = args
	return runGzip(ctx, &clone)
}

func runZcat(ctx context.Context, cc *gosh.CommandContext) int {
	args := append([]string{"-dc"}, cc.Args...)
	clone := *cc
	clone.Name = "zcat"
	clone.Args = args
	return runGzip(ctx, &clone)
}

func runGzip(_ context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return cc.PrintHelp("gzip [-d] [-k] [-c] [-1..-9] [FILE]...", "Compress or decompress gzip streams using the sandbox filesystem.")
	}
	opts, err := parseGzipArgs(cc.Args)
	if err != nil {
		commandError(cc, "%v", err)
		return 2
	}
	if len(opts.files) == 0 {
		if opts.decompress {
			return gzipDecompressStream(cc, cc.Stdin, cc.Stdout)
		}
		return gzipCompressStream(cc, cc.Stdin, cc.Stdout, opts.level)
	}
	code := 0
	for _, name := range opts.files {
		var err error
		if opts.decompress {
			err = gzipDecompressFile(cc, name, opts)
		} else {
			err = gzipCompressFile(cc, name, opts)
		}
		if err != nil {
			commandError(cc, "%s: %v", name, err)
			code = 1
		}
	}
	return code
}

func parseGzipArgs(args []string) (gzipOptions, error) {
	opts := gzipOptions{level: gzip.DefaultCompression}
	for _, arg := range args {
		if arg == "--" {
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			for _, r := range arg[1:] {
				switch {
				case r == 'd':
					opts.decompress = true
				case r == 'k':
					opts.keep = true
				case r == 'c':
					opts.stdout = true
				case r >= '1' && r <= '9':
					opts.level = int(r - '0')
				default:
					return opts, fmt.Errorf("unsupported option -%c", r)
				}
			}
			continue
		}
		opts.files = append(opts.files, arg)
	}
	return opts, nil
}

func gzipCompressStream(cc *gosh.CommandContext, src io.Reader, dst io.Writer, level int) int {
	zw, err := gzip.NewWriterLevel(dst, level)
	if err != nil {
		commandError(cc, "%v", err)
		return 1
	}
	if _, err := io.Copy(zw, src); err != nil {
		_ = zw.Close()
		commandError(cc, "%v", err)
		return 1
	}
	if err := zw.Close(); err != nil {
		commandError(cc, "%v", err)
		return 1
	}
	return 0
}

func gzipDecompressStream(cc *gosh.CommandContext, src io.Reader, dst io.Writer) int {
	zr, err := gzip.NewReader(src)
	if err != nil {
		commandError(cc, "%v", err)
		return 1
	}
	defer zr.Close()
	perEntry, _ := archiveLimits(cc)
	if err := copyLimited(dst, zr, perEntry); err != nil {
		commandError(cc, "%v", err)
		return 1
	}
	return 0
}

func gzipCompressFile(cc *gosh.CommandContext, name string, opts gzipOptions) error {
	in, err := cc.FS().Open(cc.ResolvePath(name), os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, opts.level)
	if err != nil {
		return err
	}
	if _, err := io.Copy(zw, in); err != nil {
		_ = zw.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if opts.stdout {
		_, err = cc.Stdout.Write(buf.Bytes())
		return err
	}
	outName := cc.ResolvePath(name + ".gz")
	if err := writeFile(cc, outName, buf.Bytes(), 0o644); err != nil {
		return err
	}
	if !opts.keep {
		if err := cc.FS().Remove(cc.ResolvePath(name)); err != nil {
			return err
		}
	}
	return nil
}

func gzipDecompressFile(cc *gosh.CommandContext, name string, opts gzipOptions) error {
	in, err := cc.FS().Open(cc.ResolvePath(name), os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	zr, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer zr.Close()
	perEntry, _ := archiveLimits(cc)
	data, err := readAllLimited(zr, perEntry)
	if err != nil {
		return err
	}
	if opts.stdout {
		_, err = cc.Stdout.Write(data)
		return err
	}
	outName := strings.TrimSuffix(name, ".gz")
	if outName == name {
		outName += ".out"
	}
	if err := writeFile(cc, cc.ResolvePath(outName), data, 0o644); err != nil {
		return err
	}
	if !opts.keep {
		if err := cc.FS().Remove(cc.ResolvePath(name)); err != nil {
			return err
		}
	}
	return nil
}

type tarOptions struct {
	mode            rune
	gzip            bool
	file            string
	verbose         bool
	cwd             string
	stripComponents int
	operands        []string
}

func runTar(_ context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return cc.PrintHelp("tar -c|-x|-t [-z] [-v] -f FILE [-C DIR] [--strip-components N] [FILE]...", "Create, list, or extract tar archives through the sandbox filesystem.")
	}
	opts, err := parseTarArgs(cc.Args)
	if err != nil {
		commandError(cc, "%v", err)
		return 2
	}
	switch opts.mode {
	case 'c':
		if err := tarCreate(cc, opts); err != nil {
			commandError(cc, "%v", err)
			return 1
		}
	case 't':
		if err := tarRead(cc, opts, false); err != nil {
			commandError(cc, "%v", err)
			return 1
		}
	case 'x':
		if err := tarRead(cc, opts, true); err != nil {
			commandError(cc, "%v", err)
			return 1
		}
	default:
		commandError(cc, "exactly one of -c, -x, or -t is required")
		return 2
	}
	return 0
}

func parseTarArgs(args []string) (tarOptions, error) {
	opts := tarOptions{file: "-"}
	setMode := func(m rune) error {
		if opts.mode != 0 && opts.mode != m {
			return errors.New("exactly one of -c, -x, or -t is required")
		}
		opts.mode = m
		return nil
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--strip-components":
			i++
			if i >= len(args) {
				return opts, errors.New("--strip-components requires a value")
			}
			n, err := strconv.Atoi(args[i])
			if err != nil || n < 0 {
				return opts, errors.New("--strip-components requires a non-negative integer")
			}
			opts.stripComponents = n
		case strings.HasPrefix(arg, "--strip-components="):
			n, err := strconv.Atoi(strings.TrimPrefix(arg, "--strip-components="))
			if err != nil || n < 0 {
				return opts, errors.New("--strip-components requires a non-negative integer")
			}
			opts.stripComponents = n
		case arg == "-C":
			i++
			if i >= len(args) {
				return opts, errors.New("-C requires a directory")
			}
			opts.cwd = args[i]
		case arg == "-f":
			i++
			if i >= len(args) {
				return opts, errors.New("-f requires a file")
			}
			opts.file = args[i]
		case strings.HasPrefix(arg, "-") && arg != "-":
			letters := []rune(arg[1:])
			for j := 0; j < len(letters); j++ {
				switch letters[j] {
				case 'c', 'x', 't':
					if err := setMode(letters[j]); err != nil {
						return opts, err
					}
				case 'z':
					opts.gzip = true
				case 'v':
					opts.verbose = true
				case 'f':
					if j != len(letters)-1 {
						opts.file = string(letters[j+1:])
						j = len(letters)
						break
					}
					i++
					if i >= len(args) {
						return opts, errors.New("-f requires a file")
					}
					opts.file = args[i]
				case 'C':
					i++
					if i >= len(args) {
						return opts, errors.New("-C requires a directory")
					}
					opts.cwd = args[i]
				default:
					return opts, fmt.Errorf("unsupported option -%c", letters[j])
				}
			}
		default:
			opts.operands = append(opts.operands, arg)
		}
	}
	return opts, nil
}

func tarCreate(cc *gosh.CommandContext, opts tarOptions) error {
	if len(opts.operands) == 0 {
		return errors.New("create requires at least one file")
	}
	var buf bytes.Buffer
	var out io.Writer = &buf
	var gz *gzip.Writer
	if opts.gzip {
		gz = gzip.NewWriter(&buf)
		out = gz
	}
	tw := tar.NewWriter(out)
	base := cc.Cwd()
	if opts.cwd != "" {
		base = cc.ResolvePath(opts.cwd)
	}
	for _, operand := range opts.operands {
		abs := resolveAgainst(cc, base, operand)
		name := archiveName(operand)
		if name == "." {
			name = "."
		}
		if err := addTarPath(cc, tw, abs, name, opts.verbose); err != nil {
			_ = tw.Close()
			if gz != nil {
				_ = gz.Close()
			}
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if gz != nil {
		if err := gz.Close(); err != nil {
			return err
		}
	}
	if opts.file == "-" {
		_, err := cc.Stdout.Write(buf.Bytes())
		return err
	}
	return writeFile(cc, cc.ResolvePath(opts.file), buf.Bytes(), 0o644)
}

func addTarPath(cc *gosh.CommandContext, tw *tar.Writer, abs, name string, verbose bool) error {
	info, err := cc.FS().Lstat(abs)
	if err != nil {
		return err
	}
	mode := info.Mode()
	var link string
	if mode&fs.ModeSymlink != 0 {
		link, err = cc.FS().Readlink(abs)
		if err != nil {
			return err
		}
	}
	hdr, err := tar.FileInfoHeader(info, link)
	if err != nil {
		return err
	}
	hdr.Name = name
	if info.IsDir() && !strings.HasSuffix(hdr.Name, "/") {
		hdr.Name += "/"
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if verbose {
		fmt.Fprintln(cc.Stdout, strings.TrimSuffix(hdr.Name, "/"))
	}
	if info.IsDir() {
		entries, err := cc.FS().ReadDir(abs)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			childAbs := path.Join(abs, entry.Name())
			childName := path.Join(strings.TrimSuffix(name, "/"), entry.Name())
			if err := addTarPath(cc, tw, childAbs, childName, verbose); err != nil {
				return err
			}
		}
		return nil
	}
	if mode&fs.ModeSymlink != 0 {
		return nil
	}
	in, err := cc.FS().Open(abs, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	_, err = io.Copy(tw, in)
	return err
}

func tarRead(cc *gosh.CommandContext, opts tarOptions, extract bool) error {
	var in io.Reader = cc.Stdin
	if opts.file != "-" {
		f, err := cc.FS().Open(cc.ResolvePath(opts.file), os.O_RDONLY, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}
	if opts.gzip {
		zr, err := gzip.NewReader(in)
		if err != nil {
			return err
		}
		defer zr.Close()
		in = zr
	}
	tr := tar.NewReader(in)
	dest := cc.Cwd()
	if opts.cwd != "" {
		dest = cc.ResolvePath(opts.cwd)
	}
	perEntry, totalCap := archiveLimits(cc)
	var total int64
	var entries int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		entries++
		if entries > maxArchiveEntries {
			return fmt.Errorf("archive entry count exceeds limit %d", maxArchiveEntries)
		}
		if extract && invalidArchivePath(hdr.Name) {
			return fmt.Errorf("%s: unsafe archive path", hdr.Name)
		}
		name, ok := stripComponents(hdr.Name, opts.stripComponents)
		if !ok {
			continue
		}
		if !extract {
			fmt.Fprintln(cc.Stdout, name)
			continue
		}
		if err := extractTarEntry(cc, tr, hdr, dest, name, perEntry, totalCap, &total); err != nil {
			return err
		}
		if opts.verbose {
			fmt.Fprintln(cc.Stdout, name)
		}
	}
}

func extractTarEntry(cc *gosh.CommandContext, tr *tar.Reader, hdr *tar.Header, dest, name string, perEntry, totalCap int64, total *int64) error {
	target, cleanName, err := safeArchivePath(cc, dest, name)
	if err != nil {
		return fmt.Errorf("%s: %w", hdr.Name, err)
	}
	switch hdr.Typeflag {
	case tar.TypeDir:
		if err := rejectExistingSymlinkPath(cc, dest, target, cleanName); err != nil {
			return err
		}
		return cc.FS().MkdirAll(target, 0o755)
	case tar.TypeReg, tar.TypeRegA:
		if err := rejectExistingSymlinkPath(cc, dest, target, cleanName); err != nil {
			return err
		}
		data, err := readAllLimited(tr, perEntry)
		if err != nil {
			return err
		}
		if *total+int64(len(data)) > totalCap {
			return fmt.Errorf("decompressed archive size exceeds limit %d bytes", totalCap)
		}
		if err := cc.FS().MkdirAll(path.Dir(target), 0o755); err != nil {
			return err
		}
		if err := writeFile(cc, target, data, fs.FileMode(hdr.Mode)&fs.ModePerm); err != nil {
			return err
		}
		*total += int64(len(data))
		return nil
	case tar.TypeSymlink:
		if err := rejectExistingSymlinkPath(cc, dest, target, cleanName); err != nil {
			return err
		}
		linkTarget, err := safeSymlinkTarget(cc, dest, target, hdr.Linkname)
		if err != nil {
			return fmt.Errorf("%s: %w", hdr.Name, err)
		}
		if err := cc.FS().MkdirAll(path.Dir(target), 0o755); err != nil {
			return err
		}
		return cc.FS().Symlink(linkTarget, target)
	case tar.TypeLink:
		linkAbs, linkClean, err := safeArchivePath(cc, dest, hdr.Linkname)
		if err != nil {
			return fmt.Errorf("%s: %w", hdr.Name, err)
		}
		// Reject hardlinks whose source path traverses a pre-existing symlink:
		// FS.Link follows symlinks, so without this a hardlink could reference an
		// inode reached by escaping the extraction destination (S4).
		if err := rejectExistingSymlinkPath(cc, dest, linkAbs, linkClean); err != nil {
			return err
		}
		if err := rejectExistingSymlinkPath(cc, dest, target, cleanName); err != nil {
			return err
		}
		if err := cc.FS().MkdirAll(path.Dir(target), 0o755); err != nil {
			return err
		}
		return cc.FS().Link(linkAbs, target)
	default:
		return fmt.Errorf("%s: unsupported tar entry type %d", hdr.Name, hdr.Typeflag)
	}
}

func writeFile(cc *gosh.CommandContext, abs string, data []byte, perm fs.FileMode) error {
	if perm == 0 {
		perm = 0o644
	}
	f, err := cc.FS().Open(abs, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

func readAllLimited(r io.Reader, limit int64) ([]byte, error) {
	var buf bytes.Buffer
	err := copyLimited(&buf, r, limit)
	return buf.Bytes(), err
}

func copyLimited(dst io.Writer, src io.Reader, limit int64) error {
	var written int64
	buf := make([]byte, 32*1024)
	for {
		remaining := limit - written
		if remaining < 0 {
			remaining = 0
		}
		readSize := len(buf)
		if remaining < int64(readSize) {
			readSize = int(remaining) + 1
		}
		if readSize <= 0 {
			readSize = 1
		}
		n, err := src.Read(buf[:readSize])
		if n > 0 {
			if written+int64(n) > limit {
				allowed := limit - written
				if allowed > 0 {
					if _, werr := dst.Write(buf[:allowed]); werr != nil {
						return werr
					}
				}
				return fmt.Errorf("decompressed data exceeds limit %d bytes", limit)
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
			written += int64(n)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func resolveAgainst(cc *gosh.CommandContext, base, p string) string {
	if path.IsAbs(p) {
		return cc.ResolvePath(p)
	}
	return cc.ResolvePath(path.Join(base, p))
}

func archiveName(name string) string {
	name = strings.TrimPrefix(path.Clean(name), "/")
	if name == "" {
		return "."
	}
	return name
}

func safeArchivePath(cc *gosh.CommandContext, dest, name string) (string, string, error) {
	if invalidArchivePath(name) {
		return "", "", errors.New("unsafe archive path")
	}
	clean := path.Clean(name)
	if clean == "." {
		return dest, clean, nil
	}
	target := cc.ResolvePath(path.Join(dest, clean))
	if !within(dest, target) {
		return "", "", errors.New("archive path escapes destination")
	}
	return target, clean, nil
}

func invalidArchivePath(name string) bool {
	if name == "" || strings.ContainsRune(name, '\x00') || strings.Contains(name, "\\") {
		return true
	}
	if path.IsAbs(name) || strings.HasPrefix(name, "//") {
		return true
	}
	if len(name) >= 2 && name[1] == ':' && unicode.IsLetter(rune(name[0])) {
		return true
	}
	return false
}

func safeSymlinkTarget(cc *gosh.CommandContext, dest, linkAbs, target string) (string, error) {
	if invalidArchivePath(target) {
		return "", errors.New("unsafe symlink target")
	}
	resolved := cc.ResolvePath(path.Join(path.Dir(linkAbs), target))
	if !within(dest, resolved) {
		return "", errors.New("symlink target escapes destination")
	}
	return target, nil
}

func within(base, target string) bool {
	base = path.Clean(base)
	target = path.Clean(target)
	if base == "/" {
		return strings.HasPrefix(target, "/")
	}
	return target == base || strings.HasPrefix(target, base+"/")
}

func rejectExistingSymlinkPath(cc *gosh.CommandContext, dest, target, cleanName string) error {
	if cleanName == "." {
		return nil
	}
	parts := strings.Split(cleanName, "/")
	cur := dest
	for _, part := range parts {
		cur = path.Join(cur, part)
		info, err := cc.FS().Lstat(cur)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write through symlink %s", cur)
		}
		if cur == target {
			return nil
		}
	}
	return nil
}

func stripComponents(name string, n int) (string, bool) {
	name = path.Clean(name)
	if name == "." {
		return name, n == 0
	}
	parts := strings.Split(strings.Trim(name, "/"), "/")
	if n >= len(parts) {
		return "", false
	}
	return path.Join(parts[n:]...), true
}
