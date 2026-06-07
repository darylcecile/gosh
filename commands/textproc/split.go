package textproc

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/darylcecile/gosh"
)

// cmdSplit implements a sandboxed subset of GNU split. It reads a single input
// (a FILE operand or stdin) and writes fixed-size pieces to the virtual
// filesystem as PREFIXaa, PREFIXab, ... Output files are subject to the same
// VFS size caps as any other write.
func cmdSplit(ctx context.Context, cc *gosh.CommandContext) int {
	if wantHelp(cc) {
		return cc.PrintHelp(
			"split [-l N | -b N] [-a LEN] [-d] [FILE [PREFIX]]",
			"Split a file into fixed-size pieces (default 1000 lines) written to the VFS.",
		)
	}

	mode := "l"           // "l" lines or "b" bytes
	var lineCount int64 = 1000
	var byteCount int64
	suffixLen := 2
	numeric := false
	operands := []string{}

	for i := 0; i < len(cc.Args); i++ {
		a := cc.Args[i]
		switch {
		case a == "-l" && i+1 < len(cc.Args):
			i++
			mode = "l"
			n, err := strconv.ParseInt(cc.Args[i], 10, 64)
			if err != nil || n <= 0 {
				errf(cc, "invalid number of lines: %q", cc.Args[i])
				return 1
			}
			lineCount = n
		case strings.HasPrefix(a, "-l") && len(a) > 2:
			mode = "l"
			n, err := strconv.ParseInt(a[2:], 10, 64)
			if err != nil || n <= 0 {
				errf(cc, "invalid number of lines: %q", a[2:])
				return 1
			}
			lineCount = n
		case a == "-b" && i+1 < len(cc.Args):
			i++
			n, err := parseByteSize(cc.Args[i])
			if err != nil {
				errf(cc, "invalid number of bytes: %q", cc.Args[i])
				return 1
			}
			mode = "b"
			byteCount = n
		case strings.HasPrefix(a, "-b") && len(a) > 2:
			n, err := parseByteSize(a[2:])
			if err != nil {
				errf(cc, "invalid number of bytes: %q", a[2:])
				return 1
			}
			mode = "b"
			byteCount = n
		case a == "-a" && i+1 < len(cc.Args):
			i++
			n, err := strconv.Atoi(cc.Args[i])
			if err != nil || n <= 0 {
				errf(cc, "invalid suffix length: %q", cc.Args[i])
				return 1
			}
			suffixLen = n
		case a == "-d":
			numeric = true
		case a == "-":
			operands = append(operands, a)
		case strings.HasPrefix(a, "-") && len(a) > 1:
			errf(cc, "unknown option: %q", a)
			return 1
		default:
			operands = append(operands, a)
		}
	}

	input := "-"
	prefix := "x"
	if len(operands) >= 1 {
		input = operands[0]
	}
	if len(operands) >= 2 {
		prefix = operands[1]
	}
	if len(operands) > 2 {
		errf(cc, "too many operands")
		return 1
	}

	data, err := readAll(ctx, cc, input)
	if err != nil {
		errf(cc, "%s: %v", input, err)
		return 1
	}

	var pieces [][]byte
	if mode == "b" {
		pieces = splitByBytes(data, byteCount)
	} else {
		pieces = splitByLines(data, lineCount)
	}

	for idx, piece := range pieces {
		if !tick(ctx, cc) {
			return 1
		}
		suffix, ok := suffixFor(idx, suffixLen, numeric)
		if !ok {
			errf(cc, "output file suffixes exhausted")
			return 1
		}
		name := cc.ResolvePath(prefix + suffix)
		f, err := cc.FS().Open(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			errf(cc, "%s: %v", prefix+suffix, err)
			return 1
		}
		if _, err := f.Write(piece); err != nil {
			_ = f.Close()
			errf(cc, "%s: %v", prefix+suffix, err)
			return 1
		}
		if err := f.Close(); err != nil {
			errf(cc, "%s: %v", prefix+suffix, err)
			return 1
		}
	}
	return 0
}

// splitByLines partitions data into chunks of at most n lines, preserving the
// original byte content (including trailing newline handling).
func splitByLines(data []byte, n int64) [][]byte {
	if len(data) == 0 {
		return nil
	}
	var pieces [][]byte
	var start int
	var lines int64
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			lines++
			if lines == n {
				pieces = append(pieces, data[start:i+1])
				start = i + 1
				lines = 0
			}
		}
	}
	if start < len(data) {
		pieces = append(pieces, data[start:])
	}
	return pieces
}

// splitByBytes partitions data into chunks of at most n bytes.
func splitByBytes(data []byte, n int64) [][]byte {
	if len(data) == 0 || n <= 0 {
		if len(data) == 0 {
			return nil
		}
		return [][]byte{data}
	}
	var pieces [][]byte
	for off := int64(0); off < int64(len(data)); off += n {
		end := off + n
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		pieces = append(pieces, data[off:end])
	}
	return pieces
}

// parseByteSize parses a byte count with optional K/M/G (binary) or KB/MB/GB
// (decimal) suffixes, mirroring GNU split's common forms.
func parseByteSize(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	mult := int64(1)
	upper := strings.ToUpper(s)
	switch {
	case strings.HasSuffix(upper, "KB"):
		mult, upper = 1000, strings.TrimSuffix(upper, "KB")
	case strings.HasSuffix(upper, "MB"):
		mult, upper = 1000*1000, strings.TrimSuffix(upper, "MB")
	case strings.HasSuffix(upper, "GB"):
		mult, upper = 1000*1000*1000, strings.TrimSuffix(upper, "GB")
	case strings.HasSuffix(upper, "K"):
		mult, upper = 1024, strings.TrimSuffix(upper, "K")
	case strings.HasSuffix(upper, "M"):
		mult, upper = 1024*1024, strings.TrimSuffix(upper, "M")
	case strings.HasSuffix(upper, "G"):
		mult, upper = 1024*1024*1024, strings.TrimSuffix(upper, "G")
	}
	n, err := strconv.ParseInt(upper, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid size")
	}
	return n * mult, nil
}

// suffixFor returns the split suffix for piece index idx. Alphabetic suffixes
// run aa..zz..; numeric suffixes run 00..99.. Returns ok=false when idx exceeds
// the addressable space for the given suffix length.
func suffixFor(idx, length int, numeric bool) (string, bool) {
	base := 26
	if numeric {
		base = 10
	}
	max := 1
	for i := 0; i < length; i++ {
		max *= base
	}
	if idx >= max {
		return "", false
	}
	buf := make([]byte, length)
	for pos := length - 1; pos >= 0; pos-- {
		d := idx % base
		idx /= base
		if numeric {
			buf[pos] = byte('0' + d)
		} else {
			buf[pos] = byte('a' + d)
		}
	}
	return string(buf), true
}
