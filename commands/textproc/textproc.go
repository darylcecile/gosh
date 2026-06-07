// Package textproc provides sandboxed text-processing commands for gosh.
package textproc

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/darylcecile/gosh"
)

// Commands returns the text-processing command set.
func Commands() []gosh.Command {
	names := []string{"grep", "egrep", "fgrep", "cut", "tr", "sort", "uniq", "wc", "head", "tail", "tac", "rev", "nl", "paste", "join", "comm", "column", "fold", "expand", "unexpand", "diff", "od", "strings", "xargs", "split"}
	cmds := make([]gosh.Command, 0, len(names))
	for _, name := range names {
		n := name
		cmds = append(cmds, gosh.CommandFunc(n, func(ctx context.Context, cc *gosh.CommandContext) int { return run(ctx, cc) }))
	}
	return cmds
}

func run(ctx context.Context, cc *gosh.CommandContext) int {
	switch cc.Name {
	case "grep", "egrep", "fgrep":
		return cmdGrep(ctx, cc)
	case "cut":
		return cmdCut(ctx, cc)
	case "tr":
		return cmdTr(ctx, cc)
	case "sort":
		return cmdSort(ctx, cc)
	case "uniq":
		return cmdUniq(ctx, cc)
	case "wc":
		return cmdWC(ctx, cc)
	case "head":
		return cmdHeadTail(ctx, cc, true)
	case "tail":
		return cmdHeadTail(ctx, cc, false)
	case "tac":
		return cmdTac(ctx, cc)
	case "rev":
		return cmdRev(ctx, cc)
	case "nl":
		return cmdNL(ctx, cc)
	case "paste":
		return cmdPaste(ctx, cc)
	case "join":
		return cmdJoin(ctx, cc)
	case "comm":
		return cmdComm(ctx, cc)
	case "column":
		return cmdColumn(ctx, cc)
	case "fold":
		return cmdFold(ctx, cc)
	case "expand":
		return cmdExpand(ctx, cc, false)
	case "unexpand":
		return cmdExpand(ctx, cc, true)
	case "diff":
		return cmdDiff(ctx, cc)
	case "od":
		return cmdOD(ctx, cc)
	case "strings":
		return cmdStrings(ctx, cc)
	case "xargs":
		return cmdXargs(ctx, cc)
	case "split":
		return cmdSplit(ctx, cc)
	}
	return 127
}

func wantHelp(cc *gosh.CommandContext) bool { return cc.WantsHelp() }
func errf(cc *gosh.CommandContext, f string, a ...any) {
	fmt.Fprintf(cc.Stderr, "%s: %s\n", cc.Name, fmt.Sprintf(f, a...))
}
func tick(ctx context.Context, cc *gosh.CommandContext) bool {
	select {
	case <-ctx.Done():
		errf(cc, "%v", ctx.Err())
		return false
	default:
	}
	if e := cc.Governor().StreamTick(); e != nil {
		errf(cc, "%v", e)
		return false
	}
	return true
}
func openRead(cc *gosh.CommandContext, name string) (io.ReadCloser, error) {
	f, err := cc.FS().Open(cc.ResolvePath(name), os.O_RDONLY, fs.FileMode(0))
	if err != nil {
		return nil, err
	}
	return f, nil
}
func readAll(ctx context.Context, cc *gosh.CommandContext, name string) ([]byte, error) {
	if name == "-" {
		return io.ReadAll(cc.Stdin)
	}
	r, err := openRead(cc, name)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
func inputNames(args []string) []string {
	if len(args) == 0 {
		return []string{"-"}
	}
	return args
}
func forEachLine(ctx context.Context, cc *gosh.CommandContext, files []string, fn func(file, line string, no int) error) error {
	for _, name := range inputNames(files) {
		var r io.Reader
		var closer io.Closer
		if name == "-" {
			r = cc.Stdin
		} else {
			f, err := openRead(cc, name)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			r = f
			closer = f
		}
		s := bufio.NewScanner(r)
		s.Buffer(make([]byte, 4096), 16<<20)
		no := 0
		for s.Scan() {
			if !tick(ctx, cc) {
				if closer != nil {
					_ = closer.Close()
				}
				return fmt.Errorf("stopped")
			}
			no++
			if err := fn(name, s.Text(), no); err != nil {
				if closer != nil {
					_ = closer.Close()
				}
				return err
			}
		}
		if closer != nil {
			_ = closer.Close()
		}
		if err := s.Err(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// grep
func cmdGrep(ctx context.Context, cc *gosh.CommandContext) int {
	if len(cc.Args) == 1 && (cc.Args[0] == "--help" || cc.Args[0] == "-h") {
		return cc.PrintHelp("grep [OPTIONS] PATTERN [FILE]...", "Search for PATTERN in files or standard input.")
	}
	ignore, invert, nums, count, list, only, word, fixed, rec, quiet := false, false, false, false, false, false, false, false, false, false
	showName := "auto"
	args := []string{}
	for i := 0; i < len(cc.Args); i++ {
		a := cc.Args[i]
		if a == "--" {
			args = append(args, cc.Args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			args = append(args, cc.Args[i:]...)
			break
		}
		for _, ch := range a[1:] {
			switch ch {
			case 'i':
				ignore = true
			case 'v':
				invert = true
			case 'n':
				nums = true
			case 'c':
				count = true
			case 'l':
				list = true
			case 'o':
				only = true
			case 'w':
				word = true
			case 'E':
				fixed = false
			case 'F':
				fixed = true
			case 'r', 'R':
				rec = true
			case 'H':
				showName = "yes"
			case 'h':
				showName = "no"
			case 'q':
				quiet = true
			default:
				errf(cc, "unsupported option -%c", ch)
				return 2
			}
		}
	}
	if cc.Name == "fgrep" {
		fixed = true
	}
	if cc.Name == "egrep" {
		fixed = false
	}
	if len(args) == 0 {
		errf(cc, "missing pattern")
		return 2
	}
	pat, files := args[0], args[1:]
	if word {
		pat = `\b` + pat + `\b`
	}
	if fixed {
		pat = regexp.QuoteMeta(args[0])
		if word {
			pat = `\b` + pat + `\b`
		}
	}
	if ignore {
		pat = "(?i)" + pat
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		errf(cc, "%v", err)
		return 2
	}
	if rec {
		files = expandRecursive(cc, files)
	}
	if len(files) == 0 {
		files = []string{"-"}
	}
	multi := len(files) > 1
	matchedAny := false
	hadErr := false
	for _, file := range files {
		matches := 0
		fileMatched := false
		err := forEachLine(ctx, cc, []string{file}, func(name, line string, no int) error {
			m := re.MatchString(line)
			if invert {
				m = !m
			}
			if !m {
				return nil
			}
			matchedAny = true
			fileMatched = true
			matches++
			if quiet {
				return io.EOF
			}
			if list || count {
				return nil
			}
			prefix := ""
			if showName == "yes" || (showName == "auto" && multi && name != "-") {
				prefix += name + ":"
			}
			if nums {
				prefix += strconv.Itoa(no) + ":"
			}
			if only && !invert {
				locs := re.FindAllStringIndex(line, -1)
				for _, loc := range locs {
					fmt.Fprintln(cc.Stdout, prefix+line[loc[0]:loc[1]])
				}
			} else {
				fmt.Fprintln(cc.Stdout, prefix+line)
			}
			return nil
		})
		if err != nil && err != io.EOF {
			errf(cc, "%v", err)
			hadErr = true
		}
		if quiet && fileMatched {
			return 0
		}
		if list && fileMatched {
			fmt.Fprintln(cc.Stdout, file)
		}
		if count {
			prefix := ""
			if showName == "yes" || (showName == "auto" && multi && file != "-") {
				prefix = file + ":"
			}
			fmt.Fprintf(cc.Stdout, "%s%d\n", prefix, matches)
		}
	}
	if hadErr {
		return 2
	}
	if matchedAny {
		return 0
	}
	return 1
}
func expandRecursive(cc *gosh.CommandContext, files []string) []string {
	if len(files) == 0 {
		files = []string{"."}
	}
	var out []string
	var walk func(string)
	walk = func(p string) {
		abs := cc.ResolvePath(p)
		info, err := cc.FS().Stat(abs)
		if err != nil {
			out = append(out, p)
			return
		}
		if !info.IsDir() {
			out = append(out, p)
			return
		}
		ents, err := cc.FS().ReadDir(abs)
		if err != nil {
			return
		}
		for _, e := range ents {
			walk(path.Join(abs, e.Name()))
		}
	}
	for _, f := range files {
		walk(f)
	}
	return out
}

// cut
func cmdCut(ctx context.Context, cc *gosh.CommandContext) int {
	if wantHelp(cc) {
		return cc.PrintHelp("cut [-d DELIM] (-f LIST|-c LIST) [FILE]...", "Select fields or characters from input.")
	}
	delim := "\t"
	fieldMode, charMode := false, false
	spec := ""
	comp, onlyDelim := false, false
	files := []string{}
	for i := 0; i < len(cc.Args); i++ {
		a := cc.Args[i]
		switch {
		case a == "--complement":
			comp = true
		case a == "-s":
			onlyDelim = true
		case a == "-d" && i+1 < len(cc.Args):
			i++
			delim = cc.Args[i]
		case strings.HasPrefix(a, "-d") && len(a) > 2:
			delim = a[2:]
		case a == "-f" && i+1 < len(cc.Args):
			i++
			fieldMode = true
			spec = cc.Args[i]
		case strings.HasPrefix(a, "-f") && len(a) > 2:
			fieldMode = true
			spec = a[2:]
		case a == "-c" && i+1 < len(cc.Args):
			i++
			charMode = true
			spec = cc.Args[i]
		case strings.HasPrefix(a, "-c") && len(a) > 2:
			charMode = true
			spec = a[2:]
		default:
			files = append(files, a)
		}
	}
	if (!fieldMode && !charMode) || spec == "" {
		errf(cc, "missing list")
		return 1
	}
	sel := parseList(spec)
	err := forEachLine(ctx, cc, files, func(_ string, line string, _ int) error {
		if fieldMode {
			if !strings.Contains(line, delim) {
				if !onlyDelim {
					fmt.Fprintln(cc.Stdout, line)
				}
				return nil
			}
			parts := strings.Split(line, delim)
			out := []string{}
			for i, p := range parts {
				take := sel[i+1]
				if comp {
					take = !take
				}
				if take {
					out = append(out, p)
				}
			}
			fmt.Fprintln(cc.Stdout, strings.Join(out, delim))
		} else {
			rs := []rune(line)
			out := []rune{}
			for i, r := range rs {
				take := sel[i+1]
				if comp {
					take = !take
				}
				if take {
					out = append(out, r)
				}
			}
			fmt.Fprintln(cc.Stdout, string(out))
		}
		return nil
	})
	if err != nil {
		errf(cc, "%v", err)
		return 1
	}
	return 0
}
func parseList(s string) map[int]bool {
	m := map[int]bool{}
	for _, p := range strings.Split(s, ",") {
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			ab := strings.SplitN(p, "-", 2)
			start := 1
			end := 1000000
			if ab[0] != "" {
				start, _ = strconv.Atoi(ab[0])
			}
			if ab[1] != "" {
				end, _ = strconv.Atoi(ab[1])
			}
			for i := start; i <= end && i < 1000000; i++ {
				m[i] = true
			}
		} else {
			n, _ := strconv.Atoi(p)
			if n > 0 {
				m[n] = true
			}
		}
	}
	return m
}

// tr
func cmdTr(ctx context.Context, cc *gosh.CommandContext) int {
	if wantHelp(cc) {
		return cc.PrintHelp("tr [-d] [-s] SET1 [SET2]", "Translate, delete, or squeeze characters.")
	}
	del, sq := false, false
	args := []string{}
	for _, a := range cc.Args {
		if a == "-d" {
			del = true
		} else if a == "-s" {
			sq = true
		} else {
			args = append(args, a)
		}
	}
	if len(args) < 1 {
		errf(cc, "missing operand")
		return 1
	}
	set1 := expandSet(args[0])
	set2 := ""
	if len(args) > 1 {
		set2 = expandSet(args[1])
	}
	data, err := io.ReadAll(cc.Stdin)
	if err != nil {
		errf(cc, "%v", err)
		return 1
	}
	trans := map[rune]rune{}
	dels := map[rune]bool{}
	r1 := []rune(set1)
	r2 := []rune(set2)
	for i, r := range r1 {
		if del {
			dels[r] = true
		} else if len(r2) > 0 {
			j := i
			if j >= len(r2) {
				j = len(r2) - 1
			}
			trans[r] = r2[j]
		}
	}
	var b strings.Builder
	var prev rune
	have := false
	sqset := map[rune]bool{}
	sqRunes := r1
	if !del && len(r2) > 0 {
		sqRunes = r2
	}
	for _, r := range sqRunes {
		sqset[r] = true
	}
	for _, r := range string(data) {
		if dels[r] {
			continue
		}
		if to, ok := trans[r]; ok {
			r = to
		}
		if sq && have && r == prev && sqset[r] {
			continue
		}
		b.WriteRune(r)
		prev = r
		have = true
	}
	_, _ = io.WriteString(cc.Stdout, b.String())
	_ = ctx
	return 0
}
func expandSet(s string) string {
	classes := map[string]string{"[:upper:]": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "[:lower:]": "abcdefghijklmnopqrstuvwxyz", "[:digit:]": "0123456789", "[:space:]": " \t\n\r\v\f", "[:alpha:]": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "[:alnum:]": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"}
	for k, v := range classes {
		s = strings.ReplaceAll(s, k, v)
	}
	rs := []rune(s)
	var out []rune
	for i := 0; i < len(rs); i++ {
		if i+2 < len(rs) && rs[i+1] == '-' && rs[i] <= rs[i+2] {
			for r := rs[i]; r <= rs[i+2]; r++ {
				out = append(out, r)
			}
			i += 2
		} else {
			out = append(out, rs[i])
		}
	}
	return string(out)
}

// sort/uniq/wc/head/tail basics
func cmdSort(ctx context.Context, cc *gosh.CommandContext) int {
	if wantHelp(cc) {
		return cc.PrintHelp("sort [-nruffs] [-k KEY] [-t SEP] [FILE]...", "Sort lines of text.")
	}
	numeric, rev, uniq, fold := false, false, false, false
	key := 0
	sep := ""
	files := []string{}
	for i := 0; i < len(cc.Args); i++ {
		a := cc.Args[i]
		switch {
		case a == "-n":
			numeric = true
		case a == "-r":
			rev = true
		case a == "-u":
			uniq = true
		case a == "-f":
			fold = true
		case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "-k") && !strings.HasPrefix(a, "-t") && a != "-":
			for _, c := range a[1:] {
				switch c {
				case 'n':
					numeric = true
				case 'r':
					rev = true
				case 'u':
					uniq = true
				case 'f':
					fold = true
				}
			}
		case a == "-k" && i+1 < len(cc.Args):
			i++
			key = parseKey(cc.Args[i])
		case strings.HasPrefix(a, "-k") && len(a) > 2:
			key = parseKey(a[2:])
		case a == "-t" && i+1 < len(cc.Args):
			i++
			sep = cc.Args[i]
		default:
			files = append(files, a)
		}
	}
	lines := []string{}
	err := forEachLine(ctx, cc, files, func(_, l string, _ int) error { lines = append(lines, l); return nil })
	if err != nil {
		errf(cc, "%v", err)
		return 1
	}
	val := func(s string) string {
		if key > 0 {
			fs := fieldsWithSep(s, sep)
			if key <= len(fs) {
				s = fs[key-1]
			} else {
				s = ""
			}
		}
		if fold {
			s = strings.ToLower(s)
		}
		return s
	}
	sort.SliceStable(lines, func(i, j int) bool {
		a, b := val(lines[i]), val(lines[j])
		less := a < b
		if numeric {
			af, _ := strconv.ParseFloat(strings.TrimSpace(a), 64)
			bf, _ := strconv.ParseFloat(strings.TrimSpace(b), 64)
			less = af < bf
		}
		if rev {
			return !less && a != b
		}
		return less
	})
	if uniq {
		out := lines[:0]
		seen := map[string]bool{}
		for _, l := range lines {
			k := val(l)
			if !seen[k] {
				seen[k] = true
				out = append(out, l)
			}
		}
		lines = out
	}
	for _, l := range lines {
		fmt.Fprintln(cc.Stdout, l)
	}
	return 0
}
func parseKey(s string) int {
	p := strings.Split(s, ",")[0]
	p = strings.Split(p, ".")[0]
	n, _ := strconv.Atoi(p)
	return n
}
func fieldsWithSep(s, sep string) []string {
	if sep != "" {
		return strings.Split(s, sep)
	}
	return strings.Fields(s)
}
func cmdUniq(ctx context.Context, cc *gosh.CommandContext) int {
	if wantHelp(cc) {
		return cc.PrintHelp("uniq [-cdui] [FILE]", "Report or omit repeated adjacent lines.")
	}
	count, dups, uniqOnly, fold := false, false, false, false
	files := []string{}
	for _, a := range cc.Args {
		if strings.HasPrefix(a, "-") && a != "-" {
			for _, c := range a[1:] {
				switch c {
				case 'c':
					count = true
				case 'd':
					dups = true
				case 'u':
					uniqOnly = true
				case 'i':
					fold = true
				}
			}
		} else {
			files = append(files, a)
		}
	}
	var cur string
	n := 0
	first := true
	emit := func() {
		if first {
			return
		}
		ok := (!dups && !uniqOnly) || (dups && n > 1) || (uniqOnly && n == 1)
		if ok {
			if count {
				fmt.Fprintf(cc.Stdout, "%7d %s\n", n, cur)
			} else {
				fmt.Fprintln(cc.Stdout, cur)
			}
		}
	}
	err := forEachLine(ctx, cc, files, func(_, l string, _ int) error {
		k := l
		ck := cur
		if fold {
			k = strings.ToLower(k)
			ck = strings.ToLower(ck)
		}
		if first {
			cur = l
			n = 1
			first = false
		} else if k == ck {
			n++
		} else {
			emit()
			cur = l
			n = 1
		}
		return nil
	})
	if err != nil {
		errf(cc, "%v", err)
		return 1
	}
	emit()
	return 0
}
func cmdWC(ctx context.Context, cc *gosh.CommandContext) int {
	if wantHelp(cc) {
		return cc.PrintHelp("wc [-lwcml] [FILE]...", "Count lines, words, bytes, and characters.")
	}
	fl, fw, fb, fm := false, false, false, false
	files := []string{}
	for _, a := range cc.Args {
		if strings.HasPrefix(a, "-") && a != "-" {
			for _, c := range a[1:] {
				switch c {
				case 'l':
					fl = true
				case 'w':
					fw = true
				case 'c':
					fb = true
				case 'm':
					fm = true
				}
			}
		} else {
			files = append(files, a)
		}
	}
	if !fl && !fw && !fb && !fm {
		fl, fw, fb = true, true, true
	}
	names := inputNames(files)
	totals := [4]int{}
	for _, name := range names {
		data, err := readAll(ctx, cc, name)
		if err != nil {
			errf(cc, "%s: %v", name, err)
			return 1
		}
		vals := [4]int{bytes.Count(data, []byte("\n")), len(strings.Fields(string(data))), len(data), utf8.RuneCount(data)}
		for i := range vals {
			totals[i] += vals[i]
		}
		printCounts(cc, fl, fw, fb, fm, vals, func() string {
			if len(names) > 1 {
				return name
			}
			return ""
		}())
	}
	if len(names) > 1 {
		printCounts(cc, fl, fw, fb, fm, totals, "total")
	}
	return 0
}
func printCounts(cc *gosh.CommandContext, l, w, b, m bool, v [4]int, name string) {
	parts := []string{}
	if l {
		parts = append(parts, fmt.Sprintf("%7d", v[0]))
	}
	if w {
		parts = append(parts, fmt.Sprintf("%7d", v[1]))
	}
	if b {
		parts = append(parts, fmt.Sprintf("%7d", v[2]))
	}
	if m {
		parts = append(parts, fmt.Sprintf("%7d", v[3]))
	}
	if name != "" {
		parts = append(parts, name)
	}
	fmt.Fprintln(cc.Stdout, strings.Join(parts, " "))
}
func cmdHeadTail(ctx context.Context, cc *gosh.CommandContext, head bool) int {
	name := "head"
	if !head {
		name = "tail"
	}
	if wantHelp(cc) {
		return cc.PrintHelp(name+" [-n N|-c N] [FILE]...", "Print the first or last part of files.")
	}
	mode := "n"
	spec := "10"
	files := []string{}
	for i := 0; i < len(cc.Args); i++ {
		a := cc.Args[i]
		switch {
		case a == "-n" && i+1 < len(cc.Args):
			i++
			mode = "n"
			spec = cc.Args[i]
		case a == "-c" && i+1 < len(cc.Args):
			i++
			mode = "c"
			spec = cc.Args[i]
		case strings.HasPrefix(a, "-n") && len(a) > 2:
			mode = "n"
			spec = a[2:]
		case strings.HasPrefix(a, "-c") && len(a) > 2:
			mode = "c"
			spec = a[2:]
		default:
			files = append(files, a)
		}
	}
	_ = ctx
	for _, file := range inputNames(files) {
		data, err := readAll(ctx, cc, file)
		if err != nil {
			errf(cc, "%s: %v", file, err)
			return 1
		}
		out := sliceHeadTail(data, mode, spec, head)
		_, _ = cc.Stdout.Write(out)
	}
	return 0
}
func sliceHeadTail(data []byte, mode, spec string, head bool) []byte {
	n, _ := strconv.Atoi(strings.TrimPrefix(spec, "+"))
	if n < 0 {
		n = -n
	}
	if mode == "c" {
		if head {
			if strings.HasPrefix(spec, "-") {
				if n > len(data) {
					n = len(data)
				}
				return data[:len(data)-n]
			}
			if n > len(data) {
				n = len(data)
			}
			return data[:n]
		}
		if strings.HasPrefix(spec, "+") {
			idx := n - 1
			if idx < 0 {
				idx = 0
			}
			if idx > len(data) {
				return nil
			}
			return data[idx:]
		}
		if n > len(data) {
			n = len(data)
		}
		return data[len(data)-n:]
	}
	lines := strings.SplitAfter(string(data), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if head {
		if strings.HasPrefix(spec, "-") {
			keep := len(lines) - n
			if keep < 0 {
				keep = 0
			}
			return []byte(strings.Join(lines[:keep], ""))
		}
		if n > len(lines) {
			n = len(lines)
		}
		return []byte(strings.Join(lines[:n], ""))
	}
	if strings.HasPrefix(spec, "+") {
		idx := n - 1
		if idx < 0 {
			idx = 0
		}
		if idx > len(lines) {
			return nil
		}
		return []byte(strings.Join(lines[idx:], ""))
	}
	if n > len(lines) {
		n = len(lines)
	}
	return []byte(strings.Join(lines[len(lines)-n:], ""))
}

func cmdTac(ctx context.Context, cc *gosh.CommandContext) int {
	if wantHelp(cc) {
		return cc.PrintHelp("tac [FILE]...", "Concatenate and print files in reverse line order.")
	}
	for _, f := range inputNames(cc.Args) {
		data, err := readAll(ctx, cc, f)
		if err != nil {
			errf(cc, "%s: %v", f, err)
			return 1
		}
		lines := strings.SplitAfter(string(data), "\n")
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		for i := len(lines) - 1; i >= 0; i-- {
			io.WriteString(cc.Stdout, lines[i])
		}
	}
	return 0
}
func cmdRev(ctx context.Context, cc *gosh.CommandContext) int {
	if wantHelp(cc) {
		return cc.PrintHelp("rev [FILE]...", "Reverse characters in each line.")
	}
	err := forEachLine(ctx, cc, cc.Args, func(_, l string, _ int) error {
		r := []rune(l)
		for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
			r[i], r[j] = r[j], r[i]
		}
		fmt.Fprintln(cc.Stdout, string(r))
		return nil
	})
	if err != nil {
		errf(cc, "%v", err)
		return 1
	}
	return 0
}
func cmdNL(ctx context.Context, cc *gosh.CommandContext) int {
	if wantHelp(cc) {
		return cc.PrintHelp("nl [-b STYLE] [FILE]...", "Number lines.")
	}
	style := "t"
	files := []string{}
	for i := 0; i < len(cc.Args); i++ {
		if cc.Args[i] == "-b" && i+1 < len(cc.Args) {
			i++
			style = cc.Args[i]
		} else {
			files = append(files, cc.Args[i])
		}
	}
	n := 1
	err := forEachLine(ctx, cc, files, func(_, l string, _ int) error {
		num := style == "a" || (style == "t" && l != "")
		if num {
			fmt.Fprintf(cc.Stdout, "%6d\t%s\n", n, l)
			n++
		} else {
			fmt.Fprintln(cc.Stdout, l)
		}
		return nil
	})
	if err != nil {
		errf(cc, "%v", err)
		return 1
	}
	return 0
}
func cmdPaste(ctx context.Context, cc *gosh.CommandContext) int {
	if wantHelp(cc) {
		return cc.PrintHelp("paste [-s] [-d DELIMS] [FILE]...", "Merge lines of files.")
	}
	serial := false
	delims := "\t"
	files := []string{}
	for i := 0; i < len(cc.Args); i++ {
		a := cc.Args[i]
		if a == "-s" {
			serial = true
		} else if strings.HasPrefix(a, "-s") && strings.Contains(a, "d") && len(a) > 3 {
			serial = true
			delims = a[strings.Index(a, "d")+1:]
		} else if a == "-d" && i+1 < len(cc.Args) {
			i++
			delims = cc.Args[i]
		} else {
			files = append(files, a)
		}
	}
	all := [][]string{}
	for _, f := range inputNames(files) {
		data, err := readAll(ctx, cc, f)
		if err != nil {
			errf(cc, "%s: %v", f, err)
			return 1
		}
		all = append(all, splitLinesNoNL(string(data)))
	}
	if serial {
		for _, ls := range all {
			fmt.Fprintln(cc.Stdout, joinCycle(ls, delims))
		}
	} else {
		max := 0
		for _, ls := range all {
			if len(ls) > max {
				max = len(ls)
			}
		}
		for i := 0; i < max; i++ {
			row := []string{}
			for _, ls := range all {
				if i < len(ls) {
					row = append(row, ls[i])
				} else {
					row = append(row, "")
				}
			}
			fmt.Fprintln(cc.Stdout, joinCycle(row, delims))
		}
	}
	return 0
}
func splitLinesNoNL(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}
func joinCycle(xs []string, d string) string {
	if len(xs) == 0 {
		return ""
	}
	var b strings.Builder
	for i, x := range xs {
		if i > 0 {
			b.WriteByte(d[(i-1)%len(d)])
		}
		b.WriteString(x)
	}
	return b.String()
}

func cmdJoin(ctx context.Context, cc *gosh.CommandContext) int {
	if wantHelp(cc) {
		return cc.PrintHelp("join FILE1 FILE2", "Join lines of two files on their first field.")
	}
	if len(cc.Args) != 2 {
		errf(cc, "need two files")
		return 1
	}
	a, _ := readAll(ctx, cc, cc.Args[0])
	b, _ := readAll(ctx, cc, cc.Args[1])
	m := map[string][]string{}
	for _, l := range splitLinesNoNL(string(b)) {
		fs := strings.Fields(l)
		if len(fs) > 0 {
			m[fs[0]] = append(m[fs[0]], l)
		}
	}
	for _, l := range splitLinesNoNL(string(a)) {
		fs := strings.Fields(l)
		if len(fs) > 0 {
			for _, r := range m[fs[0]] {
				rf := strings.Fields(r)
				fmt.Fprintln(cc.Stdout, strings.Join(append(fs, rf[1:]...), " "))
			}
		}
	}
	return 0
}
func cmdComm(ctx context.Context, cc *gosh.CommandContext) int {
	if wantHelp(cc) {
		return cc.PrintHelp("comm [-123] FILE1 FILE2", "Compare two sorted files line by line.")
	}
	s1, s2, s3 := true, true, true
	files := []string{}
	for _, a := range cc.Args {
		if strings.HasPrefix(a, "-") && a != "-" {
			for _, c := range a[1:] {
				if c == '1' {
					s1 = false
				} else if c == '2' {
					s2 = false
				} else if c == '3' {
					s3 = false
				}
			}
		} else {
			files = append(files, a)
		}
	}
	if len(files) != 2 {
		errf(cc, "need two files")
		return 1
	}
	da, _ := readAll(ctx, cc, files[0])
	db, _ := readAll(ctx, cc, files[1])
	a, b := splitLinesNoNL(string(da)), splitLinesNoNL(string(db))
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		if j >= len(b) || (i < len(a) && a[i] < b[j]) {
			if s1 {
				fmt.Fprintln(cc.Stdout, a[i])
			}
			i++
		} else if i >= len(a) || b[j] < a[i] {
			if s2 {
				pref := ""
				if s1 {
					pref = "\t"
				}
				fmt.Fprintln(cc.Stdout, pref+b[j])
			}
			j++
		} else {
			if s3 {
				pref := ""
				if s1 {
					pref += "\t"
				}
				if s2 {
					pref += "\t"
				}
				fmt.Fprintln(cc.Stdout, pref+a[i])
			}
			i++
			j++
		}
	}
	return 0
}
func cmdColumn(ctx context.Context, cc *gosh.CommandContext) int {
	if wantHelp(cc) {
		return cc.PrintHelp("column [-t] [-s SEP] [FILE]...", "Columnate lists.")
	}
	table := false
	sep := ""
	files := []string{}
	for i := 0; i < len(cc.Args); i++ {
		if cc.Args[i] == "-t" {
			table = true
		} else if cc.Args[i] == "-s" && i+1 < len(cc.Args) {
			i++
			sep = cc.Args[i]
		} else {
			files = append(files, cc.Args[i])
		}
	}
	lines := []string{}
	_ = forEachLine(ctx, cc, files, func(_, l string, _ int) error { lines = append(lines, l); return nil })
	if !table {
		for _, l := range lines {
			fmt.Fprintln(cc.Stdout, l)
		}
		return 0
	}
	rows := [][]string{}
	widths := []int{}
	for _, l := range lines {
		fs := fieldsWithSep(l, sep)
		rows = append(rows, fs)
		for i, f := range fs {
			if i >= len(widths) {
				widths = append(widths, 0)
			}
			if len(f) > widths[i] {
				widths[i] = len(f)
			}
		}
	}
	for _, r := range rows {
		for i, f := range r {
			if i > 0 {
				fmt.Fprint(cc.Stdout, "  ")
			}
			if i < len(r)-1 {
				fmt.Fprintf(cc.Stdout, "%-*s", widths[i], f)
			} else {
				fmt.Fprint(cc.Stdout, f)
			}
		}
		fmt.Fprintln(cc.Stdout)
	}
	return 0
}
func cmdFold(ctx context.Context, cc *gosh.CommandContext) int {
	if wantHelp(cc) {
		return cc.PrintHelp("fold [-w WIDTH] [-s] [FILE]...", "Wrap input lines.")
	}
	width := 80
	spaces := false
	files := []string{}
	for i := 0; i < len(cc.Args); i++ {
		a := cc.Args[i]
		if a == "-s" {
			spaces = true
		} else if a == "-w" && i+1 < len(cc.Args) {
			i++
			width, _ = strconv.Atoi(cc.Args[i])
		} else {
			files = append(files, a)
		}
	}
	if width <= 0 {
		width = 80
	}
	err := forEachLine(ctx, cc, files, func(_, l string, _ int) error {
		for len([]rune(l)) > width {
			rs := []rune(l)
			cut := width
			if spaces {
				for i := width; i > 0; i-- {
					if unicode.IsSpace(rs[i-1]) {
						cut = i
						break
					}
				}
			}
			fmt.Fprintln(cc.Stdout, string(rs[:cut]))
			l = strings.TrimLeftFunc(string(rs[cut:]), unicode.IsSpace)
		}
		fmt.Fprintln(cc.Stdout, l)
		return nil
	})
	if err != nil {
		errf(cc, "%v", err)
		return 1
	}
	return 0
}
func cmdExpand(ctx context.Context, cc *gosh.CommandContext, un bool) int {
	if wantHelp(cc) {
		if un {
			return cc.PrintHelp("unexpand [-a] [-t N] [FILE]...", "Convert spaces to tabs.")
		}
		return cc.PrintHelp("expand [-t N] [FILE]...", "Convert tabs to spaces.")
	}
	tab := 8
	all := false
	files := []string{}
	for i := 0; i < len(cc.Args); i++ {
		a := cc.Args[i]
		if a == "-a" {
			all = true
		} else if a == "-t" && i+1 < len(cc.Args) {
			i++
			tab, _ = strconv.Atoi(cc.Args[i])
		} else {
			files = append(files, a)
		}
	}
	err := forEachLine(ctx, cc, files, func(_, l string, _ int) error {
		if !un {
			col := 0
			for _, r := range l {
				if r == '\t' {
					n := tab - col%tab
					fmt.Fprint(cc.Stdout, strings.Repeat(" ", n))
					col += n
				} else {
					fmt.Fprint(cc.Stdout, string(r))
					col++
				}
			}
			fmt.Fprintln(cc.Stdout)
		} else {
			if all {
				l = spacesToTabs(l, tab)
			} else {
				pref := len(l) - len(strings.TrimLeft(l, " "))
				l = spacesToTabs(l[:pref], tab) + l[pref:]
			}
			fmt.Fprintln(cc.Stdout, l)
		}
		return nil
	})
	if err != nil {
		errf(cc, "%v", err)
		return 1
	}
	return 0
}
func spacesToTabs(s string, tab int) string {
	var b strings.Builder
	col := 0
	i := 0
	for i < len(s) {
		if s[i] == ' ' {
			j := i
			for j < len(s) && s[j] == ' ' {
				j++
			}
			n := j - i
			for n >= tab-col%tab {
				b.WriteByte('\t')
				n -= tab - col%tab
				if tab-col%tab == 0 {
					n -= tab
				}
				col += tab - col%tab
			}
			b.WriteString(strings.Repeat(" ", n))
			col += n
			i = j
		} else {
			b.WriteByte(s[i])
			col++
			i++
		}
	}
	return b.String()
}

func cmdDiff(ctx context.Context, cc *gosh.CommandContext) int {
	if wantHelp(cc) {
		return cc.PrintHelp("diff [-u] FILE1 FILE2", "Compare two files line by line.")
	}
	args := []string{}
	for _, a := range cc.Args {
		if a != "-u" {
			args = append(args, a)
		}
	}
	if len(args) != 2 {
		errf(cc, "need two files")
		return 2
	}
	a, erra := readAll(ctx, cc, args[0])
	b, errb := readAll(ctx, cc, args[1])
	if erra != nil || errb != nil {
		errf(cc, "cannot read files")
		return 2
	}
	if bytes.Equal(a, b) {
		return 0
	}
	al, bl := splitLinesNoNL(string(a)), splitLinesNoNL(string(b))
	fmt.Fprintf(cc.Stdout, "--- %s\n+++ %s\n@@ -1,%d +1,%d @@\n", args[0], args[1], len(al), len(bl))
	for _, l := range al {
		fmt.Fprintln(cc.Stdout, "-"+l)
	}
	for _, l := range bl {
		fmt.Fprintln(cc.Stdout, "+"+l)
	}
	return 1
}
func cmdOD(ctx context.Context, cc *gosh.CommandContext) int {
	if wantHelp(cc) {
		return cc.PrintHelp("od [-c] [-A x|d|n] [-t c|o] [FILE]", "Dump files in octal or characters.")
	}
	char := false
	addr := true
	files := []string{}
	for i := 0; i < len(cc.Args); i++ {
		a := cc.Args[i]
		if a == "-c" {
			char = true
		} else if a == "-t" && i+1 < len(cc.Args) {
			i++
			char = cc.Args[i] == "c"
		} else if a == "-A" && i+1 < len(cc.Args) {
			i++
			addr = cc.Args[i] != "n"
		} else {
			files = append(files, a)
		}
	}
	data := []byte{}
	for _, f := range inputNames(files) {
		d, err := readAll(ctx, cc, f)
		if err != nil {
			errf(cc, "%s: %v", f, err)
			return 1
		}
		data = append(data, d...)
	}
	for off := 0; off < len(data); off += 16 {
		if addr {
			fmt.Fprintf(cc.Stdout, "%07o", off)
		}
		end := off + 16
		if end > len(data) {
			end = len(data)
		}
		for _, c := range data[off:end] {
			if char {
				if c >= 32 && c < 127 {
					fmt.Fprintf(cc.Stdout, " %3c", c)
				} else {
					fmt.Fprintf(cc.Stdout, " %3s", escapeByte(c))
				}
			} else {
				fmt.Fprintf(cc.Stdout, " %03o", c)
			}
		}
		fmt.Fprintln(cc.Stdout)
	}
	if addr {
		fmt.Fprintf(cc.Stdout, "%07o\n", len(data))
	}
	return 0
}
func escapeByte(b byte) string {
	switch b {
	case '\n':
		return "\\n"
	case '\t':
		return "\\t"
	case 0:
		return "\\0"
	}
	return fmt.Sprintf("%03o", b)
}
func cmdStrings(ctx context.Context, cc *gosh.CommandContext) int {
	if wantHelp(cc) {
		return cc.PrintHelp("strings [-n MIN] [FILE]...", "Print printable character sequences.")
	}
	min := 4
	files := []string{}
	for i := 0; i < len(cc.Args); i++ {
		if cc.Args[i] == "-n" && i+1 < len(cc.Args) {
			i++
			min, _ = strconv.Atoi(cc.Args[i])
		} else {
			files = append(files, cc.Args[i])
		}
	}
	for _, f := range inputNames(files) {
		data, err := readAll(ctx, cc, f)
		if err != nil {
			errf(cc, "%s: %v", f, err)
			return 1
		}
		run := []byte{}
		flush := func() {
			if len(run) >= min {
				fmt.Fprintln(cc.Stdout, string(run))
			}
			run = nil
		}
		for _, b := range data {
			if b >= 32 && b < 127 {
				run = append(run, b)
			} else {
				flush()
			}
		}
		flush()
	}
	return 0
}
func cmdXargs(ctx context.Context, cc *gosh.CommandContext) int {
	if wantHelp(cc) {
		return cc.PrintHelp("xargs [-n N] [-I REPL] [-d DELIM] [-0] COMMAND [ARGS]...", "Build and execute command lines from standard input.")
	}
	max := 0
	repl := ""
	delim := ""
	cmd := []string{}
	for i := 0; i < len(cc.Args); i++ {
		a := cc.Args[i]
		switch {
		case a == "-n" && i+1 < len(cc.Args):
			i++
			max, _ = strconv.Atoi(cc.Args[i])
		case a == "-I" && i+1 < len(cc.Args):
			i++
			repl = cc.Args[i]
		case strings.HasPrefix(a, "-I") && len(a) > 2:
			repl = a[2:]
		case a == "-d" && i+1 < len(cc.Args):
			i++
			delim = cc.Args[i]
		case a == "-0":
			delim = "\x00"
		default:
			cmd = cc.Args[i:]
			i = len(cc.Args)
		}
	}
	if len(cmd) == 0 {
		cmd = []string{"echo"}
	}
	data, _ := io.ReadAll(cc.Stdin)
	items := splitXargs(string(data), delim)
	if repl != "" {
		code := 0
		for _, it := range items {
			argv := make([]string, len(cmd))
			for i, a := range cmd {
				argv[i] = strings.ReplaceAll(a, repl, it)
			}
			if c := cc.Exec(ctx, argv...); c != 0 {
				code = c
			}
		}
		return code
	}
	if max <= 0 {
		max = len(items)
		if max == 0 {
			max = 1
		}
	}
	code := 0
	for i := 0; i < len(items); i += max {
		end := i + max
		if end > len(items) {
			end = len(items)
		}
		argv := append(append([]string{}, cmd...), items[i:end]...)
		if c := cc.Exec(ctx, argv...); c != 0 {
			code = c
		}
	}
	return code
}
func splitXargs(s, delim string) []string {
	if delim == "\x00" {
		parts := strings.Split(strings.TrimSuffix(s, "\x00"), "\x00")
		if len(parts) == 1 && parts[0] == "" {
			return nil
		}
		return parts
	}
	if delim != "" {
		return strings.Split(strings.TrimSuffix(s, delim), delim)
	}
	return strings.Fields(s)
}
