package textlang

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/darylcecile/gosh"
)

type sedCommand struct{}

func (sedCommand) Name() string { return "sed" }

func (sedCommand) Run(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return cc.PrintHelp("sed [-nErs] [-i] [-e script] [-f scriptfile] [script] [file ...]", "Run a sandboxed pure-Go sed subset. Regexps use Go RE2 syntax; supported commands include s, p, d, n, q, =, and y.")
	}
	opts, err := parseSedArgs(cc)
	if err != nil {
		fmt.Fprintf(cc.Stderr, "sed: %v\n", err)
		return 2
	}
	cmds, err := parseSedProgram(opts.scripts, opts.quiet)
	if err != nil {
		fmt.Fprintf(cc.Stderr, "sed: %v\n", err)
		return 2
	}
	if len(cmds) == 0 {
		fmt.Fprintln(cc.Stderr, "sed: missing script")
		return 2
	}
	if opts.inPlace && (len(opts.files) == 0 || hasDash(opts.files)) {
		fmt.Fprintln(cc.Stderr, "sed: -i requires file operands")
		return 2
	}

	inputs, err := readSedInputs(cc, opts.files, opts.inPlace || opts.separate)
	if err != nil {
		fmt.Fprintf(cc.Stderr, "sed: %v\n", err)
		return 1
	}
	code := 0
	for _, in := range inputs {
		select {
		case <-ctx.Done():
			fmt.Fprintf(cc.Stderr, "sed: %v\n", ctx.Err())
			return 1
		default:
		}
		out, err := runSed(cc, cmds, in.lines)
		if err != nil {
			fmt.Fprintf(cc.Stderr, "sed: %v\n", err)
			return 1
		}
		if opts.inPlace {
			if err := writeVirtualFile(cc, in.name, out.String()); err != nil {
				fmt.Fprintf(cc.Stderr, "sed: %s: %v\n", in.name, err)
				code = 1
			}
		} else {
			_, _ = io.Copy(cc.Stdout, &out)
		}
	}
	return code
}

type sedOptions struct {
	scripts  []string
	files    []string
	quiet    bool
	inPlace  bool
	separate bool
}

func parseSedArgs(cc *gosh.CommandContext) (sedOptions, error) {
	var opts sedOptions
	args := cc.Args
	expectingScript := true
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			i++
			if len(opts.scripts) == 0 && i < len(args) {
				opts.scripts = append(opts.scripts, args[i])
				i++
			}
			opts.files = append(opts.files, args[i:]...)
			break
		}
		if expectingScript && strings.HasPrefix(arg, "-") && arg != "-" {
			if arg == "-e" || arg == "-f" || arg == "-i" {
				switch arg {
				case "-e":
					i++
					if i >= len(args) {
						return opts, fmt.Errorf("option -e requires a script")
					}
					opts.scripts = append(opts.scripts, args[i])
				case "-f":
					i++
					if i >= len(args) {
						return opts, fmt.Errorf("option -f requires a file")
					}
					src, err := readVirtualFile(cc, args[i])
					if err != nil {
						return opts, fmt.Errorf("%s: %v", args[i], err)
					}
					opts.scripts = append(opts.scripts, src)
				case "-i":
					opts.inPlace = true
				}
				continue
			}
			if strings.HasPrefix(arg, "-e") && len(arg) > 2 {
				opts.scripts = append(opts.scripts, arg[2:])
				continue
			}
			if strings.HasPrefix(arg, "-f") && len(arg) > 2 {
				src, err := readVirtualFile(cc, arg[2:])
				if err != nil {
					return opts, fmt.Errorf("%s: %v", arg[2:], err)
				}
				opts.scripts = append(opts.scripts, src)
				continue
			}
			if strings.HasPrefix(arg, "-i") {
				opts.inPlace = true
				continue
			}
			valid := true
			for _, r := range arg[1:] {
				switch r {
				case 'n':
					opts.quiet = true
				case 'E', 'r':
					// Go's regexp package is RE2/extended; these flags are accepted for compatibility.
				case 's':
					opts.separate = true
				default:
					valid = false
				}
			}
			if !valid {
				return opts, fmt.Errorf("unsupported option %s", arg)
			}
			continue
		}
		if len(opts.scripts) == 0 {
			opts.scripts = append(opts.scripts, arg)
			expectingScript = false
			continue
		}
		opts.files = append(opts.files, arg)
	}
	return opts, nil
}

type sedInput struct {
	name  string
	lines []string
}

func readSedInputs(cc *gosh.CommandContext, files []string, separate bool) ([]sedInput, error) {
	if len(files) == 0 {
		b, err := io.ReadAll(cc.Stdin)
		if err != nil {
			return nil, err
		}
		return []sedInput{{name: "-", lines: splitLines(string(b))}}, nil
	}
	inputs := make([]sedInput, 0, len(files))
	var combined []string
	for _, name := range files {
		var data string
		var err error
		if name == "-" {
			b, e := io.ReadAll(cc.Stdin)
			err = e
			data = string(b)
		} else {
			data, err = readVirtualFile(cc, name)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %v", name, err)
		}
		lines := splitLines(data)
		if separate {
			inputs = append(inputs, sedInput{name: name, lines: lines})
		} else {
			combined = append(combined, lines...)
		}
	}
	if !separate {
		inputs = append(inputs, sedInput{name: "-", lines: combined})
	}
	return inputs, nil
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}

func writeVirtualFile(cc *gosh.CommandContext, name, content string) error {
	f, err := cc.FS().Open(cc.ResolvePath(name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.WriteString(f, content)
	return err
}

func hasDash(files []string) bool {
	for _, f := range files {
		if f == "-" {
			return true
		}
	}
	return false
}

type sedCommandSpec struct {
	addr1    sedAddress
	addr2    sedAddress
	hasRange bool
	cmd      byte
	re       *regexp.Regexp
	repl     string
	global   bool
	nth      int
	print    bool
	yFrom    []rune
	yTo      []rune
	quiet    bool
	inRange  bool
}

type sedAddress struct {
	kind int
	num  int
	re   *regexp.Regexp
}

const (
	addrNone = iota
	addrLine
	addrLast
	addrRegex
)

func parseSedProgram(scripts []string, quiet bool) ([]sedCommandSpec, error) {
	var specs []sedCommandSpec
	for _, script := range scripts {
		for _, part := range splitSedCommands(script) {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			spec, err := parseSedCommand(part)
			if err != nil {
				return nil, err
			}
			spec.quiet = quiet
			specs = append(specs, spec)
		}
	}
	return specs, nil
}

func splitSedCommands(script string) []string {
	var out []string
	var b strings.Builder
	inDelim := rune(0)
	esc := false
	for _, r := range script {
		if esc {
			b.WriteRune(r)
			esc = false
			continue
		}
		if r == '\\' {
			b.WriteRune(r)
			esc = true
			continue
		}
		if inDelim != 0 {
			b.WriteRune(r)
			if r == inDelim {
				inDelim = 0
			}
			continue
		}
		if r == ';' || r == '\n' {
			out = append(out, b.String())
			b.Reset()
			continue
		}
		if strings.ContainsRune("/|:#@!", r) {
			inDelim = r
		}
		b.WriteRune(r)
	}
	out = append(out, b.String())
	return out
}

func parseSedCommand(s string) (sedCommandSpec, error) {
	var spec sedCommandSpec
	rest := s
	addr1, ok, n, err := parseAddress(rest)
	if err != nil {
		return spec, err
	}
	if ok {
		spec.addr1 = addr1
		rest = strings.TrimLeft(rest[n:], " \t")
		if strings.HasPrefix(rest, ",") {
			spec.hasRange = true
			rest = strings.TrimLeft(rest[1:], " \t")
			addr2, ok2, n2, err := parseAddress(rest)
			if err != nil {
				return spec, err
			}
			if !ok2 {
				return spec, fmt.Errorf("missing second address in range %q", s)
			}
			spec.addr2 = addr2
			rest = strings.TrimLeft(rest[n2:], " \t")
		}
	}
	if rest == "" {
		return spec, fmt.Errorf("missing command in %q", s)
	}
	spec.cmd = rest[0]
	rest = rest[1:]
	switch spec.cmd {
	case 's':
		return parseSubstitute(spec, rest)
	case 'y':
		return parseTransliterate(spec, rest)
	case 'p', 'd', 'n', 'q', '=':
		if strings.TrimSpace(rest) != "" {
			return spec, fmt.Errorf("unexpected text after %c", spec.cmd)
		}
		return spec, nil
	default:
		return spec, fmt.Errorf("unsupported command %q", string(spec.cmd))
	}
}

func parseAddress(s string) (sedAddress, bool, int, error) {
	if s == "" {
		return sedAddress{}, false, 0, nil
	}
	if s[0] >= '0' && s[0] <= '9' {
		i := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		n, _ := strconv.Atoi(s[:i])
		return sedAddress{kind: addrLine, num: n}, true, i, nil
	}
	if s[0] == '$' {
		return sedAddress{kind: addrLast}, true, 1, nil
	}
	if s[0] == '/' {
		pat, n, err := readDelimited(s, 0)
		if err != nil {
			return sedAddress{}, false, 0, err
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return sedAddress{}, false, 0, err
		}
		return sedAddress{kind: addrRegex, re: re}, true, n, nil
	}
	return sedAddress{}, false, 0, nil
}

func parseSubstitute(spec sedCommandSpec, rest string) (sedCommandSpec, error) {
	if rest == "" {
		return spec, fmt.Errorf("missing substitute delimiter")
	}
	delim, _ := utf8.DecodeRuneInString(rest)
	pat, n, err := readDelimited(rest, 0)
	if err != nil {
		return spec, err
	}
	repl, n2, err := readUntilDelimiter(rest[n:], delim)
	if err != nil {
		return spec, err
	}
	flags := rest[n+n2:]
	ignoreCase := false
	for i := 0; i < len(flags); i++ {
		switch flags[i] {
		case 'g':
			spec.global = true
		case 'p':
			spec.print = true
		case 'i', 'I':
			ignoreCase = true
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			j := i
			for j < len(flags) && flags[j] >= '0' && flags[j] <= '9' {
				j++
			}
			spec.nth, _ = strconv.Atoi(flags[i:j])
			i = j - 1
		case ' ', '\t':
		default:
			return spec, fmt.Errorf("unsupported substitute flag %q", string(flags[i]))
		}
	}
	if ignoreCase {
		pat = "(?i)" + pat
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return spec, err
	}
	spec.re = re
	spec.repl = translateSedReplacement(repl)
	return spec, nil
}

func parseTransliterate(spec sedCommandSpec, rest string) (sedCommandSpec, error) {
	if rest == "" {
		return spec, fmt.Errorf("missing transliterate delimiter")
	}
	delim, _ := utf8.DecodeRuneInString(rest)
	from, n, err := readDelimited(rest, 0)
	if err != nil {
		return spec, err
	}
	to, _, err := readUntilDelimiter(rest[n:], delim)
	if err != nil {
		return spec, err
	}
	spec.yFrom = []rune(from)
	spec.yTo = []rune(to)
	if len(spec.yFrom) != len(spec.yTo) {
		return spec, fmt.Errorf("y command strings are different lengths")
	}
	return spec, nil
}

func readDelimited(s string, start int) (string, int, error) {
	if start >= len(s) {
		return "", 0, fmt.Errorf("missing delimiter")
	}
	delim, size := utf8.DecodeRuneInString(s[start:])
	if delim == utf8.RuneError || delim == '\\' || delim == '\n' {
		return "", 0, fmt.Errorf("invalid delimiter")
	}
	var b strings.Builder
	esc := false
	for i := start + size; i < len(s); {
		r, sz := utf8.DecodeRuneInString(s[i:])
		if esc {
			if r != delim {
				b.WriteRune('\\')
			}
			b.WriteRune(r)
			esc = false
			i += sz
			continue
		}
		if r == '\\' {
			esc = true
			i += sz
			continue
		}
		if r == delim {
			return b.String(), i + sz - start, nil
		}
		b.WriteRune(r)
		i += sz
	}
	return "", 0, fmt.Errorf("unterminated delimiter")
}

func readUntilDelimiter(s string, delim rune) (string, int, error) {
	var b strings.Builder
	esc := false
	for i := 0; i < len(s); {
		r, sz := utf8.DecodeRuneInString(s[i:])
		if esc {
			if r != delim {
				b.WriteRune('\\')
			}
			b.WriteRune(r)
			esc = false
			i += sz
			continue
		}
		if r == '\\' {
			esc = true
			i += sz
			continue
		}
		if r == delim {
			return b.String(), i + sz, nil
		}
		b.WriteRune(r)
		i += sz
	}
	return "", 0, fmt.Errorf("unterminated delimiter")
}

func translateSedReplacement(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '$' {
			b.WriteString("$$")
			continue
		}
		if c == '&' {
			b.WriteString("$0")
			continue
		}
		if c == '\\' && i+1 < len(s) {
			n := s[i+1]
			if n >= '1' && n <= '9' {
				b.WriteByte('$')
				b.WriteByte(n)
				i++
				continue
			}
			if n == '&' || n == '\\' {
				b.WriteByte(n)
				i++
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

func runSed(cc *gosh.CommandContext, specs []sedCommandSpec, lines []string) (bytes.Buffer, error) {
	specs = append([]sedCommandSpec(nil), specs...)
	var out bytes.Buffer
	for i := 0; i < len(lines); i++ {
		if cc.Governor() != nil {
			if err := cc.Governor().StreamTick(); err != nil {
				return out, err
			}
		}
		lineNo := i + 1
		last := i == len(lines)-1
		space := lines[i]
		deleted := false
		quit := false
		for ci := range specs {
			spec := &specs[ci]
			if !spec.applies(space, lineNo, last) {
				continue
			}
			switch spec.cmd {
			case 's':
				newLine, changed := spec.sub(space)
				space = newLine
				if changed && spec.print {
					writeSedLine(&out, space)
				}
			case 'p':
				writeSedLine(&out, space)
			case 'd':
				deleted = true
			case 'n':
				if !spec.quiet {
					writeSedLine(&out, space)
				}
				i++
				if i >= len(lines) {
					deleted = true
					break
				}
				if cc.Governor() != nil {
					if err := cc.Governor().StreamTick(); err != nil {
						return out, err
					}
				}
				lineNo = i + 1
				last = i == len(lines)-1
				space = lines[i]
			case 'q':
				quit = true
			case '=':
				fmt.Fprintf(&out, "%d\n", lineNo)
			case 'y':
				space = spec.transliterate(space)
			}
			if deleted || quit {
				break
			}
		}
		if !deleted && !specsQuiet(specs) {
			writeSedLine(&out, space)
		}
		if quit {
			break
		}
	}
	return out, nil
}

func (s *sedCommandSpec) applies(line string, lineNo int, last bool) bool {
	if s.addr1.kind == addrNone {
		return true
	}
	if !s.hasRange {
		return s.addr1.matches(line, lineNo, last)
	}
	if s.inRange {
		if s.addr2.matches(line, lineNo, last) {
			s.inRange = false
		}
		return true
	}
	if s.addr1.matches(line, lineNo, last) {
		if !s.addr2.matches(line, lineNo, last) {
			s.inRange = true
		}
		return true
	}
	return false
}

func (a sedAddress) matches(line string, lineNo int, last bool) bool {
	switch a.kind {
	case addrLine:
		return lineNo == a.num
	case addrLast:
		return last
	case addrRegex:
		return a.re.MatchString(line)
	default:
		return true
	}
}

func (s sedCommandSpec) sub(line string) (string, bool) {
	matches := s.re.FindAllStringSubmatchIndex(line, -1)
	if len(matches) == 0 {
		return line, false
	}
	if !s.global {
		n := s.nth
		if n <= 0 {
			n = 1
		}
		if n > len(matches) {
			return line, false
		}
		m := matches[n-1]
		var b []byte
		b = append(b, line[:m[0]]...)
		b = s.re.ExpandString(b, s.repl, line, m)
		b = append(b, line[m[1]:]...)
		return string(b), true
	}
	var out []byte
	last := 0
	changed := false
	start := 0
	if s.nth > 0 {
		start = s.nth - 1
	}
	for idx, m := range matches {
		if idx < start {
			continue
		}
		out = append(out, line[last:m[0]]...)
		out = s.re.ExpandString(out, s.repl, line, m)
		last = m[1]
		changed = true
	}
	if !changed {
		return line, false
	}
	out = append(out, line[last:]...)
	return string(out), true
}

func (s sedCommandSpec) transliterate(line string) string {
	m := make(map[rune]rune, len(s.yFrom))
	for i, r := range s.yFrom {
		m[r] = s.yTo[i]
	}
	return strings.Map(func(r rune) rune {
		if to, ok := m[r]; ok {
			return to
		}
		return r
	}, line)
}

func specsQuiet(specs []sedCommandSpec) bool {
	return len(specs) > 0 && specs[0].quiet
}

func writeSedLine(w *bytes.Buffer, s string) { w.WriteString(s); w.WriteByte('\n') }
