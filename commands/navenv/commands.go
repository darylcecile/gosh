// Package navenv provides navigation, environment, time, and miscellaneous
// sandbox-safe commands for gosh.
package navenv

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/darylcecile/gosh"
)

type command struct {
	name string
	run  func(context.Context, *gosh.CommandContext) int
}

func (c command) Name() string                                         { return c.name }
func (c command) Run(ctx context.Context, cc *gosh.CommandContext) int { return c.run(ctx, cc) }

// Commands returns the navenv command group.
func Commands() []gosh.Command {
	return []gosh.Command{
		command{"basename", basenameCmd}, command{"dirname", dirnameCmd}, command{"find", findCmd},
		command{"du", duCmd}, command{"env", envCmd}, command{"printenv", printenvCmd}, command{"tee", teeCmd},
		command{"seq", seqCmd}, command{"expr", exprCmd}, command{"sleep", sleepCmd}, command{"timeout", timeoutCmd},
		command{"date", dateCmd}, command{"whoami", fixedCmd("whoami", "user")}, command{"hostname", fixedCmd("hostname", "sandbox")},
	}
}

func fixedCmd(name, value string) func(context.Context, *gosh.CommandContext) int {
	return func(ctx context.Context, cc *gosh.CommandContext) int {
		if cc.WantsHelp() {
			return cc.PrintHelp(name, "Print sandbox "+name+".")
		}
		fmt.Fprintln(cc.Stdout, value)
		return 0
	}
}
func errf(cc *gosh.CommandContext, f string, a ...any) int {
	fmt.Fprintf(cc.Stderr, cc.Name+": "+f+"\n", a...)
	return 1
}
func usage(cc *gosh.CommandContext, u, d string) int { return cc.PrintHelp(u, d) }

func basenameCmd(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return usage(cc, "basename [-a] [-s SUFFIX] NAME...", "Strip directory and optional suffix from path names.")
	}
	all := false
	suffix := ""
	args := []string{}
	for i := 0; i < len(cc.Args); i++ {
		a := cc.Args[i]
		switch {
		case a == "-a":
			all = true
		case a == "-s":
			i++
			if i >= len(cc.Args) {
				return errf(cc, "missing suffix")
			}
			suffix = cc.Args[i]
			all = true
		default:
			args = append(args, a)
		}
	}
	if len(args) == 0 || (!all && len(args) > 2) {
		return errf(cc, "invalid arguments")
	}
	if !all && len(args) == 2 {
		suffix = args[1]
		args = args[:1]
	}
	for _, p := range args {
		b := path.Base(strings.TrimRight(p, "/"))
		if p == "" {
			b = "."
		}
		if suffix != "" && strings.HasSuffix(b, suffix) {
			b = strings.TrimSuffix(b, suffix)
		}
		fmt.Fprintln(cc.Stdout, b)
	}
	return 0
}

func dirnameCmd(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return usage(cc, "dirname NAME...", "Strip last component from path names.")
	}
	if len(cc.Args) == 0 {
		return errf(cc, "missing operand")
	}
	for _, p := range cc.Args {
		if p == "" {
			fmt.Fprintln(cc.Stdout, ".")
			continue
		}
		p = strings.TrimRight(p, "/")
		if p == "" {
			fmt.Fprintln(cc.Stdout, "/")
			continue
		}
		d := path.Dir(p)
		if d == "" {
			d = "."
		}
		fmt.Fprintln(cc.Stdout, d)
	}
	return 0
}

type findOpts struct {
	name, typ, pathPat, size string
	max, min                 int
	starts                   []string
}

func findCmd(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return usage(cc, "find [PATH...] [-name GLOB] [-type f|d] [-maxdepth N] [-mindepth N] [-path GLOB] [-size N]", "Walk the virtual filesystem and print matching paths. -exec is unsupported.")
	}
	o := findOpts{max: math.MaxInt32}
	args := cc.Args
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-exec" {
			return errf(cc, "-exec is unsupported")
		}
		if strings.HasPrefix(a, "-") {
			if i+1 >= len(args) {
				return errf(cc, "%s requires an argument", a)
			}
			v := args[i+1]
			i++
			switch a {
			case "-name":
				o.name = v
			case "-type":
				if v != "f" && v != "d" {
					return errf(cc, "invalid -type %s", v)
				}
				o.typ = v
			case "-maxdepth":
				n, e := strconv.Atoi(v)
				if e != nil {
					return errf(cc, "invalid -maxdepth")
				}
				o.max = n
			case "-mindepth":
				n, e := strconv.Atoi(v)
				if e != nil {
					return errf(cc, "invalid -mindepth")
				}
				o.min = n
			case "-path":
				o.pathPat = v
			case "-size":
				o.size = v
			default:
				return errf(cc, "unsupported option %s", a)
			}
		} else {
			o.starts = append(o.starts, a)
		}
	}
	if len(o.starts) == 0 {
		o.starts = []string{"."}
	}
	code := 0
	for _, s := range o.starts {
		if walkFind(ctx, cc, o, s, 0) != 0 {
			code = 1
		}
	}
	return code
}
func walkFind(ctx context.Context, cc *gosh.CommandContext, o findOpts, display string, depth int) int {
	if err := ctx.Err(); err != nil {
		return errf(cc, "canceled")
	}
	if le := cc.Governor().StreamTick(); le != nil {
		return errf(cc, le.Error())
	}
	abs := cc.ResolvePath(display)
	info, err := cc.FS().Stat(abs)
	if err != nil {
		return errf(cc, "%s: %v", display, err)
	}
	if depth >= o.min && findMatch(display, info, o) {
		fmt.Fprintln(cc.Stdout, display)
	}
	if !info.IsDir() || depth >= o.max {
		return 0
	}
	ents, err := cc.FS().ReadDir(abs)
	if err != nil {
		return errf(cc, "%s: %v", display, err)
	}
	code := 0
	for _, e := range ents {
		child := path.Join(display, e.Name())
		if display == "/" {
			child = "/" + e.Name()
		}
		if walkFind(ctx, cc, o, child, depth+1) != 0 {
			code = 1
		}
	}
	return code
}
func findMatch(p string, info fs.FileInfo, o findOpts) bool {
	if o.name != "" {
		ok, _ := path.Match(o.name, path.Base(p))
		if !ok {
			return false
		}
	}
	if o.pathPat != "" {
		ok, _ := path.Match(o.pathPat, p)
		if !ok {
			return false
		}
	}
	if o.typ == "f" && !info.Mode().IsRegular() {
		return false
	}
	if o.typ == "d" && !info.IsDir() {
		return false
	}
	if o.size != "" {
		want, err := strconv.ParseInt(strings.TrimPrefix(o.size, "+"), 10, 64)
		if err == nil && info.Size() != want {
			return false
		}
	}
	return true
}

func duCmd(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return usage(cc, "du [-h] [-s] [-a] [PATH...]", "Estimate virtual file space usage.")
	}
	human, summary, all := false, false, false
	paths := []string{}
	for _, a := range cc.Args {
		switch a {
		case "-h":
			human = true
		case "-s":
			summary = true
		case "-a":
			all = true
		default:
			paths = append(paths, a)
		}
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}
	code := 0
	for _, p := range paths {
		sz, err := duWalk(ctx, cc, p, all && !summary)
		if err != nil {
			errf(cc, "%s: %v", p, err)
			code = 1
			continue
		}
		fmt.Fprintf(cc.Stdout, "%s\t%s\n", formatSize(sz, human), p)
	}
	return code
}
func duWalk(ctx context.Context, cc *gosh.CommandContext, p string, printFiles bool) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	info, err := cc.FS().Stat(cc.ResolvePath(p))
	if err != nil {
		return 0, err
	}
	if !info.IsDir() {
		if printFiles {
			fmt.Fprintf(cc.Stdout, "%d\t%s\n", info.Size(), p)
		}
		return info.Size(), nil
	}
	ents, err := cc.FS().ReadDir(cc.ResolvePath(p))
	if err != nil {
		return 0, err
	}
	var total int64
	for _, e := range ents {
		sz, err := duWalk(ctx, cc, path.Join(p, e.Name()), printFiles)
		if err != nil {
			return total, err
		}
		total += sz
	}
	return total, nil
}
func formatSize(n int64, h bool) string {
	if !h {
		return strconv.FormatInt(n, 10)
	}
	units := []string{"B", "K", "M", "G"}
	f := float64(n)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d%s", n, units[i])
	}
	return fmt.Sprintf("%.1f%s", f, units[i])
}

func envCmd(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return usage(cc, "env [-i] [-u NAME] [NAME=VALUE]... [COMMAND [ARG]...]", "Print or adjust the environment for a command.")
	}
	env := cc.Env.All()
	args := cc.Args
	for len(args) > 0 {
		a := args[0]
		if a == "-i" {
			env = map[string]string{}
			args = args[1:]
			continue
		}
		if a == "-u" {
			if len(args) < 2 {
				return errf(cc, "-u requires a name")
			}
			delete(env, args[1])
			args = args[2:]
			continue
		}
		if strings.Contains(a, "=") {
			kv := strings.SplitN(a, "=", 2)
			env[kv[0]] = kv[1]
			args = args[1:]
			continue
		}
		break
	}
	if len(args) == 0 {
		keys := keys(env)
		for _, k := range keys {
			fmt.Fprintf(cc.Stdout, "%s=%s\n", k, env[k])
		}
		return 0
	}
	for k, v := range env {
		cc.Env.Set(k, v)
	}
	if args[0] == "printenv" {
		return printEnvFromMap(cc, args[1:], env)
	}
	if args[0] == "env" {
		keys := keys(env)
		for _, k := range keys {
			fmt.Fprintf(cc.Stdout, "%s=%s\n", k, env[k])
		}
		return 0
	}
	return cc.Exec(ctx, args...)
}
func keys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
func printenvCmd(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return usage(cc, "printenv [NAME]", "Print environment variables.")
	}
	return printEnvFromMap(cc, cc.Args, cc.Env.All())
}
func printEnvFromMap(cc *gosh.CommandContext, args []string, env map[string]string) int {
	if len(args) == 0 {
		for _, k := range keys(env) {
			fmt.Fprintf(cc.Stdout, "%s=%s\n", k, env[k])
		}
		return 0
	}
	if len(args) != 1 {
		return errf(cc, "too many arguments")
	}
	if v, ok := env[args[0]]; ok {
		fmt.Fprintln(cc.Stdout, v)
		return 0
	}
	return 1
}

func teeCmd(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return usage(cc, "tee [-a] FILE...", "Copy stdin to stdout and virtual files.")
	}
	appendMode := false
	files := []gosh.File{}
	for _, a := range cc.Args {
		if a == "-a" {
			appendMode = true
			continue
		}
		flag := os.O_CREATE | os.O_WRONLY
		if appendMode {
			flag |= os.O_APPEND
		} else {
			flag |= os.O_TRUNC
		}
		f, err := cc.FS().Open(cc.ResolvePath(a), flag, 0o644)
		if err != nil {
			return errf(cc, "%s: %v", a, err)
		}
		defer f.Close()
		files = append(files, f)
	}
	writers := []io.Writer{cc.Stdout}
	for _, f := range files {
		writers = append(writers, f)
	}
	_, err := copyGoverned(ctx, cc, io.MultiWriter(writers...), cc.Stdin)
	if err != nil {
		return errf(cc, "%v", err)
	}
	return 0
}
func copyGoverned(ctx context.Context, cc *gosh.CommandContext, w io.Writer, r io.Reader) (int64, error) {
	br := bufio.NewReader(r)
	var total int64
	buf := make([]byte, 32*1024)
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		if le := cc.Governor().StreamTick(); le != nil {
			return total, le
		}
		n, er := br.Read(buf)
		if n > 0 {
			m, ew := w.Write(buf[:n])
			total += int64(m)
			if ew != nil {
				return total, ew
			}
		}
		if errors.Is(er, io.EOF) {
			return total, nil
		}
		if er != nil {
			return total, er
		}
	}
}

func seqCmd(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return usage(cc, "seq [-s SEP] [-w] FIRST [STEP] LAST", "Print numeric sequences.")
	}
	sep := "\n"
	width := false
	args := []string{}
	for i := 0; i < len(cc.Args); i++ {
		switch cc.Args[i] {
		case "-s":
			i++
			if i >= len(cc.Args) {
				return errf(cc, "-s requires separator")
			}
			sep = cc.Args[i]
		case "-w":
			width = true
		default:
			args = append(args, cc.Args[i])
		}
	}
	if len(args) < 1 || len(args) > 3 {
		return errf(cc, "invalid arguments")
	}
	vals := []float64{1, 1, 0}
	if len(args) == 1 {
		vals[2], _ = strconv.ParseFloat(args[0], 64)
	} else if len(args) == 2 {
		vals[0], _ = strconv.ParseFloat(args[0], 64)
		vals[2], _ = strconv.ParseFloat(args[1], 64)
	} else {
		vals[0], _ = strconv.ParseFloat(args[0], 64)
		vals[1], _ = strconv.ParseFloat(args[1], 64)
		vals[2], _ = strconv.ParseFloat(args[2], 64)
	}
	if vals[1] == 0 {
		return errf(cc, "zero step")
	}
	outs := []string{}
	for x := vals[0]; (vals[1] > 0 && x <= vals[2]) || (vals[1] < 0 && x >= vals[2]); x += vals[1] {
		outs = append(outs, fmtNum(x))
	}
	if width {
		w := 0
		for _, s := range outs {
			if len(s) > w {
				w = len(s)
			}
		}
		for i, s := range outs {
			outs[i] = fmt.Sprintf("%0*s", w, s)
		}
	}
	if len(outs) > 0 {
		fmt.Fprint(cc.Stdout, strings.Join(outs, sep))
		fmt.Fprintln(cc.Stdout)
	}
	return 0
}
func fmtNum(f float64) string {
	if f == math.Trunc(f) {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func sleepCmd(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return usage(cc, "sleep DURATION", "Advance the virtual clock by DURATION.")
	}
	if len(cc.Args) != 1 {
		return errf(cc, "invalid arguments")
	}
	d, err := parseDuration(cc.Args[0])
	if err != nil {
		return errf(cc, "invalid duration")
	}
	if err := cc.Clock().Sleep(ctx, d); err != nil {
		return errf(cc, "%v", err)
	}
	return 0
}
func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	mult := time.Second
	last := s[len(s)-1]
	if last < '0' || last > '9' {
		switch last {
		case 's':
			mult = time.Second
		case 'm':
			mult = time.Minute
		case 'h':
			mult = time.Hour
		case 'd':
			mult = 24 * time.Hour
		default:
			return 0, fmt.Errorf("bad")
		}
		s = s[:len(s)-1]
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, err
	}
	return time.Duration(f * float64(mult)), nil
}
func timeoutCmd(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return usage(cc, "timeout DURATION COMMAND [ARG]...", "Run a command with a virtual-clock timeout.")
	}
	if len(cc.Args) < 2 {
		return errf(cc, "missing command")
	}
	d, err := parseDuration(cc.Args[0])
	if err != nil {
		return errf(cc, "invalid duration")
	}
	start := cc.Clock().Now()
	tctx, cancel := context.WithCancel(ctx)
	defer cancel()
	code := cc.Exec(tctx, cc.Args[1:]...)
	if !cc.Clock().Now().Before(start.Add(d)) {
		cancel()
		return 124
	}
	return code
}

func dateCmd(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return usage(cc, "date [-u] [+FORMAT]", "Print the virtual date/time.")
	}
	utc := false
	format := "%a %b %e %H:%M:%S %Z %Y"
	when := cc.Clock().Now()
	for i := 0; i < len(cc.Args); i++ {
		a := cc.Args[i]
		if a == "-u" {
			utc = true
		} else if a == "-d" {
			i++
			if i >= len(cc.Args) {
				return errf(cc, "-d requires argument")
			}
			if t, err := parseDate(cc.Args[i], when); err == nil {
				when = t
			} else {
				return errf(cc, "invalid date")
			}
		} else if strings.HasPrefix(a, "+") {
			format = a[1:]
		} else {
			return errf(cc, "unsupported argument %s", a)
		}
	}
	if utc {
		when = when.UTC()
	}
	fmt.Fprintln(cc.Stdout, formatTime(when, format))
	return 0
}
func parseDate(s string, base time.Time) (time.Time, error) {
	if s == "now" {
		return base, nil
	}
	if d, err := parseDuration(s); err == nil {
		return base.Add(d), nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("bad")
}
func formatTime(t time.Time, f string) string {
	if !strings.Contains(f, "%") {
		return t.Format(f)
	}
	repl := map[string]string{"%Y": "2006", "%m": "01", "%d": "02", "%H": "15", "%M": "04", "%S": "05", "%F": "2006-01-02", "%T": "15:04:05", "%z": "-0700", "%Z": "MST", "%a": "Mon", "%b": "Jan", "%e": "_2"}
	out := f
	for k, v := range repl {
		out = strings.ReplaceAll(out, k, t.Format(v))
	}
	out = strings.ReplaceAll(out, "%s", strconv.FormatInt(t.Unix(), 10))
	return out
}

func exprCmd(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return usage(cc, "expr EXPRESSION", "Evaluate integer/string expressions.")
	}
	p := &exprParser{args: cc.Args}
	v, err := p.parse()
	if err != nil || p.pos != len(p.args) {
		return errf(cc, "syntax error") * 2
	}
	s := v.String()
	fmt.Fprintln(cc.Stdout, s)
	if s == "" || s == "0" {
		return 1
	}
	return 0
}

type exprVal string

func (v exprVal) String() string     { return string(v) }
func (v exprVal) Int() (int64, bool) { i, e := strconv.ParseInt(string(v), 10, 64); return i, e == nil }

type exprParser struct {
	args []string
	pos  int
}

func (p *exprParser) parse() (exprVal, error) { return p.cmp() }
func (p *exprParser) next() (string, bool) {
	if p.pos >= len(p.args) {
		return "", false
	}
	s := p.args[p.pos]
	p.pos++
	return s, true
}
func (p *exprParser) peek() string {
	if p.pos >= len(p.args) {
		return ""
	}
	return p.args[p.pos]
}
func (p *exprParser) cmp() (exprVal, error) {
	l, e := p.add()
	if e != nil {
		return "", e
	}
	for {
		op := p.peek()
		if op != "=" && op != "==" && op != "!=" && op != "<" && op != "<=" && op != ">" && op != ">=" && op != ":" {
			return l, nil
		}
		p.pos++
		r, e := p.add()
		if e != nil {
			return "", e
		}
		if op == ":" {
			re, e := regexp.Compile("^(?:" + r.String() + ")")
			if e != nil {
				return "", e
			}
			m := re.FindStringSubmatch(l.String())
			if len(m) == 0 {
				l = "0"
			} else if len(m) > 1 {
				l = exprVal(m[1])
			} else {
				l = exprVal(strconv.Itoa(len(m[0])))
			}
			continue
		}
		li, lok := l.Int()
		ri, rok := r.Int()
		cmp := strings.Compare(l.String(), r.String())
		if lok && rok {
			if li < ri {
				cmp = -1
			} else if li > ri {
				cmp = 1
			} else {
				cmp = 0
			}
		}
		ok := map[string]bool{"=": cmp == 0, "==": cmp == 0, "!=": cmp != 0, "<": cmp < 0, "<=": cmp <= 0, ">": cmp > 0, ">=": cmp >= 0}[op]
		if ok {
			l = "1"
		} else {
			l = "0"
		}
	}
}
func (p *exprParser) add() (exprVal, error) {
	l, e := p.mul()
	if e != nil {
		return "", e
	}
	for p.peek() == "+" || p.peek() == "-" {
		op, _ := p.next()
		r, e := p.mul()
		if e != nil {
			return "", e
		}
		li, ok1 := l.Int()
		ri, ok2 := r.Int()
		if !ok1 || !ok2 {
			return "", fmt.Errorf("int")
		}
		if op == "+" {
			l = exprVal(strconv.FormatInt(li+ri, 10))
		} else {
			l = exprVal(strconv.FormatInt(li-ri, 10))
		}
	}
	return l, nil
}
func (p *exprParser) mul() (exprVal, error) {
	l, e := p.prim()
	if e != nil {
		return "", e
	}
	for p.peek() == "*" || p.peek() == "/" || p.peek() == "%" {
		op, _ := p.next()
		r, e := p.prim()
		if e != nil {
			return "", e
		}
		li, ok1 := l.Int()
		ri, ok2 := r.Int()
		if !ok1 || !ok2 || ri == 0 {
			return "", fmt.Errorf("int")
		}
		switch op {
		case "*":
			l = exprVal(strconv.FormatInt(li*ri, 10))
		case "/":
			l = exprVal(strconv.FormatInt(li/ri, 10))
		case "%":
			l = exprVal(strconv.FormatInt(li%ri, 10))
		}
	}
	return l, nil
}
func (p *exprParser) prim() (exprVal, error) {
	tok, ok := p.next()
	if !ok {
		return "", fmt.Errorf("empty")
	}
	switch tok {
	case "length":
		v, e := p.prim()
		return exprVal(strconv.Itoa(len(v.String()))), e
	case "substr":
		s, e := p.prim()
		if e != nil {
			return "", e
		}
		a, e := p.prim()
		if e != nil {
			return "", e
		}
		b, e := p.prim()
		if e != nil {
			return "", e
		}
		start, _ := a.Int()
		ln, _ := b.Int()
		str := s.String()
		if start < 1 || ln <= 0 || int(start) > len(str) {
			return "", nil
		}
		end := int(start - 1 + ln)
		if end > len(str) {
			end = len(str)
		}
		return exprVal(str[int(start-1):end]), nil
	case "index":
		s, e := p.prim()
		if e != nil {
			return "", e
		}
		chars, e := p.prim()
		if e != nil {
			return "", e
		}
		idx := strings.IndexAny(s.String(), chars.String())
		if idx < 0 {
			return "0", nil
		}
		return exprVal(strconv.Itoa(idx + 1)), nil
	case "(":
		v, e := p.parse()
		if e != nil {
			return "", e
		}
		if p.peek() != ")" {
			return "", fmt.Errorf("paren")
		}
		p.pos++
		return v, nil
	}
	return exprVal(tok), nil
}

func isName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 && !(r == '_' || unicode.IsLetter(r)) {
			return false
		}
		if !(r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)) {
			return false
		}
	}
	return true
}
