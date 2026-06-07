package textlang

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/benhoyt/goawk/interp"
	"github.com/benhoyt/goawk/parser"
	"github.com/darylcecile/gosh"
)

type awkCommand struct{}

func (awkCommand) Name() string { return "awk" }

func (awkCommand) Run(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return cc.PrintHelp("awk [-F sep] [-v var=value] [-f progfile] [program] [file ...]", "Run AWK programs inside the gosh sandbox. File operands are pre-read through the virtual filesystem; system(), pipes, and AWK file reads/writes are disabled.")
	}

	opts, err := parseAwkArgs(cc)
	if err != nil {
		fmt.Fprintf(cc.Stderr, "awk: %v\n", err)
		return 2
	}
	if opts.program == "" {
		fmt.Fprintln(cc.Stderr, "awk: missing program")
		return 2
	}

	prog, err := parser.ParseProgram([]byte(opts.program), nil)
	if err != nil {
		fmt.Fprintf(cc.Stderr, "awk: %v\n", err)
		return 2
	}

	input, err := awkInput(cc, opts.files)
	if err != nil {
		fmt.Fprintf(cc.Stderr, "awk: %v\n", err)
		return 1
	}

	vars := append([]string(nil), opts.vars...)
	if opts.fieldSep != "" {
		vars = append(vars, "FS", opts.fieldSep)
	}

	config := &interp.Config{
		Stdin:        input,
		Output:       cc.Stdout,
		Error:        cc.Stderr,
		Argv0:        "awk",
		Args:         nil, // never let goawk open host files; see awkInput
		Vars:         vars,
		Environ:      []string{},
		NoExec:       true, // disables system() and command pipes
		NoFileReads:  true, // disables getline/file operands inside goawk
		NoFileWrites: true,
	}

	interpreter, err := interp.New(prog)
	if err != nil {
		fmt.Fprintf(cc.Stderr, "awk: %v\n", err)
		return 2
	}
	status, err := interpreter.ExecuteContext(ctx, config)
	if err != nil {
		if ctx.Err() != nil {
			fmt.Fprintf(cc.Stderr, "awk: %v\n", ctx.Err())
			return 1
		}
		fmt.Fprintf(cc.Stderr, "awk: %v\n", err)
		return 2
	}
	return status
}

type awkOptions struct {
	program  string
	fieldSep string
	vars     []string
	files    []string
}

func parseAwkArgs(cc *gosh.CommandContext) (awkOptions, error) {
	var opts awkOptions
	args := cc.Args
	programFromArg := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			i++
			if opts.program == "" {
				if i >= len(args) {
					return opts, fmt.Errorf("missing program after --")
				}
				opts.program = args[i]
				programFromArg = true
				i++
			}
			opts.files = append(opts.files, args[i:]...)
			break
		}
		if !programFromArg && strings.HasPrefix(arg, "-") && arg != "-" {
			switch {
			case arg == "-F":
				i++
				if i >= len(args) {
					return opts, fmt.Errorf("option -F requires an argument")
				}
				opts.fieldSep = args[i]
			case strings.HasPrefix(arg, "-F"):
				opts.fieldSep = arg[2:]
			case arg == "-v":
				i++
				if i >= len(args) {
					return opts, fmt.Errorf("option -v requires var=value")
				}
				name, val, ok := strings.Cut(args[i], "=")
				if !ok || !isAwkVarName(name) {
					return opts, fmt.Errorf("invalid -v assignment %q", args[i])
				}
				opts.vars = append(opts.vars, name, val)
			case strings.HasPrefix(arg, "-v") && len(arg) > 2:
				assign := arg[2:]
				name, val, ok := strings.Cut(assign, "=")
				if !ok || !isAwkVarName(name) {
					return opts, fmt.Errorf("invalid -v assignment %q", assign)
				}
				opts.vars = append(opts.vars, name, val)
			case arg == "-f":
				i++
				if i >= len(args) {
					return opts, fmt.Errorf("option -f requires a file")
				}
				src, err := readVirtualFile(cc, args[i])
				if err != nil {
					return opts, fmt.Errorf("%s: %v", args[i], err)
				}
				opts.program += src
				if !strings.HasSuffix(opts.program, "\n") {
					opts.program += "\n"
				}
			default:
				return opts, fmt.Errorf("unsupported option %s", arg)
			}
			continue
		}
		if opts.program == "" {
			opts.program = arg
			programFromArg = true
			continue
		}
		opts.files = append(opts.files, arg)
	}
	return opts, nil
}

func awkInput(cc *gosh.CommandContext, files []string) (io.Reader, error) {
	var buf bytes.Buffer
	if len(files) == 0 {
		if err := copyGoverned(cc, &buf, cc.Stdin); err != nil {
			return nil, err
		}
		return bytes.NewReader(buf.Bytes()), nil
	}
	for _, name := range files {
		if name == "-" {
			if err := copyGoverned(cc, &buf, cc.Stdin); err != nil {
				return nil, err
			}
			continue
		}
		data, err := readVirtualFile(cc, name)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", name, err)
		}
		if err := tickRecords(cc, data); err != nil {
			return nil, err
		}
		buf.WriteString(data)
		if len(data) > 0 && !strings.HasSuffix(data, "\n") {
			buf.WriteByte('\n')
		}
	}
	return bytes.NewReader(buf.Bytes()), nil
}

func readVirtualFile(cc *gosh.CommandContext, name string) (string, error) {
	f, err := cc.FS().Open(cc.ResolvePath(name), os.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func copyGoverned(cc *gosh.CommandContext, dst *bytes.Buffer, src io.Reader) error {
	b, err := io.ReadAll(src)
	if err != nil {
		return err
	}
	if err := tickRecords(cc, string(b)); err != nil {
		return err
	}
	_, _ = dst.Write(b)
	return nil
}

func tickRecords(cc *gosh.CommandContext, s string) error {
	if cc.Governor() == nil {
		return nil
	}
	if s == "" {
		return nil
	}
	count := strings.Count(s, "\n")
	if !strings.HasSuffix(s, "\n") {
		count++
	}
	for i := 0; i < count; i++ {
		if err := cc.Governor().StreamTick(); err != nil {
			return err
		}
	}
	return nil
}

var awkVarRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func isAwkVarName(s string) bool { return awkVarRE.MatchString(s) }
