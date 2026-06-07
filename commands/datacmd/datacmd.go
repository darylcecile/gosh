// Package datacmd provides pure-Go encoding, hashing, and structured-data
// commands for gosh.
package datacmd

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"path"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/darylcecile/gosh"
	"github.com/itchyny/gojq"
	"gopkg.in/yaml.v3"
)

// Commands returns the datacmd command group: base64, md5sum, sha1sum,
// sha256sum, jq, yq, and csv.
func Commands() []gosh.Command {
	return []gosh.Command{
		gosh.CommandFunc("base64", runBase64),
		gosh.CommandFunc("md5sum", runHash("md5sum", md5.New)),
		gosh.CommandFunc("sha1sum", runHash("sha1sum", sha1.New)),
		gosh.CommandFunc("sha256sum", runHash("sha256sum", sha256.New)),
		gosh.CommandFunc("jq", runJQ),
		gosh.CommandFunc("yq", runYQ),
		gosh.CommandFunc("csv", runCSV),
	}
}

func commandError(cc *gosh.CommandContext, name, format string, args ...any) int {
	fmt.Fprintf(cc.Stderr, "%s: %s\n", name, fmt.Sprintf(format, args...))
	return 1
}

func readOperand(ctx context.Context, cc *gosh.CommandContext, cmd, name string) ([]byte, bool) {
	if err := ctx.Err(); err != nil {
		commandError(cc, cmd, "%s", err.Error())
		return nil, false
	}
	if name == "-" {
		b, err := io.ReadAll(cc.Stdin)
		if err != nil {
			commandError(cc, cmd, "read stdin: %v", err)
			return nil, false
		}
		return b, true
	}
	f, err := cc.FS().Open(cc.ResolvePath(name), 0, 0)
	if err != nil {
		commandError(cc, cmd, "%s: %v", name, err)
		return nil, false
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		commandError(cc, cmd, "%s: %v", name, err)
		return nil, false
	}
	return b, true
}

func readInputs(ctx context.Context, cc *gosh.CommandContext, cmd string, operands []string) ([][]byte, []string, bool) {
	if len(operands) == 0 {
		b, err := io.ReadAll(cc.Stdin)
		if err != nil {
			commandError(cc, cmd, "read stdin: %v", err)
			return nil, nil, false
		}
		return [][]byte{b}, []string{"-"}, true
	}
	contents := make([][]byte, 0, len(operands))
	names := make([]string, 0, len(operands))
	for _, op := range operands {
		b, ok := readOperand(ctx, cc, cmd, op)
		if !ok {
			return nil, nil, false
		}
		contents = append(contents, b)
		names = append(names, op)
	}
	return contents, names, true
}

func runBase64(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return cc.PrintHelp("base64 [-d|--decode] [-w COLS] [FILE]...", "Encode or decode Base64 data.")
	}
	decode := false
	wrap := 76
	var files []string
	for i := 0; i < len(cc.Args); i++ {
		a := cc.Args[i]
		switch {
		case a == "-d" || a == "--decode":
			decode = true
		case a == "--ignore-garbage":
		// Decoding filters garbage bytes by default for GNU-compatible lenience.
		case a == "-w":
			i++
			if i >= len(cc.Args) {
				return commandError(cc, "base64", "missing wrap column")
			}
			n, err := strconv.Atoi(cc.Args[i])
			if err != nil || n < 0 {
				return commandError(cc, "base64", "invalid wrap column %q", cc.Args[i])
			}
			wrap = n
		case strings.HasPrefix(a, "-w") && len(a) > 2:
			n, err := strconv.Atoi(a[2:])
			if err != nil || n < 0 {
				return commandError(cc, "base64", "invalid wrap column %q", a[2:])
			}
			wrap = n
		case a == "--":
			files = append(files, cc.Args[i+1:]...)
			i = len(cc.Args)
		case strings.HasPrefix(a, "-") && a != "-":
			return commandError(cc, "base64", "unknown option %s", a)
		default:
			files = append(files, a)
		}
	}
	contents, _, ok := readInputs(ctx, cc, "base64", files)
	if !ok {
		return 1
	}
	for _, in := range contents {
		if decode {
			filtered := make([]byte, 0, len(in))
			for _, b := range in {
				if isBase64Byte(b) {
					filtered = append(filtered, b)
				}
			}
			out, err := base64.StdEncoding.DecodeString(string(filtered))
			if err != nil {
				return commandError(cc, "base64", "invalid input: %v", err)
			}
			if _, err := cc.Stdout.Write(out); err != nil {
				return 1
			}
			continue
		}
		encoded := base64.StdEncoding.EncodeToString(in)
		if wrap > 0 {
			for len(encoded) > wrap {
				fmt.Fprintln(cc.Stdout, encoded[:wrap])
				encoded = encoded[wrap:]
			}
		}
		fmt.Fprintln(cc.Stdout, encoded)
	}
	return 0
}

func isBase64Byte(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '+' || b == '/' || b == '='
}

func runHash(name string, newHash func() hash.Hash) func(context.Context, *gosh.CommandContext) int {
	return func(ctx context.Context, cc *gosh.CommandContext) int {
		if cc.WantsHelp() {
			return cc.PrintHelp(name+" [-c] [--quiet] [FILE]...", "Print or check message digests.")
		}
		check := false
		quiet := false
		var files []string
		for i := 0; i < len(cc.Args); i++ {
			a := cc.Args[i]
			switch a {
			case "-c", "--check":
				check = true
			case "--quiet":
				quiet = true
			case "--":
				files = append(files, cc.Args[i+1:]...)
				i = len(cc.Args)
			default:
				if strings.HasPrefix(a, "-") && a != "-" {
					return commandError(cc, name, "unknown option %s", a)
				}
				files = append(files, a)
			}
		}
		if check {
			return runHashCheck(ctx, cc, name, newHash, files, quiet)
		}
		contents, names, ok := readInputs(ctx, cc, name, files)
		if !ok {
			return 1
		}
		for i, in := range contents {
			h := newHash()
			_, _ = h.Write(in)
			fmt.Fprintf(cc.Stdout, "%s  %s\n", hex.EncodeToString(h.Sum(nil)), names[i])
		}
		return 0
	}
}

func runHashCheck(ctx context.Context, cc *gosh.CommandContext, name string, newHash func() hash.Hash, files []string, quiet bool) int {
	contents, _, ok := readInputs(ctx, cc, name, files)
	if !ok {
		return 1
	}
	failed := false
	for _, content := range contents {
		for lineNo, line := range strings.Split(string(content), "\n") {
			if err := ctx.Err(); err != nil {
				return commandError(cc, name, "%s", err.Error())
			}
			line = strings.TrimRight(line, "\r")
			if strings.TrimSpace(line) == "" {
				continue
			}
			if cc.Governor() != nil {
				if le := cc.Governor().StreamTick(); le != nil {
					return commandError(cc, name, "%s", le.Error())
				}
			}
			expect, fname, ok := parseChecksumLine(line)
			if !ok {
				fmt.Fprintf(cc.Stderr, "%s: improperly formatted checksum line %d\n", name, lineNo+1)
				failed = true
				continue
			}
			data, rok := readOperand(ctx, cc, name, fname)
			actual := ""
			if rok {
				h := newHash()
				_, _ = h.Write(data)
				actual = hex.EncodeToString(h.Sum(nil))
			}
			if !rok || !strings.EqualFold(expect, actual) {
				if !quiet {
					fmt.Fprintf(cc.Stdout, "%s: FAILED\n", fname)
				}
				failed = true
			} else if !quiet {
				fmt.Fprintf(cc.Stdout, "%s: OK\n", fname)
			}
		}
	}
	if failed {
		return 1
	}
	return 0
}

func parseChecksumLine(line string) (sum, name string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", "", false
	}
	return fields[0], fields[len(fields)-1], true
}

type jqOptions struct {
	raw        bool
	compact    bool
	nullInput  bool
	exitStatus bool
	slurp      bool
	args       []string
	argValues  []any
	query      string
	files      []string
}

func runJQ(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return cc.PrintHelp("jq [-r] [-c] [-n] [-e] [-s] [--arg name val] [--argjson name json] FILTER [FILE]...", "Transform JSON data with gojq.")
	}
	opts, ok := parseJQArgs(cc, "jq")
	if !ok {
		return 1
	}
	values, ok := readJSONInputs(ctx, cc, "jq", opts.files, opts.nullInput, opts.slurp)
	if !ok {
		return 1
	}
	status, err := executeJQ(ctx, cc, "jq", opts, values, outputJSON)
	if err != nil {
		return commandError(cc, "jq", "%v", err)
	}
	return status
}

func parseJQArgs(cc *gosh.CommandContext, cmd string) (jqOptions, bool) {
	var opts jqOptions
	for i := 0; i < len(cc.Args); i++ {
		a := cc.Args[i]
		switch a {
		case "-r", "--raw-output":
			opts.raw = true
		case "-c", "--compact-output":
			opts.compact = true
		case "-n", "--null-input":
			opts.nullInput = true
		case "-e", "--exit-status":
			opts.exitStatus = true
		case "-s", "--slurp":
			opts.slurp = true
		case "--arg", "--argjson":
			isJSON := a == "--argjson"
			if i+2 >= len(cc.Args) {
				commandError(cc, cmd, "%s requires name and value", a)
				return opts, false
			}
			name := cc.Args[i+1]
			val := cc.Args[i+2]
			i += 2
			var anyVal any = val
			if isJSON {
				dec := json.NewDecoder(strings.NewReader(val))
				dec.UseNumber()
				if err := dec.Decode(&anyVal); err != nil {
					commandError(cc, cmd, "invalid JSON for --argjson %s: %v", name, err)
					return opts, false
				}
				anyVal = normalizeJSON(anyVal)
			}
			opts.args = append(opts.args, "$"+name)
			opts.argValues = append(opts.argValues, anyVal)
		case "--":
			if i+1 < len(cc.Args) && opts.query == "" {
				opts.query = cc.Args[i+1]
				opts.files = append(opts.files, cc.Args[i+2:]...)
			} else {
				opts.files = append(opts.files, cc.Args[i+1:]...)
			}
			i = len(cc.Args)
		default:
			if strings.HasPrefix(a, "-") && a != "-" {
				commandError(cc, cmd, "unknown option %s", a)
				return opts, false
			}
			if opts.query == "" {
				opts.query = a
			} else {
				opts.files = append(opts.files, a)
			}
		}
	}
	if opts.query == "" {
		commandError(cc, cmd, "missing query")
		return opts, false
	}
	return opts, true
}

func readJSONInputs(ctx context.Context, cc *gosh.CommandContext, cmd string, files []string, nullInput, slurp bool) ([]any, bool) {
	if nullInput {
		return []any{nil}, true
	}
	contents, _, ok := readInputs(ctx, cc, cmd, files)
	if !ok {
		return nil, false
	}
	var values []any
	for _, content := range contents {
		dec := json.NewDecoder(bytes.NewReader(content))
		dec.UseNumber()
		for {
			if err := ctx.Err(); err != nil {
				commandError(cc, cmd, "%s", err.Error())
				return nil, false
			}
			var v any
			err := dec.Decode(&v)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				commandError(cc, cmd, "invalid JSON: %v", err)
				return nil, false
			}
			values = append(values, normalizeJSON(v))
			if cc.Governor() != nil {
				if le := cc.Governor().StreamTick(); le != nil {
					commandError(cc, cmd, "%s", le.Error())
					return nil, false
				}
			}
		}
	}
	if slurp {
		return []any{values}, true
	}
	return values, true
}

type outputFunc func(io.Writer, any, bool, bool) error

func executeJQ(ctx context.Context, cc *gosh.CommandContext, cmd string, opts jqOptions, inputs []any, output outputFunc) (int, error) {
	query, err := gojq.Parse(opts.query)
	if err != nil {
		return 1, err
	}
	code, err := gojq.Compile(query, gojq.WithVariables(opts.args))
	if err != nil {
		return 1, err
	}
	wrote := false
	last := any(nil)
	for _, input := range inputs {
		if err := ctx.Err(); err != nil {
			return 1, err
		}
		iter := code.Run(input, opts.argValues...)
		for {
			v, ok := iter.Next()
			if !ok {
				break
			}
			if halt, ok := v.(*gojq.HaltError); ok {
				if halt.Value() == nil {
					break
				}
				return halt.ExitCode(), halt
			}
			if err, ok := v.(error); ok {
				return 1, err
			}
			if cc.Governor() != nil {
				if le := cc.Governor().StreamTick(); le != nil {
					return 1, le
				}
			}
			v = normalizeJSON(v)
			if err := output(cc.Stdout, v, opts.raw, opts.compact); err != nil {
				return 1, err
			}
			wrote = true
			last = v
		}
	}
	if opts.exitStatus {
		if !wrote {
			return 4, nil
		}
		if last == nil || last == false {
			return 1, nil
		}
	}
	return 0, nil
}

func outputJSON(w io.Writer, v any, raw, compact bool) error {
	if raw {
		if s, ok := v.(string); ok {
			_, err := fmt.Fprintln(w, s)
			return err
		}
	}
	var b []byte
	var err error
	if compact {
		b, err = json.Marshal(v)
	} else {
		b, err = json.MarshalIndent(v, "", "  ")
	}
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func runYQ(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return cc.PrintHelp("yq [-p yaml|toml] [-o yaml|json|-j] FILTER [FILE]...", "Query YAML or TOML data with gojq syntax.")
	}
	opts, outputKind, inputKind, ok := parseYQArgs(cc)
	if !ok {
		return 1
	}
	values, ok := readStructuredInputs(ctx, cc, opts.files, inputKind)
	if !ok {
		return 1
	}
	out := outputYAML
	if outputKind == "json" {
		out = outputJSON
	}
	status, err := executeJQ(ctx, cc, "yq", opts, values, out)
	if err != nil {
		return commandError(cc, "yq", "%v", err)
	}
	return status
}

func parseYQArgs(cc *gosh.CommandContext) (jqOptions, string, string, bool) {
	var opts jqOptions
	out := "yaml"
	in := ""
	for i := 0; i < len(cc.Args); i++ {
		a := cc.Args[i]
		switch a {
		case "-r", "--raw-output":
			opts.raw = true
		case "-c", "--compact-output":
			opts.compact = true
		case "-e", "--exit-status":
			opts.exitStatus = true
		case "-s", "--slurp":
			opts.slurp = true
		case "-j":
			out = "json"
		case "-o", "--output-format":
			i++
			if i >= len(cc.Args) || (cc.Args[i] != "yaml" && cc.Args[i] != "json") {
				commandError(cc, "yq", "-o requires yaml or json")
				return opts, out, in, false
			}
			out = cc.Args[i]
		case "-p", "--input-format":
			i++
			if i >= len(cc.Args) || (cc.Args[i] != "yaml" && cc.Args[i] != "toml") {
				commandError(cc, "yq", "-p requires yaml or toml")
				return opts, out, in, false
			}
			in = cc.Args[i]
		case "--arg", "--argjson":
			isJSON := a == "--argjson"
			if i+2 >= len(cc.Args) {
				commandError(cc, "yq", "%s requires name and value", a)
				return opts, out, in, false
			}
			name, val := cc.Args[i+1], cc.Args[i+2]
			i += 2
			var anyVal any = val
			if isJSON {
				if err := json.Unmarshal([]byte(val), &anyVal); err != nil {
					commandError(cc, "yq", "invalid JSON for --argjson %s: %v", name, err)
					return opts, out, in, false
				}
				anyVal = normalizeJSON(anyVal)
			}
			opts.args = append(opts.args, "$"+name)
			opts.argValues = append(opts.argValues, anyVal)
		default:
			if strings.HasPrefix(a, "-") && a != "-" {
				commandError(cc, "yq", "unknown option %s", a)
				return opts, out, in, false
			}
			if opts.query == "" {
				opts.query = a
			} else {
				opts.files = append(opts.files, a)
			}
		}
	}
	if opts.query == "" {
		commandError(cc, "yq", "missing query")
		return opts, out, in, false
	}
	return opts, out, in, true
}

func readStructuredInputs(ctx context.Context, cc *gosh.CommandContext, files []string, inputKind string) ([]any, bool) {
	contents, names, ok := readInputs(ctx, cc, "yq", files)
	if !ok {
		return nil, false
	}
	var values []any
	for i, content := range contents {
		kind := inputKind
		if kind == "" {
			if strings.EqualFold(path.Ext(names[i]), ".toml") {
				kind = "toml"
			} else {
				kind = "yaml"
			}
		}
		switch kind {
		case "toml":
			var v any
			if err := toml.Unmarshal(content, &v); err != nil {
				commandError(cc, "yq", "invalid TOML: %v", err)
				return nil, false
			}
			values = append(values, normalizeJSON(v))
		case "yaml":
			dec := yaml.NewDecoder(bytes.NewReader(content))
			for {
				if err := ctx.Err(); err != nil {
					commandError(cc, "yq", "%s", err.Error())
					return nil, false
				}
				var v any
				err := dec.Decode(&v)
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					commandError(cc, "yq", "invalid YAML: %v", err)
					return nil, false
				}
				values = append(values, normalizeJSON(v))
				if cc.Governor() != nil {
					if le := cc.Governor().StreamTick(); le != nil {
						commandError(cc, "yq", "%s", le.Error())
						return nil, false
					}
				}
			}
		}
	}
	return values, true
}

func outputYAML(w io.Writer, v any, raw, compact bool) error {
	if raw {
		if s, ok := v.(string); ok {
			_, err := fmt.Fprintln(w, s)
			return err
		}
	}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		_ = enc.Close()
		return err
	}
	return enc.Close()
}

func runCSV(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return cc.PrintHelp("csv tojson [-d DELIM] [--no-header] [COLUMN]... [FILE]", "Convert CSV data to JSON.")
	}
	if len(cc.Args) == 0 || cc.Args[0] != "tojson" {
		return commandError(cc, "csv", "expected subcommand tojson")
	}
	delim := ','
	header := true
	var rest []string
	for i := 1; i < len(cc.Args); i++ {
		a := cc.Args[i]
		switch a {
		case "-d", "--delimiter":
			i++
			if i >= len(cc.Args) || cc.Args[i] == "" {
				return commandError(cc, "csv", "-d requires a delimiter")
			}
			delim = []rune(cc.Args[i])[0]
		case "--no-header":
			header = false
		case "--":
			rest = append(rest, cc.Args[i+1:]...)
			i = len(cc.Args)
		default:
			if strings.HasPrefix(a, "-") && a != "-" {
				return commandError(cc, "csv", "unknown option %s", a)
			}
			rest = append(rest, a)
		}
	}
	file := ""
	columns := rest
	if len(rest) > 0 {
		last := rest[len(rest)-1]
		if last == "-" || strings.Contains(last, "/") || strings.EqualFold(path.Ext(last), ".csv") || fileExists(cc, last) {
			file = last
			columns = rest[:len(rest)-1]
		}
	}
	var data []byte
	if file == "" {
		b, err := io.ReadAll(cc.Stdin)
		if err != nil {
			return commandError(cc, "csv", "read stdin: %v", err)
		}
		data = b
	} else {
		b, ok := readOperand(ctx, cc, "csv", file)
		if !ok {
			return 1
		}
		data = b
	}
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = false
	r.Comma = delim
	records, err := r.ReadAll()
	if err != nil {
		return commandError(cc, "csv", "%v", err)
	}
	out, ok := csvToJSON(cc, records, header, columns)
	if !ok {
		return 1
	}
	return writeJSONValue(cc.Stdout, out)
}

func fileExists(cc *gosh.CommandContext, name string) bool {
	f, err := cc.FS().Open(cc.ResolvePath(name), 0, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func csvToJSON(cc *gosh.CommandContext, records [][]string, header bool, columns []string) (any, bool) {
	if len(records) == 0 {
		return []any{}, true
	}
	start := 0
	var heads []string
	if header {
		heads = records[0]
		start = 1
	}
	indexes, ok := selectCSVIndexes(cc, heads, header, columns, records[0])
	if !ok {
		return nil, false
	}
	arr := make([]any, 0, len(records)-start)
	for _, rec := range records[start:] {
		if cc.Governor() != nil {
			if le := cc.Governor().StreamTick(); le != nil {
				commandError(cc, "csv", "%s", le.Error())
				return nil, false
			}
		}
		if header {
			obj := make(map[string]any, len(indexes))
			for _, idx := range indexes {
				val := ""
				if idx < len(rec) {
					val = rec[idx]
				}
				if idx < len(heads) {
					obj[heads[idx]] = val
				}
			}
			arr = append(arr, obj)
		} else {
			row := make([]any, 0, len(indexes))
			for _, idx := range indexes {
				val := ""
				if idx < len(rec) {
					val = rec[idx]
				}
				row = append(row, val)
			}
			arr = append(arr, row)
		}
	}
	return arr, true
}

func selectCSVIndexes(cc *gosh.CommandContext, heads []string, header bool, columns []string, first []string) ([]int, bool) {
	max := len(first)
	if header {
		max = len(heads)
	}
	if len(columns) == 0 {
		idx := make([]int, max)
		for i := range idx {
			idx[i] = i
		}
		return idx, true
	}
	idx := make([]int, 0, len(columns))
	for _, col := range columns {
		if n, err := strconv.Atoi(col); err == nil {
			if n < 0 || n >= max {
				commandError(cc, "csv", "column index out of range: %s", col)
				return nil, false
			}
			idx = append(idx, n)
			continue
		}
		if !header {
			commandError(cc, "csv", "named column requires header: %s", col)
			return nil, false
		}
		found := -1
		for i, h := range heads {
			if h == col {
				found = i
				break
			}
		}
		if found < 0 {
			commandError(cc, "csv", "unknown column: %s", col)
			return nil, false
		}
		idx = append(idx, found)
	}
	return idx, true
}

func writeJSONValue(w io.Writer, v any) int {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return 1
	}
	_, err = w.Write(append(b, '\n'))
	if err != nil {
		return 1
	}
	return 0
}

func normalizeJSON(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, v := range x {
			m[k] = normalizeJSON(v)
		}
		return m
	case map[any]any:
		m := make(map[string]any, len(x))
		for k, v := range x {
			m[fmt.Sprint(k)] = normalizeJSON(v)
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = normalizeJSON(v)
		}
		return out
	case []map[string]any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = normalizeJSON(v)
		}
		return out
	case json.Number:
		if strings.ContainsAny(x.String(), ".eE") {
			if f, err := x.Float64(); err == nil {
				return f
			}
		}
		if i, err := x.Int64(); err == nil {
			if i >= math.MinInt && i <= math.MaxInt {
				return int(i)
			}
			return float64(i)
		}
		if f, err := x.Float64(); err == nil {
			return f
		}
		return x.String()
	case int:
		return int(x)
	case int8:
		return int(x)
	case int16:
		return int(x)
	case int32:
		return int(x)
	case int64:
		if x >= math.MinInt && x <= math.MaxInt {
			return int(x)
		}
		return float64(x)
	case uint:
		return uintToJSON(x)
	case uint8:
		return int(x)
	case uint16:
		return int(x)
	case uint32:
		return int(x)
	case uint64:
		if x <= math.MaxInt64 {
			return int(x)
		}
		return float64(x)
	case float32:
		return float64(x)
	case float64, string, bool, nil:
		return x
	default:
		return fmt.Sprint(x)
	}
}

func uintToJSON(v uint) any {
	if uint64(v) <= math.MaxInt64 {
		return int(v)
	}
	return float64(v)
}
