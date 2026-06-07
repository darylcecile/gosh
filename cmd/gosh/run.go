package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/darylcecile/gosh"
	"github.com/darylcecile/gosh/goshfs"
	"github.com/darylcecile/gosh/std"
)

const hostErrorExitCode = 2

func runCLI(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cfg, err := parseArgs(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "gosh: %v\n", err)
		return hostErrorExitCode
	}
	if cfg.showHelp {
		writeUsage(stdout)
		return 0
	}
	if cfg.showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if len(cfg.mounts) > 0 {
		fmt.Fprintln(stderr, "gosh: --mount is not supported by this CLI yet; use --file HOSTPATH:VPATH")
		return hostErrorExitCode
	}
	if cfg.noNetwork && (len(cfg.origins) > 0 || cfg.fullInternet) {
		fmt.Fprintln(stderr, "gosh: --no-network conflicts with --allow-origin/--dangerously-allow-full-internet")
		return hostErrorExitCode
	}

	sh, err := newShell(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "gosh: %v\n", err)
		return hostErrorExitCode
	}
	if cfg.fullInternet {
		fmt.Fprintln(stderr, "gosh: WARNING: unrestricted network egress is enabled")
	}

	script, scriptArgs, source, err := scriptSource(cfg, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "gosh: %v\n", err)
		return hostErrorExitCode
	}
	if source == sourceREPL {
		return runREPL(sh, cfg, stdin, stdout, stderr)
	}
	if cfg.errexit {
		script = "set -e\n" + script
	}

	runStdin := stdin
	if source == sourceStdin {
		runStdin = strings.NewReader("")
	}
	return runScript(sh, cfg, script, scriptArgs, runStdin, stdout, stderr)
}

func newShell(cfg cliConfig) (*gosh.Shell, error) {
	env, err := envMap(cfg.env)
	if err != nil {
		return nil, err
	}
	files := make(map[string]string, len(cfg.files))
	for _, entry := range cfg.files {
		hostPath, vpath, err := parseFileMapping(entry)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(hostPath)
		if err != nil {
			return nil, fmt.Errorf("read --file %s: %w", hostPath, err)
		}
		files[vpath] = string(data)
	}

	limits := gosh.DefaultLimits()
	if cfg.maxOutput > 0 {
		limits.MaxOutputBytes = cfg.maxOutput
	}
	if cfg.maxCommands > 0 {
		limits.MaxCommands = cfg.maxCommands
	}

	opts := []gosh.Option{gosh.WithEnv(env), gosh.WithLimits(limits)}

	// Determine the virtual working directory. When mounting a host root, default
	// the cwd to "/" (the mount point) unless the operator set --cwd explicitly,
	// so that the mounted tree is visible at the shell's starting directory.
	cwd := cfg.cwd
	if cfg.root != "" && !cfg.cwdSet {
		cwd = "/"
	}
	if cwd != "" {
		opts = append(opts, gosh.WithCwd(cwd))
	}

	if cfg.root != "" {
		// Overlay-over-cwd: a read-only host lower layer with an in-memory upper
		// layer that captures (and ultimately discards) all writes. Seed --file
		// entries into the upper so they remain available in overlay mode.
		host, err := goshfs.NewHostReadOnlyFS(cfg.root)
		if err != nil {
			return nil, fmt.Errorf("mount --root %s: %w", cfg.root, err)
		}
		upper := gosh.NewInMemoryFS(gosh.NewVirtualClock(gosh.Epoch), limits.MaxFileBytes, limits.MaxTotalFSBytes)
		if cwd != "" {
			_ = upper.MkdirAll(cwd, 0o755)
		}
		seedUpper(upper, files)
		opts = append(opts, gosh.WithFS(goshfs.NewOverlayFS(host, upper)))
	} else {
		opts = append(opts, gosh.WithFiles(files))
	}

	if len(cfg.origins) > 0 || cfg.fullInternet {
		policy := gosh.NetworkPolicy{
			AllowedOrigins:               append([]string(nil), cfg.origins...),
			AllowedMethods:               upperList(cfg.methods),
			AllowPrivateIPs:              cfg.allowPrivateIPs,
			DangerouslyAllowFullInternet: cfg.fullInternet,
		}
		opts = append(opts, gosh.WithNetwork(policy))
	}
	return std.Shell(opts...), nil
}

// seedUpper writes the seed file map into an in-memory overlay upper layer,
// creating parent directories. Mirrors the library's own seeding for --root mode.
func seedUpper(upper *gosh.InMemoryFS, files map[string]string) {
	for vpath, content := range files {
		abs := vpath
		if !strings.HasPrefix(abs, "/") {
			abs = "/" + abs
		}
		_ = upper.MkdirAll(pathDir(abs), 0o755)
		f, err := upper.Open(abs, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			continue
		}
		_, _ = io.WriteString(f, content)
		_ = f.Close()
	}
}

func pathDir(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

type scriptSourceKind int

const (
	sourceInline scriptSourceKind = iota
	sourceFile
	sourceStdin
	sourceREPL
)

func scriptSource(cfg cliConfig, stdin io.Reader) (script string, scriptArgs []string, source scriptSourceKind, err error) {
	if cfg.inlineSet {
		return cfg.inlineScript, cfg.args, sourceInline, nil
	}
	if len(cfg.args) > 0 {
		data, err := os.ReadFile(cfg.args[0])
		if err != nil {
			return "", nil, sourceFile, fmt.Errorf("read script %s: %w", cfg.args[0], err)
		}
		return string(data), cfg.args[1:], sourceFile, nil
	}
	if isTerminal(stdin) {
		return "", nil, sourceREPL, nil
	}
	data, err := io.ReadAll(stdin)
	if err != nil {
		return "", nil, sourceStdin, fmt.Errorf("read stdin: %w", err)
	}
	return string(data), nil, sourceStdin, nil
}

func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func runScript(sh *gosh.Shell, cfg cliConfig, script string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	ctx := context.Background()
	var cancel context.CancelFunc
	if cfg.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, cfg.timeout)
		defer cancel()
	}

	if cfg.jsonOutput {
		var outBuf, errBuf bytes.Buffer
		res, err := sh.Run(ctx, script,
			gosh.RunArgs(args...),
			gosh.RunStdin(stdin),
			gosh.RunStdout(&outBuf),
			gosh.RunStderr(&errBuf),
		)
		exit := res.ExitCode
		if err != nil {
			if errBuf.Len() > 0 {
				errBuf.WriteByte('\n')
			}
			errBuf.WriteString(err.Error())
			exit = hostErrorExitCode
		}
		payload := struct {
			Stdout   string `json:"stdout"`
			Stderr   string `json:"stderr"`
			ExitCode int    `json:"exitCode"`
		}{outBuf.String(), errBuf.String(), exit}
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		if encErr := enc.Encode(payload); encErr != nil {
			fmt.Fprintf(stderr, "gosh: encode json: %v\n", encErr)
			return hostErrorExitCode
		}
		return exit
	}

	res, err := sh.Run(ctx, script,
		gosh.RunArgs(args...),
		gosh.RunStdin(stdin),
		gosh.RunStdout(stdout),
		gosh.RunStderr(stderr),
	)
	if err != nil {
		// Typed gosh.Run errors already carry a "gosh:" prefix.
		fmt.Fprintf(stderr, "%v\n", err)
		return hostErrorExitCode
	}
	return res.ExitCode
}

func runREPL(sh *gosh.Shell, cfg cliConfig, stdin io.Reader, stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, "gosh sandbox REPL (Ctrl-D or 'exit' to quit)")
	scanner := bufio.NewScanner(stdin)
	for {
		fmt.Fprint(stderr, "gosh> ")
		if !scanner.Scan() {
			break
		}
		line := scanner.Text()
		if strings.TrimSpace(line) == "exit" {
			break
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		code := runScript(sh, cfg, line, nil, strings.NewReader(""), stdout, stderr)
		if code == hostErrorExitCode {
			return code
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(stderr, "gosh: read repl: %v\n", err)
		return hostErrorExitCode
	}
	return 0
}

func upperList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, strings.ToUpper(v))
		}
	}
	return out
}
