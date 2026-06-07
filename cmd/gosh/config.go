package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
)

// version is overridden at build time via -ldflags "-X 'main.version=gosh vX.Y.Z'".
var version = "gosh dev"

type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

type cliConfig struct {
	inlineScript    string
	inlineSet       bool
	cwd             string
	cwdSet          bool
	root            string
	errexit         bool
	noNetwork       bool
	env             stringList
	files           stringList
	mounts          stringList
	origins         stringList
	methods         stringList
	maxOutput       int64
	maxCommands     int64
	timeout         time.Duration
	fullInternet    bool
	allowPrivateIPs bool
	jsonOutput      bool
	showVersion     bool
	showHelp        bool
	args            []string
}

func parseArgs(args []string, stderr io.Writer) (cliConfig, error) {
	var cfg cliConfig
	fs := flag.NewFlagSet("gosh", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { writeUsage(stderr) }

	fs.StringVar(&cfg.inlineScript, "c", "", "run inline Bash script")
	fs.StringVar(&cfg.cwd, "cwd", "", "initial virtual working directory")
	fs.StringVar(&cfg.root, "root", "", "mount HOSTDIR as a read-only overlay lower layer (reads real files, writes go to a discarded in-memory layer); use --root . for overlay-over-cwd")
	fs.BoolVar(&cfg.errexit, "e", false, "exit on first command failure (set -e)")
	fs.BoolVar(&cfg.errexit, "errexit", false, "exit on first command failure (set -e)")
	fs.BoolVar(&cfg.noNetwork, "no-network", false, "assert no network egress (the default); errors if combined with network-enabling flags")
	fs.Var(&cfg.env, "env", "seed environment variable KEY=VAL (repeatable)")
	fs.Var(&cfg.files, "file", "load HOSTPATH into the in-memory FS at VPATH as HOSTPATH:VPATH (repeatable)")
	fs.Var(&cfg.mounts, "mount", "unsupported placeholder for HOSTDIR:VPATH mounts")
	fs.Int64Var(&cfg.maxOutput, "max-output-bytes", 0, "maximum cumulative script stdout+stderr bytes")
	fs.Int64Var(&cfg.maxCommands, "max-commands", 0, "maximum simple commands per run")
	fs.DurationVar(&cfg.timeout, "timeout", 0, "wall-clock timeout for script execution, e.g. 2s or 1m")
	fs.Var(&cfg.origins, "allow-origin", "allow exact network origin, e.g. https://example.com (repeatable)")
	fs.Var(&cfg.methods, "allow-method", "allow HTTP method for network commands (repeatable; default GET,HEAD)")
	fs.BoolVar(&cfg.fullInternet, "dangerously-allow-full-internet", false, "DANGEROUS: allow unrestricted network egress")
	fs.BoolVar(&cfg.allowPrivateIPs, "allow-private-ips", false, "allow network commands to reach private/loopback IPs (SSRF protection is on by default)")
	fs.BoolVar(&cfg.jsonOutput, "json", false, "emit a single JSON object {stdout,stderr,exitCode} instead of streaming output")
	fs.BoolVar(&cfg.showVersion, "version", false, "print version and exit")
	fs.BoolVar(&cfg.showHelp, "help", false, "print help and exit")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			cfg.showHelp = true
			return cfg, nil
		}
		return cfg, err
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "c" {
			cfg.inlineSet = true
		}
		if f.Name == "cwd" {
			cfg.cwdSet = true
		}
	})
	cfg.args = fs.Args()
	return cfg, nil
}

func envMap(entries []string) (map[string]string, error) {
	out := make(map[string]string, len(entries))
	for _, entry := range entries {
		key, val, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("--env must be KEY=VAL, got %q", entry)
		}
		out[key] = val
	}
	return out, nil
}

func parseFileMapping(entry string) (hostPath, vpath string, err error) {
	hostPath, vpath, ok := strings.Cut(entry, ":")
	if !ok || hostPath == "" || vpath == "" {
		return "", "", fmt.Errorf("--file must be HOSTPATH:VPATH, got %q", entry)
	}
	return hostPath, vpath, nil
}

func writeUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  gosh [FLAGS] -c 'SCRIPT' [ARG...]
  gosh [FLAGS] SCRIPT_FILE [ARG...]
  gosh [FLAGS] < SCRIPT
  gosh [FLAGS]                  # REPL when stdin is a TTY

Runs Bash scripts inside the gosh sandbox using the std command set. Script
execution uses an in-memory virtual filesystem, never executes host processes,
never inherits host environment variables, and denies network egress by default.

Flags:
`)
	defaults := flag.NewFlagSet("usage", flag.ContinueOnError)
	defaults.String("c", "", "run inline Bash script")
	defaults.String("cwd", "", "initial virtual working directory")
	defaults.String("root", "", "mount HOSTDIR as a read-only overlay lower layer (reads real files, writes discarded); use --root . for overlay-over-cwd")
	defaults.Bool("e", false, "exit on first command failure (set -e)")
	defaults.Bool("errexit", false, "exit on first command failure (set -e)")
	defaults.Bool("no-network", false, "assert no network egress (the default); errors if combined with network-enabling flags")
	defaults.Var(&stringList{}, "env", "seed environment variable KEY=VAL (repeatable)")
	defaults.Var(&stringList{}, "file", "load HOSTPATH into the in-memory FS at VPATH as HOSTPATH:VPATH (repeatable)")
	defaults.Var(&stringList{}, "mount", "currently unsupported; reserved for HOSTDIR:VPATH mounts")
	defaults.Int64("max-output-bytes", 0, "maximum cumulative script stdout+stderr bytes")
	defaults.Int64("max-commands", 0, "maximum simple commands per run")
	defaults.Duration("timeout", 0, "wall-clock timeout for script execution")
	defaults.Var(&stringList{}, "allow-origin", "allow exact network origin (repeatable); SSRF-protected by default")
	defaults.Var(&stringList{}, "allow-method", "allow HTTP method for network commands (repeatable)")
	defaults.Bool("dangerously-allow-full-internet", false, "DANGEROUS: unrestricted network egress")
	defaults.Bool("allow-private-ips", false, "allow network commands to reach private/loopback IPs (SSRF protection is on by default)")
	defaults.Bool("json", false, "emit a single JSON object {stdout,stderr,exitCode} instead of streaming output")
	defaults.Bool("version", false, "print version and exit")
	defaults.Bool("help", false, "print help and exit")
	defaults.SetOutput(w)
	defaults.PrintDefaults()
	fmt.Fprint(w, `
Script sources are mutually exclusive by priority: -c, then SCRIPT_FILE, then
stdin. --mount is intentionally documented but not implemented by this host CLI;
use --file to seed trusted host files into the virtual filesystem, or --root to
mount a real directory read-only (writes are captured in a discarded in-memory
overlay, never touching host disk).
`)
}
