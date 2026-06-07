package gosh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// DefaultCwd is the working directory (and $HOME) of a Shell created with
// default options. It is a virtual path, not a host path.
const DefaultCwd = "/home/user"

// Result is the structured outcome of a Run. The returned Go error from Run is
// reserved for host-level failures (limits, cancellation, parse/unsupported,
// internal); a script that merely exits non-zero yields ExitCode != 0 with a
// nil error (D2).
type Result struct {
	// Stdout is the captured standard output of the script.
	Stdout string
	// Stderr is the captured standard error of the script.
	Stderr string
	// ExitCode is the script's exit status (0 on success).
	ExitCode int
	// Metadata carries auxiliary, non-essential run information such as the
	// number of commands executed and whether output was truncated.
	Metadata map[string]any
}

// Shell is a configured, reusable sandboxed interpreter. Construct one with
// New. A single *Shell owns one virtual filesystem that, by default, persists
// across its Run calls while env/functions/positional-params reset each run
// (D5). A *Shell is NOT safe for concurrent Run calls; the documented model is
// one *Shell per agent/session (construction is cheap). For safety, Run
// serializes calls with an internal mutex so concurrent misuse cannot corrupt
// state or trip the race detector (D9).
type Shell struct {
	mu sync.Mutex

	baseFS    FileSystem
	ephemeral bool

	env     map[string]string
	cwd     string
	limits  Limits
	clock   Clock
	network NetworkPolicy

	registry map[string]Command
	policy   BuiltinPolicy
}

// runState is the fully-resolved configuration for a single Run.
type runState struct {
	fsys     FileSystem
	cwd      string
	envPairs []string
	args     []string
	stdin    io.Reader
	stdout   io.Writer
	stderr   io.Writer
	governor *Governor
	clock    Clock
	registry map[string]Command
	policy   BuiltinPolicy
}

// config accumulates options during New.
type config struct {
	files      map[string]string
	env        map[string]string
	cwd        string
	limits     Limits
	fsys       FileSystem
	commands   []Command
	clock      Clock
	network    NetworkPolicy
	ephemeral  bool
	policy     BuiltinPolicy
	hasLimits  bool
	hasNetwork bool
}

// Option configures a Shell at construction time (D3).
type Option func(*config)

// WithFiles seeds the in-memory filesystem with the given path→content entries.
// Parent directories are created as needed. Ignored when a custom FS is
// supplied via WithFS.
func WithFiles(files map[string]string) Option {
	return func(c *config) {
		if c.files == nil {
			c.files = make(map[string]string)
		}
		for k, v := range files {
			c.files[k] = v
		}
	}
}

// WithEnv sets environment variables visible to scripts. Values are merged over
// the secure default (which seeds only HOME). Host environment is never
// inherited (S23).
func WithEnv(env map[string]string) Option {
	return func(c *config) {
		if c.env == nil {
			c.env = make(map[string]string)
		}
		for k, v := range env {
			c.env[k] = v
		}
	}
}

// WithCwd sets the initial working directory (and default $HOME).
func WithCwd(cwd string) Option {
	return func(c *config) { c.cwd = cleanAbs(cwd) }
}

// WithLimits overrides the resource governor limits. Zero-valued fields fall
// back to DefaultLimits; negative fields disable that limit.
func WithLimits(l Limits) Option {
	return func(c *config) { c.limits = l; c.hasLimits = true }
}

// WithFS supplies a custom FileSystem backend, replacing the default
// InMemoryFS. WithFiles is then ignored.
func WithFS(fsys FileSystem) Option {
	return func(c *config) { c.fsys = fsys }
}

// WithCommands registers one or more commands (coreutils or host extensions).
// Later registrations override earlier ones with the same Name.
func WithCommands(cmds ...Command) Option {
	return func(c *config) { c.commands = append(c.commands, cmds...) }
}

// WithClock injects a Clock. The default is a deterministic VirtualClock
// starting at Epoch (S24).
func WithClock(clock Clock) Option {
	return func(c *config) { c.clock = clock }
}

// WithNetwork sets the egress policy consumed by network-aware commands. The
// default is a deny-all policy (no network).
func WithNetwork(p NetworkPolicy) Option {
	return func(c *config) { c.network = p; c.hasNetwork = true }
}

// WithEphemeralFS makes each Run start from a fresh snapshot of the seeded
// filesystem, so mutations never persist or bleed across runs (D5).
func WithEphemeralFS() Option {
	return func(c *config) { c.ephemeral = true }
}

// WithAllowedBuiltins extends the builtin admission policy to additionally
// allow the named mvdan/sh builtins (for example "trap" or "eval"). Use with
// care: each name you allow widens the attack surface (S2).
func WithAllowedBuiltins(names ...string) Option {
	return func(c *config) {
		if c.policy.modes == nil {
			c.policy = defaultBuiltinPolicy()
		}
		p := c.policy
		for _, n := range names {
			p = p.allowBuiltin(n)
		}
		c.policy = p
	}
}

// WithDeniedBuiltins extends the builtin admission policy to additionally deny
// the named builtins, overriding the defaults.
func WithDeniedBuiltins(names ...string) Option {
	return func(c *config) {
		if c.policy.modes == nil {
			c.policy = defaultBuiltinPolicy()
		}
		p := c.policy
		for _, n := range names {
			p = p.denyBuiltin(n)
		}
		c.policy = p
	}
}

// WithBuiltinPolicy replaces the entire builtin admission policy. Most hosts
// should prefer WithAllowedBuiltins/WithDeniedBuiltins.
func WithBuiltinPolicy(p BuiltinPolicy) Option {
	return func(c *config) { c.policy = p.clone() }
}

// New constructs a Shell with secure defaults: an empty in-memory filesystem
// (with only HOME seeded in the environment), no host environment inheritance,
// cwd and $HOME of DefaultCwd, a deterministic UTC virtual clock, all resource
// governors on at DefaultLimits, no network, and registry-only execution (no
// real process is ever spawned). Options refine this baseline.
func New(opts ...Option) *Shell {
	c := &config{
		cwd:    DefaultCwd,
		limits: DefaultLimits(),
		policy: defaultBuiltinPolicy(),
	}
	for _, opt := range opts {
		opt(c)
	}

	limits := c.limits.withDefaults()

	clock := c.clock
	if clock == nil {
		clock = NewVirtualClock(Epoch)
	}

	var fsys FileSystem
	if c.fsys != nil {
		fsys = c.fsys
	} else {
		im := NewInMemoryFS(clock, limits.MaxFileBytes, limits.MaxTotalFSBytes)
		_ = im.MkdirAll(c.cwd, 0o755)
		seedFiles(im, c.files)
		fsys = im
	}

	env := map[string]string{"HOME": c.cwd}
	for k, v := range c.env {
		env[k] = v
	}

	registry := make(map[string]Command)
	for _, cmd := range c.commands {
		registry[cmd.Name()] = cmd
	}

	policy := c.policy
	if policy.modes == nil {
		policy = defaultBuiltinPolicy()
	}

	return &Shell{
		baseFS:    fsys,
		ephemeral: c.ephemeral,
		env:       env,
		cwd:       c.cwd,
		limits:    limits,
		clock:     clock,
		network:   c.network,
		registry:  registry,
		policy:    policy,
	}
}

// seedFiles writes the seed file map into an in-memory filesystem, creating
// parent directories.
func seedFiles(im *InMemoryFS, files map[string]string) {
	// Deterministic order for stable parent creation.
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		abs := cleanAbs(k)
		_ = im.MkdirAll(path.Dir(abs), 0o755)
		f, err := im.Open(abs, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			continue
		}
		_, _ = io.WriteString(f, files[k])
		_ = f.Close()
	}
}

// RunOption configures a single Run without mutating the Shell (D4).
type RunOption func(*runConfig)

type runConfig struct {
	env        map[string]string
	replaceEnv bool
	stdin      io.Reader
	args       []string
	cwd        string
	stdout     io.Writer
	stderr     io.Writer
}

// RunEnv adds/overrides environment variables for this run only.
func RunEnv(env map[string]string) RunOption {
	return func(rc *runConfig) {
		if rc.env == nil {
			rc.env = make(map[string]string)
		}
		for k, v := range env {
			rc.env[k] = v
		}
	}
}

// RunReplaceEnv, when true, makes RunEnv the COMPLETE environment for this run
// instead of merging over the Shell's environment.
func RunReplaceEnv(replace bool) RunOption {
	return func(rc *runConfig) { rc.replaceEnv = replace }
}

// RunStdin supplies standard input for this run. Accepts an io.Reader or a
// string; any other type is ignored.
func RunStdin(stdin any) RunOption {
	return func(rc *runConfig) {
		switch v := stdin.(type) {
		case io.Reader:
			rc.stdin = v
		case string:
			rc.stdin = strings.NewReader(v)
		}
	}
}

// RunArgs sets the positional parameters ($1, $2, ... and $@) for this run.
func RunArgs(args ...string) RunOption {
	return func(rc *runConfig) { rc.args = append(rc.args, args...) }
}

// RunCwd overrides the working directory for this run only.
func RunCwd(cwd string) RunOption {
	return func(rc *runConfig) { rc.cwd = cleanAbs(cwd) }
}

// RunStdout additionally streams stdout to w (bytes are still captured in
// Result.Stdout and still bounded by MaxOutputBytes) (D6).
func RunStdout(w io.Writer) RunOption {
	return func(rc *runConfig) { rc.stdout = w }
}

// RunStderr additionally streams stderr to w.
func RunStderr(w io.Writer) RunOption {
	return func(rc *runConfig) { rc.stderr = w }
}

// Run parses and executes script within the sandbox, returning a structured
// Result and a host-level error (nil for a normal or non-zero script exit).
// ctx governs cancellation and deadlines (S8/F11). Run serializes against other
// Run calls on the same Shell.
func (s *Shell) Run(ctx context.Context, script string, ropts ...RunOption) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ctx == nil {
		ctx = context.Background()
	}

	// S14a: reject oversized scripts before parsing.
	if !unbounded(s.limits.MaxScriptBytes) && int64(len(script)) > s.limits.MaxScriptBytes {
		return Result{ExitCode: 1}, &LimitError{Kind: LimitScriptBytes, Limit: s.limits.MaxScriptBytes}
	}

	rc := &runConfig{}
	for _, opt := range ropts {
		opt(rc)
	}

	// S16: parse errors are typed, never panics.
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash), syntax.KeepComments(false))
	file, perr := parser.Parse(strings.NewReader(script), "script")
	if perr != nil {
		return Result{ExitCode: 1}, toParseError(perr)
	}

	// S2a / S14a: reject unsupported constructs and structural blowups.
	if verr := validateAST(file, s.limits); verr != nil {
		return Result{ExitCode: 1}, verr
	}

	// Resolve per-run filesystem (ephemeral => fresh snapshot).
	fsys := s.baseFS
	if s.ephemeral {
		if im, ok := s.baseFS.(*InMemoryFS); ok {
			fsys = im.snapshot()
		}
	}

	cwd := s.cwd
	if rc.cwd != "" {
		cwd = rc.cwd
	}

	envPairs := s.resolveEnv(rc, cwd)

	var outBuf, errBuf bytes.Buffer
	governor := newGovernor(s.limits)

	var stdoutDest io.Writer = &outBuf
	if rc.stdout != nil {
		stdoutDest = io.MultiWriter(&outBuf, rc.stdout)
	}
	var stderrDest io.Writer = &errBuf
	if rc.stderr != nil {
		stderrDest = io.MultiWriter(&errBuf, rc.stderr)
	}

	var stdin io.Reader = rc.stdin
	if stdin == nil {
		stdin = strings.NewReader("")
	}

	rs := &runState{
		fsys:     fsys,
		cwd:      cwd,
		envPairs: envPairs,
		args:     rc.args,
		stdin:    stdin,
		stdout:   &cappedWriter{w: stdoutDest, gov: governor},
		stderr:   &cappedWriter{w: stderrDest, gov: governor},
		governor: governor,
		clock:    s.clock,
		registry: s.registry,
		policy:   s.policy,
	}

	runner, err := s.newSecureRunner(rs)
	if err != nil {
		return Result{ExitCode: 1}, &InternalError{Cause: err}
	}

	runErr := s.runGuarded(ctx, runner, file)
	exitCode, hostErr := renderRunError(runErr, governor)

	meta := map[string]any{
		"commands_executed": governor.Commands(),
		"output_truncated":  governor.OutputLimitErr() != nil,
	}

	return Result{
		Stdout:   outBuf.String(),
		Stderr:   errBuf.String(),
		ExitCode: exitCode,
		Metadata: meta,
	}, hostErr
}

// runGuarded runs the program, recovering any panic from the interpreter TCB
// into an InternalError so a malformed input can never crash the host (S16).
func (s *Shell) runGuarded(ctx context.Context, runner *interp.Runner, file *syntax.File) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = &InternalError{Cause: e}
			} else {
				err = &InternalError{Cause: errString(fmt.Sprintf("%v", r))}
			}
		}
	}()
	return runner.Run(ctx, file)
}

// resolveEnv computes the KEY=VALUE environment for a run, honoring per-run
// overrides and ensuring PWD reflects the working directory.
func (s *Shell) resolveEnv(rc *runConfig, cwd string) []string {
	merged := make(map[string]string)
	if !rc.replaceEnv {
		for k, v := range s.env {
			merged[k] = v
		}
	}
	for k, v := range rc.env {
		merged[k] = v
	}
	if _, ok := merged["PWD"]; !ok {
		merged["PWD"] = cwd
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+merged[k])
	}
	return pairs
}

// Snapshot returns a deep copy of the Shell's current in-memory filesystem so
// the host can checkpoint and later restore state (D5). It returns nil if the
// backing FS is not an InMemoryFS.
func (s *Shell) Snapshot() FileSystem {
	s.mu.Lock()
	defer s.mu.Unlock()
	if im, ok := s.baseFS.(*InMemoryFS); ok {
		return im.snapshot()
	}
	return nil
}

// Reset replaces the Shell's filesystem. Passing a FileSystem returned by
// Snapshot restores that checkpoint; passing nil resets to a fresh empty
// in-memory filesystem seeded with the working directory (D5).
func (s *Shell) Reset(fsys FileSystem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if fsys != nil {
		s.baseFS = fsys
		return
	}
	im := NewInMemoryFS(s.clock, s.limits.MaxFileBytes, s.limits.MaxTotalFSBytes)
	_ = im.MkdirAll(s.cwd, 0o755)
	s.baseFS = im
}

// FS returns the Shell's current filesystem backend, allowing the host to
// inspect or mutate state between runs.
func (s *Shell) FS() FileSystem {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.baseFS
}

// Network returns the configured egress policy (consumed by network commands).
func (s *Shell) Network() NetworkPolicy { return s.network }

// errString adapts a non-error panic value to an error.
type errString string

func (e errString) Error() string { return string(e) }

// toParseError converts an mvdan syntax error into a typed *ParseError, never
// leaking host paths or stacks (S25).
func toParseError(err error) *ParseError {
	if pe, ok := err.(syntax.ParseError); ok {
		return &ParseError{
			Filename:   "script",
			Line:       pe.Pos.Line(),
			Col:        pe.Pos.Col(),
			Msg:        pe.Text,
			Incomplete: pe.Incomplete,
		}
	}
	return &ParseError{Filename: "script", Msg: err.Error()}
}
