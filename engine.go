package gosh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
	"sync"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// Sentinels used to reroute denied/shadowed builtins from the CallHandler to
// the ExecHandler. They start with a NUL byte so they can never collide with a
// real command, builtin, or function name.
const (
	denyPrefix   = "\x00gosh-deny\x00"
	shadowPrefix = "\x00gosh-shadow\x00"
)

// validateAST walks the parsed program and rejects constructs gosh refuses to
// execute (S2a), while enforcing the structural pre-execution bounds (S14a):
// AST node count and depth, pipeline length, and command-substitution nesting.
// It returns a typed *UnsupportedError or *LimitError; nil means the program is
// admissible.
func validateAST(file *syntax.File, lim Limits) error {
	var (
		nodes    int64
		depth    int
		maxDepth int
		retErr   error
	)
	var walk func(node syntax.Node) bool
	walk = func(node syntax.Node) bool {
		if retErr != nil {
			return false
		}
		if node == nil {
			depth--
			return false
		}
		depth++
		if depth > maxDepth {
			maxDepth = depth
		}
		nodes++
		if !unbounded(lim.MaxASTNodes) && nodes > lim.MaxASTNodes {
			retErr = &LimitError{Kind: LimitASTNodes, Limit: lim.MaxASTNodes}
			return false
		}
		if !unbounded(lim.MaxASTDepth) && int64(maxDepth) > lim.MaxASTDepth {
			retErr = &LimitError{Kind: LimitASTDepth, Limit: lim.MaxASTDepth}
			return false
		}

		switch n := node.(type) {
		case *syntax.Stmt:
			if n.Background {
				retErr = unsupported("background", n.Pos())
				return false
			}
			if n.Coprocess {
				retErr = unsupported("coproc", n.Pos())
				return false
			}
			if n.Disown {
				retErr = unsupported("disown", n.Pos())
				return false
			}
		case *syntax.ProcSubst:
			retErr = unsupported("process-substitution", n.Pos())
			return false
		case *syntax.CoprocClause:
			retErr = unsupported("coproc", n.Pos())
			return false
		case *syntax.BinaryCmd:
			if n.Op == syntax.Pipe || n.Op == syntax.PipeAll {
				if l := pipelineLen(n); !unbounded(lim.MaxPipelineLength) && int64(l) > lim.MaxPipelineLength {
					retErr = &LimitError{Kind: LimitPipelineLength, Limit: lim.MaxPipelineLength}
					return false
				}
			}
		case *syntax.CmdSubst:
			if d := cmdSubstDepth(n); !unbounded(lim.MaxCmdSubstDepth) && int64(d) > lim.MaxCmdSubstDepth {
				retErr = &LimitError{Kind: LimitCmdSubstDepth, Limit: lim.MaxCmdSubstDepth}
				return false
			}
		}
		return true
	}
	syntax.Walk(file, walk)
	return retErr
}

func unsupported(construct string, pos syntax.Pos) *UnsupportedError {
	return &UnsupportedError{Construct: construct, Line: pos.Line(), Col: pos.Col()}
}

// pipelineLen returns the number of stages in a left-associative pipe chain
// rooted at b.
func pipelineLen(b *syntax.BinaryCmd) int {
	count := 2
	x := b.X
	for x != nil {
		inner, ok := x.Cmd.(*syntax.BinaryCmd)
		if !ok || (inner.Op != syntax.Pipe && inner.Op != syntax.PipeAll) {
			break
		}
		count++
		x = inner.X
	}
	return count
}

// cmdSubstDepth returns the maximum nesting depth of command substitutions at
// or below n.
func cmdSubstDepth(n *syntax.CmdSubst) int {
	max := 1
	for _, stmt := range n.Stmts {
		syntax.Walk(stmt, func(node syntax.Node) bool {
			if inner, ok := node.(*syntax.CmdSubst); ok && inner != n {
				if d := cmdSubstDepth(inner) + 1; d > max {
					max = d
				}
				return false
			}
			return true
		})
	}
	return max
}

// cappedWriter wraps a destination writer and accounts every byte against the
// run's MaxOutputBytes budget (S12). Bytes beyond the cap are silently dropped;
// the breach is recorded on the Governor and surfaced as a host LimitError
// after the run. It serializes writes so concurrent pipeline stages are
// race-free.
type cappedWriter struct {
	mu  sync.Mutex
	w   io.Writer
	gov *Governor
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	allowed := c.gov.accountOutput(len(p))
	if allowed > 0 {
		if _, err := c.w.Write(p[:allowed]); err != nil {
			return 0, err
		}
	}
	// Report the full length so commands do not see short writes; truncation is
	// intentional and reported separately as a LimitError.
	return len(p), nil
}

// fsAdapter bridges our FileSystem to mvdan/sh's open/stat/readdir handlers,
// resolving every path to an absolute, cleaned POSIX path against the runner's
// working directory before calling the backend (S3/S4). Errors are returned as
// *fs.PathError with the virtual path so script-visible messages never leak
// host paths (S25).
type fsAdapter struct {
	fsys FileSystem
}

func absFromCtx(ctx context.Context, name string) string {
	if path.IsAbs(name) {
		return cleanAbs(name)
	}
	dir := interp.HandlerCtx(ctx).Dir
	if dir == "" {
		dir = "/"
	}
	return cleanAbs(path.Join(dir, name))
}

// openHandler adapts FileSystem.Open. It returns an io.ReadWriteCloser backed
// by the VFS; it NEVER touches the host disk.
func (a fsAdapter) openHandler(ctx context.Context, name string, flag int, perm fs.FileMode) (io.ReadWriteCloser, error) {
	abs := absFromCtx(ctx, name)
	f, err := a.fsys.Open(abs, flag, perm)
	if err != nil {
		return nil, asPathError("open", abs, err)
	}
	return f, nil
}

func (a fsAdapter) statHandler(ctx context.Context, name string, follow bool) (fs.FileInfo, error) {
	abs := absFromCtx(ctx, name)
	var (
		fi  fs.FileInfo
		err error
	)
	if follow {
		fi, err = a.fsys.Stat(abs)
	} else {
		fi, err = a.fsys.Lstat(abs)
	}
	if err != nil {
		return nil, asPathError("stat", abs, err)
	}
	return fi, nil
}

func (a fsAdapter) readDirHandler(ctx context.Context, name string) ([]fs.DirEntry, error) {
	abs := absFromCtx(ctx, name)
	entries, err := a.fsys.ReadDir(abs)
	if err != nil {
		return nil, asPathError("readdir", abs, err)
	}
	return entries, nil
}

// asPathError ensures FS errors reaching mvdan are *fs.PathError with a virtual
// path, which mvdan prints cleanly to stderr. A *LimitError is preserved as-is
// so it propagates as a host fatal error.
func asPathError(op, virtualPath string, err error) error {
	var le *LimitError
	if errors.As(err, &le) {
		return le
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		// Re-wrap to guarantee the virtual path (never a host path).
		return &fs.PathError{Op: pe.Op, Path: virtualPath, Err: pe.Err}
	}
	return &fs.PathError{Op: op, Path: virtualPath, Err: err}
}

// newSecureRunner constructs the interp.Runner with EVERY option set explicitly
// (S1, fail-closed). mvdan/sh's defaults inherit os.Environ and the real
// FS/exec, so any omitted option silently breaks the sandbox. This is the only
// place a Runner is built.
func (s *Shell) newSecureRunner(rs *runState) (*interp.Runner, error) {
	adapter := fsAdapter{fsys: rs.fsys}

	runner, err := interp.New(
		// S1/S23: explicit env, EMPTY by default (never os.Environ).
		interp.Env(expand.ListEnviron(rs.envPairs...)),
		// "/" always exists on the host, so this passes mvdan's construction-time
		// stat without leaking; we immediately override Dir to the virtual cwd
		// below so no host path is ever used at runtime.
		interp.Dir("/"),
		// Positional parameters ($1, $@, ...).
		interp.Params(rs.args...),
		// Bounded, capped stdio (S12). Never the host's os.Stdout/err.
		interp.StdIO(rs.stdin, rs.stdout, rs.stderr),
		// VFS-only filesystem handlers (S3/S4). No host disk.
		interp.OpenHandler(adapter.openHandler),
		interp.StatHandler(adapter.statHandler),
		interp.ReadDirHandler2(adapter.readDirHandler),
		// Admission layer consulted for EVERY command incl. builtins (S2).
		interp.CallHandler(s.callHandler(rs)),
		// Registry-only execution; unknown command -> 127, never os/exec (S2b).
		interp.ExecHandlers(s.execMiddleware(rs)),
	)
	if err != nil {
		return nil, err
	}
	// Override the working directory with the virtual cwd. interp.Dir stats the
	// host filesystem, so we cannot pass a virtual path through it; setting the
	// exported field directly makes Reset/PWD use the sandbox path instead.
	runner.Dir = rs.cwd
	return runner, nil
}

// callHandler builds the CallHandler: it counts every command against the
// governor (S9/S10/S14a) and enforces builtin admission (S2) by rerouting
// denied/shadowed builtins to the ExecHandler via NUL-prefixed sentinels.
func (s *Shell) callHandler(rs *runState) interp.CallHandlerFunc {
	return func(ctx context.Context, args []string) ([]string, error) {
		if len(args) == 0 {
			return args, nil
		}
		hc := interp.HandlerCtx(ctx)

		// Resource governance: command count + per-call-site loop bound.
		if le := rs.governor.countCommand(uint64(hc.Pos.Offset())); le != nil {
			return nil, le
		}
		// Expansion-time bounds (S14a): argv byte size and expanded word count.
		if le := checkArgvBounds(args, rs.governor.Limits()); le != nil {
			return nil, le
		}

		name := args[0]
		if interp.IsBuiltin(name) {
			switch rs.policy.mode(name) {
			case builtinAllow:
				return args, nil
			case builtinShadow:
				out := append([]string{shadowPrefix + name}, args[1:]...)
				return out, nil
			default: // builtinDeny
				out := append([]string{denyPrefix + name}, args[1:]...)
				return out, nil
			}
		}
		// Not a builtin: a shell function (mvdan runs it) or an external command
		// (routed to the registry by the ExecHandler).
		return args, nil
	}
}

// checkArgvBounds enforces MaxArgvBytes and MaxExpandedWords for a single,
// already-expanded command (S14a).
func checkArgvBounds(args []string, lim Limits) *LimitError {
	if !unbounded(lim.MaxExpandedWords) && int64(len(args)) > lim.MaxExpandedWords {
		return &LimitError{Kind: LimitExpandedWords, Limit: lim.MaxExpandedWords}
	}
	if !unbounded(lim.MaxArgvBytes) {
		var total int64
		for _, a := range args {
			total += int64(len(a))
			if total > lim.MaxArgvBytes {
				return &LimitError{Kind: LimitArgvBytes, Limit: lim.MaxArgvBytes}
			}
		}
	}
	return nil
}

// execMiddleware builds the registry-only ExecHandler. It NEVER calls the next
// handler, so mvdan's default os/exec handler is unreachable (S2b). Denied
// builtins (rerouted here) produce a clean non-zero status; unknown commands
// produce 127.
func (s *Shell) execMiddleware(rs *runState) func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if len(args) == 0 {
				return interp.NewExitStatus(0)
			}
			name := args[0]

			if rest, ok := strings.CutPrefix(name, denyPrefix); ok {
				fmt.Fprintf(rs.stderr, "gosh: %s: command disabled\n", rest)
				return interp.NewExitStatus(126)
			}
			if rest, ok := strings.CutPrefix(name, shadowPrefix); ok {
				name = rest
			}

			cmd, ok := rs.registry[name]
			if !ok {
				fmt.Fprintf(rs.stderr, "gosh: %s: command not found\n", name)
				return interp.NewExitStatus(127)
			}

			hc := interp.HandlerCtx(ctx)
			code := s.dispatch(ctx, rs, cmd, name, args[1:], hc.Stdin, hc.Stdout, hc.Stderr, hc.Dir, hc.Env)
			if code == 0 {
				return nil
			}
			return interp.NewExitStatus(uint8(code))
		}
	}
}

// dispatch builds a CommandContext and runs a registered command.
func (s *Shell) dispatch(ctx context.Context, rs *runState, cmd Command, name string, args []string, stdin io.Reader, stdout, stderr io.Writer, cwd string, env expand.Environ) int {
	cc := &CommandContext{
		Name:     name,
		Args:     args,
		Stdin:    stdin,
		Stdout:   stdout,
		Stderr:   stderr,
		Env:      envFromExpand(env),
		cwd:      cleanAbs(cwd),
		fsys:     rs.fsys,
		clock:    rs.clock,
		governor: rs.governor,
		network:  s.network,
		exec:     s.subExec(rs),
	}
	return cmd.Run(ctx, cc)
}

// subExec returns the function backing CommandContext.Exec: it dispatches a
// sub-command through the same registry and world, enabling composition.
func (s *Shell) subExec(rs *runState) func(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, cwd string) int {
	return func(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, cwd string) int {
		if len(args) == 0 {
			return 0
		}
		if le := rs.governor.countCommand(0); le != nil {
			fmt.Fprintf(stderr, "%s\n", le.Error())
			return 1
		}
		name := args[0]
		cmd, ok := rs.registry[name]
		if !ok {
			fmt.Fprintf(stderr, "gosh: %s: command not found\n", name)
			return 127
		}
		cc := &CommandContext{
			Name:     name,
			Args:     args[1:],
			Stdin:    stdin,
			Stdout:   stdout,
			Stderr:   stderr,
			Env:      envClone(rs.envPairs),
			cwd:      cleanAbs(cwd),
			fsys:     rs.fsys,
			clock:    rs.clock,
			governor: rs.governor,
			network:  s.network,
			exec:     s.subExec(rs),
		}
		return cmd.Run(ctx, cc)
	}
}

// envFromExpand snapshots an expand.Environ into a command-local EnvAccessor.
func envFromExpand(env expand.Environ) EnvAccessor {
	m := make(map[string]string)
	if env != nil {
		env.Each(func(name string, vr expand.Variable) bool {
			if vr.IsSet() {
				m[name] = vr.String()
			}
			return true
		})
	}
	return &mapEnv{m: m}
}

// envClone builds an EnvAccessor from KEY=VALUE pairs.
func envClone(pairs []string) EnvAccessor {
	m := make(map[string]string, len(pairs))
	for _, p := range pairs {
		if i := strings.IndexByte(p, '='); i >= 0 {
			m[p[:i]] = p[i+1:]
		}
	}
	return &mapEnv{m: m}
}

// renderRunError maps the error returned by interp.Runner.Run to gosh's typed
// host errors and the script exit code. A non-zero script exit is NOT a host
// error. Cancellation, limit breaches, and internal failures ARE.
func renderRunError(err error, gov *Governor) (exitCode int, hostErr error) {
	// An output-cap breach is recorded on the governor even when Run itself
	// returns a benign status; surface it as the host error.
	if le := gov.OutputLimitErr(); le != nil {
		var status interp.ExitStatus
		if errors.As(err, &status) {
			return int(status), le
		}
		return 1, le
	}

	if err == nil {
		return 0, nil
	}

	var le *LimitError
	if errors.As(err, &le) {
		return 1, le
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return 130, &CanceledError{Cause: err}
	}
	var ue *UnsupportedError
	if errors.As(err, &ue) {
		return 1, ue
	}
	var status interp.ExitStatus
	if errors.As(err, &status) {
		return int(status), nil
	}
	if s, ok := interp.IsExitStatus(err); ok {
		return int(s), nil
	}
	return 1, &InternalError{Cause: err}
}
