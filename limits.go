package gosh

import (
	"sync"
)

// Limits configures every cooperative resource governor (S8–S14a). All limits
// have safe non-zero defaults via DefaultLimits. A value of 0 for a numeric
// limit means "use the default"; to truly disable a specific limit, set it to a
// negative value (interpreted as unbounded). Disabling limits widens the DoS
// attack surface and is discouraged.
type Limits struct {
	// --- Execution governors (S9–S13) ---

	// MaxCommands caps the total number of simple commands executed in a run
	// (S9). It is the primary backstop against runaway scripts.
	MaxCommands int64
	// MaxLoopIterations caps how many times any single command call-site may
	// execute (S10). Because a loop body re-executes the same source position
	// each iteration, this effectively bounds for/while/until loops and
	// repeated/recursive call-sites.
	MaxLoopIterations int64
	// MaxCallDepth bounds shell function recursion depth (S11). Enforcement is
	// best-effort: the underlying interpreter exposes no function-return hook,
	// so deep recursion is primarily bounded by MaxCommands and
	// MaxLoopIterations, and any stack-overflow panic is recovered into an
	// InternalError rather than crashing the host.
	MaxCallDepth int64
	// MaxOutputBytes caps cumulative bytes written to the run's stdout+stderr
	// (S12). On breach, further output is discarded and a LimitError is
	// returned from Run while the captured (truncated) output is still
	// available on Result.
	MaxOutputBytes int64
	// MaxStreamIterations caps per-command stream/record iterations for
	// stream-processing commands such as awk/sed/grep (S13). Commands consult
	// it via CommandContext.Governor().StreamTick.
	MaxStreamIterations int64
	// MaxMemoryBytes is a best-effort ceiling on in-memory VFS + buffer growth
	// (S14). It is advisory and not a hard kernel limit.
	MaxMemoryBytes int64

	// --- Pre-exec / expansion bounds (S14a) ---

	// MaxScriptBytes rejects scripts larger than this many bytes before parsing.
	MaxScriptBytes int64
	// MaxASTNodes caps the number of parsed syntax-tree nodes.
	MaxASTNodes int64
	// MaxASTDepth caps syntax-tree nesting depth.
	MaxASTDepth int64
	// MaxArgvBytes caps the total byte size of a single command's argv.
	MaxArgvBytes int64
	// MaxExpandedWords caps the number of words produced by a single expansion
	// (brace/glob/parameter expansion).
	MaxExpandedWords int64
	// MaxGlobMatches caps how many paths a single glob may match.
	MaxGlobMatches int64
	// MaxPipelineLength caps the number of stages in a single pipeline.
	MaxPipelineLength int64
	// MaxCmdSubstDepth caps command-substitution nesting depth.
	MaxCmdSubstDepth int64

	// --- Filesystem caps (S7) ---

	// MaxFileBytes caps the size of a single file in the in-memory VFS.
	MaxFileBytes int64
	// MaxTotalFSBytes caps the total bytes stored across the in-memory VFS.
	MaxTotalFSBytes int64
}

// DefaultLimits returns the safe default limits applied by New when no
// WithLimits option is supplied. The values are tuned so that legitimate agent
// scripts run unimpeded while pathological scripts are stopped quickly.
func DefaultLimits() Limits {
	return Limits{
		MaxCommands:         100_000,
		MaxLoopIterations:   1_000_000,
		MaxCallDepth:        1_000,
		MaxOutputBytes:      32 << 20, // 32 MiB
		MaxStreamIterations: 10_000_000,
		MaxMemoryBytes:      256 << 20, // 256 MiB

		MaxScriptBytes:    1 << 20, // 1 MiB
		MaxASTNodes:       250_000,
		MaxASTDepth:       500,
		MaxArgvBytes:      1 << 20, // 1 MiB
		MaxExpandedWords:  100_000,
		MaxGlobMatches:    100_000,
		MaxPipelineLength: 256,
		MaxCmdSubstDepth:  64,

		MaxFileBytes:    64 << 20,  // 64 MiB
		MaxTotalFSBytes: 256 << 20, // 256 MiB
	}
}

// withDefaults returns a copy of l where any zero-valued limit is replaced by
// the corresponding default. Negative values are preserved (meaning unbounded).
func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	pick := func(v, def int64) int64 {
		if v == 0 {
			return def
		}
		return v
	}
	return Limits{
		MaxCommands:         pick(l.MaxCommands, d.MaxCommands),
		MaxLoopIterations:   pick(l.MaxLoopIterations, d.MaxLoopIterations),
		MaxCallDepth:        pick(l.MaxCallDepth, d.MaxCallDepth),
		MaxOutputBytes:      pick(l.MaxOutputBytes, d.MaxOutputBytes),
		MaxStreamIterations: pick(l.MaxStreamIterations, d.MaxStreamIterations),
		MaxMemoryBytes:      pick(l.MaxMemoryBytes, d.MaxMemoryBytes),
		MaxScriptBytes:      pick(l.MaxScriptBytes, d.MaxScriptBytes),
		MaxASTNodes:         pick(l.MaxASTNodes, d.MaxASTNodes),
		MaxASTDepth:         pick(l.MaxASTDepth, d.MaxASTDepth),
		MaxArgvBytes:        pick(l.MaxArgvBytes, d.MaxArgvBytes),
		MaxExpandedWords:    pick(l.MaxExpandedWords, d.MaxExpandedWords),
		MaxGlobMatches:      pick(l.MaxGlobMatches, d.MaxGlobMatches),
		MaxPipelineLength:   pick(l.MaxPipelineLength, d.MaxPipelineLength),
		MaxCmdSubstDepth:    pick(l.MaxCmdSubstDepth, d.MaxCmdSubstDepth),
		MaxFileBytes:        pick(l.MaxFileBytes, d.MaxFileBytes),
		MaxTotalFSBytes:     pick(l.MaxTotalFSBytes, d.MaxTotalFSBytes),
	}
}

// unbounded reports whether a limit value means "no limit" (negative).
func unbounded(v int64) bool { return v < 0 }

// Governor tracks live resource counters for a single Run and enforces the
// configured Limits. A fresh Governor is created per Run, so counters never
// bleed across runs. It is safe for concurrent use because pipelines may write
// output from multiple goroutines.
//
// Commands receive the Governor via CommandContext.Governor() and should call
// StreamTick once per processed record/line so that stream-heavy commands
// (awk/sed/grep) stay within MaxStreamIterations (S13).
type Governor struct {
	limits Limits

	mu         sync.Mutex
	commands   int64
	output     int64
	stream     int64
	posCounts  map[uint64]int64
	firstLimit *LimitError // first breach recorded (e.g. output cap) for deferred reporting
	outputDone bool        // true once the output cap has been hit
}

// newGovernor builds a Governor for one run from already-defaulted limits.
func newGovernor(limits Limits) *Governor {
	return &Governor{limits: limits, posCounts: make(map[uint64]int64)}
}

// Limits returns the effective limits in force for this run.
func (g *Governor) Limits() Limits { return g.limits }

// countCommand records execution of a simple command at the given source
// offset. It enforces MaxCommands (S9) and MaxLoopIterations (S10, via
// per-call-site repetition). It returns a *LimitError on breach.
func (g *Governor) countCommand(offset uint64) *LimitError {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.commands++
	if !unbounded(g.limits.MaxCommands) && g.commands > g.limits.MaxCommands {
		return &LimitError{Kind: LimitCommands, Limit: g.limits.MaxCommands}
	}
	if !unbounded(g.limits.MaxLoopIterations) {
		g.posCounts[offset]++
		if g.posCounts[offset] > g.limits.MaxLoopIterations {
			return &LimitError{Kind: LimitLoopIterations, Limit: g.limits.MaxLoopIterations}
		}
	}
	return nil
}

// accountOutput records n bytes about to be written to script stdout/stderr and
// returns how many of those bytes are permitted (the rest must be discarded).
// Once the cap is exceeded it records a LimitError (retrievable via
// OutputLimitErr) so Run can surface it after capturing truncated output (S12).
func (g *Governor) accountOutput(n int) int {
	if unbounded(g.limits.MaxOutputBytes) {
		return n
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	remaining := g.limits.MaxOutputBytes - g.output
	if remaining <= 0 {
		if !g.outputDone {
			g.outputDone = true
			g.recordLocked(&LimitError{Kind: LimitOutputBytes, Limit: g.limits.MaxOutputBytes})
		}
		return 0
	}
	if int64(n) <= remaining {
		g.output += int64(n)
		return n
	}
	g.output = g.limits.MaxOutputBytes
	if !g.outputDone {
		g.outputDone = true
		g.recordLocked(&LimitError{Kind: LimitOutputBytes, Limit: g.limits.MaxOutputBytes})
	}
	return int(remaining)
}

// OutputLimitErr returns the recorded output-limit breach, if any, so the
// engine can report it as a host error after the run completes.
func (g *Governor) OutputLimitErr() *LimitError {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.firstLimit != nil && g.firstLimit.Kind == LimitOutputBytes {
		return g.firstLimit
	}
	return nil
}

func (g *Governor) recordLocked(e *LimitError) {
	if g.firstLimit == nil {
		g.firstLimit = e
	}
}

// StreamTick records one unit of work inside a stream-processing command and
// enforces MaxStreamIterations (S13). Commands such as awk/sed/grep should call
// it once per input record. It returns a *LimitError when the cap is exceeded;
// the command should stop and propagate a non-zero exit.
func (g *Governor) StreamTick() *LimitError {
	if unbounded(g.limits.MaxStreamIterations) {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stream++
	if g.stream > g.limits.MaxStreamIterations {
		return &LimitError{Kind: LimitStreamIterations, Limit: g.limits.MaxStreamIterations}
	}
	return nil
}

// Commands returns the number of simple commands executed so far this run.
func (g *Governor) Commands() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.commands
}
