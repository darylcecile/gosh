package gosh

import (
	"errors"
	"fmt"
)

// ErrNotFound is the sentinel returned when a referenced command is not present
// in the registry. It is exposed so hosts can match it via errors.Is, although
// in normal script execution an unknown command surfaces as exit code 127
// rather than a host-level error.
var ErrNotFound = errors.New("gosh: command not found")

// LimitKind identifies which configured governor limit was exceeded. It is the
// stable, machine-readable discriminator carried by LimitError.
type LimitKind string

// The set of limit kinds. Each corresponds to a field on Limits (see limits.go)
// and to a security requirement in the PRD (S8–S14a).
const (
	LimitCommands         LimitKind = "max_commands"          // S9
	LimitLoopIterations   LimitKind = "max_loop_iterations"   // S10
	LimitCallDepth        LimitKind = "max_call_depth"        // S11
	LimitOutputBytes      LimitKind = "max_output_bytes"      // S12
	LimitStreamIterations LimitKind = "max_stream_iterations" // S13
	LimitMemoryBytes      LimitKind = "max_memory_bytes"      // S14
	LimitScriptBytes      LimitKind = "max_script_bytes"      // S14a
	LimitASTNodes         LimitKind = "max_ast_nodes"         // S14a
	LimitASTDepth         LimitKind = "max_ast_depth"         // S14a
	LimitArgvBytes        LimitKind = "max_argv_bytes"        // S14a
	LimitExpandedWords    LimitKind = "max_expanded_words"    // S14a
	LimitGlobMatches      LimitKind = "max_glob_matches"      // S14a
	LimitPipelineLength   LimitKind = "max_pipeline_length"   // S14a
	LimitCmdSubstDepth    LimitKind = "max_cmd_subst_depth"   // S14a
	LimitFileBytes        LimitKind = "max_file_bytes"        // S7
	LimitTotalFSBytes     LimitKind = "max_total_fs_bytes"    // S7
)

// LimitError is returned as a host-level error from Shell.Run when execution
// breaches one of the configured governor limits. It names the specific limit
// so callers (and models) can react. It is matchable via errors.As.
type LimitError struct {
	// Kind is the limit that was hit.
	Kind LimitKind
	// Limit is the configured numeric bound that was exceeded.
	Limit int64
	// Detail optionally adds human-readable context (never host paths/state).
	Detail string
}

// Error implements the error interface with a stable, host-path-free message.
func (e *LimitError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("gosh: limit exceeded (%s=%d): %s", e.Kind, e.Limit, e.Detail)
	}
	return fmt.Sprintf("gosh: limit exceeded (%s=%d)", e.Kind, e.Limit)
}

// ParseError wraps a syntax error from the underlying Bash parser. It never
// embeds host stack traces; only the virtual filename, position, and message
// are surfaced (S25).
type ParseError struct {
	// Filename is the virtual script name (default "script").
	Filename string
	// Line and Col are 1-based source coordinates of the error.
	Line uint
	Col  uint
	// Msg is the parser's human-readable message.
	Msg string
	// Incomplete is true when the script ended in the middle of a construct.
	Incomplete bool
}

// Error implements the error interface.
func (e *ParseError) Error() string {
	return fmt.Sprintf("gosh: parse error at %s:%d:%d: %s", e.Filename, e.Line, e.Col, e.Msg)
}

// UnsupportedError is returned when a script uses a construct that gosh refuses
// to execute by policy (S2a): background jobs (&), process substitution,
// coprocesses, or redirects to unsupported special file descriptors/host paths.
// Rejection happens before any statement runs.
type UnsupportedError struct {
	// Construct is a short identifier for the rejected feature, e.g.
	// "background", "process-substitution", "coproc".
	Construct string
	// Line and Col locate the construct in the virtual script.
	Line uint
	Col  uint
}

// Error implements the error interface.
func (e *UnsupportedError) Error() string {
	return fmt.Sprintf("gosh: unsupported construct %q at script:%d:%d", e.Construct, e.Line, e.Col)
}

// CanceledError is returned when the context passed to Run is canceled or its
// deadline is exceeded. The originating context error is wrapped and matchable
// via errors.Is(err, context.Canceled) / context.DeadlineExceeded (F11/S8).
type CanceledError struct {
	// Cause is the underlying context error.
	Cause error
}

// Error implements the error interface.
func (e *CanceledError) Error() string {
	return fmt.Sprintf("gosh: execution canceled: %v", e.Cause)
}

// Unwrap exposes the underlying context error for errors.Is matching.
func (e *CanceledError) Unwrap() error { return e.Cause }

// InternalError wraps an unexpected failure inside the trusted computing base
// (for example a recovered panic from the interpreter). The message is
// sanitized of host paths and stack traces before reaching script output; the
// full Go error is available to the host via Unwrap.
type InternalError struct {
	// Cause is the wrapped internal error.
	Cause error
}

// Error implements the error interface.
func (e *InternalError) Error() string {
	return fmt.Sprintf("gosh: internal error: %v", e.Cause)
}

// Unwrap exposes the wrapped error.
func (e *InternalError) Unwrap() error { return e.Cause }
