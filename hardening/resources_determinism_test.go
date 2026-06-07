package hardening_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/darylcecile/gosh"
)

// TestResourceExhaustionIsBounded attacks loop/output/expansion/pipeline/recursion DoS paths (S9-S14, S13, S14a).
func TestResourceExhaustionIsBounded(t *testing.T) {
	t.Run("infinite loop hits command or loop governor", func(t *testing.T) {
		sh := hardenedShell(gosh.WithLimits(gosh.Limits{MaxCommands: 100, MaxLoopIterations: 50}))
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := sh.Run(ctx, `while true; do :; done`)
		var le *gosh.LimitError
		if !errors.As(err, &le) || (le.Kind != gosh.LimitCommands && le.Kind != gosh.LimitLoopIterations) {
			t.Fatalf("want command/loop LimitError, got %T %v", err, err)
		}
	})

	t.Run("output bomb is truncated and reported", func(t *testing.T) {
		sh := hardenedShell(gosh.WithLimits(gosh.Limits{MaxOutputBytes: 64, MaxCommands: 10000, MaxLoopIterations: 10000}))
		got := runScript(t, sh, `i=0; while [ $i -lt 1000 ]; do printf 0123456789; i=$((i+1)); done`)
		var le *gosh.LimitError
		if !errors.As(got.err, &le) || le.Kind != gosh.LimitOutputBytes {
			t.Fatalf("want output LimitError, got exit=%d err=%T %v stdout-len=%d", got.res.ExitCode, got.err, got.err, len(got.stdout))
		}
		if len(got.stdout) > 64 {
			t.Fatalf("output not capped: len=%d", len(got.stdout))
		}
	})

	t.Run("pipeline and expansion are rejected before unbounded work", func(t *testing.T) {
		pipe := runScript(t, hardenedShell(gosh.WithLimits(gosh.Limits{MaxPipelineLength: 3})), `echo x | cat | cat | cat | cat`)
		var le *gosh.LimitError
		if !errors.As(pipe.err, &le) || le.Kind != gosh.LimitPipelineLength {
			t.Fatalf("want pipeline LimitError, got %T %v", pipe.err, pipe.err)
		}

		exp := runScript(t, hardenedShell(gosh.WithLimits(gosh.Limits{MaxExpandedWords: 10})), `printf '%s\n' {1..1000}`)
		if !errors.As(exp.err, &le) || le.Kind != gosh.LimitExpandedWords {
			t.Fatalf("want expansion LimitError, got exit=%d err=%T %v stdout=%q stderr=%q", exp.res.ExitCode, exp.err, exp.err, exp.stdout, exp.stderr)
		}
	})

	t.Run("stream iteration cap bounds text processors", func(t *testing.T) {
		sh := hardenedShell(gosh.WithLimits(gosh.Limits{MaxStreamIterations: 5, MaxCommands: 1000, MaxOutputBytes: 4096}))
		got := runScript(t, sh, `printf 'a\na\na\na\na\na\na\n' | grep a`)
		assertBlocked(t, got, "grep stream cap")
		if !strings.Contains(got.stderr, "max_stream_iterations") {
			t.Fatalf("want stream cap in stderr, got stdout=%q stderr=%q err=%v", got.stdout, got.stderr, got.err)
		}
	})

	t.Run("deep recursion returns control", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := hardenedShell(gosh.WithLimits(gosh.Limits{MaxCommands: 1000, MaxLoopIterations: 1000, MaxCallDepth: 32})).Run(ctx, `f(){ f; }; f`)
		if err == nil {
			t.Fatalf("want recursion to be contained by host error")
		}
	})
}

// TestVirtualClockAndFilesystemDeterminism validates reproducible clock and filesystem behavior (S24).
func TestVirtualClockAndFilesystemDeterminism(t *testing.T) {
	script := `date; date -u +%FT%TZ; sleep 2; date -u +%s`
	first := runScript(t, hardenedShell(), script)
	second := runScript(t, hardenedShell(), script)
	if first.err != nil || second.err != nil || first.res.ExitCode != 0 || second.res.ExitCode != 0 {
		t.Fatalf("date/sleep failed: first=%+v second=%+v", first, second)
	}
	if first.stdout != second.stdout {
		t.Fatalf("virtual clock not reproducible: first=%q second=%q", first.stdout, second.stdout)
	}

	fsScript := `mkdir -p /work; printf 'data\n' > /work/a; printf 'more\n' > /work/b; find / -type f | sort | while read p; do printf '%s=' "$p"; cat "$p"; done`
	fs1 := runScript(t, hardenedShell(), fsScript)
	fs2 := runScript(t, hardenedShell(), fsScript)
	if fs1.err != nil || fs2.err != nil || fs1.res.ExitCode != 0 || fs2.res.ExitCode != 0 {
		t.Fatalf("snapshot script failed: fs1=%+v fs2=%+v", fs1, fs2)
	}
	if fs1.stdout != fs2.stdout {
		t.Fatalf("identical filesystem runs diverged: first=%q second=%q", fs1.stdout, fs2.stdout)
	}
}
