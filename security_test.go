package gosh_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/darylcecile/gosh"
)

// TestBuiltinBypassHolesClosed verifies that builtins which can dispatch other
// builtins directly (command, builtin) — thereby bypassing the CallHandler
// admission layer — are denied by default, so they cannot be used to smuggle a
// denied builtin like eval (S2).
func TestBuiltinBypassHolesClosed(t *testing.T) {
	sh := gosh.New()
	for _, script := range []string{
		`command eval 'echo pwned'`,
		`builtin eval 'echo pwned'`,
		`command echo pwned`,
		`builtin echo pwned`,
	} {
		res, err := sh.Run(context.Background(), script)
		if err != nil {
			t.Fatalf("%q: host error %v", script, err)
		}
		if strings.Contains(res.Stdout, "pwned") {
			t.Fatalf("%q: bypass succeeded, stdout=%q", script, res.Stdout)
		}
		if res.ExitCode == 0 {
			t.Fatalf("%q: expected non-zero exit", script)
		}
	}
}

// TestSourceDenied confirms source/. are denied by default (no script-file
// execution unless explicitly enabled).
func TestSourceDenied(t *testing.T) {
	sh := gosh.New(gosh.WithFiles(map[string]string{"/home/user/lib.sh": "echo sourced"}))
	for _, script := range []string{`source /home/user/lib.sh`, `. /home/user/lib.sh`} {
		res, _ := sh.Run(context.Background(), script)
		if strings.Contains(res.Stdout, "sourced") {
			t.Fatalf("%q: source should be denied, stdout=%q", script, res.Stdout)
		}
	}
}

// TestSafeBuiltinsWork confirms the allow-listed shell-control builtins run.
func TestSafeBuiltinsWork(t *testing.T) {
	sh := gosh.New()
	res, err := sh.Run(context.Background(), `
mkdir_done=skip
cd /
pwd
export X=1
echo "X=$X"
if [ -n "$X" ]; then echo yes; fi
`)
	if err != nil {
		t.Fatalf("host error: %v", err)
	}
	want := "/\nX=1\nyes\n"
	if res.Stdout != want {
		t.Fatalf("stdout=%q want %q", res.Stdout, want)
	}
}

// TestFunctionsAndRecursionBacktop confirms user functions run and that
// unbounded recursion is stopped by the command/loop governors rather than
// crashing the host (S11/S16).
func TestFunctionsAndRecursion(t *testing.T) {
	sh := gosh.New()
	res, err := sh.Run(context.Background(), `
greet() { echo "hi $1"; }
greet world
`)
	if err != nil {
		t.Fatalf("host error: %v", err)
	}
	if res.Stdout != "hi world\n" {
		t.Fatalf("stdout=%q", res.Stdout)
	}

	// Infinite recursion must be stopped by a governor, not a host crash.
	rsh := gosh.New(gosh.WithLimits(gosh.Limits{MaxCommands: 5000, MaxLoopIterations: 5000}))
	_, rerr := rsh.Run(context.Background(), `f() { f; }; f`)
	if rerr == nil {
		t.Fatalf("expected a limit error for infinite recursion")
	}
}

// TestShadowedHelpRoutesToRegistry confirms a registered `help` command runs
// even though help is an mvdan builtin (it is shadowed by policy).
func TestShadowedHelpRoutesToRegistry(t *testing.T) {
	help := gosh.CommandFunc("help", func(ctx context.Context, cc *gosh.CommandContext) int {
		cc.Stdout.Write([]byte("custom help\n"))
		return 0
	})
	sh := gosh.New(gosh.WithCommands(help))
	res, err := sh.Run(context.Background(), `help`)
	if err != nil {
		t.Fatalf("host error: %v", err)
	}
	if res.Stdout != "custom help\n" {
		t.Fatalf("stdout=%q", res.Stdout)
	}
}

// TestPipelineLengthLimit confirms over-long pipelines are rejected pre-exec
// (S14a).
func TestPipelineLengthLimit(t *testing.T) {
	sh := gosh.New(gosh.WithLimits(gosh.Limits{MaxPipelineLength: 3}))
	_, err := sh.Run(context.Background(), `echo a | cat | cat | cat | cat`)
	var le *gosh.LimitError
	if !errors.As(err, &le) || le.Kind != gosh.LimitPipelineLength {
		t.Fatalf("want pipeline LimitError, got %T: %v", err, err)
	}
}

// TestASTDepthLimit confirms deeply nested scripts are rejected at parse-time
// (S14a).
func TestASTDepthLimit(t *testing.T) {
	sh := gosh.New(gosh.WithLimits(gosh.Limits{MaxASTDepth: 5}))
	deep := strings.Repeat("if true; then ", 20) + "echo x" + strings.Repeat("; fi", 20)
	_, err := sh.Run(context.Background(), deep)
	var le *gosh.LimitError
	if !errors.As(err, &le) {
		t.Fatalf("want LimitError for deep AST, got %T: %v", err, err)
	}
}
