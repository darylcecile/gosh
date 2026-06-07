package gosh_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/darylcecile/gosh"
)

// testCommands returns a small set of registered commands used to exercise the
// registry, pipes, and redirection without depending on the (not-yet-built)
// coreutils packages.
func testCommands() []gosh.Command {
	cat := gosh.CommandFunc("cat", func(ctx context.Context, cc *gosh.CommandContext) int {
		if len(cc.Args) == 0 {
			_, _ = io.Copy(cc.Stdout, cc.Stdin)
			return 0
		}
		code := 0
		for _, arg := range cc.Args {
			f, err := cc.FS().Open(cc.ResolvePath(arg), 0 /*O_RDONLY*/, 0)
			if err != nil {
				// Render a clean, host-path-free message.
				cc.Stderr.Write([]byte("cat: " + arg + ": no such file\n"))
				code = 1
				continue
			}
			_, _ = io.Copy(cc.Stdout, f)
			_ = f.Close()
		}
		return code
	})
	errcmd := gosh.CommandFunc("errcmd", func(ctx context.Context, cc *gosh.CommandContext) int {
		cc.Stderr.Write([]byte(strings.Join(cc.Args, " ") + "\n"))
		return 0
	})
	upper := gosh.CommandFunc("upper", func(ctx context.Context, cc *gosh.CommandContext) int {
		b, _ := io.ReadAll(cc.Stdin)
		cc.Stdout.Write([]byte(strings.ToUpper(string(b))))
		return 0
	})
	return []gosh.Command{cat, errcmd, upper}
}

func run(t *testing.T, sh *gosh.Shell, script string, ropts ...gosh.RunOption) (gosh.Result, error) {
	t.Helper()
	return sh.Run(context.Background(), script, ropts...)
}

func TestPipes(t *testing.T) {
	sh := gosh.New(gosh.WithCommands(testCommands()...))
	res, err := run(t, sh, `echo hello | cat | upper`)
	if err != nil {
		t.Fatalf("host error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
	if res.Stdout != "HELLO\n" {
		t.Fatalf("stdout=%q want %q", res.Stdout, "HELLO\n")
	}
}

func TestRedirectionThroughVFS(t *testing.T) {
	sh := gosh.New(gosh.WithCommands(testCommands()...))
	res, err := run(t, sh, `
echo one > /home/user/f.txt
echo two >> /home/user/f.txt
cat /home/user/f.txt
`)
	if err != nil {
		t.Fatalf("host error: %v", err)
	}
	if res.Stdout != "one\ntwo\n" {
		t.Fatalf("stdout=%q", res.Stdout)
	}
}

func TestRedirectStderrToStdout(t *testing.T) {
	sh := gosh.New(gosh.WithCommands(testCommands()...))
	res, err := run(t, sh, `errcmd boom 2>&1`)
	if err != nil {
		t.Fatalf("host error: %v", err)
	}
	if res.Stdout != "boom\n" {
		t.Fatalf("stdout=%q stderr=%q", res.Stdout, res.Stderr)
	}
}

func TestListChaining(t *testing.T) {
	sh := gosh.New(gosh.WithCommands(testCommands()...))
	res, _ := run(t, sh, `echo a && echo b || echo c ; echo d`)
	if res.Stdout != "a\nb\nd\n" {
		t.Fatalf("stdout=%q", res.Stdout)
	}
	res, _ = run(t, sh, `false && echo x || echo y`)
	if res.Stdout != "y\n" {
		t.Fatalf("stdout=%q", res.Stdout)
	}
}

func TestVariablesAndExpansion(t *testing.T) {
	sh := gosh.New()
	res, err := run(t, sh, `name=world; echo "hello ${name}"; echo ${#name}`)
	if err != nil {
		t.Fatalf("host error: %v", err)
	}
	if res.Stdout != "hello world\n5\n" {
		t.Fatalf("stdout=%q", res.Stdout)
	}
}

func TestLoopIterationLimit(t *testing.T) {
	sh := gosh.New(gosh.WithLimits(gosh.Limits{
		MaxLoopIterations: 5,
		MaxCommands:       1_000_000,
	}))
	_, err := run(t, sh, `i=0; while true; do i=$((i+1)); done`)
	var le *gosh.LimitError
	if !errors.As(err, &le) {
		t.Fatalf("want *LimitError, got %T: %v", err, err)
	}
	if le.Kind != gosh.LimitLoopIterations {
		t.Fatalf("kind=%v want %v", le.Kind, gosh.LimitLoopIterations)
	}
}

func TestForLoopIterationLimit(t *testing.T) {
	sh := gosh.New(gosh.WithLimits(gosh.Limits{
		MaxLoopIterations: 3,
		MaxCommands:       1_000_000,
	}))
	_, err := run(t, sh, `for i in 1 2 3 4 5 6 7 8 9 10; do echo $i; done`)
	var le *gosh.LimitError
	if !errors.As(err, &le) || le.Kind != gosh.LimitLoopIterations {
		t.Fatalf("want loop LimitError, got %T: %v", err, err)
	}
}

func TestCommandCountLimit(t *testing.T) {
	sh := gosh.New(gosh.WithLimits(gosh.Limits{MaxCommands: 3}))
	_, err := run(t, sh, `echo a; echo b; echo c; echo d; echo e`)
	var le *gosh.LimitError
	if !errors.As(err, &le) {
		t.Fatalf("want *LimitError, got %T: %v", err, err)
	}
	if le.Kind != gosh.LimitCommands {
		t.Fatalf("kind=%v want %v", le.Kind, gosh.LimitCommands)
	}
}

func TestOutputByteCap(t *testing.T) {
	sh := gosh.New(gosh.WithLimits(gosh.Limits{MaxOutputBytes: 5}))
	res, err := run(t, sh, `echo abcdefghij`)
	var le *gosh.LimitError
	if !errors.As(err, &le) || le.Kind != gosh.LimitOutputBytes {
		t.Fatalf("want output LimitError, got %T: %v", err, err)
	}
	if len(res.Stdout) > 5 {
		t.Fatalf("stdout not truncated: %q", res.Stdout)
	}
	if trunc, _ := res.Metadata["output_truncated"].(bool); !trunc {
		t.Fatalf("expected output_truncated metadata")
	}
}

func TestUnknownCommand(t *testing.T) {
	sh := gosh.New()
	res, err := run(t, sh, `definitely_not_a_command arg`)
	if err != nil {
		t.Fatalf("host error should be nil for 127: %v", err)
	}
	if res.ExitCode != 127 {
		t.Fatalf("exit=%d want 127", res.ExitCode)
	}
	if !strings.Contains(res.Stderr, "command not found") {
		t.Fatalf("stderr=%q", res.Stderr)
	}
}

func TestBackgroundRejected(t *testing.T) {
	sh := gosh.New()
	_, err := run(t, sh, `echo hi &`)
	var ue *gosh.UnsupportedError
	if !errors.As(err, &ue) {
		t.Fatalf("want *UnsupportedError, got %T: %v", err, err)
	}
	if ue.Construct != "background" {
		t.Fatalf("construct=%q", ue.Construct)
	}
}

func TestProcessSubstitutionRejected(t *testing.T) {
	sh := gosh.New(gosh.WithCommands(testCommands()...))
	_, err := run(t, sh, `cat <(echo hi)`)
	var ue *gosh.UnsupportedError
	if !errors.As(err, &ue) {
		t.Fatalf("want *UnsupportedError, got %T: %v", err, err)
	}
}

func TestParseError(t *testing.T) {
	sh := gosh.New()
	_, err := run(t, sh, `if then fi (`)
	var pe *gosh.ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("want *ParseError, got %T: %v", err, err)
	}
}

func TestCancellation(t *testing.T) {
	sh := gosh.New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := sh.Run(ctx, `echo hi`)
	var ce *gosh.CanceledError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CanceledError, got %T: %v", err, err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want errors.Is context.Canceled")
	}
}

func TestDeadlineCancellation(t *testing.T) {
	sh := gosh.New(gosh.WithLimits(gosh.Limits{MaxCommands: 100_000_000, MaxLoopIterations: 100_000_000}))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := sh.Run(ctx, `while true; do :; done`)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
}

func TestNoHostEnvLeak(t *testing.T) {
	t.Setenv("GOSH_LEAK_PROBE", "leaked-secret")
	sh := gosh.New()
	res, err := run(t, sh, `echo "[${GOSH_LEAK_PROBE}]"; echo "[${PATH}]"`)
	if err != nil {
		t.Fatalf("host error: %v", err)
	}
	if res.Stdout != "[]\n[]\n" {
		t.Fatalf("host env leaked: stdout=%q", res.Stdout)
	}
}

func TestDefaultHomeAndPwd(t *testing.T) {
	sh := gosh.New()
	res, _ := run(t, sh, `echo "$HOME"; echo "$PWD"; pwd`)
	want := "/home/user\n/home/user\n/home/user\n"
	if res.Stdout != want {
		t.Fatalf("stdout=%q want %q", res.Stdout, want)
	}
}

func TestDeniedBuiltinEval(t *testing.T) {
	sh := gosh.New()
	res, err := run(t, sh, `eval 'echo pwned'`)
	if err != nil {
		t.Fatalf("host error: %v", err)
	}
	if strings.Contains(res.Stdout, "pwned") {
		t.Fatalf("eval should be denied, stdout=%q", res.Stdout)
	}
	if res.ExitCode == 0 {
		t.Fatalf("eval should yield non-zero exit, got 0")
	}
	if !strings.Contains(res.Stderr, "disabled") {
		t.Fatalf("stderr=%q", res.Stderr)
	}
}

func TestAllowedBuiltinEvalOptIn(t *testing.T) {
	sh := gosh.New(gosh.WithAllowedBuiltins("eval"))
	res, err := run(t, sh, `eval 'echo ok'`)
	if err != nil {
		t.Fatalf("host error: %v", err)
	}
	if res.Stdout != "ok\n" {
		t.Fatalf("stdout=%q", res.Stdout)
	}
}

func TestPerRunOverrides(t *testing.T) {
	sh := gosh.New(gosh.WithCommands(testCommands()...))
	res, _ := run(t, sh, `echo "$FOO-$1"`, gosh.RunEnv(map[string]string{"FOO": "bar"}), gosh.RunArgs("baz"))
	if res.Stdout != "bar-baz\n" {
		t.Fatalf("stdout=%q", res.Stdout)
	}
	// Ensure the instance env was not mutated by the per-run override.
	res2, _ := run(t, sh, `echo "[$FOO]"`)
	if res2.Stdout != "[]\n" {
		t.Fatalf("per-run env leaked into instance: %q", res2.Stdout)
	}
}

func TestRunStdin(t *testing.T) {
	sh := gosh.New(gosh.WithCommands(testCommands()...))
	res, _ := run(t, sh, `upper`, gosh.RunStdin("quiet"))
	if res.Stdout != "QUIET" {
		t.Fatalf("stdout=%q", res.Stdout)
	}
}

func TestFSPersistenceAndEphemeral(t *testing.T) {
	// Persistent (default): file written in run 1 is visible in run 2.
	sh := gosh.New(gosh.WithCommands(testCommands()...))
	if _, err := run(t, sh, `echo data > /home/user/p.txt`); err != nil {
		t.Fatalf("host error: %v", err)
	}
	res, _ := run(t, sh, `cat /home/user/p.txt`)
	if res.Stdout != "data\n" {
		t.Fatalf("persistence broken: %q", res.Stdout)
	}

	// Ephemeral: mutations do not persist across runs.
	esh := gosh.New(gosh.WithEphemeralFS(), gosh.WithCommands(testCommands()...))
	if _, err := run(t, esh, `echo data > /home/user/e.txt`); err != nil {
		t.Fatalf("host error: %v", err)
	}
	res, _ = run(t, esh, `cat /home/user/e.txt`)
	if res.ExitCode == 0 {
		t.Fatalf("ephemeral FS leaked across runs: %q", res.Stdout)
	}
}

func TestPathTraversalConfinement(t *testing.T) {
	sh := gosh.New(gosh.WithCommands(testCommands()...))
	// Attempt to escape the virtual root to the host's /etc/passwd.
	res, err := run(t, sh, `cat ../../../../../../etc/passwd`)
	if err != nil {
		t.Fatalf("host error: %v", err)
	}
	if res.ExitCode == 0 || res.Stdout != "" {
		t.Fatalf("path traversal not confined: exit=%d stdout=%q", res.ExitCode, res.Stdout)
	}
	if strings.Contains(res.Stdout, "root:") {
		t.Fatalf("LEAKED host /etc/passwd")
	}
}

func TestSeededFiles(t *testing.T) {
	sh := gosh.New(
		gosh.WithCommands(testCommands()...),
		gosh.WithFiles(map[string]string{"/data/a.txt": "alpha\n"}),
	)
	res, _ := run(t, sh, `cat /data/a.txt`)
	if res.Stdout != "alpha\n" {
		t.Fatalf("stdout=%q", res.Stdout)
	}
}

func TestSnapshotReset(t *testing.T) {
	sh := gosh.New(gosh.WithCommands(testCommands()...))
	run(t, sh, `echo v1 > /home/user/s.txt`)
	snap := sh.Snapshot()
	run(t, sh, `echo v2 > /home/user/s.txt`)
	res, _ := run(t, sh, `cat /home/user/s.txt`)
	if res.Stdout != "v2\n" {
		t.Fatalf("pre-reset stdout=%q", res.Stdout)
	}
	sh.Reset(snap)
	res, _ = run(t, sh, `cat /home/user/s.txt`)
	if res.Stdout != "v1\n" {
		t.Fatalf("snapshot restore failed: %q", res.Stdout)
	}
}

func TestScriptByteLimit(t *testing.T) {
	sh := gosh.New(gosh.WithLimits(gosh.Limits{MaxScriptBytes: 10}))
	_, err := run(t, sh, `echo this is a long script that exceeds the limit`)
	var le *gosh.LimitError
	if !errors.As(err, &le) || le.Kind != gosh.LimitScriptBytes {
		t.Fatalf("want script-byte LimitError, got %T: %v", err, err)
	}
}

func TestExecComposition(t *testing.T) {
	// A command that drives another command via cc.Exec.
	driver := gosh.CommandFunc("drive", func(ctx context.Context, cc *gosh.CommandContext) int {
		return cc.Exec(ctx, "upper")
	})
	sh := gosh.New(gosh.WithCommands(append(testCommands(), driver)...))
	res, _ := run(t, sh, `echo composed | drive`)
	if res.Stdout != "COMPOSED\n" {
		t.Fatalf("stdout=%q", res.Stdout)
	}
}

func TestVirtualClockDeterministic(t *testing.T) {
	dateCmd := gosh.CommandFunc("now", func(ctx context.Context, cc *gosh.CommandContext) int {
		cc.Stdout.Write([]byte(cc.Clock().Now().Format(time.RFC3339)))
		return 0
	})
	sh := gosh.New(gosh.WithCommands(dateCmd))
	res, _ := run(t, sh, `now`)
	if res.Stdout != "2000-01-01T00:00:00Z" {
		t.Fatalf("virtual clock not deterministic: %q", res.Stdout)
	}
}
