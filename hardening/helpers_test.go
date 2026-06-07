package hardening_test

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/darylcecile/gosh"
	"github.com/darylcecile/gosh/std"
)

type runOut struct {
	res    gosh.Result
	err    error
	stdout string
	stderr string
}

func runScript(t testing.TB, sh *gosh.Shell, script string) runOut {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var out, errb bytes.Buffer
	res, err := sh.Run(ctx, script, gosh.RunStdout(&out), gosh.RunStderr(&errb))
	return runOut{res: res, err: err, stdout: out.String(), stderr: errb.String()}
}

func hardenedShell(opts ...gosh.Option) *gosh.Shell {
	return std.Shell(opts...)
}

func assertBlocked(t *testing.T, got runOut, script string) {
	t.Helper()
	if got.err == nil && got.res.ExitCode == 0 {
		t.Fatalf("%q succeeded unexpectedly: stdout=%q stderr=%q", script, got.stdout, got.stderr)
	}
}

func assertNoHostLeakOutput(t *testing.T, got runOut) {
	t.Helper()
	forbidden := []string{"root:x:", "uid=", "gid=", "Python", "git version"}
	combined := got.stdout + got.stderr
	for _, s := range forbidden {
		if strings.Contains(combined, s) {
			t.Fatalf("host-looking output %q leaked in stdout=%q stderr=%q", s, got.stdout, got.stderr)
		}
	}
}

func tarBytes(t testing.TB, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := io.WriteString(tw, body); err != nil {
			t.Fatalf("tar body %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

func fuzzRun(t *testing.T, sh *gosh.Shell, script string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic for %q: %v", script, r)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	_, _ = sh.Run(ctx, script)
}

func oneLine(s string) string { return strings.ReplaceAll(fmt.Sprint(s), "\n", `\n`) }
