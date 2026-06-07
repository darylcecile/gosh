package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func runTestCLI(t *testing.T, args []string, stdin string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runCLI(args, strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestInlineEcho(t *testing.T) {
	code, stdout, stderr := runTestCLI(t, []string{"-c", "echo hi"}, "")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	if stdout != "hi\n" {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestFailingCommandExitCode(t *testing.T) {
	code, _, stderr := runTestCLI(t, []string{"-c", "definitely-not-a-gosh-command"}, "")
	if code == 0 || code == hostErrorExitCode {
		t.Fatalf("exit code = %d, stderr = %q; want script-level non-zero", code, stderr)
	}
}

func TestFileFlagLoadsHostFileIntoVFS(t *testing.T) {
	hostPath := ".gosh-cli-test-host-file"
	if err := os.WriteFile(hostPath, []byte("from host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(hostPath)

	code, stdout, stderr := runTestCLI(t, []string{"--file", hostPath + ":/data/input.txt", "-c", "cat /data/input.txt"}, "")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	if stdout != "from host\n" {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestEnvFlagVisibleToScript(t *testing.T) {
	code, stdout, stderr := runTestCLI(t, []string{"--env", "FOO=bar", "-c", "echo $FOO"}, "")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	if stdout != "bar\n" {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestCrossGroupPipeline(t *testing.T) {
	code, stdout, stderr := runTestCLI(t, []string{"-c", "seq 1 5 | sort -r"}, "")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	want := "5\n4\n3\n2\n1\n"
	if stdout != want {
		t.Fatalf("stdout = %q, want %q", stdout, want)
	}
}

func TestNetworkOffCurlFailsWithoutHostError(t *testing.T) {
	code, _, stderr := runTestCLI(t, []string{"-c", "curl http://example.invalid"}, "")
	if code == 0 || code == hostErrorExitCode {
		t.Fatalf("exit code = %d, stderr = %q; want script-level network failure", code, stderr)
	}
	if !strings.Contains(stderr, "curl") {
		t.Fatalf("stderr = %q, want curl failure", stderr)
	}
}
