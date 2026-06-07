package main

import (
	"bytes"
	"encoding/json"
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

func TestJSONOutput(t *testing.T) {
	code, stdout, stderr := runTestCLI(t, []string{"--json", "-c", "echo out; echo err 1>&2; exit 4"}, "")
	if code != 4 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	var got struct {
		Stdout   string `json:"stdout"`
		Stderr   string `json:"stderr"`
		ExitCode int    `json:"exitCode"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v; raw=%q", err, stdout)
	}
	if got.Stdout != "out\n" || got.Stderr != "err\n" || got.ExitCode != 4 {
		t.Fatalf("unexpected json payload: %+v", got)
	}
}

func TestJSONOutputHostError(t *testing.T) {
	code, stdout, _ := runTestCLI(t, []string{"--json", "--max-commands", "1", "-c", "echo a; echo b; echo c"}, "")
	if code != hostErrorExitCode {
		t.Fatalf("exit code = %d, want %d", code, hostErrorExitCode)
	}
	var got struct {
		Stderr   string `json:"stderr"`
		ExitCode int    `json:"exitCode"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v; raw=%q", err, stdout)
	}
	if got.ExitCode != hostErrorExitCode || !strings.Contains(got.Stderr, "limit exceeded") {
		t.Fatalf("unexpected json payload: %+v", got)
	}
	if strings.Contains(got.Stderr, "gosh: gosh:") {
		t.Fatalf("doubled error prefix in stderr: %q", got.Stderr)
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

func TestRootMountReadsRealFileAndDiscardsWrites(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(root+"/data.txt", []byte("real content"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Reads see the real host file.
	code, stdout, stderr := runTestCLI(t, []string{"--root", root, "-c", "cat /data.txt"}, "")
	if code != 0 || stdout != "real content" {
		t.Fatalf("read: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	// Writes are captured in the in-memory upper and visible within the run...
	code, stdout, _ = runTestCLI(t, []string{"--root", root, "-c", "echo CHANGED > /data.txt; cat /data.txt"}, "")
	if code != 0 || stdout != "CHANGED\n" {
		t.Fatalf("overlay write: code=%d stdout=%q", code, stdout)
	}
	// ...but never touch host disk.
	onDisk, err := os.ReadFile(root + "/data.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != "real content" {
		t.Fatalf("host disk mutated: %q", onDisk)
	}
}

func TestRootMountBlocksSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	secretDir := t.TempDir()
	if err := os.WriteFile(secretDir+"/secret.txt", []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secretDir+"/secret.txt", root+"/escape"); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	code, stdout, _ := runTestCLI(t, []string{"--root", root, "-c", "cat /escape"}, "")
	if code == 0 || strings.Contains(stdout, "SECRET") {
		t.Fatalf("symlink escape not blocked: code=%d stdout=%q", code, stdout)
	}
}

func TestNoNetworkConflictsWithAllowOrigin(t *testing.T) {
	code, _, stderr := runTestCLI(t, []string{"--no-network", "--allow-origin", "https://example.com", "-c", "echo hi"}, "")
	if code != hostErrorExitCode {
		t.Fatalf("expected host error, code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "no-network") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestNoNetworkAloneIsAccepted(t *testing.T) {
	code, stdout, stderr := runTestCLI(t, []string{"--no-network", "-c", "echo ok"}, "")
	if code != 0 || stdout != "ok\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestErrexitStopsOnFailure(t *testing.T) {
	code, stdout, _ := runTestCLI(t, []string{"-e", "-c", "false; echo SHOULD_NOT_PRINT"}, "")
	if code == 0 {
		t.Fatalf("errexit did not fail: code=%d", code)
	}
	if strings.Contains(stdout, "SHOULD_NOT_PRINT") {
		t.Fatalf("errexit did not stop execution: stdout=%q", stdout)
	}
}

func TestErrexitLongFlag(t *testing.T) {
	code, stdout, _ := runTestCLI(t, []string{"--errexit", "-c", "true; echo A; false; echo B"}, "")
	if code == 0 || !strings.Contains(stdout, "A") || strings.Contains(stdout, "B") {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
}

func TestRootMountSeedsFileFlagIntoUpper(t *testing.T) {
	root := t.TempDir()
	hostFile := t.TempDir() + "/seed.txt"
	if err := os.WriteFile(hostFile, []byte("seeded"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runTestCLI(t, []string{"--root", root, "--file", hostFile + ":/seed.txt", "-c", "cat /seed.txt"}, "")
	if code != 0 || stdout != "seeded" {
		t.Fatalf("seed in overlay mode: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
