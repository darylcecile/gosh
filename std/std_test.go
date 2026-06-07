package std_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/darylcecile/gosh"
	"github.com/darylcecile/gosh/std"
)

// run executes a script on a std-equipped shell and returns stdout, stderr and
// the exit code.
func run(t *testing.T, script string, opts ...gosh.Option) (string, string, int) {
	t.Helper()
	sh := std.Shell(opts...)
	var out, errb bytes.Buffer
	res, err := sh.Run(context.Background(), script, gosh.RunStdout(&out), gosh.RunStderr(&errb))
	if err != nil {
		t.Fatalf("Run(%q) host error: %v", script, err)
	}
	return out.String(), errb.String(), res.ExitCode
}

func TestStandardSetIsBroad(t *testing.T) {
	cmds := std.Commands()
	if len(cmds) < 50 {
		t.Fatalf("expected the standard set to be broad, got %d commands", len(cmds))
	}
	names := make(map[string]bool, len(cmds))
	for _, c := range cmds {
		names[c.Name()] = true
	}
	// A representative sampling drawn from every group plus help.
	for _, want := range []string{
		"cat", "ls", "cp", "grep", "sort", "wc", "awk", "sed",
		"find", "env", "seq", "date", "base64", "sha256sum", "jq",
		"yq", "gzip", "tar", "curl", "html2md", "help",
	} {
		if !names[want] {
			t.Errorf("standard set missing expected command %q", want)
		}
	}
}

func TestNoDuplicateNames(t *testing.T) {
	seen := map[string]int{}
	for _, c := range std.Commands() {
		seen[c.Name()]++
	}
	for name, n := range seen {
		if n > 1 {
			t.Errorf("command %q registered %d times in the standard set", name, n)
		}
	}
}

func TestPipelineAcrossGroups(t *testing.T) {
	// Exercises fileops (cat), textproc (grep/sort/uniq) composed by the shell.
	files := map[string]string{"/data.txt": "banana\napple\napple\ncherry\nbanana\n"}
	out, _, code := run(t, "cat /data.txt | sort | uniq", gosh.WithFiles(files))
	if code != 0 {
		t.Fatalf("pipeline exit=%d", code)
	}
	if out != "apple\nbanana\ncherry\n" {
		t.Fatalf("unexpected pipeline output: %q", out)
	}
}

func TestHelpListsCommands(t *testing.T) {
	out, _, code := run(t, "help")
	if code != 0 {
		t.Fatalf("help exit=%d", code)
	}
	if !strings.Contains(out, "Available commands:") {
		t.Fatalf("help output missing header: %q", out)
	}
	for _, want := range []string{"grep", "awk", "curl", "help"} {
		if !strings.Contains(out, want) {
			t.Errorf("help listing missing %q", want)
		}
	}
}

func TestHelpForwardsToCommand(t *testing.T) {
	// `help grep` should forward to `grep --help`, which prints a Usage line.
	out, _, code := run(t, "help grep")
	if code != 0 {
		t.Fatalf("help grep exit=%d", code)
	}
	if !strings.Contains(strings.ToLower(out), "usage") {
		t.Fatalf("expected forwarded grep help to contain a usage line, got: %q", out)
	}
}

func TestNetworkDeniedByDefault(t *testing.T) {
	// With no WithNetwork option, curl must refuse to run (S17): deny-by-default.
	_, errb, code := run(t, "curl http://example.com")
	if code == 0 {
		t.Fatalf("curl should fail with no network configured; got exit 0")
	}
	if errb == "" {
		t.Fatalf("expected an error message on stderr when network is disabled")
	}
}

func TestWithStandardOptionEquivalent(t *testing.T) {
	// gosh.New(std.WithStandard()) should behave like std.Shell().
	sh := gosh.New(std.WithStandard(), gosh.WithFiles(map[string]string{"/a": "hi\n"}))
	var out bytes.Buffer
	res, err := sh.Run(context.Background(), "cat /a", gosh.RunStdout(&out))
	if err != nil {
		t.Fatalf("host error: %v", err)
	}
	if res.ExitCode != 0 || out.String() != "hi\n" {
		t.Fatalf("unexpected result: exit=%d out=%q", res.ExitCode, out.String())
	}
}
