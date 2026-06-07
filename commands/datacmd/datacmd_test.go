package datacmd

import (
	"context"
	"strings"
	"testing"

	"github.com/darylcecile/gosh"
)

func runScript(t *testing.T, sh *gosh.Shell, script string, opts ...gosh.RunOption) gosh.Result {
	t.Helper()
	res, err := sh.Run(context.Background(), script, opts...)
	if err != nil {
		t.Fatalf("host error: %v", err)
	}
	return res
}

func newShell(files map[string]string) *gosh.Shell {
	if files == nil {
		files = map[string]string{}
	}
	return gosh.New(gosh.WithCommands(Commands()...), gosh.WithFiles(files))
}

func TestBase64RoundTripDecodeAndWrapping(t *testing.T) {
	cases := []struct {
		name   string
		script string
		stdin  string
		want   string
	}{
		{"encode", "base64 -w0", "hello", "aGVsbG8=\n"},
		{"decode", "base64 -d", "aG VsbG8=!!\n", "hello"},
		{"wrap", "base64 -w4", "hello", "aGVs\nbG8=\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runScript(t, newShell(nil), tc.script, gosh.RunStdin(tc.stdin))
			if res.ExitCode != 0 || res.Stdout != tc.want {
				t.Fatalf("exit=%d stdout=%q stderr=%q want %q", res.ExitCode, res.Stdout, res.Stderr, tc.want)
			}
		})
	}
}

func TestHashKnownVectors(t *testing.T) {
	files := map[string]string{"/empty": "", "/abc": "abc"}
	cases := []struct {
		cmd  string
		want string
	}{
		{"md5sum", "d41d8cd98f00b204e9800998ecf8427e  /empty\n900150983cd24fb0d6963f7d28e17f72  /abc\n"},
		{"sha1sum", "da39a3ee5e6b4b0d3255bfef95601890afd80709  /empty\na9993e364706816aba3e25717850c26c9cd0d89d  /abc\n"},
		{"sha256sum", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  /empty\nba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  /abc\n"},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			res := runScript(t, newShell(files), tc.cmd+" /empty /abc")
			if res.ExitCode != 0 || res.Stdout != tc.want {
				t.Fatalf("exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
			}
		})
	}
}

func TestHashCheckOKFailedAndQuiet(t *testing.T) {
	files := map[string]string{
		"/abc":  "abc",
		"/sums": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  /abc\n0000000000000000000000000000000000000000000000000000000000000000  /abc\n",
	}
	res := runScript(t, newShell(files), "sha256sum -c /sums")
	if res.ExitCode != 1 || res.Stdout != "/abc: OK\n/abc: FAILED\n" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
	res = runScript(t, newShell(files), "sha256sum --quiet -c /sums")
	if res.ExitCode != 1 || res.Stdout != "" {
		t.Fatalf("quiet exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestJQ(t *testing.T) {
	cases := []struct {
		name   string
		script string
		stdin  string
		want   string
		exit   int
	}{
		{"identity", "jq .", `{"foo":1}`, "{\n  \"foo\": 1\n}\n", 0},
		{"field", "jq .foo", `{"foo":1}`, "1\n", 0},
		{"array", "jq '.[]'", `[1,2]`, "1\n2\n", 0},
		{"map", "jq 'map(.+1)'", `[1,2]`, "[\n  2,\n  3\n]\n", 0},
		{"raw", "jq -r .foo", `{"foo":"bar"}`, "bar\n", 0},
		{"compact", "jq -c .", `{"foo":1,"bar":[2]}`, "{\"bar\":[2],\"foo\":1}\n", 0},
		{"arg", "jq --arg name daryl '. + $name'", `"hi "`, "\"hi daryl\"\n", 0},
		{"slurp", "jq -s 'map(.x)'", `{"x":1}
{"x":2}
`, "[\n  1,\n  2\n]\n", 0},
		{"exit-false", "jq -e .", `false`, "false\n", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runScript(t, newShell(nil), tc.script, gosh.RunStdin(tc.stdin))
			if res.ExitCode != tc.exit || res.Stdout != tc.want {
				t.Fatalf("exit=%d stdout=%q stderr=%q want exit=%d stdout=%q", res.ExitCode, res.Stdout, res.Stderr, tc.exit, tc.want)
			}
		})
	}
}

func TestYQYAMLAndTOML(t *testing.T) {
	files := map[string]string{"/doc.yaml": "a:\n  b: 2\n", "/doc.toml": "[a]\nb = 3\n"}
	cases := []struct {
		name   string
		script string
		want   string
	}{
		{"yaml", "yq .a.b /doc.yaml", "2\n"},
		{"yaml-json", "yq -o json .a /doc.yaml", "{\n  \"b\": 2\n}\n"},
		{"toml", "yq -p toml .a.b /doc.toml", "3\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runScript(t, newShell(files), tc.script)
			if res.ExitCode != 0 || res.Stdout != tc.want {
				t.Fatalf("exit=%d stdout=%q stderr=%q want %q", res.ExitCode, res.Stdout, res.Stderr, tc.want)
			}
		})
	}
}

func TestCSVToJSON(t *testing.T) {
	cases := []struct {
		name   string
		script string
		stdin  string
		want   string
	}{
		{"header", "csv tojson", "name,age\nAda,37\nBob,41\n", "[\n  {\n    \"age\": \"37\",\n    \"name\": \"Ada\"\n  },\n  {\n    \"age\": \"41\",\n    \"name\": \"Bob\"\n  }\n]\n"},
		{"no-header", "csv tojson --no-header", "Ada,37\nBob,41\n", "[\n  [\n    \"Ada\",\n    \"37\"\n  ],\n  [\n    \"Bob\",\n    \"41\"\n  ]\n]\n"},
		{"select", "csv tojson name", "name,age\nAda,37\n", "[\n  {\n    \"name\": \"Ada\"\n  }\n]\n"},
		{"delimiter", "csv tojson -d ';' --no-header 1", "Ada;37\n", "[\n  [\n    \"37\"\n  ]\n]\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runScript(t, newShell(nil), tc.script, gosh.RunStdin(tc.stdin))
			if res.ExitCode != 0 || res.Stdout != tc.want || strings.TrimSpace(res.Stderr) != "" {
				t.Fatalf("exit=%d stdout=%q stderr=%q want %q", res.ExitCode, res.Stdout, res.Stderr, tc.want)
			}
		})
	}
}
