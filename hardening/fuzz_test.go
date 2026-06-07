package hardening_test

import (
	"strings"
	"testing"

	"github.com/darylcecile/gosh"
)

// FuzzRunScript fuzzes arbitrary Bash input through the public shell API and asserts crash-resistance (S16/S-robustness).
func FuzzRunScript(f *testing.F) {
	seeds := []string{
		`echo ok`, `$(nosuch)`, "`nosuch`", `printf '%s\n' "$((1+2))"`, `cat <<'EOF'
unterminated`, `if true; then echo x; fi`, `for i in {1..20}; do echo $i; done`, `😀=$((1))`, strings.Repeat("(", 32), `cat /../../etc/passwd`, `echo ${A:-$(echo nested)}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		sh := hardenedShell(gosh.WithLimits(gosh.Limits{MaxCommands: 200, MaxLoopIterations: 100, MaxOutputBytes: 2048, MaxStreamIterations: 200, MaxScriptBytes: 4096, MaxASTNodes: 2000, MaxASTDepth: 80, MaxArgvBytes: 2048, MaxExpandedWords: 128, MaxPipelineLength: 16, MaxCmdSubstDepth: 8, MaxFileBytes: 4096, MaxTotalFSBytes: 16384}))
		fuzzRun(t, sh, string(data))
	})
}

// FuzzInMemoryFSPaths fuzzes VFS-touching shell commands and asserts paths cannot crash or escape the VFS (S4/S7/S16).
func FuzzInMemoryFSPaths(f *testing.F) {
	seeds := []string{"/etc/passwd", "../../etc/passwd", "/a/../../escape", "normal", "sp ace", "unicodé", "//unc", "C:/windows", strings.Repeat("a", 300)}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if strings.ContainsRune(p, '\x00') {
			t.Skip("NUL cannot be embedded in shell words")
		}
		q := strings.ReplaceAll(p, `'`, `''`)
		script := "mkdir -p /safe; printf data > /safe/file; cat '" + q + "'; ls '" + q + "'; mkdir -p '" + q + "/child'"
		sh := hardenedShell(gosh.WithLimits(gosh.Limits{MaxCommands: 100, MaxLoopIterations: 100, MaxOutputBytes: 2048, MaxStreamIterations: 200, MaxScriptBytes: 4096, MaxASTNodes: 2000, MaxASTDepth: 80, MaxArgvBytes: 2048, MaxExpandedWords: 128, MaxFileBytes: 4096, MaxTotalFSBytes: 16384}))
		fuzzRun(t, sh, script)
	})
}
