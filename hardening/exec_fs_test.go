package hardening_test

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/darylcecile/gosh"
	"github.com/darylcecile/gosh/goshfs"
)

// TestHostExecutionSurfacesAreBlocked attacks builtin and external-command escape seams (S1-S6, S2a, S2b).
func TestHostExecutionSurfacesAreBlocked(t *testing.T) {
	cases := []struct {
		name   string
		script string
	}{
		{"eval", `eval 'echo PWNED'`},
		{"source", `source /home/user/seed.sh`},
		{"dot", `. /home/user/seed.sh`},
		{"exec", `exec echo PWNED`},
		{"command", `command echo PWNED`},
		{"builtin", `builtin echo PWNED`},
		{"enable", `enable -n echo`},
		{"trap", `trap 'echo PWNED' EXIT`},
		{"alias", `alias ll='echo PWNED'`},
		{"unalias", `unalias ll`},
		{"jobs", `jobs`},
		{"fg", `fg`},
		{"bg", `bg`},
		{"wait", `wait`},
		{"kill", `kill 1`},
		{"background", `echo PWNED &`},
	}
	sh := hardenedShell(gosh.WithFiles(map[string]string{"/home/user/seed.sh": "echo PWNED\n"}))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runScript(t, sh, tc.script)
			assertBlocked(t, got, tc.script)
			if strings.Contains(got.stdout, "PWNED") {
				t.Fatalf("disabled construct executed: stdout=%q stderr=%q err=%v", got.stdout, got.stderr, got.err)
			}
		})
	}
}

// TestCommandSubstitutionAndPipelinesStayInRegistry proves subshells/pipelines cannot fall through to host exec (S1-S6, S2b).
func TestCommandSubstitutionAndPipelinesStayInRegistry(t *testing.T) {
	cases := []string{
		`echo before $(definitely-not-registered) after`,
		"echo before `definitely-not-registered` after",
		`definitely-not-registered | cat`,
		`echo hi | definitely-not-registered`,
		`$(rm -rf /)`,
		`/bin/sh -c 'echo PWNED'`,
		`python -c 'print("PWNED")'`,
		`git --version`,
		`curl http://example.com`,
	}
	for _, script := range cases {
		t.Run(oneLine(script), func(t *testing.T) {
			got := runScript(t, hardenedShell(), script)
			if got.err != nil {
				t.Fatalf("unexpected host error: %v", got.err)
			}
			if !strings.Contains(got.stderr, "command not found") && !strings.Contains(got.stderr, "curl: command not found") && !strings.Contains(got.stderr, "refusing to remove /") {
				t.Fatalf("want registry refusal or sandboxed rm refusal, got exit=%d stdout=%q stderr=%q", got.res.ExitCode, got.stdout, got.stderr)
			}
			assertNoHostLeakOutput(t, got)
		})
	}
}

// TestFilesystemConfinement attacks host-path, traversal, symlink, and read-only adapter seams (S7-S8).
func TestFilesystemConfinement(t *testing.T) {
	t.Run("host paths and traversal stay in VFS", func(t *testing.T) {
		sh := hardenedShell(gosh.WithFiles(map[string]string{"/safe/file": "SAFE\n"}))
		cases := []string{
			`cat /etc/passwd`,
			`cat /a/../../etc/passwd`,
			`mkdir -p /a && printf X > /a/../../etc/passwd && cat /etc/passwd`,
		}
		for _, script := range cases {
			got := runScript(t, sh, script)
			assertBlocked(t, got, script)
			assertNoHostLeakOutput(t, got)
		}
	})

	t.Run("symlink to root cannot escape virtual filesystem", func(t *testing.T) {
		got := runScript(t, hardenedShell(gosh.WithFiles(map[string]string{"/safe/file": "SAFE\n"})), `ln -s / /rootlink && cat /rootlink/etc/passwd && printf X > /rootlink/escape && cat /escape`)
		if strings.Contains(got.stdout, "root:x:") {
			t.Fatalf("symlink escaped to host /etc/passwd: stdout=%q stderr=%q", got.stdout, got.stderr)
		}
		if got.err != nil {
			t.Fatalf("host error: %v", got.err)
		}
		if got.res.ExitCode == 0 && got.stdout != "X" && got.stdout != "X\n" {
			t.Fatalf("unexpected symlink-root behavior stdout=%q stderr=%q", got.stdout, got.stderr)
		}
	})

	t.Run("symlink traversal cannot escape virtual root", func(t *testing.T) {
		got := runScript(t, hardenedShell(), `ln -s ../../../../etc /home/user/etc-link && cat /home/user/etc-link/passwd`)
		assertBlocked(t, got, "symlink traversal")
		assertNoHostLeakOutput(t, got)
	})

	t.Run("read-only filesystem denies writes", func(t *testing.T) {
		base := gosh.NewInMemoryFS(gosh.NewVirtualClock(gosh.Epoch), 1024, 4096)
		if err := base.MkdirAll("/home/user", 0o755); err != nil {
			t.Fatal(err)
		}
		f, err := base.Open("/home/user/seed", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(f, "seed\n"); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		sh := hardenedShell(gosh.WithFS(goshfs.NewReadOnlyFS(base)))
		read := runScript(t, sh, `cat /home/user/seed`)
		if read.err != nil || read.res.ExitCode != 0 || read.stdout != "seed\n" {
			t.Fatalf("read-only read failed: exit=%d err=%v stdout=%q stderr=%q", read.res.ExitCode, read.err, read.stdout, read.stderr)
		}
		write := runScript(t, sh, `printf nope > /home/user/new`)
		assertBlocked(t, write, "write through read-only fs")
		if !strings.Contains(write.stderr, "permission") && !strings.Contains(write.stderr, "operation not permitted") {
			t.Fatalf("want permission denial, stderr=%q err=%v", write.stderr, write.err)
		}
	})
}
