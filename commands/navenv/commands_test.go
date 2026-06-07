package navenv_test

import (
	"context"
	"io"
	"testing"

	"github.com/darylcecile/gosh"
	"github.com/darylcecile/gosh/commands/navenv"
)

func run(t *testing.T, sh *gosh.Shell, script string) gosh.Result {
	t.Helper()
	res, err := sh.Run(context.Background(), script)
	if err != nil {
		t.Fatalf("host error: %v", err)
	}
	return res
}

func newShell(files map[string]string) *gosh.Shell {
	return gosh.New(gosh.WithCommands(navenv.Commands()...), gosh.WithFiles(files))
}

func TestBasenameDirname(t *testing.T) {
	sh := newShell(nil)
	res := run(t, sh, `basename /a/b/c.txt .txt; basename -a -s .go /x/y.go z.go; dirname /a/b/c.txt; dirname file; dirname /`)
	want := "c\ny\nz\n/a/b\n.\n/\n"
	if res.ExitCode != 0 || res.Stdout != want {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestFindFilters(t *testing.T) {
	sh := newShell(map[string]string{"/home/user/a.txt": "a", "/home/user/dir/b.log": "b", "/home/user/dir/c.txt": "c"})
	res := run(t, sh, `find . -name '*.txt' -type f -maxdepth 1`)
	if res.ExitCode != 0 || res.Stdout != "a.txt\n" {
		t.Fatalf("find stdout=%q stderr=%q exit=%d", res.Stdout, res.Stderr, res.ExitCode)
	}
	res = run(t, sh, `find . -type d -maxdepth 1`)
	if res.Stdout != ".\ndir\n" {
		t.Fatalf("find dirs stdout=%q", res.Stdout)
	}
}

func TestFindRejectsExec(t *testing.T) {
	sh := newShell(nil)
	res := run(t, sh, `find . -exec echo {} \;`)
	if res.ExitCode == 0 || res.Stderr != "find: -exec is unsupported\n" {
		t.Fatalf("exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
}

func TestDuSizes(t *testing.T) {
	sh := newShell(map[string]string{"/home/user/a": "123", "/home/user/d/b": "12345"})
	res := run(t, sh, `du -s .; du -a d`)
	want := "8\t.\n5\td/b\n5\td\n"
	if res.ExitCode != 0 || res.Stdout != want {
		t.Fatalf("du stdout=%q stderr=%q", res.Stdout, res.Stderr)
	}
}

func TestEnvAndPrintenv(t *testing.T) {
	sh := newShell(nil)
	res := run(t, sh, `env FOO=bar printenv FOO; printenv HOME`)
	if res.ExitCode != 0 || res.Stdout != "bar\n/home/user\n" {
		t.Fatalf("stdout=%q stderr=%q exit=%d", res.Stdout, res.Stderr, res.ExitCode)
	}
	res = run(t, sh, `env -i Z=last A=first`)
	if res.Stdout != "A=first\nZ=last\n" {
		t.Fatalf("env stdout=%q", res.Stdout)
	}
}

func TestTeeWriteback(t *testing.T) {
	sh := newShell(nil)
	res, err := sh.Run(context.Background(), `echo hello | tee out`)
	if err != nil {
		t.Fatalf("host error: %v", err)
	}
	if res.ExitCode != 0 || res.Stdout != "hello\n" {
		t.Fatalf("tee result=%+v", res)
	}
	f, err := sh.FS().Open("/home/user/out", 0, 0)
	if err != nil {
		t.Fatalf("open out: %v", err)
	}
	defer f.Close()
	b, _ := io.ReadAll(f)
	if string(b) != "hello\n" {
		t.Fatalf("file=%q", b)
	}
}

func TestSeqVariants(t *testing.T) {
	sh := newShell(nil)
	res := run(t, sh, `seq 3; seq -s , 1 2 5; seq -w 8 10`)
	want := "1\n2\n3\n1,3,5\n08\n09\n10\n"
	if res.ExitCode != 0 || res.Stdout != want {
		t.Fatalf("seq stdout=%q stderr=%q", res.Stdout, res.Stderr)
	}
}

func TestExprArithmeticRegex(t *testing.T) {
	sh := newShell(nil)
	res := run(t, sh, `expr 2 + 3 '*' 4; expr abc : 'a(.*)'; expr length hello`)
	if res.ExitCode != 0 || res.Stdout != "14\nbc\n5\n" {
		t.Fatalf("expr stdout=%q stderr=%q exit=%d", res.Stdout, res.Stderr, res.ExitCode)
	}
	res = run(t, sh, `expr 1 - 1`)
	if res.ExitCode != 1 || res.Stdout != "0\n" {
		t.Fatalf("zero semantics: %+v", res)
	}
}

func TestDateSleepVirtualClock(t *testing.T) {
	sh := newShell(nil)
	res := run(t, sh, `date -u +%Y-%m-%dT%H:%M:%SZ; sleep 90; date -u +%Y-%m-%dT%H:%M:%SZ`)
	want := "2000-01-01T00:00:00Z\n2000-01-01T00:01:30Z\n"
	if res.ExitCode != 0 || res.Stdout != want {
		t.Fatalf("date/sleep stdout=%q stderr=%q", res.Stdout, res.Stderr)
	}
}

func TestTimeout(t *testing.T) {
	sh := newShell(nil)
	res := run(t, sh, `timeout 1 sleep 2`)
	if res.ExitCode != 124 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestWhoamiHostname(t *testing.T) {
	sh := newShell(nil)
	res := run(t, sh, `whoami; hostname`)
	if res.ExitCode != 0 || res.Stdout != "user\nsandbox\n" {
		t.Fatalf("stdout=%q", res.Stdout)
	}
}
