package textlang_test

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/darylcecile/gosh"
	"github.com/darylcecile/gosh/commands/textlang"
)

func newShell(files map[string]string) *gosh.Shell {
	return gosh.New(gosh.WithCommands(textlang.Commands()...), gosh.WithFiles(files))
}

func run(t *testing.T, sh *gosh.Shell, script string, opts ...gosh.RunOption) gosh.Result {
	t.Helper()
	res, err := sh.Run(context.Background(), script, opts...)
	if err != nil {
		t.Fatalf("host error: %v", err)
	}
	return res
}

func readFile(t *testing.T, fsys gosh.FileSystem, name string) string {
	t.Helper()
	f, err := fsys.Open(name, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func TestAwkFieldProcessing(t *testing.T) {
	sh := newShell(nil)
	res := run(t, sh, `awk '{print $2}'`, gosh.RunStdin("one two\nred blue\n"))
	if res.ExitCode != 0 || res.Stdout != "two\nblue\n" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestAwkFieldSeparatorVarAndBeginEnd(t *testing.T) {
	sh := newShell(map[string]string{"/home/user/data.csv": "a,2\nb,3\n"})
	res := run(t, sh, `awk -F, -v mult=10 'BEGIN {print "start"} {sum += $2 * mult} END {print sum}' data.csv`)
	if res.ExitCode != 0 || res.Stdout != "start\n50\n" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestAwkProgramFileAndSandboxNoHostRead(t *testing.T) {
	sh := newShell(map[string]string{"/home/user/prog.awk": "{ print $1 }\n"})
	res := run(t, sh, `awk -f prog.awk /definitely/not/seeded`)
	if res.ExitCode == 0 || !strings.Contains(res.Stderr, "file does not exist") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestAwkSystemDisabled(t *testing.T) {
	sh := newShell(nil)
	res := run(t, sh, `awk 'BEGIN { system("echo pwned") }'`)
	if res.ExitCode == 0 || !strings.Contains(res.Stderr, "NoExec") || strings.Contains(res.Stdout, "pwned") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestSedSubstituteGlobal(t *testing.T) {
	sh := newShell(nil)
	res := run(t, sh, `sed 's/foo/bar/g'`, gosh.RunStdin("foo foo\nbaz\n"))
	if res.ExitCode != 0 || res.Stdout != "bar bar\nbaz\n" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestSedAddressesDelete(t *testing.T) {
	sh := newShell(nil)
	res := run(t, sh, `sed '2d'`, gosh.RunStdin("a\nb\nc\n"))
	if res.ExitCode != 0 || res.Stdout != "a\nc\n" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestSedQuietPrintAndRange(t *testing.T) {
	sh := newShell(nil)
	res := run(t, sh, `sed -n '/begin/,/end/p'`, gosh.RunStdin("skip\nbegin\nmid\nend\nskip\n"))
	if res.ExitCode != 0 || res.Stdout != "begin\nmid\nend\n" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestSedTransliterate(t *testing.T) {
	sh := newShell(nil)
	res := run(t, sh, `sed 'y/abc/ABC/'`, gosh.RunStdin("cab\n"))
	if res.ExitCode != 0 || res.Stdout != "CAB\n" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestSedInPlaceWriteback(t *testing.T) {
	sh := newShell(map[string]string{"/home/user/file.txt": "one two\n"})
	res := run(t, sh, `sed -i 's/two/three/' file.txt`)
	if res.ExitCode != 0 || res.Stdout != "" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
	if got := readFile(t, sh.FS(), "/home/user/file.txt"); got != "one three\n" {
		t.Fatalf("file=%q", got)
	}
}
