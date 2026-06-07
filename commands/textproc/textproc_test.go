package textproc

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/darylcecile/gosh"
)

func textprocShell(files map[string]string) *gosh.Shell {
	argv := gosh.CommandFunc("argv", func(ctx context.Context, cc *gosh.CommandContext) int {
		fmt.Fprintln(cc.Stdout, strings.Join(cc.Args, ","))
		return 0
	})
	cmds := append(Commands(), argv)
	return gosh.New(gosh.WithCommands(cmds...), gosh.WithFiles(files))
}

func TestTextprocCommandsThroughShell(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		files  map[string]string
		script string
		want   string
		code   int
	}{
		{"grep numbers", map[string]string{"/f.txt": "foo\nbar\nfoo bar\n"}, "grep -n foo /f.txt", "1:foo\n3:foo bar\n", 0},
		{"grep no match", map[string]string{"/f.txt": "foo\n"}, "grep zzz /f.txt", "", 1},
		{"grep recursive", map[string]string{"/d/a.txt": "x\n", "/d/sub/b.txt": "hit\n"}, "grep -rH hit /d", "/d/sub/b.txt:hit\n", 0},
		{"grep re2 metacharacters", map[string]string{"/f.txt": "foo\nfao\nf.o\n"}, "grep 'f.o' /f.txt", "foo\nfao\nf.o\n", 0},
		{"fgrep fixed", map[string]string{"/f.txt": "foo\nf.o\n"}, "fgrep 'f.o' /f.txt", "f.o\n", 0},
		{"cut fields complement", map[string]string{"/f.txt": "a:b:c\n"}, "cut -d: -f2 --complement /f.txt", "a:c\n", 0},
		{"tr translate squeeze", nil, "printf 'aaabbb\n' | tr -s a-z A-Z", "AB\n", 0},
		{"sort pipeline", nil, "printf 'b\na\n' | sort", "a\nb\n", 0},
		{"sort numeric reverse unique", nil, "printf '2 x\n10 y\n2 x\n' | sort -nru", "10 y\n2 x\n", 0},
		{"uniq count ignore case", nil, "printf 'A\na\nb\n' | uniq -ci", "      2 A\n      1 b\n", 0},
		{"wc multi totals", map[string]string{"/a": "one two\n", "/b": "x\ny\n"}, "wc -lwc /a /b", "      1       2       8 /a\n      2       2       4 /b\n      3       4      12 total\n", 0},
		{"head negative", nil, "printf 'a\nb\nc\n' | head -n -1", "a\nb\n", 0},
		{"tail plus", nil, "printf 'a\nb\nc\n' | tail -n +2", "b\nc\n", 0},
		{"tac rev nl", nil, "printf 'ab\ncd\n' | tac | rev | nl -b a", "     1\tdc\n     2\tba\n", 0},
		{"paste serial", map[string]string{"/a": "a\nb\n"}, "paste -sd, /a", "a,b\n", 0},
		{"join", map[string]string{"/a": "1 A\n2 B\n", "/b": "1 X\n3 Z\n"}, "join /a /b", "1 A X\n", 0},
		{"comm", map[string]string{"/a": "a\nb\n", "/b": "b\nc\n"}, "comm -3 /a /b", "a\n\tc\n", 0},
		{"column", nil, "printf 'a:b\nlong:c\n' | column -t -s :", "a     b\nlong  c\n", 0},
		{"fold spaces", nil, "printf 'aa bb cc\n' | fold -w 5 -s", "aa \nbb cc\n", 0},
		{"expand unexpand", nil, "printf 'a\tb\n' | expand -t 4 | unexpand -a -t 4", "a\tb\n", 0},
		{"diff differs", map[string]string{"/a": "a\n", "/b": "b\n"}, "diff -u /a /b", "--- /a\n+++ /b\n@@ -1,1 +1,1 @@\n-a\n+b\n", 1},
		{"od chars", map[string]string{"/a": "A\n"}, "od -c -A n /a", "   A  \\n\n", 0},
		{"strings min", map[string]string{"/a": "\x00abc\x00abcd\x00"}, "strings -n 4 /a", "abcd\n", 0},
		{"xargs exec composition", nil, "printf 'a b c' | xargs -n 2 argv pre", "pre,a,b\npre,c\n", 0},
		{"xargs replace", nil, "printf 'a\nb\n' | xargs -I{} argv X{}", "Xa\nXb\n", 0},
		{"empty input", nil, "printf '' | sort", "", 0},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sh := textprocShell(tt.files)
			res, err := sh.Run(context.Background(), tt.script)
			if err != nil {
				t.Fatalf("Run error: %v", err)
			}
			if res.ExitCode != tt.code {
				t.Fatalf("exit code = %d, want %d; stderr=%q stdout=%q", res.ExitCode, tt.code, res.Stderr, res.Stdout)
			}
			if res.Stdout != tt.want {
				t.Fatalf("stdout = %q, want %q", res.Stdout, tt.want)
			}
		})
	}
}

func TestCommandHelp(t *testing.T) {
	t.Parallel()
	sh := textprocShell(nil)
	res, err := sh.Run(context.Background(), "sort --help")
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "Usage: sort") {
		t.Fatalf("unexpected help result: code=%d stdout=%q", res.ExitCode, res.Stdout)
	}
}
