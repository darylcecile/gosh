package netcmd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/darylcecile/gosh"
)

func runNet(t *testing.T, policy gosh.NetworkPolicy, script string, opts ...gosh.RunOption) (gosh.Result, *gosh.Shell) {
	t.Helper()
	sh := gosh.New(gosh.WithCommands(Commands()...), gosh.WithNetwork(policy))
	res, err := sh.Run(context.Background(), script, opts...)
	if err != nil {
		t.Fatalf("Run returned host error: %v", err)
	}
	return res, sh
}

func allowServer(ts *httptest.Server) gosh.NetworkPolicy {
	// httptest servers listen on loopback, so legitimately reaching them
	// requires the explicit private-IP opt-in (SSRF protection is on by default).
	return gosh.NetworkPolicy{AllowedOrigins: []string{ts.URL}, AllowPrivateIPs: true}
}

func readFile(t *testing.T, sh *gosh.Shell, name string) string {
	t.Helper()
	f, err := sh.FS().Open(name, os.O_RDONLY, 0)
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

func TestCurlGETAllowedOrigin(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s", r.Method)
		}
		_, _ = io.WriteString(w, "hello")
	}))
	defer ts.Close()

	res, _ := runNet(t, allowServer(ts), "curl "+ts.URL)
	if res.ExitCode != 0 || res.Stdout != "hello" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestCurlOutputWritesSandboxFile(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "file-body")
	}))
	defer ts.Close()

	res, sh := runNet(t, allowServer(ts), "curl -o out.txt "+ts.URL)
	if res.ExitCode != 0 || res.Stdout != "" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
	if got := readFile(t, sh, "/home/user/out.txt"); got != "file-body" {
		t.Fatalf("file body = %q", got)
	}
}

func TestCurlIncludeHeadersAndHead(t *testing.T) {
	var sawHEAD atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "yes")
		if r.URL.Path == "/head" {
			if r.Method != http.MethodHead {
				t.Fatalf("method = %s", r.Method)
			}
			sawHEAD.Store(true)
			return
		}
		_, _ = io.WriteString(w, "body")
	}))
	defer ts.Close()

	res, _ := runNet(t, allowServer(ts), "curl -i "+ts.URL)
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "HTTP/1.1 200 OK") || !strings.Contains(res.Stdout, "X-Test: yes") || !strings.HasSuffix(res.Stdout, "body") {
		t.Fatalf("unexpected -i result: exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
	res, _ = runNet(t, allowServer(ts), "curl -I "+ts.URL+"/head")
	if res.ExitCode != 0 || !sawHEAD.Load() || !strings.Contains(res.Stdout, "HTTP/1.1 200 OK") || strings.Contains(res.Stdout, "body") {
		t.Fatalf("unexpected -I result: exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestCurlFollowsRedirectWithRevalidation(t *testing.T) {
	ts := httptest.NewServer(nil)
	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, ts.URL+"/final", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "final")
	})
	defer ts.Close()

	res, _ := runNet(t, allowServer(ts), "curl -L "+ts.URL+"/redir")
	if res.ExitCode != 0 || res.Stdout != "final" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestCurlDenyAllUnavailable(t *testing.T) {
	res, _ := runNet(t, gosh.NetworkPolicy{}, "curl http://example.invalid")
	if res.ExitCode != 127 || !strings.Contains(res.Stderr, "curl: command not found") {
		t.Fatalf("exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
}

func TestCurlRefusesDisallowedOriginWithoutConnecting(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "should not happen")
	}))
	defer ts.Close()

	policy := gosh.NetworkPolicy{AllowedOrigins: []string{"http://allowed.invalid"}, AllowPrivateIPs: true}
	res, _ := runNet(t, policy, "curl "+ts.URL)
	if res.ExitCode == 0 || !strings.Contains(res.Stderr, "origin") || hits.Load() != 0 {
		t.Fatalf("exit=%d stderr=%q hits=%d", res.ExitCode, res.Stderr, hits.Load())
	}
}

func TestCurlRefusesMethodNotAllowed(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer ts.Close()

	res, _ := runNet(t, allowServer(ts), "curl -X POST "+ts.URL)
	if res.ExitCode == 0 || !strings.Contains(res.Stderr, "method POST") || hits.Load() != 0 {
		t.Fatalf("exit=%d stderr=%q hits=%d", res.ExitCode, res.Stderr, hits.Load())
	}
}

func TestCurlRefusesPathPrefixNotAllowed(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer ts.Close()

	policy := allowServer(ts)
	policy.AllowedPathPrefixes = []string{"/allowed"}
	res, _ := runNet(t, policy, "curl "+ts.URL+"/denied")
	if res.ExitCode == 0 || !strings.Contains(res.Stderr, "path") || hits.Load() != 0 {
		t.Fatalf("exit=%d stderr=%q hits=%d", res.ExitCode, res.Stderr, hits.Load())
	}
}

func TestCurlRefusesPrivateIPByDefault(t *testing.T) {
	// No AllowPrivateIPs / DangerouslyAllowFullInternet: SSRF protection is on by
	// default even though the loopback origin is explicitly allow-listed.
	policy := gosh.NetworkPolicy{AllowedOrigins: []string{"http://127.0.0.1:9"}}
	res, _ := runNet(t, policy, "curl http://127.0.0.1:9")
	if res.ExitCode == 0 || !strings.Contains(res.Stderr, "forbidden private IP") {
		t.Fatalf("exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
}

func TestCurlRefusesRedirectToDisallowedOrigin(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/secret", http.StatusFound)
	}))
	defer source.Close()

	res, _ := runNet(t, allowServer(source), "curl -L "+source.URL)
	if res.ExitCode == 0 || !strings.Contains(res.Stderr, "origin") || targetHits.Load() != 0 {
		t.Fatalf("exit=%d stderr=%q targetHits=%d", res.ExitCode, res.Stderr, targetHits.Load())
	}
}

func TestCurlCapsResponseBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "0123456789")
	}))
	defer ts.Close()

	policy := allowServer(ts)
	policy.MaxResponseBytes = 4
	res, _ := runNet(t, policy, "curl "+ts.URL)
	if res.ExitCode != 0 || res.Stdout != "0123" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestCurlCredentialTransformOverridesScriptHeader(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Token"); got != "host" {
			t.Fatalf("X-Token = %q", got)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer ts.Close()

	policy := allowServer(ts)
	policy.CredentialTransforms = []func(*http.Request){func(r *http.Request) { r.Header.Set("X-Token", "host") }}
	res, _ := runNet(t, policy, "curl -H 'X-Token: script' "+ts.URL)
	if res.ExitCode != 0 || res.Stdout != "ok" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestHTML2MDFromStdin(t *testing.T) {
	html := `<html><body><h1>Title</h1><p>Hello <strong>bold</strong> <a href="/x">link</a>.</p><ul><li>One</li><li>Two</li></ul></body></html>`
	res, _ := runNet(t, gosh.NetworkPolicy{AllowedOrigins: []string{"http://example.invalid"}}, "html2md", gosh.RunStdin(html))
	wantParts := []string{"# Title", "Hello **bold** [link](/x) .", "- One", "- Two"}
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
	for _, part := range wantParts {
		if !strings.Contains(res.Stdout, part) {
			t.Fatalf("markdown missing %q in %q", part, res.Stdout)
		}
	}
}
