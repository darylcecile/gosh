package hardening_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/darylcecile/gosh"
)

// TestNetworkEgressPolicy attacks deny-by-default, origin allow-list, and private-IP SSRF controls (S17-S22).
func TestNetworkEgressPolicy(t *testing.T) {
	t.Run("no network configured makes curl unavailable", func(t *testing.T) {
		got := runScript(t, hardenedShell(), `curl http://example.com`)
		assertBlocked(t, got, "curl without network")
		if got.res.ExitCode != 127 || !strings.Contains(got.stderr, "command not found") {
			t.Fatalf("want 127 command-not-found, got exit=%d stderr=%q err=%v", got.res.ExitCode, got.stderr, got.err)
		}
	})

	t.Run("allow-list rejects different origins", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
		defer ts.Close()
		sh := hardenedShell(gosh.WithNetwork(gosh.NetworkPolicy{AllowedOrigins: []string{"http://example.com"}, AllowPrivateIPs: true}))
		got := runScript(t, sh, `curl `+ts.URL)
		assertBlocked(t, got, "curl disallowed origin")
		if !strings.Contains(got.stderr, "not allowed by NetworkPolicy") {
			t.Fatalf("want origin refusal, stderr=%q", got.stderr)
		}
	})

	t.Run("private IP SSRF blocked by default even when allow-listed", func(t *testing.T) {
		sh := hardenedShell(gosh.WithNetwork(gosh.NetworkPolicy{AllowedOrigins: []string{"http://127.0.0.1:1"}}))
		got := runScript(t, sh, `curl http://127.0.0.1:1/metadata`)
		assertBlocked(t, got, "curl loopback without AllowPrivateIPs")
		if !strings.Contains(got.stderr, "forbidden private IP") {
			t.Fatalf("want private IP refusal, stderr=%q", got.stderr)
		}
	})

	t.Run("positive loopback path requires explicit AllowPrivateIPs", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "sandbox-ok") }))
		defer ts.Close()
		sh := hardenedShell(gosh.WithNetwork(gosh.NetworkPolicy{AllowedOrigins: []string{ts.URL}, AllowPrivateIPs: true}))
		got := runScript(t, sh, `curl `+ts.URL)
		if got.err != nil || got.res.ExitCode != 0 || got.stdout != "sandbox-ok" {
			t.Fatalf("allowed loopback request failed: exit=%d err=%v stdout=%q stderr=%q", got.res.ExitCode, got.err, got.stdout, got.stderr)
		}
	})

	t.Run("metadata address is blocked", func(t *testing.T) {
		sh := hardenedShell(gosh.WithNetwork(gosh.NetworkPolicy{AllowedOrigins: []string{"http://169.254.169.254"}}))
		got := runScript(t, sh, `curl http://169.254.169.254/latest/meta-data/`)
		assertBlocked(t, got, "curl metadata")
		if !strings.Contains(got.stderr, "forbidden private IP") {
			t.Fatalf("want metadata refusal, stderr=%q", got.stderr)
		}
	})
}

// TestArchiveExtractionSafety attacks tar path traversal, absolute paths, and decompression caps (S4/S7 archive safety).
func TestArchiveExtractionSafety(t *testing.T) {
	for _, tc := range []struct{ name, entry string }{{"parent traversal", "../escape"}, {"absolute path", "/escape"}} {
		t.Run(tc.name, func(t *testing.T) {
			arc := tarBytes(t, map[string]string{tc.entry: "PWNED\n"})
			sh := hardenedShell(gosh.WithFiles(map[string]string{"/evil.tar": string(arc)}))
			got := runScript(t, sh, `mkdir -p /out && tar -xf /evil.tar -C /out; cat /escape`)
			assertBlocked(t, got, "unsafe tar path")
			if strings.Contains(got.stdout, "PWNED") {
				t.Fatalf("unsafe tar entry escaped destination: stdout=%q stderr=%q", got.stdout, got.stderr)
			}
		})
	}

	t.Run("decompression size cap", func(t *testing.T) {
		arc := tarBytes(t, map[string]string{"big": strings.Repeat("A", 256)})
		base := gosh.NewInMemoryFS(gosh.NewVirtualClock(gosh.Epoch), 4096, 8192)
		if err := base.MkdirAll("/home/user", 0o755); err != nil {
			t.Fatal(err)
		}
		f, err := base.Open("/big.tar", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(arc); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		sh := hardenedShell(gosh.WithFS(base), gosh.WithLimits(gosh.Limits{MaxFileBytes: 64, MaxTotalFSBytes: 1024}))
		got := runScript(t, sh, `mkdir -p /out && tar -xf /big.tar -C /out`)
		assertBlocked(t, got, "tar decompression bomb")
		if !strings.Contains(got.stderr, "exceeds limit") && !strings.Contains(got.stderr, "max_file_bytes") {
			t.Fatalf("want archive cap, stderr=%q err=%v", got.stderr, got.err)
		}
	})
}

// TestAwkSedIsolation attacks language-level file and command escape primitives (S1-S8, S13).
func TestAwkSedIsolation(t *testing.T) {
	t.Run("awk system cannot execute host command", func(t *testing.T) {
		got := runScript(t, hardenedShell(), `awk 'BEGIN{system("id")}'`)
		assertBlocked(t, got, "awk system")
		assertNoHostLeakOutput(t, got)
	})

	t.Run("awk cannot read host path", func(t *testing.T) {
		got := runScript(t, hardenedShell(), `awk '{print}' /etc/passwd`)
		assertBlocked(t, got, "awk host path")
		assertNoHostLeakOutput(t, got)
	})

	t.Run("sed cannot read host path", func(t *testing.T) {
		got := runScript(t, hardenedShell(), `sed -n '1p' /etc/passwd`)
		assertBlocked(t, got, "sed host path")
		assertNoHostLeakOutput(t, got)
	})
}
