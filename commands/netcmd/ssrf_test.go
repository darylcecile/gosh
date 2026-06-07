package netcmd

import (
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"net/http"
	"net/http/httptest"

	"github.com/darylcecile/gosh"
)

// TestForbiddenIPCoversSpecialRanges locks in SSRF coverage for cloud-metadata
// and IANA special-purpose ranges that Go's Is* predicates do not classify, plus
// IPv4-embedding IPv6 transition addresses (S22).
func TestForbiddenIPCoversSpecialRanges(t *testing.T) {
	forbidden := []string{
		// classic private/loopback/link-local
		"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
		"169.254.169.254",    // AWS/GCP/Azure/DO metadata (link-local)
		"0.0.0.0", "0.1.2.3", // "this network" (RFC 1122)
		// cloud metadata + special-purpose previously reachable
		"100.100.100.200", // Alibaba Cloud metadata (CGNAT)
		"192.0.0.192",     // Oracle Cloud metadata
		"100.64.0.1",      // CGNAT shared address space
		"198.18.0.1",      // benchmarking
		"192.88.99.1",     // 6to4 relay anycast
		"192.0.2.1",       // TEST-NET-1 documentation
		"198.51.100.1",    // TEST-NET-2 documentation
		"203.0.113.1",     // TEST-NET-3 documentation
		"240.0.0.1",       // reserved
		"255.255.255.255", // broadcast
		"224.0.0.1",       // multicast
		"239.1.2.3",       // global multicast
		// IPv6
		"::1",              // loopback
		"::ffff:127.0.0.1", // v4-mapped loopback
		"::ffff:169.254.169.254",
		"fd00:ec2::254",      // AWS IPv6 metadata
		"fc00::1",            // unique local
		"fe80::1",            // link-local
		"ff02::1",            // multicast
		"2001:db8::1",        // documentation
		"2001::1",            // Teredo
		"64:ff9b::7f00:1",    // NAT64 embedding 127.0.0.1
		"64:ff9b::a9fe:a9fe", // NAT64 embedding 169.254.169.254
		"2002:7f00:1::1",     // 6to4 embedding 127.0.0.1
		"2002:6464:6464::1",  // 6to4 embedding 100.100.100.100 (CGNAT)
	}
	for _, s := range forbidden {
		ip := netip.MustParseAddr(s)
		if !forbiddenIP(ip) {
			t.Errorf("forbiddenIP(%s) = false, want true (SSRF range must be blocked)", s)
		}
	}

	allowed := []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34", // public IPv4
		"2606:4700:4700::1111", "2620:fe::fe", // public IPv6 resolvers
		"64:ff9b::808:808",  // NAT64 embedding 8.8.8.8 (public) must stay allowed
		"2002:5db8:d822::1", // 6to4 embedding 93.184.216.34 (public)
	}
	for _, s := range allowed {
		ip := netip.MustParseAddr(s)
		if forbiddenIP(ip) {
			t.Errorf("forbiddenIP(%s) = true, want false (public address must be reachable)", s)
		}
	}
}

// TestEmbeddedIPv4 verifies extraction of IPv4 from NAT64/6to4 transition forms.
func TestEmbeddedIPv4(t *testing.T) {
	cases := map[string]string{
		"64:ff9b::7f00:1":   "127.0.0.1",
		"64:ff9b::808:808":  "8.8.8.8",
		"2002:7f00:1::1":    "127.0.0.1",
		"2002:0808:0808::1": "8.8.8.8",
	}
	for in, want := range cases {
		got, ok := embeddedIPv4(netip.MustParseAddr(in))
		if !ok || got != netip.MustParseAddr(want) {
			t.Errorf("embeddedIPv4(%s) = (%v,%v), want %s", in, got, ok, want)
		}
	}
	if _, ok := embeddedIPv4(netip.MustParseAddr("2606:4700:4700::1111")); ok {
		t.Errorf("embeddedIPv4 should not match a non-transition IPv6 address")
	}
	if _, ok := embeddedIPv4(netip.MustParseAddr("8.8.8.8")); ok {
		t.Errorf("embeddedIPv4 should not match a plain IPv4 address")
	}
}

// TestCurlRefusesSpecialRangeLiterals confirms that, with SSRF protection on,
// curl refuses to connect to literal cloud-metadata/special IPs even when the
// origin is explicitly allow-listed — and never opens a connection (S22).
func TestCurlRefusesSpecialRangeLiterals(t *testing.T) {
	for _, host := range []string{
		"100.100.100.200", // Alibaba metadata
		"192.0.0.192",     // Oracle metadata
		"100.64.0.1",      // CGNAT
		"198.18.0.1",      // benchmarking
		"[64:ff9b::7f00:1]",
	} {
		origin := "http://" + host
		policy := gosh.NetworkPolicy{AllowedOrigins: []string{origin}}
		res, _ := runNet(t, policy, "curl "+origin+"/latest/meta-data/")
		if res.ExitCode == 0 {
			t.Errorf("curl %s succeeded, want SSRF refusal", origin)
		}
		if !strings.Contains(res.Stderr, "forbidden private IP") {
			t.Errorf("curl %s: stderr=%q, want forbidden private IP", origin, res.Stderr)
		}
	}
}

// TestPolicyTransportIgnoresProxyEnv proves the transport never inherits ambient
// host proxy settings. With SSRF on this would otherwise let the proxy reach an
// unvalidated target and defeat the dial-time IP check; with SSRF off it would
// still leak egress (and injected credentials) through ambient host config,
// violating the explicit-policy-only network model.
func TestPolicyTransportIgnoresProxyEnv(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://evil.proxy.invalid:8080")
	t.Setenv("HTTPS_PROXY", "http://evil.proxy.invalid:8080")
	cases := []struct {
		name   string
		policy gosh.NetworkPolicy
	}{
		{"ssrf on", gosh.NetworkPolicy{AllowedOrigins: []string{"http://example.com"}}},
		{"private allowed", gosh.NetworkPolicy{AllowedOrigins: []string{"http://example.com"}, AllowPrivateIPs: true}},
		{"full internet", gosh.NetworkPolicy{DangerouslyAllowFullInternet: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := policyTransport(tc.policy)
			if tr.Proxy != nil {
				t.Fatalf("policyTransport.Proxy = non-nil, want nil so ambient HTTP_PROXY cannot leak egress or bypass SSRF dial check")
			}
		})
	}
}

// TestCurlPathPrefixRejectsEncodedTraversal confirms that, when path prefixes are
// configured, encoded or dot-segment traversal cannot satisfy an allowed prefix
// and the request never reaches the server (S18).
func TestCurlPathPrefixRejectsEncodedTraversal(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer ts.Close()

	policy := allowServer(ts)
	policy.AllowedPathPrefixes = []string{"/api"}
	for _, p := range []string{"/api/../admin", "/api/%2e%2e/admin", "/api%2fsecret"} {
		res, _ := runNet(t, policy, "curl "+ts.URL+p)
		if res.ExitCode == 0 || !strings.Contains(res.Stderr, "path") {
			t.Errorf("curl %s: exit=%d stderr=%q, want path refusal", p, res.ExitCode, res.Stderr)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("server was contacted %d times despite path-prefix refusals", hits.Load())
	}
}

func TestRemoteFileNameRejectsDecodedPathSegments(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"http://example.test/files/report%2etxt", "report.txt"},
		{"http://example.test/files/plain.txt", "plain.txt"},
		{"http://example.test/files/..", "index.html"},
		{"http://example.test/files/%2e%2e", "%2e%2e"},
		{"http://example.test/files/%2e%2e%2fpwned", "%2e%2e%2fpwned"},
		{"http://example.test/files/%2Fabsolute", "%2Fabsolute"},
		{"http://example.test/files/%5cwindows", "%5cwindows"},
		{"http://example.test/files/%00bad", "%00bad"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			u, err := url.Parse(tc.raw)
			if err != nil {
				t.Fatalf("parse URL: %v", err)
			}
			got := remoteFileName(u)
			if got != tc.want {
				t.Fatalf("remoteFileName(%q) = %q, want %q", tc.raw, got, tc.want)
			}
			if unsafeRemoteFileName(got) {
				t.Fatalf("remoteFileName(%q) returned unsafe filename %q", tc.raw, got)
			}
		})
	}
}
