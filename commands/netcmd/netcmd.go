// Package netcmd provides policy-gated network commands for gosh.
package netcmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	pathpkg "path"
	"strconv"
	"strings"
	"time"

	"github.com/darylcecile/gosh"
	"golang.org/x/net/html"
)

const (
	defaultMaxResponseBytes int64 = 10 << 20
	defaultMaxRedirects           = 5
)

// Commands returns the network command group. Each command still checks the
// per-run NetworkPolicy before doing work, so a deny-all policy makes it behave
// like an unavailable command.
func Commands() []gosh.Command {
	return []gosh.Command{
		curlCommand{},
		htmlCommand{name: "html2md"},
		htmlCommand{name: "htmlmd"},
	}
}

type curlCommand struct{}

func (curlCommand) Name() string { return "curl" }

func (curlCommand) Run(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return cc.PrintHelp("curl [OPTIONS] URL", "Fetch an HTTP(S) URL through the configured gosh NetworkPolicy.")
	}
	if !cc.Network().Enabled() {
		fmt.Fprintln(cc.Stderr, "curl: command not found")
		return 127
	}

	opts, err := parseCurlArgs(cc.Args)
	if err != nil {
		fmt.Fprintf(cc.Stderr, "curl: %v\n", err)
		return 2
	}
	if opts.url == "" {
		fmt.Fprintln(cc.Stderr, "curl: no URL specified")
		return 2
	}
	if opts.headOnly {
		opts.method = http.MethodHead
	}
	if opts.method == "" {
		opts.method = http.MethodGet
	}
	if opts.data != nil && opts.method == http.MethodGet {
		opts.method = http.MethodPost
	}

	ctx, cancel := withMaxTime(ctx, opts.maxTime)
	defer cancel()

	resp, err := doPolicyRequest(ctx, cc.Network(), requestSpec{
		method:          opts.method,
		rawURL:          opts.url,
		headers:         opts.headers,
		body:            opts.data,
		followRedirects: opts.followRedirects,
		userAgent:       opts.userAgent,
		basicAuth:       opts.basicAuth,
	})
	if err != nil {
		printCurlError(cc, opts, err)
		return 1
	}
	defer resp.Body.Close()

	if opts.fail && resp.StatusCode >= 400 {
		printCurlError(cc, opts, fmt.Errorf("HTTP status %d", resp.StatusCode))
		return 22
	}

	var out io.Writer = cc.Stdout
	var file gosh.File
	if opts.output != "" || opts.remoteName {
		name := opts.output
		if opts.remoteName {
			name = remoteFileName(resp.Request.URL)
		}
		f, err := cc.FS().Open(cc.ResolvePath(name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			printCurlError(cc, opts, err)
			return 1
		}
		defer f.Close()
		file = f
		out = file
	}

	if opts.includeHeaders || opts.headOnly {
		if err := writeResponseHeaders(out, resp); err != nil {
			printCurlError(cc, opts, err)
			return 1
		}
	}
	if opts.headOnly {
		return 0
	}
	_, err = io.Copy(out, boundedBodyReader(resp.Body, cc.Network()))
	if err != nil {
		printCurlError(cc, opts, err)
		return 1
	}
	return 0
}

type curlOptions struct {
	url             string
	method          string
	headers         http.Header
	data            []byte
	output          string
	remoteName      bool
	silent          bool
	showError       bool
	includeHeaders  bool
	headOnly        bool
	followRedirects bool
	fail            bool
	maxTime         time.Duration
	userAgent       string
	basicAuth       string
}

func parseCurlArgs(args []string) (curlOptions, error) {
	opts := curlOptions{headers: make(http.Header)}
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("option %s requires an argument", a)
			}
			i++
			return args[i], nil
		}
		switch {
		case a == "-X":
			v, err := next()
			if err != nil {
				return opts, err
			}
			opts.method = strings.ToUpper(v)
		case strings.HasPrefix(a, "-X") && len(a) > 2:
			opts.method = strings.ToUpper(a[2:])
		case a == "-H":
			v, err := next()
			if err != nil {
				return opts, err
			}
			if err := addHeader(opts.headers, v); err != nil {
				return opts, err
			}
		case a == "-d" || a == "--data" || a == "--data-binary":
			v, err := next()
			if err != nil {
				return opts, err
			}
			opts.data = []byte(v)
		case strings.HasPrefix(a, "--data="):
			opts.data = []byte(strings.TrimPrefix(a, "--data="))
		case strings.HasPrefix(a, "--data-binary="):
			opts.data = []byte(strings.TrimPrefix(a, "--data-binary="))
		case a == "-o":
			v, err := next()
			if err != nil {
				return opts, err
			}
			opts.output = v
		case a == "-O":
			opts.remoteName = true
		case a == "-s":
			opts.silent = true
		case a == "-S":
			opts.showError = true
		case a == "-i":
			opts.includeHeaders = true
		case a == "-I":
			opts.headOnly = true
		case a == "-L":
			opts.followRedirects = true
		case a == "-f":
			opts.fail = true
		case a == "--max-time":
			v, err := next()
			if err != nil {
				return opts, err
			}
			d, err := parseSeconds(v)
			if err != nil {
				return opts, err
			}
			opts.maxTime = d
		case a == "-A":
			v, err := next()
			if err != nil {
				return opts, err
			}
			opts.userAgent = v
		case a == "-u":
			v, err := next()
			if err != nil {
				return opts, err
			}
			opts.basicAuth = v
		case a == "--":
			if i+1 < len(args) {
				opts.url = args[i+1]
			}
			return opts, nil
		case strings.HasPrefix(a, "-"):
			return opts, fmt.Errorf("unsupported option %s", a)
		default:
			opts.url = a
		}
	}
	return opts, nil
}

func addHeader(h http.Header, line string) error {
	name, val, ok := strings.Cut(line, ":")
	if !ok || strings.TrimSpace(name) == "" {
		return fmt.Errorf("invalid header %q", line)
	}
	h.Add(strings.TrimSpace(name), strings.TrimSpace(val))
	return nil
}

func parseSeconds(s string) (time.Duration, error) {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("invalid --max-time %q", s)
	}
	return time.Duration(f * float64(time.Second)), nil
}

func withMaxTime(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}

func printCurlError(cc *gosh.CommandContext, opts curlOptions, err error) {
	if opts.silent && !opts.showError {
		return
	}
	fmt.Fprintf(cc.Stderr, "curl: %v\n", err)
}

type requestSpec struct {
	method          string
	rawURL          string
	headers         http.Header
	body            []byte
	followRedirects bool
	userAgent       string
	basicAuth       string
}

func doPolicyRequest(ctx context.Context, policy gosh.NetworkPolicy, spec requestSpec) (*http.Response, error) {
	client := &http.Client{
		Transport:     policyTransport(policy),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	current := spec
	var previousOrigin string
	maxRedirects := policy.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = defaultMaxRedirects
	}
	for hop := 0; ; hop++ {
		u, err := parseAndValidateURL(current.rawURL, policy, current.method)
		if err != nil {
			return nil, err
		}
		body := io.Reader(nil)
		if current.body != nil {
			body = bytes.NewReader(current.body)
		}
		req, err := http.NewRequestWithContext(ctx, current.method, u.String(), body)
		if err != nil {
			return nil, err
		}
		copyHeaders(req.Header, spec.headers)
		if current.userAgent != "" {
			req.Header.Set("User-Agent", current.userAgent)
		}
		if current.basicAuth != "" {
			req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(current.basicAuth)))
		}
		if previousOrigin != "" && previousOrigin != originOf(u) {
			req.Header.Del("Authorization")
		}
		for _, transform := range policy.CredentialTransforms {
			if transform != nil {
				transform(req)
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if !current.followRedirects || !isRedirect(resp.StatusCode) {
			return resp, nil
		}
		if hop >= maxRedirects {
			resp.Body.Close()
			return nil, fmt.Errorf("redirect limit exceeded")
		}
		loc := resp.Header.Get("Location")
		resp.Body.Close()
		if loc == "" {
			return nil, fmt.Errorf("redirect missing Location")
		}
		nextURL, err := u.Parse(loc)
		if err != nil {
			return nil, err
		}
		previousOrigin = originOf(u)
		current.rawURL = nextURL.String()
		if resp.StatusCode == http.StatusSeeOther || ((resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound) && current.method != http.MethodHead) {
			current.method = http.MethodGet
			current.body = nil
		}
	}
}

func parseAndValidateURL(raw string, policy gosh.NetworkPolicy, method string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("missing URL host")
	}
	if !methodAllowed(policy, method) {
		return nil, fmt.Errorf("method %s not allowed by NetworkPolicy", method)
	}
	if !policy.DangerouslyAllowFullInternet && !originAllowed(policy, u) {
		return nil, fmt.Errorf("origin %s not allowed by NetworkPolicy", originOf(u))
	}
	if len(policy.AllowedPathPrefixes) > 0 {
		p := u.EscapedPath()
		if p == "" {
			p = "/"
		}
		ok := false
		for _, prefix := range policy.AllowedPathPrefixes {
			if strings.HasPrefix(p, prefix) {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("path %s not allowed by NetworkPolicy", p)
		}
	}
	if shouldDenyPrivate(policy) {
		if ip, err := netip.ParseAddr(strings.Trim(u.Hostname(), "[]")); err == nil && forbiddenIP(ip) {
			return nil, fmt.Errorf("host resolves to forbidden private IP %s", ip)
		}
	}
	return u, nil
}

func methodAllowed(policy gosh.NetworkPolicy, method string) bool {
	allowed := policy.AllowedMethods
	if len(allowed) == 0 {
		allowed = []string{http.MethodGet, http.MethodHead}
	}
	for _, m := range allowed {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

func originAllowed(policy gosh.NetworkPolicy, u *url.URL) bool {
	want := originOf(u)
	for _, allowed := range policy.AllowedOrigins {
		if normalizeOrigin(allowed) == want {
			return true
		}
	}
	return false
}

func normalizeOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

func originOf(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

func policyTransport(policy gosh.NetworkPolicy) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if shouldDenyPrivate(policy) {
		d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		resolver := net.DefaultResolver
		tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := resolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("host %s resolved to no addresses", host)
			}
			for _, ip := range ips {
				addr, ok := netip.AddrFromSlice(ip.IP)
				if !ok {
					return nil, fmt.Errorf("host %s resolved to invalid address", host)
				}
				addr = addr.Unmap()
				if forbiddenIP(addr) {
					return nil, fmt.Errorf("host %s resolves to forbidden private IP %s", host, addr)
				}
			}
			var last error
			for _, ip := range ips {
				addr, _ := netip.AddrFromSlice(ip.IP)
				target := net.JoinHostPort(addr.Unmap().String(), port)
				conn, err := d.DialContext(ctx, network, target)
				if err == nil {
					return conn, nil
				}
				last = err
			}
			return nil, last
		}
	}
	return tr
}

// shouldDenyPrivate reports whether dial-time private/loopback/metadata IP
// checks apply. SSRF protection is secure-by-default: it is ON unless the host
// has either explicitly opted into reaching private IPs (AllowPrivateIPs) or
// opted into unrestricted egress (DangerouslyAllowFullInternet).
func shouldDenyPrivate(policy gosh.NetworkPolicy) bool {
	return !policy.DangerouslyAllowFullInternet && !policy.AllowPrivateIPs
}

func forbiddenIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	return ip == netip.MustParseAddr("169.254.169.254") || ip == netip.MustParseAddr("fd00:ec2::254")
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func isRedirect(code int) bool {
	return code == http.StatusMovedPermanently || code == http.StatusFound || code == http.StatusSeeOther || code == http.StatusTemporaryRedirect || code == http.StatusPermanentRedirect
}

func writeResponseHeaders(w io.Writer, resp *http.Response) error {
	bw := bufio.NewWriter(w)
	if _, err := fmt.Fprintf(bw, "HTTP/%d.%d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.Status); err != nil {
		return err
	}
	if err := resp.Header.Write(bw); err != nil {
		return err
	}
	if _, err := bw.WriteString("\r\n"); err != nil {
		return err
	}
	return bw.Flush()
}

func boundedBodyReader(r io.Reader, policy gosh.NetworkPolicy) io.Reader {
	max := policy.MaxResponseBytes
	if max <= 0 {
		max = defaultMaxResponseBytes
	}
	return io.LimitReader(r, max)
}

func remoteFileName(u *url.URL) string {
	base := pathpkg.Base(u.EscapedPath())
	if base == "." || base == "/" || base == "" {
		return "index.html"
	}
	if decoded, err := url.PathUnescape(base); err == nil && decoded != "" && decoded != "." && decoded != "/" {
		return decoded
	}
	return base
}

type htmlCommand struct{ name string }

func (c htmlCommand) Name() string { return c.name }

func (c htmlCommand) Run(ctx context.Context, cc *gosh.CommandContext) int {
	if cc.WantsHelp() {
		return cc.PrintHelp(c.name+" [FILE|URL]", "Convert HTML from stdin, a sandbox file, or an allowed HTTP(S) URL to Markdown.")
	}
	if !cc.Network().Enabled() {
		fmt.Fprintf(cc.Stderr, "%s: command not found\n", c.name)
		return 127
	}
	data, err := readHTMLInput(ctx, cc)
	if err != nil {
		fmt.Fprintf(cc.Stderr, "%s: %v\n", c.name, err)
		if errors.Is(err, errNetworkDisabled) {
			return 127
		}
		return 1
	}
	doc, err := html.Parse(bytes.NewReader(data))
	if err != nil {
		fmt.Fprintf(cc.Stderr, "%s: %v\n", c.name, err)
		return 1
	}
	md := renderMarkdown(doc)
	_, err = io.WriteString(cc.Stdout, strings.TrimSpace(md)+"\n")
	if err != nil {
		fmt.Fprintf(cc.Stderr, "%s: %v\n", c.name, err)
		return 1
	}
	return 0
}

var errNetworkDisabled = errors.New("command not found")

func readHTMLInput(ctx context.Context, cc *gosh.CommandContext) ([]byte, error) {
	if len(cc.Args) == 0 {
		return io.ReadAll(cc.Stdin)
	}
	src := cc.Args[0]
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		if !cc.Network().Enabled() {
			return nil, errNetworkDisabled
		}
		resp, err := doPolicyRequest(ctx, cc.Network(), requestSpec{method: http.MethodGet, rawURL: src})
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
		}
		return io.ReadAll(boundedBodyReader(resp.Body, cc.Network()))
	}
	f, err := cc.FS().Open(cc.ResolvePath(src), os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func renderMarkdown(n *html.Node) string {
	var r mdRenderer
	r.walk(n)
	return r.String()
}

type mdRenderer struct {
	b          strings.Builder
	listDepth  int
	pre        bool
	suppressWS bool
}

func (r *mdRenderer) String() string {
	lines := strings.Split(r.b.String(), "\n")
	out := make([]string, 0, len(lines))
	blank := false
	for _, line := range lines {
		line = strings.TrimRight(line, " \t")
		if line == "" {
			if !blank && len(out) > 0 {
				out = append(out, "")
			}
			blank = true
			continue
		}
		out = append(out, line)
		blank = false
	}
	return strings.Join(out, "\n")
}

func (r *mdRenderer) walk(n *html.Node) {
	if n.Type == html.TextNode {
		r.text(n.Data)
		return
	}
	if n.Type != html.ElementNode && n.Type != html.DocumentNode {
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			r.walk(c)
		}
		return
	}
	tag := strings.ToLower(n.Data)
	switch tag {
	case "script", "style", "head":
		return
	case "h1", "h2", "h3", "h4", "h5", "h6":
		r.block()
		level := int(tag[1] - '0')
		r.b.WriteString(strings.Repeat("#", level) + " ")
		r.children(n)
		r.block()
	case "p", "div", "section", "article":
		r.block()
		r.children(n)
		r.block()
	case "br":
		r.b.WriteString("\n")
	case "strong", "b":
		r.wordSep()
		r.b.WriteString("**")
		r.children(n)
		r.b.WriteString("**")
	case "em", "i":
		r.wordSep()
		r.b.WriteString("*")
		r.children(n)
		r.b.WriteString("*")
	case "code":
		if r.pre {
			r.children(n)
		} else {
			r.wordSep()
			r.b.WriteString("`")
			r.children(n)
			r.b.WriteString("`")
		}
	case "pre":
		r.block()
		r.b.WriteString("```\n")
		old := r.pre
		r.pre = true
		r.children(n)
		r.pre = old
		r.b.WriteString("\n```\n")
		r.block()
	case "a":
		href := attr(n, "href")
		if href == "" {
			r.children(n)
			return
		}
		r.wordSep()
		r.b.WriteString("[")
		r.children(n)
		r.b.WriteString("](" + href + ")")
	case "ul", "ol":
		r.block()
		r.listDepth++
		r.children(n)
		r.listDepth--
		r.block()
	case "li":
		r.ensureLineStart()
		r.b.WriteString(strings.Repeat("  ", max(0, r.listDepth-1)) + "- ")
		r.children(n)
		r.b.WriteString("\n")
	case "blockquote":
		r.block()
		sub := mdRenderer{listDepth: r.listDepth, pre: r.pre}
		sub.children(n)
		for _, line := range strings.Split(strings.TrimSpace(sub.String()), "\n") {
			r.b.WriteString("> " + line + "\n")
		}
		r.block()
	default:
		r.children(n)
	}
}

func (r *mdRenderer) children(n *html.Node) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		r.walk(c)
	}
}

func (r *mdRenderer) text(s string) {
	if r.pre {
		r.b.WriteString(s)
		return
	}
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return
	}
	if !r.suppressWS && r.b.Len() > 0 {
		last := r.b.String()[r.b.Len()-1]
		if last != ' ' && last != '\n' && last != '[' && last != '(' && last != '*' && last != '`' {
			r.b.WriteByte(' ')
		}
	}
	r.b.WriteString(strings.Join(fields, " "))
}

func (r *mdRenderer) wordSep() {
	if r.b.Len() == 0 {
		return
	}
	last := r.b.String()[r.b.Len()-1]
	if last != ' ' && last != '\n' && last != '[' && last != '(' {
		r.b.WriteByte(' ')
	}
}

func (r *mdRenderer) block() {
	s := r.b.String()
	if s == "" || strings.HasSuffix(s, "\n\n") {
		return
	}
	if strings.HasSuffix(s, "\n") {
		r.b.WriteString("\n")
	} else {
		r.b.WriteString("\n\n")
	}
}

func (r *mdRenderer) ensureLineStart() {
	if r.b.Len() == 0 {
		return
	}
	if !strings.HasSuffix(r.b.String(), "\n") {
		r.b.WriteByte('\n')
	}
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}
