package gosh

import "net/http"

// NetworkPolicy describes the egress capabilities granted to network-aware
// commands (e.g. a future curl). The zero value is a deny-all policy: with no
// network configured, network commands are absent entirely (S17). The shape is
// defined now so command-group agents can consume a stable type even before
// curl exists.
//
// All fields enforce deny-by-default semantics: a request must match an entry
// in AllowedOrigins (and, when set, AllowedPathPrefixes) and use a method in
// AllowedMethods to be permitted (S18/S19). The policy also hardens against
// SSRF and credential leakage (S20–S22).
type NetworkPolicy struct {
	// AllowedOrigins is the allow-list of exact origins (scheme://host[:port])
	// that may be contacted. Empty means no origin is allowed.
	AllowedOrigins []string
	// AllowedPathPrefixes optionally restricts requests to URL paths beginning
	// with one of these prefixes. Empty means any path on an allowed origin.
	AllowedPathPrefixes []string
	// AllowedMethods is the HTTP method allow-list. When empty, the safe
	// defaults GET and HEAD apply (S19).
	AllowedMethods []string
	// MaxResponseBytes caps the size of a response body read into the sandbox
	// (decompression-bomb defense). Zero means a conservative built-in default
	// is applied by the network command.
	MaxResponseBytes int64
	// MaxRedirects caps how many redirects are followed; each hop is
	// re-validated against this policy (S20).
	MaxRedirects int
	// CredentialTransforms are host-side functions that inject secrets (e.g.
	// Authorization headers) into outbound requests at the egress boundary.
	// They run outside the sandbox, are never visible to scripts, and override
	// any script-supplied header of the same name (S21).
	CredentialTransforms []func(*http.Request)
	// AllowPrivateIPs is a narrow, explicit opt-OUT of the SSRF defense. By
	// default (the zero value, false) gosh refuses to connect to private,
	// loopback, link-local, unspecified, and cloud-metadata addresses even when
	// the origin is allow-listed — resolution is checked at dial time so DNS
	// rebinding cannot bypass it, and the check is re-applied on every redirect
	// hop (S22). Set AllowPrivateIPs to true ONLY when you deliberately need to
	// reach an internal/loopback service (e.g. a trusted intranet host or a test
	// server); never enable it for untrusted scripts that can choose URLs.
	//
	// Security-by-default note: SSRF protection is ON whenever the policy is not
	// DangerouslyAllowFullInternet, regardless of how the policy was
	// constructed. A host that merely sets AllowedOrigins is protected without
	// having to remember an extra flag.
	AllowPrivateIPs bool
	// DangerouslyAllowFullInternet disables the origin allow-list AND the
	// private-IP SSRF defense, granting unrestricted egress. It exists for
	// explicit, loudly-warned opt-in only and must never be enabled for
	// untrusted scripts (S22).
	DangerouslyAllowFullInternet bool
}

// Enabled reports whether any network egress is permitted under this policy.
// Network commands use it to decide whether to register themselves at all
// (S17): a disabled policy means the command is reported as not found.
func (p NetworkPolicy) Enabled() bool {
	return p.DangerouslyAllowFullInternet || len(p.AllowedOrigins) > 0
}

// methods returns the effective method allow-list, applying the GET/HEAD
// default when none are configured.
func (p NetworkPolicy) methods() []string {
	if len(p.AllowedMethods) == 0 {
		return []string{http.MethodGet, http.MethodHead}
	}
	return p.AllowedMethods
}
