package gosh

// builtinMode classifies how the engine treats a name that mvdan/sh recognizes
// as a shell builtin.
type builtinMode int

const (
	// builtinAllow lets mvdan/sh run its native builtin (safe shell control).
	builtinAllow builtinMode = iota
	// builtinDeny refuses the builtin with a clean non-zero result; it never
	// runs and never falls through to the registry.
	builtinDeny
	// builtinShadow bypasses the native builtin and routes the call to the
	// command registry instead, so a host-registered command of the same name
	// wins (falling back to 127 if none is registered).
	builtinShadow
)

// BuiltinPolicy is the deny-by-default admission policy for mvdan/sh's own
// builtins (S2). Only the explicitly-allowed, pure shell-control builtins run
// natively; everything else (job control, interactive, host-touching, and
// dynamic-evaluation builtins) is denied unless the host opts in.
//
// SEAM AUDIT (OQ1). mvdan/sh dispatches functions and its own builtins BEFORE
// the ExecHandler, so overriding exec is not sufficient (S2). The CallHandler
// (see engine.go) consults this policy for EVERY command. The rationale for
// each builtin is documented in defaultBuiltinPolicy below; this is the
// authoritative allow/deny decision the PRD requires.
type BuiltinPolicy struct {
	// modes maps a builtin name to its handling. Names absent from the map are
	// treated as builtinDeny (deny-by-default).
	modes map[string]builtinMode
}

// mode returns the configured handling for a builtin name, defaulting to deny.
func (p BuiltinPolicy) mode(name string) builtinMode {
	if p.modes == nil {
		return builtinDeny
	}
	if m, ok := p.modes[name]; ok {
		return m
	}
	return builtinDeny
}

// clone returns a deep copy so per-Shell mutation is isolated.
func (p BuiltinPolicy) clone() BuiltinPolicy {
	m := make(map[string]builtinMode, len(p.modes))
	for k, v := range p.modes {
		m[k] = v
	}
	return BuiltinPolicy{modes: m}
}

// DefaultBuiltinPolicy returns the secure default builtin admission policy
// (the same one New applies). Hosts can derive a customized policy from it via
// Allow/Deny and install it with WithBuiltinPolicy.
func DefaultBuiltinPolicy() BuiltinPolicy { return defaultBuiltinPolicy() }

// Allow returns a copy of the policy that additionally permits the named
// builtins to run natively.
func (p BuiltinPolicy) Allow(names ...string) BuiltinPolicy {
	np := p.clone()
	for _, n := range names {
		np.modes[n] = builtinAllow
	}
	return np
}

// Deny returns a copy of the policy that additionally refuses the named
// builtins.
func (p BuiltinPolicy) Deny(names ...string) BuiltinPolicy {
	np := p.clone()
	for _, n := range names {
		np.modes[n] = builtinDeny
	}
	return np
}

// defaultBuiltinPolicy returns the secure default admission policy.
//
// ALLOWED (pure shell control; no path to host FS/exec/net/time):
//
//	:, true, false           — no-ops
//	cd, pwd                   — virtual working-directory control (via VFS handlers)
//	echo, printf              — output through the bounded stdio writers
//	read                      — reads the sandboxed stdin
//	test, [                   — conditionals (stat via VFS handler)
//	export, readonly, unset   — variable lifecycle
//	declare, typeset, local   — variable declaration/scoping
//	set, shopt                — shell option state (in-process only)
//	shift, getopts            — positional-parameter handling
//	return, break, continue, exit — control flow
//	let                       — arithmetic
//	mapfile, readarray        — read sandboxed stdin into arrays
//	dirs, pushd, popd         — directory stack (VFS-backed)
//	type                      — reports command classification (no host probe)
//
// DENIED (deny-by-default; each is a real or potential seam):
//
//	eval                      — dynamic evaluation of constructed strings (PRD: block)
//	source, .                 — execute another script file (PRD: block unless enabled)
//	exec                      — process-replacement / exec semantics (out of scope)
//	command, builtin          — can dispatch a builtin DIRECTLY, bypassing this
//	                            admission layer (a real bypass hole) — deny (PRD F9)
//	enable                    — could toggle/re-enable denied builtins — deny
//	trap                      — deny-by-default per PRD F9 (host may enable)
//	alias, unalias            — alias subsystem, deny-by-default per PRD F9
//	bg, fg, jobs, wait,       — job control / background (also rejected at S2a)
//	disown, suspend
//	kill                      — could signal host processes — deny
//	fc, history, bind, logout — interactive-only / may read host history — deny
//	newgrp                    — host group switch — deny
//	hash                      — command-path cache / host LookPath probe — deny
//	compgen, complete, compopt— completion machinery / host probe — deny
//	times, ulimit, caller,    — host resource/time/stack introspection — deny
//	umask                       (also unimplemented by mvdan) — deny
//	help                      — SHADOWED so a registered `help` coreutil can run;
//	                            falls back to 127 if none registered
func defaultBuiltinPolicy() BuiltinPolicy {
	allow := []string{
		":", "true", "false",
		"cd", "pwd",
		"echo", "printf",
		"read",
		"test", "[",
		"export", "readonly", "unset",
		"declare", "typeset", "local",
		"set", "shopt",
		"shift", "getopts",
		"return", "break", "continue", "exit",
		"let",
		"mapfile", "readarray",
		"dirs", "pushd", "popd",
		"type",
	}
	m := make(map[string]builtinMode, len(allow)+1)
	for _, name := range allow {
		m[name] = builtinAllow
	}
	m["help"] = builtinShadow
	// All other builtins (eval, source, ., exec, command, builtin, enable,
	// trap, alias, unalias, bg, fg, jobs, wait, disown, suspend, kill, fc,
	// history, bind, logout, newgrp, hash, compgen, complete, compopt, times,
	// ulimit, caller, umask) are absent and therefore denied by default.
	return BuiltinPolicy{modes: m}
}

// allowBuiltin returns a copy of the policy with name set to allow. Used by
// WithAllowedBuiltins.
func (p BuiltinPolicy) allowBuiltin(name string) BuiltinPolicy {
	np := p.clone()
	np.modes[name] = builtinAllow
	return np
}

// denyBuiltin returns a copy of the policy with name set to deny.
func (p BuiltinPolicy) denyBuiltin(name string) BuiltinPolicy {
	np := p.clone()
	np.modes[name] = builtinDeny
	return np
}
