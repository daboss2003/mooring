// Package updatecheck periodically asks GitHub whether a newer Mooring release
// exists and — critically — whether the RUNNING version is affected by a published
// security advisory, so the operator is told to update (and paged, for a security
// advisory) even when nobody is watching the dashboard. It is OPT-IN: with the check
// disabled it never contacts the network. When enabled it contacts ONLY the GitHub
// API and sends no telemetry payload (plain GETs of public release/advisory data).
package updatecheck

import (
	"strconv"
	"strings"
)

// semver is a parsed major.minor.patch (pre-release / build metadata ignored — a
// release tag is always vX.Y.Z here).
type semver struct{ major, minor, patch int }

// parseSemver parses "v1.2.3" or "1.2.3" (ignoring any -pre / +build suffix). ok is
// false for a non-version string like "dev" or "" — the caller then suppresses the
// update banner rather than guessing.
func parseSemver(s string) (semver, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	// Drop pre-release / build metadata: 1.2.3-rc1+abc → 1.2.3
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	var v semver
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, false
		}
		switch i {
		case 0:
			v.major = n
		case 1:
			v.minor = n
		case 2:
			v.patch = n
		}
	}
	return v, true
}

// cmp returns -1 if a<b, 0 if a==b, 1 if a>b.
func cmp(a, b semver) int {
	for _, d := range [][2]int{{a.major, b.major}, {a.minor, b.minor}, {a.patch, b.patch}} {
		if d[0] < d[1] {
			return -1
		}
		if d[0] > d[1] {
			return 1
		}
	}
	return 0
}

// newer reports whether latest is strictly greater than running (both must parse).
func newer(running, latest string) bool {
	r, ok1 := parseSemver(running)
	l, ok2 := parseSemver(latest)
	if !ok1 || !ok2 {
		return false
	}
	return cmp(l, r) > 0
}

// affectedByRange reports whether version satisfies a GitHub
// `vulnerable_version_range` — a comma-separated list of constraints ALL of which
// must hold, e.g. "< 0.4.4", ">= 0.4.0, < 0.4.4", "= 0.4.2". ok is false when any
// constraint can't be parsed; the caller then FAILS SAFE (treats it as affected) so
// a Mooring compromise is never silently under-reported.
func affectedByRange(version semver, rng string) (affected, ok bool) {
	rng = strings.TrimSpace(rng)
	if rng == "" {
		return false, false
	}
	for _, tok := range strings.Split(rng, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		op, verStr := splitConstraint(tok)
		want, good := parseSemver(verStr)
		if !good {
			return false, false
		}
		c := cmp(version, want)
		satisfied := false
		switch op {
		case "<":
			satisfied = c < 0
		case "<=":
			satisfied = c <= 0
		case ">":
			satisfied = c > 0
		case ">=":
			satisfied = c >= 0
		case "=", "==":
			satisfied = c == 0
		default:
			return false, false // unknown operator → unparseable
		}
		if !satisfied {
			return false, true // a constraint failed → not in range (parsed cleanly)
		}
	}
	return true, true
}

// splitConstraint separates a leading operator from the version in a constraint
// token like ">= 1.2.3" or "<0.4.4". A bare version means "=".
func splitConstraint(tok string) (op, ver string) {
	tok = strings.TrimSpace(tok)
	for _, o := range []string{">=", "<=", "==", ">", "<", "="} {
		if strings.HasPrefix(tok, o) {
			return o, strings.TrimSpace(tok[len(o):])
		}
	}
	return "=", tok
}
