// Package apitoken is the scoped API-token model (plan §17.1): the keystone
// integration primitive — a new front DOOR, never a new trust PATH. A token is
// strictly LESS privileged than a browser session: its scope grammar has NO SYMBOL
// for a Tier-1 capability (key/allowlist/bind), nor for reveal-secret / raw-Caddy /
// setup-run / mint-another-token — those are simply not expressible, the same
// structural impossibility that makes the Tier-2/3 files dashboard-writable.
//
// Tokens are minted ONLY over the CLI/SSH (web minting would be a privesc surface),
// stored argon2id-hashed (the id scopes the lookup so exactly one verify runs per
// request), carry a mandatory expiry + a non-empty CIDR set (a token is an auth
// factor, NOT an allowlist bypass), and are constant-time compared + revocable.
package apitoken

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/crypto"
)

// readScopes are the read-only capabilities a token may carry.
var readScopes = map[string]bool{
	"status:read": true, "metrics:read": true, "events:read": true, "audit:read": true,
}

var (
	slugRe   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)
	deployRe = regexp.MustCompile(`^deploy:write:([a-z][a-z0-9-]{1,30})$`)
	tokenRe  = regexp.MustCompile(`^hmt_([a-f0-9]{24})_([A-Za-z0-9_-]{43})$`)
	idRe     = regexp.MustCompile(`^[a-f0-9]{24}$`)
)

// ValidScope reports whether s is a permissible scope. The ONLY shapes are the
// read scopes and deploy:write:<slug> — there is deliberately no grammar for a
// Tier-1 / reveal / caddy / setup / mint capability, so a token can never express
// more than the API exposes.
func ValidScope(s string) bool {
	return readScopes[s] || deployRe.MatchString(s)
}

// ParseScopes validates every requested scope, rejecting the empty set and any
// unknown/over-broad symbol.
func ParseScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, fmt.Errorf("a token must carry at least one scope")
	}
	out := make([]string, 0, len(scopes))
	seen := map[string]bool{}
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if !ValidScope(s) {
			return nil, fmt.Errorf("invalid or over-broad scope %q (allowed: status:read, metrics:read, events:read, audit:read, deploy:write:<slug>)", s)
		}
		if !seen[s] {
			out = append(out, s)
			seen[s] = true
		}
	}
	return out, nil
}

// ParseCIDRs validates a non-empty CIDR set, rejecting a 0-bit prefix (0.0.0.0/0 or
// ::/0 would turn the bounded CI exception into a global allowlist bypass).
func ParseCIDRs(cidrs []string) ([]netip.Prefix, error) {
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("a token requires a non-empty CIDR set (it is not an allowlist bypass)")
	}
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", c, err)
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("CIDR %q is a catch-all (0 bits) — refused (a token never bypasses the allowlist)", c)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Record is one stored token (no plaintext secret — only the argon2id hash).
type Record struct {
	ID        string
	Hash      string // argon2id-encoded
	Scopes    []string
	CIDRs     []netip.Prefix
	ExpiresAt int64
	Revoked   bool
}

// Allows reports whether the token's scopes permit the requested capability.
func (r Record) Allows(scope string) bool {
	for _, s := range r.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// active reports whether the token is usable at now (not revoked, not expired).
func (r Record) active(now int64) bool { return !r.Revoked && r.ExpiresAt > now }

// Minted is the freshly-minted token: the one-time plaintext (shown ONCE) + the
// stored Record.
type Minted struct {
	Plaintext string
	Record    Record
}

// Mint creates a token. ttl must be positive (mandatory expiry); scopes + cidrs are
// validated. The plaintext "hmt_<id>_<secret>" is returned ONCE; only the hash is
// stored.
func Mint(scopes, cidrs []string, ttl time.Duration, now time.Time) (Minted, error) {
	sc, err := ParseScopes(scopes)
	if err != nil {
		return Minted{}, err
	}
	cd, err := ParseCIDRs(cidrs)
	if err != nil {
		return Minted{}, err
	}
	if ttl <= 0 {
		return Minted{}, fmt.Errorf("a token requires a positive expiry (--ttl)")
	}
	id, err := randHex(12) // 24 hex chars
	if err != nil {
		return Minted{}, err
	}
	secret, err := randB64(32) // 43 base64url chars
	if err != nil {
		return Minted{}, err
	}
	hash, err := crypto.HashPassword([]byte(secret), crypto.DefaultArgon2Params)
	if err != nil {
		return Minted{}, err
	}
	rec := Record{ID: id, Hash: hash, Scopes: sc, CIDRs: cd, ExpiresAt: now.Add(ttl).Unix()}
	return Minted{Plaintext: "hmt_" + id + "_" + secret, Record: rec}, nil
}

// SplitBearer extracts the (id, secret) from a bearer, or ok=false on any malformed
// input. It does NOT hit the DB — the caller looks up by id, so a malformed/unknown
// token is never an unauthenticated DB-lookup oracle.
func SplitBearer(bearer string) (id, secret string, ok bool) {
	m := tokenRe.FindStringSubmatch(strings.TrimSpace(bearer))
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// ValidID reports whether s is a well-formed token id (for the store lookup).
func ValidID(s string) bool { return idRe.MatchString(s) }

// AuditTarget is what an audit event records for a typed token id: the id, the id part of a whole
// token pasted in its place, else "". Intentional: what was typed is never stored as is — a pasted
// token would put its secret in the audit log.
func AuditTarget(typed string) string {
	if ValidID(typed) {
		return typed
	}
	if id, _, ok := SplitBearer(typed); ok {
		return id
	}
	return ""
}

// VerifySecret constant-time-checks the presented secret against the record and its
// active window. The argon2id verify ALWAYS runs first (even for an expired/revoked
// record) so the cost is identical whether or not the token is active — an
// expired/revoked id must not be distinguishable by latency from a live one (the
// active() check used to short-circuit before argon2, which leaked a revocation/expiry
// timing oracle; M19 review). The id already selected the single record, so the verify
// still runs at most ONCE per request.
func (r Record) VerifySecret(secret string, now int64) bool {
	ok, err := crypto.VerifyPassword(r.Hash, []byte(secret))
	if err != nil || !ok {
		return false
	}
	return r.active(now)
}

// CIDRUnion returns the union of every ACTIVE token's CIDR set — the precomputed set
// the IP allowlist checks the unspoofable peer against BEFORE any bearer is parsed
// (so a token id can't be an enumeration oracle and an unknown bearer can't trigger
// a DB lookup before the peer is admitted).
func CIDRUnion(records []Record, now int64) []netip.Prefix {
	var out []netip.Prefix
	for _, r := range records {
		if r.active(now) {
			out = append(out, r.CIDRs...)
		}
	}
	return out
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// base64url without padding: 32 bytes → 43 chars (matches tokenRe).
	return base64.RawURLEncoding.EncodeToString(b), nil
}
