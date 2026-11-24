package apitoken

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func mustTime() time.Time { return time.Unix(1_700_000_000, 0) }

// The scope grammar must have NO symbol for any Tier-1 / reveal / caddy / setup /
// mint capability — those privileges are structurally inexpressible.
func TestScopeGrammarHasNoTier1Symbol(t *testing.T) {
	forbidden := []string{
		"key:write", "key:read", "allowlist:write", "bind:write", "auth:write",
		"secret:reveal", "reveal:secret", "caddy:write", "edge:raw", "setup:run",
		"token:mint", "apitoken:mint", "deploy:write", "deploy:write:*",
		"*", "admin", "status:write", "metrics:write", "deploy:write:",
		"deploy:write:UPPER", "deploy:write:1bad", "status:read ",
	}
	for _, s := range forbidden {
		if ValidScope(s) {
			t.Errorf("scope %q must NOT be expressible", s)
		}
	}
	for _, s := range []string{"status:read", "metrics:read", "events:read", "audit:read", "deploy:write:web", "deploy:write:my-app"} {
		if !ValidScope(s) {
			t.Errorf("scope %q must be valid", s)
		}
	}
}

func TestParseScopesRejectsEmptyAndDupes(t *testing.T) {
	if _, err := ParseScopes(nil); err == nil {
		t.Error("empty scope set must be rejected")
	}
	if _, err := ParseScopes([]string{"status:read", "bogus"}); err == nil {
		t.Error("any invalid scope must reject the whole set")
	}
	out, err := ParseScopes([]string{"status:read", "status:read", "metrics:read"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Errorf("dupes must collapse, got %v", out)
	}
}

func TestParseCIDRsRejectsCatchAll(t *testing.T) {
	if _, err := ParseCIDRs(nil); err == nil {
		t.Error("empty CIDR set must be rejected (a token is not an allowlist bypass)")
	}
	for _, c := range []string{"0.0.0.0/0", "::/0"} {
		if _, err := ParseCIDRs([]string{c}); err == nil {
			t.Errorf("catch-all %q must be refused", c)
		}
	}
	// A valid mixed set, including one good prefix alongside a catch-all → still rejected.
	if _, err := ParseCIDRs([]string{"10.0.0.0/8", "0.0.0.0/0"}); err == nil {
		t.Error("a catch-all anywhere in the set must reject the whole set")
	}
	out, err := ParseCIDRs([]string{"203.0.113.0/24", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Errorf("expected 2 prefixes, got %v", out)
	}
}

func TestMintRequiresPositiveTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Hour} {
		if _, err := Mint([]string{"status:read"}, []string{"10.0.0.0/8"}, ttl, mustTime()); err == nil {
			t.Errorf("ttl %v must be rejected (mandatory expiry)", ttl)
		}
	}
}

func TestMintAndVerifyRoundTrip(t *testing.T) {
	now := mustTime()
	m, err := Mint([]string{"status:read", "deploy:write:web"}, []string{"10.0.0.0/8"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	// Plaintext must parse, and only the hash is stored (no secret in the record).
	if !strings.HasPrefix(m.Plaintext, "hmt_") {
		t.Errorf("plaintext must be hmt_-prefixed, got %q", m.Plaintext)
	}
	if strings.Contains(m.Record.Hash, m.Plaintext) || m.Record.Hash == "" {
		t.Error("record must store only the argon2id hash, never the plaintext")
	}
	id, secret, ok := SplitBearer(m.Plaintext)
	if !ok || id != m.Record.ID {
		t.Fatalf("SplitBearer failed: ok=%v id=%q want %q", ok, id, m.Record.ID)
	}
	nowUnix := now.Unix()
	if !m.Record.VerifySecret(secret, nowUnix) {
		t.Error("correct secret must verify within the active window")
	}
	if m.Record.VerifySecret("wrong-secret-wrong-secret-wrong-secret-wro", nowUnix) {
		t.Error("a wrong secret must NOT verify")
	}
	if !m.Record.Allows("deploy:write:web") || m.Record.Allows("deploy:write:other") {
		t.Error("Allows must reflect exactly the granted scopes")
	}
}

func TestVerifyRespectsExpiryAndRevocation(t *testing.T) {
	now := mustTime()
	m, err := Mint([]string{"status:read"}, []string{"10.0.0.0/8"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	_, secret, _ := SplitBearer(m.Plaintext)
	// After expiry.
	if m.Record.VerifySecret(secret, m.Record.ExpiresAt+1) {
		t.Error("an expired token must not verify")
	}
	// Exactly at expiry boundary (ExpiresAt is exclusive: active requires ExpiresAt > now).
	if m.Record.VerifySecret(secret, m.Record.ExpiresAt) {
		t.Error("a token at its exact expiry instant must not verify")
	}
	// Revoked.
	rev := m.Record
	rev.Revoked = true
	if rev.VerifySecret(secret, now.Unix()) {
		t.Error("a revoked token must not verify even with the correct secret")
	}
}

func TestSplitBearerRejectsMalformed(t *testing.T) {
	for _, b := range []string{
		"", "hmt_", "hmt_short_x", "Bearer hmt_...", "hmt_" + strings.Repeat("g", 24) + "_" + strings.Repeat("a", 43),
		"hmt_" + strings.Repeat("a", 23) + "_" + strings.Repeat("a", 43), // 23 hex (too short)
		"hmt_" + strings.Repeat("a", 24) + "_" + strings.Repeat("a", 42), // 42 secret (too short)
		"xmt_" + strings.Repeat("a", 24) + "_" + strings.Repeat("a", 43), // wrong prefix
	} {
		if _, _, ok := SplitBearer(b); ok {
			t.Errorf("malformed bearer %q must not split", b)
		}
	}
	// A well-formed shape splits (even if no such token exists — the DB lookup decides).
	good := "hmt_" + strings.Repeat("a", 24) + "_" + strings.Repeat("a", 43)
	if id, _, ok := SplitBearer(good); !ok || !ValidID(id) {
		t.Errorf("well-formed bearer must split into a valid id")
	}
}

func TestCIDRUnionOnlyActive(t *testing.T) {
	now := mustTime().Unix()
	mk := func(cidr string, exp int64, revoked bool) Record {
		p, _ := netip.ParsePrefix(cidr)
		return Record{CIDRs: []netip.Prefix{p}, ExpiresAt: exp, Revoked: revoked}
	}
	recs := []Record{
		mk("10.0.0.0/8", now+1000, false),    // active
		mk("172.16.0.0/12", now-1, false),    // expired
		mk("192.168.0.0/16", now+1000, true), // revoked
	}
	union := CIDRUnion(recs, now)
	if len(union) != 1 || union[0].String() != "10.0.0.0/8" {
		t.Errorf("union must contain ONLY active tokens' CIDRs, got %v", union)
	}
}

// AuditTarget never returns a token's secret: an id stays, a whole pasted token keeps only its id,
// anything else is dropped.
func TestAuditTargetNeverKeepsASecret(t *testing.T) {
	m, err := Mint([]string{"status:read"}, []string{"203.0.113.0/24"}, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id := m.Record.ID
	_, secret, _ := SplitBearer(m.Plaintext)
	for _, tc := range []struct{ in, want string }{
		{id, id},
		{m.Plaintext, id},
		{"  " + m.Plaintext + "\n", id},
		{"not an id; " + secret, ""},
		{"", ""},
	} {
		got := AuditTarget(tc.in)
		if got != tc.want {
			t.Errorf("AuditTarget(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if secret != "" && strings.Contains(got, secret) {
			t.Errorf("AuditTarget(%q) kept the secret", tc.in)
		}
	}
}
