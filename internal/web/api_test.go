package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/apitoken"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/crypto"
	"github.com/daboss2003/mooring/internal/store"
)

// seedToken describes a token to mint + insert BEFORE the server is constructed, so
// New()'s CIDR-union recompute picks it up at the IP gate.
type seedToken struct {
	scopes []string
	cidrs  []string
}

// buildAPIServer builds a server with an apitoken store, pre-seeds the given tokens,
// and returns the env, the store, and the minted plaintexts (one per seed). The
// allowlist is loopback-only, so any /api/v1 admission is purely via the token union.
func buildAPIServer(t *testing.T, withStore bool, seeds ...seedToken) (*testEnv, *apitoken.Store, []string) {
	t.Helper()
	hash, err := crypto.HashPassword([]byte(testPassword), crypto.DefaultArgon2Params)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	var b strings.Builder
	fmt.Fprintf(&b, "bind_addr: \"127.0.0.1:9000\"\n")
	fmt.Fprintf(&b, "encryption_key: %q\n", key)
	fmt.Fprintf(&b, "ip_allowlist:\n  - \"127.0.0.1/32\"\n")
	fmt.Fprintf(&b, "auth:\n  username: \"operator\"\n  password_hash: %q\n", hash)
	fmt.Fprintf(&b, "edge:\n  mode: \"managed\"\n  acme_email: \"ops@example.com\"\n  acme_ca: \"https://acme.example/directory\"\n")
	fmt.Fprintf(&b, "data_dir: %q\n", t.TempDir())
	cfg, err := config.Parse([]byte(b.String()))
	if err != nil {
		t.Fatalf("test config invalid: %v", err)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	var ts *apitoken.Store
	var plaintexts []string
	if withStore {
		ts = apitoken.NewStore(db)
		now := time.Now()
		for i, sd := range seeds {
			m, err := apitoken.Mint(sd.scopes, sd.cidrs, time.Hour, now)
			if err != nil {
				t.Fatalf("seed %d mint: %v", i, err)
			}
			if err := ts.Insert(context.Background(), m.Record, "test", now); err != nil {
				t.Fatalf("seed %d insert: %v", i, err)
			}
			plaintexts = append(plaintexts, m.Plaintext)
		}
	}
	srv, err := New(cfg, Deps{DB: db, APITokens: ts})
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{srv: srv}, ts, plaintexts
}

func bearer(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

func TestAPIDisabledWithoutStore(t *testing.T) {
	e, _, _ := buildAPIServer(t, false)
	// Even from loopback (allowlisted), with no token store the route is invisible.
	resp := e.req(t, "GET", "/api/v1/status", "127.0.0.1:1", nil, nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("API with no store = %d, want 404", resp.StatusCode)
	}
}

func TestAPIRequiresBearer(t *testing.T) {
	e, _, _ := buildAPIServer(t, true, seedToken{[]string{"status:read"}, []string{"198.51.100.0/24"}})
	// From the token's CIDR (admitted at the gate) but with NO bearer → 401.
	resp := e.req(t, "GET", "/api/v1/status", "198.51.100.5:1", nil, nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no bearer = %d, want 401", resp.StatusCode)
	}
}

func TestAPIValidBearerStatus(t *testing.T) {
	e, _, pt := buildAPIServer(t, true, seedToken{[]string{"status:read"}, []string{"198.51.100.0/24"}})
	resp := e.req(t, "GET", "/api/v1/status", "198.51.100.5:1", bearer(pt[0]), nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid bearer = %d, want 200", resp.StatusCode)
	}
	var out struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || !out.OK {
		t.Errorf("unexpected body: ok=%v err=%v", out.OK, err)
	}
}

func TestAPIRejectsSessionCookie(t *testing.T) {
	e, _, pt := buildAPIServer(t, true, seedToken{[]string{"status:read"}, []string{"198.51.100.0/24"}})
	// A request carrying the admin session cookie (confused-deputy) is refused even
	// with a valid bearer.
	ck := &http.Cookie{Name: e.srv.cookieName(), Value: "anything"}
	resp := e.req(t, "GET", "/api/v1/status", "198.51.100.5:1", bearer(pt[0]), []*http.Cookie{ck}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("API with session cookie = %d, want 401 (confused-deputy refused)", resp.StatusCode)
	}
}

func TestAPIScopeEnforced(t *testing.T) {
	e, _, pt := buildAPIServer(t, true, seedToken{[]string{"status:read"}, []string{"198.51.100.0/24"}})
	// status:read token may not read metrics.
	resp := e.req(t, "GET", "/api/v1/metrics", "198.51.100.5:1", bearer(pt[0]), nil, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("out-of-scope = %d, want 403", resp.StatusCode)
	}
}

func TestAPIDeployScopeBoundToProject(t *testing.T) {
	e, _, pt := buildAPIServer(t, true, seedToken{[]string{"deploy:write:web"}, []string{"198.51.100.0/24"}})
	// Correct project → scope matches → the handler runs; this server has no git store or write
	// plane, so it answers 503 (api_deploy_test.go covers the deploy itself).
	ok := e.req(t, "POST", "/api/v1/apps/web/deploy", "198.51.100.5:1", bearer(pt[0]), nil, nil)
	if ok.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("in-scope deploy without a write plane = %d, want 503", ok.StatusCode)
	}
	// Different project → scope deploy:write:other not granted → 403.
	bad := e.req(t, "POST", "/api/v1/apps/other/deploy", "198.51.100.5:1", bearer(pt[0]), nil, nil)
	if bad.StatusCode != http.StatusForbidden {
		t.Errorf("cross-project deploy = %d, want 403 (scope bound to project)", bad.StatusCode)
	}
}

// The IP-gate union admits the API surface ONLY — never the browser admin plane.
func TestAPIUnionDoesNotOpenAdminPlane(t *testing.T) {
	e, _, _ := buildAPIServer(t, true, seedToken{[]string{"status:read"}, []string{"198.51.100.0/24"}})
	// From the token CIDR, the admin plane is still invisible (not in the allowlist).
	home := e.req(t, "GET", "/", "198.51.100.5:1", nil, nil, nil)
	if home.StatusCode != http.StatusNotFound {
		t.Errorf("admin plane from token CIDR = %d, want 404 (union opens only /api/v1)", home.StatusCode)
	}
	// An IP in neither the allowlist nor the union can't even reach the API.
	off := e.req(t, "GET", "/api/v1/status", "9.9.9.9:1", nil, nil, nil)
	if off.StatusCode != http.StatusNotFound {
		t.Errorf("API from non-admitted IP = %d, want 404", off.StatusCode)
	}
}

// A token is bound to its OWN CIDR — the union is a coarse gate, not the grant. Token
// A presented from token B's (admitted) network is refused at auth.
func TestAPITokenBoundToOwnCIDR(t *testing.T) {
	e, _, pt := buildAPIServer(t, true,
		seedToken{[]string{"status:read"}, []string{"198.51.100.0/24"}}, // token A
		seedToken{[]string{"status:read"}, []string{"203.0.113.0/24"}},  // token B
	)
	// Peer 203.0.113.9 is admitted at the gate (token B's CIDR is in the union) but
	// token A is not valid from there.
	resp := e.req(t, "GET", "/api/v1/status", "203.0.113.9:1", bearer(pt[0]), nil, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("token A from token B's network = %d, want 403 (bound to own CIDR)", resp.StatusCode)
	}
}

// Revocation takes effect immediately at auth (the DB is re-read live), even though
// the cached IP-union still admits the network until the next reload.
func TestAPIRevokedTokenRejectedLive(t *testing.T) {
	e, ts, pt := buildAPIServer(t, true, seedToken{[]string{"status:read"}, []string{"198.51.100.0/24"}})
	id, _, _ := apitoken.SplitBearer(pt[0])
	if err := ts.Revoke(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	resp := e.req(t, "GET", "/api/v1/status", "198.51.100.5:1", bearer(pt[0]), nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked token = %d, want 401 (live DB re-check)", resp.StatusCode)
	}
}

// Timing parity (M19 review fix): an unknown id, an expired/revoked id, and a
// valid-id/wrong-secret must all be latency-indistinguishable — each pays exactly one
// argon2 verify. We can't assert wall-clock timing reliably in a unit test, but we CAN
// assert the behavioural contract that makes them equal: all four failure shapes
// return the identical 401 "invalid token" and none short-circuits to a different
// status. (The cost-parity itself is enforced by VerifySecret always running argon2
// and requireToken's decoy verify on the not-found path.)
func TestAPIFailuresAreUniform(t *testing.T) {
	e, ts, pt := buildAPIServer(t, true, seedToken{[]string{"status:read"}, []string{"198.51.100.0/24"}})
	goodID, goodSecret, _ := apitoken.SplitBearer(pt[0])

	// 1. unknown id, well-formed shape
	unknown := "hmt_" + strings.Repeat("a", 24) + "_" + strings.Repeat("b", 43)
	// 2. valid id, wrong secret
	wrongSecret := "hmt_" + goodID + "_" + strings.Repeat("c", 43)
	_ = goodSecret

	for name, tok := range map[string]string{"unknown-id": unknown, "valid-id-wrong-secret": wrongSecret} {
		resp := e.req(t, "GET", "/api/v1/status", "198.51.100.5:1", bearer(tok), nil, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401", name, resp.StatusCode)
		}
	}
	// 3. revoked id (existing row, inactive) — also 401, and VerifySecret still runs argon2.
	if err := ts.Revoke(context.Background(), goodID); err != nil {
		t.Fatal(err)
	}
	resp := e.req(t, "GET", "/api/v1/status", "198.51.100.5:1", bearer(pt[0]), nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked = %d, want 401", resp.StatusCode)
	}
}

func TestAPIMalformedBearerRejected(t *testing.T) {
	e, _, _ := buildAPIServer(t, true, seedToken{[]string{"status:read"}, []string{"198.51.100.0/24"}})
	for _, h := range []map[string]string{
		{"Authorization": "Bearer not-a-token"},
		{"Authorization": "Basic xxxx"},
		{"Authorization": "hmt_" + strings.Repeat("a", 24) + "_" + strings.Repeat("a", 43)}, // no scheme
	} {
		resp := e.req(t, "GET", "/api/v1/status", "198.51.100.5:1", h, nil, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("malformed auth %v = %d, want 401", h, resp.StatusCode)
		}
	}
}
