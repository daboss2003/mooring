package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/crypto"
	"github.com/daboss2003/mooring/internal/session"
)

// requirePerm enforces the acting user's role against the route's capability tier.
func TestRequirePermGates(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	hash, err := crypto.HashPassword([]byte(testPassword), crypto.DefaultArgon2Params)
	if err != nil {
		t.Fatal(err)
	}
	e.srv.cfg.ExtraUsers = []config.UserConfig{
		{Username: "dep", PasswordHash: hash, Role: config.RoleDeployer},
		{Username: "vie", PasswordHash: hash, Role: config.RoleViewer},
	}
	sec, err := buildSecState(e.srv.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.srv.sec.Store(sec)

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	cases := []struct {
		user, perm string
		want       int
	}{
		{"operator", "admin", http.StatusNoContent}, // owner: everything
		{"operator", "deploy", http.StatusNoContent},
		{"operator", "view", http.StatusNoContent},
		{"dep", "deploy", http.StatusNoContent}, // deployer: view+deploy
		{"dep", "view", http.StatusNoContent},
		{"dep", "admin", http.StatusForbidden},
		{"vie", "view", http.StatusNoContent}, // viewer: view only
		{"vie", "deploy", http.StatusForbidden},
		{"vie", "admin", http.StatusForbidden},
		{"ghost", "view", http.StatusForbidden}, // unknown user (no resolvable role) → denied
	}
	for _, tc := range cases {
		h := e.srv.requirePerm(tc.perm, okHandler)
		r := httptest.NewRequest("POST", "/x", nil)
		r = r.WithContext(withSession(r.Context(), &session.Session{Username: tc.user}))
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != tc.want {
			t.Errorf("user=%s perm=%s: got %d want %d", tc.user, tc.perm, w.Code, tc.want)
		}
	}
}

// The single-use TOTP watermark is PER USER: one user's code must not burn another's, even
// when (pathologically) they share a secret.
func TestTOTPWatermarkIsolatedPerUser(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := crypto.HashPassword([]byte(testPassword), crypto.DefaultArgon2Params)
	e.srv.cfg.Auth.TOTPSecret = secret // owner "operator" gets TOTP
	e.srv.cfg.ExtraUsers = []config.UserConfig{
		{Username: "dep", PasswordHash: hash, TOTPSecret: secret, Role: config.RoleDeployer}, // same secret on purpose
	}
	sec, err := buildSecState(e.srv.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.srv.sec.Store(sec)

	ctx := context.Background()
	code, err := crypto.GenerateTOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// operator consumes their watermark.
	if !e.srv.verifyTOTPOnce(ctx, "operator", code) {
		t.Fatal("operator's first use of a valid code must succeed")
	}
	// A replay for operator is rejected.
	if e.srv.verifyTOTPOnce(ctx, "operator", code) {
		t.Fatal("operator replay of the same code must be rejected")
	}
	// dep, with the SAME code, must still succeed — its watermark is separate.
	if !e.srv.verifyTOTPOnce(ctx, "dep", code) {
		t.Fatal("a different user's watermark must not be burned by operator's use")
	}
}
