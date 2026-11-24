package web

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/crypto"
)

// totpLastStepKey + ":" + username holds that user's last consumed TOTP time step, so a
// code cannot be replayed within its validity window (review #4).
const totpLastStepKey = "auth_totp_last_step"

// requireAuth gates protected routes (pipeline step 6). Unauthenticated GETs are
// redirected to /login; other methods get 401. It runs BEFORE requireCSRF where
// both wrap a state-changing handler.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if SessionFrom(r.Context()) == nil {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// requirePerm gates a handler behind BOTH a valid session (requireAuth) AND the acting user's
// ROLE having capability `perm` ("view" | "deploy" | "admin"). viewer→view only, deployer→
// view+deploy, owner→everything. Fail-closed: a user whose role can't be resolved is denied.
// GET pages stay on requireAuth (= view for any authenticated user); this wraps the mutating
// (and secret-exfil) routes. Denials are audited.
func (s *Server) requirePerm(perm string, next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		user := sessionUser(r)
		role, ok := s.security().role(user)
		if !ok || !role.Can(perm) {
			_ = s.audit.Log(r.Context(), audit.Event{
				Actor: user, IP: ClientIP(r.Context()).String(), Action: "rbac_deny",
				Target: r.Method + " " + r.URL.Path, Outcome: audit.Deny, Level: audit.Security,
				Detail: "role lacks '" + perm + "'", UA: r.UserAgent(),
			})
			http.Error(w, "forbidden — your role can't perform this action", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	if SessionFrom(r.Context()) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.renderLogin(w, r, "")
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	// The UA rides on ctx so the lockout event recordFailure may write carries it too.
	ctx := audit.WithUserAgent(r.Context(), r.UserAgent())
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	totp := r.PostFormValue("totp")
	peer := ClientIP(ctx).String()
	sec := s.security()

	// Lockout check first (plan §5.2). A generic message — never reveal whether
	// the username exists or whether the lock is peer- or user-scoped.
	if s.locked(ctx, peer, username) {
		_ = s.audit.Log(ctx, audit.Event{
			Actor: username, IP: peer, Action: "login", Outcome: audit.Deny,
			Level: audit.Security, Detail: "locked out", UA: r.UserAgent(),
		})
		s.renderLogin(w, r, "Too many attempts. Try again later.")
		return
	}

	// Resolve the submitted username to a user; argon2id verify ALWAYS runs (dummy hash on a
	// miss) so response timing never reveals whether the user exists.
	u, userMatch := sec.user(username)
	hashToCheck := sec.dummyHash
	if userMatch {
		hashToCheck = u.passwordHash
	}
	// Bounded-concurrency gate around the expensive argon2id verify so a burst of
	// concurrent logins can't OOM a tiny box (review #10). Acquire, verify,
	// release immediately.
	select {
	case s.verifySem <- struct{}{}:
	case <-time.After(2 * time.Second):
		http.Error(w, "server busy, try again", http.StatusServiceUnavailable)
		return
	case <-ctx.Done():
		return
	}
	pwOK, _ := crypto.VerifyPassword(hashToCheck, []byte(password))
	<-s.verifySem
	ok := userMatch && pwOK
	why := "invalid password"
	if !userMatch {
		why = "unknown user"
	}

	// TOTP, when configured. Only checked when the password already matched (&&
	// short-circuits), so an attacker without the password can't burn the watermark.
	if ok {
		switch s.checkTOTPOnce(ctx, username, totp) {
		case totpPassed:
		case totpReplayed:
			ok, why = false, "TOTP code already used"
		case totpCheckFailed:
			ok, why = false, "TOTP check failed"
		default:
			ok, why = false, "invalid TOTP code"
		}
	}

	if !ok {
		s.recordFailure(ctx, peer, username)
		// Intentional: the audit row says which check failed (so the SIEM can tell a guessed
		// password from a stolen one missing its second factor); the response is the same for
		// every reason, so it confirms neither a username nor a password.
		_ = s.audit.Log(ctx, audit.Event{
			Actor: username, IP: peer, Action: "login", Outcome: audit.Deny,
			Level: audit.Security, Detail: why, UA: r.UserAgent(),
		})
		s.renderLogin(w, r, "Invalid credentials.")
		return
	}

	// Success: clear counters, mint a session for the RESOLVED acting user (not the owner).
	s.clearFailures(ctx, peer, username)
	rawID, err := s.sessions.Create(ctx, username, peer, r.UserAgent())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, rawID)
	_ = s.audit.Log(ctx, audit.Event{
		Actor: username, IP: peer, Action: "login", Outcome: audit.OK, Level: audit.Security,
		UA: r.UserAgent(),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// totpResult is the outcome of checkTOTPOnce.
type totpResult int

const (
	totpPassed      totpResult = iota // the code was valid and unused, or the user has no 2FA
	totpWrong                         // unknown user, or a missing, malformed or wrong code
	totpReplayed                      // a valid code whose step (or a later one) was already used
	totpCheckFailed                   // the watermark write failed
)

// verifyTOTPOnce validates a TOTP code against the configured secret and atomically
// advances the single-use watermark so the same code can't be replayed within its
// window — across login AND any other re-auth (e.g. the destructive app-delete). When
// 2FA is not configured it returns true (nothing to check). Not widened under clock
// skew (plan §5.9). Callers must gate this behind a prior password match (&&-short-
// circuit) so an attacker without the password can't burn the watermark.
func (s *Server) verifyTOTPOnce(ctx context.Context, username, code string) bool {
	return s.checkTOTPOnce(ctx, username, code) == totpPassed
}

// checkTOTPOnce is verifyTOTPOnce reporting why a code was refused (for the audit row only).
func (s *Server) checkTOTPOnce(ctx context.Context, username, code string) totpResult {
	sec := s.security()
	u, ok := sec.user(username)
	if !ok {
		return totpWrong // unknown user — fail closed
	}
	if u.totpSecret == "" {
		return totpPassed // 2FA not configured for this user
	}
	step, vok := crypto.ValidateTOTPStep(u.totpSecret, code, time.Now(), 1)
	if !vok {
		return totpWrong
	}
	// The single-use watermark is PER USER (a code is one secret's; one user's login must not
	// burn another's watermark within the same 30s step).
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO settings(key, value) VALUES(@k, @s)
		 ON CONFLICT(key) DO UPDATE SET value = @s WHERE CAST(value AS INTEGER) < @s`,
		sql.Named("k", totpLastStepKey+":"+username), sql.Named("s", int64(step)))
	if err != nil {
		return totpCheckFailed
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return totpReplayed // n==0 → already consumed (replay)
	}
	return totpPassed
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if c, err := r.Cookie(s.cookieName()); err == nil && c.Value != "" {
		_ = s.sessions.Delete(ctx, c.Value)
	}
	s.clearSessionCookie(w)
	if sess := SessionFrom(ctx); sess != nil {
		_ = s.audit.Log(ctx, audit.Event{
			Actor: sess.Username, IP: ClientIP(ctx).String(), Action: "logout", Outcome: audit.OK,
			UA: r.UserAgent(),
		})
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
