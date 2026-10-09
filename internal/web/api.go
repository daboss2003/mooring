package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/apitoken"
	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/crypto"
)

// The scoped machine API (/api/v1, plan §17.1) is a SEPARATE auth surface from the
// browser admin plane: bearer-ONLY, cookie-REJECTING, and CSRF-EXEMPT (it carries no
// ambient credential, so there is nothing for a cross-site request to abuse). It
// authenticates strictly LESS than a session — a token can express only the read
// scopes + deploy:write:<slug>, never a Tier-1 / reveal / setup / mint capability
// (the grammar has no symbol for them). Every route is registered WITHOUT requireAuth
// and WITHOUT requireCSRF; requireToken is the only gate, applied per-route.

// apiErr writes a minimal JSON error. It never echoes the bearer or distinguishes
// "no such token" from "wrong secret" (no enumeration oracle).
func apiErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func apiJSON(w http.ResponseWriter, v any) { apiJSONStatus(w, http.StatusOK, v) }

// apiJSONStatus writes v as JSON with the given status.
func apiJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// bearerToken extracts the credential from an "Authorization: Bearer <token>"
// header (case-insensitive scheme), or "" if absent/malformed.
func bearerToken(h string) string {
	const scheme = "bearer "
	if len(h) <= len(scheme) || !strings.EqualFold(h[:len(scheme)], scheme) {
		return ""
	}
	return strings.TrimSpace(h[len(scheme):])
}

// fixedScope adapts a constant scope to the scopeFn signature requireToken expects.
func fixedScope(scope string) func(*http.Request) string {
	return func(*http.Request) string { return scope }
}

// requireToken is the /api/v1 gate (pipeline step 6, the bearer analogue of
// requireAuth). scopeFn computes the capability THIS request needs (constant for
// read routes; deploy:write:<project> for the deploy route). It:
//   - 404s when the API is disabled (no store) — never reveals the route exists;
//   - REJECTS any request bearing the admin session cookie (a confused-deputy: a
//     browser must never drive the machine API with its ambient credential);
//   - parses the bearer, looks the token up BY ID (one indexed row → at most one
//     argon2id verify, bounded by verifySem), and constant-time-verifies the secret;
//   - re-binds the presented token to its OWN CIDR set (the IP-gate union is a coarse
//     admit; the grant requires the client to be inside THIS token's declared range);
//   - enforces the scope. Any failure is a uniform 401/403 with an audit line.
func (s *Server) requireToken(scopeFn func(*http.Request) string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.apiTokens == nil {
			notFound(w)
			return
		}
		// A machine client never carries the admin session cookie; its presence means
		// a browser is being used as a confused deputy → refuse outright.
		if c, err := r.Cookie(s.cookieName()); err == nil && c.Value != "" {
			s.auditAPI(r, "", audit.Deny, "session cookie presented to the API")
			apiErr(w, http.StatusUnauthorized, "the API does not accept session cookies")
			return
		}
		id, secret, ok := apitoken.SplitBearer(bearerToken(r.Header.Get("Authorization")))
		if !ok {
			s.auditAPI(r, "", audit.Deny, "missing or malformed bearer")
			apiErr(w, http.StatusUnauthorized, "a valid bearer token is required")
			return
		}
		rec, err := s.apiTokens.Get(r.Context(), id)
		if err != nil {
			// ErrNotFound and any store error must be INDISTINGUISHABLE from a wrong
			// secret — including by latency. Pay one decoy argon2id verify (same params
			// a real token uses) so a present-and-active id can't be told from an
			// unknown/expired/revoked one by timing (mirrors the login dummy-hash
			// parity; M19 review). VerifySecret itself always runs argon2 before the
			// active check, so expired/revoked existing ids cost the same too.
			s.apiVerifySem <- struct{}{}
			_, _ = crypto.VerifyPassword(s.apiDummyHash, []byte(secret))
			<-s.apiVerifySem
			s.auditAPI(r, id, audit.Deny, "unknown token")
			apiErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		now := time.Now()
		// Bound concurrent argon2id verifications (its OWN pool, never starves login) so
		// a flood of known-id/wrong-secret attempts from an admitted IP can't exhaust
		// memory.
		s.apiVerifySem <- struct{}{}
		valid := rec.VerifySecret(secret, now.Unix())
		<-s.apiVerifySem
		if !valid {
			s.auditAPI(r, id, audit.Deny, "invalid or expired token")
			apiErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		// The IP union admitted SOME active token's network at the gate; the presented
		// token must itself be valid from this client's network.
		if !prefixesContain(rec.CIDRs, ClientIP(r.Context())) {
			s.auditAPI(r, id, audit.Deny, "token used outside its CIDR set")
			apiErr(w, http.StatusForbidden, "token is not valid from this network")
			return
		}
		scope := scopeFn(r)
		if !apitoken.ValidScope(scope) || !rec.Allows(scope) {
			s.auditAPI(r, id, audit.Deny, "token lacks scope "+scope)
			apiErr(w, http.StatusForbidden, "token lacks the required scope")
			return
		}
		s.apiTokens.TouchLastUsed(r.Context(), id, now)
		r = r.WithContext(withTokenID(r.Context(), id))
		h(w, r)
	}
}

// auditAPI records an API auth/authorization decision (token id as actor, never the
// secret).
func (s *Server) auditAPI(r *http.Request, tokenID string, outcome audit.Outcome, detail string) {
	actor := "api"
	if tokenID != "" {
		actor = "api:" + tokenID
	}
	_ = s.audit.Log(r.Context(), audit.Event{
		Actor: actor, IP: ClientIP(r.Context()).String(), Action: "api_request",
		Outcome: outcome, Level: audit.Security, Target: r.Method + " " + r.URL.Path, Detail: detail,
	})
}

// --- read endpoints ---

type apiStatusService struct {
	Service string `json:"service"`
	State   string `json:"state"`
	Health  string `json:"health,omitempty"`
}

type apiStatusApp struct {
	Project  string             `json:"project"`
	Services []apiStatusService `json:"services"`
}

// handleAPIStatus (status:read) returns a curated per-app health summary — never the
// internal Snapshot struct (no working dirs, images, or other operational detail).
func (s *Server) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	out := struct {
		OK       bool           `json:"ok"`
		DockerOK bool           `json:"docker_ok"`
		Apps     []apiStatusApp `json:"apps"`
	}{OK: true}
	if s.mon != nil {
		if snap := s.mon.Snapshot(); snap != nil {
			out.DockerOK = snap.DockerOK
			for _, a := range snap.Apps {
				app := apiStatusApp{Project: a.Project}
				for _, svc := range a.Services {
					app.Services = append(app.Services, apiStatusService{Service: svc.Service, State: svc.State, Health: svc.Health})
				}
				out.Apps = append(out.Apps, app)
			}
		}
	}
	apiJSON(w, out)
}

// handleAPIMetrics (metrics:read) returns the host resource sample.
func (s *Server) handleAPIMetrics(w http.ResponseWriter, r *http.Request) {
	out := struct {
		CPUPercent float64 `json:"cpu_percent"`
		Load1      float64 `json:"load1"`
		MemTotal   uint64  `json:"mem_total"`
		MemUsed    uint64  `json:"mem_used"`
		DiskTotal  uint64  `json:"disk_total"`
		DiskUsed   uint64  `json:"disk_used"`
		Available  bool    `json:"available"`
	}{}
	if s.mon != nil {
		if snap := s.mon.Snapshot(); snap != nil && snap.HostOK {
			h := snap.Host
			out.CPUPercent, out.Load1 = h.CPUPercent, h.Load1
			out.MemTotal, out.MemUsed = h.MemTotal, h.MemUsed
			out.DiskTotal, out.DiskUsed = h.DiskTotal, h.DiskUsed
			out.Available = true
		}
	}
	apiJSON(w, out)
}

// handleAPIEvents (events:read) returns recent info-level events.
func (s *Server) handleAPIEvents(w http.ResponseWriter, r *http.Request) {
	s.writeAPIEvents(w, r, "info")
}

// handleAPIAudit (audit:read) returns recent security-level events (the audit trail).
func (s *Server) handleAPIAudit(w http.ResponseWriter, r *http.Request) {
	s.writeAPIEvents(w, r, "security")
}

type apiEvent struct {
	Seq     int64  `json:"seq"`
	TS      int64  `json:"ts"`
	Actor   string `json:"actor,omitempty"`
	IP      string `json:"ip,omitempty"`
	Action  string `json:"action"`
	Target  string `json:"target,omitempty"`
	Outcome string `json:"outcome"`
	Level   string `json:"level"`
	Detail  string `json:"detail,omitempty"`
}

func (s *Server) writeAPIEvents(w http.ResponseWriter, r *http.Request, level string) {
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT seq, ts, actor, ip, action, target, outcome, level, detail
		 FROM events WHERE level = ? ORDER BY seq DESC LIMIT 100`, level)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	out := []apiEvent{}
	for rows.Next() {
		var e apiEvent
		if err := rows.Scan(&e.Seq, &e.TS, &e.Actor, &e.IP, &e.Action, &e.Target, &e.Outcome, &e.Level, &e.Detail); err != nil {
			apiErr(w, http.StatusInternalServerError, "scan failed")
			return
		}
		out = append(out, e)
	}
	apiJSON(w, struct {
		Events []apiEvent `json:"events"`
	}{Events: out})
}

// deployScope derives the per-project scope a deploy request requires. The deploy
// handler itself is handleAPIDeploy (api_deploy.go).
func deployScope(r *http.Request) string { return "deploy:write:" + r.PathValue("project") }
