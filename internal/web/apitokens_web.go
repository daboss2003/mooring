package web

import (
	"net/http"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
)

// The API tokens screen is read-only + revoke: it lists scoped machine tokens (id,
// scopes, allowed networks, expiry, state) and lets the operator revoke one. Minting
// stays CLI-only by design (`mooring token mint`) — the web can never create a token,
// so a dashboard compromise can't issue API credentials.

type apiTokenRow struct {
	ID      string
	Scopes  []string
	CIDRs   []string
	Expires int64  // unix seconds; the "ts" template renders it localised
	State   string // active | expired | revoked
}

func (s *Server) handleAPITokens(w http.ResponseWriter, r *http.Request) {
	if s.apiTokens == nil {
		notFound(w)
		return
	}
	recs, err := s.apiTokens.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	now := time.Now().Unix()
	rows := make([]apiTokenRow, 0, len(recs))
	for _, rc := range recs {
		state := "active"
		switch {
		case rc.Revoked:
			state = "revoked"
		case rc.ExpiresAt <= now:
			state = "expired"
		}
		cidrs := make([]string, 0, len(rc.CIDRs))
		for _, p := range rc.CIDRs {
			cidrs = append(cidrs, p.String())
		}
		rows = append(rows, apiTokenRow{
			ID: rc.ID, Scopes: rc.Scopes, CIDRs: cidrs,
			Expires: rc.ExpiresAt,
			State:   state,
		})
	}
	s.render(w, r, "apitokens.html", tmplData{
		Title:        "API tokens — Mooring",
		CSRFToken:    CSRFToken(r.Context()),
		Username:     sessionUser(r),
		APITokenRows: rows,
	})
}

func (s *Server) handleAPITokenRevoke(w http.ResponseWriter, r *http.Request) {
	if s.apiTokens == nil {
		notFound(w)
		return
	}
	id := r.PostFormValue("id")
	err := s.apiTokens.Revoke(r.Context(), id)
	outcome := audit.OK
	if err != nil {
		outcome = audit.Error
	}
	_ = s.audit.Log(r.Context(), audit.Event{
		Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "api_token_revoke",
		Target: id, Outcome: outcome, Level: audit.Security,
	})
	http.Redirect(w, r, "/settings/api-tokens", http.StatusSeeOther)
}
