package web

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
)

// The entity page (owner only): one account's or address's risk score, its incidents and its
// false-positive mutes, from Server.incidentSvc.

// entitySearchRange is the time range of an entity's Security logs link (the longest preset).
const entitySearchRange = "14d"

// entityRef is an account or address as the pages show and link it.
type entityRef struct {
	Kind, Key, Scope string
	Label            string // "IP", "Mooring user", "Server user", "<app> user", "Account"
	URL              string
}

func entityLabel(e siem.Entity) string {
	switch {
	case e.Kind == siem.EntityAddress:
		return "IP"
	case e.Kind != siem.EntityAccount:
		return e.Kind
	case e.Scope == "mooring":
		return "Mooring user"
	case e.Scope == "host":
		return "Server user"
	case strings.HasPrefix(e.Scope, "app:"):
		return e.Scope[len("app:"):] + " user"
	}
	return "Account"
}

func entityURL(e siem.Entity, extra url.Values) string {
	v := url.Values{"kind": {e.Kind}, "key": {e.Key}}
	if e.Scope != "" {
		v.Set("scope", e.Scope)
	}
	for k, x := range extra {
		v[k] = x
	}
	return withQuery("/security/entities", v)
}

func entityRefOf(e siem.Entity) entityRef {
	return entityRef{Kind: e.Kind, Key: e.Key, Scope: e.Scope, Label: entityLabel(e), URL: entityURL(e, nil)}
}

// entityScopes are the account scopes the detection engine gives entities (the event's source;
// "app" for an app event whose app is unknown), besides "app:<slug>" (entityAppScope).
var entityScopes = map[string]bool{"": true, "mooring": true, "host": true, "edge": true, "app": true}

// entityAppScope is an app account's scope: "app:" and the app's slug.
var entityAppScope = regexp.MustCompile(`^app:[a-z0-9][a-z0-9-]{0,62}$`)

// parseEntity checks an entity from a link or a form: an address is an IP address or prefix (an
// IPv6 /64) with no scope; an account's scope is one of entityScopes or "app:<slug>".
func parseEntity(kind, key, scope string) (siem.Entity, bool) {
	if !validText(key, siem.MaxShort) {
		return siem.Entity{}, false
	}
	switch kind {
	case siem.EntityAddress:
		if scope != "" {
			return siem.Entity{}, false
		}
		if _, err := netip.ParseAddr(key); err != nil {
			if _, err := netip.ParsePrefix(key); err != nil {
				return siem.Entity{}, false
			}
		}
	case siem.EntityAccount:
		if !entityScopes[scope] && !entityAppScope.MatchString(scope) {
			return siem.Entity{}, false
		}
	default:
		return siem.Entity{}, false
	}
	return siem.Entity{Kind: kind, Key: key, Scope: scope}, true
}

// entitySearch is the Security logs search for an entity's events ("" when its key can't be
// searched as itself): ip:<key> for an address (a prefix searches the prefix); for an account,
// actor:<key> and its scope's source (src:<scope>, and app:<slug> for "app:<slug>"), since the same
// name is a different account on the server, in Mooring and in each app.
func entitySearch(e siem.Entity) (term, link string) {
	type pair struct{ field, value string }
	want := []pair{{"actor", e.Key}}
	switch {
	case e.Kind == siem.EntityAddress:
		want[0].field = "ip"
	case e.Scope == "mooring", e.Scope == "host", e.Scope == "edge", e.Scope == "app":
		want = append(want, pair{"src", e.Scope})
	case entityAppScope.MatchString(e.Scope):
		want = append(want, pair{"src", siem.SrcApp}, pair{"app", e.Scope[len("app:"):]})
	}
	if !searchableKey(want[0].field, e.Key) {
		return "", ""
	}
	terms := make([]string, len(want))
	for i, p := range want {
		terms[i] = searchTerm(p.field, p.value)
	}
	term = strings.Join(terms, " ")
	// Each term must parse back onto its own field and value, so no key can widen the search.
	q, err := query.Parse(term)
	if err != nil || len(q.Text) > 0 || len(q.Terms) != len(want) {
		return "", ""
	}
	for i, t := range q.Terms {
		if t.Field != want[i].field || t.Value != want[i].value || t.Op != query.OpEq || t.Neg {
			return "", ""
		}
	}
	return term, "/security?" + securityParams(term, entitySearchRange, time.Time{}, time.Time{}).Encode()
}

// entityView backs security_entity.html.
type entityView struct {
	entityRef
	Noun                string // "address" or "account"
	Score, ScoreClass   string
	Pct                 float64
	Updated, UpdatedAgo string
	Open                string
	Rows                []incRow
	Mutes               []muteRow
	SearchTerm          string
	SearchURL           string
	Notice, Err         string
}

// muteRow is one mute as the entity and incident pages show it.
type muteRow struct {
	RuleID, RuleURL         string
	Entity                  entityRef
	Until, UntilISO, Remain string
	Ended                   bool
	By                      string
	IncidentURL             string
	IncidentID              int64
}

func muteRowOf(m siem.Mute, now time.Time) muteRow {
	row := muteRow{
		RuleID: m.RuleID, RuleURL: withQuery("/security/detections", url.Values{"rule": {m.RuleID}}),
		Entity: entityRefOf(m.Entity), By: m.By, IncidentID: m.IncidentID,
	}
	if !m.Until.IsZero() {
		row.Until, row.UntilISO, row.Remain = m.Until.UTC().Format("2006-01-02 15:04"), m.Until.UTC().Format(time.RFC3339), secAgo(now, m.Until)
		row.Ended = !m.Until.After(now)
	}
	if m.IncidentID > 0 {
		row.IncidentURL = "/security/incidents/" + strconv.FormatInt(m.IncidentID, 10)
	}
	return row
}

// entityDoneText are the fixed notices of the entity page's ?done=.
var entityDoneText = map[string]string{"unmuted": "Mute removed."}

const entityTmpl = "security_entity.html"

// handleSecEntity renders an account's or address's page
// (GET /security/entities?kind=account|address&key=…&scope=…).
func (s *Server) handleSecEntity(w http.ResponseWriter, r *http.Request) {
	if s.incidentSvc == nil {
		s.renderInc(w, r, http.StatusOK, entityTmpl, "Account or address", &incPage{Off: true})
		return
	}
	q := r.URL.Query()
	en, ok := parseEntity(q.Get("kind"), q.Get("key"), q.Get("scope"))
	if !ok {
		s.renderInc(w, r, http.StatusBadRequest, entityTmpl, "Account or address", &incPage{Missing: "That is not a valid account or address."})
		return
	}
	s.showEntity(w, r, http.StatusOK, en, entityDoneText[q.Get("done")], "")
}

// showEntity renders en's page with a notice, or with a refused change's message and status.
func (s *Server) showEntity(w http.ResponseWriter, r *http.Request, status int, en siem.Entity, notice, errMsg string) {
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	rs, incs, mutes, err := s.incidentSvc.Entity(ctx, en)
	if err != nil {
		st, msg, _ := s.serviceError(err, "That is not a valid account or address", "security incidents: entity", "kind", en.Kind)
		if st != http.StatusUnprocessableEntity {
			msg = "The account or address could not be read. Mooring's log has the details."
		} else {
			st = http.StatusBadRequest
		}
		s.renderInc(w, r, st, entityTmpl, "Account or address", &incPage{Missing: msg})
		return
	}
	now := time.Now().UTC()
	owners := s.incidentOwners()
	v := &entityView{
		entityRef: entityRefOf(en), Noun: "account", Score: riskScoreText(rs.Score), Pct: riskPct(rs.Score),
		Open: groupDigits(rs.OpenIncidents), Notice: notice, Err: errMsg,
	}
	if en.Kind == siem.EntityAddress {
		v.Noun = "address"
	}
	switch {
	case v.Pct >= 90:
		v.ScoreClass = "is-down"
	case v.Pct >= 75:
		v.ScoreClass = "is-warn"
	}
	if !rs.Updated.IsZero() {
		v.Updated, v.UpdatedAgo = rs.Updated.UTC().Format("2006-01-02 15:04"), secAgo(now, rs.Updated)
	}
	v.SearchTerm, v.SearchURL = entitySearch(en)
	for i := range incs {
		v.Rows = append(v.Rows, incRowOf(&incs[i], owners, now))
	}
	for _, m := range mutes {
		v.Mutes = append(v.Mutes, muteRowOf(m, now))
	}
	s.renderInc(w, r, status, entityTmpl, en.Key, &incPage{Ent: v})
}

// handleSecMuteRemove ends a false-positive mute of a rule for an entity (POST /security/mutes/remove).
// From an incident's page (incident=<id>) it goes back there, else to the entity's page. The audit
// row names the rule, never the entity's key.
func (s *Server) handleSecMuteRemove(w http.ResponseWriter, r *http.Request) {
	const action = "security_mute_remove"
	if s.incidentSvc == nil {
		s.incOffPost(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	rule := r.PostFormValue("rule")
	en, okEntity := parseEntity(r.PostFormValue("kind"), r.PostFormValue("key"), r.PostFormValue("scope"))
	okRule := validText(rule, siem.MaxShort)
	var incID int64
	okIncident := true
	if raw := r.PostFormValue("incident"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		incID, okIncident = id, err == nil && id > 0
	}
	target := "mute"
	if okRule {
		target = "mute:" + rule
	}
	if !okRule || !okEntity || !okIncident {
		s.detectAudit(r, action, target, audit.Error, "result=rejected")
		s.renderInc(w, r, http.StatusBadRequest, entityTmpl, "Account or address", &incPage{Missing: "That is not a valid mute."})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	detail := "kind=" + en.Kind
	if err := s.incidentSvc.RemoveMute(ctx, rule, en, sessionUser(r)); err != nil {
		status, msg, result := s.serviceError(err, "The mute was not removed", "security incidents: mute remove", "rule", rule)
		s.detectAudit(r, action, target, audit.Error, detail+" result="+result)
		if incID > 0 {
			s.showIncident(w, r, status, incID, "", msg, nil)
		} else {
			s.showEntity(w, r, status, en, "", msg)
		}
		return
	}
	s.detectAudit(r, action, target, audit.OK, detail)
	back := entityURL(en, url.Values{"done": {"unmuted"}})
	if incID > 0 {
		back = withQuery("/security/incidents/"+strconv.FormatInt(incID, 10), url.Values{"done": {"unmuted"}})
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}
