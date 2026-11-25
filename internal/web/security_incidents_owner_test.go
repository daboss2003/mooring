package web

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
)

var optionValue = regexp.MustCompile(`<option value="([^"]*)"`)

// selectValues is the option values of the first <select> after marker in body.
func selectValues(t *testing.T, body, marker string) []string {
	t.Helper()
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("no %s in the page", marker)
	}
	rest := body[i:]
	start := strings.Index(rest, "<select")
	end := strings.Index(rest, "</select>")
	if start < 0 || end < start {
		t.Fatalf("no select after %s", marker)
	}
	var vals []string
	for _, m := range optionValue.FindAllStringSubmatch(rest[start:end], -1) {
		vals = append(vals, html.UnescapeString(m[1]))
	}
	return vals
}

// Only owners can open the incident pages, so only owners are offered as assignees (the auth owner
// first, then the users: owners by name) and the POST refuses anyone else; an assignee who is not
// an owner (a deployer, a viewer, a removed user, an owner demoted by a reload) is marked.
func TestIncidentAssignOwnersOnly(t *testing.T) {
	now := time.Now().UTC()
	f := newIncFake(now)
	e := incEnv(t, f)
	sess, csrf := e.detLogin(t, "operator")
	owners := []string{"", "operator", "ann", "zed"}

	_, body := e.get(t, "/security/incidents/12", sess)
	if got := selectValues(t, body, `action="/security/incidents/12/assign"`); !slices.Equal(got, owners) {
		t.Errorf("assign options = %q, want %q", got, owners)
	}
	_, body = e.get(t, "/security/incidents", sess)
	if got := selectValues(t, body, `<label for="inc-assignee">`); !slices.Equal(got, owners) {
		t.Errorf("filter options = %q, want %q", got, owners)
	}
	// incident 9 is assigned to the deployer dep: marked in the list and on its page, not offered.
	if !strings.Contains(body, "dep (no longer an owner)") {
		t.Error("the list does not mark an assignee who is not an owner")
	}
	_, body = e.get(t, "/security/incidents/9", sess)
	if !strings.Contains(body, "dep (no longer an owner)") || !strings.Contains(body, `<option value="" selected>Unassigned</option>`) {
		t.Error("incident 9: want dep marked and the select at Unassigned")
	}
	if got := selectValues(t, body, `action="/security/incidents/9/assign"`); !slices.Equal(got, owners) {
		t.Errorf("incident 9 assign options = %q, want %q", got, owners)
	}

	// The POST takes owners only.
	n := len(f.changeList())
	for _, name := range []string{"dep", "vie", "bob"} {
		resp, body := e.detPost(t, "/security/incidents/12/assign", sess, csrf, url.Values{"assignee": {name}})
		if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "Pick an owner, or Unassigned.") {
			t.Errorf("assign %s = %d, want 422 with the message", name, resp.StatusCode)
		}
	}
	if len(f.changeList()) != n {
		t.Fatal("a non-owner assignee reached the service")
	}
	for _, name := range []string{"zed", "ann", "operator"} {
		if resp, _ := e.detPost(t, "/security/incidents/12/assign", sess, csrf, url.Values{"assignee": {name}}); resp.StatusCode != http.StatusSeeOther {
			t.Errorf("assign %s = %d, want 303", name, resp.StatusCode)
		}
		if got := f.lastChange(t); got.Method != "Assign" || got.Assignee != name {
			t.Errorf("assign %s: call %+v", name, got)
		}
	}

	// A reload demotes zed: no longer offered, refused, and marked where assigned.
	for i, u := range e.srv.cfg.ExtraUsers {
		if u.Username == "zed" {
			e.srv.cfg.ExtraUsers[i].Role = config.RoleDeployer
		}
	}
	sec, err := buildSecState(e.srv.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.srv.sec.Store(sec)
	f.set(func(f *incFake) { f.incs[0].Assignee = "zed" })
	_, body = e.get(t, "/security/incidents/12", sess)
	if got, want := selectValues(t, body, `action="/security/incidents/12/assign"`), []string{"", "operator", "ann"}; !slices.Equal(got, want) {
		t.Errorf("after the demotion: options %q, want %q", got, want)
	}
	if !strings.Contains(body, "zed (no longer an owner)") {
		t.Error("a demoted assignee is not marked")
	}
	n = len(f.changeList())
	if resp, _ := e.detPost(t, "/security/incidents/12/assign", sess, csrf, url.Values{"assignee": {"zed"}}); resp.StatusCode != http.StatusUnprocessableEntity || len(f.changeList()) != n {
		t.Errorf("assign a demoted owner = %d, want 422 and no call", resp.StatusCode)
	}
	for _, r := range secAuditRows(t, e, "security_incident_assign") {
		noLeak(t, r, "dep", "vie", "bob", "zed", "ann")
	}
}

// section is the panel of body that starts with heading.
func section(t *testing.T, body, heading string) string {
	t.Helper()
	i := strings.Index(body, heading)
	if i < 0 {
		t.Fatalf("no %s in the page", heading)
	}
	j := strings.Index(body[i:], "</section>")
	if j < 0 {
		t.Fatalf("%s: no end of the section", heading)
	}
	return body[i : i+j]
}

// muteFormFields is each mute Remove form of body: its hidden fields, without the CSRF token.
var (
	muteFormRe   = regexp.MustCompile(`(?s)<form method="post" action="/security/mutes/remove"[^>]*>(.*?)</form>`)
	hiddenInputs = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)
)

func muteFormFields(body string) []url.Values {
	var out []url.Values
	for _, m := range muteFormRe.FindAllStringSubmatch(body, -1) {
		v := url.Values{}
		for _, in := range hiddenInputs.FindAllStringSubmatch(m[1], -1) {
			if in[1] != "csrf_token" {
				v.Set(in[1], html.UnescapeString(in[2]))
			}
		}
		out = append(out, v)
	}
	return out
}

// The incident page lists the mutes the incident made that are still in force, each with Remove
// (back to the incident page), and says that Reopen removes them.
func TestIncidentPageListsMutes(t *testing.T) {
	now := time.Now().UTC()
	f := newIncFake(now)
	carol := siem.Entity{Kind: siem.EntityAccount, Key: "carol", Scope: "app:shop"}
	until1, until2 := now.Add(29*24*time.Hour), now.Add(30*24*time.Hour)
	f.set(func(f *incFake) {
		f.incs[3].Mutes = []siem.Mute{ // incident 3, a false positive
			{RuleID: "edge.scan", Entity: addrOther, Until: until1, By: "ann", IncidentID: 3, Created: now.Add(-24 * time.Hour)},
			{RuleID: "auth.new_country", Entity: carol, Until: until2, By: "operator", IncidentID: 3, Created: now},
		}
	})
	e := incEnv(t, f)
	sess, csrf := e.detLogin(t, "operator")
	resp, body := e.get(t, "/security/incidents/3", sess)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET = %d", resp.StatusCode)
	}
	if !strings.Contains(body, "Reopening the incident removes its mutes.") || !strings.Contains(body, `name="state" value="open"`) {
		t.Error("the page does not say that Reopen removes the mutes")
	}
	panel := section(t, body, "<h2>Mutes in force</h2>")
	for _, want := range []string{
		`href="/security/detections?rule=edge.scan"`, `href="/security/detections?rule=auth.new_country"`,
		entityHref(addrOther), entityHref(carol), "shop user",
		until1.Format("2006-01-02 15:04"), until2.Format("2006-01-02 15:04"), "<td>ann</td>", "<td>operator</td>",
	} {
		if !strings.Contains(panel, want) {
			t.Errorf("mutes panel missing %q", want)
		}
	}
	forms := muteFormFields(body)
	want := []url.Values{
		{"rule": {"edge.scan"}, "kind": {"address"}, "key": {"198.51.100.7"}, "scope": {""}, "incident": {"3"}},
		{"rule": {"auth.new_country"}, "kind": {"account"}, "key": {"carol"}, "scope": {"app:shop"}, "incident": {"3"}},
	}
	if len(forms) != len(want) {
		t.Fatalf("remove forms = %v, want %v", forms, want)
	}
	for i := range want {
		if forms[i].Encode() != want[i].Encode() {
			t.Errorf("remove form %d = %v, want %v", i, forms[i], want[i])
		}
	}
	// No mutes: no panel, no Reopen sentence (incident 4 is resolved: Reopen is offered).
	for _, id := range []string{"12", "4"} {
		_, body := e.get(t, "/security/incidents/"+id, sess)
		if strings.Contains(body, `action="/security/mutes/remove"`) || strings.Contains(body, "Reopening the incident removes its mutes.") {
			t.Errorf("incident %s (no mutes) shows a mute", id)
		}
	}

	// Remove from the incident page: the mute's rule and entity, then back to the incident.
	form := forms[1]
	resp, _ = e.detPost(t, "/security/mutes/remove", sess, csrf, form)
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/security/incidents/3?done=unmuted" {
		t.Errorf("remove = %d → %q", resp.StatusCode, loc)
	}
	if got, want := f.lastChange(t), (incChange{Method: "RemoveMute", RuleID: "auth.new_country", Entity: carol, Actor: "operator"}); got != want {
		t.Errorf("call %+v, want %+v", got, want)
	}
	if _, body := e.get(t, "/security/incidents/3?done=unmuted", sess); !strings.Contains(body, `<div class="notice" role="status">Mute removed.</div>`) {
		t.Error("the incident page does not confirm the removal")
	}
	// A refused removal is shown on the incident page.
	f.set(func(f *incFake) { f.writeErr = fmt.Errorf("%w: no such mute", siem.ErrInvalidInput) })
	resp, body = e.detPost(t, "/security/mutes/remove", sess, csrf, forms[0])
	if msg := detFormError.FindStringSubmatch(body); resp.StatusCode != http.StatusUnprocessableEntity || msg == nil ||
		msg[1] != "The mute was not removed: no such mute" || !strings.Contains(body, `<h1 class="sec-title">False alarm</h1>`) {
		t.Errorf("refused removal = %d, message %q", resp.StatusCode, msg)
	}
	f.set(func(f *incFake) { f.writeErr = nil })
	n := len(f.changeList())
	for _, bad := range []string{"abc", "0", "-3", "3x"} {
		form := url.Values{"rule": {"edge.scan"}, "kind": {"address"}, "key": {"198.51.100.7"}, "incident": {bad}}
		if resp, _ := e.detPost(t, "/security/mutes/remove", sess, csrf, form); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("incident=%q = %d, want 400", bad, resp.StatusCode)
		}
	}
	if len(f.changeList()) != n {
		t.Error("a removal with a bad incident reached the service")
	}
	for _, r := range secAuditRows(t, e, "security_mute_remove") {
		noLeak(t, r, "198.51.100.7", "carol")
	}
}

// A username longer than 64 bytes (up to siem.MaxShort, the engine's bound) works on the incident
// pages: offered and accepted as an assignee, kept as a filter, passed whole as the actor.
func TestIncidentLongUsernames(t *testing.T) {
	now := time.Now().UTC()
	long := strings.Repeat("o", 100)
	f := newIncFake(now)
	e := incEnv(t, f, config.UserConfig{Username: long, Role: config.RoleOwner})
	sess, csrf := e.detLogin(t, long)
	_, body := e.get(t, "/security/incidents/12", sess)
	if !slices.Contains(selectValues(t, body, `action="/security/incidents/12/assign"`), long) {
		t.Fatal("an owner with a long name is not offered")
	}
	if resp, _ := e.detPost(t, "/security/incidents/12/assign", sess, csrf, url.Values{"assignee": {long}}); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("assign = %d, want 303", resp.StatusCode)
	}
	if got, want := f.lastChange(t), (incChange{Method: "Assign", ID: 12, Assignee: long, Actor: long}); got != want {
		t.Errorf("call %+v, want %+v", got, want)
	}
	if resp, _ := e.detPost(t, "/security/incidents/12/note", sess, csrf, url.Values{"note": {"n"}}); resp.StatusCode != http.StatusSeeOther || f.lastChange(t).Actor != long {
		t.Errorf("note = %d, actor %q", resp.StatusCode, f.lastChange(t).Actor)
	}
	if resp, _ := e.detPost(t, "/security/mutes/remove", sess, csrf, url.Values{"rule": {"edge.scan"}, "kind": {"address"}, "key": {"198.51.100.7"}}); resp.StatusCode != http.StatusSeeOther || f.lastChange(t).Actor != long {
		t.Errorf("mute remove = %d, actor %q", resp.StatusCode, f.lastChange(t).Actor)
	}
	for _, name := range []string{long, strings.Repeat("m", siem.MaxShort)} {
		e.get(t, "/security/incidents?assignee="+name, sess)
		if fl := f.lastFilter(t); fl.Assignee != name {
			t.Errorf("a %d-byte assignee filter was dropped", len(name))
		}
	}
}

// An account's Security logs link searches its own system only: the same name is a different
// account on the server, in Mooring and in each app.
func TestEntitySearchScopedBySource(t *testing.T) {
	realQueryParser(t)
	for _, c := range []struct {
		en   siem.Entity
		want string
	}{
		{siem.Entity{Kind: siem.EntityAccount, Key: "alice", Scope: "mooring"}, "actor:alice src:mooring"},
		{siem.Entity{Kind: siem.EntityAccount, Key: "root", Scope: "host"}, "actor:root src:host"},
		{siem.Entity{Kind: siem.EntityAccount, Key: "alice", Scope: "edge"}, "actor:alice src:edge"},
		{siem.Entity{Kind: siem.EntityAccount, Key: "alice", Scope: "app"}, "actor:alice src:app"},
		{siem.Entity{Kind: siem.EntityAccount, Key: "alice", Scope: "app:shop"}, "actor:alice src:app app:shop"},
		{siem.Entity{Kind: siem.EntityAccount, Key: `al "x" ice`, Scope: "app:my-app-2"}, `actor:"al \"x\" ice" src:app app:my-app-2`},
		{siem.Entity{Kind: siem.EntityAccount, Key: "alice"}, "actor:alice"},
		{addrScan, "ip:203.0.113.9"},
	} {
		term, link := entitySearch(c.en)
		if term != c.want {
			t.Errorf("%+v: term %q, want %q", c.en, term, c.want)
		}
		u, err := url.Parse(link)
		if err != nil || u.Path != "/security" || u.Query().Get("q") != c.want || u.Query().Get("range") != entitySearchRange {
			t.Errorf("%+v: link %q", c.en, link)
		}
	}
	// The search matches the app account only.
	term, _ := entitySearch(siem.Entity{Kind: siem.EntityAccount, Key: "alice", Scope: "app:shop"})
	q, err := query.Parse(term)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		ev   siem.Event
		want bool
	}{
		{siem.Event{Src: siem.SrcApp, App: "shop", Actor: "alice"}, true},
		{siem.Event{Src: siem.SrcApp, App: "blog", Actor: "alice"}, false},
		{siem.Event{Src: siem.SrcHost, Actor: "alice"}, false},
		{siem.Event{Src: siem.SrcMooring, Actor: "alice"}, false},
	} {
		if got := q.Match(&c.ev); got != c.want {
			t.Errorf("%q on %+v = %v, want %v", term, c.ev, got, c.want)
		}
	}
	// The entity page links it.
	f := newIncFake(time.Now().UTC())
	e := incEnv(t, f)
	sess := e.loginAs(t, "operator")
	_, body := e.get(t, "/security/entities?kind=account&key=alice&scope=app:shop", sess)
	links := detSearchLink.FindAllStringSubmatch(body, -1)
	if len(links) != 1 {
		t.Fatalf("search links = %d, want 1", len(links))
	}
	if u, _ := url.Parse(html.UnescapeString(links[0][1])); u.Query().Get("q") != "actor:alice src:app app:shop" {
		t.Errorf("entity page search link %q", links[0][1])
	}
	if !strings.Contains(body, "<code>actor:alice src:app app:shop</code>") {
		t.Error("the entity page does not show the search")
	}
}
