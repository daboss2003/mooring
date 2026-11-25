package detect

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
)

// incHarness is a harness with incident grouping on, as in production.
func incHarness(t *testing.T, withMain bool) *harness {
	t.Helper()
	h := newHarness(t, withMain)
	h.incidents = true
	h.e.lim.incidents = true
	return h
}

// incRule is a rule firing at every matching event (count 1 in 1h).
func incRule(id string, sev siem.Severity, groupBy, query string) siem.Rule {
	return siem.Rule{ID: id, Name: id, Type: siem.RuleThreshold, Severity: sev, Query: query, GroupBy: groupBy,
		Count: 1, Window: time.Hour}
}

// incEv is an event of kind at t0+at.
func incEv(at time.Duration, src, kind, ip, actor string, f map[string]any) siem.Event {
	return ev(at, src, kind, "", ip, actor, f)
}

const (
	addrX = "203.0.113.7"
	addrY = "198.51.100.9"
	addrZ = "192.0.2.44"
)

func (h *harness) incList(t *testing.T) []siem.Incident {
	t.Helper()
	h.e.flush(true)
	incs, err := h.e.Incidents(context.Background(), siem.IncidentFilter{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	return incs
}

func (h *harness) incGet(t *testing.T, id int64) siem.Incident {
	t.Helper()
	h.e.flush(true)
	inc, ok, err := h.e.Incident(context.Background(), id)
	if err != nil || !ok {
		t.Fatalf("incident %d: %v %v", id, ok, err)
	}
	return inc
}

// only1 returns the single incident.
func (h *harness) only1(t *testing.T) siem.Incident {
	t.Helper()
	incs := h.incList(t)
	if len(incs) != 1 {
		t.Fatalf("want one incident, got %d: %+v", len(incs), incs)
	}
	return incs[0]
}

// detIncident returns the incident_id stored on the newest detection of rule for key.
func (h *harness) detIncident(t *testing.T, rule, key string) int64 {
	t.Helper()
	h.e.flush(true)
	var id int64
	if err := h.e.db.w.QueryRow(`SELECT incident_id FROM detections WHERE rule_id = ? AND key = ? ORDER BY id DESC LIMIT 1`,
		rule, key).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func addr(k string) siem.Entity { return siem.Entity{Kind: siem.EntityAddress, Key: k} }
func acct(scope, k string) siem.Entity {
	return siem.Entity{Kind: siem.EntityAccount, Key: k, Scope: scope}
}

func hasEntity(es []siem.Entity, x siem.Entity) bool {
	for _, e := range es {
		if e == x {
			return true
		}
	}
	return false
}

// flushAlerts writes what is pending (incident alerts are raised after the write) and drains the
// alert queue as a worker whose sends succeed.
func (h *harness) flushAlerts() []alert.Outbox {
	h.e.flush(true)
	return h.alerts()
}

func TestIncidentGroupsDetectionsOfAnAddress(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.a", siem.SevMedium, "ip", "kind:t.a"), incRule("custom.b", siem.SevMedium, "ip", "kind:t.b"))
	h.feed(incEv(0, siem.SrcMooring, "t.a", addrX, "", nil))
	h.feed(incEv(2*time.Hour, siem.SrcMooring, "t.b", addrX, "", nil))
	h.feed(incEv(3*time.Hour, siem.SrcMooring, "t.a", addrY, "", nil))
	incs := h.incList(t)
	if len(incs) != 2 {
		t.Fatalf("two addresses: want 2 incidents, got %+v", incs)
	}
	x := incs[1] // older
	if x.Detections != 2 || strings.Join(x.Rules, ",") != "custom.a,custom.b" || len(x.Entities) != 1 || x.Entities[0] != addr(addrX) {
		t.Fatalf("incident of %s: %+v", addrX, x)
	}
	if x.State != siem.IncidentOpen || x.Severity != siem.SevMedium || !x.First.Equal(t0) || !x.Last.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("incident of %s: %+v", addrX, x)
	}
	if a, b := h.detIncident(t, "custom.a", addrX), h.detIncident(t, "custom.b", addrX); a != x.ID || b != x.ID {
		t.Fatalf("detections linked to %d and %d, want %d", a, b, x.ID)
	}
	if y := incs[0]; y.Detections != 1 || y.Entities[0] != addr(addrY) || h.detIncident(t, "custom.a", addrY) != y.ID {
		t.Fatalf("incident of %s: %+v", addrY, y)
	}
}

func TestIncidentGroupsDetectionsOfAnAccount(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.a", siem.SevLow, "actor", "kind:t.a"), incRule("custom.b", siem.SevLow, "actor", "kind:t.b"))
	h.feed(incEv(0, siem.SrcMooring, "t.a", "", "alice", nil))
	h.feed(incEv(5*time.Hour, siem.SrcMooring, "t.b", "", "alice", nil))
	inc := h.only1(t)
	if inc.Detections != 2 || len(inc.Entities) != 1 || inc.Entities[0] != acct("mooring", "alice") {
		t.Fatalf("account incident: %+v", inc)
	}
}

// An account is kept per scope: a server user alice is not Mooring's alice nor an app's.
func TestIncidentScopesNotMixed(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.a", siem.SevLow, "actor", "kind:t.a"))
	h.feed(incEv(0, siem.SrcHost, "t.a", "", "alice", nil))
	h.feed(incEv(time.Minute, siem.SrcMooring, "t.a", "", "bob", nil))
	h.feed(incEv(2*time.Hour, siem.SrcMooring, "t.a", "", "alice", nil))
	e := incEv(4*time.Hour, siem.SrcApp, "t.a", "", "alice", nil)
	e.App = "shop"
	h.feed(e)
	incs := h.incList(t)
	if len(incs) != 4 {
		t.Fatalf("want 4 incidents (alice in 3 scopes, bob), got %+v", incs)
	}
	var scopes []string
	for _, inc := range incs {
		if inc.Entities[0].Key == "alice" {
			scopes = append(scopes, inc.Entities[0].Scope)
		}
	}
	if strings.Join(scopes, ",") != "app:shop,mooring,host" {
		t.Fatalf("scopes %v", scopes)
	}
}

// A rule without src: coalesces one key from two sources into one detection: its account stays in
// the scope of the detection's first event.
func TestIncidentDetectionScopeIsTheFirstEvents(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.a", siem.SevLow, "actor", "kind:t.a"))
	h.feed(incEv(0, siem.SrcMooring, "t.a", "", "alice", nil))
	e := incEv(time.Minute, siem.SrcApp, "t.a", "", "alice", nil)
	e.App = "shop"
	h.feed(e)
	inc := h.only1(t)
	if len(inc.Entities) != 1 || inc.Entities[0] != acct("mooring", "alice") {
		t.Fatalf("entities %+v", inc.Entities)
	}
}

// Detections join when they share an entity within 24 hours of its last detection, not later.
func TestIncidentJoinWindowBoundary(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.a", siem.SevLow, "ip", "kind:t.a"), incRule("custom.b", siem.SevLow, "ip", "kind:t.b"),
		incRule("custom.c", siem.SevLow, "ip", "kind:t.c"))
	h.feed(incEv(0, siem.SrcEdge, "t.a", addrX, "", nil))
	h.feed(incEv(24*time.Hour, siem.SrcEdge, "t.b", addrX, "", nil))
	if inc := h.only1(t); inc.Detections != 2 {
		t.Fatalf("exactly 24h after: want joined, got %+v", inc)
	}
	h.feed(incEv(48*time.Hour+time.Second, siem.SrcEdge, "t.c", addrX, "", nil))
	if incs := h.incList(t); len(incs) != 2 || incs[0].Detections != 1 {
		t.Fatalf("24h and 1s after: want a new incident, got %+v", incs)
	}
}

// A detection's evidence addresses and accounts are listed on its incident, but only its key joins
// one (owner decision): a detection keyed by an account or address another incident lists as
// evidence opens its own.
func TestIncidentMultipleEntities(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.ip", siem.SevLow, "ip", "kind:t.ip"), incRule("custom.act", siem.SevLow, "actor", "kind:t.act"),
		incRule("custom.ip2", siem.SevLow, "ip", "kind:t.ip2"))
	h.feed(incEv(0, siem.SrcMooring, "t.ip", addrX, "alice", nil))
	h.feed(incEv(time.Hour, siem.SrcMooring, "t.act", addrY, "alice", nil))
	h.feed(incEv(2*time.Hour, siem.SrcMooring, "t.ip2", addrY, "", nil))
	h.feed(incEv(3*time.Hour, siem.SrcMooring, "t.ip2", addrX, "", nil))
	incs := h.incList(t) // most recently active first
	if len(incs) != 3 {
		t.Fatalf("want 3 incidents (keys X, alice, Y), got %+v", incs)
	}
	byKey := map[siem.Entity]siem.Incident{}
	for _, inc := range incs {
		byKey[inc.Entities[0]] = inc
	}
	x, a, y := byKey[addr(addrX)], byKey[acct("mooring", "alice")], byKey[addr(addrY)]
	if x.Detections != 2 || len(x.Entities) != 2 || !hasEntity(x.Entities, acct("mooring", "alice")) {
		t.Fatalf("incident of %s (its two detections, alice as context): %+v", addrX, x)
	}
	if a.Detections != 1 || len(a.Entities) != 2 || !hasEntity(a.Entities, addr(addrY)) {
		t.Fatalf("incident of alice (%s as context): %+v", addrY, a)
	}
	if y.Detections != 1 || len(y.Entities) != 1 {
		t.Fatalf("incident of %s: %+v", addrY, y)
	}
	// An ssh.invalid_user name is no account; a loopback address is no entity.
	h2 := incHarness(t, false)
	h2.only(t, incRule("custom.ip", siem.SevLow, "ip", "kind:ssh.invalid_user"), incRule("custom.lo", siem.SevLow, "ip", "kind:t.lo"))
	h2.feed(incEv(0, siem.SrcHost, siem.KindSSHInvalidUser, addrX, "oracle", nil))
	h2.feed(incEv(0, siem.SrcHost, "t.lo", "127.0.0.1", "root", nil))
	if inc := h2.only1(t); len(inc.Entities) != 1 || inc.Entities[0] != addr(addrX) {
		t.Fatalf("invalid user name kept as an account: %+v", inc)
	}
}

// IPv6 addresses are entities as their /64.
func TestIncidentIPv6Slash64(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.a", siem.SevLow, "ip", "kind:t.a"), incRule("custom.b", siem.SevLow, "ip", "kind:t.b"))
	h.feed(incEv(0, siem.SrcMooring, "t.a", "2001:db8:1:2::10", "alice", nil))
	h.feed(incEv(time.Hour, siem.SrcMooring, "t.b", "2001:db8:1:2::99", "bob", nil))
	inc := h.only1(t)
	if inc.Entities[0] != addr("2001:db8:1:2::/64") || inc.Detections != 2 {
		t.Fatalf("one /64: %+v", inc)
	}
}

// Rollups, app /ops detections and rules whose key is no account or address open no incident and
// keep their own alerts.
func TestIncidentExclusionsKeepTheirAlerts(t *testing.T) {
	h := incHarness(t, false)
	h.e.lim.newPerHour = 1
	jail := incRule("custom.jail", siem.SevHigh, "f.jail", "kind:t.jail")
	whole := incRule("custom.whole", siem.SevHigh, "", "kind:t.whole")
	h.only(t, incRule("custom.hi", siem.SevHigh, "ip", "kind:t.hi"), jail, whole)
	h.feed(incEv(0, siem.SrcEdge, "t.hi", addrX, "", nil))
	h.feed(incEv(time.Second, siem.SrcEdge, "t.hi", addrY, "", nil)) // over the hourly cap: rollup
	h.feed(incEv(2*time.Second, siem.SrcHost, "t.jail", "", "", map[string]any{"jail": "sshd"}))
	h.feed(incEv(3*time.Second, siem.SrcHost, "t.whole", addrZ, "", nil))
	h.e.report(siem.Detection{RuleID: "ops:a/s/x", RuleName: "x", Severity: siem.SevHigh, Key: "k", App: "a",
		Service: "s", Summary: "s", First: h.clk.now(), Last: h.clk.now()})
	keys := map[string]string{}
	for _, o := range h.flushAlerts() {
		keys[o.DedupeKey] = o.Kind
	}
	incs := h.incList(t)
	if len(incs) != 1 || incs[0].Entities[0] != addr(addrX) || incs[0].Detections != 1 {
		t.Fatalf("only the address detection opens an incident: %+v", incs)
	}
	want := map[string]string{
		"siem-incident:" + itoa(incs[0].ID): IncidentAlertKind,
		"siem-rollup:custom.hi":             AlertKind,
		"siem:custom.jail:sshd":             AlertKind,
		"siem:custom.whole:":                AlertKind,
		"siem:ops:a/s/x:k":                  AlertKind,
	}
	if len(keys) != len(want) {
		t.Fatalf("alerts %v, want %v", keys, want)
	}
	for k, kind := range want {
		if keys[k] != kind {
			t.Errorf("alert %s: kind %q, want %q (all: %v)", k, keys[k], kind, keys)
		}
	}
}

// host.user_change joins through the account changed (f.user); a line naming only a group does not.
func TestIncidentHostUserChangeByUser(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, packByID["host.user_change"].Rule)
	h.feed(incEv(0, siem.SrcHost, siem.KindUserChange, "", "", map[string]any{"user": "deploy", "program": "usermod"}))
	h.feed(incEv(time.Minute, siem.SrcHost, siem.KindUserChange, "", "", map[string]any{"group": "docker", "program": "groupadd"}))
	al := h.flushAlerts()
	inc := h.only1(t)
	if inc.Entities[0] != acct("host", "deploy") {
		t.Fatalf("host.user_change entity: %+v", inc)
	}
	if len(al) != 2 || al[0].Kind != IncidentAlertKind && al[1].Kind != IncidentAlertKind {
		t.Fatalf("want the incident's alert and the group line's own: %+v", al)
	}
	for _, o := range al {
		if o.Kind == AlertKind && o.DedupeKey != "siem:host.user_change:docker" {
			t.Fatalf("own alert %+v", o)
		}
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// The rules of the known chains, as built-in IDs, matching test kinds. chainSignIn is keyed by the
// account: it joins a brute force's incident (keyed by the address) when that lists the account and
// the sign-in completes the chain there (chainIncident).
var (
	chainBF       = incRule("mooring.login_bruteforce", siem.SevHigh, "ip", "kind:t.bf")
	chainSignIn   = incRule("mooring.login_new_country", siem.SevHigh, "actor", "kind:t.signin")
	chainSignInIP = incRule("mooring.login_success_after_failures", siem.SevHigh, "ip", "kind:t.signinip")
	chainChange   = incRule("mooring.user_change", siem.SevMedium, "f.target", "kind:t.change")
	chainListed   = incRule("edge.spamhaus_ip", siem.SevLow, "ip", "kind:t.listed")
	chainTor      = incRule("mooring.login_tor", siem.SevMedium, "ip", "kind:t.tor")
	chainKeepLow  = incRule("custom.keep", siem.SevLow, "ip", "kind:t.keep")
)

func TestChainBruteForceThenSignIn(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, chainBF, chainSignIn)
	h.feed(incEv(0, siem.SrcMooring, "t.bf", addrX, "alice", nil)) // the brute force tried alice
	al := h.flushAlerts()
	if len(al) != 1 || al[0].Level != alert.LevelWarning {
		t.Fatalf("brute force alone: one warning, got %+v", al)
	}
	h.feed(incEv(time.Hour, siem.SrcMooring, "t.signin", addrX, "alice", nil))
	al = h.flushAlerts()
	inc := h.only1(t)
	if inc.Severity != siem.SevCritical || inc.Chain != "Brute force then sign-in" ||
		inc.Title != "Brute force then sign-in: "+addrX {
		t.Fatalf("chain: %+v", inc)
	}
	if len(al) != 1 || al[0].Level != alert.LevelCritical || al[0].Summary != inc.Title+" — incident #"+itoa(inc.ID) {
		t.Fatalf("rise to critical: one critical alert, got %+v", al)
	}
	tl := h.incGet(t, inc.ID).Timeline
	var kinds []string
	for _, x := range tl {
		kinds = append(kinds, x.Kind)
	}
	if strings.Join(kinds, ",") != "opened,detection,detection,escalated" || tl[3].Severity != siem.SevCritical ||
		!strings.Contains(tl[3].Text, "known chain Brute force then sign-in") {
		t.Fatalf("timeline %+v", tl)
	}

	// A sign-in keyed by the address joins the brute force's incident through its key.
	h = incHarness(t, false)
	h.only(t, chainBF, chainSignInIP)
	h.feed(incEv(0, siem.SrcMooring, "t.bf", addrX, "", nil))
	h.feed(incEv(time.Hour, siem.SrcMooring, "t.signinip", addrX, "alice", nil))
	if inc := h.only1(t); inc.Severity != siem.SevCritical || inc.Chain != "Brute force then sign-in" {
		t.Fatalf("by address: %+v", inc)
	}
}

// The sign-in must not come before the brute force, and the two steps are at most 24h apart.
func TestChainOrderAndWindow(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, chainBF, chainSignIn)
	h.feed(incEv(0, siem.SrcMooring, "t.signin", addrX, "alice", nil))
	h.feed(incEv(time.Hour, siem.SrcMooring, "t.bf", addrX, "alice", nil))
	if incs := h.incList(t); len(incs) != 2 || incs[0].Chain != "" || incs[1].Chain != "" || incs[0].Severity != siem.SevHigh {
		t.Fatalf("sign-in before the brute force is no chain (and joins nothing): %+v", incs)
	}

	h = incHarness(t, false)
	h.only(t, chainBF, chainSignIn, chainKeepLow)
	h.feed(incEv(0, siem.SrcMooring, "t.bf", addrX, "alice", nil))
	h.feed(incEv(20*time.Hour, siem.SrcMooring, "t.keep", addrX, "", nil))
	h.feed(incEv(43*time.Hour, siem.SrcMooring, "t.signin", addrX, "alice", nil))
	if incs := h.incList(t); len(incs) != 2 || incs[0].Chain != "" || incs[1].Chain != "" || incs[1].Detections != 2 {
		t.Fatalf("steps 43h apart are no chain: %+v", incs)
	}

	// A brute force that doesn't list the account: the sign-in joins nothing of the address.
	h = incHarness(t, false)
	h.only(t, chainBF, chainSignIn)
	h.feed(incEv(0, siem.SrcMooring, "t.bf", addrX, "", nil))
	h.feed(incEv(time.Hour, siem.SrcMooring, "t.signin", addrX, "alice", nil))
	if incs := h.incList(t); len(incs) != 2 || incs[0].Chain != "" || incs[1].Chain != "" {
		t.Fatalf("account not listed: %+v", incs)
	}

	h = incHarness(t, false)
	h.only(t, chainBF, chainSignIn)
	h.feed(incEv(0, siem.SrcMooring, "t.bf", addrX, "alice", nil))
	h.feed(incEv(24*time.Hour, siem.SrcMooring, "t.signin", addrX, "alice", nil))
	if inc := h.only1(t); inc.Severity != siem.SevCritical || inc.Detections != 2 {
		t.Fatalf("steps exactly 24h apart are a chain: %+v", inc)
	}
}

func TestChainAccountTakeover(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, chainSignIn, chainChange)
	h.feed(incEv(0, siem.SrcMooring, "t.signin", addrX, "alice", nil))
	h.feed(incEv(time.Hour, siem.SrcMooring, "t.change", addrZ, "admin", map[string]any{"target": "alice"}))
	inc := h.only1(t)
	if inc.Severity != siem.SevCritical || inc.Chain != "Account takeover" ||
		inc.Title != "Account takeover: account alice (mooring)" {
		t.Fatalf("takeover: %+v", inc)
	}
	// A sign-in over Tor (keyed by the address) by alice, then a change of alice: the change
	// completes the chain in the sign-in's incident, which lists alice.
	h = incHarness(t, false)
	h.only(t, chainTor, chainChange)
	h.feed(incEv(0, siem.SrcMooring, "t.tor", addrX, "alice", nil))
	h.feed(incEv(time.Hour, siem.SrcMooring, "t.change", addrZ, "admin", map[string]any{"target": "alice"}))
	if inc := h.only1(t); inc.Severity != siem.SevCritical || inc.Chain != "Account takeover" || inc.Detections != 2 {
		t.Fatalf("takeover through a listed account: %+v", inc)
	}
	// The change of another account (by the one that signed in, or on the same address) is keyed
	// by the account changed, which the sign-in's incident doesn't list: no chain.
	for _, actor := range []string{"alice", "carol"} {
		h = incHarness(t, false)
		h.only(t, chainSignIn, chainChange)
		h.feed(incEv(0, siem.SrcMooring, "t.signin", addrX, "alice", nil))
		h.feed(incEv(time.Hour, siem.SrcMooring, "t.change", addrX, actor, map[string]any{"target": "bob"}))
		if incs := h.incList(t); len(incs) != 2 || incs[0].Chain != "" || incs[1].Chain != "" || incs[1].Severity != siem.SevHigh {
			t.Fatalf("change of bob by %s: %+v", actor, incs)
		}
	}
}

func TestChainListedAddressWithAccess(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, chainListed, chainTor)
	h.feed(incEv(0, siem.SrcMooring, "t.tor", addrX, "alice", nil))
	h.feed(incEv(time.Hour, siem.SrcEdge, "t.listed", addrX, "", nil))
	inc := h.only1(t)
	if inc.Severity != siem.SevCritical || inc.Chain != "Listed address with access" {
		t.Fatalf("listed then (earlier) sign-in, either order: %+v", inc)
	}
}

// One alert per incident: later detections update it; another alert only when its severity rises.
// The detections in it have no alert of their own.
func TestIncidentAlertsOnceAndOnRise(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.m", siem.SevMedium, "ip", "kind:t.m"), incRule("custom.h1", siem.SevHigh, "ip", "kind:t.h1"),
		incRule("custom.h2", siem.SevHigh, "ip", "kind:t.h2"), incRule("custom.c1", siem.SevCritical, "ip", "kind:t.c1"),
		incRule("custom.c2", siem.SevCritical, "ip", "kind:t.c2"))
	var all []alert.Outbox
	step := func(at time.Duration, kind string, want int) {
		t.Helper()
		h.feed(incEv(at, siem.SrcEdge, kind, addrX, "", nil))
		al := h.flushAlerts()
		if len(al) != want {
			t.Fatalf("%s: %d alerts, want %d: %+v", kind, len(al), want, al)
		}
		all = append(all, al...)
	}
	step(0, "t.m", 0)
	step(time.Minute, "t.h1", 1)
	step(2*time.Minute, "t.h2", 0)
	step(3*time.Minute, "t.h1", 0) // an update
	step(4*time.Minute, "t.c1", 1)
	step(5*time.Minute, "t.c2", 0)
	inc := h.only1(t)
	key := "siem-incident:" + itoa(inc.ID)
	for i, lvl := range []string{alert.LevelWarning, alert.LevelCritical} {
		o := all[i]
		if o.Kind != IncidentAlertKind || o.Level != lvl || o.DedupeKey != key || o.Target != TargetSIEM ||
			o.Transition != "firing" || o.RuleID != 0 || !strings.HasSuffix(o.Summary, " — incident #"+itoa(inc.ID)) {
			t.Fatalf("alert %d: %+v", i, o)
		}
	}
	if !strings.HasPrefix(all[0].Summary, "custom.h1: "+addrX) || !strings.HasPrefix(all[1].Summary, "custom.c1: ") {
		t.Fatalf("titles: %q, %q", all[0].Summary, all[1].Summary)
	}
	if inc.Detections != 5 {
		t.Fatalf("incident %+v", inc)
	}
}

// Incident alerts are not counted under a rule's hourly cap, and leave no summary.
func TestIncidentAlertsOutsideTheRuleCap(t *testing.T) {
	h := incHarness(t, false)
	h.e.lim.alertsPerHour = 1
	h.only(t, incRule("custom.h", siem.SevHigh, "ip", "kind:t.h"))
	for i, ip := range []string{addrX, addrY, addrZ} {
		h.feed(incEv(time.Duration(i)*time.Second, siem.SrcEdge, "t.h", ip, "", nil))
	}
	if al := h.flushAlerts(); len(al) != 3 {
		t.Fatalf("three incidents: three alerts, got %+v", al)
	}
	h.e.sendCaps(true)
	if al := h.alerts(); len(al) != 0 {
		t.Fatalf("no summary: %+v", al)
	}
}

// A snoozed rule's detection joins its incident (and sets its severity) but alerts nothing.
func TestIncidentSnoozedRuleDoesNotAlert(t *testing.T) {
	h := incHarness(t, false)
	snoozed := incRule("custom.s", siem.SevCritical, "ip", "kind:t.s")
	snoozed.SnoozedUntil = t0.Add(48 * time.Hour)
	h.only(t, snoozed, incRule("custom.m", siem.SevMedium, "ip", "kind:t.m"), incRule("custom.h", siem.SevHigh, "ip", "kind:t.h"))
	h.feed(incEv(0, siem.SrcEdge, "t.s", addrX, "", nil))
	h.feed(incEv(time.Minute, siem.SrcEdge, "t.m", addrX, "", nil))
	if al := h.flushAlerts(); len(al) != 0 {
		t.Fatalf("snoozed critical: no alert, got %+v", al)
	}
	if inc := h.only1(t); inc.Severity != siem.SevCritical {
		t.Fatalf("severity %s", inc.Severity)
	}
	h.feed(incEv(2*time.Minute, siem.SrcEdge, "t.h", addrX, "", nil))
	if al := h.flushAlerts(); len(al) != 1 || al[0].Level != alert.LevelWarning {
		t.Fatalf("a high detection of a rule not snoozed: one warning, got %+v", al)
	}
}

// An incident's alert is recorded with it: no second one after a restart; one raised but not
// recorded before the restart is raised again, once.
func TestIncidentAlertAcrossRestart(t *testing.T) {
	h := incHarness(t, false)
	rs := []siem.Rule{incRule("custom.h1", siem.SevHigh, "ip", "kind:t.h1"), incRule("custom.h2", siem.SevHigh, "ip", "kind:t.h2")}
	h.only(t, rs...)
	h.feed(incEv(0, siem.SrcEdge, "t.h1", addrX, "", nil))
	if al := h.flushAlerts(); len(al) != 1 {
		t.Fatalf("first: %+v", al)
	}
	h.reopen(t)
	h.e.lim.incidents = true
	h.only(t, rs...)
	h.feed(incEv(time.Minute, siem.SrcEdge, "t.h2", addrX, "", nil))
	if al := h.flushAlerts(); len(al) != 0 {
		t.Fatalf("after a restart: no second alert, got %+v", al)
	}
	if inc := h.only1(t); inc.Detections != 2 {
		t.Fatalf("joined the incident read back: %+v", inc)
	}

	// Raised, never reported back (killed): owed after the restart.
	h.feed(incEv(2*time.Minute, siem.SrcEdge, "t.h1", addrY, "", nil))
	h.e.flush(true)
	if n := len(h.e.alerts); n != 1 {
		t.Fatalf("queued: %d", n)
	}
	h.reopen(t)
	h.e.lim.incidents = true
	al := h.flushAlerts()
	if len(al) != 1 || al[0].DedupeKey != "siem-incident:2" {
		t.Fatalf("owed alert after the restart: %+v", al)
	}
	h.e.flush(true)
	h.reopen(t)
	if al := h.flushAlerts(); len(al) != 0 {
		t.Fatalf("recorded: no third alert, got %+v", al)
	}
}

// A failed incident alert is raised again after incAlertRetry.
func TestIncidentAlertFailureRetried(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.h", siem.SevHigh, "ip", "kind:t.h"))
	h.feed(incEv(0, siem.SrcEdge, "t.h", addrX, "", nil))
	h.e.flush(true)
	if al := h.failAlerts(); len(al) != 1 {
		t.Fatalf("first try: %+v", al)
	}
	h.e.flush(true)
	if n := len(h.e.alerts); n != 0 {
		t.Fatalf("raised again at once: %d", n)
	}
	h.clk.advance(incAlertRetry + time.Second)
	if al := h.flushAlerts(); len(al) != 1 || al[0].DedupeKey != "siem-incident:1" {
		t.Fatalf("retried: %+v", al)
	}
	h.clk.advance(2 * incAlertRetry)
	if al := h.flushAlerts(); len(al) != 0 {
		t.Fatalf("sent: no more, got %+v", al)
	}
}

// Each detection adds to its entities' risk by severity (5, 15, 35, 60), capped at 100, halving
// every 72 hours.
func TestRiskScore(t *testing.T) {
	h := incHarness(t, false)
	var rs []siem.Rule
	for _, s := range []siem.Severity{siem.SevLow, siem.SevMedium, siem.SevHigh, siem.SevCritical} {
		rs = append(rs, incRule("custom."+string(s), s, "ip", "kind:t."+string(s)))
	}
	h.only(t, rs...)
	ctx := context.Background()
	score := func(x siem.Entity) siem.RiskScore {
		t.Helper()
		h.e.flush(true)
		r, _, _, err := h.e.Entity(ctx, x)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for i, c := range []struct {
		kind string
		want float64
	}{{"t.low", 5}, {"t.medium", 20}, {"t.high", 55}, {"t.critical", 100}} {
		h.feed(incEv(time.Duration(i)*time.Minute, siem.SrcEdge, c.kind, addrX, "", nil))
		if r := score(addr(addrX)); r.Score != c.want || r.OpenIncidents != 1 {
			t.Fatalf("after %s: %+v, want %v", c.kind, r, c.want)
		}
	}
	h.feed(incEv(4*time.Minute, siem.SrcEdge, "t.medium", addrY, "", nil))
	h.clk.advance(riskHalfLife)
	if r := score(addr(addrX)); r.Score < 49.9 || r.Score > 50.1 {
		t.Fatalf("after 72h: %+v", r)
	}
	top, err := h.e.Risky(ctx, 10)
	if err != nil || len(top) != 2 || top[0].Entity != addr(addrX) || top[1].Entity != addr(addrY) || top[1].Score < 7.4 || top[1].Score > 7.6 {
		t.Fatalf("risky: %+v %v", top, err)
	}
	if r := score(addr(addrZ)); r.Score != 0 || r.Entity != addr(addrZ) {
		t.Fatalf("unknown entity: %+v", r)
	}
	// Bounded: past maxRisk the lowest scores go.
	for i := range maxRisk {
		h.e.risk[incEnt{kind: siem.EntityAddress, key: ipv4(i)}] = &riskEntry{score: 50, at: h.clk.now()}
	}
	h.e.addRisk(incEnt{kind: siem.EntityAddress, key: "192.0.2.200"}, 4, h.clk.now())
	if n := len(h.e.risk); n > maxRisk {
		t.Fatalf("risk entries %d > %d", n, maxRisk)
	}
	if _, ok := h.e.risk[incEnt{kind: siem.EntityAddress, key: addrY}]; ok {
		t.Fatal("the lowest score was kept")
	}
}

// Every incident change is emitted as a siem.incident event once the incident is stored.
func TestIncidentOpenedAndEscalatedEvents(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, chainBF, chainSignIn)
	h.feed(incEv(0, siem.SrcMooring, "t.bf", addrX, "alice", nil))
	h.feed(incEv(time.Minute, siem.SrcMooring, "t.signin", addrX, "alice", nil))
	if evs := incEvents(h); len(evs) != 0 {
		t.Fatalf("emitted before written: %+v", evs)
	}
	h.e.flush(true)
	evs := incEvents(h)
	if len(evs) != 2 || evs[0].F["change"] != changeOpened || evs[1].F["change"] != changeEscalated {
		t.Fatalf("events %+v", evs)
	}
	e := evs[1]
	if e.Src != siem.SrcSIEM || e.Kind != KindIncident || e.F["incident_id"] != float64(1) || e.F["severity"] != "critical" ||
		e.F["state"] != "open" || e.F["chain"] != "Brute force then sign-in" || e.IP != addrX || e.Actor != "alice" ||
		e.F["entities"] != "address:"+addrX+",account:mooring:alice" || !strings.Contains(e.Msg, "known chain") || e.Lvl != siem.LvlCritical {
		t.Fatalf("escalated event %+v", e)
	}
	// The detections' own events name their incident.
	for _, x := range h.out.events() {
		if x.Kind == KindDetection && x.F["incident_id"] != float64(1) {
			t.Fatalf("detection event without its incident: %+v", x)
		}
	}
}

func incEvents(h *harness) []siem.Event {
	var out []siem.Event
	for _, e := range h.out.events() {
		if e.Kind == KindIncident {
			out = append(out, e)
		}
	}
	return out
}

// The group-bys whose key is an account: actor, f.account, f.target and f.user.
func TestIncidentAccountGroupBys(t *testing.T) {
	for _, gb := range []string{"actor", "f.account", "f.target", "f.user"} {
		h := incHarness(t, false)
		h.only(t, incRule("custom.a", siem.SevLow, gb, "kind:t.a"))
		f := map[string]any{"account": "bob", "target": "bob", "user": "bob"}
		h.feed(incEv(0, siem.SrcMooring, "t.a", "", "bob", f))
		if inc := h.only1(t); len(inc.Entities) != 1 || inc.Entities[0] != acct("mooring", "bob") {
			t.Fatalf("group-by %s: %+v", gb, inc)
		}
	}
	for _, gb := range []string{"app", "kind", "f.host"} {
		h := incHarness(t, false)
		h.only(t, incRule("custom.a", siem.SevLow, gb, "kind:t.a"))
		e := incEv(0, siem.SrcEdge, "t.a", "", "", map[string]any{"host": "shop.example.com"})
		e.App = "shop"
		h.feed(e)
		if incs := h.incList(t); len(incs) != 0 {
			t.Fatalf("group-by %s opened an incident: %+v", gb, incs)
		}
	}
}

// An incident opened by the last events before a shutdown is written, and its alert sent, before
// the alert worker stops.
func TestIncidentAlertSentAtShutdown(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.h", siem.SevHigh, "ip", "kind:t.h"))
	stop := h.run(t)
	h.e.Subscriber()(incEv(0, siem.SrcEdge, "t.h", addrX, "", nil))
	waitFor(t, "event taken", func() bool { return h.e.Stats().Queue == 0 })
	stop()
	al := h.al.all()
	if len(al) != 1 || al[0].DedupeKey != "siem-incident:1" {
		t.Fatalf("alerts at shutdown: %+v", al)
	}
	var alerted int
	if err := h.e.db.w.QueryRow(`SELECT alerted_rank FROM incidents WHERE id = 1`).Scan(&alerted); err != nil || alerted != 3 {
		t.Fatalf("alert recorded: %d, %v", alerted, err)
	}
}

// A chain takes detections of two different rules: a rule in both steps (a sign-in from a listed
// address) is no chain on its own, nor with another detection of itself.
func TestChainNeedsTwoRules(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("ssh.login_spamhaus_ip", siem.SevHigh, "ip", "kind:t.sl"))
	h.feed(incEv(0, siem.SrcHost, "t.sl", addrX, "root", nil))
	h.feed(incEv(2*time.Hour, siem.SrcHost, "t.sl", addrX, "root", nil))
	if inc := h.only1(t); inc.Severity != siem.SevHigh || inc.Chain != "" || inc.Detections != 2 {
		t.Fatalf("one rule: %+v", inc)
	}
}
