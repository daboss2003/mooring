package detect

import (
	"context"
	"maps"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// scopeEv is an event of kind for account alice from src (an app's: the app shop).
func scopeEv(at time.Duration, src, kind, ip, actor string) siem.Event {
	e := incEv(at, src, kind, ip, actor, nil)
	if src == siem.SrcApp {
		e.App = "shop"
	}
	return e
}

// scopeRules: custom.a keeps an account's detections apart per scope (its query lets every source
// through); custom.m pins Mooring's events; custom.i is keyed by an address.
func scopeRules() []siem.Rule {
	return []siem.Rule{incRule("custom.a", siem.SevHigh, "actor", "kind:t.a"),
		incRule("custom.m", siem.SevHigh, "actor", "src:mooring kind:t.a"),
		incRule("custom.i", siem.SevHigh, "ip", "kind:t.i")}
}

const (
	dkMooring = "siem-acct:custom.a:mooring|alice"
	dkShop    = "siem-acct:custom.a:app:shop|alice"
	dkHost    = "siem-acct:custom.a:host|alice"
)

// Owner decision (reversing "the scopes of an account share one alert cooldown and dedupe key"):
// two detections of one rule for the same account name in different systems each alert on their
// own, with incidents off too: the cooldown, the alerts in flight and the dedupe key are per scope.
// A detection that isn't kept apart per scope keeps the keys it had.
func TestAlertPerAccountScope(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, scopeRules()...)
	// Both in flight at once: neither holds the other back.
	h.feed(scopeEv(0, siem.SrcMooring, "t.a", "", "alice"), scopeEv(time.Second, siem.SrcApp, "t.a", "", "alice"))
	want := map[string]int{dkMooring: 1, dkShop: 1, "siem:custom.m:alice": 1}
	if got := byDedupe(h.alerts()); !maps.Equal(got, want) {
		t.Fatalf("alerts %v, want %v", got, want)
	}
	// Each scope's cooldown holds its own detection.
	h.feed(scopeEv(time.Minute, siem.SrcMooring, "t.a", "", "alice"), scopeEv(time.Minute, siem.SrcApp, "t.a", "", "alice"))
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("within each scope's cooldown: %+v", got)
	}
	// A third system's alice, sent after the others': its own alert.
	h.feed(scopeEv(2*time.Minute, siem.SrcHost, "t.a", "", "alice"))
	if got := byDedupe(h.alerts()); !maps.Equal(got, map[string]int{dkHost: 1}) {
		t.Fatalf("the host's alice: %v", got)
	}
	for _, mk := range []string{scopedKey("custom.a", "mooring", "alice"), scopedKey("custom.a", "app:shop", "alice"),
		scopedKey("custom.a", "host", "alice"), mapKey("custom.m", "alice")} {
		if _, ok := h.e.cooldown[mk]; !ok {
			t.Errorf("no cooldown under %q: %v", mk, h.e.cooldown)
		}
	}
	if _, ok := h.e.cooldown[mapKey("custom.a", "alice")]; ok || len(h.e.cooldown) != 4 || len(h.e.inflight) != 0 {
		t.Errorf("cooldowns %v, in flight %v", h.e.cooldown, h.e.inflight)
	}
	// The rule's hourly cap is per rule, as before: the three scopes' alerts count in one.
	hour := h.clk.now().UTC().Truncate(time.Hour)
	if cs := h.e.caps[capKey{"custom.a", hour.Unix()}]; cs == nil || cs.sent != 3 || cs.more != 0 {
		t.Errorf("custom.a's hour: %+v", cs)
	}
	// An address from two sources is one detection (the scope of its first event): one alert, under
	// the key it always had.
	h.feed(scopeEv(3*time.Minute, siem.SrcMooring, "t.i", addrX, ""), scopeEv(4*time.Minute, siem.SrcApp, "t.i", addrX, ""))
	if got := byDedupe(h.alerts()); !maps.Equal(got, map[string]int{"siem:custom.i:" + addrX: 1}) {
		t.Fatalf("an address from two sources: %v", got)
	}
	if _, ok := h.e.cooldown[mapKey("custom.i", addrX)]; !ok {
		t.Errorf("the address's cooldown: %v", h.e.cooldown)
	}
}

// Past the rule's hourly cap a scope's detection is counted in the rule's summary like any other.
func TestAlertPerAccountScopeUnderTheRuleCap(t *testing.T) {
	h := newHarness(t, false)
	h.e.lim.alertsPerHour = 1
	h.only(t, scopeRules()[0])
	h.feed(scopeEv(0, siem.SrcMooring, "t.a", "", "alice"), scopeEv(time.Second, siem.SrcApp, "t.a", "", "alice"))
	if got := byDedupe(h.alerts()); !maps.Equal(got, map[string]int{dkMooring: 1}) {
		t.Fatalf("alerts %v", got)
	}
	hour := h.clk.now().UTC().Truncate(time.Hour)
	if cs := h.e.caps[capKey{"custom.a", hour.Unix()}]; cs == nil || cs.sent != 1 || cs.more != 1 {
		t.Fatalf("custom.a's hour: %+v", cs)
	}
}

// The cooldowns read back at start are per scope too for a rule that keeps scopes apart, and per
// rule and key for every other (as stored before: no second alert after an upgrade).
func TestAlertScopeCooldownAcrossRestart(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	for _, r := range scopeRules() {
		r.Enabled = true
		if err := h.e.SaveRule(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	h.feed(scopeEv(0, siem.SrcMooring, "t.a", "", "alice"), scopeEv(time.Second, siem.SrcApp, "t.a", "", "alice"),
		scopeEv(2*time.Second, siem.SrcMooring, "t.i", addrX, ""))
	if got := h.alerts(); len(got) != 4 {
		t.Fatalf("alerts %+v", got)
	}
	h.clk.advance(5 * time.Minute)
	h.reopen(t)
	want := []string{scopedKey("custom.a", "mooring", "alice"), scopedKey("custom.a", "app:shop", "alice"),
		mapKey("custom.m", "alice"), mapKey("custom.i", addrX)}
	for _, mk := range want {
		if at, ok := h.e.cooldown[mk]; !ok || at.Before(t0) || at.After(t0.Add(2*time.Second)) {
			t.Errorf("cooldown read back under %q: %v %v", mk, at, ok)
		}
	}
	if len(h.e.cooldown) != len(want) {
		t.Errorf("cooldowns read back: %q", slicesOfKeys(h.e.cooldown))
	}
	// The alerted scopes and keys stay quiet; another system's alice alerts.
	h.feed(scopeEv(6*time.Minute, siem.SrcMooring, "t.a", "", "alice"), scopeEv(6*time.Minute, siem.SrcApp, "t.a", "", "alice"),
		scopeEv(6*time.Minute, siem.SrcApp, "t.i", addrX, ""))
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("alerted before the restart: %+v", got)
	}
	h.feed(scopeEv(7*time.Minute, siem.SrcHost, "t.a", "", "alice"))
	if got := byDedupe(h.alerts()); !maps.Equal(got, map[string]int{dkHost: 1}) {
		t.Fatalf("the host's alice after the restart: %v", got)
	}
}

func slicesOfKeys(m map[string]time.Time) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A backlog replayed after a restart makes a new detection of a scope alerted minutes ago: the
// stored detection read back gives its alert time to its own scope's cooldown (also when the
// startup read of the alert times failed), and to no other scope's.
func TestAlertScopeBacklogCooldown(t *testing.T) {
	h := newHarness(t, false)
	h.clk.set(t0.Add(22 * time.Hour))
	h.only(t, scopeRules()[0])
	h.feedRaw(scopeEv(time.Hour, siem.SrcMooring, "t.a", "", "alice"))
	if got := h.alerts(); len(got) != 1 {
		t.Fatalf("alerts %+v", got)
	}
	h.clk.advance(time.Minute)
	h.reopen(t)
	h.only(t, scopeRules()[0])
	clear(h.e.cooldown)
	h.feedRaw(scopeEv(5*time.Hour, siem.SrcMooring, "t.a", "", "alice"))
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("a new detection of the scope alerted a minute ago: %+v", got)
	}
	if ds := h.detections(t, "custom.a"); len(ds) != 2 {
		t.Fatalf("detections %+v", ds)
	}
	h.feedRaw(scopeEv(5*time.Hour, siem.SrcApp, "t.a", "", "alice"))
	if got := byDedupe(h.alerts()); !maps.Equal(got, map[string]int{dkShop: 1}) {
		t.Fatalf("the app's alice: %v", got)
	}
}
