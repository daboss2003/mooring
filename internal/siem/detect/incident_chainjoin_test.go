package detect

import (
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
)

// Chain-completing joins (owner decision): a detection of a chain step joins another key's
// incident that lists its key, only when it is the missing step of a known chain there.

func appEv(at time.Duration, app, kind, ip, actor string) siem.Event {
	e := incEv(at, siem.SrcApp, kind, ip, actor, nil)
	e.App = app
	return e
}

// An address-keyed brute force whose evidence lists alice, then alice's account-keyed sign-in of
// any of the sign-in rules: "Brute force then sign-in", critical, in the brute force's incident.
func TestChainCompletingJoin(t *testing.T) {
	for _, c := range []struct {
		bf, signin string
		ev         func(at time.Duration, kind, ip, actor string) siem.Event
		scope      string
	}{
		{"ssh.bruteforce", "ssh.login_new_country", hostEv, "host"},
		{"ssh.bruteforce", "ssh.login_travel", hostEv, "host"},
		{"ssh.spray", "baseline.signin_unusual", hostEv, "host"},
		{"app.auth_bruteforce", "app.auth_success_after_failures", shopEv, "app:shop"},
		{"app.auth_bruteforce", "app.auth_new_country", shopEv, "app:shop"},
		{"mooring.login_bruteforce", "mooring.login_travel", mooringEv, "mooring"},
	} {
		h := incHarness(t, false)
		h.only(t, incRule(c.bf, siem.SevHigh, "ip", "kind:t.bf"), incRule(c.signin, siem.SevHigh, "actor", "kind:t.si"))
		h.feed(c.ev(0, "t.bf", addrX, "alice"))
		if al := h.flushAlerts(); len(al) != 1 || al[0].Level != alert.LevelWarning {
			t.Fatalf("%s: brute force %+v", c.bf, al)
		}
		h.feed(c.ev(time.Hour, "t.si", addrY, "alice"))
		al := h.flushAlerts()
		inc := h.only1(t)
		if inc.Chain != "Brute force then sign-in" || inc.Severity != siem.SevCritical || inc.Detections != 2 ||
			inc.Entities[0] != addr(addrX) || !hasEntity(inc.Entities, acct(c.scope, "alice")) {
			t.Fatalf("%s then %s: %+v", c.bf, c.signin, inc)
		}
		if len(al) != 1 || al[0].Kind != IncidentAlertKind || al[0].Level != alert.LevelCritical {
			t.Fatalf("%s then %s: alerts %+v", c.bf, c.signin, al)
		}
	}
}

func hostEv(at time.Duration, kind, ip, actor string) siem.Event {
	return incEv(at, siem.SrcHost, kind, ip, actor, nil)
}
func shopEv(at time.Duration, kind, ip, actor string) siem.Event {
	return appEv(at, "shop", kind, ip, actor)
}
func mooringEv(at time.Duration, kind, ip, actor string) siem.Event {
	return incEv(at, siem.SrcMooring, kind, ip, actor, nil)
}

// No merge: a detection of a rule of no chain step never joins through a listed account (before or
// after the account completed a chain there); an account of another scope is another entity; a
// chain step that isn't the missing one (the chain is made already) opens its own incident.
func TestChainCompletingJoinNoMerge(t *testing.T) {
	t.Run("not a chain step", func(t *testing.T) {
		h := incHarness(t, false)
		h.only(t, chainBF, chainSignIn, incRule("custom.act", siem.SevHigh, "actor", "kind:t.act"),
			incRule("mooring.lockout", siem.SevHigh, "actor", "kind:t.lock"))
		h.feed(incEv(0, siem.SrcMooring, "t.bf", addrX, "alice", nil))
		h.feed(incEv(time.Minute, siem.SrcMooring, "t.act", addrY, "alice", nil))
		h.feed(incEv(2*time.Minute, siem.SrcMooring, "t.lock", addrY, "alice", nil))
		bf := h.detIncident(t, "mooring.login_bruteforce", addrX)
		for _, r := range []string{"custom.act", "mooring.lockout"} {
			if id := h.detIncident(t, r, "alice"); id == bf || id == 0 {
				t.Fatalf("%s joined %d (the brute force's is %d)", r, id, bf)
			}
		}
		// alice completes the chain in the brute force's incident; her later detections of rules of
		// no chain step still go to her own.
		h.feed(incEv(time.Hour, siem.SrcMooring, "t.signin", addrY, "alice", nil))
		if id := h.detIncident(t, "mooring.login_new_country", "alice"); id != bf {
			t.Fatalf("sign-in joined %d, want %d", id, bf)
		}
		h.feed(incEv(3*time.Hour, siem.SrcMooring, "t.act", addrY, "alice", nil))
		if id := h.detIncident(t, "custom.act", "alice"); id == bf {
			t.Fatal("a rule of no chain step joined through the chain's account")
		}
	})
	t.Run("another scope", func(t *testing.T) {
		h := incHarness(t, false)
		h.only(t, incRule("app.auth_bruteforce", siem.SevHigh, "ip", "kind:t.bf"),
			incRule("ssh.login_new_country", siem.SevHigh, "actor", "kind:t.ssi"),
			incRule("app.auth_new_country", siem.SevHigh, "actor", "kind:t.asi"))
		h.feed(appEv(0, "shop", "t.bf", addrX, "alice"))
		h.feed(hostEv(time.Hour, "t.ssi", addrY, "alice"))
		h.feed(appEv(time.Hour, "other", "t.asi", addrY, "alice"))
		incs := h.incList(t)
		if len(incs) != 3 {
			t.Fatalf("want 3 incidents: %+v", incs)
		}
		for _, inc := range incs {
			if inc.Chain != "" || inc.Detections != 1 {
				t.Fatalf("merged across scopes: %+v", inc)
			}
		}
	})
	t.Run("own key first", func(t *testing.T) {
		// alice's own incident (her unusual sign-in) and a Tor sign-in's incident listing alice would
		// both be completed by a change of alice: her own key's is taken.
		h := incHarness(t, false)
		h.only(t, chainSignIn, chainTor, chainChange)
		h.feed(incEv(0, siem.SrcMooring, "t.signin", addrY, "alice", nil))
		h.feed(incEv(time.Hour, siem.SrcMooring, "t.tor", addrX, "alice", nil))
		h.feed(incEv(2*time.Hour, siem.SrcMooring, "t.change", addrZ, "admin", map[string]any{"target": "alice"}))
		own := h.detIncident(t, "mooring.login_new_country", "alice")
		if id := h.detIncident(t, "mooring.user_change", "alice"); id != own || len(h.incList(t)) != 2 {
			t.Fatalf("change joined %d, want alice's own %d", id, own)
		}
	})
	t.Run("chain made already", func(t *testing.T) {
		h := incHarness(t, false)
		h.only(t, chainBF, chainSignIn, incRule("mooring.login_travel", siem.SevHigh, "actor", "kind:t.travel"))
		h.feed(incEv(0, siem.SrcMooring, "t.bf", addrX, "alice", nil))
		h.feed(incEv(time.Hour, siem.SrcMooring, "t.signin", addrY, "alice", nil))
		h.flushAlerts()
		h.feed(incEv(2*time.Hour, siem.SrcMooring, "t.travel", addrZ, "alice", nil))
		al := h.flushAlerts()
		bf := h.detIncident(t, "mooring.login_bruteforce", addrX)
		if id := h.detIncident(t, "mooring.login_travel", "alice"); id == bf || id == 0 || len(al) != 1 ||
			al[0].DedupeKey != "siem-incident:"+itoa(id) {
			t.Fatalf("second sign-in joined %d (brute force %d), alerts %+v", id, bf, al)
		}
	})
}

// Two attackers brute-force alice from two addresses; each one's chain completes in its own
// incident and alerts critical, even when the first attacker's incident is the more recently
// active one.
func TestChainCompletingTwoAttackers(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, chainBF, chainSignIn)
	h.feed(incEv(0, siem.SrcMooring, "t.bf", addrX, "alice", nil))
	h.feed(incEv(time.Hour, siem.SrcMooring, "t.signin", addrZ, "alice", nil))
	a1 := h.flushAlerts()
	cA := h.detIncident(t, "mooring.login_bruteforce", addrX)
	h.feed(incEv(3*time.Hour, siem.SrcMooring, "t.bf", addrY, "alice", nil))
	h.feed(incEv(4*time.Hour, siem.SrcMooring, "t.bf", addrX, "alice", nil)) // the first goes on
	h.flushAlerts()
	cB := h.detIncident(t, "mooring.login_bruteforce", addrY)
	h.feed(incEv(5*time.Hour, siem.SrcMooring, "t.signin", addrZ, "alice", nil))
	a2 := h.flushAlerts()
	if cA == cB || h.detIncident(t, "mooring.login_new_country", "alice") != cB {
		t.Fatalf("second sign-in in %d, want %d (first attacker's %d)", h.detIncident(t, "mooring.login_new_country", "alice"), cB, cA)
	}
	for i, al := range [][]alert.Outbox{a1, a2} {
		want := "siem-incident:" + itoa([]int64{cA, cB}[i])
		if len(al) != 1 || al[0].Level != alert.LevelCritical || al[0].DedupeKey != want {
			t.Fatalf("attacker %d: %+v, want critical %s", i+1, al, want)
		}
	}
}

// A chain-completing join of a key new to an incident that had alerted critical already alerts
// again (critical), once per such key; the re-alert owed survives a restart.
func TestChainCompletingReAlert(t *testing.T) {
	rules := []siem.Rule{chainBF, chainSignIn, chainChange, incRule("custom.crit", siem.SevCritical, "ip", "kind:t.crit")}
	setup := func(t *testing.T) (*harness, int64) {
		h := incHarness(t, false)
		h.only(t, rules...)
		h.feed(incEv(0, siem.SrcMooring, "t.bf", addrX, "alice", nil))
		h.feed(incEv(time.Minute, siem.SrcMooring, "t.crit", addrX, "", nil))
		if al := h.flushAlerts(); len(al) != 1 || al[0].Level != alert.LevelCritical {
			t.Fatalf("critical already: %+v", al)
		}
		return h, h.detIncident(t, "mooring.login_bruteforce", addrX)
	}
	h, id := setup(t)
	h.feed(incEv(time.Hour, siem.SrcMooring, "t.signin", addrY, "alice", nil))
	al := h.flushAlerts()
	if len(al) != 1 || al[0].Level != alert.LevelCritical || al[0].DedupeKey != "siem-incident:"+itoa(id) {
		t.Fatalf("new key completing the chain: %+v", al)
	}
	if inc := h.only1(t); inc.Chain != "Brute force then sign-in" || inc.Detections != 3 {
		t.Fatalf("%+v", inc)
	}
	// alice again, completing another chain there (Account takeover): no second re-alert.
	h.feed(incEv(2*time.Hour, siem.SrcMooring, "t.change", addrZ, "admin", map[string]any{"target": "alice"}))
	if al := h.flushAlerts(); len(al) != 0 || h.detIncident(t, "mooring.user_change", "alice") != id {
		t.Fatalf("same key again: %+v", al)
	}

	// Owed when Mooring stops before the re-alert is recorded: sent once at the next start; and the
	// key is known from the stored detections after it.
	h, id = setup(t)
	h.feed(incEv(time.Hour, siem.SrcMooring, "t.signin", addrY, "alice", nil))
	h.e.flush(true)
	<-h.e.alerts // raised, never recorded
	h.reopen(t)
	h.e.lim.incidents = true
	h.only(t, rules...)
	if al := h.flushAlerts(); len(al) != 1 || al[0].Level != alert.LevelCritical || al[0].DedupeKey != "siem-incident:"+itoa(id) {
		t.Fatalf("after a restart: %+v", al)
	}
	h.reopen(t)
	h.e.lim.incidents = true
	h.only(t, rules...)
	if al := h.flushAlerts(); len(al) != 0 {
		t.Fatalf("recorded: %+v", al)
	}
	h.feed(incEv(2*time.Hour, siem.SrcMooring, "t.change", addrZ, "admin", map[string]any{"target": "alice"}))
	if al := h.flushAlerts(); len(al) != 0 || h.detIncident(t, "mooring.user_change", "alice") != id {
		t.Fatalf("same key after a restart: %+v", al)
	}
}
