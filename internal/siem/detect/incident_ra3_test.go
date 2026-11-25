package detect

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
)

// Re-audit 3 of the chain-completing joins: one test per fix.

// Fixes 1 and 9: two addresses brute-force root, X the less recently active; X's root sign-in
// joins X's incident (keyed by its own evidence address), not Y's. With X's own sign-in already
// making the chain there, it joins with no new alert. A flood of other incidents listing root
// (pushing X's out of the listed index) changes nothing.
func TestChainJoinTakesTheSameAddressFirst(t *testing.T) {
	for _, withSAF := range []bool{false, true} {
		h := incHarness(t, false)
		rules := []siem.Rule{incRule("ssh.bruteforce", siem.SevHigh, "ip", "kind:t.bf"),
			incRule("ssh.login_new_country", siem.SevHigh, "actor", "kind:t.si")}
		if withSAF {
			rules = append(rules, incRule("ssh.success_after_failures", siem.SevCritical, "ip", "kind:t.si"))
		}
		h.only(t, rules...)
		h.feed(hostEv(0, "t.bf", addrX, "root"))
		h.feed(hostEv(10*time.Minute, "t.bf", addrY, "root"))
		h.flushAlerts()
		iX, iY := h.detIncident(t, "ssh.bruteforce", addrX), h.detIncident(t, "ssh.bruteforce", addrY)
		h.feed(hostEv(20*time.Minute, "t.si", addrX, "root"))
		al := h.flushAlerts()
		if got := h.detIncident(t, "ssh.login_new_country", "root"); got != iX {
			t.Fatalf("withSAF %v: X's sign-in joined %d, want X's %d (Y's is %d)", withSAF, got, iX, iY)
		}
		if len(al) != 1 || al[0].Level != alert.LevelCritical || al[0].DedupeKey != "siem-incident:"+itoa(iX) {
			t.Fatalf("withSAF %v: alerts %+v", withSAF, al)
		}
		if y := h.incGet(t, iY); y.Chain != "" || y.Detections != 1 {
			t.Fatalf("withSAF %v: Y's incident %+v", withSAF, y)
		}
	}

	// X's chain made (and alerted) already by its own sign-in; root's account-keyed sign-in from X
	// after it joins X's incident with no new alert, not Y's (which it would complete).
	h := incHarness(t, false)
	h.only(t, incRule("ssh.bruteforce", siem.SevHigh, "ip", "kind:t.bf"), incRule("ssh.login_new_country", siem.SevHigh, "actor", "kind:t.si"),
		incRule("ssh.success_after_failures", siem.SevHigh, "ip", "kind:t.saf"))
	h.feed(hostEv(0, "t.bf", addrX, "root"))
	h.feed(hostEv(10*time.Minute, "t.bf", addrY, "root"))
	h.feed(hostEv(20*time.Minute, "t.saf", addrX, "root"))
	h.flushAlerts()
	iX := h.detIncident(t, "ssh.bruteforce", addrX)
	h.feed(hostEv(25*time.Minute, "t.si", addrX, "root"))
	if al := h.flushAlerts(); len(al) != 0 || h.detIncident(t, "ssh.login_new_country", "root") != iX {
		t.Fatalf("made already: joined %d (X's %d), alerts %+v", h.detIncident(t, "ssh.login_new_country", "root"), iX, al)
	}

	h = incHarness(t, false)
	h.only(t, incRule("ssh.bruteforce", siem.SevHigh, "ip", "kind:t.bf"), incRule("ssh.login_new_country", siem.SevHigh, "actor", "kind:t.si"))
	h.feed(hostEv(0, "t.bf", addrX, "root"))
	for i := range 2 * maxEntIncs { // later decoys, all trying root
		h.feed(hostEv(time.Duration(i+1)*time.Minute, "t.bf", fmt.Sprintf("192.0.2.%d", i+1), "root"))
	}
	h.flushAlerts()
	iX = h.detIncident(t, "ssh.bruteforce", addrX)
	if refs := h.e.listIdx[incEnt{siem.EntityAccount, "host", "root"}]; len(refs) > maxEntIncs {
		t.Fatalf("listed index unbounded: %d", len(refs))
	}
	h.feed(hostEv(30*time.Minute, "t.si", addrX, "root"))
	if got := h.detIncident(t, "ssh.login_new_country", "root"); got != iX {
		t.Fatalf("after the flood: joined %d, want %d", got, iX)
	}
}

// Fix 2: a chain is made for the account that joined: one spray that tried alice and bob, then
// both sign in; bob's sign-in completes the chain again (and re-alerts critical, once), whatever
// its rule's severity.
func TestChainMadeAgainForAnotherAccountOfTheSpray(t *testing.T) {
	for _, sev := range []siem.Severity{siem.SevHigh, siem.SevMedium} {
		h := incHarness(t, false)
		h.only(t, incRule("app.auth_spray", siem.SevMedium, "ip", "kind:t.spray"),
			incRule("app.auth_success_after_failures", sev, "actor", "kind:t.ok"),
			incRule("app.auth_new_country", sev, "actor", "kind:t.nc"))
		h.feed(shopEv(0, "t.spray", addrX, "alice"), shopEv(time.Second, "t.spray", addrX, "bob"))
		h.flushAlerts()
		h.feed(shopEv(time.Minute, "t.ok", addrX, "alice"))
		if a1 := h.flushAlerts(); len(a1) != 1 || a1[0].Level != alert.LevelCritical {
			t.Fatalf("%s: alice %+v", sev, a1)
		}
		iX := h.detIncident(t, "app.auth_spray", addrX)
		h.feed(shopEv(2*time.Minute, "t.ok", addrX, "bob"))
		a2 := h.flushAlerts()
		if len(a2) != 1 || a2[0].Level != alert.LevelCritical || a2[0].DedupeKey != "siem-incident:"+itoa(iX) ||
			h.detIncident(t, "app.auth_success_after_failures", "bob") != iX {
			t.Fatalf("%s: bob %+v", sev, a2)
		}
		// bob again, by another sign-in rule from the same address: made for bob, no new alert.
		h.feed(shopEv(3*time.Minute, "t.nc", addrX, "bob"))
		if a3 := h.flushAlerts(); len(a3) != 0 || h.detIncident(t, "app.auth_new_country", "bob") != iX {
			t.Fatalf("%s: bob again %+v", sev, a3)
		}
	}
}

// Fix 3: a re-alert owed while the incident is resolved goes out when it is reopened.
func TestReopenSendsTheOwedReAlert(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, chainBF, chainSignIn, incRule("custom.crit", siem.SevCritical, "ip", "kind:t.crit"))
	h.feed(incEv(0, siem.SrcMooring, "t.bf", addrX, "alice", nil))
	h.feed(incEv(time.Minute, siem.SrcMooring, "t.crit", addrX, "", nil))
	h.flushAlerts()
	id := h.detIncident(t, "mooring.login_bruteforce", addrX)
	h.feed(incEv(time.Hour, siem.SrcMooring, "t.signin", addrY, "alice", nil))
	state := func(s string) {
		t.Helper()
		rep := make(chan incReply, 1)
		h.e.serve(&incReq{op: opState, id: id, state: s, actor: "owner", reply: rep})
		if r := <-rep; r.err != nil {
			t.Fatal(r.err)
		}
	}
	state(siem.IncidentResolved)
	if al := h.flushAlerts(); len(al) != 0 {
		t.Fatalf("resolved: %+v", al)
	}
	state(siem.IncidentOpen)
	if al := h.flushAlerts(); len(al) != 1 || al[0].Level != alert.LevelCritical || al[0].DedupeKey != "siem-incident:"+itoa(id) {
		t.Fatalf("reopened: %+v", al)
	}
}

// Fix 4: the edge's block-list rules never take the chain-join exception: a listed carrier address
// doesn't raise the sign-ins of the accounts behind it; its detection groups by its own key.
func TestEdgeBlockListNeverChainJoins(t *testing.T) {
	for _, rule := range []string{"edge.spamhaus_ip", "edge.dshield_ip"} {
		h := incHarness(t, false)
		h.only(t, chainSignIn, incRule(rule, siem.SevLow, "ip", "kind:t.listed"))
		const nat = "100.64.9.9"
		for i, u := range []string{"alice", "bob", "carol"} {
			h.feed(incEv(time.Duration(i)*time.Minute, siem.SrcMooring, "t.signin", nat, u, nil))
		}
		h.feed(incEv(10*time.Minute, siem.SrcEdge, "t.listed", nat, "", nil))
		incs := h.incList(t)
		if len(incs) != 4 || h.incGet(t, h.detIncident(t, rule, nat)).Detections != 1 {
			t.Fatalf("%s: %+v", rule, incs)
		}
		for _, inc := range incs {
			if inc.Chain != "" || inc.Severity == siem.SevCritical {
				t.Fatalf("%s raised %+v", rule, inc)
			}
		}
	}
}

// Fix 5: the flush keeps the incident cache bounded while it waits out a write backoff.
func TestFlushEvictsDuringWriteBackoff(t *testing.T) {
	h := incHarness(t, false)
	h.e.lim.newPerHour = 1 << 30
	h.only(t, incRule("custom.ip", siem.SevLow, "ip", "kind:t.ip"))
	const n = maxIncCache + 300
	for i := range n {
		h.feed(incEv(time.Duration(i)*time.Millisecond, siem.SrcEdge, "t.ip", ipv4(i+1), "", nil))
		if i%1000 == 999 {
			h.e.flush(true)
		}
	}
	h.e.flush(true)
	load := func() {
		for id := int64(1); id <= n; id++ {
			if h.e.incs[id] == nil {
				if _, ok, err := h.e.incident(id); !ok || err != nil {
					t.Fatal(id, ok, err)
				}
			}
		}
	}
	if _, err := h.e.db.w.Exec(`CREATE TRIGGER fail_incidents BEFORE INSERT ON incidents BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END`); err != nil {
		t.Fatal(err)
	}
	h.feed(incEv(time.Minute, siem.SrcEdge, "t.ip", addrX, "", nil))
	h.e.flush(false) // fails: the flushes back off
	if h.e.writeBackoff == 0 {
		t.Fatal("no backoff")
	}
	load()
	h.e.flush(false)
	if len(h.e.incs) > maxIncCache {
		t.Fatalf("during the backoff: %d in memory", len(h.e.incs))
	}
}

// Fix 6: an alert result for an incident that left memory, when detect.db can't be read, drops
// that stale copy (a dashboard change made since stays) and the alert is owed again.
func TestStaleCopyNotWrittenBack(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.h", siem.SevHigh, "ip", "kind:t.h"))
	h.feed(incEv(0, siem.SrcEdge, "t.h", addrX, "", nil))
	h.e.flush(true)
	j := <-h.e.alerts
	stale := j.inc
	delete(h.e.incs, stale.id) // left memory
	h.e.entIdx.unpin(map[*incident]bool{stale: true})
	h.e.closed.Store(true) // and detect.db can't be read
	h.e.finishAlert(alertResult{job: j, ok: true})
	h.e.closed.Store(false)
	if _, dirty := h.e.incDirty[stale]; dirty {
		t.Fatal("stale copy kept")
	}
	rep := make(chan incReply, 1)
	h.e.serve(&incReq{op: opState, id: stale.id, state: siem.IncidentAcknowledged, actor: "owner", reply: rep})
	if r := <-rep; r.err != nil {
		t.Fatal(r.err)
	}
	al := h.flushAlerts()
	if inc := h.incGet(t, stale.id); inc.State != siem.IncidentAcknowledged {
		t.Fatalf("dashboard change undone: %+v", inc)
	}
	if len(al) != 1 || al[0].DedupeKey != "siem-incident:"+itoa(stale.id) {
		t.Fatalf("owed again: %+v", al)
	}
}

// Fix 7: removing an incident unlinks its detections in memory, so a pending write doesn't store
// the removed incident's ID.
func TestForgetUnlinksDetectionsInMemory(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.h", siem.SevHigh, "ip", "kind:t.h"))
	h.feed(incEv(0, siem.SrcEdge, "t.h", addrX, "", nil))
	h.e.flush(true)
	id := h.detIncident(t, "custom.h", addrX)
	h.feed(incEv(time.Minute, siem.SrcEdge, "t.h", addrX, "", nil)) // an update, not written yet
	if _, err := h.e.db.deleteIncidents(context.Background(), []int64{id}, false); err != nil {
		t.Fatal(err)
	}
	h.e.forgetIncidents([]int64{id})
	if got := h.detIncident(t, "custom.h", addrX); got != 0 {
		t.Fatalf("detection stored linked to removed incident %d", got)
	}
}

// Fix 8 (owner decision): a false positive with mute mutes only the rules of the detections keyed by
// the incident's own key entity; root's sign-in, joined to complete the chain, keeps alerting.
func TestFalsePositiveMutesOnlyTheIncidentsKey(t *testing.T) {
	h := incHarness(t, true)
	h.only(t, incRule("ssh.bruteforce", siem.SevHigh, "ip", "kind:t.bf"), incRule("ssh.login_new_country", siem.SevHigh, "actor", "kind:t.si"))
	h.feed(hostEv(0, "t.bf", addrX, "root"))
	h.flushAlerts()
	id := h.detIncident(t, "ssh.bruteforce", addrX)
	h.feed(hostEv(10*time.Minute, "t.si", addrY, "root")) // chain-joined, not written yet
	rep := make(chan incReply, 1)
	h.e.serve(&incReq{op: opFPPairs, id: id, reply: rep})
	if r := <-rep; r.err != nil || len(r.pairs) != 1 || r.pairs[0].RuleID != "ssh.bruteforce" || r.pairs[0].Entity != addr(addrX) {
		t.Fatalf("pairs from memory: %+v %v", r.pairs, r.err)
	}
	h.flushAlerts()
	if h.detIncident(t, "ssh.login_new_country", "root") != id {
		t.Fatal("setup: not chain-joined")
	}
	stop := h.run(t)
	if err := h.e.MarkFalsePositive(context.Background(), id, "owner", true, ""); err != nil {
		t.Fatal(err)
	}
	stop()
	var n int
	if err := h.main.QueryRow(`SELECT COUNT(*) FROM security_mutes`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("stored mutes %d, %v", n, err)
	}
	h.feed(hostEv(3*time.Hour, "t.si", addrZ, "root"))
	if al := h.flushAlerts(); len(al) != 1 {
		t.Fatalf("root's later sign-in: %+v", al)
	}
}
