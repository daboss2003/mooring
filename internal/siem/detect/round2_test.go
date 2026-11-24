package detect

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
)

// Review round 2: the alert cooldown across a restart, the rollup's key, the new_value memory,
// updates of a removed row, and the per-rule alert cap.

func actorFail(at time.Duration, actor string) siem.Event {
	return ev(at, siem.SrcHost, siem.KindSSHLogin, siem.OutFailure, "203.0.113.5", actor, map[string]any{"method": "password"})
}

func actorRule(sev siem.Severity) siem.Rule {
	return siem.Rule{ID: "custom.act", Name: "Act", Type: siem.RuleThreshold, Query: "kind:ssh.login out:failure",
		GroupBy: "actor", Count: 1, Window: time.Hour, Severity: sev}
}

func alertedNS(t *testing.T, h *harness, where string, args ...any) int64 {
	t.Helper()
	var v int64
	if err := h.e.db.w.QueryRow(`SELECT alerted_ns FROM detections WHERE `+where, args...).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func byDedupe(os []alert.Outbox) map[string]int {
	m := map[string]int{}
	for _, o := range os {
		m[o.DedupeKey]++
	}
	return m
}

// 1. An alert raised while Run drains at shutdown is recorded on its detection before the last
// write: after a restart the same detection doesn't alert again within the hour.
func TestShutdownAlertRecordedAcrossRestart(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, oneRule(siem.SevCritical))
	ip := "203.0.113.9"
	h.e.Subscriber()(sshFail(0, ip))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.e.Run(ctx)
	if n := len(h.al.all()); n != 1 {
		t.Fatalf("alerts sent at shutdown: %d", n)
	}
	if got := alertedNS(t, h, "1"); got != t0.UnixNano() {
		t.Fatalf("stored alerted_ns %d, want the alert's time %d", got, t0.UnixNano())
	}
	if err := h.e.Close(); err != nil {
		t.Fatal(err)
	}
	h.clk.advance(5 * time.Minute)
	h.open(t)
	h.only(t, oneRule(siem.SevCritical))
	h.feed(sshFail(5*time.Minute, ip))
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("after a restart, the same detection 5 minutes later alerted again: %+v", got)
	}
	if ds := h.all(t); len(ds) != 1 || ds[0].Count != 2 {
		t.Fatalf("the stored detection is updated: %+v", ds)
	}
	// Control: an hour after the alert, it alerts again.
	h.feed(sshFail(time.Hour+time.Second, ip))
	if got := h.alerts(); len(got) != 1 {
		t.Fatalf("an hour later: %+v", got)
	}
}

// backlog feeds one successful SSH login after 5 failures from ip, timed at t0+base (a backlog
// read now), and returns the alerts of ssh.success_after_failures for ip.
func backlog(t *testing.T, h *harness, ip string, base time.Duration) int {
	t.Helper()
	for i := range 5 {
		h.hostLine(t, t0.Add(base+time.Duration(i)*time.Second).Format(time.RFC3339)+" web1 sshd[1]: Failed password for root from "+ip+" port 1 ssh2")
	}
	h.hostLine(t, t0.Add(base+time.Minute).Format(time.RFC3339)+" web1 sshd[1]: Accepted password for root from "+ip+" port 2 ssh2")
	return byDedupe(h.alerts())["siem:ssh.success_after_failures:"+ip]
}

// 1. A backlog replayed across restarts makes several detections of one key within minutes: one
// alert, also when the newest stored detection of the key was never alerted itself.
func TestBacklogAcrossRestartAlertsOnce(t *testing.T) {
	h := newHarness(t, false)
	h.clk.set(t0.Add(22 * time.Hour))
	ip := "203.0.113.8"
	n := backlog(t, h, ip, time.Hour)
	h.clk.advance(time.Minute)
	h.reopen(t)
	n += backlog(t, h, ip, 5*time.Hour) // the newest stored detection is the first one (alerted)
	h.clk.advance(time.Minute)
	h.reopen(t)
	n += backlog(t, h, ip, 9*time.Hour) // the newest stored detection is the second one (not alerted)
	if ds := h.detections(t, "ssh.success_after_failures"); len(ds) != 3 {
		t.Fatalf("three detections from the backlog: %+v", ds)
	}
	if n != 1 {
		t.Fatalf("%d alerts for one rule and key within 2 minutes across two restarts, want 1", n)
	}
	// When the startup read of the alert times failed, the time of a stored detection read back
	// still counts for a new detection of its key.
	h2 := newHarness(t, false)
	h2.clk.set(t0.Add(22 * time.Hour))
	n = backlog(t, h2, ip, time.Hour)
	h2.clk.advance(time.Minute)
	h2.reopen(t)
	clear(h2.e.cooldown)
	if n += backlog(t, h2, ip, 5*time.Hour); n != 1 {
		t.Fatalf("without the startup read: %d alerts, want 1", n)
	}
}

// 1. An alert reported back after its detection left memory (written, then evicted) is still
// recorded on the stored row.
func TestAlertResultAfterDetectionLeftMemory(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, oneRule(siem.SevCritical))
	ip := "203.0.113.9"
	h.feed(sshFail(0, ip))
	h.e.flush(true)
	j := <-h.e.alerts
	h.e.retire(h.e.active[mapKey("custom.one", ip)])
	h.e.finishAlert(alertResult{job: j, ok: true})
	// Read back from the database before that is written: its copy has no alert time.
	h.feed(sshFail(time.Minute, ip))
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("alerted again within the hour: %+v", got)
	}
	h.e.flush(false)
	if got := alertedNS(t, h, "1"); got != t0.UnixNano() {
		t.Fatalf("stored alerted_ns %d, want %d", got, t0.UnixNano())
	}
	if len(h.e.alertedRows) != 0 {
		t.Fatalf("pending alert times after the write: %v", h.e.alertedRows)
	}
	// A later write of that copy never clears it.
	h.clk.advance(writeEvery)
	h.feed(sshFail(2*time.Minute, ip))
	h.e.flush(false)
	if got, n := alertedNS(t, h, "1"), h.all(t)[0].Count; got != t0.UnixNano() || n != 3 {
		t.Fatalf("after an update: alerted_ns %d, count %d", got, n)
	}
	h.reopen(t)
	h.only(t, oneRule(siem.SevCritical))
	h.clk.advance(10 * time.Minute)
	h.feed(sshFail(11*time.Minute, ip))
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("after a restart within the hour: %+v", got)
	}
}

// 2. A real key "*" is never the rollup: after a restart its firing updates its own detection,
// never the rollup's, and the two alert on their own (distinct cooldowns and dedupe keys).
func TestRollupNeverTakenForARealKey(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, actorRule(siem.SevLow))
	h.feed(actorFail(0, "*")) // its own detection (1 of 50)
	for i := range 60 {
		h.feed(actorFail(time.Second+time.Duration(i)*time.Millisecond, fmt.Sprint("u", i)))
	}
	h.e.flush(true)
	keys, err := h.e.db.recentKeys(context.Background(), t0.Add(-time.Hour), 1000)
	if err != nil || len(keys) != newPerHour {
		t.Fatalf("recent keys: %d (%v), want the %d real ones, not the rollup", len(keys), err, newPerHour)
	}
	h.clk.advance(time.Minute)
	h.reopen(t)
	h.only(t, actorRule(siem.SevLow))
	h.feed(actorFail(2*time.Minute, "*"))
	var roll, real []siem.Detection
	for _, d := range h.detections(t, "custom.act") {
		switch {
		case d.Key != RollupKey:
		case strings.HasPrefix(d.Summary, "and "):
			roll = append(roll, d)
		default:
			real = append(real, d)
		}
	}
	if len(roll) != 1 || roll[0].Count != 11 || roll[0].Summary != "and 11 more keys this hour (at most 50 new detections per rule an hour)" {
		t.Fatalf("rollup after a restart: %+v", roll)
	}
	if len(real) != 1 || real[0].Count != 2 || real[0].Summary != "* — 2 matching events in 1h" {
		t.Fatalf("the real key *: %+v", real)
	}
	var n int
	if err := h.e.db.w.QueryRow(`SELECT COUNT(*) FROM detections WHERE rollup = 1`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows marked rollup: %d (%v)", n, err)
	}

	// Alerts: a critical rule's real key "*" and its rollup each alert (criticals are not capped).
	h2 := newHarness(t, false)
	h2.only(t, actorRule(siem.SevCritical))
	h2.feed(actorFail(0, "*"))
	for i := range 60 {
		h2.feed(actorFail(time.Second+time.Duration(i)*time.Millisecond, fmt.Sprint("u", i)))
	}
	got := byDedupe(h2.alerts())
	if got["siem:custom.act:*"] != 1 || got["siem-rollup:custom.act"] != 1 || len(got) != newPerHour+1 {
		t.Fatalf("alerts by dedupe key: %v", got)
	}

	// A real key "cap" and the rule's hourly summary have distinct dedupe keys.
	h3 := newHarness(t, false)
	h3.only(t, actorRule(siem.SevHigh))
	h3.feed(actorFail(0, "cap"))
	for i := range 6 {
		h3.feed(actorFail(time.Second+time.Duration(i)*time.Millisecond, fmt.Sprint("u", i)))
	}
	individual := byDedupe(h3.alerts())
	h3.clk.set(t0.Add(time.Hour))
	h3.e.sendCaps(false)
	sum := h3.alerts()
	if individual["siem:custom.act:cap"] != 1 || len(sum) != 1 || sum[0].DedupeKey != "siem-cap:custom.act" ||
		individual[sum[0].DedupeKey] != 0 {
		t.Fatalf("individual %v, summary %+v", individual, sum)
	}
}

// 2. Rows stored before the rollup column are marked by the migration (by their summary).
func TestMigrationMarksOldRollups(t *testing.T) {
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	var m3 string
	for _, m := range ms {
		if m.version == 3 {
			m3 = m.sql
		}
	}
	h := newHarness(t, false)
	w := h.e.db.w
	if _, err := w.Exec(`DROP INDEX detections_alerted; ALTER TABLE detections DROP COLUMN rollup;
		DELETE FROM schema_version WHERE version = 3`); err != nil {
		t.Fatal(err)
	}
	for _, r := range [][2]string{{"*", "and 3 more keys this hour (at most 50 new detections per rule an hour)"},
		{"*", "* — 2 matching events in 1h"}, {"x", "and 3 more keys this hour (at most 50 new detections per rule an hour)"},
		{"*", "and 1 more key this hour (at most 50 new detections per rule an hour)"}} {
		if _, err := w.Exec(`INSERT INTO detections(source, rule_id, rule_name, severity, sev_rank, key, first_ns, last_ns,
			count, summary) VALUES ('siem', 'r', 'r', 'low', 1, ?, 1, 1, 1, ?)`, r[0], r[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Exec(m3); err != nil {
		t.Fatal(err)
	}
	rows, err := w.Query(`SELECT id FROM detections WHERE rollup = 1 ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if rows.Close(); fmt.Sprint(ids) != "[1 4]" {
		t.Fatalf("rows marked rollup: %v, want [1 4]", ids)
	}
	// The startup read of the last hour's alerts uses the partial index (no full scan).
	var plan, detail string
	rows, err = w.Query(`EXPLAIN QUERY PLAN SELECT rule_id, key, rollup, MAX(alerted_ns) AS at FROM detections
		WHERE alerted_ns > 0 AND alerted_ns >= ? GROUP BY rule_id, key, rollup ORDER BY at DESC LIMIT ?`, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var a, b, c int
		if err := rows.Scan(&a, &b, &c, &detail); err != nil {
			t.Fatal(err)
		}
		plan += detail + "; "
	}
	if rows.Close(); !strings.Contains(plan, "detections_alerted") {
		t.Fatalf("query plan: %s", plan)
	}
}

// 3. One key with many values doesn't make a new_value rule forget the other keys: a key's own
// least recently seen values go first.
func TestNewValueHotKeyKeepsOtherKeys(t *testing.T) {
	s := newSeen()
	sec := int64(time.Second)
	s.observe("victim", "NG", 1*sec, 0)
	for i := range maxSeen + 1 {
		s.observe("attacker", fmt.Sprint("v", i), int64(i+2)*sec, 0)
	}
	n := 0
	for _, p := range s.pairs {
		if p.k == hash64("k", "attacker") {
			n++
		}
	}
	if n > maxPairsPerKey || n != s.keys[hash64("k", "attacker")].n || len(s.keys) != 2 {
		t.Fatalf("after the flood: %d keys, %d pairs, the hot key's %d (counted %d)", len(s.keys), len(s.pairs), n,
			s.keys[hash64("k", "attacker")].n)
	}
	if s.observe("victim", "NG", int64(maxSeen+10)*sec, 0) {
		t.Fatal("the victim's usual country fired as new")
	}
	if !s.observe("victim", "FR", int64(maxSeen+11)*sec, 0) {
		t.Fatal("the victim's new country did not fire (key forgotten)")
	}
	if s.observe("attacker", fmt.Sprint("v", maxSeen), int64(maxSeen+12)*sec, 0) {
		t.Fatal("the hot key's most recent value fired as new")
	}
	if !s.observe("attacker", "v0", int64(maxSeen+13)*sec, 0) {
		t.Fatal("the hot key's oldest value is still held: its values are not capped")
	}
	// The counts are rebuilt from a saved state: the cap still holds after a restart.
	got, err := decodeSeen(s.encode())
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range s.keys {
		if got.keys[k] != v {
			t.Fatalf("key %x after the round trip: %+v, want %+v", k, got.keys[k], v)
		}
	}
	for i := range 2 * maxPairsPerKey {
		got.observe("attacker", fmt.Sprint("w", i), int64(maxSeen+20+i)*sec, 0)
	}
	if k := got.keys[hash64("k", "attacker")]; k.n > maxPairsPerKey || len(got.pairs) > maxPairsPerKey+2 {
		t.Fatalf("after a restart: the hot key holds %d, %d pairs in all", k.n, len(got.pairs))
	}
}

// 4. An update of a detection whose row the size cap removed stores it again (a new ID), and it is
// emitted with that ID.
func TestUpdateOfRemovedRowStoredAgain(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, oneRule(siem.SevLow))
	ip := "203.0.113.7"
	h.feed(sshFail(0, ip))
	h.e.flush(true)
	first := h.all(t)[0].ID
	h.e.lim.dbBytes = 1 // force the cap
	h.e.capSize()
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("rows after the cap: %+v", ds)
	}
	h.feed(sshFail(time.Minute, ip)) // the same detection, still active
	h.e.flush(true)
	ds := h.all(t)
	evs := h.out.events()
	if len(ds) != 1 || ds[0].Count != 2 || !ds[0].First.Equal(t0) || ds[0].ID == first {
		t.Fatalf("after the update: %+v (first id %d)", ds, first)
	}
	if last := evs[len(evs)-1]; last.F["detection_id"] != float64(ds[0].ID) || last.F["count"] != float64(2) {
		t.Fatalf("last emitted %+v, want detection_id %d", last.F, ds[0].ID)
	}

	// An alert's time is all that changed (nothing new to emit): stored again and emitted with its
	// new ID too.
	h2 := newHarness(t, false)
	h2.only(t, oneRule(siem.SevHigh))
	h2.feed(sshFail(0, ip))
	h2.e.flush(true)
	first = h2.all(t)[0].ID
	h2.e.lim.dbBytes = 1
	h2.e.capSize()
	if got := h2.alerts(); len(got) != 1 {
		t.Fatalf("alerts %+v", got)
	}
	h2.e.flush(true)
	ds = h2.all(t)
	evs = h2.out.events()
	if len(ds) != 1 || ds[0].ID == first || alertedNS(t, h2, "id = ?", ds[0].ID) != t0.UnixNano() ||
		len(evs) != 2 || evs[1].F["detection_id"] != float64(ds[0].ID) {
		t.Fatalf("stored %+v, emitted %+v", ds, evs)
	}
}

// 5. Critical detections are alerted at once, not capped and never in a summary (still once per
// rule and key an hour); the cap and the summary (a warning) are for high detections only.
func TestCriticalAlertsBypassTheCap(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, oneRule(siem.SevCritical))
	for i := range 8 {
		h.feed(sshFail(time.Duration(i)*time.Second, ipv4(i)))
	}
	got := h.alerts()
	if len(got) != 8 || len(byDedupe(got)) != 8 {
		t.Fatalf("8 critical keys in an hour: %+v", got)
	}
	for _, o := range got {
		if o.Level != alert.LevelCritical {
			t.Fatalf("level %s", o.Level)
		}
	}
	h.feed(sshFail(10*time.Second, ipv4(0)))
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("a critical key within its hour: %+v", got)
	}
	// The same rule as high this hour: criticals didn't use the high cap.
	h.only(t, oneRule(siem.SevHigh))
	for i := 10; i < 17; i++ {
		h.feed(sshFail(time.Duration(i)*time.Second, ipv4(i)))
	}
	if got := h.alerts(); len(got) != alertsPerHour {
		t.Fatalf("7 high keys after 8 critical ones: %d alerts, want %d", len(got), alertsPerHour)
	}
	h.clk.set(t0.Add(time.Hour))
	h.e.sendCaps(false)
	got = h.alerts()
	want := alert.Outbox{Target: TargetSIEM, Kind: AlertKind, Level: alert.LevelWarning, Transition: "firing",
		Summary: "One: 2 more detections this hour — see the Detections page", DedupeKey: "siem-cap:custom.one"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("summary %+v\nwant %+v", got, want)
	}
}

// 6. No summary for a rule snoozed, switched off or deleted when the hour ends (at shutdown too);
// its detections stay recorded.
func TestNoSummaryForSnoozedOrSwitchedOffRule(t *testing.T) {
	for name, change := range map[string]func(t *testing.T, h *harness){
		"unchanged": func(*testing.T, *harness) {},
		"snoozed": func(t *testing.T, h *harness) {
			r := oneRule(siem.SevHigh)
			r.SnoozedUntil = t0.Add(24 * time.Hour)
			h.only(t, r)
		},
		"switched off": func(_ *testing.T, h *harness) { h.e.rules.Load().byID["custom.one"].r.Enabled = false },
		"deleted":      func(t *testing.T, h *harness) { h.only(t, actorRule(siem.SevHigh)) },
		"snooze ended": func(t *testing.T, h *harness) {
			r := oneRule(siem.SevHigh)
			r.SnoozedUntil = t0.Add(30 * time.Minute)
			h.only(t, r)
		},
	} {
		for _, shutdown := range []bool{false, true} {
			t.Run(fmt.Sprint(name, " shutdown=", shutdown), func(t *testing.T) {
				h := newHarness(t, false)
				h.only(t, oneRule(siem.SevHigh))
				for i := range 8 {
					h.feed(sshFail(time.Duration(i)*time.Second, ipv4(i)))
				}
				if got := h.alerts(); len(got) != alertsPerHour {
					t.Fatalf("alerts %d", len(got))
				}
				change(t, h)
				h.clk.set(t0.Add(time.Hour))
				if shutdown {
					h.clk.set(t0.Add(59 * time.Minute))
				}
				h.e.sendCaps(shutdown)
				got := h.alerts()
				want := 0
				if name == "unchanged" || name == "snooze ended" {
					want = 1
				}
				// At shutdown the hour's counters stay for the last save: the alerts sent, and the
				// detections still owed a summary when none went out now.
				wantCaps, wantMore := 0, 0
				if shutdown {
					wantCaps, wantMore = 1, 3*(1-want)
				}
				cs := h.e.caps[capKey{"custom.one", t0.Unix()}]
				if len(got) != want || len(h.e.caps) != wantCaps || (shutdown && (cs == nil || cs.sent != alertsPerHour || cs.more != wantMore)) {
					t.Fatalf("summaries %+v (want %d), caps left %d (want %d): %+v", got, want, len(h.e.caps), wantCaps, cs)
				}
				if ds := h.detections(t, "custom.one"); len(ds) != 8 {
					t.Fatalf("detections %d", len(ds))
				}
			})
		}
	}
}

// 7. The summary counts the detections never alerted on their own: one counted, then alerted when
// failed alerts gave its slot back (or its rule became critical), is not in it; counted again
// when that alert fails too.
func TestSummaryCountsOnlyDetectionsNeverAlerted(t *testing.T) {
	for _, tc := range []struct {
		name    string
		then    func(h *harness) []alert.Outbox
		summary string
	}{
		{"alerted", (*harness).alerts, ""},
		{"alert failed", (*harness).failAlerts, "One: 1 more detection this hour — see the Detections page"},
		{"became critical", func(h *harness) []alert.Outbox { return h.alerts() }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, false)
			h.only(t, oneRule(siem.SevHigh))
			for i := range 6 {
				h.feed(sshFail(time.Duration(i)*time.Second, ipv4(i)))
			}
			if tc.name == "became critical" {
				h.alerts()
				h.only(t, oneRule(siem.SevCritical))
			} else {
				h.failAlerts() // the 5 raised fail for good: their slots are free again
			}
			h.feed(sshFail(10*time.Second, ipv4(5))) // the one counted fires again
			if got := tc.then(h); len(got) != 1 || got[0].DedupeKey != "siem:custom.one:"+ipv4(5) {
				t.Fatalf("individual alert %+v", got)
			}
			h.clk.set(t0.Add(time.Hour))
			h.e.sendCaps(false)
			got := h.alerts()
			switch {
			case tc.summary == "" && len(got) != 0:
				t.Fatalf("summary %+v, want none", got)
			case tc.summary != "" && (len(got) != 1 || got[0].Summary != tc.summary):
				t.Fatalf("summary %+v, want %q", got, tc.summary)
			}
		})
	}
}

// 8. A past hour's summary that couldn't be queued is kept for the next try, also when the rule
// alerts again in the new hour.
func TestPastSummaryKeptUntilQueued(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, oneRule(siem.SevHigh))
	for i := range 6 {
		h.feed(sshFail(time.Duration(i)*time.Second, ipv4(i)))
	}
	h.alerts()
	h.clk.set(t0.Add(time.Hour))
	for full := false; !full; {
		select {
		case h.e.alerts <- &alertJob{}:
		default:
			full = true
		}
	}
	h.e.sendCaps(false)                               // the queue is full: kept
	h.feed(sshFail(time.Hour+time.Second, ipv4(100))) // the rule alerts in the new hour (dropped too)
	for len(h.e.alerts) > 0 {
		<-h.e.alerts
	}
	h.e.sendCaps(false)
	got := h.alerts()
	if len(got) != 1 || got[0].DedupeKey != "siem-cap:custom.one" ||
		got[0].Summary != "One: 1 more detection this hour — see the Detections page" {
		t.Fatalf("the past hour's summary: %+v", got)
	}
	// The new hour's alert, dropped while the queue was full, goes on the key's next firing.
	h.feed(sshFail(time.Hour+2*time.Second, ipv4(100)))
	if got := h.alerts(); len(got) != 1 || got[0].DedupeKey != "siem:custom.one:"+ipv4(100) {
		t.Fatalf("new hour: %+v", got)
	}
}
