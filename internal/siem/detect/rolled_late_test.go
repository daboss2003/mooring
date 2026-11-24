package detect

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
)

// kill closes the engine without the shutdown pass or a save, then opens a new one at at.
func (h *harness) kill(t *testing.T, at time.Time, rs ...siem.Rule) {
	t.Helper()
	if err := h.e.Close(); err != nil {
		t.Fatal(err)
	}
	h.clk.set(at)
	h.open(t)
	h.only(t, rs...)
}

// lateSummary is the summary of hour 12:00 (t0's) sent after a start in the next hour.
func lateSummary(n int) string {
	what := "detections"
	if n == 1 {
		what = "detection"
	}
	return fmt.Sprintf("One: %d more %s in the previous hour (2026-11-24 12:00–13:00 UTC) — see the Detections page", n, what)
}

func savedRolled(t *testing.T, h *harness, rule string) []byte {
	t.Helper()
	var b []byte
	if err := h.e.db.w.QueryRow(`SELECT rolled FROM rule_hours WHERE rule_id = ?`, rule).Scan(&b); err != nil {
		t.Fatal(err)
	}
	return b
}

// The keys counted in a rule's rollup hold across a restart within the hour: one counted before
// isn't counted again, a new one is; the next hour starts fresh.
func TestRolledKeysHeldAcrossRestart(t *testing.T) {
	h := newHarness(t, false)
	r := oneRule(siem.SevLow)
	h.only(t, r)
	for i := range newPerHour + 5 { // keys 50–54 rolled up
		h.feed(sshFail(time.Duration(i)*100*time.Millisecond, ipv4(i)))
	}
	if roll := rollupRows(t, h); len(roll) != 1 || roll[0][1] != 5 {
		t.Fatalf("rollup: %v", roll)
	}
	h.restartAt(t, t0.Add(10*time.Minute), r)
	for i := newPerHour; i < newPerHour+5; i++ {
		h.feed(sshFail(10*time.Minute+time.Duration(i)*time.Millisecond, ipv4(i)))
	}
	if roll := rollupRows(t, h); len(roll) != 1 || roll[0][1] != 5 {
		t.Fatalf("keys rolled up before the restart counted again: %v", roll)
	}
	h.feed(sshFail(11*time.Minute, ipv4(70)))
	if roll := rollupRows(t, h); roll[0][1] != 6 {
		t.Fatalf("a new key after the restart: %v", roll)
	}
	h.restartAt(t, t0.Add(20*time.Minute), r) // saved again with the new key
	h.feed(sshFail(20*time.Minute, ipv4(70)), sshFail(20*time.Minute+time.Second, ipv4(50)))
	h.feed(sshFail(21*time.Minute, ipv4(71)))
	if roll := rollupRows(t, h); len(roll) != 1 || roll[0][1] != 7 {
		t.Fatalf("after a second restart: %v", roll)
	}
	// Saved as keyed hashes: a version byte, the rollup's 16-byte key, 8 bytes a key.
	h.e.persist()
	b := savedRolled(t, h, "custom.one")
	if len(b) != 1+16+8*7 || bytes.Contains(b, []byte(ipv4(70))) {
		t.Fatalf("saved set: %d bytes", len(b))
	}
	first := rollupRows(t, h)[0]

	// The next hour: 50 new detections, then a key rolled up last hour counts in the new rollup.
	h.restartAt(t, t0.Add(time.Hour+time.Second), r)
	for i := 100; i < 100+newPerHour; i++ {
		h.feed(sshFail(time.Hour+time.Second+time.Duration(i)*time.Millisecond, ipv4(i)))
	}
	h.feed(sshFail(time.Hour+2*time.Minute, ipv4(50)))
	if rolls := rollupRows(t, h); len(rolls) != 2 || rolls[0] != first || rolls[1][1] != 1 {
		t.Fatalf("next hour: %v (last hour's %v)", rolls, first)
	}
	// The hour after, without a restart: the keys remembered (bounded in all) start again too.
	for i := 200; i < 200+newPerHour+2; i++ {
		h.feed(sshFail(2*time.Hour+time.Duration(i)*time.Millisecond, ipv4(i)))
	}
	if h.e.rolledN != 2 {
		t.Fatalf("keys remembered in the third hour: %d, want its 2", h.e.rolledN)
	}
}

// A damaged set is dropped (its keys count again) while the rollup row is kept, and what is read
// back stays within the bound on remembered keys.
func TestRolledKeysBoundedAndDamagedSet(t *testing.T) {
	h := newHarness(t, false)
	r := oneRule(siem.SevLow)
	h.only(t, r)
	for i := range newPerHour + 1 { // key 50 rolled up
		h.feed(sshFail(time.Duration(i)*100*time.Millisecond, ipv4(i)))
	}
	for _, tc := range []struct {
		name    string
		damage  func(b []byte) []byte
		counted bool // key 50 is counted again after the restart
	}{
		{"intact", func(b []byte) []byte { return b }, false},
		{"too short", func([]byte) []byte { return []byte{1, 2, 3} }, true},
		{"other version", func(b []byte) []byte { return append([]byte{2}, b[1:]...) }, true},
		{"not whole hashes", func(b []byte) []byte { return append(b, make([]byte, 7)...) }, true},
	} {
		h.e.flush(true)
		h.e.persist()
		bad := tc.damage(savedRolled(t, h, "custom.one"))
		if _, err := h.e.db.w.Exec(`UPDATE rule_hours SET rolled = ?`, bad); err != nil {
			t.Fatal(err)
		}
		before := rollupRows(t, h)
		h.kill(t, h.clk.now().Add(time.Second), r)
		h.feed(sshFail(h.clk.now().Sub(t0), ipv4(newPerHour)))
		after := rollupRows(t, h)
		want := before[0][1]
		if tc.counted {
			want++
		}
		if len(after) != 1 || after[0][0] != before[0][0] || after[0][1] != want || h.e.rolledN != 1 {
			t.Fatalf("%s: rollup %v → %v (want count %d), %d keys", tc.name, before, after, want, h.e.rolledN)
		}
	}

	h.e.persist()
	big := append([]byte{1}, make([]byte, 16)...)
	for i := range maxRolledKeys + 10 {
		big = binary.LittleEndian.AppendUint64(big, uint64(i)+1)
	}
	if _, err := h.e.db.w.Exec(`UPDATE rule_hours SET rolled = ?`, big); err != nil {
		t.Fatal(err)
	}
	h.kill(t, h.clk.now().Add(time.Second), r)
	if h.e.rolledN != maxRolledKeys || len(h.e.rollups) != 1 {
		t.Fatalf("read back: %d keys, %d rollups, want %d and 1", h.e.rolledN, len(h.e.rollups), maxRolledKeys)
	}
}

// Killed across the hour boundary (no shutdown summary): the previous hour's summary is sent once
// at the next start, saying which hour it covers; once settled it is saved as sent, so a start
// after another kill doesn't send it again. A summary sent in time is not sent again either.
func TestLateSummaryAfterKillAcrossTheHour(t *testing.T) {
	h := newHarness(t, false)
	r := oneRule(siem.SevHigh)
	h.only(t, r)
	for i := range alertsPerHour + 3 {
		h.feed(sshFail(time.Duration(i)*time.Second, ipv4(i)))
	}
	h.alerts()
	h.restartAt(t, t0.Add(time.Hour+30*time.Second), r) // saved at 12:00:07, killed, started at 13:00:30
	h.e.sendCaps(false)
	want := alert.Outbox{Target: TargetSIEM, Kind: AlertKind, Level: alert.LevelWarning, Transition: "firing",
		Summary: lateSummary(3), DedupeKey: "siem-cap:custom.one"}
	if got := h.alerts(); len(got) != 1 || got[0] != want {
		t.Fatalf("late summary: %+v\nwant %+v", got, want)
	}
	h.e.sendCaps(false)
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("sent twice: %+v", got)
	}
	h.e.saveHourIfDirty() // the next write tick
	h.kill(t, t0.Add(time.Hour+time.Minute), r)
	h.e.sendCaps(false)
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("sent again after another kill: %+v", got)
	}

	// The summary sent in time at 13:00, then a kill: nothing late.
	h2 := newHarness(t, false)
	h2.only(t, r)
	for i := range alertsPerHour + 2 {
		h2.feed(sshFail(time.Duration(i)*time.Second, ipv4(i)))
	}
	h2.alerts()
	h2.e.persist() // 12:00:06
	h2.clk.set(t0.Add(time.Hour + time.Second))
	h2.e.sendCaps(false)
	if got := h2.alerts(); len(got) != 1 || got[0].Summary != summaryOf(2) {
		t.Fatalf("summary in time: %+v", got)
	}
	h2.e.saveHourIfDirty()
	h2.kill(t, t0.Add(time.Hour+2*time.Minute), r)
	h2.e.sendCaps(false)
	if got := h2.alerts(); len(got) != 0 {
		t.Fatalf("a summary sent in time sent again late: %+v", got)
	}
}

// A clean stop sends the hour's summary then: nothing is sent late at the next start (a kill at
// the same time does send it late).
func TestNoLateSummaryAfterCleanStop(t *testing.T) {
	for _, clean := range []bool{true, false} {
		h := newHarness(t, false)
		r := oneRule(siem.SevHigh)
		h.only(t, r)
		for i := range alertsPerHour + 3 {
			h.feed(sshFail(time.Duration(i)*time.Second, ipv4(i)))
		}
		h.alerts()
		h.clk.set(t0.Add(55 * time.Minute))
		if clean {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			h.e.Run(ctx)
			if n := len(h.al.all()); n != 1 {
				t.Fatalf("alerts at shutdown: %d, want the summary", n)
			}
		} else {
			h.e.flush(true)
			h.e.persist() // the periodic save at 12:55, then the kill
		}
		h.kill(t, t0.Add(time.Hour+30*time.Second), r)
		h.e.sendCaps(false)
		got := h.alerts()
		if clean && len(got) != 0 {
			t.Fatalf("late summary after a clean stop: %+v", got)
		}
		if !clean && (len(got) != 1 || got[0].Summary != lateSummary(3)) {
			t.Fatalf("late summary after a kill: %+v", got)
		}
	}
}

// No late summary for a rule snoozed, switched off or deleted when it would be sent; an app's /ops
// alert (no rule here to switch off) always gets one.
func TestLateSummaryRuleChecks(t *testing.T) {
	for name, change := range map[string]func(t *testing.T, h *harness){
		"snoozed": func(t *testing.T, h *harness) {
			x := oneRule(siem.SevHigh)
			x.SnoozedUntil = t0.Add(24 * time.Hour)
			h.only(t, x)
		},
		"switched off": func(_ *testing.T, h *harness) { h.e.rules.Load().byID["custom.one"].r.Enabled = false },
		"deleted":      func(t *testing.T, h *harness) { h.only(t, actorRule(siem.SevHigh)) },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, false)
			r := oneRule(siem.SevHigh)
			h.only(t, r)
			for i := range alertsPerHour + 3 {
				h.feed(sshFail(time.Duration(i)*time.Second, ipv4(i)))
			}
			h.alerts()
			h.restartAt(t, t0.Add(time.Hour+30*time.Second), r)
			change(t, h)
			h.e.sendCaps(false)
			if got := h.alerts(); len(got) != 0 {
				t.Fatalf("late summary: %+v", got)
			}
			// Dropped for good: not sent after the rule is back on and another kill.
			h.e.saveHourIfDirty()
			h.kill(t, t0.Add(time.Hour+time.Minute), r)
			h.e.sendCaps(false)
			if got := h.alerts(); len(got) != 0 {
				t.Fatalf("late summary after the rule is back: %+v", got)
			}
		})
	}
	t.Run("app ops alert", func(t *testing.T) {
		h := newHarness(t, false)
		h.only(t, oneRule(siem.SevHigh))
		for i := range alertsPerHour + 2 {
			h.e.report(siem.Detection{RuleID: "ops:shop/web/queue", RuleName: "Queue depth", Severity: siem.SevHigh,
				Key: ipv4(i), App: "shop", Service: "web", Summary: "queue depth 900", Last: t0.Add(time.Duration(i) * time.Second)})
		}
		if got := h.alerts(); len(got) != alertsPerHour {
			t.Fatalf("%d alerts", len(got))
		}
		h.restartAt(t, t0.Add(time.Hour+30*time.Second), oneRule(siem.SevHigh))
		h.e.sendCaps(false)
		got := h.alerts()
		if len(got) != 1 || got[0].DedupeKey != "siem-cap:ops:shop/web/queue" || got[0].Target != "shop/web" ||
			got[0].Summary != "Queue depth: 2 more detections in the previous hour (2026-11-24 12:00–13:00 UTC) — see the Detections page" {
			t.Fatalf("late /ops summary: %+v", got)
		}
	})
}

// Only exactly the previous clock hour: a start two hours later, or with the clock behind the
// save, sends nothing. A summary still owed survives another save and kill within the hour.
func TestLateSummaryOnlyForThePreviousHour(t *testing.T) {
	setup := func(t *testing.T) (*harness, siem.Rule) {
		h := newHarness(t, false)
		r := oneRule(siem.SevHigh)
		h.only(t, r)
		for i := range alertsPerHour + 3 {
			h.feed(sshFail(time.Duration(i)*time.Second, ipv4(i)))
		}
		h.alerts()
		return h, r
	}
	for name, at := range map[string]time.Time{"two hours later": t0.Add(2*time.Hour + 30*time.Second),
		"clock behind": t0.Add(-30 * time.Minute)} {
		t.Run(name, func(t *testing.T) {
			h, r := setup(t)
			h.restartAt(t, at, r)
			h.e.sendCaps(true)
			if got := h.alerts(); len(got) != 0 {
				t.Fatalf("summary: %+v", got)
			}
		})
	}
	t.Run("owed across another kill", func(t *testing.T) {
		h, r := setup(t)
		h.restartAt(t, t0.Add(time.Hour+10*time.Second), r) // started, not sent yet
		h.restartAt(t, t0.Add(time.Hour+20*time.Minute), r) // the periodic save, then a kill
		h.e.sendCaps(false)
		if got := h.alerts(); len(got) != 1 || got[0].Summary != lateSummary(3) {
			t.Fatalf("summary owed across a second kill: %+v", got)
		}
	})
}

// A late summary that fails is retried like any summary (the alert worker's tries).
func TestLateSummaryRetried(t *testing.T) {
	fa := &flakyAlerter{}
	h := newHarness(t, false, func(o *Options) { o.Alerter = fa })
	r := oneRule(siem.SevHigh)
	h.only(t, r)
	for i := range alertsPerHour + 3 {
		h.feed(sshFail(time.Duration(i)*time.Second, ipv4(i)))
	}
	h.alerts()
	h.restartAt(t, t0.Add(time.Hour+30*time.Second), r)
	h.e.lim.alertBackoff = []time.Duration{5 * time.Millisecond, 10 * time.Millisecond}
	fa.mu.Lock()
	fa.fails = fa.n + 1 // the next attempt fails
	fa.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.e.Run(ctx); close(done) }()
	waitFor(t, "the late summary", func() bool { _, sent := fa.counts(); return sent == 1 })
	// Once recorded, the write tick saves the counters without it.
	waitFor(t, "the hour's counters saved", func() bool {
		var n int
		err := h.e.db.r.QueryRow(`SELECT COUNT(*) FROM rule_hours WHERE hour = ?`, t0.Unix()).Scan(&n)
		return err == nil && n == 0
	})
	cancel()
	<-done
	attempts, sent := fa.counts()
	fa.mu.Lock()
	got := fa.got[0].Summary
	fa.mu.Unlock()
	if attempts != 2 || sent != 1 || got != lateSummary(3) {
		t.Fatalf("%d attempts, %d sent: %q", attempts, sent, got)
	}
	h.kill(t, t0.Add(time.Hour+time.Minute), r)
	h.e.sendCaps(false)
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("sent again: %+v", got)
	}
}
