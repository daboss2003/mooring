package detect

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
)

// rollupRows returns the stored rollup detections (id, count), after writing what is pending.
func rollupRows(t *testing.T, h *harness) [][2]int64 {
	t.Helper()
	h.e.flush(true)
	rows, err := h.e.db.w.Query(`SELECT id, count FROM detections WHERE rollup = 1 ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out [][2]int64
	for rows.Next() {
		var r [2]int64
		if err := rows.Scan(&r[0], &r[1]); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// restartAt saves the engine's state (the periodic persist) and opens a new engine with the clock
// at at: a stop without the shutdown pass (no summary sent).
func (h *harness) restartAt(t *testing.T, at time.Time, rs ...siem.Rule) {
	t.Helper()
	h.e.flush(true)
	h.e.persist()
	if err := h.e.Close(); err != nil {
		t.Fatal(err)
	}
	h.clk.set(at)
	h.open(t)
	h.only(t, rs...)
}

func summaryOf(n int) string {
	what := "detections"
	if n == 1 {
		what = "detection"
	}
	return fmt.Sprintf("One: %d more %s this hour — see the Detections page", n, what)
}

func nonRollups(ds []siem.Detection) int {
	n := 0
	for _, d := range ds {
		if d.Key != RollupKey {
			n++
		}
	}
	return n
}

// The per-rule hourly limits hold across a restart within the hour: no 6th high alert, no 51st new
// detection (the hour's rollup row goes on counting), and the summary at the end of the hour counts
// every high detection never sent on its own once, those from before the restart too.
func TestHourlyCapsHoldAcrossRestart(t *testing.T) {
	h := newHarness(t, false)
	r := oneRule(siem.SevHigh)
	h.only(t, r)
	for i := range newPerHour + 5 { // 50 new detections, 5 keys rolled up
		h.feed(sshFail(time.Duration(i)*time.Second, ipv4(i)))
	}
	if got := h.alerts(); len(got) != alertsPerHour {
		t.Fatalf("%d alerts before the restart, want %d", len(got), alertsPerHour)
	}
	before := rollupRows(t, h)
	if len(before) != 1 || before[0][1] != 5 {
		t.Fatalf("rollup before the restart: %v", before)
	}

	h.restartAt(t, t0.Add(2*time.Minute), r)
	for i := newPerHour + 5; i < newPerHour+8; i++ { // 3 more keys
		h.feed(sshFail(2*time.Minute+time.Duration(i)*time.Millisecond, ipv4(i)))
	}
	h.feed(sshFail(3*time.Minute, ipv4(20))) // counted for the summary before the restart
	h.feed(sshFail(3*time.Minute, ipv4(0)))  // alerted before the restart
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("alerts after a restart within the hour: %+v", got)
	}
	ds := h.detections(t, "custom.one")
	if n := nonRollups(ds); n != newPerHour {
		t.Fatalf("%d detections after a restart within the hour, want %d", n, newPerHour)
	}
	after := rollupRows(t, h)
	if len(after) != 1 || after[0][0] != before[0][0] || after[0][1] != 8 {
		t.Fatalf("rollup after the restart: %v, want row %d with count 8", after, before[0][0])
	}

	// A second restart within the hour changes nothing either.
	h.restartAt(t, t0.Add(4*time.Minute), r)
	h.feed(sshFail(4*time.Minute+time.Second, ipv4(900)))
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("alerts after a second restart: %+v", got)
	}
	if after := rollupRows(t, h); len(after) != 1 || after[0][0] != before[0][0] || after[0][1] != 9 {
		t.Fatalf("rollup after a second restart: %v", after)
	}

	// The hour ends: one summary for 45 detections and the rollup.
	h.clk.set(t0.Add(time.Hour))
	h.e.sendCaps(false)
	want := alert.Outbox{Target: TargetSIEM, Kind: AlertKind, Level: alert.LevelWarning, Transition: "firing",
		Summary: summaryOf(newPerHour - alertsPerHour + 1), DedupeKey: "siem-cap:custom.one"}
	if got := h.alerts(); len(got) != 1 || got[0] != want {
		t.Fatalf("summary at the end of the hour: %+v\nwant %+v", got, want)
	}
	// The next hour starts at 0.
	for i := 1000; i < 1000+alertsPerHour+1; i++ {
		h.feed(sshFail(time.Hour+time.Duration(i)*time.Millisecond, ipv4(i)))
	}
	if got := h.alerts(); len(got) != alertsPerHour {
		t.Fatalf("next hour: %d alerts, want %d", len(got), alertsPerHour)
	}
}

// Saved counters are for the hour they were saved in: a restart in a later hour starts at 0 (and a
// new rollup row), and a later save removes them.
func TestHourlyCapsRestartNextHourStartsFresh(t *testing.T) {
	h := newHarness(t, false)
	r := oneRule(siem.SevHigh)
	h.only(t, r)
	for i := range newPerHour + 5 {
		h.feed(sshFail(time.Duration(i)*time.Second, ipv4(i)))
	}
	h.alerts()
	first := rollupRows(t, h)

	h.restartAt(t, t0.Add(time.Hour+10*time.Second), r)
	for i := 100; i < 100+newPerHour+2; i++ {
		h.feed(sshFail(time.Hour+10*time.Second+time.Duration(i)*time.Millisecond, ipv4(i)))
	}
	// The new hour's 5, and hour 12's summary, owed after the kill and sent late.
	got := byDedupe(h.alerts())
	if len(got) != alertsPerHour+1 || got["siem-cap:custom.one"] != 1 {
		t.Fatalf("next hour after a restart: %v, want %d alerts and the late summary", got, alertsPerHour)
	}
	ds := h.detections(t, "custom.one")
	if n := nonRollups(ds); n != 2*newPerHour {
		t.Fatalf("%d detections, want %d (50 in each hour)", n, 2*newPerHour)
	}
	if rolls := rollupRows(t, h); len(rolls) != 2 || rolls[0] != first[0] || rolls[1][1] != 2 {
		t.Fatalf("rollups %v: want hour 12's %v kept and a new one with 2 keys", rolls, first)
	}
	// Nothing past the hour is kept: a save in a quiet hour leaves no counters.
	h.clk.set(t0.Add(3 * time.Hour))
	h.e.persist()
	var n int
	if err := h.e.db.w.QueryRow(`SELECT COUNT(*) FROM rule_hours`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("saved counters after a quiet hour: %d (%v)", n, err)
	}
}

// A clock step never brings back counters: ones saved for an hour ahead of the clock (it was
// ahead, then corrected) are not used, nor later when the clock reaches that hour. A stored count
// below 0 counts as 0, and the counters read back stay within the in-memory bounds.
func TestHourlyCapsClockStepAndBadRows(t *testing.T) {
	h := newHarness(t, false)
	r := oneRule(siem.SevHigh)
	h.only(t, r)
	h.clk.set(t0.Add(3 * time.Hour)) // the clock is ahead
	for i := range alertsPerHour + 1 {
		h.feed(sshFail(3*time.Hour+time.Duration(i)*time.Second, ipv4(i)))
	}
	if got := h.alerts(); len(got) != alertsPerHour {
		t.Fatalf("%d alerts", len(got))
	}
	h.restartAt(t, t0.Add(10*time.Minute), r) // corrected
	for i := 10; i < 10+alertsPerHour+1; i++ {
		h.feed(sshFail(10*time.Minute+time.Duration(i)*time.Second, ipv4(i)))
	}
	if got := h.alerts(); len(got) != alertsPerHour {
		t.Fatalf("after the clock went back: %d alerts, want %d (counters of a later hour unused)", len(got), alertsPerHour)
	}
	h.clk.set(t0.Add(3*time.Hour + time.Minute)) // the saved hour again, same process
	h.feed(sshFail(3*time.Hour+time.Minute, ipv4(50)))
	if got := byDedupe(h.alerts()); len(got) != 2 || got["siem:custom.one:"+ipv4(50)] != 1 || got["siem-cap:custom.one"] != 1 {
		t.Fatalf("at the saved hour again: %v, want the key's alert and the past hour's summary", got)
	}

	// A row with counts below 0 (and a rollup ID that is no row's) counts as none.
	h.restartAt(t, t0.Add(5*time.Hour), r)
	h.e.persist()
	insert := func(hour time.Time, id string, newCount, rollupID, sent, more int) {
		t.Helper()
		if _, err := h.e.db.w.Exec(`INSERT INTO rule_hours(rule_id, hour, new_count, rollup_id, sent, more, source, name, target)
			VALUES (?, ?, ?, ?, ?, ?, 'siem', 'One', 'security-logs')`, id, hour.Unix(), newCount, rollupID, sent, more); err != nil {
			t.Fatal(err)
		}
	}
	insert(t0.Add(5*time.Hour), "custom.one", -40, -3, -7, -2)
	if err := h.e.Close(); err != nil { // no save: it would replace the row
		t.Fatal(err)
	}
	h.open(t)
	h.only(t, r)
	for i := range newPerHour + 1 {
		h.feed(sshFail(5*time.Hour+time.Duration(i)*time.Second, ipv4(2000+i)))
	}
	if got := h.alerts(); len(got) != alertsPerHour {
		t.Fatalf("%d alerts with counts below 0 stored, want %d", len(got), alertsPerHour)
	}
	// 6 at the hour ahead, 6 + 1 after the clock went back, 50 now.
	if n := nonRollups(h.detections(t, "custom.one")); n != 2*(alertsPerHour+1)+1+newPerHour {
		t.Fatalf("%d detections in all", n)
	}
	h.clk.set(t0.Add(6 * time.Hour))
	h.e.sendCaps(false)
	if got := h.alerts(); len(got) != 1 || got[0].Summary != summaryOf(newPerHour-alertsPerHour+1) {
		t.Fatalf("summary: %+v", got)
	}

	// More rules than the engine keeps counters for: what is read back stays within its bounds.
	h.e.persist()
	for i := range maxRuleHours + 10 {
		insert(t0.Add(6*time.Hour), fmt.Sprint("custom.x", i), 1, 0, 1, 1)
	}
	if err := h.e.Close(); err != nil {
		t.Fatal(err)
	}
	h.open(t)
	if len(h.e.newRows) != maxRuleHours || len(h.e.caps) != maxRuleHours {
		t.Fatalf("counters read back: %d new, %d caps, want %d each", len(h.e.newRows), len(h.e.caps), maxRuleHours)
	}
}

// At shutdown the current hour's summary goes out at once; after a restart within the hour the
// rule still has no alert left, and the summary at the end of the hour counts only the detections
// not in the one sent at the stop.
func TestShutdownSummaryNotCountedAgainAfterRestart(t *testing.T) {
	h := newHarness(t, false)
	r := oneRule(siem.SevHigh)
	h.only(t, r)
	for i := range alertsPerHour + 3 {
		h.feed(sshFail(time.Duration(i)*time.Second, ipv4(i)))
	}
	if got := h.alerts(); len(got) != alertsPerHour {
		t.Fatalf("%d alerts", len(got))
	}
	h.clk.set(t0.Add(5 * time.Minute))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.e.Run(ctx)
	var sums []string
	for _, o := range h.al.all() {
		if o.DedupeKey == "siem-cap:custom.one" {
			sums = append(sums, o.Summary)
		}
	}
	if len(sums) != 1 || sums[0] != summaryOf(3) {
		t.Fatalf("summaries at shutdown: %q", sums)
	}
	if err := h.e.Close(); err != nil {
		t.Fatal(err)
	}
	h.clk.set(t0.Add(10 * time.Minute))
	h.open(t)
	h.only(t, r)
	h.feed(sshFail(10*time.Minute, ipv4(6))) // in the stop's summary: not counted again
	for i := 20; i < 22; i++ {
		h.feed(sshFail(10*time.Minute+time.Duration(i)*time.Second, ipv4(i)))
	}
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("alerts after the restart: %+v", got)
	}
	h.clk.set(t0.Add(time.Hour))
	h.e.sendCaps(false)
	if got := h.alerts(); len(got) != 1 || got[0].Summary != summaryOf(2) {
		t.Fatalf("summary at the end of the hour: %+v, want %q", got, summaryOf(2))
	}
}

// A detection counted again for the summary after its own alert failed (it had been written as not
// counted) is stored as counted: a firing after a restart doesn't count it twice.
func TestRecountedDetectionStaysCountedAcrossRestart(t *testing.T) {
	h := newHarness(t, false)
	r := oneRule(siem.SevHigh)
	h.only(t, r)
	drain := func(fail string) int {
		n := 0
		for {
			select {
			case j := <-h.e.alerts:
				n++
				h.e.finishAlert(alertResult{job: j, ok: j.o.DedupeKey != fail})
			default:
				return n
			}
		}
	}
	for i := range alertsPerHour + 1 { // the 6th is counted for the summary
		h.feed(sshFail(time.Duration(i)*time.Second, ipv4(i)))
	}
	drain("siem:custom.one:" + ipv4(4)) // one alert fails: its place is free again
	h.feed(sshFail(10*time.Second, ipv4(5)))
	h.e.flush(true) // stored as alerted on its own, no longer counted
	if n := drain("siem:custom.one:" + ipv4(5)); n != 1 {
		t.Fatalf("%d alerts for the counted key, want 1", n)
	}
	h.restartAt(t, t0.Add(20*time.Minute), r)
	h.feed(sshFail(20*time.Minute, ipv4(40))) // takes the free place
	h.feed(sshFail(21*time.Minute, ipv4(5)))  // counted before the restart
	if got := h.alerts(); len(got) != 1 || got[0].DedupeKey != "siem:custom.one:"+ipv4(40) {
		t.Fatalf("alerts after the restart: %+v", got)
	}
	h.clk.set(t0.Add(time.Hour))
	h.e.sendCaps(false)
	if got := h.alerts(); len(got) != 1 || got[0].Summary != summaryOf(1) {
		t.Fatalf("summary: %+v, want %q", got, summaryOf(1))
	}
}

// A summary sent at shutdown that couldn't be recorded is owed again: after a restart within the
// hour, the summary at the end of the hour counts its detections.
func TestFailedShutdownSummaryOwedAfterRestart(t *testing.T) {
	h := newHarness(t, false)
	r := oneRule(siem.SevHigh)
	h.only(t, r)
	for i := range alertsPerHour + 3 {
		h.feed(sshFail(time.Duration(i)*time.Second, ipv4(i)))
	}
	h.alerts()
	h.e.sendCaps(true)
	if got := h.failAlerts(); len(got) != 1 || got[0].Summary != summaryOf(3) {
		t.Fatalf("summary at shutdown: %+v", got)
	}
	h.restartAt(t, t0.Add(20*time.Minute), r)
	h.feed(sshFail(20*time.Minute, ipv4(30)))
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("alerts after the restart: %+v", got)
	}
	h.clk.set(t0.Add(time.Hour))
	h.e.sendCaps(false)
	if got := h.alerts(); len(got) != 1 || got[0].Summary != summaryOf(4) {
		t.Fatalf("summary at the end of the hour: %+v, want %q", got, summaryOf(4))
	}
}
