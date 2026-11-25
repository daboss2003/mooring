package detect

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
)

func TestSIEMEventsAreIgnored(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, siem.Rule{ID: "custom.any", Type: siem.RuleThreshold, Query: "lvl>=info", Count: 1, Window: time.Hour})
	h.feed(ev(0, siem.SrcSIEM, KindDetection, "", "203.0.113.7", "", map[string]any{"rule": "x"}),
		ev(time.Second, siem.SrcSIEM, siem.KindDropped, "", "", "", nil))
	h.e.Subscriber()(ev(2*time.Second, siem.SrcSIEM, KindDetection, "", "", "", nil))
	if n := len(h.e.in); n != 0 {
		t.Fatalf("subscriber queued %d siem events", n)
	}
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("a siem event was evaluated: %+v", ds)
	}
	h.feed(ev(3*time.Second, siem.SrcApp, "log", "", "", "", nil))
	if ds := h.all(t); len(ds) != 1 {
		t.Fatalf("control: an app event should match: %+v", ds)
	}
}

func TestOldAndFutureEventsAreIgnored(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, thresholdRule(1, time.Hour))
	h.clk.set(t0.Add(48 * time.Hour))
	now := h.clk.now()
	for _, ts := range []time.Time{now.Add(-24*time.Hour - time.Second), now.Add(5*time.Minute + time.Second)} {
		e := sshFail(0, "203.0.113.7")
		e.TS = ts
		h.feedRaw(e)
		h.e.Subscriber()(e)
	}
	if n := len(h.e.in); n != 0 {
		t.Fatalf("subscriber queued %d out-of-time events", n)
	}
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("replayed or future event evaluated: %+v", ds)
	}
	for i, ts := range []time.Time{now.Add(-23 * time.Hour), now.Add(4 * time.Minute)} {
		e := sshFail(0, fmt.Sprint("203.0.113.", 10+i))
		e.TS = ts
		h.feedRaw(e)
	}
	if ds := h.all(t); len(ds) != 2 {
		t.Fatalf("events inside the bounds: %d detections, want 2", len(ds))
	}
}

func TestSubscriberNeverBlocks(t *testing.T) {
	h := newHarness(t, false)
	sub := h.e.Subscriber()
	start := time.Now()
	for i := range 20000 {
		sub(sshFail(time.Duration(i)*time.Millisecond, "203.0.113.7"))
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("20000 subscriber calls took %s", d)
	}
	if got := h.e.Stats().Dropped; got != 20000-queueSize {
		t.Fatalf("dropped %d, want %d", got, 20000-queueSize)
	}
}

// The engine goroutine stuck (an Emit that never returns): the pipeline still never waits.
func TestSubscriberNeverBlocksWhenEngineIsStuck(t *testing.T) {
	stuck := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(stuck) })
	entered := make(chan struct{}, 1)
	h := newHarness(t, false, func(o *Options) {
		o.Emit = func(siem.Event) bool {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-stuck
			return true
		}
	})
	h.only(t, thresholdRule(1, time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.e.Run(ctx); close(done) }()
	sub := h.e.Subscriber()
	sub(sshFail(0, "203.0.113.7"))
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the engine never emitted")
	}
	start := time.Now()
	for i := range 20000 {
		sub(sshFail(time.Duration(i)*time.Millisecond, "203.0.113.8"))
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("subscriber waited on a stuck engine: %s", d)
	}
	if h.e.Stats().Dropped == 0 {
		t.Fatal("nothing dropped although the engine is stuck")
	}
	cancel()
	release.Do(func() { close(stuck) })
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
}

func TestSubscriberCopiesFields(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, siem.Rule{ID: "custom.f", Type: siem.RuleThreshold, Query: "f.user:root", GroupBy: "ip", Count: 1, Window: time.Hour})
	e := sshFail(0, "203.0.113.7")
	h.e.Subscriber()(e)
	e.F["user"] = "changed by another subscriber"
	queued := <-h.e.in
	h.e.process(&queued)
	if ds := h.all(t); len(ds) != 1 {
		t.Fatalf("the engine saw the shared map changed: %+v", ds)
	}
}

// A flood of attacker-chosen keys and values stays within the bounds.
func TestFloodStaysBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("flood")
	}
	h := newHarness(t, false)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	n := 60000
	if raceOn {
		n = 15000 // still more keys than maxKeys
	}
	big := strings.Repeat("x", 200)
	for i := range n {
		at := time.Duration(i) * time.Millisecond
		ip := fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)
		u := fmt.Sprintf("user-%d-%s", i, big)
		f1 := sshFail(at, ip)
		f1.Actor = u
		inv := invalidUser(at, "203.0.113.7", u)
		req := ev(at, siem.SrcEdge, siem.KindHTTPRequest, "", ip, "", map[string]any{"status": float64(404), "host": "h" + u})
		req.Geo = geo("NG", "Lagos", 6.45, 3.39)
		req.Geo.Lists = []string{"spamhaus-drop"}
		login := ev(at, siem.SrcMooring, "mooring.login", siem.OutSuccess, ip, u, nil)
		login.Geo = geo(fmt.Sprintf("C%d", i%5000), "X", float64(i%180-90), float64(i%360-180))
		h.feed(f1, inv, req, login)
		if i%500 == 0 {
			h.e.flush(false) // Run's write tick
		}
	}
	h.e.flush(true)
	for id, st := range h.e.states {
		if len(st.keys) > maxKeys || st.lru.Len()+st.plru.Len() != len(st.keys) || st.pEntries > maxProtEntries {
			t.Errorf("rule %s: %d keys (lists %d+%d), cap %d", id, len(st.keys), st.lru.Len(), st.plru.Len(), maxKeys)
		}
		if st.entries > maxEntries {
			t.Errorf("rule %s: %d entries, cap %d", id, st.entries, maxEntries)
		}
		sum := 0
		for _, el := range st.keys {
			sum += el.Value.(*keyState).cost
		}
		if sum != st.entries {
			t.Errorf("rule %s: budget %d but keys cost %d", id, st.entries, sum)
		}
		if st.nv != nil && (len(st.nv.pairs) > maxSeen || len(st.nv.keys) > maxSeen) {
			t.Errorf("rule %s: seen %d/%d", id, len(st.nv.pairs), len(st.nv.keys))
		}
	}
	if len(h.e.active) > maxActive || h.e.actLRU.Len() != len(h.e.active) {
		t.Errorf("active detections %d (lru %d), cap %d", len(h.e.active), h.e.actLRU.Len(), maxActive)
	}
	if len(h.e.dirty) != 0 || len(h.e.parked) != 0 || h.e.rolledN > maxRolledKeys || len(h.e.newRows) > maxRuleHours ||
		len(h.e.cooldown) > maxCooldowns {
		t.Errorf("dirty %d parked %d rolled %d rules %d cooldowns %d", len(h.e.dirty), len(h.e.parked), h.e.rolledN,
			len(h.e.newRows), len(h.e.cooldown))
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > 300<<20 {
		t.Errorf("heap grew %d MiB over the flood", grew>>20)
	}
}

// Many keys with long windows share the rule's entry budget: the least recently used go.
func TestEntriesBudget(t *testing.T) {
	st := newRuleState("sig")
	capN := ringCap(maxCount)
	for k := range 100 {
		for i := range 5000 {
			ks := st.key(fmt.Sprint("k", k))
			ks.ring.add(int64(k*5000+i)*int64(time.Second), 1, 7*24*time.Hour, capN)
			st.charge(ks)
		}
	}
	if st.entries > maxEntries {
		t.Fatalf("%d entries, budget %d", st.entries, maxEntries)
	}
	if len(st.keys) >= 100 || len(st.keys) < maxEntries/5001 {
		t.Fatalf("%d keys kept", len(st.keys))
	}
	if _, ok := st.keys["k99"]; !ok {
		t.Fatal("the most recent key was evicted")
	}
}

// One key with a huge Count keeps a bounded window (merged per second, capped).
func TestRingBounded(t *testing.T) {
	var r ring
	for i := range 100000 {
		r.add(int64(i)*int64(time.Second), 1, 7*24*time.Hour, ringCap(10))
	}
	if r.len() > ringCap(10) || r.sum < 10 {
		t.Fatalf("ring len %d sum %d, cap %d", r.len(), r.sum, ringCap(10))
	}
	var r2 ring
	for i := range 100000 {
		r2.add(int64(i)*int64(time.Millisecond), 1, time.Hour, ringCap(maxCount))
	}
	if r2.len() > 101 || r2.sum != 100000 {
		t.Fatalf("same-second events: len %d sum %d", r2.len(), r2.sum)
	}
}

func TestCoalescing(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, thresholdRule(2, 10*time.Minute))
	ip := "203.0.113.7"
	for i := range 30 {
		h.feed(sshFail(time.Duration(i)*time.Minute, ip)) // fires every 2 events for 30 minutes
	}
	ds := h.all(t)
	if len(ds) != 1 {
		t.Fatalf("one ongoing attack: %d detections", len(ds))
	}
	d := ds[0]
	if d.Count != 30 || !d.First.Equal(t0.Add(time.Minute)) || !d.Last.Equal(t0.Add(29*time.Minute)) {
		t.Fatalf("coalesced: count %d first %s last %s", d.Count, d.First, d.Last)
	}
	if len(d.Evidence) != siem.MaxEvidence {
		t.Fatalf("evidence %d, want %d", len(d.Evidence), siem.MaxEvidence)
	}
	for _, el := range h.e.active {
		if n := len(el.Value.(*activeDet).s.d.Evidence); n > siem.MaxEvidence {
			t.Fatalf("evidence in memory: %d", n)
		}
	}
	var raw string
	if err := h.e.db.r.QueryRow(`SELECT evidence FROM detections WHERE id = ?`, d.ID).Scan(&raw); err != nil ||
		strings.Count(raw, `"ts"`) != siem.MaxEvidence {
		t.Fatalf("stored evidence %q, %v", raw, err)
	}
	// Quiet for more than an hour (the window is shorter): a new detection.
	h.feed(sshFail(29*time.Minute+time.Hour+time.Second, ip), sshFail(29*time.Minute+time.Hour+2*time.Second, ip))
	if ds := h.all(t); len(ds) != 2 {
		t.Fatalf("after an hour of quiet: %d detections, want 2", len(ds))
	}
	// Within the hour: the same one.
	h2 := newHarness(t, false)
	h2.only(t, thresholdRule(2, 10*time.Minute))
	h2.feed(sshFail(0, ip), sshFail(time.Second, ip), sshFail(59*time.Minute, ip), sshFail(59*time.Minute+time.Second, ip))
	if ds := h2.all(t); len(ds) != 1 || ds[0].Count != 4 {
		t.Fatalf("second firing 59m later: %+v", ds)
	}
}

// The in-memory record is gone (restart, eviction): the stored one is updated.
func TestCoalescingAfterRestart(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, thresholdRule(1, 10*time.Minute))
	h.feed(sshFail(0, "203.0.113.7"))
	h.reopen(t)
	h.only(t, thresholdRule(1, 10*time.Minute))
	h.feed(sshFail(time.Minute, "203.0.113.7"))
	ds := h.all(t)
	if len(ds) != 1 || ds[0].Count != 2 {
		t.Fatalf("after a restart: %+v", ds)
	}
}

func TestEmittedEvent(t *testing.T) {
	h := newHarness(t, false)
	r := thresholdRule(3, 10*time.Minute)
	r.Severity, r.MITRE = siem.SevHigh, []string{"T1110.001", "T1078"}
	h.only(t, r)
	g := &siem.Geo{Country: "NG", City: "Lagos", ASN: 37148, Org: "Example"}
	for i := range 3 {
		e := sshFail(time.Duration(i)*time.Second, "203.0.113.7")
		e.App, e.Geo = "shop", g
		h.feed(e)
	}
	if n := len(h.out.events()); n != 0 {
		t.Fatalf("emitted %d events before the write", n)
	}
	h.e.flush(false)
	evs := h.out.events()
	if len(evs) != 1 {
		t.Fatalf("emitted %d events, want 1", len(evs))
	}
	e := evs[0]
	ds := h.all(t)
	if e.Src != siem.SrcSIEM || e.Kind != KindDetection || e.Lvl != siem.LvlError || e.IP != "203.0.113.7" ||
		e.Actor != "" || e.App != "shop" || e.Geo == nil || e.Geo.City != "Lagos" || e.Msg != ds[0].Summary {
		t.Fatalf("event: %+v", e)
	}
	want := map[string]any{"rule": "custom.t", "severity": "high", "count": float64(3), "mitre": "T1110.001,T1078",
		"key": "203.0.113.7", "detection_id": float64(ds[0].ID)}
	if fmt.Sprint(e.F) != fmt.Sprint(want) {
		t.Fatalf("F = %v, want %v", e.F, want)
	}
	if ds[0].Summary != "203.0.113.7 (Lagos, NG; AS37148 Example) — 3 matching events in 10m" {
		t.Errorf("summary %q", ds[0].Summary)
	}
	e.Normalize(h.clk.now()) // the stored form stays within the event bounds
	if len(e.F) != 6 {
		t.Errorf("normalized F lost fields: %v", e.F)
	}

	// Actor key; levels by severity.
	for sev, lvl := range map[siem.Severity]string{siem.SevLow: siem.LvlInfo, siem.SevMedium: siem.LvlWarn,
		siem.SevCritical: siem.LvlCritical} {
		h := newHarness(t, false)
		h.only(t, siem.Rule{ID: "custom.a", Type: siem.RuleThreshold, Query: "kind:sudo.command", GroupBy: "actor",
			Count: 1, Window: time.Hour, Severity: sev})
		h.feed(ev(0, siem.SrcHost, siem.KindSudo, siem.OutFailure, "", "alice", nil))
		h.e.flush(false)
		evs := h.out.events()
		if len(evs) != 1 || evs[0].Lvl != lvl || evs[0].Actor != "alice" || evs[0].IP != "" || evs[0].F["mitre"] != nil {
			t.Errorf("%s: %+v", sev, evs)
		}
	}
}

// A new detection is written (and emitted) by the next flush; its updates at most every
// writeEvery, all in one write.
func TestUpdatesAreThrottled(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, thresholdRule(1, 10*time.Minute))
	h.clk.set(t0)
	h.feedRaw(sshFail(0, "203.0.113.7"))
	h.e.flush(false)
	if evs := h.out.events(); len(evs) != 1 || evs[0].F["count"] != float64(1) {
		t.Fatalf("new detection: %+v", evs)
	}
	for i := range 49 {
		h.feedRaw(sshFail(time.Duration(i+1)*time.Millisecond, "203.0.113.7"))
	}
	h.e.flush(false)
	if n := len(h.out.events()); n != 1 {
		t.Fatalf("49 updates within writeEvery emitted: %d events", n)
	}
	h.clk.advance(writeEvery)
	h.e.flush(false)
	evs := h.out.events()
	if len(evs) != 2 || evs[1].F["count"] != float64(50) || evs[1].F["detection_id"] != evs[0].F["detection_id"] {
		t.Fatalf("after writeEvery: %+v", evs)
	}
	ds, _ := h.e.Detections(context.Background(), siem.DetectionFilter{})
	if len(ds) != 1 || ds[0].Count != 50 {
		t.Fatalf("stored: %+v", ds)
	}
	h.e.flush(false)
	if n := len(h.out.events()); n != 2 {
		t.Fatalf("a flush with nothing new emitted: %d", n)
	}
}

func TestAlerts(t *testing.T) {
	h := newHarness(t, false)
	h.only(t,
		siem.Rule{ID: "custom.high", Name: "High rule", Type: siem.RuleThreshold, Query: "kind:ssh.login", GroupBy: "ip",
			Count: 1, Window: 10 * time.Minute, Severity: siem.SevHigh},
		siem.Rule{ID: "custom.crit", Name: "Critical rule", Type: siem.RuleThreshold, Query: "kind:sudo.command",
			GroupBy: "actor", Count: 1, Window: 10 * time.Minute, Severity: siem.SevCritical},
		siem.Rule{ID: "custom.med", Type: siem.RuleThreshold, Query: "kind:su.session", Count: 1, Window: time.Minute,
			Severity: siem.SevMedium},
		siem.Rule{ID: "custom.low", Type: siem.RuleThreshold, Query: "kind:host.user_change", Count: 1, Window: time.Minute,
			Severity: siem.SevLow},
	)
	h.feed(sshFail(0, "203.0.113.7"), ev(time.Second, siem.SrcHost, siem.KindSudo, siem.OutFailure, "", "alice", nil),
		ev(2*time.Second, siem.SrcHost, siem.KindSu, siem.OutFailure, "", "bob", nil),
		ev(3*time.Second, siem.SrcHost, siem.KindUserChange, "", "", "", nil))
	got := h.alerts()
	if len(got) != 2 {
		t.Fatalf("alerts %+v, want high + critical only", got)
	}
	ds := h.detections(t, "custom.high")
	want := alert.Outbox{RuleID: 0, Target: TargetSIEM, Kind: AlertKind, Level: alert.LevelWarning, Transition: "firing",
		Summary: "High rule: " + ds[0].Summary, DedupeKey: "siem:custom.high:203.0.113.7"}
	if got[0] != want {
		t.Errorf("high alert %+v\nwant %+v", got[0], want)
	}
	// custom.crit's query pins no source, so alice's detections are kept apart per system: the
	// alert's key says which (dedupeKey).
	if got[1].Level != alert.LevelCritical || got[1].DedupeKey != "siem-acct:custom.crit:host|alice" {
		t.Errorf("critical alert %+v", got[1])
	}
	if len(h.all(t)) != 4 {
		t.Errorf("every severity is recorded: %d", len(h.all(t)))
	}

	// Cooldown: the same rule and key alert once an hour while it keeps firing.
	h.feed(sshFail(30*time.Minute, "203.0.113.7"))
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("second alert within the hour: %+v", got)
	}
	h.feed(sshFail(30*time.Minute, "198.51.100.1")) // another key alerts on its own
	if got := h.alerts(); len(got) != 1 || got[0].DedupeKey != "siem:custom.high:198.51.100.1" {
		t.Fatalf("another key: %+v", got)
	}
	h.feed(sshFail(59*time.Minute, "203.0.113.7"))
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("alert at 59m: %+v", got)
	}
	h.feed(sshFail(60*time.Minute, "203.0.113.7"))
	if got := h.alerts(); len(got) != 1 {
		t.Fatalf("after an hour: %+v", got)
	}
}

func TestSnoozeRecordsWithoutAlert(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, siem.Rule{ID: "custom.s", Type: siem.RuleThreshold, Query: "kind:ssh.login", GroupBy: "ip",
		Count: 1, Window: 10 * time.Minute, Severity: siem.SevCritical, SnoozedUntil: t0.Add(time.Hour)})
	h.feed(sshFail(0, "203.0.113.7"))
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("snoozed rule alerted: %+v", got)
	}
	ds := h.all(t)
	if len(ds) != 1 || !ds[0].Snoozed {
		t.Fatalf("snoozed detection: %+v", ds)
	}
	if n := len(h.out.events()); n != 1 {
		t.Fatalf("snoozed detection emitted %d events", n)
	}
	// The snooze ends: the next firing alerts (it was never sent).
	h.feed(sshFail(time.Hour+time.Second, "203.0.113.7"))
	if got := h.alerts(); len(got) != 1 {
		t.Fatalf("after the snooze: %+v", got)
	}
}

func TestAlertQueueFull(t *testing.T) {
	h := newHarness(t, false)
	// 60 high rules on the same events, 5 keys each (the per-rule cap): 300 alerts at once.
	var rs []siem.Rule
	for i := range 60 {
		rs = append(rs, siem.Rule{ID: fmt.Sprint("custom.h", i), Type: siem.RuleThreshold, Query: "kind:ssh.login",
			GroupBy: "ip", Count: 1, Window: 10 * time.Minute, Severity: siem.SevHigh})
	}
	h.only(t, rs...)
	for i := range 5 {
		h.feed(sshFail(time.Duration(i)*time.Millisecond, fmt.Sprint("10.0.0.", i)))
	}
	if got := h.e.Stats().AlertsDropped; got != 300-alertQueue {
		t.Fatalf("alerts dropped %d, want %d", got, 300-alertQueue)
	}
	h.e.flush(true)
	var n int
	if err := h.e.db.r.QueryRow(`SELECT COUNT(*) FROM detections`).Scan(&n); err != nil || n != 300 {
		t.Fatalf("detections %d (%v), want all recorded", n, err)
	}
	// A dropped alert isn't counted as sent (nor toward its rule's cap): the key's next firing alerts.
	h.alerts()
	h.feed(sshFail(time.Second, "10.0.0.4")) // the last key: its alerts of the last rules were dropped
	if got := h.alerts(); len(got) != 300-alertQueue {
		t.Fatalf("retry after dropped alerts: %d alerts, want %d", len(got), 300-alertQueue)
	}
}

// Run end to end: events through the subscriber, alerts through the worker.
func TestRun(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, siem.Rule{ID: "custom.h", Type: siem.RuleThreshold, Query: "kind:ssh.login", GroupBy: "ip",
		Count: 2, Window: 10 * time.Minute, Severity: siem.SevHigh})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.e.Run(ctx); close(done) }()
	sub := h.e.Subscriber()
	sub(sshFail(0, "203.0.113.7"))
	sub(sshFail(time.Second, "203.0.113.7"))
	deadline := time.Now().Add(5 * time.Second)
	for len(h.al.all()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := h.al.all(); len(got) != 1 || got[0].Kind != AlertKind {
		t.Fatalf("alerts via the worker: %+v", got)
	}
	cancel()
	<-done
	h.e.Run(context.Background()) // a second Run returns at once
}

func TestSummaryIsCleanAndBounded(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, siem.Rule{ID: "custom.u", Name: "User", Type: siem.RuleThreshold, Query: "kind:ssh.invalid_user",
		GroupBy: "actor", Count: 1, Window: time.Hour, Severity: siem.SevHigh})
	name := "<!channel>\n@everyone `x`‮" + strings.Repeat("é", 300)
	h.feed(invalidUser(0, "203.0.113.7", name))
	ds := h.all(t)
	if len(ds) != 1 {
		t.Fatal(ds)
	}
	s := ds[0].Summary
	if strings.ContainsAny(s, "<>@`\n‮") || len(s) > maxSummary || !utf8.ValidString(s) {
		t.Fatalf("summary %q", s)
	}
	o := h.alerts()
	if len(o) != 1 || strings.ContainsAny(o[0].Summary, "<>@`\n") || len(o[0].Summary) > maxSummary ||
		!utf8.ValidString(o[0].Summary) || !strings.HasPrefix(o[0].Summary, "User: ") {
		t.Fatalf("alert summary %+v", o)
	}
}

// The longest summary the parts can make (a long f.* key, a travel between two long place names)
// is cut at maxSummary.
func TestSummaryCutAtLimit(t *testing.T) {
	h := newHarness(t, false)
	fk := strings.Repeat("k", siem.MaxFieldKey) // the longest group-by name
	h.only(t, siem.Rule{ID: "custom.tr", Type: siem.RuleTravel, Query: "kind:x.login", GroupBy: "f." + fk, SpeedKMH: 100})
	sess := strings.Repeat("s", 120)
	g := func(lon float64) *siem.Geo {
		return &siem.Geo{Country: "ABCDEFGH", City: strings.Repeat("c", 40), Lat: 0.1, Lon: lon, ASN: 4294967295,
			Org: strings.Repeat("o", 40)}
	}
	e1 := ev(0, siem.SrcApp, "x.login", "", "203.0.113.7", "", map[string]any{fk: sess})
	e1.Geo = g(0.1)
	e2 := ev(23*time.Hour+59*time.Minute+59*time.Second, siem.SrcApp, "x.login", "", "203.0.113.7", "", map[string]any{fk: sess})
	e2.Geo = g(179.9)
	h.feed(e1, e2)
	ds := h.all(t)
	if len(ds) != 1 || len(ds[0].Summary) != maxSummary || !utf8.ValidString(ds[0].Summary) {
		t.Fatalf("summary of %d bytes: %+v", len(ds[0].Summary), ds)
	}
}

// A reported detection's long name and summary are cut, on a UTF-8 boundary, in the record and the
// alert.
func TestReportedSummaryBounded(t *testing.T) {
	h := newHarness(t, false)
	h.e.report(siem.Detection{RuleID: "ops:a/s/x", RuleName: strings.Repeat("n", 200), Severity: siem.SevCritical,
		App: "a", Service: "s", Summary: strings.Repeat("é", 400)})
	ds := h.all(t)
	if len(ds) != 1 || len(ds[0].Summary) > maxSummary || !utf8.ValidString(ds[0].Summary) || len(ds[0].RuleName) > maxRuleName {
		t.Fatalf("stored: %+v", ds)
	}
	a := h.alerts()
	if len(a) != 1 || len(a[0].Summary) > maxSummary || !utf8.ValidString(a[0].Summary) {
		t.Fatalf("alert summary %d bytes: %+v", len(a[0].Summary), a)
	}
}

func TestPanicIsRecovered(t *testing.T) {
	h := newHarness(t, false)
	h.e.safe(func() { panic("boom") })
	if h.e.Stats().Panics != 1 {
		t.Fatal("panic not counted")
	}
}

func TestFmtDur(t *testing.T) {
	for d, want := range map[time.Duration]string{45 * time.Second: "45s", 10 * time.Minute: "10m", time.Hour: "1h",
		90 * time.Minute: "1h30m", 7 * 24 * time.Hour: "7d", 0: "0s", 61*time.Minute + 5*time.Second: "1h1m"} {
		if got := fmtDur(d); got != want {
			t.Errorf("fmtDur(%s) = %q, want %q", d, got, want)
		}
	}
}
