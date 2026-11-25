package detect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/parse"
)

// hostF feeds an auth.log line through the real parser with extra F fields (what the pipeline's
// sender check adds).
func (h *harness) hostF(t *testing.T, at time.Duration, prog, msg string, f map[string]any) {
	t.Helper()
	line := t0.Add(at).Format(time.RFC3339) + " web1 " + prog + ": " + msg
	e, ok := parse.AuthLog(line, t0.Add(at), time.UTC)
	if !ok {
		t.Fatalf("parse %q", line)
	}
	if e.F == nil {
		e.F = map[string]any{}
	}
	for k, v := range f {
		e.F[k] = v
	}
	h.feed(e)
}

// hostLine evaluates a host line as read now (a backlog line keeps its own time).
func (h *harness) hostLine(t *testing.T, line string) {
	t.Helper()
	e, ok := parse.AuthLog(line, h.clk.now(), time.UTC)
	if !ok {
		t.Fatalf("parse %q", line)
	}
	e.Normalize(h.clk.now())
	h.e.process(&e)
}

// failWrites makes every detection insert and update fail until the returned func is called.
func failWrites(t *testing.T, h *harness) (restore func()) {
	t.Helper()
	if _, err := h.e.db.w.Exec(`CREATE TABLE fail(x); INSERT INTO fail VALUES(1);
		CREATE TRIGGER failins BEFORE INSERT ON detections WHEN EXISTS(SELECT 1 FROM fail) BEGIN SELECT RAISE(ABORT, 'disk full'); END;
		CREATE TRIGGER failupd BEFORE UPDATE ON detections WHEN EXISTS(SELECT 1 FROM fail) BEGIN SELECT RAISE(ABORT, 'disk full'); END;`); err != nil {
		t.Fatal(err)
	}
	return func() {
		if _, err := h.e.db.w.Exec(`DELETE FROM fail`); err != nil {
			t.Fatal(err)
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func ipv4(i int) string { return fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255) }

func oneRule(sev siem.Severity) siem.Rule {
	return siem.Rule{ID: "custom.one", Name: "One", Type: siem.RuleThreshold, Query: "kind:ssh.login out:failure",
		GroupBy: "ip", Count: 1, Window: time.Hour, Severity: sev}
}

// 1. At most newPerHour new detections per rule per wall-clock hour; more keys are counted once
// each in the rule's rollup detection (key "*").
func TestNewDetectionsCappedPerRuleHour(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, oneRule(siem.SevLow))
	for i := range 200 {
		h.feed(sshFail(time.Duration(i)*100*time.Millisecond, ipv4(i)))
	}
	ds := h.all(t)
	if len(ds) != newPerHour+1 {
		t.Fatalf("200 keys in an hour: %d detections, want %d + the rollup", len(ds), newPerHour)
	}
	var roll *siem.Detection
	for i := range ds {
		if ds[i].Key == RollupKey {
			roll = &ds[i]
		}
	}
	if roll == nil || roll.Count != 150 || roll.Summary != "and 150 more keys this hour (at most 50 new detections per rule an hour)" ||
		roll.RuleID != "custom.one" || len(roll.Evidence) != siem.MaxEvidence {
		t.Fatalf("rollup: %+v", roll)
	}
	// The rolled-up keys again: each counted once. A recorded key updates its own detection.
	for i := 50; i < 200; i++ {
		h.feed(sshFail(30*time.Second+time.Duration(i)*time.Millisecond, ipv4(i)))
	}
	h.feed(sshFail(time.Minute, ipv4(3)))
	ds = h.all(t)
	for _, d := range ds {
		switch d.Key {
		case RollupKey:
			if d.Count != 150 {
				t.Errorf("rollup count after the same keys again: %d", d.Count)
			}
		case ipv4(3):
			if d.Count != 2 {
				t.Errorf("recorded key: count %d, want 2", d.Count)
			}
		}
	}
	if len(ds) != newPerHour+1 {
		t.Fatalf("%d detections, want %d", len(ds), newPerHour+1)
	}
	// The next wall-clock hour: new keys get their own detections again.
	h.clk.set(t0.Add(time.Hour))
	h.feed(sshFail(time.Hour+time.Second, ipv4(500)))
	if ds := h.all(t); len(ds) != newPerHour+2 {
		t.Fatalf("next hour: %d detections, want %d", len(ds), newPerHour+2)
	}
	// Bounded: the per-hour maps.
	if len(h.e.newRows) > maxRuleHours || h.e.rolledN > maxRolledKeys {
		t.Fatalf("hour maps: %d rules, %d keys", len(h.e.newRows), h.e.rolledN)
	}
}

// 1. detect.db's pages in use stay within the cap: the oldest low and medium detections go first.
func TestDBSizeCap(t *testing.T) {
	h := newHarness(t, false)
	h.e.lim.newPerHour = 1 << 30
	sevs := []siem.Severity{siem.SevLow, siem.SevMedium, siem.SevLow, siem.SevHigh}
	evid := make([]siem.Evidence, siem.MaxEvidence)
	for i := range evid {
		evid[i] = siem.Evidence{TS: t0, Kind: "x.y", IP: "2001:db8::1", Actor: strings.Repeat("a", 64), App: "app"}
	}
	for i := range 4000 {
		h.clk.set(t0.Add(time.Duration(i) * time.Second))
		h.e.report(siem.Detection{RuleID: fmt.Sprint("ops:a/s/r", i%7), Key: fmt.Sprint("k", i), Severity: sevs[i%4],
			Summary: strings.Repeat("s", 290), Evidence: evid})
		if i%500 == 0 {
			h.e.flush(true)
		}
	}
	h.e.flush(true)
	ctx := context.Background()
	count := func(where string) int {
		var n int
		if err := h.e.db.w.QueryRow(`SELECT COUNT(*) FROM detections WHERE ` + where).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	used, err := h.e.db.used(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A cap the oldest low and medium detections make room for: no high one goes.
	h.e.lim.dbBytes = used / 10 * 8
	h.e.capSize()
	after, _ := h.e.db.used(ctx)
	if after > h.e.lim.dbBytes {
		t.Fatalf("pages in use %d after the cap, cap %d (before %d)", after, h.e.lim.dbBytes, used)
	}
	if n := count("sev_rank >= 3"); n != 1000 {
		t.Fatalf("high detections %d, want all 1000 kept while low and medium ones remain", n)
	}
	lowLeft := count("sev_rank <= 2")
	if lowLeft == 0 || lowLeft >= 3000 {
		t.Fatalf("low and medium detections %d", lowLeft)
	}
	var oldestLow int64
	_ = h.e.db.w.QueryRow(`SELECT MIN(id) FROM detections WHERE sev_rank <= 2`).Scan(&oldestLow)
	if want := int64(3000-lowLeft) / 3 * 4; oldestLow < want {
		t.Errorf("the oldest low/medium detection left is id %d, want the oldest gone first (>= %d)", oldestLow, want)
	}
	// A cap below what the high ones take: every low and medium one goes, then the oldest high ones.
	h.e.db.chunk = 50
	h.e.lim.dbBytes = after / 8
	h.e.capSize()
	if n := count("sev_rank <= 2"); n != 0 {
		t.Fatalf("low and medium left: %d", n)
	}
	n := count("1")
	var minID int64
	_ = h.e.db.w.QueryRow(`SELECT MIN(id) FROM detections`).Scan(&minID)
	if n == 0 || n >= 1000 || minID != int64(4004-4*n) {
		t.Fatalf("high detections left %d (oldest id %d): want the newest kept", n, minID)
	}
	if final, _ := h.e.db.used(ctx); final > h.e.lim.dbBytes {
		t.Fatalf("pages in use %d, cap %d", final, h.e.lim.dbBytes)
	}
}

// 2. An IPv6 address is keyed by its /64.
func TestIPv6KeyedBySlash64(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7": "203.0.113.7", "2001:db8:1:2::abcd": "2001:db8:1:2::/64", "2001:DB8:1:2:ffff::1": "2001:db8:1:2::/64",
		"::ffff:203.0.113.7": "203.0.113.7", "fe80::1%eth0": "fe80::/64", "not-an-ip": "not-an-ip", "": "",
	} {
		if got := ipKey(in); got != want {
			t.Errorf("ipKey(%q) = %q, want %q", in, got, want)
		}
	}
	h := newHarness(t, false)
	for i := range 20 {
		h.feed(sshFail(time.Duration(i)*time.Second, fmt.Sprintf("2001:db8:1:2::%x", i+1)))
	}
	ds := h.detections(t, "ssh.bruteforce")
	if len(ds) != 1 || ds[0].Key != "2001:db8:1:2::/64" || !strings.HasPrefix(ds[0].Summary, "2001:db8:1:2::/64 — 20 failed SSH logins") {
		t.Fatalf("20 failures from one /64 (one per address): %+v", ds)
	}
	var em *siem.Event
	for _, e := range h.out.events() {
		if e.F["rule"] == "ssh.bruteforce" {
			em = &e
		}
	}
	if em == nil || em.IP != "2001:db8:1:2::14" || em.F["key"] != "2001:db8:1:2::/64" {
		t.Fatalf("emitted: ip is the newest address, key the /64: %+v", em)
	}
	// Another /64 is another key.
	for i := range 19 {
		h.feed(sshFail(time.Minute+time.Duration(i)*time.Second, fmt.Sprintf("2001:db8:1:3::%x", i+1)))
	}
	if ds := h.detections(t, "ssh.bruteforce"); len(ds) != 1 {
		t.Fatalf("19 failures from another /64: %+v", ds)
	}
}

type flakyAlerter struct {
	mu    sync.Mutex
	fails int // attempts that fail first
	n     int
	got   []alert.Outbox
}

func (f *flakyAlerter) EnqueueInfra(_ context.Context, o alert.Outbox) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	if f.n <= f.fails {
		return errors.New("database is locked")
	}
	f.got = append(f.got, o)
	return nil
}

func (f *flakyAlerter) counts() (attempts, sent int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n, len(f.got)
}

// 3. A failed alert is retried; the cooldown starts only once one is recorded.
func TestAlertRetriedAndCooldownAfterSuccess(t *testing.T) {
	run := func(t *testing.T, fails int) (*harness, *flakyAlerter, func()) {
		fa := &flakyAlerter{fails: fails}
		h := newHarness(t, false, func(o *Options) { o.Alerter = fa })
		h.e.lim.alertBackoff = []time.Duration{5 * time.Millisecond, 10 * time.Millisecond}
		h.only(t, oneRule(siem.SevCritical))
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { h.e.Run(ctx); close(done) }()
		return h, fa, func() { cancel(); <-done }
	}
	t.Run("recorded on the third try", func(t *testing.T) {
		h, fa, stop := run(t, 2)
		defer stop()
		h.e.Subscriber()(sshFail(0, "203.0.113.9"))
		waitFor(t, "the alert", func() bool { _, sent := fa.counts(); return sent == 1 })
		var alerted int64
		waitFor(t, "alerted stored", func() bool {
			_ = h.e.db.r.QueryRow(`SELECT alerted_ns FROM detections`).Scan(&alerted)
			return alerted != 0
		})
		h.clk.set(t0.Add(10 * time.Minute))
		h.e.Subscriber()(sshFail(10*time.Minute, "203.0.113.9"))
		waitFor(t, "the second firing", func() bool {
			ds, _ := h.e.Detections(context.Background(), siem.DetectionFilter{})
			return len(ds) == 1 && ds[0].Count == 2
		})
		time.Sleep(50 * time.Millisecond)
		if attempts, sent := fa.counts(); attempts != 3 || sent != 1 {
			t.Fatalf("after a sent alert, a firing within the hour: %d attempts, %d sent", attempts, sent)
		}
	})
	t.Run("given up, then the next firing alerts", func(t *testing.T) {
		h, fa, stop := run(t, 1<<30)
		defer stop()
		h.e.Subscriber()(sshFail(0, "203.0.113.9"))
		waitFor(t, "the alert given up", func() bool { return h.e.Stats().AlertsFailed == 1 })
		if attempts, _ := fa.counts(); attempts != alertTries {
			t.Fatalf("%d attempts, want %d", attempts, alertTries)
		}
		h.clk.set(t0.Add(10 * time.Minute))
		h.e.Subscriber()(sshFail(10*time.Minute, "203.0.113.9"))
		waitFor(t, "the alert raised again", func() bool { attempts, _ := fa.counts(); return attempts > alertTries })
	})
}

// 3. (synchronous) a failed alert leaves no cooldown: the next firing queues it again.
func TestFailedAlertNotCountedAsSent(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, oneRule(siem.SevCritical))
	h.feed(sshFail(0, "203.0.113.9"))
	if got := h.failAlerts(); len(got) != 1 {
		t.Fatalf("alerts %+v", got)
	}
	h.feed(sshFail(10*time.Minute, "203.0.113.9"))
	if got := h.alerts(); len(got) != 1 {
		t.Fatalf("after a failed alert, the next firing: %+v", got)
	}
	h.feed(sshFail(20*time.Minute, "203.0.113.9"))
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("after a sent alert: %+v", got)
	}
	// While an alert is in flight, the key's further firings don't queue another.
	h.feed(sshFail(0, "198.51.100.7"), sshFail(time.Second, "198.51.100.7"), sshFail(2*time.Second, "198.51.100.7"))
	if got := h.alerts(); len(got) != 1 {
		t.Fatalf("firings while in flight: %+v", got)
	}
}

// 4. While writes fail: no write per event, every unwritten detection stays findable (no
// duplicate row once writes work again), and the memory they take is bounded.
func TestWriteFailureBoundedNoDuplicates(t *testing.T) {
	if testing.Short() {
		t.Skip("many detections")
	}
	h := newHarness(t, false)
	h.e.lim.newPerHour = 1 << 30
	h.only(t, oneRule(siem.SevLow))
	restore := failWrites(t, h)
	h.feed(sshFail(0, ipv4(0)))
	h.e.flush(false) // fails: writes now wait for the backoff
	if h.e.Stats().WriteErrors != 1 {
		t.Fatalf("write errors %d", h.e.Stats().WriteErrors)
	}
	h.e.flush(false)
	start := time.Now()
	n := maxActive + 3000
	for i := 1; i < n; i++ {
		h.feed(sshFail(time.Duration(i)*time.Millisecond, ipv4(i)))
	}
	t.Logf("%d firings while writes fail: %v", n, time.Since(start))
	if got := h.e.Stats().WriteErrors; got != 1 {
		t.Fatalf("%d write attempts during the failure, want none after the first (no write per eviction)", got)
	}
	if len(h.e.dirty) > maxActive+maxParked || len(h.e.parked) > maxParked || h.e.parkLRU.Len() != len(h.e.parked) {
		t.Fatalf("dirty %d, parked %d (list %d)", len(h.e.dirty), len(h.e.parked), h.e.parkLRU.Len())
	}
	// ip 0 was evicted while unwritten; it fires again: the same detection.
	h.feed(sshFail(time.Duration(n)*time.Millisecond, ipv4(0)))
	restore()
	h.e.flush(true)
	var rows, cnt int
	if err := h.e.db.w.QueryRow(`SELECT COUNT(*), MAX(count) FROM detections WHERE key = ?`, ipv4(0)).Scan(&rows, &cnt); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || cnt != 2 {
		t.Fatalf("ip 0: %d rows (count %d), want 1 row counting 2", rows, cnt)
	}
	var all int
	_ = h.e.db.w.QueryRow(`SELECT COUNT(*) FROM detections`).Scan(&all)
	if all != n || len(h.e.dirty) != 0 || len(h.e.parked) != 0 {
		t.Fatalf("after recovery: %d rows (want %d), dirty %d, parked %d", all, n, len(h.e.dirty), len(h.e.parked))
	}
}

// 4. Past maxParked unwritten detections the oldest are dropped (counted), never more memory.
func TestWriteFailureParkedBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("many detections")
	}
	h := newHarness(t, false)
	h.e.lim.newPerHour = 1 << 30
	h.only(t, oneRule(siem.SevLow))
	failWrites(t, h)
	n := maxActive + maxParked + 500
	for i := range n {
		h.feed(sshFail(time.Duration(i)*time.Millisecond, ipv4(i)))
	}
	if got := h.e.Stats().Lost; got != 500 {
		t.Fatalf("lost %d, want 500", got)
	}
	if len(h.e.dirty) != maxActive+maxParked || len(h.e.parked) != maxParked {
		t.Fatalf("dirty %d, parked %d", len(h.e.dirty), len(h.e.parked))
	}
}

// 5. A backlog replay that makes several detections of one key at once alerts once.
func TestBacklogAlertsOncePerRuleKey(t *testing.T) {
	h := newHarness(t, false)
	h.clk.set(t0.Add(22 * time.Hour))
	ip := "203.0.113.8"
	n := 0
	for _, base := range []time.Duration{time.Hour, 5 * time.Hour, 9 * time.Hour} {
		for i := range 5 {
			h.hostLine(t, t0.Add(base+time.Duration(i)*time.Second).Format(time.RFC3339)+" web1 sshd[1]: Failed password for root from "+ip+" port 1 ssh2")
		}
		h.hostLine(t, t0.Add(base+time.Minute).Format(time.RFC3339)+" web1 sshd[1]: Accepted password for root from "+ip+" port 2 ssh2")
		for _, o := range h.alerts() { // the worker sends between the lines
			if o.DedupeKey == "siem:ssh.success_after_failures:"+ip {
				n++
			}
		}
	}
	if ds := h.detections(t, "ssh.success_after_failures"); len(ds) != 3 {
		t.Fatalf("three detections from the backlog: %+v", ds)
	}
	if n != 1 {
		t.Fatalf("%d alerts for one rule and key within the same second, want 1", n)
	}
}

// 6. At most alertsPerHour alerts per rule per wall-clock hour for high detections; the rest are
// counted in one summary alert (a warning) sent when the hour ends. Critical detections are not
// capped (owner decision, review round 2).
func TestAlertCapPerRuleHour(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, siem.Rule{ID: "custom.h", Name: "High rule", Type: siem.RuleThreshold, Query: "kind:ssh.login out:failure",
		GroupBy: "ip", Count: 1, Window: time.Hour, Severity: siem.SevHigh},
		siem.Rule{ID: "custom.c", Name: "Critical rule", Type: siem.RuleThreshold, Query: "kind:ssh.login out:failure",
			GroupBy: "ip", Count: 1, Window: time.Hour, Severity: siem.SevCritical})
	for i := range 8 {
		h.feed(sshFail(time.Duration(i)*time.Minute, ipv4(i)))
	}
	got := h.alerts()
	if len(got) != alertsPerHour+8 {
		t.Fatalf("8 keys of a high and a critical rule in an hour: %d alerts, want %d", len(got), alertsPerHour+8)
	}
	// A suppressed detection firing again is the same detection: counted once.
	h.feed(sshFail(20*time.Minute, ipv4(7)))
	h.e.sendCaps(false) // the hour hasn't ended
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("summary before the hour ended: %+v", got)
	}
	h.clk.set(t0.Add(time.Hour))
	h.e.sendCaps(false)
	got = h.alerts()
	want := alert.Outbox{Target: TargetSIEM, Kind: AlertKind, Level: alert.LevelWarning, Transition: "firing",
		Summary: "High rule: 3 more detections this hour — see the Detections page", DedupeKey: "siem-cap:custom.h"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("summaries: %+v\nwant %+v", got, want)
	}
	// The next hour: the high rule alerts again (a key suppressed last hour has no cooldown); the
	// critical rule's key is within the hour of its alert.
	h.feed(sshFail(time.Hour+time.Second, ipv4(7)))
	if got := h.alerts(); len(got) != 1 || got[0].DedupeKey != "siem:custom.h:"+ipv4(7) {
		t.Fatalf("next hour: %+v", got)
	}
	// One more past the cap, then shutdown: the hour's summary goes out at once, singular.
	for i := 20; i < 25; i++ {
		h.feed(sshFail(time.Hour+time.Duration(i)*time.Second, ipv4(i)))
	}
	if got := h.alerts(); len(got) != alertsPerHour-1+5 {
		t.Fatalf("5 keys: %d alerts", len(got))
	}
	h.e.sendCaps(true)
	got = h.alerts()
	if len(got) != 1 || got[0].Summary != "High rule: 1 more detection this hour — see the Detections page" {
		t.Fatalf("summary at shutdown: %+v", got)
	}
}

// 7. At shutdown Run evaluates what is still queued before its last write.
func TestRunDrainsQueuesAtShutdown(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, siem.Rule{ID: "custom.n", Type: siem.RuleThreshold, Query: "kind:ssh.login", GroupBy: "ip", Count: 100,
		Window: time.Hour})
	sub := h.e.Subscriber()
	for i := range 100 {
		sub(sshFail(time.Duration(i)*time.Millisecond, "203.0.113.7"))
	}
	h.e.Report(siem.Detection{RuleID: "ops:a/s/x", Summary: "x"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.e.Run(ctx)
	got := ruleIDs(h.all(t))
	if got["custom.n"] != 1 || got["ops:a/s/x"] != 1 {
		t.Fatalf("queued events and reports at shutdown: %v", got)
	}
}

// 8. Account changes are keyed per account: a new account is a new detection and alerts.
func TestAccountChangesPerAccount(t *testing.T) {
	h := newHarness(t, false)
	h.host(t, 0, "usermod[500]", "change user 'deploy' shell from '/bin/sh' to '/bin/bash'", nil)
	if a := h.alerts(); len(a) != 1 {
		t.Fatalf("first change: %+v", a)
	}
	h.host(t, 50*time.Minute, "useradd[600]", "new user: name=backdoor, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/1", nil)
	a := h.alerts()
	if len(a) != 1 || a[0].DedupeKey != "siem:host.user_change:backdoor" ||
		a[0].Summary != "Host account change: account backdoor — 1 user or group changes in 1h" {
		t.Fatalf("a new account 50 minutes later: %+v", a)
	}
	h.host(t, 51*time.Minute, "groupadd[601]", "group added to /etc/group: name=wheel2, GID=1002", nil)
	h.host(t, 52*time.Minute, "gpasswd[602]", "members of group sudo set by root", nil) // names no account
	if a := h.alerts(); len(a) != 2 {
		t.Fatalf("a group and an unnamed change: %+v", a)
	}
	ds := h.detections(t, "host.user_change")
	keys := map[string]bool{}
	for _, d := range ds {
		keys[d.Key] = true
	}
	if len(ds) != 4 || !keys["deploy"] || !keys["backdoor"] || !keys["wheel2"] || !keys[""] {
		t.Fatalf("detections per account (a group, and the lines naming none together): %+v", ds)
	}

	// Mooring's users: per target.
	for i, target := range []string{"mallory", "eve"} {
		h.mooring(time.Hour+time.Duration(i)*time.Minute, audit.Event{Actor: "system", Action: "user_added", Target: target,
			Outcome: audit.OK, Level: audit.Security}, nil)
	}
	a = h.alerts()
	if len(a) != 2 || a[1].Summary != "Mooring user change: user eve — 1 user changes in 1h" {
		t.Fatalf("two Mooring users added: %+v", a)
	}
}

// 9. A closing event ends the sequence whether or not it fired.
func TestSequenceClosingEventResets(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, sequenceRule()) // 3 then 1
	ip := "203.0.113.7"
	h.feed(sshFail(0, ip), sshFail(time.Minute, ip), sshOK(2*time.Minute, ip, "root", nil),
		sshFail(3*time.Minute, ip), sshOK(4*time.Minute, ip, "root", nil))
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("2 failures, success, 1 failure, success: %+v", ds)
	}
	h.feed(sshFail(5*time.Minute, ip), sshFail(6*time.Minute, ip), sshFail(7*time.Minute, ip), sshOK(8*time.Minute, ip, "root", nil))
	if ds := h.all(t); len(ds) != 1 || ds[0].Count != 3 {
		t.Fatalf("3 failures then success: %+v", ds)
	}
	// A closing event for a key never seen keeps no state.
	h.feed(sshOK(9*time.Minute, "198.51.100.1", "root", nil))
	if _, ok := h.e.states["custom.seq"].keys["198.51.100.1"]; ok {
		t.Fatal("state kept for a closing event alone")
	}
}

// 10. A line its journal sender couldn't have written counts for no host rule but the forged-line
// one.
func TestForgedHostLines(t *testing.T) {
	h := newHarness(t, false)
	forged := map[string]any{"sender_mismatch": true, "sender_uid": "1001"}
	for i := range 3 {
		h.hostF(t, time.Duration(i)*time.Second, "su[200]", "FAILED SU (to root) alice on pts/0", forged)
	}
	h.hostF(t, 5*time.Second, "passwd[300]", "pam_unix(passwd:chauthtok): password changed for root", forged)
	for i := range 25 {
		h.hostF(t, 10*time.Second+time.Duration(i)*time.Second, "sshd[1]", "Failed password for root from 203.0.113.9 port 1 ssh2", forged)
	}
	got := ruleIDs(h.all(t))
	if got["sudo.failures"] != 0 || got["host.user_change"] != 0 || got["ssh.bruteforce"] != 0 {
		t.Fatalf("forged lines counted: %v", got)
	}
	ds := h.detections(t, "host.forged_log_line")
	if len(ds) != 1 || ds[0].Key != "1001" || ds[0].Count != 29 || ds[0].Severity != siem.SevMedium ||
		!strings.HasPrefix(ds[0].Summary, "uid 1001 — 29 forged log lines") {
		t.Fatalf("forged line rule: %+v", ds)
	}
	// Control: the same lines from their real sender.
	for i := range 3 {
		h.hostF(t, time.Minute+time.Duration(i)*time.Second, "su[200]", "FAILED SU (to root) bob on pts/0", map[string]any{"sender_uid": "0"})
	}
	if got := ruleIDs(h.all(t)); got["sudo.failures"] != 1 {
		t.Fatalf("real failures: %v", got)
	}
}

// 11. F.repeated weighs only in host events.
func TestRepeatedOnlyFromHost(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, siem.Rule{ID: "custom.w", Type: siem.RuleThreshold, Query: "kind:x.fail", GroupBy: "ip", Count: 5, Window: time.Hour})
	h.feed(ev(0, siem.SrcApp, "x.fail", "", "203.0.113.7", "", map[string]any{"repeated": float64(1000)}))
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("an app line's repeated field counted: %+v", ds)
	}
	h.feed(ev(time.Second, siem.SrcHost, "x.fail", "", "198.51.100.7", "", map[string]any{"repeated": float64(5)}))
	if ds := h.all(t); len(ds) != 1 || ds[0].Count != 5 {
		t.Fatalf("a host line's repeated count: %+v", ds)
	}
}

// 12. ssh.bruteforce counts password attempts and unknown-user connections, not key or "none"
// failures.
func TestSSHBruteForceCountsPasswordAttempts(t *testing.T) {
	h := newHarness(t, false)
	for i := range 30 {
		at := time.Duration(i) * time.Second
		h.host(t, at, "sshd[1]", fmt.Sprintf("Failed publickey for deploy from 198.51.100.9 port %d ssh2: ED25519 SHA256:abc", 4000+i), nil)
		h.host(t, at, "sshd[1]", fmt.Sprintf("Failed none for root from 198.51.100.10 port %d ssh2", 4000+i), nil)
		h.host(t, at, "sshd[1]", fmt.Sprintf("Failed hostbased for root from 198.51.100.13 port %d ssh2", 4000+i), nil)
	}
	if got := ruleIDs(h.all(t)); got["ssh.bruteforce"] != 0 {
		t.Fatalf("key and none failures counted: %v", got)
	}
	for i := range 20 {
		h.host(t, time.Minute+time.Duration(i)*time.Second, "sshd[2]",
			fmt.Sprintf("Failed keyboard-interactive/pam for root from 198.51.100.11 port %d ssh2", 5000+i), nil)
	}
	attempt := func(i int) {
		at, port := 2*time.Minute+time.Duration(i)*time.Second, 6000+i
		for _, l := range []string{"Invalid user u%d from 198.51.100.12 port %d", "Failed none for invalid user u%d from 198.51.100.12 port %d ssh2",
			"Failed password for invalid user u%d from 198.51.100.12 port %d ssh2", "Connection closed by invalid user u%d 198.51.100.12 port %d [preauth]"} {
			h.host(t, at, "sshd[3]", fmt.Sprintf(l, i, port), nil)
		}
	}
	for i := range 19 {
		attempt(i)
	}
	ds := h.detections(t, "ssh.bruteforce")
	if len(ds) != 1 || ds[0].Key != "198.51.100.11" {
		t.Fatalf("20 keyboard-interactive failures fire; 19 unknown-user attempts don't: %+v", ds)
	}
	attempt(19)
	if ds := h.detections(t, "ssh.bruteforce"); len(ds) != 2 || ds[0].Key != "198.51.100.12" || ds[0].Count != 20 {
		t.Fatalf("20 unknown-user attempts, each once: %+v", ds)
	}
}

// 13. The learning period runs from the rule's first event: a key's first surge fires.
func TestAnomalyFirstSurgeFires(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, anomalyRule()) // count 10, factor 3, learn 24h
	history(h, "other.example.com", 30, 2)
	spike(h, "shop.example.com", 30*time.Hour, 20)
	if ds := h.detections(t, "custom.an"); len(ds) != 1 || ds[0].Key != "shop.example.com" {
		t.Fatalf("a host's first surge once the rule has learned: %+v", ds)
	}
	// Before the rule has learned, nothing fires.
	h2 := newHarness(t, false)
	h2.only(t, anomalyRule())
	history(h2, "other.example.com", 20, 2)
	spike(h2, "shop.example.com", 20*time.Hour, 40)
	if ds := h2.all(t); len(ds) != 0 {
		t.Fatalf("fired before the rule learned: %+v", ds)
	}
	// The rule's start survives a restart.
	h2.clk.set(t0.Add(25 * time.Hour))
	h2.reopen(t)
	h2.only(t, anomalyRule())
	spike(h2, "new.example.com", 25*time.Hour, 20)
	if ds := h2.all(t); len(ds) != 1 || ds[0].Key != "new.example.com" {
		t.Fatalf("after a restart (start kept): %+v", ds)
	}
}

// 13. One-off keys don't evict a key with a history; Host values are normalised.
func TestAnomalyBaselineKeptAndHostNormalised(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, anomalyRule())
	history(h, "shop.example.com", 30, 2)
	at := 30 * time.Hour
	for i := range 3000 {
		h.feed(errorReq(at+time.Duration(i)*time.Millisecond, fmt.Sprintf("probe%d.example.com", i)))
	}
	st := h.e.states["custom.an"]
	if _, kept := st.keys["shop.example.com"]; !kept {
		t.Fatalf("3000 one-off keys evicted the baseline (%d keys kept)", len(st.keys))
	}
	if st.entries > maxEntries || st.pEntries > maxProtEntries || st.lru.Len()+st.plru.Len() != len(st.keys) {
		t.Fatalf("bounds: %d entries (%d protected), lists %d+%d, %d keys", st.entries, st.pEntries, st.lru.Len(), st.plru.Len(), len(st.keys))
	}
	// The spike, with the Host header in other spellings: one key.
	for i := range 40 {
		host := []string{"Shop.Example.COM:443", "shop.example.com.", "shop.example.com"}[i%3]
		h.feed(errorReq(30*time.Hour+30*time.Minute+time.Duration(i)*time.Second, host))
	}
	ds := h.detections(t, "custom.an")
	if len(ds) != 1 || ds[0].Key != "shop.example.com" {
		t.Fatalf("spike on the kept baseline: %+v", ds)
	}
	for in, want := range map[string]string{"Shop.Example.com:8443": "shop.example.com", "[2001:DB8::1]:443": "[2001:db8::1]",
		"[::1]": "[::1]", "example.com.": "example.com", "2001:db8::1": "2001:db8::1"} {
		if got := hostKey(in); got != want {
			t.Errorf("hostKey(%q) = %q, want %q", in, got, want)
		}
	}
	// Protected keys are capped: past three quarters, the least recently used goes back.
	ps := newRuleState("sig")
	for i := range maxProtKeys + 10 {
		k := ps.key(fmt.Sprint("k", i))
		k.an = &anomaly{}
		k.an.hours[0], k.an.hours[1] = 1, 1
		ps.charge(k)
		ps.promote(k)
	}
	if ps.plru.Len() > maxProtKeys || ps.pEntries > maxProtEntries || len(ps.keys) > maxKeys {
		t.Fatalf("protected %d (%d entries), keys %d", ps.plru.Len(), ps.pEntries, len(ps.keys))
	}
}

// 13. The documented key limit of an anomaly rule is the one the entry budget gives.
func TestAnomalyKeyLimitDocumented(t *testing.T) {
	b, err := os.ReadFile("../../../docs/security-detections.md")
	if err != nil {
		t.Fatal(err)
	}
	n := maxEntries / (1 + anomalyCost)
	if want := fmt.Sprintf("%d,%03d", n/1000, n%1000); !strings.Contains(string(b), want) {
		t.Fatalf("docs don't state an anomaly rule's key limit %s", want)
	}
	st := newRuleState("sig")
	for i := range 2 * n {
		k := st.key(fmt.Sprint("k", i))
		k.an = &anomaly{}
		st.charge(k)
	}
	if len(st.keys) != n {
		t.Fatalf("anomaly keys kept %d, documented %d", len(st.keys), n)
	}
}

// 14. A trim never forgets a pair of a key it keeps.
func TestNewValueTrimKeepsPairsOfKeptKeys(t *testing.T) {
	s := newSeen()
	sec := int64(time.Second)
	s.observe("alice", "NG", 1*sec, 0)
	for i := range maxSeen + 100 {
		s.observe(fmt.Sprint("k", i), "v", int64(i+2)*sec, 0)
		if i%1000 == 0 {
			s.observe("alice", "DE", int64(i+2)*sec, 0) // alice stays in use
		}
	}
	if len(s.pairs) > maxSeen || len(s.keys) > maxSeen {
		t.Fatalf("seen sets: %d pairs, %d keys", len(s.pairs), len(s.keys))
	}
	if s.observe("alice", "NG", int64(maxSeen+200)*sec, 0) {
		t.Fatal("alice's usual country fired as new after a trim")
	}
	if !s.observe("alice", "FR", int64(maxSeen+201)*sec, 0) {
		t.Fatal("control: a new country of a kept key fires")
	}
	// Encoding keeps a pair's key.
	got, err := decodeSeen(s.encode())
	if err != nil || len(got.pairs) != len(s.pairs) || len(got.keys) != len(s.keys) {
		t.Fatalf("round trip: %v", err)
	}
	for h, p := range s.pairs {
		if got.pairs[h] != p {
			t.Fatalf("pair %x: %+v, want %+v", h, got.pairs[h], p)
		}
	}
}

// 15. A detection is emitted only once stored, with its ID.
func TestEmittedOnlyOnceWritten(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, oneRule(siem.SevLow))
	restore := failWrites(t, h)
	h.feed(sshFail(0, "203.0.113.7"))
	h.e.flush(false)
	if evs := h.out.events(); len(evs) != 0 {
		t.Fatalf("emitted before it was stored: %+v", evs)
	}
	restore()
	h.clk.advance(writeBackoffMin)
	h.e.flush(false)
	evs := h.out.events()
	ds := h.all(t)
	if len(evs) != 1 || len(ds) != 1 || evs[0].F["detection_id"] != float64(ds[0].ID) || ds[0].ID == 0 {
		t.Fatalf("emitted once stored: %+v (stored %+v)", evs, ds)
	}
}

// 16. A stored built-in setting that doesn't validate falls back for that setting only.
func TestStoredOverridePerField(t *testing.T) {
	h := newHarness(t, true)
	snooze := t0.Add(60 * 24 * time.Hour).Format(time.RFC3339)
	for id, js := range map[string]string{
		"ssh.bruteforce": `{"enabled":false,"severity":"high","count":7,"window":600000000000,"snoozed_until":"` + snooze + `"}`,
		"edge.scan":      `{"enabled":true,"severity":"critical","count":0,"window":120000000000}`,
	} {
		if _, err := h.main.Exec(`INSERT INTO security_rules(id, json, updated_at) VALUES (?, ?, 1)`, id, js); err != nil {
			t.Fatal(err)
		}
	}
	h.reopen(t)
	if r, _ := findRule(t, h.e, "ssh.bruteforce"); r.Enabled || r.Count != 7 || r.Severity != siem.SevHigh || !r.SnoozedUntil.IsZero() {
		t.Errorf("too long a snooze: switched off and the count kept, the snooze dropped: %+v", r)
	}
	p := packByID["edge.scan"]
	if r, _ := findRule(t, h.e, "edge.scan"); r.Count != p.Count || r.Window != 2*time.Minute || r.Severity != siem.SevCritical {
		t.Errorf("bad count: the pack's count, the stored window and severity: %+v", r)
	}
}

// 16. A stored custom rule that doesn't validate is listed switched off, counts toward the limit,
// and can be fixed or deleted.
func TestInvalidStoredCustomRuleListed(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	for i := range MaxCustomRules - 2 {
		if err := h.e.SaveRule(ctx, customRule(fmt.Sprint("r", i))); err != nil {
			t.Fatal(err)
		}
	}
	for id, js := range map[string]string{
		"custom.broken":                      `{"name":"Broken <x>","type":"threshold","query":"nosuch:1","severity":"bogus","count":1,"window":60000000000,"enabled":true,"mitre":["T1078","x"]}`,
		"custom.garbled":                     `not json`,
		"custom." + strings.Repeat("a", 200): `{"name":"long"}`,
	} {
		if _, err := h.main.Exec(`INSERT INTO security_rules(id, json, updated_at) VALUES (?, ?, 1)`, id, js); err != nil {
			t.Fatal(err)
		}
	}
	h.reopen(t)
	r, ok := findRule(t, h.e, "custom.broken")
	if !ok || r.Enabled || r.Builtin || r.Name != "Broken x" || r.Severity != siem.SevLow || len(r.MITRE) != 1 ||
		r.Description != `stored rule is invalid: unknown severity "bogus" (low, medium, high, critical)` {
		t.Fatalf("listed invalid rule: %+v", r)
	}
	if r, ok := findRule(t, h.e, "custom.garbled"); !ok || r.Enabled || !strings.Contains(r.Description, "unreadable") {
		t.Fatalf("unreadable rule: %+v", r)
	}
	if _, ok := findRule(t, h.e, "custom."+strings.Repeat("a", 200)); ok {
		t.Fatal("a rule with a 207-byte ID listed")
	}
	if rs, _ := h.e.Rules(ctx); len(rs) != len(pack)+MaxCustomRules {
		t.Fatalf("%d rules listed", len(rs))
	}
	// 98 valid + 2 invalid listed: at the limit (the unlisted one doesn't count).
	if err := h.e.SaveRule(ctx, customRule("one-more")); !errors.Is(err, siem.ErrInvalidRule) {
		t.Fatalf("past the limit: %v", err)
	}
	// Fixed from the dashboard: evaluated.
	fixed := customRule("broken")
	if err := h.e.SaveRule(ctx, fixed); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.e.rules.Load().byID["custom.broken"]; !ok {
		t.Fatal("fixed rule not evaluated")
	}
	if err := h.e.DeleteRule(ctx, "custom.garbled"); err != nil {
		t.Fatal(err)
	}
	if err := h.e.SaveRule(ctx, customRule("one-more")); err != nil {
		t.Fatalf("after deleting the invalid one: %v", err)
	}
}

// ErrInvalid is the contract's ErrInvalidRule.
func TestErrInvalidIsContractError(t *testing.T) {
	h := newHarness(t, true)
	r := customRule("x")
	r.Count = 0
	if err := h.e.SaveRule(context.Background(), r); !errors.Is(err, siem.ErrInvalidRule) || !errors.Is(err, ErrInvalid) {
		t.Fatalf("validation error %v", err)
	}
}

// 17. An address on a block list and the Tor list fires the block list's rules; a sign-in over
// Tor fires its own (medium) rule.
func TestListedTorExit(t *testing.T) {
	h := newHarness(t, false)
	g := &siem.Geo{Country: "DE", City: "Berlin", Lat: 52.5, Lon: 13.4, Lists: []string{"spamhaus-drop", "tor-exit"}}
	h.host(t, 0, "sshd[1]", "Accepted password for root from 198.51.100.77 port 40000 ssh2", g)
	e := ev(time.Second, siem.SrcEdge, siem.KindHTTPRequest, "", "198.51.100.77", "", map[string]any{"status": float64(200), "host": "x"})
	e.Geo = g
	h.feed(e)
	h.mooring(2*time.Second, audit.Event{Actor: "operator", IP: "198.51.100.78", Action: "login", Outcome: audit.OK,
		Level: audit.Security}, &siem.Geo{Lists: []string{"tor-exit"}})
	got := ruleIDs(h.all(t))
	for _, id := range []string{"ssh.login_spamhaus_ip", "edge.spamhaus_ip", "ssh.login_tor", "mooring.login_tor"} {
		if got[id] != 1 {
			t.Errorf("%s: %d detections (%v)", id, got[id], got)
		}
	}
	if got["ssh.login_dshield_ip"] != 0 || got["edge.dshield_ip"] != 0 {
		t.Errorf("a list the address isn't on fired: %v", got)
	}
	for _, id := range []string{"ssh.login_tor", "mooring.login_tor"} {
		if r := packByID[id]; r.Severity != siem.SevMedium || !strings.Contains(strings.Join(r.MITRE, ","), "T1090.003") {
			t.Errorf("%s: %+v", id, r.Rule)
		}
	}
}

// 18. Detections are listed most recently seen first and paged by (Last, ID).
func TestDetectionsOrderedByLastSeen(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, oneRule(siem.SevLow))
	h.feed(sshFail(0, "203.0.113.1"), sshFail(time.Minute, "203.0.113.2"))
	h.feed(sshFail(2*time.Minute, "203.0.113.1")) // the first detection is seen again
	ds := h.all(t)
	if len(ds) != 2 || ds[0].Key != "203.0.113.1" || ds[0].ID > ds[1].ID {
		t.Fatalf("most recently seen first: %+v", ds)
	}
	// Five detections last seen at the same time: paged one by one, each once.
	for i := range 5 {
		h.e.report(siem.Detection{RuleID: "ops:a/s/x", Key: fmt.Sprint("k", i), Last: t0.Add(3 * time.Minute)})
	}
	h.e.flush(true)
	ctx := context.Background()
	var (
		order []string
		bl    time.Time
		b     int64
	)
	for range 20 {
		p, err := h.e.Detections(ctx, siem.DetectionFilter{BeforeLast: bl, Before: b, Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		if len(p) == 0 {
			break
		}
		order = append(order, p[0].Key)
		bl, b = p[0].Last, p[0].ID
	}
	if strings.Join(order, ",") != "k4,k3,k2,k1,k0,203.0.113.1,203.0.113.2" {
		t.Fatalf("paged order %v", order)
	}
	// BeforeLast alone: only those seen before it.
	p, _ := h.e.Detections(ctx, siem.DetectionFilter{BeforeLast: t0.Add(3 * time.Minute)})
	if len(p) != 2 {
		t.Fatalf("before 3m: %+v", p)
	}
	// From/To bound Last.
	if p, _ := h.e.Detections(ctx, siem.DetectionFilter{From: t0.Add(90 * time.Second), To: t0.Add(3 * time.Minute)}); len(p) != 1 ||
		p[0].Key != "203.0.113.1" {
		t.Fatalf("from-to on last: %+v", p)
	}
	if p, _ := h.e.Detections(ctx, siem.DetectionFilter{To: t0.Add(2 * time.Minute)}); len(p) != 1 || p[0].Key != "203.0.113.2" {
		t.Fatalf("to on last (203.0.113.1 began before, but was last seen at 2m): %+v", p)
	}
	var plan, detail string
	rows, err := h.e.db.r.Query(`EXPLAIN QUERY PLAN SELECT `+detCols+` FROM detections WHERE (last_ns, id) < (?, ?)
		ORDER BY last_ns DESC, id DESC LIMIT 50`, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var a, b2, c int
		if err := rows.Scan(&a, &b2, &c, &detail); err != nil {
			t.Fatal(err)
		}
		plan += detail + "; "
	}
	rows.Close()
	if !strings.Contains(plan, "detections_last_id") || strings.Contains(plan, "TEMP B-TREE") {
		t.Fatalf("query plan: %s", plan)
	}
	var v int
	if err := h.e.db.w.QueryRow(`SELECT MAX(version) FROM schema_version`).Scan(&v); err != nil || v != 6 {
		t.Fatalf("schema version %d, %v", v, err)
	}
}
