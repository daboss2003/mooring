package detect

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
)

// seed stores n detections: rule custom.r<i%3>, severity cycling low…critical, app a<i%2>, one
// minute apart.
func seed(t *testing.T, h *harness, n int) {
	t.Helper()
	sevs := []siem.Severity{siem.SevLow, siem.SevMedium, siem.SevHigh, siem.SevCritical}
	for i := range n {
		at := t0.Add(time.Duration(i) * time.Minute)
		h.clk.set(at)
		h.e.report(siem.Detection{RuleID: fmt.Sprint("custom.r", i%3), RuleName: "R", Severity: sevs[i%4],
			Key: fmt.Sprint("k", i), App: fmt.Sprint("a", i%2), First: at, Last: at, Summary: "s", Snoozed: true})
	}
	h.e.flush(true)
}

func TestDetectionsPagingAndFilters(t *testing.T) {
	h := newHarness(t, false)
	seed(t, h, 120)
	ctx := context.Background()
	page, err := h.e.Detections(ctx, siem.DetectionFilter{})
	if err != nil || len(page) != 50 {
		t.Fatalf("default page: %d, %v", len(page), err)
	}
	for i := 1; i < len(page); i++ {
		if !page[i].Last.Before(page[i-1].Last) {
			t.Fatal("not most recently seen first")
		}
	}
	seen := map[int64]bool{}
	var beforeLast time.Time
	before := int64(0)
	for {
		p, err := h.e.Detections(ctx, siem.DetectionFilter{BeforeLast: beforeLast, Before: before, Limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		if len(p) == 0 {
			break
		}
		for _, d := range p {
			if seen[d.ID] {
				t.Fatalf("id %d on two pages", d.ID)
			}
			seen[d.ID] = true
		}
		beforeLast, before = p[len(p)-1].Last, p[len(p)-1].ID
	}
	if len(seen) != 120 {
		t.Fatalf("paged through %d, want 120", len(seen))
	}
	if p, _ := h.e.Detections(ctx, siem.DetectionFilter{Limit: 1000}); len(p) != 120 && len(p) != 200 {
		if len(p) > 200 {
			t.Fatalf("limit not capped: %d", len(p))
		}
	}
	count := func(f siem.DetectionFilter) int {
		f.Limit = 200
		p, err := h.e.Detections(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		return len(p)
	}
	if n := count(siem.DetectionFilter{RuleID: "custom.r1"}); n != 40 {
		t.Errorf("rule filter: %d", n)
	}
	if n := count(siem.DetectionFilter{MinSeverity: siem.SevHigh}); n != 60 {
		t.Errorf("min severity high: %d", n)
	}
	if n := count(siem.DetectionFilter{MinSeverity: siem.SevCritical, App: "a1"}); n != 30 {
		t.Errorf("critical in a1: %d", n)
	}
	if n := count(siem.DetectionFilter{From: t0.Add(100 * time.Minute)}); n != 20 {
		t.Errorf("from: %d", n)
	}
	if n := count(siem.DetectionFilter{To: t0.Add(10 * time.Minute)}); n != 10 {
		t.Errorf("to (exclusive): %d", n)
	}
	if n := count(siem.DetectionFilter{From: t0.Add(10 * time.Minute), To: t0.Add(20 * time.Minute)}); n != 10 {
		t.Errorf("from-to: %d", n)
	}
	d, ok, err := h.e.Detection(ctx, page[0].ID)
	if err != nil || !ok || d.ID != page[0].ID || d.Key != page[0].Key {
		t.Fatalf("Detection(%d): %+v %v %v", page[0].ID, d, ok, err)
	}
	if _, ok, err := h.e.Detection(ctx, 99999); ok || err != nil {
		t.Fatalf("missing id: %v %v", ok, err)
	}
}

func TestReporterOpsDetections(t *testing.T) {
	h := newHarness(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.e.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	h.e.Report(siem.Detection{Source: "spoofed", RuleID: "ops:dns/resolver/upstream_down", RuleName: "Upstream down",
		Severity: siem.SevCritical, App: "dns", Service: "resolver", Count: 1, Summary: "upstream errors <!channel>",
		MITRE: []string{"T1499", "bad"}, Evidence: make([]siem.Evidence, 20)})
	h.e.Report(siem.Detection{RuleID: "ops:dns/resolver/slow", RuleName: "Slow", Severity: siem.SevMedium,
		App: "dns", Service: "resolver", Summary: "p95 high"})
	deadline := time.Now().Add(5 * time.Second)
	for len(h.al.all()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	got := h.al.all()
	if len(got) != 1 {
		t.Fatalf("alerts %+v", got)
	}
	want := alert.Outbox{Target: "dns/resolver", Kind: AlertKind, Level: alert.LevelCritical, Transition: "firing",
		Summary: "Upstream down: upstream errors !channel", DedupeKey: "siem:ops:dns/resolver/upstream_down:"}
	if got[0] != want {
		t.Fatalf("ops alert %+v\nwant %+v", got[0], want)
	}
	var ds []siem.Detection
	for time.Now().Before(deadline) {
		ds, _ = h.e.Detections(context.Background(), siem.DetectionFilter{})
		if len(ds) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(ds) != 2 {
		t.Fatalf("stored ops detections: %+v", ds)
	}
	d := ds[1]
	if d.Source != siem.DetectionOps || d.App != "dns" || d.Service != "resolver" || len(d.Evidence) != siem.MaxEvidence ||
		len(d.MITRE) != 1 || d.Count != 1 || d.First.IsZero() {
		t.Fatalf("ops detection: %+v", d)
	}
	evs := h.out.events()
	if len(evs) != 2 || evs[0].Kind != KindDetection || evs[0].Svc != "resolver" || evs[0].F["rule"] != "ops:dns/resolver/upstream_down" {
		t.Fatalf("ops events: %+v", evs)
	}
}

func TestReporterCoalescesAndSnoozes(t *testing.T) {
	h := newHarness(t, false)
	r := siem.Detection{RuleID: "ops:a/s/x", RuleName: "X", Severity: siem.SevHigh, App: "a", Service: "s", Summary: "x"}
	h.e.report(r)
	if got := h.alerts(); len(got) != 1 || got[0].Level != alert.LevelWarning {
		t.Fatalf("alerts: %+v", got)
	}
	h.clk.advance(30 * time.Minute)
	h.e.report(r)
	if ds := h.all(t); len(ds) != 1 || ds[0].Count != 2 {
		t.Fatalf("second report within the hour: %+v", ds)
	}
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("second report alerted within the hour: %+v", got)
	}
	h.clk.advance(2 * time.Hour)
	r.Snoozed = true
	h.e.report(r)
	if ds := h.all(t); len(ds) != 2 || !ds[0].Snoozed {
		t.Fatalf("report after two hours: %+v", ds)
	}
	if got := h.alerts(); len(got) != 0 {
		t.Fatalf("snoozed report alerted: %+v", got)
	}
	h.e.report(siem.Detection{}) // no rule ID: dropped
	if ds := h.all(t); len(ds) != 2 {
		t.Fatalf("empty report stored: %+v", ds)
	}
}

func TestReportNeverBlocks(t *testing.T) {
	h := newHarness(t, false)
	start := time.Now()
	for range reportQueue + 100 {
		h.e.Report(siem.Detection{RuleID: "ops:a/s/x"})
	}
	if time.Since(start) > time.Second || h.e.Stats().ReportsDropped != 100 {
		t.Fatalf("Report: %s, dropped %d", time.Since(start), h.e.Stats().ReportsDropped)
	}
}

func TestPrune(t *testing.T) {
	h := newHarness(t, false)
	h.e.report(siem.Detection{RuleID: "ops:a/s/old", Summary: "old"})
	h.clk.advance(300 * 24 * time.Hour)
	h.e.report(siem.Detection{RuleID: "ops:a/s/new", Summary: "new"})
	h.e.flush(true)
	h.clk.advance(101 * 24 * time.Hour) // old: 401 days, new: 101 days
	h.e.prune()
	ds := h.all(t)
	if len(ds) != 1 || ds[0].RuleID != "ops:a/s/new" {
		t.Fatalf("after prune: %+v", ds)
	}
}

func TestClosedEngine(t *testing.T) {
	h := newHarness(t, false)
	h.e.Close()
	if _, err := h.e.Detections(context.Background(), siem.DetectionFilter{}); err == nil {
		t.Fatal("Detections on a closed engine")
	}
	h.feed(sshFail(0, "203.0.113.7")) // no panic
	h.e.flush(true)
	h.e.persist()
	if err := h.e.Close(); err != nil {
		t.Fatal(err)
	}
}
