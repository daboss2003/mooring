package detect

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

func evictMsg(word string, i int) string {
	a, b := 'a'+rune(i%26), 'a'+rune(i/26)
	return fmt.Sprintf("%s%c%c beta%c%c gamma%c%c", word, a, b, a, b, a, b)
}

func newKeys(t *testing.T, h *harness) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, d := range h.detections(t, rulePatternNew) {
		out[d.Key] = true
	}
	return out
}

// A new template whose report waits for the next hour (patReportsPerHour were sent) is forgotten
// for room after every other unprotected template, however long ago its last line was: its report
// still comes.
func TestPatternPendingReportEvictedLast(t *testing.T) {
	t.Run("scope cap", func(t *testing.T) { pendingEvictedLast(t, 60, defaultPatLimits.templates) })
	t.Run("global cap", func(t *testing.T) { pendingEvictedLast(t, 1000, 60) })
}

func pendingEvictedLast(t *testing.T, scopeCap, globalCap int) {
	h := patHarness(t, nil)
	m := h.pm()
	m.lim.scopeTemplates, m.lim.templates, m.lim.newPerMin, m.lim.newPerHour = scopeCap, globalCap, 1000, 1000
	// Ten templates learned in one hour (unprotected), then fifty new ones: forty reported, ten waiting.
	h.learnedScope("shop", "web", t0)
	h.patTick(t0)
	var learned, fresh []string
	for i := range 10 {
		learned = append(learned, evictMsg("learned", i))
		h.mine(appLine(t0, "shop", "web", "", learned[i]))
	}
	h.learnedScope("shop", "web", t0.Add(-8*day))
	ids := make([]string, 50)
	for i := range ids {
		fresh = append(fresh, evictMsg("fresh", i))
		h.mine(appLine(t0.Add(time.Second+time.Duration(i)*time.Millisecond), "shop", "web", "", fresh[i]))
		ids[i] = h.tmplOf("shop", "web", fresh[i]).id
	}
	h.patTick(t0.Add(6 * time.Minute))
	if n := len(newKeys(t, h)); n != patReportsPerHour {
		t.Fatalf("setup: %d reports, want %d", n, patReportsPerHour)
	}
	// Every other template has a line after the waiting ones' last.
	at := t0.Add(7 * time.Minute)
	for _, msg := range append(learned, fresh[:patReportsPerHour]...) {
		h.mine(appLine(at, "shop", "web", "", msg))
	}
	// Five more new templates need room: none of the waiting ten gives it.
	for i := range 5 {
		h.mine(appLine(at.Add(time.Second), "shop", "web", "", evictMsg("later", i)))
	}
	if m.ntmpl != 60 {
		t.Fatalf("%d templates, want the cap's 60", m.ntmpl)
	}
	for i := patReportsPerHour; i < 50; i++ {
		if tp := h.tmplOf("shop", "web", fresh[i]); tp == nil || tp.id != ids[i] || !tp.pending {
			t.Fatalf("waiting template %d was forgotten for room before the reported and learned ones", i)
		}
	}
	checkPatBounds(t, m)
	h.patTick(t0.Add(time.Hour + time.Minute))
	got := newKeys(t, h)
	for i, id := range ids {
		if !got[id] {
			t.Errorf("pattern %d was never reported", i)
		}
	}
	if n := m.reportsLost.Load(); n != 0 {
		t.Errorf("%d reports counted lost", n)
	}
}

// When only templates with a waiting report, protected and owner-marked ones are left, a waiting
// one is forgotten for room before those: its report is sent then if the hour has reports left,
// else it is counted. A template that doesn't have its rule's count of lines, or is forgotten
// before it settled, is owed no report.
func TestPatternPendingReportSentAtEviction(t *testing.T) {
	ctx := context.Background()
	h := patHarness(t, nil)
	h.only(t, patRule(rulePatternNew, func(r *siem.Rule) { r.Count = 2 }), patRule(rulePatternNewError), patRule(rulePatternChurn))
	m := h.pm()
	m.lim.scopeTemplates, m.lim.newPerMin, m.lim.newPerHour = 46, 1000, 1000
	h.learnedScope("shop", "web", t0.Add(-8*day))
	h.patTick(t0)
	twice := func(at time.Time, msg string) string {
		h.mine(appLine(at, "shop", "web", "", msg), appLine(at, "shop", "web", "", msg))
		return h.tmplOf("shop", "web", msg).id
	}
	var fresh, ids []string
	for i := range 45 {
		fresh = append(fresh, evictMsg("fresh", i))
		ids = append(ids, twice(t0.Add(time.Duration(i)*time.Millisecond), fresh[i]))
	}
	h.patTick(t0.Add(6 * time.Minute))
	if n := len(newKeys(t, h)); n != patReportsPerHour {
		t.Fatalf("setup: %d reports, want %d", n, patReportsPerHour)
	}
	// The reported forty are the owner's (expected) but two, seen in a second hour: protected.
	// Only the five waiting are unprotected.
	for _, id := range ids[2:patReportsPerHour] {
		if err := h.e.SetPatternState(ctx, id, siem.PatternExpected, "o"); err != nil {
			t.Fatal(err)
		}
	}
	h.clk.set(t0.Add(8 * time.Minute))
	h.patFire()
	m.mu.Lock()
	for _, id := range ids[:2] {
		tp := m.byID[id]
		tp.seen = 2
		m.protect(tp)
	}
	m.mu.Unlock()
	// One line of a 46th template (the rule wants two): it waits too, and is the most recently used.
	h.mine(appLine(t0.Add(9*time.Minute), "shop", "web", "", "single line of a template"))
	checkPatBounds(t, m)

	// The hour's reports are used up: the two waiting longest make room, their reports are lost and counted.
	twice(t0.Add(10*time.Minute), evictMsg("later", 0))
	twice(t0.Add(10*time.Minute), evictMsg("later", 1))
	h.patFire()
	for i := range 45 {
		if gone := h.tmplOf("shop", "web", fresh[i]) == nil; gone != (i == 40 || i == 41) {
			t.Fatalf("template %d forgotten: %v (want the two waiting longest, before any protected or owner-marked one)", i, gone)
		}
	}
	if got, lost := newKeys(t, h), m.reportsLost.Load(); len(got) != patReportsPerHour || lost != 2 {
		t.Fatalf("with no reports left this hour: %d detections, %d counted lost; want %d and 2", len(got), lost, patReportsPerHour)
	}
	// The next hour has reports left: a waiting template forgotten for room is reported as it goes.
	at := t0.Add(time.Hour + 2*time.Minute)
	twice(at, evictMsg("next", 0))
	twice(at, evictMsg("next", 1))
	if h.patFire() != 2 {
		t.Fatal("want the two forgotten templates' reports sent when they were forgotten")
	}
	got := newKeys(t, h)
	if h.tmplOf("shop", "web", fresh[42]) != nil || h.tmplOf("shop", "web", fresh[43]) != nil || !got[ids[42]] || !got[ids[43]] || got[ids[44]] ||
		len(got) != patReportsPerHour+2 || m.reportsLost.Load() != 2 || m.rep[0].n != 2 {
		t.Fatalf("the next hour: reported %v %v %v of %d, %d lost", got[ids[42]], got[ids[43]], got[ids[44]], len(got), m.reportsLost.Load())
	}
	twice(at.Add(time.Second), evictMsg("next", 2))
	if got := newKeys(t, h); h.patFire() != 1 || h.tmplOf("shop", "web", fresh[44]) != nil || !newKeys(t, h)[ids[44]] || len(got) != patReportsPerHour+2 {
		t.Fatal("the last of the waiting five: want it reported as it was forgotten")
	}
	// The one-line template goes next: it was owed no report, so none is sent and none counted.
	twice(at.Add(2*time.Second), evictMsg("next", 3))
	if h.patFire() != 0 || h.tmplOf("shop", "web", "single line of a template") != nil || m.reportsLost.Load() != 2 || len(newKeys(t, h)) != patReportsPerHour+3 {
		t.Fatalf("a template without its rule's count of lines: %d reports, %d lost", len(newKeys(t, h)), m.reportsLost.Load())
	}
	// A template forgotten before it settled is owed none either.
	later := []string{h.tmplOf("shop", "web", evictMsg("later", 0)).id, h.tmplOf("shop", "web", evictMsg("later", 1)).id}
	unsettled := h.tmplOf("shop", "web", evictMsg("next", 0)).id
	twice(at.Add(3*time.Second), evictMsg("next", 4))
	twice(at.Add(3*time.Second), evictMsg("next", 5))
	if got := newKeys(t, h); h.patFire() != 2 || !newKeys(t, h)[later[0]] || !newKeys(t, h)[later[1]] || len(got) != patReportsPerHour+3 {
		t.Fatal("the two made in the hour before: want them reported as they were forgotten")
	}
	twice(at.Add(4*time.Second), evictMsg("next", 6))
	if h.patFire() != 0 || h.tmplOf("shop", "web", evictMsg("next", 0)) != nil || newKeys(t, h)[unsettled] || m.reportsLost.Load() != 2 {
		t.Fatalf("a template forgotten before it settled: reported %v, %d lost", newKeys(t, h)[unsettled], m.reportsLost.Load())
	}
	checkPatBounds(t, m)
	// The rest are reported at the tick, each once.
	h.patTick(at.Add(10 * time.Minute))
	if n, all := len(newKeys(t, h)), len(h.detections(t, rulePatternNew)); n != patReportsPerHour+5+6 || all != n || m.rep[0].n != 11 {
		t.Fatalf("after the tick: %d patterns reported in %d detections (%d counted this hour), want %d", n, all, m.rep[0].n, patReportsPerHour+5+6)
	}
}
