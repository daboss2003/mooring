package opsalert

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/ops"
	"github.com/daboss2003/mooring/internal/siem"
)

var (
	t0      = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	drops   = definition.OpsMetricRef{Group: "Limiter", Label: "Ratelimit drops"}
	qps     = definition.OpsMetricRef{Queue: "dns", Count: "qps"}
	errsRef = definition.OpsMetricRef{Group: "Upstream", Label: "Errors"}
	key     = Key{App: "shop", Service: "resolver", Name: "a"}
)

const step = 30 * time.Second

// feed observes vs at t0, t0+30s, … and returns every report (index of the sample → report).
func feed(e *Evaluator, a Alert, from time.Time, vs ...float64) map[int]Report {
	out := map[int]Report{}
	for i, v := range vs {
		if r, ok := e.Observe(key, a, "c1", from.Add(time.Duration(i)*step), v); ok {
			out[i] = r
		}
	}
	return out
}

func repeat(v float64, n int) []float64 {
	out := make([]float64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func TestFromDefinitionDefaults(t *testing.T) {
	cases := map[string]struct {
		in   definition.OpsAlert
		want Alert
	}{
		"increases": {definition.OpsAlert{Name: "a", Metric: drops, When: "increases"},
			Alert{Name: "a", Metric: drops, When: WhenIncreases, Window: 5 * time.Minute, Severity: siem.SevHigh}},
		"above": {definition.OpsAlert{Name: "a", Metric: errsRef, When: "above", Value: 50, Severity: "critical"},
			Alert{Name: "a", Metric: errsRef, When: WhenAbove, Value: 50, Window: time.Minute, Severity: siem.SevCritical}},
		"above_usual": {definition.OpsAlert{Name: "a", Metric: qps, When: "above_usual", Min: 200, Window: "2m", Severity: "medium"},
			Alert{Name: "a", Metric: qps, When: WhenAboveUsual, Factor: 5, Min: 200, Window: 2 * time.Minute, Severity: siem.SevMedium}},
		"explicit factor": {definition.OpsAlert{Name: "a", Metric: qps, When: "above_usual", Factor: 2.5},
			Alert{Name: "a", Metric: qps, When: WhenAboveUsual, Factor: 2.5, Window: time.Minute, Severity: siem.SevHigh}},
	}
	for name, c := range cases {
		if got := FromDefinition(c.in); got != c.want {
			t.Errorf("%s: got %+v, want %+v", name, got, c.want)
		}
	}
}

func TestValue(t *testing.T) {
	res := &ops.Result{Mode: ops.RICH,
		Metrics: []ops.MetricGroup{
			{Title: "Limiter", Items: []ops.MetricItem{{Label: "Ratelimit drops", Value: "98123"}, {Label: "Active", Value: "1.5e3"}}},
			{Title: "Rules", Items: []ops.MetricItem{{Label: "Categories", Value: "ads,malware"}, {Label: "NaN", Value: "NaN"}, {Label: "Inf", Value: "+Inf"}, {Label: "Empty", Value: ""}}},
			{Title: "Limiter", Items: []ops.MetricItem{{Label: "Empty questions", Value: "7"}}}, // a second group with the same title
		},
		Queues: []ops.Queue{{Name: "dns", Counts: []ops.QueueCount{{Name: "qps", Value: 143}}}},
	}
	cases := map[string]struct {
		ref  definition.OpsMetricRef
		want float64
		ok   bool
	}{
		"integer":          {drops, 98123, true},
		"exponent":         {definition.OpsMetricRef{Group: "Limiter", Label: "Active"}, 1500, true},
		"second group":     {definition.OpsMetricRef{Group: "Limiter", Label: "Empty questions"}, 7, true},
		"queue count":      {qps, 143, true},
		"non-numeric":      {definition.OpsMetricRef{Group: "Rules", Label: "Categories"}, 0, false},
		"NaN":              {definition.OpsMetricRef{Group: "Rules", Label: "NaN"}, 0, false},
		"Inf":              {definition.OpsMetricRef{Group: "Rules", Label: "Inf"}, 0, false},
		"empty":            {definition.OpsMetricRef{Group: "Rules", Label: "Empty"}, 0, false},
		"missing label":    {definition.OpsMetricRef{Group: "Limiter", Label: "Nope"}, 0, false},
		"missing group":    {definition.OpsMetricRef{Group: "Cache", Label: "Ratelimit drops"}, 0, false},
		"label case":       {definition.OpsMetricRef{Group: "Limiter", Label: "ratelimit drops"}, 0, false},
		"missing queue":    {definition.OpsMetricRef{Queue: "mail", Count: "qps"}, 0, false},
		"missing count":    {definition.OpsMetricRef{Queue: "dns", Count: "waiting"}, 0, false},
		"queue not metric": {definition.OpsMetricRef{Group: "dns", Label: "qps"}, 0, false},
	}
	for name, c := range cases {
		got, ok := Value(res, c.ref)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: Value = %v, %v; want %v, %v", name, got, ok, c.want, c.ok)
		}
	}
	if _, ok := Value(&ops.Result{Mode: ops.BASIC, Queues: res.Queues}, qps); ok {
		t.Error("a BASIC (failed) result must carry no value")
	}
	if _, ok := Value(nil, qps); ok {
		t.Error("a nil result must carry no value")
	}
}

func TestIncreases(t *testing.T) {
	a := Alert{Name: "a", Metric: drops, When: WhenIncreases, Value: 100, Window: time.Minute, Severity: siem.SevHigh}

	// Rises by exactly 100 over the minute: not more than value.
	if got := feed(NewEvaluator(), a, t0, 1000, 1050, 1100); len(got) != 0 {
		t.Errorf("a rise of exactly value must not fire: %+v", got)
	}
	// Rises by 200 over the minute (t+30s → t+90s).
	got := feed(NewEvaluator(), a, t0, 1000, 1000, 1100, 1200)
	r, ok := got[3]
	if len(got) != 1 || !ok {
		t.Fatalf("a rise of 200 in 1m must fire once at the 4th sample: %+v", got)
	}
	if want := "Limiter / Ratelimit drops rose by 200 in 1m (now 1200)"; r.Summary != want {
		t.Errorf("summary = %q, want %q", r.Summary, want)
	}
	// No sample at or before now-window yet: the comparison point doesn't exist.
	if got := feed(NewEvaluator(), a, t0, 0, 5000); len(got) != 0 {
		t.Errorf("must not fire before the history covers the window: %+v", got)
	}
}

// A counter that drops restarted: the rise counts from 0 at the drop, never as a negative delta.
func TestIncreasesCounterReset(t *testing.T) {
	a := Alert{Name: "a", Metric: drops, When: WhenIncreases, Value: 200, Window: 90 * time.Second, Severity: siem.SevHigh}
	// Window 90 s at the 4th sample: baseline 1000 → 1100 (+100) → 50 (restart: +50) → 120 (+70) = 220.
	got := feed(NewEvaluator(), a, t0, 1000, 1100, 50, 120)
	r, ok := got[3]
	if !ok {
		t.Fatalf("rise of 220 across a restart must fire: %+v", got)
	}
	if want := "Limiter / Ratelimit drops rose by 220 in 1m30s (now 120)"; r.Summary != want {
		t.Errorf("summary = %q, want %q", r.Summary, want)
	}
	// A restart alone (1000 → 0 → 10) is a rise of 10, not a fire.
	if got := feed(NewEvaluator(), Alert{Name: "a", Metric: drops, When: WhenIncreases, Value: 50, Window: time.Minute}, t0, 1000, 0, 10); len(got) != 0 {
		t.Errorf("a restart must not count as a rise: %+v", got)
	}
}

func TestAboveSustainedVsDip(t *testing.T) {
	a := Alert{Name: "a", Metric: errsRef, When: WhenAbove, Value: 50, Window: time.Minute, Severity: siem.SevHigh}

	got := feed(NewEvaluator(), a, t0, 10, 60, 70, 75)
	if len(got) != 1 {
		t.Fatalf("above for 1m must fire once: %+v", got)
	}
	if r := got[3]; r.Summary != "Upstream / Errors above 50 for 1m (now 75)" {
		t.Errorf("report = %+v", r)
	}
	// Above at t+30s and t+60s only: held 30 s, not the minute.
	if got := feed(NewEvaluator(), a, t0, 10, 60, 70); len(got) != 0 {
		t.Errorf("above for less than the window must not fire: %+v", got)
	}
	// One dip inside the window.
	if got := feed(NewEvaluator(), a, t0, 60, 70, 40, 80, 90); len(got) != 0 {
		t.Errorf("a dip within the window must not fire: %+v", got)
	}
	// Equal to the limit is not above it.
	if got := feed(NewEvaluator(), a, t0, 50, 50, 50, 50); len(got) != 0 {
		t.Errorf("a value equal to the limit must not fire: %+v", got)
	}
}

func TestAboveUsual(t *testing.T) {
	a := Alert{Name: "a", Metric: qps, When: WhenAboveUsual, Factor: 5, Window: time.Minute, Severity: siem.SevHigh}
	hour := int(time.Hour / step) // samples in an hour

	// Warm-up: 1 h of history (but not 1 h + window) then a spike: no fire.
	if got := feed(NewEvaluator(), a, t0, append(repeat(100, hour-1), 1000, 1000, 1000)...); len(got) != 0 {
		t.Errorf("must not fire during the warm-up: %+v", got)
	}
	// After the warm-up the same spike fires.
	got := feed(NewEvaluator(), a, t0, append(repeat(100, hour+2), 1000, 1000, 1000)...)
	if len(got) != 1 {
		t.Fatalf("spike after the warm-up must fire once: %+v", got)
	}
	for _, r := range got {
		if want := "queue dns qps 1000 for 1m, usual 100 (×10)"; r.Summary != want {
			t.Errorf("summary = %q, want %q", r.Summary, want)
		}
	}

	// Usual is the median: rare big outliers don't raise it (the mean of this history is about 1150,
	// which would make 600 an ordinary value).
	hist := repeat(100, hour+2)
	for i := 0; i < len(hist); i += 10 {
		hist[i] = 10000
	}
	if got := feed(NewEvaluator(), a, t0, append(hist, 600, 600, 600)...); len(got) != 1 {
		t.Errorf("600 against a median of 100 (factor 5) must fire: %+v", got)
	}

	// Factor: 450 is 4.5× the usual 100 — below factor 5, above factor 4.
	if got := feed(NewEvaluator(), a, t0, append(repeat(100, hour+2), 450, 450, 450)...); len(got) != 0 {
		t.Errorf("4.5× must not fire at factor 5: %+v", got)
	}
	a4 := a
	a4.Factor = 4
	if got := feed(NewEvaluator(), a4, t0, append(repeat(100, hour+2), 450, 450, 450)...); len(got) != 1 {
		t.Errorf("4.5× must fire at factor 4: %+v", got)
	}

	// Min: usual 10 → 5× is 50, but min 200 holds the bar at 200.
	am := a
	am.Min = 200
	if got := feed(NewEvaluator(), am, t0, append(repeat(10, hour+2), 150, 150, 150)...); len(got) != 0 {
		t.Errorf("150 must not fire below min 200: %+v", got)
	}
	got = feed(NewEvaluator(), am, t0, append(repeat(10, hour+2), 250, 250, 250)...)
	if len(got) != 1 {
		t.Fatalf("250 must fire above min 200: %+v", got)
	}
	for _, r := range got {
		if want := "queue dns qps 250 for 1m, usual 10 (×25)"; r.Summary != want {
			t.Errorf("summary = %q, want %q", r.Summary, want)
		}
	}

	// A usual level of 0 has no ratio.
	got = feed(NewEvaluator(), am, t0, append(repeat(0, hour+2), 250, 250, 250)...)
	if len(got) != 1 {
		t.Errorf("250 against a usual 0 must fire above min 200: %+v", got)
	}
	for _, r := range got {
		if want := "queue dns qps 250 for 1m, usual 0"; r.Summary != want {
			t.Errorf("summary = %q, want %q", r.Summary, want)
		}
	}
	// A spike that doesn't hold for the window.
	if got := feed(NewEvaluator(), a, t0, append(repeat(100, hour+2), 1000, 90, 1000)...); len(got) != 0 {
		t.Errorf("a spike with a dip must not fire: %+v", got)
	}
}

// While a condition holds, reports repeat at most once per max(window, 15m), all with the run's first
// time; a run that ends starts again.
func TestReportThrottling(t *testing.T) {
	a := Alert{Name: "a", Metric: errsRef, When: WhenAbove, Value: 50, Window: time.Minute, Severity: siem.SevHigh}
	e := NewEvaluator()
	n := int(32 * time.Minute / step)
	got := feed(e, a, t0, append([]float64{10}, repeat(99, n)...)...)
	// Fires at sample 3 (t0+90s), again 15 m later (sample 33), again at sample 63.
	want := []int{3, 33, 63}
	if len(got) != len(want) {
		t.Fatalf("reports at %v, want at %v", keys(got), want)
	}
	for _, i := range want {
		r, ok := got[i]
		if !ok {
			t.Errorf("no report at sample %d: %v", i, keys(got))
			continue
		}
		if !r.First.Equal(t0.Add(3*step)) || !r.Last.Equal(t0.Add(time.Duration(i)*step)) {
			t.Errorf("sample %d: first %v last %v", i, r.First, r.Last)
		}
	}
	// The condition clears, then holds again: a new run, reported at once.
	from := t0.Add(time.Duration(n+1) * step)
	got = feed(e, a, from, 10, 99, 99, 99)
	if r, ok := got[3]; !ok || len(got) != 1 || !r.First.Equal(from.Add(3*step)) {
		t.Errorf("a new run must report at once with its own first time: %+v", got)
	}

	// A window longer than 15 m sets the repeat interval.
	long := Alert{Name: "a", Metric: errsRef, When: WhenAbove, Value: 50, Window: 20 * time.Minute, Severity: siem.SevHigh}
	got = feed(NewEvaluator(), long, t0, repeat(99, int(61*time.Minute/step))...)
	_, r40 := got[40]
	_, r80 := got[80]
	_, r120 := got[120]
	if len(got) != 3 || !r40 || !r80 || !r120 {
		t.Errorf("window 20m must repeat every 20m: reports at %v", keys(got))
	}
}

func keys(m map[int]Report) []int {
	var out []int
	for k := range m {
		out = append(out, k)
	}
	return out
}

// The history is bounded: samples older than 24 h go (one is kept as the 24 h comparison point), and
// never more than MaxSamples.
func TestHistoryBounded(t *testing.T) {
	a := Alert{Name: "a", Metric: drops, When: WhenIncreases, Window: 24 * time.Hour, Severity: siem.SevHigh}
	e := NewEvaluator()
	n := int(25 * time.Hour / step)
	for i := 0; i < n; i++ {
		e.Observe(key, a, "c1", t0.Add(time.Duration(i)*step), float64(i))
	}
	if got, want := e.Samples(key), int(24*time.Hour/step)+1; got != want {
		t.Errorf("samples after 25 h = %d, want %d", got, want)
	}
	// A sample every second for an hour stays within MaxSamples.
	e2 := NewEvaluator()
	for i := 0; i < 3600; i++ {
		e2.Observe(key, a, "c1", t0.Add(time.Duration(i)*time.Second), 1)
	}
	if got := e2.Samples(key); got != MaxSamples {
		t.Errorf("samples = %d, want the %d cap", got, MaxSamples)
	}
	// An out-of-order or repeated timestamp is dropped, also from another source.
	e3 := NewEvaluator()
	e3.Observe(key, a, "c1", t0, 1)
	e3.Observe(key, a, "c1", t0, 2)
	e3.Observe(key, a, "c1", t0.Add(-time.Second), 3)
	e3.Observe(key, a, "c2", t0, 4)
	if got := e3.Samples(key); got != 1 {
		t.Errorf("samples = %d, want 1", got)
	}
	// A non-finite value is no sample.
	e3.Observe(key, a, "c1", t0.Add(time.Second), nan())
	if got := e3.Samples(key); got != 1 {
		t.Errorf("NaN must not be stored: %d samples", got)
	}
}

func nan() float64 { var z float64; return z / z }

// A changed metric starts the history again; a changed limit keeps the history but ends the run.
func TestAlertChange(t *testing.T) {
	a := Alert{Name: "a", Metric: errsRef, When: WhenAbove, Value: 50, Window: time.Minute, Severity: siem.SevHigh}
	e := NewEvaluator()
	feed(e, a, t0, 99, 99, 99, 99)
	if e.Samples(key) != 4 {
		t.Fatalf("samples = %d", e.Samples(key))
	}
	b := a
	b.Metric = drops
	e.Observe(key, b, "c1", t0.Add(4*step), 1)
	if got := e.Samples(key); got != 1 {
		t.Errorf("a new metric must start a new history: %d samples", got)
	}
	c := b
	c.Value = 0.5
	e.Observe(key, c, "c1", t0.Add(5*step), 1)
	if got := e.Samples(key); got != 2 {
		t.Errorf("a new limit keeps the history: %d samples", got)
	}
	// Run state: a continuing run with a new limit reports again at once, as a new run.
	e2 := NewEvaluator()
	got := feed(e2, a, t0, 99, 99, 99, 99)
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	d := a
	d.Value = 60
	if r, ok := e2.Observe(key, d, "c1", t0.Add(4*step), 99); !ok || !r.First.Equal(t0.Add(4*step)) {
		t.Errorf("a changed condition must start a new run: %+v %v", r, ok)
	}
}

func TestRetain(t *testing.T) {
	a := Alert{Name: "a", Metric: drops, When: WhenIncreases, Window: time.Minute}
	e := NewEvaluator()
	other := Key{App: "shop", Service: "", Name: "b"}
	e.Observe(key, a, "c1", t0, 1)
	e.Observe(other, a, "c1", t0, 1)
	e.Retain(func(k Key) bool { return k == other })
	if e.Samples(key) != 0 || e.Samples(other) != 1 || e.Len() != 1 {
		t.Errorf("Retain kept %d alerts (key %d, other %d samples)", e.Len(), e.Samples(key), e.Samples(other))
	}
}

// observeAt observes v at each offset from t0 (offsets in seconds) and returns the offsets that fired.
func observeAt(e *Evaluator, a Alert, src string, pts ...[2]float64) []float64 {
	var fired []float64
	for _, p := range pts {
		if _, ok := e.Observe(key, a, src, t0.Add(time.Duration(p[0])*time.Second), p[1]); ok {
			fired = append(fired, p[0])
		}
	}
	return fired
}

// After a gap in the readings (failed probes) the reading before it is no comparison point: a 2 h
// outage's rise is not a rise "in 5m". The comparison reading may be one missed reading (MaxGap)
// older than the window, no more.
func TestIncreasesAfterGap(t *testing.T) {
	a := Alert{Name: "a", Metric: drops, When: WhenIncreases, Value: 100, Window: 5 * time.Minute, Severity: siem.SevHigh}
	e := NewEvaluator()
	ts, v := t0, 0.0
	for i := 0; i < 20; i++ { // 10 minutes of +1 per reading: never fires
		ts, v = ts.Add(step), v+1
		if _, ok := e.Observe(key, a, "c1", ts, v); ok {
			t.Fatal("fired in the quiet period")
		}
	}
	// 2 h without readings while the counter grew by 240 (2 a minute, well under 100 per 5m).
	ts, v = ts.Add(2*time.Hour), v+240
	if r, ok := e.Observe(key, a, "c1", ts, v); ok {
		t.Fatalf("a rise across a 2 h gap must not fire as a rise in 5m: %q", r.Summary)
	}
	// Readings resume; until they reach back 5m nothing fires, then a real rise does.
	for i := 0; i < 10; i++ {
		ts = ts.Add(step)
		if _, ok := e.Observe(key, a, "c1", ts, v); ok {
			t.Fatalf("fired at reading %d after the gap, before a real rise", i)
		}
	}
	if _, ok := e.Observe(key, a, "c1", ts.Add(step), v+200); !ok {
		t.Error("a real rise once the history covers the window again must fire")
	}

	w := Alert{Name: "a", Metric: drops, When: WhenIncreases, Value: 100, Window: time.Minute, Severity: siem.SevHigh}
	// One missed reading at the window's start: the comparison reading is 90 s old (window + 30 s).
	if got := observeAt(NewEvaluator(), w, "c1", [2]float64{0, 1000}, [2]float64{60, 1000}, [2]float64{90, 1200}); len(got) != 1 || got[0] != 90 {
		t.Errorf("one missed reading must not stop the alert: fired at %v", got)
	}
	// The comparison reading exactly window + MaxGap old still counts; one second more doesn't.
	if got := observeAt(NewEvaluator(), w, "c1", [2]float64{0, 1000}, [2]float64{120, 1200}); len(got) != 1 {
		t.Errorf("a comparison reading window+MaxGap old must count: fired at %v", got)
	}
	if got := observeAt(NewEvaluator(), w, "c1", [2]float64{0, 1000}, [2]float64{121, 1200}); len(got) != 0 {
		t.Errorf("a comparison reading older than window+MaxGap must not count: fired at %v", got)
	}
}

// "Held for window" needs readings covering the window with no gap longer than MaxGap: two readings
// 2 h apart say nothing about the time between them.
func TestAboveAfterGap(t *testing.T) {
	a := Alert{Name: "a", Metric: errsRef, When: WhenAbove, Value: 10, Window: 10 * time.Minute, Severity: siem.SevHigh}
	e := NewEvaluator()
	if _, ok := e.Observe(key, a, "c1", t0, 50); ok {
		t.Fatal("fired on the first reading")
	}
	from := t0.Add(2 * time.Hour)
	got := feed(e, a, from, repeat(50, 25)...)
	// The first reading 10 m after the gap (index 20) is the first with a gap-free window.
	if _, ok := got[20]; !ok || len(got) != 1 {
		t.Errorf("above after a 2 h gap must wait for 10 m of readings: reports at %v", keys(got))
	}

	w := Alert{Name: "a", Metric: errsRef, When: WhenAbove, Value: 10, Window: 2 * time.Minute, Severity: siem.SevHigh}
	// One missed reading (60 s apart) inside the window: still held.
	if got := observeAt(NewEvaluator(), w, "c1", [2]float64{0, 50}, [2]float64{30, 50}, [2]float64{90, 50}, [2]float64{120, 50}); len(got) != 1 || got[0] != 120 {
		t.Errorf("one missed reading must not break a held window: fired at %v", got)
	}
	// Two missed readings (90 s apart) inside the window: not held until the window is past the gap.
	got2 := observeAt(NewEvaluator(), w, "c1", [2]float64{0, 50}, [2]float64{30, 50}, [2]float64{120, 50}, [2]float64{150, 50},
		[2]float64{180, 50}, [2]float64{210, 50}, [2]float64{240, 50})
	if len(got2) != 1 || got2[0] != 240 {
		t.Errorf("a 90 s gap must hold the alert back until the window is past it: fired at %v", got2)
	}

	// above_usual: the same rule for its window, after the warm-up. Usual 100, then 1000 at T and T+30s,
	// a 90 s gap, and 1000 from T+120s on: held without a gap only once the window starts at T+120s.
	u := Alert{Name: "a", Metric: qps, When: WhenAboveUsual, Factor: 5, Window: 2 * time.Minute, Severity: siem.SevHigh}
	eu := NewEvaluator()
	hour := int(time.Hour / step)
	feed(eu, u, t0, repeat(100, hour+10)...)
	T := t0.Add(time.Duration(hour+10) * step)
	var fired []int
	for _, off := range []int{0, 30, 120, 150, 180, 210, 240, 270} {
		if _, ok := eu.Observe(key, u, "c1", T.Add(time.Duration(off)*time.Second), 1000); ok {
			fired = append(fired, off)
		}
	}
	if len(fired) != 1 || fired[0] != 240 {
		t.Errorf("above_usual across a 90 s gap must wait until its window is past the gap: fired at %v s", fired)
	}
}

// The history is per source (the container a value was read from): a reading from another source
// starts it again, so another copy's unrelated counter is never a rise. A drop from the same source is
// still a counter reset.
func TestSourceSwitch(t *testing.T) {
	a := Alert{Name: "a", Metric: drops, When: WhenIncreases, Value: 100, Window: 5 * time.Minute, Severity: siem.SevHigh}
	e := NewEvaluator()
	ts, v := t0, 50000.0 // copy A, long-running
	for i := 0; i < 20; i++ {
		ts, v = ts.Add(step), v+1
		if _, ok := e.Observe(key, a, "copy-a", ts, v); ok {
			t.Fatal("fired in the quiet period")
		}
	}
	ts = ts.Add(step)
	if r, ok := e.Observe(key, a, "copy-b", ts, 30000); ok { // copy B, also long-running
		t.Fatalf("a switch to another copy must not fire: %q", r.Summary)
	}
	if n := e.Samples(key); n != 1 {
		t.Errorf("a switch must start the history again: %d samples", n)
	}
	// B's own history: quiet until it covers the window, then a real rise fires.
	b := 30000.0
	for i := 0; i < 10; i++ {
		ts, b = ts.Add(step), b+1
		if _, ok := e.Observe(key, a, "copy-b", ts, b); ok {
			t.Fatalf("fired at B's reading %d", i)
		}
	}
	if _, ok := e.Observe(key, a, "copy-b", ts.Add(step), b+500); !ok {
		t.Error("a real rise on the new copy must fire")
	}
	// Back to A (higher value): a switch again, not a rise.
	if _, ok := e.Observe(key, a, "copy-a", ts.Add(2*step), 90000); ok || e.Samples(key) != 1 {
		t.Errorf("a switch back must start the history again (%d samples)", e.Samples(key))
	}

	// A held above alert doesn't carry over a switch either.
	h := Alert{Name: "a", Metric: errsRef, When: WhenAbove, Value: 50, Window: time.Minute, Severity: siem.SevHigh}
	eh := NewEvaluator()
	feed(eh, h, t0, 99, 99, 99, 99)
	if _, ok := eh.Observe(key, h, "copy-b", t0.Add(4*step), 99); ok {
		t.Error("above must not fire on the first reading of another copy")
	}
}

func TestSummaryBounded(t *testing.T) {
	long := strings.Repeat("é", 128) // 256 bytes each
	a := Alert{Name: "a", Metric: definition.OpsMetricRef{Group: long, Label: long}, When: WhenAbove, Value: 1e12, Window: time.Minute}
	got := feed(NewEvaluator(), a, t0, 3e300, 3e300, 3e300)
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	for _, r := range got {
		if len(r.Summary) > maxSummary || !strings.HasSuffix(r.Summary, " above 1000000000000 for 1m (now 3e+300)") {
			t.Errorf("summary (%d bytes) = %q", len(r.Summary), r.Summary)
		}
		if !utf8.ValidString(r.Summary) {
			t.Errorf("summary is not valid UTF-8: %q", r.Summary)
		}
	}
}
