// Package opsalert evaluates the alerts an app declares on the values its own /ops interface reports
// (mooring.yaml ops_interface.alerts): a bounded in-memory history per alert and the three conditions
// (increases, above, above_usual). It does no I/O; the caller reads the values and reports what fires.
package opsalert

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/ops"
	"github.com/daboss2003/mooring/internal/siem"
)

// Conditions (ops_interface.alerts[].when).
const (
	WhenIncreases  = "increases"   // the value rose by more than Value within Window
	WhenAbove      = "above"       // the value stayed above Value for Window
	WhenAboveUsual = "above_usual" // the value stayed above max(Factor × the usual level, Min) for Window
)

const (
	// PollInterval is how often the caller reads the values.
	PollInterval = 30 * time.Second
	// MaxGap is the longest time between two readings that still count as one unbroken history (one
	// missed reading). A comparison reading may be at most this much older than the window, and a
	// held condition needs readings no further apart than this.
	MaxGap = 2 * PollInterval
	// History is how far back the samples of one alert reach.
	History = 24 * time.Hour
	// MaxSamples bounds one alert's samples (24 h at a 30 s poll is 2880).
	MaxSamples = 3000
	// WarmUp is how much history before its window an above_usual alert needs before it can fire.
	WarmUp = time.Hour
	// MinRepeat is the shortest interval between two reports of one run.
	MinRepeat = 15 * time.Minute

	defaultIncreasesWindow = 5 * time.Minute
	defaultHeldWindow      = time.Minute
	defaultFactor          = 5
	maxSummary             = 300 // siem.Detection.Summary bound
	maxNamePart            = 64  // bytes of a group/label/queue/count name in a summary
)

// Alert is one ops_interface alert with its defaults applied.
type Alert struct {
	Name     string
	Metric   definition.OpsMetricRef
	When     string
	Value    float64
	Factor   float64
	Min      float64
	Window   time.Duration
	Severity siem.Severity
}

// FromDefinition applies the defaults to a validated definition alert: window 5m for increases and
// 1m otherwise, factor 5 for above_usual, severity high.
func FromDefinition(d definition.OpsAlert) Alert {
	a := Alert{Name: d.Name, Metric: d.Metric, When: d.When, Value: d.Value, Factor: d.Factor, Min: d.Min, Severity: siem.Severity(d.Severity)}
	if w, err := time.ParseDuration(d.Window); err == nil && w > 0 {
		a.Window = w
	} else if a.When == WhenIncreases {
		a.Window = defaultIncreasesWindow
	} else {
		a.Window = defaultHeldWindow
	}
	if a.When == WhenAboveUsual && a.Factor == 0 {
		a.Factor = defaultFactor
	}
	if a.Severity == "" {
		a.Severity = siem.SevHigh
	}
	return a
}

// Value reads one metric from an ops result: a /metrics item's value parsed as a number (group title
// and item label matched exactly), or a /queues count. ok is false when the result is not RICH, does
// not carry the value, or the value is not a finite number.
func Value(res *ops.Result, m definition.OpsMetricRef) (float64, bool) {
	if res == nil || res.Mode != ops.RICH {
		return 0, false
	}
	if m.Queue != "" {
		for _, q := range res.Queues {
			if q.Name != m.Queue {
				continue
			}
			for _, c := range q.Counts {
				if c.Name == m.Count {
					return float64(c.Value), true
				}
			}
		}
		return 0, false
	}
	for _, g := range res.Metrics {
		if g.Title != m.Group {
			continue
		}
		for _, it := range g.Items {
			if it.Label != m.Label {
				continue
			}
			v, err := strconv.ParseFloat(strings.TrimSpace(it.Value), 64)
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
				return 0, false
			}
			return v, true
		}
	}
	return 0, false
}

// Key identifies one alert: its app, its service ("" for the app-level ops_interface) and its name.
type Key struct {
	App, Service, Name string
}

// Report is one firing the caller should send on.
type Report struct {
	First   time.Time // when the current run was first reported
	Last    time.Time // this sample's time
	Summary string    // one line, at most 300 bytes
}

type sample struct {
	ts time.Time
	v  float64
}

type state struct {
	alert   Alert
	src     string   // where the samples were read (the container)
	samples []sample // oldest first, strictly increasing ts
	running bool     // the condition held at the last evaluation
	first   time.Time
	last    time.Time // the last report of the run
}

// Evaluator keeps every alert's history and run state in memory. It is not safe for concurrent use.
type Evaluator struct {
	states map[Key]*state
}

// NewEvaluator returns an empty Evaluator.
func NewEvaluator() *Evaluator { return &Evaluator{states: map[Key]*state{}} }

// Observe adds the alert's value read at ts from src (the container it came from) and evaluates the
// alert at ts. It returns a report when the condition holds and either no report was made yet in this
// run or the last one is at least max(Window, MinRepeat) old. A non-finite value, or a ts not after the
// alert's latest sample, is ignored. A changed metric or another src starts the history again; any
// other change to the alert starts a new run.
func (e *Evaluator) Observe(k Key, a Alert, src string, ts time.Time, v float64) (Report, bool) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return Report{}, false
	}
	st := e.states[k]
	switch {
	case st == nil || st.alert.Metric != a.Metric:
		st = &state{src: src}
		e.states[k] = st
	case st.alert != a:
		st.running = false
	}
	st.alert = a
	if n := len(st.samples); n > 0 && !ts.After(st.samples[n-1].ts) {
		return Report{}, false
	}
	if st.src != src {
		// Intentional: a value read from another container (a scaled service's probe reaching another
		// copy, a recreated container) is unrelated to the history — neither a rise nor a counter
		// reset — so the history starts again from it.
		st.src, st.samples, st.running = src, st.samples[:0], false
	}
	st.samples = append(st.samples, sample{ts: ts, v: v})
	st.trim(ts)

	summary, holds := evaluate(a, st.samples, ts)
	if !holds {
		st.running = false
		return Report{}, false
	}
	if st.running && ts.Sub(st.last) < max(a.Window, MinRepeat) {
		return Report{}, false
	}
	if !st.running {
		st.running, st.first = true, ts
	}
	st.last = ts
	return Report{First: st.first, Last: ts, Summary: summary}, true
}

// trim drops the samples older than the newest one at or before now − History (that one stays as the
// comparison point of a 24 h window), then the oldest beyond MaxSamples.
func (st *state) trim(now time.Time) {
	drop := 0
	if b := baseline(st.samples, now.Add(-History)); b > 0 {
		drop = b
	}
	if over := len(st.samples) - drop - MaxSamples; over > 0 {
		drop += over
	}
	if drop > 0 {
		st.samples = append(st.samples[:0], st.samples[drop:]...)
	}
}

// Retain drops the state of every alert keep reports false for.
func (e *Evaluator) Retain(keep func(Key) bool) {
	for k := range e.states {
		if !keep(k) {
			delete(e.states, k)
		}
	}
}

// Len is the number of alerts with state.
func (e *Evaluator) Len() int { return len(e.states) }

// Samples is the number of samples kept for one alert.
func (e *Evaluator) Samples(k Key) int {
	if st := e.states[k]; st != nil {
		return len(st.samples)
	}
	return 0
}

// baseline returns the index of the newest sample at or before t, or -1 when there is none.
func baseline(s []sample, t time.Time) int {
	i := sort.Search(len(s), func(i int) bool { return s[i].ts.After(t) })
	return i - 1
}

// evaluate reports whether the alert's condition holds at now, with the summary line when it does.
// Every condition needs a comparison sample — the newest at or before now − Window — that is at most
// MaxGap older than that; until the history reaches back that far, or after a longer gap in the
// readings, it does not hold. A held condition (above, above_usual) also needs no gap longer than
// MaxGap from the comparison sample on.
func evaluate(a Alert, s []sample, now time.Time) (string, bool) {
	start := now.Add(-a.Window)
	b := baseline(s, start)
	if b < 0 || s[b].ts.Before(start.Add(-MaxGap)) {
		return "", false
	}
	name := describe(a.Metric)
	latest := s[len(s)-1].v
	switch a.When {
	case WhenIncreases:
		rise := 0.0
		for i := b + 1; i < len(s); i++ {
			d := s[i].v - s[i-1].v
			if d < 0 {
				// Intentional: a counter that went down was reset (the app restarted), so the rise since
				// the previous sample is the new value itself, counted from 0 — never a negative delta.
				d = s[i].v
			}
			rise += d
		}
		if rise > a.Value {
			return clipSummary(name + " rose by " + fmtNum(rise) + " in " + fmtDur(a.Window) + " (now " + fmtNum(latest) + ")"), true
		}
	case WhenAbove:
		if unbroken(s[b:]) && heldAbove(s[b:], a.Value) {
			return clipSummary(name + " above " + fmtNum(a.Value) + " for " + fmtDur(a.Window) + " (now " + fmtNum(latest) + ")"), true
		}
	case WhenAboveUsual:
		if s[0].ts.After(start.Add(-WarmUp)) {
			return "", false // warm-up: less than an hour of history before the window
		}
		usual, ok := usualLevel(s, now.Add(-History), start)
		if !ok || !unbroken(s[b:]) || !heldAbove(s[b:], math.Max(a.Factor*usual, a.Min)) {
			return "", false
		}
		line := name + " " + fmtNum(latest) + " for " + fmtDur(a.Window) + ", usual " + fmtNum(usual)
		if usual > 0 {
			line += " (×" + fmtRatio(latest/usual) + ")"
		}
		return clipSummary(line), true
	}
	return "", false
}

// heldAbove reports whether every sample is above limit. The caller passes the samples from the newest
// one at or before the window's start, so the value read just before the window counts too: the value
// is taken to hold between two readings.
func heldAbove(s []sample, limit float64) bool {
	for _, x := range s {
		if !(x.v > limit) {
			return false
		}
	}
	return len(s) > 0
}

// unbroken reports whether no two consecutive samples are more than MaxGap apart.
func unbroken(s []sample) bool {
	for i := 1; i < len(s); i++ {
		if s[i].ts.Sub(s[i-1].ts) > MaxGap {
			return false
		}
	}
	return true
}

// usualLevel is the median of the samples in [from, to).
func usualLevel(s []sample, from, to time.Time) (float64, bool) {
	var vs []float64
	for _, x := range s {
		if !x.ts.Before(from) && x.ts.Before(to) {
			vs = append(vs, x.v)
		}
	}
	if len(vs) == 0 {
		return 0, false
	}
	sort.Float64s(vs)
	n := len(vs)
	if n%2 == 1 {
		return vs[n/2], true
	}
	return (vs[n/2-1] + vs[n/2]) / 2, true
}

// describe names a metric for a summary: "Limiter / Ratelimit drops" or "queue dns qps".
func describe(m definition.OpsMetricRef) string {
	if m.Queue != "" {
		return "queue " + clipName(m.Queue) + " " + clipName(m.Count)
	}
	return clipName(m.Group) + " / " + clipName(m.Label)
}

// fmtNum formats a value plainly: integers without a fraction, others with at most two decimals,
// and very large or small magnitudes in exponent form.
func fmtNum(v float64) string {
	if v == 0 {
		return "0" // also -0
	}
	if a := math.Abs(v); a >= 1e15 || a < 0.005 {
		return strconv.FormatFloat(v, 'g', 4, 64)
	}
	s := strconv.FormatFloat(v, 'f', 2, 64)
	s = strings.TrimRight(s, "0")
	return strings.TrimSuffix(s, ".")
}

func fmtRatio(r float64) string {
	if r >= 1e15 {
		return strconv.FormatFloat(r, 'g', 3, 64)
	}
	s := strconv.FormatFloat(r, 'f', 1, 64)
	return strings.TrimSuffix(s, ".0")
}

// fmtDur formats a window as it is written in mooring.yaml: "5m", "1h30m", "90s" → "1m30s".
func fmtDur(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

func clipName(s string) string { return clipBytes(s, maxNamePart, "…") }

func clipSummary(s string) string { return clipBytes(s, maxSummary, "") }

// clipBytes cuts s to at most n bytes on a rune boundary, ending in tail when cut (tail counts).
func clipBytes(s string, n int, tail string) string {
	if len(s) <= n {
		return s
	}
	cut := n - len(tail)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + tail
}
