package web

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/envstore"
	"github.com/daboss2003/mooring/internal/ops"
	"github.com/daboss2003/mooring/internal/opsalert"
	"github.com/daboss2003/mooring/internal/opsclient"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/store"
)

// opsAlertDoer is a fake ops endpoint at every base URL: the ops.v1 descriptor, a healthy
// /ops/health/live, and /ops/metrics with "Limiter / Ratelimit drops" and "Upstream / Errors".
type opsAlertDoer struct {
	mu          sync.Mutex
	fail        bool
	drops, errs int
	dropsAt     map[string]int  // drops per base URL, over drops
	failAt      map[string]bool // base URLs that fail, besides fail
	delay       time.Duration
	onMetrics   func() // called on every /ops/metrics request (a test moves its clock)
	calls       []opsAlertCall
	inFlight    int
	maxInFlight int
}

type opsAlertCall struct{ base, path, header, secret string }

func (d *opsAlertDoer) set(drops int, fail bool) {
	d.mu.Lock()
	d.drops, d.fail = drops, fail
	d.mu.Unlock()
}

func (d *opsAlertDoer) setAt(base string, drops int) {
	d.mu.Lock()
	if d.dropsAt == nil {
		d.dropsAt = map[string]int{}
	}
	d.dropsAt[base] = drops
	d.mu.Unlock()
}

func (d *opsAlertDoer) setErrs(errs int) {
	d.mu.Lock()
	d.errs = errs
	d.mu.Unlock()
}

func (d *opsAlertDoer) Get(_ context.Context, base, relPath, header string, sec secret.Redacted) (*opsclient.Response, error) {
	d.mu.Lock()
	d.inFlight++
	d.maxInFlight = max(d.maxInFlight, d.inFlight)
	d.calls = append(d.calls, opsAlertCall{base: base, path: relPath, header: header, secret: sec.Reveal()})
	fail, drops, errs, delay, hook := d.fail || d.failAt[base], d.drops, d.errs, d.delay, d.onMetrics
	if v, ok := d.dropsAt[base]; ok {
		drops = v
	}
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.inFlight--
		d.mu.Unlock()
	}()
	time.Sleep(delay)
	if relPath == "/ops/metrics" && hook != nil {
		hook()
	}
	if fail {
		return nil, errors.New("connection refused")
	}
	body := ""
	switch relPath {
	case "/.well-known/ops":
		body = `{"opsInterfaceVersion":"1.0","capabilities":["health","queues","metrics"],"basePath":"/ops"}`
	case "/ops/health/live":
		body = `{"status":"ok","details":{"upstream":{"status":"up"}}}`
	case "/ops/metrics":
		body = fmt.Sprintf(`{"groups":[{"title":"Limiter","items":[{"label":"Ratelimit drops","value":%d}]},`+
			`{"title":"Upstream","items":[{"label":"Errors","value":%d}]}]}`, drops, errs)
	case "/ops/queues":
		body = `{"queues":[{"name":"dns","counts":{"qps":143}}]}`
	default:
		return &opsclient.Response{Status: 404}, nil
	}
	return &opsclient.Response{Status: 200, Body: []byte(body)}, nil
}

func (d *opsAlertDoer) Post(context.Context, string, string, string, secret.Redacted, []byte) (*opsclient.Response, error) {
	return nil, errors.New("the poller never posts")
}

func (d *opsAlertDoer) callsTo(path string) []opsAlertCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []opsAlertCall
	for _, c := range d.calls {
		if c.path == path {
			out = append(out, c)
		}
	}
	return out
}

// metricsBases is the base URL of every /ops/metrics request since the last call, in order.
func (d *opsAlertDoer) metricsBases() []string { return d.takeBases("/ops/metrics") }

// takeBases is the base URL of every request to path since the last call, in order; it forgets
// every request so far.
func (d *opsAlertDoer) takeBases(path string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for _, c := range d.calls {
		if c.path == path {
			out = append(out, c.base)
		}
	}
	d.calls = nil
	return out
}

type opsAlertReporter struct {
	mu  sync.Mutex
	got []siem.Detection
}

func (r *opsAlertReporter) Report(d siem.Detection) {
	r.mu.Lock()
	r.got = append(r.got, d)
	r.mu.Unlock()
}

func (r *opsAlertReporter) all() []siem.Detection {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]siem.Detection(nil), r.got...)
}

// opsCopies is the poller's container list in the tests: the running copies of each (app, service).
type opsCopies struct {
	down bool
	m    map[string][]replica
}

func (c *opsCopies) list(context.Context) (map[string][]replica, bool) {
	if c.down {
		return nil, false
	}
	return c.m, true
}

func (c *opsCopies) set(app, service string, copies ...replica) { c.m[svcKey(app, service)] = copies }

// opsAlertServer is a Server with a real definition store, env store (OPS_SECRET = s3cret for app
// "shop"), ops config store and prober over doer.
func opsAlertServer(t *testing.T, doer ops.Doer, rep siem.Reporter, logw io.Writer) (*Server, *definition.Store) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cipher, err := secret.NewCipher(make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	es := envstore.New(db, cipher)
	if _, err := es.Save(context.Background(), "shop", []envstore.Entry{{Key: "OPS_SECRET", Value: secret.New("s3cret"), Secret: true}}, "test"); err != nil {
		t.Fatal(err)
	}
	if logw == nil {
		logw = io.Discard
	}
	ds := definition.NewStore(db, make([]byte, 32))
	s := &Server{
		log:            slog.New(slog.NewTextHandler(logw, nil)),
		db:             db,
		defStore:       ds,
		envStore:       es,
		opsStore:       ops.NewConfigStore(db, cipher),
		prober:         ops.NewProber(nil, doer, nil, nil),
		detectReporter: rep,
	}
	return s, ds
}

// testOpsPoller is the server's poller with a fake container list (resolver 10.0.0.5, api 10.0.0.6,
// worker 10.0.0.7 and web 10.0.0.8 of app "shop", one copy each) and, when clock is set, its clock.
func testOpsPoller(s *Server, clock *time.Time) (*opsAlertPoller, *opsCopies) {
	p := s.newOpsAlertPoller()
	copies := &opsCopies{m: map[string][]replica{}}
	for name, ip := range map[string]string{"resolver": "10.0.0.5", "api": "10.0.0.6", "worker": "10.0.0.7", "web": "10.0.0.8"} {
		copies.set("shop", name, replica{ID: "c-" + name, IP: ip})
	}
	p.replicas = copies.list
	if clock != nil {
		p.now = func() time.Time { return *clock }
	}
	return p, copies
}

func saveOpsDef(t *testing.T, ds *definition.Store, spec string) {
	t.Helper()
	saveOpsDefFor(t, ds, "shop", spec)
}

func saveOpsDefFor(t *testing.T, ds *definition.Store, slug, spec string) {
	t.Helper()
	d, err := definition.Parse([]byte("apiVersion: mooring/v1\nkind: App\nmetadata: {slug: " + slug + "}\nspec:\n" + spec))
	if err != nil {
		t.Fatalf("definition: %v", err)
	}
	if _, err := ds.SaveCanonical(context.Background(), d, "test", ""); err != nil {
		t.Fatal(err)
	}
}

// opsService is one service with an enabled ops_interface and the given alert lines.
func opsService(name, port string, alerts ...string) string {
	s := "      " + name + ":\n        image: coredns/coredns:1.11.1\n        ops_interface:\n" +
		"          enabled: true\n          base_url: http://" + name + ":" + port + "\n          base_path: /ops\n" +
		"          secret_header: X-Ops-Secret\n          secret: OPS_SECRET\n"
	if len(alerts) > 0 {
		s += "          alerts:\n"
		for _, a := range alerts {
			s += "            - " + a + "\n"
		}
	}
	return s
}

const (
	opsSecrets  = "  secrets:\n    - {name: OPS_SECRET, generate: 'password:32'}\n"
	dropsAlert  = "{ name: ratelimit-drops, metric: { group: Limiter, label: Ratelimit drops }, when: increases, value: 100, window: 1m }"
	errorsAlert = "{ name: upstream-errors, metric: { group: Upstream, label: Errors }, when: above, value: 50, window: 1m, severity: critical }"
	appOpsSec   = "an-app-level-secret-value"
)

var opsT0 = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

// setAppOps stores the app-level ops settings the dashboard edits (and the monitor probes).
func setAppOps(t *testing.T, s *Server, enabled bool) {
	t.Helper()
	sec := appOpsSec
	if err := s.opsStore.Set("shop", ops.SetInput{Enabled: enabled, BaseURL: "http://web:8080", SecretHeader: "X-App-Secret",
		NewSecret: &sec, OpsMode: "auto", BasePath: "/ops"}); err != nil {
		t.Fatal(err)
	}
}

// A per-service ops_interface with alerts is probed through the service page's path (secret from the
// env store) at the address of the service's running copy, and a firing is reported with the ops rule ID.
func TestOpsAlertPerServiceProbe(t *testing.T) {
	rep := &opsAlertReporter{}
	doer := &opsAlertDoer{}
	s, ds := opsAlertServer(t, doer, rep, nil)
	saveOpsDef(t, ds, opsSecrets+"  compose:\n    services:\n"+opsService("resolver", "8081", dropsAlert))
	clock := opsT0
	p, _ := testOpsPoller(s, &clock)

	for _, v := range []int{100, 100, 100, 300} {
		doer.set(v, false)
		p.tick(context.Background())
		clock = clock.Add(30 * time.Second)
	}
	got := rep.all()
	if len(got) != 1 {
		t.Fatalf("detections = %+v, want one", got)
	}
	want := siem.Detection{
		Source: siem.DetectionOps, RuleID: "ops:shop/resolver/ratelimit-drops", RuleName: "ratelimit-drops",
		Severity: siem.SevHigh, Key: "resolver", App: "shop", Service: "resolver",
		First: opsT0.Add(90 * time.Second), Last: opsT0.Add(90 * time.Second), Count: 1,
		Summary: "Limiter / Ratelimit drops rose by 200 in 1m (now 300)",
	}
	if d := got[0]; d.Source != want.Source || d.RuleID != want.RuleID || d.RuleName != want.RuleName || d.Severity != want.Severity ||
		d.Key != want.Key || d.App != want.App || d.Service != want.Service || !d.First.Equal(want.First) ||
		!d.Last.Equal(want.Last) || d.Count != want.Count || d.Summary != want.Summary {
		t.Errorf("detection = %+v\nwant        %+v", d, want)
	}
	calls := doer.callsTo("/ops/metrics")
	if len(calls) != 4 {
		t.Fatalf("metrics probes = %d, want 4", len(calls))
	}
	for _, c := range calls {
		if c.base != "http://10.0.0.5:8081" || c.header != "X-Ops-Secret" || c.secret != "s3cret" {
			t.Errorf("probe %+v: want the running copy's IP and the env-store secret", c)
		}
	}
}

// Every report of a run carries Count 1: the detection engine adds each report's count to the
// detection a report within the hour updates, so the stored count is the number of reports.
func TestOpsAlertCountOnePerReport(t *testing.T) {
	rep := &opsAlertReporter{}
	doer := &opsAlertDoer{errs: 99}
	s, ds := opsAlertServer(t, doer, rep, nil)
	saveOpsDef(t, ds, opsSecrets+"  compose:\n    services:\n"+opsService("resolver", "8081", errorsAlert))
	clock := opsT0
	p, _ := testOpsPoller(s, &clock)
	for i := 0; i <= 120; i++ { // an hour, always above
		p.tick(context.Background())
		clock = clock.Add(30 * time.Second)
	}
	got := rep.all()
	if len(got) != 4 { // at 1m30s, then every 15 m
		t.Fatalf("reports = %d, want 4: %+v", len(got), got)
	}
	for i, d := range got {
		if d.Count != 1 || !d.First.Equal(got[0].First) {
			t.Errorf("report %d: count %d first %v, want count 1 and the run's first time %v", i, d.Count, d.First, got[0].First)
		}
	}
}

// The app-level ops_interface is probed with the dashboard's ops settings (the ones the monitor uses:
// its secret, header and base URL) at the address of the base URL's service; when those settings turn
// it off nothing is read.
func TestOpsAlertAppLevelProbe(t *testing.T) {
	rep := &opsAlertReporter{}
	doer := &opsAlertDoer{}
	s, ds := opsAlertServer(t, doer, rep, nil)
	saveOpsDef(t, ds, "  compose:\n    services:\n      web: {image: nginx:1}\n"+
		"  ops_interface:\n    enabled: true\n    base_url: http://web:8080\n    alerts:\n      - "+errorsAlert+"\n")
	setAppOps(t, s, true)
	clock := opsT0
	p, _ := testOpsPoller(s, &clock)
	for _, v := range []int{10, 60, 70, 75} {
		doer.setErrs(v)
		p.tick(context.Background())
		clock = clock.Add(30 * time.Second)
	}
	got := rep.all()
	if len(got) != 1 {
		t.Fatalf("detections = %+v, want one", got)
	}
	d := got[0]
	if d.RuleID != "ops:shop/-/upstream-errors" || d.Key != "app" || d.Service != "" || d.App != "shop" || d.Count != 1 ||
		d.Severity != siem.SevCritical || d.Summary != "Upstream / Errors above 50 for 1m (now 75)" ||
		!d.Last.Equal(opsT0.Add(90*time.Second)) {
		t.Errorf("detection = %+v", d)
	}
	calls := doer.callsTo("/ops/metrics")
	if len(calls) != 4 {
		t.Fatalf("metrics probes = %d, want 4", len(calls))
	}
	for _, c := range calls {
		if c.base != "http://10.0.0.8:8080" || c.header != "X-App-Secret" || c.secret != appOpsSec {
			t.Errorf("probe %+v: want web's copy and the ops settings' header and secret", c)
		}
	}

	// Ops turned off in the ops settings: no probe, no sample.
	setAppOps(t, s, false)
	doer.metricsBases()
	k := opsalert.Key{App: "shop", Name: "upstream-errors"}
	before := p.eval.Samples(k)
	p.tick(context.Background())
	if n := len(doer.metricsBases()); n != 0 || p.eval.Samples(k) != before {
		t.Errorf("ops off: %d probes, samples %d → %d", n, before, p.eval.Samples(k))
	}
}

// The poller keeps reading the copy it read last while that copy runs, so a scale-up doesn't switch
// it. When the copy goes (scale-down, recreate) it reads another, and that copy's unrelated counter
// starts the history again instead of counting as a rise.
func TestOpsAlertReplicaSwitch(t *testing.T) {
	rep := &opsAlertReporter{}
	doer := &opsAlertDoer{}
	s, ds := opsAlertServer(t, doer, rep, nil)
	saveOpsDef(t, ds, opsSecrets+"  compose:\n    services:\n"+opsService("resolver", "8081",
		"{ name: ratelimit-drops, metric: { group: Limiter, label: Ratelimit drops }, when: increases, value: 100, window: 5m }"))
	clock := opsT0
	p, copies := testOpsPoller(s, &clock)
	const a, b, c = "http://10.0.0.5:8081", "http://10.0.0.9:8081", "http://10.0.0.2:8081"
	copies.set("shop", "resolver", replica{ID: "copy-b", IP: "10.0.0.9"}, replica{ID: "copy-a", IP: "10.0.0.5"})
	doer.setAt(b, 30000)
	k := opsalert.Key{App: "shop", Service: "resolver", Name: "ratelimit-drops"}
	tick := func() {
		p.tick(context.Background())
		clock = clock.Add(30 * time.Second)
	}
	for i := 0; i < 20; i++ { // copy A (lowest address), long-running, +1 per reading
		doer.setAt(a, 50000+i)
		tick()
	}
	if bases := doer.metricsBases(); len(bases) != 20 || bases[0] != a || bases[19] != a {
		t.Fatalf("must read the lowest-address copy A: %v", bases)
	}

	// Scale-up: copy C with a lower address. A still runs, so the poller stays on it.
	copies.set("shop", "resolver", replica{ID: "copy-c", IP: "10.0.0.2"}, replica{ID: "copy-b", IP: "10.0.0.9"}, replica{ID: "copy-a", IP: "10.0.0.5"})
	doer.setAt(c, 0)
	doer.setAt(a, 50020)
	tick()
	if bases := doer.metricsBases(); len(bases) != 1 || bases[0] != a {
		t.Fatalf("a scale-up must not move the poller off a running copy: %v", bases)
	}

	// Scale-down removes A and C: the poller reads B, whose counter is lower and unrelated.
	copies.set("shop", "resolver", replica{ID: "copy-b", IP: "10.0.0.9"})
	tick()
	if bases := doer.metricsBases(); len(bases) != 1 || bases[0] != b {
		t.Fatalf("after A went the poller must read B: %v", bases)
	}
	if got := rep.all(); len(got) != 0 {
		t.Fatalf("a switch to another copy must not be reported as a rise: %+v", got)
	}
	if n := p.eval.Samples(k); n != 1 {
		t.Errorf("a switch must start the history again: %d samples", n)
	}
	// B's own rise is reported once its history covers the window.
	for i := 1; i <= 10; i++ {
		doer.setAt(b, 30000+i)
		tick()
	}
	doer.setAt(b, 30500)
	tick()
	if got := rep.all(); len(got) != 1 || !strings.Contains(got[0].Summary, "(now 30500)") {
		t.Errorf("B's own rise must be reported: %+v", got)
	}
}

// A failed probe adds no sample and is logged once per interval, not once per poll.
func TestOpsAlertFailedProbeNoSample(t *testing.T) {
	var logs bytes.Buffer
	doer := &opsAlertDoer{}
	s, ds := opsAlertServer(t, doer, &opsAlertReporter{}, &logs)
	saveOpsDef(t, ds, opsSecrets+"  compose:\n    services:\n"+opsService("resolver", "8081", dropsAlert))
	clock := opsT0
	p, _ := testOpsPoller(s, &clock)
	k := opsalert.Key{App: "shop", Service: "resolver", Name: "ratelimit-drops"}

	doer.set(100, true)
	for i := 0; i < 3; i++ {
		p.tick(context.Background())
		clock = clock.Add(30 * time.Second)
	}
	if n := p.eval.Samples(k); n != 0 {
		t.Errorf("failed probes stored %d samples", n)
	}
	if n := strings.Count(logs.String(), "ops probe failed"); n != 1 {
		t.Errorf("failed-probe log lines = %d, want 1 (rate-limited):\n%s", n, logs.String())
	}
	doer.set(100, false)
	p.tick(context.Background())
	if n := p.eval.Samples(k); n != 1 {
		t.Errorf("a good probe after failures stored %d samples, want 1", n)
	}
}

// An endpoint that keeps failing is tried 1, 2, 4, 8 … rounds apart, at most every 20 rounds (10
// minutes); the first good probe ends the wait, and a later failure starts the backoff from the
// beginning. Other endpoints are probed every round meanwhile.
func TestOpsAlertBackoff(t *testing.T) {
	const failing = "http://10.0.0.5:8081"
	doer := &opsAlertDoer{drops: 1, failAt: map[string]bool{failing: true}}
	s, ds := opsAlertServer(t, doer, &opsAlertReporter{}, nil)
	saveOpsDef(t, ds, opsSecrets+"  compose:\n    services:\n"+opsService("resolver", "8081", dropsAlert)+opsService("api", "8080", dropsAlert))
	clock := opsT0
	p, _ := testOpsPoller(s, &clock)
	var tried []int
	apiRounds := 0
	for round := 1; round <= 100; round++ {
		switch round {
		case 80: // the endpoint recovers; the next try finds it
			doer.mu.Lock()
			doer.failAt = nil
			doer.mu.Unlock()
		case 96: // and fails again
			doer.mu.Lock()
			doer.failAt = map[string]bool{failing: true}
			doer.mu.Unlock()
		}
		p.tick(context.Background())
		clock = clock.Add(30 * time.Second)
		for _, base := range doer.takeBases("/.well-known/ops") { // every try starts with the descriptor
			switch base {
			case failing:
				tried = append(tried, round)
			case "http://10.0.0.6:8080":
				apiRounds++
			}
		}
	}
	want := []int{1, 2, 4, 8, 16, 32, 52, 72, 92, 93, 94, 95, 96, 97, 99}
	if fmt.Sprint(tried) != fmt.Sprint(want) {
		t.Errorf("failing endpoint tried in rounds %v, want %v", tried, want)
	}
	if apiRounds != 100 {
		t.Errorf("the healthy endpoint was probed in %d of 100 rounds", apiRounds)
	}
}

// No probe starts more than 20 s into a round; the next round starts with the first one left out, so
// every interface gets its turn.
func TestOpsAlertRoundBudget(t *testing.T) {
	var logs bytes.Buffer
	doer := &opsAlertDoer{drops: 1}
	s, ds := opsAlertServer(t, doer, &opsAlertReporter{}, &logs)
	var spec strings.Builder
	spec.WriteString(opsSecrets + "  compose:\n    services:\n")
	for i := 0; i < 5; i++ {
		spec.WriteString(opsService("s"+strconv.Itoa(i), "8081", dropsAlert))
	}
	saveOpsDef(t, ds, spec.String())
	clock := opsT0
	p, copies := testOpsPoller(s, &clock)
	for i := 0; i < 5; i++ {
		copies.set("shop", "s"+strconv.Itoa(i), replica{ID: "c" + strconv.Itoa(i), IP: "10.0.1." + strconv.Itoa(i+1)})
	}
	doer.onMetrics = func() { clock = clock.Add(7 * time.Second) } // every probe takes 7 s
	var rounds [][]string
	for r := 0; r < 4; r++ {
		start := clock
		p.tick(context.Background())
		clock = start.Add(30 * time.Second)
		var got []string
		for _, b := range doer.metricsBases() {
			got = append(got, strings.TrimSuffix(strings.TrimPrefix(b, "http://10.0.1."), ":8081"))
		}
		rounds = append(rounds, got)
	}
	// Probes start at 0, 7 and 14 s; at 21 s the round is out of time.
	if want := "[[1 2 3] [4 5 1] [2 3 4] [5 1 2]]"; fmt.Sprint(rounds) != want {
		t.Errorf("copies probed per round = %v, want %s", rounds, want)
	}
	if n := strings.Count(logs.String(), "ran out of time"); n != 1 {
		t.Errorf("out-of-time log lines = %d, want 1 (rate-limited):\n%s", n, logs.String())
	}
}

// opsSlowDoer is opsAlertDoer whose /ops/metrics at base URLs starting with slow take 5.9 s on the
// test clock (a slow but healthy endpoint: the probe still succeeds).
type opsSlowDoer struct {
	*opsAlertDoer
	clock *time.Time
	slow  string
}

func (d *opsSlowDoer) Get(ctx context.Context, base, rel, h string, sec secret.Redacted) (*opsclient.Response, error) {
	if rel == "/ops/metrics" && strings.HasPrefix(base, d.slow) {
		*d.clock = d.clock.Add(5900 * time.Millisecond)
	}
	return d.opsAlertDoer.Get(ctx, base, rel, h, sec)
}

// opsSlowApps runs rounds 30 s apart with app "aaa" (8 slow interfaces at 10.0.9.1-8), app "bbb"
// (8 interfaces at 10.0.9.101-108, slow when bbbSlow, else at 10.0.7.1-8 and instant) and app "zzz"
// (one instant interface at 10.0.8.1 whose upstream-errors alert, errs 75 > 50, holds throughout).
// It returns the /ops/metrics probes of every round by base URL and the reports.
func opsSlowApps(t *testing.T, rounds int, bbbSlow bool) ([]map[string]int, []siem.Detection) {
	t.Helper()
	inner := &opsAlertDoer{}
	inner.setErrs(75)
	clock := opsT0
	d := &opsSlowDoer{opsAlertDoer: inner, clock: &clock, slow: "http://10.0.9."}
	rep := &opsAlertReporter{}
	s, ds := opsAlertServer(t, d, rep, nil)
	var spec strings.Builder
	spec.WriteString(opsSecrets + "  compose:\n    services:\n")
	for i := 0; i < 8; i++ {
		spec.WriteString(opsService("s"+strconv.Itoa(i), "8081", dropsAlert))
	}
	saveOpsDefFor(t, ds, "aaa", spec.String())
	saveOpsDefFor(t, ds, "bbb", spec.String())
	saveOpsDefFor(t, ds, "zzz", opsSecrets+"  compose:\n    services:\n"+opsService("api", "8081", errorsAlert))
	p, copies := testOpsPoller(s, &clock)
	for i := 0; i < 8; i++ {
		copies.set("aaa", "s"+strconv.Itoa(i), replica{ID: "a" + strconv.Itoa(i), IP: "10.0.9." + strconv.Itoa(i+1)})
		bbbIP := "10.0.7." + strconv.Itoa(i+1)
		if bbbSlow {
			bbbIP = "10.0.9." + strconv.Itoa(i+101)
		}
		copies.set("bbb", "s"+strconv.Itoa(i), replica{ID: "b" + strconv.Itoa(i), IP: bbbIP})
	}
	copies.set("zzz", "api", replica{ID: "z", IP: "10.0.8.1"})
	var probed []map[string]int
	for r := 0; r < rounds; r++ {
		start := clock
		p.tick(context.Background())
		if clock.Sub(start) >= opsAlertEvery {
			t.Fatalf("round %d took %v, longer than the poll interval", r, clock.Sub(start))
		}
		got := map[string]int{}
		for _, b := range inner.metricsBases() {
			got[b]++
		}
		probed = append(probed, got)
		clock = start.Add(opsAlertEvery)
	}
	return probed, rep.all()
}

// Two apps with 8 slow (5.9 s) but healthy endpoints each fill every round's 20 s budget. Each app
// gets a fair share of the round, so a third app's endpoint is still probed every round and its
// held `above` alert fires; the slow apps' endpoints all keep their turns.
func TestOpsAlertSlowAppsDoNotStarveOthers(t *testing.T) {
	probed, reports := opsSlowApps(t, 40, true)
	for r, got := range probed {
		if got["http://10.0.8.1:8081"] != 1 {
			t.Fatalf("round %d: zzz probed %d times, want every round (%v)", r, got["http://10.0.8.1:8081"], got)
		}
	}
	fired := 0
	for _, d := range reports {
		if d.App == "zzz" {
			fired++
		}
	}
	if fired == 0 {
		t.Error("zzz's above alert never fired in 20 minutes of errs=75 > 50")
	}
	total := map[string]int{}
	for _, got := range probed {
		for b, n := range got {
			total[b] += n
		}
	}
	for i := 0; i < 8; i++ { // 2 probes per app per round: each endpoint every 4 rounds
		for _, ip := range []string{"10.0.9." + strconv.Itoa(i+1), "10.0.9." + strconv.Itoa(i+101)} {
			if n := total["http://"+ip+":8081"]; n != 10 {
				t.Errorf("%s probed %d times in 40 rounds, want 10", ip, n)
			}
		}
	}
}

// The share is of the round's time, not of its probes: an app whose endpoints answer at once gets
// all of them probed every round beside an app whose endpoints take 5.9 s each.
func TestOpsAlertFairShareIsTime(t *testing.T) {
	probed, _ := opsSlowApps(t, 8, false)
	for r, got := range probed {
		for i := 1; i <= 8; i++ {
			if b := "http://10.0.7." + strconv.Itoa(i) + ":8081"; got[b] != 1 {
				t.Errorf("round %d: fast app endpoint %s probed %d times, want 1", r, b, got[b])
			}
		}
		slow := 0
		for b, n := range got {
			if strings.HasPrefix(b, "http://10.0.9.") {
				slow += n
			}
		}
		if slow != 4 { // probes start at 0, 5.9, 11.8 and 17.7 s
			t.Errorf("round %d: slow app probed %d times, want 4", r, slow)
		}
	}
}

// Owner decision: in a scaled service the poller stays on the copy it reads while that copy runs,
// but after 3 failed probes of it in a row it moves to the running copy with the lowest address
// among the others, whose history starts again. The endpoint's backoff carries on across the move.
// Two failures then a good probe don't move it; a service with one copy stays on it.
func TestOpsAlertMovesOffAFailingCopy(t *testing.T) {
	const a, b, c = "http://10.0.0.5:8081", "http://10.0.0.9:8081", "http://10.0.0.7:8081"
	rep := &opsAlertReporter{}
	doer := &opsAlertDoer{drops: 1}
	s, ds := opsAlertServer(t, doer, rep, nil)
	saveOpsDef(t, ds, opsSecrets+"  compose:\n    services:\n"+opsService("resolver", "8081", dropsAlert))
	clock := opsT0
	p, copies := testOpsPoller(s, &clock)
	copies.set("shop", "resolver", replica{ID: "copy-b", IP: "10.0.0.9"}, replica{ID: "copy-a", IP: "10.0.0.5"})
	k := opsalert.Key{App: "shop", Service: "resolver", Name: "ratelimit-drops"}
	failAt := func(bases ...string) {
		doer.mu.Lock()
		doer.failAt = map[string]bool{}
		for _, x := range bases {
			doer.failAt[x] = true
		}
		doer.mu.Unlock()
	}
	// rounds runs n rounds and returns the copy each try went to, by round ("-": none). Every try
	// starts with the descriptor.
	rounds := func(n int) []string {
		var out []string
		for i := 0; i < n; i++ {
			p.tick(context.Background())
			clock = clock.Add(30 * time.Second)
			got := doer.takeBases("/.well-known/ops")
			if len(got) == 0 {
				out = append(out, "-")
				continue
			}
			out = append(out, strings.Join(got, ","))
		}
		return out
	}
	if got := rounds(4); fmt.Sprint(got) != fmt.Sprint([]string{a, a, a, a}) {
		t.Fatalf("must read copy A (lowest address): %v", got)
	}

	// Two failures in a row, then a good probe: still A.
	failAt(a)
	rounds(2) // fail 1 (round 1), fail 2 (round 2); the next try is a round later
	failAt()
	if got := rounds(2); fmt.Sprint(got) != fmt.Sprint([]string{"-", a}) {
		t.Fatalf("after two failures and a good probe the poller must stay on A: %v", got)
	}

	// Three failures in a row: tried 1, 2, 4 rounds apart (the backoff), then the next try reads C,
	// the lowest address among the other copies — C was started after the poller settled on A.
	copies.set("shop", "resolver", replica{ID: "copy-b", IP: "10.0.0.9"}, replica{ID: "copy-a", IP: "10.0.0.5"}, replica{ID: "copy-c", IP: "10.0.0.7"})
	failAt(a)
	before := p.eval.Samples(k)
	want := []string{a, a, "-", a, "-", "-", "-", c}
	if got := rounds(len(want)); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("probes = %v\nwant     %v", got, want)
	}
	if before < 2 || p.eval.Samples(k) != 1 {
		t.Errorf("the move to C must start the history again: %d samples before, %d after", before, p.eval.Samples(k))
	}
	if got := rounds(2); fmt.Sprint(got) != fmt.Sprint([]string{c, c}) {
		t.Errorf("the poller must stay on C while it answers (A's failures don't matter now): %v", got)
	}

	// C fails 3 times: the lowest address among the others is A again.
	failAt(c)
	want = []string{c, c, "-", c, "-", "-", "-", a}
	if got := rounds(len(want)); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("probes = %v\nwant     %v", got, want)
	}

	// One copy: it stays on it however often it fails.
	copies.set("shop", "resolver", replica{ID: "copy-b", IP: "10.0.0.9"})
	failAt(b)
	want = []string{b, b, "-", b, "-", "-", "-", b}
	if got := rounds(len(want)); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("single copy: probes = %v\nwant     %v", got, want)
	}
	if got := rep.all(); len(got) != 0 {
		t.Errorf("no copy's counter rose: %+v", got)
	}
}

// With more apps than fit in a round, the next round starts at the app the last one ran out of time
// at, so every app gets its turn.
func TestOpsAlertRoundBudgetAcrossApps(t *testing.T) {
	doer := &opsAlertDoer{drops: 1}
	s, ds := opsAlertServer(t, doer, &opsAlertReporter{}, nil)
	clock := opsT0
	p, copies := testOpsPoller(s, &clock)
	apps := []string{"aa", "bb", "cc", "dd", "ee"}
	for n, app := range apps {
		saveOpsDefFor(t, ds, app, opsSecrets+"  compose:\n    services:\n"+opsService("api", "8081", dropsAlert))
		copies.set(app, "api", replica{ID: app, IP: "10.0.3." + strconv.Itoa(n+1)})
	}
	doer.onMetrics = func() { clock = clock.Add(7 * time.Second) } // every probe takes 7 s
	var rounds [][]string
	for r := 0; r < 4; r++ {
		start := clock
		p.tick(context.Background())
		clock = start.Add(30 * time.Second)
		var got []string
		for _, b := range doer.metricsBases() {
			n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(b, "http://10.0.3."), ":8081"))
			got = append(got, apps[n-1])
		}
		rounds = append(rounds, got)
	}
	if want := "[[aa bb cc] [dd ee aa] [bb cc dd] [ee aa bb]]"; fmt.Sprint(rounds) != want {
		t.Errorf("apps probed per round = %v, want %s", rounds, want)
	}
}

// The move off a failing copy doesn't reset the endpoint's backoff: when every copy fails, the
// tries stay 1, 2, 4, 8 … rounds apart across the moves.
func TestOpsAlertMoveKeepsBackoff(t *testing.T) {
	const a, b, c = "http://10.0.0.5:8081", "http://10.0.0.9:8081", "http://10.0.0.7:8081"
	doer := &opsAlertDoer{drops: 1, failAt: map[string]bool{a: true, b: true, c: true}}
	s, ds := opsAlertServer(t, doer, &opsAlertReporter{}, nil)
	saveOpsDef(t, ds, opsSecrets+"  compose:\n    services:\n"+opsService("resolver", "8081", dropsAlert))
	clock := opsT0
	p, copies := testOpsPoller(s, &clock)
	copies.set("shop", "resolver", replica{ID: "copy-b", IP: "10.0.0.9"}, replica{ID: "copy-a", IP: "10.0.0.5"}, replica{ID: "copy-c", IP: "10.0.0.7"})
	var tries []string
	for round := 1; round <= 60; round++ {
		p.tick(context.Background())
		clock = clock.Add(30 * time.Second)
		for _, base := range doer.takeBases("/.well-known/ops") {
			tries = append(tries, strconv.Itoa(round)+"="+map[string]string{a: "A", b: "B", c: "C"}[base])
		}
	}
	// A fails 3 times, then C (lowest of the others) 3 times, then A again; skips 0, 1, 3, 7, 15, 19.
	if want := "[1=A 2=A 4=A 8=C 16=C 32=C 52=A]"; fmt.Sprint(tries) != want {
		t.Errorf("tries = %v, want %s", tries, want)
	}
}

// opsAlertsDef is an app (built directly, not validated) with the given services, each with an
// enabled ops_interface at a literal address and n alerts.
func opsAlertsDef(app string, services, n int) *definition.Definition {
	d := &definition.Definition{}
	d.Metadata.Slug = app
	d.Spec.Compose.Services = map[string]definition.Service{}
	for i := 0; i < services; i++ {
		oi := &definition.OpsInterface{Enabled: true, BaseURL: fmt.Sprintf("http://10.%d.%d.1:8081", len(app), i), BasePath: "/ops"}
		for j := 0; j < n; j++ {
			oi.Alerts = append(oi.Alerts, definition.OpsAlert{Name: "a" + strconv.Itoa(j),
				Metric: definition.OpsMetricRef{Group: "Limiter", Label: "Ratelimit drops"}, When: "increases", Value: 100})
		}
		d.Spec.Compose.Services["s"+strconv.Itoa(i)] = definition.Service{OpsInterface: oi}
	}
	return d
}

// At most MaxOpsAlertInterfaces alerting interfaces of one app, and 256 alerts in all, are evaluated;
// the rest are skipped (not probed, no state) and logged once per interval.
func TestOpsAlertCaps(t *testing.T) {
	var logs bytes.Buffer
	doer := &opsAlertDoer{drops: 1}
	s, _ := opsAlertServer(t, doer, &opsAlertReporter{}, &logs)
	clock := opsT0
	p, _ := testOpsPoller(s, &clock)

	// One app with 10 alerting services: s0…s7 run, s8 and s9 don't.
	defs := map[string]*definition.Definition{"shop": opsAlertsDef("shop", 10, 1)}
	p.defs = func(context.Context) (map[string]*definition.Definition, map[string]error, error) {
		return defs, nil, nil
	}
	for i := 0; i < 2; i++ {
		p.tick(context.Background())
		clock = clock.Add(30 * time.Second)
	}
	if n := len(doer.metricsBases()); n != 2*definition.MaxOpsAlertInterfaces {
		t.Errorf("probes over 2 rounds = %d, want %d", n, 2*definition.MaxOpsAlertInterfaces)
	}
	if p.eval.Len() != definition.MaxOpsAlertInterfaces || p.eval.Samples(opsalert.Key{App: "shop", Service: "s8", Name: "a0"}) != 0 {
		t.Errorf("alerts with state = %d, want %d (s8, s9 skipped)", p.eval.Len(), definition.MaxOpsAlertInterfaces)
	}
	if n := strings.Count(logs.String(), "more ops interfaces than allowed"); n != 1 || !strings.Contains(logs.String(), "shop/s8") {
		t.Errorf("per-app cap log lines = %d, want 1 naming the skipped ones:\n%s", n, logs.String())
	}

	// 20 apps × 1 service × 16 alerts = 320 alerts: 16 interfaces (256 alerts) run.
	defs = map[string]*definition.Definition{}
	for i := 0; i < 20; i++ {
		app := fmt.Sprintf("app%02d", i)
		defs[app] = opsAlertsDef(app, 1, 16)
	}
	logs.Reset()
	p.tick(context.Background())
	if n := len(doer.metricsBases()); n != 16 {
		t.Errorf("probes = %d, want 16 interfaces (256 alerts)", n)
	}
	if p.eval.Len() != 256 {
		t.Errorf("alerts with state = %d, want 256", p.eval.Len())
	}
	if !strings.Contains(logs.String(), "more alerts than Mooring evaluates") || !strings.Contains(logs.String(), "app19/s0") {
		t.Errorf("the global cap must be logged naming the skipped interfaces:\n%s", logs.String())
	}
}

// One app whose stored definition can't be read is skipped (and keeps its history); every other app's
// alerts keep running.
func TestOpsAlertBadDefinitionSkipsOneApp(t *testing.T) {
	var logs bytes.Buffer
	doer := &opsAlertDoer{drops: 1}
	s, ds := opsAlertServer(t, doer, &opsAlertReporter{}, &logs)
	saveOpsDef(t, ds, opsSecrets+"  compose:\n    services:\n"+opsService("resolver", "8081", dropsAlert))
	saveOpsDefFor(t, ds, "blog", opsSecrets+"  compose:\n    services:\n"+opsService("api", "8080", dropsAlert))
	clock := opsT0
	p, copies := testOpsPoller(s, &clock)
	copies.set("blog", "api", replica{ID: "blog-api", IP: "10.0.2.1"})
	shop := opsalert.Key{App: "shop", Service: "resolver", Name: "ratelimit-drops"}
	blog := opsalert.Key{App: "blog", Service: "api", Name: "ratelimit-drops"}
	p.tick(context.Background())
	clock = clock.Add(30 * time.Second)
	if p.eval.Samples(shop) != 1 || p.eval.Samples(blog) != 1 {
		t.Fatalf("samples: shop %d, blog %d", p.eval.Samples(shop), p.eval.Samples(blog))
	}

	if _, err := s.db.Exec(`UPDATE definition_versions SET yaml=replace(yaml,'coredns','evil') WHERE slug='blog'`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		p.tick(context.Background())
		clock = clock.Add(30 * time.Second)
	}
	if n := p.eval.Samples(shop); n != 3 {
		t.Errorf("a bad definition of another app must not stop shop's alerts: %d samples, want 3", n)
	}
	if n := p.eval.Samples(blog); n != 1 {
		t.Errorf("the unreadable app must keep its history and get no sample: %d samples, want 1", n)
	}
	if !strings.Contains(logs.String(), "definition can't be read") || !strings.Contains(logs.String(), "app=blog") ||
		strings.Count(logs.String(), "definition can't be read") != 1 {
		t.Errorf("the skipped app must be logged once, by name:\n%s", logs.String())
	}
}

// The state of a removed alert, and of a deleted app, is dropped; a failed definitions read keeps it.
func TestOpsAlertDropsRemovedState(t *testing.T) {
	doer := &opsAlertDoer{drops: 5, errs: 1}
	s, ds := opsAlertServer(t, doer, &opsAlertReporter{}, nil)
	setAppOps(t, s, true)
	appLevel := "  ops_interface:\n    enabled: true\n    base_url: http://web:8080\n    alerts:\n      - " + errorsAlert + "\n"
	withAlerts := opsSecrets + appLevel + "  compose:\n    services:\n" + opsService("resolver", "8081", dropsAlert)
	saveOpsDef(t, ds, withAlerts)
	clock := opsT0
	p, _ := testOpsPoller(s, &clock)
	svcKey := opsalert.Key{App: "shop", Service: "resolver", Name: "ratelimit-drops"}
	appKey := opsalert.Key{App: "shop", Name: "upstream-errors"}
	tick := func() {
		p.tick(context.Background())
		clock = clock.Add(30 * time.Second)
	}

	tick()
	if p.eval.Samples(svcKey) != 1 || p.eval.Samples(appKey) != 1 {
		t.Fatalf("samples: service %d, app %d", p.eval.Samples(svcKey), p.eval.Samples(appKey))
	}

	p.defs = func(context.Context) (map[string]*definition.Definition, map[string]error, error) {
		return nil, nil, errors.New("database is locked")
	}
	tick()
	if p.eval.Len() != 2 {
		t.Errorf("a failed definitions read must keep the history: %d alerts", p.eval.Len())
	}
	p.defs = ds.CurrentEach

	// The service alert removed (its ops_interface stays).
	saveOpsDef(t, ds, opsSecrets+appLevel+"  compose:\n    services:\n"+opsService("resolver", "8081"))
	tick()
	if p.eval.Samples(svcKey) != 0 || p.eval.Samples(appKey) == 0 || p.eval.Len() != 1 {
		t.Errorf("after removing the service alert: %d alerts, service %d samples", p.eval.Len(), p.eval.Samples(svcKey))
	}

	// The app deleted.
	saveOpsDef(t, ds, withAlerts)
	tick()
	if err := ds.DeleteApp(context.Background(), "shop"); err != nil {
		t.Fatal(err)
	}
	tick()
	if p.eval.Len() != 0 || len(p.source) != 0 || len(p.backoff) != 0 {
		t.Errorf("after deleting the app: %d alerts, %d sources, %d backoffs kept", p.eval.Len(), len(p.source), len(p.backoff))
	}
}

// Services are probed one at a time.
func TestOpsAlertOneProbeAtATime(t *testing.T) {
	doer := &opsAlertDoer{drops: 1, delay: 10 * time.Millisecond}
	s, ds := opsAlertServer(t, doer, &opsAlertReporter{}, nil)
	saveOpsDef(t, ds, opsSecrets+"  compose:\n    services:\n"+
		opsService("resolver", "8081", dropsAlert)+opsService("api", "8080", dropsAlert)+opsService("worker", "9100", dropsAlert))
	p, _ := testOpsPoller(s, nil)
	p.tick(context.Background())

	if doer.maxInFlight != 1 {
		t.Errorf("probes in flight at once = %d, want 1", doer.maxInFlight)
	}
	seen := map[string]int{}
	for _, c := range doer.callsTo("/ops/metrics") {
		seen[c.base]++
	}
	for _, base := range []string{"http://10.0.0.5:8081", "http://10.0.0.6:8080", "http://10.0.0.7:9100"} {
		if seen[base] != 1 {
			t.Errorf("%s probed %d times, want 1 (all: %v)", base, seen[base], seen)
		}
	}
}

// Without a reporter (detection off) the loop doesn't run; with one it runs until the context ends.
func TestOpsAlertRunLoop(t *testing.T) {
	s, _ := opsAlertServer(t, &opsAlertDoer{}, nil, nil)
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { s.RunOpsAlerts(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunOpsAlerts with no reporter must return at once")
	}

	s.detectReporter = &opsAlertReporter{}
	done2 := make(chan struct{})
	ctx2, cancel2 := context.WithCancel(context.Background())
	go func() { s.RunOpsAlerts(ctx2); close(done2) }()
	select {
	case <-done2:
		t.Fatal("RunOpsAlerts with a reporter must keep running")
	case <-time.After(100 * time.Millisecond):
	}
	cancel2()
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("RunOpsAlerts must return when its context ends")
	}
}
