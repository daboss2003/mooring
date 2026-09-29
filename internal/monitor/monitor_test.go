package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/docker"
	"github.com/daboss2003/mooring/internal/hostmon"
	"github.com/daboss2003/mooring/internal/store"
)

func fakeEngine(t *testing.T) *docker.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Version":"26.1.0"}`))
	})
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
			{"Id":"abc","Names":["/shop-web-1"],"Image":"nginx","State":"running","Status":"Up (healthy)",
			 "Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web"}},
			{"Id":"def","Names":["/shop-db-1"],"Image":"postgres","State":"exited","Status":"Exited (0)",
			 "Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"db"}},
			{"Id":"xyz","Names":["/loose"],"Image":"redis","State":"running","Status":"Up","Labels":{}}
		]`))
	})
	mux.HandleFunc("/containers/abc/json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Id":"abc","RestartCount":1,"State":{"Status":"running","Running":true,"Health":{"Status":"healthy"}}}`))
	})
	mux.HandleFunc("/containers/def/json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Id":"def","RestartCount":5,"State":{"Status":"exited","Running":false}}`))
	})
	mux.HandleFunc("/containers/abc/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"cpu_stats":{"cpu_usage":{"total_usage":2000},"system_cpu_usage":100000,"online_cpus":2},
			"precpu_stats":{},"memory_stats":{"usage":1048576,"limit":2097152,"stats":{}}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return docker.New(strings.TrimPrefix(srv.URL, "http://"))
}

func newTestMonitor(t *testing.T) (*Monitor, *store.DB) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := New(db, fakeEngine(t), hostmon.New("/"), time.Second, time.Hour, log, nil)
	return m, db
}

func TestPollDiscoversAppsAndPersists(t *testing.T) {
	m, db := newTestMonitor(t)
	snap := m.pollOnce(context.Background())

	if !snap.DockerOK {
		t.Fatalf("docker not OK: %s", snap.DockerErr)
	}
	if len(snap.Apps) != 1 {
		t.Fatalf("want 1 app (unlabeled container excluded), got %d", len(snap.Apps))
	}
	app := snap.Apps[0]
	if app.Project != "shop" || app.Total() != 2 {
		t.Fatalf("app grouping wrong: %+v", app)
	}
	if app.UpCount() != 1 || !app.Degraded() { // db is exited → degraded
		t.Errorf("expected 1 up + degraded, got up=%d degraded=%v", app.UpCount(), app.Degraded())
	}
	// services sorted: db, web
	if app.Services[0].Service != "db" || app.Services[0].RestartCount != 5 {
		t.Errorf("db service wrong: %+v", app.Services[0])
	}
	if app.Services[1].Service != "web" || app.Services[1].Health != "healthy" {
		t.Errorf("web service wrong: %+v", app.Services[1])
	}

	// persisted: apps row + container_metrics rows
	var nApps, nMetrics int
	_ = db.QueryRow(`SELECT COUNT(*) FROM apps WHERE project='shop'`).Scan(&nApps)
	_ = db.QueryRow(`SELECT COUNT(*) FROM container_metrics WHERE project='shop'`).Scan(&nMetrics)
	if nApps != 1 {
		t.Errorf("apps rows = %d, want 1", nApps)
	}
	if nMetrics != 2 {
		t.Errorf("container_metrics rows = %d, want 2", nMetrics)
	}
}

func TestPollDockerDownIsGraceful(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// point at a dead address
	m := New(db, docker.New("127.0.0.1:1"), hostmon.New("/"), time.Second, time.Hour, log, nil)
	snap := m.pollOnce(context.Background())
	if snap.DockerOK {
		t.Error("expected DockerOK=false against a dead proxy")
	}
	if snap.DockerErr == "" {
		t.Error("expected a DockerErr message")
	}
}

func TestSnapshotAppByProject(t *testing.T) {
	s := &Snapshot{Apps: []App{{Project: "a"}, {Project: "b"}}}
	if s.AppByProject("b") == nil || s.AppByProject("c") != nil {
		t.Error("AppByProject lookup wrong")
	}
}

// scriptedEngine is a fake read plane whose container list and per-container inspect
// and stats bodies a test changes between polls (an absent body fails that call). It
// records the ids inspected in a poll, in call order. With budget > 0 the inspect
// after that many spends the poll's budget: it cancels the poll's context, as the
// deadline would, so every later call of that poll is skipped.
type scriptedEngine struct {
	mu        sync.Mutex
	list      []docker.Container
	inspect   map[string]string
	stats     map[string]string
	budget    int
	spend     context.CancelFunc
	inspected []string
}

func (e *scriptedEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	defer e.mu.Unlock()
	reply := func(body string, ok bool) {
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}
	id := strings.TrimPrefix(r.URL.Path, "/containers/")
	switch {
	case r.URL.Path == "/version":
		reply(`{"Version":"26.1.0"}`, true)
	case r.URL.Path == "/containers/json":
		_ = json.NewEncoder(w).Encode(e.list)
	case strings.HasSuffix(id, "/json"):
		if e.budget > 0 && len(e.inspected) == e.budget {
			e.spend()
			http.Error(w, "poll budget spent", http.StatusServiceUnavailable)
			return
		}
		id = strings.TrimSuffix(id, "/json")
		e.inspected = append(e.inspected, id)
		body, ok := e.inspect[id]
		reply(body, ok)
	case strings.HasSuffix(id, "/stats"):
		body, ok := e.stats[strings.TrimSuffix(id, "/stats")]
		reply(body, ok)
	default:
		http.NotFound(w, r)
	}
}

// update changes the engine's script between polls.
func (e *scriptedEngine) update(f func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	f()
}

// poll runs one poll and returns its snapshot and the ids inspected, in call order.
func (e *scriptedEngine) poll(m *Monitor) (*Snapshot, []string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.update(func() { e.spend, e.inspected = cancel, nil })
	snap := m.pollOnce(ctx)
	e.mu.Lock()
	defer e.mu.Unlock()
	return snap, slices.Clone(e.inspected)
}

func newScriptedMonitor(t *testing.T, e *scriptedEngine) *Monitor {
	t.Helper()
	if e.inspect == nil {
		e.inspect = map[string]string{}
	}
	if e.stats == nil {
		e.stats = map[string]string{}
	}
	srv := httptest.NewServer(e)
	t.Cleanup(srv.Close)
	db, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(db, docker.New(strings.TrimPrefix(srv.URL, "http://")), hostmon.New("/"), time.Second, time.Hour, log, nil)
}

// svcCtr is a list entry for one container of service svc in project "shop".
func svcCtr(id, svc, state, status string) docker.Container {
	return docker.Container{
		ID: id, Names: []string{"/shop-" + id}, Image: "img", State: state, Status: status,
		Labels: map[string]string{docker.LabelProject: "shop", docker.LabelService: svc},
	}
}

// running is a running container of service "svc" with no health in its Status.
func running(id string) docker.Container { return svcCtr(id, "svc", "running", "Up 1 hour") }

// inspectBody is an inspect response; health "" means no healthcheck.
func inspectBody(state, health, startedAt string, restarts int) string {
	h := ""
	if health != "" {
		h = fmt.Sprintf(`,"Health":{"Status":%q}`, health)
	}
	return fmt.Sprintf(`{"RestartCount":%d,"State":{"Status":%q,"Running":%t,"StartedAt":%q%s}}`,
		restarts, state, state == "running", startedAt, h)
}

// statsBody is a one-shot stats response with the given raw CPU counters on one CPU.
func statsBody(total, system uint64) string {
	return fmt.Sprintf(`{"cpu_stats":{"cpu_usage":{"total_usage":%d},"system_cpu_usage":%d,"online_cpus":1},`+
		`"memory_stats":{"usage":1048576,"limit":4194304,"stats":{}}}`, total, system)
}

// statusOf returns the published status of container id.
func statusOf(t *testing.T, snap *Snapshot, id string) ServiceStatus {
	t.Helper()
	for _, a := range snap.Apps {
		for _, s := range a.Services {
			if s.ContainerID == id {
				return s
			}
		}
	}
	t.Fatalf("container %s is not in the snapshot", id)
	return ServiceStatus{}
}

func TestInspectOrder(t *testing.T) {
	cases := []struct {
		name  string
		cs    []docker.Container // list order: newest first
		known map[string]inspectRecord
		seq   int64
		want  []string
	}{
		{
			name: "urgent classes first, whatever the list order",
			cs: []docker.Container{
				running("new"),
				running("ok"),
				svcCtr("down", "svc", "exited", "Exited (1) 2 minutes ago"),
				running("boot"),
				svcCtr("sick", "svc", "running", "Up 1 hour (unhealthy)"),
			},
			known: map[string]inspectRecord{
				"ok":   {seq: 4, health: "healthy"},
				"down": {seq: 4, health: "none"},
				"boot": {seq: 4, health: "starting"},
				"sick": {seq: 4, health: "healthy"}, // the list has seen it turn unhealthy since
			},
			seq:  5, // 5 % 5 == 0: ties in plain id order
			want: []string{"down", "boot", "sick", "new", "ok"},
		},
		{
			name:  "least recently inspected first within a class",
			cs:    []docker.Container{running("a"), running("b"), running("c")},
			known: map[string]inspectRecord{"a": {seq: 9}, "b": {seq: 7}, "c": {seq: 8}},
			seq:   10,
			want:  []string{"b", "c", "a"},
		},
		{
			name:  "never inspected before the rest, least recent first",
			cs:    []docker.Container{running("fresh"), running("a"), running("b")},
			known: map[string]inspectRecord{"a": {seq: 3}, "b": {seq: 2}},
			seq:   3,
			want:  []string{"fresh", "b", "a"},
		},
		{
			name:  "ties rotate with the poll (seq 4)",
			cs:    []docker.Container{running("a"), running("b"), running("c")},
			known: map[string]inspectRecord{"a": {seq: 1}, "b": {seq: 1}, "c": {seq: 1}},
			seq:   4, // 4 % 3 == 1
			want:  []string{"b", "c", "a"},
		},
		{
			name:  "ties rotate with the poll (seq 5)",
			cs:    []docker.Container{running("a"), running("b"), running("c")},
			known: map[string]inspectRecord{"a": {seq: 1}, "b": {seq: 1}, "c": {seq: 1}},
			seq:   5,
			want:  []string{"c", "a", "b"},
		},
		{name: "empty", seq: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, i := range inspectOrder(tc.cs, tc.known, tc.seq) {
				got = append(got, tc.cs[i].ID)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("order = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestInspectOrderNeverStarves(t *testing.T) {
	// 7 healthy containers, a budget of 3 inspects a poll: once all have been reached,
	// every one must have a fresh inspect at most ceil(7/3)-1 = 2 polls old, so the
	// carry-forward always covers it.
	cs := []docker.Container{running("a"), running("b"), running("c"), running("d"),
		running("e"), running("f"), running("g")}
	known := map[string]inspectRecord{}
	for seq := int64(1); seq <= 40; seq++ {
		for _, i := range inspectOrder(cs, known, seq)[:3] {
			known[cs[i].ID] = inspectRecord{seq: seq, health: "healthy"}
		}
		if seq < 3 {
			continue // still reaching the never-inspected ones
		}
		for _, c := range cs {
			if age := seq - known[c.ID].seq; age > inspectCarryPolls {
				t.Fatalf("poll %d: %s last inspected %d polls ago", seq, c.ID, age)
			}
		}
	}
}

func TestPollInspectsUrgentFirstUnderBudget(t *testing.T) {
	// Poll 1 (no budget) inspects everything; poll 2 lists a new container and allows
	// only budget inspects. Poll 2's full priority order is: down (not running), boot
	// (starting), new (never inspected), then the healthy rest — ok1, ok2, db here,
	// the list order (db, the oldest, last) no longer deciding anything.
	const started = "2026-09-29T10:00:00Z"
	all := []string{"down", "boot", "new", "ok1", "ok2", "db"}
	cases := []struct {
		budget int
		want   []string
	}{
		{budget: 1, want: all[:1]},
		{budget: 2, want: all[:2]},
		{budget: 3, want: all[:3]},
		{budget: 0, want: all},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("budget %d", tc.budget), func(t *testing.T) {
			e := &scriptedEngine{
				list: []docker.Container{
					running("ok2"),
					svcCtr("down", "svc", "exited", "Exited (137) 1 minute ago"),
					svcCtr("boot", "svc", "running", "Up 5 seconds (health: starting)"),
					running("ok1"),
					running("db"),
				},
				inspect: map[string]string{
					"ok2":  inspectBody("running", "", started, 0),
					"down": inspectBody("exited", "", started, 0),
					"boot": inspectBody("running", "starting", started, 0),
					"ok1":  inspectBody("running", "", started, 0),
					"db":   inspectBody("running", "", started, 0),
					"new":  inspectBody("running", "", started, 0),
				},
			}
			m := newScriptedMonitor(t, e)
			if _, calls := e.poll(m); len(calls) != 5 {
				t.Fatalf("warm-up poll inspected %v, want all 5", calls)
			}

			e.update(func() {
				e.list = append([]docker.Container{running("new")}, e.list...)
				e.budget = tc.budget
			})
			snap, calls := e.poll(m)
			if !slices.Equal(calls, tc.want) {
				t.Fatalf("inspected %v, want %v", calls, tc.want)
			}
			if partial := snap.DockerErr != ""; partial != (tc.budget > 0) {
				t.Errorf("DockerErr = %q with budget %d", snap.DockerErr, tc.budget)
			}
			for _, id := range all {
				// Everything but a never-inspected container skipped by the budget is
				// Inspected: fresh, or carried from poll 1.
				want := id != "new" || slices.Contains(calls, "new")
				if got := statusOf(t, snap, id).Inspected; got != want {
					t.Errorf("%s: Inspected = %v, want %v", id, got, want)
				}
			}
		})
	}
}

func TestInspectCarryForward(t *testing.T) {
	const t0 = "2026-09-29T10:00:00.5Z"
	started, _ := time.Parse(time.RFC3339Nano, t0)
	good := inspectBody("running", "healthy", t0, 2)
	e := &scriptedEngine{list: []docker.Container{svcCtr("web1", "web", "running", "Up 1 hour (healthy)")}}
	m := newScriptedMonitor(t, e)

	steps := []struct {
		name      string
		inspectOK bool
		want      bool // Inspected
	}{
		{"fresh", true, true},
		{"1 poll old: carried", false, true},
		{"2 polls old: carried", false, true},
		{"3 polls old: defaults", false, false},
		{"4 polls old: defaults", false, false},
		{"fresh again", true, true},
		{"1 poll old again: carried", false, true},
	}
	for _, st := range steps {
		e.update(func() {
			if st.inspectOK {
				e.inspect["web1"] = good
			} else {
				delete(e.inspect, "web1")
			}
		})
		snap, _ := e.poll(m)
		s := statusOf(t, snap, "web1")
		if s.Inspected != st.want {
			t.Fatalf("%s: Inspected = %v, want %v", st.name, s.Inspected, st.want)
		}
		if st.want && (s.Health != "healthy" || s.RestartCount != 2 || !s.StartedAt.Equal(started)) {
			t.Errorf("%s: fields not carried: %+v", st.name, s)
		}
		if !st.want && (s.Health != "none" || s.RestartCount != 0 || !s.StartedAt.IsZero()) {
			t.Errorf("%s: want the defaults, got %+v", st.name, s)
		}
	}

	// A container that leaves the list is forgotten, so its record can't come back.
	e.update(func() { e.list = nil })
	e.poll(m)
	if _, ok := m.inspected["web1"]; ok {
		t.Error("the record of an unlisted container was not pruned")
	}
}

func TestCarryForwardVoidedByTheList(t *testing.T) {
	// A carried inspect must not contradict the (fresher) list entry.
	cases := []struct {
		name string
		now  docker.Container // the list entry on the poll whose inspect fails
		want bool             // Inspected
	}{
		{"unchanged", svcCtr("web1", "web", "running", "Up 1 hour (healthy)"), true},
		{"no health in the status", svcCtr("web1", "web", "running", "Up 1 hour"), true},
		{"state changed", svcCtr("web1", "web", "exited", "Exited (137) 5 seconds ago"), false},
		{"health changed", svcCtr("web1", "web", "running", "Up 1 hour (unhealthy)"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &scriptedEngine{
				list:    []docker.Container{svcCtr("web1", "web", "running", "Up 1 hour (healthy)")},
				inspect: map[string]string{"web1": inspectBody("running", "healthy", "2026-09-29T10:00:00Z", 0)},
			}
			m := newScriptedMonitor(t, e)
			e.poll(m)
			e.update(func() {
				e.list = []docker.Container{tc.now}
				delete(e.inspect, "web1")
			})
			snap, _ := e.poll(m)
			if got := statusOf(t, snap, "web1").Inspected; got != tc.want {
				t.Errorf("Inspected = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseStartedAt(t *testing.T) {
	cases := []struct {
		in   string
		want time.Time
	}{
		{"2026-09-29T10:11:12.123456789Z", time.Date(2026, 9, 29, 10, 11, 12, 123456789, time.UTC)},
		{"2026-09-29T12:11:12+02:00", time.Date(2026, 9, 29, 10, 11, 12, 0, time.UTC)},
		{"0001-01-01T00:00:00Z", time.Time{}}, // Docker's "never started"
		{"", time.Time{}},
		{"yesterday", time.Time{}},
	}
	for _, tc := range cases {
		got := parseStartedAt(tc.in)
		if !got.Equal(tc.want) || got.IsZero() != tc.want.IsZero() {
			t.Errorf("parseStartedAt(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestCPUValid(t *testing.T) {
	const run1, run2 = "2026-09-29T10:00:00Z", "2026-09-29T11:00:00Z"
	e := &scriptedEngine{list: []docker.Container{
		svcCtr("web1", "web", "running", "Up 1 hour"),
		svcCtr("old1", "old", "exited", "Exited (0) 1 hour ago"),
	}}
	m := newScriptedMonitor(t, e)
	e.update(func() {
		e.inspect["old1"] = inspectBody("exited", "", run1, 0)
		e.stats["old1"] = statsBody(1, 1) // never asked for: it isn't running
	})

	steps := []struct {
		name      string
		startedAt string // web1's inspect State.StartedAt
		stats     string // web1's stats body; "" fails the call
		wantValid bool
		wantCPU   float64
	}{
		{"first sample", run1, statsBody(1000, 100000), false, 0},
		{"delta", run1, statsBody(6000, 200000), true, 5},
		{"stats failed", run1, "", false, 0},
		{"delta across the failed sample", run1, statsBody(16000, 400000), true, 5},
		{"counters reset by a restart", run1, statsBody(500, 500000), false, 0},
		{"delta after the reset", run1, statsBody(10500, 600000), true, 10},
		{"new run (StartedAt changed)", run2, statsBody(11000, 700000), false, 0},
		{"delta in the new run", run2, statsBody(21000, 800000), true, 10},
		{"idle", run2, statsBody(21000, 900000), true, 0},
	}
	for _, st := range steps {
		e.update(func() {
			e.inspect["web1"] = inspectBody("running", "", st.startedAt, 0)
			if st.stats == "" {
				delete(e.stats, "web1")
			} else {
				e.stats["web1"] = st.stats
			}
		})
		snap, _ := e.poll(m)
		s := statusOf(t, snap, "web1")
		if s.CPUValid != st.wantValid || math.Abs(s.CPUPercent-st.wantCPU) > 1e-9 {
			t.Errorf("%s: CPUValid=%v CPUPercent=%v, want %v %v", st.name, s.CPUValid, s.CPUPercent, st.wantValid, st.wantCPU)
		}
		if old := statusOf(t, snap, "old1"); old.CPUValid || old.MemBytes != 0 {
			t.Errorf("%s: a stopped container got a stats sample: %+v", st.name, old)
		}
	}
}

func TestPublishedOrderKeepsCopiesNewestFirst(t *testing.T) {
	// Sorted by service; the copies of one service keep the list order (newest first)
	// whatever order they were inspected in, also past the size where sort.Slice is
	// no longer stable.
	var list []docker.Container
	var webs []string
	for i := 20; i > 0; i-- { // newest first
		id := fmt.Sprintf("web%02d", i)
		list = append(list, svcCtr(id, "web", "running", "Up 1 hour"))
		webs = append(webs, id)
	}
	list = append(list, svcCtr("db1", "db", "exited", "Exited (1) 1 minute ago"))
	e := &scriptedEngine{list: list}
	m := newScriptedMonitor(t, e)
	for poll := 0; poll < 3; poll++ {
		snap, _ := e.poll(m)
		var got []string
		for _, s := range snap.Apps[0].Services {
			got = append(got, s.ContainerID)
		}
		if want := append([]string{"db1"}, webs...); !slices.Equal(got, want) {
			t.Fatalf("poll %d: published order %v, want %v", poll, got, want)
		}
	}
}
