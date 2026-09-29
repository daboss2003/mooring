package web

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/hostmon"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/startgate"
)

// roBehaviour is what a container reports for the age of its current run.
type roBehaviour func(age time.Duration) (state, health string, exitCode int)

func roHealthyAfter(d time.Duration) roBehaviour {
	return func(age time.Duration) (string, string, int) {
		if age < d {
			return "running", "starting", 0
		}
		return "running", "healthy", 0
	}
}

func roExited(code int) roBehaviour {
	return func(time.Duration) (string, string, int) { return "exited", "none", code }
}

var (
	roHealthy    = roHealthyAfter(0)
	roStarting   = roBehaviour(func(time.Duration) (string, string, int) { return "running", "starting", 0 })
	roUnhealthy  = roBehaviour(func(time.Duration) (string, string, int) { return "running", "unhealthy", 0 })
	roNoCheck    = roBehaviour(func(time.Duration) (string, string, int) { return "running", "none", 0 })
	roRestarting = roBehaviour(func(time.Duration) (string, string, int) { return "restarting", "none", 1 })
)

// roCtr is one container of the fake host.
type roCtr struct {
	app, svc, id string
	tag          string // names this run in call logs: <svc>#<n> for the n-th container an up created, <id>#<runs> for a copy
	runs         int
	started      time.Time
	b            roBehaviour
	cpu          float64 // per core
}

// roCall is one logged docker call and what the last container view handed out showed when it ran.
type roCall struct {
	ok          bool
	argv, shown string
}

// roWorld is a fake host for rollout tests. Its `docker` (first on PATH) logs every call together with
// what the last container view it handed out showed, and fails every call naming failOn. Its
// container view (the server's snapFn) plays the logged calls: `compose … up … -- <svc>` replaces the
// service's containers with a new one (unless the service is marked unchanged), `restart|start <id>`
// begins a new run of that copy. A container reports what its behaviour says for its run's age.
type roWorld struct {
	t      *testing.T
	logf   string
	statef string

	mu        sync.Mutex
	applied   int // logged calls already played
	ctrs      []*roCtr
	on        map[string]roBehaviour // "app/svc" → what a container the rollout starts does (default healthy)
	unchanged map[string]bool        // "app/svc": an up leaves the service as it is
	gens      map[string]int
	hostCPU   float64
	last      *monitor.Snapshot
	frozen    bool // the view stopped updating
}

var (
	roDockerOnce sync.Once
	roDockerDir  string
	roDockerErr  error
)

// roDocker returns the directory of the fake docker, written once per test run: the first run of a
// new executable can take the OS most of a second (macOS scans it), which would skew the timings the
// tests measure. Each world points it at its own files through DOCKER_CONFIG, which the runner passes
// on to docker.
func roDocker() (string, error) {
	roDockerOnce.Do(func() {
		dir, err := os.MkdirTemp("", "mooring-rollout-docker")
		if err != nil {
			roDockerErr = err
			return
		}
		script := `#!/bin/sh
code=0
fail=$(cat "$DOCKER_CONFIG/fail" 2>/dev/null)
if [ -n "$fail" ]; then
	case " $* " in *" $fail "*) code=1 ;; esac
fi
echo "$code|$*|$(cat "$DOCKER_CONFIG/shown" 2>/dev/null)" >> "$DOCKER_CONFIG/calls.log"
exit $code
`
		bin := filepath.Join(dir, "docker")
		if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
			roDockerErr = err
			return
		}
		warm := exec.Command(bin)
		warm.Env = append(os.Environ(), "DOCKER_CONFIG="+dir)
		roDockerDir, roDockerErr = dir, warm.Run()
	})
	return roDockerDir, roDockerErr
}

func newRoWorld(t *testing.T, failOn string) *roWorld {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake docker")
	}
	bin, err := roDocker()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	w := &roWorld{t: t, logf: filepath.Join(dir, "calls.log"), statef: filepath.Join(dir, "shown"),
		on: map[string]roBehaviour{}, unchanged: map[string]bool{}, gens: map[string]int{}}
	if failOn != "" {
		if err := os.WriteFile(filepath.Join(dir, "fail"), []byte(failOn), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("DOCKER_CONFIG", dir)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return w
}

// add puts a container in the view whose current run began at started.
func (w *roWorld) add(app, svc, id string, started time.Time, b roBehaviour) *roCtr {
	w.mu.Lock()
	defer w.mu.Unlock()
	c := &roCtr{app: app, svc: svc, id: id, tag: id + "#0", started: started, b: b, cpu: 1}
	w.ctrs = append(w.ctrs, c)
	return c
}

// freeze stops the view: every later snapshot is the last one again.
func (w *roWorld) freeze() {
	w.snap()
	w.mu.Lock()
	w.frozen = true
	w.mu.Unlock()
}

func (w *roWorld) calls() []roCall {
	b, err := os.ReadFile(w.logf)
	if err != nil {
		return nil // no call yet
	}
	var out []roCall
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if p := strings.SplitN(line, "|", 3); len(p) == 3 {
			out = append(out, roCall{ok: p[0] == "0", argv: p[1], shown: p[2]})
		}
	}
	return out
}

func (w *roWorld) argvs() []string {
	var out []string
	for _, c := range w.calls() {
		out = append(out, c.argv)
	}
	return out
}

func (w *roWorld) behaviour(key string) roBehaviour {
	if b := w.on[key]; b != nil {
		return b
	}
	return roHealthy
}

// play applies the docker calls logged since the last view.
func (w *roWorld) play() {
	calls := w.calls()
	now := time.Now()
	for _, c := range calls[w.applied:] {
		if !c.ok {
			continue
		}
		args := strings.Fields(c.argv)
		switch {
		case len(args) > 3 && args[0] == "compose" && strings.Contains(c.argv, " up "):
			app, svc := args[2], args[len(args)-1]
			key := app + "/" + svc
			if w.unchanged[key] {
				continue
			}
			keep := w.ctrs[:0]
			for _, x := range w.ctrs {
				if x.app != app || x.svc != svc {
					keep = append(keep, x)
				}
			}
			w.gens[key]++
			n := w.gens[key]
			w.ctrs = append(keep, &roCtr{app: app, svc: svc, id: fmt.Sprintf("%s-%d", svc, n),
				tag: fmt.Sprintf("%s#%d", svc, n), started: now, b: w.behaviour(key), cpu: 1})
		case len(args) == 2 && (args[0] == "restart" || args[0] == "start"):
			for _, x := range w.ctrs {
				if x.id != args[1] {
					continue
				}
				if state, _, _ := x.b(now.Sub(x.started)); args[0] == "start" && state == "running" {
					continue // docker start leaves a running container alone
				}
				x.runs++
				x.tag = fmt.Sprintf("%s#%d", x.id, x.runs)
				x.started = now
				x.b = w.behaviour(x.app + "/" + x.svc)
			}
		}
	}
	w.applied = len(calls)
}

// snap is the server's container view: every call a new snapshot (a later At), after playing the
// calls docker was asked to make. It also leaves what it showed for the fake docker to log.
func (w *roWorld) snap() *monitor.Snapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.frozen {
		return w.last
	}
	w.play()
	at := time.Now()
	if w.last != nil && !at.After(w.last.At) {
		at = w.last.At.Add(time.Microsecond)
	}
	snap := &monitor.Snapshot{At: at, DockerOK: true, HostOK: true, Host: hostmon.Sample{CPUPercent: w.hostCPU}}
	var shown []string
	for _, c := range w.ctrs {
		state, health, exit := c.b(at.Sub(c.started))
		a := snap.AppByProject(c.app)
		if a == nil {
			snap.Apps = append(snap.Apps, monitor.App{Project: c.app})
			a = &snap.Apps[len(snap.Apps)-1]
		}
		a.Services = append(a.Services, monitor.ServiceStatus{
			Service: c.svc, ContainerID: c.id, State: state, Health: health, ExitCode: exit,
			StartedAt: c.started, Inspected: true, CPUPercent: c.cpu, CPUValid: state == "running",
		})
		if state == "running" {
			shown = append(shown, c.tag+"="+health)
		} else {
			shown = append(shown, c.tag+"="+state)
		}
	}
	if err := os.WriteFile(w.statef, []byte(strings.Join(shown, " ")), 0o644); err != nil {
		w.t.Error(err)
	}
	w.last = snap
	return snap
}

// newRolloutTest builds a server for rollout tests: a write-plane runner, a start gate (DefaultConfig
// for 2 CPUs, adjusted by tune) and w as its container view. Rollout timings are shrunk; the pacing
// budgets are generous unless a test lowers them.
func newRolloutTest(t *testing.T, failOn string, tune func(*startgate.Config)) (*Server, *roWorld) {
	t.Helper()
	poll, beat, snapWait, renew := rolloutPoll, rolloutHeartbeat, rolloutSnapshotWait, rolloutRenewEvery
	rolloutPoll, rolloutHeartbeat, rolloutSnapshotWait = 5*time.Millisecond, 60*time.Millisecond, 400*time.Millisecond
	t.Cleanup(func() {
		rolloutPoll, rolloutHeartbeat, rolloutSnapshotWait, rolloutRenewEvery = poll, beat, snapWait, renew
	})
	w := newRoWorld(t, failOn)
	gc := startgate.DefaultConfig(2)
	if tune != nil {
		tune(&gc)
	}
	cfg := &config.Config{}
	cfg.Server.StartGate = config.StartGateConfig{
		DeployWait:    rolloutDur(2 * time.Second),
		ServiceSettle: config.Duration(10 * time.Second),
		RolloutBudget: config.Duration(20 * time.Second),
	}
	s := &Server{cfg: cfg, runner: dockerexec.NewRunner(dockerexec.NewSemaphore(), true, ""),
		startGate: startgate.New(gc), snapFn: w.snap}
	return s, w
}

// roUp is a rollout step of app shop's service svc: a compose up (with the conflict reap).
func roUp(svc string, deadline time.Duration) rolloutStep {
	return rolloutStep{Service: svc, Reap: true, Deadline: deadline,
		Job: dockerexec.Job{Project: "shop", Action: []string{"up", "-d", "--no-deps", "--no-build"}, Service: svc}}
}

func roCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // a deadlock fails fast
	t.Cleanup(cancel)
	return ctx
}

type roResult struct {
	problems []rolloutProblem
	err      error
	lines    []string
	started  []string
	took     time.Duration
}

func (r roResult) count(sub string) int {
	n := 0
	for _, l := range r.lines {
		if strings.Contains(l, sub) {
			n++
		}
	}
	return n
}

func (r roResult) has(sub string) bool { return r.count(sub) > 0 }

func (r roResult) output() string { return strings.Join(r.lines, "\n") }

// runRolloutTest runs a rollout of app shop, collecting its output and Started calls.
func runRolloutTest(ctx context.Context, s *Server, steps []rolloutStep, o rolloutOpts) roResult {
	var mu sync.Mutex
	var res roResult
	o.App = "shop"
	o.OnLine = func(l string) {
		mu.Lock()
		res.lines = append(res.lines, l)
		mu.Unlock()
	}
	if o.Started == nil {
		o.Started = func(svc string) { res.started = append(res.started, svc) }
	}
	begin := time.Now()
	res.problems, res.err = s.runRollout(ctx, steps, o)
	res.took = time.Since(begin)
	mu.Lock()
	defer mu.Unlock()
	return res
}

// Each service starts only once the container the previous step started is healthy.
func TestRolloutStartsEachServiceAfterThePreviousIsHealthy(t *testing.T) {
	s, w := newRolloutTest(t, "", nil)
	w.on["shop/api"] = roHealthyAfter(150 * time.Millisecond)
	w.on["shop/web"] = roHealthyAfter(50 * time.Millisecond)
	res := runRolloutTest(roCtx(t), s, []rolloutStep{roUp("api", 5*time.Second), roUp("web", 5*time.Second)}, rolloutOpts{})
	if res.err != nil || len(res.problems) != 0 {
		t.Fatalf("err=%v problems=%v\n%s", res.err, res.problems, res.output())
	}
	calls := w.calls()
	if len(calls) != 2 || calls[0].argv != "compose -p shop up -d --no-deps --no-build -- api" ||
		calls[1].argv != "compose -p shop up -d --no-deps --no-build -- web" {
		t.Fatalf("calls = %v", w.argvs())
	}
	if !strings.Contains(calls[1].shown, "api#1=healthy") {
		t.Fatalf("web was started while api's new container showed %q; it must wait until that one is healthy", calls[1].shown)
	}
	for _, want := range []string{
		"→ api (1/2): docker compose up -d --no-deps --no-build -- api", "  api: healthy after",
		"→ web (2/2): docker compose up -d --no-deps --no-build -- web", "  web: healthy after",
	} {
		if !res.has(want) {
			t.Errorf("output lacks %q:\n%s", want, res.output())
		}
	}
	if strings.Join(res.started, ",") != "api,web" {
		t.Errorf("Started = %v", res.started)
	}
}

// A service that never settles is reported once its deadline passes, and the next one still starts at
// once: the rollout's own still-starting service never holds it back.
func TestRolloutReportsAServiceThatNeverSettlesAndCarriesOn(t *testing.T) {
	s, w := newRolloutTest(t, "", nil)
	w.on["shop/api"] = roStarting
	res := runRolloutTest(roCtx(t), s, []rolloutStep{roUp("api", 200*time.Millisecond), roUp("web", 5*time.Second)}, rolloutOpts{})
	if res.err != nil {
		t.Fatal(res.err)
	}
	if len(res.problems) != 1 || res.problems[0] != (rolloutProblem{Service: "api", Reason: "still starting after 200ms"}) {
		t.Fatalf("problems = %v", res.problems)
	}
	if len(w.calls()) != 2 || !res.has("  ⚠ api: still starting after 200ms — continuing") || !res.has("  web: healthy after") {
		t.Fatalf("calls=%v\n%s", w.argvs(), res.output())
	}
	if res.has("web: waiting") {
		t.Fatalf("web waited on its own app's start:\n%s", res.output())
	}
}

// A failed docker call is reported, the next service still starts, and only the started one is
// released (Started); the lease is renewed after every step.
func TestRolloutReportsAFailedStartAndCarriesOn(t *testing.T) {
	s, w := newRolloutTest(t, "api", nil)
	renews := 0
	res := runRolloutTest(roCtx(t), s, []rolloutStep{roUp("api", 5*time.Second), roUp("web", 5*time.Second)},
		rolloutOpts{Renew: func() { renews++ }})
	if res.err != nil {
		t.Fatal(res.err)
	}
	if len(res.problems) != 1 || res.problems[0] != (rolloutProblem{Service: "api", Reason: "start failed: exit status 1"}) {
		t.Fatalf("problems = %v", res.problems)
	}
	if calls := w.calls(); len(calls) != 2 || calls[0].ok || !calls[1].ok {
		t.Fatalf("calls = %v", calls)
	}
	if strings.Join(res.started, ",") != "web" {
		t.Fatalf("Started = %v, want only web", res.started)
	}
	if renews != 2 {
		t.Fatalf("Renew called %d times, want once per step", renews)
	}
	if res.has("api: healthy") || res.has("api: starting…") {
		t.Fatalf("no settle wait after a failed start:\n%s", res.output())
	}
}

// A busy host holds the rollout back for at most deploy_wait in total, not per service.
func TestRolloutWaitsForCPUOnceAcrossTheRollout(t *testing.T) {
	s, w := newRolloutTest(t, "", nil)
	s.cfg.Server.StartGate.DeployWait = rolloutDur(500 * time.Millisecond)
	w.hostCPU = 95
	old := time.Now().Add(-time.Hour)
	for _, svc := range []string{"api", "web", "worker"} {
		w.add("shop", svc, svc+"-old", old, roHealthy)
	}
	s.observeStarts(w.snap()) // the gate has CPU samples from before the rollout
	s.observeStarts(w.snap())
	res := runRolloutTest(roCtx(t), s, []rolloutStep{roUp("api", 5*time.Second), roUp("web", 5*time.Second), roUp("worker", 5*time.Second)}, rolloutOpts{})
	if res.err != nil || len(res.problems) != 0 {
		t.Fatalf("err=%v problems=%v", res.err, res.problems)
	}
	if len(w.calls()) != 3 {
		t.Fatalf("calls = %v", w.argvs())
	}
	if !res.has("  api: waiting — host CPU") || res.has("web: waiting") || res.has("worker: waiting") {
		t.Fatalf("only the first service may wait:\n%s", res.output())
	}
	if n := res.count("  waited 500ms for CPU/other starts — starting anyway"); n != 1 {
		t.Fatalf("the budget line appears %d times:\n%s", n, res.output())
	}
	if res.took < 500*time.Millisecond || res.took > time.Second {
		t.Fatalf("rollout took %s; want one 500ms wait budget for the whole rollout", res.took)
	}
}

// The service's own busy copies don't make it wait for CPU, and a service with no running copy never
// waits for CPU.
func TestRolloutDoesNotWaitForTheServicesOwnCPU(t *testing.T) {
	s, w := newRolloutTest(t, "", nil)
	s.cfg.Server.StartGate.DeployWait = rolloutDur(time.Second)
	w.hostCPU = 90
	busy := w.add("shop", "api", "api-old", time.Now().Add(-time.Hour), roHealthy)
	busy.cpu = 180 // 180% of one core on 2 CPUs: all of the host's 90%
	s.observeStarts(w.snap())
	s.observeStarts(w.snap())
	res := runRolloutTest(roCtx(t), s, []rolloutStep{roUp("api", 5*time.Second), roUp("worker", 5*time.Second)}, rolloutOpts{})
	if res.err != nil || len(res.problems) != 0 || len(w.calls()) != 2 {
		t.Fatalf("err=%v problems=%v calls=%v", res.err, res.problems, w.argvs())
	}
	if res.has("waiting") || res.took > 700*time.Millisecond {
		t.Fatalf("no CPU wait expected (took %s):\n%s", res.took, res.output())
	}
}

// Another app's container that is still starting holds the rollout until it is healthy.
func TestRolloutWaitsForAnotherAppsStart(t *testing.T) {
	s, w := newRolloutTest(t, "", nil)
	w.add("other", "db", "db1", time.Now(), roHealthyAfter(200*time.Millisecond))
	res := runRolloutTest(roCtx(t), s, []rolloutStep{roUp("api", 5*time.Second)}, rolloutOpts{})
	if res.err != nil || len(res.problems) != 0 {
		t.Fatalf("err=%v problems=%v", res.err, res.problems)
	}
	calls := w.calls()
	if len(calls) != 1 || !strings.Contains(calls[0].shown, "db1#0=healthy") {
		t.Fatalf("api must start after other/db is healthy: %v", calls)
	}
	if !res.has("  api: waiting — other/db is still starting") || res.has("starting anyway") {
		t.Fatalf("output:\n%s", res.output())
	}
}

// Waiting on another app's start is bounded by deploy_wait, for the whole rollout.
func TestRolloutWaitForOtherStartsIsBounded(t *testing.T) {
	s, w := newRolloutTest(t, "", nil)
	s.cfg.Server.StartGate.DeployWait = rolloutDur(300 * time.Millisecond)
	w.add("other", "db", "db1", time.Now(), roStarting)
	res := runRolloutTest(roCtx(t), s, []rolloutStep{roUp("api", 5*time.Second), roUp("web", 5*time.Second)}, rolloutOpts{})
	if res.err != nil || len(res.problems) != 0 {
		t.Fatalf("err=%v problems=%v", res.err, res.problems)
	}
	calls := w.calls()
	if len(calls) != 2 || !strings.Contains(calls[0].shown, "db1#0=starting") {
		t.Fatalf("api must start anyway while other/db is still starting: %v", calls)
	}
	if res.count("  waited 300ms for CPU/other starts — starting anyway") != 1 || res.has("web: waiting") {
		t.Fatalf("output:\n%s", res.output())
	}
	if res.took < 300*time.Millisecond || res.took > 900*time.Millisecond {
		t.Fatalf("rollout took %s", res.took)
	}
}

// The rollout's own app never holds it back: neither another of its services still starting nor a
// start of the app the gate hasn't seen settle.
func TestRolloutIsNotHeldByItsOwnAppsStarts(t *testing.T) {
	s, w := newRolloutTest(t, "", nil)
	w.add("shop", "worker", "worker1", time.Now(), roStarting)
	now := time.Now()
	s.startGate.Record("shop", "", now, now, true)
	res := runRolloutTest(roCtx(t), s, []rolloutStep{roUp("api", 5*time.Second)}, rolloutOpts{})
	if res.err != nil || len(res.problems) != 0 || len(w.calls()) != 1 {
		t.Fatalf("err=%v problems=%v calls=%v", res.err, res.problems, w.argvs())
	}
	if res.has("waiting") || res.took > time.Second {
		t.Fatalf("api waited on its own app (took %s):\n%s", res.took, res.output())
	}
	if d := s.startGate.Admit(time.Now(), startgate.AdmitOpts{}); d.OK {
		t.Fatal("another app must still be held by shop's starts (the exemption is the rollout's own)")
	}
}

// Once the rollout budget is used up, the remaining services start without any waiting.
func TestRolloutBudgetEndsPacing(t *testing.T) {
	s, w := newRolloutTest(t, "", nil)
	s.cfg.Server.StartGate.RolloutBudget = config.Duration(300 * time.Millisecond)
	for _, svc := range []string{"api", "web", "worker"} {
		w.on["shop/"+svc] = roStarting
	}
	res := runRolloutTest(roCtx(t), s, []rolloutStep{roUp("api", 5*time.Second), roUp("web", 5*time.Second), roUp("worker", 5*time.Second)}, rolloutOpts{})
	if res.err != nil {
		t.Fatal(res.err)
	}
	// The service being waited on when the budget ran out isn't blamed; the rollout reports once that
	// what followed went unchecked.
	if len(res.problems) != 1 || res.problems[0].Service != "(rollout)" || !strings.Contains(res.problems[0].Reason, "without checking their health") {
		t.Fatalf("problems = %v", res.problems)
	}
	if n := res.count("  pacing budget (300ms) used up — starting the remaining services without waiting"); n != 1 {
		t.Fatalf("budget line %d times:\n%s", n, res.output())
	}
	if len(w.calls()) != 3 || res.took > 1500*time.Millisecond {
		t.Fatalf("calls=%v took=%s", w.argvs(), res.took)
	}
}

// Copies restart one at a time, each waited for; Started comes once, after the last copy.
func TestRolloutRestartsCopiesOneAtATime(t *testing.T) {
	s, w := newRolloutTest(t, "", nil)
	old := time.Now().Add(-time.Hour)
	ids := []string{"web-a", "web-b", "web-c"}
	for _, id := range ids {
		w.add("shop", "web", id, old, roHealthy)
	}
	w.on["shop/web"] = roHealthyAfter(80 * time.Millisecond)
	step := rolloutStep{Service: "web", Copies: ids, CopyAction: "restart", Deadline: 5 * time.Second}
	res := runRolloutTest(roCtx(t), s, []rolloutStep{step}, rolloutOpts{})
	if res.err != nil || len(res.problems) != 0 {
		t.Fatalf("err=%v problems=%v", res.err, res.problems)
	}
	calls := w.calls()
	if got := strings.Join(w.argvs(), ", "); got != "restart web-a, restart web-b, restart web-c" {
		t.Fatalf("calls = %s", got)
	}
	if !strings.Contains(calls[1].shown, "web-a#1=healthy") || !strings.Contains(calls[2].shown, "web-b#1=healthy") {
		t.Fatalf("each copy must wait for the previous one's restart to be healthy: %v", calls)
	}
	if !res.has("→ web copy web-a (1/3): docker restart web-a") || !res.has("  web copy web-c: healthy after") {
		t.Fatalf("output:\n%s", res.output())
	}
	if strings.Join(res.started, ",") != "web" {
		t.Fatalf("Started = %v, want web once", res.started)
	}
}

// Stopped copies start one at a time; a copy that is already running is left as it is.
func TestRolloutStartsStoppedCopiesOneAtATime(t *testing.T) {
	s, w := newRolloutTest(t, "", nil)
	old := time.Now().Add(-time.Hour)
	w.add("shop", "worker", "worker-a", old, roExited(0))
	w.add("shop", "worker", "worker-b", old, roExited(137))
	w.add("shop", "worker", "worker-c", old, roHealthy)
	w.on["shop/worker"] = roHealthyAfter(50 * time.Millisecond)
	step := rolloutStep{Service: "worker", Copies: []string{"worker-a", "worker-b", "worker-c"}, CopyAction: "start", Deadline: 5 * time.Second}
	res := runRolloutTest(roCtx(t), s, []rolloutStep{step}, rolloutOpts{})
	if res.err != nil || len(res.problems) != 0 {
		t.Fatalf("err=%v problems=%v\n%s", res.err, res.problems, res.output())
	}
	calls := w.calls()
	if got := strings.Join(w.argvs(), ", "); got != "start worker-a, start worker-b, start worker-c" {
		t.Fatalf("calls = %s", got)
	}
	if !strings.Contains(calls[1].shown, "worker-a#1=healthy") {
		t.Fatalf("worker-b must wait for worker-a: %v", calls)
	}
	if !res.has("  worker copy worker-c: already running") {
		t.Fatalf("output:\n%s", res.output())
	}
}

// Lock is taken before the docker slot and Unlock comes after it is released, once per step.
func TestRolloutLockWrapsEachDockerCall(t *testing.T) {
	s, _ := newRolloutTest(t, "", nil)
	sem := s.runner.Semaphore()
	slotFree := func(when string) {
		if !sem.TryAcquire() {
			t.Errorf("the docker slot is held %s", when)
			return
		}
		sem.Release()
	}
	locks, unlocks := 0, 0
	o := rolloutOpts{
		Lock:   func() bool { slotFree("when Lock is called"); locks++; return true },
		Unlock: func() { slotFree("when Unlock is called"); unlocks++ },
	}
	res := runRolloutTest(roCtx(t), s, []rolloutStep{roUp("api", 5*time.Second), roUp("web", 5*time.Second)}, o)
	if res.err != nil || len(res.problems) != 0 {
		t.Fatalf("err=%v problems=%v", res.err, res.problems)
	}
	if locks != 2 || unlocks != 2 {
		t.Fatalf("Lock %d, Unlock %d; want one pair per step", locks, unlocks)
	}
}

// Lock refusing stops the rollout before the step: no further docker call.
func TestRolloutStopsWhenLockRefuses(t *testing.T) {
	s, w := newRolloutTest(t, "", nil)
	locks, unlocks := 0, 0
	o := rolloutOpts{Lock: func() bool { locks++; return locks < 2 }, Unlock: func() { unlocks++ }}
	res := runRolloutTest(roCtx(t), s, []rolloutStep{roUp("api", 5*time.Second), roUp("web", 5*time.Second), roUp("worker", 5*time.Second)}, o)
	if !errors.Is(res.err, errRolloutLocked) {
		t.Fatalf("err = %v, want errRolloutLocked", res.err)
	}
	if got := w.argvs(); len(got) != 1 || !strings.HasSuffix(got[0], "-- api") {
		t.Fatalf("calls = %v, want only api's", got)
	}
	if locks != 2 || unlocks != 1 {
		t.Fatalf("Lock %d, Unlock %d", locks, unlocks)
	}
}

// The gate is asked again under the docker slot: a start that slipped in between sends the step back to
// waiting, giving the slot and the lock back first.
func TestRolloutReChecksTheGateUnderTheSlot(t *testing.T) {
	s, w := newRolloutTest(t, "", nil)
	locks, unlocks := 0, 0
	o := rolloutOpts{
		Lock: func() bool {
			locks++
			if locks == 1 { // after the gate said yes, before the slot: another app starts a container
				w.add("other", "db", "db1", time.Now(), roHealthyAfter(150*time.Millisecond))
			}
			return true
		},
		Unlock: func() { unlocks++ },
	}
	res := runRolloutTest(roCtx(t), s, []rolloutStep{roUp("api", 5*time.Second)}, o)
	if res.err != nil || len(res.problems) != 0 {
		t.Fatalf("err=%v problems=%v", res.err, res.problems)
	}
	calls := w.calls()
	if len(calls) != 1 || !strings.Contains(calls[0].shown, "db1#0=healthy") {
		t.Fatalf("api must start after other/db settled: %v", calls)
	}
	if locks != 2 || unlocks != 2 || !res.has("  api: waiting — other/db is still starting") {
		t.Fatalf("Lock %d, Unlock %d\n%s", locks, unlocks, res.output())
	}
}

// A cancelled context ends the rollout promptly, whichever wait it is in.
func TestRolloutStopsWhenCancelled(t *testing.T) {
	t.Run("settle wait", func(t *testing.T) {
		s, w := newRolloutTest(t, "", nil)
		w.on["shop/api"] = roStarting
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		time.AfterFunc(150*time.Millisecond, cancel)
		res := runRolloutTest(ctx, s, []rolloutStep{roUp("api", 30*time.Second), roUp("web", 30*time.Second)}, rolloutOpts{})
		if !errors.Is(res.err, context.Canceled) || res.took > time.Second || len(w.calls()) != 1 {
			t.Fatalf("err=%v took=%s calls=%v", res.err, res.took, w.argvs())
		}
	})
	t.Run("gate wait", func(t *testing.T) {
		s, w := newRolloutTest(t, "", nil)
		s.cfg.Server.StartGate.DeployWait = rolloutDur(30 * time.Second)
		w.add("other", "db", "db1", time.Now(), roStarting)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		time.AfterFunc(150*time.Millisecond, cancel)
		res := runRolloutTest(ctx, s, []rolloutStep{roUp("api", 30*time.Second)}, rolloutOpts{})
		if !errors.Is(res.err, context.Canceled) || res.took > time.Second || len(w.calls()) != 0 {
			t.Fatalf("err=%v took=%s calls=%v", res.err, res.took, w.argvs())
		}
	})
}

// An up that leaves the service unchanged starts nothing, so there is nothing to wait for.
func TestRolloutUnchangedServiceDoesNotWait(t *testing.T) {
	s, w := newRolloutTest(t, "", nil)
	w.add("shop", "api", "api-old", time.Now().Add(-time.Hour), roHealthy)
	w.unchanged["shop/api"] = true
	res := runRolloutTest(roCtx(t), s, []rolloutStep{roUp("api", 5*time.Second)}, rolloutOpts{})
	if res.err != nil || len(res.problems) != 0 || len(w.calls()) != 1 {
		t.Fatalf("err=%v problems=%v calls=%v", res.err, res.problems, w.argvs())
	}
	if !res.has("  api: unchanged") || res.has("starting…") || res.took > time.Second {
		t.Fatalf("took %s:\n%s", res.took, res.output())
	}
}

// Only a container view taken after the step counts: a stale one would show the old container and
// nothing new. A view that stops updating is reported and the rollout goes on.
func TestRolloutNeedsAViewTakenAfterTheStep(t *testing.T) {
	s, w := newRolloutTest(t, "", nil)
	w.add("shop", "api", "api-old", time.Now().Add(-time.Hour), roHealthy)
	w.freeze()
	res := runRolloutTest(roCtx(t), s, []rolloutStep{roUp("api", 5*time.Second), roUp("web", 5*time.Second)}, rolloutOpts{})
	if res.err != nil || len(w.calls()) != 2 {
		t.Fatalf("err=%v calls=%v", res.err, w.argvs())
	}
	want := rolloutProblem{Service: "api", Reason: "couldn't check health: the container view isn't updating"}
	if len(res.problems) != 2 || res.problems[0] != want || res.problems[1].Service != "web" {
		t.Fatalf("problems = %v", res.problems)
	}
	if res.took > 2*time.Second {
		t.Fatalf("took %s", res.took)
	}
}

// How a started container settles or fails.
func TestRolloutSettleOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name             string
		b                roBehaviour
		notify, restarts bool
		deadline         time.Duration
		problem, line    string
	}{
		{"healthy", roHealthy, false, false, 2 * time.Second, "", "  api: healthy after"},
		{"exit 0 without a restart policy is done", roExited(0), false, false, 2 * time.Second, "", "  api: completed"},
		{"exit 0 with a restart policy is done too", roExited(0), false, true, 2 * time.Second, "", "  api: completed"},
		{"exit 1", roExited(1), false, false, 2 * time.Second, "exited (code 1)", ""},
		{"exit 1 with a restart policy may come back", roExited(1), false, true, 200 * time.Millisecond, "not running after 200ms", ""},
		{"restarting", roRestarting, false, false, 200 * time.Millisecond, "not running after 200ms", ""},
		{"unhealthy", roUnhealthy, false, false, 2 * time.Second, "unhealthy", ""},
		{"unhealthy with on_unhealthy notify", roUnhealthy, true, false, 2 * time.Second, "", "  api: unhealthy after"},
		{"still starting", roStarting, false, false, 200 * time.Millisecond, "still starting after 200ms", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, w := newRolloutTest(t, "", nil)
			w.on["shop/api"] = tc.b
			step := roUp("api", tc.deadline)
			step.Notify, step.Restarts = tc.notify, tc.restarts
			res := runRolloutTest(roCtx(t), s, []rolloutStep{step}, rolloutOpts{})
			if res.err != nil {
				t.Fatal(res.err)
			}
			switch {
			case tc.problem == "" && len(res.problems) != 0:
				t.Fatalf("problems = %v", res.problems)
			case tc.problem != "" && (len(res.problems) != 1 || res.problems[0].Reason != tc.problem):
				t.Fatalf("problems = %v, want %q", res.problems, tc.problem)
			}
			if tc.line != "" && !res.has(tc.line) {
				t.Fatalf("output lacks %q:\n%s", tc.line, res.output())
			}
			if tc.problem != "" && tc.deadline < time.Second && res.took < tc.deadline {
				t.Fatalf("gave up after %s, before the %s deadline", res.took, tc.deadline)
			}
		})
	}
}

// Without a healthcheck, a container has settled once the start gate stops counting it as starting
// (its settle grace, then its start-up CPU).
func TestRolloutWaitsForAServiceWithoutAHealthcheck(t *testing.T) {
	s, w := newRolloutTest(t, "", func(c *startgate.Config) { c.SettleGrace = 300 * time.Millisecond })
	w.on["shop/api"] = roNoCheck
	res := runRolloutTest(roCtx(t), s, []rolloutStep{roUp("api", 5*time.Second)}, rolloutOpts{})
	if res.err != nil || len(res.problems) != 0 || !res.has("  api: started") {
		t.Fatalf("err=%v problems=%v\n%s", res.err, res.problems, res.output())
	}
	if res.took < 300*time.Millisecond || res.took > 2*time.Second {
		t.Fatalf("took %s; want the gate's 300ms settle grace", res.took)
	}
}

// Without pacing (no start gate, or server.start_gate.enabled: false) the steps run back to back,
// each still recorded with the gate.
func TestRolloutWithoutPacing(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*Server)
	}{
		{"no start gate", func(s *Server) { s.startGate = nil }},
		{"start gate disabled", func(s *Server) { off := false; s.cfg.Server.StartGate.Enabled = &off }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, w := newRolloutTest(t, "", nil)
			tc.setup(s)
			w.on["shop/api"], w.on["shop/web"] = roStarting, roStarting
			w.add("other", "db", "db1", time.Now(), roStarting)
			res := runRolloutTest(roCtx(t), s, []rolloutStep{roUp("api", 5*time.Second), roUp("web", 5*time.Second)}, rolloutOpts{})
			if res.err != nil || len(res.problems) != 0 || len(w.calls()) != 2 {
				t.Fatalf("err=%v problems=%v calls=%v", res.err, res.problems, w.argvs())
			}
			if res.has("waiting") || res.has("starting…") || res.took > time.Second {
				t.Fatalf("took %s:\n%s", res.took, res.output())
			}
			if strings.Join(res.started, ",") != "api,web" {
				t.Fatalf("Started = %v", res.started)
			}
			if s.startGate != nil {
				if d := s.startGate.Admit(time.Now(), startgate.AdmitOpts{}); d.OK || !strings.HasPrefix(d.Blocker, "shop/") {
					t.Fatalf("the starts must still be recorded: %+v", d)
				}
			}
		})
	}
}

// A settle wait longer than the lease keeps renewing it.
func TestRolloutRenewsTheLeaseDuringALongWait(t *testing.T) {
	s, w := newRolloutTest(t, "", nil)
	rolloutRenewEvery = 50 * time.Millisecond
	w.on["shop/api"] = roStarting
	renews := 0
	res := runRolloutTest(roCtx(t), s, []rolloutStep{roUp("api", 400*time.Millisecond)}, rolloutOpts{Renew: func() { renews++ }})
	if res.err != nil || len(res.problems) != 1 {
		t.Fatalf("err=%v problems=%v", res.err, res.problems)
	}
	if renews < 4 {
		t.Fatalf("Renew called %d times over a 400ms wait renewing every 50ms", renews)
	}
}

// Without the write plane every step is reported, none run.
func TestRolloutWithoutARunner(t *testing.T) {
	s, _ := newRolloutTest(t, "", nil)
	s.runner = nil
	res := runRolloutTest(roCtx(t), s, []rolloutStep{roUp("api", time.Second), roUp("web", time.Second)}, rolloutOpts{})
	if res.err != nil || len(res.problems) != 2 || res.problems[1] != (rolloutProblem{Service: "web", Reason: "start failed: write plane unavailable"}) {
		t.Fatalf("err=%v problems=%v", res.err, res.problems)
	}
}

// A view that covers only part of the host's containers proves nothing by a service's absence.
func TestRolloutCheckTruncatedView(t *testing.T) {
	s, _ := newRolloutTest(t, "", nil)
	r := &rolloutRun{s: s, o: rolloutOpts{App: "shop"}}
	u := rolloutUnit{st: rolloutStep{Service: "api"}, label: "api"}
	snap := &monitor.Snapshot{At: time.Now(), DockerOK: true, Apps: []monitor.App{{Project: "shop"}}}
	if v := r.check(snap, u, time.Now()); v.done != "unchanged" {
		t.Fatalf("complete view without the service: %+v", v)
	}
	snap.Truncated = true
	if v := r.check(snap, u, time.Now()); v.done != "" || !strings.HasPrefix(v.problem, "couldn't check health") {
		t.Fatalf("truncated view without the service: %+v", v)
	}
}
