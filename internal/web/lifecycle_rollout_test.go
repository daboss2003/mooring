package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/selfheal"
	"github.com/daboss2003/mooring/internal/startgate"
)

// lcDocker puts a fake `docker` first on PATH. It logs each invocation's argv as one line, runs extra
// (shell) and exits 0; it returns the logged invocations.
func lcDocker(t *testing.T, extra string) func() []string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake docker")
	}
	dir := t.TempDir()
	logf := filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\necho \"$*\" >> '" + logf + "'\n" + extra + "exit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() []string {
		b, _ := os.ReadFile(logf)
		if s := strings.TrimSpace(string(b)); s != "" {
			return strings.Split(s, "\n")
		}
		return nil
	}
}

// lcFailOn is a lcDocker extra: invocations whose argv contains pattern exit 1.
func lcFailOn(pattern string) string {
	return "case \"$*\" in *'" + pattern + "'*) exit 1 ;; esac\n"
}

func lcID(c byte) string { return strings.Repeat(string(c), 64) }

var (
	lcStore  = lcID('1')
	lcAPI1   = lcID('a')
	lcAPI2   = lcID('b')
	lcWorker = lcID('c')
)

// lcDefYAML: api and worker depend on store, so dependency order differs from name order; report only
// runs on a schedule.
const lcDefYAML = `apiVersion: mooring/v1
kind: App
metadata: {slug: shop}
spec:
  compose:
    source: generated
    services:
      api:
        image: nginx:1.27
        depends_on: [store]
      store:
        image: postgres:16
      worker:
        image: busybox:1.36
        depends_on: [store]
      report:
        image: busybox:1.36
  scheduled_tasks:
    - {name: nightly, service: report, every: 24h}
`

// lcEnv is a server whose write plane runs the fake docker CLI, with operator holds and lcDefYAML as the
// app's definition; paced adds a start gate. It returns the app's working dir (with its compose file).
func lcEnv(t *testing.T, paced bool) (*testEnv, string) {
	t.Helper()
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), true, "")
	e.srv.selfHeal = selfheal.NewStore(e.srv.db)
	e.srv.defStore = definition.NewStore(e.srv.db, make([]byte, 32))
	// Bounds any settle wait a rollout makes on the fake containers.
	e.srv.cfg.Server.StartGate.ServiceSettle = config.Duration(2 * time.Second)
	if paced {
		e.srv.startGate = startgate.New(startgate.DefaultConfig(2))
	}
	d, err := definition.Parse([]byte(lcDefYAML))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.defStore.SaveCanonical(context.Background(), d, "deploy", ""); err != nil {
		t.Fatal(err)
	}
	wd := t.TempDir()
	compose := "services:\n  api:\n    image: nginx:1.27\n  store:\n    image: postgres:16\n  worker:\n    image: busybox:1.36\n"
	if err := os.WriteFile(filepath.Join(wd, "docker-compose.yml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	return e, wd
}

// lcSnapshots serves the app with svcs until the fake docker CLI has run, then with every container
// (plus extra) running, healthy and just started — so a rollout that waits for its steps to settle sees
// them settle at once.
func lcSnapshots(calls func() []string, wd string, svcs []monitor.ServiceStatus, extra ...monitor.ServiceStatus) func() *monitor.Snapshot {
	return func() *monitor.Snapshot {
		app := monitor.App{Project: "shop", WorkingDir: wd, ConfigFiles: []string{filepath.Join(wd, "docker-compose.yml")}}
		if len(calls()) == 0 {
			app.Services = append(app.Services, svcs...)
		} else {
			now := time.Now()
			for _, c := range append(append([]monitor.ServiceStatus(nil), svcs...), extra...) {
				c.State, c.Health, c.StartedAt, c.Inspected = "running", "healthy", now, true
				app.Services = append(app.Services, c)
			}
		}
		return &monitor.Snapshot{At: time.Now(), DockerOK: true, Apps: []monitor.App{app}}
	}
}

// lcDo runs one lifecycle action on the app "shop" and returns the streamed output.
func lcDo(e *testEnv, service, action, query string) string {
	path := "/apps/shop/" + action
	if service != "" {
		path = "/apps/shop/services/" + service + "/" + action
	}
	if query != "" {
		path += "?" + query
	}
	w := httptest.NewRecorder()
	e.srv.runLifecycle(w, httptest.NewRequest(http.MethodPost, path, nil), "shop", service, action)
	return w.Body.String()
}

// lcCompose is the fake docker's argv for a compose call on the app "shop" run from dir.
func lcCompose(dir, action string) string {
	return "compose -p shop --project-directory " + dir + " -f " + filepath.Join(dir, "docker-compose.yml") + " " + action
}

func lcLastDeployOutcome(t *testing.T, e *testEnv) string {
	t.Helper()
	var outcome string
	if err := e.srv.db.QueryRow(`SELECT outcome FROM deploys ORDER BY id DESC LIMIT 1`).Scan(&outcome); err != nil {
		t.Fatal(err)
	}
	return outcome
}

func lcHold(t *testing.T, e *testEnv, services ...string) {
	t.Helper()
	for _, svc := range services {
		if err := e.srv.selfHeal.SetHeld(context.Background(), selfheal.Key{App: "shop", Service: svc}, "operator", time.Now().Unix()); err != nil {
			t.Fatal(err)
		}
	}
}

func lcHeld(t *testing.T, e *testEnv) map[selfheal.Key]bool {
	t.Helper()
	held, err := e.srv.selfHeal.ActiveHeld()
	if err != nil {
		t.Fatal(err)
	}
	return held
}

// A paced app restart restarts every copy by id, one at a time, dependencies first — never one
// `compose restart` of everything.
func TestPacedAppRestartGoesCopyByCopyInDependencyOrder(t *testing.T) {
	calls := lcDocker(t, "")
	e, wd := lcEnv(t, true)
	e.srv.snapFn = lcSnapshots(calls, wd, []monitor.ServiceStatus{
		{Service: "worker", ContainerID: lcWorker, State: "running"},
		{Service: "api", ContainerID: lcAPI1, State: "running"},
		{Service: "api", ContainerID: lcAPI2, State: "exited"},
		{Service: "store", ContainerID: lcStore, State: "running"},
	})
	out := lcDo(e, "", "restart", "")
	want := []string{"restart " + lcStore, "restart " + lcAPI1, "restart " + lcAPI2, "restart " + lcWorker}
	if got := calls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("docker calls = %q\nwant %q\n%s", got, want, out)
	}
	if !strings.Contains(out, "[done") || strings.Contains(out, "[failed") {
		t.Fatalf("output:\n%s", out)
	}
	if got := lcLastDeployOutcome(t, e); got != "ok" {
		t.Fatalf("deploy outcome = %q, want ok", got)
	}
}

// "All at once" (now=1), or no enabled start gate, keeps the single compose call.
func TestAppRestartAllAtOnceIsOneComposeCall(t *testing.T) {
	off := false
	for _, tc := range []struct {
		name    string
		paced   bool
		enabled *bool
		query   string
	}{
		{"now=1", true, nil, "now=1"},
		{"no start gate", false, nil, ""},
		{"start gate disabled", true, &off, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := lcDocker(t, "")
			e, wd := lcEnv(t, tc.paced)
			e.srv.cfg.Server.StartGate.Enabled = tc.enabled
			e.srv.snapFn = lcSnapshots(calls, wd, []monitor.ServiceStatus{
				{Service: "store", ContainerID: lcStore, State: "running"},
				{Service: "api", ContainerID: lcAPI1, State: "exited"},
			})
			out := lcDo(e, "", "restart", tc.query)
			if got, want := calls(), []string{lcCompose(wd, "restart")}; !reflect.DeepEqual(got, want) {
				t.Fatalf("docker calls = %q\nwant %q\n%s", got, want, out)
			}
		})
	}
}

// A service redeploy never starts or recreates the services it depends on — paced or all at once.
func TestServiceRedeployUsesNoDeps(t *testing.T) {
	for _, query := range []string{"", "now=1"} {
		t.Run("query="+query, func(t *testing.T) {
			calls := lcDocker(t, "")
			e, wd := lcEnv(t, true)
			e.srv.snapFn = lcSnapshots(calls, wd, []monitor.ServiceStatus{
				{Service: "store", ContainerID: lcStore, State: "exited"},
				{Service: "api", ContainerID: lcAPI1, State: "running"},
			})
			out := lcDo(e, "api", "redeploy", query)
			if got, want := calls(), []string{lcCompose(wd, "up -d --no-deps --force-recreate -- api")}; !reflect.DeepEqual(got, want) {
				t.Fatalf("docker calls = %q\nwant %q\n%s", got, want, out)
			}
		})
	}
}

// A paced app redeploy recreates the services one at a time, dependencies first.
func TestPacedAppRedeployRecreatesOneServiceAtATime(t *testing.T) {
	calls := lcDocker(t, "")
	e, wd := lcEnv(t, true)
	e.srv.snapFn = lcSnapshots(calls, wd, []monitor.ServiceStatus{
		{Service: "api", ContainerID: lcAPI1, State: "running"},
		{Service: "store", ContainerID: lcStore, State: "running"},
		{Service: "worker", ContainerID: lcWorker, State: "running"},
	})
	out := lcDo(e, "", "redeploy", "")
	var want []string
	for _, svc := range []string{"store", "api", "worker"} {
		want = append(want, lcCompose(wd, "up -d --no-deps --force-recreate -- "+svc))
	}
	if got := calls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("docker calls = %q\nwant %q\n%s", got, want, out)
	}
}

// A paced start leaves running services alone, starts only the stopped copies (by id), brings up a
// service with no container at all, and never names a scheduled service.
func TestPacedAppStartStartsOnlyWhatIsDown(t *testing.T) {
	calls := lcDocker(t, "")
	e, wd := lcEnv(t, true)
	e.srv.snapFn = lcSnapshots(calls, wd, []monitor.ServiceStatus{
		{Service: "store", ContainerID: lcStore, State: "running"},
		{Service: "api", ContainerID: lcAPI1, State: "running"},
		{Service: "api", ContainerID: lcAPI2, State: "exited"},
	}, monitor.ServiceStatus{Service: "worker", ContainerID: lcWorker})
	out := lcDo(e, "", "start", "")
	want := []string{"start " + lcAPI2, lcCompose(wd, "up -d --no-deps -- worker")}
	if got := calls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("docker calls = %q\nwant %q\n%s", got, want, out)
	}
	if !strings.Contains(out, "store: already running") || strings.Contains(out, "report") {
		t.Fatalf("output:\n%s", out)
	}
}

// Each service's hold is released as soon as its own start succeeded. A service whose start failed
// stays held, the rest of the rollout still runs, and the action ends "with problems".
func TestPacedAppStartReleasesHoldsPerStep(t *testing.T) {
	calls := lcDocker(t, lcFailOn(lcAPI2))
	e, wd := lcEnv(t, true)
	lcHold(t, e, "store", "api", "worker")
	e.srv.snapFn = lcSnapshots(calls, wd, []monitor.ServiceStatus{
		{Service: "store", ContainerID: lcStore, State: "exited"},
		{Service: "api", ContainerID: lcAPI2, State: "exited"},
		{Service: "worker", ContainerID: lcWorker, State: "exited"},
	})
	out := lcDo(e, "", "start", "")
	if got, want := calls(), []string{"start " + lcStore, "start " + lcAPI2, "start " + lcWorker}; !reflect.DeepEqual(got, want) {
		t.Fatalf("docker calls = %q\nwant %q (the rollout carries on past a failed start)\n%s", got, want, out)
	}
	if got, want := lcHeld(t, e), map[selfheal.Key]bool{{App: "shop", Service: "api"}: true}; !reflect.DeepEqual(got, want) {
		t.Fatalf("holds = %v, want only the service whose start failed still held", got)
	}
	if !strings.Contains(out, "[done — with problems]") || !strings.Contains(out, "⚠ api: ") {
		t.Fatalf("output:\n%s", out)
	}
	if got := lcLastDeployOutcome(t, e); got != "problems" {
		t.Fatalf("deploy outcome = %q, want problems", got)
	}
}

// When nothing starts, the action fails as the single compose call would: the hold stays.
func TestPacedServiceStartFailsWhenNothingStarts(t *testing.T) {
	calls := lcDocker(t, lcFailOn("start"))
	e, wd := lcEnv(t, true)
	lcHold(t, e, "api")
	e.srv.snapFn = lcSnapshots(calls, wd, []monitor.ServiceStatus{
		{Service: "api", ContainerID: lcAPI1, State: "exited"},
	})
	out := lcDo(e, "api", "start", "")
	if len(calls()) != 1 || !strings.Contains(out, "[failed: api: ") {
		t.Fatalf("calls %q, output:\n%s", calls(), out)
	}
	if !lcHeld(t, e)[selfheal.Key{App: "shop", Service: "api"}] {
		t.Fatal("a service that failed to start must stay held")
	}
	if got := lcLastDeployOutcome(t, e); got != "error" {
		t.Fatalf("deploy outcome = %q, want error", got)
	}
}

// A per-copy restart goes through the rollout when paced (a failed docker call is then reported as a
// problem of the service); "all at once" and no start gate keep the direct `docker restart`.
func TestPerCopyRestartGoesThroughTheRollout(t *testing.T) {
	for _, tc := range []struct {
		name    string
		paced   bool
		query   string
		rollout bool
	}{
		{"paced", true, "", true},
		{"now=1", true, "&now=1", false},
		{"no start gate", false, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := lcDocker(t, lcFailOn(lcAPI2))
			e, wd := lcEnv(t, tc.paced)
			e.srv.snapFn = lcSnapshots(calls, wd, []monitor.ServiceStatus{
				{Service: "api", ContainerID: lcAPI1, State: "running"},
				{Service: "api", ContainerID: lcAPI2, State: "running"},
			})
			out := lcDo(e, "api", "restart", "copy="+lcAPI2+tc.query)
			if got, want := calls(), []string{"restart " + lcAPI2}; !reflect.DeepEqual(got, want) {
				t.Fatalf("docker calls = %q\nwant %q\n%s", got, want, out)
			}
			if got := strings.Contains(out, "[failed: api: "); got != tc.rollout {
				t.Fatalf("failure reported by the rollout = %v, want %v:\n%s", got, tc.rollout, out)
			}
		})
	}
}

// A paced per-copy start starts just that copy and ends clean.
func TestPacedPerCopyStart(t *testing.T) {
	calls := lcDocker(t, "")
	e, wd := lcEnv(t, true)
	e.srv.snapFn = lcSnapshots(calls, wd, []monitor.ServiceStatus{
		{Service: "api", ContainerID: lcAPI1, State: "running"},
		{Service: "api", ContainerID: lcAPI2, State: "exited"},
	})
	out := lcDo(e, "api", "start", "copy="+lcAPI2)
	if got, want := calls(), []string{"start " + lcAPI2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("docker calls = %q\nwant %q\n%s", got, want, out)
	}
	if !strings.Contains(out, "[done") || strings.Contains(out, "[failed") {
		t.Fatalf("output:\n%s", out)
	}
}

// Abuse: a copy id that isn't a hex container id never reaches `docker restart|start` (which has no
// `--` before its ids), even if the snapshot lists it.
func TestCopyActionRefusesAMalformedID(t *testing.T) {
	calls := lcDocker(t, "")
	for _, paced := range []bool{true, false} {
		e, wd := lcEnv(t, paced)
		e.srv.snapFn = lcSnapshots(calls, wd, []monitor.ServiceStatus{
			{Service: "api", ContainerID: lcAPI1, State: "running"},
			{Service: "api", ContainerID: "--time=0", State: "running"},
		})
		w := httptest.NewRecorder()
		e.srv.runLifecycle(w, httptest.NewRequest(http.MethodPost, "/apps/shop/services/api/restart?copy=--time%3D0", nil), "shop", "api", "restart")
		if w.Code != http.StatusBadRequest || len(calls()) != 0 {
			t.Fatalf("paced=%v: status %d, docker calls %q", paced, w.Code, calls())
		}
	}
}

// The lifecycle buttons and the deploy button carry an "all at once" checkbox in their .lc-group
// (app.js appends now=1 when it is ticked).
func TestLifecycleButtonsOfferAllAtOnce(t *testing.T) {
	calls := lcDocker(t, "")
	e, wd := lcEnv(t, true)
	e.srv.snapFn = lcSnapshots(calls, wd, []monitor.ServiceStatus{
		{Service: "api", ContainerID: lcAPI1, Name: "shop-api-1", State: "running"},
		{Service: "api", ContainerID: lcAPI2, Name: "shop-api-2", State: "running"},
	})
	configureRepo(t, e, "shop", strings.Repeat("f", 40)) // an update is staged: "Deploy update" shows
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	page := readBody(e.req(t, "GET", "/apps/shop", "127.0.0.1:1", nil, cookies, nil))
	if n := strings.Count(page, `<input type="checkbox" class="lc-now">`); n != 2 || strings.Count(page, "lc-group") != 2 || !strings.Contains(page, "Deploy update") {
		t.Fatalf("app page: want the lifecycle and deploy groups each with an all-at-once box (%d boxes)", n)
	}
	page = readBody(e.req(t, "GET", "/apps/shop/services/api", "127.0.0.1:1", nil, cookies, nil))
	if !strings.Contains(page, `<input type="checkbox" class="lc-now">`) || !strings.Contains(page, "lc-group") || !strings.Contains(page, "Restart this copy") {
		t.Fatal("service page: want the action row in an lc-group with an all-at-once box")
	}
}

// lcCertFixture: resolver depends on broker and both bind a cert. Returns a run dir whose recorded
// digests are old, and the digests after the leaves renewed.
func lcCertFixture(t *testing.T, e *testEnv) (rd string, def *definition.Definition, old, cur map[string]string) {
	t.Helper()
	def, err := definition.Parse([]byte(`apiVersion: mooring/v1
kind: App
metadata: {slug: shop}
spec:
  compose:
    source: generated
    services:
      resolver:
        image: coredns/coredns:1.11.1
        depends_on: [broker]
        cert_bindings: [{hostname: dns.example.com, mount: /etc/certs}]
      broker:
        image: emqx/emqx:5.8.3
        cert_bindings: [{hostname: mqtt.example.com, mount: /etc/certs}]
`))
	if err != nil {
		t.Fatal(err)
	}
	rd = t.TempDir()
	old = map[string]string{"broker": "old-broker", "resolver": "old-resolver"}
	cur = map[string]string{"broker": "new-broker", "resolver": "new-resolver"}
	if err := e.srv.writeDigestState(rd, old); err != nil {
		t.Fatal(err)
	}
	return rd, def, old, cur
}

func lcRenewJob(rd string) dockerexec.Job {
	return dockerexec.Job{Project: "shop", Dir: rd, ConfigFiles: []string{filepath.Join(rd, "docker-compose.yml")}}
}

// lcCertSnapshots shows the renewal's services running (and, once recreated, just started and healthy),
// so a rollout never waits on a read plane that looks down.
func lcCertSnapshots(e *testEnv, calls func() []string, rd string) {
	e.srv.snapFn = lcSnapshots(calls, rd, []monitor.ServiceStatus{
		{Service: "broker", ContainerID: lcID('e'), State: "running", Health: "healthy"},
		{Service: "resolver", ContainerID: lcID('f'), State: "running", Health: "healthy"},
	})
}

func lcWaitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// A paced renewal recreates the changed services one at a time, dependencies first, records the new
// digests and leaves the git-deploy gate free.
func TestCertRenewRecreatesOneServiceAtATime(t *testing.T) {
	calls := lcDocker(t, "")
	e, _ := lcEnv(t, true)
	rd, def, old, cur := lcCertFixture(t, e)
	lcCertSnapshots(e, calls, rd)
	e.srv.recreateRenewed(context.Background(), "shop", rd, def, lcRenewJob(rd), []string{"resolver", "broker"}, old, cur)
	want := []string{
		lcCompose(rd, "up -d --no-deps --no-build --force-recreate -- broker"),
		lcCompose(rd, "up -d --no-deps --no-build --force-recreate -- resolver"),
	}
	if got := calls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("docker calls = %q\nwant %q", got, want)
	}
	if got := readDigestState(rd); !reflect.DeepEqual(got, cur) {
		t.Fatalf("digests = %v, want %v", got, cur)
	}
	if !e.srv.gitDeploy.TryAcquire() {
		t.Fatal("the git-deploy gate must be free after the renewal")
	}
	e.srv.gitDeploy.Release()
}

// The git-deploy gate is held only around each docker call: a deploy that asks for it while the first
// service is being recreated gets it before the second, and the renewal then stops without recording
// digests (the deploy recreates what changed itself).
func TestCertRenewFreesTheGitGateBetweenSteps(t *testing.T) {
	goFile := filepath.Join(t.TempDir(), "go")
	// The broker's recreate runs until the test lets it finish (at most 10s).
	calls := lcDocker(t, "case \"$*\" in *'-- broker'*) i=0; while [ ! -f '"+goFile+"' ] && [ $i -lt 500 ]; do sleep 0.02; i=$((i+1)); done ;; esac\n")
	e, _ := lcEnv(t, true)
	rd, def, old, cur := lcCertFixture(t, e)
	lcCertSnapshots(e, calls, rd)
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.srv.recreateRenewed(context.Background(), "shop", rd, def, lcRenewJob(rd), []string{"broker", "resolver"}, old, cur)
	}()
	lcWaitFor(t, "the broker's recreate", func() bool { return len(calls()) == 1 })
	if e.srv.gitDeploy.TryAcquire() {
		e.srv.gitDeploy.Release()
		t.Fatal("the gate must be held while a service is being recreated")
	}
	acquired := make(chan error, 1)
	go func() { acquired <- e.srv.gitDeploy.Acquire(context.Background()) }() // a deploy waiting for the gate
	time.Sleep(100 * time.Millisecond)                                        // let it queue behind the running step
	if err := os.WriteFile(goFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-acquired:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the waiting deploy never got the gate")
	}
	defer e.srv.gitDeploy.Release()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the renewal did not stop")
	}
	if got := calls(); len(got) != 1 {
		t.Fatalf("the renewal must stop once a git operation holds the gate: %q", got)
	}
	// The service recreated before the stop keeps its new digest (the next tick doesn't recreate it
	// again); the rest keep the old ones and are retried.
	want := map[string]string{}
	for k, v := range old {
		want[k] = v
	}
	want["broker"] = "new-broker"
	if got := readDigestState(rd); !reflect.DeepEqual(got, want) {
		t.Fatalf("digests = %v, want %v", got, want)
	}
}

// A git deploy that finished between two steps (it recorded new digests) stops the renewal: the rest
// would be recreated with an env file rendered for the commit deployed before it.
func TestCertRenewStopsAfterADeployRecordedDigests(t *testing.T) {
	e, _ := lcEnv(t, true)
	rd, def, old, cur := lcCertFixture(t, e)
	state := filepath.Join(rd, ".mooring", "state", "digests")
	calls := lcDocker(t, "case \"$*\" in *'-- broker'*) echo 'broker by-deploy' > '"+state+"'; echo 'resolver by-deploy' >> '"+state+"' ;; esac\n")
	lcCertSnapshots(e, calls, rd)
	e.srv.recreateRenewed(context.Background(), "shop", rd, def, lcRenewJob(rd), []string{"broker", "resolver"}, old, cur)
	if got := calls(); len(got) != 1 {
		t.Fatalf("docker calls = %q, want only the broker's", got)
	}
	if got, want := readDigestState(rd), map[string]string{"broker": "by-deploy", "resolver": "by-deploy"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("digests = %v, want the deploy's kept", got)
	}
}

// A service whose recreate failed keeps its old digest, so the next tick retries only it.
func TestCertRenewRetriesOnlyTheServiceThatFailed(t *testing.T) {
	calls := lcDocker(t, lcFailOn("-- resolver"))
	e, _ := lcEnv(t, true)
	rd, def, old, cur := lcCertFixture(t, e)
	lcCertSnapshots(e, calls, rd)
	e.srv.recreateRenewed(context.Background(), "shop", rd, def, lcRenewJob(rd), []string{"broker", "resolver"}, old, cur)
	if got := calls(); len(got) != 2 {
		t.Fatalf("docker calls = %q, want both services tried", got)
	}
	if got, want := readDigestState(rd), map[string]string{"broker": "new-broker", "resolver": "old-resolver"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("digests = %v, want %v", got, want)
	}
}

// End to end from the watcher: a renewed leaf is recreated through the paced path when starts are
// paced, and with the single unpaced call otherwise.
func TestCertRenewWatcherPacesTheRecreate(t *testing.T) {
	for _, paced := range []bool{true, false} {
		t.Run(fmt.Sprint("paced=", paced), func(t *testing.T) {
			calls := lcDocker(t, "")
			e, _ := lcEnv(t, paced)
			ctx := context.Background()
			yaml := "apiVersion: mooring/v1\nkind: App\nmetadata: {slug: shop}\nspec:\n  compose:\n    source: generated\n    services:\n" +
				"      broker:\n        image: emqx/emqx:5.8.3\n        cert_bindings:\n          - {hostname: mqtt.example.com, mount: /etc/certs}\n"
			sha := gitObjStoreFixture(t, e.srv.gitObjectDir("shop"), yaml)
			configureRepo(t, e, "shop", sha)
			e.srv.gitStore.SetDeployed(ctx, "shop", sha)
			cfg, _, err := e.srv.gitStore.Get("shop")
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			leaf := filepath.Join(root, "acme-v02.api.letsencrypt.org-directory", "mqtt.example.com")
			if err := os.MkdirAll(leaf, 0o755); err != nil {
				t.Fatal(err)
			}
			_ = os.WriteFile(filepath.Join(leaf, "mqtt.example.com.crt"), []byte("RENEWED"), 0o600)
			_ = os.WriteFile(filepath.Join(leaf, "mqtt.example.com.key"), []byte("KEY"), 0o600)
			e.srv.caddyCertRoot = root
			rd := e.srv.appRunDir("shop")
			if err := os.MkdirAll(rd, 0o700); err != nil {
				t.Fatal(err)
			}
			lcCertSnapshots(e, calls, rd)
			if err := e.srv.writeDigestState(rd, map[string]string{"broker": "before-renewal"}); err != nil {
				t.Fatal(err)
			}
			def, err := definition.Parse([]byte(yaml))
			if err != nil {
				t.Fatal(err)
			}
			e.srv.refreshCertsForApp(ctx, cfg, def)
			want := "up -d --no-build --force-recreate -- broker"
			if paced {
				want = "up -d --no-deps --no-build --force-recreate -- broker"
			}
			if got := calls(); len(got) != 1 || !strings.HasSuffix(got[0], " "+want) {
				t.Fatalf("docker calls = %q, want one ending in %q", got, want)
			}
			if readDigestState(rd)["broker"] == "before-renewal" {
				t.Fatal("the renewed leaf's digest must be recorded")
			}
		})
	}
}
