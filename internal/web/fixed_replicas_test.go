package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/scale"
	"github.com/daboss2003/mooring/internal/selfheal"
)

// enabledTestPolicy is a valid, enabled autoscaling policy.
func enabledTestPolicy() scale.PolicyRow {
	return scale.PolicyRow{Enabled: true, PerReplicaMem: 64 << 20, PerReplicaCPU: 100, Policy: scale.Policy{
		Min: 1, Max: 3, UpCPUPct: 80, DownCPUPct: 40, UpMemPct: 80, DownMemPct: 40, BreachForSecs: 60, CooldownUpSecs: 60, CooldownDownSecs: 300}}
}

// A policy left enabled for a service that now declares `replicas` is disabled (kept, not deleted) when
// the definition is applied, so the autoscaler can't fight compose's `scale:`. A dashboard-managed policy
// of a service without `replicas` is left alone, and spec.scaling is still applied.
func TestApplyScalingDisablesALeftoverPolicyOfAFixedService(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.scaling = scale.NewStore(e.srv.db)
	ctx := context.Background()
	for _, svc := range []string{"web", "worker"} {
		if err := e.srv.scaling.SavePolicy(ctx, scale.Key{App: "shop", Service: svc}, enabledTestPolicy()); err != nil {
			t.Fatal(err)
		}
	}
	def, err := definition.Parse([]byte(`apiVersion: mooring/v1
kind: App
metadata: {slug: shop}
spec:
  compose:
    source: generated
    services:
      web:
        image: nginx:1.27
        replicas: 3
      worker:
        image: busybox:1.36
      api:
        image: nginx:1.27
  scaling:
    - {service: api, enabled: true, min: 1, max: 2, per_replica_mem_mib: 64, per_replica_cpu_milli: 100}
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.applyScaling(ctx, "shop", def); err != nil {
		t.Fatal(err)
	}
	web, ok, err := e.srv.scaling.PolicyFor(scale.Key{App: "shop", Service: "web"})
	if err != nil || !ok || web.Enabled || web.Max != 3 {
		t.Fatalf("web's policy must be kept but disabled: %+v ok=%v err=%v", web, ok, err)
	}
	enabled, err := e.srv.scaling.EnabledPolicies()
	if err != nil {
		t.Fatal(err)
	}
	if _, on := enabled[scale.Key{App: "shop", Service: "worker"}]; !on {
		t.Fatal("a service without replicas keeps its dashboard policy")
	}
	if _, on := enabled[scale.Key{App: "shop", Service: "api"}]; !on {
		t.Fatal("spec.scaling must still be applied")
	}
	if _, on := enabled[scale.Key{App: "shop", Service: "web"}]; on {
		t.Fatal("the scaler must not step a service with a fixed count")
	}
}

// fixedYAML: api runs a fixed two copies; store is single.
const fixedYAML = `apiVersion: mooring/v1
kind: App
metadata: {slug: shop}
spec:
  compose:
    source: generated
    services:
      api:
        image: nginx:1.27
        replicas: 2
        depends_on: [store]
      store:
        image: postgres:16
`

// fixedEnv is lcEnv with fixedYAML as the deployed definition.
func fixedEnv(t *testing.T) (*testEnv, string) {
	t.Helper()
	e, wd := lcEnv(t, false)
	d, err := definition.Parse([]byte(fixedYAML))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.defStore.SaveCanonical(context.Background(), d, "deploy", ""); err != nil {
		t.Fatal(err)
	}
	e.srv.shInfo = nil
	return e, wd
}

// The supervisor learns a service's fixed count from the deployed definition.
func TestSelfHealServicesCarriesTheFixedCount(t *testing.T) {
	e, _ := fixedEnv(t)
	info, ok := e.srv.SelfHealServices("shop")
	if !ok || info["api"].Replicas != 2 || info["store"].Replicas != 0 {
		t.Fatalf("info = %+v ok=%v", info, ok)
	}
}

// A restore runs `up --no-recreate --scale api=N` scoped to the service, which starts the missing copy and
// leaves the other copies alone; a replacement first removes exactly the sick copies.
func TestRemediateRestoresAFixedCount(t *testing.T) {
	calls := lcDocker(t, "")
	e, wd := fixedEnv(t)
	app := monitor.App{Project: "shop", WorkingDir: wd, ConfigFiles: []string{wd + "/docker-compose.yml"}, Services: []monitor.ServiceStatus{
		{Service: "api", ContainerID: lcAPI1, State: "running", Health: "healthy"},
	}}
	ctx := context.Background()
	if err := e.srv.Remediate(ctx, app, "api", selfheal.RungRestore, selfheal.Target{Restore: true}); err != nil {
		t.Fatal(err)
	}
	got := calls()
	if len(got) != 1 || !strings.Contains(got[0], " up -d --no-deps --no-build --no-recreate --scale api=2 -- api") {
		t.Fatalf("restore argv = %q, want one scoped `up --no-recreate --scale api=2 -- api`", got)
	}
	app.Services = append(app.Services, monitor.ServiceStatus{Service: "api", ContainerID: lcAPI2, State: "exited", ExitCode: 1})
	if err := e.srv.Remediate(ctx, app, "api", selfheal.RungRecreate, selfheal.Target{Remove: []string{lcAPI2}, Restore: true}); err != nil {
		t.Fatal(err)
	}
	got = calls()[1:]
	if len(got) != 2 || got[0] != "rm -f "+lcAPI2 || !strings.Contains(got[1], " up -d --no-deps --no-build --no-recreate --scale api=2 -- api") ||
		strings.Contains(got[1], "--force-recreate") {
		t.Fatalf("replacement argv = %q, want the sick copy removed, then `up --no-recreate --scale api=2 -- api`", got)
	}
}

// saveDef stores yaml as the app's deployed definition.
func saveDef(t *testing.T, e *testEnv, yaml string) {
	t.Helper()
	d, err := definition.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.defStore.SaveCanonical(context.Background(), d, "deploy", ""); err != nil {
		t.Fatal(err)
	}
}

// A restore adds ONE copy: `--scale` is one more than the copies left (after the removals), capped at the
// count the deployed definition declares — never the run dir's compose `scale:`, which a failed deploy may
// have left at another value.
func TestRemediateRestoresOneCopyPerStep(t *testing.T) {
	lcAPI3 := lcID('d')
	for _, tc := range []struct {
		name   string
		copies []string
		remove []string
		want   []string
	}{
		{"no copy", nil, nil, []string{"up -d --no-deps --no-build --no-recreate --scale api=1 -- api"}},
		{"one of three", []string{lcAPI1}, nil, []string{"up -d --no-deps --no-build --no-recreate --scale api=2 -- api"}},
		{"two of three", []string{lcAPI1, lcAPI2}, nil, []string{"up -d --no-deps --no-build --no-recreate --scale api=3 -- api"}},
		{"replace two sick of three", []string{lcAPI1, lcAPI2, lcAPI3}, []string{lcAPI2, lcAPI3},
			[]string{"rm -f " + lcAPI2 + " " + lcAPI3, "up -d --no-deps --no-build --no-recreate --scale api=2 -- api"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := lcDocker(t, "")
			e, wd := fixedEnv(t)
			saveDef(t, e, strings.Replace(fixedYAML, "replicas: 2", "replicas: 3", 1))
			// The run dir's compose (from a deploy that didn't finish) says 5.
			if err := os.WriteFile(filepath.Join(wd, "docker-compose.yml"), []byte("services:\n  api:\n    image: nginx:1.27\n    scale: 5\n  store:\n    image: postgres:16\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			app := monitor.App{Project: "shop", WorkingDir: wd, ConfigFiles: []string{wd + "/docker-compose.yml"}}
			for _, id := range tc.copies {
				app.Services = append(app.Services, monitor.ServiceStatus{Service: "api", ContainerID: id, State: "running", Health: "healthy"})
			}
			app.Services = append(app.Services, monitor.ServiceStatus{Service: "store", ContainerID: lcStore, State: "running"})
			if err := e.srv.Remediate(context.Background(), app, "api", selfheal.RungRestore, selfheal.Target{Restore: true, Remove: tc.remove}); err != nil {
				t.Fatal(err)
			}
			got := calls()
			if len(got) != len(tc.want) {
				t.Fatalf("calls = %q, want %q", got, tc.want)
			}
			for i := range got {
				if !strings.HasSuffix(got[i], tc.want[i]) {
					t.Fatalf("call %d = %q, want it to end with %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// A restore of a service that already runs its count (the definition lowered it since the supervisor read
// it) is refused before any docker call, as ErrNothingMissing. A replacement whose removals leave the count
// it declares removes the sick copies and starts nothing.
func TestRemediateRefusesARestoreWhenNothingIsMissing(t *testing.T) {
	calls := lcDocker(t, "")
	e, wd := fixedEnv(t) // api: replicas 2
	lcAPI3 := lcID('d')
	app := monitor.App{Project: "shop", WorkingDir: wd, ConfigFiles: []string{wd + "/docker-compose.yml"}, Services: []monitor.ServiceStatus{
		{Service: "api", ContainerID: lcAPI1, State: "running", Health: "healthy"},
		{Service: "api", ContainerID: lcAPI2, State: "running", Health: "healthy"},
	}}
	ctx := context.Background()
	if err := e.srv.Remediate(ctx, app, "api", selfheal.RungRestore, selfheal.Target{Restore: true}); !errors.Is(err, selfheal.ErrNothingMissing) {
		t.Fatalf("want ErrNothingMissing, got %v", err)
	}
	if len(calls()) != 0 {
		t.Fatalf("no docker call may run: %v", calls())
	}
	app.Services = append(app.Services, monitor.ServiceStatus{Service: "api", ContainerID: lcAPI3, State: "exited", ExitCode: 1})
	if err := e.srv.Remediate(ctx, app, "api", selfheal.RungRecreate, selfheal.Target{Remove: []string{lcAPI3}, Restore: true}); err != nil {
		t.Fatal(err)
	}
	if got := calls(); len(got) != 1 || got[0] != "rm -f "+lcAPI3 {
		t.Fatalf("calls = %q, want only the sick copy removed", got)
	}
}

// Saving a definition drops the cached self-healing facts, so the supervisor sees a changed `replicas` at
// once rather than after the cache's 30 seconds.
func TestApplyDefinitionRefreshesSelfHealFacts(t *testing.T) {
	e, _ := fixedEnv(t)
	if info, ok := e.srv.SelfHealServices("shop"); !ok || info["api"].Replicas != 2 {
		t.Fatalf("info = %+v ok=%v", info, ok)
	}
	d, err := definition.Parse([]byte(strings.Replace(fixedYAML, "replicas: 2", "replicas: 3", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.applyDefinition(context.Background(), "shop", d, "git deploy: test", ""); err != nil {
		t.Fatal(err)
	}
	if info, ok := e.srv.SelfHealServices("shop"); !ok || info["api"].Replicas != 3 {
		t.Fatalf("after the save: info = %+v ok=%v, want api's 3 copies", info, ok)
	}
}

// fixedStopYAML: api runs a fixed two copies, store is single, report only runs on a schedule.
const fixedStopYAML = `apiVersion: mooring/v1
kind: App
metadata: {slug: shop}
spec:
  compose:
    source: generated
    services:
      api:
        image: nginx:1.27
        replicas: 2
        depends_on: [store]
      store:
        image: postgres:16
      report:
        image: busybox:1.36
  scheduled_tasks:
    - {name: nightly, service: report, every: 24h}
`

// Stopping the whole app holds every long-running service of its deployed definition — also one that has
// no container (a fixed count self-healing gave up on), which would otherwise be started again with the
// next sibling. Starting the app releases every hold, paced or all at once.
func TestAppStopHoldsEveryDeclaredService(t *testing.T) {
	for _, paced := range []bool{false, true} {
		t.Run(fmt.Sprintf("paced=%v", paced), func(t *testing.T) {
			calls := lcDocker(t, "")
			e, wd := lcEnv(t, paced)
			saveDef(t, e, fixedStopYAML)
			e.srv.snapFn = lcSnapshots(calls, wd, []monitor.ServiceStatus{{Service: "store", ContainerID: lcStore, State: "running"}},
				monitor.ServiceStatus{Service: "api", ContainerID: lcAPI1}, monitor.ServiceStatus{Service: "api", ContainerID: lcAPI2})
			out := lcDo(e, "", "stop", "")
			held := lcHeld(t, e)
			want := map[selfheal.Key]bool{{App: "shop", Service: "api"}: true, {App: "shop", Service: "store"}: true}
			if len(held) != len(want) || !held[selfheal.Key{App: "shop", Service: "api"}] || !held[selfheal.Key{App: "shop", Service: "store"}] {
				t.Fatalf("held = %v, want %v (not the scheduled report)\n%s", held, want, out)
			}
			out = lcDo(e, "", "start", "")
			if held := lcHeld(t, e); len(held) != 0 {
				t.Fatalf("starting the app must release every hold, still held: %v\n%s", held, out)
			}
		})
	}
}

// An app delete holds the expected_down lease while `compose down` runs: a snapshot taken mid-teardown
// (a fixed service already gone, siblings still running) must not make self-heal restore copies of the app
// being deleted. The lease is released afterwards.
func TestAppDeleteHoldsTheExpectedDownLease(t *testing.T) {
	marks := t.TempDir()
	lcDocker(t, "case \"$*\" in *' down '*) touch '"+marks+"/in-down'; i=0; while [ ! -f '"+marks+"/go' ] && [ $i -lt 400 ]; do sleep 0.05; i=$((i+1)); done ;; esac\n")
	e, _ := lcEnv(t, false)
	done := make(chan error, 1)
	go func() {
		gateErr, _ := e.srv.teardownApp(context.Background(), "shop")
		done <- gateErr
	}()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(marks, "in-down")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the teardown never ran `compose down`")
		}
		time.Sleep(20 * time.Millisecond)
	}
	leases, err := e.srv.selfHeal.ActiveExpectedDown(time.Now().Unix())
	if err := os.WriteFile(filepath.Join(marks, "go"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if gateErr := <-done; gateErr != nil {
		t.Fatalf("teardown: %v", gateErr)
	}
	if err != nil || !leases["shop"] {
		t.Fatalf("during `compose down` the app must hold the expected_down lease: %v err=%v", leases, err)
	}
	after, err := e.srv.selfHeal.ActiveExpectedDown(time.Now().Unix())
	if err != nil || after["shop"] || e.srv.leaseHolders["shop"] != 0 {
		t.Fatalf("the lease must be released after the teardown: %v holders=%d err=%v", after, e.srv.leaseHolders["shop"], err)
	}
}

// A restore is refused, before any docker call, for a service the deployed definition doesn't give a
// fixed count of two or more — without `scale:`, `up -- <svc>` would cut it to one copy — and for one
// the autoscaler manages.
func TestRemediateRefusesARestoreWithoutAFixedCount(t *testing.T) {
	calls := lcDocker(t, "")
	e, wd := fixedEnv(t)
	app := monitor.App{Project: "shop", WorkingDir: wd, Services: []monitor.ServiceStatus{
		{Service: "store", ContainerID: lcStore, State: "running"},
		{Service: "api", ContainerID: lcAPI1, State: "running"},
		{Service: "api", ContainerID: lcAPI2, State: "exited"},
	}}
	ctx := context.Background()
	if err := e.srv.Remediate(ctx, app, "store", selfheal.RungRestore, selfheal.Target{Restore: true}); !errors.Is(err, selfheal.ErrNotFixed) {
		t.Fatalf("store has no fixed count: want ErrNotFixed, got %v", err)
	}
	e.srv.scaling = scale.NewStore(e.srv.db)
	if err := e.srv.scaling.SavePolicy(ctx, scale.Key{App: "shop", Service: "api"}, enabledTestPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Remediate(ctx, app, "api", selfheal.RungRecreate, selfheal.Target{Remove: []string{lcAPI2}, Restore: true}); !errors.Is(err, selfheal.ErrNotFixed) {
		t.Fatalf("an autoscaled service: want ErrNotFixed, got %v", err)
	}
	if err := e.srv.Remediate(ctx, app, "api", selfheal.RungRestart, selfheal.Target{CopyID: lcAPI2, Restore: true}); err == nil {
		t.Fatal("a single-copy target can't be combined with a restore")
	}
	if len(calls()) != 0 {
		t.Fatalf("no docker call may run: %v", calls())
	}
}

// A per-copy stop of a fixed-count service is refused: nothing would keep the copy stopped, and the
// operator stops the whole service instead. No docker call runs and no hold is written.
func TestPerCopyStopRefusedForAFixedCount(t *testing.T) {
	calls := lcDocker(t, "")
	e, wd := fixedEnv(t)
	stopped := ""
	e.srv.replicaStopper = func(_, _, id string) { stopped = id }
	e.srv.snapFn = lcSnapshots(calls, wd, []monitor.ServiceStatus{
		{Service: "api", ContainerID: lcAPI1, State: "running"},
		{Service: "api", ContainerID: lcAPI2, State: "running"},
	})
	w := httptest.NewRecorder()
	e.srv.runLifecycle(w, httptest.NewRequest(http.MethodPost, "/apps/shop/services/api/stop?copy="+lcAPI2, nil), "shop", "api", "stop")
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "fixed number of copies") {
		t.Fatalf("status %d body %q, want 409 naming the fixed count", w.Code, w.Body.String())
	}
	if stopped != "" || len(calls()) != 0 || len(lcHeld(t, e)) != 0 {
		t.Fatalf("nothing may happen: stopper %q, calls %v, holds %v", stopped, calls(), lcHeld(t, e))
	}
	// Restarting one copy is still offered and works.
	out := lcDo(e, "api", "restart", "copy="+lcAPI2)
	if got := calls(); len(got) != 1 || got[0] != "restart "+lcAPI2 {
		t.Fatalf("per-copy restart: calls %q\n%s", got, out)
	}
}

// The service page of a fixed-count service shows the count, offers no ±1 replica and no per-copy stop,
// and keeps the per-copy restart.
func TestServicePageShowsAFixedCount(t *testing.T) {
	calls := lcDocker(t, "")
	e, wd := fixedEnv(t)
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), true, "")
	e.srv.snapFn = lcSnapshots(calls, wd, []monitor.ServiceStatus{
		{Service: "api", ContainerID: lcAPI1, Name: "shop-api-1", State: "running"},
		{Service: "api", ContainerID: lcAPI2, Name: "shop-api-2", State: "running"},
	})
	sess, csrf := e.authed(t)
	page := readBody(e.req(t, "GET", "/apps/shop/services/api", "127.0.0.1:1", nil, []*http.Cookie{sess, csrf}, nil))
	if !strings.Contains(page, "Fixed: 2 copies") || !strings.Contains(page, "replicas in mooring.yaml") {
		t.Fatal("the page must show the fixed count")
	}
	for _, gone := range []string{"Stop this copy", "+1 replica", "−1 replica", "Desired replicas", "Enable auto-scaling for this service"} {
		if strings.Contains(page, gone) {
			t.Errorf("a fixed-count service must not offer %q", gone)
		}
	}
	if !strings.Contains(page, "Restart this copy") {
		t.Error("restarting one copy is still offered")
	}
	// A service without a fixed count keeps the copy actions.
	e.srv.snapFn = lcSnapshots(calls, wd, []monitor.ServiceStatus{
		{Service: "store", ContainerID: lcAPI1, Name: "shop-store-1", State: "running"},
		{Service: "store", ContainerID: lcAPI2, Name: "shop-store-2", State: "running"},
	})
	page = readBody(e.req(t, "GET", "/apps/shop/services/store", "127.0.0.1:1", nil, []*http.Cookie{sess, csrf}, nil))
	if strings.Contains(page, "Fixed:") || !strings.Contains(page, "Stop this copy") {
		t.Error("a service without replicas keeps its per-copy stop and shows no fixed count")
	}
}

// A definition saved while a self-heal read was in flight must win: the read that started before the save
// may be returned once, but it must not be cached over the newer definition.
func TestSelfHealCacheKeepsASaveThatRacedARead(t *testing.T) {
	e, _ := fixedEnv(t)
	three, err := definition.Parse([]byte(strings.Replace(fixedYAML, "replicas: 2", "replicas: 3", 1)))
	if err != nil {
		t.Fatal(err)
	}
	selfHealReadHook = func(app string) {
		selfHealReadHook = nil
		if err := e.srv.applyDefinition(context.Background(), app, three, "git deploy: test", ""); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { selfHealReadHook = nil })
	e.srv.forgetSelfHealInfo("shop") // force a read
	if info, ok := e.srv.SelfHealServices("shop"); !ok || info["api"].Replicas != 2 {
		t.Fatalf("the in-flight read returns what it read: info = %+v ok=%v", info, ok)
	}
	if info, ok := e.srv.SelfHealServices("shop"); !ok || info["api"].Replicas != 3 {
		t.Fatalf("the save that raced the read must not be hidden by it: info = %+v ok=%v, want 3 copies", info, ok)
	}
}
