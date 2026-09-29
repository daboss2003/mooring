package web

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/scale"
	"github.com/daboss2003/mooring/internal/selfheal"
)

// recordingDockerCLI puts a `docker` script first on PATH that appends its argv to a log file and
// succeeds; it returns a reader for the logged invocations.
func recordingDockerCLI(t *testing.T) func() []string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake docker")
	}
	dir := t.TempDir()
	logf := filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\necho \"$*\" >> " + logf + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() []string {
		b, _ := os.ReadFile(logf)
		return strings.Fields(strings.ReplaceAll(strings.TrimSpace(string(b)), "\n", " | "))
	}
}

const (
	copyA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	copyB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func scaledApp() monitor.App {
	return monitor.App{Project: "shop", Services: []monitor.ServiceStatus{
		{Service: "web", ContainerID: copyA, State: "running", Health: "healthy"},
		{Service: "web", ContainerID: copyB, State: "exited", ExitCode: 1},
	}}
}

// The restart rung with a target restarts exactly that copy — never every copy of the service.
func TestRemediateRestartsOneCopy(t *testing.T) {
	calls := recordingDockerCLI(t)
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), true, "")
	err := e.srv.Remediate(context.Background(), scaledApp(), "web", selfheal.RungRestart, selfheal.Target{CopyID: copyB})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls(), " "); got != "restart "+copyB {
		t.Fatalf("argv = %q, want a restart of the one sick copy", got)
	}
}

// Removal takes out the sick copies (the autoscaler starts fresh ones) when the service is autoscaled.
func TestRemediateRemovesSickCopies(t *testing.T) {
	calls := recordingDockerCLI(t)
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), true, "")
	e.srv.scaling = scale.NewStore(e.srv.db)
	pr := scale.PolicyRow{Enabled: true, PerReplicaMem: 64 << 20, PerReplicaCPU: 100, Policy: scale.Policy{
		Min: 1, Max: 3, UpCPUPct: 80, DownCPUPct: 40, UpMemPct: 80, DownMemPct: 40, BreachForSecs: 60, CooldownUpSecs: 60, CooldownDownSecs: 300}}
	if err := e.srv.scaling.SavePolicy(context.Background(), scale.Key{App: "shop", Service: "web"}, pr); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Remediate(context.Background(), scaledApp(), "web", selfheal.RungRecreate, selfheal.Target{Remove: []string{copyB}}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls(), " "); got != "rm -f "+copyB {
		t.Fatalf("argv = %q, want the sick copy removed", got)
	}
}

// Without an autoscaling policy nothing would replace a removed copy: the removal is refused (never
// silently turned into an unpaced recreate), and so is a single-copy target on a non-restart rung.
func TestRemediateRefusesUnsafeTargets(t *testing.T) {
	calls := recordingDockerCLI(t)
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), true, "")
	e.srv.scaling = scale.NewStore(e.srv.db)
	ctx := context.Background()
	if err := e.srv.Remediate(ctx, scaledApp(), "web", selfheal.RungRecreate, selfheal.Target{Remove: []string{copyB}}); !errors.Is(err, selfheal.ErrNoReplacement) {
		t.Fatalf("removing a copy of a service the autoscaler doesn't manage must be refused with ErrNoReplacement, got %v", err)
	}
	if err := e.srv.Remediate(ctx, scaledApp(), "web", selfheal.RungRecreate, selfheal.Target{CopyID: copyB}); err == nil {
		t.Fatal("a single-copy target is only valid for a restart")
	}
	if len(calls()) != 0 {
		t.Fatalf("no docker call may run: %v", calls())
	}
}

// A target that isn't a container of the service is refused before any docker call.
func TestRemediateRefusesAForeignCopy(t *testing.T) {
	calls := recordingDockerCLI(t)
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), true, "")
	err := e.srv.Remediate(context.Background(), scaledApp(), "api", selfheal.RungRestart, selfheal.Target{CopyID: copyB})
	if err == nil {
		t.Fatal("a copy of another service must be refused")
	}
	if len(calls()) != 0 {
		t.Fatalf("no docker call may run: %v", calls())
	}
}

// A scale call names its service, so compose converges only that service (never resetting other
// scaled services or starting stopped/held ones), and never builds.
func TestScaleJobIsScopedToTheService(t *testing.T) {
	j := scaleJob(&monitor.App{Project: "shop", WorkingDir: "/w"}, "/env", "web", 3)
	if j.Service != "web" {
		t.Fatalf("the scale call must name its service, got %q", j.Service)
	}
	want := "up -d --no-deps --no-recreate --no-build --scale web=3"
	if got := strings.Join(j.Action, " "); got != want {
		t.Fatalf("action = %q, want %q", got, want)
	}
}

// Self-heal's facts come from the deployed definition (cached), but whether a service is autoscaled is
// read fresh from the scale store — the same source Remediate checks before removing copies.
func TestSelfHealServicesReadsScaledFromTheScaleStore(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.defStore = definition.NewStore(e.srv.db, make([]byte, 32))
	e.srv.scaling = scale.NewStore(e.srv.db)
	ctx := context.Background()
	d, err := definition.Parse([]byte(`apiVersion: mooring/v1
kind: App
metadata: {slug: shop}
spec:
  compose:
    source: generated
    services:
      web:
        image: nginx:1.27
        stop_grace_period: 90s
        depends_on: [db]
      db:
        image: postgres:16
`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.defStore.SaveCanonical(ctx, d, "deploy", ""); err != nil {
		t.Fatal(err)
	}
	info, ok := e.srv.SelfHealServices("shop")
	if !ok || info["web"].Scaled || info["web"].StopGrace != 90*time.Second || len(info["web"].DependsOn) != 1 {
		t.Fatalf("definition facts: %+v %v", info, ok)
	}
	pr := scale.PolicyRow{Enabled: true, PerReplicaMem: 64 << 20, PerReplicaCPU: 100, Policy: scale.Policy{
		Min: 1, Max: 3, UpCPUPct: 80, DownCPUPct: 40, UpMemPct: 80, DownMemPct: 40, BreachForSecs: 60, CooldownUpSecs: 60, CooldownDownSecs: 300}}
	if err := e.srv.scaling.SavePolicy(ctx, scale.Key{App: "shop", Service: "web"}, pr); err != nil {
		t.Fatal(err)
	}
	if info, _ := e.srv.SelfHealServices("shop"); !info["web"].Scaled || info["db"].Scaled {
		t.Fatalf("Scaled must follow the scale store at once, not the cached definition: %+v", info)
	}
}
