package web

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/envstore"
	"github.com/daboss2003/mooring/internal/gitstore"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/selfheal"
	"github.com/daboss2003/mooring/internal/startgate"
)

// fakeDockerScript is the body of a `docker` CLI stand-in ($d is its directory). It logs every call, one
// per line; answers `compose … config --hash=*` from $d/hashes and `image inspect … -- <ref>` from
// $d/images ("<ref> <id>" lines); and fails `up … -- <svc>` when $d/fail-<svc> or $d/fail-all exists,
// logging the failed call's line number to $d/failed.log (docker calls never overlap: one child at a time).
const fakeDockerScript = `
printf '%s\n' "$*" >> "$d/calls.log"
n=$(wc -l < "$d/calls.log")
last=""
for a in "$@"; do last="$a"; done
case "$*" in
*"config --hash=*"*)
	cat "$d/hashes"
	exit 0 ;;
"image inspect "*)
	while read -r ref id; do
		if [ "$ref" = "$last" ]; then echo "$id"; exit 0; fi
	done < "$d/images"
	echo "Error: No such image: $last" >&2
	exit 1 ;;
*" up "*)
	if [ -f "$d/fail-all" ] || [ -f "$d/fail-$last" ]; then
		echo $n >> "$d/failed.log"
		echo "Error response from daemon: cannot start $last" >&2
		exit 1
	fi ;;
esac
exit 0
`

// fakeDocker drives the fakeDockerScript it put first on PATH.
type fakeDocker struct{ dir string }

func newFakeDocker(t *testing.T, hashes, images map[string]string) *fakeDocker {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake docker")
	}
	dir := t.TempDir()
	var hb, ib strings.Builder
	for svc, h := range hashes {
		fmt.Fprintf(&hb, "%s %s\n", svc, h)
	}
	for ref, id := range images {
		fmt.Fprintf(&ib, "%s %s\n", ref, id)
	}
	files := map[string]string{"hashes": hb.String(), "images": ib.String(), "docker": "#!/bin/sh\nd='" + dir + "'" + fakeDockerScript}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return &fakeDocker{dir: dir}
}

// failUp makes every `up … -- <svc>` fail from now on ("all" fails every up).
func (d *fakeDocker) failUp(t *testing.T, svc string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(d.dir, "fail-"+svc), nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

// clearFailures makes every `up` succeed again.
func (d *fakeDocker) clearFailures(t *testing.T) {
	t.Helper()
	marks, _ := filepath.Glob(filepath.Join(d.dir, "fail-*"))
	for _, m := range marks {
		if err := os.Remove(m); err != nil {
			t.Fatal(err)
		}
	}
}

// calls returns every docker invocation so far ("$*" per call).
func (d *fakeDocker) calls() []string {
	b, _ := os.ReadFile(filepath.Join(d.dir, "calls.log"))
	s := strings.TrimSpace(string(b))
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// failed reports which calls (by index into calls) exited with an error.
func (d *fakeDocker) failed() map[int]bool {
	b, _ := os.ReadFile(filepath.Join(d.dir, "failed.log"))
	out := map[int]bool{}
	for _, f := range strings.Fields(string(b)) {
		var n int
		if _, err := fmt.Sscan(f, &n); err == nil {
			out[n-1] = true
		}
	}
	return out
}

// ups returns the services named by per-service `up … -- <svc>` calls, in order.
func (d *fakeDocker) ups() []string {
	var out []string
	for _, c := range d.calls() {
		if f := strings.Fields(c); strings.Contains(c, " up ") && len(f) > 2 && f[len(f)-2] == "--" {
			out = append(out, f[len(f)-1])
		}
	}
	return out
}

// fakeView is the monitor's view of one app in these tests: its initial containers, changed by the fake
// docker's calls — a successful `up … -- <svc>` leaves one fresh, healthy copy running the service's current
// definition and image; `rm -f <id>…` removes containers.
type fakeView struct {
	docker   *fakeDocker
	slug     string
	initial  []monitor.ServiceStatus
	hashes   map[string]string // service → current config hash
	imageIDs map[string]string // service → current image id

	mu      sync.Mutex
	started map[int]time.Time // call index → when this view first saw that start
}

func (v *fakeView) snapshot() *monitor.Snapshot {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.started == nil {
		v.started = map[int]time.Time{}
	}
	cs := slices.Clone(v.initial)
	failed := v.docker.failed()
	for i, call := range v.docker.calls() {
		f := strings.Fields(call)
		switch {
		case failed[i]:
		case len(f) > 2 && f[0] == "rm" && f[1] == "-f":
			cs = slices.DeleteFunc(cs, func(c monitor.ServiceStatus) bool { return slices.Contains(f[2:], c.ContainerID) })
		case strings.Contains(call, " up ") && len(f) > 2 && f[len(f)-2] == "--":
			svc := f[len(f)-1]
			if _, ok := v.started[i]; !ok {
				v.started[i] = time.Now()
			}
			cs = slices.DeleteFunc(cs, func(c monitor.ServiceStatus) bool { return c.Service == svc })
			cs = append(cs, monitor.ServiceStatus{
				Service: svc, ContainerID: fmt.Sprintf("%064x", i+1), State: "running", Health: "healthy",
				Inspected: true, StartedAt: v.started[i], ConfigHash: v.hashes[svc], ImageID: v.imageIDs[svc],
			})
		}
	}
	return &monitor.Snapshot{At: time.Now(), DockerOK: true, Apps: []monitor.App{{Project: v.slug, Services: cs}}}
}

func testConfigHash(svc string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte("config:"+svc)))
}
func testImageID(ref string) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("image:"+ref)))
}

// pacedYAML: web → api → db (depends_on), cache on its own, report only on a schedule.
const pacedYAML = `apiVersion: mooring/v1
kind: App
metadata: {slug: app}
spec:
  compose:
    source: generated
    services:
      api:
        image: nginx:1.27
        depends_on: [db]
      cache:
        image: redis:7
      db:
        image: postgres:16
      report:
        image: busybox:1.36
      web:
        image: caddy:2
        depends_on: [api]
  scheduled_tasks:
    - name: nightly
      service: report
      every: 24h
`

var (
	cacheCopy  = strings.Repeat("ca", 32)
	dbCopy     = strings.Repeat("db", 32)
	apiCopy    = strings.Repeat("a1", 32)
	legacyCopy = strings.Repeat("1e", 32)
)

// pacedDeployEnv is the app "shop" (pacedYAML) ready for a paced deploy against the fake docker CLI and
// view: cache runs its current definition and image, db runs an older image, api was stopped by the
// operator (held — as is cache), web has no container yet, and legacy is a service mooring.yaml dropped.
type pacedDeployEnv struct {
	e      *testEnv
	cfg    gitstore.Config
	sha    string
	docker *fakeDocker

	mu    sync.Mutex
	lines []string
}

func newPacedDeployEnv(t *testing.T) *pacedDeployEnv {
	t.Helper()
	p := newPacedServer(t, map[string]string{"api": "nginx:1.27", "cache": "redis:7", "db": "postgres:16", "web": "caddy:2"},
		[]monitor.ServiceStatus{
			{Service: "api", ContainerID: apiCopy, State: "exited", Health: "none", Inspected: true, ConfigHash: testConfigHash("api"), ImageID: testImageID("nginx:1.27")},
			{Service: "cache", ContainerID: cacheCopy, State: "running", Health: "healthy", Inspected: true, ConfigHash: testConfigHash("cache"), ImageID: testImageID("redis:7")},
			{Service: "db", ContainerID: dbCopy, State: "running", Health: "healthy", Inspected: true, ConfigHash: testConfigHash("db"), ImageID: testImageID("postgres:15")},
			{Service: "legacy", ContainerID: legacyCopy, State: "running", Health: "none", Inspected: true},
		})
	for _, svc := range []string{"api", "cache"} {
		if err := p.e.srv.selfHeal.SetHeld(context.Background(), selfheal.Key{App: "shop", Service: svc}, "operator", time.Now().Unix()); err != nil {
			t.Fatal(err)
		}
	}
	p.connect(t, pacedYAML)
	return p
}

// newPacedServer is a server whose deploys of the app "shop" are paced, with docker played by a fake CLI
// that knows each service's current config hash and image (refs: service → image ref) and the app's
// containers emulated from initial.
func newPacedServer(t *testing.T, refs map[string]string, initial []monitor.ServiceStatus) *pacedDeployEnv {
	t.Helper()
	hashes, images, ids := map[string]string{}, map[string]string{}, map[string]string{}
	for svc, ref := range refs {
		hashes[svc] = testConfigHash(svc)
		images[ref] = testImageID(ref)
		ids[svc] = testImageID(ref)
	}
	docker := newFakeDocker(t, hashes, images)
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), true, "")
	e.srv.selfHeal = selfheal.NewStore(e.srv.db)
	e.srv.startGate = startgate.New(startgate.DefaultConfig(1))
	// Tiny pacing limits, so nothing a rollout waits for can hold a test up.
	sg := &e.srv.cfg.Server.StartGate
	sg.MaxSettle, sg.ServiceSettle = config.Duration(10*time.Millisecond), config.Duration(50*time.Millisecond)
	sg.DeployWait, sg.RolloutBudget = rolloutDur(10*time.Millisecond), config.Duration(time.Second)
	view := &fakeView{docker: docker, slug: "shop", hashes: hashes, imageIDs: ids, initial: initial}
	e.srv.snapFn = view.snapshot
	return &pacedDeployEnv{e: e, docker: docker}
}

// connect commits mooringYAML to the app's repo and stages it for deploy.
func (p *pacedDeployEnv) connect(t *testing.T, mooringYAML string) {
	t.Helper()
	p.sha = gitObjStoreFixture(t, p.e.srv.gitObjectDir("shop"), mooringYAML)
	p.cfg = configureRepo(t, p.e, "shop", p.sha)
}

func (p *pacedDeployEnv) deploy(atOnce bool) ([]rolloutProblem, error) {
	return p.e.srv.deployRepoApp(context.Background(), p.cfg, p.sha, "manual", "operator", false, atOnce, func(l string) {
		p.mu.Lock()
		p.lines = append(p.lines, l)
		p.mu.Unlock()
	})
}

func (p *pacedDeployEnv) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.lines, "\n")
}

// held lists the app's services under an operator hold.
func (p *pacedDeployEnv) held(t *testing.T) []string {
	t.Helper()
	all, err := p.e.srv.selfHeal.ActiveHeld()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for k := range all {
		if k.App == "shop" {
			out = append(out, k.Service)
		}
	}
	sort.Strings(out)
	return out
}

// lastDeployOutcome is the outcome recorded for the app's latest deploy.
func (p *pacedDeployEnv) lastDeployOutcome(t *testing.T) string {
	t.Helper()
	var outcome string
	if err := p.e.srv.db.QueryRow(`SELECT outcome FROM deploys WHERE project='shop' ORDER BY id DESC LIMIT 1`).Scan(&outcome); err != nil {
		t.Fatal(err)
	}
	return outcome
}

// problemAlerts lists the transitions of the app's deploy_problems alert rows, oldest first.
func (p *pacedDeployEnv) problemAlerts(t *testing.T) []string {
	t.Helper()
	rows, err := p.e.srv.db.Query(`SELECT transition, level, target FROM alert_outbox WHERE kind=? AND dedupe_key='deploy:shop' ORDER BY id`, deployProblemsKind)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var transition, level, target string
		if err := rows.Scan(&transition, &level, &target); err != nil {
			t.Fatal(err)
		}
		if level != "warning" || target != "shop" {
			t.Errorf("deploy_problems alert: level %q target %q, want warning / shop", level, target)
		}
		out = append(out, transition)
	}
	return out
}

// A paced deploy starts every changed service with its own `up … -- <svc>`, dependencies first, leaves an
// unchanged service running, starts (and releases) a service the operator stopped, never starts a
// scheduled service, and removes the containers of a service mooring.yaml no longer has.
func TestPacedDeployStartsOneServiceAtATime(t *testing.T) {
	p := newPacedDeployEnv(t)
	problems, err := p.deploy(false)
	if err != nil || len(problems) != 0 {
		t.Fatalf("deploy: problems=%v err=%v\n%s", problems, err, p.output())
	}
	if got := p.docker.ups(); !slices.Equal(got, []string{"db", "api", "web"}) {
		t.Fatalf("per-service starts = %v, want [db api web] (dependencies first; cache unchanged; report scheduled)\n%s",
			got, strings.Join(p.docker.calls(), "\n"))
	}
	for _, c := range p.docker.calls() {
		if strings.Contains(c, " up ") && !strings.Contains(c, " up -d --no-deps --no-build -- ") {
			t.Errorf("a paced start must be exactly `up -d --no-deps --no-build -- <svc>` (no whole-project up, no --force-recreate without changed files), got %q", c)
		}
	}
	if !slices.Contains(p.docker.calls(), "rm -f "+legacyCopy) {
		t.Errorf("the container of the dropped legacy service must be removed by id:\n%s", strings.Join(p.docker.calls(), "\n"))
	}
	if held := p.held(t); len(held) != 0 {
		t.Errorf("the holds of the started (api) and unchanged (cache) services must be released, still held: %v", held)
	}
	for _, want := range []string{"unchanged, left running: cache", "removed 1 container(s) of services no longer in mooring.yaml: legacy"} {
		if !strings.Contains(p.output(), want) {
			t.Errorf("deploy log lacks %q:\n%s", want, p.output())
		}
	}
	if cfg, _, _ := p.e.srv.gitStore.Get("shop"); cfg.DeployedCommit != p.sha || cfg.UpdateState != "up_to_date" {
		t.Errorf("deployed commit %q state %q, want %q up_to_date", cfg.DeployedCommit, cfg.UpdateState, p.sha)
	}
	if got := p.lastDeployOutcome(t); got != "ok" {
		t.Errorf("deploy outcome = %q, want ok", got)
	}
	if got := p.problemAlerts(t); len(got) != 0 {
		t.Errorf("a clean deploy with no open alert must not notify, got %v", got)
	}
}

// "All at once" (now=1) keeps the whole-project `up`: no comparison, no per-service starts.
func TestDeployAllAtOnceKeepsTheWholeProjectUp(t *testing.T) {
	p := newPacedDeployEnv(t)
	sess, csrf := p.e.authed(t)
	resp := p.e.req(t, "POST", "/apps/shop/git/deploy?sha="+p.sha+"&now=1", "127.0.0.1:1",
		map[string]string{"Origin": "https://example.com"}, []*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}})
	body := readBody(resp)
	if !strings.Contains(body, "(all at once)") || !strings.Contains(body, "\n[done]\n") {
		t.Fatalf("response:\n%s", body)
	}
	whole := 0
	for _, c := range p.docker.calls() {
		if strings.HasSuffix(c, " up -d --remove-orphans --no-build") {
			whole++
		}
		if strings.Contains(c, "config --hash") || strings.HasPrefix(c, "image inspect") {
			t.Errorf("an all-at-once deploy compares nothing: %q", c)
		}
	}
	if whole != 1 || len(p.docker.ups()) != 0 {
		t.Fatalf("want exactly one whole-project up and no per-service starts:\n%s", strings.Join(p.docker.calls(), "\n"))
	}
}

// A service that fails to start is reported and the rollout carries on: the deploy succeeds "with problems",
// pins the commit, keeps that service's hold, and raises a WARNING alert — which the next clean deploy
// resolves.
func TestPacedDeployCarriesOnPastAServiceThatFailsToStart(t *testing.T) {
	p := newPacedDeployEnv(t)
	p.docker.failUp(t, "api")
	problems, err := p.deploy(false)
	if err != nil {
		t.Fatalf("one service failing to start must not fail the deploy: %v\n%s", err, p.output())
	}
	if len(problems) != 1 || problems[0].Service != "api" || !deployStartFailed(problems[0]) {
		t.Fatalf("problems = %+v, want api's failed start", problems)
	}
	if got := p.docker.ups(); !slices.Equal(got, []string{"db", "api", "web"}) {
		t.Fatalf("the rollout must go on to web after api failed: %v", got)
	}
	if !strings.Contains(p.output(), "⚠ api: start failed") {
		t.Errorf("the problem must be streamed:\n%s", p.output())
	}
	if held := p.held(t); !slices.Equal(held, []string{"api"}) {
		t.Errorf("only api (not started) keeps its hold, held = %v", held)
	}
	if cfg, _, _ := p.e.srv.gitStore.Get("shop"); cfg.DeployedCommit != p.sha || cfg.UpdateState != "up_to_date" {
		t.Errorf("a deploy with problems still pins its commit (the next deploy is never blocked): %q %q", cfg.DeployedCommit, cfg.UpdateState)
	}
	if got := p.lastDeployOutcome(t); got != "problems" {
		t.Errorf("deploy outcome = %q, want problems", got)
	}
	if got := p.problemAlerts(t); !slices.Equal(got, []string{"firing"}) {
		t.Fatalf("deploy_problems alerts = %v, want one firing", got)
	}

	// The follow-up deploy: everything else already runs the new version, so only api starts; the alert resolves.
	p.docker.clearFailures(t)
	problems, err = p.deploy(false)
	if err != nil || len(problems) != 0 {
		t.Fatalf("follow-up deploy: problems=%v err=%v\n%s", problems, err, p.output())
	}
	if got := p.docker.ups(); !slices.Equal(got, []string{"db", "api", "web", "api"}) {
		t.Fatalf("the follow-up must start only api: %v", got)
	}
	if got := p.problemAlerts(t); !slices.Equal(got, []string{"firing", "resolved"}) {
		t.Fatalf("deploy_problems alerts = %v, want firing then resolved", got)
	}
	if held := p.held(t); len(held) != 0 {
		t.Errorf("api's hold must be released once it started, held = %v", held)
	}
}

// When no service starts at all the deploy fails like a failed whole-project `up`: nothing new runs, so
// the old version keeps every container (even of services the new definition drops) and every hold.
func TestPacedDeployWhereNothingStartsFails(t *testing.T) {
	p := newPacedDeployEnv(t)
	p.docker.failUp(t, "all")
	problems, err := p.deploy(false)
	if err == nil || !strings.Contains(err.Error(), "up failed") || problems != nil {
		t.Fatalf("want a failed deploy, got problems=%v err=%v", problems, err)
	}
	// Containers of services dropped from the definition go first, as with the whole-project
	// `up --remove-orphans` (a renamed service may need their host port) — before any start.
	firstUp := -1
	for i, c := range p.docker.calls() {
		switch {
		case strings.Contains(c, " up -d ") && firstUp < 0:
			firstUp = i
		case strings.HasPrefix(c, "rm ") && firstUp >= 0:
			t.Errorf("orphans must be removed before the first start, got %q after it", c)
		}
	}
	if cfg, _, _ := p.e.srv.gitStore.Get("shop"); cfg.UpdateState != "update_blocked" || cfg.DeployedCommit == p.sha {
		t.Errorf("a failed deploy: state %q deployed %q", cfg.UpdateState, cfg.DeployedCommit)
	}
	if got := p.lastDeployOutcome(t); got != "error" {
		t.Errorf("deploy outcome = %q, want error", got)
	}
	if got := p.problemAlerts(t); len(got) != 0 {
		t.Errorf("a failed deploy raises no deploy_problems alert, got %v", got)
	}
	if held := p.held(t); !slices.Equal(held, []string{"api", "cache"}) {
		t.Errorf("a deploy where nothing started changes no hold, held = %v", held)
	}
}

// A service whose managed files changed is force-recreated; if that start fails, the next deploy
// force-recreates it again — and only it, not the services that did pick up their new files.
func TestPacedDeployRecreatesChangedFilesUntilTheServiceStarts(t *testing.T) {
	p := newPacedServer(t, map[string]string{"api": "nginx:1.27", "web": "caddy:2"}, nil)
	setKey := func(v string) {
		t.Helper()
		if _, err := p.e.srv.envStore.Save(context.Background(), "shop",
			[]envstore.Entry{{Key: "app_key", Value: secret.New(v), Secret: true}}, "operator"); err != nil {
			t.Fatal(err)
		}
	}
	setKey("v1")
	p.connect(t, `apiVersion: mooring/v1
kind: App
metadata: {slug: app}
spec:
  compose:
    source: generated
    services:
      api:
        image: nginx:1.27
        config_files:
          - template: "key = {{hm.KEY}}\n"
            mount: /etc/app.conf
            bindings: {KEY: {secret: app_key}}
      web:
        image: caddy:2
        config_files:
          - template: "key = {{hm.KEY}}\n"
            mount: /etc/app.conf
            bindings: {KEY: {secret: app_key}}
  secrets: [{name: app_key}]
`)
	forced := func() []string {
		var out []string
		for _, c := range p.docker.calls() {
			if f := strings.Fields(c); strings.Contains(c, " up ") && strings.Contains(c, "--force-recreate") {
				out = append(out, f[len(f)-1])
			}
		}
		return out
	}
	if problems, err := p.deploy(false); err != nil || len(problems) != 0 {
		t.Fatalf("first deploy: problems=%v err=%v\n%s", problems, err, p.output())
	}
	setKey("v2") // both services' rendered config changes
	p.docker.failUp(t, "api")
	if problems, err := p.deploy(false); err != nil || len(problems) != 1 || problems[0].Service != "api" {
		t.Fatalf("second deploy: problems=%v err=%v\n%s", problems, err, p.output())
	}
	p.docker.clearFailures(t)
	if problems, err := p.deploy(false); err != nil || len(problems) != 0 {
		t.Fatalf("third deploy: problems=%v err=%v\n%s", problems, err, p.output())
	}
	if got := forced(); !slices.Equal(got, []string{"api", "web", "api"}) {
		t.Fatalf("force-recreates = %v, want api and web for the new files, then api again (it never started)\n%s",
			got, strings.Join(p.docker.calls(), "\n"))
	}
}

// The unchanged check needs positive evidence for every copy; anything missing counts as changed.
func TestUnchangedSetTreatsMissingDataAsChanged(t *testing.T) {
	hash, image := testConfigHash("web"), testImageID("nginx:1.27")
	copyOf := func(state, h, img string) monitor.ServiceStatus {
		return monitor.ServiceStatus{Service: "web", ContainerID: strings.Repeat("ab", 32), State: state, ConfigHash: h, ImageID: img}
	}
	app := func(cs ...monitor.ServiceStatus) *monitor.App { return &monitor.App{Project: "shop", Services: cs} }
	current := copyOf("running", hash, image)
	cases := []struct {
		name           string
		changed        map[string]bool
		hashes, images map[string]string
		app            *monitor.App
		want           bool
	}{
		{"current and running", nil, map[string]string{"web": hash}, map[string]string{"web": image}, app(current), true},
		{"every copy of a scaled service current", nil, map[string]string{"web": hash}, map[string]string{"web": image}, app(current, current), true},
		{"managed files changed", map[string]bool{"web": true}, map[string]string{"web": hash}, map[string]string{"web": image}, app(current), false},
		{"no compose hash", nil, nil, map[string]string{"web": image}, app(current), false},
		{"no compose hash, unlabelled copy", nil, nil, map[string]string{"web": image}, app(copyOf("running", "", image)), false},
		{"no image id", nil, map[string]string{"web": hash}, nil, app(current), false},
		{"no image id, copy without one", nil, map[string]string{"web": hash}, nil, app(copyOf("running", hash, "")), false},
		{"no container", nil, map[string]string{"web": hash}, map[string]string{"web": image}, app(), false},
		{"app not in the view", nil, map[string]string{"web": hash}, map[string]string{"web": image}, nil, false},
		{"a stopped copy", nil, map[string]string{"web": hash}, map[string]string{"web": image}, app(current, copyOf("exited", hash, image)), false},
		{"created from another definition", nil, map[string]string{"web": hash}, map[string]string{"web": image}, app(copyOf("running", testConfigHash("old"), image)), false},
		{"running another image", nil, map[string]string{"web": hash}, map[string]string{"web": image}, app(copyOf("running", hash, testImageID("nginx:1.26"))), false},
	}
	for _, tc := range cases {
		if got := unchangedSet([]string{"web"}, tc.changed, tc.hashes, tc.images, tc.app)["web"]; got != tc.want {
			t.Errorf("%s: unchanged = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Each step is one service's own compose call; the order runs through services left out as unchanged.
func TestDeployRolloutSteps(t *testing.T) {
	def, err := definition.Parse([]byte(`apiVersion: mooring/v1
kind: App
metadata: {slug: shop}
spec:
  compose:
    source: generated
    services:
      api:
        image: nginx:1.27
        depends_on: [cache]
        restart: unless-stopped
        self_healing: {on_unhealthy: notify}
        healthcheck:
          test: [wget, -qO-, "http://localhost/health"]
          interval: 10s
          timeout: 5s
          retries: 2
          start_period: 1m
      cache:
        image: redis:7
        depends_on: [db]
      db:
        image: postgres:16
`))
	if err != nil {
		t.Fatal(err)
	}
	base := dockerexec.Job{Project: "shop", Dir: "/w", ConfigFiles: []string{"/w/docker-compose.yml"}, EnvFile: "/w/env"}
	gs := config.StartGateSettings{MaxSettle: 3 * time.Minute, ServiceSettle: 15 * time.Minute}
	steps := deployRolloutSteps(def, []string{"api", "cache", "db"}, map[string]bool{"cache": true}, map[string]bool{"api": true}, base, gs)
	if len(steps) != 2 || steps[0].Service != "db" || steps[1].Service != "api" {
		t.Fatalf("steps = %+v, want db then api (api depends on db through the unchanged cache)", steps)
	}
	db, api := steps[0], steps[1]
	if got := strings.Join(db.Job.Action, " "); got != "up -d --no-deps --no-build" || db.Job.Service != "db" || !db.Reap {
		t.Errorf("db step: %q -- %q reap=%v", got, db.Job.Service, db.Reap)
	}
	if got := strings.Join(api.Job.Action, " "); got != "up -d --no-deps --no-build --force-recreate" || api.Job.Service != "api" {
		t.Errorf("api (changed managed files) step: %q -- %q", got, api.Job.Service)
	}
	if api.Job.Project != "shop" || api.Job.Dir != "/w" || api.Job.EnvFile != "/w/env" || len(api.Job.ConfigFiles) != 1 {
		t.Errorf("a step targets the deploy's compose project: %+v", api.Job)
	}
	if want := time.Minute + 15*time.Second*3 + time.Minute; api.Deadline != want || !api.Notify || !api.Restarts {
		t.Errorf("api: deadline %s (want %s) notify=%v restarts=%v", api.Deadline, want, api.Notify, api.Restarts)
	}
	if want := 3*time.Minute + 30*time.Second; db.Deadline != want || db.Notify || db.Restarts {
		t.Errorf("db: deadline %s (want %s) notify=%v restarts=%v", db.Deadline, want, db.Notify, db.Restarts)
	}
}

// Orphans are containers of services the definition doesn't declare (scheduled ones are declared).
func TestOrphanContainers(t *testing.T) {
	app := &monitor.App{Project: "shop", Services: []monitor.ServiceStatus{
		{Service: "web", ContainerID: strings.Repeat("aa", 32)},
		{Service: "report", ContainerID: strings.Repeat("bb", 32)},
		{Service: "old", ContainerID: strings.Repeat("cc", 32)},
		{Service: "old", ContainerID: strings.Repeat("dd", 32)},
		{Service: "", ContainerID: strings.Repeat("ee", 32)},
		{Service: "gone", ContainerID: "not-a-container-id"},
	}}
	ids, services := orphanContainers(app, map[string]bool{"web": true, "report": true})
	if !slices.Equal(ids, []string{strings.Repeat("cc", 32), strings.Repeat("dd", 32)}) || !slices.Equal(services, []string{"old"}) {
		t.Fatalf("orphans = %v %v", ids, services)
	}
	if ids, _ := orphanContainers(nil, nil); ids != nil {
		t.Fatalf("no app, no orphans: %v", ids)
	}
}

// A stale container view is no view: the deploy then treats every service as changed and removes nothing.
func TestDeploySnapshotRefusesAStaleView(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	at := time.Now().Add(-10 * time.Minute)
	e.srv.snapFn = func() *monitor.Snapshot { return &monitor.Snapshot{At: at, DockerOK: true} }
	if snap := e.srv.deploySnapshot(context.Background()); snap != nil {
		t.Fatalf("a snapshot from %s ago must not stand in for the current view", time.Since(at).Round(time.Second))
	}
	at = time.Now()
	if snap := e.srv.deploySnapshot(context.Background()); snap == nil {
		t.Fatal("a current snapshot must be used")
	}
}

// A changed service that failed to start keeps its old digest, so the next deploy recreates it again.
func TestKeepDeployDigests(t *testing.T) {
	next := map[string]string{"api": "new-api", "web": "new-web", "fresh": "new-fresh"}
	prev := map[string]string{"api": "old-api", "web": "old-web"}
	got := keepDeployDigests(next, prev, []string{"api", "fresh"})
	if want := map[string]string{"api": "old-api", "web": "new-web"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("digests = %v, want %v", got, want)
	}
	if next["api"] != "new-api" {
		t.Fatal("the new digests must not be modified")
	}
}

// The stream's last line and the audit record tell a clean deploy, one with problems, and a failure apart.
func TestDeployVerdict(t *testing.T) {
	var lines []string
	emit := func(l string) { lines = append(lines, l) }
	problems := []rolloutProblem{{Service: "api", Reason: "unhealthy"}}
	cases := []struct {
		atOnce       bool
		problems     []rolloutProblem
		err          error
		line, detail string
		outcome      audit.Outcome
	}{
		{false, nil, nil, "\n[done]", "", audit.OK},
		{true, nil, nil, "\n[done]", "all at once", audit.OK},
		{false, problems, nil, "\n[done — deployed with problems]", "deployed with problems: api: unhealthy", audit.OK},
		{false, nil, errors.New("boom"), "\n[failed: boom]", "boom", audit.Error},
		{true, nil, errors.New("boom"), "\n[failed: boom]", "all at once; boom", audit.Error},
	}
	for i, tc := range cases {
		lines = nil
		outcome, detail := deployVerdict(emit, tc.atOnce, tc.problems, tc.err)
		if len(lines) != 1 || lines[0] != tc.line || detail != tc.detail || outcome != tc.outcome {
			t.Errorf("case %d: lines %q detail %q outcome %q", i, lines, detail, outcome)
		}
	}
}

// A deploy stream that goes quiet writes a progress line, so a proxy or browser doesn't drop it.
func TestStreamDeployKeepalive(t *testing.T) {
	old := streamKeepalive
	streamKeepalive = 20 * time.Millisecond
	t.Cleanup(func() { streamKeepalive = old })
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	if !e.srv.gitDeploy.TryAcquire() {
		t.Fatal("could not take the git gate")
	}
	rec := httptest.NewRecorder()
	e.srv.streamDeploy(rec, "$ deploy shop", func(_ context.Context, emit func(string)) {
		time.Sleep(150 * time.Millisecond)
		emit("late line")
	})
	body := rec.Body.String()
	keep, late := strings.Index(body, "… still working ("), strings.Index(body, "late line")
	if !strings.HasPrefix(body, "$ deploy shop\n") || keep < 0 || late < keep {
		t.Fatalf("want a keepalive line during the silence, before the late line:\n%s", body)
	}
}

func TestVolumesOnlyForFailedServices(t *testing.T) {
	def := &definition.Definition{}
	def.Spec.Compose.Services = map[string]definition.Service{
		"api":    {Volumes: []definition.Volume{{Name: "data", Target: "/data"}}},
		"worker": {Volumes: []definition.Volume{{Name: "data", Target: "/data"}, {Name: "cache", Target: "/c"}}},
	}
	vols := []reconciledVol{{name: "shop_data", prevUID: 1000}, {name: "shop_cache", prevUID: 1000}}
	got := volumesOnlyFor(def, "shop", vols, []string{"worker"})
	if len(got) != 1 || got[0].name != "shop_cache" {
		t.Fatalf("only the volume no started service uses is rolled back: %+v", got)
	}
	if got := volumesOnlyFor(def, "shop", vols, []string{"api", "worker"}); len(got) != 2 {
		t.Fatalf("every user failed: both roll back: %+v", got)
	}
}
