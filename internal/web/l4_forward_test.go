package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/compose"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/l4"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/scale"
)

// kernelYAML serves DNS (53/udp + 53/tcp) and DoT passthrough (853/tcp) with forward: kernel.
const kernelYAML = `apiVersion: mooring/v1
kind: App
metadata: {slug: app}
spec:
  compose:
    source: generated
    services:
      dns:
        image: coredns/coredns:1.11.1
  edge:
    l4_routes:
      - { listen: 53,  protocol: udp, service: dns, port: 5353, forward: kernel }
      - { listen: 53,  protocol: tcp, service: dns, port: 5353, forward: kernel }
      - { listen: 853, protocol: tcp, service: dns, port: 8853, tls: passthrough, forward: kernel }
`

const kernelPublishes = "        ports:\n" +
	"            - 0.0.0.0:53:5353/udp\n" +
	"            - 0.0.0.0:53:5353/tcp\n" +
	"            - 0.0.0.0:853:8853/tcp\n"

const l4OffWarning = "warning: edge.l4_routes are not served on this server: the L4 load balancer is off (it needs edge.mode: managed, edge.l4_enabled: true and nginx with the stream module)"

func parseKernelDef(t *testing.T) *definition.Definition {
	t.Helper()
	d, err := definition.Parse([]byte(kernelYAML))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// With L4 off the compose is generated from a copy without l4_routes; the caller's definition is never
// changed. With L4 on (or no routes) it is the definition itself.
func TestComposeDef(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	def := parseKernelDef(t)
	got, dropped := e.srv.composeDef(def)
	if !dropped || got == def || len(got.Spec.Edge.L4Routes) != 0 {
		t.Fatalf("L4 off: dropped=%v same=%v routes=%d", dropped, got == def, len(got.Spec.Edge.L4Routes))
	}
	if len(def.Spec.Edge.L4Routes) != 3 {
		t.Fatal("composeDef must not change the caller's definition")
	}
	if got.Metadata != def.Metadata || len(got.Spec.Compose.Services) != 1 {
		t.Errorf("the copy must keep everything else: %+v", got)
	}
	plain, err := definition.Parse([]byte(repoMooringYAML))
	if err != nil {
		t.Fatal(err)
	}
	if got, dropped := e.srv.composeDef(plain); dropped || got != plain {
		t.Error("no l4_routes: nothing to drop")
	}
	e.srv.l4Routes = l4.NewRouteStore(e.srv.db)
	if got, dropped := e.srv.composeDef(def); dropped || got != def {
		t.Error("L4 on: the definition is used as is")
	}
}

// L4 off: the deploy's compose publishes nothing for a kernel route, and the log says the routes aren't
// served. L4 on: the target service publishes each kernel route on 0.0.0.0.
func TestDeployKernelRouteCompose(t *testing.T) {
	for _, l4On := range []bool{false, true} {
		e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
		e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
		if l4On {
			e.srv.l4Routes = l4.NewRouteStore(e.srv.db)
		}
		slug := "shop"
		sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), kernelYAML)
		cfg := configureRepo(t, e, slug, sha)
		var lines []string
		_, err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, false, func(l string) { lines = append(lines, l) })
		if err == nil || !strings.Contains(err.Error(), "up failed") {
			t.Fatalf("l4=%v: expected up to fail (write plane disabled) after generation, got %v", l4On, err)
		}
		out, rerr := os.ReadFile(filepath.Join(e.srv.appRunDir(slug), "docker-compose.yml"))
		if rerr != nil {
			t.Fatal(rerr)
		}
		log := strings.Join(lines, "\n")
		if l4On {
			if !strings.Contains(string(out), kernelPublishes) {
				t.Errorf("L4 on: kernel routes must be published:\n%s", out)
			}
			if strings.Contains(log, l4OffWarning) {
				t.Errorf("L4 on: no warning expected:\n%s", log)
			}
			continue
		}
		if strings.Contains(string(out), "ports") || strings.Contains(string(out), "0.0.0.0") {
			t.Errorf("L4 off: a kernel route must publish nothing:\n%s", out)
		}
		if strings.Count(log, l4OffWarning) != 1 {
			t.Errorf("L4 off: the deploy must warn once:\n%s", log)
		}
	}
}

// A listener another app owns — as an L4 route, or under one of this app's own published host ports —
// fails the deploy before the compose is generated or docker is called.
func TestDeployL4CollisionRefusedBeforeDocker(t *testing.T) {
	cases := map[string]struct {
		yaml  string
		owner []l4.Route
		want  string
	}{
		"kernel route on another app's listener": {
			yaml:  kernelYAML,
			owner: []l4.Route{{Listen: 53, Protocol: "udp", Service: "resolver", Port: 53}},
			want:  `l4 route 53/udp is already in use by app "other"`,
		},
		"proxy route on another app's kernel listener": {
			yaml:  strings.ReplaceAll(kernelYAML, ", forward: kernel", ""),
			owner: []l4.Route{{Listen: 853, Protocol: "tcp", Service: "dot", Port: 853, Forward: "kernel"}},
			want:  `l4 route 853/tcp is already in use by app "other"`,
		},
		"published host port on another app's listener": {
			yaml:  repoMooringYAML + "        ports:\n          - { internal: 8853, publish: true, public: true, published: 853, protocol: tcp }\n",
			owner: []l4.Route{{Listen: 853, Protocol: "tcp", Service: "dot", Port: 853}},
			want:  `published host port 853/tcp is already in use by an l4_route of app "other"`,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := newPacedServer(t, map[string]string{"dns": "coredns/coredns:1.11.1", "web": "nginx:1.27"}, nil)
			p.e.srv.l4Routes = l4.NewRouteStore(p.e.srv.db)
			if err := p.e.srv.l4Routes.ReplaceProject(context.Background(), "other", tc.owner); err != nil {
				t.Fatal(err)
			}
			p.connect(t, tc.yaml)
			_, err := p.deploy(false)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v\n%s", tc.want, err, p.output())
			}
			if got, _, _ := p.e.srv.gitStore.Get("shop"); got.UpdateState != "update_blocked" {
				t.Errorf("state = %q, want update_blocked", got.UpdateState)
			}
			if _, serr := os.Stat(filepath.Join(p.e.srv.appRunDir("shop"), "docker-compose.yml")); serr == nil {
				t.Error("the refusal must come before the compose is generated")
			}
			if calls := p.docker.calls(); len(calls) != 0 {
				t.Errorf("no docker call may run before the refusal: %v", calls)
			}
			if rs, _ := p.e.srv.l4Routes.List(); len(rs) != 1 || rs[0].AppID != "other" {
				t.Errorf("the owner's route must be untouched: %+v", rs)
			}
		})
	}
}

// A full deploy with L4 on stores the app's routes with their forward mode, so the L4 render skips the
// kernel ones.
func TestDeployStoresKernelRoutes(t *testing.T) {
	p := newPacedServer(t, map[string]string{"dns": "coredns/coredns:1.11.1"}, nil)
	p.e.srv.l4Routes = l4.NewRouteStore(p.e.srv.db)
	p.connect(t, kernelYAML)
	if _, err := p.deploy(false); err != nil {
		t.Fatalf("deploy: %v\n%s", err, p.output())
	}
	rs, err := p.e.srv.l4Routes.List()
	if err != nil || len(rs) != 3 {
		t.Fatalf("stored routes: %+v %v", rs, err)
	}
	for _, r := range rs {
		if r.AppID != "shop" || r.Forward != "kernel" {
			t.Errorf("stored route %+v, want app shop forward kernel", r)
		}
	}
	for i := range rs {
		rs[i].Pool = []string{"172.18.0.5:5353"}
	}
	if out, err := l4.Render(rs); err != nil || strings.Contains(out, "listen") {
		t.Errorf("kernel routes must render no listener: %v\n%s", err, out)
	}
}

// The compose a failed release puts back is generated like a deploy's: no kernel publish while L4 is off.
func TestDeployedComposeHonoursL4Off(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.defStore = definition.NewStore(e.srv.db, make([]byte, 32))
	def := parseKernelDef(t)
	def.Metadata.Slug = "shop"
	if _, err := e.srv.defStore.SaveCanonical(context.Background(), def, "git deploy", strings.Repeat("ab", 20)); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	b, why := e.srv.deployedCompose("shop", dir, compose.Env{}, func(string) {})
	if why != "" {
		t.Fatal(why)
	}
	if strings.Contains(string(b), "0.0.0.0") {
		t.Errorf("L4 off: the put-back compose must not publish kernel routes:\n%s", b)
	}
	e.srv.l4Routes = l4.NewRouteStore(e.srv.db)
	if b, why = e.srv.deployedCompose("shop", dir, compose.Env{}, func(string) {}); why != "" || !strings.Contains(string(b), kernelPublishes) {
		t.Errorf("L4 on: the put-back compose publishes kernel routes (%s):\n%s", why, b)
	}
}

// A PR preview strips l4_routes (and host publishes), so a fork's kernel route never publishes a port.
func TestPreviewNeverPublishesKernelRoute(t *testing.T) {
	def := parseKernelDef(t)
	svc := def.Spec.Compose.Services["dns"]
	svc.Ports = []definition.Port{{Internal: 5353, Publish: true, Public: true, Published: 5353, Protocol: "udp"}}
	def.Spec.Compose.Services["dns"] = svc
	applyPreviewPrefix(def, "shop-pr9", "")
	out, err := definition.ComposeBytes(def)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "ports") {
		t.Errorf("a preview must publish nothing:\n%s", out)
	}
}

// A policy left enabled for a kernel-route target is disabled when the definition is applied: the
// service runs one copy.
func TestApplyScalingDisablesALeftoverPolicyOfAKernelTarget(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.scaling = scale.NewStore(e.srv.db)
	ctx := context.Background()
	for _, svc := range []string{"dns", "web"} {
		if err := e.srv.scaling.SavePolicy(ctx, scale.Key{App: "shop", Service: svc}, enabledTestPolicy()); err != nil {
			t.Fatal(err)
		}
	}
	def, err := definition.Parse([]byte(strings.Replace(kernelYAML, "  edge:\n", "      web:\n        image: nginx:1.27\n  edge:\n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.applyScaling(ctx, "shop", def); err != nil {
		t.Fatal(err)
	}
	enabled, err := e.srv.scaling.EnabledPolicies()
	if err != nil {
		t.Fatal(err)
	}
	if _, on := enabled[scale.Key{App: "shop", Service: "dns"}]; on {
		t.Error("a kernel-route target must not stay autoscaled")
	}
	if _, on := enabled[scale.Key{App: "shop", Service: "web"}]; !on {
		t.Error("another service keeps its dashboard policy")
	}
}

// proxyYAML is kernelYAML served through the L4 load balancer.
var proxyYAML = strings.ReplaceAll(kernelYAML, ", forward: kernel", "")

var dnsCopy = strings.Repeat("d5", 32)

// l4SwitchEnv is the app "shop" (one dns copy running an older config) with L4 on: its stored L4 routes come
// from stored ("" = none), every L4 reconcile is recorded with what had happened by then, and the port probe
// is played by free.
type l4SwitchEnv struct {
	*pacedDeployEnv
	t   *testing.T
	mu  sync.Mutex
	rec []reconcileSeen
	// reconcileErr fails the next reconcile when set (then clears).
	reconcileErr error
	probes       []string
}

// reconcileSeen is one L4 reconcile: the `up` calls docker had run before it and how many of shop's stored
// routes were kernel routes at that moment.
type reconcileSeen struct{ ups, kernel int }

func newL4SwitchEnv(t *testing.T, stored string, free func(n int, port int, proto string) bool) *l4SwitchEnv {
	t.Helper()
	p := newPacedServer(t, map[string]string{"dns": "coredns/coredns:1.11.1"}, []monitor.ServiceStatus{
		{Service: "dns", ContainerID: dnsCopy, State: "running", Health: "healthy", Inspected: true, ConfigHash: "old", ImageID: testImageID("coredns/coredns:1.11.1")},
	})
	e := &l4SwitchEnv{pacedDeployEnv: p, t: t}
	p.e.srv.l4Routes = l4.NewRouteStore(p.e.srv.db)
	if stored != "" {
		d, err := definition.Parse([]byte(stored))
		if err != nil {
			t.Fatal(err)
		}
		if err := p.e.srv.l4Routes.ReplaceProject(context.Background(), "shop", l4RoutesOf(d)); err != nil {
			t.Fatal(err)
		}
	}
	p.e.srv.l4Reconcile = func(context.Context) error {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.rec = append(e.rec, reconcileSeen{ups: e.upCalls(), kernel: e.storedKernel()})
		if err := e.reconcileErr; err != nil {
			e.reconcileErr = nil
			return err
		}
		return nil
	}
	oldFree, oldWait, oldPoll := l4PortFree, l4SwitchWait, l4SwitchPoll
	t.Cleanup(func() { l4PortFree, l4SwitchWait, l4SwitchPoll = oldFree, oldWait, oldPoll })
	l4SwitchPoll = 5 * time.Millisecond
	l4PortFree = func(port int, proto string) bool {
		e.mu.Lock()
		e.probes = append(e.probes, fmt.Sprintf("%d/%s", port, proto))
		n := len(e.probes)
		e.mu.Unlock()
		return free(n, port, proto)
	}
	return e
}

// upCalls counts the `up` calls docker ran, per-service and whole-project alike.
func (e *l4SwitchEnv) upCalls() int {
	n := 0
	for _, c := range e.docker.calls() {
		if strings.Contains(" "+c+" ", " up ") {
			n++
		}
	}
	return n
}

func (e *l4SwitchEnv) storedKernel() int {
	rs, err := e.e.srv.l4Routes.List()
	if err != nil {
		e.t.Fatal(err)
	}
	n := 0
	for _, r := range rs {
		if r.AppID == "shop" && r.Kernel() {
			n++
		}
	}
	return n
}

func (e *l4SwitchEnv) reconciles() []reconcileSeen {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.rec)
}

func (e *l4SwitchEnv) probed() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.probes)
}

// Switching proxy routes to kernel in one deploy: before the first `up` (paced or all at once) the new routes
// are stored, the L4 LB is reconciled so nginx lets go of the ports, and the deploy waits until each port
// binds.
func TestKernelSwitchReleasesTheListenerBeforeTheFirstUp(t *testing.T) {
	for _, atOnce := range []bool{false, true} {
		t.Run(fmt.Sprintf("atOnce=%v", atOnce), func(t *testing.T) {
			e := newL4SwitchEnv(t, proxyYAML, func(n, _ int, _ string) bool { return n > 2 }) // busy twice, then free
			e.connect(t, kernelYAML)
			if _, err := e.deploy(atOnce); err != nil {
				t.Fatalf("deploy: %v\n%s", err, e.output())
			}
			rec := e.reconciles()
			if len(rec) == 0 || rec[0].ups != 0 || rec[0].kernel != 3 {
				t.Fatalf("the kernel routes must be stored and the LB reconciled before any up, got %+v", rec)
			}
			if e.upCalls() == 0 {
				t.Fatal("the service must still be started")
			}
			probes := e.probed()
			for _, want := range []string{"53/udp", "53/tcp", "853/tcp"} {
				if !slices.Contains(probes, want) {
					t.Errorf("port %s must be probed, probes %v", want, probes)
				}
			}
			if len(probes) < 5 {
				t.Errorf("a busy port must be probed again until it is free, probes %v", probes)
			}
			if !strings.Contains(e.output(), "53/udp, 53/tcp, 853/tcp") {
				t.Errorf("the deploy log must name the moving listeners:\n%s", e.output())
			}
		})
	}
}

// A port still held when the wait ends refuses the deploy before any `up`, and the app's previous routes are
// put back so the L4 LB serves the running copy again.
func TestKernelSwitchTimeoutRefusesBeforeAnyUp(t *testing.T) {
	e := newL4SwitchEnv(t, proxyYAML, func(_, port int, proto string) bool { return !(port == 53 && proto == "udp") })
	l4SwitchWait = 100 * time.Millisecond
	// Another app's route is never part of shop's previous set.
	if err := e.e.srv.l4Routes.ReplaceProject(context.Background(), "other", []l4.Route{{Listen: 5300, Protocol: "udp", Service: "x", Port: 53}}); err != nil {
		t.Fatal(err)
	}
	e.connect(t, kernelYAML)
	_, err := e.deploy(false)
	if err == nil || !strings.Contains(err.Error(), "port 53/udp is still held after the L4 load balancer released it") {
		t.Fatalf("want the still-held refusal, got %v\n%s", err, e.output())
	}
	if n := e.upCalls(); n != 0 {
		t.Errorf("no up may run, got %d:\n%s", n, strings.Join(e.docker.calls(), "\n"))
	}
	if got, _, _ := e.e.srv.gitStore.Get("shop"); got.UpdateState != "update_blocked" {
		t.Errorf("state = %q, want update_blocked", got.UpdateState)
	}
	if n := e.storedKernel(); n != 0 {
		t.Errorf("the previous proxy routes must be put back, %d kernel routes stored", n)
	}
	owners := map[string]int{}
	rs, _ := e.e.srv.l4Routes.List()
	for _, r := range rs {
		owners[r.AppID]++
	}
	if owners["shop"] != 3 || owners["other"] != 1 {
		t.Errorf("after the put-back shop owns its 3 routes and other its 1, got %v", owners)
	}
	if rec := e.reconciles(); len(rec) != 2 || rec[1].kernel != 0 {
		t.Errorf("the LB must be reconciled again with the previous routes, got %+v", rec)
	}
}

// A failed reconcile refuses the deploy before any `up` and puts the previous routes back.
func TestKernelSwitchReconcileFailureRefuses(t *testing.T) {
	e := newL4SwitchEnv(t, proxyYAML, func(int, int, string) bool { return true })
	e.reconcileErr = errors.New("nginx -t failed")
	e.connect(t, kernelYAML)
	_, err := e.deploy(false)
	if err == nil || !strings.Contains(err.Error(), "nginx -t failed") {
		t.Fatalf("want the reconcile error, got %v\n%s", err, e.output())
	}
	if n := e.upCalls(); n != 0 {
		t.Errorf("no up may run, got %d", n)
	}
	if n := e.storedKernel(); n != 0 {
		t.Errorf("the previous proxy routes must be put back, %d kernel routes stored", n)
	}
	if p := e.probed(); len(p) != 0 {
		t.Errorf("no port is waited for after a failed reconcile: %v", p)
	}
}

// Without a proxy → kernel switch the routes are stored only after the rollout, as before, and no port is
// probed.
func TestNoKernelSwitchStoresNothingEarly(t *testing.T) {
	cases := map[string]struct{ stored, deploy string }{
		"proxy stays proxy":         {proxyYAML, proxyYAML},
		"kernel stays kernel":       {kernelYAML, kernelYAML},
		"new kernel route":          {"", kernelYAML},
		"kernel back to proxy":      {kernelYAML, proxyYAML},
		"proxy on another listener": {strings.NewReplacer("listen: 53,", "listen: 54,", "listen: 853,", "listen: 854,").Replace(proxyYAML), kernelYAML},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newL4SwitchEnv(t, tc.stored, func(int, int, string) bool { return true })
			e.connect(t, tc.deploy)
			if _, err := e.deploy(false); err != nil {
				t.Fatalf("deploy: %v\n%s", err, e.output())
			}
			rec := e.reconciles()
			if len(rec) == 0 {
				t.Fatal("the routes must still be applied after the rollout")
			}
			for _, r := range rec {
				if r.ups == 0 {
					t.Errorf("no reconcile may run before the rollout: %+v", rec)
				}
			}
			if p := e.probed(); len(p) != 0 {
				t.Errorf("no port may be probed: %v", p)
			}
		})
	}
}

// The real probe: a port another socket holds is busy, and free once it is closed.
func TestProbePortFree(t *testing.T) {
	l, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Skipf("tcp4 listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if probePortFree(port, "tcp") {
		t.Error("a held tcp port must be busy")
	}
	l.Close()
	if !probePortFree(port, "tcp") {
		t.Error("a released tcp port must be free")
	}
	pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Skipf("udp4 listen: %v", err)
	}
	uport := pc.LocalAddr().(*net.UDPAddr).Port
	if probePortFree(uport, "udp") {
		t.Error("a held udp port must be busy")
	}
	pc.Close()
	if !probePortFree(uport, "udp") {
		t.Error("a released udp port must be free")
	}
}

// alphaYAML: another app whose dns service publishes 53/udp itself; publishes is its ports block.
func alphaYAML(publishes string) string {
	return `apiVersion: mooring/v1
kind: App
metadata: {slug: alpha}
spec:
  compose:
    source: generated
    services:
      dns:
        image: coredns/coredns:1.11.1
        ports:
` + publishes
}

const alphaPublishes53 = "          - { internal: 5353, publish: true, public: true, published: 53, protocol: udp }\n"

// Abuse: an l4_route (kernel or proxy) on a port another app's service publishes itself is refused before
// any docker call, and the other app is untouched. Another port, or the app's own earlier publish, is fine.
func TestL4RouteOnAnotherAppsPublishedPortRefused(t *testing.T) {
	const on53 = `l4 route 53/udp is already in use by app "alpha", which publishes it on service "dns"`
	cases := map[string]struct {
		owner, ownerSlug, deploy string
		want                     string // "" = not refused
	}{
		"kernel route": {alphaYAML(alphaPublishes53), "alpha", kernelYAML, on53},
		"proxy route":  {alphaYAML(alphaPublishes53), "alpha", proxyYAML, on53},
		"no protocol is tcp": {alphaYAML("          - { internal: 8853, publish: true, public: true, published: 853 }\n"), "alpha", kernelYAML,
			`l4 route 853/tcp is already in use by app "alpha", which publishes it on service "dns"`},
		"unrelated port": {alphaYAML("          - { internal: 8080, publish: true }\n"), "alpha", kernelYAML, ""},
		"same app":       {strings.Replace(alphaYAML(alphaPublishes53), "slug: alpha", "slug: shop", 1), "shop", kernelYAML, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := newPacedServer(t, map[string]string{"dns": "coredns/coredns:1.11.1"}, nil)
			p.e.srv.l4Routes = l4.NewRouteStore(p.e.srv.db)
			p.e.srv.defStore = definition.NewStore(p.e.srv.db, make([]byte, 32))
			owner, err := definition.Parse([]byte(tc.owner))
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if _, err := p.e.srv.defStore.SaveCanonical(ctx, owner, "git deploy: abc1234", strings.Repeat("ab", 20)); err != nil {
				t.Fatal(err)
			}
			before, _ := p.e.srv.defStore.List(tc.ownerSlug)
			p.connect(t, tc.deploy)
			_, err = p.deploy(false)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("deploy: %v\n%s", err, p.output())
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
			if calls := p.docker.calls(); len(calls) != 0 {
				t.Errorf("no docker call may run before the refusal: %v", calls)
			}
			if got, _, _ := p.e.srv.gitStore.Get("shop"); got.UpdateState != "update_blocked" {
				t.Errorf("state = %q, want update_blocked", got.UpdateState)
			}
			after, _ := p.e.srv.defStore.List("alpha")
			if len(after) != len(before) {
				t.Errorf("alpha's definition must be untouched: %d → %d versions", len(before), len(after))
			}
			if cur, err := p.e.srv.defStore.Current("alpha"); err != nil || cur.Spec.Compose.Services["dns"].Ports[0].Published == 0 {
				t.Errorf("alpha's definition changed: %+v %v", cur, err)
			}
			if rs, _ := p.e.srv.l4Routes.List(); len(rs) != 0 {
				t.Errorf("no route may be stored: %+v", rs)
			}
		})
	}
}
