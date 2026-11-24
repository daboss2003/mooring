package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/ops"
	"github.com/daboss2003/mooring/internal/opsalert"
	"github.com/daboss2003/mooring/internal/siem"
)

const (
	opsAlertEvery        = opsalert.PollInterval // how often the app /ops alerts are evaluated (30 s)
	opsAlertLogEvery     = 15 * time.Minute      // at most one log line per failure key in this long
	opsAlertProbeTimeout = 6 * time.Second       // one probe's bound, the service page's
	opsAlertRoundBudget  = 20 * time.Second      // no probe starts later than this into a round
	opsAlertMaxAlerts    = 256                   // alerts evaluated across all apps
	// opsAlertMaxSkip bounds a failing endpoint's backoff: it is tried at least every 20 rounds (10 min).
	opsAlertMaxSkip = int(10*time.Minute/opsAlertEvery) - 1
	opsAlertLogList = 20 // interface names listed in a cap log line
	// opsAlertMoveAfter is how many probes of one copy of a scaled service fail in a row before the
	// poller moves to another running copy.
	opsAlertMoveAfter = 3
)

// RunOpsAlerts evaluates the alerts apps declare on their own /ops values (mooring.yaml
// ops_interface.alerts) every 30 s and reports each firing through the detection reporter. Every
// ops_interface with alerts — per service, and the app-level one with the dashboard's ops settings —
// is probed here, one at a time, at the address of one running copy of its base_url's service. The
// history is in memory only. Serve starts it; it returns at once when detection is off (no reporter)
// or there is no definition store.
func (s *Server) RunOpsAlerts(ctx context.Context) {
	if s.detectReporter == nil || s.defStore == nil {
		return
	}
	p := s.newOpsAlertPoller()
	t := time.NewTicker(opsAlertEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.tick(ctx)
		}
	}
}

// opsAlertPoller is RunOpsAlerts' state. Its function fields are the server's own paths; tests replace
// them. Used by one goroutine only.
type opsAlertPoller struct {
	defs      func(context.Context) (map[string]*definition.Definition, map[string]error, error)
	replicas  func(context.Context) (map[string][]replica, bool) // running copies by svcKey; false: no list
	svcTarget func(project string, svc definition.Service) (ops.Target, bool)
	appTarget func(project string) (opsAlertTarget, bool, error)
	probe     func(ctx context.Context, project string, t ops.Target, adapter, mode string) *ops.Result
	report    siem.Reporter
	now       func() time.Time
	log       *slog.Logger
	eval      *opsalert.Evaluator
	logged    map[string]time.Time        // failure key → when it was last logged
	backoff   map[string]*opsAlertBackoff // interface key → its run of failed probes
	source    map[string]*opsAlertSource  // interface key → the container it is read from
	resume    map[string]string           // app → interface key its next turn starts at (none: its first)
	resumeApp string                      // the app the next round starts at ("": the first)
}

// opsAlertSource is the container an interface is read from and its run of failed probes.
type opsAlertSource struct {
	id    string // replica ID, or "ip:<address>" for a literal-IP base_url
	fails int    // probes of it failed in a row
}

// opsAlertIface is one ops_interface whose alerts are evaluated.
type opsAlertIface struct {
	key     string // app + "\x00" + service: the round's order (the app-level one sorts first)
	app     string
	service string // "" for the app-level ops_interface
	alerts  []definition.OpsAlert
	svc     definition.Service // per-service: the service, for its ops target
}

func (i opsAlertIface) name() string {
	if i.service == "" {
		return i.app + "/-"
	}
	return i.app + "/" + i.service
}

// opsAlertTarget is an ops endpoint with the adapter and mode it is probed with.
type opsAlertTarget struct {
	ops.Target
	adapter, mode string
}

type opsAlertBackoff struct {
	fails int // probes failed in a row
	skip  int // rounds left to skip before the next try
}

func (s *Server) newOpsAlertPoller() *opsAlertPoller {
	return &opsAlertPoller{
		defs:      s.defStore.CurrentEach,
		replicas:  func(ctx context.Context) (map[string][]replica, bool) { return discoverReplicas(ctx, s.docker, s.log) },
		svcTarget: s.serviceOpsTarget, // the service page's target: secret from the env store
		appTarget: s.appOpsTarget,
		probe:     s.probeOpsTarget,
		report:    s.detectReporter,
		now:       time.Now,
		log:       s.log,
		eval:      opsalert.NewEvaluator(),
		logged:    map[string]time.Time{},
		backoff:   map[string]*opsAlertBackoff{},
		source:    map[string]*opsAlertSource{},
	}
}

// appOpsTarget is the app-level ops endpoint as the dashboard's ops settings have it (the monitor probes
// the same one). ok is false when those settings turn it off or to mode basic.
func (s *Server) appOpsTarget(project string) (opsAlertTarget, bool, error) {
	if s.opsStore == nil {
		return opsAlertTarget{}, false, nil
	}
	cfg, ok, err := s.opsStore.Get(project)
	if err != nil || !ok || !cfg.Enabled || cfg.OpsMode == "basic" {
		return opsAlertTarget{}, false, err
	}
	return opsAlertTarget{
		Target:  ops.Target{BaseURL: cfg.BaseURL, SecretHeader: cfg.SecretHeader, Secret: cfg.Secret, BasePath: cfg.BasePath},
		adapter: cfg.Adapter, mode: cfg.OpsMode,
	}, true, nil
}

// probeOpsTarget probes one ops target the way the service page does, bounded to 6 s.
func (s *Server) probeOpsTarget(ctx context.Context, project string, t ops.Target, adapter, mode string) *ops.Result {
	if s.prober == nil {
		return nil
	}
	pctx, cancel := context.WithTimeout(ctx, opsAlertProbeTimeout)
	defer cancel()
	return s.prober.ProbeTarget(pctx, project, t, adapter, mode)
}

// tick reads every app's current definition, probes each ops_interface with alerts (within the round's
// time budget, skipping endpoints in backoff), reports what fires, and drops the state of alerts that no
// longer exist.
func (p *opsAlertPoller) tick(ctx context.Context) {
	start := p.now()
	defs, bad, err := p.defs(ctx)
	if err != nil {
		// Intentional: keep every alert's history — a failed read is not a removed alert.
		p.logFailure("definitions", "ops alerts: can't read the app definitions", "err", err)
		return
	}
	for _, app := range opsSortedKeys(bad) {
		p.logFailure("definition\x00"+app, "ops alerts: skipping an app whose definition can't be read", "app", app, "err", bad[app])
	}
	ifaces := p.interfaces(defs)
	keepAlert := map[opsalert.Key]bool{}
	keepIface := map[string]bool{}
	for _, i := range ifaces {
		keepIface[i.key] = true
		for _, a := range i.alerts {
			keepAlert[opsalert.Key{App: i.app, Service: i.service, Name: a.Name}] = true
		}
	}
	// Intentional: an app whose definition can't be read keeps its alerts' state, like a failed read of
	// all of them — it comes back when the definition does.
	p.eval.Retain(func(k opsalert.Key) bool { return keepAlert[k] || bad[k.App] != nil })
	keepKey := func(key string) bool {
		app, _, _ := strings.Cut(key, "\x00")
		return keepIface[key] || bad[app] != nil
	}
	for k := range p.backoff {
		if !keepKey(k) {
			delete(p.backoff, k)
		}
	}
	for k := range p.source {
		if !keepKey(k) {
			delete(p.source, k)
		}
	}

	p.probeRound(ctx, start, ifaces)

	for k, at := range p.logged {
		if p.now().Sub(at) >= opsAlertLogEvery {
			delete(p.logged, k)
		}
	}
}

// interfaces lists the ops_interfaces with alerts, sorted by key: per app at most
// MaxOpsAlertInterfaces (the app-level one first, then the services by name), and opsAlertMaxAlerts
// alerts in all (apps by name). The ones over a cap are logged and left out.
func (p *opsAlertPoller) interfaces(defs map[string]*definition.Definition) []opsAlertIface {
	var out, overTotal []opsAlertIface
	total := 0
	for _, app := range opsSortedKeys(defs) {
		def := defs[app]
		if def == nil {
			continue
		}
		var mine []opsAlertIface
		if oi := def.Spec.OpsInterface; hasOpsAlerts(oi) {
			mine = append(mine, opsAlertIface{key: app + "\x00", app: app, alerts: oi.Alerts})
		}
		for _, name := range opsSortedKeys(def.Spec.Compose.Services) {
			if svc := def.Spec.Compose.Services[name]; hasOpsAlerts(svc.OpsInterface) {
				mine = append(mine, opsAlertIface{key: app + "\x00" + name, app: app, service: name, alerts: svc.OpsInterface.Alerts, svc: svc})
			}
		}
		if len(mine) > definition.MaxOpsAlertInterfaces {
			// Validation refuses this; a definition stored before the limit can still carry it.
			p.logFailure("cap\x00"+app, "ops alerts: the app declares alerts on more ops interfaces than allowed; the rest are skipped",
				"app", app, "interfaces", len(mine), "max", definition.MaxOpsAlertInterfaces, "skipped", ifaceNames(mine[definition.MaxOpsAlertInterfaces:]))
			mine = mine[:definition.MaxOpsAlertInterfaces]
		}
		for _, i := range mine {
			if total+len(i.alerts) > opsAlertMaxAlerts {
				overTotal = append(overTotal, i)
				continue
			}
			total += len(i.alerts)
			out = append(out, i)
		}
	}
	if len(overTotal) > 0 {
		p.logFailure("cap", "ops alerts: more alerts than Mooring evaluates; the rest are skipped",
			"max", opsAlertMaxAlerts, "skipped_interfaces", len(overTotal), "skipped", ifaceNames(overTotal))
	}
	sort.Slice(out, func(a, b int) bool { return out[a].key < out[b].key })
	return out
}

// opsAlertTurns is one app's interfaces in a round, in the order they are probed, and the time its
// probes have taken so far.
type opsAlertTurns struct {
	app   string
	items []opsAlertIface
	next  int
	used  time.Duration
}

// probeRound probes the interfaces one at a time. Each app gets a fair share of the round's time: the
// next probe is always one of the app whose probes have taken the least time so far in the round
// (ties: the app the last round ran out of time at, then by name), so one app's slow endpoints don't
// take another app's turns. An app's interfaces go in order, starting where its last turn ran out of
// time, so that every interface gets its turn. No probe starts later than opsAlertRoundBudget into the
// round; an interface in backoff uses up one of its skipped rounds instead.
func (p *opsAlertPoller) probeRound(ctx context.Context, start time.Time, ifaces []opsAlertIface) {
	apps := p.roundTurns(ifaces)
	p.resume, p.resumeApp = nil, ""
	var copies map[string][]replica
	listed, listOK := false, false
	list := func() (map[string][]replica, bool) {
		if !listed {
			copies, listOK = p.replicas(ctx)
			listed = true
		}
		return copies, listOK
	}
	for {
		if ctx.Err() != nil {
			return
		}
		var q *opsAlertTurns
		for _, a := range apps {
			if a.next < len(a.items) && (q == nil || a.used < q.used) {
				q = a
			}
		}
		if q == nil {
			return // every interface had its turn
		}
		if p.now().Sub(start) >= opsAlertRoundBudget {
			p.resumeApp, p.resume = q.app, map[string]string{}
			left := 0
			for _, a := range apps {
				if a.next < len(a.items) {
					p.resume[a.app] = a.items[a.next].key
					left += len(a.items) - a.next
				}
			}
			p.logFailure("budget", "ops alerts: a round of probes ran out of time; the rest are probed first in the next round",
				"left", left, "budget", opsAlertRoundBudget)
			return
		}
		i := q.items[q.next]
		q.next++
		if b := p.backoff[i.key]; b != nil && b.skip > 0 {
			b.skip--
			continue
		}
		began := p.now()
		p.sample(ctx, i, list)
		q.used += p.now().Sub(began)
	}
}

// roundTurns groups the interfaces (sorted by key) by app: the apps from the one the last round ran out
// of time at, then by name around; each app's interfaces from where its last turn stopped, around.
func (p *opsAlertPoller) roundTurns(ifaces []opsAlertIface) []*opsAlertTurns {
	var apps []*opsAlertTurns
	for _, i := range ifaces {
		if len(apps) == 0 || apps[len(apps)-1].app != i.app {
			apps = append(apps, &opsAlertTurns{app: i.app})
		}
		a := apps[len(apps)-1]
		a.items = append(a.items, i)
	}
	for _, a := range apps {
		if from, ok := p.resume[a.app]; ok {
			n := sort.Search(len(a.items), func(k int) bool { return a.items[k].key >= from }) % len(a.items)
			a.items = append(a.items[n:len(a.items):len(a.items)], a.items[:n]...)
		}
	}
	n := sort.Search(len(apps), func(k int) bool { return apps[k].app >= p.resumeApp }) % max(len(apps), 1)
	return append(apps[n:len(apps):len(apps)], apps[:n]...)
}

// sample probes one interface and samples its alerts.
func (p *opsAlertPoller) sample(ctx context.Context, i opsAlertIface, list func() (map[string][]replica, bool)) {
	var t opsAlertTarget
	if i.service == "" {
		var ok bool
		var err error
		if t, ok, err = p.appTarget(i.app); err != nil {
			p.logFailure(i.key, "ops alerts: can't read the app's ops settings", "interface", i.name(), "err", err)
			return
		} else if !ok {
			return // off or mode basic in the dashboard's ops settings: nothing is read
		}
	} else {
		st, ok := p.svcTarget(i.app, i.svc)
		if !ok {
			return // mode basic: nothing is read
		}
		t = opsAlertTarget{Target: st, adapter: i.svc.OpsInterface.Adapter, mode: i.svc.OpsInterface.Mode}
	}
	src, dial, err := p.locate(i, t.BaseURL, list)
	if err != nil {
		p.logFailure(i.key, "ops alerts: ops endpoint not reachable", "interface", i.name(), "err", err)
		return
	}
	cur := p.source[i.key]
	if cur == nil || cur.id != src {
		cur = &opsAlertSource{id: src}
		p.source[i.key] = cur
	}
	t.BaseURL = dial
	res := p.probe(ctx, i.app, t.Target, t.adapter, t.mode)
	at := p.now()
	if res == nil {
		return // mode basic, or no prober: nothing is read
	}
	if res.Mode != ops.RICH {
		cur.fails++
		p.failed(i.key)
		p.logFailure(i.key, "ops alerts: ops probe failed", "interface", i.name(), "err", res.Err)
		return
	}
	cur.fails = 0
	delete(p.backoff, i.key)
	p.observe(i, src, res, at)
}

// locate picks the container a probe of base reaches and returns it (the readings' source) with the
// base URL that dials it. A literal-IP host is dialed as it is. A service name is the copy the
// interface is read from while it runs (so a scale-up doesn't move the poller) — unless its last
// opsAlertMoveAfter probes failed and another copy runs — else the running copy with the lowest
// address (ServiceIP's choice for the service page), among the others when moving off a failing one.
func (p *opsAlertPoller) locate(i opsAlertIface, base string, list func() (map[string][]replica, bool)) (src, dial string, err error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return "", "", errors.New("bad base_url")
	}
	host := u.Hostname()
	if net.ParseIP(host) != nil {
		return "ip:" + host, base, nil
	}
	copies, ok := list()
	if !ok {
		return "", "", errors.New("can't list the running containers (socket-proxy down?)")
	}
	running := copies[svcKey(i.app, host)]
	if len(running) == 0 {
		return "", "", fmt.Errorf("service %q has no running copy", host)
	}
	pick, found, avoid := replica{}, false, ""
	if cur := p.source[i.key]; cur != nil {
		for _, c := range running {
			if c.ID == cur.id {
				pick, found = c, true
				break
			}
		}
		// Intentional (owner decision): a copy whose probes keep failing while others run is left
		// for the lowest-address other copy; the move starts that interface's history again, as any
		// change of copy does. The endpoint's backoff is not reset by the move.
		if found && cur.fails >= opsAlertMoveAfter && len(running) > 1 {
			found, avoid = false, cur.id
		}
	}
	if !found {
		for _, c := range running {
			if c.ID != avoid && (!found || c.IP < pick.IP) {
				pick, found = c, true
			}
		}
	}
	if port := u.Port(); port != "" {
		u.Host = net.JoinHostPort(pick.IP, port)
	} else if strings.Contains(pick.IP, ":") {
		u.Host = "[" + pick.IP + "]"
	} else {
		u.Host = pick.IP
	}
	return pick.ID, u.String(), nil
}

// failed records a failed probe: the endpoint skips the next 0, 1, 3, 7 … rounds (tried 1, 2, 4, 8 …
// rounds apart), at most opsAlertMaxSkip.
func (p *opsAlertPoller) failed(key string) {
	b := p.backoff[key]
	if b == nil {
		b = &opsAlertBackoff{}
		p.backoff[key] = b
	}
	b.fails++
	b.skip = min(1<<min(b.fails-1, 30)-1, opsAlertMaxSkip)
}

func (p *opsAlertPoller) observe(i opsAlertIface, src string, res *ops.Result, at time.Time) {
	for _, da := range i.alerts {
		a := opsalert.FromDefinition(da)
		v, ok := opsalert.Value(res, a.Metric)
		if !ok {
			continue // the endpoint didn't report this value (or not as a number): no sample
		}
		k := opsalert.Key{App: i.app, Service: i.service, Name: a.Name}
		if r, fire := p.eval.Observe(k, a, src, at, v); fire {
			// siem.Reporter doesn't say whether it took the detection: when the engine's report queue
			// is full the report is lost, and this run's next one follows after the repeat interval.
			p.report.Report(opsDetection(k, a, r))
		}
	}
}

// opsDetection is the detection for one report: rule "ops:<app>/<service>/<name>" ("-" for the app-level
// interface), keyed by the service ("app" for the app-level interface).
func opsDetection(k opsalert.Key, a opsalert.Alert, r opsalert.Report) siem.Detection {
	svcPart, key := k.Service, k.Service
	if k.Service == "" {
		svcPart, key = "-", "app"
	}
	return siem.Detection{
		Source:   siem.DetectionOps,
		RuleID:   "ops:" + k.App + "/" + svcPart + "/" + k.Name,
		RuleName: k.Name,
		Severity: a.Severity,
		Key:      key,
		App:      k.App,
		Service:  k.Service,
		First:    r.First,
		Last:     r.Last,
		// Intentional: 1, not the reports so far in the run — the engine adds each report's count to
		// the detection a report within the hour updates, so the stored count is the number of reports.
		Count:   1,
		Summary: r.Summary,
	}
}

func (p *opsAlertPoller) logFailure(key, msg string, args ...any) {
	now := p.now()
	if at, ok := p.logged[key]; ok && now.Sub(at) < opsAlertLogEvery {
		return
	}
	p.logged[key] = now
	p.log.Warn(msg, args...)
}

func hasOpsAlerts(oi *definition.OpsInterface) bool {
	return oi != nil && oi.Enabled && len(oi.Alerts) > 0
}

// ifaceNames lists interfaces for a log line: at most opsAlertLogList names, then how many more.
func ifaceNames(is []opsAlertIface) string {
	var b strings.Builder
	for n, i := range is {
		if n == opsAlertLogList {
			fmt.Fprintf(&b, " (+%d more)", len(is)-n)
			break
		}
		if n > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(i.name())
	}
	return b.String()
}

func opsSortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
