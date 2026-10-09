package web

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/selfheal"
)

// A git deploy is paced whenever the start gate is enabled: instead of one whole-project `up`, the new
// version starts one service at a time through a rollout (rollout.go), dependencies first.
//   - A service whose containers all run its current compose definition and image, and whose managed
//     files didn't change, is left running untouched — when it runs the copies the deploy would give it:
//     an autoscaled one keeps every copy, one with a fixed `replicas` count needs exactly that many, and
//     any other service exactly one.
//   - Every other service gets its own `up -d --no-deps --no-build [--force-recreate] -- <svc>`. That
//     also starts a service the operator stopped (its hold is released once it started), and brings a
//     scaled service back as one fresh copy (no --scale) that the autoscaler then adds to. A service with
//     a fixed `replicas` count gets all its copies in that one step (compose `scale:`), replaced together.
//   - A service that fails to start or to settle is reported and the rest still ship: the deploy ends
//     "deployed with problems" and raises a WARNING alert.
//   - First, containers of services no longer in the definition are removed (what the whole-project
//     `up --remove-orphans` did).
// A manual deploy or rollback run "all at once" (now=1) keeps the whole-project `up`.

// deployRollout is a paced deploy's input from deployRepoApp.
type deployRollout struct {
	slug    string
	def     *definition.Definition
	base    dockerexec.Job // the deploy's compose target: Project, Dir, ConfigFiles, EnvFile
	changed []string       // services whose managed files changed: force-recreated
}

// deployRolloutResult is what a paced deploy's rollout did.
type deployRolloutResult struct {
	steps    []string // the services it started or tried to, in order
	problems []rolloutProblem
}

// deployStartFailed reports whether a rollout problem is a failed start command ("start failed: …"), not a
// service that started but didn't settle.
func deployStartFailed(p rolloutProblem) bool { return strings.HasPrefix(p.Reason, "start failed") }

// failedToStart returns the services among svcs whose start command failed.
func (r deployRolloutResult) failedToStart(svcs []string) []string {
	failed := map[string]bool{}
	for _, p := range r.problems {
		if deployStartFailed(p) {
			failed[p.Service] = true
		}
	}
	var out []string
	for _, svc := range svcs {
		if failed[svc] {
			out = append(out, svc)
		}
	}
	return out
}

// allFailed reports that the rollout had services to start and none of them started: nothing new is
// running, as after a failed whole-project `up`.
func (r deployRolloutResult) allFailed() bool {
	return len(r.steps) > 0 && len(r.failedToStart(r.steps)) == len(r.steps)
}

// runDeployRollout starts a deploy's services one at a time (see above). err is non-nil only when the
// rollout was cut short (ctx ended); the services it didn't reach were not started.
func (s *Server) runDeployRollout(ctx context.Context, d deployRollout, onLine func(string)) (deployRolloutResult, error) {
	sched := d.def.Spec.ScheduledServiceSet()
	var services []string
	for name := range d.def.Spec.Compose.Services {
		if !sched[name] { // a scheduled service only ever runs on its schedule
			services = append(services, name)
		}
	}
	sort.Strings(services)
	changed := make(map[string]bool, len(d.changed))
	for _, svc := range d.changed {
		changed[svc] = true
	}

	unchanged := s.unchangedServices(ctx, d, services, changed, onLine)
	var kept []string
	for _, name := range services {
		if unchanged[name] {
			kept = append(kept, name)
		}
	}
	if len(kept) > 0 {
		onLine("unchanged, left running: " + strings.Join(kept, ", "))
	}
	// A service left running unchanged runs the new version too, so the deploy releases its hold — once the
	// deploy has gone ahead (a deploy where nothing started changes nothing).
	releaseKept := func() {
		for _, name := range kept {
			s.releaseDeployHold(d.slug, name)
		}
	}

	steps := deployRolloutSteps(d.def, services, unchanged, changed, d.base, s.cfg.Server.StartGateSettings())
	var res deployRolloutResult
	var recreate []string
	for _, st := range steps {
		res.steps = append(res.steps, st.Service)
		if changed[st.Service] {
			recreate = append(recreate, st.Service)
		}
	}
	if len(steps) == 0 {
		onLine("nothing to start")
		releaseKept()
		return res, nil
	}
	onLine(fmt.Sprintf("starting %d service(s) one at a time: %s", len(steps), strings.Join(res.steps, ", ")))
	if len(recreate) > 0 {
		onLine("force-recreating (changed config/secret/cert): " + strings.Join(recreate, ", "))
	}
	bg := context.Background()
	var err error
	res.problems, err = s.runRollout(ctx, steps, rolloutOpts{
		App:      d.slug,
		OnLine:   onLine,
		Declared: declaredServiceSet(d.def), // the new definition's services, for the name-conflict cleanup
		Renew:    func() { s.renewExpectedDown(bg, d.slug) },
		Started: func(svc string) {
			s.releaseDeployHold(d.slug, svc)
			// Point the edge at the new containers now rather than at its next periodic refresh: the rest of
			// a paced rollout can take minutes.
			s.reconcileEdgeAfter(ctx)
		},
	})
	if err == nil && !res.allFailed() {
		releaseKept()
	}
	return res, err
}

// deployRolloutSteps lists a paced deploy's steps: every service that isn't unchanged, in dependency order
// (computed over all services, so a dependency chain through an unchanged service still holds), each started
// by its own `up -d --no-deps --no-build [--force-recreate] -- <svc>`.
func deployRolloutSteps(def *definition.Definition, services []string, unchanged, changed map[string]bool, base dockerexec.Job, gs config.StartGateSettings) []rolloutStep {
	deps := make(map[string][]string, len(services))
	for _, name := range services {
		deps[name] = def.Spec.Compose.Services[name].DependsOn
	}
	var steps []rolloutStep
	for _, name := range rolloutOrder(services, deps) {
		if unchanged[name] {
			continue
		}
		svc := def.Spec.Compose.Services[name]
		job := base
		job.Action = []string{"up", "-d", "--no-deps", "--no-build"}
		if changed[name] {
			job.Action = append(job.Action, "--force-recreate")
		}
		job.Service = name
		steps = append(steps, rolloutStep{
			Service:   name,
			Job:       job,
			Reap:      true,
			Deadline:  settleDeadline(svc.Healthcheck, gs.MaxSettle, gs.ServiceSettle),
			Notify:    svc.OnUnhealthy() == definition.OnUnhealthyNotify,
			Restarts:  restartPolicy(svc.Restart),
			StopGrace: stopGrace(svc.StopGracePeriod),
		})
	}
	return steps
}

// unchangedServices returns the services a paced deploy leaves running as they are (unchangedSet). When it
// can't read the compose hashes or a usable container view, every service is started.
func (s *Server) unchangedServices(ctx context.Context, d deployRollout, services []string, changed map[string]bool, onLine func(string)) map[string]bool {
	hashes, err := s.composeHashes(ctx, d.base)
	if err != nil {
		onLine("could not compare the running services with this deploy (compose config: " + err.Error() + "); starting every service")
		return nil
	}
	images := s.serviceImageIDs(ctx, d.slug, d.def, services)
	snap := s.deploySnapshot(ctx)
	if snap == nil || !snap.DockerOK || snap.ListFailed || snap.Truncated {
		onLine("could not compare the running services with this deploy (container view unavailable); starting every service")
		return nil
	}
	replicas := make(map[string]int, len(services))
	for _, name := range services {
		replicas[name] = declaredReplicas(d.def, name)
	}
	counts := deployCopyCounts(services, replicas, s.deployAutoscaled(d.slug, d.def))
	return unchangedSet(services, changed, hashes, images, counts, snap.AppByProject(d.slug))
}

// deployAutoscaled reports which services the autoscaler keeps the copy count of once the deploy's
// definition is applied: an enabled spec.scaling entry, or — for a service spec.scaling leaves out — an
// enabled policy in the scale store (applyScaling leaves those alone).
func (s *Server) deployAutoscaled(slug string, def *definition.Definition) map[string]bool {
	out := map[string]bool{}
	inDef := map[string]bool{}
	for _, sc := range def.Spec.Scaling {
		inDef[sc.Service] = true
		out[sc.Service] = sc.Enabled
	}
	if s.scaling == nil {
		return out
	}
	enabled, err := s.scaling.EnabledPolicies()
	if err != nil {
		// Intentional: when the store can't be read, every service spec.scaling leaves out and that has no
		// replicas counts as autoscaled (any copy count), so a dashboard-autoscaled service isn't cut to one
		// copy because of a read error — the count check then only catches a changed replicas.
		for name, svc := range def.Spec.Compose.Services {
			if !inDef[name] && svc.Replicas == 0 {
				out[name] = true
			}
		}
		return out
	}
	for k := range enabled {
		if k.App == slug && !inDef[k.Service] {
			out[k.Service] = true
		}
	}
	return out
}

// deployCopyCounts returns how many copies each service must run for a paced deploy to leave it as it is:
// its fixed `replicas` count; 0 (any number) when the autoscaler keeps its count; otherwise 1 — what the
// service's own `up` would converge it to, since its compose file then has no `scale:`.
func deployCopyCounts(services []string, replicas map[string]int, autoscaled map[string]bool) map[string]int {
	out := make(map[string]int, len(services))
	for _, name := range services {
		switch {
		case replicas[name] > 0:
			out[name] = replicas[name] // applyScaling disables a policy left over for it
		case autoscaled[name]:
			out[name] = 0
		default:
			out[name] = 1
		}
	}
	return out
}

// unchangedSet decides which services are unchanged. A service is unchanged when its managed files didn't
// change and it has at least one container, every one of them running, created from the service's current
// compose definition (its config-hash label equals `compose config --hash`) and running the service's
// current image — and, when counts[name] > 0, exactly that many. Anything missing — no hash, no image id,
// no container — counts as changed.
func unchangedSet(services []string, changed map[string]bool, hashes, images map[string]string, counts map[string]int, app *monitor.App) map[string]bool {
	out := map[string]bool{}
	if app == nil {
		return out
	}
	copies := map[string][]monitor.ServiceStatus{}
	for _, c := range app.Services {
		copies[c.Service] = append(copies[c.Service], c)
	}
	for _, name := range services {
		hash, image, cs := hashes[name], images[name], copies[name]
		if changed[name] || hash == "" || image == "" || len(cs) == 0 {
			continue
		}
		// Intentional: compose's config hash leaves out `scale`, so a changed or removed `replicas` alone
		// shows up only in the copy count.
		if n := counts[name]; n > 0 && len(cs) != n {
			continue
		}
		same := true
		for _, c := range cs {
			if !c.Running() || c.ConfigHash != hash || c.ImageID != image {
				same = false
				break
			}
		}
		if same {
			out[name] = true
		}
	}
	return out
}

var composeHashRe = regexp.MustCompile(`^[0-9a-f]{16,128}$`)

// composeHashes returns compose's config hash of each service it would start (`docker compose config
// --hash=*` prints "<service> <hash>"): the com.docker.compose.config-hash label of a container created
// from the current definition.
func (s *Server) composeHashes(ctx context.Context, base dockerexec.Job) (map[string]string, error) {
	job := base
	job.Action, job.Service = []string{"config", "--hash=*"}, ""
	hctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	out := map[string]string{}
	err := s.runner.Run(hctx, job, func(l string) {
		if f := strings.Fields(l); len(f) == 2 && composeHashRe.MatchString(f[1]) {
			out[f[0]] = f[1]
		}
	})
	return out, err
}

// deploySnapshotWait bounds how long a deploy waits for the monitor to poll after asking it to;
// deploySnapshotMaxAge is how old the latest snapshot may be to stand in when no new one arrived.
var (
	deploySnapshotWait   = 15 * time.Second
	deploySnapshotMaxAge = 2 * time.Minute
)

// deploySnapshot asks the monitor for a poll now and returns the first snapshot taken after the ask. When
// none arrives within deploySnapshotWait it returns the latest one — or nil if that is older than
// deploySnapshotMaxAge (or there is none): a stale view is no view.
func (s *Server) deploySnapshot(ctx context.Context) *monitor.Snapshot {
	asked := time.Now()
	if s.mon != nil { // tests inject snapshots through snapFn instead
		s.mon.Kick()
		deadline := asked.Add(deploySnapshotWait)
		for {
			if snap := s.snapshot(); snap != nil && !snap.At.Before(asked) {
				return snap
			}
			if ctx.Err() != nil || !time.Now().Before(deadline) {
				break
			}
			select {
			case <-ctx.Done():
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	snap := s.snapshot()
	if snap == nil || time.Since(snap.At) > deploySnapshotMaxAge {
		return nil
	}
	return snap
}

// removeOrphanContainers removes this app's containers whose service is no longer in its definition (known
// holds every declared service, scheduled ones included) — what the whole-project `up --remove-orphans`
// did. The edge stops dialing them first. Skipped when the container view may be incomplete.
func (s *Server) removeOrphanContainers(ctx context.Context, slug string, known map[string]bool, onLine func(string)) {
	if s.runner == nil || s.cfg.IsProtectedProject(slug) {
		return
	}
	snap := s.deploySnapshot(ctx)
	if snap == nil || !snap.DockerOK || snap.ListFailed || snap.Truncated {
		return
	}
	ids, services := orphanContainers(snap.AppByProject(slug), known)
	if len(ids) == 0 {
		return
	}
	if s.edgeRecon != nil {
		dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		_ = s.edgeRecon.DrainContainers(dctx, ids)
		cancel()
	}
	var out []string
	rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	err := s.runner.RemoveContainers(rctx, ids, func(l string) { out = append(out, l) })
	cancel()
	if err != nil {
		if s.edgeRecon != nil {
			uctx, ucancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			_ = s.edgeRecon.UndrainContainers(uctx, ids)
			ucancel()
		}
		for _, l := range out {
			onLine(l)
		}
		onLine(fmt.Sprintf("warning: could not remove the containers of services no longer in mooring.yaml (%s): %v", strings.Join(services, ", "), err))
		return
	}
	onLine(fmt.Sprintf("removed %d container(s) of services no longer in mooring.yaml: %s", len(ids), strings.Join(services, ", ")))
}

// orphanContainers returns the ids of app's containers whose service isn't in known, and those services
// (sorted). A container without a service label or a well-formed id is left alone.
func orphanContainers(app *monitor.App, known map[string]bool) (ids, services []string) {
	if app == nil {
		return nil, nil
	}
	seen := map[string]bool{}
	for _, c := range app.Services {
		if c.Service == "" || known[c.Service] || !hexIDRe.MatchString(c.ContainerID) {
			continue
		}
		ids = append(ids, c.ContainerID)
		if !seen[c.Service] {
			seen[c.Service] = true
			services = append(services, c.Service)
		}
	}
	sort.Strings(services)
	return ids, services
}

// releaseDeployHold clears the operator's hold on one of the app's services (a deploy started it, or found
// it running). Detached and bounded: the deploy's own context may already be gone.
func (s *Server) releaseDeployHold(app, service string) {
	if s.selfHeal == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.selfHeal.ClearHeld(ctx, selfheal.Key{App: app, Service: service})
}

// keepDeployDigests is the managed-file digest state to record after a paced deploy: the new digests, except
// that each service in failed keeps its previous digest.
func keepDeployDigests(next, prev map[string]string, failed []string) map[string]string {
	if len(failed) == 0 {
		return next
	}
	out := make(map[string]string, len(next))
	for k, v := range next {
		out[k] = v
	}
	// Intentional: a changed service whose start failed never got its new files mounted, so it keeps the
	// old digest and the next deploy force-recreates it again.
	for _, svc := range failed {
		if v, ok := prev[svc]; ok {
			out[svc] = v
		} else {
			delete(out, svc)
		}
	}
	return out
}

// deployProblemsKind is the infra alert a deploy raises when it leaves services that didn't start or settle.
const deployProblemsKind = "deploy_problems"

// reportDeployProblems streams one "⚠ <service>: <reason>" line per rollout problem and raises the app's
// WARNING deploy_problems alert.
func (s *Server) reportDeployProblems(slug string, problems []rolloutProblem, onLine func(string)) {
	for _, p := range problems {
		onLine("⚠ " + p.Service + ": " + deployText(p.Reason, 500))
	}
	if s.alertStore == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.alertStore.EnqueueInfra(ctx, alert.Outbox{
		Target: slug, Kind: deployProblemsKind, Level: alert.LevelWarning, Transition: "firing",
		Summary:   slug + " deployed with problems: " + deployProblemsText(problems),
		DedupeKey: "deploy:" + slug,
	})
}

// resolveDeployProblems resolves the app's deploy_problems alert after a clean paced deploy — only when one
// is open, so a clean deploy on its own never notifies.
func (s *Server) resolveDeployProblems(slug string) {
	if s.alertStore == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	open, err := s.alertStore.OpenInfraAlerts(ctx, deployProblemsKind)
	if err != nil {
		return
	}
	if _, firing := open["deploy:"+slug]; !firing {
		return
	}
	_ = s.alertStore.EnqueueInfra(ctx, alert.Outbox{
		Target: slug, Kind: deployProblemsKind, Level: alert.LevelWarning, Transition: "resolved",
		Summary:   slug + " deployed cleanly: every service started",
		DedupeKey: "deploy:" + slug,
	})
}

// deployProblemsText is a one-line, bounded list of rollout problems: "<service>: <reason>; …".
func deployProblemsText(problems []rolloutProblem) string {
	parts := make([]string, 0, len(problems))
	for _, p := range problems {
		parts = append(parts, p.Service+": "+p.Reason)
	}
	return deployText(strings.Join(parts, "; "), 1000)
}

// deployText flattens s onto one line and bounds it to max bytes (cut on a rune boundary).
func deployText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return ' '
		}
		return r
	}, s)
	if len(s) <= max {
		return s
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max] + "…"
}

// deployVerdict writes a deploy stream's last line — "[failed: …]", "[done — deployed with problems]" or
// "[done]" — and returns the audit outcome and detail for it.
func deployVerdict(emit func(string), atOnce bool, problems []rolloutProblem, err error) (audit.Outcome, string) {
	outcome, detail := audit.OK, ""
	switch {
	case err != nil:
		emit(fmt.Sprintf("\n[failed: %v]", err))
		outcome, detail = audit.Error, err.Error()
	case len(problems) > 0:
		emit("\n[done — deployed with problems]")
		detail = "deployed with problems: " + deployProblemsText(problems)
	default:
		emit("\n[done]")
	}
	if atOnce {
		detail = strings.TrimSuffix("all at once; "+detail, "; ")
	}
	return outcome, detail
}
