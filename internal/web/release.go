package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/compose"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/monitor"
)

// spec.release is a one-off `docker compose run --rm` of a service's newly built image (typically a database
// migration) that a deploy runs after its build and before it replaces or removes any running service.
//   - The service's dependencies (its depends_on, followed through other services) that have no running
//     container start first: paced like a deploy, or with one `up` for an all-at-once deploy. Running ones are
//     left as they are until the rollout. None starts while a running container of a service the definition
//     no longer declares shares a volume or host port with it.
//   - A non-zero exit or the timeout fails the deploy, and so does a build failure. The run dir's compose file
//     is generated again from the previous release's definition and each build service's image ref goes back
//     to the image it had before the build, so a self-heal recreate, an autoscaler scale-up or a scheduled task
//     still runs the previous code.
//   - A PR preview runs it only when the BASE app's deployed definition sets release.previews: true.
// The job's container is a compose one-off (label com.docker.compose.oneoff=True): the monitor leaves it out
// of the snapshot that self-heal, the autoscaler and the start gate read, and edge discovery skips it.

// releaseBackupTag is the second tag that keeps each build service's previous image for the length of a deploy
// with a release job. Without it the containerd image store deletes the previous image as soon as the build
// moves <slug>-<service> to the new one, leaving nothing to put back.
const releaseBackupTag = "mooring-previous"

// Release job limits (variables so tests can shrink them).
var (
	releaseJobTimeout       = (*definition.Release).TimeoutD // the job's run-time cap
	releaseLeaseEvery       = 5 * time.Minute                // expected_down lease renewal while the job waits or runs
	releaseDepsWait         = 5 * time.Minute                // all at once: how long stopped dependencies get to become healthy
	releaseImageCallTimeout = 30 * time.Second               // one image inspect/tag or container inspect, once the docker slot is held
	releaseRestoreSlotWait  = 15 * time.Minute               // how long putting the previous images back waits for the docker slot
)

// The job's output in the deploy log: the first releaseLogHead lines as they arrive, then the last
// releaseLogTail when it ends, each cut to releaseLineMax bytes.
const (
	releaseLogHead = 200
	releaseLogTail = 300
	releaseLineMax = 4 << 10
)

// releasePrev is the previous release's images a deploy with a release job keeps for the length of the deploy.
type releasePrev struct {
	images map[string]string // build service → the image id its ref had before the build, kept by releaseBackupTag
	keep   map[string]bool   // build services whose ref couldn't be put back: their backup tag outlives the deploy
}

// releaseRun is a deploy's input to runRelease and restoreRelease.
type releaseRun struct {
	slug  string
	dir   string // the app's run dir
	def   *definition.Definition
	rel   *definition.Release
	base  dockerexec.Job // the deploy's compose target: Project, Dir, ConfigFiles, EnvFile
	env   compose.Env    // the deploy's env, for the §5.6 check of the previous release's compose
	paced bool
	prev  *releasePrev
	vols  []reconciledVol // named volumes the deploy re-owned before the job
}

// releaseResult is what runRelease did before the job ran.
type releaseResult struct {
	started  []string         // dependencies it started
	problems []rolloutProblem // dependencies that didn't start or settle cleanly
}

// releaseToRun returns the release job this deploy runs: def's, except on a PR preview whose base app doesn't
// opt in.
func (s *Server) releaseToRun(previewOf string, def *definition.Definition, onLine func(string)) *definition.Release {
	rel := def.Spec.Release
	if rel == nil || previewOf == "" {
		return rel
	}
	// Intentional: the preview's own `previews` value is never read — its file is the PR head (fork input).
	if ok, why := s.releaseOnPreview(previewOf); !ok {
		onLine("release job skipped on this PR preview: " + why)
		return nil
	}
	return rel
}

// releaseOnPreview reports whether a preview of base runs its release job: only when base's deployed
// (HMAC-verified) definition sets release.previews: true. A definition that can't be read means no.
func (s *Server) releaseOnPreview(base string) (bool, string) {
	if s.defStore == nil {
		return false, "the base app's definition can't be read"
	}
	bdef, err := s.defStore.Current(base)
	switch {
	case err != nil || bdef == nil:
		return false, "the base app's deployed definition can't be read"
	case bdef.Spec.Release == nil || !bdef.Spec.Release.Previews:
		return false, "the base app doesn't set release.previews: true"
	}
	return true, ""
}

// deployedDefinition returns the definition of slug's running release: the latest version a git deploy or
// rollback recorded (one with a commit), or, in a history from before versions carried a commit, the latest
// version. nil, nil when there is none (a first deploy).
func (s *Server) deployedDefinition(slug string) (*definition.Definition, string, error) {
	if s.defStore == nil {
		return nil, "", errors.New("the definition store is unavailable")
	}
	// Intentional: not defStore.Current — a dashboard edit saves a newer version without a commit, and only a
	// git deploy writes the run dir's compose, so that version never ran.
	var latest int64
	for off := 0; ; off += 50 {
		page, more, err := s.defStore.ListPage(slug, 50, off)
		if err != nil {
			return nil, "", err
		}
		for _, v := range page {
			if latest == 0 {
				latest = v.ID
			}
			if v.Commit != "" {
				def, err := s.defStore.Version(slug, v.ID)
				return def, v.Commit, err
			}
		}
		if !more {
			break
		}
	}
	if latest == 0 {
		return nil, "", nil
	}
	def, err := s.defStore.Version(slug, latest)
	return def, "", err
}

// previousReleaseCompose returns the compose file of the release r replaces: generated again from its deployed
// definition, then checked by the §5.6 validator as a deploy checks its own. why says what stopped it
// otherwise: no previous release (a first deploy), a definition that can't be read or generated, or a
// validator finding (in review mode a finding is only a warning, as for a deploy).
func (s *Server) previousReleaseCompose(r releaseRun, onLine func(string)) (b []byte, why string) {
	return s.deployedCompose(r.slug, r.dir, r.env, onLine)
}

// deployedCompose is the compose of the release deployed in dir: generated again from its definition and
// commit, then checked by the §5.6 validator as a deploy checks its own (see previousReleaseCompose).
func (s *Server) deployedCompose(slug, dir string, env compose.Env, onLine func(string)) (b []byte, why string) {
	def, commit, err := s.deployedDefinition(slug)
	switch {
	case err != nil:
		return nil, "the deployed definition can't be read: " + err.Error()
	case def == nil:
		return nil, noPreviousRelease
	}
	if b, err = definition.ComposeBytesAt(def, commit); err != nil {
		return nil, "the previous release's compose can't be generated: " + err.Error()
	}
	res := compose.ValidateBytes(b, env, dir, compose.Options{ProtectedPaths: s.protectedHostPaths()})
	if !res.OK() {
		res.SortViolations()
		if s.cfg.ComposeValidation.Mode != "review" {
			return nil, fmt.Sprintf("the previous release's compose fails the §5.6 validator (%d finding(s), first: %s)", len(res.Violations), res.Violations[0].String())
		}
		onLine(fmt.Sprintf("release: WARNING (review mode): the previous release's compose has %d validator finding(s); putting it back anyway", len(res.Violations)))
	}
	return b, ""
}

// backupBuildImages tags each build service's current image <slug>-<service>:mooring-previous before the
// build, and returns the ids it kept. A ref that doesn't exist yet (a new service) has nothing to keep; one
// that can't be read or tagged is a warning naming the service.
func (s *Server) backupBuildImages(ctx context.Context, slug string, def *definition.Definition, onLine func(string)) map[string]string {
	ids := map[string]string{}
	svcs := buildServiceNames(def)
	if len(svcs) == 0 {
		return ids
	}
	// Intentional: the wait for the slot is bounded only by the deploy's own deadline, never a call timeout — a
	// scheduled task or backup holding the slot delays the backup and must not skip it.
	sem := s.runner.Semaphore()
	if err := sem.Acquire(ctx); err != nil {
		onLine(fmt.Sprintf("warning: could not keep the current images of %s (%v); if the release job fails they can't be put back", strings.Join(svcs, ", "), err))
		return ids
	}
	defer sem.Release()
	for _, svc := range svcs {
		ref := imageRef(slug, svc)
		cctx, cancel := context.WithTimeout(ctx, releaseImageCallTimeout)
		id, err := s.imageIDHeld(cctx, ref)
		if err == nil && id != "" {
			err = s.runner.TagImageHeld(cctx, id, ref+":"+releaseBackupTag, nil)
		}
		cancel()
		switch {
		case err != nil:
			onLine(fmt.Sprintf("warning: could not keep %s's current image (%v); if the release job fails, %s's previous image can't be put back", ref, err, svc))
		case id != "":
			ids[svc] = id
		}
	}
	return ids
}

// dropBuildImageBackups removes the backup tags when the deploy ends. Docker deletes an image whose last
// reference that was, unless a container still uses it (an old copy still running); the tag then stays
// until the next deploy with a release job moves it. The tag of a ref restoreRelease couldn't put back is
// kept: it is the only reference left to the previous image.
func (s *Server) dropBuildImageBackups(slug string, prev *releasePrev, onLine func(string)) {
	for _, svc := range sortedKeys(prev.images) {
		tag := imageRef(slug, svc) + ":" + releaseBackupTag
		if prev.keep[svc] {
			onLine(fmt.Sprintf("release: kept %s, the only reference left to %s's previous image", tag, imageRef(slug, svc)))
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		_ = s.runner.UntagImage(ctx, tag, nil)
		cancel()
	}
}

// runRelease starts the job's stopped dependencies and runs the job (see the top of this file). An error
// means the job failed or couldn't run; the compose file, the image refs and the re-owned volumes are then
// already back as they were.
func (s *Server) runRelease(ctx context.Context, r releaseRun, onLine func(string)) (releaseResult, error) {
	stopRenew := s.renewLeaseEvery(r.slug, releaseLeaseEvery)
	defer stopRenew()
	var res releaseResult
	if deps := releaseDeps(r.def, r.rel.Service); len(deps) > 0 {
		start, app, ok := s.releaseDepsToStart(ctx, r.slug, deps)
		switch {
		case !ok:
			onLine("release: the container view is unavailable, so the dependencies of " + r.rel.Service + " aren't started first")
		case len(start) > 0:
			if err := s.releaseOrphanClash(ctx, r, app, start); err != nil {
				s.restoreRelease(ctx, r, false, onLine)
				s.releaseFailed(r, nil, onLine)
				return res, fmt.Errorf("release job didn't run: %w", err)
			}
			var err error
			if res, err = s.startReleaseDeps(ctx, r, start, onLine); err != nil {
				s.restoreRelease(ctx, r, false, onLine)
				s.releaseFailed(r, res.started, onLine)
				return res, fmt.Errorf("release job didn't run: %w", err)
			}
		}
	}
	if err := s.runReleaseJob(ctx, r, onLine); err != nil {
		s.releaseFailed(r, res.started, onLine)
		return res, err
	}
	return res, nil
}

// releaseDeps returns the services svc depends on, directly or through other services, sorted: never svc
// itself or a scheduled-only service.
func releaseDeps(def *definition.Definition, svc string) []string {
	sched := def.Spec.ScheduledServiceSet()
	seen := map[string]bool{svc: true}
	var out []string
	var walk func(string)
	walk = func(name string) {
		for _, d := range def.Spec.Compose.Services[name].DependsOn {
			if seen[d] {
				continue
			}
			seen[d] = true
			if _, ok := def.Spec.Compose.Services[d]; !ok || sched[d] {
				continue
			}
			out = append(out, d)
			walk(d)
		}
	}
	walk(svc)
	sort.Strings(out)
	return out
}

// releaseDepsToStart returns the deps with no running container, and the app's containers in the view it
// read (nil when it has none). ok is false when the container view is unavailable or incomplete: a dependency
// missing from it may be running, and starting a running one could replace it.
func (s *Server) releaseDepsToStart(ctx context.Context, slug string, deps []string) ([]string, *monitor.App, bool) {
	running, app, ok := s.runningServices(ctx, slug)
	if !ok {
		return nil, nil, false
	}
	var out []string
	for _, d := range deps {
		if !running[d] {
			out = append(out, d)
		}
	}
	return out, app, true
}

// runningServices returns the services of slug with a running container, and the app's containers, from a
// fresh container view. ok is false when that view is unavailable or incomplete.
func (s *Server) runningServices(ctx context.Context, slug string) (map[string]bool, *monitor.App, bool) {
	snap := s.deploySnapshot(ctx)
	if snap == nil || !snap.DockerOK || snap.ListFailed || snap.Truncated {
		return nil, nil, false
	}
	running := map[string]bool{}
	app := snap.AppByProject(slug)
	if app != nil {
		for _, c := range app.Services {
			if c.Running() {
				running[c.Service] = true
			}
		}
	}
	return running, app, true
}

// releaseClaim is a volume, run-dir bind or host port a container mounts or publishes.
type releaseClaim struct {
	key  string // "volume <name>", "bind <host path>" or "host port <port>/<proto>"
	rw   bool   // a writable mount; a host port is always exclusive
	user string // the service
}

// releaseOrphanClash refuses to start deps while a live container of a service the definition no longer
// declares (removed or renamed: its containers are removed only after the job) mounts a volume or run-dir bind
// one of them mounts — at least one side writable — or publishes a host port one of them publishes. A renamed
// database would otherwise run twice on one data directory. Fails closed when those containers can't be
// inspected.
func (s *Server) releaseOrphanClash(ctx context.Context, r releaseRun, app *monitor.App, deps []string) error {
	if app == nil {
		return nil
	}
	live := monitor.App{Project: app.Project}
	for _, c := range app.Services {
		switch c.State {
		case "running", "restarting", "paused":
			live.Services = append(live.Services, c)
		}
	}
	ids, orphans := orphanContainers(&live, declaredServiceSet(r.def))
	if len(ids) == 0 {
		return nil
	}
	want := releaseDepClaims(r, deps)
	if len(want) == 0 {
		return nil
	}
	got, err := s.inspectContainerClaims(ctx, ids)
	if err != nil {
		return fmt.Errorf("could not check whether %s (no longer in mooring.yaml) shares a volume or host port with %s: %w",
			strings.Join(orphans, ", "), strings.Join(deps, ", "), err)
	}
	for _, c := range live.Services {
		if !slices.Contains(ids, c.ContainerID) {
			continue
		}
		claims, inspected := got[c.ContainerID]
		if !inspected {
			return fmt.Errorf("could not check whether %s (no longer in mooring.yaml) shares a volume or host port with %s: docker inspect didn't report container %s",
				c.Service, strings.Join(deps, ", "), c.ContainerID[:12])
		}
		for _, oc := range claims {
			for _, w := range want {
				if oc.key != w.key || !(oc.rw || w.rw) {
					continue
				}
				verb := "mounts"
				if strings.HasPrefix(w.key, "host port ") {
					verb = "publishes"
				}
				return fmt.Errorf("%s, a service no longer in mooring.yaml, still runs and %s %s, which %s %s too; starting %s before the job would run both. "+
					"Stop %s, or deploy this change once without spec.release (that deploy removes %s before it starts %s)",
					c.Service, verb, w.key, w.user, verb, w.user, c.Service, c.Service, w.user)
			}
		}
	}
	return nil
}

// releaseDepClaims returns the volumes, run-dir binds and host ports deps mount or publish.
func releaseDepClaims(r releaseRun, deps []string) []releaseClaim {
	var out []releaseClaim
	for _, d := range deps {
		svc := r.def.Spec.Compose.Services[d]
		for _, v := range svc.Volumes {
			key := "volume " + r.slug + "_" + v.Name // compose's default naming: <project>_<volume>
			if v.Name == "" {
				key = "bind " + filepath.Join(r.dir, filepath.FromSlash(v.Source))
			}
			out = append(out, releaseClaim{key: key, rw: !v.ReadOnly, user: d})
		}
		for _, p := range svc.Ports {
			if !p.Publish {
				continue
			}
			host, proto := p.Internal, p.Protocol
			if p.Published != 0 {
				host = p.Published
			}
			if proto == "" {
				proto = "tcp"
			}
			out = append(out, releaseClaim{key: fmt.Sprintf("host port %d/%s", host, proto), rw: true, user: d})
		}
	}
	return out
}

// containerClaimsFormat makes `docker container inspect` print one line per container: its id, its mounts and
// its port bindings, tab-separated (JSON escapes a tab inside a value).
const containerClaimsFormat = "{{.Id}}\t{{json .Mounts}}\t{{json .HostConfig.PortBindings}}"

// inspectContainerClaims returns the volumes, binds and host ports of each container in ids (well-formed hex
// ids), keyed by the id as given. It waits for the docker slot as the deploy's other docker calls do.
func (s *Server) inspectContainerClaims(ctx context.Context, ids []string) (map[string][]releaseClaim, error) {
	sem := s.runner.Semaphore()
	if err := sem.Acquire(ctx); err != nil {
		return nil, err
	}
	defer sem.Release()
	cctx, cancel := context.WithTimeout(ctx, releaseImageCallTimeout)
	defer cancel()
	var out bytes.Buffer
	var stderr []string
	argv := append([]string{"container", "inspect", "--format", containerClaimsFormat, "--"}, ids...)
	if err := s.runner.RunStreamHeld(cctx, argv, &out, func(l string) { stderr = append(stderr, l) }); err != nil {
		if len(stderr) > 0 {
			return nil, fmt.Errorf("%w: %s", err, deployText(stderr[len(stderr)-1], 300))
		}
		return nil, err
	}
	return parseContainerClaims(out.String(), ids)
}

// parseContainerClaims parses inspectContainerClaims' output, matching each line to an id in ids by prefix.
func parseContainerClaims(out string, ids []string) (map[string][]releaseClaim, error) {
	res := map[string][]releaseClaim{}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 || !hexIDRe.MatchString(f[0]) {
			return nil, fmt.Errorf("unexpected docker inspect output %q", deployText(line, 200))
		}
		var mounts []struct {
			Type, Name, Source string
			RW                 bool
		}
		var ports map[string][]struct{ HostPort string }
		if err := json.Unmarshal([]byte(f[1]), &mounts); err != nil {
			return nil, fmt.Errorf("docker inspect mounts: %w", err)
		}
		if err := json.Unmarshal([]byte(f[2]), &ports); err != nil {
			return nil, fmt.Errorf("docker inspect port bindings: %w", err)
		}
		var claims []releaseClaim
		for _, m := range mounts {
			switch {
			case m.Type == "volume" && m.Name != "":
				claims = append(claims, releaseClaim{key: "volume " + m.Name, rw: m.RW})
			case m.Type == "bind" && m.Source != "":
				claims = append(claims, releaseClaim{key: "bind " + filepath.Clean(m.Source), rw: m.RW})
			}
		}
		for port, binds := range ports {
			_, proto, _ := strings.Cut(port, "/")
			if proto == "" {
				proto = "tcp"
			}
			for _, b := range binds {
				// An empty HostPort is one docker picked at start, which a fixed host port can't be.
				if b.HostPort != "" {
					claims = append(claims, releaseClaim{key: "host port " + b.HostPort + "/" + proto, rw: true})
				}
			}
		}
		for _, id := range ids {
			if idMatch(f[0], id) {
				res[id] = claims
			}
		}
	}
	return res, nil
}

// startReleaseDeps starts deps (none of them running) before the job. A dependency that fails to start doesn't
// stop the job — its exit shows whether it needed it. The error is non-nil only when ctx ended.
func (s *Server) startReleaseDeps(ctx context.Context, r releaseRun, deps []string, onLine func(string)) (releaseResult, error) {
	onLine("release: starting what " + r.rel.Service + " depends on and isn't running: " + strings.Join(deps, ", "))
	declared := declaredServiceSet(r.def)
	if !r.paced {
		job := r.base
		// --wait: the job usually connects to these (a database) as soon as it starts.
		job.Action = append([]string{"up", "-d", "--no-deps", "--no-build", "--wait", "--wait-timeout", strconv.Itoa(int(releaseDepsWait / time.Second)), "--"}, deps...)
		onLine("$ docker compose " + strings.Join(job.Action, " "))
		upStart := time.Now()
		err := s.runUpWithConflictReap(ctx, r.slug, declared,
			func(c context.Context, ol func(string)) error { return s.runner.Run(c, job, ol) },
			s.runner.RemoveContainers, onLine)
		s.recordStart(r.slug, "", upStart, false)
		if err != nil {
			onLine("release: warning: could not start them: " + err.Error())
			return releaseResult{started: s.releaseDepsRunning(ctx, r.slug, deps)}, nil
		}
		for _, d := range deps {
			s.releaseDeployHold(r.slug, d)
		}
		return releaseResult{started: deps}, nil
	}
	// Intentional: no --force-recreate for a dependency whose managed files changed — it isn't running, so the
	// start mounts its current files anyway.
	steps := deployRolloutSteps(r.def, deps, nil, nil, r.base, s.cfg.Server.StartGateSettings())
	bg := context.Background()
	problems, err := s.runRollout(ctx, steps, rolloutOpts{
		App:      r.slug,
		OnLine:   onLine,
		Declared: declared,
		Renew:    func() { s.renewExpectedDown(bg, r.slug) },
		Started: func(svc string) {
			s.releaseDeployHold(r.slug, svc)
			s.reconcileEdgeAfter(ctx)
		},
	})
	res := releaseResult{problems: problems}
	notStarted := deployRolloutResult{problems: problems}.failedToStart(deps)
	for _, d := range deps {
		if !slices.Contains(notStarted, d) {
			res.started = append(res.started, d)
		}
	}
	return res, err
}

// releaseDepsRunning returns the deps a failed all-at-once `up` left running: compose may have started some
// before it failed. Their holds are released, as for a successful start. When the container view can't tell,
// every dep counts as started (nothing undoes what a running one uses), and no hold is touched.
func (s *Server) releaseDepsRunning(ctx context.Context, slug string, deps []string) []string {
	running, _, ok := s.runningServices(ctx, slug)
	if !ok {
		return deps
	}
	var out []string
	for _, d := range deps {
		if running[d] {
			out = append(out, d)
			s.releaseDeployHold(slug, d)
		}
	}
	return out
}

// releaseJob is the compose call that runs r: a one-off container of r.Service with r.Command in place of its
// command, no dependency started, no TTY. Compose publishes no host port for a one-off.
func releaseJob(base dockerexec.Job, r *definition.Release) dockerexec.Job {
	job := base
	job.Action = []string{"run", "--rm", "--no-deps", "-T"}
	job.Service = r.Service
	job.Args = append([]string(nil), r.Command...)
	return job
}

// runReleaseJob runs the job under the docker slot. On a failure it removes the job's container if the
// compose CLI was killed, and puts the compose file and the image refs back while it still holds the slot.
func (s *Server) runReleaseJob(ctx context.Context, r releaseRun, onLine func(string)) error {
	timeout := releaseJobTimeout(r.rel)
	job := releaseJob(r.base, r.rel)
	onLine(fmt.Sprintf("$ docker compose run --rm --no-deps -T -- %s %s  (release job, timeout %s)",
		r.rel.Service, deployText(strings.Join(r.rel.Command, " "), 500), rolloutRound(timeout)))
	sem := s.runner.Semaphore()
	if err := sem.Acquire(ctx); err != nil {
		s.restoreRelease(ctx, r, false, onLine)
		return fmt.Errorf("release job didn't start: %w", err)
	}
	defer sem.Release()
	start := time.Now()
	out := &releaseOutput{onLine: onLine}
	// Detached from ctx: the job runs to its own timeout (deployTimeout leaves room for the longest).
	jctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	runErr := s.runner.RunHeld(jctx, job, out.add)
	timedOut := errors.Is(jctx.Err(), context.DeadlineExceeded)
	cancel()
	out.flush()
	if runErr != nil {
		// Killing the compose CLI doesn't stop its container. Holding the slot, no scheduled task's one-off is
		// running, so every one-off of the app is this job's.
		rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		s.runner.ReapOneOffHeld(rctx, r.slug)
		rcancel()
	}
	s.recordStart(r.slug, r.rel.Service, start, false)
	if runErr == nil {
		onLine("release: done")
		return nil
	}
	s.restoreRelease(ctx, r, true, onLine)
	if timedOut {
		return fmt.Errorf("release job timed out after %s", rolloutRound(timeout))
	}
	return fmt.Errorf("release job failed: %w", runErr)
}

// restoreRelease puts back the previous release's compose file (previousReleaseCompose; when there is none
// the file stays as this deploy wrote it) and each build service's image ref as it was before the build. A
// ref it can't point back is recorded in r.prev.keep. holdsSlot says the caller already holds the docker slot.
func (s *Server) restoreRelease(ctx context.Context, r releaseRun, holdsSlot bool, onLine func(string)) {
	if b, why := s.previousReleaseCompose(r, onLine); why != "" {
		onLine("release: warning: docker-compose.yml not put back: " + why)
	} else if err := atomicWrite(filepath.Join(r.dir, "docker-compose.yml"), b, 0o644, r.dir); err != nil {
		onLine("release: warning: could not put back the previous release's docker-compose.yml: " + err.Error())
	} else {
		onLine("release: put back the previous release's docker-compose.yml")
	}
	if len(r.prev.images) == 0 {
		return
	}
	bg := context.WithoutCancel(ctx)
	if !holdsSlot {
		// Intentional: the previous images must go back even after the deploy's deadline has passed or while
		// another app's self-healing holds the slot, so the wait has a bound of its own instead of a call timeout.
		wctx, cancel := context.WithTimeout(bg, releaseRestoreSlotWait)
		err := s.runner.Semaphore().Acquire(wctx)
		cancel()
		if err != nil {
			for _, svc := range sortedKeys(r.prev.images) {
				if r.prev.keep == nil {
					r.prev.keep = map[string]bool{}
				}
				r.prev.keep[svc] = true
			}
			onLine(fmt.Sprintf("release: warning: the docker slot stayed busy for %s; the previous images were not put back (their %s tags are kept)", releaseRestoreSlotWait, releaseBackupTag))
			return
		}
		defer s.runner.Semaphore().Release()
	}
	for _, svc := range sortedKeys(r.prev.images) {
		id, ref := r.prev.images[svc], imageRef(r.slug, svc)
		tctx, cancel := context.WithTimeout(bg, releaseImageCallTimeout)
		err := s.runner.TagImageHeld(tctx, id, ref, nil)
		cancel()
		if err != nil {
			if r.prev.keep == nil {
				r.prev.keep = map[string]bool{}
			}
			r.prev.keep[svc] = true
			onLine(fmt.Sprintf("release: warning: could not point %s back at its previous image: %v", ref, err))
			continue
		}
		onLine(fmt.Sprintf("release: %s points at its previous image %s again", ref, strings.TrimPrefix(id, "sha256:")[:12]))
	}
}

// noPreviousRelease is deployedCompose's reason on a first deploy.
const noPreviousRelease = "there is no previous release (first deploy)"

// putBackDeployedCompose writes the deployed release's compose back over the one a deploy wrote, when the deploy
// stopped before starting any service. Restarts, scale-ups and scheduled tasks read the run dir's compose, so
// they keep running the release that is actually deployed, with its MOORING_COMMIT. Nothing on a first deploy.
func (s *Server) putBackDeployedCompose(slug, dir string, env compose.Env, onLine func(string)) {
	b, why := s.deployedCompose(slug, dir, env, onLine)
	switch {
	case why == noPreviousRelease:
		return
	case why != "":
		onLine("warning: docker-compose.yml not put back: " + why)
		return
	}
	if err := atomicWrite(filepath.Join(dir, "docker-compose.yml"), b, 0o644, dir); err != nil {
		onLine("warning: could not put back the deployed release's docker-compose.yml: " + err.Error())
		return
	}
	onLine("put back the deployed release's docker-compose.yml")
}

// releaseFailed gives the volumes the deploy re-owned their previous owner — except one a dependency the job
// started uses (that dependency runs the new version) — and says the deploy stopped.
func (s *Server) releaseFailed(r releaseRun, started []string, onLine func(string)) {
	if len(r.vols) > 0 {
		s.rollbackVolumeOwnership(context.Background(), volumesNotUsedBy(r.def, r.slug, r.vols, started), onLine)
	}
	onLine("release: the deploy stopped before replacing any service; the previous release keeps running")
}

// volumesNotUsedBy returns the reconciled volumes no service in svcs mounts.
func volumesNotUsedBy(def *definition.Definition, slug string, vols []reconciledVol, svcs []string) []reconciledVol {
	if len(svcs) == 0 || len(vols) == 0 {
		return vols
	}
	var others []string
	for name := range def.Spec.Compose.Services {
		if !slices.Contains(svcs, name) {
			others = append(others, name)
		}
	}
	return volumesOnlyFor(def, slug, vols, others)
}

// renewLeaseEvery renews slug's expected_down lease every interval until the returned stop is called.
func (s *Server) renewLeaseEvery(slug string, every time.Duration) (stop func()) {
	done, finished := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				s.renewExpectedDown(ctx, slug)
				cancel()
			}
		}
	}()
	return func() {
		close(done)
		<-finished
	}
}

// withReleaseProblems puts the problems of the job's dependencies ahead of the rollout's, leaving out a
// service the rollout started again (its own result counts).
func withReleaseProblems(rel, rollout []rolloutProblem, steps []string) []rolloutProblem {
	if len(rel) == 0 {
		return rollout
	}
	var out []rolloutProblem
	for _, p := range rel {
		if !slices.Contains(steps, p.Service) {
			out = append(out, p)
		}
	}
	return append(out, rollout...)
}

// withoutServices returns svcs less drop (svcs itself is not modified).
func withoutServices(svcs, drop []string) []string {
	if len(drop) == 0 {
		return svcs
	}
	return slices.DeleteFunc(slices.Clone(svcs), func(s string) bool { return slices.Contains(drop, s) })
}

// releaseOutput forwards the job's output to the deploy log, each line prefixed "release: " and cut to
// releaseLineMax: the first releaseLogHead lines as they arrive, the last releaseLogTail by flush, with a count
// of the lines left out in between.
type releaseOutput struct {
	onLine  func(string)
	head    int
	tail    []string
	omitted int
}

func (o *releaseOutput) add(l string) {
	l = "release: " + deployText(l, releaseLineMax)
	if o.head < releaseLogHead {
		o.head++
		o.onLine(l)
		return
	}
	o.tail = append(o.tail, l)
	if len(o.tail) > releaseLogTail {
		o.tail = o.tail[1:]
		o.omitted++
	}
}

func (o *releaseOutput) flush() {
	if o.omitted > 0 {
		o.onLine(fmt.Sprintf("release: … %d lines omitted", o.omitted))
	}
	for _, l := range o.tail {
		o.onLine(l)
	}
	o.tail, o.omitted = nil, 0
}

// sortedKeys returns m's keys, sorted.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
