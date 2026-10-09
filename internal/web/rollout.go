package web

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/startgate"
)

// A rollout starts an app's services one at a time, dependencies first. Before each start it waits —
// at most server.start_gate.deploy_wait in total per rollout — while the host CPU is busy or another
// app's container is still starting; after each start it waits for what that step started to become
// healthy (settleDeadline, at most service_settle). A service that fails to start or doesn't settle
// in time is reported and the rollout carries on with the rest: deploys and operator actions are
// paced, never blocked (a deploy may be the fix for the unhealthy service). Once the rollout has
// paced for rollout_budget, the remaining services start without waiting.

// rolloutStep is one service of a rollout, started with one compose call (Job) or copy by copy
// (Copies).
type rolloutStep struct {
	Service string
	// Job is the compose call that starts the service (Job.Service set). Unused when Copies is set.
	Job dockerexec.Job
	// Reap: Job is an `up` — recover a stranded container-name conflict (runUpWithConflictReap).
	Reap bool
	// Copies are started (CopyAction "start") or restarted ("restart") one at a time with
	// `docker start|restart <id>`, each paced and waited for like a step of its own.
	Copies     []string
	CopyAction string
	// Deadline bounds the wait for what the step started to settle (settleDeadline).
	Deadline time.Duration
	// Notify: the service declares on_unhealthy: notify — an unhealthy new copy isn't a problem.
	Notify bool
	// Restarts: the service has a restart policy, so a copy that exited may still come back.
	Restarts bool
	// Timeout bounds the step's docker call (0: 3m for a copy, 10m for a compose call); the service's
	// StopGrace (stop_grace_period) is added, as stopping a copy may take all of it.
	Timeout   time.Duration
	StopGrace time.Duration
}

// rolloutProblem is a service the rollout couldn't bring up cleanly; the rollout went on regardless.
type rolloutProblem struct {
	Service string
	Reason  string // e.g. "start failed: …", "still starting after 3m30s", "unhealthy", "exited (code 1)"
}

// rolloutOpts configures a rollout.
type rolloutOpts struct {
	App    string
	OnLine func(string)
	// Renew renews the app's expected_down lease after each step (nil = none).
	Renew func()
	// Started is called after a step's docker call succeeded (e.g. to release the service's hold).
	Started func(service string)
	// Lock and Unlock wrap each step's docker call (a certificate renewal takes the git-deploy
	// single-flight only around its docker calls, never across a wait). Lock returning false stops
	// the rollout with errRolloutLocked. nil = none.
	Lock   func() bool
	Unlock func()
	// Declared are the services of the definition being rolled out, for the name-conflict cleanup of an
	// `up` step (nil: the app's stored definition — during a deploy that is still the previous one).
	Declared map[string]bool
}

// errRolloutLocked: rolloutOpts.Lock refused, so the rollout stopped before its next step.
var errRolloutLocked = errors.New("rollout stopped: another git operation is running")

// Rollout timing (variables so tests can shrink them).
var (
	rolloutPoll         = 2 * time.Second  // how often a wait asks the start gate and reads the container view again
	rolloutHeartbeat    = 15 * time.Second // how often a wait says it is still waiting
	rolloutSnapshotWait = time.Minute      // longest wait for a container view taken after a step's docker call
	rolloutRenewEvery   = 5 * time.Minute  // lease renewal during a long settle wait (a wait may outlast the lease)
)

// runRollout runs steps in order, one service at a time (see the package comment above), writing
// progress to o.OnLine. It returns the problems it reported; the error is non-nil only when ctx
// ended or o.Lock refused, and then the remaining steps didn't run.
func (s *Server) runRollout(ctx context.Context, steps []rolloutStep, o rolloutOpts) ([]rolloutProblem, error) {
	r := &rolloutRun{s: s, o: o, onLine: o.OnLine, set: s.cfg.Server.StartGateSettings(), began: time.Now()}
	if r.onLine == nil {
		r.onLine = func(string) {}
	}
	r.paced = s.startGate != nil && r.set.Enabled
	if s.runner == nil {
		for _, st := range steps {
			r.problem(rolloutUnit{st: st, label: st.Service}, "start failed: write plane unavailable")
		}
		return r.problems, nil
	}
	r.declared = o.Declared
	for _, st := range steps {
		if r.declared == nil && st.Reap && len(st.Copies) == 0 {
			r.declared = s.reapScope(ctx, o.App)
			break
		}
	}
	for i, st := range steps {
		if len(st.Copies) == 0 {
			u := rolloutUnit{st: st, label: st.Service,
				head: fmt.Sprintf("→ %s (%d/%d): %s", st.Service, i+1, len(steps), rolloutJobLine(st.Job))}
			if _, err := r.run(ctx, u); err != nil {
				return r.problems, err
			}
			continue
		}
		verb := "start"
		if st.CopyAction == "restart" {
			verb = "restart"
		}
		started := false
		var err error
		for j, id := range st.Copies {
			short := shortContainerID(id)
			u := rolloutUnit{st: st, copy: id, label: st.Service + " copy " + short,
				head: fmt.Sprintf("→ %s copy %s (%d/%d): docker %s %s", st.Service, short, j+1, len(st.Copies), verb, short)}
			var ok bool
			ok, err = r.run(ctx, u)
			started = started || ok
			if err != nil {
				break
			}
		}
		// Also when ctx or o.Lock cut the copies short: a copy did start.
		if started && o.Started != nil {
			o.Started(st.Service)
		}
		if err != nil {
			return r.problems, err
		}
	}
	if r.unpaced {
		// Intentional: reported as a problem, so the deploy doesn't claim a clean result (or clear an
		// open alert) for services it started without checking.
		r.problems = append(r.problems, rolloutProblem{Service: "(rollout)",
			Reason: fmt.Sprintf("pacing budget (%s) used up: not every service was checked for health", rolloutRound(r.set.RolloutBudget))})
	}
	return r.problems, nil
}

// rolloutRun is the state of one runRollout call.
type rolloutRun struct {
	s        *Server
	o        rolloutOpts
	onLine   func(string)
	set      config.StartGateSettings
	paced    bool          // the start gate paces this rollout (it is set and enabled)
	began    time.Time     // the rollout budget counts from here
	waited   time.Duration // spent waiting for CPU or other apps' starts; at most set.DeployWait
	waitOver bool          // the wait budget is used up: no more waiting for CPU or other starts
	unpaced  bool          // the rollout budget is used up: no more waiting at all
	renewed  time.Time     // last o.Renew
	declared map[string]bool
	problems []rolloutProblem
}

// rolloutUnit is one docker call of a rollout: a step's compose call, or one copy of a Copies step.
type rolloutUnit struct {
	st    rolloutStep
	copy  string // the copy's container id; "" for the step's compose call
	label string // how progress lines name it
	head  string // the line printed before it starts
}

// run starts one unit: waits for the start gate, takes o.Lock and the docker slot, makes the docker
// call, records it, and waits for what it started to settle. It reports whether the docker call
// succeeded; the error is non-nil only when ctx ended or o.Lock refused.
func (r *rolloutRun) run(ctx context.Context, u rolloutUnit) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	r.onLine(u.head)
	sem := r.s.runner.Semaphore()
	if err := r.acquire(ctx, u, sem); err != nil {
		return false, err
	}
	start := time.Now()
	cctx, ccancel := context.WithTimeout(ctx, rolloutCallTimeout(u.st, u.copy != ""))
	callErr := r.call(cctx, u)
	ccancel()
	end := time.Now()
	// Recorded before the slot is released, so no other starter starts a container before the gate
	// knows about this one. Intentional: only a copy's start is recorded as certain to have started a
	// container — a compose `up` that found the service unchanged starts nothing, and a record that
	// waits for a new container would hold every other start until it expired.
	r.s.recordStart(r.o.App, u.st.Service, start, callErr == nil && u.copy != "")
	sem.Release()
	r.unlock()
	r.renew()
	if callErr == nil && u.copy == "" && r.o.Started != nil {
		r.o.Started(u.st.Service)
	}
	if err := ctx.Err(); err != nil {
		return callErr == nil, err // interrupted, not failed: no problem to report
	}
	if callErr != nil {
		r.problem(u, "start failed: "+callErr.Error())
		return false, nil
	}
	return true, r.settle(ctx, u, start, end)
}

// acquire returns holding o.Lock (if set) and the docker slot. While the rollout paces, it first
// waits until the start gate admits u, then asks again under the slot: a background starter may have
// started a container in between. All of a rollout's waiting here draws on one budget, DeployWait.
func (r *rolloutRun) acquire(ctx context.Context, u rolloutUnit, sem *dockerexec.Semaphore) error {
	var since, said time.Time // the current wait began; the last "waiting" line
	stop := func() {
		if !since.IsZero() {
			r.waited += time.Since(since)
			since = time.Time{}
		}
	}
	defer stop()
	// held waits one poll after the gate turned u down, or ends the waiting once the budget is used up.
	held := func(reason string) error {
		now := time.Now()
		if since.IsZero() {
			since = now
		}
		if r.waited+now.Sub(since) >= r.set.DeployWait {
			// Intentional: start anyway. A deploy may be the fix for what keeps the host busy or
			// another app from settling, so it is paced, never blocked.
			r.waitOver = true
			r.onLine(fmt.Sprintf("  waited %s for CPU/other starts — starting anyway", rolloutRound(r.set.DeployWait)))
			return nil
		}
		if said.IsZero() || now.Sub(said) >= rolloutHeartbeat {
			said = now
			r.onLine("  " + u.label + ": waiting — " + reason)
		}
		return rolloutSleep(ctx, rolloutPoll)
	}
	for {
		if r.waits() {
			if d := r.admit(u); !d.OK {
				if err := held(d.Reason); err != nil {
					return err
				}
				continue
			}
		}
		stop() // time spent on the lock and the slot isn't waiting for the gate
		if r.o.Lock != nil && !r.o.Lock() {
			return errRolloutLocked
		}
		if err := r.acquireSlot(ctx, sem); err != nil {
			r.unlock()
			return err
		}
		if !r.waits() {
			return nil
		}
		d := r.admit(u)
		if d.OK {
			return nil
		}
		sem.Release()
		r.unlock() // never held across a wait
		if err := held(d.Reason); err != nil {
			return err
		}
	}
}

// acquireSlot takes the docker slot, however long another holder keeps it (a backup, a scheduled
// task), renewing the app's expected_down lease meanwhile so it can't lapse mid-rollout.
func (r *rolloutRun) acquireSlot(ctx context.Context, sem *dockerexec.Semaphore) error {
	for {
		actx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := sem.Acquire(actx)
		cancel()
		if err == nil || ctx.Err() != nil {
			return err
		}
		if time.Since(r.renewed) >= rolloutRenewEvery {
			r.renew()
		}
	}
}

// waits reports whether the rollout still waits for the start gate before a start.
func (r *rolloutRun) waits() bool { return !r.waitOver && r.pacing() }

// pacing reports whether the rollout still paces: the start gate is on and the rollout budget isn't
// used up. It says so once when the budget runs out.
func (r *rolloutRun) pacing() bool {
	if !r.paced || r.unpaced {
		return false
	}
	if time.Since(r.began) < r.set.RolloutBudget {
		return true
	}
	// Intentional: past the budget the remaining services start back to back. The rollout has to
	// end (a deploy may be the fix), and every service so far had its own deadline.
	r.unpaced = true
	r.onLine(fmt.Sprintf("  pacing budget (%s) used up — starting the remaining services without waiting", rolloutRound(r.set.RolloutBudget)))
	return false
}

// admit asks the start gate whether u may start now, after folding in the latest container view.
// The service's own containers never hold it back and their CPU doesn't count; this app's other
// starts don't hold it back either (the rollout paces its own app itself); a service with no running
// copy doesn't wait for CPU.
func (r *rolloutRun) admit(u rolloutUnit) startgate.Decision {
	snap := r.s.snapshot()
	r.s.observeStarts(snap)
	var ids []string
	running := false
	if rolloutViewOK(snap) {
		if a := snap.AppByProject(r.o.App); a != nil {
			for _, c := range a.Services {
				if c.Service == u.st.Service {
					ids = append(ids, c.ContainerID)
					running = running || c.Running()
				}
			}
		}
	}
	return r.s.startGate.Admit(time.Now(), startgate.AdmitOpts{ExcludeContainerIDs: ids, IgnoreCPU: !running, IgnoreApp: r.o.App})
}

// call makes u's docker call. The caller holds the docker slot, so only the *Held runner methods.
func (r *rolloutRun) call(ctx context.Context, u rolloutUnit) error {
	s := r.s
	switch {
	case u.copy != "" && u.st.CopyAction == "restart":
		return s.runner.RestartContainersHeld(ctx, []string{u.copy}, r.onLine)
	case u.copy != "":
		return s.runner.StartContainersHeld(ctx, []string{u.copy}, r.onLine)
	case u.st.Reap:
		job := u.st.Job
		return s.runUpWithConflictReap(ctx, r.o.App, r.declared,
			func(c context.Context, ol func(string)) error { return s.runner.RunHeld(c, job, ol) },
			s.runner.RemoveContainersHeld, r.onLine)
	default:
		return s.runner.RunHeld(ctx, u.st.Job, r.onLine)
	}
}

// settle waits, while the rollout paces, for what u's docker call (made at start, returned at end)
// started to settle, reading only container views taken after end. A container that fails, or
// doesn't settle within the step's deadline (cut to what is left of the rollout budget), is reported
// and the rollout goes on. The docker slot isn't held.
func (r *rolloutRun) settle(ctx context.Context, u rolloutUnit, start, end time.Time) error {
	if !r.pacing() {
		return nil
	}
	if r.s.mon != nil {
		r.s.mon.Kick() // see what the step started without waiting for the next poll
	}
	limit := u.st.Deadline
	if limit <= 0 {
		limit = settleDeadline(nil, r.set.MaxSettle, r.set.ServiceSettle)
	}
	if left := r.set.RolloutBudget - time.Since(r.began); left < limit {
		limit = left
	}
	fresh := false // a container view taken after end has arrived
	waiting := "still starting"
	said := end
	viewWait := rolloutSnapshotWait
	if pi := r.s.cfg.Monitor.PollInterval.D(); pi > 0 {
		// A poll may take up to max(2×interval, 30s), and a kick can queue behind one in progress.
		budget := 2 * pi
		if budget < 30*time.Second {
			budget = 30 * time.Second
		}
		if w := 2*budget + 10*time.Second; w > viewWait {
			viewWait = w
		}
	}
	budgetCut := limit < u.st.Deadline || u.st.Deadline <= 0 && limit < settleDeadline(nil, r.set.MaxSettle, r.set.ServiceSettle)
	for {
		if snap := r.s.snapshot(); rolloutViewOK(snap) && snap.At.After(end) {
			fresh = true
			r.s.observeStarts(snap)
			v := r.check(snap, u, start)
			switch {
			case v.problem != "":
				r.problem(u, v.problem)
				return nil
			case v.done != "":
				r.onLine(r.settledLine(u, v.done, time.Since(end)))
				return nil
			}
			waiting = v.waiting
		}
		now := time.Now()
		switch {
		case now.Sub(end) >= limit && budgetCut:
			// The rollout budget ran out while waiting: stop waiting without calling this service a problem
			// (the rollout reports the unchecked services once).
			if !r.unpaced {
				r.unpaced = true
				r.onLine(fmt.Sprintf("  pacing budget (%s) used up — starting the remaining services without waiting", rolloutRound(r.set.RolloutBudget)))
			}
			r.onLine("  " + u.label + ": not waiting any longer to see it settle")
			return nil
		case !fresh && now.Sub(end) >= viewWait:
			r.problem(u, "couldn't check health: the container view isn't updating")
			return nil
		case !fresh && now.Sub(end) >= limit: // a deadline shorter than the view wait
			r.problem(u, fmt.Sprintf("couldn't check health within %s", rolloutRound(limit)))
			return nil
		case now.Sub(end) >= limit:
			r.problem(u, fmt.Sprintf("%s after %s", waiting, rolloutRound(limit)))
			return nil
		}
		if now.Sub(said) >= rolloutHeartbeat {
			said = now
			r.onLine(fmt.Sprintf("  %s: starting… (%s)", u.label, rolloutRound(now.Sub(end))))
		}
		if now.Sub(r.renewed) >= rolloutRenewEvery {
			r.renew()
		}
		if err := rolloutSleep(ctx, rolloutPoll); err != nil {
			return err
		}
	}
}

// rolloutVerdict is what one container view says about what a unit started: done (how it settled),
// problem (why it failed), or neither (waiting says what it is still doing).
type rolloutVerdict struct {
	done, problem, waiting string
}

// check reads what u started from snap: this app's containers of the service (for a copy, that
// copy) whose current run began at or after start, less 1s for clock rounding. A container not yet
// inspected may be one of them. The step fails on the first container that failed; it is done when
// all of them settled, or at once when it started none (compose left the service as it was).
func (r *rolloutRun) check(snap *monitor.Snapshot, u rolloutUnit, start time.Time) rolloutVerdict {
	var v rolloutVerdict
	wait := func(why string) {
		if v.waiting != "not running" {
			v.waiting = why
		}
	}
	listed, mine := false, 0
	unhealthy, noCheck, completed := false, false, false
	if a := snap.AppByProject(r.o.App); a != nil {
		for _, c := range a.Services {
			if c.Service != u.st.Service || (u.copy != "" && !idMatch(c.ContainerID, u.copy)) {
				continue
			}
			listed = true
			if c.Inspected && c.StartedAt.Before(start.Add(-time.Second)) {
				continue // running since before the step: not something it started
			}
			mine++
			switch {
			case !c.Inspected:
				wait("still starting")
			case c.Running():
				switch c.Health {
				case "healthy":
				case "unhealthy":
					if !u.st.Notify {
						return rolloutVerdict{problem: "unhealthy"}
					}
					unhealthy = true
				case "starting":
					wait("still starting")
				default: // no healthcheck: settled once the start gate stops counting it as starting
					if r.s.startGate.Unsettled(c.ContainerID, time.Now()) {
						wait("still starting")
					} else {
						noCheck = true
					}
				}
			case c.State == "restarting":
				wait("not running") // its restart policy is bringing it back
			case c.ExitCode == 0:
				completed = true // ended cleanly (a run-once service); a restart policy may start it again
			case u.st.Restarts:
				wait("not running") // its restart policy may still bring it back
			default:
				return rolloutVerdict{problem: fmt.Sprintf("exited (code %d)", c.ExitCode)}
			}
		}
	}
	switch {
	case v.waiting != "":
		return v
	case mine == 0 && !listed && snap.Truncated:
		// The view covers only part of the host's containers: absence proves nothing.
		return rolloutVerdict{problem: "couldn't check health: the container view doesn't list it (too many containers)"}
	case mine == 0:
		v.done = "unchanged"
	case unhealthy:
		v.done = "unhealthy"
	case completed:
		v.done = "completed"
	case noCheck:
		v.done = "started"
	default:
		v.done = "healthy"
	}
	return v
}

// settledLine is the progress line for a unit that settled (how, from check) took after its call.
func (r *rolloutRun) settledLine(u rolloutUnit, how string, took time.Duration) string {
	switch how {
	case "unchanged":
		if u.copy != "" {
			return "  " + u.label + ": already running"
		}
		return "  " + u.label + ": unchanged"
	case "healthy":
		return fmt.Sprintf("  %s: healthy after %s", u.label, rolloutRound(took))
	case "unhealthy":
		return fmt.Sprintf("  %s: unhealthy after %s (on_unhealthy: notify)", u.label, rolloutRound(took))
	}
	return "  " + u.label + ": " + how
}

// problem reports that u didn't come up cleanly; the rollout goes on.
func (r *rolloutRun) problem(u rolloutUnit, reason string) {
	r.onLine("  ⚠ " + u.label + ": " + reason + " — continuing")
	if u.copy != "" {
		reason += " (copy " + shortContainerID(u.copy) + ")"
	}
	r.problems = append(r.problems, rolloutProblem{Service: u.st.Service, Reason: reason})
}

func (r *rolloutRun) unlock() {
	if r.o.Unlock != nil {
		r.o.Unlock()
	}
}

func (r *rolloutRun) renew() {
	r.renewed = time.Now()
	if r.o.Renew != nil {
		r.o.Renew()
	}
}

// rolloutCallTimeout bounds one docker call of st: its Timeout (default 3m for a copy, 10m for a compose
// call) plus the service's stop grace, which stopping a copy may take in full.
func rolloutCallTimeout(st rolloutStep, copy bool) time.Duration {
	d := st.Timeout
	if d <= 0 {
		d = 10 * time.Minute
		if copy {
			d = 3 * time.Minute
		}
	}
	if st.StopGrace > 0 {
		d += st.StopGrace
	}
	return d
}

// rolloutJobLine is a step's compose call, for its header line.
func rolloutJobLine(j dockerexec.Job) string {
	line := "docker compose " + strings.Join(j.Action, " ")
	if j.Service != "" {
		line += " -- " + j.Service
	}
	return line
}

// rolloutViewOK reports whether snap lists the host's containers.
func rolloutViewOK(snap *monitor.Snapshot) bool {
	return snap != nil && snap.DockerOK && !snap.ListFailed
}

// rolloutSleep waits d, or until ctx ends.
func rolloutSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// rolloutRound rounds a duration for progress lines: to the second, or to the millisecond below one.
func rolloutRound(d time.Duration) time.Duration {
	if d >= time.Second {
		return d.Round(time.Second)
	}
	return d.Round(time.Millisecond)
}

// settleDeadline is how long a rollout waits for a service to settle after starting it: with a
// healthcheck, its whole start-up window — start_period + (interval + timeout) × (retries + 1) +
// 60s — else maxSettle + 30s (the start gate's bound on a start without a healthcheck); never more
// than limit.
func settleDeadline(hc *definition.Healthcheck, maxSettle, limit time.Duration) time.Duration {
	d := maxSettle + 30*time.Second
	if hc != nil && len(hc.Test) > 0 {
		d = hc.StartPeriodD() + (hc.IntervalD()+hc.TimeoutD())*time.Duration(hc.RetriesN()+1) + time.Minute
	}
	if limit > 0 && d > limit {
		d = limit
	}
	return d
}

// rolloutOrder lists services with each one after the services it depends on (deps), otherwise by
// name. A dependency on a service not in services is ignored; a cycle is broken where it closes.
func rolloutOrder(services []string, deps map[string][]string) []string {
	names := append([]string(nil), services...)
	sort.Strings(names)
	present := make(map[string]bool, len(names))
	for _, n := range names {
		present[n] = true
	}
	state := map[string]int{} // 1 visiting, 2 done
	out := make([]string, 0, len(names))
	var visit func(n string)
	visit = func(n string) {
		if state[n] != 0 {
			return
		}
		state[n] = 1
		ds := append([]string(nil), deps[n]...)
		sort.Strings(ds)
		for _, d := range ds {
			if present[d] {
				visit(d)
			}
		}
		state[n] = 2
		out = append(out, n)
	}
	for _, n := range names {
		visit(n)
	}
	return out
}

// restartPolicy reports whether a compose restart policy restarts a container that exited.
func restartPolicy(p string) bool {
	switch strings.TrimSpace(p) {
	case "always", "unless-stopped", "on-failure":
		return true
	}
	return strings.HasPrefix(strings.TrimSpace(p), "on-failure:")
}

// deployTimeout bounds a build-and-rollout action (lifecycle redeploys, certificate renewals): the build
// (and the fetch before it, gitDeployTimeout) and the rollout's pacing budget, with room for the docker
// calls themselves.
func (s *Server) deployTimeout() time.Duration {
	budget := 45 * time.Minute // server.start_gate.rollout_budget's default
	if s.cfg != nil {
		budget = s.cfg.Server.StartGateSettings().RolloutBudget
	}
	return gitDeployTimeout + budget + 10*time.Minute
}

// repoDeployTimeout bounds a whole git deploy: deployTimeout plus the longest spec.release job.
func (s *Server) repoDeployTimeout() time.Duration {
	return s.deployTimeout() + definition.ReleaseTimeoutMax
}
