package web

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/monitor"
)

// cronBaseInterval is how often the scheduler wakes to check which tasks are due.
const cronBaseInterval = time.Minute

// A single scheduled-task run is capped by its per-task timeout (spec.scheduled_tasks[].timeout,
// default 30m via ScheduledTask.TimeoutD) — a stuck job can't hold the docker slot forever; the
// process group is reaped on timeout.

// cronHistoryTTL is how long a finished run (and its captured log) is kept on the Scheduled-tasks tab.
const cronHistoryTTL = 7 * 24 * time.Hour

// cronLog accumulates a scheduled task's output, bounded to the last cronLogKeep bytes (the tail —
// where the error usually is), so a chatty task can't blow up memory or the stored log.
const cronLogKeep = 64 << 10

type cronLog struct {
	lines []string
	bytes int
}

func (b *cronLog) add(l string) {
	b.lines = append(b.lines, l)
	b.bytes += len(l) + 1
	for b.bytes > cronLogKeep && len(b.lines) > 1 {
		b.bytes -= len(b.lines[0]) + 1
		b.lines = b.lines[1:]
	}
}

func (b *cronLog) String() string { return strings.Join(b.lines, "\n") }

// RunCron is the scheduled-task (cron) loop: each minute it checks every app's scheduled_tasks
// and runs any that are DUE (its interval has elapsed since the last run) as a fresh one-shot
// `docker compose run --rm --no-deps <service>` container — never an exec into a running one.
// It rides the one-docker-child slot via TryAcquire (skip-don't-queue): a task never QUEUES a
// docker child, and one that can't get the slot this minute retries the next. (A task that is
// already running does hold the slot for its duration, so a deploy triggered meanwhile waits
// behind it — bounded by cronTaskTimeout.) Last-run state is persisted so a restart doesn't
// re-fire everything.
func (s *Server) RunCron(ctx context.Context) {
	if s.cronStore == nil || s.gitStore == nil || s.defStore == nil || s.runner == nil || s.dockerSem == nil {
		return
	}
	// A one-shot cron container cannot survive a restart, so any run still flagged "running" is a
	// phantom from a prior crash/shutdown — clear it so the "running now" view is honest.
	_ = s.cronStore.ReconcileRunningOnBoot(context.WithoutCancel(ctx), time.Now().Unix())
	select {
	case <-time.After(90 * time.Second): // let boot settle
	case <-ctx.Done():
		return
	}
	t := time.NewTicker(cronBaseInterval)
	defer t.Stop()
	for {
		s.cronTick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) cronTick(ctx context.Context) {
	// Trim run history + logs past the TTL (indexed delete; usually a no-op).
	_ = s.cronStore.PruneHistory(context.WithoutCancel(ctx), time.Now().Add(-cronHistoryTTL).Unix())
	if ok, _ := s.runner.WriteAllowed(); !ok {
		return
	}
	apps, err := s.gitStore.List()
	if err != nil {
		return
	}
	now := time.Now().Unix()
	for _, a := range apps {
		if ctx.Err() != nil {
			return
		}
		def, err := s.defStore.Current(a.Project)
		if err != nil || def == nil || len(def.Spec.ScheduledTasks) == 0 {
			continue
		}
		for _, task := range def.Spec.ScheduledTasks {
			every, perr := time.ParseDuration(task.Every)
			if perr != nil || every < time.Minute {
				every = time.Minute
			}
			last, _ := s.cronStore.Get(ctx, a.Project, task.Name)
			if now-last.LastRun < int64(every.Seconds()) {
				continue // not due yet
			}
			s.runScheduledTask(ctx, a.Project, task, now)
		}
	}
}

// runScheduledTask runs one due task under a briefly-held docker slot (TryAcquire; skip if a
// deploy holds it). It reuses the deploy machinery — the app's run dir, its generated compose,
// and a freshly-rendered 0600 env-file — so the one-shot container gets the app's env, secrets,
// and network. Records the outcome and alerts on failure.
func (s *Server) runScheduledTask(ctx context.Context, slug string, task definition.ScheduledTask, now int64) {
	if !s.dockerSem.TryAcquire() {
		return // a deploy/self-heal holds the slot — retry next tick
	}
	defer s.dockerSem.Release()

	rd := s.appRunDir(slug)
	composeAbs := filepath.Join(rd, "docker-compose.yml")
	if _, err := os.Stat(composeAbs); err != nil {
		return // app not deployed yet — nothing to run
	}
	app := &monitor.App{Project: slug, WorkingDir: rd, ConfigFiles: []string{composeAbs}}
	env := s.composeEnv(app)
	envFile, cleanup, ferr := s.renderEnvFile(app, env)
	defer cleanup()
	if ferr != nil {
		s.log.Warn("scheduled task: env render failed", "app", slug, "task", task.Name)
		return
	}
	job := dockerexec.Job{
		Project: slug, Dir: rd, ConfigFiles: app.ConfigFiles, EnvFile: envFile,
		Action: []string{"run", "--rm", "--no-deps"}, Service: task.Service,
	}
	// Bind the run to the SERVER ctx (+ the task's cap) so a Mooring shutdown reaps a hung task
	// instead of blocking the graceful stop for the whole timeout. Bookkeeping writes use a detached
	// context so the outcome is still recorded even as the server ctx cancels. The timeout is
	// per-task (spec.scheduled_tasks[].timeout), defaulting to 30m — a task holds the single docker
	// slot for its whole run, so the ceiling bounds how long it can block deploys/other tasks.
	bg := context.WithoutCancel(ctx)
	timeout := task.TimeoutD()
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Record the run start (a "running" row) so the Scheduled-tasks tab shows it live.
	runID, _ := s.cronStore.StartRun(bg, slug, task.Name, task.Service, now)

	var lastLine string
	var lg cronLog
	runErr := s.runner.RunHeld(rctx, job, func(l string) { lastLine = l; lg.add(l) })
	ok := runErr == nil
	if runErr != nil {
		// `run --rm` auto-removes on a clean exit, but a KILLED CLI (timeout/shutdown) can't —
		// best-effort reap the app's orphaned one-shot container so it can't keep running or
		// accumulate. Safe because RunCron is serial (no other one-shot is live right now).
		s.runner.ReapOneOffHeld(bg, slug)
	}
	_ = s.cronStore.Record(bg, slug, task.Name, now, ok)
	detail := "service " + task.Service
	exitCode := 0
	if runErr != nil {
		detail += ": " + cronFailReason(lastLine, rctx.Err(), timeout)
		exitCode, _ = classifyExit(runErr)
	}
	_ = s.cronStore.FinishRun(bg, runID, time.Now().Unix(), ok, exitCode, detail, lg.String())
	outcome := audit.OK
	if runErr != nil {
		outcome = audit.Error
		s.log.Warn("scheduled task failed", "app", slug, "task", task.Name, "err", runErr)
		if s.alertStore != nil {
			_ = s.alertStore.EnqueueInfra(bg, alert.Outbox{
				Target: slug, Kind: "scheduled_task", Level: alert.LevelWarning, Transition: "firing",
				Summary:   fmt.Sprintf("scheduled task %q for %s failed: %s", task.Name, slug, lastLine),
				DedupeKey: "cron:" + slug + ":" + task.Name,
			})
		}
	}
	// Record WHY in the audit Detail too (the same concise reason recorded on the run). Previously
	// always blank, which made a failed task's incident row unable to show a reason.
	_ = s.audit.Log(bg, audit.Event{Actor: "scheduler", Action: "scheduled_task", Target: slug + "/" + task.Name, Outcome: outcome, Level: audit.Security, Detail: detail})
}

// cronFailReason builds a concise, single-line reason for a failed scheduled task: the task's last
// output line if it produced one (that is where the real error usually is), else a classified reason
// for the empty-output cases (timeout uses the actual per-task cap). CR/LF/NUL are flattened and the
// string is length-bounded so it can't break the audit row.
func cronFailReason(lastLine string, ctxErr error, timeout time.Duration) string {
	r := strings.TrimSpace(lastLine)
	if r == "" {
		switch ctxErr {
		case context.DeadlineExceeded:
			return fmt.Sprintf("timed out after %s", timeout)
		case context.Canceled:
			return "cancelled (Mooring shutting down)"
		default:
			return "run failed"
		}
	}
	r = strings.Map(func(rn rune) rune {
		if rn == '\r' || rn == '\n' || rn == 0 {
			return ' '
		}
		return rn
	}, r)
	if len(r) > 300 {
		r = r[:300] + "…"
	}
	return r
}
