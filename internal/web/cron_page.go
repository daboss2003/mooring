package web

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/daboss2003/mooring/internal/cronstore"
	"github.com/daboss2003/mooring/internal/docker"
)

// cronHistoryView is one row in the run-history table.
type cronHistoryView struct {
	ID           int64
	Slug         string // the app that owns the task
	Task         string
	Service      string
	StartedAt    int64
	Finished     bool
	OK           bool
	ExitCode     int
	Detail       string
	DurationText string // "1m 30s" for a finished run, "" while running
}

// cronRunningView is one currently-running task, with live resource use.
type cronRunningView struct {
	ID          int64
	Slug        string
	Task        string
	Service     string
	ElapsedText string
	HasStats    bool
	CPUPercent  float64
	MemUsed     uint64
	MemLimit    uint64
}

// historyView adapts a store row for the table.
func historyView(r cronstore.HistoryRow) cronHistoryView {
	v := cronHistoryView{
		ID: r.ID, Slug: r.Slug, Task: r.Task, Service: r.Service,
		StartedAt: r.StartedAt, Finished: r.Finished, OK: r.OK, ExitCode: r.ExitCode, Detail: r.Detail,
	}
	if r.Finished && r.FinishedAt >= r.StartedAt {
		v.DurationText = humanDurSecs(r.FinishedAt - r.StartedAt)
	}
	return v
}

// humanDurSecs renders a whole-second duration compactly (e.g. "2h 3m", "1m 30s", "12s").
func humanDurSecs(secs int64) string {
	if secs < 0 {
		secs = 0
	}
	d := time.Duration(secs) * time.Second
	switch {
	case d >= time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
}

// handleCron renders the Scheduled-tasks tab: what is running right now (with live CPU/memory) and
// the recent run history (paginated), across all apps. Read-only; auth-gated.
func (s *Server) handleCron(w http.ResponseWriter, r *http.Request) {
	if s.cronStore == nil {
		http.Error(w, "scheduled tasks unavailable", http.StatusServiceUnavailable)
		return
	}
	const pageSize = 30
	page := 1
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 1 {
		page = p
	}
	d := tmplData{Title: "Scheduled tasks — Mooring", Username: sessionUser(r)}
	d.CronRunning = s.runningCrons(r.Context())
	if rows, hasMore, err := s.cronStore.History(r.Context(), "", pageSize, (page-1)*pageSize); err == nil {
		for _, row := range rows {
			d.CronHistory = append(d.CronHistory, historyView(row))
		}
		if page == 2 {
			d.CronPrevURL = "/cron"
		} else if page > 2 {
			d.CronPrevURL = "/cron?page=" + strconv.Itoa(page-1)
		}
		if hasMore {
			d.CronNextURL = "/cron?page=" + strconv.Itoa(page+1)
		}
	}
	s.render(w, r, "cron.html", d)
}

// handleCronRunning is the live-poll fragment for the "running now" section — refreshed on a timer so
// elapsed time and CPU/memory update without a full reload.
func (s *Server) handleCronRunning(w http.ResponseWriter, r *http.Request) {
	if s.cronStore == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	s.render(w, r, "cron_running.html", tmplData{CronRunning: s.runningCrons(r.Context())})
}

// handleCronRunLog shows one run's captured output (bounded, 7-day TTL).
func (s *Server) handleCronRunLog(w http.ResponseWriter, r *http.Request) {
	if s.cronStore == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	run, ok, err := s.cronStore.GetRun(r.Context(), id)
	if err != nil || !ok {
		http.Error(w, "run not found (it may have passed its 7-day retention)", http.StatusNotFound)
		return
	}
	s.render(w, r, "cron_log.html", tmplData{
		Title:    "Task run — " + run.Slug + "/" + run.Task,
		Username: sessionUser(r),
		CronRun:  &run,
	})
}

// runningCrons returns the in-flight task runs with live CPU/memory read from their one-shot
// containers (found via the read-plane by compose project+service+one-off label). Live stats need
// two stats samples ~600ms apart, so this only pays that cost when a task is actually running
// (usually zero — the scheduler runs tasks one at a time).
func (s *Server) runningCrons(ctx context.Context) []cronRunningView {
	running, err := s.cronStore.Running(ctx)
	if err != nil || len(running) == 0 {
		return nil
	}
	now := time.Now().Unix()
	var conts []docker.Container
	if s.docker != nil {
		conts, _ = s.docker.ListContainers(ctx, false) // running only
	}
	out := make([]cronRunningView, 0, len(running))
	for _, run := range running {
		v := cronRunningView{
			ID: run.ID, Slug: run.Slug, Task: run.Task, Service: run.Service,
			ElapsedText: humanDurSecs(now - run.StartedAt),
		}
		if c, ok := findOneOff(conts, run.Slug, run.Service); ok {
			if cpu, mu, ml, ok := s.liveContainerStats(ctx, c.ID); ok {
				v.HasStats, v.CPUPercent, v.MemUsed, v.MemLimit = true, cpu, mu, ml
			}
		}
		out = append(out, v)
	}
	return out
}

// findOneOff returns the running one-shot (`compose run`) container for a project+service, if any.
func findOneOff(conts []docker.Container, project, service string) (docker.Container, bool) {
	for _, c := range conts {
		if c.OneOff() && c.Project() == project && c.Service() == service {
			return c, true
		}
	}
	return docker.Container{}, false
}

// liveContainerStats computes a container's live CPU% + memory from two quick stats samples.
func (s *Server) liveContainerStats(ctx context.Context, id string) (cpuPct float64, memUsed, memLimit uint64, ok bool) {
	if s.docker == nil {
		return 0, 0, 0, false
	}
	a, err := s.docker.StatsOneShot(ctx, id)
	if err != nil {
		return 0, 0, 0, false
	}
	select {
	case <-ctx.Done():
		return 0, 0, 0, false
	case <-time.After(600 * time.Millisecond):
	}
	b, err := s.docker.StatsOneShot(ctx, id)
	if err != nil {
		return 0, 0, 0, false
	}
	return b.CPUPercentBetween(a.CPUStats.CPUUsage.TotalUsage, a.CPUStats.SystemUsage), b.MemUsed(), b.MemLimit(), true
}
