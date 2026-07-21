// Package monitor is the read-plane poller (plan §4): it discovers apps (one
// per Docker Compose project), builds the normalized BASIC health record for
// each service (plan §4.3), samples host metrics, holds the latest snapshot in
// memory for the UI, and persists metric samples. It only ever READS Docker
// (through the socket-proxy) — no write can originate here.
package monitor

import (
	"context"
	"log/slog"
	"sort"
	"sync/atomic"
	"time"

	"github.com/daboss2003/mooring/internal/docker"
	"github.com/daboss2003/mooring/internal/hostmon"
	"github.com/daboss2003/mooring/internal/ops"
	"github.com/daboss2003/mooring/internal/store"
)

// ServiceStatus is the normalized BASIC record for one container/service.
type ServiceStatus struct {
	Service      string
	ContainerID  string
	Name         string
	Image        string
	State        string
	Health       string
	CPUPercent   float64
	MemBytes     uint64
	MemLimit     uint64
	RestartCount int
	ExitCode     int  // last exit code (137 ≈ OOM/at-limit kill — used by the supervisor)
	OOMKilled    bool // the container's last stop was an OOM kill
	HasRWVolume  bool // a shared read-write bind/named volume (auto-scaling C3 disqualifier)
	StatusText   string
}

// Running reports whether the service container is running.
func (s ServiceStatus) Running() bool { return s.State == "running" }

// App is one Compose project and its services. Ops is the canonical App Ops
// Interface record (nil when ops is not configured for this app — plan §4.3).
// WorkingDir/ConfigFiles come from the compose labels and let the write plane
// target `docker compose` for this project.
type App struct {
	Project     string
	DisplayName string
	Services    []ServiceStatus
	Ops         *ops.Result
	WorkingDir  string
	ConfigFiles []string
}

// Rich reports whether the app has a RICH ops record.
func (a App) Rich() bool { return a.Ops != nil && a.Ops.Mode == ops.RICH }

// UpCount returns the number of running services.
func (a App) UpCount() int {
	n := 0
	for _, s := range a.Services {
		if s.Running() {
			n++
		}
	}
	return n
}

// Total returns the number of services.
func (a App) Total() int { return len(a.Services) }

// Degraded reports whether any service is down or unhealthy.
func (a App) Degraded() bool {
	for _, s := range a.Services {
		if !s.Running() || s.Health == "unhealthy" {
			return true
		}
	}
	return false
}

// Snapshot is the full read-plane view the UI renders.
type Snapshot struct {
	At        time.Time
	DockerOK  bool
	DockerErr string
	Version   string
	Apps      []App
	Host      hostmon.Sample
	HostOK    bool
	HostErr   string
}

// AppByProject returns the app with the given project, or nil.
func (s *Snapshot) AppByProject(project string) *App {
	for i := range s.Apps {
		if s.Apps[i].Project == project {
			return &s.Apps[i]
		}
	}
	return nil
}

// Monitor runs the poll loop and publishes snapshots.
type Monitor struct {
	db        *store.DB
	cli       *docker.Client
	host      *hostmon.Sampler
	interval  time.Duration
	retention time.Duration
	log       *slog.Logger

	snap               atomic.Pointer[Snapshot]
	hostUnsupp         bool // logged-once flag for unsupported host metrics
	containerCapWarned bool // logged-once flag for the per-poll container cap
	pruneEvery         int
	tickCount          int
	prober             *ops.Prober // may be nil (ops disabled → BASIC only)
	// prevCPU carries last tick's raw CPU counters per container for %-delta
	// calc. Accessed only from the single Run/pollOnce goroutine.
	prevCPU map[string]cpuCounters
}

// cpuCounters holds a container's raw CPU usage counters for one tick.
type cpuCounters struct{ total, system uint64 }

// New builds a Monitor. prober may be nil (ops probing disabled).
func New(db *store.DB, cli *docker.Client, host *hostmon.Sampler, interval, retention time.Duration, log *slog.Logger, prober *ops.Prober) *Monitor {
	return &Monitor{
		db: db, cli: cli, host: host,
		interval: interval, retention: retention, log: log,
		prober:     prober,
		pruneEvery: 30, // prune roughly every 30 ticks
	}
}

// Snapshot returns the latest published snapshot (nil before the first poll).
func (m *Monitor) Snapshot() *Snapshot { return m.snap.Load() }

// Run polls immediately, then every interval, until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) {
	m.snap.Store(m.pollOnce(ctx))
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.snap.Store(m.pollOnce(ctx))
		}
	}
}

// maxContainersPerPoll bounds per-tick Docker round-trips and inserts so an
// accidentally (or maliciously) huge host can't make a poll run for minutes or
// flood the DB (review #5). Far above any tiny-box workload.
const maxContainersPerPoll = 500

// pollBudget caps the wall-clock time of a single poll so a slow-but-not-dead
// proxy can't stall the poller proportional to container count (review #1). The
// per-request http.Client timeouts are secondary guards under this.
func (m *Monitor) pollBudget() time.Duration {
	if b := 2 * m.interval; b > 30*time.Second {
		return b
	}
	return 30 * time.Second
}

func (m *Monitor) pollOnce(parent context.Context) *Snapshot {
	now := time.Now()
	snap := &Snapshot{At: now}

	ctx, cancel := context.WithTimeout(parent, m.pollBudget())
	defer cancel()

	ver, err := m.cli.Version(ctx)
	if err != nil {
		snap.DockerErr = "cannot reach docker socket-proxy"
		m.sampleHost(snap)
		return snap
	}
	snap.DockerOK = true
	snap.Version = ver.Version

	containers, err := m.cli.ListContainers(ctx, true)
	if err != nil {
		snap.DockerErr = "cannot list containers"
		m.sampleHost(snap)
		return snap
	}
	if len(containers) > maxContainersPerPoll {
		sort.Slice(containers, func(i, j int) bool { return containers[i].ID < containers[j].ID })
		if !m.containerCapWarned {
			m.containerCapWarned = true
			m.log.Warn("container count exceeds per-poll cap; only a subset is monitored",
				"count", len(containers), "cap", maxContainersPerPoll)
		}
		containers = containers[:maxContainersPerPoll]
	}

	prev := m.prevCPU
	if prev == nil {
		prev = map[string]cpuCounters{}
	}
	next := make(map[string]cpuCounters)

	byProject := map[string][]ServiceStatus{}
	projMeta := map[string]docker.Container{} // first container per project (for labels)
	for _, c := range containers {
		project := c.Project()
		if project == "" {
			continue // not a compose-managed app
		}
		if c.OneOff() {
			continue // transient `compose run` one-shot (cron task / backup sidecar), not a service
		}
		if _, ok := projMeta[project]; !ok {
			projMeta[project] = c
		}
		svc := ServiceStatus{
			Service:     c.Service(),
			ContainerID: c.ID,
			Name:        c.Name(),
			Image:       c.Image,
			State:       c.State,
			StatusText:  c.Status,
			Health:      "none",
		}
		if ci, err := m.cli.InspectContainer(ctx, c.ID); err == nil {
			svc.RestartCount = ci.RestartCount
			svc.Health = ci.HealthStatus()
			svc.ExitCode = ci.State.ExitCode
			svc.OOMKilled = ci.State.OOMKilled
			svc.HasRWVolume = ci.HasSharedRWVolume()
		}
		if c.State == "running" {
			if st, err := m.cli.StatsOneShot(ctx, c.ID); err == nil {
				total, system := st.RawCPU()
				if p, ok := prev[c.ID]; ok {
					svc.CPUPercent = st.CPUPercentBetween(p.total, p.system)
				}
				next[c.ID] = cpuCounters{total: total, system: system}
				svc.MemBytes = st.MemUsed()
				svc.MemLimit = st.MemLimit()
			}
		}
		byProject[project] = append(byProject[project], svc)
	}
	m.prevCPU = next

	for project, svcs := range byProject {
		sort.Slice(svcs, func(i, j int) bool { return svcs[i].Service < svcs[j].Service })
		meta := projMeta[project]
		snap.Apps = append(snap.Apps, App{
			Project: project, DisplayName: project, Services: svcs,
			WorkingDir: meta.WorkingDir(), ConfigFiles: meta.ConfigFiles(),
		})
	}
	sort.Slice(snap.Apps, func(i, j int) bool { return snap.Apps[i].Project < snap.Apps[j].Project })

	// App Ops Interface probe (plan §4): sequential, within the per-poll budget.
	// A compromised app's response can only ever degrade it to BASIC, never crash.
	if m.prober != nil {
		for i := range snap.Apps {
			if ctx.Err() != nil {
				break
			}
			if res, ok := m.prober.Probe(ctx, snap.Apps[i].Project); ok {
				snap.Apps[i].Ops = res
			}
		}
	}

	// If the per-poll budget expired mid-collection, surface that the view is
	// partial rather than silently showing a subset (review #1).
	if ctx.Err() != nil {
		snap.DockerErr = "metrics poll timed out (slow socket-proxy?); showing partial data"
	}

	m.sampleHost(snap)
	m.persist(parent, snap)
	return snap
}

func (m *Monitor) sampleHost(snap *Snapshot) {
	s, err := m.host.Sample()
	if err != nil {
		snap.HostErr = "host metrics unavailable"
		if err == hostmon.ErrUnsupported && !m.hostUnsupp {
			m.hostUnsupp = true
			m.log.Info("host metrics not supported on this platform; app monitoring continues")
		}
		return
	}
	snap.HostOK = true
	snap.Host = s
}

// persist writes the snapshot's metrics in ONE transaction (review #5) through
// the single SQLite writer, derived from parent with a short deadline so a
// shutdown (parent cancel) aborts cleanly. All writes are best-effort: a failed
// metric insert must never break the read plane.
func (m *Monitor) persist(parent context.Context, snap *Snapshot) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	ts := snap.At.Unix()

	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	for _, app := range snap.Apps {
		// Reconcile the app registry.
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO apps(project, display_name, discovered, first_seen, last_seen)
			 VALUES(?, ?, 1, ?, ?)
			 ON CONFLICT(project) DO UPDATE SET last_seen = excluded.last_seen`,
			app.Project, app.DisplayName, ts, ts); err != nil {
			return
		}
		for _, s := range app.Services {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO container_metrics(ts, project, service, container_id, state, health, cpu_pct, mem_bytes, mem_limit, restart_count)
				 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				ts, app.Project, s.Service, s.ContainerID, s.State, s.Health,
				s.CPUPercent, int64(s.MemBytes), int64(s.MemLimit), s.RestartCount); err != nil {
				return
			}
		}
	}
	if snap.HostOK {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO host_metrics(ts, cpu_pct, load1, mem_total, mem_used, disk_total, disk_used)
			 VALUES(?, ?, ?, ?, ?, ?, ?)`,
			ts, snap.Host.CPUPercent, snap.Host.Load1,
			int64(snap.Host.MemTotal), int64(snap.Host.MemUsed),
			int64(snap.Host.DiskTotal), int64(snap.Host.DiskUsed)); err != nil {
			return
		}
	}

	// Opportunistic age-based pruning (full retention/VACUUM is §16/M18).
	m.tickCount++
	if m.tickCount%m.pruneEvery == 0 {
		cutoff := snap.At.Add(-m.retention).Unix()
		_, _ = tx.ExecContext(ctx, `DELETE FROM container_metrics WHERE ts < ?`, cutoff)
		_, _ = tx.ExecContext(ctx, `DELETE FROM host_metrics WHERE ts < ?`, cutoff)
	}

	if err := tx.Commit(); err == nil {
		committed = true
	}
}
