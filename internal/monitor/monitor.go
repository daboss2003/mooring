// Package monitor is the read-plane poller (plan §4): it discovers apps (one
// per Docker Compose project), builds the normalized BASIC health record for
// each service (plan §4.3), samples host metrics, holds the latest snapshot in
// memory for the UI, and persists metric samples. It only ever READS Docker
// (through the socket-proxy) — no write can originate here.
package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
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
	// StartedAt is when the container's current run started (its last run, if it is
	// not running): inspect State.StartedAt. Zero when unknown, unparseable, or
	// Docker's zero time (never started). A restart keeps the container id, so a new
	// StartedAt only arrives with a fresh inspect.
	StartedAt time.Time
	// Inspected reports that Health, RestartCount, ExitCode, OOMKilled, StartedAt and
	// HasRWVolume come from a successful inspect: this poll's or, when this poll's
	// failed or the budget ran out, the last one carried forward if it is at most
	// inspectCarryPolls (2) polls old and this poll's list entry still agrees with it
	// (same State, no other health in the Status text). False means they are defaults
	// and must not be trusted.
	Inspected bool
	// CPUValid reports that CPUPercent is a real delta between two stats samples of
	// the same run; after a missed sample the delta spans the longer window. False,
	// with CPUPercent 0, on a container's first sample, when it is not running, when
	// its stats failed or were skipped this poll, and across a restart.
	CPUValid bool
	// ImageID is the image the container runs (sha256:…) and ConfigHash compose's hash of the
	// service definition it was created from — both from the container list.
	ImageID    string
	ConfigHash string
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

	// ListFailed: the container list couldn't be read, so Apps is empty although containers may be
	// running. Anything that acts on the absence of containers (self-heal pruning its state, the
	// autoscaler, the start gate) must skip such a snapshot. Deploys are not refused for it.
	ListFailed bool
	// Truncated: the host has more containers than one poll covers (maxContainersPerPoll), so a
	// container missing from Apps may still exist. Never read absence as "gone" from such a snapshot.
	Truncated bool
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
	// prevCPU carries each listed container's last raw CPU counters for %-delta
	// calc. Accessed only from the single Run/pollOnce goroutine, as are seq and
	// inspected.
	prevCPU map[string]cpuCounters
	// seq numbers the polls (failed ones too), so an inspect's age is counted in polls.
	seq int64
	// inspected holds each listed container's last successful inspect, carried
	// forward over polls where its inspect fails or is skipped (see inspect).
	inspected map[string]inspectRecord
	// kick asks Run for a poll now (Kick).
	kick chan struct{}
}

// cpuCounters holds a container's raw CPU usage counters from one stats sample and
// the run they belong to (its StartedAt; zero when unknown).
type cpuCounters struct {
	total, system uint64
	startedAt     time.Time
}

// continuedBy reports whether cur can be diffed against c as one stretch of the same
// run: both counters moved forward (a restart resets the container's cgroup
// counters, and a system counter that did not move means no time passed) and, when
// both are known, the StartedAt is unchanged.
func (c cpuCounters) continuedBy(cur cpuCounters) bool {
	if cur.total < c.total || cur.system <= c.system {
		return false
	}
	return c.startedAt.IsZero() || cur.startedAt.IsZero() || c.startedAt.Equal(cur.startedAt)
}

// inspectCarryPolls is how many polls old a container's last successful inspect may
// be and still stand in for this poll's, when this poll's failed or the budget ran out.
const inspectCarryPolls = 2

// inspectRecord is the inspect-derived part of a ServiceStatus, taken on poll seq.
type inspectRecord struct {
	seq          int64
	state        string // State.Status when taken; a different list State voids the carry-forward
	health       string
	restartCount int
	exitCode     int
	oomKilled    bool
	startedAt    time.Time
	hasRWVolume  bool
}

// New builds a Monitor. prober may be nil (ops probing disabled).
func New(db *store.DB, cli *docker.Client, host *hostmon.Sampler, interval, retention time.Duration, log *slog.Logger, prober *ops.Prober) *Monitor {
	return &Monitor{
		db: db, cli: cli, host: host,
		interval: interval, retention: retention, log: log,
		prober:     prober,
		pruneEvery: 30, // prune roughly every 30 ticks
		kick:       make(chan struct{}, 1),
	}
}

// Kick asks for a poll now instead of at the next tick (a rollout wants to see what it just
// started). Kicks while one is pending coalesce; it never blocks.
func (m *Monitor) Kick() {
	if m == nil || m.kick == nil {
		return
	}
	select {
	case m.kick <- struct{}{}:
	default:
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
		case <-m.kick:
			m.snap.Store(m.pollOnce(ctx))
			t.Reset(m.interval)
		}
	}
}

// maxContainersPerPoll bounds per-tick Docker round-trips and inserts so an
// accidentally (or maliciously) huge host can't make a poll run for minutes or
// flood the DB (review #5). Far above any tiny-box workload.
const maxContainersPerPoll = 500

// pollBudget caps the wall-clock time of a single poll so a slow-but-not-dead
// proxy can't stall the poller proportional to container count (review #1). The
// per-request http.Client timeouts are secondary guards under this. When the
// budget runs out part-way, the containers not yet reached are the least urgent
// (inspectOrder) and carry their last inspect forward (inspect).
func (m *Monitor) pollBudget() time.Duration {
	if b := 2 * m.interval; b > 30*time.Second {
		return b
	}
	return 30 * time.Second
}

func (m *Monitor) pollOnce(parent context.Context) *Snapshot {
	m.seq++
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
		snap.ListFailed = true
		snap.DockerErr = "cannot list containers"
		m.sampleHost(snap)
		return snap
	}
	if len(containers) > maxContainersPerPoll {
		snap.Truncated = true
		sort.Slice(containers, func(i, j int) bool { return containers[i].ID < containers[j].ID })
		if !m.containerCapWarned {
			m.containerCapWarned = true
			m.log.Warn("container count exceeds per-poll cap; only a subset is monitored",
				"count", len(containers), "cap", maxContainersPerPoll)
		}
		containers = containers[:maxContainersPerPoll]
	}

	// The supervised compose services' containers, in list order (newest first).
	cs := make([]docker.Container, 0, len(containers))
	listed := make(map[string]bool, len(containers))
	for _, c := range containers {
		if c.Project() == "" {
			continue // not a compose-managed app
		}
		if c.OneOff() {
			continue // transient `compose run` one-shot (cron task / backup sidecar), not a service
		}
		cs = append(cs, c)
		listed[c.ID] = true
	}

	// Collect in inspect-priority order: if the budget runs out part-way, the calls
	// that fail are the least urgent ones, and those carry their last inspect forward.
	if m.inspected == nil {
		m.inspected = map[string]inspectRecord{}
	}
	statuses := make([]ServiceStatus, len(cs))
	next := make(map[string]cpuCounters, len(cs))
	for _, i := range inspectOrder(cs, m.inspected, m.seq) {
		statuses[i] = m.collect(ctx, cs[i], next)
	}
	m.prevCPU = next
	for id := range m.inspected {
		if !listed[id] {
			delete(m.inspected, id) // gone from the list
		}
	}

	byProject := map[string][]ServiceStatus{}
	projMeta := map[string]docker.Container{} // first container per project (for labels)
	for i, c := range cs {
		project := c.Project()
		if _, ok := projMeta[project]; !ok {
			projMeta[project] = c
		}
		byProject[project] = append(byProject[project], statuses[i])
	}

	for project, svcs := range byProject {
		// Stable over the list order, so the copies of a scaled service stay newest
		// first (the service page shows the first copy as the newest).
		sort.SliceStable(svcs, func(i, j int) bool { return svcs[i].Service < svcs[j].Service })
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

// collect builds one container's ServiceStatus from its list entry, its inspect
// (fresh or carried forward) and, when it is running, a one-shot stats sample. It
// stores the container's CPU baseline for the next poll in next.
func (m *Monitor) collect(ctx context.Context, c docker.Container, next map[string]cpuCounters) ServiceStatus {
	svc := ServiceStatus{
		Service:     c.Service(),
		ContainerID: c.ID,
		Name:        c.Name(),
		Image:       c.Image,
		State:       c.State,
		StatusText:  c.Status,
		Health:      "none",
		ImageID:     c.ImageID,
		ConfigHash:  c.ConfigHash(),
	}
	if rec, ok := m.inspect(ctx, c); ok {
		svc.RestartCount = rec.restartCount
		svc.Health = rec.health
		svc.ExitCode = rec.exitCode
		svc.OOMKilled = rec.oomKilled
		svc.HasRWVolume = rec.hasRWVolume
		svc.StartedAt = rec.startedAt
		svc.Inspected = true
	}
	prev, havePrev := m.prevCPU[c.ID]
	if c.State == "running" && ctx.Err() == nil {
		if st, err := m.cli.StatsOneShot(ctx, c.ID); err == nil {
			cur := cpuCounters{startedAt: svc.StartedAt}
			cur.total, cur.system = st.RawCPU()
			if havePrev && prev.continuedBy(cur) {
				svc.CPUPercent = st.CPUPercentBetween(prev.total, prev.system)
				svc.CPUValid = true
			}
			next[c.ID] = cur
			svc.MemBytes = st.MemUsed()
			svc.MemLimit = st.MemLimit()
			return svc
		}
	}
	if havePrev {
		// No sample this poll: keep the baseline, so the next sample is still a real
		// delta (over a longer window) rather than another first sample.
		next[c.ID] = prev
	}
	return svc
}

// inspect returns c's inspect-derived fields. A successful inspect is recorded and
// returned. When it fails, or the poll budget has already run out, the last
// successful one stands in if it is at most inspectCarryPolls polls old and the list
// shows nothing it describes has changed since: the same State, and no other health
// in the Status text. ok=false leaves the caller's defaults.
func (m *Monitor) inspect(ctx context.Context, c docker.Container) (inspectRecord, bool) {
	if ctx.Err() == nil {
		if ci, err := m.cli.InspectContainer(ctx, c.ID); err == nil {
			rec := inspectRecord{
				seq:          m.seq,
				state:        ci.State.Status,
				health:       ci.HealthStatus(),
				restartCount: ci.RestartCount,
				exitCode:     ci.State.ExitCode,
				oomKilled:    ci.State.OOMKilled,
				startedAt:    parseStartedAt(ci.State.StartedAt),
				hasRWVolume:  ci.HasSharedRWVolume(),
			}
			if rec.state == "" {
				rec.state = c.State // an inspect without State.Status: take the list's
			}
			m.inspected[c.ID] = rec
			return rec, true
		}
	}
	rec, ok := m.inspected[c.ID]
	if !ok || m.seq-rec.seq > inspectCarryPolls || rec.state != c.State {
		return inspectRecord{}, false
	}
	if h := listHealth(c.Status); h != "" && h != rec.health {
		return inspectRecord{}, false
	}
	// A container restarted since the record (`docker restart` keeps its id and its "running" state)
	// lists a shorter uptime than the record's StartedAt implies: the record is from its previous run.
	if up, ok := listUptimeMax(c.Status); ok && !rec.startedAt.IsZero() && time.Since(rec.startedAt) > up+5*time.Second {
		return inspectRecord{}, false
	}
	return rec, true
}

// listUptimeMax reads the uptime in a running container's list Status ("Up 5 seconds", "Up About a
// minute (healthy)", …, as docker's units.HumanDuration writes it) and returns an upper bound for it.
// ok is false when the text isn't an uptime, or is too coarse (days and longer) to be useful.
func listUptimeMax(status string) (time.Duration, bool) {
	rest, ok := strings.CutPrefix(status, "Up ")
	if !ok {
		return 0, false
	}
	if i := strings.Index(rest, " ("); i >= 0 {
		rest = rest[:i]
	}
	switch rest {
	case "Less than a second":
		return time.Second, true
	case "About a minute":
		return 2 * time.Minute, true
	case "About an hour":
		return 2 * time.Hour, true
	}
	var n int
	var unit string
	if _, err := fmt.Sscanf(rest, "%d %s", &n, &unit); err != nil || n < 0 {
		return 0, false
	}
	switch strings.TrimSuffix(unit, "s") {
	case "second":
		return time.Duration(n+1) * time.Second, true
	case "minute":
		return time.Duration(n+1) * time.Minute, true
	case "hour":
		return time.Duration(n+1) * time.Hour, true
	}
	return 0, false
}

// inspectOrder returns the indexes of cs in the order to inspect them this poll. The
// budget can run out before every container is inspected (each call is slow on a
// CPU-starved host), and Docker lists newest first, so a fixed order would leave the
// same oldest containers (often the database) uninspected poll after poll. Most
// urgent first:
//
//  0. not running: self-heal acts on its ExitCode/OOMKilled;
//  1. last known health unhealthy or starting (the inspect record, or the list's
//     fresher Status text);
//  2. never inspected (new containers);
//  3. the rest.
//
// Within a class the least recently inspected go first, and ties follow container id
// order rotated by the poll sequence, so no container is starved across polls.
func inspectOrder(cs []docker.Container, known map[string]inspectRecord, seq int64) []int {
	n := len(cs)
	byID := make([]int, n)
	for i := range byID {
		byID[i] = i
	}
	sort.Slice(byID, func(a, b int) bool { return cs[byID[a]].ID < cs[byID[b]].ID })
	order := make([]int, 0, n) // id order, rotated by the poll: the tie-break
	if n > 0 {
		k := int(seq % int64(n))
		order = append(append(order, byID[k:]...), byID[:k]...)
	}
	class := make([]int, n)
	last := make([]int64, n) // poll of the last successful inspect; 0 = never
	for i, c := range cs {
		rec, ok := known[c.ID]
		class[i], last[i] = inspectClass(c, rec, ok), rec.seq
	}
	sort.SliceStable(order, func(a, b int) bool {
		i, j := order[a], order[b]
		if class[i] != class[j] {
			return class[i] < class[j]
		}
		return last[i] < last[j]
	})
	return order
}

// inspectClass ranks how urgently c needs a fresh inspect (see inspectOrder).
func inspectClass(c docker.Container, rec inspectRecord, known bool) int {
	lh := listHealth(c.Status)
	switch {
	case c.State != "running":
		return 0
	case rec.health == "unhealthy" || rec.health == "starting" || lh == "unhealthy" || lh == "starting":
		return 1
	case !known:
		return 2
	}
	return 3
}

// listHealth returns the healthcheck status Docker puts at the end of a list entry's
// Status text ("Up 2 minutes (healthy)", "Up 3 seconds (health: starting)", "Up 1
// hour (unhealthy)"), or "" when there is none. It is only a hint for ordering
// inspects and for spotting a carried-forward inspect the list has overtaken; it
// never stands in for an inspect.
func listHealth(status string) string {
	switch {
	case strings.HasSuffix(status, "(healthy)"):
		return "healthy"
	case strings.HasSuffix(status, "(unhealthy)"):
		return "unhealthy"
	case strings.HasSuffix(status, "(health: starting)"):
		return "starting"
	}
	return ""
}

// parseStartedAt parses an inspect State.StartedAt (RFC 3339). An empty or
// unparseable value, and Docker's "0001-01-01T00:00:00Z" for a container that has
// never started, yield the zero time.
func parseStartedAt(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.IsZero() {
		return time.Time{}
	}
	return t
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
