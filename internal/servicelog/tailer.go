package servicelog

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// logStreamer follows a container's logs through the read plane (satisfied by *docker.Client; faked
// in tests). It is the SAME call the live SSE tail uses — capture just tees it into the store.
type logStreamer interface {
	StreamLogs(ctx context.Context, id string, tail int, follow bool, onLine func(string)) error
}

// Target is one running service container to capture.
type Target struct {
	ContainerID string
	App         string
	Service     string
}

// maxTailers caps concurrent follow-streams (each holds one read-only socket-proxy connection), so a
// host with a huge number of containers can't exhaust the proxy's connection pool.
const maxTailers = 100

// Manager keeps one follow-tailer per running service container, driven by periodic reconcile off the
// monitor snapshot (mirroring the edge-pool discovery refresher — it runs outside any reconcile lock,
// attaches to discovered containers, and is fail-safe). It cancels a tailer the instant its container
// leaves the running set; a tailer that EOFs (container stop/restart) removes itself and the next
// reconcile re-attaches to the replacement container id.
type Manager struct {
	store  *Store
	docker logStreamer
	log    *slog.Logger
	max    int

	mu     sync.Mutex
	active map[string]context.CancelFunc // containerID → cancel
	root   context.Context
}

// NewManager builds a Manager. dockerCli must be non-nil.
func NewManager(store *Store, dockerCli logStreamer, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{store: store, docker: dockerCli, log: log, max: maxTailers, active: map[string]context.CancelFunc{}}
}

// Run reconciles the tailer set every interval from targets() until ctx is done, then stops all.
func (m *Manager) Run(ctx context.Context, interval time.Duration, targets func() []Target) {
	m.root = ctx
	if interval <= 0 {
		interval = 15 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	m.reconcile(targets())
	for {
		select {
		case <-ctx.Done():
			m.stopAll()
			return
		case <-t.C:
			m.reconcile(targets())
		}
	}
}

func (m *Manager) reconcile(targets []Target) {
	want := make(map[string]Target, len(targets))
	for _, t := range targets {
		if t.ContainerID != "" && t.App != "" && t.Service != "" {
			want[t.ContainerID] = t
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Stop tailers whose container is no longer running.
	for id, cancel := range m.active {
		if _, ok := want[id]; !ok {
			cancel()
			delete(m.active, id)
		}
	}
	// Start tailers for newly-seen containers, up to the concurrency cap.
	for id, t := range want {
		if _, ok := m.active[id]; ok {
			continue
		}
		if len(m.active) >= m.max {
			break
		}
		tctx, cancel := context.WithCancel(m.root)
		m.active[id] = cancel
		go m.tail(tctx, t)
	}
}

func (m *Manager) tail(ctx context.Context, t Target) {
	copyID := t.ContainerID
	if len(copyID) > 12 {
		copyID = copyID[:12]
	}
	// tail=1: minimal backlog on attach, so a Mooring restart re-ingests at most one already-seen line
	// (accepting a small gap for lines the app emitted while Mooring was down).
	err := m.docker.StreamLogs(ctx, t.ContainerID, 1, true, func(line string) {
		m.store.Record(t.App, t.Service, copyID, line)
	})
	if err != nil && ctx.Err() == nil {
		m.log.Debug("servicelog: tailer ended", "app", t.App, "service", t.Service, "err", err)
	}
	// Remove self (idempotent with a concurrent reconcile cancel) so the next reconcile re-attaches to
	// the replacement container if the service is still running under a new id.
	m.mu.Lock()
	if cancel, ok := m.active[t.ContainerID]; ok {
		cancel()
		delete(m.active, t.ContainerID)
	}
	m.mu.Unlock()
}

func (m *Manager) stopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, cancel := range m.active {
		cancel()
		delete(m.active, id)
	}
}
