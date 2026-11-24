package servicelog

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// logStreamer follows a container's logs through the read plane (satisfied by *docker.Client; faked
// in tests). It is the same read-plane endpoint the live SSE tail uses, with Docker's per-line
// timestamps, so a re-attach can start where the last stream ended.
type logStreamer interface {
	StreamLogsSince(ctx context.Context, id string, tail int, since time.Time, follow bool, onLine func(ts time.Time, line string)) error
}

// Target is one running service container to capture.
type Target struct {
	ContainerID string
	App         string
	Service     string
}

const (
	// maxTailers caps concurrent follow-streams (each holds one read-only socket-proxy connection), so
	// a host with a huge number of containers can't exhaust the proxy's connection pool.
	maxTailers = 100
	// backfillTail caps the backlog one attach reads (Docker's tail), whatever its since.
	backfillTail = 1000
	// cursorTTL is how long a container's cursor is kept after it leaves the running set, so a copy
	// stopped and started again (same id) resumes where it stopped; maxCursors bounds the map.
	cursorTTL  = 24 * time.Hour
	maxCursors = 4096
)

// Manager keeps one follow-tailer per running service container, driven by periodic reconcile off the
// monitor snapshot (mirroring the edge-pool discovery refresher — it runs outside any reconcile lock,
// attaches to discovered containers, and is fail-safe). It cancels a tailer the instant its container
// leaves the running set; a tailer that EOFs (container stop/restart) removes itself and the next
// reconcile re-attaches, from the last line it emitted.
//
// Each line read goes to the line sink (SetLineSink) and then to the store, which applies its
// per-service rate cap: the sink sees every line. Either may be absent.
type Manager struct {
	store  *Store // nil: lines go to the sink only
	docker logStreamer
	log    *slog.Logger
	max    int
	now    func() time.Time
	sink   atomic.Pointer[func(Line)]

	mu         sync.Mutex
	active     map[string]*tailer // containerID → its running tailer
	cursors    map[string]*cursor // containerID → where its next attach starts
	root       context.Context
	start      time.Time // when Run began: the first attach of a container without a cursor starts here
	cursorFile string    // where cursors are kept across restarts ("" = memory only)
	tailers    sync.WaitGroup

	// Cursor file state, used on Run's goroutine only.
	savedTS       map[string]int64 // the line times last written
	lastSave      time.Time
	saveInterval  time.Duration // saveEvery (tests lower it)
	saveErrLogged bool
	writeState    func(path string, b []byte) error // writeFileAtomic (a test seam)
}

type tailer struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// cursor is one container's position: the Docker timestamp of the newest line emitted for it.
type cursor struct {
	last atomic.Int64 // unix nanoseconds; 0 = no line yet
	gone time.Time    // when the container left the running set; zero while in it (guarded by Manager.mu)
}

// NewManager builds a Manager. dockerCli must be non-nil; store may be nil (service logs off), in
// which case lines only reach the line sink.
func NewManager(store *Store, dockerCli logStreamer, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{
		store: store, docker: dockerCli, log: log, max: maxTailers, now: time.Now,
		active: map[string]*tailer{}, cursors: map[string]*cursor{}, writeState: writeFileAtomic, saveInterval: saveEvery,
	}
}

// SetLineSink sets the function every line read is handed to, before the store's rate cap (nil
// removes it). Line.At is the capture time and Line.TS the line's Docker timestamp (zero when it has
// none). fn runs on the tailer's goroutine for each line, so it must not block. Safe to call at any
// time, before Run included.
func (m *Manager) SetLineSink(fn func(Line)) {
	if fn == nil {
		m.sink.Store(nil)
		return
	}
	m.sink.Store(&fn)
}

// Run reconciles the tailer set every interval from targets() until ctx is done, then stops all
// (and, with a cursor file, saves every container's position).
func (m *Manager) Run(ctx context.Context, interval time.Duration, targets func() []Target) {
	m.begin(ctx)
	if interval <= 0 {
		interval = 15 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	var save <-chan time.Time
	if m.cursorPath() != "" {
		st := time.NewTicker(m.saveInterval)
		defer st.Stop()
		save = st.C
	}
	m.reconcile(targets())
	for {
		select {
		case <-ctx.Done():
			m.stopAll()
			m.waitTailers(tailerStopWait)
			m.saveCursors(m.now(), true)
			return
		case <-t.C:
			m.reconcile(targets())
		case <-save:
			m.saveCursors(m.now(), false)
		}
	}
}

// begin records the run start and loads the cursor file, before the first reconcile.
func (m *Manager) begin(ctx context.Context) {
	now := m.now()
	m.mu.Lock()
	m.root, m.start = ctx, now
	m.mu.Unlock()
	m.loadCursors(now)
}

// waitTailers waits up to d for every tailer to return, so the final save has their last lines.
func (m *Manager) waitTailers(d time.Duration) {
	done := make(chan struct{})
	go func() { m.tailers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}

func (m *Manager) reconcile(targets []Target) {
	want := make(map[string]Target, len(targets))
	for _, t := range targets {
		if t.ContainerID != "" && t.App != "" && t.Service != "" {
			want[t.ContainerID] = t
		}
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	// Stop tailers whose container is no longer running.
	for id, tl := range m.active {
		if _, ok := want[id]; !ok {
			tl.cancel()
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
		cur := m.cursors[id]
		if cur == nil {
			cur = &cursor{}
			m.cursors[id] = cur
		}
		tctx, cancel := context.WithCancel(m.root)
		tl := &tailer{ctx: tctx, cancel: cancel}
		m.active[id] = tl
		m.tailers.Add(1)
		go m.tail(tl, t, cur)
	}
	m.pruneCursorsLocked(want, now)
}

// pruneCursorsLocked forgets the cursors of containers gone for longer than cursorTTL and, past
// maxCursors, the longest-gone ones. Caller holds m.mu.
func (m *Manager) pruneCursorsLocked(want map[string]Target, now time.Time) {
	var gone []string
	for id, c := range m.cursors {
		if _, ok := want[id]; ok || m.active[id] != nil {
			c.gone = time.Time{}
			continue
		}
		if c.gone.IsZero() {
			c.gone = now
		}
		if now.Sub(c.gone) > cursorTTL {
			delete(m.cursors, id)
			continue
		}
		gone = append(gone, id)
	}
	if extra := len(m.cursors) - maxCursors; extra > 0 && len(gone) > 0 {
		sort.Slice(gone, func(i, j int) bool { return m.cursors[gone[i]].gone.Before(m.cursors[gone[j]].gone) })
		for i := 0; i < extra && i < len(gone); i++ {
			delete(m.cursors, gone[i])
		}
	}
}

func (m *Manager) tail(tl *tailer, t Target, cur *cursor) {
	defer m.tailers.Done()
	copyID := t.ContainerID
	if len(copyID) > 12 {
		copyID = copyID[:12]
	}
	m.mu.Lock()
	since := m.start
	m.mu.Unlock()
	// A container with a cursor (seen before, in this run or, through the cursor file, the last one)
	// resumes at its last line: Docker's since includes lines stamped exactly then, so the lines at or
	// before it are skipped until a newer one arrives. A container without one starts at the manager's
	// start: a new container's first lines are kept, and nothing captured before is read again. Either
	// way at most backfillTail lines of backlog are read.
	last := cur.last.Load()
	if last > 0 {
		since = time.Unix(0, last)
	}
	tail := backfillTail
	if since.IsZero() {
		tail = 1
	}
	skipping := last > 0
	err := m.docker.StreamLogsSince(tl.ctx, t.ContainerID, tail, since, true, func(ts time.Time, text string) {
		var n int64
		if !ts.IsZero() {
			n = ts.UnixNano()
			if skipping {
				if n <= last {
					return
				}
				// Intentional: dedupe only at the boundary. Past the first newer line every line is
				// kept, even one stamped earlier (a wall-clock step back).
				skipping = false
			}
		}
		if p := m.sink.Load(); p != nil {
			(*p)(Line{At: m.now().Unix(), App: t.App, Svc: t.Service, Copy: copyID, Text: text, TS: ts})
		}
		if m.store != nil {
			m.store.Record(t.App, t.Service, copyID, text)
		}
		// The cursor moves once the line was handed on, so a crash between the two reads it again
		// rather than losing it.
		if n > cur.last.Load() {
			cur.last.Store(n)
		}
	})
	if err != nil && tl.ctx.Err() == nil {
		m.log.Debug("servicelog: tailer ended", "app", t.App, "service", t.Service, "err", err)
	}
	// Remove self so the next reconcile re-attaches if the service is still running — unless a
	// reconcile already replaced this tailer (it was cancelled and a new one started for the id).
	tl.cancel()
	m.mu.Lock()
	if m.active[t.ContainerID] == tl {
		delete(m.active, t.ContainerID)
	}
	m.mu.Unlock()
}

func (m *Manager) stopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, tl := range m.active {
		tl.cancel()
		delete(m.active, id)
	}
}
