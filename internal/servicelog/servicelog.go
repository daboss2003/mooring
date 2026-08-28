// Package servicelog captures and retains each running service's own container output (stdout +
// stderr) so an operator can SEARCH a service's recent logs — the real error/stack behind an Errors-tab
// entry — instead of only live-tailing. It tees the same read-plane log stream the live tail already
// uses (docker.StreamLogs, through the read-only socket-proxy) into a bounded, TTL'd file store.
//
// It is DISABLED by default: unlike the Errors tab (which stores only the edge's request metadata),
// this writes the app's own output to disk, which can contain secrets/tokens/PII the app prints. So
// it is opt-in (server.service_log_enabled), the file is 0600 in the root-only data dir, and entries
// expire on a short TTL — see docs.
//
// Bounded three ways so a chatty or crash-looping service can neither evict every other service nor
// burn disk/CPU: a PER-SERVICE ring (each service keeps only its most recent lines, so it only ever
// evicts its OWN history), a cap on the NUMBER of services tracked, and a PER-SERVICE ingest RATE cap
// (excess lines are dropped and coalesced into one "… N lines dropped" marker). Persisted to a JSONL
// file (atomic rewrite), SEPARATE from the single-conn SQLite DB, and reloaded on start.
package servicelog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Line is one captured log line.
type Line struct {
	At   int64  `json:"at"`             // unix seconds (capture time)
	App  string `json:"app"`            // owning app (compose project)
	Svc  string `json:"svc"`            // service name
	Copy string `json:"copy,omitempty"` // short (12-char) container id of the replica; "" for a synthetic marker
	Text string `json:"text"`           // the log line (CR/·control already sanitized upstream)
}

const (
	defaultTTL     = 48 * time.Hour
	perServiceMax  = 1000 // recent lines kept PER service (its own ring; never evicts other services)
	maxServices    = 48   // distinct services tracked (a box with more is extreme; new ones are dropped)
	rateCapPerSec  = 200  // per-service lines/sec accepted; excess dropped + coalesced to a marker
	maxLineBytes   = 8 << 10
	maxSearchLimit = 2000
	defaultSearchN = 500
)

// svcBuf is one service's ring plus its per-second rate-limit state.
type svcBuf struct {
	app, svc string
	lines    []Line // oldest-first, capped at perServiceMax
	rateSec  int64  // the second the rate window is counting
	rateN    int    // lines accepted in this second
	dropped  int    // lines dropped in this second (→ a marker on rollover)
}

// Store is a bounded, TTL'd, file-backed per-service log store. Safe for concurrent use.
type Store struct {
	mu             sync.Mutex
	path           string
	ttl            time.Duration
	now            func() time.Time
	log            *slog.Logger
	svcs           map[string]*svcBuf
	dirty          bool
	overflowLogged bool // logged once when maxServices is hit
}

// New opens (or creates) a store backed by path, loading any recent lines on disk.
func New(path string, log *slog.Logger) *Store { return newWithClock(path, time.Now, log) }

func newWithClock(path string, now func() time.Time, log *slog.Logger) *Store {
	if log == nil {
		log = slog.Default()
	}
	s := &Store{path: path, ttl: defaultTTL, now: now, log: log, svcs: map[string]*svcBuf{}}
	s.load()
	return s
}

func key(app, svc string) string { return app + "\x00" + svc }

// Record captures one line for (app, svc, copy). copy is the short container id (replica attribution).
// It enforces the per-service rate cap (dropping + coalescing excess) and the per-service ring. O(1)
// amortized; pruning by TTL is lazy (read paths + Flush).
func (s *Store) Record(app, svc, copy, text string) {
	if s == nil || app == "" || svc == "" {
		return
	}
	if len(text) > maxLineBytes {
		text = text[:maxLineBytes] + "…"
	}
	at := s.now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()

	k := key(app, svc)
	buf := s.svcs[k]
	if buf == nil {
		if len(s.svcs) >= maxServices {
			if !s.overflowLogged {
				s.log.Warn("servicelog: tracking cap reached; not retaining more services", "cap", maxServices)
				s.overflowLogged = true
			}
			return
		}
		buf = &svcBuf{app: app, svc: svc, rateSec: at}
		s.svcs[k] = buf
	}

	// Rate window rollover: emit a marker for any lines dropped in the window that just ended.
	if at != buf.rateSec {
		if buf.dropped > 0 {
			s.appendLine(buf, Line{At: at, App: app, Svc: svc, Text: fmt.Sprintf("… %d line(s) dropped (over %d/s rate limit)", buf.dropped, rateCapPerSec)})
		}
		buf.rateSec, buf.rateN, buf.dropped = at, 0, 0
	}
	if buf.rateN >= rateCapPerSec {
		buf.dropped++
		return
	}
	buf.rateN++
	s.appendLine(buf, Line{At: at, App: app, Svc: svc, Copy: copy, Text: text})
}

// appendLine appends to a buf's ring, evicting its oldest line past the per-service cap, and marks
// the store dirty. Caller holds s.mu.
func (s *Store) appendLine(buf *svcBuf, l Line) {
	buf.lines = append(buf.lines, l)
	if len(buf.lines) > perServiceMax {
		buf.lines = buf.lines[len(buf.lines)-perServiceMax:]
	}
	s.dirty = true
}

// Search returns one service's captured lines, newest-first, filtered by an optional copy id, a
// case-insensitive substring q, and an inclusive [since, until] time window (each <=0 disables that
// bound), capped at limit. Marker (dropped-count) lines are only returned when no copy filter is set.
func (s *Store) Search(app, svc, copy, q string, since, until int64, limit int) []Line {
	if limit <= 0 || limit > maxSearchLimit {
		limit = defaultSearchN
	}
	q = strings.ToLower(strings.TrimSpace(q))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	buf := s.svcs[key(app, svc)]
	if buf == nil {
		return nil
	}
	var out []Line
	for i := len(buf.lines) - 1; i >= 0 && len(out) < limit; i-- {
		l := buf.lines[i]
		if copy != "" && l.Copy != copy {
			continue
		}
		if since > 0 && l.At < since {
			continue
		}
		if until > 0 && l.At > until {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(l.Text), q) {
			continue
		}
		out = append(out, l)
	}
	return out
}

// Copies returns the distinct replica ids seen for a service (for the copy filter), sorted.
func (s *Store) Copies(app, svc string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	buf := s.svcs[key(app, svc)]
	if buf == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, l := range buf.lines {
		if l.Copy != "" {
			seen[l.Copy] = true
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Has reports whether any lines are retained for a service.
func (s *Store) Has(app, svc string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	buf := s.svcs[key(app, svc)]
	return buf != nil && len(buf.lines) > 0
}

// Delete drops all retained lines for an app (teardown).
func (s *Store) Delete(app string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, buf := range s.svcs {
		if buf.app == app {
			delete(s.svcs, k)
			s.dirty = true
		}
	}
}

// Flush persists to disk if there are unsaved changes (called periodically by the owner).
func (s *Store) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	if s.dirty {
		s.persistLocked()
	}
}

// pruneLocked drops lines older than the TTL from each service, removing empty services. Lines are
// appended in time order, so the cut point is the first line within the window.
func (s *Store) pruneLocked() {
	cut := s.now().Add(-s.ttl).Unix()
	for k, buf := range s.svcs {
		i := 0
		for i < len(buf.lines) && buf.lines[i].At < cut {
			i++
		}
		if i > 0 {
			buf.lines = append([]Line(nil), buf.lines[i:]...)
			s.dirty = true
		}
		if len(buf.lines) == 0 {
			delete(s.svcs, k)
			s.dirty = true
		}
	}
}

func (s *Store) persistLocked() {
	if s.path == "" {
		return
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, buf := range s.svcs {
		for _, l := range buf.lines {
			_ = enc.Encode(l)
		}
	}
	if w.Flush() != nil || f.Sync() != nil || f.Close() != nil {
		_ = os.Remove(tmp)
		return
	}
	if os.Rename(tmp, s.path) == nil {
		s.dirty = false
	}
}

func (s *Store) load() {
	f, err := os.Open(s.path)
	if err != nil {
		return
	}
	defer f.Close()
	cut := s.now().Add(-s.ttl).Unix()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var l Line
		if json.Unmarshal(sc.Bytes(), &l) != nil || l.At < cut || l.App == "" || l.Svc == "" {
			continue
		}
		k := key(l.App, l.Svc)
		buf := s.svcs[k]
		if buf == nil {
			if len(s.svcs) >= maxServices {
				continue
			}
			buf = &svcBuf{app: l.App, svc: l.Svc, rateSec: l.At}
			s.svcs[k] = buf
		}
		buf.lines = append(buf.lines, l)
		if len(buf.lines) > perServiceMax {
			buf.lines = buf.lines[len(buf.lines)-perServiceMax:]
		}
	}
}
