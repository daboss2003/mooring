// Package edgeerr captures the managed edge's (Caddy's) ERROR responses — 4xx/5xx — per route, so an
// operator can see WHICH of an app's routes are erroring, when, and with what request, without
// tailing logs. It is fed by the same in-process access-log stream as the autoscaling metrics
// (attributed host+path → route via the HostIndex). Entries are the edge's view of the request
// (time, method, path, status, client IP, latency) — NOT the app's internal error text, which the
// edge never sees.
//
// Bounded two ways so it can't grow without limit: a 24h TTL (older entries pruned) and a hard cap on
// the number of retained entries (oldest evicted first). Persisted to a JSONL file (atomic rewrite),
// SEPARATE from the single-conn SQLite DB (so it never contends with it), and reloaded on start.
package edgeerr

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Entry is one edge-observed error response.
type Entry struct {
	At       int64   `json:"at"`           // unix seconds
	App      string  `json:"app"`          // owning app (compose project)
	Service  string  `json:"svc"`          // service the route fronts
	Host     string  `json:"host"`         // route hostname
	Prefix   string  `json:"prefix"`       // route path prefix ("" = whole host)
	Method   string  `json:"method"`       // request method
	Path     string  `json:"path"`         // request path (query stripped)
	Status   int     `json:"status"`       // 4xx/5xx
	RemoteIP string  `json:"ip,omitempty"` // client IP
	DurMs    float64 `json:"dur_ms"`       // latency (ms)
}

// RouteSummary is one route's error rollup for the accordion header.
type RouteSummary struct {
	App, Service, Host, Prefix string
	Count24h, CountHour        int
	Count5xx                   int
	LastAt                     int64
	LastStatus                 int
}

// RouteKey identifies a route (app + host + prefix).
func RouteKey(app, host, prefix string) string { return app + "\x00" + host + "\x00" + prefix }

const (
	defaultTTL = 24 * time.Hour
	defaultMax = 20000 // hard cap on retained entries (oldest evicted first)
)

// Store is a bounded, TTL'd, file-backed edge-error log. Safe for concurrent use.
type Store struct {
	mu      sync.Mutex
	path    string
	ttl     time.Duration
	max     int
	now     func() time.Time
	entries []Entry // oldest first
	dirty   bool
}

// New opens (or creates) a store backed by path, loading any recent entries on disk.
func New(path string) *Store { return newWithClock(path, time.Now) }

func newWithClock(path string, now func() time.Time) *Store {
	s := &Store{path: path, ttl: defaultTTL, max: defaultMax, now: now}
	s.load()
	return s
}

// Record appends one error entry (evicting the oldest if at the cap). Pruning by TTL is lazy (done in
// the read paths + Flush), keeping this off-the-hot-path O(1) amortized.
func (s *Store) Record(e Entry) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.entries = append(s.entries, e)
	if len(s.entries) > s.max {
		s.entries = s.entries[len(s.entries)-s.max:]
	}
	s.dirty = true
	s.mu.Unlock()
}

// Routes returns each route that has errored within the TTL, most-recently-active first, with error
// counts (24h, last hour, 5xx) for the accordion.
func (s *Store) Routes() []RouteSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	now := s.now().Unix()
	hourAgo := now - 3600
	byKey := map[string]*RouteSummary{}
	for _, e := range s.entries {
		k := RouteKey(e.App, e.Host, e.Prefix)
		r := byKey[k]
		if r == nil {
			r = &RouteSummary{App: e.App, Service: e.Service, Host: e.Host, Prefix: e.Prefix}
			byKey[k] = r
		}
		r.Count24h++
		if e.At >= hourAgo {
			r.CountHour++
		}
		if e.Status >= 500 {
			r.Count5xx++
		}
		if e.At >= r.LastAt {
			r.LastAt, r.LastStatus = e.At, e.Status
		}
	}
	out := make([]RouteSummary, 0, len(byKey))
	for _, r := range byKey {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastAt > out[j].LastAt })
	return out
}

// Errors returns one route's error entries, newest first, optionally filtered by a case-insensitive
// substring across the rendered fields, capped at limit.
func (s *Store) Errors(app, host, prefix, q string, limit int) []Entry {
	if limit <= 0 {
		limit = 500
	}
	q = strings.ToLower(strings.TrimSpace(q))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	var out []Entry
	for i := len(s.entries) - 1; i >= 0 && len(out) < limit; i-- {
		e := s.entries[i]
		if e.App != app || e.Host != host || e.Prefix != prefix {
			continue
		}
		if q != "" && !strings.Contains(entryHaystack(e), q) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// entryHaystack is the lower-cased text an error is matched against for the filter.
func entryHaystack(e Entry) string {
	return strings.ToLower(e.Method + " " + e.Path + " " + strconv.Itoa(e.Status) + " " + e.RemoteIP)
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

// pruneLocked drops entries older than the TTL. Entries are appended in time order, so the cut point
// is the first entry within the window.
func (s *Store) pruneLocked() {
	cut := s.now().Add(-s.ttl).Unix()
	i := 0
	for i < len(s.entries) && s.entries[i].At < cut {
		i++
	}
	if i > 0 {
		s.entries = append([]Entry(nil), s.entries[i:]...)
		s.dirty = true
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
	for _, e := range s.entries {
		_ = enc.Encode(e)
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
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.At >= cut {
			s.entries = append(s.entries, e)
		}
	}
	if len(s.entries) > s.max {
		s.entries = s.entries[len(s.entries)-s.max:]
	}
}
