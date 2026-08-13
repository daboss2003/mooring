// Package eventlog captures Mooring's own WARN/ERROR operational events — deploys, image builds,
// vulnerability scans, backups, git-fetch failures, scale decisions, self-heal actions — into a
// small, DEDUPED, file-backed store that the dashboard's Activity tab renders. It exists so an
// operator never has to `journalctl -u mooring | grep` to see what Mooring (or the things it manages)
// is doing or complaining about.
//
// Bounded three ways so it can't grow without limit:
//   - DEDUP: identical repeats (same level+message+attrs) collapse to ONE row with a count +
//     first/last-seen — so the "scale: refused" line every 10s is a single "×N, last …" row.
//   - TTL: rows whose last activity is older than the retention window (24h) are pruned.
//   - CAP: the number of DISTINCT rows is hard-capped (oldest evicted first).
//
// It is persisted to a JSONL file (atomic rewrite), SEPARATE from the main SQLite DB (so it never
// contends with the single-conn database), and reloaded on start — so restarts don't lose recent
// activity and raw log volume never sits in memory. The events shown are exactly what already goes to
// journald, for the authenticated operator, so there is no new exposure; Mooring's WARN/ERROR logs
// are credential-free by design (see git.classifyErr, the audit log, etc.).
package eventlog

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"sync"
	"time"
)

// Event is one deduped operational event.
type Event struct {
	Level string `json:"level"`           // WARN | ERROR
	Msg   string `json:"msg"`             // the log message
	Attrs string `json:"attrs,omitempty"` // stable "k=v k=v" (sorted) — the dedup discriminator + context
	Count int    `json:"count"`           // how many times it has fired within the window
	First int64  `json:"first"`           // unix seconds, first occurrence
	Last  int64  `json:"last"`            // unix seconds, most recent occurrence
}

const (
	defaultTTL     = 24 * time.Hour
	defaultMaxRows = 500
)

// Store is a bounded, deduped, file-backed event store. Safe for concurrent use.
type Store struct {
	mu      sync.Mutex
	path    string
	ttl     time.Duration
	maxRows int
	now     func() time.Time // injectable for tests
	byKey   map[string]*Event
	dirty   bool
}

// New opens (or creates) a store backed by path, loading any recent events already on disk.
func New(path string) *Store { return newWithClock(path, time.Now) }

// newWithClock is New with an injectable clock (used by tests so load() prunes against the same clock).
func newWithClock(path string, now func() time.Time) *Store {
	s := &Store{path: path, ttl: defaultTTL, maxRows: defaultMaxRows, now: now, byKey: map[string]*Event{}}
	s.load()
	return s
}

func key(level, msg, attrs string) string { return level + "\x00" + msg + "\x00" + attrs }

// Record adds/collapses one event. O(1) amortized: it never prunes here (that would put an O(n) scan
// on the logging hot path) — pruning is done lazily in List and by the periodic Flush. Eviction on a
// full store is the only O(n) branch and is rare (distinct rows stay small thanks to dedup).
func (s *Store) Record(level, msg, attrs string) {
	if msg == "" {
		return
	}
	now := s.now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.byKey[key(level, msg, attrs)]; e != nil {
		e.Count++
		e.Last = now
	} else {
		if len(s.byKey) >= s.maxRows {
			s.evictOldestLocked()
		}
		s.byKey[key(level, msg, attrs)] = &Event{Level: level, Msg: msg, Attrs: attrs, Count: 1, First: now, Last: now}
	}
	s.dirty = true
}

// List returns the events newest-activity-first, after pruning expired ones.
func (s *Store) List() []Event {
	now := s.now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	out := make([]Event, 0, len(s.byKey))
	for _, e := range s.byKey {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Last != out[j].Last {
			return out[i].Last > out[j].Last
		}
		return out[i].Msg < out[j].Msg
	})
	return out
}

func (s *Store) pruneLocked(now int64) {
	cutoff := now - int64(s.ttl.Seconds())
	for k, e := range s.byKey {
		if e.Last < cutoff {
			delete(s.byKey, k)
			s.dirty = true
		}
	}
}

// evictOldestLocked drops the least-recently-active row (the store is at cap). Caller holds the lock.
func (s *Store) evictOldestLocked() {
	var oldestKey string
	var oldest int64 = 1<<63 - 1
	for k, e := range s.byKey {
		if e.Last < oldest {
			oldest, oldestKey = e.Last, k
		}
	}
	if oldestKey != "" {
		delete(s.byKey, oldestKey)
	}
}

// Flush prunes then writes the deduped set to disk IF it changed, via an atomic temp+rename. Cheap —
// the set is bounded. Call periodically and on shutdown.
func (s *Store) Flush() error {
	now := s.now().Unix()
	s.mu.Lock()
	s.pruneLocked(now)
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	events := make([]Event, 0, len(s.byKey))
	for _, e := range s.byKey {
		events = append(events, *e)
	}
	s.dirty = false
	s.mu.Unlock()

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for i := range events {
		if err := enc.Encode(&events[i]); err != nil {
			return err
		}
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// load reads recent (within-TTL) events from disk. A missing/corrupt file is fine (start empty).
func (s *Store) load() {
	f, err := os.Open(s.path)
	if err != nil {
		return
	}
	defer f.Close()
	cutoff := s.now().Unix() - int64(s.ttl.Seconds())
	dec := json.NewDecoder(f)
	for {
		var e Event
		if err := dec.Decode(&e); err != nil {
			break // EOF or a truncated trailing record — keep what parsed
		}
		if e.Msg == "" || e.Last < cutoff {
			continue
		}
		ev := e // copy out of the loop variable before taking its address
		s.byKey[key(ev.Level, ev.Msg, ev.Attrs)] = &ev
	}
}
