// Package servicelog captures and retains each running service's own container output (stdout +
// stderr) so an operator can SEARCH a service's history — the real error/stack behind an Errors-tab
// entry — instead of only live-tailing. It tees the same read-plane log stream the live tail already
// uses (docker.StreamLogs, through the read-only socket-proxy) into bounded per-service files.
//
// It is ON by default (server.service_log_enabled). Unlike the Errors tab (which stores only the
// edge's request metadata) this writes the app's own output to disk, which can contain secrets the
// app prints, so the files are 0600 in 0700 directories under the root-only data dir, retention is
// short by default, and turning the feature off deletes them on the next start.
//
// Layout: <dir>/<app>/<service>/<segment>.jsonl — append-only segment files per service (see
// segment.go). Only a small write buffer per service lives in memory; search streams the segments
// newest-first. Bounded per service by its policy (retain, max_lines: the definition's `logs:`
// clamped to the server ceilings, 48h / 2000 lines by default), across services by a total disk
// budget (oldest segments go first), and by a per-service ingest RATE cap (excess lines are dropped
// and coalesced into one "… N line(s) dropped" marker). When the data-dir filesystem is at or above
// the disk-pressure threshold, capture pauses and every service is cut back to the default policy.
// Kept SEPARATE from the single-conn SQLite DB.
package servicelog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	// maxServices bounds the services tracked at once. Each costs at most one write buffer
	// (pendingFlushBytes) plus a small index in memory — lines live on disk under the global budget.
	maxServices    = 256
	rateCapPerSec  = 200 // per-service lines/sec accepted; excess dropped + coalesced to a marker
	maxLineBytes   = 8 << 10
	maxSearchLimit = 2000
	defaultSearchN = 500

	pendingFlushBytes  = 32 << 10 // a service's buffered lines are written once they reach this
	defaultSegMaxBytes = 4 << 20  // a segment is closed once it reaches this size
	minSegMaxBytes     = 256 << 10
	maxSearchBytes     = 4 << 20 // text returned by one Search
	maxCopies          = 64      // replica ids remembered per service
	copySeedLines      = 2000    // lines read from the newest segment at load to rebuild the replica list
	searchSlots        = 4       // concurrent searches (each holds one read buffer + its result)
)

// One Search's budget: past either, it returns the lines found so far.
const (
	searchScanBudget = 64 << 20        // segment bytes one Search may read
	searchTimeBudget = 5 * time.Second // how long one Search may take, waiting for a slot included
)

// deletedAppTTL is how long Record drops lines for an app after Delete.
//
// Intentional: two minutes, not until the next deploy of the name. The teardown removes the app's
// containers before it deletes the logs, so only a tailer still delivering its last lines can write
// late, and tailers are reconciled every 15s. A longer window would drop the first output of an app
// connected again under the same name.
const deletedAppTTL = 2 * time.Minute

var defaultMaxDisk = int64(2048) << 20

// nameRe is the only shape of app or service name that becomes a path component: compose's project
// name alphabet (a superset of Mooring slugs and service names), no dots or separators.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

func validName(n string) bool { return nameRe.MatchString(n) }

// Options configures a Store.
type Options struct {
	Dir          string // root of the per-service segment files, e.g. <data_dir>/service-logs
	LegacyFile   string // pre-segment single-file store (<data_dir>/service-logs.jsonl): imported once, then removed
	Ceiling      Policy // largest policy any service gets (zero fields = 30d / 200000 lines)
	MaxDiskBytes int64  // total budget for all segment files (0 = 2 GiB)
	// DiskUsage reports the data-dir filesystem's used and total bytes (ok=false: unknown). At or
	// above DiskThresholdPct capture pauses. nil disables the check.
	DiskUsage        func() (used, total uint64, ok bool)
	DiskThresholdPct float64
	Log              *slog.Logger
}

// svcLog is one service's in-memory state: its segment index, write buffer, rate-limit window and
// replica list. Its mutex is held across that service's file I/O only.
type svcLog struct {
	app, svc, dir string

	mu             sync.Mutex
	gone           bool      // deleted/forgotten; a holder must look the service up again
	segs           []segment // oldest first (ascending seq)
	nextSeq        uint64
	pending        []Line // captured, not yet written (oldest first)
	pendingBytes   int
	lastAt         int64 // newest capture time; capture time never goes backwards within a service
	rateSec        int64 // the second the rate window is counting
	rateN          int   // lines accepted in this second
	rateDropped    int   // lines dropped in this second (→ a marker on rollover)
	pausedDropped  int   // lines dropped under disk pressure (→ a marker on resume)
	copies         map[string]int64
	policy         Policy
	policyKnown    bool
	policyTried    bool // a Flush has asked the policy source for this service
	writeErrLogged bool
}

func (sl *svcLog) noteCopy(c string, at int64) {
	if c == "" {
		return
	}
	if _, ok := sl.copies[c]; !ok && len(sl.copies) >= maxCopies {
		oldest, oldestAt := "", int64(0)
		for k, v := range sl.copies {
			if oldest == "" || v < oldestAt {
				oldest, oldestAt = k, v
			}
		}
		delete(sl.copies, oldest)
	}
	if at > sl.copies[c] {
		sl.copies[c] = at
	}
}

// append buffers one line. Caller holds sl.mu.
func (sl *svcLog) append(l Line) {
	sl.pending = append(sl.pending, l)
	sl.pendingBytes += len(l.Text) + len(l.Copy) + 32
	if l.At > sl.lastAt {
		sl.lastAt = l.At
	}
	sl.noteCopy(l.Copy, l.At)
}

// Store is the bounded, file-backed per-service log store. Safe for concurrent use: Record and
// Search lock only the one service they touch; Flush runs maintenance one service at a time.
type Store struct {
	dir         string
	ceil        Policy
	maxDisk     int64
	segMaxBytes int64
	diskUsage   func() (used, total uint64, ok bool)
	threshold   float64
	now         func() time.Time
	log         *slog.Logger

	copySeedLines int
	source        atomic.Pointer[PolicySource]
	paused        atomic.Bool
	searchSem     chan struct{}
	scanBudget    int64                               // searchScanBudget (tests lower it)
	timeBudget    time.Duration                       // searchTimeBudget (tests lower it)
	searchOpen    func(path string) (*os.File, error) // openSegment (a test seam)

	mu             sync.Mutex // guards svcs, deleted and the log-once flags; never held across file I/O
	svcs           map[string]*svcLog
	deleted        map[string]int64 // app → unix time until which Record drops its lines (see Delete)
	overflowLogged bool
	badNameLogged  bool

	maintMu sync.Mutex // serializes Flush passes (Record and Search never take it)
}

// New opens the store at opts.Dir, indexing any segments already there and importing the legacy
// single-file store if one exists.
func New(opts Options) *Store { return newStore(opts, time.Now) }

func newStore(opts Options, now func() time.Time) *Store {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	ceil := opts.Ceiling
	if ceil.Retain <= 0 {
		ceil.Retain = defaultCeiling.Retain
	}
	if ceil.MaxLines <= 0 {
		ceil.MaxLines = defaultCeiling.MaxLines
	}
	maxDisk := opts.MaxDiskBytes
	if maxDisk <= 0 {
		maxDisk = defaultMaxDisk
	}
	// A segment is a small slice of the budget, so the budget is enforced at a fine grain.
	segMax := maxDisk / 64
	if segMax > defaultSegMaxBytes {
		segMax = defaultSegMaxBytes
	}
	if segMax < minSegMaxBytes {
		segMax = minSegMaxBytes
	}
	s := &Store{
		dir: opts.Dir, ceil: ceil, maxDisk: maxDisk, segMaxBytes: segMax,
		diskUsage: opts.DiskUsage, threshold: opts.DiskThresholdPct, now: now, log: opts.Log,
		copySeedLines: copySeedLines, searchSem: make(chan struct{}, searchSlots),
		scanBudget: searchScanBudget, timeBudget: searchTimeBudget, searchOpen: openSegment,
		svcs: map[string]*svcLog{}, deleted: map[string]int64{},
	}
	if s.dir == "" {
		return s
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		s.log.Warn("servicelog: cannot create the log directory", "dir", s.dir, "err", err)
	}
	_ = os.Chmod(s.dir, 0o700)
	s.load()
	if opts.LegacyFile != "" {
		s.importLegacy(opts.LegacyFile)
	}
	return s
}

// Purge deletes everything a store keeps on disk (used when capture is turned off, so captured
// output doesn't outlive the setting).
func Purge(dir, legacyFile string) {
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
	if legacyFile != "" {
		_ = os.Remove(legacyFile)
		_ = os.Remove(legacyFile + ".tmp")
	}
}

// SetPolicySource wires where each service's requested retention comes from (its deployed
// definition). Until set, every service gets the default.
func (s *Store) SetPolicySource(fn PolicySource) {
	if s == nil {
		return
	}
	if fn == nil {
		s.source.Store(nil)
		return
	}
	s.source.Store(&fn)
}

func (s *Store) policySource() PolicySource {
	if p := s.source.Load(); p != nil {
		return *p
	}
	return nil
}

// load indexes every <app>/<service> directory already on disk (whatever the service cap; they are
// pruned like any other). Symlinks and unexpected names are ignored.
func (s *Store) load() {
	apps, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	for _, a := range apps {
		if !a.IsDir() || !validName(a.Name()) {
			continue
		}
		appDir := filepath.Join(s.dir, a.Name())
		svcs, err := os.ReadDir(appDir)
		if err != nil {
			continue
		}
		for _, d := range svcs {
			if !d.IsDir() || !validName(d.Name()) {
				continue
			}
			sl := s.newSvcLog(a.Name(), d.Name())
			s.loadSegments(sl)
			if len(sl.segs) == 0 {
				_ = os.Remove(sl.dir)
				continue
			}
			s.svcs[key(sl.app, sl.svc)] = sl
		}
		_ = os.Remove(appDir) // only succeeds when empty
	}
}

func key(app, svc string) string { return app + "\x00" + svc }

func (s *Store) newSvcLog(app, svc string) *svcLog {
	return &svcLog{app: app, svc: svc, dir: filepath.Join(s.dir, app, svc), copies: map[string]int64{}}
}

// service returns the tracked state for (app, svc), creating it when create is set, the app wasn't
// deleted within deletedAppTTL, and the service cap allows. Names must already be valid.
func (s *Store) service(app, svc string, create bool) *svcLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(app, svc)
	if sl := s.svcs[k]; sl != nil || !create {
		return sl
	}
	if until, ok := s.deleted[app]; ok {
		if s.now().Unix() < until {
			return nil
		}
		delete(s.deleted, app)
	}
	if len(s.svcs) >= maxServices {
		if !s.overflowLogged {
			s.log.Warn("servicelog: tracking cap reached; not retaining more services", "cap", maxServices)
			s.overflowLogged = true
		}
		return nil
	}
	sl := s.newSvcLog(app, svc)
	s.svcs[k] = sl
	return sl
}

// forget drops sl from the map if it is still the tracked entry for its service.
func (s *Store) forget(sl *svcLog) {
	s.mu.Lock()
	k := key(sl.app, sl.svc)
	if s.svcs[k] == sl {
		delete(s.svcs, k)
	}
	s.mu.Unlock()
}

func (s *Store) snapshot() []*svcLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*svcLog, 0, len(s.svcs))
	for _, sl := range s.svcs {
		out = append(out, sl)
	}
	return out
}

func (s *Store) badName(app, svc string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.badNameLogged {
		s.badNameLogged = true
		s.log.Warn("servicelog: not retaining a service whose name can't be a file name", "app", truncName(app), "service", truncName(svc))
	}
}

func truncName(n string) string {
	if len(n) > 64 {
		return n[:64] + "…"
	}
	return n
}

// segPolicy sizes a service's segments: its own policy once known, else the default. Caller holds sl.mu.
func (s *Store) segPolicy(sl *svcLog) Policy {
	if sl.policyKnown {
		return sl.policy
	}
	return Effective(Policy{}, s.ceil)
}

// keepPolicy is what a service's files and searches are held to: its own policy, the default when a
// Flush has tried and failed to read it, and no more than the default under disk pressure. Caller
// holds sl.mu.
//
// Intentional: the ceiling until the first Flush has asked for the policy. Only a Flush prunes, so
// before that attempt nothing has been cut and a search may see everything on disk; after it, an
// unknown policy never keeps more than the default.
func (s *Store) keepPolicy(sl *svcLog, paused bool) Policy {
	var p Policy
	switch {
	case sl.policyKnown:
		p = sl.policy
	case sl.policyTried:
		p = Effective(Policy{}, s.ceil)
	default:
		p = s.ceil
	}
	if paused {
		p = minPolicy(p, Effective(Policy{}, s.ceil))
	}
	return p
}

// resolvePolicy reads a service's policy from the source when no Flush has asked yet, so the page and
// searches use the service's own policy from the start. A failed read changes nothing (the next Flush
// decides). Called without sl.mu: the source may read the database.
func (s *Store) resolvePolicy(sl *svcLog) {
	sl.mu.Lock()
	need := !sl.policyKnown && !sl.policyTried && !sl.gone
	sl.mu.Unlock()
	if !need {
		return
	}
	req, ok := Policy{}, true
	if src := s.policySource(); src != nil {
		req, ok = src(sl.app, sl.svc)
	}
	if !ok {
		return
	}
	sl.mu.Lock()
	if !sl.gone && !sl.policyKnown { // a Flush that ran meanwhile has the newer answer
		sl.policy, sl.policyKnown = Effective(req, s.ceil), true
	}
	sl.mu.Unlock()
}

// Record captures one line for (app, svc, copy). copy is the short container id (replica
// attribution). It enforces the per-service rate cap (dropping + coalescing excess), drops lines
// while capture is paused for disk pressure, and writes the service's buffer once it is full.
func (s *Store) Record(app, svc, copy, text string) {
	if s == nil {
		return
	}
	if !validName(app) || !validName(svc) {
		s.badName(app, svc)
		return
	}
	if len(text) > maxLineBytes {
		text = text[:maxLineBytes] + "…"
	}
	now := s.now().Unix()
	for {
		sl := s.service(app, svc, true)
		if sl == nil {
			return
		}
		sl.mu.Lock()
		if sl.gone {
			sl.mu.Unlock()
			s.forget(sl)
			continue
		}
		s.recordLocked(sl, now, copy, text)
		sl.mu.Unlock()
		return
	}
}

func (s *Store) recordLocked(sl *svcLog, now int64, copy, text string) {
	at := now
	// Intentional: capture time never goes backwards within a service (a wall-clock step back
	// reuses the last time), so every segment is in time order and Search can stop at the first
	// line older than its window.
	if at < sl.lastAt {
		at = sl.lastAt
	}
	if at != sl.rateSec {
		if sl.rateDropped > 0 {
			sl.append(Line{At: at, Text: fmt.Sprintf("… %d line(s) dropped (over %d/s rate limit)", sl.rateDropped, rateCapPerSec)})
		}
		sl.rateSec, sl.rateN, sl.rateDropped = at, 0, 0
	}
	if s.paused.Load() {
		sl.pausedDropped++
		return
	}
	if sl.rateN >= rateCapPerSec {
		sl.rateDropped++
		return
	}
	sl.rateN++
	sl.append(Line{At: at, Copy: copy, Text: text})
	if sl.pendingBytes >= pendingFlushBytes {
		s.writePendingLocked(sl)
	}
}

// Search returns one service's captured lines, newest-first, filtered by an optional copy id, a
// text query q, and an inclusive [since, until] time window (each <=0 disables that bound), capped at
// limit. The query is word-AND: it is split on whitespace and a line must contain EVERY word (each a
// case-insensitive substring, in any order) — so "statusCode 502" matches `{"statusCode":502}`. Marker
// (dropped-count) lines are only returned when no copy filter is set. Only the service's retained
// window (its retain and max_lines) is searched. more reports that matches beyond the cap exist, or
// that the search stopped early: ctx ended, the search used up its time or byte budget
// (searchTimeBudget, searchScanBudget), or no search slot freed up in time. The lines found until then
// are returned.
func (s *Store) Search(ctx context.Context, app, svc, copyID, q string, since, until int64, limit int) (out []Line, more bool) {
	if s == nil || !validName(app) || !validName(svc) {
		return nil, false
	}
	if limit <= 0 || limit > maxSearchLimit {
		limit = defaultSearchN
	}
	terms := strings.Fields(strings.ToLower(q))
	sl := s.service(app, svc, false)
	if sl == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeBudget)
	defer cancel()
	select {
	case s.searchSem <- struct{}{}:
	case <-ctx.Done():
		return nil, true
	}
	defer func() { <-s.searchSem }()
	if ctx.Err() != nil {
		return nil, true
	}
	s.resolvePolicy(sl)

	// Take a snapshot under the lock and read the files without it, so Record and Flush never wait for
	// a search. Each segment is read up to the size it had here: later lines are in the pending copy.
	type segRef struct {
		seq         uint64
		name        string
		bytes       int64
		first, last int64
		lines       int
	}
	sl.mu.Lock()
	if sl.gone {
		sl.mu.Unlock()
		return nil, false
	}
	pol := s.keepPolicy(sl, s.paused.Load())
	pending := append([]Line(nil), sl.pending...)
	refs := make([]segRef, 0, len(sl.segs))
	for i := len(sl.segs) - 1; i >= 0; i-- {
		g := sl.segs[i]
		refs = append(refs, segRef{seq: g.seq, name: g.name, bytes: g.bytes, first: g.first, last: g.last, lines: g.lines})
	}
	sl.mu.Unlock()

	if cut := s.now().Unix() - pol.retainSecs(); since < cut {
		since = cut
	}
	seen, outBytes, stop := 0, 0, false
	// consider applies the window and filters to the next-older line; false stops the search.
	consider := func(l Line) bool {
		seen++
		if seen > pol.MaxLines || l.At < since {
			return false
		}
		if (until > 0 && l.At > until) || (copyID != "" && l.Copy != copyID) || !matchesAll(l.Text, terms) {
			return true
		}
		if len(out) >= limit || outBytes+len(l.Text) > maxSearchBytes {
			more = true
			return false
		}
		l.App, l.Svc = app, svc
		out = append(out, l)
		outBytes += len(l.Text)
		return true
	}
	for i := len(pending) - 1; i >= 0 && !stop; i-- {
		stop = !consider(pending[i])
	}
	budget := s.scanBudget
	for _, g := range refs {
		// Segments are in time order, newest first: none past this one can be in the window.
		if stop || g.last < since || seen >= pol.MaxLines {
			break
		}
		if until > 0 && g.first > until {
			seen += g.lines // still counts toward max_lines
			continue
		}
		f, size, ok, gone := s.openForSearch(sl, g.seq, g.name)
		if gone {
			break
		}
		if !ok {
			continue // pruned since the snapshot
		}
		if g.bytes < size {
			size = g.bytes
		}
		err := eachLineBackward(&budgetReader{r: f, ctx: ctx, left: &budget}, size, 0, func(b []byte) bool {
			var d diskLine
			if json.Unmarshal(b, &d) != nil {
				return true
			}
			stop = !consider(Line{At: d.At, Copy: d.Copy, Text: d.Text})
			return !stop
		})
		_ = f.Close()
		if errors.Is(err, errSearchBudget) {
			more = true
			break
		}
	}
	return out, more
}

// errSearchBudget stops a search whose context ended or whose byte budget is used up.
var errSearchBudget = errors.New("servicelog: search budget used up")

// budgetReader reads a segment for a search, failing with errSearchBudget once the search's context
// has ended or its byte budget is spent (checked before each chunk read).
type budgetReader struct {
	r    io.ReaderAt
	ctx  context.Context
	left *int64
}

func (b *budgetReader) ReadAt(p []byte, off int64) (int, error) {
	if b.ctx.Err() != nil || *b.left <= 0 {
		return 0, errSearchBudget
	}
	*b.left -= int64(len(p))
	return b.r.ReadAt(p, off)
}

// openForSearch opens one of sl's segments for a search. A segment closed since the search's snapshot
// was renamed, so a missing file is looked up again by seq. ok=false: the segment is gone (pruned) or
// unreadable; gone=true: the service was deleted.
func (s *Store) openForSearch(sl *svcLog, seq uint64, name string) (f *os.File, size int64, ok, gone bool) {
	for attempt := 0; attempt < 2; attempt++ {
		f, err := s.searchOpen(filepath.Join(sl.dir, name))
		if err == nil {
			fi, serr := f.Stat()
			if serr != nil || !fi.Mode().IsRegular() {
				_ = f.Close()
				return nil, 0, false, false
			}
			return f, fi.Size(), true, false
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, 0, false, false
		}
		sl.mu.Lock()
		gone = sl.gone
		cur := ""
		for _, g := range sl.segs {
			if g.seq == seq {
				cur = g.name
				break
			}
		}
		sl.mu.Unlock()
		if gone {
			return nil, 0, false, true
		}
		if cur == "" || cur == name {
			return nil, 0, false, false
		}
		name = cur
	}
	return nil, 0, false, false
}

// matchesAll reports whether text contains every term (case-insensitive substring). No terms matches
// everything.
func matchesAll(text string, terms []string) bool {
	if len(terms) == 0 {
		return true
	}
	lt := strings.ToLower(text)
	for _, t := range terms {
		if !strings.Contains(lt, t) {
			return false
		}
	}
	return true
}

// Copies returns the replica ids seen for a service within its retained window (for the copy
// filter), sorted.
func (s *Store) Copies(app, svc string) []string {
	if s == nil || !validName(app) || !validName(svc) {
		return nil
	}
	sl := s.service(app, svc, false)
	if sl == nil {
		return nil
	}
	s.resolvePolicy(sl)
	sl.mu.Lock()
	defer sl.mu.Unlock()
	cut := s.now().Unix() - s.keepPolicy(sl, s.paused.Load()).retainSecs()
	out := make([]string, 0, len(sl.copies))
	for c, at := range sl.copies {
		if at >= cut {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// Policy returns the retention the store applies to a service (its definition's `logs:` clamped to the
// server ceilings; the default when unset or unreadable; see keepPolicy), ignoring disk pressure. For a
// service with nothing captured yet, it is the policy the service will get.
func (s *Store) Policy(app, svc string) Policy {
	if s == nil {
		return DefaultPolicy
	}
	if !validName(app) || !validName(svc) {
		return Effective(Policy{}, s.ceil)
	}
	if sl := s.service(app, svc, false); sl != nil {
		s.resolvePolicy(sl)
		sl.mu.Lock()
		p, gone := s.keepPolicy(sl, false), sl.gone
		sl.mu.Unlock()
		if !gone {
			return p
		}
	}
	if src := s.policySource(); src != nil {
		if req, ok := src(app, svc); ok {
			return Effective(req, s.ceil)
		}
	}
	return Effective(Policy{}, s.ceil)
}

// Default is the policy of a service without `logs:` (DefaultPolicy, clamped to the ceilings); every
// service is cut back to it while capture is paused.
func (s *Store) Default() Policy {
	if s == nil {
		return DefaultPolicy
	}
	return Effective(Policy{}, s.ceil)
}

// Paused reports whether capture is paused because the data-dir filesystem is at or above the
// disk-pressure threshold.
func (s *Store) Paused() bool { return s != nil && s.paused.Load() }

// Delete removes everything retained for an app, on disk at once (teardown). Lines recorded for the
// app during the next deletedAppTTL are dropped, so a tailer's late line can't recreate its files.
func (s *Store) Delete(app string) {
	if s == nil || !validName(app) || s.dir == "" {
		return
	}
	s.mu.Lock()
	now := s.now().Unix()
	for a, until := range s.deleted {
		if now >= until {
			delete(s.deleted, a)
		}
	}
	s.deleted[app] = now + int64(deletedAppTTL/time.Second)
	var victims []*svcLog
	for k, sl := range s.svcs {
		if sl.app == app {
			victims = append(victims, sl)
			delete(s.svcs, k)
		}
	}
	s.mu.Unlock()
	for _, sl := range victims {
		sl.mu.Lock()
		sl.gone = true
		sl.pending, sl.segs = nil, nil
		sl.mu.Unlock()
	}
	if err := os.RemoveAll(filepath.Join(s.dir, app)); err != nil {
		s.log.Warn("servicelog: cannot remove an app's captured logs", "app", app, "err", err)
	}
}

// Flush writes every service's buffered lines and runs maintenance: it re-reads each service's
// policy, checks disk pressure, prunes each service to its policy, and enforces the total disk
// budget. Called periodically by the owner, at shutdown, and after an app delete.
func (s *Store) Flush() {
	if s == nil || s.dir == "" {
		return
	}
	s.maintMu.Lock()
	defer s.maintMu.Unlock()
	paused := s.checkDisk()
	src := s.policySource()
	now := s.now().Unix()
	for _, sl := range s.snapshot() {
		req, known := Policy{}, true
		if src != nil {
			req, known = src(sl.app, sl.svc) // outside every lock: this may read the database
		}
		sl.mu.Lock()
		if sl.gone {
			sl.mu.Unlock()
			continue
		}
		if known {
			sl.policy, sl.policyKnown = Effective(req, s.ceil), true
		}
		sl.policyTried = true
		if !paused && sl.pausedDropped > 0 {
			at := now
			if at < sl.lastAt {
				at = sl.lastAt
			}
			sl.append(Line{At: at, Text: fmt.Sprintf("… %d line(s) dropped (disk usage at or above %g%%)", sl.pausedDropped, s.threshold)})
			sl.pausedDropped = 0
		}
		s.writePendingLocked(sl)
		s.pruneLocked(sl, s.keepPolicy(sl, paused), now)
		idle := len(sl.segs) == 0 && len(sl.pending) == 0 && sl.rateDropped == 0 && sl.pausedDropped == 0
		if idle {
			sl.gone = true
		}
		sl.mu.Unlock()
		if idle {
			s.forget(sl)
			_ = os.Remove(sl.dir)               // only succeeds when empty
			_ = os.Remove(filepath.Dir(sl.dir)) // the app dir, likewise
		}
	}
	s.enforceDiskCap()
}

// checkDisk samples the data-dir filesystem and updates the pause flag, logging each change once.
func (s *Store) checkDisk() bool {
	if s.diskUsage == nil || s.threshold <= 0 {
		return s.paused.Load()
	}
	used, total, ok := s.diskUsage()
	if !ok || total == 0 {
		return s.paused.Load() // unknown: keep the current state
	}
	pct := float64(used) / float64(total) * 100
	p := pct >= s.threshold
	if was := s.paused.Swap(p); p && !was {
		s.log.Warn("servicelog: disk usage at or above threshold; pausing log capture and cutting history to the default",
			"used_pct", fmt.Sprintf("%.1f", pct), "threshold_pct", s.threshold)
	} else if !p && was {
		s.log.Info("servicelog: disk usage below threshold; log capture resumed", "used_pct", fmt.Sprintf("%.1f", pct))
	}
	return p
}

// enforceDiskCap removes the globally oldest segments (by newest line, across every service) until
// the total is within the disk budget. Each removal holds only its own service's lock.
func (s *Store) enforceDiskCap() {
	type cand struct {
		sl          *svcLog
		seq         uint64
		last, first int64
		bytes       int64
	}
	var cands []cand
	var total int64
	for _, sl := range s.snapshot() {
		sl.mu.Lock()
		if !sl.gone {
			for _, g := range sl.segs {
				cands = append(cands, cand{sl: sl, seq: g.seq, last: g.last, first: g.first, bytes: g.bytes})
				total += g.bytes
			}
		}
		sl.mu.Unlock()
	}
	if total <= s.maxDisk {
		return
	}
	sort.Slice(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.last != b.last {
			return a.last < b.last
		}
		return a.first < b.first
	})
	for _, c := range cands {
		if total <= s.maxDisk {
			return
		}
		c.sl.mu.Lock()
		if !c.sl.gone {
			for i, g := range c.sl.segs {
				if g.seq != c.seq {
					continue
				}
				if c.sl.removeSegment(g) {
					c.sl.segs = append(c.sl.segs[:i], c.sl.segs[i+1:]...)
					total -= g.bytes
				}
				break
			}
		}
		c.sl.mu.Unlock()
	}
}
