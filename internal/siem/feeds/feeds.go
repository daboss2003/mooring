// Package feeds downloads and refreshes the enrichment data the security-log enricher uses (DB-IP
// City and ASN Lite, Spamhaus DROP, the Tor exit list, DShield's block list), checks it, keeps it in
// a directory of its own, and hands it to an enrich.Enricher. What is on disk is used at start, so
// enrichment works after a restart and offline. Every request goes through a client limited to the
// four feed hosts (newClient).
package feeds

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/enrich"
)

// Feed names (siem.FeedStatus.Name).
const (
	NameCity     = "dbip-city"
	NameASN      = "dbip-asn"
	NameSpamhaus = "spamhaus-drop"
	NameTor      = "tor-exits"
	NameDShield  = "dshield"
)

// Schedule and limits.
const (
	minBackoff   = time.Hour      // the first retry after a failure; doubled per failure
	maxBackoff   = 24 * time.Hour // and never more
	rateLimitMin = 5 * time.Minute
	defaultGap   = 5 * time.Minute // least time between two attempts of a feed, across restarts
	maxWait      = time.Hour       // Run looks at the schedule at least this often
	maxFails     = 64
	stateName    = "state.json"
	stateCap     = 64 << 10
	errTextMax   = 300
)

// Options configures a Manager.
type Options struct {
	Dir      string // <data_dir>/security-logs/feeds; created 0700
	Enricher *enrich.Enricher
	// Which feeds run: GeoIP is DB-IP City + ASN Lite (checked daily for a new month), Spamhaus the
	// DROP lists (daily), Tor the exit list (every 6 hours). DShield's block list (daily) runs only
	// with DShieldContact, an email address sent in its User-Agent as SANS ISC asks.
	GeoIP, Spamhaus, Tor bool
	DShieldContact       string
	Version              string // Mooring's version, for the User-Agent
	Log                  *slog.Logger
	Now                  func() time.Time

	// Test seams: the HTTP client (nil: newClient for Hosts) and the feed URLs ("": the real ones).
	client *http.Client
	urls   urls
}

type urls struct{ dbip, spamhaus, tor, dshield string }

var defaultURLs = urls{
	dbip:     "https://download.db-ip.com/free/",
	spamhaus: "https://www.spamhaus.org/drop/",
	tor:      "https://check.torproject.org/torbulkexitlist",
	dshield:  "https://feeds.dshield.org/block.txt",
}

// feedState is one feed's schedule and what is in use; persisted in state.json.
type feedState struct {
	Version     string    `json:"version,omitempty"`
	Updated     time.Time `json:"updated,omitzero"` // when the data in use was fetched
	Entries     int       `json:"entries,omitempty"`
	LastAttempt time.Time `json:"last_attempt,omitzero"`
	LastSuccess time.Time `json:"last_success,omitzero"`
	NextTry     time.Time `json:"next_try,omitzero"`
	Fails       int       `json:"fails,omitempty"` // failures in a row
	LastError   string    `json:"last_error,omitempty"`
}

type stateFile struct {
	V     int                  `json:"v"`
	Feeds map[string]feedState `json:"feeds"`
}

// result is what a successful fetch changed, and whether any fetch downloaded something.
type result struct {
	changed    bool // new data is in use
	version    string
	entries    int
	downloaded bool // a file was received (HTTP 200), also when the attempt then failed; set by fetchSpamhaus
}

type feed struct {
	name     string
	enabled  bool
	file     string        // the data file in Dir
	interval time.Duration // after a success
	minGap   time.Duration // least time between two attempts
	// The least wait after an attempt that downloaded something, failed or not (Spamhaus).
	afterDownload time.Duration
	timeout       time.Duration // one attempt, all its requests
	// DB-IP only: the kind, the URL slug and the size caps of the download.
	kind, slug      string
	compCap, rawCap int64
	fetch           func(ctx context.Context, f *feed, now time.Time) (result, error)
	load            func(f *feed) error // the data file on disk → the enricher
	st              feedState           // guarded by Manager.mu
}

// Manager keeps the feeds' data current and in the Enricher. Run does the downloads; FeedStatus is
// safe to call at any time.
type Manager struct {
	root    *os.Root
	x       *enrich.Enricher
	feeds   []*feed
	log     *slog.Logger
	now     func() time.Time
	client  *http.Client
	urls    urls
	ua      string
	uaISC   string // DShield's, with the contact
	after   func(time.Duration) <-chan time.Time
	mu      sync.Mutex
	running atomic.Bool
}

var _ siem.FeedStatusSource = (*Manager)(nil)

// New creates Dir (0700) and loads the state and every enabled feed's data already on disk into the
// Enricher (a file that can't be used is reported in FeedStatus and fetched again when due; no file
// makes New fail or panic). It makes no request. It fails only for bad options or when Dir can't be
// created or opened. Close releases Dir.
func New(opt Options) (*Manager, error) {
	if opt.Dir == "" {
		return nil, errors.New("feeds: no directory")
	}
	if opt.Enricher == nil {
		return nil, errors.New("feeds: no enricher")
	}
	if c := opt.DShieldContact; c != "" && !headerSafe(c) {
		return nil, errors.New("feeds: the DShield contact is not usable in a User-Agent")
	}
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.client == nil {
		opt.client = newClient(clientConfig{allow: Hosts})
	}
	u := defaultURLs
	for _, p := range []struct {
		dst *string
		v   string
	}{{&u.dbip, opt.urls.dbip}, {&u.spamhaus, opt.urls.spamhaus},
		{&u.tor, opt.urls.tor}, {&u.dshield, opt.urls.dshield}} {
		if p.v != "" {
			*p.dst = p.v
		}
	}
	if err := os.MkdirAll(opt.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("feeds: %w", err)
	}
	root, err := os.OpenRoot(opt.Dir)
	if err != nil {
		return nil, fmt.Errorf("feeds: %w", err)
	}
	m := &Manager{
		root: root, x: opt.Enricher, log: opt.Log, now: opt.Now, client: opt.client, urls: u,
		ua: userAgent(opt.Version), after: time.After,
	}
	m.uaISC = m.ua + " (+" + opt.DShieldContact + ")"
	m.feeds = []*feed{
		{name: NameCity, enabled: opt.GeoIP, file: "dbip-city.mmdb", interval: 24 * time.Hour, minGap: defaultGap, timeout: 15 * time.Minute,
			kind: enrich.KindCity, slug: "city", compCap: 120 << 20, rawCap: 256 << 20, fetch: m.fetchDBIP, load: m.loadDBIP},
		{name: NameASN, enabled: opt.GeoIP, file: "dbip-asn.mmdb", interval: 24 * time.Hour, minGap: defaultGap, timeout: 15 * time.Minute,
			kind: enrich.KindASN, slug: "asn", compCap: 20 << 20, rawCap: 40 << 20, fetch: m.fetchDBIP, load: m.loadDBIP},
		// Intentional: Spamhaus asks that the DROP files are downloaded at most once a day and never
		// twice within an hour: an attempt that received any of its files waits a day, failed or not;
		// one that received none waits its backoff, at least an hour. Across restarts and crashes: the
		// attempt and a day's wait are saved before the first request (attempt).
		{name: NameSpamhaus, enabled: opt.Spamhaus, file: "spamhaus-drop.json", interval: 24 * time.Hour, minGap: time.Hour,
			afterDownload: 24 * time.Hour, timeout: time.Minute, fetch: m.fetchSpamhaus, load: m.loadList},
		{name: NameTor, enabled: opt.Tor, file: "tor-exits.json", interval: 6 * time.Hour, minGap: defaultGap, timeout: time.Minute,
			fetch: m.fetchTor, load: m.loadList},
		{name: NameDShield, enabled: opt.DShieldContact != "", file: "dshield.json", interval: 24 * time.Hour, minGap: defaultGap, timeout: time.Minute,
			fetch: m.fetchDShield, load: m.loadList},
	}
	m.removeTemp()
	m.loadState()
	m.loadFeeds()
	return m, nil
}

// Close releases Dir. Call it once Run has returned (after Close an attempt fails without a
// request); the data already in the Enricher stays in use until the Enricher's own Close. Safe to
// call more than once.
func (m *Manager) Close() { _ = m.root.Close() }

// loadFeeds loads every enabled feed's file on disk into the enricher. A file that can't be used
// leaves its feed without data and is reported in its LastError.
func (m *Manager) loadFeeds() {
	for _, f := range m.feeds {
		if !f.enabled {
			continue
		}
		if err := m.loadSafe(f); err != nil {
			f.st.Version, f.st.Updated, f.st.Entries = "", time.Time{}, 0
			if !errors.Is(err, fs.ErrNotExist) {
				f.st.LastError = cleanText("the file on disk can't be used: " + err.Error())
				m.log.Warn("security feeds: the file on disk can't be used; fetching it again when due", "feed", f.name, "err", f.st.LastError)
			}
		}
	}
}

// loadSafe is f.load with a panic turned into an error, the feed's data then taken out of the
// enricher.
//
// Intentional: recover — New runs at startup, and a decoding bug reached by a damaged or altered
// file on disk must leave that one feed empty, not stop Mooring from starting.
func (m *Manager) loadSafe(f *feed) (err error) {
	defer func() {
		if v := recover(); v != nil {
			m.unload(f)
			err = fmt.Errorf("reading it failed unexpectedly: %v", v)
			m.log.Error("security feeds: reading the file on disk failed unexpectedly; the feed starts empty", "feed", f.name,
				"err", cleanText(fmt.Sprint(v)))
		}
	}()
	return f.load(f)
}

// unload takes f's data out of the enricher.
func (m *Manager) unload(f *feed) {
	switch f.kind {
	case enrich.KindCity:
		m.x.SetCity(nil)
	case enrich.KindASN:
		m.x.SetASN(nil)
	default:
		m.x.SetList(listName(f.name), nil)
	}
}

// FeedStatus reports every feed, in a fixed order (dbip-city, dbip-asn, spamhaus-drop, tor-exits,
// dshield). A disabled feed has only its name.
func (m *Manager) FeedStatus() []siem.FeedStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]siem.FeedStatus, 0, len(m.feeds))
	for _, f := range m.feeds {
		s := siem.FeedStatus{Name: f.name, Enabled: f.enabled}
		if f.enabled {
			s.Version, s.Updated, s.Entries, s.LastError, s.NextTry = f.st.Version, f.st.Updated, f.st.Entries, f.st.LastError, dueAt(f)
		}
		out = append(out, s)
	}
	return out
}

// Run fetches each enabled feed when it is due, one at a time, until ctx ends. A second Run while
// one runs returns at once.
func (m *Manager) Run(ctx context.Context) {
	if !m.running.CompareAndSwap(false, true) {
		m.log.Warn("security feeds: already running")
		return
	}
	defer m.running.Store(false)
	for {
		next := m.runDue(ctx)
		if ctx.Err() != nil {
			return
		}
		if next.IsZero() { // no feed enabled
			<-ctx.Done()
			return
		}
		wait := min(max(next.Sub(m.now()), time.Second), maxWait)
		select {
		case <-ctx.Done():
			return
		case <-m.after(wait):
		}
	}
}

// runDue attempts every enabled feed that is due and returns when the next one is (zero: none
// enabled).
func (m *Manager) runDue(ctx context.Context) time.Time {
	for _, f := range m.feeds {
		if !f.enabled {
			continue
		}
		if ctx.Err() != nil {
			return time.Time{}
		}
		now := m.now()
		m.mu.Lock()
		clampFuture(&f.st, now)
		due := !dueAt(f).After(now)
		m.mu.Unlock()
		if due {
			m.attempt(ctx, f)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var next time.Time
	for _, f := range m.feeds {
		if t := dueAt(f); f.enabled && (next.IsZero() || t.Before(next)) {
			next = t
		}
	}
	return next
}

// dueAt is when f may be attempted: its scheduled time, but never within minGap of the last attempt.
// The caller holds m.mu.
func dueAt(f *feed) time.Time {
	next := f.st.NextTry
	if !f.st.LastAttempt.IsZero() {
		if g := f.st.LastAttempt.Add(f.minGap); g.After(next) {
			next = g
		}
	}
	return next
}

// attempt fetches f once and schedules the next attempt. The attempt time, and a next try as if
// the attempt failed after a download, are saved before any request, so a restart or a crash
// mid-attempt doesn't retry early; when that save fails nothing is requested. An attempt cut short
// because ctx ended is not a failure.
// safeFetch runs f.fetch with no lock held. Intentional: a panic in it (a bug meeting hostile download
// content) is recovered into a failed attempt, since a background download must never take serve
// down; it counts as having downloaded, so Spamhaus still waits its day before the next attempt.
func (m *Manager) safeFetch(ctx context.Context, f *feed, now time.Time) (res result, err error) {
	defer func() {
		if r := recover(); r != nil {
			res = result{downloaded: true}
			err = fmt.Errorf("internal error while processing the download: %s", cleanText(fmt.Sprint(r)))
			m.log.Error("security feeds: processing a download failed with an internal error", "feed", f.name, "err", err)
		}
	}()
	return f.fetch(ctx, f, now)
}

func (m *Manager) attempt(ctx context.Context, f *feed) {
	start := m.now()
	m.mu.Lock()
	prevNext := f.st.NextTry
	f.st.LastAttempt = start
	// Intentional: the worst case is saved first (the failure backoff, and for Spamhaus a day, as if
	// a file had arrived); the end of the attempt replaces it.
	f.st.NextTry = start.Add(max(backoff(f.st.Fails+1), f.afterDownload))
	m.mu.Unlock()
	if err := m.saveState(); err != nil {
		// Intentional: no request without a saved schedule — a restart couldn't know this attempt
		// happened and could repeat it at once (Spamhaus's once a day). A failure, backed off.
		m.mu.Lock()
		f.st.Fails = min(f.st.Fails+1, maxFails)
		f.st.LastError = cleanText("the schedule can't be saved, so nothing was downloaded: " + err.Error())
		f.st.NextTry = start.Add(backoff(f.st.Fails))
		msg := f.st.LastError
		m.mu.Unlock()
		m.log.Warn("security feeds: update skipped", "feed", f.name, "err", msg)
		return
	}

	actx, cancel := context.WithTimeout(ctx, f.timeout)
	res, err := m.safeFetch(actx, f, start)
	cancel()
	if ctx.Err() != nil {
		// Shut down mid-attempt: the next start waits only minGap, or afterDownload when a file
		// arrived.
		m.mu.Lock()
		f.st.NextTry = prevNext
		if res.downloaded && start.Add(f.afterDownload).After(prevNext) {
			f.st.NextTry = start.Add(f.afterDownload)
		}
		m.mu.Unlock()
		_ = m.saveState()
		return
	}
	now := m.now()
	m.mu.Lock()
	var wait time.Duration
	if err == nil {
		f.st.Fails, f.st.LastError, f.st.LastSuccess = 0, "", now
		wait = f.interval
		if res.changed {
			f.st.Version, f.st.Updated, f.st.Entries = res.version, now, res.entries
		}
	} else {
		f.st.Fails = min(f.st.Fails+1, maxFails)
		f.st.LastError = cleanText(err.Error())
		wait = backoff(f.st.Fails)
		var rl *rateLimitedError
		if errors.As(err, &rl) {
			wait = rateLimitDelay(f.st.Fails, rl.after)
		}
	}
	if res.downloaded {
		wait = max(wait, f.afterDownload)
	}
	f.st.NextTry = now.Add(wait)
	st := f.st
	m.mu.Unlock()
	_ = m.saveState()
	switch {
	case err != nil:
		m.log.Warn("security feeds: update failed", "feed", f.name, "err", st.LastError, "next_try", st.NextTry.UTC().Format(time.RFC3339))
	case res.changed:
		m.log.Info("security feeds: updated", "feed", f.name, "version", st.Version, "entries", st.Entries)
	}
}

// backoff is the wait after fails failures in a row: 1 h, 2 h, 4 h … at most 24 h.
func backoff(fails int) time.Duration {
	d := minBackoff
	for i := 1; i < fails && d < maxBackoff; i++ {
		d *= 2
	}
	return min(d, maxBackoff)
}

// rateLimitDelay is the wait after an HTTP 429: the backoff, or Retry-After when longer, never under
// 5 minutes, at most 24 h.
func rateLimitDelay(fails int, retryAfter time.Duration) time.Duration {
	return min(max(backoff(fails), retryAfter, rateLimitMin), maxBackoff)
}

// loadState reads state.json; a missing or damaged file starts every feed afresh. Times in the
// future (the clock was set back) are clamped (clampFuture).
func (m *Manager) loadState() {
	b, err := readFile(m.root, stateName, stateCap)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			m.log.Warn("security feeds: can't read the state; starting afresh", "err", err)
		}
		return
	}
	var s stateFile
	if err := json.Unmarshal(b, &s); err != nil || s.V != 1 {
		m.log.Warn("security feeds: the state file is damaged; starting afresh")
		return
	}
	now := m.now()
	for _, f := range m.feeds {
		st, ok := s.Feeds[f.name]
		if !ok {
			continue
		}
		clampFuture(&st, now)
		if !versionRe.MatchString(st.Version) {
			st.Version = ""
		}
		st.Fails = min(max(st.Fails, 0), maxFails)
		st.Entries = min(max(st.Entries, 0), maxEntries)
		st.LastError = cleanText(st.LastError)
		f.st = st
	}
}

// clampFuture handles times in st the clock has not reached (it was set back): a last attempt
// after now is moved to now and the next try back by as much, so the wait that followed the attempt
// is kept from now; the other times are moved to now. A next try further away than any schedule
// sets (24 h) is cut to that, so nothing holds a feed off longer.
func clampFuture(st *feedState, now time.Time) {
	if st.LastAttempt.After(now) {
		shift := st.LastAttempt.Sub(now)
		st.LastAttempt = now
		if !st.NextTry.IsZero() {
			st.NextTry = st.NextTry.Add(-shift)
		}
	}
	for _, t := range []*time.Time{&st.Updated, &st.LastSuccess} {
		if t.After(now) {
			*t = now
		}
	}
	if st.NextTry.After(now.Add(maxBackoff)) {
		st.NextTry = now.Add(maxBackoff)
	}
}

// saveState writes state.json; a failure is logged and returned.
func (m *Manager) saveState() error {
	m.mu.Lock()
	s := stateFile{V: 1, Feeds: make(map[string]feedState, len(m.feeds))}
	for _, f := range m.feeds {
		s.Feeds[f.name] = f.st
	}
	m.mu.Unlock()
	b, err := json.Marshal(s)
	if err == nil {
		err = writeFile(m.root, stateName, b)
	}
	if err != nil {
		m.log.Error("security feeds: can't save the state", "err", err)
	}
	return err
}

// loadList reads f's snapshot into the enricher.
func (m *Manager) loadList(f *feed) error {
	b, err := readFile(m.root, f.file, snapshotCap)
	if err != nil {
		return err
	}
	snap, set, err := decodeSnapshot(b, f.name)
	if err != nil {
		return err
	}
	m.x.SetList(listName(f.name), set)
	f.st.Version, f.st.Updated, f.st.Entries = snap.Version, snap.Fetched, snap.Entries
	return nil
}

func listName(feed string) string {
	switch feed {
	case NameSpamhaus:
		return enrich.ListSpamhaus
	case NameTor:
		return enrich.ListTor
	}
	return enrich.ListDShield
}

// fetchSpamhaus downloads the three DROP files and installs them as one list. Its result says
// whether any file was received, also with an error (the next attempt then waits a day).
func (m *Manager) fetchSpamhaus(ctx context.Context, f *feed, now time.Time) (result, error) {
	var all list
	downloaded := false
	for _, part := range []struct {
		file string
		asn  bool
	}{{"drop_v4.json", false}, {"drop_v6.json", false}, {"asndrop.json", true}} {
		resp, err := m.get(ctx, m.urls.spamhaus+part.file, m.ua)
		if err != nil {
			return result{downloaded: downloaded}, fmt.Errorf("%s: %w", part.file, err)
		}
		downloaded = true
		body, err := readBody(resp, spamhausCap)
		if err != nil {
			return result{downloaded: true}, fmt.Errorf("%s: %w", part.file, err)
		}
		l, err := parseSpamhaus(body, part.asn)
		if err != nil {
			return result{downloaded: true}, fmt.Errorf("%s: %w", part.file, err)
		}
		all.ranges, all.asns, all.entries = append(all.ranges, l.ranges...), append(all.asns, l.asns...), all.entries+l.entries
		if l.date.After(all.date) {
			all.date = l.date
		}
	}
	res, err := m.installList(f, all, now)
	res.downloaded = true
	return res, err
}

func (m *Manager) fetchTor(ctx context.Context, f *feed, now time.Time) (result, error) {
	body, h, err := m.getBody(ctx, m.urls.tor, m.ua, torCap)
	if err != nil {
		return result{}, err
	}
	l, err := parseTor(body)
	if err != nil {
		return result{}, err
	}
	if t, err := http.ParseTime(h.Get("Last-Modified")); err == nil && !t.After(now.Add(time.Hour)) {
		l.date = t
	}
	return m.installList(f, l, now)
}

func (m *Manager) fetchDShield(ctx context.Context, f *feed, now time.Time) (result, error) {
	body, _, err := m.getBody(ctx, m.urls.dshield, m.uaISC, dshieldCap)
	if err != nil {
		return result{}, err
	}
	l, err := parseDShield(body)
	if err != nil {
		return result{}, err
	}
	return m.installList(f, l, now)
}

// installList writes l's snapshot and puts it in the enricher. Its version is the list's own date,
// else the fetch time. A list whose snapshot the next start would refuse (decodeSnapshot,
// snapshotCap) is refused here, so what is in use is what a restart loads.
func (m *Manager) installList(f *feed, l list, now time.Time) (result, error) {
	date := l.date
	if date.IsZero() {
		date = now
	}
	version := date.UTC().Format(versionLayout)
	b, err := encodeSnapshot(f.name, version, now, l)
	if err != nil {
		return result{}, fmt.Errorf("save the list: %w", err)
	}
	if len(b) > snapshotCap {
		return result{}, fmt.Errorf("the list is larger than %d KiB saved", snapshotCap>>10)
	}
	_, set, err := decodeSnapshot(b, f.name)
	if err != nil {
		return result{}, fmt.Errorf("the list can't be saved as it is: %w", err)
	}
	if err := writeFile(m.root, f.file, b); err != nil {
		return result{}, fmt.Errorf("save the list: %w", err)
	}
	m.x.SetList(listName(f.name), set)
	return result{changed: true, version: version, entries: l.entries}, nil
}

var errNotFound = errors.New("not found (HTTP 404)")

type rateLimitedError struct{ after time.Duration }

func (e *rateLimitedError) Error() string { return "rate limited (HTTP 429)" }

// get sends a GET and returns a 200 response; 404 is errNotFound, 429 a *rateLimitedError.
func (m *Manager) get(ctx context.Context, u, ua string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusOK {
		return resp, nil
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
	}()
	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil, errNotFound
	case http.StatusTooManyRequests:
		return nil, &rateLimitedError{after: retryAfter(resp.Header.Get("Retry-After"), m.now())}
	}
	return nil, fmt.Errorf("%s answered %d %s", req.URL.Host, resp.StatusCode, http.StatusText(resp.StatusCode))
}

// getBody is get's body, at most limit bytes.
func (m *Manager) getBody(ctx context.Context, u, ua string, limit int) ([]byte, http.Header, error) {
	resp, err := m.get(ctx, u, ua)
	if err != nil {
		return nil, nil, err
	}
	b, err := readBody(resp, limit)
	if err != nil {
		return nil, nil, err
	}
	return b, resp.Header, nil
}

// readBody reads and closes resp's body, at most limit bytes.
func readBody(resp *http.Response, limit int) ([]byte, error) {
	defer resp.Body.Close()
	if resp.ContentLength > int64(limit) {
		return nil, tooLarge(limit)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, tooLarge(limit)
	}
	return b, nil
}

// retryAfter parses a Retry-After header (seconds or an HTTP date); 0 when absent or bad.
func retryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
		return time.Duration(min(n, int64(maxBackoff/time.Second))) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return min(t.Sub(now), maxBackoff)
	}
	return 0
}

var versionChars = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)

// userAgent is "Mooring/<version>" ("dev" for an empty or odd version).
func userAgent(version string) string {
	if !versionChars.MatchString(version) {
		version = "dev"
	}
	return "Mooring/" + version
}

// headerSafe reports whether s can go in a header value: printable, no line break, bounded.
func headerSafe(s string) bool {
	if len(s) > 320 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// cleanText makes an error text safe to log and show: control characters removed, cut.
func cleanText(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	return siem.Cut(s, errTextMax)
}

// removeTemp deletes temporary files an interrupted write left (only this process writes Dir).
func (m *Manager) removeTemp() {
	d, err := m.root.Open(".")
	if err != nil {
		return
	}
	names, _ := d.Readdirnames(-1)
	d.Close()
	for _, n := range names {
		if strings.Contains(n, tmpMark) {
			_ = m.root.Remove(n)
		}
	}
}

const tmpMark = ".tmp-"

// createTemp creates a new 0600 file for name in the root.
func createTemp(root *os.Root, name string) (string, *os.File, error) {
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", nil, err
	}
	tmp := name + tmpMark + hex.EncodeToString(rnd[:])
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	return tmp, f, err
}

// afterTempWrite is called in writeFile once the temporary file is written (tests).
var afterTempWrite func()

// writeFile replaces name in the root with b: a temporary file, synced, then renamed.
func writeFile(root *os.Root, name string, b []byte) error {
	tmp, f, err := createTemp(root, name)
	if err != nil {
		return err
	}
	renamed := false
	defer func() {
		// Intentional: keyed on completion, not on an error, so a panic unwinding through here also
		// closes and removes the temporary file (as installDBIP). Closing a closed file only returns an
		// error.
		if !renamed {
			_ = f.Close()
			_ = root.Remove(tmp)
		}
	}()
	_, err = f.Write(b)
	if afterTempWrite != nil {
		afterTempWrite()
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = root.Rename(tmp, name)
	}
	renamed = err == nil
	return err
}

// readFile reads name in the root, a regular file of at most limit bytes.
func readFile(root *os.Root, name string, limit int64) ([]byte, error) {
	fi, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d KiB", name, limit>>10)
	}
	return b, nil
}
