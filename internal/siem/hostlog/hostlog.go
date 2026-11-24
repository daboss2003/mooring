// Package hostlog follows the host's auth and Fail2Ban log files (and, where there is no auth log
// file, the systemd journal for sshd, sudo, su and the user and group programs) and hands each new
// line on.
package hostlog

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/siem"
)

// Sources (Line.Source).
const (
	SourceAuth     = "auth"
	SourceFail2Ban = "fail2ban"
	SourceJournal  = "journal"
)

// Line is one new line from a host log; At is when it was read.
type Line struct {
	Source string
	Text   string
	At     time.Time
}

// Config is what to follow. Empty paths are not followed.
type Config struct {
	AuthLog     string
	Fail2BanLog string
	Journal     bool   // follow sshd/sudo/su and the user/group programs in the systemd journal (journalctl -f -o json)
	StateDir    string // where read offsets / the journal cursor are kept (0700 dir, 0600 files)
	Poll        time.Duration
	Log         *slog.Logger

	authViaJournal bool // set by FromConfig: AuthLog can't be read, the journal replaces it
}

const (
	defaultPoll = time.Second
	// linesPerPoll caps the lines one source hands on per Poll, so a backlog (Mooring was down, a
	// brute-force flood) drains at a rate the pipeline's queue can take instead of overflowing it.
	linesPerPoll = 2000
	// permHint is the status of a log the service user may not read.
	permHint = "permission denied: the mooring user needs the adm group (sudo mooring setup --yes, then restart Mooring)"
	// authViaJournal is the host:auth status when the journal replaces an unreadable auth log.
	authViaJournal = "permission denied: reading sshd, sudo, su and user changes from the journal instead"
	// maxState bounds a state file read back.
	maxState = 4 << 10
)

// varLog is where the default logs live (a var for tests).
var varLog = "/var/log"

// FromConfig resolves the security_logs.host_logs block (defaults: /var/log/auth.log, else
// /var/log/secure; /var/log/fail2ban.log; the journal only when no auth log file exists).
func FromConfig(h config.SecurityLogsHost, stateDir string, log *slog.Logger) Config {
	if log == nil {
		log = slog.Default()
	}
	cfg := Config{StateDir: stateDir, Poll: defaultPoll, Log: log}
	if !h.On() {
		return cfg
	}
	cfg.AuthLog = configuredPath(h.AuthLog, "auth_log", log)
	if cfg.AuthLog == "" {
		for _, name := range []string{"auth.log", "secure"} {
			if p := filepath.Join(varLog, name); exists(p) {
				cfg.AuthLog = p
				break
			}
		}
	}
	cfg.Fail2BanLog = configuredPath(h.Fail2BanLog, "fail2ban_log", log)
	if cfg.Fail2BanLog == "" {
		cfg.Fail2BanLog = filepath.Join(varLog, "fail2ban.log") // followed even when absent: Fail2Ban may be installed later
	}
	switch {
	case h.Journal != nil:
		cfg.Journal = *h.Journal
	case cfg.AuthLog == "":
		cfg.Journal = true
	case unreadable(cfg.AuthLog):
		// Intentional: decided once, here at start, and the file is then not followed (no event
		// is collected twice). The service's groups are fixed for its lifetime, so a file made
		// readable later needs a restart either way.
		cfg.Journal, cfg.authViaJournal = true, true
		log.Warn("security_logs: the auth log can't be read; reading sshd, sudo, su and user changes from the journal instead", "path", cfg.AuthLog)
	}
	return cfg
}

// unreadable reports whether the log at p exists but opening it is denied.
func unreadable(p string) bool {
	t, _, err := openLog(p, isDefault(p))
	if err != nil {
		return errors.Is(err, fs.ErrPermission)
	}
	t.f.Close()
	return false
}

// configuredPath is p when it is an absolute, clean path; anything else is ignored (the default
// applies) with a warning.
func configuredPath(p, key string, log *slog.Logger) string {
	if p == "" {
		return ""
	}
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		log.Warn("security_logs: host_logs."+key+" is not an absolute, clean path; using the default", "path", p)
		return ""
	}
	return p
}

// exists reports whether something is at p (a dangling symlink or an unreadable entry counts: the
// follower reports what is wrong with it).
func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil || !errors.Is(err, fs.ErrNotExist)
}

// isDefault reports whether p is one of the built-in default log paths.
func isDefault(p string) bool {
	for _, name := range []string{"auth.log", "secure", "fail2ban.log"} {
		if p == filepath.Join(varLog, name) {
			return true
		}
	}
	return false
}

// Follower follows the configured logs.
type Follower struct {
	cfg       Config
	files     []fileSpec
	journalSI int // index of host:journal in st, -1 when the journal isn't followed

	// Timings and seams (tests shorten or replace them).
	now          func() time.Time
	sleep        func(context.Context, time.Duration) bool // false when ctx ended first
	journalctl   string
	retry        time.Duration // a log that can't be opened is tried again after this
	persistEvery time.Duration // offsets and the cursor are saved at most this often (and on exit)
	grace        time.Duration // a rotated-away file is still read this long, until its writer reopens
	backoffMin   time.Duration // journalctl restart backoff…
	backoffMax   time.Duration
	healthy      time.Duration // …reset after a run that lasted this long
	missingRetry time.Duration // journalctl not installed: look again after this

	dirOnce sync.Once
	dirErr  error

	mu sync.Mutex
	st []siem.SourceStatus
}

// fileSpec is one followed file.
type fileSpec struct {
	si     int // index in Follower.st
	source string
	path   string
}

// New builds a Follower.
func New(cfg Config) *Follower {
	if cfg.Poll <= 0 {
		cfg.Poll = defaultPoll
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	f := &Follower{
		cfg: cfg, journalSI: -1,
		now: time.Now, sleep: sleepCtx, journalctl: "journalctl",
		retry: 10 * time.Second, persistEvery: 5 * time.Second, grace: 5 * time.Second,
		backoffMin: time.Second, backoffMax: time.Minute, healthy: time.Minute, missingRetry: 5 * time.Minute,
	}
	add := func(name string) int {
		f.st = append(f.st, siem.SourceStatus{Name: name, Err: "not started"})
		return len(f.st) - 1
	}
	switch {
	case cfg.AuthLog != "" && cfg.authViaJournal:
		si := add("host:" + SourceAuth)
		f.st[si].Err = authViaJournal
	case cfg.AuthLog != "":
		f.files = append(f.files, fileSpec{add("host:" + SourceAuth), SourceAuth, cfg.AuthLog})
	}
	if cfg.Fail2BanLog != "" {
		f.files = append(f.files, fileSpec{add("host:" + SourceFail2Ban), SourceFail2Ban, cfg.Fail2BanLog})
	}
	if cfg.Journal {
		f.journalSI = add("host:" + SourceJournal)
	}
	return f
}

// Run follows until ctx ends, calling emit for every new line (from the saved offset, or the end
// of the file on the first run). It survives rotation, truncation and a file that doesn't exist
// yet or can't be read (reported by Status, retried).
//
// emit is called from one goroutine per source, so concurrently; it must be safe for concurrent
// use and must not block (the pipeline's HostLine only enqueues). Run returns once every source
// has stopped and saved its position; call it once.
func (f *Follower) Run(ctx context.Context, emit func(Line)) {
	f.forgetUnfollowed()
	var wg sync.WaitGroup
	for _, spec := range f.files {
		ff := f.newFile(spec, emit)
		wg.Go(func() { ff.run(ctx) })
	}
	if f.journalSI >= 0 {
		wg.Go(func() { f.runJournal(ctx, emit) })
	}
	wg.Wait()
}

// forgetUnfollowed removes the saved position of each source this run doesn't follow. A source
// taken up again on a later start (the journal replacing an unreadable auth log, or the auth log
// the journal) then starts at now: resuming from a position older than the period the other source
// covered would collect those events twice.
func (f *Follower) forgetUnfollowed() {
	if f.cfg.StateDir == "" {
		return
	}
	followed := map[string]bool{}
	for _, spec := range f.files {
		followed[spec.source+".offset"] = true
	}
	if f.journalSI >= 0 {
		followed[journalStateFile] = true
	}
	for _, name := range []string{SourceAuth + ".offset", SourceFail2Ban + ".offset", journalStateFile} {
		if followed[name] {
			continue
		}
		if err := os.Remove(filepath.Join(f.cfg.StateDir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			f.cfg.Log.Warn("security_logs: removing a saved host log position failed", "file", name, "err", err)
		}
	}
}

// Status reports each followed source ("host:auth", "host:fail2ban", "host:journal").
func (f *Follower) Status() []siem.SourceStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.st)
}

// lineFunc wraps emit for one source: it stamps the line and counts it.
func (f *Follower) lineFunc(si int, source string, emit func(Line)) func(string) {
	return func(text string) {
		at := f.now()
		emit(Line{Source: source, Text: text, At: at})
		f.mu.Lock()
		f.st[si].Events++
		f.st[si].LastSeen = at
		f.mu.Unlock()
	}
}

// setOK marks source si as reading, logging the change.
func (f *Follower) setOK(si int, attrs ...any) {
	if name, changed := f.markOK(si); changed {
		f.cfg.Log.Info("security_logs: reading host log", append([]any{"source", name}, attrs...)...)
	}
}

// markOK marks source si as reading and reports whether it wasn't.
func (f *Follower) markOK(si int) (name string, changed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := &f.st[si]
	changed = !s.OK
	s.OK, s.Err = true, ""
	return s.Name, changed
}

// setErr marks source si as not reading, logging each new reason once.
func (f *Follower) setErr(si int, msg string, attrs ...any) {
	f.mu.Lock()
	s := &f.st[si]
	changed := s.OK || s.Err != msg
	s.OK, s.Err = false, msg
	name := s.Name
	f.mu.Unlock()
	if changed {
		f.cfg.Log.Warn("security_logs: host log not readable", append([]any{"source", name, "err", msg}, attrs...)...)
	}
}

// readState decodes the state file name into v; false when there is none or it is unreadable.
func (f *Follower) readState(name string, v any) bool {
	if f.cfg.StateDir == "" {
		return false
	}
	r, err := os.Open(filepath.Join(f.cfg.StateDir, name))
	if err != nil {
		return false
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, maxState))
	return err == nil && json.Unmarshal(b, v) == nil
}

// writeState replaces the state file name with v (0600, via a temp file and rename).
func (f *Follower) writeState(name string, v any) error {
	dir := f.cfg.StateDir
	if dir == "" {
		return nil
	}
	f.dirOnce.Do(func() {
		if f.dirErr = os.MkdirAll(dir, 0o700); f.dirErr == nil {
			f.dirErr = os.Chmod(dir, 0o700)
		}
	})
	if f.dirErr != nil {
		return f.dirErr
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+name+".*") // CreateTemp makes it 0600
	if err != nil {
		return err
	}
	_, err = tmp.Write(b)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), filepath.Join(dir, name))
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
