package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/alertstore"
	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/hostmon"
	"github.com/daboss2003/mooring/internal/servicelog"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/archive"
	"github.com/daboss2003/mooring/internal/siem/hostlog"
	"github.com/daboss2003/mooring/internal/siem/pipeline"
	"github.com/daboss2003/mooring/internal/siem/query"
	"github.com/daboss2003/mooring/internal/siem/redact"
	siemstore "github.com/daboss2003/mooring/internal/siem/store"
	"github.com/daboss2003/mooring/internal/store"
	"github.com/daboss2003/mooring/internal/web"
)

// Security-log infra alert kinds (docs/alerting.md).
const (
	kindSecLogsArchiveFailed  = "security_log_archive_failed"
	kindSecLogsSegmentChanged = "security_log_segment_changed"
	kindSecLogsNotRunning     = "security_logs_not_running"
)

// securityLogPrune is how often the on-host store is pruned (and its due hours sealed).
const securityLogPrune = 5 * time.Minute

// securityLogs is serve's security-log collection (docs/security-logs.md): the on-host store, the
// pipeline every source feeds, the host-log follower, the S3 archiver and the periodic prune. A nil
// *securityLogs means security logs are off; every method is nil-safe. failed is set when they are on
// but didn't start: the Security page then shows why instead of "off".
type securityLogs struct {
	store    *siemstore.Store
	pipe     *pipeline.Pipeline
	red      *redact.Redactor
	follower *hostlog.Follower
	arch     *archive.Archiver
	dir      string // <data_dir>/security-logs
	failed   string

	workerCtx   context.Context // the follower's, the archiver's, the prune's and the CLI poll's: ended by close
	stopWorkers context.CancelFunc
	workers     sync.WaitGroup
	stopPipe    context.CancelFunc
	pipeDone    chan struct{}
	closeOnce   sync.Once
}

// openSecurityLogs builds and starts security-log collection when cfg turns it on (nil when off).
// Intentional: a failure to start never refuses boot (an upgrade must not take the edge down): it is
// logged, alerted and shown on the Security page, and Mooring runs without security logs.
func openSecurityLogs(ctx context.Context, cfg *config.Config, alerts *alertstore.Store, log *slog.Logger) *securityLogs {
	if !cfg.SecurityLogs.On() {
		return nil
	}
	s, err := startSecurityLogs(ctx, cfg, alerts, log)
	if err != nil {
		log.Error("security logs: not started; Mooring runs without them", "err", err)
		if alerts != nil {
			_ = alerts.EnqueueInfra(context.Background(), alert.Outbox{
				Target: "security-logs", Kind: kindSecLogsNotRunning, Level: alert.LevelWarning, Transition: "firing",
				Summary:   "Security logs are turned on but didn't start, so nothing is being collected: " + err.Error() + ". Run sudo mooring doctor, fix the cause, then restart Mooring.",
				DedupeKey: "security-logs:not-running",
			})
		}
		return &securityLogs{failed: err.Error()}
	}
	if alerts != nil {
		// A start after a failed one closes that alert.
		if open, oerr := alerts.OpenInfraAlerts(context.Background(), kindSecLogsNotRunning); oerr == nil && len(open) > 0 {
			_ = alerts.EnqueueInfra(context.Background(), alert.Outbox{
				Target: "security-logs", Kind: kindSecLogsNotRunning, Level: alert.LevelWarning, Transition: "resolved",
				Summary: "Security logs are running again.", DedupeKey: "security-logs:not-running",
			})
		}
	}
	return s
}

func startSecurityLogs(ctx context.Context, cfg *config.Config, alerts *alertstore.Store, log *slog.Logger) (*securityLogs, error) {
	master, err := config.DecodeKey(cfg.EncryptionKey)
	if err != nil {
		return nil, err
	}
	piiKey, err := siem.DeriveKey(master, siem.KeyPII)
	if err != nil {
		return nil, err
	}
	pii := cfg.SecurityLogs.PII
	red, err := redact.New(piiKey, redact.Options{HashFields: pii.HashFields, DropFields: pii.DropFields, KeepFields: pii.KeepFields})
	if err != nil {
		return nil, err
	}
	box := securityLogBox()
	dir := filepath.Join(cfg.DataDir, "security-logs")
	st, err := siemstore.Open(siemstore.Options{
		Dir: dir, Box: box,
		HotRetention:      cfg.SecurityLogs.HotRetentionOrDefault(),
		MaxDiskBytes:      cfg.SecurityLogs.HotMaxDiskBytes(),
		ArchiveConfigured: cfg.SecurityLogs.Archive.S3 != nil,
		// The data dir shares its filesystem with mooring.db: at the disk-pressure threshold the store
		// removes uploaded segments and then refuses new events, like the service-log capture.
		DiskUsage:        diskUsageOf(cfg.DataDir),
		DiskThresholdPct: float64(cfg.Server.DiskGCThresholdPct()),
		Log:              log,
	})
	if err != nil {
		return nil, err
	}
	s := &securityLogs{store: st, red: red, dir: dir, pipeDone: make(chan struct{})}
	s.pipe = pipeline.New(pipeline.Options{Store: st, Redactor: red, Log: log})

	// The pipeline drains on its own context, after every source has stopped (close).
	pipeCtx, stopPipe := context.WithCancel(context.Background())
	s.stopPipe = stopPipe
	go func() { defer close(s.pipeDone); s.pipe.Run(pipeCtx) }()

	wctx, stopWorkers := context.WithCancel(ctx)
	s.workerCtx, s.stopWorkers = wctx, stopWorkers
	s.follower = hostlog.New(hostlog.FromConfig(cfg.SecurityLogs.HostLogs, filepath.Join(dir, "hostlog"), log))
	s.workers.Add(1)
	go func() { defer s.workers.Done(); s.follower.Run(wctx, s.pipe.HostLine) }()

	if sc := cfg.SecurityLogs.Archive.S3; sc != nil {
		cl, cerr := s3ClientFor(sc)
		if cerr != nil {
			log.Error("security logs: the S3 archive is off", "err", cerr)
		} else {
			var al archive.Alerter
			if alerts != nil {
				al = securityLogAlerts{alerts}
			}
			s.arch = archive.New(archive.Options{Store: st, Up: cl, Key: master, Prefix: sc.Prefix, Box: box,
				Retention: cfg.SecurityLogs.Archive.RetentionOrDefault(), Alerts: al, Log: log,
				// A seal left in the bucket from before a key rotation still counts as this server's.
				PreviousKey: func() []byte {
					if cfg.EncryptionKeyPrevious == "" {
						return nil
					}
					prev, perr := config.DecodeKey(cfg.EncryptionKeyPrevious)
					if perr != nil || len(prev) != 32 {
						log.Warn("security logs: encryption_key_previous is not a 32-byte key; the archive ignores it", "err", perr)
						return nil
					}
					return prev
				}()})
			s.workers.Add(1)
			go func() { defer s.workers.Done(); s.arch.Run(wctx) }()
		}
	}

	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		t := time.NewTicker(securityLogPrune)
		defer t.Stop()
		for {
			select {
			case <-wctx.Done():
				return
			case <-t.C:
				if perr := st.Prune(); perr != nil {
					log.Warn("security logs: prune failed", "err", perr)
				}
			}
		}
	}()
	log.Info("security logs enabled", "dir", dir, "box", box, "archive", s.arch != nil)
	return s, nil
}

// cliAuditPoll is how often serve copies the audit events CLI commands wrote.
const cliAuditPoll = 30 * time.Second

// followCLIAudit copies the audit events written by CLI commands (`mooring token`, `mooring secret
// import`: actor "cli:…") into security logs. They come from another process, so the audit sink never
// sees them. The position (the newest events.seq examined) is kept in <dir>/cli-audit.seq; with none
// yet it starts at the newest row, so older history isn't copied.
//
// Intentional: it runs on the security logs' own worker context, not the caller's: close (deferred in
// serve) waits for it, and on an early return serve's own context is cancelled only after close.
func (s *securityLogs) followCLIAudit(db *store.DB, log *slog.Logger) {
	if !s.running() || db == nil {
		return
	}
	ctx := s.workerCtx
	posFile := filepath.Join(s.dir, "cli-audit.seq")
	pos, ok := readSeqFile(posFile)
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		t := time.NewTicker(cliAuditPoll)
		defer t.Stop()
		for {
			var hi int64
			// Two statements one after the other, never one while the other's rows are open (the main DB
			// has a single connection).
			if err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) FROM events`).Scan(&hi); err == nil {
				if !ok || hi < pos {
					// First run: start at the newest row. A position past the newest row means the
					// database was restored from an older copy: start again from its newest row.
					pos, ok = hi, true
				}
				if hi > pos {
					evs, err := cliAuditRows(ctx, db, pos, hi)
					if err != nil {
						log.Warn("security logs: reading CLI audit events failed", "err", err)
					} else {
						for _, e := range evs {
							s.pipe.Audit(e.ts, e.ev)
						}
						pos = hi
					}
				}
				if err := writeSeqFile(posFile, pos); err != nil {
					log.Warn("security logs: saving the CLI audit position failed", "err", err)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

type cliAuditRow struct {
	ts time.Time
	ev audit.Event
}

// cliAuditRows reads the CLI-written events with lo < seq ≤ hi (all rows scanned, then closed).
// Intentional: ip = 'local' too — only the CLI writes it, and a web login attempt with a username
// starting "cli:" (LIKE is case-insensitive) reached the sink already; copying it would double it.
func cliAuditRows(ctx context.Context, db *store.DB, lo, hi int64) ([]cliAuditRow, error) {
	rows, err := db.QueryContext(ctx, `SELECT ts, actor, ip, action, target, outcome, level, detail, user_agent
		FROM events WHERE seq > ? AND seq <= ? AND actor LIKE 'cli:%' AND ip = 'local' ORDER BY seq`, lo, hi)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cliAuditRow
	for rows.Next() {
		var ts int64
		var e audit.Event
		var outcome, level string
		if err := rows.Scan(&ts, &e.Actor, &e.IP, &e.Action, &e.Target, &outcome, &level, &e.Detail, &e.UA); err != nil {
			return nil, err
		}
		e.Outcome, e.Level = audit.Outcome(outcome), audit.Level(level)
		out = append(out, cliAuditRow{ts: time.Unix(ts, 0), ev: e})
	}
	return out, rows.Err()
}

func readSeqFile(path string) (int64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func writeSeqFile(path string, n int64) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(n, 10)+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// diskUsageOf samples the filesystem holding dir (used and total bytes; ok false when unknown).
func diskUsageOf(dir string) func() (uint64, uint64, bool) {
	sampler := hostmon.New(dir)
	return func() (uint64, uint64, bool) {
		hs, err := sampler.Sample()
		if err != nil {
			return 0, 0, false
		}
		return hs.DiskUsed, hs.DiskTotal, true
	}
}

// close stops the host follower, the archiver and the prune, drains the pipeline and closes the
// store. Call it after every other source (log tailers, the edge, the web server) has stopped.
func (s *securityLogs) close() {
	if s == nil || s.store == nil {
		return
	}
	s.closeOnce.Do(func() {
		s.stopWorkers()
		s.workers.Wait()
		s.stopPipe()
		<-s.pipeDone
		_ = s.store.Close()
	})
}

// running reports whether events are being collected.
func (s *securityLogs) running() bool { return s != nil && s.pipe != nil }

// appLine is the servicelog sink: every app container line, with Docker's time for it when known.
func (s *securityLogs) appLine(l servicelog.Line) {
	if !s.running() {
		return
	}
	at := l.At
	if !l.TS.IsZero() {
		at = l.TS.Unix()
	}
	s.pipe.AppLine(at, l.App, l.Svc, l.Copy, l.Text)
}

// edgeLine takes one raw Caddy stdout line.
func (s *securityLogs) edgeLine(raw []byte) {
	if s.running() {
		s.pipe.EdgeLine(raw)
	}
}

// auditSink is the audit logger's sink (nil when not collecting, so no sink is set).
func (s *securityLogs) auditSink() func(time.Time, audit.Event) {
	if !s.running() {
		return nil
	}
	return s.pipe.Audit
}

// webSource is what the Security page reads: nil (off) only when security logs are off.
func (s *securityLogs) webSource() web.SecurityLogs {
	if s == nil {
		return nil
	}
	return securityLogsSource{s}
}

// securityLogsSource adapts securityLogs to web.SecurityLogs.
type securityLogsSource struct{ s *securityLogs }

var errSecurityLogsNotRunning = errors.New("security logs didn't start (see the status above)")

func (a securityLogsSource) Search(ctx context.Context, q query.Query, limit int) (siemstore.Result, error) {
	if !a.s.running() {
		return siemstore.Result{}, errSecurityLogsNotRunning
	}
	return a.s.store.Search(ctx, q, limit)
}

func (a securityLogsSource) Export(ctx context.Context, q query.Query, w io.Writer, maxEvents int) (int, error) {
	if !a.s.running() {
		return 0, errSecurityLogsNotRunning
	}
	return a.s.store.Export(ctx, q, w, maxEvents)
}

func (a securityLogsSource) SearchValue(field, value string) string {
	if !a.s.running() {
		return value
	}
	return a.s.red.SearchValue(field, value)
}

func (a securityLogsSource) SearchText(text string) string {
	if !a.s.running() {
		return text
	}
	return a.s.red.SearchText(text)
}

func (a securityLogsSource) SecretField(field string) bool {
	return a.s.running() && a.s.red.SecretField(field)
}

func (a securityLogsSource) Status() siem.Status {
	s := a.s
	if !s.running() {
		return siem.Status{Enabled: true, Sources: []siem.SourceStatus{{Name: "pipeline", Err: "not started: " + s.failed}}}
	}
	st := siem.Status{Enabled: true, Sources: append(s.pipe.Sources(), s.follower.Status()...)}
	st.Queue, st.QueueCap = s.pipe.Queue()
	st.DiskBytes, st.Segments, st.Oldest = s.store.DiskBytes(), s.store.Segments(), s.store.Oldest()
	if s.arch != nil {
		st.ArchiveOn = true
		st.LastArchived, st.ArchiveBehind, st.ArchiveErr = s.arch.LastArchived(), s.arch.Behind(), s.arch.Err()
	}
	return st
}

// securityLogAlerts raises the archive's alerts as Mooring infra alerts.
type securityLogAlerts struct{ store *alertstore.Store }

func (a securityLogAlerts) ArchiveFailing(ctx context.Context, failing bool, detail string) {
	o := alert.Outbox{Target: "security-logs", Kind: kindSecLogsArchiveFailed, Level: alert.LevelWarning,
		DedupeKey: "security-logs:archive"}
	if failing {
		o.Transition, o.Summary = "firing", "Security-log uploads to S3 are failing, so the off-host copy is behind: "+detail
	} else {
		o.Transition, o.Summary = "resolved", "Security-log uploads to S3 work again."
	}
	_ = a.store.EnqueueInfra(ctx, o)
}

func (a securityLogAlerts) SegmentChanged(ctx context.Context, segment, detail string) {
	_ = a.store.EnqueueInfra(ctx, alert.Outbox{Target: "security-logs", Kind: kindSecLogsSegmentChanged,
		Level: alert.LevelCritical, Transition: "firing", Summary: detail,
		DedupeKey: "security-logs:segment-changed:" + segment})
}

// securityLogBox is this host's name for segment and archive object names: the hostname cut to the
// characters siem.SafeName allows (other characters become '-'), at most 64 bytes, "host" when empty.
func securityLogBox() string {
	h, _ := os.Hostname()
	var b strings.Builder
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-') // '.' too: a dotted FQDN would look like extensions in the object names
		}
		if b.Len() >= 64 {
			break
		}
	}
	box := strings.Trim(b.String(), "-")
	if !siem.SafeName(box) {
		return "host"
	}
	return box
}
