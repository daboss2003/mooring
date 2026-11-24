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
	"sync/atomic"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/alertstore"
	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/hostmon"
	"github.com/daboss2003/mooring/internal/servicelog"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/archive"
	"github.com/daboss2003/mooring/internal/siem/detect"
	"github.com/daboss2003/mooring/internal/siem/enrich"
	"github.com/daboss2003/mooring/internal/siem/feeds"
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
	kindDetectionNotRunning   = "security_detection_not_running"
	kindFeedsNotRunning       = "security_feeds_not_running"
)

// securityLogPrune is how often the on-host store is pruned (and its due hours sealed).
const securityLogPrune = 5 * time.Minute

// securityFeedsDelay is how long after start the enrichment feeds are first checked.
const securityFeedsDelay = 2 * time.Minute

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
	enr      *enrich.Enricher // GeoIP + threat-intel enrichment (filled by feeds)
	feeds    *feeds.Manager   // nil when it couldn't start
	det      *detect.Engine   // nil when detection is off or didn't start
	dir      string           // <data_dir>/security-logs
	failed   string
	log      *slog.Logger

	workerCtx   context.Context // the follower's, the archiver's, the prune's and the CLI poll's: ended by close
	stopWorkers context.CancelFunc
	workers     sync.WaitGroup
	stopPipe    context.CancelFunc
	pipeDone    chan struct{}
	stopDet     context.CancelFunc
	detDone     chan struct{}
	closeOnce   sync.Once
}

// openSecurityLogs builds and starts security-log collection when cfg turns it on (nil when off).
// Intentional: a failure to start never refuses boot (an upgrade must not take the edge down): it is
// logged, alerted and shown on the Security page, and Mooring runs without security logs.
func openSecurityLogs(ctx context.Context, cfg *config.Config, alerts *alertstore.Store, db *store.DB, log *slog.Logger) *securityLogs {
	if !cfg.SecurityLogs.On() {
		// Turned off instead of fixed: nothing that was failing runs any more.
		resolveInfra(alerts, kindSecLogsNotRunning, "security-logs:not-running", "Security logs are turned off.")
		resolveInfra(alerts, kindDetectionNotRunning, "security-logs:detection-not-running", "Security logs, and with them security detection, are turned off.")
		resolveInfra(alerts, kindFeedsNotRunning, "security-logs:feeds-not-running", "Security logs, and with them the enrichment feeds, are turned off.")
		return nil
	}
	s, err := startSecurityLogs(ctx, cfg, alerts, db, log)
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

func startSecurityLogs(ctx context.Context, cfg *config.Config, alerts *alertstore.Store, db *store.DB, log *slog.Logger) (*securityLogs, error) {
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
	s := &securityLogs{store: st, red: red, dir: dir, log: log, pipeDone: make(chan struct{})}

	// Enrichment (docs/security-logs.md "Enrichment"): GeoIP and threat-intel lists, kept current by
	// the feeds manager. A manager that can't start leaves events unenriched; collection goes on.
	s.enr = enrich.New()
	if fm, ferr := feeds.New(feeds.Options{
		Dir: filepath.Join(dir, "feeds"), Enricher: s.enr,
		GeoIP: cfg.SecurityFeedGeoIP(), Spamhaus: cfg.SecurityFeedSpamhaus(), Tor: cfg.SecurityFeedTor(),
		DShieldContact: cfg.SecurityDShieldContact(), Version: Version, Log: log.With("component", "feeds"),
	}); ferr != nil {
		log.Error("security logs: the enrichment feeds didn't start; events are stored without geo and list data", "err", ferr)
		if alerts != nil {
			_ = alerts.EnqueueInfra(context.Background(), alert.Outbox{
				Target: "security-logs", Kind: kindFeedsNotRunning, Level: alert.LevelWarning, Transition: "firing",
				Summary:   "The security-log enrichment feeds didn't start, so events are stored without location and threat-list data: " + ferr.Error() + ". Fix the cause, then restart Mooring.",
				DedupeKey: "security-logs:feeds-not-running",
			})
		}
	} else {
		s.feeds = fm
		resolveInfra(alerts, kindFeedsNotRunning, "security-logs:feeds-not-running", "The security-log enrichment feeds are running again.")
	}

	// Detection (docs/security-detections.md). The engine hands its siem.detection events back to the
	// pipeline, which is built after it: Emit reads it through pipeRef.
	var pipeRef atomic.Pointer[pipeline.Pipeline]
	var subscribers []func(siem.Event)
	if cfg.SecurityDetectionOn() {
		var al detect.Alerter
		if alerts != nil {
			al = alerts
		}
		eng, derr := detect.New(detect.Options{
			Dir: dir, MainDB: db, Alerter: al,
			Emit:     func(e siem.Event) bool { p := pipeRef.Load(); return p != nil && p.Emit(e) },
			MapValue: detectMapValue(red),
			Log:      log.With("component", "detect"),
		})
		if derr != nil {
			// Intentional: like security logs themselves, a detection that can't start never refuses
			// boot; it is logged and alerted, and collection goes on without it.
			log.Error("security logs: detection didn't start; events are collected but not checked", "err", derr)
			if alerts != nil {
				_ = alerts.EnqueueInfra(context.Background(), alert.Outbox{
					Target: "security-logs", Kind: kindDetectionNotRunning, Level: alert.LevelWarning, Transition: "firing",
					Summary:   "Security detection is turned on but didn't start, so events aren't checked: " + derr.Error() + ". Fix the cause, then restart Mooring.",
					DedupeKey: "security-logs:detection-not-running",
				})
			}
		} else {
			s.det = eng
			subscribers = append(subscribers, eng.Subscriber())
			resolveInfra(alerts, kindDetectionNotRunning, "security-logs:detection-not-running", "Security detection is running again.")
		}
	} else {
		resolveInfra(alerts, kindDetectionNotRunning, "security-logs:detection-not-running", "Security detection is turned off.")
	}
	s.pipe = pipeline.New(pipeline.Options{Store: st, Redactor: red, Log: log, Enricher: s.enr.Enrich, Subscribers: subscribers})
	pipeRef.Store(s.pipe)

	// The pipeline drains on its own context, after every source has stopped (close).
	pipeCtx, stopPipe := context.WithCancel(context.Background())
	s.stopPipe = stopPipe
	go func() { defer close(s.pipeDone); s.pipe.Run(pipeCtx) }()

	// The engine runs on its own context too: close stops it after the pipeline has handed it every
	// source event and before the pipeline stops, since its last step stores and emits the
	// detections still pending.
	if s.det != nil {
		detCtx, stopDet := context.WithCancel(context.Background())
		s.stopDet, s.detDone = stopDet, make(chan struct{})
		go func() { defer close(s.detDone); s.det.Run(detCtx) }()
	}

	wctx, stopWorkers := context.WithCancel(ctx)
	s.workerCtx, s.stopWorkers = wctx, stopWorkers
	s.follower = hostlog.New(hostlog.FromConfig(cfg.SecurityLogs.HostLogs, filepath.Join(dir, "hostlog"), log))
	s.workers.Add(1)
	go func() { defer s.workers.Done(); s.follower.Run(wctx, s.pipe.HostLine) }()
	if s.feeds != nil {
		s.workers.Add(1)
		go func() {
			defer s.workers.Done()
			// The files already on disk are in use from the start; downloads wait until boot is over.
			select {
			case <-wctx.Done():
				return
			case <-time.After(securityFeedsDelay):
			}
			s.feeds.Run(wctx)
		}()
	}

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
	log.Info("security logs enabled", "dir", dir, "box", box, "archive", s.arch != nil, "feeds", s.feeds != nil, "detection", s.det != nil)
	return s, nil
}

// resolveInfra closes an open "didn't start" alert of kind after a start that worked, or when what
// failed to start is turned off.
func resolveInfra(alerts *alertstore.Store, kind, dedupe, summary string) {
	if alerts == nil {
		return
	}
	if open, err := alerts.OpenInfraAlerts(context.Background(), kind); err == nil && len(open) > 0 {
		_ = alerts.EnqueueInfra(context.Background(), alert.Outbox{
			Target: "security-logs", Kind: kind, Level: alert.LevelWarning, Transition: "resolved",
			Summary: summary, DedupeKey: dedupe,
		})
	}
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

// drainInputsTimeout bounds close's wait for the pipeline's source drain (which keeps to its own
// budget, pipeline drainBudget); it only matters if the pipeline's Run isn't serving.
const drainInputsTimeout = 10 * time.Second

// close stops the host follower, the archiver and the prune, drains the pipeline and closes the
// store. Call it after every other source (log tailers, the edge, the web server) has stopped.
//
// With detection running it stops in two phases: the pipeline first hands every source event it
// still holds to the engine, which is still running (DrainInputs), then the engine stops (its last
// step stores and emits the pending detections), then the pipeline stops, storing those.
func (s *securityLogs) close() {
	if s == nil || s.store == nil {
		return
	}
	s.closeOnce.Do(func() {
		s.stopWorkers()
		s.workers.Wait()
		if s.feeds != nil {
			s.feeds.Close() // its Run (a worker) has returned
		}
		if s.stopDet != nil {
			dctx, cancel := context.WithTimeout(context.Background(), drainInputsTimeout)
			if err := s.pipe.DrainInputs(dctx); err != nil && s.log != nil {
				s.log.Warn("security logs: the queue wasn't handed to detection before it stopped", "err", err)
			}
			cancel()
			s.stopDet()
			<-s.detDone
		}
		s.stopPipe()
		<-s.pipeDone
		if s.det != nil {
			_ = s.det.Close()
		}
		s.enr.Close() // after the pipeline has drained: no enrichment can still be running
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

// detections is what the Detections and Rules pages use (nil when detection isn't running; an untyped
// nil, so the web layer sees "off").
func (s *securityLogs) detections() siem.DetectionService {
	if s == nil || s.det == nil {
		return nil
	}
	return s.det
}

// detectionReporter is where the app /ops alerts report (nil when detection isn't running).
func (s *securityLogs) detectionReporter() siem.Reporter {
	if s == nil || s.det == nil {
		return nil
	}
	return s.det
}

// feedStatus reports the enrichment feeds (nil when they aren't running).
func (s *securityLogs) feedStatus() siem.FeedStatusSource {
	if s == nil || s.feeds == nil {
		return nil
	}
	return s.feeds
}

// detectMapValue maps a clear value in a detection rule's query to its stored form, as Apply stores
// it: field is "actor" or "f.<key>", and the redactor classifies the full key (its dotted parents
// count, as when the event was stored). A prefix pattern (value*) and an already-hashed value stay.
func detectMapValue(red *redact.Redactor) func(field, value string) string {
	return func(field, value string) string {
		if strings.HasSuffix(value, "*") {
			return value
		}
		switch {
		case field == "actor":
			return red.SearchValue("actor", value)
		case strings.HasPrefix(field, "f."):
			return red.SearchValue(strings.TrimPrefix(field, "f."), value)
		}
		return value
	}
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
