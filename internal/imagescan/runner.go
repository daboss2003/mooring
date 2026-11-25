package imagescan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/serverinfo"
)

// Target is one thing to scan: an image ref (Kind "image", scanned from the
// registry) or a checkout directory (Kind "fs", scanned for language deps).
type Target struct {
	Project string
	Kind    string // "image" | "fs"
	Ref     string // image ref, or the host dir for fs
	Label   string // display label (image ref, or "<app> dependencies")
}

// Target kinds.
const (
	KindImage = "image"
	KindFS    = "fs"
)

// alertSink is the alert dispatch surface (satisfied by *alertstore.Store).
type alertSink interface {
	EnqueueInfra(ctx context.Context, o alert.Outbox) error
}

// scanIface is the scanner surface (satisfied by *Scanner; faked in tests).
type scanIface interface {
	ScanImage(ctx context.Context, ref string) (Report, error)
	ScanFS(ctx context.Context, hostDir, label string) (Report, error)
	ScanHost(ctx context.Context, plan HostPlan) (HostScan, error)
}

// Runner periodically scans the host (when WithHost is set) and every app's targets, and stores +
// alerts on the results.
type Runner struct {
	scanner  scanIface
	store    *Store
	alerts   alertSink                          // may be nil (alerting disabled)
	targets  func(ctx context.Context) []Target // enumerates all apps' targets (injected; nil = no app scans)
	interval time.Duration
	log      *slog.Logger

	alerted map[string]string // project → last-alerted "crit/high" signature (avoid re-paging)

	// Host scan (WithHost).
	hostPlan            func(ctx context.Context) HostPlan
	hostStore           *HostStore
	onOwnedCaddyFixable func(ctx context.Context)
	reboot              func() (bool, []string) // serverinfo.RebootRequired (injected in tests)
	hostAlerted         map[string]bool         // "ID|Package|ReportTarget" of every finding a host_vulnerabilities alert included this process
	rebootAlerted       map[string]bool         // host_reboot_required signatures paged this process
}

// NewRunner builds a Runner. interval floors at 1h in Run.
func NewRunner(scanner scanIface, store *Store, alerts alertSink, targets func(context.Context) []Target, interval time.Duration, log *slog.Logger) *Runner {
	if sc, ok := scanner.(*Scanner); ok && sc != nil && sc.log == nil {
		sc.log = log // the scanner's own warnings (a scan container it could not remove) go to the same log
	}
	return &Runner{
		scanner: scanner, store: store, alerts: alerts, targets: targets, interval: interval, log: log,
		alerted: map[string]string{}, reboot: serverinfo.RebootRequired,
		hostAlerted: map[string]bool{}, rebootAlerted: map[string]bool{},
	}
}

// WithHost turns on the host scan. ScanAll then scans the host FIRST, then the apps (the targets func
// may return nil — image scanning off). onOwnedCaddyFixable (may be nil) is called synchronously when
// the report with Role == RoleOwnedCaddy has ANY finding with a fixed version; the callee returns fast
// (it spawns its own goroutine). Host alerts + the reboot-required alert are raised here.
func (r *Runner) WithHost(plan func(ctx context.Context) HostPlan, store *HostStore, onOwnedCaddyFixable func(ctx context.Context)) *Runner {
	r.hostPlan, r.hostStore, r.onOwnedCaddyFixable = plan, store, onOwnedCaddyFixable
	return r
}

const minInterval = time.Hour

// Run scans a few minutes after boot (so the box settles + the vuln DB warms), then
// every interval, until ctx is done. New CVEs are disclosed daily, so re-scanning
// UNCHANGED images matters — that's why this is scheduled, not only on deploy.
func (r *Runner) Run(ctx context.Context) {
	iv := r.interval
	if iv < minInterval {
		iv = minInterval
	}
	select {
	case <-time.After(2 * time.Minute):
	case <-ctx.Done():
		return
	}
	r.ScanAll(ctx)
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.ScanAll(ctx)
		}
	}
}

// ScanAll scans the host (when WithHost is set), then every app's targets, sequentially (one Trivy
// container at a time — it is heavy) and persists the results.
func (r *Runner) ScanAll(ctx context.Context) {
	if r.hostPlan != nil && r.hostStore != nil {
		r.scanHost(ctx)
	}
	if r.targets == nil || ctx.Err() != nil {
		return
	}
	byProject := map[string][]Target{}
	for _, t := range r.targets(ctx) {
		byProject[t.Project] = append(byProject[t.Project], t)
	}
	for project, tgs := range byProject {
		if ctx.Err() != nil {
			return
		}
		r.scanApp(ctx, project, tgs)
	}
}

// ScanProject scans one app's targets on demand (e.g. after a deploy).
func (r *Runner) ScanProject(ctx context.Context, project string) {
	if r.targets == nil {
		return
	}
	var tgs []Target
	for _, t := range r.targets(ctx) {
		if t.Project == project {
			tgs = append(tgs, t)
		}
	}
	if len(tgs) > 0 {
		r.scanApp(ctx, project, tgs)
	}
}

// appScanFailed is what the Server tab shows next to an app when a target's scan failed for a reason
// that is only safe in the log (the scanner's stderr).
const appScanFailed = "one or more targets could not be scanned"

// appFailure is the Server tab's text for a failed app target, and whether it names the reason: it
// does when the scanner ran but its report could not be used (as hostFailure does for the host).
func appFailure(err error) (string, bool) {
	var oe *outputError
	if errors.As(err, &oe) {
		return appScanFailed + ": " + oe.reason, true
	}
	return appScanFailed, false
}

func (r *Runner) scanApp(ctx context.Context, project string, tgs []Target) {
	a := AppScan{Project: project, ScannedAt: time.Now().Unix()}
	for _, t := range tgs {
		var (
			rep Report
			err error
		)
		switch t.Kind {
		case KindImage:
			rep, err = r.scanner.ScanImage(ctx, t.Ref)
		case KindFS:
			rep, err = r.scanner.ScanFS(ctx, t.Ref, t.Label)
		default:
			continue
		}
		if err != nil {
			text, explicit := appFailure(err)
			if explicit {
				r.log.Warn("imagescan: target failed", "project", project, "target", t.Label, "err", err)
			} else {
				// Intentional: Debug. An image Trivy can't pull (a private registry) fails on
				// every pass, and the cause is the scanner's stderr.
				r.log.Debug("imagescan: target failed", "project", project, "target", t.Label, "err", err)
			}
			// The first reason wins; a reason replaces the text that has none.
			if a.Error == "" || (a.Error == appScanFailed && explicit) {
				a.Error = text
			}
			continue
		}
		a.Critical += rep.Critical
		a.High += rep.High
		a.Medium += rep.Medium
		a.Low += rep.Low
		a.Reports = append(a.Reports, rep)
	}
	if err := r.store.Save(ctx, a); err != nil {
		r.log.Warn("imagescan: save failed", "project", project, "err", err)
	}
	r.maybePage(ctx, a)
}

// maybePage raises a High/Critical alert once per (project, severity-signature) so a
// new or worsened set re-pages but a steady state doesn't spam.
func (r *Runner) maybePage(ctx context.Context, a AppScan) {
	if !a.Actionable() || r.alerts == nil {
		return
	}
	sig := strconv.Itoa(a.Critical) + "/" + strconv.Itoa(a.High)
	if r.alerted[a.Project] == sig {
		return
	}
	r.alerted[a.Project] = sig
	level := alert.LevelWarning
	if a.Critical > 0 {
		level = alert.LevelCritical
	}
	summary := fmt.Sprintf("Vulnerabilities in %s: %d critical, %d high (%d medium, %d low). Review + rebuild/upgrade the affected images.",
		a.Project, a.Critical, a.High, a.Medium, a.Low)
	o := alert.Outbox{
		RuleID:     0,
		Target:     a.Project,
		Kind:       "image_vulnerabilities",
		Level:      level,
		Transition: "firing",
		Summary:    summary,
		DedupeKey:  "imagevuln:" + a.Project + ":" + sig,
	}
	if err := r.alerts.EnqueueInfra(ctx, o); err != nil {
		r.log.Warn("imagescan: could not enqueue vuln alert", "project", a.Project, "err", err)
	}
}
