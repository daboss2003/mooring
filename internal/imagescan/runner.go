package imagescan

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
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
}

// Runner periodically scans every app's targets and stores + alerts on the results.
type Runner struct {
	scanner  scanIface
	store    *Store
	alerts   alertSink                          // may be nil (alerting disabled)
	targets  func(ctx context.Context) []Target // enumerates all apps' targets (injected)
	interval time.Duration
	log      *slog.Logger

	alerted map[string]string // project → last-alerted "crit/high" signature (avoid re-paging)
}

// NewRunner builds a Runner. interval floors at 1h in Run.
func NewRunner(scanner scanIface, store *Store, alerts alertSink, targets func(context.Context) []Target, interval time.Duration, log *slog.Logger) *Runner {
	return &Runner{scanner: scanner, store: store, alerts: alerts, targets: targets, interval: interval, log: log, alerted: map[string]string{}}
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

// ScanAll scans every app's targets sequentially (one Trivy container at a time — it
// is heavy) and persists per-app results.
func (r *Runner) ScanAll(ctx context.Context) {
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
			r.log.Debug("imagescan: target failed", "project", project, "target", t.Label, "err", err)
			if a.Error == "" {
				a.Error = "one or more targets could not be scanned"
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
