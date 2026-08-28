package imageupdate

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/dockerexec"
)

// Target is one pull-image service to check.
type Target struct {
	Project string
	Service string
	Ref     string // the pinned image ref from mooring.yaml (e.g. "postgres:16")
}

// alertSink is the alert dispatch surface (satisfied by *alertstore.Store; faked in tests).
type alertSink interface {
	EnqueueInfra(ctx context.Context, o alert.Outbox) error
}

// Runner periodically resolves each pull-image service's local vs registry digest, stores the
// result, and alerts once per newly-available digest. It is modeled on imagescan.Runner (boot
// delay → ticker) but does NOT gate on dashboard activity: the operator wants to be told an update
// is available even with the tab closed, like vulnerability scanning.
type Runner struct {
	exec     digestExec
	store    *Store
	alerts   alertSink                          // may be nil (alerting disabled)
	targets  func(ctx context.Context) []Target // enumerates all apps' pull-image services (injected)
	interval time.Duration
	log      *slog.Logger

	now     func() int64      // injectable clock (tests)
	alerted map[string]string // "project/service" → last-alerted latest digest (avoid re-paging a known update)
}

// NewRunner builds a Runner. interval floors at 1h in Run.
func NewRunner(exec digestExec, store *Store, alerts alertSink, targets func(context.Context) []Target, interval time.Duration, log *slog.Logger) *Runner {
	return &Runner{
		exec: exec, store: store, alerts: alerts, targets: targets, interval: interval, log: log,
		now: func() int64 { return time.Now().Unix() }, alerted: map[string]string{},
	}
}

const (
	minInterval  = time.Hour
	bootDelay    = 3 * time.Minute  // let the box settle before the first registry round-trips
	perCheckWait = 25 * time.Second // per-call ceiling (a slow/unreachable registry can't hang the loop)
)

// Run checks a few minutes after boot, then every interval, until ctx is done. Registry tags move
// slowly and Docker Hub rate-limits anonymous pulls, so the cadence is hours (default 24h), never
// the git poller's minutes.
func (r *Runner) Run(ctx context.Context) {
	iv := r.interval
	if iv < minInterval {
		iv = minInterval
	}
	select {
	case <-time.After(bootDelay):
	case <-ctx.Done():
		return
	}
	r.CheckAll(ctx)
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.CheckAll(ctx)
		}
	}
}

// CheckAll resolves every pull-image service once, sequentially (each digest read rides the
// one-docker-child slot via TryAcquire), then prunes rows for services that no longer exist.
func (r *Runner) CheckAll(ctx context.Context) {
	for _, t := range r.targets(ctx) {
		if ctx.Err() != nil {
			return
		}
		if isDigestPinned(t.Ref) {
			continue // a digest-pinned ref can't move
		}
		r.checkTarget(ctx, t)
	}
	if ctx.Err() != nil {
		return
	}
	// Prune rows for services no longer present, from a FRESH enumeration — NOT the set captured at the
	// top of this pass. An app torn down DURING the (potentially minutes-long) check loop is then absent
	// here, so its rows — including any a mid-pass check re-inserted just before the teardown's own
	// delete — are pruned THIS pass rather than lingering until the next one (up to a full interval).
	live := map[string]map[string]bool{}
	for _, t := range r.targets(ctx) {
		if isDigestPinned(t.Ref) {
			continue
		}
		if live[t.Project] == nil {
			live[t.Project] = map[string]bool{}
		}
		live[t.Project][t.Service] = true
	}
	if err := r.store.PruneExcept(ctx, live); err != nil {
		r.log.Debug("imageupdate: prune failed", "err", err)
	}
}

// checkTarget resolves one service's registry + local digest and persists the outcome. A held
// docker slot (a deploy in progress) or a disarmed write plane makes the check SKIP this tick (no
// store write) rather than queue behind the deploy — trying again next cycle is always fine for an
// advisory check.
func (r *Runner) checkTarget(ctx context.Context, t Target) {
	lctx, lcancel := context.WithTimeout(ctx, perCheckWait)
	latest, lerr := latestDigest(lctx, r.exec, t.Ref)
	lcancel()
	if skip(lerr) {
		return
	}
	dctx, dcancel := context.WithTimeout(ctx, perCheckWait)
	deployed, derr := deployedDigest(dctx, r.exec, t.Ref)
	dcancel()
	if skip(derr) {
		return
	}

	row := Row{Project: t.Project, Service: t.Service, ImageRef: t.Ref, CheckedAt: r.now()}
	if lerr != nil {
		// Registry unreachable / auth / no buildx — record it, never alert on a failed check.
		row.Error = "could not check the registry for this image"
		r.log.Debug("imageupdate: registry check failed", "project", t.Project, "service", t.Service, "err", lerr)
	} else {
		row.LatestDigest = latest
	}
	if derr == nil {
		row.DeployedDigest = deployed
	}
	row.UpdateAvailable = row.LatestDigest != "" && row.DeployedDigest != "" && row.LatestDigest != row.DeployedDigest

	if err := r.store.Save(ctx, row); err != nil {
		r.log.Warn("imageupdate: save failed", "project", t.Project, "service", t.Service, "err", err)
	}
	if row.UpdateAvailable {
		r.maybePage(ctx, row)
	}
}

// skip reports whether a resolve error means "the write plane is busy/disabled" — in which case we
// silently skip the target this tick rather than recording a spurious failure.
func skip(err error) bool {
	return errors.Is(err, dockerexec.ErrBusy) || errors.Is(err, dockerexec.ErrWritePlaneDisabled)
}

// maybePage raises one alert per (service, latest-digest) so a NEW update re-pages but a steady
// "update available" state doesn't spam every cycle. On restart the in-memory map is empty, so a
// known-pending update pages once more — acceptable, matching imagescan.
func (r *Runner) maybePage(ctx context.Context, row Row) {
	if r.alerts == nil {
		return
	}
	k := row.Project + "/" + row.Service
	if r.alerted[k] == row.LatestDigest {
		return
	}
	o := alert.Outbox{
		Target:     row.Project + "/" + row.Service,
		Kind:       "image_update_available",
		Level:      alert.LevelWarning,
		Transition: "firing",
		Summary: "A newer image is available for " + row.Service + " in " + row.Project +
			" (" + row.ImageRef + ") — redeploy to pull it.",
		DedupeKey: "imgupdate:" + row.Project + ":" + row.Service + ":" + row.LatestDigest,
	}
	if err := r.alerts.EnqueueInfra(ctx, o); err != nil {
		// Record the dedup key ONLY on success, so a transient enqueue error is retried next cycle
		// instead of permanently suppressing this update's alert.
		r.log.Warn("imageupdate: could not enqueue update alert", "project", row.Project, "service", row.Service, "err", err)
		return
	}
	r.alerted[k] = row.LatestDigest
}
