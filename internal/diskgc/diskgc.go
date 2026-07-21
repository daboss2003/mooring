// Package diskgc is the disk-pressure auto-reclaim loop. When host disk usage crosses a
// threshold it reclaims DANGLING docker images + build cache — the superseded builds that pile
// up as apps redeploy and are the usual reason a box fills up — and alerts the operator.
//
// It only ever removes GARBAGE: `docker image prune -f` never touches a tagged image or one
// used by a container (running or stopped), and a Mooring rollback rebuilds its image, so this
// can't break a rollback or delete app data. It rides the one-docker-child semaphore via
// TryAcquire (skip-don't-queue), so it never delays a deploy.
package diskgc

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Sampler returns current host disk usage. ok=false means unavailable (skip this tick).
type Sampler func() (used, total uint64, ok bool)

// Pruner runs the reclaim commands under a semaphore the CALLER already holds (satisfied by
// dockerexec.Runner). Both methods are the *Held variants: diskgc.Check holds the one docker
// slot across both prunes, so a non-Held call that re-Acquires the same slot would deadlock.
type Pruner interface {
	PruneImagesHeld(ctx context.Context, onLine func(string)) error
	PruneBuildCacheHeld(ctx context.Context, keep string, onLine func(string)) error
}

// Sem is the one-docker-child gate (satisfied by dockerexec.Semaphore).
type Sem interface {
	TryAcquire() bool
	Release()
}

// Runner is the disk-pressure watcher.
type Runner struct {
	sample       Sampler
	prune        Pruner
	sem          Sem
	threshold    float64 // percent
	interval     time.Duration
	keep         string // build-cache keep size (e.g. "5GB")
	buildCacheGC bool   // honor server.build_cache_keep_enabled (skip the cache prune when off)
	alert        func(level, title, detail string)
	log          *slog.Logger
	lastAlert    time.Time
}

// New builds a Runner. alert may be nil. buildCacheGC=false skips the build-cache prune (honors
// the operator's build_cache_keep_enabled:false opt-out); the dangling-image prune always runs.
func New(sample Sampler, prune Pruner, sem Sem, thresholdPct int, interval time.Duration, keep string, buildCacheGC bool, alert func(level, title, detail string), log *slog.Logger) *Runner {
	return &Runner{sample: sample, prune: prune, sem: sem, threshold: float64(thresholdPct), interval: interval, keep: keep, buildCacheGC: buildCacheGC, alert: alert, log: log}
}

const minInterval = 5 * time.Minute

// Run checks a couple of minutes after boot, then every interval, until ctx is done.
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
	r.Check(ctx)
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.Check(ctx)
		}
	}
}

// Check reclaims if disk usage is at/over the threshold and the docker slot is free. Returns
// true if it ran a prune this call.
func (r *Runner) Check(ctx context.Context) bool {
	used, total, ok := r.sample()
	if !ok || total == 0 {
		return false
	}
	pct := float64(used) / float64(total) * 100
	if pct < r.threshold {
		return false
	}
	if !r.sem.TryAcquire() {
		return false // a deploy/self-heal holds the slot — try next tick (never queue)
	}
	defer r.sem.Release()

	var lines []string
	onLine := func(l string) {
		lines = append(lines, l)
		if r.log != nil {
			r.log.Info("diskgc", "line", l)
		}
	}
	reclaimed := false // did at least one prune actually run (so the alert doesn't falsely claim success)?
	if err := r.prune.PruneImagesHeld(ctx, onLine); err != nil {
		if r.log != nil {
			r.log.Warn("diskgc: image prune", "err", err)
		}
	} else {
		reclaimed = true
	}
	// Honor the operator's build-cache opt-out (server.build_cache_keep_enabled:false); the
	// dangling-image prune above always runs.
	if r.buildCacheGC {
		if err := r.prune.PruneBuildCacheHeld(ctx, r.keep, onLine); err != nil {
			if r.log != nil {
				r.log.Warn("diskgc: build-cache prune", "err", err)
			}
		} else {
			reclaimed = true
		}
	}
	r.notify(pct, lines, reclaimed)
	return true
}

// notify alerts the operator, at most once per 6h (so a persistently-full disk doesn't spam).
// The wording reflects whether reclamation actually ran — it never falsely claims success (e.g.
// when the write plane is disabled and both prunes no-op).
func (r *Runner) notify(pct float64, lines []string, reclaimed bool) {
	if r.alert == nil {
		return
	}
	now := time.Now()
	if !r.lastAlert.IsZero() && now.Sub(r.lastAlert) < 6*time.Hour {
		return
	}
	r.lastAlert = now
	var detail string
	if reclaimed {
		detail = fmt.Sprintf("Disk reached %.0f%%. Reclaimed dangling docker images%s. %sIf disk stays high, the cause is app data or logs, not old deploys.",
			pct, buildCacheNote(r.buildCacheGC), reclaimedLine(lines))
		r.alert("warning", "Disk pressure — reclaimed docker garbage", detail)
		return
	}
	detail = fmt.Sprintf("Disk reached %.0f%%, but automatic reclaim could not run (the write plane may be disabled or docker unreachable). Free space manually if it stays high.", pct)
	r.alert("warning", "Disk pressure — reclaim unavailable", detail)
}

func buildCacheNote(on bool) string {
	if on {
		return " + build cache"
	}
	return ""
}

// reclaimedLine pulls docker's "Total reclaimed space: …" line (if any) for the alert body.
func reclaimedLine(lines []string) string {
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(lines[i], "reclaimed space") {
			return strings.TrimSpace(lines[i]) + ". "
		}
	}
	return ""
}
