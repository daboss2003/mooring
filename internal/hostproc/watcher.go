package hostproc

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
)

// Alert kinds the Watcher raises (level warning).
const (
	KindRestarted = "edge_child_restarted" // a stale child was restarted on the updated files
	KindStale     = "edge_child_stale"     // a stale child was left running (check failed, or restarted too recently)
)

const (
	validateTimeout = 30 * time.Second
	alertTimeout    = 10 * time.Second
	maxListed       = 3    // replaced files named in an alert
	maxErrText      = 1000 // characters of a check failure quoted in an alert (Caddy's module error chains run ~500)
)

// AlertSink receives the Watcher's alerts (the alert store).
type AlertSink interface {
	EnqueueInfra(ctx context.Context, o alert.Outbox) error
}

// Child is one supervised process the Watcher keeps on current files.
type Child struct {
	Name     string // display: "Caddy", "L4 nginx"
	Target   string // alert target: "caddy", "nginx-l4"
	PID      func() int
	Validate func(ctx context.Context) error // the updated files start cleanly; nil = no check
	Restart  func()
}

// Watcher restarts a supervised child that still runs files a package upgrade replaced, once the
// replaced set has stopped changing and the updated files pass the child's check, at most once per
// MinGap per child, and alerts. A child whose updated files fail the check keeps running on the old
// ones (with an alert) and is checked again on the next tick.
type Watcher struct {
	Children []Child
	Alerts   AlertSink // nil = log only
	Log      *slog.Logger
	Interval time.Duration // 0 = 1m
	Settle   time.Duration // 0 = 2m: the same stale set, seen continuously this long, before a restart
	MinGap   time.Duration // 0 = 30m: at most one automatic restart per child in this window

	stale func(pid int) ([]string, error) // nil = Stale
	now   func() time.Time                // nil = time.Now
	st    []childState                    // per Children index; used only from Run's goroutine
}

// childState tracks one child. Everything but lastRestart is about the current pid and is reset when
// the pid changes.
type childState struct {
	pid         int
	files       []string        // the replaced files seen at the last check
	since       time.Time       // when files was first seen (unchanged since)
	restarted   bool            // this pid was restarted by the Watcher: it is on its way out
	notified    map[string]bool // the reasons (reasonRecent, reasonCheck) a stale alert was sent for this pid
	readErr     bool            // a /proc read error for this pid was logged
	lastRestart time.Time       // the child's last automatic restart, across pids
}

// Why a stale child was left running; one alert per pid and reason.
const (
	reasonRecent = "recent" // restarted within MinGap
	reasonCheck  = "check"  // the updated files fail Validate
)

func (w *Watcher) interval() time.Duration { return orDefault(w.Interval, time.Minute) }
func (w *Watcher) settle() time.Duration   { return orDefault(w.Settle, 2*time.Minute) }
func (w *Watcher) minGap() time.Duration   { return orDefault(w.MinGap, 30*time.Minute) }

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

func (w *Watcher) log() *slog.Logger {
	if w.Log != nil {
		return w.Log
	}
	return slog.Default()
}

func (w *Watcher) clock() time.Time {
	if w.now != nil {
		return w.now()
	}
	return time.Now()
}

func (w *Watcher) staleFiles(pid int) ([]string, error) {
	if w.stale != nil {
		return w.stale(pid)
	}
	return Stale(pid)
}

// Run checks the children every Interval until ctx ends.
func (w *Watcher) Run(ctx context.Context) {
	t := time.NewTicker(w.interval())
	defer t.Stop()
	for {
		w.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (w *Watcher) tick(ctx context.Context) {
	if len(w.st) != len(w.Children) {
		w.st = make([]childState, len(w.Children))
	}
	for i := range w.Children {
		if ctx.Err() != nil {
			return
		}
		w.check(ctx, &w.Children[i], &w.st[i])
	}
}

func (w *Watcher) check(ctx context.Context, c *Child, st *childState) {
	pid := 0
	if c.PID != nil {
		pid = c.PID()
	}
	if pid != st.pid {
		*st = childState{pid: pid, lastRestart: st.lastRestart}
	}
	if pid == 0 || st.restarted {
		return
	}
	files, err := w.staleFiles(pid)
	if err != nil {
		// Intentional: a process that just exited has no /proc entry — not stale, nothing to report.
		// Anything else (no permission) is logged once, so a watcher that can't see is not silent.
		if !errors.Is(err, fs.ErrNotExist) && !st.readErr {
			st.readErr = true
			w.log().Warn("hostproc: can't read which files the "+c.Name+" process runs; it is not restarted after package upgrades",
				"pid", pid, "err", err.Error())
		}
		st.files, st.since = nil, time.Time{}
		return
	}
	if len(files) == 0 {
		st.files, st.since = nil, time.Time{}
		return
	}
	now := w.clock()
	if !slices.Equal(files, st.files) {
		// New, or more files replaced: the upgrade may still be running. Wait until it has settled.
		st.files, st.since = files, now
		w.log().Info("hostproc: "+c.Name+" runs files a package upgrade replaced; restarting it once they have settled",
			"pid", pid, "files", strings.Join(files, ","), "settle", w.settle().String())
		return
	}
	if now.Sub(st.since) < w.settle() {
		return
	}
	// The check runs before the MinGap gate: the "recent" alert advises restarting Mooring now, which is
	// only sound for files that pass it.
	if c.Validate != nil {
		vctx, cancel := context.WithTimeout(ctx, validateTimeout)
		verr := c.Validate(vctx)
		cancel()
		if ctx.Err() != nil {
			return // shutting down: not a failed check
		}
		if verr != nil {
			// No "restart Mooring" advice here: the relaunch would fail the same way and leave the child down.
			what := "the updated files fail the start check (" + oneLine(verr.Error(), maxErrText) + "), so the old process keeps running; restarting Mooring would not start it either. Fix what the check reports (for an interrupted upgrade, `sudo dpkg --configure -a`) and run `sudo mooring doctor`; Mooring restarts it once the check passes."
			// A check that holds the restart back for a reason other than the updated files (serve's Caddy
			// check while Caddy refuses the edge config) says what to do itself: the child would start.
			var held interface{ StaleAdvice() string }
			if errors.As(verr, &held) {
				what = "the restart is held back (" + oneLine(verr.Error(), maxErrText) + "), so the old process keeps running. " + held.StaleAdvice()
			}
			w.notifyStale(ctx, c, st, reasonCheck, what, "check failed: "+verr.Error())
			return
		}
	}
	if !st.lastRestart.IsZero() && now.Sub(st.lastRestart) < w.minGap() {
		what := fmt.Sprintf("Mooring already restarted it in the last %s, so it restarts it again after that. To restart it now, run `sudo systemctl restart mooring`.",
			humanDuration(w.minGap()))
		if c.Validate != nil {
			what = "the updated files pass the start check, but " + what
		}
		w.notifyStale(ctx, c, st, reasonRecent, what, "restarted recently")
		return
	}
	st.lastRestart, st.restarted = now, true
	w.log().Warn("hostproc: "+c.Name+" runs files a package upgrade replaced; restarting it on the updated files",
		"pid", pid, "files", strings.Join(files, ","))
	if c.Restart != nil {
		c.Restart()
	}
	w.alert(ctx, alert.Outbox{
		Target: c.Target, Kind: KindRestarted, Level: "warning", Transition: "firing",
		Summary: fmt.Sprintf("Mooring restarted %s (pid %d) on updated files: a package upgrade replaced %s while it ran. Run `sudo mooring doctor` to check the server.",
			c.Name, pid, listFiles(files)),
		DedupeKey: "stalerestart:" + c.Target + ":" + strconv.Itoa(pid),
	})
}

// notifyStale logs and alerts, once per pid and reason, that a stale child was left running: what
// happened is a sentence for the alert, why a short reason for the log. The reason is in the dedupe
// key, so the alert store never folds one reason's alert into the other's.
func (w *Watcher) notifyStale(ctx context.Context, c *Child, st *childState, reason, what, why string) {
	if st.notified[reason] {
		return
	}
	if st.notified == nil {
		st.notified = map[string]bool{}
	}
	st.notified[reason] = true
	w.log().Warn("hostproc: "+c.Name+" runs files a package upgrade replaced; not restarting it",
		"pid", st.pid, "files", strings.Join(st.files, ","), "reason", why)
	w.alert(ctx, alert.Outbox{
		Target: c.Target, Kind: KindStale, Level: "warning", Transition: "firing",
		Summary: fmt.Sprintf("%s (pid %d) still runs files a package upgrade replaced (%s) and was not restarted: %s",
			c.Name, st.pid, listFiles(st.files), what),
		DedupeKey: "stale:" + c.Target + ":" + strconv.Itoa(st.pid) + ":" + reason,
	})
}

// alert enqueues o on a bounded context: a slow or failing alert store never holds the watcher.
func (w *Watcher) alert(ctx context.Context, o alert.Outbox) {
	if w.Alerts == nil {
		return
	}
	actx, cancel := context.WithTimeout(ctx, alertTimeout)
	defer cancel()
	if err := w.Alerts.EnqueueInfra(actx, o); err != nil {
		w.log().Warn("hostproc: can't record the alert", "kind", o.Kind, "err", err.Error())
	}
}

// listFiles names up to maxListed files: "/a, /b, /c and 2 more".
func listFiles(files []string) string {
	if len(files) <= maxListed {
		return strings.Join(files, ", ")
	}
	return strings.Join(files[:maxListed], ", ") + " and " + strconv.Itoa(len(files)-maxListed) + " more"
}

// oneLine folds s onto one line and bounds it to n characters.
func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		s = string(r[:n]) + "…"
	}
	return s
}

// humanDuration prints d for a person: "30 minutes", "1 hour", else d's Go form.
func humanDuration(d time.Duration) string {
	unit := func(n int64, one string) string {
		if n == 1 {
			return "1 " + one
		}
		return strconv.FormatInt(n, 10) + " " + one + "s"
	}
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		return unit(int64(d/time.Hour), "hour")
	case d >= time.Minute && d%time.Minute == 0:
		return unit(int64(d/time.Minute), "minute")
	}
	return d.String()
}
