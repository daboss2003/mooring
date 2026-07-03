package updatecheck

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/github"
)

// ghAPI is the slice of the GitHub client the checker needs (unauthenticated).
type ghAPI interface {
	LatestRelease(ctx context.Context, owner, repo string) (github.Release, error)
	SecurityAdvisories(ctx context.Context, owner, repo string) ([]github.Advisory, error)
}

// alertSink is the alert dispatch surface (satisfied by *alertstore.Store); nil-safe
// at the call site so alerting-disabled installs still get the banner.
type alertSink interface {
	EnqueueInfra(ctx context.Context, o alert.Outbox) error
}

// State is the current update posture the dashboard banner renders. Held in an
// atomic pointer and read (cheaply) on every page render.
type State struct {
	Checked         bool
	At              time.Time
	RunningVersion  string
	LatestVersion   string
	LatestURL       string
	UpdateAvailable bool
	Advisory        *AdvisoryState // non-nil ⇒ the RUNNING version is vulnerable — update now
	LastError       string
}

// AdvisoryState describes the published security advisory affecting the running version.
type AdvisoryState struct {
	GHSAID   string
	Severity string
	Summary  string
	URL      string
	Patched  string
}

// Checker periodically asks GitHub whether a newer Mooring exists and whether the
// running version is affected by a published security advisory.
type Checker struct {
	gh       ghAPI
	owner    string
	repo     string
	version  string
	interval time.Duration
	alerts   alertSink // may be nil (alerting disabled) — guarded before use
	log      *slog.Logger

	snap    atomic.Pointer[State]
	alerted map[string]bool // GHSA ids already paged this process (avoid re-paging every tick)
}

// New builds a Checker. interval is clamped to a sane floor by Run.
func New(gh ghAPI, owner, repo, version string, interval time.Duration, alerts alertSink, log *slog.Logger) *Checker {
	return &Checker{gh: gh, owner: owner, repo: repo, version: version, interval: interval, alerts: alerts, log: log, alerted: map[string]bool{}}
}

// State returns the latest computed posture (nil until the first check completes).
func (c *Checker) State() *State { return c.snap.Load() }

const minInterval = time.Hour

// Run does one check shortly after boot, then every interval, until ctx is done.
// The check runs UNCONDITIONALLY (unlike the git poller) — security state must
// update even when no operator is watching the dashboard.
func (c *Checker) Run(ctx context.Context) {
	iv := c.interval
	if iv < minInterval {
		iv = minInterval
	}
	// A short delay after boot so a fresh start surfaces state without a network call
	// on the hot path; ctx-cancellable so shutdown isn't blocked.
	select {
	case <-time.After(30 * time.Second):
	case <-ctx.Done():
		return
	}
	c.checkOnce(ctx)
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.checkOnce(ctx)
		}
	}
}

// checkOnce fetches the latest release + published advisories and recomputes state.
// A non-release running version ("dev", unparseable) skips the network entirely — a
// dev build has no meaningful "newer release" or advisory match.
func (c *Checker) checkOnce(parent context.Context) {
	st := &State{RunningVersion: c.version, At: time.Now()}
	if _, ok := parseSemver(c.version); !ok {
		st.Checked = true
		c.snap.Store(st)
		return
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()

	if rel, err := c.gh.LatestRelease(ctx, c.owner, c.repo); err != nil {
		st.LastError = "could not check for updates"
		c.log.Debug("updatecheck: latest release", "err", err)
	} else if !rel.Draft && !rel.Prerelease && newer(c.version, rel.TagName) {
		st.UpdateAvailable = true
		st.LatestVersion = rel.TagName
		st.LatestURL = rel.HTMLURL
	}

	if advs, err := c.gh.SecurityAdvisories(ctx, c.owner, c.repo); err != nil {
		c.log.Debug("updatecheck: security advisories", "err", err)
	} else if a := c.affectedAdvisory(advs); a != nil {
		st.Advisory = a
	}

	st.Checked = true
	c.snap.Store(st)

	// Page (critical) once per GHSA per process — the DB also dedupes un-sent rows.
	if st.Advisory != nil && c.alerts != nil && !c.alerted[st.Advisory.GHSAID] {
		c.alerted[st.Advisory.GHSAID] = true
		c.page(parent, st.Advisory)
	}
}

// affectedAdvisory returns the highest-severity published advisory whose version
// range covers the running version (fail-safe: an unparseable range counts as
// affected). nil when none apply.
func (c *Checker) affectedAdvisory(advs []github.Advisory) *AdvisoryState {
	running, _ := parseSemver(c.version) // parseable (checkOnce guards)
	var best *AdvisoryState
	for _, a := range advs {
		hit := false
		patched := ""
		for _, v := range a.Vulnerabilities {
			aff, ok := affectedByRange(running, v.VulnerableVersionRange)
			if aff || !ok { // in range, OR unparseable → fail safe
				hit = true
				if v.PatchedVersions != "" {
					patched = v.PatchedVersions
				}
			}
		}
		if !hit {
			continue
		}
		cand := &AdvisoryState{GHSAID: a.GHSAID, Severity: a.Severity, Summary: a.Summary, URL: a.HTMLURL, Patched: patched}
		if best == nil || severityRank(cand.Severity) > severityRank(best.Severity) {
			best = cand
		}
	}
	return best
}

func (c *Checker) page(ctx context.Context, a *AdvisoryState) {
	patched := a.Patched
	if patched == "" {
		patched = "the latest release"
	}
	summary := fmt.Sprintf("SECURITY: your Mooring %s is affected by %s (%s): %s. Update to %s immediately.",
		c.version, a.GHSAID, a.Severity, a.Summary, patched)
	o := alert.Outbox{
		RuleID:     0,
		Target:     "mooring",
		Kind:       "security_update_available",
		Level:      alert.LevelCritical, // always pages, bypasses quiet hours
		Transition: "firing",
		Summary:    summary,
		DedupeKey:  "mooring:advisory:" + a.GHSAID,
	}
	if err := c.alerts.EnqueueInfra(ctx, o); err != nil {
		c.log.Warn("updatecheck: could not enqueue security alert", "err", err)
	}
}

// severityRank orders advisory severities so the worst wins.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
