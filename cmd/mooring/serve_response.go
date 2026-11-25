package main

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"sync/atomic"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/alertstore"
	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/blocklist"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/edge"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/detect"
	"github.com/daboss2003/mooring/internal/siem/respond"
	"github.com/daboss2003/mooring/internal/store"
	"github.com/daboss2003/mooring/internal/web"
)

// ownedCaddyDir is the data dir the Mooring-owned Caddy build is resolved from, or "" when it must
// not be used. Intentional: when Mooring itself runs as root (unsupported — the shipped unit runs it
// as `mooring`), the owned build is OFF everywhere (resolve, check, install): it lives in data_dir,
// which a non-root account may control, so launching it as root would hand root to that account.
func ownedCaddyDir(cfg *config.Config) string {
	if os.Geteuid() == 0 {
		return ""
	}
	return cfg.DataDir
}

// edgeOwnedOnHost reports whether Mooring runs the edge here: managed mode and a caddy to run.
func edgeOwnedOnHost(cfg *config.Config) bool {
	if cfg.Edge.Mode != config.EdgeManaged {
		return false
	}
	ok, _ := edge.Available(edge.ResolveCaddy(ownedCaddyDir(cfg)))
	return ok
}

// lateBound connects the block list and the responder — opened before the security logs, so the
// detection engine gets the responder and its last requests are taken at shutdown — to what is
// created after them: the pipeline and the engine (events, incident timelines), the dashboard (the
// live allowlist, API tokens' CIDRs, sessions) and the edge's 0-RTT refusal.
type lateBound struct {
	secLogs atomic.Pointer[securityLogs]
	web     atomic.Pointer[web.Server]
	// refuse0RTT: the edge render refuses QUIC 0-RTT (set once the edge block has read the running
	// Caddy's version); why says why not.
	refuse0RTT atomic.Bool
	why0RTT    atomic.Pointer[string]
}

func (l *lateBound) emit(e siem.Event) bool {
	if s := l.secLogs.Load(); s != nil {
		return s.emit(e)
	}
	return false
}

func (l *lateBound) timeline(ctx context.Context, id int64, ev siem.IncidentEvent) error {
	if s := l.secLogs.Load(); s != nil {
		return s.noteResponse(ctx, id, ev)
	}
	return nil
}

// caddyOK is blocklist.Options.CaddyOK: automatic blocks need an edge whose QUIC 0-RTT is refused
// (Caddy ≥ 2.11), so a spoofed early-data address can't make Mooring block someone else.
func (l *lateBound) caddyOK() (bool, string) {
	if l.refuse0RTT.Load() {
		return true, ""
	}
	if w := l.why0RTT.Load(); w != nil {
		return false, *w
	}
	return false, "the edge hasn't started"
}

// set0RTT records, once the edge block has decided it, whether the edge refuses QUIC 0-RTT. When it
// doesn't because automated response is off (the edge is told to refuse 0-RTT only for it or for
// trusted proxies), that is the reason; with it on, the running Caddy's version is, recorded before.
func (l *lateBound) set0RTT(refuse bool, mode string) {
	if !refuse && mode == siem.ResponseModeOff {
		why := "the edge doesn't refuse QUIC 0-RTT while automated response is off (security_logs.response.mode)"
		l.why0RTT.Store(&why)
	}
	l.refuse0RTT.Store(refuse)
}

// noEdge records that Mooring runs no edge on this host, as the reason automatic blocks are refused.
func (l *lateBound) noEdge(reason string) {
	why := "Mooring doesn't run the edge on this host: " + reason
	l.why0RTT.Store(&why)
	l.refuse0RTT.Store(false)
}

// l4BlockState is what blocklist.Blocker.SetL4 is told: whether an L4 load balancer takes the block
// list (runs: its reconciler exists) and, when none does, why (unavailable: l4.Available's reason).
func l4BlockState(cfg *config.Config, runs bool, unavailable string) (on bool, why string) {
	switch {
	case runs:
		return true, ""
	case cfg.Edge.Mode != config.EdgeManaged:
		return false, "Mooring doesn't run the edge (edge.mode external), so it runs no L4 load balancer"
	case !cfg.Edge.L4Enabled:
		return false, "edge.l4_enabled is off"
	}
	return false, "the L4 load balancer doesn't run on this host: " + unavailable
}

// blockGuard is the never-block set's inputs: until the dashboard is up, config.yaml's allowlist
// and no tokens or sessions. The block list's Open runs before the dashboard exists and publishes
// the stored blocks then (the edge's first render and the L4 initial reconcile serve them), so it
// keeps every block that was suspended when last saved suspended until its Run — started after
// late.web is set — re-checks them against the full set.
func blockGuard(cfg *config.Config, l *lateBound, log *slog.Logger) blocklist.Guard {
	static := cfg.Allowlist()
	var proxies []netip.Prefix
	for _, e := range cfg.Edge.TrustedProxies {
		ps, err := edge.ParseTrustedProxy(e)
		if err != nil {
			log.Warn("edge block list: an edge.trusted_proxies entry wasn't read", "entry", e, "err", err)
			continue
		}
		proxies = append(proxies, ps...)
	}
	proxies = append(proxies, cfg.TrustedProxyPrefixes()...)
	return blocklist.Guard{
		Allowlist: func() []netip.Prefix {
			if w := l.web.Load(); w != nil {
				return w.GuardAllowlist()
			}
			return static
		},
		TokenCIDRs: func() []netip.Prefix {
			if w := l.web.Load(); w != nil {
				return w.GuardTokenCIDRs()
			}
			return nil
		},
		Proxies:    proxies,
		CDN:        edge.CDNRanges(),
		Configured: cfg.SecurityLogs.Blocking.NeverBlockPrefixes(),
		Sessions: func(ctx context.Context) []netip.Addr {
			if w := l.web.Load(); w != nil {
				return w.SessionPeers(ctx)
			}
			return nil
		},
	}
}

// openBlocker opens the edge block list (security logs on or off). nil when it can't be read: Mooring
// runs without blocks, and an alert says so.
func openBlocker(ctx context.Context, cfg *config.Config, db *store.DB, alerts *alertstore.Store, l *lateBound, log *slog.Logger) *blocklist.Blocker {
	b, err := blocklist.Open(ctx, blocklist.Options{
		DB: db, Guard: blockGuard(cfg, l, log), EdgeOwned: edgeOwnedOnHost(cfg), CaddyOK: l.caddyOK,
		MaxAuto:           cfg.SecurityLogs.Blocking.MaxEntriesOrDefault(),
		MaxAutoDuration:   cfg.SecurityLogs.Response.MaxBlockDurationOrDefault(),
		ManualMaxDuration: cfg.SecurityLogs.Blocking.ManualMaxDurationOrDefault(),
		L4:                cfg.SecurityLogs.Blocking.L4,
		Alerter:           alerts,
		Emit:              l.emit,
		Log:               log.With("component", "blocklist"),
	})
	if err != nil {
		log.Error("edge block list: not read; the edge runs without blocks", "err", err)
		if alerts != nil {
			_ = alerts.EnqueueInfra(context.Background(), alert.Outbox{Target: "blocklist", Kind: "security_blocking",
				Level: alert.LevelWarning, Transition: "firing", DedupeKey: "blocklist:open",
				Summary: "The edge block list couldn't be read, so no address is blocked: " + err.Error() + ". Fix the cause, then restart Mooring."})
		}
		return nil
	}
	resolveOpenAlert(alerts, "security_blocking", "blocklist:open", "blocklist", "The edge block list is read again.")
	return b
}

// resolveOpenAlert sends the "resolved" of a start-up alert (kind, dedupe key) when that alert is
// still open from an earlier start: the start that works closes it.
func resolveOpenAlert(alerts *alertstore.Store, kind, dedupe, target, summary string) {
	if alerts == nil {
		return
	}
	open, err := alerts.OpenInfraAlerts(context.Background(), kind)
	if err != nil {
		return
	}
	if _, ok := open[dedupe]; !ok {
		return
	}
	_ = alerts.EnqueueInfra(context.Background(), alert.Outbox{Target: target, Kind: kind, Level: alert.LevelWarning,
		Transition: "resolved", Summary: summary, DedupeKey: dedupe})
}

// blockService is b as a blocklist.Service: an untyped nil for a nil b.
func blockService(b *blocklist.Blocker) blocklist.Service {
	if b == nil {
		return nil
	}
	return b
}

// openResponder opens automated response (its history is kept with security logs on or off). nil
// when it can't start: no response is made, and an alert says so.
func openResponder(ctx context.Context, cfg *config.Config, db *store.DB, alerts *alertstore.Store, blocks blocklist.Service,
	auditLog *audit.Logger, l *lateBound, log *slog.Logger) *respond.Responder {
	var al respond.Alerter
	if alerts != nil {
		al = alerts
	}
	var aud func(context.Context, audit.Event) error
	if auditLog != nil {
		aud = auditLog.Log
	}
	r, err := respond.Open(ctx, respond.Options{
		DB: db, Mode: cfg.SecurityResponseMode(),
		MaxBlocksPerHour:  cfg.SecurityLogs.Response.MaxBlocksPerHourOrDefault(),
		MaxRevokesPerHour: cfg.SecurityLogs.Response.MaxRevokesPerHourOrDefault(),
		ManualMaxDuration: cfg.SecurityLogs.Blocking.ManualMaxDurationOrDefault(),
		Blocks:            blocks, Timeline: l.timeline, Alerter: al, Audit: aud, Emit: l.emit,
		Log: log.With("component", "respond"),
	})
	if err != nil {
		log.Error("automated response: didn't start; detections are recorded, nothing is blocked or signed out", "err", err)
		if alerts != nil {
			_ = alerts.EnqueueInfra(context.Background(), alert.Outbox{Target: "respond", Kind: respond.AlertKind,
				Level: alert.LevelWarning, Transition: "firing", DedupeKey: "respond:open",
				Summary: "Automated response didn't start, so nothing is blocked or signed out automatically: " + err.Error() + ". Fix the cause, then restart Mooring."})
		}
		return nil
	}
	resolveOpenAlert(alerts, respond.AlertKind, "respond:open", "respond", "Automated response is running again.")
	return r
}

// withResponder hands the detection engine the responder when automated response is on.
func withResponder(cfg *config.Config, r *respond.Responder) []func(*detect.Options) {
	if r == nil || cfg.SecurityResponseMode() == siem.ResponseModeOff {
		return nil
	}
	return []func(*detect.Options){func(o *detect.Options) { o.Responder = r }}
}

// responseService is r as a siem.ResponseService: an untyped nil for a nil r.
func responseService(r *respond.Responder) siem.ResponseService {
	if r == nil {
		return nil
	}
	return r
}

// blockApply is the block list's apply: the edge and L4 take the current snapshot.
func blockApply(edgeRecon *edge.Reconciler, l4Reconcile func(context.Context) error, l4DenyErr func() string) func(context.Context) error {
	return func(ctx context.Context) error {
		var errs []error
		if edgeRecon != nil {
			errs = append(errs, edgeRecon.Reconcile(ctx))
		}
		if l4Reconcile != nil {
			errs = append(errs, l4Reconcile(ctx))
			if l4DenyErr != nil {
				if why := l4DenyErr(); why != "" {
					errs = append(errs, errors.New("L4: nginx refused the deny list, so L4 listeners don't refuse blocked addresses: "+why))
				}
			}
		}
		return errors.Join(errs...)
	}
}
