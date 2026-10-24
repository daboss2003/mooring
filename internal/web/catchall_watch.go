package web

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/edge"
)

// A namespace catch-all (`*.<apex>`) is served ONLY by the namespace's DNS-01 wildcard certificate, and
// that needs the namespace's Caddy DNS provider plugin. These checks keep a catch-all from going dark
// silently: a deploy that would ADD one while its plugin is known to be missing is refused, a deploy that
// keeps an existing one goes ahead with a warning, and a background watch raises a CRITICAL alert (and the
// Edge page a banner) while a stored catch-all serves no certificate.

const (
	catchAllDarkKind   = "edge_catchall_dark"
	catchAllFirstCheck = time.Minute
	catchAllCheckEvery = 2 * time.Minute
	// catchAllProbeFailures failed probes in a row (about 6 minutes at catchAllCheckEvery) mark a catch-all
	// dark while its plugin is installed: longer than a normal DNS-01 issuance.
	catchAllProbeFailures = 3
	// catchAllProbeAddr is the managed edge's HTTPS listener (Caddy listens on :443).
	catchAllProbeAddr = "127.0.0.1:443"
)

func catchAllAlertKey(apex string) string { return "catchall:" + apex }

// wildcardOffCause says why apex's wildcard certificate is known to be off: Caddy refused the namespace's
// DNS-01 config, or its DNS plugin (provider) is known to be unavailable (an install failed, the provider
// is unknown, the running binary's modules can't be read, …). "" while it may still come up (the plugin's
// first install is running). nil plugin state knows of nothing.
func (s *Server) wildcardOffCause(apex, provider string) string {
	if rejected, why := s.edgeDNSPlugins.NamespaceRejected(apex); rejected {
		return "Caddy refused the namespace's DNS-01 config: " + deployText(why, 500)
	}
	if missing, why := s.edgeDNSPlugins.KnownMissing(provider); missing {
		return "the DNS plugin for " + provider + " isn't available: " + deployText(why, 500)
	}
	return ""
}

// catchAllPluginGate applies "refuse new, warn existing" to the catch-all on apex, whose namespace issues
// its wildcard through provider; existing reports whether the app already has this catch-all stored. A NEW
// catch-all is refused while the namespace's wildcard is known to be off (wildcardOffCause). Otherwise,
// while the wildcard isn't active, it returns a deploy-log warning. With no plugin state (nil) nothing is
// refused or warned.
func (s *Server) catchAllPluginGate(apex, provider string, existing bool) (string, error) {
	if s.edgeDNSPlugins == nil || s.edgeDNSPlugins.Active(provider, apex) {
		return "", nil
	}
	cause := s.wildcardOffCause(apex, provider)
	if cause != "" && !existing {
		return "", fmt.Errorf("refusing a new catch-all on namespace %s: its wildcard certificate is off — %s. Deploy again once the Edge page shows the wildcard active",
			apex, cause)
	}
	// Intentional: a NEW catch-all while the plugin's first install is still running is allowed (it isn't
	// KNOWN missing yet) and warned like an existing one; the catch-all watch alerts if that install fails.
	state := "the DNS plugin for " + provider + " is installing"
	if cause != "" {
		state = cause
	}
	return fmt.Sprintf("⚠ catch-all *.%s has no wildcard certificate yet (%s) — the names it catches fail TLS until it is issued",
		apex, state), nil
}

// storedCatchAllHosts returns the catch-all hostnames project has stored now (lowercased).
func (s *Server) storedCatchAllHosts(project string) map[string]bool {
	out := map[string]bool{}
	if s.edgeRoutes == nil {
		return out
	}
	routes, err := s.edgeRoutes.List()
	if err != nil {
		// Intentional: an unreadable route store counts as "not stored yet", so the gate refuses rather
		// than lets a catch-all through unverified (fail closed). It only matters while the plugin is
		// known missing.
		s.log.Warn("catch-all gate: can't read the stored edge routes", "project", project, "err", err)
		return out
	}
	for _, rt := range routes {
		if rt.AppID == project && rt.CatchAll {
			out[strings.ToLower(strings.TrimSpace(rt.Hostname))] = true
		}
	}
	return out
}

// catchAllWildcardCheck runs the catch-all plugin gate over an EXPANDED definition (a catch-all route
// carries hostname "*.<apex>") before a deploy builds anything, and returns the deploy-log warnings or the
// refusal. A namespace that isn't declared or has no dns01 is skipped: applyRoutes refuses that catch-all.
func (s *Server) catchAllWildcardCheck(project string, def *definition.Definition) ([]string, error) {
	if s.edgeDNSPlugins == nil || def == nil {
		return nil, nil
	}
	var warns []string
	var stored map[string]bool // read once, only when a catch-all's plugin isn't in the running edge
	seen := map[string]bool{}
	for _, r := range def.Spec.Edge.Routes {
		host := strings.ToLower(strings.TrimSpace(r.Hostname))
		if !strings.HasPrefix(host, "*.") || seen[host] {
			continue // a catch-all on several paths is checked once
		}
		seen[host] = true
		apex := strings.TrimPrefix(host, "*.")
		bd, ok := s.cfg.BaseDomainByApex(apex)
		if !ok || bd.DNS01 == nil || s.edgeDNSPlugins.Active(bd.DNS01.Provider, apex) {
			continue
		}
		if stored == nil {
			stored = s.storedCatchAllHosts(project)
		}
		warn, err := s.catchAllPluginGate(apex, bd.DNS01.Provider, stored[host])
		if err != nil {
			return nil, err
		}
		if warn != "" {
			warns = append(warns, warn)
		}
	}
	return warns, nil
}

// RunCatchAllWatch checks every stored catch-all's wildcard certificate (first about a minute after start,
// then every 2 minutes) and alerts while one serves none. Started by serve when the edge is owned.
func (s *Server) RunCatchAllWatch(ctx context.Context) {
	if s.edgeRoutes == nil {
		return
	}
	t := time.NewTimer(catchAllFirstCheck)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.checkCatchAlls(ctx)
			t.Reset(catchAllCheckEvery)
		}
	}
}

// catchAllVerdict is one check's outcome for a served catch-all.
type catchAllVerdict int

const (
	catchAllPending catchAllVerdict = iota // plugin still installing, or fewer than catchAllProbeFailures failed probes
	catchAllServing                        // the probe found a valid wildcard certificate
	catchAllIsDark                         // plugin known missing, or catchAllProbeFailures failed probes in a row
)

// catchAllObservation is what one check saw for an apex, before the failure counts are applied.
type catchAllObservation struct {
	missing    string // why the wildcard is known to be off (wildcardOffCause); "" when it isn't
	installing bool   // the plugin's first install is still running (not probed)
	probeErr   error  // the probe's result when it ran
}

// checkCatchAlls runs one catch-all check: every apex with a served catch-all is dark while its DNS plugin
// is known missing, or once the plugin is installed and the wildcard probe has failed catchAllProbeFailures
// times in a row. A CRITICAL edge_catchall_dark alert fires for each dark apex and resolves when its probe
// passes again or the catch-all is gone.
func (s *Server) checkCatchAlls(ctx context.Context) {
	if s.edgeRoutes == nil {
		return
	}
	routes, err := s.edgeRoutes.List()
	if err != nil {
		s.log.Debug("catch-all watch: can't list edge routes", "err", err)
		return
	}
	active := map[string]string{} // apex → DNS provider, for every catch-all the edge serves
	for _, rt := range routes {
		if !rt.CatchAll || !rt.Enabled {
			continue
		}
		apex := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(rt.Hostname)), "*.")
		// The reconciler's consent test: a catch-all whose namespace lost dns01 or consent isn't rendered
		// (its names fall back to the default 404), so there is no certificate to watch.
		if bd, ok := s.cfg.BaseDomainByApex(apex); ok && bd.DNS01 != nil && bd.CatchAll {
			active[apex] = bd.DNS01.Provider
		}
	}
	apexes := sortedKeys(active)

	// Probes are network calls: run them before taking the lock.
	seen := make(map[string]catchAllObservation, len(apexes))
	for _, apex := range apexes {
		provider := active[apex]
		if cause := s.wildcardOffCause(apex, provider); cause != "" {
			seen[apex] = catchAllObservation{missing: cause}
			continue
		}
		if s.edgeDNSPlugins != nil && !s.edgeDNSPlugins.Active(provider, apex) {
			seen[apex] = catchAllObservation{installing: true} // a probe could only fail until the install lands
			continue
		}
		seen[apex] = catchAllObservation{probeErr: s.probeCatchAll(ctx, apex)}
	}
	if ctx.Err() != nil {
		return // shutting down: a cancelled probe says nothing about the certificate
	}

	verdicts := make(map[string]catchAllVerdict, len(apexes))
	dark := map[string]string{}
	s.catchAllMu.Lock()
	if s.catchAllFails == nil {
		s.catchAllFails = map[string]int{}
	}
	for apex := range s.catchAllFails {
		if _, ok := active[apex]; !ok {
			delete(s.catchAllFails, apex)
		}
	}
	for _, apex := range apexes {
		o := seen[apex]
		switch {
		case o.missing != "":
			delete(s.catchAllFails, apex)
			verdicts[apex] = catchAllIsDark
			dark[apex] = o.missing
		case o.installing:
			delete(s.catchAllFails, apex)
			verdicts[apex] = catchAllPending
		case o.probeErr == nil:
			delete(s.catchAllFails, apex)
			verdicts[apex] = catchAllServing
		default:
			s.catchAllFails[apex]++
			verdicts[apex] = catchAllPending
			if s.catchAllFails[apex] >= catchAllProbeFailures {
				verdicts[apex] = catchAllIsDark
				dark[apex] = deployText(o.probeErr.Error(), 500) + " (ACME DNS-01 issuance may be failing — check the namespace's dns01 api_token and Caddy's log)"
			}
		}
	}
	prevDark := s.catchAllDark
	s.catchAllDark = dark
	s.catchAllMu.Unlock()

	for _, apex := range sortedKeys(dark) {
		if _, was := prevDark[apex]; !was {
			s.log.Warn("edge: catch-all serves no certificate; every name it catches fails TLS", "catch_all", "*."+apex, "cause", dark[apex])
		}
	}
	for _, apex := range sortedKeys(prevDark) {
		if _, still := dark[apex]; still {
			continue
		}
		state := "removed"
		if _, ok := active[apex]; ok {
			state = "waiting for its wildcard certificate"
			if verdicts[apex] == catchAllServing {
				state = "serves its wildcard certificate again"
			}
		}
		s.log.Info("edge: catch-all no longer dark", "catch_all", "*."+apex, "state", state)
	}

	if s.alertStore == nil {
		return
	}
	bg := context.WithoutCancel(ctx)
	octx, cancel := context.WithTimeout(bg, 5*time.Second)
	open, err := s.alertStore.OpenInfraAlerts(octx, catchAllDarkKind)
	cancel()
	if err != nil {
		return
	}
	for _, apex := range sortedKeys(dark) {
		if _, firing := open[catchAllAlertKey(apex)]; firing {
			continue
		}
		s.enqueueCatchAllAlert(bg, apex, "firing", "catch-all on *."+apex+" is serving no certificate: "+dark[apex])
	}
	for _, key := range sortedKeys(open) {
		apex := strings.TrimPrefix(key, "catchall:")
		if _, ok := active[apex]; !ok {
			s.enqueueCatchAllAlert(bg, apex, "resolved", "catch-all on *."+apex+" is no longer served (route removed, or its namespace no longer allows a catch-all)")
			continue
		}
		// Intentional: a PENDING apex (plugin installing, or fewer than catchAllProbeFailures failed probes)
		// keeps its alert open — only a passing probe proves the certificate is back.
		if verdicts[apex] == catchAllServing {
			s.enqueueCatchAllAlert(bg, apex, "resolved", "catch-all on *."+apex+" serves its wildcard certificate again")
		}
	}
}

func (s *Server) enqueueCatchAllAlert(ctx context.Context, apex, transition, summary string) {
	ectx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = s.alertStore.EnqueueInfra(ectx, alert.Outbox{
		Target: apex, Kind: catchAllDarkKind, Level: alert.LevelCritical, Transition: transition,
		Summary:   deployText(summary, 1000),
		DedupeKey: catchAllAlertKey(apex),
	})
}

// probeCatchAll checks that the local edge serves a valid certificate covering *.<apex>.
func (s *Server) probeCatchAll(ctx context.Context, apex string) error {
	if s.catchAllProbe != nil {
		return s.catchAllProbe(ctx, apex)
	}
	return edge.ProbeWildcard(ctx, catchAllProbeAddr, apex)
}

// darkCatchAlls returns the catch-alls the last check found serving no certificate, sorted by apex.
func (s *Server) darkCatchAlls() []edgeDarkView {
	s.catchAllMu.Lock()
	defer s.catchAllMu.Unlock()
	out := make([]edgeDarkView, 0, len(s.catchAllDark))
	for _, apex := range sortedKeys(s.catchAllDark) {
		out = append(out, edgeDarkView{Apex: apex, Cause: s.catchAllDark[apex]})
	}
	return out
}
