package web

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/edge"
	"github.com/daboss2003/mooring/internal/l4"
	"github.com/daboss2003/mooring/internal/ops"
	"github.com/daboss2003/mooring/internal/scale"
	"github.com/daboss2003/mooring/internal/selfheal"
)

// handleDefinitionYAML serves the app's stored definition as mooring.yaml — what is
// currently deployed, including any dashboard-set operational pieces (config files,
// cert bindings, scaling, ops). Useful to export and commit into your repo; Mooring
// never pushes to the repo itself (git access is fetch-only).
func (s *Server) handleDefinitionYAML(w http.ResponseWriter, r *http.Request) {
	if s.defStore == nil {
		http.Error(w, "definition store unavailable", http.StatusServiceUnavailable)
		return
	}
	project := r.PathValue("project")
	def, err := s.defStore.Current(project)
	if err != nil {
		http.Error(w, "could not load the definition", http.StatusInternalServerError)
		return
	}
	if def == nil {
		http.Error(w, "no canonical definition yet — deploy once to create it", http.StatusNotFound)
		return
	}
	canon, err := definition.Canonical(def)
	if err != nil {
		http.Error(w, "could not render the definition", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="mooring.yaml"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(canon)
}

// applyDefinition persists the app's definition and reconciles every runtime projection
// from it. It is called by a deploy (the repo's mooring.yaml is the source for the app's
// shape — services, edge & L4 routes) AND by the dashboard editors for the OPERATIONAL
// pieces that stay editable (config files, cert bindings, scaling, ops). It re-validates
// the definition (the same gate a committed file gets), stores it as a new version, then
// applies the projections (edge/L4 routes, scaling, self-healing, ops). note records the
// writer (e.g. "git deploy: <sha>" / "dashboard: scaling api"); commit is the git sha this
// version was deployed from ("" for dashboard edits — those are not rollback targets).
func (s *Server) applyDefinition(ctx context.Context, project string, def *definition.Definition, note, commit string) error {
	if s.defStore != nil {
		canon, err := definition.Canonical(def)
		if err != nil {
			return fmt.Errorf("render canonical: %w", err)
		}
		if _, err := definition.Parse(canon); err != nil { // re-validate before it becomes the truth
			return fmt.Errorf("invalid definition: %w", err)
		}
		if _, err := s.defStore.SaveCanonical(ctx, def, note, commit); err != nil {
			return fmt.Errorf("save canonical: %w", err)
		}
	}
	if err := s.applyRoutes(ctx, project, def); err != nil {
		return err
	}
	if err := s.applyScaling(ctx, project, def); err != nil {
		return err
	}
	if err := s.applySelfHealing(ctx, project, def); err != nil {
		return err
	}
	return s.applyOps(ctx, project, def)
}

// applyOps reconciles this app's mooring.yaml ops_interface into the ops config store
// (the prober reads it for RICH health). Gated + additive: it only runs when ops is
// owned and the def declares the block; an omitted block leaves any dashboard-set ops
// config untouched. The shared-secret VALUE never lives in the YAML — if the block
// names a `secret` reference, its value is resolved from the encrypted secret store at
// deploy; with no reference, ops.Set keeps the stored secret (NewSecret left nil), so
// a dashboard-managed secret survives a yaml deploy.
func (s *Server) applyOps(ctx context.Context, project string, def *definition.Definition) error {
	if s.opsStore == nil || def.Spec.OpsInterface == nil {
		return nil
	}
	oi := def.Spec.OpsInterface
	in := ops.SetInput{
		Enabled:      oi.Enabled,
		BaseURL:      oi.BaseURL,
		SecretHeader: oi.SecretHeader,
		OpsMode:      oi.Mode,
		BasePath:     oi.BasePath,
		Adapter:      oi.Adapter,
	}
	if oi.Secret != "" && s.envStore != nil {
		if v, ok, err := s.envStore.Reveal(project, oi.Secret); err == nil && ok {
			in.NewSecret = &v
		}
	}
	if err := s.opsStore.Set(project, in); err != nil {
		return fmt.Errorf("apply ops_interface: %w", err)
	}
	return nil
}

// applySelfHealing persists this app's mooring.yaml self-healing tunables into the
// supervisor's per-app policy store (the watcher reads it per tick, so a redeploy
// re-tunes without a restart). Gated + additive: it only runs when the supervisor is
// owned and the def declares the block; omitted fields keep the built-in default. An
// omitted block leaves any existing policy untouched (matching applyScaling), so a
// dashboard-managed default is never silently reset.
func (s *Server) applySelfHealing(ctx context.Context, project string, def *definition.Definition) error {
	if s.selfHeal == nil || def.Spec.SelfHealing == nil {
		return nil
	}
	if err := s.selfHeal.SavePolicy(ctx, project, selfHealPolicy(def.Spec.SelfHealing), time.Now().Unix()); err != nil {
		return fmt.Errorf("apply self_healing: %w", err)
	}
	return nil
}

// selfHealPolicy maps a definition self-healing block onto a controller policy: it
// starts from the conservative built-in default and overrides only the fields the
// YAML sets (0 = keep the default). redeploy_enabled is a bool, so it's always taken
// from the YAML (default off).
func selfHealPolicy(sh *definition.SelfHealing) selfheal.Policy {
	p := selfheal.DefaultPolicy()
	if sh.SustainTicks > 0 {
		p.SustainTicks = sh.SustainTicks
	}
	if sh.AttemptCap > 0 {
		p.AttemptCap = sh.AttemptCap
	}
	if sh.StabilizeTicks > 0 {
		p.StabilizeTicks = sh.StabilizeTicks
	}
	if sh.OOMStrikeCap > 0 {
		p.OOMStrikeCap = sh.OOMStrikeCap
	}
	if sh.WindowSeconds > 0 {
		p.WindowSeconds = int64(sh.WindowSeconds)
	}
	if sh.BackoffBaseSecs > 0 {
		p.BackoffBaseSecs = int64(sh.BackoffBaseSecs)
	}
	if sh.BackoffMaxSecs > 0 {
		p.BackoffMaxSecs = int64(sh.BackoffMaxSecs)
	}
	p.RedeployEnabled = sh.RedeployEnabled
	return p
}

// applyRoutes reconciles an app's edge (L7) + L4 routes FROM its deployed definition
// (the repo's mooring.yaml) — replace-by-project, so the file's set is exactly what's
// live. Routes are READ-ONLY in the dashboard; only a deploy changes them, so an empty
// set in the file correctly clears the app's routes.
//
// Persisting is fail-closed: a bad route or a cross-app listener/hostname collision
// returns an error and blocks (the stores are transactional, so nothing half-applies).
// A reconcile failure is best-effort/logged (matching cert_bindings): the routes are
// persisted and a later reconcile or edge restart picks them up, so a transient edge
// hiccup can't block an otherwise-good apply.
// expandSubdomains resolves every `subdomain:` shorthand on the definition's edge routes and
// cert_bindings into a full <subdomain>.<edge.base_domain> hostname IN PLACE, then clears the
// Subdomain field. This is the SINGLE expansion point: after it, every downstream consumer
// (compose bind mounts, cert issue/wait/sync, routes, collision checks, the re-validated
// canonical) reads the final FQDN from .Hostname and none has to know about subdomains. It
// errors if a subdomain is used but edge.base_domain isn't configured. The schema already
// validated the label and the hostname/subdomain XOR.
func (s *Server) expandSubdomains(def *definition.Definition) error {
	base := strings.TrimSpace(s.cfg.Edge.BaseDomain)
	need := func(sub string) error {
		return fmt.Errorf("subdomain %q needs edge.base_domain set in config.yaml (e.g. base_domain: mooring.example.com)", sub)
	}
	for i := range def.Spec.Edge.Routes {
		if sub := def.Spec.Edge.Routes[i].Subdomain; sub != "" {
			if base == "" {
				return need(sub)
			}
			def.Spec.Edge.Routes[i].Hostname = sub + "." + base
			def.Spec.Edge.Routes[i].Subdomain = ""
		}
	}
	// Services is a map of structs, but CertBindings is a slice whose backing array is shared
	// with the stored Service, so mutating its elements in place updates the definition.
	for name := range def.Spec.Compose.Services {
		cbs := def.Spec.Compose.Services[name].CertBindings
		for i := range cbs {
			if sub := cbs[i].Subdomain; sub != "" {
				if base == "" {
					return need(sub)
				}
				cbs[i].Hostname = sub + "." + base
				cbs[i].Subdomain = ""
			}
		}
	}
	return nil
}

// defUsesSubdomain reports whether any edge route or cert_binding uses the subdomain
// shorthand (vs a literal hostname).
func defUsesSubdomain(def *definition.Definition) bool {
	for _, r := range def.Spec.Edge.Routes {
		if r.Subdomain != "" {
			return true
		}
	}
	for _, svc := range def.Spec.Compose.Services {
		for _, cb := range svc.CertBindings {
			if cb.Subdomain != "" {
				return true
			}
		}
	}
	return false
}

// adviseSubdomainDNS surfaces — once per deploy that uses the subdomain shorthand — the
// single wildcard DNS record the operator needs, plus a best-effort check that it already
// resolves. Purely advisory (never blocks): ACME issuance is the real gate, this just gives
// a clearer heads-up than a cert that silently fails to issue. The lookup is a plain DNS
// resolve of a fixed probe label (no attacker-controlled dial → no SSRF surface).
func (s *Server) adviseSubdomainDNS(ctx context.Context, def *definition.Definition, onLine func(string)) {
	base := strings.TrimSpace(s.cfg.Edge.BaseDomain)
	if base == "" || onLine == nil || !defUsesSubdomain(def) {
		return
	}
	onLine("subdomains resolve via one wildcard DNS record: *." + base + "  A/AAAA → this server's public IP")
	probe := "mooring-dns-check." + base
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if addrs, err := net.DefaultResolver.LookupHost(cctx, probe); err != nil || len(addrs) == 0 {
		onLine("  ⚠ the wildcard record isn't resolving yet (" + probe + " → no answer) — add it, or certs can't issue")
	} else {
		onLine("  ✓ wildcard resolves (" + strings.Join(addrs, ", ") + ")")
	}
}

func (s *Server) applyRoutes(ctx context.Context, project string, def *definition.Definition) error {
	if s.edgeRoutes != nil {
		routes := make([]edge.Route, 0, len(def.Spec.Edge.Routes))
		for _, r := range def.Spec.Edge.Routes {
			port := r.Port
			if port == 0 {
				port = 80
			}
			scheme := r.UpstreamScheme
			if scheme == "" {
				scheme = "http"
			}
			host := r.Hostname // subdomains were already expanded to a full FQDN upstream
			// Reject a hostname already claimed by ANOTHER app with a clear message (the
			// UNIQUE(hostname, path_prefix) constraint is the race-safe backstop; this is
			// the friendly, specific error the operator sees — "pick a different one").
			if owner, taken, oerr := s.edgeRoutes.HostnameOwner(ctx, host, r.PathPrefix, project); oerr == nil && taken {
				return fmt.Errorf("hostname %q is already in use by app %q — pick a different one", host, owner)
			}
			// A route may opt into a private CA by name; it MUST be defined in the
			// root-of-trust config (an app repo can't introduce a trusted CA).
			if r.CA != "" && !s.cfg.HasEdgeCA(r.CA) {
				return fmt.Errorf("edge route %q references unknown CA %q — define it in config.yaml edge.cas", host, r.CA)
			}
			routes = append(routes, edge.Route{
				Hostname:        host,
				Upstream:        r.Service + ":" + strconv.Itoa(port), // selector, resolved at apply
				UpstreamScheme:  scheme,
				PathPrefix:      r.PathPrefix,
				HSTS:            r.HSTS,
				SecurityHeaders: r.SecurityHeaders,
				RedirectHTTP:    r.RedirectHTTP,
				Enabled:         true,
				CA:              r.CA,
			})
		}
		if err := s.edgeRoutes.ReplaceProject(ctx, project, routes); err != nil {
			return fmt.Errorf("apply edge routes: %w", err)
		}
		if s.edgeRecon != nil {
			if err := s.edgeRecon.Reconcile(ctx); err != nil {
				s.log.Warn("edge not reconciled after route apply (will pick up later)", "project", project, "err", err)
			}
		}
	}

	if s.l4Routes != nil {
		routes := make([]l4.Route, 0, len(def.Spec.Edge.L4Routes))
		for _, r := range def.Spec.Edge.L4Routes {
			routes = append(routes, l4.Route{
				Listen:   r.Listen,
				Protocol: r.Protocol,
				Service:  r.Service,
				Port:     r.Port,
				LB:       r.LB,
			})
		}
		if err := s.l4Routes.ReplaceProject(ctx, project, routes); err != nil {
			return fmt.Errorf("apply l4 routes: %w", err)
		}
		if s.l4Reconcile != nil {
			if err := s.l4Reconcile(ctx); err != nil {
				s.log.Warn("L4 LB not reconciled after route apply (will pick up later)", "project", project, "err", err)
			}
		}
	}
	return nil
}

// applyScaling persists this app's mooring.yaml scaling policies (one per service)
// into the scale store, so a repo's yaml drives auto-scaling for SEVERAL services —
// e.g. an HTTP api and an L4 resolver in one app. Additive + gated: it only runs when
// the scaler is owned and the def declares scaling; SavePolicy validates each policy
// (and a bad one — e.g. too-small dead band — blocks the deploy, fail-closed). It does
// not touch services the def omits, so dashboard-managed policies are left alone.
func (s *Server) applyScaling(ctx context.Context, project string, def *definition.Definition) error {
	if s.scaling == nil || len(def.Spec.Scaling) == 0 {
		return nil
	}
	for _, sc := range def.Spec.Scaling {
		if err := s.scaling.SavePolicy(ctx, scale.Key{App: project, Service: sc.Service}, scalingPolicyRow(sc)); err != nil {
			return fmt.Errorf("apply scaling for %q: %w", sc.Service, err)
		}
	}
	return nil
}

// scalingPolicyRow maps a definition scaling entry to a controller policy, filling
// the dashboard defaults for any field the YAML omits so the controller contract
// (≥20-pt dead band, positive breach window, down-lazy cooldowns) holds.
func scalingPolicyRow(sc definition.Scaling) scale.PolicyRow {
	upCPU, downCPU := sc.UpCPUPct, sc.DownCPUPct
	if upCPU == 0 {
		upCPU = 80
	}
	if downCPU == 0 {
		downCPU = 40
	}
	upMem, downMem := sc.UpMemPct, sc.DownMemPct
	if upMem == 0 {
		upMem = 80
	}
	if downMem == 0 {
		downMem = 40
	}
	min, max := sc.Min, sc.Max
	if min < 1 {
		min = 1
	}
	if max < min {
		max = min
	}
	breach := int64(sc.BreachForSecs)
	if breach <= 0 {
		breach = 60
	}
	cdUp := int64(sc.CooldownUpSecs)
	if cdUp <= 0 {
		cdUp = 60
	}
	cdDown := int64(sc.CooldownDownSecs)
	if cdDown < cdUp {
		cdDown = 300
		if cdDown < cdUp {
			cdDown = cdUp
		}
	}
	return scale.PolicyRow{
		Policy: scale.Policy{
			Min: min, Max: max,
			UpCPUPct: upCPU, DownCPUPct: downCPU,
			UpMemPct: upMem, DownMemPct: downMem,
			BreachForSecs: breach, CooldownUpSecs: cdUp, CooldownDownSecs: cdDown,
		},
		Enabled:       sc.Enabled,
		PerReplicaMem: uint64(sc.PerReplicaMemMiB) << 20,
		PerReplicaCPU: uint64(sc.PerReplicaCPUMilli),
	}
}
