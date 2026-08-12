package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/scale"
)

// Scale makes *Server the auto-scaler's Scaler: it changes a service's replica count
// with a static-argv `docker compose up -d --no-deps --no-recreate --scale <svc>=<n>`
// through the gated write path (env render + §5.6 validation), via RunHeld — the
// scaler's safety gate already holds the one-docker-child semaphore. A protected
// project is refused (authority never widens what may run).
func (s *Server) Scale(ctx context.Context, appProject, service string, replicas int) error {
	if s.runner == nil {
		return fmt.Errorf("write plane unavailable")
	}
	if s.cfg.IsProtectedProject(appProject) {
		return fmt.Errorf("refusing to scale a protected project %q", appProject)
	}
	var app *monitor.App
	if snap := s.snapshot(); snap != nil {
		app = snap.AppByProject(appProject)
	}
	if app == nil {
		return fmt.Errorf("app %q not found", appProject)
	}
	env := s.composeEnv(app)
	envFile, cleanup, err := s.renderEnvFile(app, env)
	defer cleanup()
	if err != nil {
		return fmt.Errorf("render env file: %w", err)
	}
	if res := s.validateAppCompose(app, env); !res.OK() && s.cfg.ComposeValidation.Mode != "review" {
		return fmt.Errorf("§5.6 compose validation failed (%d findings)", len(res.Violations))
	}
	job := dockerexec.Job{
		Project: appProject, Dir: app.WorkingDir, ConfigFiles: app.ConfigFiles, EnvFile: envFile,
		Action: []string{"up", "-d", "--no-deps", "--no-recreate", "--scale", service + "=" + strconv.Itoa(replicas)},
	}
	return s.runner.RunHeld(ctx, job, nil)
}

// handleScalingSave persists a per-service scaling policy. Enabling scaling is hard-
// gated: a protected project, a stateful image (C4 — refused at the chokepoint, not
// merely attested), or an invalid policy / missing reservation is rejected.
func (s *Server) handleScalingSave(w http.ResponseWriter, r *http.Request) {
	if s.scaling == nil {
		http.Error(w, "scaling unavailable", http.StatusServiceUnavailable)
		return
	}
	project := r.PathValue("project")
	if s.cfg.IsProtectedProject(project) {
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	service := r.PostFormValue("service")
	if service == "" {
		http.Error(w, "service is required", http.StatusUnprocessableEntity)
		return
	}
	enabled := r.PostFormValue("enabled") == "on"

	if enabled {
		// The service must exist in the running deployment, so the C4 image gate is
		// actually evaluated (a typo'd / not-yet-deployed service can't slip enablement
		// past the denylist).
		img := s.serviceImage(project, service)
		if img == "" {
			http.Error(w, "service not found in the running deployment", http.StatusUnprocessableEntity)
			return
		}
		// C4 hard gate: never scale a known stateful/clustered image, whatever the
		// operator attests — scaling a database risks data corruption.
		if scale.StatefulImage(img) {
			http.Error(w, "this service runs a stateful image ("+img+") and cannot be auto-scaled (C4)", http.StatusUnprocessableEntity)
			return
		}
		// C1/C2/C3/C6 attestation: the operator must confirm the candidacy contract.
		if r.PostFormValue("attest") != "on" {
			http.Error(w, "you must confirm the service is a stateless, edge-fronted HTTP service with no fixed host port and no read-write volume", http.StatusUnprocessableEntity)
			return
		}
	}

	// Write-back: a dashboard edit updates the CANONICAL mooring.yaml (the source of
	// truth) and reconciles the scale store FROM it — so editing here is the same as
	// editing the file. If the app has no canonical yet (never deployed under the
	// canonical store), fall back to writing the projection directly.
	if s.defStore != nil {
		if def, derr := s.defStore.Current(project); derr == nil && def != nil {
			// Preserve custom metrics (source: edge / source: ops): they're deploy-time config authored
			// in mooring.yaml, NOT editable in this CPU/mem panel, and must survive a dashboard tune.
			entry := preserveMetrics(def.Spec.Scaling, scalingFromForm(service, enabled, r))
			def.Spec.Scaling = upsertScaling(def.Spec.Scaling, entry)
			if err := s.applyDefinition(r.Context(), project, def, "dashboard: scaling "+service, ""); err != nil {
				http.Error(w, "scaling policy rejected: "+err.Error(), http.StatusUnprocessableEntity)
				return
			}
			_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "scaling_policy_save", Target: project + "/" + service, Outcome: audit.OK, Level: audit.Security})
			http.Redirect(w, r, "/apps/"+project+"/services/"+url.PathEscape(service), http.StatusSeeOther)
			return
		}
	}

	pr := scalingPolicyRow(scalingFromForm(service, enabled, r))
	if err := s.scaling.SavePolicy(r.Context(), scale.Key{App: project, Service: service}, pr); err != nil {
		http.Error(w, "scaling policy rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "scaling_policy_save", Target: project + "/" + service, Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/apps/"+project+"/services/"+url.PathEscape(service), http.StatusSeeOther)
}

// scalingFromForm builds a definition scaling entry from the dashboard form.
func scalingFromForm(service string, enabled bool, r *http.Request) definition.Scaling {
	return definition.Scaling{
		Service:            service,
		Enabled:            enabled,
		Min:                atoiDefault(r.PostFormValue("min"), 1),
		Max:                atoiDefault(r.PostFormValue("max"), 1),
		UpCPUPct:           atofDefault(r.PostFormValue("up_cpu"), 80),
		DownCPUPct:         atofDefault(r.PostFormValue("down_cpu"), 40),
		UpMemPct:           atofDefault(r.PostFormValue("up_mem"), 80),
		DownMemPct:         atofDefault(r.PostFormValue("down_mem"), 40),
		PerReplicaMemMiB:   atoiDefault(r.PostFormValue("per_replica_mem_mib"), 0),
		PerReplicaCPUMilli: atoiDefault(r.PostFormValue("per_replica_cpu_milli"), 0),
		BreachForSecs:      atoiDefault(r.PostFormValue("breach_for"), 60),
		CooldownUpSecs:     atoiDefault(r.PostFormValue("cooldown_up"), 60),
		CooldownDownSecs:   atoiDefault(r.PostFormValue("cooldown_down"), 300),
	}
}

// upsertScaling replaces the entry for e.Service (or appends it), so the canonical
// holds exactly one policy per service.
// preserveMetrics carries an existing service's custom metrics (source: edge/ops) into a
// dashboard-form entry, which never sets them (scalingFromForm covers only CPU/mem/min/max). Without
// this, a dashboard scaling save would REPLACE the entry and silently drop mooring.yaml-authored
// signals. Metrics are edited in the file, not this panel; here we only keep them intact.
func preserveMetrics(existing []definition.Scaling, entry definition.Scaling) definition.Scaling {
	for _, ex := range existing {
		if ex.Service == entry.Service {
			entry.Metrics = ex.Metrics
			break
		}
	}
	return entry
}

func upsertScaling(list []definition.Scaling, e definition.Scaling) []definition.Scaling {
	for i := range list {
		if list[i].Service == e.Service {
			list[i] = e
			return list
		}
	}
	return append(list, e)
}

// scalingDesired returns the per-service desired replica count for a project (the
// controller's current target), for the read-only app view.
func (s *Server) scalingDesired(project string) map[string]int {
	out := map[string]int{}
	if s.scaling == nil {
		return out
	}
	states, err := s.scaling.LoadStates()
	if err != nil {
		return out
	}
	for k, st := range states {
		if k.App == project {
			out[k.Service] = st.Replicas
		}
	}
	return out
}

// serviceImage returns a service's image from the latest snapshot ("" if unknown).
func (s *Server) serviceImage(project, service string) string {
	snap := s.snapshot()
	if snap == nil {
		return ""
	}
	app := snap.AppByProject(project)
	if app == nil {
		return ""
	}
	for _, svc := range app.Services {
		if svc.Service == service {
			return svc.Image
		}
	}
	return ""
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

func atofDefault(s string, def float64) float64 {
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return def
}
