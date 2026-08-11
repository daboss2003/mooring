package web

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/ops"
	secretpkg "github.com/daboss2003/mooring/internal/secret"
)

// serviceView is the per-service page model: one service's live status, self-heal
// phase, desired replicas, and its current scaling policy (to pre-fill the form). A
// dedicated page per service keeps each service's logs/actions/auto-scaling separate
// instead of crammed into one shared app screen.
type serviceView struct {
	Project, Service          string
	Found                     bool // has a live container in the snapshot
	Running                   bool
	State, Health, StatusText string
	CPUPercent                float64
	MemBytes, MemLimit        uint64
	RestartCount              int
	ContainerID               string    // the SPECIFIC copy being shown (a scaled service has many)
	ContainerName             string    // e.g. myapp-api-2 — so the user sees which copy this is
	Copies                    []copyRef // sibling replicas of this service, for the copy switcher
	Phase                     string              // self-heal supervisor phase, e.g. CIRCUIT_OPEN
	DesiredReplicas           int                 // 0 when scaling isn't active
	Policy                    *definition.Scaling // current scaling policy; nil = none yet
	HasOps                    bool                // the service declares an enabled (non-basic) ops endpoint → live-poll its fragment
	Ops                       *ops.Result         // live ops probe (RICH queues/metrics); nil if no ops endpoint or unreachable
}

// copyRef identifies one replica (copy) of a scaled service for the per-service page's copy
// switcher. Selected marks the one currently being viewed.
type copyRef struct {
	ID       string
	Name     string
	Selected bool
}

// selectCopy picks the container to show for a (service, optional copyID): the requested copy when
// it matches a LIVE container of THIS service, else the first (newest). Because it only ever ranges
// this app's own service containers, a client-supplied copyID can never select a container outside
// this app+service — a stale/foreign id simply falls back to the first. Also returns every copy of
// the service (for the switcher).
func selectCopy(app *monitor.App, service, copyID string) (chosen monitor.ServiceStatus, copies []monitor.ServiceStatus, ok bool) {
	if app == nil {
		return
	}
	for _, svc := range app.Services {
		if svc.Service != service {
			continue
		}
		copies = append(copies, svc)
		if !ok || (copyID != "" && svc.ContainerID == copyID) {
			chosen, ok = svc, true
		}
	}
	return
}

// probeServiceOps probes one service's own ops endpoint (from the canonical def) on
// demand and returns the RICH result (queues/metrics), or nil when the service has no
// ops endpoint, ops is off/basic, or it isn't reachable. Bounded timeout so a slow
// endpoint degrades to nil rather than hanging the request. Shared by the page handler
// and the live-poll fragment so the two can never drift.
func (s *Server) probeServiceOps(ctx context.Context, project string, svcDef definition.Service) *ops.Result {
	if s.prober == nil {
		return nil
	}
	target, ok := s.serviceOpsTarget(project, svcDef)
	if !ok {
		return nil
	}
	oi := svcDef.OpsInterface
	pctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	return s.prober.ProbeTarget(pctx, project, target, oi.Adapter, oi.Mode)
}

// serviceOpsTarget resolves a service's ops endpoint Target from its OpsInterface
// (decrypting the configured secret env var). ok=false when the service has no
// enabled, non-basic ops interface. Shared by probeServiceOps (read) and the
// per-service queue-action handler (write) so the action POSTs to the SAME endpoint
// whose queues are shown.
func (s *Server) serviceOpsTarget(project string, svcDef definition.Service) (ops.Target, bool) {
	oi := svcDef.OpsInterface
	if oi == nil || !oi.Enabled || oi.Mode == "basic" {
		return ops.Target{}, false
	}
	secret := ""
	if oi.Secret != "" && s.envStore != nil {
		if ent, ok, _ := s.envStore.Get(project, oi.Secret); ok {
			if v, derr := ent.DecodedValue(); derr == nil {
				secret = string(v)
			}
		}
	}
	return ops.Target{BaseURL: oi.BaseURL, SecretHeader: oi.SecretHeader, Secret: secretpkg.New(secret), BasePath: oi.BasePath}, true
}

// handleServiceQueueAction runs a queue pause/resume/retry-failed against THIS
// service's own ops endpoint (not the project-level ops target). It mirrors
// handleQueueAction's guards (protected-project block, audit) but resolves the
// per-service Target so the action hits the same endpoint the page's queues came
// from. Redirects back to the service page.
func (s *Server) handleServiceQueueAction(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	service := r.PathValue("service")
	queue := r.PathValue("queue")
	action := r.PathValue("action")
	actor := sessionUser(r)
	peer := ClientIP(r.Context()).String()
	auditTarget := project + "/" + service + "/" + queue

	if s.cfg.IsProtectedProject(project) {
		_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "ops_queue_" + action, Target: auditTarget, Outcome: audit.Deny, Level: audit.Security, Detail: "protected project"})
		http.Error(w, "this is a protected project and cannot be controlled as an app", http.StatusForbidden)
		return
	}
	if s.prober == nil {
		http.Error(w, "ops not available", http.StatusNotFound)
		return
	}
	def := s.currentDef(project)
	if def == nil {
		http.Error(w, "service ops not configured", http.StatusNotFound)
		return
	}
	svcDef, ok := def.Spec.Compose.Services[service]
	if !ok {
		http.Error(w, "service not found", http.StatusNotFound)
		return
	}
	target, ok := s.serviceOpsTarget(project, svcDef)
	if !ok {
		http.Error(w, "this service has no ops endpoint", http.StatusNotFound)
		return
	}

	err := s.prober.QueueActionTarget(r.Context(), project, target, queue, action)
	outcome := audit.OK
	if err != nil {
		outcome = audit.Error
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "ops_queue_" + action, Target: auditTarget, Outcome: outcome, Level: audit.Info})
	if err != nil {
		http.Error(w, "queue action failed", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/apps/"+url.PathEscape(project)+"/services/"+url.PathEscape(service), http.StatusSeeOther)
}

// handleServiceGet renders the per-service page.
func (s *Server) handleServiceGet(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	service := r.PathValue("service")

	var app *monitor.App
	if snap := s.snapshot(); snap != nil {
		app = snap.AppByProject(project)
	}
	sv := &serviceView{Project: project, Service: service}
	// A scaled service has many containers (copies) sharing one service name; ?copy=<id> selects
	// the specific one, else the first. Without this every copy resolved to the newest.
	if chosen, copies, found := selectCopy(app, service, r.URL.Query().Get("copy")); found {
		sv.Found = true
		sv.Running = chosen.Running()
		sv.State, sv.Health, sv.StatusText = chosen.State, chosen.Health, chosen.StatusText
		sv.CPUPercent, sv.MemBytes, sv.MemLimit = chosen.CPUPercent, chosen.MemBytes, chosen.MemLimit
		sv.RestartCount = chosen.RestartCount
		sv.ContainerID, sv.ContainerName = chosen.ContainerID, chosen.Name
		if len(copies) > 1 { // only show the switcher when the service actually has multiple copies
			for _, c := range copies {
				sv.Copies = append(sv.Copies, copyRef{ID: c.ContainerID, Name: c.Name, Selected: c.ContainerID == chosen.ContainerID})
			}
		}
	}
	inDef := false
	var svcDef definition.Service
	if def := s.currentDef(project); def != nil {
		if sd, ok := def.Spec.Compose.Services[service]; ok {
			inDef = true
			svcDef = sd
		}
		for i := range def.Spec.Scaling {
			if def.Spec.Scaling[i].Service == service {
				sv.Policy = &def.Spec.Scaling[i]
				break
			}
		}
	}
	// Unknown service: neither running nor declared in the definition.
	if !sv.Found && !inDef {
		http.Error(w, "service not found", http.StatusNotFound)
		return
	}
	sv.Phase = s.supervisorStates(project)[service]
	sv.DesiredReplicas = s.scalingDesired(project)[service]

	// Per-service ops: probe THIS service's ops endpoint (from the canonical) on demand,
	// so its RICH queues / metric cards render on its own page. (The live poll fragment
	// /partials/service/.../ops re-runs the same probe; both go through probeServiceOps.)
	if oi := svcDef.OpsInterface; oi != nil && oi.Enabled && oi.Mode != "basic" {
		sv.HasOps = true // the page wraps the ops panels in a poll fragment only when true
	}
	sv.Ops = s.probeServiceOps(r.Context(), project, svcDef)

	s.render(w, r, "service.html", tmplData{
		Title:               service + " — " + project,
		CSRFToken:           CSRFToken(r.Context()),
		Username:            sessionUser(r),
		Project:             project,
		Protected:           s.cfg.IsProtectedProject(project),
		WriteDisabledReason: s.writeDisabledReason(),
		Svc:                 sv,
	})
}

// handleServiceOpsPartial re-probes one service's ops endpoint and returns just the
// ops fragment, for the service page's live poll (mirrors handleAppPartial). The probe
// is the same one the page handler runs, via probeServiceOps.
func (s *Server) handleServiceOpsPartial(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	service := r.PathValue("service")
	sv := &serviceView{Project: project, Service: service}
	if def := s.currentDef(project); def != nil {
		if sd, ok := def.Spec.Compose.Services[service]; ok {
			sv.Ops = s.probeServiceOps(r.Context(), project, sd)
		}
	}
	s.renderPartial(w, "service_ops", tmplData{
		Svc:       sv, // Svc carries Project + Service for the action-form URLs
		CSRFToken: CSRFToken(r.Context()),
		Protected: s.cfg.IsProtectedProject(project),
	})
}
