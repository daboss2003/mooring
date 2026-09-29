package web

import (
	"time"

	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/scale"
	"github.com/daboss2003/mooring/internal/selfheal"
	"github.com/daboss2003/mooring/internal/startgate"
)

// SetStartGate wires the host-wide start gate (set post-construction by cmd_serve). Deploys and
// lifecycle actions record their container starts with it so the autoscaler and self-heal wait for
// those containers to settle; scheduled tasks consult it before starting.
func (s *Server) SetStartGate(g *startgate.Gate) { s.startGate = g }

// StartObservation converts a monitor snapshot into the start gate's view. Containers of protected
// projects (Mooring's own edge, socket-proxy, ntfy) never hold app starts back.
func StartObservation(snap *monitor.Snapshot, protected map[string]bool) startgate.Observation {
	o := startgate.Observation{At: snap.At, HostOK: snap.HostOK, HostCPUPct: snap.Host.CPUPercent}
	for _, a := range snap.Apps {
		for _, c := range a.Services {
			o.Containers = append(o.Containers, startgate.Container{
				ID: c.ContainerID, App: a.Project, Service: c.Service, Running: c.Running(), Health: c.Health,
				StartedAt: c.StartedAt, RestartCount: c.RestartCount, CPUPercent: c.CPUPercent, CPUValid: c.CPUValid,
				Inspected: c.Inspected, Protected: protected[a.Project],
			})
		}
	}
	return o
}

// observeStarts folds snap into the start gate (idempotent per snapshot; skips an unusable one).
func (s *Server) observeStarts(snap *monitor.Snapshot) {
	if s.startGate == nil || snap == nil || !snap.DockerOK || snap.ListFailed {
		return
	}
	protected := make(map[string]bool, len(s.cfg.ProtectedProjects))
	for _, p := range s.cfg.ProtectedProjects {
		protected[p] = true
	}
	s.startGate.Observe(StartObservation(snap, protected))
}

// recordStart tells the start gate that an action on project began at start and has just returned.
// service "" covers every service of the app (a deploy or an app-level action). ok is whether the
// action succeeded — for a per-copy action, whose container must then show up before the start counts
// as settled; app-level actions pass false, since unchanged services start nothing.
func (s *Server) recordStart(project, service string, start time.Time, ok bool) {
	if s.startGate != nil {
		s.startGate.Record(project, service, start, time.Now(), ok)
	}
}

// shInfoTTL is how long an app's per-service self-healing facts are cached.
const shInfoTTL = 30 * time.Second

// shInfoEntry is one app's cached per-service self-healing facts.
type shInfoEntry struct {
	at   time.Time
	info map[string]selfheal.ServiceInfo
}

// SelfHealServices returns what an app's canonical (HMAC-verified) definition says about each
// service for self-heal: its depends_on, whether on_unhealthy is notify, its healthcheck interval,
// whether it only runs on a schedule, and its stop grace — cached for shInfoTTL, a failed read keeping
// the last good value — plus whether an enabled autoscaling policy keeps its copy count, read fresh
// from the scale store (the source Remediate checks before removing copies). The dependency graph
// never comes from anything the app reports about itself.
func (s *Server) SelfHealServices(app string) (map[string]selfheal.ServiceInfo, bool) {
	info, ok := s.selfHealDefinition(app)
	if !ok {
		return nil, false
	}
	var enabled map[scale.Key]scale.PolicyRow
	if s.scaling != nil {
		enabled, _ = s.scaling.EnabledPolicies() // on error: nothing counts as autoscaled (recreate, never remove)
	}
	out := make(map[string]selfheal.ServiceInfo, len(info))
	for name, si := range info {
		_, si.Scaled = enabled[scale.Key{App: app, Service: name}]
		out[name] = si
	}
	return out, true
}

// selfHealDefinition returns the cached, definition-derived part of SelfHealServices.
func (s *Server) selfHealDefinition(app string) (map[string]selfheal.ServiceInfo, bool) {
	s.shInfoMu.Lock()
	e, cached := s.shInfo[app]
	s.shInfoMu.Unlock()
	if cached && time.Since(e.at) < shInfoTTL {
		return e.info, e.info != nil
	}
	if s.defStore == nil {
		return nil, false
	}
	def, err := s.defStore.Current(app)
	if err != nil {
		return e.info, e.info != nil // keep the last good value
	}
	info := serviceInfoFrom(def)
	s.shInfoMu.Lock()
	if s.shInfo == nil {
		s.shInfo = map[string]shInfoEntry{}
	}
	s.shInfo[app] = shInfoEntry{at: time.Now(), info: info}
	s.shInfoMu.Unlock()
	return info, info != nil
}

// serviceInfoFrom extracts the per-service self-healing facts from a definition (nil for none);
// SelfHealServices fills Scaled.
func serviceInfoFrom(def *definition.Definition) map[string]selfheal.ServiceInfo {
	if def == nil {
		return nil
	}
	scheduled := def.Spec.ScheduledServiceSet()
	info := make(map[string]selfheal.ServiceInfo, len(def.Spec.Compose.Services))
	for name, svc := range def.Spec.Compose.Services {
		si := selfheal.ServiceInfo{
			DependsOn: append([]string(nil), svc.DependsOn...),
			Notify:    svc.OnUnhealthy() == definition.OnUnhealthyNotify,
			Scheduled: scheduled[name],
		}
		if svc.Healthcheck != nil && len(svc.Healthcheck.Test) > 0 {
			si.Interval = svc.Healthcheck.IntervalD()
		}
		if d, err := time.ParseDuration(svc.StopGracePeriod); err == nil && d > 0 {
			si.StopGrace = d
		}
		info[name] = si
	}
	return info
}
