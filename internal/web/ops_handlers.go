package web

import (
	"net/http"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/ops"
)

// handleOpsConfigGet renders the per-app App Ops Interface configuration form.
func (s *Server) handleOpsConfigGet(w http.ResponseWriter, r *http.Request) {
	if s.opsStore == nil {
		http.Error(w, "ops not available", http.StatusNotFound)
		return
	}
	project := r.PathValue("project")
	cfg, _, err := s.opsStore.Get(project)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	cfg.Project = project
	s.renderOpsConfig(w, r, project, &cfg, "")
}

// handleOpsConfigPost saves ops coordinates. The shared secret is write-only:
// a blank field keeps the stored secret; "clear_secret" removes it.
func (s *Server) handleOpsConfigPost(w http.ResponseWriter, r *http.Request) {
	if s.opsStore == nil {
		http.Error(w, "ops not available", http.StatusNotFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	project := r.PathValue("project")

	if r.PostFormValue("enabled") != "on" && s.appOpsAlertsDeclared(project) {
		// Intentional (owner decision): turning ops off is refused while the yaml declares app-level
		// alerts. Alerts need enabled: true, so the write-back of an "off" would fail and the yaml would
		// silently keep ops on; refused before anything is applied.
		cfg, _, _ := s.opsStore.Get(project)
		cfg.Project = project
		s.renderOpsConfig(w, r, project, &cfg, opsDisableRefused)
		return
	}

	in := ops.SetInput{
		Enabled:      r.PostFormValue("enabled") == "on",
		BaseURL:      r.PostFormValue("base_url"),
		SecretHeader: r.PostFormValue("secret_header"),
		OpsMode:      r.PostFormValue("ops_mode"),
		BasePath:     r.PostFormValue("base_path"),
		Adapter:      r.PostFormValue("adapter"),
	}
	// Tri-state secret: clear > replace > keep.
	if r.PostFormValue("clear_secret") == "on" {
		empty := ""
		in.NewSecret = &empty
	} else if v := r.PostFormValue("secret"); v != "" {
		in.NewSecret = &v
	}

	if err := s.opsStore.Set(project, in); err != nil {
		// Re-render the form with the validation error (no secret echoed back).
		cfg, _, _ := s.opsStore.Get(project)
		cfg.Project = project
		s.renderOpsConfig(w, r, project, &cfg, err.Error())
		return
	}
	s.opsWriteBack(r, project)
	_ = s.audit.Log(r.Context(), audit.Event{
		Actor: sessionUser(r), IP: ClientIP(r.Context()).String(),
		Action: "ops_config_set", Target: project, Outcome: audit.OK, Level: audit.Security,
	})
	http.Redirect(w, r, "/apps/"+project, http.StatusSeeOther)
}

const opsDisableRefused = "This app's mooring.yaml declares ops alerts; remove them from mooring.yaml and deploy before turning the ops interface off."

// appOpsAlertsDeclared reports whether the app's canonical mooring.yaml declares alerts on its app-level
// ops_interface. An unreadable canonical reports false: the write-back skips it too.
func (s *Server) appOpsAlertsDeclared(project string) bool {
	if s.defStore == nil {
		return false
	}
	def, err := s.defStore.Current(project)
	return err == nil && def != nil && def.Spec.OpsInterface != nil && len(def.Spec.OpsInterface.Alerts) > 0
}

// opsWriteBack persists the just-applied ops config (everything but the secret VALUE)
// into the canonical mooring.yaml, so "the file, dashboard-updated last" stays true
// and an export/redeploy reflects the edit. It reads the NORMALIZED config back from
// the ops store (so the canonical matches exactly what was applied) and preserves any
// existing secret reference — the value lives only in the encrypted ops store. It is
// best-effort: the ops config is already applied, so a missing canonical (app never
// deployed from yaml) or a re-validation hiccup is logged, never fatal.
func (s *Server) opsWriteBack(r *http.Request, project string) {
	if s.defStore == nil {
		return
	}
	def, err := s.defStore.Current(project)
	if err != nil || def == nil {
		return // no canonical yet → nothing to keep in sync (the ops store is the record)
	}
	cfg, ok, gerr := s.opsStore.Get(project)
	if gerr != nil || !ok {
		return
	}
	ref := ""
	var alerts []definition.OpsAlert
	if def.Spec.OpsInterface != nil {
		ref = def.Spec.OpsInterface.Secret // the value is excepted; keep the reference, if any
		// The dashboard doesn't edit alerts; only the yaml declares them, so they are kept as they are.
		alerts = def.Spec.OpsInterface.Alerts
	}
	def.Spec.OpsInterface = &definition.OpsInterface{
		Enabled:      cfg.Enabled,
		BaseURL:      cfg.BaseURL,
		SecretHeader: cfg.SecretHeader,
		Secret:       ref,
		Mode:         cfg.OpsMode,
		BasePath:     cfg.BasePath,
		Adapter:      cfg.Adapter,
		Alerts:       alerts,
	}
	canon, cerr := definition.Canonical(def)
	if cerr != nil {
		s.log.Warn("ops write-back: could not render canonical (ops config applied)", "project", project, "err", cerr)
		return
	}
	if _, perr := definition.ParseStored(canon); perr != nil {
		s.log.Warn("ops write-back: canonical re-validation failed (ops config applied)", "project", project, "err", perr)
		return
	}
	if _, serr := s.defStore.SaveCanonical(r.Context(), def, "dashboard: ops_interface", ""); serr != nil {
		s.log.Warn("ops write-back: could not save canonical (ops config applied)", "project", project, "err", serr)
	}
}

// handleQueueAction performs a server-side, secret-bearing queue action (the
// secret never reaches the browser, plan §4.2).
func (s *Server) handleQueueAction(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	queue := r.PathValue("queue")
	action := r.PathValue("action")

	// Protected/managed projects (the read-plane proxy, edge) are Mooring's own
	// infrastructure — never app-controllable, mirroring lifecycle/scale/env (plan §3).
	// Checked first so the policy holds regardless of whether ops is available.
	if s.cfg.IsProtectedProject(project) {
		_ = s.audit.Log(r.Context(), audit.Event{
			Actor: sessionUser(r), IP: ClientIP(r.Context()).String(),
			Action: "ops_queue_" + action, Target: project + "/" + queue, Outcome: audit.Deny, Level: audit.Security, Detail: "protected project",
		})
		http.Error(w, "this is a protected project and cannot be controlled as an app", http.StatusForbidden)
		return
	}
	if s.prober == nil {
		http.Error(w, "ops not available", http.StatusNotFound)
		return
	}

	err := s.prober.QueueAction(r.Context(), project, queue, action)
	outcome := audit.OK
	if err != nil {
		outcome = audit.Error
	}
	_ = s.audit.Log(r.Context(), audit.Event{
		Actor: sessionUser(r), IP: ClientIP(r.Context()).String(),
		Action: "ops_queue_" + action, Target: project + "/" + queue, Outcome: outcome, Level: audit.Info,
	})
	if err != nil {
		http.Error(w, "queue action failed", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/apps/"+project, http.StatusSeeOther)
}

func (s *Server) renderOpsConfig(w http.ResponseWriter, r *http.Request, project string, cfg *ops.Config, errMsg string) {
	sess := SessionFrom(r.Context())
	var status *ops.Status
	if st, ok := s.opsStore.Status(project); ok {
		status = &st
	}
	s.render(w, r, "ops_config.html", tmplData{
		Title:     "Ops config — " + project,
		CSRFToken: CSRFToken(r.Context()),
		Username:  sess.Username,
		Error:     errMsg,
		Project:   project,
		OpsCfg:    cfg,
		OpsStatus: status,
	})
}

func sessionUser(r *http.Request) string {
	if s := SessionFrom(r.Context()); s != nil {
		return s.Username
	}
	return ""
}
