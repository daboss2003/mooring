package web

import (
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/cfgfile"
	"github.com/daboss2003/mooring/internal/definition"
)

// configfiles_canonical.go backs the config-files editor: config files + cert bindings
// are dashboard-EDITABLE per service (persisted to the app's stored definition and
// reconciled), like scaling and ops. They may also be declared in mooring.yaml, which
// seeds them on deploy. (Edge & L4 routes are NOT editable here — they come read-only
// from the repo's mooring.yaml.) The legacy app-level cfgStore editor (configfiles.go)
// stays for provisioned apps with no stored definition; a one-time migration moves
// legacy rows into the per-service model.

// currentDef returns the app's canonical definition, or nil when there is none (no
// definition store, a read error, or a legacy provisioned app) — in which case the
// caller falls back to the legacy cfgStore editor.
func (s *Server) currentDef(project string) *definition.Definition {
	if s.defStore == nil {
		return nil
	}
	def, err := s.defStore.Current(project)
	if err != nil {
		return nil
	}
	return def
}

// canonServiceNames returns the app's service names, sorted (for the editor selects).
func canonServiceNames(def *definition.Definition) []string {
	names := make([]string, 0, len(def.Spec.Compose.Services))
	for n := range def.Spec.Compose.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// populateCanonicalConfig fills the view from the canonical (per-service) config files
// + cert bindings, plus the service list for the add/update selects, plus any legacy
// cfgStore rows still awaiting migration into the canonical.
func (s *Server) populateCanonicalConfig(data *tmplData, def *definition.Definition, project string) {
	data.ConfigCanonical = true
	data.ConfigServices = canonServiceNames(def)
	for _, name := range data.ConfigServices {
		svc := def.Spec.Compose.Services[name]
		for _, cf := range svc.ConfigFiles {
			secretBearing := configFileSecretBearing(svc, cf)
			src := "(inline)"
			if cf.Repo != "" {
				src = cf.Repo
			}
			mode := "0640"
			if secretBearing {
				mode = "0600"
			}
			data.ManagedFiles = append(data.ManagedFiles, configFileView{
				Service: name, Name: path.Base(cf.Mount), Mount: cf.Mount, RelPath: cf.Mount,
				Source: src, Bindings: bindingViewsFromCanonical(cf.Bindings),
				SecretBearing: secretBearing, Mode: mode,
			})
		}
		for _, cb := range svc.CertBindings {
			data.CertBindings = append(data.CertBindings, certBindingView{
				Service: name, Hostname: cb.Hostname, Mount: cb.Mount, Required: true,
			})
		}
	}
	// Legacy rows still in the app-level store → offer migration into the canonical.
	if s.cfgStore != nil {
		if legacy, err := s.cfgStore.ConfigFiles(project); err == nil {
			for _, f := range legacy {
				data.LegacyFiles = append(data.LegacyFiles, configFileView{
					Name: f.Name, RelPath: f.RelPath, Bindings: legacyBindingViews(f.Bindings),
					SecretBearing: f.SecretBearing,
				})
			}
		}
	}
}

// configFileSecretBearing reports whether rendering this config file would emit a
// secret value (a secret: binding, or an env: binding backed by a secret) — so the
// view + the materialized file are tightened to 0600.
func configFileSecretBearing(svc definition.Service, cf definition.ConfigFile) bool {
	for _, b := range cf.Bindings {
		if b.Secret != "" {
			return true
		}
		if b.Env != "" {
			if ev, ok := svc.Env[b.Env]; ok && ev.Secret != "" {
				return true
			}
		}
	}
	return false
}

// bindingViewsFromCanonical renders a canonical binding map (sorted) for display.
func bindingViewsFromCanonical(bs map[string]definition.Binding) []bindingView {
	keys := make([]string, 0, len(bs))
	for k := range bs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]bindingView, 0, len(keys))
	for _, k := range keys {
		out = append(out, bindingView{Key: k, Source: bindingSourceString(bs[k])})
	}
	return out
}

// bindingSourceString renders one binding as its editor source string.
func bindingSourceString(b definition.Binding) string {
	switch {
	case b.Secret != "":
		return "secret:" + b.Secret
	case b.Env != "":
		return "env:" + b.Env
	case b.App != "":
		return "app:" + b.App
	case b.Cert != "":
		return "cert:" + b.Cert
	default:
		return "literal:" + b.Value
	}
}

// parseCanonicalBindings parses "key=source" lines into canonical bindings. source is
// one of secret:NAME, env:NAME, app:FIELD, cert:HOST.field, literal:VALUE. Field-level
// validity (declared secret, same-service cert, …) is re-checked by applyDefinition.
func parseCanonicalBindings(text string) (map[string]definition.Binding, error) {
	out := map[string]definition.Binding{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			return nil, fmt.Errorf("binding line %q must be key=source", line)
		}
		key := strings.TrimSpace(line[:i])
		b, err := parseBindingSourceStr(strings.TrimSpace(line[i+1:]))
		if err != nil {
			return nil, fmt.Errorf("binding %q: %v", key, err)
		}
		out[key] = b
	}
	return out, nil
}

func parseBindingSourceStr(src string) (definition.Binding, error) {
	kind, arg, ok := strings.Cut(src, ":")
	if !ok || arg == "" {
		return definition.Binding{}, fmt.Errorf("source %q must be kind:arg (secret|env|app|cert|literal)", src)
	}
	switch kind {
	case "secret":
		return definition.Binding{Secret: arg}, nil
	case "env":
		return definition.Binding{Env: arg}, nil
	case "app":
		return definition.Binding{App: arg}, nil
	case "cert":
		return definition.Binding{Cert: arg}, nil
	case "literal":
		return definition.Binding{Value: arg}, nil
	default:
		return definition.Binding{}, fmt.Errorf("unknown source kind %q (secret|env|app|cert|literal)", kind)
	}
}

// --- config-file write-back ---

func (s *Server) saveCanonicalConfigFile(w http.ResponseWriter, r *http.Request, def *definition.Definition, project string) {
	service := strings.TrimSpace(r.PostFormValue("service"))
	mount := strings.TrimSpace(r.PostFormValue("mount"))
	svc, ok := def.Spec.Compose.Services[service]
	if !ok {
		http.Error(w, "unknown service "+service, http.StatusUnprocessableEntity)
		return
	}
	bindings, err := parseCanonicalBindings(r.PostFormValue("bindings"))
	if err != nil {
		http.Error(w, "config file rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	svc.ConfigFiles = upsertConfigFileByMount(svc.ConfigFiles, definition.ConfigFile{
		Template: r.PostFormValue("template"), Mount: mount, Bindings: bindings,
	})
	def.Spec.Compose.Services[service] = svc
	if err := s.applyDefinition(r.Context(), project, def, "dashboard: config-file "+service+" "+mount, ""); err != nil {
		http.Error(w, "config file rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "config_file_save", Target: project + "/" + service + mount, Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/apps/"+project+"/config-files", http.StatusSeeOther)
}

func (s *Server) deleteCanonicalConfigFile(w http.ResponseWriter, r *http.Request, def *definition.Definition, project string) {
	service := strings.TrimSpace(r.PostFormValue("service"))
	mount := strings.TrimSpace(r.PostFormValue("mount"))
	svc, ok := def.Spec.Compose.Services[service]
	if !ok {
		http.Redirect(w, r, "/apps/"+project+"/config-files", http.StatusSeeOther)
		return
	}
	svc.ConfigFiles = removeConfigFileByMount(svc.ConfigFiles, mount)
	def.Spec.Compose.Services[service] = svc
	if err := s.applyDefinition(r.Context(), project, def, "dashboard: config-file delete "+service+" "+mount, ""); err != nil {
		http.Error(w, "delete rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "config_file_delete", Target: project + "/" + service + mount, Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/apps/"+project+"/config-files", http.StatusSeeOther)
}

// --- cert-binding write-back ---

func (s *Server) saveCanonicalCertBinding(w http.ResponseWriter, r *http.Request, def *definition.Definition, project string) {
	service := strings.TrimSpace(r.PostFormValue("service"))
	hostname := strings.TrimSpace(r.PostFormValue("hostname"))
	mount := strings.TrimSpace(r.PostFormValue("mount"))
	svc, ok := def.Spec.Compose.Services[service]
	if !ok {
		http.Error(w, "unknown service "+service, http.StatusUnprocessableEntity)
		return
	}
	svc.CertBindings = upsertCertBindingByHost(svc.CertBindings, definition.CertBinding{Hostname: hostname, Mount: mount})
	def.Spec.Compose.Services[service] = svc
	if err := s.applyDefinition(r.Context(), project, def, "dashboard: cert-binding "+service+" "+hostname, ""); err != nil {
		http.Error(w, "cert binding rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "cert_binding_save", Target: project + "/" + service + "/" + hostname, Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/apps/"+project+"/config-files", http.StatusSeeOther)
}

func (s *Server) deleteCanonicalCertBinding(w http.ResponseWriter, r *http.Request, def *definition.Definition, project string) {
	service := strings.TrimSpace(r.PostFormValue("service"))
	hostname := strings.TrimSpace(r.PostFormValue("hostname"))
	svc, ok := def.Spec.Compose.Services[service]
	if !ok {
		http.Redirect(w, r, "/apps/"+project+"/config-files", http.StatusSeeOther)
		return
	}
	svc.CertBindings = removeCertBindingByHost(svc.CertBindings, hostname)
	def.Spec.Compose.Services[service] = svc
	if err := s.applyDefinition(r.Context(), project, def, "dashboard: cert-binding delete "+service+" "+hostname, ""); err != nil {
		http.Error(w, "delete rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "cert_binding_delete", Target: project + "/" + service + "/" + hostname, Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/apps/"+project+"/config-files", http.StatusSeeOther)
}

// --- legacy → canonical migration (operator assigns a service + mount) ---

// handleConfigFileMigrate moves one legacy app-level config file into the canonical
// per-service model. The operator picks the target service + container mount; the
// stored template + bindings are carried over (cert: bindings are remapped from the
// legacy binding NAME to its hostname). applyDefinition re-validates the result, and
// only on success is the legacy row removed (fail-safe: a reject leaves it in place).
func (s *Server) handleConfigFileMigrate(w http.ResponseWriter, r *http.Request) {
	if s.cfgStore == nil || s.defStore == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	project := r.PathValue("project")
	if s.cfg.IsProtectedProject(project) {
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	def := s.currentDef(project)
	if def == nil {
		http.Error(w, "no canonical mooring.yaml to migrate into", http.StatusConflict)
		return
	}
	name := r.PostFormValue("name")
	service := strings.TrimSpace(r.PostFormValue("service"))
	mount := strings.TrimSpace(r.PostFormValue("mount"))
	svc, ok := def.Spec.Compose.Services[service]
	if !ok {
		http.Error(w, "unknown service "+service, http.StatusUnprocessableEntity)
		return
	}
	files, err := s.cfgStore.ConfigFiles(project)
	if err != nil {
		http.Error(w, "could not read legacy files", http.StatusInternalServerError)
		return
	}
	var legacy *legacyConfigFile
	for i := range files {
		if files[i].Name == name {
			legacy = &legacyConfigFile{template: files[i].Template.Reveal(), bindings: files[i].Bindings}
			break
		}
	}
	if legacy == nil {
		http.Error(w, "legacy config file not found", http.StatusNotFound)
		return
	}
	bindings, err := s.convertLegacyBindings(project, legacy.bindings)
	if err != nil {
		http.Error(w, "migration rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	svc.ConfigFiles = upsertConfigFileByMount(svc.ConfigFiles, definition.ConfigFile{
		Template: legacy.template, Mount: mount, Bindings: bindings,
	})
	def.Spec.Compose.Services[service] = svc
	if err := s.applyDefinition(r.Context(), project, def, "dashboard: migrate config-file "+name+" → "+service+mount, ""); err != nil {
		http.Error(w, "migration rejected (legacy file kept): "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	_ = s.cfgStore.DeleteConfigFile(r.Context(), project, name) // only after a clean apply
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "config_file_migrate", Target: project + "/" + name + " → " + service + mount, Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/apps/"+project+"/config-files", http.StatusSeeOther)
}

type legacyConfigFile struct {
	template string
	bindings []cfgfile.Binding
}

// convertLegacyBindings maps legacy cfgfile.Binding (Key + "kind:arg" Source) to the
// canonical Binding type. A cert source names a legacy binding NAME; it is remapped to
// that binding's hostname (the canonical references certs by hostname).
func (s *Server) convertLegacyBindings(project string, bs []cfgfile.Binding) (map[string]definition.Binding, error) {
	var certHost map[string]string // legacy binding name → hostname
	out := map[string]definition.Binding{}
	for _, b := range bs {
		kind, arg, err := cfgfile.ParseSource(b.Source)
		if err != nil {
			return nil, err
		}
		switch kind {
		case "secret":
			out[b.Key] = definition.Binding{Secret: arg}
		case "env":
			out[b.Key] = definition.Binding{Env: arg}
		case "app":
			out[b.Key] = definition.Binding{App: arg}
		case "cert":
			if certHost == nil {
				certHost = map[string]string{}
				certs, _ := s.cfgStore.CertBindings(project)
				for _, c := range certs {
					certHost[c.BindingName] = c.Hostname
				}
			}
			bindingName, field, _ := strings.Cut(arg, ".")
			host, ok := certHost[bindingName]
			if !ok {
				return nil, fmt.Errorf("cert binding %q has no hostname — migrate the cert binding first", bindingName)
			}
			out[b.Key] = definition.Binding{Cert: host + "." + field}
		default:
			return nil, fmt.Errorf("unsupported legacy binding source %q", b.Source)
		}
	}
	return out, nil
}

// --- slice helpers (match by the canonical identity: mount / hostname) ---

func upsertConfigFileByMount(list []definition.ConfigFile, e definition.ConfigFile) []definition.ConfigFile {
	for i := range list {
		if list[i].Mount == e.Mount {
			list[i] = e
			return list
		}
	}
	return append(list, e)
}

func removeConfigFileByMount(list []definition.ConfigFile, mount string) []definition.ConfigFile {
	out := list[:0]
	for _, cf := range list {
		if cf.Mount != mount {
			out = append(out, cf)
		}
	}
	return out
}

func upsertCertBindingByHost(list []definition.CertBinding, e definition.CertBinding) []definition.CertBinding {
	for i := range list {
		if list[i].Hostname == e.Hostname {
			list[i] = e
			return list
		}
	}
	return append(list, e)
}

func removeCertBindingByHost(list []definition.CertBinding, hostname string) []definition.CertBinding {
	out := list[:0]
	for _, cb := range list {
		if cb.Hostname != hostname {
			out = append(out, cb)
		}
	}
	return out
}
