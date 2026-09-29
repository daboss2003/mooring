package web

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/cfgfile"
	"github.com/daboss2003/mooring/internal/compose"
	"github.com/daboss2003/mooring/internal/envimport"
	"github.com/daboss2003/mooring/internal/envstore"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/secret"
)

// envKeyForm validates an env var name typed in the dashboard.
var envKeyForm = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// envEntryView is a template-safe view of one env entry (no plaintext for secrets).
type envEntryView struct {
	Key    string
	Value  string // masked for secrets
	Secret bool
}

type fileSecretView struct {
	Name    string
	Path    string
	Present bool
	Mode    string
}

func (s *Server) handleEnvGet(w http.ResponseWriter, r *http.Request) {
	if s.envStore == nil {
		http.Error(w, "env store unavailable", http.StatusServiceUnavailable)
		return
	}
	project := r.PathValue("project")
	entries, version, err := s.envStore.Current(project)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := tmplData{
		Title:      "Env — " + project,
		CSRFToken:  CSRFToken(r.Context()),
		Username:   sessionUser(r),
		Project:    project,
		BackURL:    s.appBackURL(project),
		EnvVersion: version,
	}
	var literals []string
	for _, e := range entries {
		if e.Secret {
			data.EnvSecrets = append(data.EnvSecrets, envEntryView{Key: e.Key, Value: secret.Marker, Secret: true})
		} else {
			literals = append(literals, e.Key+"="+e.Value.Reveal())
			data.EnvLiterals = append(data.EnvLiterals, envEntryView{Key: e.Key, Value: e.Value.Reveal()})
		}
	}
	sort.Strings(literals)
	data.EnvLiteralText = strings.Join(literals, "\n")
	if vs, _ := s.envStore.Versions(project); vs != nil {
		for _, v := range vs {
			data.EnvVersions = append(data.EnvVersions, v)
		}
	}
	data.FileSecrets = s.fileSecretsForApp(project)
	s.render(w, r, "env.html", data)
}

// handleEnvSaveLiterals replaces all NON-secret entries from a dotenv textarea,
// preserving existing secret entries.
func (s *Server) handleEnvSaveLiterals(w http.ResponseWriter, r *http.Request) {
	if s.envStore == nil {
		http.Error(w, "env store unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	project := r.PathValue("project")
	cur, _, err := s.envStore.Current(project)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// keep existing secrets; replace literals with the parsed textarea
	next := keepSecrets(cur)
	for k, v := range compose.ParseEnvFile([]byte(r.PostFormValue("literals"))) {
		next = append(next, envstore.Entry{Key: k, Value: secret.New(v), Secret: false})
	}
	s.saveEnv(w, r, project, next, "env_save_literals")
}

func (s *Server) handleEnvSetSecret(w http.ResponseWriter, r *http.Request) {
	if s.envStore == nil {
		http.Error(w, "env store unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	project := r.PathValue("project")
	key := strings.TrimSpace(r.PostFormValue("key"))
	val := r.PostFormValue("value")
	if key == "" || val == "" {
		http.Redirect(w, r, "/apps/"+project+"/env", http.StatusSeeOther)
		return
	}
	cur, _, err := s.envStore.Current(project)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// upsert the secret entry
	next := make([]envstore.Entry, 0, len(cur)+1)
	for _, e := range cur {
		if e.Key != key {
			next = append(next, e)
		}
	}
	next = append(next, envstore.Entry{Key: key, Value: secret.New(val), Secret: true})
	s.saveEnv(w, r, project, next, "env_set_secret")
}

func (s *Server) handleEnvRemoveSecret(w http.ResponseWriter, r *http.Request) {
	if s.envStore == nil {
		http.Error(w, "env store unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	project := r.PathValue("project")
	key := strings.TrimSpace(r.PostFormValue("key"))
	cur, _, err := s.envStore.Current(project)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	next := make([]envstore.Entry, 0, len(cur))
	for _, e := range cur {
		if e.Key != key {
			next = append(next, e)
		}
	}
	s.saveEnv(w, r, project, next, "env_remove_secret")
}

// handleEnvAddLiteral upserts ONE non-secret variable from key+value fields (the
// per-row editor), preserving every other entry. A value that trips the literal-
// secret lint is rejected with a pointer to the Secret field — a plain literal is
// stored in clear, so an obvious secret must not land here.
func (s *Server) handleEnvAddLiteral(w http.ResponseWriter, r *http.Request) {
	if s.envStore == nil {
		http.Error(w, "env store unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	project := r.PathValue("project")
	key := strings.TrimSpace(r.PostFormValue("key"))
	val := r.PostFormValue("value")
	if key == "" {
		http.Redirect(w, r, "/apps/"+project+"/env", http.StatusSeeOther)
		return
	}
	if !envKeyForm.MatchString(key) {
		http.Error(w, "invalid key: must match [A-Za-z_][A-Za-z0-9_]*", http.StatusUnprocessableEntity)
		return
	}
	if reason, hit := cfgfile.LiteralSecretLint([]byte(val)); hit {
		http.Error(w, "that value "+reason+" — use the Secret field instead so it's stored masked", http.StatusUnprocessableEntity)
		return
	}
	cur, _, err := s.envStore.Current(project)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	next := make([]envstore.Entry, 0, len(cur)+1)
	for _, e := range cur {
		if e.Key != key {
			next = append(next, e)
		}
	}
	next = append(next, envstore.Entry{Key: key, Value: secret.New(val), Secret: false})
	s.saveEnv(w, r, project, next, "env_add_literal")
}

// handleEnvRemoveLiteral drops one non-secret variable by key.
func (s *Server) handleEnvRemoveLiteral(w http.ResponseWriter, r *http.Request) {
	if s.envStore == nil {
		http.Error(w, "env store unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	project := r.PathValue("project")
	key := strings.TrimSpace(r.PostFormValue("key"))
	cur, _, err := s.envStore.Current(project)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	next := make([]envstore.Entry, 0, len(cur))
	for _, e := range cur {
		if e.Key != key {
			next = append(next, e)
		}
	}
	s.saveEnv(w, r, project, next, "env_remove_literal")
}

// handleEnvImport ingests an uploaded .env file (pick-a-file): it is parsed,
// hygiene-checked, and CLASSIFIED (biased toward secret) by the same code path as
// `mooring secret import`, with the override-proof literal-secret HARD STOP — so an
// obvious secret in the file is stored masked, never as a clear literal. Parsed
// entries are upserted into the current set (existing keys updated, others kept).
func (s *Server) handleEnvImport(w http.ResponseWriter, r *http.Request) {
	if s.envStore == nil {
		http.Error(w, "env store unavailable", http.StatusServiceUnavailable)
		return
	}
	project := r.PathValue("project")
	f, _, err := r.FormFile("envfile")
	if err != nil {
		http.Error(w, "choose a .env file to import", http.StatusBadRequest)
		return
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 256<<10)) // bounded
	if err != nil {
		http.Error(w, "could not read the file", http.StatusBadRequest)
		return
	}
	entries, err := envimport.Parse(raw) // parse + hygiene + classify (biased secret)
	if err != nil {
		http.Error(w, "import rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := envimport.ValidateForIngest(entries); err != nil {
		http.Error(w, "import rejected: "+err.Error(), http.StatusUnprocessableEntity) // literal-secret hard stop
		return
	}
	cur, _, err := s.envStore.Current(project)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	merged := map[string]envstore.Entry{}
	for _, e := range cur {
		merged[e.Key] = e
	}
	for _, e := range entries {
		merged[e.Key] = envstore.Entry{Key: e.Key, Value: e.Value, Secret: e.Secret}
	}
	next := make([]envstore.Entry, 0, len(merged))
	for _, e := range merged {
		next = append(next, e)
	}
	s.saveEnv(w, r, project, next, "env_import_file")
}

// handleEnvReveal returns one value as text/plain, no-store, audited (plan §5.5).
func (s *Server) handleEnvReveal(w http.ResponseWriter, r *http.Request) {
	if s.envStore == nil {
		http.Error(w, "env store unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	project := r.PathValue("project")
	if !s.envEditable(w, project) {
		return
	}
	key := strings.TrimSpace(r.PostFormValue("key"))
	val, ok, err := s.envStore.Reveal(project, key)
	if err != nil || !ok {
		// Audit failed/probing reveals too (review #4).
		_ = s.audit.Log(r.Context(), audit.Event{
			Actor: sessionUser(r), IP: ClientIP(r.Context()).String(),
			Action: "env_reveal", Target: project + "/" + key, Outcome: audit.Deny, Level: audit.Security,
			Detail: "not found",
		})
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{
		Actor: sessionUser(r), IP: ClientIP(r.Context()).String(),
		Action: "env_reveal", Target: project + "/" + key, Outcome: audit.OK, Level: audit.Security,
	})
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(val))
}

func (s *Server) handleEnvRollback(w http.ResponseWriter, r *http.Request) {
	if s.envStore == nil {
		http.Error(w, "env store unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	project := r.PathValue("project")
	if !s.envEditable(w, project) {
		return
	}
	version, _ := strconv.Atoi(r.PostFormValue("version"))
	if _, err := s.envStore.Rollback(r.Context(), project, version, sessionUser(r)); err != nil {
		http.Error(w, "rollback failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{
		Actor: sessionUser(r), IP: ClientIP(r.Context()).String(),
		Action: "env_rollback", Target: project, Outcome: audit.OK, Level: audit.Security,
		Detail: "to v" + strconv.Itoa(version),
	})
	http.Redirect(w, r, "/apps/"+project+"/env", http.StatusSeeOther)
}

// saveEnv persists a new env version and redirects. Validation errors are shown
// to the operator; internal errors are kept generic (no raw-error leak, review #9).
func (s *Server) saveEnv(w http.ResponseWriter, r *http.Request, project string, entries []envstore.Entry, action string) {
	if !s.envEditable(w, project) {
		return
	}
	if _, err := s.envStore.Save(r.Context(), project, entries, sessionUser(r)); err != nil {
		if isEnvValidationErr(err) {
			http.Error(w, "invalid env: "+err.Error(), http.StatusUnprocessableEntity)
		} else {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{
		Actor: sessionUser(r), IP: ClientIP(r.Context()).String(),
		Action: action, Target: project, Outcome: audit.OK, Level: audit.Security,
	})
	http.Redirect(w, r, "/apps/"+project+"/env", http.StatusSeeOther)
}

// isEnvValidationErr reports whether err is an operator-facing env validation
// error (safe to echo) vs an internal error (kept generic).
func isEnvValidationErr(err error) bool {
	return errors.Is(err, envstore.ErrBadKey) ||
		errors.Is(err, envstore.ErrBadValue) ||
		strings.Contains(err.Error(), "duplicate key")
}

// envEditable reports whether a project's env may be changed/revealed. Protected
// projects (the edge / socket-proxy) are off-limits, mirroring lifecycle (#7/#11).
func (s *Server) envEditable(w http.ResponseWriter, project string) bool {
	if s.cfg.IsProtectedProject(project) {
		http.Error(w, "this is a protected project; its environment is not editable", http.StatusForbidden)
		return false
	}
	return true
}

func keepSecrets(entries []envstore.Entry) []envstore.Entry {
	var out []envstore.Entry
	for _, e := range entries {
		if e.Secret {
			out = append(out, e)
		}
	}
	return out
}

// fileSecretsForApp reads the app's compose top-level file secrets and stats them
// (present/missing + mode) WITHOUT reading their contents (plan §7).
func (s *Server) fileSecretsForApp(project string) []fileSecretView {
	var app *monitor.App
	if snap := s.snapshot(); snap != nil {
		app = snap.AppByProject(project)
	}
	if app == nil || len(app.ConfigFiles) == 0 {
		return nil
	}
	env := s.composeEnv(app)
	var out []fileSecretView
	seen := map[string]bool{}
	for _, f := range app.ConfigFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		rd := filepath.Clean(app.WorkingDir)
		for _, fs := range compose.FileSecrets(data, env) {
			dedup := fs.Name + "\x00" + fs.Path // dedupe by name+path (review #8)
			if seen[dedup] {
				continue
			}
			seen[dedup] = true
			v := fileSecretView{Name: fs.Name, Path: fs.Path}
			p := fs.Path
			if !filepath.IsAbs(p) && app.WorkingDir != "" {
				p = filepath.Join(app.WorkingDir, p)
			}
			p = filepath.Clean(p)
			// Confine the stat under run_dir (review #3): never disclose the
			// presence/mode of an arbitrary host path (e.g. /etc/shadow).
			if app.WorkingDir == "" || !pathUnder(p, rd) {
				v.Mode = "(outside app directory)"
			} else if fi, err := os.Stat(p); err == nil {
				v.Present = true
				v.Mode = fi.Mode().Perm().String()
			}
			out = append(out, v)
		}
	}
	return out
}

// composeEnv builds the env used for BOTH §5.6 validation and the deploy
// --env-file, so validate == deploy. The store overlays the project .env (M5);
// after env-import (M17) the store becomes authoritative.
func (s *Server) composeEnv(app *monitor.App) compose.Env {
	env := compose.Env{}
	if app.WorkingDir != "" {
		if data, err := os.ReadFile(filepath.Join(app.WorkingDir, ".env")); err == nil {
			env = compose.ParseEnvFile(data)
		}
	}
	if s.envStore != nil {
		if rendered, err := s.envStore.Render(app.Project); err == nil {
			for k, v := range rendered {
				env[k] = v // store overrides .env
			}
		}
	}
	// docker compose recursively expands ${VAR} inside env values; our YAML
	// interpolation is single-pass, so a value like IMG="alpine:${TAG}" would be
	// validated un-expanded (validate != deploy, review #2). Pre-expand env values
	// to a fixpoint so the validator sees the fully-resolved values compose will.
	return resolveEnvValues(env)
}

// resolveEnvValues expands ${VAR} references that appear INSIDE env values, using
// the env map itself, until stable (capped). Over-resolving relative to compose's
// forward-reference rules is safe for validation (the validator only gets stricter).
func resolveEnvValues(env compose.Env) compose.Env {
	for pass := 0; pass < 10; pass++ {
		changed := false
		for k, v := range env {
			if nv := compose.Interpolate(v, env); nv != v {
				env[k] = nv
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return env
}

// renderEnvFile writes the merged env to a 0600 Mooring-owned file and returns
// its path + cleanup, but only when the store holds entries (else compose loads
// the project .env itself — identical result). Mooring owns the live env.
func (s *Server) renderEnvFile(app *monitor.App, env compose.Env) (string, func(), error) {
	noop := func() {}
	if s.envStore == nil {
		return "", noop, nil
	}
	entries, _, err := s.envStore.Current(app.Project)
	if err != nil || len(entries) == 0 {
		return "", noop, nil
	}
	dir := filepath.Join(s.cfg.DataDir, "envfiles")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", noop, err
	}
	// A UNIQUE, freshly-created 0600 file per deploy (review #1/#6): CreateTemp's
	// random suffix means distinct/colliding project names never share a file
	// (no cross-app secret leak), concurrent deploys never race on it, and the
	// O_EXCL create can't follow a pre-existing symlink.
	f, err := os.CreateTemp(dir, sanitizeProject(app.Project)+"-*.env")
	if err != nil {
		return "", noop, err
	}
	path := f.Name()
	cleanup := func() { _ = os.Remove(path) }
	_ = f.Chmod(0o600)

	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	var dropped []string
	for _, k := range keys {
		// Sanitize against env-file injection on the .env-merge path (review
		// #5/#10): the store validates on save, but .env values from disk do not
		// go through it. Skip any unsafe key/value rather than emit a broken line.
		if !envKeyRe.MatchString(k) {
			continue
		}
		// This file is compose's --env-file (interpolation only — container env comes from the
		// generated `environment:` entries). Compose also reads its own control variables from it, so
		// an app env key like COMPOSE_PROFILES=mooring-scheduled would start scheduled services on every
		// `up`, COMPOSE_PROJECT_NAME / COMPOSE_FILE / COMPOSE_COMPATIBILITY would change what a compose
		// command acts on, and DOCKER_DEFAULT_PLATFORM would force a foreign build platform. Mooring owns
		// all of that: those keys are never passed through. Other COMPOSE_-prefixed names (an app's own
		// COMPOSE_TOKEN, say) are ordinary variables and still render. (dockerexec's minimalEnv also pins
		// the dangerous ones in the process environment, which covers the repo's own .env when no
		// --env-file is passed.)
		if composeControlKeys[k] {
			dropped = append(dropped, k)
			continue
		}
		v := strings.TrimRight(env[k], "\r")
		if strings.ContainsAny(v, "\x00\n\r") {
			continue
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		cleanup()
		return "", noop, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", noop, err
	}
	if len(dropped) > 0 && s.log != nil {
		// Key names only — never values.
		s.log.Warn("env file: ignored compose control variables (Mooring sets these itself)", "app", app.Project, "keys", strings.Join(dropped, ","))
	}
	return path, cleanup, nil
}

// envKeyRe mirrors envstore.keyRe for the .env-merge sanitization path.
// composeControlKeys are Docker Compose's own settings (its documented pre-defined environment
// variables) plus the build-platform override. Compose reads them from an env file; Mooring sets them.
var composeControlKeys = map[string]bool{
	"COMPOSE_PROJECT_NAME": true, "COMPOSE_FILE": true, "COMPOSE_PROFILES": true, "COMPOSE_PATH_SEPARATOR": true,
	"COMPOSE_COMPATIBILITY": true, "COMPOSE_IGNORE_ORPHANS": true, "COMPOSE_REMOVE_ORPHANS": true,
	"COMPOSE_CONVERT_WINDOWS_PATHS": true, "COMPOSE_PARALLEL_LIMIT": true, "COMPOSE_ENV_FILES": true,
	"COMPOSE_DISABLE_ENV_FILE": true, "COMPOSE_BAKE": true, "COMPOSE_MENU": true, "COMPOSE_EXPERIMENTAL": true,
	"COMPOSE_ANSI": true, "COMPOSE_STATUS_STDOUT": true, "COMPOSE_PROGRESS": true, "COMPOSE_HTTP_TIMEOUT": true,
	"COMPOSE_TLS_VERSION": true, "DOCKER_DEFAULT_PLATFORM": true,
}

var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// pathUnder reports whether p is within dir (p == dir or a descendant).
func pathUnder(p, dir string) bool {
	if dir == "" {
		return false
	}
	if p == dir {
		return true
	}
	return strings.HasPrefix(p, dir+string(filepath.Separator))
}

func sanitizeProject(p string) string {
	var b strings.Builder
	for _, r := range p {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "app"
	}
	return b.String()
}
