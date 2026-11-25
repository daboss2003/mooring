package web

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/crypto"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/envstore"
	"github.com/daboss2003/mooring/internal/gitstore"
	"github.com/daboss2003/mooring/internal/sandbox"
	"github.com/daboss2003/mooring/internal/secret"
)

// M9 setup-script sandbox (plan §7/§9, Mode 3). OFF by default; every run is
// confirm-token-gated, fail-closed (a live self-test must pass first), counted
// against the global one-docker-child semaphore, and NEVER triggered from an auto
// path. Captured output is treated as hostile data.

// --- single-use confirm-token store (bound to slug + script checksum) ---

type confirmStore struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]confirmEntry
}

type confirmEntry struct {
	slug     string
	checksum string
	exp      time.Time
}

func newConfirmStore(ttl time.Duration) *confirmStore {
	return &confirmStore{ttl: ttl, m: make(map[string]confirmEntry)}
}

func (c *confirmStore) mint(slug, checksum string) string {
	tok := crypto.RandomToken(18)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.m {
		if now.After(e.exp) {
			delete(c.m, k)
		}
	}
	if len(c.m) > 1024 {
		c.m = make(map[string]confirmEntry)
	}
	c.m[tok] = confirmEntry{slug: slug, checksum: checksum, exp: now.Add(c.ttl)}
	return tok
}

// take consumes a token once and reports whether it matches (slug, checksum) and
// is unexpired. A non-match still consumes it (single-use).
func (c *confirmStore) take(tok, slug, checksum string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[tok]
	if !ok {
		return false
	}
	delete(c.m, tok)
	return time.Now().Before(e.exp) && e.slug == slug && e.checksum == checksum
}

// --- view ---

type setupView struct {
	Project       string
	Script        string
	Trigger       string
	Produces      string
	Enabled       bool   // setup.enabled in config
	Available     bool   // jail backend available on this host
	Unavailable   string // why not (fail-closed reason)
	Checksum      string
	ConfirmToken  string
	PlanFindings  []string
	WriteDisabled string
}

func (s *Server) setupLimits() sandbox.Limits {
	return sandbox.Limits{
		WallClock: s.cfg.Setup.WallClock.D(), CPUs: s.cfg.Setup.CPUs,
		MemoryMB: s.cfg.Setup.MemoryMB, PidsLimit: s.cfg.Setup.PidsLimit,
		ScratchMB: s.cfg.Setup.ScratchMB, OutputCapKB: s.cfg.Setup.OutputCapKB,
	}
}

func (s *Server) handleSetupGet(w http.ResponseWriter, r *http.Request) {
	if s.setupStore == nil {
		http.Error(w, "setup unavailable", http.StatusServiceUnavailable)
		return
	}
	project := r.PathValue("project")
	v := &setupView{Project: project, Trigger: sandbox.TriggerNever, Enabled: s.cfg.Setup.Enabled, WriteDisabled: s.writeDisabledReason()}
	avail, why := sandbox.Available()
	v.Available = avail
	v.Unavailable = why
	if ss, ok, _ := s.setupStore.Get(project); ok {
		v.Script = ss.Script
		v.Trigger = ss.Trigger
		v.Produces = strings.Join(ss.Produces, "\n")
		p := sandbox.Plan(ss.Script)
		v.PlanFindings = p.Findings
		v.Checksum = ss.Checksum(s.setupLimits())
		// Mint a single-use confirm token bound to THIS checksum, only when a run
		// could actually proceed (enabled + jail available + write plane armed).
		if s.cfg.Setup.Enabled && avail && v.WriteDisabled == "" {
			v.ConfirmToken = s.setupConfirm.mint(project, v.Checksum)
		}
	}
	s.render(w, r, "setup.html", tmplData{
		Title:     "Setup script — " + project,
		CSRFToken: CSRFToken(r.Context()),
		Username:  sessionUser(r),
		Project:   project,
		Setup:     v,
	})
}

// handleSetupSync ingests the setup script from an uploaded mooring.yaml — the setup
// script is DECLARED in the definition (spec.setup), never typed into the dashboard.
// The file goes through the hardened definition parser; only spec.setup is extracted
// and persisted (encrypted) into the setup store. Running it is still a separate,
// confirm-token-gated step.
func (s *Server) handleSetupSync(w http.ResponseWriter, r *http.Request) {
	if s.setupStore == nil {
		http.Error(w, "setup unavailable", http.StatusServiceUnavailable)
		return
	}
	project := r.PathValue("project")
	if s.cfg.IsProtectedProject(project) {
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	if err := r.ParseMultipartForm(512 << 10); err != nil {
		http.Error(w, "attach your mooring.yaml", http.StatusBadRequest)
		return
	}
	file, hdr, err := r.FormFile("definition")
	if err != nil {
		http.Error(w, "attach your mooring.yaml (field 'definition')", http.StatusBadRequest)
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 512<<10))
	if err != nil {
		http.Error(w, "could not read the upload", http.StatusBadRequest)
		return
	}
	// The name in the messages is the uploaded file's when it is a mooring file name; the browser
	// sends it, so anything else is not echoed.
	name := "mooring.yaml"
	if base := filepath.Base(hdr.Filename); gitstore.ValidMooringFile(base) {
		name = base
	}
	d, err := definition.ParseNamed(raw, name)
	if err != nil {
		msg := "mooring.yaml rejected: " + err.Error()
		if detail := definitionDetail(err); detail != "" {
			msg = "mooring.yaml rejected:\n" + detail
		}
		http.Error(w, msg, http.StatusUnprocessableEntity) // text/plain + nosniff: the excerpt is the upload's own text
		return
	}
	if d.Spec.Setup == nil {
		http.Error(w, "the uploaded mooring.yaml has no spec.setup", http.StatusUnprocessableEntity)
		return
	}
	// auto-setup + git.auto_deploy is a hard reject (plan §7); setupStore.Save re-validates.
	autoDeploy := false
	if s.gitStore != nil {
		if cfg, ok, _ := s.gitStore.Get(project); ok {
			autoDeploy = cfg.AutoDeploy
		}
	}
	ss := sandbox.ScriptSet{Script: d.Spec.Setup.Script, Trigger: d.Spec.Setup.Trigger, Produces: d.Spec.Setup.Produces}
	if err := s.setupStore.Save(r.Context(), project, ss, autoDeploy); err != nil {
		http.Error(w, "setup rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "setup_sync", Target: project, Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/apps/"+project+"/setup", http.StatusSeeOther)
}

func (s *Server) handleSetupDelete(w http.ResponseWriter, r *http.Request) {
	if s.setupStore == nil {
		http.Error(w, "setup unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	project := r.PathValue("project")
	_ = s.setupStore.Delete(r.Context(), project)
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "setup_delete", Target: project, Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/apps/"+project+"/setup", http.StatusSeeOther)
}

// handleSetupRun executes the setup script in the jail — the most dangerous path
// in Mooring, gated at every step (plan §7):
//  1. setup.enabled (config) — else 403.
//  2. NEVER an auto path (this is an operator POST with CSRF).
//  3. single-use confirm token bound to (slug, checksum) + typed app id.
//  4. the §0 write-plane gate (>=1GB).
//  5. sandbox.Available + a LIVE SelfTest immediately before the run (fail-closed).
//  6. the global one-docker-child semaphore.
//  7. capture-as-hostile-data; re-validate before persisting.
func (s *Server) handleSetupRun(w http.ResponseWriter, r *http.Request) {
	if s.setupStore == nil {
		http.Error(w, "setup unavailable", http.StatusServiceUnavailable)
		return
	}
	project := r.PathValue("project")
	actor := sessionUser(r)
	peer := ClientIP(r.Context()).String()
	deny := func(code int, msg, detail string) {
		_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "setup_run", Target: project, Outcome: audit.Deny, Level: audit.Security, Detail: detail})
		http.Error(w, msg, code)
	}

	if !s.cfg.Setup.Enabled {
		deny(http.StatusForbidden, "setup scripts are disabled (set setup.enabled over SSH)", "disabled")
		return
	}
	if s.cfg.IsProtectedProject(project) {
		deny(http.StatusForbidden, "protected project", "protected")
		return
	}
	ss, ok, err := s.setupStore.Get(project)
	if err != nil || !ok {
		http.Error(w, "no setup script", http.StatusNotFound)
		return
	}
	_ = r.ParseForm()
	checksum := ss.Checksum(s.setupLimits())
	// Confirm token must be bound to THIS exact checksum (void on any byte change).
	if !s.setupConfirm.take(r.PostFormValue("confirm_token"), project, checksum) {
		deny(http.StatusForbidden, "stale or missing confirmation; reload the setup page and confirm again", "bad confirm token")
		return
	}
	// Typed app-id confirmation (plan §7).
	if strings.TrimSpace(r.PostFormValue("confirm_app_id")) != project {
		deny(http.StatusUnprocessableEntity, "type the app id exactly to confirm", "app id mismatch")
		return
	}
	if s.runner != nil {
		if allowed, reason := s.runner.WriteAllowed(); !allowed {
			deny(http.StatusForbidden, reason, "write plane gate closed")
			return
		}
	}
	if avail, why := sandbox.Available(); !avail {
		deny(http.StatusServiceUnavailable, "setup sandbox unavailable: "+why, "sandbox unavailable")
		return
	}
	if s.dockerSem == nil {
		http.Error(w, "write plane unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	clearWriteDeadline(w) // long-lived setup stream — exempt from the 60s WriteTimeout
	flusher, _ := w.(http.Flusher)
	writeln := func(format string, a ...any) {
		fmt.Fprintf(w, format+"\n", a...)
		if flusher != nil {
			flusher.Flush()
		}
	}

	// One docker child at a time across the whole process (plan §4).
	if err := s.dockerSem.Acquire(r.Context()); err != nil {
		return
	}
	defer s.dockerSem.Release()

	cfg := sandbox.Config{Image: s.cfg.Setup.Image, Binary: "docker", Limits: s.setupLimits(), UID: os.Getuid(), GID: os.Getgid()}

	// LIVE self-test immediately before the run — fail-closed (plan §7 runtime
	// precondition / §15 escape test).
	writeln("$ verifying sandbox posture (self-test)…")
	if err := sandbox.SelfTest(r.Context(), cfg); err != nil {
		writeln("[blocked: sandbox self-test failed: %v]", err)
		s.recordSetupBlocked(project, checksum, actor)
		_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "setup_run", Target: project, Outcome: audit.Deny, Level: audit.Security, Detail: "self-test failed"})
		return
	}

	// Fresh, Mooring-owned 0700 scratch — the jail's ONLY writable mount.
	scratch, err := os.MkdirTemp(filepath.Dir(s.appRunDir(project)), ".setup-"+project+"-")
	if err != nil {
		writeln("[error: could not create scratch dir]")
		return
	}
	defer os.RemoveAll(scratch)
	_ = os.Chmod(scratch, 0o700)

	runID := s.setupStore.RecordRunStart(context.Background(), project, checksum, actor)
	writeln("$ running setup script in the jail (wall-clock %s)…", s.cfg.Setup.WallClock.D())
	res, runErr := sandbox.Run(r.Context(), cfg, ss, scratch)
	if res.Output != "" {
		writeln("--- script output ---\n%s", res.Output)
	}
	if runErr != nil {
		writeln("[failed: %v]", runErr)
		s.setupStore.RecordRunFinish(context.Background(), runID, "error", res.ExitCode)
		_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "setup_run", Target: project, Outcome: audit.Error, Level: audit.Security})
		return
	}
	if res.ExitCode != 0 {
		writeln("[script exited %d]", res.ExitCode)
		s.setupStore.RecordRunFinish(context.Background(), runID, "error", res.ExitCode)
		return
	}

	// Capture outputs as HOSTILE DATA (validate before persisting).
	captured, cerr := s.captureSetupOutputs(scratch, project, ss, actor)
	if cerr != nil {
		writeln("[capture rejected: %v]", cerr)
		s.setupStore.RecordRunFinish(context.Background(), runID, "error", 0)
		return
	}
	if captured != "" {
		writeln("%s", captured)
	}
	s.setupStore.RecordRunFinish(context.Background(), runID, "ok", 0)
	writeln("\n[done]")
	_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "setup_run", Target: project, Outcome: audit.OK, Level: audit.Security})
}

func (s *Server) recordSetupBlocked(project, checksum, actor string) {
	id := s.setupStore.RecordRunStart(context.Background(), project, checksum, actor)
	s.setupStore.RecordRunFinish(context.Background(), id, "blocked", 0)
}

// captureSetupOutputs ingests the jail's declared outputs (plan §7): env vars
// from a single .mooring.env file (only keys DECLARED in produces, each through
// the hostile-data validators → encrypted store) and declared files (regular,
// size-capped, confined under run_dir, 0600). Anything not declared is ignored.
func (s *Server) captureSetupOutputs(scratch, project string, ss sandbox.ScriptSet, actor string) (string, error) {
	declaredEnv := map[string]bool{}
	var declaredFiles []string
	for _, p := range ss.Produces {
		if strings.HasPrefix(p, "env:") {
			declaredEnv[strings.TrimPrefix(p, "env:")] = true
		} else if strings.HasPrefix(p, "file:") {
			declaredFiles = append(declaredFiles, strings.TrimPrefix(p, "file:"))
		}
	}
	var notes []string

	// env capture from scratch/.mooring.env (KEY=VALUE lines).
	if len(declaredEnv) > 0 && s.envStore != nil {
		envPath := filepath.Join(scratch, ".mooring.env")
		// Same parent-symlink defense as file captures: O_NOFOLLOW guards only the
		// final component, so canonicalize-then-confine the whole path under scratch
		// (a hostile `ln -s /etc /work/.mooring` must not redirect this read).
		if !confinedUnder(envPath, scratch) || noSymlinkComponents(envPath, scratch) != nil {
			return "", fmt.Errorf("env capture resolves outside the scratch dir (symlink?)")
		}
		kv, err := readCapturedEnv(envPath)
		if err != nil {
			return "", err
		}
		cur, _, _ := s.envStore.Current(project)
		next := cur
		added := 0
		for k, v := range kv {
			if !declaredEnv[k] {
				continue // only DECLARED keys are captured
			}
			if err := sandbox.ValidateCapturedEnvKey(k); err != nil {
				return "", err
			}
			if err := sandbox.ValidateCapturedEnvValue(v); err != nil {
				return "", err
			}
			next = upsertSecret(next, k, v)
			added++
		}
		if added > 0 {
			if _, err := s.envStore.Save(context.Background(), project, next, actor); err != nil {
				return "", fmt.Errorf("persist captured env: %w", err)
			}
			notes = append(notes, fmt.Sprintf("captured %d env secret(s)", added))
		}
	}

	// file captures, confined under the run dir, regular-file-only, 0600.
	runDir := s.appRunDir(project)
	for _, rel := range declaredFiles {
		srcDest, err := sandbox.ConfineCapturePath(scratch, rel)
		if err != nil {
			return "", err
		}
		dst, err := sandbox.ConfineCapturePath(runDir, rel)
		if err != nil {
			return "", err
		}
		// A hostile script can plant a SYMLINKED PARENT in scratch (e.g. ln -s /etc
		// certs) — O_NOFOLLOW only guards the final component, so resolve symlinks on
		// the whole source path and re-confine it under scratch before reading
		// (canonicalize-then-confine; plan §7). This blocks the host-file-read primitive.
		if !confinedUnder(srcDest, scratch) || noSymlinkComponents(srcDest, scratch) != nil {
			return "", fmt.Errorf("capture %q resolves outside the scratch dir (symlink?)", rel)
		}
		data, err := readRegularCapped(srcDest, int64(s.cfg.Setup.OutputCapKB)<<10*4)
		if err != nil {
			return "", fmt.Errorf("capture %q: %w", rel, err)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return "", err
		}
		// Symlink-safe destination (a parent-symlink in run_dir must not redirect
		// the write outside it).
		if !confinedUnder(dst, runDir) || noSymlinkComponents(dst, runDir) != nil {
			return "", fmt.Errorf("capture %q escapes the app directory", rel)
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			return "", fmt.Errorf("write capture %q: %w", rel, err)
		}
		notes = append(notes, fmt.Sprintf("captured file %s (0600)", rel))
	}
	if len(notes) == 0 {
		return "", nil
	}
	return "captured: " + strings.Join(notes, "; "), nil
}

// readCapturedEnv reads KEY=VALUE lines from a regular, size-capped file.
func readCapturedEnv(path string) (map[string]string, error) {
	data, err := readRegularCapped(path, 256<<10)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no env file produced — fine
		}
		return nil, err
	}
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '='); i > 0 {
			out[strings.TrimSpace(line[:i])] = line[i+1:]
		}
	}
	return out, nil
}

// readRegularCapped reads a path with O_NOFOLLOW (no symlink), asserting a regular
// file and a size cap on the open descriptor (capture-as-hostile-data).
func readRegularCapped(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("file exceeds the %d-byte capture cap", max)
	}
	buf := make([]byte, fi.Size())
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// upsertSecret replaces (or adds) a captured value as a SECRET env entry (opaque,
// masked — never re-expanded through compose interpolation).
func upsertSecret(entries []envstore.Entry, key, value string) []envstore.Entry {
	out := make([]envstore.Entry, 0, len(entries)+1)
	for _, e := range entries {
		if e.Key != key {
			out = append(out, e)
		}
	}
	return append(out, envstore.Entry{Key: key, Value: secret.New(value), Secret: true})
}
