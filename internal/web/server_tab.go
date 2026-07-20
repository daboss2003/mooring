package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/hostmon"
	"github.com/daboss2003/mooring/internal/imagescan"
	"github.com/daboss2003/mooring/internal/serverinfo"
)

// procTopN bounds the process list so a busy host can't produce an unbounded
// table (and so the per-request /proc scan stays cheap).
const procTopN = 25

// fileReadCap / fileListCap bound the read-only file view.
const (
	fileReadCap = 2 << 20 // 2 MiB
	fileListCap = 2000
)

// serverView backs the main Server page + its live fragment.
type serverView struct {
	// live (host monitor)
	HostOK  bool
	Host    hostmonSampleView
	Procs   []hostmon.Process
	ProcErr string
	At      int64 // unix seconds; the "ts" template renders it localised

	// disk footprint (cached; computed off the request path)
	Footprint      serverinfo.Footprint
	FootprintReady bool

	// release-artifact cleanup
	DebCacheDir string
	Debs        []serverinfo.Deb
	Version     string
	TOTPEnabled bool

	// file view (opt-in)
	FileEnabled bool
	FileRoots   []serverinfo.Root

	// image vulnerability scans (opt-in): per-app Trivy results, worst-first.
	ScanEnabled bool
	Scans       []imagescan.AppScan
}

// hostmonSampleView mirrors hostmon.Sample for the template (kept local so the
// template funcs ratioPct/humanBytes apply cleanly).
type hostmonSampleView struct {
	CPUPercent float64
	Load1      float64
	MemTotal   uint64
	MemUsed    uint64
	DiskTotal  uint64
	DiskUsed   uint64
}

// crumb is one breadcrumb segment in the file view.
type crumb struct {
	Name string
	Rel  string
}

// serverFilesView backs the read-only file browser page.
type serverFilesView struct {
	Enabled  bool
	Roots    []serverinfo.Root
	Root     string
	Rel      string
	Crumbs   []crumb
	Entries  []serverinfo.Entry
	UpRel    string
	HasUp    bool
	IsFile   bool
	FileName string
	Content  string
	Binary   bool
	Err      string
}

// footprintCache holds the last on-disk footprint measurement and refreshes it in
// the background when stale. Sizing Mooring's dirs means a filepath.WalkDir over
// potentially large git stores, which must NEVER run on a request (it would stall
// the page) — so the handler serves the cached value and kicks an async refresh.
type footprintCache struct {
	mu        sync.Mutex
	val       serverinfo.Footprint
	have      bool
	computing bool
	ttl       time.Duration
	targets   func() []serverinfo.Target
}

func newFootprintCache(ttl time.Duration, targets func() []serverinfo.Target) *footprintCache {
	return &footprintCache{ttl: ttl, targets: targets}
}

// get returns the cached footprint (have=false until the first measurement
// finishes) and triggers a background refresh when missing or stale.
func (c *footprintCache) get() (serverinfo.Footprint, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	stale := !c.have || time.Since(c.val.At) > c.ttl
	if stale && !c.computing {
		c.computing = true
		go c.refresh()
	}
	return c.val, c.have
}

func (c *footprintCache) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	fp := serverinfo.MeasureFootprint(ctx, c.targets())
	c.mu.Lock()
	c.val, c.have, c.computing = fp, true, false
	c.mu.Unlock()
}

// footprint returns the lazily-initialized footprint cache.
func (s *Server) footprint() *footprintCache {
	s.footprintOnce.Do(func() {
		s.footprintC = newFootprintCache(5*time.Minute, s.footprintTargets)
	})
	return s.footprintC
}

// footprintTargets are the disjoint directory trees whose sizes the Server tab
// shows. appsRoot is a SIBLING of DataDir (DataDir+"-apps"), so the two don't
// overlap and their sizes sum cleanly.
func (s *Server) footprintTargets() []serverinfo.Target {
	var t []serverinfo.Target
	if s.cfg.DataDir != "" {
		t = append(t,
			serverinfo.Target{Label: "Mooring data (DB, git deploy history, secrets, state)", Path: s.cfg.DataDir},
			serverinfo.Target{Label: "App working dirs (repo clones, generated compose/Dockerfile)", Path: s.appsRoot()},
		)
	}
	return t
}

// fileBrowser builds a read-only browser over the operator's allow-listed roots,
// with the secret/state directories ALWAYS denied (even if mis-listed as a root).
func (s *Server) fileBrowser() *serverinfo.FileBrowser {
	var roots []serverinfo.Root
	for _, r := range s.cfg.Server.FileRoots {
		roots = append(roots, serverinfo.Root{Name: r.Name, Path: r.Path})
	}
	deny := []string{"/etc/mooring", "/root/.ssh", "/etc/ssh", "/etc/shadow"}
	if s.cfg.DataDir != "" {
		deny = append(deny, s.cfg.DataDir, s.appsRoot())
	}
	if s.configPath != "" {
		deny = append(deny, s.configPath, filepath.Dir(s.configPath))
	}
	return serverinfo.NewFileBrowser(roots, deny, fileListCap, fileReadCap)
}

// handleServer renders the read-only Server tab: host monitor, top processes,
// disk footprint, and (when configured) the release-.deb cleanup + file-view link.
func (s *Server) handleServer(w http.ResponseWriter, r *http.Request) {
	v := s.buildServerLive()
	v.Version = s.version
	v.TOTPEnabled = s.security().totpEnabled(sessionUser(r))
	v.DebCacheDir = s.cfg.Server.DebCacheDir
	if debs, err := serverinfo.ListDebs(s.cfg.Server.DebCacheDir, s.version); err == nil {
		v.Debs = debs
	}
	fp, ready := s.footprint().get()
	v.Footprint, v.FootprintReady = fp, ready
	fb := s.fileBrowser()
	v.FileEnabled = fb.Enabled()
	v.FileRoots = fb.Roots()
	v.ScanEnabled = s.cfg.Server.ImageScanOn()
	if s.imageScans != nil {
		if scans, err := s.imageScans.List(r.Context()); err == nil {
			v.Scans = scans
		}
	}
	s.render(w, r, "server.html", tmplData{Title: "Server — Mooring", Server: v, Error: r.URL.Query().Get("err")})
}

// handleServerPartial is the live-polled fragment (host meters + process table).
func (s *Server) handleServerPartial(w http.ResponseWriter, r *http.Request) {
	s.renderPartial(w, "serverlive", tmplData{Server: s.buildServerLive()})
}

// buildServerLive gathers the cheap, always-available live data: host metrics
// (from the read-plane snapshot) and a fresh top-by-memory process list.
func (s *Server) buildServerLive() *serverView {
	v := &serverView{At: time.Now().Unix()}
	if snap := s.snapshot(); snap != nil && snap.HostOK {
		v.HostOK = true
		v.Host = hostmonSampleView{
			CPUPercent: snap.Host.CPUPercent, Load1: snap.Host.Load1,
			MemTotal: snap.Host.MemTotal, MemUsed: snap.Host.MemUsed,
			DiskTotal: snap.Host.DiskTotal, DiskUsed: snap.Host.DiskUsed,
		}
	}
	if procs, err := hostmon.Processes(procTopN); err == nil {
		v.Procs = procs
	} else {
		v.ProcErr = "process list isn't available on this platform"
	}
	return v
}

// handleServerFiles serves the READ-ONLY file view. ?root=&path= select a dir to
// list or a file to read; everything is allow-listed + denied per fileBrowser.
func (s *Server) handleServerFiles(w http.ResponseWriter, r *http.Request) {
	fb := s.fileBrowser()
	v := &serverFilesView{Enabled: fb.Enabled(), Roots: fb.Roots()}
	actor := sessionUser(r)
	peer := ClientIP(r.Context()).String()

	root := r.URL.Query().Get("root")
	rel := cleanRel(r.URL.Query().Get("path"))
	v.Root, v.Rel = root, rel

	if !fb.Enabled() || root == "" {
		s.render(w, r, "server_files.html", tmplData{Title: "Files — Mooring", ServerFiles: v})
		return
	}

	// A trailing component named like a file is ambiguous; try a directory listing
	// first, and fall back to reading it as a file if listing fails as "not a dir".
	entries, listErr := fb.List(root, rel)
	if listErr == nil {
		v.Entries = entries
		v.Crumbs = buildCrumbs(rel)
		v.UpRel, v.HasUp = parentRel(rel)
		s.render(w, r, "server_files.html", tmplData{Title: "Files — Mooring", ServerFiles: v})
		return
	}

	// Not a directory (or denied) — try to read it as a file.
	content, binary, readErr := fb.Read(root, rel)
	if readErr != nil {
		// Report a generic message (don't leak which gate failed) + audit denials.
		v.Err = "can’t open that path"
		if readErr == serverinfo.ErrTooBig {
			v.Err = "file too large to view here"
		}
		_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "server_file_read", Target: root + ":" + rel, Outcome: audit.Deny, Level: audit.Security, Detail: readErr.Error()})
		s.render(w, r, "server_files.html", tmplData{Title: "Files — Mooring", ServerFiles: v})
		return
	}
	v.IsFile = true
	v.FileName = filepath.Base(rel)
	v.Binary = binary
	if !binary {
		v.Content = string(content)
	}
	v.Crumbs = buildCrumbs(rel)
	v.UpRel, v.HasUp = parentRel(rel)
	_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "server_file_read", Target: root + ":" + rel, Outcome: audit.OK, Level: audit.Info})
	s.render(w, r, "server_files.html", tmplData{Title: "Files — Mooring", ServerFiles: v})
}

// handleDebDelete deletes ONE old Mooring .deb from deb_cache_dir. It is a
// destructive action, so — exactly like app delete — it re-authenticates
// (password + TOTP when enabled) behind the same brute-force lockout, never
// touches the running version, and audits the outcome.
func (s *Server) handleDebDelete(w http.ResponseWriter, r *http.Request) {
	actor := sessionUser(r)
	peer := ClientIP(r.Context()).String()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	name := r.PostFormValue("name")

	if s.cfg.Server.DebCacheDir == "" {
		http.Error(w, "no deb_cache_dir configured", http.StatusForbidden)
		return
	}
	if s.locked(r.Context(), peer, actor) {
		_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "deb_delete", Target: name, Outcome: audit.Deny, Level: audit.Security, Detail: "locked out"})
		http.Error(w, "too many attempts — try again later", http.StatusTooManyRequests)
		return
	}
	reauthOK := s.verifyOperatorPassword(r.Context(), actor, r.PostFormValue("password")) &&
		s.verifyTOTPOnce(r.Context(), actor, r.PostFormValue("totp"))
	if !reauthOK {
		s.recordFailure(r.Context(), peer, actor)
		_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "deb_delete", Target: name, Outcome: audit.Deny, Level: audit.Security, Detail: "re-auth failed"})
		s.redirectErr(w, r, "/server", "password or 2FA code incorrect — nothing deleted")
		return
	}
	s.clearFailures(r.Context(), peer, actor)

	if err := serverinfo.DeleteDeb(s.cfg.Server.DebCacheDir, name, s.version); err != nil {
		_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "deb_delete", Target: name, Outcome: audit.Deny, Level: audit.Security, Detail: err.Error()})
		s.redirectErr(w, r, "/server", "could not delete: "+err.Error())
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "deb_delete", Target: name, Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/server", http.StatusSeeOther)
}

// redirectErr redirects to path with an ?err= flash (mirrors redirectAlertsErr).
func (s *Server) redirectErr(w http.ResponseWriter, r *http.Request, path, msg string) {
	http.Redirect(w, r, path+"?err="+url.QueryEscape(msg), http.StatusSeeOther)
}

// cleanRel normalizes a user-supplied relative path: trims slashes/space and drops
// a leading "/" so it's always relative (the browser re-validates containment).
func cleanRel(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "/")
	return p
}

// buildCrumbs splits a rel path into cumulative breadcrumb links.
func buildCrumbs(rel string) []crumb {
	if rel == "" {
		return nil
	}
	parts := strings.Split(rel, "/")
	var out []crumb
	acc := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if acc == "" {
			acc = p
		} else {
			acc = acc + "/" + p
		}
		out = append(out, crumb{Name: p, Rel: acc})
	}
	return out
}

// parentRel returns the parent of rel and whether one exists (rel != root).
func parentRel(rel string) (string, bool) {
	if rel == "" {
		return "", false
	}
	i := strings.LastIndex(rel, "/")
	if i < 0 {
		return "", true // parent is the root
	}
	return rel[:i], true
}

// handleReclaimDisk reclaims dangling docker images + build cache on demand — the disk hog from
// superseded builds. It removes only garbage (docker never prunes a tagged or in-use image; a
// rollback rebuilds), so it's gated by the normal auth+CSRF rather than a re-auth. Streams the
// docker output to the caller (the lc-btn on the Server tab).
func (s *Server) handleReclaimDisk(w http.ResponseWriter, r *http.Request) {
	actor := sessionUser(r)
	peer := ClientIP(r.Context()).String()
	if s.runner == nil {
		http.Error(w, "write plane unavailable", http.StatusServiceUnavailable)
		return
	}
	if ok, reason := s.runner.WriteAllowed(); !ok {
		http.Error(w, reason, http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	clearWriteDeadline(w)
	flusher, _ := w.(http.Flusher)
	emit := func(line string) {
		fmt.Fprintln(w, line)
		if flusher != nil {
			flusher.Flush()
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	// Audit on a non-cancellable ctx so an aborted/timed-out reclaim (the case most worth
	// recording) is still logged even though the request ctx is by then cancelled.
	auditCtx := context.WithoutCancel(ctx)
	emit("$ docker image prune -f   (removing dangling build images)")
	if err := s.runner.PruneImages(ctx, emit); err != nil {
		emit("[failed: " + err.Error() + "]")
		_ = s.audit.Log(auditCtx, audit.Event{Actor: actor, IP: peer, Action: "disk_reclaim", Outcome: audit.Error, Level: audit.Security, Detail: err.Error()})
		return
	}
	if s.cfg.Server.BuildCacheGCOn() {
		keep := s.cfg.Server.BuildCacheKeepSize()
		emit("$ docker builder prune   (keeping " + keep + " of recent cache)")
		if err := s.runner.PruneBuildCache(ctx, keep, emit); err != nil {
			emit("build-cache prune skipped: " + err.Error())
		}
	}
	emit("\n[done] reload the page to see updated disk usage")
	_ = s.audit.Log(auditCtx, audit.Event{Actor: actor, IP: peer, Action: "disk_reclaim", Outcome: audit.OK, Level: audit.Security})
}
