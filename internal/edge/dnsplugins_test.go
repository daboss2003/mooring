package edge

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// refreshRig is an installer with an owned build (cloudflare) and, when extras is set, a system caddy
// carrying that plugin. install is the fake InstallPluginBuild; installs and swaps are counted.
type refreshRig struct {
	inst    *DNSPluginInstaller
	state   *DNSPlugins
	dataDir string
	swaps   atomic.Int32
	mu      sync.Mutex
	opts    []InstallOptions
}

func (r *refreshRig) calls() []InstallOptions {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]InstallOptions(nil), r.opts...)
}

func newRefreshRig(t *testing.T, providers []string, extras bool, install func(InstallOptions) (string, error)) *refreshRig {
	t.Helper()
	skipNoShell(t)
	pathDir := t.TempDir()
	if extras {
		writeExec(t, filepath.Join(pathDir, "caddy"), fakeCaddy("v2.11.2 h1:x", []string{"http.handlers.reverse_proxy"},
			map[string]string{"http.handlers.extra": "github.com/acme/caddy-extra"}))
	}
	t.Setenv("PATH", pathDir)
	r := &refreshRig{dataDir: t.TempDir(), state: NewDNSPlugins(providers)}
	writeExec(t, OwnedCaddyPath(r.dataDir), fakeCaddy("v2.11.2 h1:x", []string{"dns.providers.cloudflare"}, nil))
	r.inst = &DNSPluginInstaller{DataDir: r.dataDir, Providers: providers, State: r.state, Log: quietLog(),
		OnSwap: func() { r.swaps.Add(1) },
		Install: func(_ context.Context, opt InstallOptions) (string, error) {
			r.mu.Lock()
			r.opts = append(r.opts, opt)
			r.mu.Unlock()
			return install(opt)
		}}
	if missing := r.inst.Check(context.Background()); len(missing) != 0 {
		t.Fatalf("the owned build must have every provider: missing %v", missing)
	}
	return r
}

func swapIn(t *testing.T) func(InstallOptions) (string, error) {
	return func(opt InstallOptions) (string, error) {
		writeExec(t, OwnedCaddyPath(opt.DataDir), fakeCaddy("v2.11.3 h1:y", []string{"dns.providers.cloudflare"}, nil))
		return OwnedCaddyPath(opt.DataDir), nil
	}
}

// A changed build is swapped in with the same packages the install loop builds, and the edge restarts.
func TestRefreshSwapsAChangedBuild(t *testing.T) {
	r := newRefreshRig(t, []string{"cloudflare"}, true, swapIn(t))
	swapped, err := r.inst.Refresh(context.Background())
	if err != nil || !swapped {
		t.Fatalf("swapped=%v err=%v", swapped, err)
	}
	if r.swaps.Load() != 1 {
		t.Errorf("OnSwap ran %d times; want once", r.swaps.Load())
	}
	calls := r.calls()
	if len(calls) != 1 {
		t.Fatalf("installs = %d", len(calls))
	}
	opt := calls[0]
	if !opt.SkipIfSame || opt.DataDir != r.dataDir ||
		strings.Join(opt.Packages, ",") != "github.com/acme/caddy-extra,github.com/caddy-dns/cloudflare" ||
		strings.Join(opt.WantModules, ",") != "dns.providers.cloudflare" {
		t.Errorf("install options = %+v; want SkipIfSame, every provider plus the system caddy's plugins", opt)
	}
	if st := r.state.Status("cloudflare"); !st.OnDisk || st.Err != "" || st.Installing {
		t.Errorf("provider after the refresh = %+v; want on disk", st)
	}
}

// An identical build is not swapped and the edge isn't restarted; it isn't retried without the plugins.
// The download is still logged, so the daily refresh shows in the journal.
func TestRefreshUnchangedBuildIsNotSwapped(t *testing.T) {
	r := newRefreshRig(t, []string{"cloudflare"}, true, func(InstallOptions) (string, error) { return "", ErrBuildUnchanged })
	var logBuf bytes.Buffer
	r.inst.Log = slog.New(slog.NewTextHandler(&logBuf, nil))
	swapped, err := r.inst.Refresh(context.Background())
	if err != nil || swapped {
		t.Fatalf("swapped=%v err=%v; want (false, nil)", swapped, err)
	}
	if r.swaps.Load() != 0 || len(r.calls()) != 1 {
		t.Errorf("swaps=%d installs=%d; want no restart and one download", r.swaps.Load(), len(r.calls()))
	}
	if !strings.Contains(logBuf.String(), `level=INFO msg="edge: the downloaded Caddy build is the same as the installed one; kept"`) {
		t.Errorf("an unchanged build must be logged at Info:\n%s", logBuf.String())
	}
}

// renameIn puts body at path as a new file (a new identity), the way an install swaps a build in.
func renameIn(t *testing.T, path string, body []byte) {
	t.Helper()
	tmp := path + ".tmp"
	writeExec(t, tmp, body)
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// A refresh swaps in a build already checked for every provider's module: the relaunch onto it keeps
// OK, so the config pushed right after the restart carries the wildcards (no per-name HTTP-01 orders,
// no catch-all name without a certificate). Another file at the path afterwards is read as usual.
func TestRefreshSwapKeepsOKOnTheRelaunch(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "fail")
	r := newRefreshRig(t, []string{"cloudflare"}, false, func(opt InstallOptions) (string, error) {
		renameIn(t, OwnedCaddyPath(opt.DataDir), flakyCaddy(marker, "dns.providers.cloudflare"))
		return OwnedCaddyPath(opt.DataDir), nil
	})
	r.inst.SyncRetry = time.Millisecond
	var okAtSwap atomic.Bool
	r.inst.OnSwap = func() { okAtSwap.Store(r.state.OK("cloudflare")); r.swaps.Add(1) }
	if swapped, err := r.inst.Refresh(context.Background()); !swapped || err != nil {
		t.Fatalf("swapped=%v err=%v", swapped, err)
	}
	if !okAtSwap.Load() {
		t.Error("the running edge still has the module: OK must stay on until the restart")
	}
	// Reading the new build would fail now (a busy host): the relaunch must not need a read.
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	gen := r.inst.Launched()
	if !r.state.OK("cloudflare") {
		t.Fatal("the relaunch onto the refreshed build must keep OK")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if read, enabled := r.inst.Sync(ctx, gen); !read || enabled {
		t.Errorf("Sync on the refreshed build: read=%v enabled=%v; want it taken as read", read, enabled)
	}
	if st := r.state.Status("cloudflare"); !st.OK || st.SyncErr != "" || !st.OnDisk {
		t.Errorf("after the relaunch: %+v; want OK, on disk, no read error", st)
	}

	// A file the refresh didn't check: the normal rules (OK off until Sync has read it).
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	renameIn(t, OwnedCaddyPath(r.dataDir), fakeCaddy("v2.11.4 h1:z", []string{"dns.providers.cloudflare"}, nil))
	gen = r.inst.Launched()
	if r.state.OK("cloudflare") {
		t.Error("a launch on a file the refresh didn't check must clear OK until it is read")
	}
	if read, enabled := r.inst.Sync(ctx, gen); !read || !enabled {
		t.Errorf("Sync on the other file: read=%v enabled=%v; want both", read, enabled)
	}
}

// A refresh while a provider is off (the running edge's modules not read yet) doesn't switch it on: the
// old process runs until the restart, and the relaunch reads the new build, as after an install.
func TestRefreshSwapLeavesAProviderThatIsOffToSync(t *testing.T) {
	r := newRefreshRig(t, []string{"cloudflare"}, false, func(opt InstallOptions) (string, error) {
		renameIn(t, OwnedCaddyPath(opt.DataDir), fakeCaddy("v2.11.3 h1:y", []string{"dns.providers.cloudflare"}, nil))
		return OwnedCaddyPath(opt.DataDir), nil
	})
	// The edge relaunched on a build whose modules haven't been read yet.
	renameIn(t, OwnedCaddyPath(r.dataDir), fakeCaddy("v2.11.2 h1:x", []string{"dns.providers.cloudflare"}, nil))
	r.inst.Launched()
	if r.state.OK("cloudflare") {
		t.Fatal("setup: a launch on an unread build clears OK")
	}
	if swapped, err := r.inst.Refresh(context.Background()); !swapped || err != nil {
		t.Fatalf("swapped=%v err=%v", swapped, err)
	}
	if r.state.OK("cloudflare") {
		t.Error("a refresh must not switch a provider on while the old edge process runs")
	}
	gen := r.inst.Launched()
	if r.state.OK("cloudflare") {
		t.Error("the relaunch must read the new build before its wildcards are rendered")
	}
	if read, enabled := r.inst.Sync(context.Background(), gen); !read || !enabled || !r.state.OK("cloudflare") {
		t.Errorf("Sync on the refreshed build: read=%v enabled=%v ok=%v", read, enabled, r.state.OK("cloudflare"))
	}
}

// A build with the carried plugins that fails is retried with only the DNS providers, like an install.
func TestRefreshRetriesWithoutTheCarriedPlugins(t *testing.T) {
	r := newRefreshRig(t, []string{"cloudflare"}, true, nil)
	ok := swapIn(t)
	r.inst.Install = func(_ context.Context, opt InstallOptions) (string, error) {
		r.mu.Lock()
		r.opts = append(r.opts, opt)
		r.mu.Unlock()
		for _, p := range opt.Packages {
			if p == "github.com/acme/caddy-extra" {
				return "", errors.New("build failed: github.com/acme/caddy-extra doesn't compile")
			}
		}
		return ok(opt)
	}
	swapped, err := r.inst.Refresh(context.Background())
	calls := r.calls()
	if err != nil || !swapped || len(calls) != 2 || strings.Join(calls[1].Packages, ",") != "github.com/caddy-dns/cloudflare" || !calls[1].SkipIfSame {
		t.Fatalf("swapped=%v err=%v calls=%+v", swapped, err, calls)
	}
	if r.swaps.Load() != 1 {
		t.Errorf("swaps = %d", r.swaps.Load())
	}
}

// A failed refresh keeps the current build and the provider state, and returns the error.
func TestRefreshFailureKeepsTheBuild(t *testing.T) {
	r := newRefreshRig(t, []string{"cloudflare"}, false, func(InstallOptions) (string, error) {
		return "", errors.New("edge: Caddy build server answered 502 Bad Gateway")
	})
	swapped, err := r.inst.Refresh(context.Background())
	if swapped || err == nil || errors.Is(err, ErrRefreshTooSoon) || !strings.Contains(err.Error(), "502") {
		t.Fatalf("swapped=%v err=%v", swapped, err)
	}
	if r.swaps.Load() != 0 {
		t.Error("a failed refresh must not restart the edge")
	}
	if st := r.state.Status("cloudflare"); !st.OnDisk || !st.OK || st.Err != "" || st.Attempts != 0 {
		t.Errorf("provider after a failed refresh = %+v; want it unchanged", st)
	}
}

// At most one download per RefreshEvery (default 20h), counted from the previous attempt, failed or not.
// 20h, not 24h: the hook runs after each daily scan, and a few minutes of scan-time jitter must not get
// every other day's refresh refused.
func TestRefreshRateLimit(t *testing.T) {
	if got := (&DNSPluginInstaller{}).refreshEvery(); got != 20*time.Hour {
		t.Errorf("RefreshEvery 0 = %v; want 20h", got)
	}
	fail := true
	r := newRefreshRig(t, []string{"cloudflare"}, false, func(opt InstallOptions) (string, error) {
		if fail {
			return "", errors.New("download failed")
		}
		return OwnedCaddyPath(opt.DataDir), nil
	})
	r.inst.RefreshEvery = time.Hour
	if _, err := r.inst.Refresh(context.Background()); err == nil {
		t.Fatal("the first refresh should fail")
	}
	fail = false
	if swapped, err := r.inst.Refresh(context.Background()); swapped || !errors.Is(err, ErrRefreshTooSoon) {
		t.Fatalf("a second refresh within RefreshEvery: swapped=%v err=%v; want ErrRefreshTooSoon", swapped, err)
	}
	if len(r.calls()) != 1 {
		t.Errorf("installs = %d; a refresh that is too soon must not download", len(r.calls()))
	}
	r.inst.RefreshEvery = 20 * time.Millisecond
	time.Sleep(40 * time.Millisecond)
	if swapped, err := r.inst.Refresh(context.Background()); !swapped || err != nil {
		t.Errorf("after RefreshEvery: swapped=%v err=%v", swapped, err)
	}
}

// Nothing to refresh: no data dir (Mooring as root), no owned build, or the install loop is running
// (it builds a current Caddy itself). None of these uses up the rate limit.
func TestRefreshSkips(t *testing.T) {
	never := func(InstallOptions) (string, error) { t.Error("must not download"); return "", nil }
	r := newRefreshRig(t, []string{"cloudflare"}, false, never)
	r.inst.RefreshEvery = time.Hour

	r.inst.running.Store(true)
	if swapped, err := r.inst.Refresh(context.Background()); swapped || err != nil {
		t.Errorf("install loop running: swapped=%v err=%v", swapped, err)
	}
	r.inst.running.Store(false)

	asRoot := &DNSPluginInstaller{Providers: []string{"cloudflare"}, State: r.state, Log: quietLog(),
		Install: func(context.Context, InstallOptions) (string, error) { t.Error("must not download"); return "", nil }}
	if swapped, err := asRoot.Refresh(context.Background()); swapped || err != nil {
		t.Errorf("no data dir: swapped=%v err=%v", swapped, err)
	}

	none := &DNSPluginInstaller{DataDir: t.TempDir(), State: NewDNSPlugins(nil), Log: quietLog(),
		Install: func(context.Context, InstallOptions) (string, error) { t.Error("must not download"); return "", nil }}
	if swapped, err := none.Refresh(context.Background()); swapped || err != nil {
		t.Errorf("no owned build: swapped=%v err=%v", swapped, err)
	}
	if err := os.MkdirAll(OwnedCaddyPath(none.DataDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if swapped, err := none.Refresh(context.Background()); swapped || err != nil {
		t.Errorf("owned path is a directory: swapped=%v err=%v", swapped, err)
	}

	// The skips didn't count as attempts: nothing was recorded, and a real refresh still runs.
	if _, err := os.Lstat(refreshMarkerPath(r.dataDir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a skipped refresh must not record an attempt: %v", err)
	}
	r.inst.Install = func(_ context.Context, opt InstallOptions) (string, error) { return OwnedCaddyPath(opt.DataDir), nil }
	if swapped, err := r.inst.Refresh(context.Background()); !swapped || err != nil {
		t.Errorf("after the skips: swapped=%v err=%v", swapped, err)
	}
}

// Without dns01 (an owned build `mooring setup` installed for the version) the refresh is a plain
// current build plus the system caddy's plugins.
func TestRefreshWithoutProviders(t *testing.T) {
	r := newRefreshRig(t, nil, true, swapIn(t))
	swapped, err := r.inst.Refresh(context.Background())
	calls := r.calls()
	if err != nil || !swapped || len(calls) != 1 || strings.Join(calls[0].Packages, ",") != "github.com/acme/caddy-extra" ||
		len(calls[0].WantModules) != 0 {
		t.Fatalf("swapped=%v err=%v calls=%+v", swapped, err, calls)
	}
	nilState := &DNSPluginInstaller{DataDir: r.dataDir, Log: quietLog(), RefreshEvery: time.Nanosecond,
		Install: func(_ context.Context, opt InstallOptions) (string, error) { return OwnedCaddyPath(opt.DataDir), nil }}
	if swapped, err := nilState.Refresh(context.Background()); !swapped || err != nil {
		t.Errorf("nil State: swapped=%v err=%v", swapped, err)
	}
}

// Two refreshes at once download once: the second is told a refresh is under way.
func TestRefreshConcurrentCallsDownloadOnce(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	r := newRefreshRig(t, []string{"cloudflare"}, false, func(opt InstallOptions) (string, error) {
		close(entered)
		<-release
		return OwnedCaddyPath(opt.DataDir), nil
	})
	r.inst.RefreshEvery = time.Nanosecond // only the in-flight guard can stop the second call
	type res struct {
		swapped bool
		err     error
	}
	first := make(chan res, 1)
	go func() { s, e := r.inst.Refresh(context.Background()); first <- res{s, e} }()
	<-entered
	if swapped, err := r.inst.Refresh(context.Background()); swapped || !errors.Is(err, ErrRefreshTooSoon) {
		t.Errorf("a refresh while one runs: swapped=%v err=%v; want ErrRefreshTooSoon", swapped, err)
	}
	close(release)
	if got := <-first; !got.swapped || got.err != nil {
		t.Errorf("the first refresh: %+v", got)
	}
	if len(r.calls()) != 1 || r.swaps.Load() != 1 {
		t.Errorf("installs=%d swaps=%d; want one each", len(r.calls()), r.swaps.Load())
	}
}

// A refresh download that passes `version`/`list-modules` but refuses the config the edge serves (the
// daily refresh pulling a new release, or a newer DNS plugin, that rejects a field Mooring renders) is
// never swapped in: a restart onto it would crash-loop the edge, unattended. CheckBuild (serve: `caddy
// validate` of the served config) runs on the download first; on failure the download is deleted, the
// current build and the provider state stay, OnSwap isn't called, and the error says why. A download
// that passes is swapped in as before.
func TestRefreshKeepsABuildThatRefusesTheServedConfig(t *testing.T) {
	skipNoShell(t)
	t.Setenv("PATH", t.TempDir()) // no system caddy
	ctx := context.Background()
	dataDir := t.TempDir()
	mods := []string{"dns.providers.cloudflare"}
	current := configCaddy("v2.11.2 h1:x", mods, false)
	writeExec(t, OwnedCaddyPath(dataDir), current)
	srv, hits := buildServer(t, http.StatusOK, configCaddy("v2.12.0 h1:new", mods, true))
	state := NewDNSPlugins([]string{"cloudflare"})
	var swaps atomic.Int32
	var checked []string
	inst := &DNSPluginInstaller{DataDir: dataDir, Providers: []string{"cloudflare"}, State: state, Log: quietLog(),
		BuildServer: srv.URL, Client: srv.Client(), OnSwap: func() { swaps.Add(1) },
		CheckBuild: func(ctx context.Context, bin string) error {
			checked = append(checked, bin)
			return validateServed(ctx, bin)
		}}
	inst.Check(ctx)
	before := state.Status("cloudflare")

	swapped, err := inst.Refresh(ctx)
	if swapped || !errors.Is(err, ErrBuildCheckFailed) || !strings.Contains(err.Error(), `unknown field "bogus"`) {
		t.Fatalf("swapped=%v err=%v; want no swap and ErrBuildCheckFailed with Caddy's error", swapped, err)
	}
	if swaps.Load() != 0 {
		t.Error("a build that fails the check must not restart the edge")
	}
	if len(checked) != 1 || checked[0] == OwnedCaddyPath(dataDir) {
		t.Errorf("checked %v; want the download (not the installed build), once", checked)
	}
	if got, _ := os.ReadFile(OwnedCaddyPath(dataDir)); !bytes.Equal(got, current) {
		t.Error("the current build must stay in place")
	}
	if left := leftoverDownloads(t, dataDir); len(left) != 0 {
		t.Errorf("the refused download must be deleted: %v", left)
	}
	if _, err := os.Stat(OwnedCaddyPath(dataDir) + ".bak"); !errors.Is(err, os.ErrNotExist) {
		t.Error("caddy.bak must not be touched by a refused download")
	}
	if got := state.Status("cloudflare"); got != before {
		t.Errorf("provider state after a refused refresh = %+v; want it unchanged (%+v)", got, before)
	}
	if hits.Load() != 1 {
		t.Errorf("downloads = %d; want one", hits.Load())
	}

	fixed := configCaddy("v2.12.1 h1:fixed", mods, false)
	srv2, _ := buildServer(t, http.StatusOK, fixed)
	inst.BuildServer, inst.Client, inst.RefreshEvery = srv2.URL, srv2.Client(), time.Nanosecond
	if swapped, err := inst.Refresh(ctx); !swapped || err != nil || swaps.Load() != 1 {
		t.Fatalf("a build that passes the check: swapped=%v err=%v swaps=%d", swapped, err, swaps.Load())
	}
	if got, _ := os.ReadFile(OwnedCaddyPath(dataDir)); !bytes.Equal(got, fixed) {
		t.Error("the build that passed the check must be installed")
	}
	if bak, _ := os.ReadFile(OwnedCaddyPath(dataDir) + ".bak"); !bytes.Equal(bak, current) {
		t.Error("caddy.bak must hold the previous build")
	}
}

// A build that fails the check isn't downloaded again without the carried plugins: they aren't in the
// edge config, so the second build would fail the same way.
func TestRefreshCheckFailureIsNotRetriedWithoutTheCarriedPlugins(t *testing.T) {
	r := newRefreshRig(t, []string{"cloudflare"}, true, nil)
	srv, hits := buildServer(t, http.StatusOK, configCaddy("v2.12.0 h1:new", []string{"dns.providers.cloudflare"}, true))
	r.inst.Install, r.inst.BuildServer, r.inst.Client, r.inst.CheckBuild = nil, srv.URL, srv.Client(), validateServed
	if swapped, err := r.inst.Refresh(context.Background()); swapped || !errors.Is(err, ErrBuildCheckFailed) {
		t.Fatalf("swapped=%v err=%v", swapped, err)
	}
	if hits.Load() != 1 || r.swaps.Load() != 0 {
		t.Errorf("downloads=%d swaps=%d; want one download and no restart", hits.Load(), r.swaps.Load())
	}
}

// The install loop's plugin build gets the same check: one that refuses the served config is deleted,
// the provider shows the install error (retried with backoff like any failed attempt), and nothing is
// swapped; a build that passes is installed and the edge restarts on it.
func TestDNSPluginInstallerChecksTheBuildBeforeTheSwap(t *testing.T) {
	skipNoShell(t)
	pathDir := t.TempDir()
	writeExec(t, filepath.Join(pathDir, "caddy"), configCaddy("v2.11.2 h1:system", []string{"http.handlers.reverse_proxy"}, false))
	t.Setenv("PATH", pathDir)
	ctx := context.Background()
	dataDir := t.TempDir()
	mods := []string{"dns.providers.cloudflare"}
	srv, _ := buildServer(t, http.StatusOK, configCaddy("v2.12.0 h1:new", mods, true))
	state := NewDNSPlugins([]string{"cloudflare"})
	var swaps atomic.Int32
	checks := 0
	inst := &DNSPluginInstaller{DataDir: dataDir, Providers: []string{"cloudflare"}, State: state, Log: quietLog(),
		BuildServer: srv.URL, Client: srv.Client(), OnSwap: func() { swaps.Add(1) },
		CheckBuild: func(ctx context.Context, bin string) error { checks++; return validateServed(ctx, bin) }}
	missing := inst.Check(ctx)
	if len(missing) != 1 {
		t.Fatalf("missing = %v", missing)
	}
	if err := inst.attempt(ctx, missing); !errors.Is(err, ErrBuildCheckFailed) {
		t.Fatalf("attempt: %v; want ErrBuildCheckFailed", err)
	}
	if checks != 1 || swaps.Load() != 0 {
		t.Errorf("checks=%d swaps=%d; want the build checked and no restart", checks, swaps.Load())
	}
	if _, err := os.Stat(OwnedCaddyPath(dataDir)); !errors.Is(err, os.ErrNotExist) {
		t.Error("a build that fails the check must not be installed")
	}
	if left := leftoverDownloads(t, dataDir); len(left) != 0 {
		t.Errorf("the refused download must be deleted: %v", left)
	}
	st := state.Status("cloudflare")
	if known, why := state.KnownMissing("cloudflare"); !known || !strings.Contains(why, `unknown field "bogus"`) || st.OnDisk || st.Installing || st.Attempts != 1 {
		t.Errorf("provider after the refused build = %+v; want known missing with the check's error", st)
	}

	srv2, _ := buildServer(t, http.StatusOK, configCaddy("v2.12.1 h1:fixed", mods, false))
	inst.BuildServer, inst.Client = srv2.URL, srv2.Client()
	if err := inst.attempt(ctx, missing); err != nil {
		t.Fatalf("attempt with a build that passes the check: %v", err)
	}
	if checks != 2 || swaps.Load() != 1 || !state.Status("cloudflare").OnDisk || ResolveCaddy(dataDir) != OwnedCaddyPath(dataDir) {
		t.Errorf("checks=%d swaps=%d status=%+v; want the build installed and the edge restarted", checks, swaps.Load(), state.Status("cloudflare"))
	}
}

// diskShortcutRig is an install loop whose next launch's binary is the owned build at body (put there by
// `mooring setup`, which runs no config check) while the provider is still pending, with a build server
// serving download; every CheckBuild path and every restart is counted.
type diskShortcutRig struct {
	inst    *DNSPluginInstaller
	state   *DNSPlugins
	dataDir string
	hits    *atomic.Int32
	swaps   atomic.Int32
	mu      sync.Mutex
	checked []string
}

func newDiskShortcutRig(t *testing.T, onDisk, download []byte) *diskShortcutRig {
	t.Helper()
	skipNoShell(t)
	t.Setenv("PATH", t.TempDir()) // no system caddy
	r := &diskShortcutRig{dataDir: t.TempDir(), state: NewDNSPlugins([]string{"cloudflare"})}
	writeExec(t, OwnedCaddyPath(r.dataDir), onDisk)
	srv, hits := buildServer(t, http.StatusOK, download)
	r.hits = hits
	r.inst = &DNSPluginInstaller{DataDir: r.dataDir, Providers: []string{"cloudflare"}, State: r.state, Log: quietLog(),
		BuildServer: srv.URL, Client: srv.Client(), OnSwap: func() { r.swaps.Add(1) },
		CheckBuild: func(ctx context.Context, bin string) error {
			r.mu.Lock()
			r.checked = append(r.checked, bin)
			r.mu.Unlock()
			return validateServed(ctx, bin)
		}}
	return r
}

func (r *diskShortcutRig) checks() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.checked...)
}

// The on-disk shortcut (the binary the edge launches next already has every module) gets the same check
// as a download before the edge restarts onto it. One that fails it is not swapped in: the attempt fails
// like an install (the provider shows the error and counts the attempt, Run backs off), and the next
// attempt downloads a fresh build instead of checking the same file again — a refused build on disk
// neither restarts the edge nor holds the install back for good.
func TestDNSPluginInstallerChecksTheBuildOnDisk(t *testing.T) {
	ctx := context.Background()
	mods := []string{"dns.providers.cloudflare"}
	refusing := configCaddy("v2.12.0 h1:setup", mods, true)
	r := newDiskShortcutRig(t, refusing, configCaddy("v2.12.1 h1:fixed", mods, false))
	owned := OwnedCaddyPath(r.dataDir)
	missing := r.inst.pending()
	if len(missing) != 1 {
		t.Fatalf("pending = %v; want the provider", missing)
	}

	err := r.inst.attempt(ctx, missing)
	if err == nil || !strings.Contains(err.Error(), `unknown field "bogus"`) {
		t.Fatalf("attempt onto a build on disk that refuses the served config: %v; want the check's error", err)
	}
	if r.swaps.Load() != 0 || r.hits.Load() != 0 {
		t.Errorf("swaps=%d downloads=%d; want no restart and no download", r.swaps.Load(), r.hits.Load())
	}
	if c := r.checks(); len(c) != 1 || c[0] != owned {
		t.Errorf("checked %v; want the build on disk, once", c)
	}
	st := r.state.Status("cloudflare")
	if known, why := r.state.KnownMissing("cloudflare"); !known || !strings.Contains(why, `unknown field "bogus"`) || st.OnDisk || st.Installing || st.Attempts != 1 {
		t.Errorf("provider after the refused build on disk = %+v; want known missing with the check's error, one attempt", st)
	}
	if got, _ := os.ReadFile(owned); !bytes.Equal(got, refusing) {
		t.Error("the build on disk must be left in place")
	}
	if p := r.inst.pending(); len(p) != 1 {
		t.Fatalf("pending after the refusal = %v; the provider must still be pending", p)
	}

	// Next attempt: the same unchanged file isn't checked again; a fresh build is downloaded, checked and
	// installed, and the edge restarts on it.
	if err := r.inst.attempt(ctx, missing); err != nil {
		t.Fatalf("the attempt after a refused build on disk must download a fresh one: %v", err)
	}
	c := r.checks()
	if r.hits.Load() != 1 || r.swaps.Load() != 1 || len(c) != 2 || c[1] == owned || !r.state.Status("cloudflare").OnDisk {
		t.Errorf("downloads=%d swaps=%d checked=%v status=%+v; want one download, checked, installed and restarted onto",
			r.hits.Load(), r.swaps.Load(), c, r.state.Status("cloudflare"))
	}
}

// A build on disk that passes the check is restarted onto without a download — also when it replaced a
// file at the path that failed it before (another file, so it is checked afresh).
func TestDNSPluginInstallerRestartsOntoACheckedBuildOnDisk(t *testing.T) {
	ctx := context.Background()
	mods := []string{"dns.providers.cloudflare"}
	r := newDiskShortcutRig(t, configCaddy("v2.12.0 h1:setup", mods, true), configCaddy("v2.12.1 h1:dl", mods, true))
	owned := OwnedCaddyPath(r.dataDir)
	missing := r.inst.pending()
	if err := r.inst.attempt(ctx, missing); err == nil {
		t.Fatal("a build on disk that fails the check must fail the attempt")
	}
	passing := configCaddy("v2.12.2 h1:setup-again", mods, false)
	renameIn(t, owned, passing) // `mooring setup` installed another build meanwhile
	if err := r.inst.attempt(ctx, missing); err != nil {
		t.Fatalf("a build on disk that passes the check: %v", err)
	}
	if c := r.checks(); r.hits.Load() != 0 || r.swaps.Load() != 1 || len(c) != 2 || c[1] != owned {
		t.Errorf("downloads=%d swaps=%d checked=%v; want the new file checked and restarted onto, nothing downloaded", r.hits.Load(), r.swaps.Load(), c)
	}
	if st := r.state.Status("cloudflare"); !st.OnDisk || st.Err != "" {
		t.Errorf("provider after the restart onto the build on disk = %+v; want on disk, no error", st)
	}
	if got, _ := os.ReadFile(owned); !bytes.Equal(got, passing) {
		t.Error("the build on disk must be the one restarted onto")
	}
}

// Run treats a refused build on disk as a failed attempt: it waits its backoff before the next one (which
// downloads) instead of retrying at once.
func TestDNSPluginInstallerBacksOffAfterARefusedBuildOnDisk(t *testing.T) {
	mods := []string{"dns.providers.cloudflare"}
	r := newDiskShortcutRig(t, configCaddy("v2.12.0 h1:setup", mods, true), configCaddy("v2.12.1 h1:dl", mods, false))
	r.inst.MinBackoff = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.inst.Run(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for len(r.checks()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	for r.state.Status("cloudflare").NextAttempt.IsZero() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	st := r.state.Status("cloudflare")
	if c := r.checks(); len(c) != 1 || r.hits.Load() != 0 || r.swaps.Load() != 0 {
		t.Errorf("checks=%v downloads=%d swaps=%d; want one check of the build on disk, then the backoff", c, r.hits.Load(), r.swaps.Load())
	}
	if st.NextAttempt.IsZero() || time.Until(st.NextAttempt) < 30*time.Minute {
		t.Errorf("next attempt = %v; want it a backoff away", st.NextAttempt)
	}
}

// refreshMarkerPath is the file Refresh records its last download attempt in.
func refreshMarkerPath(dataDir string) string {
	return filepath.Join(dataDir, filepath.FromSlash(refreshAttemptRel))
}

// restartedInstaller is the installer a Mooring restart builds on r's data dir: no in-memory state, a
// 1h limit, downloads counted (install's result is what each download returns).
func restartedInstaller(r *refreshRig, install func(InstallOptions) (string, error), downloads *atomic.Int32) *DNSPluginInstaller {
	return &DNSPluginInstaller{DataDir: r.dataDir, Providers: r.inst.Providers, State: NewDNSPlugins(r.inst.Providers),
		Log: quietLog(), RefreshEvery: time.Hour,
		Install: func(_ context.Context, opt InstallOptions) (string, error) { downloads.Add(1); return install(opt) }}
}

func unchangedBuild(InstallOptions) (string, error) { return "", ErrBuildUnchanged }

// markerTime reads the recorded attempt (a unix timestamp in seconds).
func markerTime(t *testing.T, dataDir string) time.Time {
	t.Helper()
	b, err := os.ReadFile(refreshMarkerPath(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	sec, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		t.Fatalf("the marker %q is not a unix timestamp: %v", b, err)
	}
	return time.Unix(sec, 0)
}

// The limit is kept across a Mooring restart: the installer a restart builds doesn't download within
// RefreshEvery of the last attempt (failed or not), so a Mooring that restarts often doesn't pull a
// ~50 MB build after every boot. The attempt is a 0600 file next to the build; writing it never
// touches bin/caddy, whose identity (inode, size, mtime) tells the edge which binary it launched.
func TestRefreshRateLimitSurvivesRestart(t *testing.T) {
	r := newRefreshRig(t, []string{"cloudflare"}, false, func(InstallOptions) (string, error) {
		return "", errors.New("download failed")
	})
	r.inst.RefreshEvery = time.Hour
	before, err := os.Stat(OwnedCaddyPath(r.dataDir))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Truncate(time.Second)
	if _, err := r.inst.Refresh(context.Background()); err == nil || errors.Is(err, ErrRefreshTooSoon) {
		t.Fatalf("the first refresh should fail its download: %v", err)
	}
	fi, err := os.Lstat(refreshMarkerPath(r.dataDir))
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the attempt must be recorded as a regular 0600 file: %v %v", fi, err)
	}
	if at := markerTime(t, r.dataDir); at.Before(start) || at.After(time.Now()) {
		t.Errorf("recorded attempt %v; want the time it started (after %v)", at, start)
	}
	after, err := os.Stat(OwnedCaddyPath(r.dataDir))
	if err != nil || !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) || after.Size() != before.Size() {
		t.Errorf("recording the attempt must leave bin/caddy alone: before %v, after %v (%v)", before, after, err)
	}

	var downloads atomic.Int32
	restarted := restartedInstaller(r, unchangedBuild, &downloads)
	if swapped, err := restarted.Refresh(context.Background()); swapped || !errors.Is(err, ErrRefreshTooSoon) {
		t.Fatalf("a refresh after a restart within RefreshEvery: swapped=%v err=%v; want ErrRefreshTooSoon", swapped, err)
	}
	if downloads.Load() != 0 {
		t.Errorf("downloads = %d; a refresh refused by the recorded attempt must not download", downloads.Load())
	}
	restarted.RefreshEvery = 20 * time.Millisecond
	time.Sleep(40 * time.Millisecond)
	if swapped, err := restarted.Refresh(context.Background()); swapped || err != nil || downloads.Load() != 1 {
		t.Errorf("after RefreshEvery: swapped=%v err=%v downloads=%d; want one download", swapped, err, downloads.Load())
	}
}

// A marker that isn't a timestamp (a torn write, an edit by hand) or can't be read sets no limit and
// never fails the refresh; the attempt replaces it with a good one.
func TestRefreshCorruptMarkerSetsNoLimit(t *testing.T) {
	r := newRefreshRig(t, []string{"cloudflare"}, false, unchangedBuild)
	for _, body := range []string{"garbage", "", "  \n", "1.7e9", "12345678901234567890123", "-", strings.Repeat("1", 200)} {
		if err := os.WriteFile(refreshMarkerPath(r.dataDir), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		var downloads atomic.Int32
		if swapped, err := restartedInstaller(r, unchangedBuild, &downloads).Refresh(context.Background()); swapped || err != nil || downloads.Load() != 1 {
			t.Errorf("marker %q: swapped=%v err=%v downloads=%d; want one download, no error", body, swapped, err, downloads.Load())
		}
		if at := markerTime(t, r.dataDir); time.Since(at) > time.Minute {
			t.Errorf("marker %q: the attempt must replace it with the current time, got %v", body, at)
		}
		if _, err := restartedInstaller(r, unchangedBuild, &downloads).Refresh(context.Background()); !errors.Is(err, ErrRefreshTooSoon) {
			t.Errorf("marker %q: the replaced marker must limit the next instance: %v", body, err)
		}
	}

	// A directory at the marker's path can be neither read nor replaced: the refresh still runs, and the
	// in-memory limit still holds for this process.
	if err := os.Remove(refreshMarkerPath(r.dataDir)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(refreshMarkerPath(r.dataDir), 0o700); err != nil {
		t.Fatal(err)
	}
	var downloads atomic.Int32
	inst := restartedInstaller(r, unchangedBuild, &downloads)
	if swapped, err := inst.Refresh(context.Background()); swapped || err != nil || downloads.Load() != 1 {
		t.Errorf("unreadable marker: swapped=%v err=%v downloads=%d; want one download, no error", swapped, err, downloads.Load())
	}
	if _, err := inst.Refresh(context.Background()); !errors.Is(err, ErrRefreshTooSoon) {
		t.Errorf("the in-memory limit must hold when the marker can't be written: %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(r.dataDir, "bin")); len(entries) != 2 {
		t.Errorf("a failed marker write must leave no temp file behind: %v", entries)
	}
}

// A recorded attempt in the future (the clock was set back after it was written) sets no limit: a clock
// change must not block the refresh until the clock catches up. The attempt records the current time.
func TestRefreshFutureMarkerSetsNoLimit(t *testing.T) {
	r := newRefreshRig(t, []string{"cloudflare"}, false, unchangedBuild)
	future := strconv.FormatInt(time.Now().Add(48*time.Hour).Unix(), 10)
	if err := os.WriteFile(refreshMarkerPath(r.dataDir), []byte(future+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var downloads atomic.Int32
	if swapped, err := restartedInstaller(r, unchangedBuild, &downloads).Refresh(context.Background()); swapped || err != nil || downloads.Load() != 1 {
		t.Fatalf("future marker: swapped=%v err=%v downloads=%d; want one download", swapped, err, downloads.Load())
	}
	if at := markerTime(t, r.dataDir); at.After(time.Now()) || time.Since(at) > time.Minute {
		t.Errorf("the attempt must record the current time, got %v", at)
	}
	if _, err := restartedInstaller(r, unchangedBuild, &downloads).Refresh(context.Background()); !errors.Is(err, ErrRefreshTooSoon) {
		t.Errorf("the rewritten marker must limit the next instance: %v", err)
	}
}

// The marker is never read or written through a symlink: a link to a recent timestamp sets no limit,
// the link's target is left alone, and the attempt replaces the link with a regular file. A link to the
// build itself never truncates or rewrites the build.
func TestRefreshMarkerSymlinkIsNotFollowed(t *testing.T) {
	r := newRefreshRig(t, []string{"cloudflare"}, false, unchangedBuild)
	marker := refreshMarkerPath(r.dataDir)
	target := filepath.Join(r.dataDir, "bin", "elsewhere")
	recent := strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)
	if err := os.WriteFile(target, []byte(recent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", marker); err != nil {
		t.Fatal(err)
	}
	var downloads atomic.Int32
	if swapped, err := restartedInstaller(r, unchangedBuild, &downloads).Refresh(context.Background()); swapped || err != nil || downloads.Load() != 1 {
		t.Errorf("symlinked marker: swapped=%v err=%v downloads=%d; want the link ignored (one download)", swapped, err, downloads.Load())
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != recent {
		t.Errorf("the link's target must not be written: %q %v", b, err)
	}
	if fi, err := os.Lstat(marker); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("the attempt must replace the link with a regular file: %v %v", fi, err)
	}

	owned := OwnedCaddyPath(r.dataDir)
	body, err := os.ReadFile(owned)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(owned)
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("caddy", marker); err != nil {
		t.Fatal(err)
	}
	if _, err := restartedInstaller(r, unchangedBuild, &downloads).Refresh(context.Background()); err != nil || downloads.Load() != 2 {
		t.Errorf("marker linked to the build: err=%v downloads=%d", err, downloads.Load())
	}
	after, _ := os.Stat(owned)
	if got, _ := os.ReadFile(owned); !bytes.Equal(got, body) || !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
		t.Error("a marker linked to the build must never write the build")
	}
}

// A symlinked bin dir is refused for the marker, as for an install: nothing is read or written through
// it, even when it points inside data_dir.
func TestRefreshMarkerRefusesSymlinkedBinDir(t *testing.T) {
	skipNoShell(t)
	t.Setenv("PATH", t.TempDir())
	dataDir := t.TempDir()
	realBin := filepath.Join(dataDir, "realbin")
	writeExec(t, filepath.Join(realBin, "caddy"), fakeCaddy("v2.11.2 h1:x", nil, nil))
	recent := strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)
	behind := filepath.Join(realBin, filepath.Base(refreshAttemptRel))
	if err := os.WriteFile(behind, []byte(recent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("realbin", filepath.Join(dataDir, "bin")); err != nil {
		t.Fatal(err)
	}
	var downloads atomic.Int32
	inst := &DNSPluginInstaller{DataDir: dataDir, State: NewDNSPlugins(nil), Log: quietLog(), RefreshEvery: time.Hour,
		Install: func(_ context.Context, opt InstallOptions) (string, error) {
			downloads.Add(1)
			return unchangedBuild(opt)
		}}
	if swapped, err := inst.Refresh(context.Background()); swapped || err != nil || downloads.Load() != 1 {
		t.Errorf("symlinked bin dir: swapped=%v err=%v downloads=%d; want the marker behind it ignored", swapped, err, downloads.Load())
	}
	if b, err := os.ReadFile(behind); err != nil || string(b) != recent {
		t.Errorf("nothing may be written through a symlinked bin dir: %q %v", b, err)
	}
	if entries, _ := os.ReadDir(realBin); len(entries) != 2 {
		t.Errorf("no temp file may be created through a symlinked bin dir: %v", entries)
	}
}
