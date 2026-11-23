package edge

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// heldByConfig is a CheckBuild error caused by the edge config Caddy refuses rather than by the build
// (serve's *edgeRestartHeld when the candidate refuses the refused render too, or the running Caddy
// accepts it too).
type heldByConfig struct{ msg string }

func (e heldByConfig) Error() string        { return e.msg }
func (e heldByConfig) Is(target error) bool { return target == ErrHeldByConfig }

// heldReason is what the held check says: Caddy's refusal of the current render.
const heldReason = `Caddy refuses the current edge config and so does the new Caddy: json: unknown field "bogus"`

// heldRig is an install loop for cloudflare with a TLS build server serving a build every check accepts
// unless verdict says otherwise, and a refused render the test sets (nil = Caddy refuses nothing).
// Downloads, checks and restarts are counted.
type heldRig struct {
	inst    *DNSPluginInstaller
	state   *DNSPlugins
	dataDir string
	hits    *atomic.Int32
	swaps   atomic.Int32

	mu      sync.Mutex
	verdict error  // what CheckBuild returns
	render  []byte // what RefusedRender returns
	checked []string
	during  func() // runs inside CheckBuild (a render changing mid-check)
}

func newHeldRig(t *testing.T, onDisk []byte) *heldRig {
	t.Helper()
	skipNoShell(t)
	t.Setenv("PATH", t.TempDir()) // no system caddy
	r := &heldRig{dataDir: t.TempDir(), state: NewDNSPlugins([]string{"cloudflare"})}
	if onDisk != nil {
		writeExec(t, OwnedCaddyPath(r.dataDir), onDisk)
	}
	srv, hits := buildServer(t, http.StatusOK, configCaddy("v2.12.1 h1:dl", []string{"dns.providers.cloudflare"}, false))
	r.hits = hits
	r.inst = &DNSPluginInstaller{DataDir: r.dataDir, Providers: []string{"cloudflare"}, State: r.state, Log: quietLog(),
		BuildServer: srv.URL, Client: srv.Client(), OnSwap: func() { r.swaps.Add(1) },
		CheckBuild: func(context.Context, string) error {
			r.mu.Lock()
			during := r.during
			r.mu.Unlock()
			if during != nil {
				during()
			}
			r.mu.Lock()
			defer r.mu.Unlock()
			r.checked = append(r.checked, "x")
			return r.verdict
		},
		RefusedRender: func() []byte {
			r.mu.Lock()
			defer r.mu.Unlock()
			return append([]byte(nil), r.render...)
		}}
	return r
}

func (r *heldRig) set(verdict error, render string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verdict = verdict
	r.render = nil
	if render != "" {
		r.render = []byte(render)
	}
}

func (r *heldRig) checks() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.checked)
}

// While Caddy refuses the current render for a reason no build fixes (the check of a download says so:
// ErrHeldByConfig), the install loop doesn't download another ~50 MB build that would fail the same way.
// The attempt fails at once, recorded like a failed install with a message that says what it waits for.
// A different refused render, or Caddy accepting one, makes the next attempt download again.
func TestDNSPluginInstallerWaitsForTheConfigAfterAHeldBuild(t *testing.T) {
	ctx := context.Background()
	r := newHeldRig(t, nil)
	missing := r.inst.pending()
	if len(missing) != 1 {
		t.Fatalf("pending = %v", missing)
	}
	r.set(heldByConfig{heldReason}, `{"render":1}`)

	err := r.inst.attempt(ctx, missing)
	if !errors.Is(err, ErrBuildCheckFailed) || !errors.Is(err, ErrHeldByConfig) || r.hits.Load() != 1 {
		t.Fatalf("first attempt: err=%v downloads=%d; want one download that fails its check because of the config", err, r.hits.Load())
	}

	// The same refused render: no download, no check, a recorded failure that says why.
	err = r.inst.attempt(ctx, missing)
	if !errors.Is(err, ErrHeldByConfig) || !strings.Contains(err.Error(), "waiting for Caddy to accept the edge config: ") ||
		!strings.Contains(err.Error(), `unknown field "bogus"`) {
		t.Fatalf("attempt while the same render is refused: %v; want it to wait for the config with Caddy's reason", err)
	}
	if r.hits.Load() != 1 || r.checks() != 1 || r.swaps.Load() != 0 {
		t.Errorf("downloads=%d checks=%d swaps=%d; want no download, check or restart while the same render is refused", r.hits.Load(), r.checks(), r.swaps.Load())
	}
	st := r.state.Status("cloudflare")
	if known, why := r.state.KnownMissing("cloudflare"); !known || !strings.Contains(why, "waiting for Caddy to accept the edge config") || st.Attempts != 2 || st.Installing || st.OnDisk {
		t.Errorf("provider while waiting = %+v; want a recorded failure (known missing, the wait in Err, two attempts)", st)
	}

	// Another refused render: the next attempt downloads (the new render may be one a build fixes).
	r.set(heldByConfig{heldReason}, `{"render":2}`)
	if err := r.inst.attempt(ctx, missing); !errors.Is(err, ErrBuildCheckFailed) || r.hits.Load() != 2 {
		t.Fatalf("a different refused render: err=%v downloads=%d; want a download, held again", err, r.hits.Load())
	}
	if err := r.inst.attempt(ctx, missing); !errors.Is(err, ErrHeldByConfig) || r.hits.Load() != 2 {
		t.Fatalf("the new refused render is remembered: err=%v downloads=%d", err, r.hits.Load())
	}

	// Caddy accepts a render: the next attempt downloads and installs.
	r.set(nil, "")
	if err := r.inst.attempt(ctx, missing); err != nil || r.hits.Load() != 3 || r.swaps.Load() != 1 {
		t.Fatalf("after Caddy accepted the config: err=%v downloads=%d swaps=%d; want the build downloaded, installed and restarted onto", err, r.hits.Load(), r.swaps.Load())
	}
	if st := r.state.Status("cloudflare"); !st.OnDisk || st.Err != "" {
		t.Errorf("provider after the install = %+v", st)
	}
}

// Only a check failure caused by the refused config stops the downloads, and only while the render it
// was checked against is still the refused one before and after the check. Every other failure keeps
// today's behaviour: the next attempt downloads.
func TestDNSPluginInstallerKeepsDownloadingForOtherCheckFailures(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		verdict error
		render  string
		hook    bool           // RefusedRender set
		during  func(*heldRig) // runs inside the first check
		between func(*heldRig) // runs after the first attempt
	}{
		{name: "the build refuses the served config", verdict: errors.New(`caddy validate refused the edge config: unknown field "bogus"`), render: `{"render":1}`, hook: true},
		{name: "held, but not by the config (no copy of the render, no running Caddy, running Caddy can't be checked)",
			verdict: errors.New("Caddy refuses the current edge config and no running Caddy can be checked"), render: `{"render":1}`, hook: true},
		{name: "held by the config, but nothing is refused now", verdict: heldByConfig{heldReason}, hook: true},
		{name: "held by the config, no RefusedRender hook", verdict: heldByConfig{heldReason}, render: `{"render":1}`},
		// The check may have seen the other render: what it held back is unknown, so nothing is remembered,
		// also once the first render is back.
		{name: "held by the config, but the refused render changed during the check", verdict: heldByConfig{heldReason}, render: `{"render":1}`, hook: true,
			during:  func(r *heldRig) { r.set(heldByConfig{heldReason}, `{"render":2}`) },
			between: func(r *heldRig) { r.set(heldByConfig{heldReason}, `{"render":1}`) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newHeldRig(t, nil)
			r.set(tc.verdict, tc.render)
			if !tc.hook {
				r.inst.RefusedRender = nil
			}
			if tc.during != nil {
				once := sync.Once{}
				r.mu.Lock()
				r.during = func() { once.Do(func() { tc.during(r) }) }
				r.mu.Unlock()
			}
			missing := r.inst.pending()
			for n := int32(1); n <= 2; n++ {
				err := r.inst.attempt(ctx, missing)
				if !errors.Is(err, ErrBuildCheckFailed) || r.hits.Load() != n {
					t.Fatalf("attempt %d: err=%v downloads=%d; want a download that fails its check", n, err, r.hits.Load())
				}
				if strings.Contains(err.Error(), "waiting for Caddy") {
					t.Errorf("attempt %d must not wait for the config: %v", n, err)
				}
				if n == 1 && tc.between != nil {
					tc.between(r)
				}
			}
		})
	}
}

// Refresh honours the same memory: while the render that held a build back is still refused it fails at
// once (no download, the refresh limit not spent), and a refresh download held back by the config is
// remembered for the install loop too. Once Caddy accepts a render, the next refresh downloads.
func TestRefreshWaitsForTheConfig(t *testing.T) {
	ctx := context.Background()
	mods := []string{"dns.providers.cloudflare"}
	current := configCaddy("v2.11.2 h1:x", mods, false)
	r := newHeldRig(t, current)
	r.inst.RefreshEvery = time.Nanosecond
	r.inst.Check(ctx)
	r.set(heldByConfig{heldReason}, `{"render":1}`)

	swapped, err := r.inst.Refresh(ctx)
	if swapped || !errors.Is(err, ErrBuildCheckFailed) || !errors.Is(err, ErrHeldByConfig) || r.hits.Load() != 1 {
		t.Fatalf("first refresh: swapped=%v err=%v downloads=%d; want one download held back by the config", swapped, err, r.hits.Load())
	}
	if err := os.Remove(refreshMarkerPath(r.dataDir)); err != nil {
		t.Fatal(err)
	}
	swapped, err = r.inst.Refresh(ctx)
	if swapped || !errors.Is(err, ErrHeldByConfig) || !strings.Contains(err.Error(), "waiting for Caddy to accept the edge config: ") || r.hits.Load() != 1 {
		t.Fatalf("refresh while the same render is refused: swapped=%v err=%v downloads=%d; want no download and the wait", swapped, err, r.hits.Load())
	}
	if _, err := os.Stat(refreshMarkerPath(r.dataDir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refresh that downloads nothing must not record an attempt (it would spend the refresh limit): %v", err)
	}
	// The install loop shares the memory: its attempt doesn't download either.
	if err := r.inst.attempt(ctx, []string{"cloudflare"}); !errors.Is(err, ErrHeldByConfig) || r.hits.Load() != 1 {
		t.Errorf("install attempt after a held refresh: err=%v downloads=%d; want the wait", err, r.hits.Load())
	}
	if got, _ := os.ReadFile(OwnedCaddyPath(r.dataDir)); !bytes.Equal(got, current) || r.swaps.Load() != 0 {
		t.Error("the current build must stay and the edge must not restart")
	}

	r.set(nil, "")
	if swapped, err := r.inst.Refresh(ctx); !swapped || err != nil || r.hits.Load() != 2 || r.swaps.Load() != 1 {
		t.Fatalf("after Caddy accepted the config: swapped=%v err=%v downloads=%d swaps=%d; want the refresh downloaded and swapped in", swapped, err, r.hits.Load(), r.swaps.Load())
	}
}

// The on-disk shortcut honours the memory too, and a build on disk held back by the config is checked
// again once that refusal is over (no download): the config, not the file, was the cause.
func TestDNSPluginInstallerOnDiskShortcutWaitsForTheConfig(t *testing.T) {
	ctx := context.Background()
	mods := []string{"dns.providers.cloudflare"}
	r := newHeldRig(t, configCaddy("v2.12.0 h1:setup", mods, false))
	owned := OwnedCaddyPath(r.dataDir)
	missing := r.inst.pending()
	r.set(heldByConfig{heldReason}, `{"render":1}`)

	// The build on disk is checked first and held back by the config.
	if err := r.inst.attempt(ctx, missing); !errors.Is(err, ErrHeldByConfig) || r.checks() != 1 || r.hits.Load() != 0 {
		t.Fatalf("attempt onto the build on disk: err=%v checks=%d downloads=%d; want one check of it, no download", err, r.checks(), r.hits.Load())
	}
	// The same file isn't checked again while the same render is refused: a build is downloaded, and its
	// check is held back by the config too.
	if err := r.inst.attempt(ctx, missing); !errors.Is(err, ErrBuildCheckFailed) || r.checks() != 2 || r.hits.Load() != 1 {
		t.Fatalf("second attempt: err=%v checks=%d downloads=%d; want the download checked", err, r.checks(), r.hits.Load())
	}
	// Now remembered: nothing is checked or downloaded.
	if err := r.inst.attempt(ctx, missing); !errors.Is(err, ErrHeldByConfig) || r.checks() != 2 || r.hits.Load() != 1 {
		t.Fatalf("third attempt: err=%v checks=%d downloads=%d; want the wait, no check, no download", err, r.checks(), r.hits.Load())
	}

	// Caddy accepts a render: the same build on disk is checked again and restarted onto, nothing downloaded.
	r.set(nil, "")
	if err := r.inst.attempt(ctx, missing); err != nil {
		t.Fatalf("after Caddy accepted the config: %v", err)
	}
	if r.checks() != 3 || r.hits.Load() != 1 || r.swaps.Load() != 1 || !r.state.Status("cloudflare").OnDisk {
		t.Errorf("checks=%d downloads=%d swaps=%d status=%+v; want the build on disk checked and restarted onto, no download",
			r.checks(), r.hits.Load(), r.swaps.Load(), r.state.Status("cloudflare"))
	}
	if got, _ := os.ReadFile(owned); !bytes.Equal(got, configCaddy("v2.12.0 h1:setup", mods, false)) {
		t.Error("the build on disk must be the one restarted onto")
	}
}

// While the install loop waits for the config, a build put on disk meanwhile (`mooring setup --yes`) is
// not checked either; it is once Caddy accepts a render.
func TestDNSPluginInstallerWaitDoesNotCheckANewBuildOnDisk(t *testing.T) {
	ctx := context.Background()
	mods := []string{"dns.providers.cloudflare"}
	r := newHeldRig(t, nil)
	missing := r.inst.pending()
	r.set(heldByConfig{heldReason}, `{"render":1}`)
	if err := r.inst.attempt(ctx, missing); !errors.Is(err, ErrBuildCheckFailed) || r.hits.Load() != 1 || r.checks() != 1 {
		t.Fatalf("first attempt: err=%v downloads=%d checks=%d", err, r.hits.Load(), r.checks())
	}
	writeExec(t, OwnedCaddyPath(r.dataDir), configCaddy("v2.12.2 h1:setup", mods, false))
	if err := r.inst.attempt(ctx, missing); !errors.Is(err, ErrHeldByConfig) || r.checks() != 1 || r.hits.Load() != 1 || r.swaps.Load() != 0 {
		t.Fatalf("a new build on disk while waiting: err=%v checks=%d downloads=%d swaps=%d; want the wait, nothing checked", err, r.checks(), r.hits.Load(), r.swaps.Load())
	}
	r.set(nil, "")
	if err := r.inst.attempt(ctx, missing); err != nil || r.checks() != 2 || r.hits.Load() != 1 || r.swaps.Load() != 1 {
		t.Fatalf("after Caddy accepted the config: err=%v checks=%d downloads=%d swaps=%d; want the build on disk checked and restarted onto", err, r.checks(), r.hits.Load(), r.swaps.Load())
	}
}

// A build on disk held back by the config is checked again when the refused render changes, too. A
// build on disk that fails its check for a reason of its own is still not offered again (round 4).
func TestDNSPluginInstallerOnDiskShortcutRechecksAfterTheRenderChanges(t *testing.T) {
	ctx := context.Background()
	mods := []string{"dns.providers.cloudflare"}
	r := newHeldRig(t, configCaddy("v2.12.0 h1:setup", mods, false))
	missing := r.inst.pending()
	r.set(heldByConfig{heldReason}, `{"render":1}`)
	if err := r.inst.attempt(ctx, missing); !errors.Is(err, ErrHeldByConfig) || r.checks() != 1 {
		t.Fatalf("first attempt: %v (checks %d)", err, r.checks())
	}
	r.set(errors.New("refuses the startup config"), `{"render":2}`)
	if err := r.inst.attempt(ctx, missing); err == nil || r.checks() != 2 || r.hits.Load() != 0 {
		t.Fatalf("after the render changed: err=%v checks=%d downloads=%d; want the build on disk checked again", err, r.checks(), r.hits.Load())
	}
	if err := r.inst.attempt(ctx, missing); !errors.Is(err, ErrBuildCheckFailed) || r.checks() != 3 || r.hits.Load() != 1 {
		t.Fatalf("a build on disk that fails for its own reason: err=%v checks=%d downloads=%d; want the next attempt to download", err, r.checks(), r.hits.Load())
	}
}

// The install loop backing off after a build held back by the config tries again as soon as Caddy
// accepts a render (ConfigAccepted, called by the Reconciler), not after the backoff (up to 6 hours).
func TestDNSPluginInstallerWakesWhenCaddyAcceptsTheConfig(t *testing.T) {
	r := newHeldRig(t, nil)
	r.inst.MinBackoff = time.Hour
	r.set(heldByConfig{heldReason}, `{"render":1}`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); r.inst.Run(ctx) }()
	waitFor(t, "the held attempt and its backoff", func() bool { return !r.state.Status("cloudflare").NextAttempt.IsZero() })

	r.set(nil, "")
	r.inst.ConfigAccepted()
	waitFor(t, "the install after Caddy accepted the config", func() bool { return r.swaps.Load() == 1 })
	<-done // nothing pending any more: Run returns
	if r.hits.Load() != 2 {
		t.Errorf("downloads = %d; want the held one and the one after the wake", r.hits.Load())
	}
}

// A wake only ends a backoff that waits for the config: after a failure of another kind (a download
// that failed, a build that refuses the served config) the loop keeps its backoff.
func TestDNSPluginInstallerWakeOnlyEndsAWaitForTheConfig(t *testing.T) {
	r := newHeldRig(t, nil)
	r.inst.MinBackoff = time.Hour
	r.set(errors.New(`caddy validate refused the edge config: unknown field "bogus"`), `{"render":1}`)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.inst.Run(ctx) }()
	waitFor(t, "the failed attempt and its backoff", func() bool { return !r.state.Status("cloudflare").NextAttempt.IsZero() })
	r.set(nil, "")
	r.inst.ConfigAccepted()
	time.Sleep(300 * time.Millisecond)
	cancel()
	<-done
	if r.hits.Load() != 1 || r.swaps.Load() != 0 {
		t.Errorf("downloads=%d swaps=%d; want the backoff kept (one download, no install)", r.hits.Load(), r.swaps.Load())
	}
}

// fakeTimer is Run's backoff timer in a test: it records every wait Run starts and ends one only when the
// test fires it.
type fakeTimer struct {
	mu    sync.Mutex
	waits []time.Duration
	ch    chan time.Time
}

func newFakeTimer() *fakeTimer { return &fakeTimer{ch: make(chan time.Time)} }

func (f *fakeTimer) after(d time.Duration) <-chan time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.waits = append(f.waits, d)
	return f.ch
}

func (f *fakeTimer) started() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Duration(nil), f.waits...)
}

// fire ends the wait Run is in.
func (f *fakeTimer) fire(t *testing.T) {
	t.Helper()
	select {
	case f.ch <- time.Time{}:
	case <-time.After(10 * time.Second):
		t.Fatal("Run never waited on its timer")
	}
}

// A refusal that keeps clearing and coming back (a reconcile accepts a config, the next one is refused the
// same way again) must not cost a ~50 MB download per clear. A wake can't end two waits in a row: after an
// attempt a wake started is held back again, the loop waits out its backoff however often Caddy accepts a
// config meanwhile; after an attempt the timer started, a wake ends the wait again. A wake from before an
// attempt began is spent by it. The backoff keeps doubling.
func TestDNSPluginInstallerWakeCantEndTwoWaitsInARow(t *testing.T) {
	r := newHeldRig(t, nil)
	r.inst.MinBackoff = time.Minute
	tm := newFakeTimer()
	r.inst.after = tm.after
	const refused = `{"render":1}`
	r.set(heldByConfig{heldReason}, refused)
	// Caddy refuses the same render again while each build downloads, before its check.
	r.inst.Install = func(ctx context.Context, opt InstallOptions) (string, error) {
		r.set(heldByConfig{heldReason}, refused)
		return InstallPluginBuild(ctx, opt)
	}
	accept := func() {
		r.set(heldByConfig{heldReason}, "") // a reconcile accepted a config
		configAccepted(t, "a reconcile accepted a config", r.inst, 1)
	}
	at := func(what string, waits int, downloads int32) {
		t.Helper()
		waitFor(t, what, func() bool { return len(tm.started()) == waits && r.hits.Load() == downloads })
	}
	still := func(what string, waits int, downloads int32) {
		t.Helper()
		time.Sleep(300 * time.Millisecond)
		if n := len(tm.started()); n != waits || r.hits.Load() != downloads {
			t.Fatalf("%s: waits=%d downloads=%d; want %d and %d", what, n, r.hits.Load(), waits, downloads)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.inst.Run(ctx) }()
	defer func() { cancel(); <-done }()

	at("the first download, held back", 1, 1)
	accept()
	at("the download a wake started, held back again", 2, 2)
	accept()
	accept()
	still("wakes while waiting after an attempt a wake started", 2, 2)
	tm.fire(t)
	at("the download the timer started, held back again", 3, 3)
	accept()
	at("the download the next wake started", 4, 4)
	accept()
	still("a wake after it", 4, 4)
	if got, want := tm.started(), []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute}; !slices.Equal(got, want) {
		t.Errorf("backoff waits = %v; want %v (doubling)", got, want)
	}
}

// A held build is forgotten MaxBackoff after it was recorded, even while Caddy still refuses the same
// render: the download may have refused it for a reason of its own (a bad build) while the refusal is the
// running binary's, which only another build fixes. While held, a build is downloaded at most once per
// MaxBackoff, and a build held back again is remembered from its own check.
func TestDNSPluginInstallerHeldBuildExpiresAfterMaxBackoff(t *testing.T) {
	ctx := context.Background()
	r := newHeldRig(t, nil)
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	r.inst.now = clk.now
	r.inst.MaxBackoff = 6 * time.Hour
	missing := r.inst.pending()
	r.set(heldByConfig{heldReason}, `{"render":1}`)
	for n := int32(1); n <= 3; n++ {
		if err := r.inst.attempt(ctx, missing); !errors.Is(err, ErrBuildCheckFailed) || !errors.Is(err, ErrHeldByConfig) || r.hits.Load() != n {
			t.Fatalf("download %d: err=%v downloads=%d; want a download held back by the config", n, err, r.hits.Load())
		}
		clk.advance(6*time.Hour - time.Second)
		err := r.inst.attempt(ctx, missing)
		if !errors.Is(err, ErrHeldByConfig) || errors.Is(err, ErrBuildCheckFailed) || r.hits.Load() != n {
			t.Fatalf("just before the held build expires: err=%v downloads=%d; want the wait, no download", err, r.hits.Load())
		}
		if want := clk.now().Add(time.Second).UTC().Format(time.RFC3339); !strings.Contains(err.Error(), want) {
			t.Errorf("the wait's error %q should say when the next download may run (%s)", err, want)
		}
		clk.advance(time.Second)
	}
}

// Refresh honours the expiry too.
func TestRefreshDownloadsAgainOnceTheHeldBuildExpires(t *testing.T) {
	ctx := context.Background()
	r := newHeldRig(t, configCaddy("v2.11.2 h1:x", []string{"dns.providers.cloudflare"}, false))
	r.inst.RefreshEvery = time.Nanosecond
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	r.inst.now = clk.now
	r.inst.Check(ctx)
	r.set(heldByConfig{heldReason}, `{"render":1}`)
	if _, err := r.inst.Refresh(ctx); !errors.Is(err, ErrBuildCheckFailed) || !errors.Is(err, ErrHeldByConfig) || r.hits.Load() != 1 {
		t.Fatalf("first refresh: err=%v downloads=%d; want one download held back by the config", err, r.hits.Load())
	}
	clk.advance(6*time.Hour - time.Second)
	if _, err := r.inst.Refresh(ctx); !errors.Is(err, ErrHeldByConfig) || errors.Is(err, ErrBuildCheckFailed) || r.hits.Load() != 1 {
		t.Fatalf("refresh before the held build expires: err=%v downloads=%d; want the wait, no download", err, r.hits.Load())
	}
	clk.advance(time.Second)
	if _, err := r.inst.Refresh(ctx); !errors.Is(err, ErrBuildCheckFailed) || r.hits.Load() != 2 {
		t.Fatalf("refresh once the held build expired: err=%v downloads=%d; want a download", err, r.hits.Load())
	}
}

// configAccepted calls ConfigAccepted n times, failing the test instead of hanging it if a call blocks.
func configAccepted(t *testing.T, what string, i *DNSPluginInstaller, n int) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range n {
			i.ConfigAccepted()
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("ConfigAccepted blocked (%s)", what)
	}
}

// ConfigAccepted runs on the reconcile path (Reconciler.SetRefusalCleared): it must never block, whether
// the install loop never started, has returned, or is waiting.
func TestConfigAcceptedNeverBlocks(t *testing.T) {
	// 4: a waiting loop can take one wake in its select and drop one before its attempt, and the channel
	// holds one more; a blocking send blocks on the fourth.
	burst := func(what string, i *DNSPluginInstaller) {
		t.Helper()
		configAccepted(t, what, i, 4)
	}
	burst("an installer never started", &DNSPluginInstaller{})

	idle := newHeldRig(t, nil)
	idle.inst.Run(context.Background())
	if idle.swaps.Load() != 1 || len(idle.inst.pending()) != 0 {
		t.Fatalf("the loop should have installed and returned: swaps=%d pending=%v", idle.swaps.Load(), idle.inst.pending())
	}
	burst("a loop that returned", idle.inst)

	// It takes one wake, then (that attempt held back again) waits on its timer only.
	r := newHeldRig(t, nil)
	r.inst.MinBackoff = time.Hour
	r.set(heldByConfig{heldReason}, `{"render":1}`)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.inst.Run(ctx) }()
	defer func() { cancel(); <-done }()
	waitFor(t, "the held attempt and its backoff", func() bool { return !r.state.Status("cloudflare").NextAttempt.IsZero() })
	burst("a loop waiting after a held attempt", r.inst)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
