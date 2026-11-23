package edge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DNSModuleID is the Caddy module ID a DNS provider plugin registers: dns.providers.<name>.
func DNSModuleID(provider string) string {
	return "dns.providers." + strings.ToLower(strings.TrimSpace(provider))
}

// ProviderStatus is the state of one DNS provider's Caddy plugin.
type ProviderStatus struct {
	Provider string
	// OK: the module is in the binary the edge child is RUNNING. Set from the launched binary after each
	// launch (Sync), never at the moment a swap lands — until the restart completes, the old child (which
	// lacks the module) is still the one serving, and a wildcard rendered into it would be rejected.
	OK bool
	// OnDisk: the binary the edge will launch next has the module (an install landed). It ends the
	// install loop; OK follows on the next launch.
	OnDisk     bool
	Installing bool   // an install attempt is in progress
	Permanent  bool   // can't be used on this host (unknown provider, Mooring running as root, …): no retry
	Err        string // the last install failure (bounded command output); "" when none
	// SyncErr: the last read of the running binary's modules failed (Sync retries it). Kept apart from Err
	// so a read failure and its recovery never hide an install failure.
	SyncErr     string
	Attempts    int       // failed install attempts so far
	NextAttempt time.Time // when the next retry runs; zero when none is pending
}

// DNSPlugins is the concurrency-safe DNS plugin state read by the edge (which wildcards to render),
// the deploy gate (refuse a new catch-all while its plugin is known to be missing) and the dashboard.
// All methods are safe on a nil *DNSPlugins (no dns01 configured, or the edge isn't owned).
type DNSPlugins struct {
	mu sync.Mutex
	st map[string]*ProviderStatus
	// rejected: namespace apex → the error Caddy gave for that namespace's wildcard config. Kept per
	// namespace, not per provider: one namespace's malformed token must not switch off another
	// namespace's wildcard on the same provider.
	rejected map[string]string
}

// NamespaceRejection is a namespace whose wildcard config Caddy refused.
type NamespaceRejection struct {
	Apex   string
	Reason string
}

// NewDNSPlugins tracks providers (lowercased, deduplicated), all not-yet-present.
func NewDNSPlugins(providers []string) *DNSPlugins {
	p := &DNSPlugins{st: map[string]*ProviderStatus{}, rejected: map[string]string{}}
	for _, name := range providers {
		n := strings.ToLower(strings.TrimSpace(name))
		if n != "" && p.st[n] == nil {
			p.st[n] = &ProviderStatus{Provider: n}
		}
	}
	return p
}

// OK reports whether provider's plugin is in the running edge binary.
func (p *DNSPlugins) OK(provider string) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.st[strings.ToLower(strings.TrimSpace(provider))]
	return s != nil && s.OK
}

// KnownMissing reports whether provider's plugin is absent AND an install has already failed (or it
// can't be installed at all, or the running binary's modules can't be read), with the reason. A
// provider whose first install is still running is not "known" missing. nil-safe (false).
func (p *DNSPlugins) KnownMissing(provider string) (bool, string) {
	if p == nil {
		return false, ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.st[strings.ToLower(strings.TrimSpace(provider))]
	switch {
	case s == nil || s.OK:
		return false, ""
	case s.Err != "":
		return true, s.Err
	case s.SyncErr != "":
		return true, s.SyncErr
	}
	return false, ""
}

// Status returns one provider's state (Provider "" when it isn't tracked).
func (p *DNSPlugins) Status(provider string) ProviderStatus {
	if p == nil {
		return ProviderStatus{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if s := p.st[strings.ToLower(strings.TrimSpace(provider))]; s != nil {
		return *s
	}
	return ProviderStatus{}
}

// Snapshot returns every tracked provider's state, sorted by name (for the dashboard).
func (p *DNSPlugins) Snapshot() []ProviderStatus {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]ProviderStatus, 0, len(p.st))
	for _, s := range p.st {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out
}

// MarkUnavailable records that provider's plugin can't be installed at all on this host (reason
// shown to the operator): it becomes known-missing and is never retried.
func (p *DNSPlugins) MarkUnavailable(provider, reason string) {
	p.update(provider, func(s *ProviderStatus) {
		s.OK, s.Installing, s.Permanent = false, false, true
		s.Err, s.NextAttempt = reason, time.Time{}
	})
}

// RejectNamespace records that Caddy refused apex's wildcard config (reason shown to the operator). That
// namespace's wildcard stays off until Mooring restarts; other namespaces are unaffected.
func (p *DNSPlugins) RejectNamespace(apex, reason string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rejected == nil {
		p.rejected = map[string]string{}
	}
	p.rejected[normApex(apex)] = reason
}

// NamespaceRejected reports whether Caddy refused apex's wildcard config, with Caddy's error.
func (p *DNSPlugins) NamespaceRejected(apex string) (bool, string) {
	if p == nil {
		return false, ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	why, ok := p.rejected[normApex(apex)]
	return ok, why
}

// Active reports whether apex's wildcard, issued through provider, may be rendered: provider's plugin
// is in the running edge binary and Caddy hasn't refused the namespace's config.
func (p *DNSPlugins) Active(provider, apex string) bool {
	if rejected, _ := p.NamespaceRejected(apex); rejected {
		return false
	}
	return p.OK(provider)
}

// Rejected returns the namespaces whose wildcard config Caddy refused, sorted by apex (for the dashboard).
func (p *DNSPlugins) Rejected() []NamespaceRejection {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]NamespaceRejection, 0, len(p.rejected))
	for apex, why := range p.rejected {
		out = append(out, NamespaceRejection{Apex: apex, Reason: why})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Apex < out[j].Apex })
	return out
}

func normApex(apex string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(apex)), ".")
}

func (p *DNSPlugins) update(provider string, fn func(*ProviderStatus)) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	n := strings.ToLower(strings.TrimSpace(provider))
	s := p.st[n]
	if s == nil {
		s = &ProviderStatus{Provider: n}
		p.st[n] = s
	}
	fn(s)
}

// DNSPluginInstaller keeps every configured DNS provider's plugin in the edge's Caddy. Missing
// plugins are installed as a Mooring-owned Caddy build (InstallPluginBuild) in the background; a
// failure is retried with exponential backoff, and a successful swap restarts the edge child
// (OnSwap) so it runs the new binary. Nothing is downloaded when every plugin is already present.
type DNSPluginInstaller struct {
	DataDir   string   // "" = never use or install a Mooring-owned build (Mooring running as root)
	Providers []string // distinct dns01 providers from config.yaml
	State     *DNSPlugins
	OnSwap    func() // restart the supervised Caddy on the new binary (nil: no restart)
	Log       *slog.Logger

	BuildServer string       // "" = DefaultBuildServer
	Client      *http.Client // nil = a bounded https client
	MinBackoff  time.Duration
	MaxBackoff  time.Duration
	// Install replaces InstallPluginBuild in tests.
	Install func(ctx context.Context, opt InstallOptions) (string, error)
	// CheckBuild, when set, is InstallOptions.Check for every build this installer downloads (the install
	// loop's and Refresh's): the download must pass it before it replaces the current binary and the edge
	// restarts on it. The install loop also runs it on a binary already on disk before restarting the
	// edge onto it. serve runs `caddy validate` of the config the edge serves, so a build that would
	// refuse it (and crash-loop the edge) is never swapped in. nil = only the version and module checks.
	// An error matching ErrHeldByConfig says the edge config Caddy refuses, not the build, is the cause.
	CheckBuild func(ctx context.Context, bin string) error
	// RefusedRender, when set, returns the edge config Caddy refuses now (Reconciler.LoadRefused), nil
	// when it refuses none. After a downloaded build fails CheckBuild with ErrHeldByConfig, no build is
	// downloaded or checked again (install loop, Refresh, the build on disk) while Caddy still refuses
	// that same config, for at most MaxBackoff after that check: every one would fail the same way. nil =
	// nothing is remembered.
	RefusedRender func() []byte
	// SyncRetry is the first wait before Sync reads the modules again after a failed read (doubling, up
	// to 2 minutes); 0 = 5s. Tests shorten it.
	SyncRetry time.Duration
	// RefreshEvery is the least time between two Refresh downloads, across restarts (refreshAttemptRel);
	// 0 = 20h.
	RefreshEvery time.Duration

	syncGen atomic.Uint64 // bumped by Launched; a Sync for an older launch never writes the state
	// Guarded by State.mu: synced is the binary file the state's OK was last read from (Check or Sync, or
	// the build a Refresh swapped in after checking it); launched is the file at the binary path when the
	// current launch started.
	synced, launched *binIdentity
	// diskRefused is the binary on disk that last failed CheckBuild in attempt's shortcut: while the file
	// at the path is still that one, attempt downloads a build instead of checking it again.
	diskRefused atomic.Pointer[diskRefusal]
	// held is the refused render that held the last downloaded build back (ErrHeldByConfig), nil when none.
	held     atomic.Pointer[heldBuild]
	kickOnce sync.Once
	kick     chan struct{} // ConfigAccepted → a Run waiting after a held attempt tries again
	// Test seams: now is the clock a held build's age is measured on (nil = time.Now); after is Run's
	// backoff timer (nil = time.After).
	now   func() time.Time
	after func(time.Duration) <-chan time.Time

	running atomic.Bool // the install loop (Start) is running
	startMu sync.Mutex  // orders Start's wg.Add before Wait (a WaitGroup can't Add from zero during Wait)
	stopped bool        // Wait was called: no new loop starts
	wg      sync.WaitGroup

	refreshMu   sync.Mutex
	refreshing  bool      // a Refresh is downloading
	lastRefresh time.Time // when this process's last Refresh download started (refreshAttemptRel keeps it across restarts)
}

// syncErrPrefix starts SyncErr.
const syncErrPrefix = "can't read the modules of the running Caddy: "

// binIdentity is the file at a binary path at one moment. A swap (rename) or an in-place rewrite gives a
// different identity, so a read of the path can be matched to the binary a child launched from.
type binIdentity struct {
	path string
	fi   os.FileInfo
}

// statBin returns path's identity, or nil when path is "" or can't be read.
func statBin(path string) *binIdentity {
	if path == "" {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil
	}
	return &binIdentity{path: path, fi: fi}
}

// same reports whether a and b are the same unchanged file (nil is never the same as anything).
func (a *binIdentity) same(b *binIdentity) bool {
	return a != nil && b != nil && a.path == b.path && os.SameFile(a.fi, b.fi) &&
		a.fi.Size() == b.fi.Size() && a.fi.ModTime().Equal(b.fi.ModTime())
}

// ErrHeldByConfig matches (errors.Is) a CheckBuild error caused by the edge config Caddy refuses now
// rather than by the build checked: no build would pass the check while Caddy refuses that config. It is
// also the start of the error an install attempt or Refresh fails with, without downloading, while it
// waits for Caddy to accept the edge config.
var ErrHeldByConfig = errors.New("edge: waiting for Caddy to accept the edge config")

// heldBuild is the refused render (its sum) that held the last downloaded build back, the check's error,
// and when the check failed (clock).
type heldBuild struct {
	render string
	err    error
	at     time.Time
}

// diskRefusal is a binary on disk that failed CheckBuild in attempt's shortcut. held is the sum of the
// refused render that held it back (ErrHeldByConfig), "" when the check failed for another reason.
type diskRefusal struct {
	id   *binIdentity
	held string
}

// refusedSum is the SHA-256 of RefusedRender, "" when Caddy refuses no render or there is no hook.
func (i *DNSPluginInstaller) refusedSum() string {
	if i.RefusedRender == nil {
		return ""
	}
	r := i.RefusedRender()
	if len(r) == 0 {
		return ""
	}
	sum := sha256.Sum256(r)
	return hex.EncodeToString(sum[:])
}

// check runs CheckBuild on bin. held is the sum of the render Caddy refuses when the check failed because
// of it (ErrHeldByConfig) and that render was the refused one both before and after the check (a render
// that changed meanwhile isn't the one checked); "" otherwise.
func (i *DNSPluginInstaller) check(ctx context.Context, bin string) (held string, err error) {
	before := i.refusedSum()
	err = i.CheckBuild(ctx, bin)
	if errors.Is(err, ErrHeldByConfig) && before != "" && before == i.refusedSum() {
		held = before
	}
	return held, err
}

// downloadCheck is InstallOptions.Check for a download: CheckBuild, remembering the refused render when
// it held the build back. nil without CheckBuild.
func (i *DNSPluginInstaller) downloadCheck() func(context.Context, string) error {
	if i.CheckBuild == nil {
		return nil
	}
	return func(ctx context.Context, bin string) error {
		held, err := i.check(ctx, bin)
		if held != "" {
			i.held.Store(&heldBuild{render: held, err: err, at: i.clock()})
		}
		return err
	}
}

// waitingForConfig returns the error an attempt or Refresh fails with, before downloading anything, while
// Caddy still refuses the render that held the last downloaded build back, for at most MaxBackoff after
// that build's check; nil (forgetting that render) once Caddy refuses no render or another one, or
// MaxBackoff has passed.
func (i *DNSPluginInstaller) waitingForConfig() error {
	h := i.held.Load()
	if h == nil {
		return nil
	}
	// Intentional: a held build is forgotten MaxBackoff after its check even while Caddy refuses the same
	// render. A download that refuses that render for a reason of its own (a bad build) is held back too,
	// while the refusal may be the running binary's, which only another build fixes: without this, no build
	// would be downloaded until the render changed or Mooring restarted. Costs at most one download per
	// MaxBackoff while held.
	until := h.at.Add(i.maxBackoff())
	if cur := i.refusedSum(); cur != h.render || !i.clock().Before(until) {
		i.held.CompareAndSwap(h, nil)
		return nil
	}
	return fmt.Errorf("%w: %w (no new build is downloaded until Caddy accepts an edge config, the refused one changes, or %s)",
		ErrHeldByConfig, h.err, until.UTC().Format(time.RFC3339))
}

// ConfigAccepted tells the install loop that Caddy accepted an edge config after refusing one (serve
// calls it from Reconciler.SetRefusalCleared): a loop backing off after an attempt held back by the
// config (ErrHeldByConfig) tries again now, unless a ConfigAccepted started that attempt (see Run). Any
// other backoff is kept. Never blocks.
func (i *DNSPluginInstaller) ConfigAccepted() {
	select {
	case i.kickCh() <- struct{}{}:
	default:
	}
}

func (i *DNSPluginInstaller) kickCh() chan struct{} {
	i.kickOnce.Do(func() { i.kick = make(chan struct{}, 1) })
	return i.kick
}

func (i *DNSPluginInstaller) clock() time.Time {
	if i.now != nil {
		return i.now()
	}
	return time.Now()
}

func (i *DNSPluginInstaller) timer(d time.Duration) <-chan time.Time {
	if i.after != nil {
		return i.after(d)
	}
	return time.After(d)
}

func (i *DNSPluginInstaller) minBackoff() time.Duration {
	if i.MinBackoff > 0 {
		return i.MinBackoff
	}
	return time.Minute
}

// maxBackoff caps the retry delay. 6 hours: a failure that won't fix itself (the build server serving
// a Caddy major Mooring doesn't support, a plugin that can't be built) shouldn't pull a ~50 MB build
// every hour forever; restarting Mooring retries at once.
func (i *DNSPluginInstaller) maxBackoff() time.Duration {
	if i.MaxBackoff > 0 {
		return i.MaxBackoff
	}
	return 6 * time.Hour
}

func (i *DNSPluginInstaller) log() *slog.Logger {
	if i.Log != nil {
		return i.Log
	}
	return slog.Default()
}

// modulesOf lists bin's modules, retrying once after a short pause (a CPU-starved boot can time out
// the first `list-modules`; counting that as "missing" would trigger a needless download).
func modulesOf(ctx context.Context, bin string) (map[string]bool, error) {
	mods, err := CaddyModules(ctx, bin)
	if err == nil {
		return mods, nil
	}
	select {
	case <-ctx.Done():
		return nil, err
	case <-time.After(2 * time.Second):
	}
	return CaddyModules(ctx, bin)
}

// Check records, without installing anything, which providers the binary the edge is about to launch
// already has, and returns the ones that are missing (installable ones only). Run it at startup,
// before the edge renders its first config.
func (i *DNSPluginInstaller) Check(ctx context.Context) []string {
	var mods map[string]bool
	if bin := ResolveCaddy(i.DataDir); bin != "" {
		before := statBin(bin)
		var err error
		if mods, err = modulesOf(ctx, bin); err != nil {
			i.log().Warn("edge: can't list the modules of the current Caddy; treating its DNS plugins as missing", "caddy", bin, "err", err.Error())
		} else if i.State != nil {
			if after := statBin(bin); before.same(after) {
				i.State.mu.Lock()
				i.synced = before // the first launch of this same file keeps the OK set below
				i.State.mu.Unlock()
			}
		}
	}
	var missing []string
	for _, p := range i.Providers {
		if _, ok := DNSProviderModule(p); !ok {
			i.State.update(p, func(s *ProviderStatus) {
				s.OK, s.OnDisk, s.Permanent = false, false, true
				s.Err = "unknown DNS provider — supported: " + strings.Join(KnownDNSProviders(), ", ")
			})
			continue
		}
		have := mods[DNSModuleID(p)]
		i.State.update(p, func(s *ProviderStatus) {
			s.OK, s.OnDisk = have, have
			if have {
				s.Err, s.NextAttempt = "", time.Time{}
			}
		})
		if !have {
			missing = append(missing, p)
		}
	}
	return missing
}

// Launched records that a new edge child was started and returns its launch generation for Sync. When
// the binary at the path is the same file the state was last read from, OK is kept: the config pushed
// right after the launch carries the wildcards at once. Otherwise every provider's OK is cleared until
// Sync has read the new binary's modules, so that push carries no wildcard the binary might lack (fail
// closed). A provider marked Permanent is left alone.
func (i *DNSPluginInstaller) Launched() uint64 {
	id := statBin(ResolveCaddy(i.DataDir))
	p := i.State
	if p == nil {
		return i.syncGen.Add(1)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	gen := i.syncGen.Add(1)
	i.launched = id
	if id.same(i.synced) {
		return gen
	}
	for _, name := range i.Providers {
		if s := p.st[strings.ToLower(strings.TrimSpace(name))]; s != nil && !s.Permanent {
			s.OK = false
		}
	}
	return gen
}

// Sync reads the modules of the binary the edge launched (the launch Launched returned gen for) and sets
// each provider's OK from them. Call it after the routes are pushed again: reading the modules runs the
// binary, which can be slow on a busy host. A failed read sets SyncErr (so the gate, the catch-all watch
// and the dashboard see it) and is retried with backoff until it succeeds, ctx ends, or a later launch
// takes over. A read of a file other than the one launched (a build swapped in after the launch) is
// discarded: it says nothing about the running child. When a read finds a module missing from a binary
// it was expected on, the install loop is started again. read reports that this launch's modules were
// read; enabled, that a provider became OK (a wildcard can now be rendered).
func (i *DNSPluginInstaller) Sync(ctx context.Context, gen uint64) (read, enabled bool) {
	wait := i.SyncRetry
	if wait <= 0 {
		wait = 5 * time.Second
	}
	if i.launchedSynced(gen) {
		// The same unchanged file the state was read from: its modules are known, and a read that failed
		// now must not switch the wildcards off.
		return true, false
	}
	for failed := false; ; {
		bin := ResolveCaddy(i.DataDir)
		before := statBin(bin)
		var mods map[string]bool
		err := errors.New("no caddy binary found")
		if bin != "" {
			mods, err = modulesOf(ctx, bin)
		}
		res := i.applySync(gen, before, statBin(bin), mods, err)
		switch {
		case res.superseded:
			return false, false
		case res.changed:
			i.log().Info("edge: the Caddy binary changed after the edge started; its modules are read at the next start", "caddy", bin)
			return false, false
		case err == nil:
			if failed {
				i.log().Info("edge: read the running Caddy's modules", "caddy", bin)
			}
			if res.lost {
				i.log().Warn("edge: the running Caddy lacks a DNS plugin it had; reinstalling it", "caddy", bin)
				i.Start(ctx)
			}
			return true, res.enabled
		}
		if !failed {
			i.log().Warn("edge: can't list the running Caddy's modules; its DNS-01 wildcards stay off until a retry succeeds", "caddy", bin, "err", err.Error())
			failed = true
		}
		select {
		case <-ctx.Done():
			return false, false
		case <-time.After(wait):
		}
		if wait *= 2; wait > 2*time.Minute {
			wait = 2 * time.Minute
		}
	}
}

// launchedSynced reports whether launch gen is current and runs the file the state was last read from.
func (i *DNSPluginInstaller) launchedSynced(gen uint64) bool {
	p := i.State
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return i.syncGen.Load() == gen && i.launched.same(i.synced)
}

// syncResult is what applySync did with one module read.
type syncResult struct {
	superseded bool // a later launch has started: nothing written
	changed    bool // the file read isn't the one launched (or changed during the read): nothing written
	enabled    bool // a provider became OK
	lost       bool // a module expected on disk is missing: the install loop must run again
}

// applySync writes one module read of the file before/after identifies into the state. The generation
// and the launched file are checked under the state's lock, so an older launch's slow read, or a read of
// a build swapped in after the launch, can't overwrite the state of the running child.
func (i *DNSPluginInstaller) applySync(gen uint64, before, after *binIdentity, mods map[string]bool, readErr error) syncResult {
	p := i.State
	if p == nil {
		return syncResult{superseded: i.syncGen.Load() != gen}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if i.syncGen.Load() != gen {
		return syncResult{superseded: true}
	}
	if readErr == nil && (!before.same(after) || !before.same(i.launched)) {
		return syncResult{changed: true}
	}
	var res syncResult
	for _, name := range i.Providers {
		if _, ok := DNSProviderModule(name); !ok {
			continue
		}
		n := strings.ToLower(strings.TrimSpace(name))
		s := p.st[n]
		if s == nil {
			s = &ProviderStatus{Provider: n}
			p.st[n] = s
		}
		if s.Permanent {
			continue
		}
		if readErr != nil {
			s.OK, s.SyncErr = false, syncErrPrefix+readErr.Error()
			continue
		}
		s.SyncErr = ""
		if mods[DNSModuleID(n)] {
			res.enabled = res.enabled || !s.OK
			s.OK, s.OnDisk, s.Err, s.NextAttempt = true, true, "", time.Time{}
			continue
		}
		s.OK = false
		if s.OnDisk {
			// The binary the edge runs (and launches next) lacks a module it was expected to have — e.g. the
			// system caddy was replaced by a package upgrade. It has to be installed again.
			s.OnDisk = false
			if i.DataDir == "" {
				s.Err = "the running Caddy has no " + DNSModuleID(n) + " module, and Mooring running as root installs no Caddy build"
			} else {
				res.lost = true
			}
		}
	}
	if readErr == nil {
		i.synced = before
	}
	return res
}

// Start runs the install loop (Run) in the background unless it is already running or nothing is
// pending; it returns at once and is safe to call repeatedly. Wait waits for it to return.
func (i *DNSPluginInstaller) Start(ctx context.Context) {
	i.startMu.Lock()
	defer i.startMu.Unlock()
	if i.stopped || ctx.Err() != nil || len(i.pending()) == 0 || !i.running.CompareAndSwap(false, true) {
		return
	}
	i.wg.Add(1)
	go func() {
		defer i.wg.Done()
		for {
			i.Run(ctx)
			i.running.Store(false)
			// A provider that became pending after Run's last check (and whose Start lost the race above)
			// is picked up here.
			if ctx.Err() != nil || len(i.pending()) == 0 || !i.running.CompareAndSwap(false, true) {
				return
			}
		}
	}()
}

// Wait stops further Starts and blocks until the install loop has returned (call it at shutdown, after
// cancelling the loop's context).
func (i *DNSPluginInstaller) Wait() {
	i.startMu.Lock()
	i.stopped = true
	i.startMu.Unlock()
	i.wg.Wait()
}

// Run installs the missing plugins and retries a failure with exponential backoff (MinBackoff,
// doubling, capped at MaxBackoff) until every installable provider is on disk or ctx ends. After an
// attempt held back by the edge config Caddy refuses (ErrHeldByConfig), ConfigAccepted ends the wait
// early, unless a ConfigAccepted started that attempt: a wake never ends two waits in a row. Edge
// settings change only on a restart, which runs Check + Run again.
func (i *DNSPluginInstaller) Run(ctx context.Context) {
	backoff := i.minBackoff()
	woken := false // the next attempt is the one a ConfigAccepted started
	for {
		missing := i.pending()
		if len(missing) == 0 || ctx.Err() != nil {
			return
		}
		// A wake from before this attempt is spent by it: the attempt sees the refusal as it is now.
		select {
		case <-i.kickCh():
		default:
		}
		err := i.attempt(ctx, missing)
		byWake := woken
		woken = false
		if err == nil {
			backoff = i.minBackoff()
			continue
		}
		next := time.Now().Add(backoff)
		for _, p := range missing {
			i.State.update(p, func(s *ProviderStatus) { s.NextAttempt = next })
		}
		var accepted chan struct{} // nil: never ready
		// Intentional: after an attempt a wake started is held back again, wakes are ignored until the timer
		// ends this wait. A refusal that keeps clearing and coming back would otherwise download a ~50 MB build
		// per clear with no backoff; this way a wake adds at most one download per backoff period.
		if errors.Is(err, ErrHeldByConfig) && !byWake {
			accepted = i.kickCh()
		}
		select {
		case <-ctx.Done():
			return
		case <-i.timer(backoff):
		case <-accepted:
			woken = true
		}
		backoff = min(backoff*2, i.maxBackoff())
	}
}

// pending lists the known providers whose module isn't on disk yet and that can be installed.
func (i *DNSPluginInstaller) pending() []string {
	if i.DataDir == "" {
		return nil // no Mooring-owned build to install into
	}
	var out []string
	for _, p := range i.Providers {
		if _, ok := DNSProviderModule(p); !ok {
			continue
		}
		if st := i.State.Status(p); !st.OnDisk && !st.Permanent {
			out = append(out, strings.ToLower(strings.TrimSpace(p)))
		}
	}
	return out
}

// attempt makes the missing modules available: if the binary the edge will launch already has them
// (`mooring setup` installed a build meanwhile) and passes CheckBuild, it only restarts the edge onto
// it; otherwise it builds one Caddy with EVERY configured provider (so a provider already present is
// never dropped) plus the plugins the system caddy carries, and installs it. The new build takes effect
// on the restart (OnSwap); OK follows from Sync on that launch. A binary on disk that fails CheckBuild
// fails the attempt like an install (Run backs off), and the same unchanged file is not offered again
// (while Caddy refuses the same render, when that render held it back): the next attempt downloads a
// build. While Caddy refuses the render that held the last download back (waitingForConfig), the
// attempt fails at once: nothing is checked or downloaded.
func (i *DNSPluginInstaller) attempt(ctx context.Context, missing []string) error {
	if err := i.waitingForConfig(); err != nil {
		i.installFailed(missing, err)
		return err
	}
	dns, want := i.dnsPackages()
	if bin := ResolveCaddy(i.DataDir); bin != "" {
		id := statBin(bin)
		// Intentional: the same unchanged file that failed CheckBuild is not checked again, the attempt
		// downloads a build instead; checking it again would fail the same way, and no download would ever run.
		// A file held back by a refused render is checked again once Caddy refuses no render or another one.
		if r := i.diskRefused.Load(); r == nil || !id.same(r.id) || (r.held != "" && r.held != i.refusedSum()) {
			if mods, err := CaddyModules(ctx, bin); err == nil && hasAll(mods, want) {
				// setup checks a build only against config.yaml's edge settings, not the routes the edge
				// serves: check it as a download is checked.
				if i.CheckBuild != nil {
					// Intentional: a refusal here doesn't stop the downloads (only a download's does): this file
					// may be an older Caddy than the build server's, which may accept the refused render.
					if held, cerr := i.check(ctx, bin); cerr != nil {
						i.diskRefused.Store(&diskRefusal{id: id, held: held})
						err := fmt.Errorf("edge: the Caddy on disk (%s) has the DNS plugin(s) but fails its check, so the edge isn't restarted onto it; the next attempt downloads a new build: %w", bin, cerr)
						i.installFailed(missing, err)
						return err
					}
				}
				i.markOnDisk()
				i.log().Info("edge: the Caddy on disk already has the DNS plugin(s); restarting the edge onto it", "caddy", bin)
				i.swap()
				return nil
			}
		}
	}
	pkgs, extras := i.withSystemPlugins(ctx, dns)
	for _, p := range missing {
		i.State.update(p, func(s *ProviderStatus) { s.Installing = true })
	}
	i.log().Info("edge: installing a Caddy build with the DNS plugin(s) for the wildcard certs",
		"missing", strings.Join(missing, ","), "packages", strings.Join(pkgs, ","), "path", OwnedCaddyPath(i.DataDir))
	path, err := i.install(ctx, InstallOptions{DataDir: i.DataDir, Packages: pkgs, WantModules: want, BuildServer: i.BuildServer,
		Client: i.Client, Check: i.downloadCheck()}, extras)
	if err != nil {
		i.installFailed(missing, err)
		return err
	}
	i.markOnDisk()
	i.log().Info("edge: Caddy DNS plugin(s) installed; restarting the edge on the new binary", "path", path)
	i.swap()
	return nil
}

// installFailed records a failed attempt for the missing providers (the error, one more attempt) and
// logs it; Run retries with backoff.
func (i *DNSPluginInstaller) installFailed(missing []string, err error) {
	for _, p := range missing {
		i.State.update(p, func(s *ProviderStatus) {
			s.Installing = false
			s.Err = err.Error()
			s.Attempts++
		})
	}
	i.log().Warn("edge: Caddy DNS plugin install failed — wildcards using it stay off (subdomains fall back to per-name HTTP-01; a catch-all has no certificate) until it succeeds; retrying with backoff",
		"missing", strings.Join(missing, ","), "err", err.Error())
}

// dnsPackages returns the Go module path (deduplicated) and the module ID of every configured provider
// Mooring knows.
func (i *DNSPluginInstaller) dnsPackages() (pkgs, want []string) {
	seen := map[string]bool{}
	for _, p := range i.Providers {
		mod, ok := DNSProviderModule(p)
		if !ok || seen[mod] {
			continue
		}
		seen[mod] = true
		pkgs = append(pkgs, mod)
		want = append(want, DNSModuleID(p))
	}
	return pkgs, want
}

// withSystemPlugins returns the packages of a new owned build: dns plus the non-standard plugins of the
// system caddy (extras), sorted. Plugins are carried over only from the system caddy (root-owned): the
// Mooring-owned build is writable by the service user, so its own report of what's built in must not
// decide what goes into the next build.
func (i *DNSPluginInstaller) withSystemPlugins(ctx context.Context, dns []string) (pkgs, extras []string) {
	if sys, err := exec.LookPath("caddy"); err == nil {
		if x, xerr := CaddyExtraPackages(ctx, sys); xerr != nil {
			i.log().Warn("edge: can't read the plugins in the system Caddy (needs `list-modules --packages --skip-standard`); the new build has only the DNS providers",
				"caddy", sys, "err", xerr.Error())
		} else {
			extras = x
		}
	}
	seen := map[string]bool{}
	pkgs = append(pkgs, dns...)
	for _, p := range dns {
		seen[p] = true
	}
	for _, x := range extras {
		if !seen[x] {
			seen[x] = true
			pkgs = append(pkgs, x)
		}
	}
	sort.Strings(pkgs)
	return pkgs, extras
}

// install runs one install of opt (i.Install, else InstallPluginBuild). A build with carried plugins
// that fails is retried at once with only the DNS providers: a carried plugin may not build against the
// latest Caddy, and Mooring doesn't use it. A build that failed the check (CheckBuild) is not: the edge
// config doesn't use the carried plugins, so a second download would fail the same way.
func (i *DNSPluginInstaller) install(ctx context.Context, opt InstallOptions, extras []string) (string, error) {
	install := i.Install
	if install == nil {
		install = InstallPluginBuild
	}
	path, err := install(ctx, opt)
	if err != nil && len(extras) > 0 && !errors.Is(err, ErrBuildUnchanged) && !errors.Is(err, ErrBuildCheckFailed) {
		i.log().Warn("edge: the Caddy build with the carried plugins failed; retrying with only the DNS providers", "err", err.Error())
		opt.Packages = dnsOnly(opt.Packages, extras)
		path, err = install(ctx, opt)
	}
	return path, err
}

// ErrRefreshTooSoon: Refresh ran (or is running) within RefreshEvery.
var ErrRefreshTooSoon = errors.New("edge: the Mooring-owned Caddy was refreshed recently")

// refreshEvery defaults to 20h: below the host scan's default 24h interval, so the hook a daily scan
// runs is never refused because this scan started a few minutes earlier than the last one's download,
// while the download still happens at most about once a day.
func (i *DNSPluginInstaller) refreshEvery() time.Duration {
	if i.RefreshEvery > 0 {
		return i.RefreshEvery
	}
	return 20 * time.Hour
}

// refreshAttemptRel is the file in data_dir that records when the last Refresh download attempt
// started (a unix timestamp in seconds). It sits next to the owned build, but never matches
// "caddy.new*": an install deletes old files with that prefix.
const refreshAttemptRel = "bin/caddy.refresh-attempt"

// maxRefreshAttemptSize bounds a read of the record (a timestamp is a dozen bytes).
const maxRefreshAttemptSize = 64

// recordedAttempt returns the attempt time an earlier Refresh recorded (in this process or before a
// restart); ok=false (no limit) when there is none, it can't be read, or it is later than now.
func (i *DNSPluginInstaller) recordedAttempt(now time.Time) (at time.Time, ok bool) {
	at, err := readRefreshAttempt(i.DataDir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return time.Time{}, false
	case err != nil:
		i.log().Warn("edge: can't read the last Caddy build refresh attempt; not limiting this refresh",
			"path", filepath.Join(i.DataDir, refreshAttemptRel), "err", err.Error())
		return time.Time{}, false
	case at.After(now):
		// Intentional: a recorded time in the future sets no limit. The clock was set back after it was
		// written; honouring it would hold every refresh off until the clock caught up.
		i.log().Warn("edge: the last Caddy build refresh attempt is recorded in the future (the clock changed); not limiting this refresh",
			"path", filepath.Join(i.DataDir, refreshAttemptRel), "recorded", at.UTC().Format(time.RFC3339))
		return time.Time{}, false
	}
	return at, true
}

// openRefreshRoot opens an os.Root on dataDir (no path out of it, whatever symlinks are planted there)
// and checks that its bin is a real directory: a symlinked bin dir is refused, as for an install.
func openRefreshRoot(dataDir string) (*os.Root, error) {
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		return nil, err
	}
	if fi, err := root.Lstat("bin"); err != nil {
		root.Close()
		return nil, err
	} else if !fi.IsDir() {
		root.Close()
		return nil, errors.New("bin is not a directory (a symlink is refused)")
	}
	return root, nil
}

// readRefreshAttempt reads the time recorded at refreshAttemptRel in dataDir. The record must be a
// regular file (a symlink is refused, never followed) holding a unix timestamp.
func readRefreshAttempt(dataDir string) (time.Time, error) {
	root, err := openRefreshRoot(dataDir)
	if err != nil {
		return time.Time{}, err
	}
	defer root.Close()
	fi, err := root.Lstat(refreshAttemptRel)
	if err != nil {
		return time.Time{}, err
	}
	if !fi.Mode().IsRegular() {
		return time.Time{}, errors.New("not a regular file (a symlink is refused)")
	}
	f, err := root.Open(refreshAttemptRel)
	if err != nil {
		return time.Time{}, err
	}
	defer f.Close()
	// os.Root follows a symlink that stays inside data_dir: the file opened must be the one checked.
	if ofi, err := f.Stat(); err != nil || !os.SameFile(fi, ofi) {
		return time.Time{}, errors.New("replaced while being read")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxRefreshAttemptSize+1))
	if err != nil {
		return time.Time{}, err
	}
	if len(b) > maxRefreshAttemptSize {
		return time.Time{}, fmt.Errorf("over %d bytes: not a timestamp", maxRefreshAttemptSize)
	}
	sec, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return time.Time{}, errors.New("not a unix timestamp")
	}
	return time.Unix(sec, 0), nil
}

// writeRefreshAttempt records at in dataDir's refreshAttemptRel as a 0600 file. It writes a new file
// and renames it into place: a rename replaces a symlink at the path instead of writing through it, and
// a reader never sees a half-written record. Nothing else in bin is touched.
func writeRefreshAttempt(dataDir string, at time.Time) error {
	root, err := openRefreshRoot(dataDir)
	if err != nil {
		return err
	}
	defer root.Close()
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := refreshAttemptRel + ".tmp." + hex.EncodeToString(rnd[:])
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(strconv.FormatInt(at.Unix(), 10) + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = root.Rename(tmp, refreshAttemptRel)
	}
	if werr != nil {
		_ = root.Remove(tmp)
	}
	return werr
}

// Refresh downloads a current build of the Mooring-owned Caddy with the same packages the install loop
// uses (every configured provider + the system caddy's extra plugins; DNS-only retry), checked like an
// install (CheckBuild included: a build that fails it is deleted and its error, wrapping
// ErrBuildCheckFailed, returned), and swaps it in only when its Go build info differs from the installed
// build's (SkipIfSame).
// Swapped → OnSwap() and (true, nil); when every provider was OK, the relaunch onto the new build keeps
// OK without reading it again (it was checked for every module). Unchanged build, no owned build,
// DataDir == "", or the install loop running (it installs a current build itself) → (false, nil).
// Within RefreshEvery of the previous download attempt, or while another Refresh runs → (false,
// ErrRefreshTooSoon). The start of each attempt is recorded in <data_dir>/bin/caddy.refresh-attempt, so
// the limit holds across a Mooring restart; a missing, unreadable or corrupt record, or one later than
// the current time, sets no limit (the in-memory limit of this process still applies), and a failure
// to write it is logged, never returned. A failed download keeps the current build and returns the
// error. While Caddy refuses the render that held the last downloaded build back (CheckBuild failed
// with ErrHeldByConfig, see RefusedRender), it returns (false, error matching ErrHeldByConfig) without
// downloading or recording an attempt. Works with no Providers.
func (i *DNSPluginInstaller) Refresh(ctx context.Context) (bool, error) {
	if i.DataDir == "" {
		return false, nil
	}
	owned := OwnedCaddyPath(i.DataDir)
	if fi, err := os.Lstat(owned); err != nil || !fi.Mode().IsRegular() {
		return false, nil
	}
	if i.running.Load() {
		return false, nil
	}
	i.refreshMu.Lock()
	if i.refreshing || (!i.lastRefresh.IsZero() && time.Since(i.lastRefresh) < i.refreshEvery()) {
		i.refreshMu.Unlock()
		return false, ErrRefreshTooSoon
	}
	now := time.Now()
	if last, ok := i.recordedAttempt(now); ok && now.Sub(last) < i.refreshEvery() {
		i.refreshMu.Unlock()
		return false, ErrRefreshTooSoon
	}
	// After the rate limit, so a refresh within RefreshEvery stays ErrRefreshTooSoon (no alert); before the
	// attempt is recorded, since nothing is downloaded.
	if err := i.waitingForConfig(); err != nil {
		i.refreshMu.Unlock()
		i.log().Warn("edge: Caddy build refresh waits for Caddy to accept the edge config; keeping the current build", "err", err.Error())
		return false, err
	}
	i.refreshing, i.lastRefresh = true, now
	i.refreshMu.Unlock()
	defer func() {
		i.refreshMu.Lock()
		i.refreshing = false
		i.refreshMu.Unlock()
	}()
	if err := writeRefreshAttempt(i.DataDir, now); err != nil {
		i.log().Warn("edge: can't record the Caddy build refresh attempt; the refresh limit won't survive a Mooring restart",
			"path", filepath.Join(i.DataDir, refreshAttemptRel), "err", err.Error())
	}

	dns, want := i.dnsPackages()
	pkgs, extras := i.withSystemPlugins(ctx, dns)
	i.log().Info("edge: refreshing the Mooring-owned Caddy build", "packages", strings.Join(pkgs, ","), "path", owned)
	path, err := i.install(ctx, InstallOptions{DataDir: i.DataDir, Packages: pkgs, WantModules: want,
		BuildServer: i.BuildServer, Client: i.Client, SkipIfSame: true, Check: i.downloadCheck()}, extras)
	switch {
	case errors.Is(err, ErrBuildUnchanged):
		i.log().Info("edge: the downloaded Caddy build is the same as the installed one; kept", "path", owned)
		return false, nil
	case err != nil:
		i.log().Warn("edge: Caddy build refresh failed; keeping the current build", "err", err.Error())
		return false, err
	}
	// The new build passed the checks (every provider's module, CheckBuild), so the next launch has them all.
	i.markOnDisk()
	i.adoptRefreshed(owned)
	i.log().Info("edge: refreshed the Mooring-owned Caddy build; restarting the edge on it", "path", path)
	i.swap()
	return true, nil
}

// adoptRefreshed records the build Refresh just swapped in at path as the file the state was read from
// (synced), so the relaunch onto it keeps OK and its first config push carries the wildcards: the build
// was checked for every provider's module (WantModules), which is what Sync would read from it. Only
// when every provider is OK already, i.e. the running edge has every module too.
func (i *DNSPluginInstaller) adoptRefreshed(path string) {
	p := i.State
	id := statBin(path)
	if p == nil || id == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, name := range i.Providers {
		if _, ok := DNSProviderModule(name); !ok {
			continue
		}
		s := p.st[strings.ToLower(strings.TrimSpace(name))]
		if s != nil && s.Permanent {
			continue
		}
		if s == nil || !s.OK {
			// Intentional: nothing is recorded, so the relaunch reads the new build (Sync), as after an
			// install. Setting OK here would hand the wildcard to the old process before the restart (it may
			// lack the module: a refused /load pins the namespace off until Mooring restarts), and a failing
			// Sync of that process could clear OK again with synced already on the new build, leaving the
			// wildcard off with no read to turn it on.
			return
		}
	}
	i.synced = id
}

// markOnDisk records that the next launch's binary has every known provider's module. A Permanent
// provider keeps its error: it stays unusable whatever the binary has.
func (i *DNSPluginInstaller) markOnDisk() {
	for _, p := range i.Providers {
		if _, ok := DNSProviderModule(p); ok {
			i.State.update(p, func(s *ProviderStatus) {
				s.OnDisk, s.Installing = true, false
				if !s.Permanent {
					s.Err, s.NextAttempt = "", time.Time{}
				}
			})
		}
	}
}

func (i *DNSPluginInstaller) swap() {
	if i.OnSwap != nil {
		i.OnSwap()
	}
}

func hasAll(mods map[string]bool, want []string) bool {
	for _, m := range want {
		if !mods[m] {
			return false
		}
	}
	return true
}

// dnsOnly is pkgs without extras.
func dnsOnly(pkgs, extras []string) []string {
	drop := map[string]bool{}
	for _, x := range extras {
		drop[x] = true
	}
	var out []string
	for _, p := range pkgs {
		if !drop[p] || strings.HasPrefix(p, "github.com/caddy-dns/") {
			out = append(out, p)
		}
	}
	return out
}
