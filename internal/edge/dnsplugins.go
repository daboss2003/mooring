package edge

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"sort"
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
	// SyncRetry is the first wait before Sync reads the modules again after a failed read (doubling, up
	// to 2 minutes); 0 = 5s. Tests shorten it.
	SyncRetry time.Duration

	syncGen atomic.Uint64 // bumped by Launched; a Sync for an older launch never writes the state
	// Guarded by State.mu: synced is the binary file the state's OK was last read from (Check or Sync);
	// launched is the file at the binary path when the current launch started.
	synced, launched *binIdentity

	running atomic.Bool // the install loop (Start) is running
	startMu sync.Mutex  // orders Start's wg.Add before Wait (a WaitGroup can't Add from zero during Wait)
	stopped bool        // Wait was called: no new loop starts
	wg      sync.WaitGroup
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
// doubling, capped at MaxBackoff) until every installable provider is on disk or ctx ends. Edge
// settings change only on a restart, which runs Check + Run again.
func (i *DNSPluginInstaller) Run(ctx context.Context) {
	backoff := i.minBackoff()
	for {
		missing := i.pending()
		if len(missing) == 0 || ctx.Err() != nil {
			return
		}
		if err := i.attempt(ctx, missing); err == nil {
			backoff = i.minBackoff()
			continue
		}
		next := time.Now().Add(backoff)
		for _, p := range missing {
			i.State.update(p, func(s *ProviderStatus) { s.NextAttempt = next })
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
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
// (`mooring setup` installed a build meanwhile), it only restarts the edge onto it; otherwise it builds
// one Caddy with EVERY configured provider (so a provider already present is never dropped) plus the
// plugins the system caddy carries, and installs it. The new build takes effect on the restart
// (OnSwap); OK follows from Sync on that launch.
func (i *DNSPluginInstaller) attempt(ctx context.Context, missing []string) error {
	var pkgs, want []string
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
	if bin := ResolveCaddy(i.DataDir); bin != "" {
		if mods, err := CaddyModules(ctx, bin); err == nil && hasAll(mods, want) {
			i.markOnDisk()
			i.log().Info("edge: the Caddy on disk already has the DNS plugin(s); restarting the edge onto it", "caddy", bin)
			i.swap()
			return nil
		}
	}
	// Carry plugins over only from the system caddy (root-owned): the Mooring-owned build is writable by
	// the service user, so its own report of what's built in must not decide what goes into the next
	// build.
	var extras []string
	if sys, err := exec.LookPath("caddy"); err == nil {
		if x, xerr := CaddyExtraPackages(ctx, sys); xerr != nil {
			i.log().Warn("edge: can't read the plugins in the system Caddy (needs `list-modules --packages --skip-standard`); the new build has only the DNS providers",
				"caddy", sys, "err", xerr.Error())
		} else {
			extras = x
		}
	}
	for _, x := range extras {
		if !seen[x] {
			seen[x] = true
			pkgs = append(pkgs, x)
		}
	}
	sort.Strings(pkgs)
	for _, p := range missing {
		i.State.update(p, func(s *ProviderStatus) { s.Installing = true })
	}
	i.log().Info("edge: installing a Caddy build with the DNS plugin(s) for the wildcard certs",
		"missing", strings.Join(missing, ","), "packages", strings.Join(pkgs, ","), "path", OwnedCaddyPath(i.DataDir))
	install := i.Install
	if install == nil {
		install = InstallPluginBuild
	}
	opt := InstallOptions{DataDir: i.DataDir, Packages: pkgs, WantModules: want, BuildServer: i.BuildServer, Client: i.Client}
	path, err := install(ctx, opt)
	if err != nil && len(extras) > 0 {
		// A carried plugin may not build against the latest Caddy; Mooring doesn't use it, so try again
		// with only the DNS providers rather than fail forever.
		i.log().Warn("edge: the Caddy build with the carried plugins failed; retrying with only the DNS providers", "err", err.Error())
		opt.Packages = dnsOnly(pkgs, extras)
		path, err = install(ctx, opt)
	}
	if err != nil {
		for _, p := range missing {
			i.State.update(p, func(s *ProviderStatus) {
				s.Installing = false
				s.Err = err.Error()
				s.Attempts++
			})
		}
		i.log().Warn("edge: Caddy DNS plugin install failed — wildcards using it stay off (subdomains fall back to per-name HTTP-01; a catch-all has no certificate) until it succeeds; retrying with backoff",
			"missing", strings.Join(missing, ","), "err", err.Error())
		return err
	}
	i.markOnDisk()
	i.log().Info("edge: Caddy DNS plugin(s) installed; restarting the edge on the new binary", "path", path)
	i.swap()
	return nil
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
