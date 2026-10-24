package edge

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeCaddy returns a shell script that answers `version` with version, `list-modules` with modules,
// and `list-modules --packages --skip-standard` with "<id> <path>" lines from pkgs.
func fakeCaddy(version string, modules []string, pkgs map[string]string) []byte {
	var plain, packaged strings.Builder
	for _, m := range modules {
		fmt.Fprintf(&plain, "echo %q\n", m)
	}
	for id, p := range pkgs {
		fmt.Fprintf(&packaged, "echo %q\n", id+" "+p)
	}
	return []byte("#!/bin/sh\n" +
		"case \"$1\" in\n" +
		"  version) echo " + fmt.Sprintf("%q", version) + " ;;\n" +
		"  list-modules)\n" +
		"    if [ \"$2\" = \"--packages\" ]; then\n" + packaged.String() +
		"      echo ''\n      echo '  Non-standard modules: 1'\n" +
		"    else\n" + plain.String() +
		"      echo ''\n      echo '  Standard modules: 106'\n" +
		"    fi ;;\n" +
		"  *) echo 'Error: unknown command' >&2; echo \"Run 'caddy --help' for usage.\" >&2; exit 1 ;;\n" +
		"esac\n")
}

// leftoverDownloads lists any caddy.new* files in <dataDir>/bin.
func leftoverDownloads(t *testing.T, dataDir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dataDir, "bin", "caddy.new*"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func skipNoShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
}

func writeExec(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o700); err != nil {
		t.Fatal(err)
	}
}

// buildServer is a TLS test build server returning body for every request (and counting them).
func buildServer(t *testing.T, status int, body []byte) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestParseCaddyVersion(t *testing.T) {
	ok := map[string]Version{
		"v2.11.2 h1:abcdef=":      {2, 11, 2},
		"2.6.2":                   {2, 6, 2},
		"v2.11.0-beta.1 h1:x":     {2, 11, 0},
		"v2.10 h1:x":              {2, 10, 0},
		"2.6.2\nsomething else\n": {2, 6, 2},
	}
	for in, want := range ok {
		if got, ok := ParseCaddyVersion(in); !ok || got != want {
			t.Errorf("ParseCaddyVersion(%q) = %v,%v; want %v", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "(devel)", "v2", "vX.Y.Z", "2.a.1"} {
		if _, ok := ParseCaddyVersion(bad); ok {
			t.Errorf("ParseCaddyVersion(%q) should fail", bad)
		}
	}
	if !(Version{2, 11, 0}).AtLeast(MinCaddyVersion) || (Version{2, 10, 9}).AtLeast(MinCaddyVersion) ||
		!(Version{3, 0, 0}).AtLeast(MinCaddyVersion) || (Version{2, 6, 2}).AtLeast(MinCaddyVersion) {
		t.Error("Version.AtLeast is wrong around 2.11")
	}
}

// Package paths reach the download URL, so anything but a plain module path is refused.
func TestBuildServerURLRejectsInjection(t *testing.T) {
	u, err := BuildServerURL("", "linux", "amd64", []string{"github.com/caddy-dns/cloudflare", "github.com/caddy-dns/route53"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u, DefaultBuildServer+"?") || strings.Count(u, "p=") != 2 ||
		!strings.Contains(u, "os=linux") || !strings.Contains(u, "arch=amd64") {
		t.Errorf("unexpected URL %s", u)
	}
	for _, bad := range []string{
		"github.com/x&p=evil", "github.com/../x", " github.com/x", "github.com/a b", "http://github.com/x",
		"GITHUB.COM/x", "github.com", "localhost/x", "github.com/x?y=1", "github.com/x#y", strings.Repeat("a", 200) + ".com/x/y", // over the 200-char cap
	} {
		if _, err := BuildServerURL("", "linux", "amd64", []string{bad}); err == nil {
			t.Errorf("package path %q must be refused", bad)
		}
	}
	if _, err := BuildServerURL("http://caddyserver.com/api/download", "linux", "amd64", []string{"github.com/x/y"}); err == nil {
		t.Error("a non-https build server must be refused")
	}
	if _, err := BuildServerURL("", "linux;rm", "amd64", []string{"github.com/x/y"}); err == nil {
		t.Error("an invalid os must be refused")
	}
}

func TestInstallPluginBuildSwapsSafely(t *testing.T) {
	skipNoShell(t)
	ctx := context.Background()
	dataDir := t.TempDir()
	want := []string{"dns.providers.cloudflare"}
	good := fakeCaddy("v2.11.2 h1:x", []string{"http.handlers.reverse_proxy", "dns.providers.cloudflare"}, nil)
	srv, hits := buildServer(t, http.StatusOK, good)

	opt := InstallOptions{DataDir: dataDir, Packages: []string{"github.com/caddy-dns/cloudflare"}, WantModules: want,
		BuildServer: srv.URL, Client: srv.Client(), GOOS: "linux", GOARCH: "amd64"}
	path, err := InstallPluginBuild(ctx, opt)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if path != OwnedCaddyPath(dataDir) || ResolveCaddy(dataDir) != path {
		t.Fatalf("installed at %q, resolve=%q; want the owned path", path, ResolveCaddy(dataDir))
	}
	if left := leftoverDownloads(t, dataDir); len(left) != 0 {
		t.Errorf("downloads left behind: %v", left)
	}
	if hits.Load() != 1 {
		t.Errorf("build server hits = %d, want 1", hits.Load())
	}

	// A second install keeps the previous build as .bak.
	if err := os.WriteFile(path, append(good, []byte("# previous\n")...), 0o700); err != nil {
		t.Fatal(err)
	}
	prev, _ := os.ReadFile(path)
	if _, err := InstallPluginBuild(ctx, opt); err != nil {
		t.Fatalf("second install: %v", err)
	}
	bak, err := os.ReadFile(path + ".bak")
	if err != nil || !bytes.Equal(bak, prev) {
		t.Errorf(".bak must hold the previous binary (err=%v)", err)
	}
	if now, _ := os.ReadFile(path); !bytes.Equal(now, good) {
		t.Error("the new build must be at the owned path")
	}
}

// Every bad download is refused WITHOUT touching the current binary.
func TestInstallPluginBuildRefusesBadDownloads(t *testing.T) {
	skipNoShell(t)
	ctx := context.Background()
	want := []string{"dns.providers.cloudflare"}
	cases := []struct {
		name    string
		status  int
		body    []byte
		errPart string
	}{
		{"does not run", http.StatusOK, []byte("\x7fELF garbage"), "does not run"},
		{"too old", http.StatusOK, fakeCaddy("2.6.2", []string{"dns.providers.cloudflare"}, nil), "older than"},
		{"future major", http.StatusOK, fakeCaddy("v3.0.0 h1:x", []string{"dns.providers.cloudflare"}, nil), "supports Caddy 2.x"},
		{"module missing", http.StatusOK, fakeCaddy("v2.11.2 h1:x", []string{"http.handlers.reverse_proxy"}, nil), "lacks dns.providers.cloudflare"},
		{"server error", http.StatusBadRequest, []byte("invalid package path\nsecond line"), "400"},
		{"empty", http.StatusOK, nil, "empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dataDir := t.TempDir()
			current := fakeCaddy("v2.11.0 h1:current", []string{"http.handlers.reverse_proxy"}, nil)
			writeExec(t, OwnedCaddyPath(dataDir), current)
			srv, _ := buildServer(t, c.status, c.body)
			_, err := InstallPluginBuild(ctx, InstallOptions{DataDir: dataDir, Packages: []string{"github.com/caddy-dns/cloudflare"},
				WantModules: want, BuildServer: srv.URL, Client: srv.Client(), GOOS: "linux", GOARCH: "amd64"})
			if err == nil || !strings.Contains(err.Error(), c.errPart) {
				t.Fatalf("err = %v; want it to mention %q", err, c.errPart)
			}
			if got, _ := os.ReadFile(OwnedCaddyPath(dataDir)); !bytes.Equal(got, current) {
				t.Error("a refused download must leave the current binary untouched")
			}
			if left := leftoverDownloads(t, dataDir); len(left) != 0 {
				t.Errorf("downloads left behind after a refused download: %v", left)
			}
			if _, err := os.Stat(OwnedCaddyPath(dataDir) + ".bak"); !errors.Is(err, os.ErrNotExist) {
				t.Error(".bak must not exist after a refused download")
			}
		})
	}
}

func TestInstallPluginBuildRefusesOversizeAndPlainRedirect(t *testing.T) {
	skipNoShell(t)
	ctx := context.Background()
	opt := func(srv *httptest.Server, dataDir string) InstallOptions {
		return InstallOptions{DataDir: dataDir, Packages: []string{"github.com/caddy-dns/cloudflare"},
			WantModules: []string{"dns.providers.cloudflare"}, BuildServer: srv.URL, Client: srv.Client(), GOOS: "linux", GOARCH: "amd64"}
	}

	old := maxCaddyDownload
	maxCaddyDownload = 64
	t.Cleanup(func() { maxCaddyDownload = old })
	big, _ := buildServer(t, http.StatusOK, bytes.Repeat([]byte("x"), 200))
	if _, err := InstallPluginBuild(ctx, opt(big, t.TempDir())); err == nil || !strings.Contains(err.Error(), "over") {
		t.Errorf("an oversize download must be refused, got %v", err)
	}
	maxCaddyDownload = old

	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(fakeCaddy("v2.11.2 h1:x", []string{"dns.providers.cloudflare"}, nil))
	}))
	t.Cleanup(plain.Close)
	redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/caddy", http.StatusFound)
	}))
	t.Cleanup(redir.Close)
	dataDir := t.TempDir()
	if _, err := InstallPluginBuild(ctx, opt(redir, dataDir)); err == nil || !strings.Contains(err.Error(), "off https") {
		t.Errorf("a redirect to plain http must be refused, got %v", err)
	}
	if ResolveCaddy(dataDir) == OwnedCaddyPath(dataDir) {
		t.Error("nothing may be installed after a refused redirect")
	}
}

func TestResolveCaddyPrefersOwnedThenPath(t *testing.T) {
	skipNoShell(t)
	pathDir := t.TempDir()
	writeExec(t, filepath.Join(pathDir, "caddy"), fakeCaddy("2.6.2", nil, nil))
	t.Setenv("PATH", pathDir)
	dataDir := t.TempDir()
	if got := ResolveCaddy(dataDir); got != filepath.Join(pathDir, "caddy") {
		t.Errorf("no owned build: resolve = %q, want the PATH caddy", got)
	}
	owned := OwnedCaddyPath(dataDir)
	if err := os.MkdirAll(filepath.Dir(owned), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(owned, []byte("#!/bin/sh\n"), 0o600); err != nil { // not executable
		t.Fatal(err)
	}
	if got := ResolveCaddy(dataDir); got == owned {
		t.Error("a non-executable owned file must not be used")
	}
	if err := os.Chmod(owned, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := ResolveCaddy(dataDir); got != owned {
		t.Errorf("resolve = %q, want the owned build %q", got, owned)
	}
	t.Setenv("PATH", t.TempDir())
	if got := ResolveCaddy(t.TempDir()); got != "" {
		t.Errorf("no caddy anywhere: resolve = %q, want empty", got)
	}
}

func TestCaddyModulesAndExtraPackages(t *testing.T) {
	skipNoShell(t)
	ctx := context.Background()
	bin := filepath.Join(t.TempDir(), "caddy")
	writeExec(t, bin, fakeCaddy("v2.11.2 h1:x", []string{"http.handlers.reverse_proxy", "dns.providers.route53"},
		map[string]string{"dns.providers.route53": "github.com/caddy-dns/route53", "http.handlers.bad": "not a path"}))
	mods, err := CaddyModules(ctx, bin)
	if err != nil || !mods["dns.providers.route53"] || !mods["http.handlers.reverse_proxy"] || mods["Standard"] {
		t.Errorf("modules = %v, err %v", mods, err)
	}
	pkgs, err := CaddyExtraPackages(ctx, bin)
	if err != nil || len(pkgs) != 1 || pkgs[0] != "github.com/caddy-dns/route53" {
		t.Errorf("extra packages = %v, err %v (want only the valid route53 path)", pkgs, err)
	}
	v, err := CaddyVersion(ctx, bin)
	if err != nil || v != (Version{2, 11, 2}) {
		t.Errorf("version = %v, err %v", v, err)
	}
}

// The failure that hid the real cause: Caddy 2.6.2 prints the useful line FIRST and a generic hint
// last. The error must carry both.
func TestRunCaddyErrorKeepsTheCause(t *testing.T) {
	skipNoShell(t)
	bin := filepath.Join(t.TempDir(), "caddy")
	writeExec(t, bin, fakeCaddy("2.6.2", nil, nil))
	_, err := runCaddy(context.Background(), bin, "add-package", "github.com/caddy-dns/cloudflare")
	if err == nil || !strings.Contains(err.Error(), "unknown command") || !strings.Contains(err.Error(), "caddy --help") {
		t.Errorf("the error must keep the whole tail, got %v", err)
	}
	long := strings.Repeat("line\n", 50) + "last"
	if got := tailLines([]byte(long), 20); strings.Count(got, "|") != 19 || !strings.HasSuffix(got, "last") {
		t.Errorf("tailLines kept the wrong lines: %q", got)
	}
}

func TestDNSPluginInstallerRetriesThenSwaps(t *testing.T) {
	skipNoShell(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pathDir := t.TempDir()
	writeExec(t, filepath.Join(pathDir, "caddy"), fakeCaddy("2.6.2", []string{"http.handlers.reverse_proxy"},
		map[string]string{"http.handlers.extra": "github.com/acme/caddy-extra"}))
	t.Setenv("PATH", pathDir)

	state := NewDNSPlugins([]string{"cloudflare", "Route53", "nosuch"})
	dataDir := t.TempDir()
	var calls, swaps atomic.Int32
	var gotPkgs []string
	inst := &DNSPluginInstaller{
		DataDir: dataDir, Providers: []string{"cloudflare", "Route53", "nosuch"}, State: state,
		OnSwap: func() { swaps.Add(1) }, MinBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond,
		Install: func(_ context.Context, opt InstallOptions) (string, error) {
			if calls.Add(1) <= 2 {
				// The whole first attempt fails (with the carried plugin, then without it): state must show
				// the providers as KNOWN missing with the reason, and Run must back off and retry.
				return "", errors.New("edge: download a Caddy plugin build: dial tcp: no route to host")
			}
			gotPkgs = opt.Packages
			// A real build lands on disk; Sync on the next launch reads its modules.
			writeExec(t, OwnedCaddyPath(opt.DataDir), fakeCaddy("v2.11.2 h1:x", []string{"dns.providers.cloudflare", "dns.providers.route53"}, nil))
			return OwnedCaddyPath(opt.DataDir), nil
		},
	}
	missing := inst.Check(ctx)
	if len(missing) != 2 {
		t.Fatalf("missing = %v, want cloudflare + route53 (nosuch is unknown, not installable)", missing)
	}
	if m, why := state.KnownMissing("nosuch"); !m || !strings.Contains(why, "unknown DNS provider") {
		t.Errorf("an unknown provider is known-missing for good: %v %q", m, why)
	}
	if m, _ := state.KnownMissing("cloudflare"); m {
		t.Error("before any install attempt a provider is not KNOWN missing")
	}

	inst.Run(ctx)
	if calls.Load() != 3 || swaps.Load() != 1 {
		t.Fatalf("install calls = %d, swaps = %d; want a failed attempt (2 calls), then one success + one restart", calls.Load(), swaps.Load())
	}
	// The swap landed but the edge hasn't relaunched yet: on disk, NOT ok — a wildcard rendered now would
	// go to the old child, which lacks the module.
	if st := state.Status("cloudflare"); !st.OnDisk || st.OK || st.Err != "" || st.Installing || !st.NextAttempt.IsZero() || st.Attempts != 1 {
		t.Errorf("cloudflare status after the swap = %+v; want on disk, not OK, one failed attempt", st)
	}
	want := []string{"github.com/acme/caddy-extra", "github.com/caddy-dns/cloudflare", "github.com/caddy-dns/route53"}
	if strings.Join(gotPkgs, ",") != strings.Join(want, ",") {
		t.Errorf("packages = %v, want every configured provider plus the plugin carried from the system caddy %v", gotPkgs, want)
	}

	// The edge relaunches on the owned build: Sync reads ITS modules.
	if read, enabled := inst.Sync(ctx, inst.Launched()); !read || !enabled {
		t.Errorf("Sync read=%v enabled=%v; want the new binary read and its wildcards enabled", read, enabled)
	}
	if !state.OK("cloudflare") || !state.OK("route53") || state.OK("nosuch") {
		t.Errorf("after the relaunch: cloudflare=%v route53=%v nosuch=%v", state.OK("cloudflare"), state.OK("route53"), state.OK("nosuch"))
	}
}

// A carried plugin that won't build doesn't fail the install forever: the same attempt retries with
// only the DNS providers.
func TestDNSPluginInstallerDropsUnbuildableExtras(t *testing.T) {
	skipNoShell(t)
	pathDir := t.TempDir()
	writeExec(t, filepath.Join(pathDir, "caddy"), fakeCaddy("2.6.2", nil, map[string]string{"http.handlers.extra": "github.com/acme/caddy-extra"}))
	t.Setenv("PATH", pathDir)
	state := NewDNSPlugins([]string{"cloudflare"})
	var tried [][]string
	inst := &DNSPluginInstaller{DataDir: t.TempDir(), Providers: []string{"cloudflare"}, State: state, MinBackoff: time.Millisecond,
		Install: func(_ context.Context, opt InstallOptions) (string, error) {
			tried = append(tried, opt.Packages)
			for _, p := range opt.Packages {
				if p == "github.com/acme/caddy-extra" {
					return "", errors.New("build failed: github.com/acme/caddy-extra doesn't compile against this Caddy")
				}
			}
			return OwnedCaddyPath(opt.DataDir), nil
		}}
	inst.Check(context.Background())
	inst.Run(context.Background())
	if len(tried) != 2 || strings.Join(tried[1], ",") != "github.com/caddy-dns/cloudflare" {
		t.Fatalf("attempts = %v; want one with the carried plugin, then one with only cloudflare", tried)
	}
	if st := state.Status("cloudflare"); !st.OnDisk || st.Attempts != 0 {
		t.Errorf("status = %+v; the fallback build succeeded within the same attempt", st)
	}
}

// When the binary on disk already has the modules (`mooring setup` installed a build meanwhile), the
// installer only restarts the edge onto it — no download.
func TestDNSPluginInstallerRestartsOntoBuildAlreadyOnDisk(t *testing.T) {
	skipNoShell(t)
	t.Setenv("PATH", t.TempDir())
	dataDir := t.TempDir()
	state := NewDNSPlugins([]string{"cloudflare"})
	var swaps atomic.Int32
	inst := &DNSPluginInstaller{DataDir: dataDir, Providers: []string{"cloudflare"}, State: state, OnSwap: func() { swaps.Add(1) },
		Install: func(context.Context, InstallOptions) (string, error) { t.Error("must not download"); return "", nil }}
	inst.Check(context.Background()) // no caddy at all yet → missing
	writeExec(t, OwnedCaddyPath(dataDir), fakeCaddy("v2.11.2 h1:x", []string{"dns.providers.cloudflare"}, nil))
	inst.Run(context.Background())
	if swaps.Load() != 1 || !state.Status("cloudflare").OnDisk {
		t.Errorf("swaps = %d, status = %+v; want one restart onto the build already on disk", swaps.Load(), state.Status("cloudflare"))
	}
}

// flakyCaddy is a fake caddy (with modules) whose every command fails while marker exists: a read that
// fails and later succeeds on the SAME file.
func flakyCaddy(marker string, modules ...string) []byte {
	var b strings.Builder
	for _, m := range modules {
		fmt.Fprintf(&b, "echo %q\n", m)
	}
	return []byte("#!/bin/sh\n[ -f " + marker + " ] && exit 1\ncase \"$1\" in\n  version) echo 'v2.11.2 h1:x' ;;\n  list-modules)\n" + b.String() + "  ;;\nesac\n")
}

// Sync fails closed and loud: while the launched binary's modules can't be read, no wildcard is rendered
// and the provider carries the read error (so the gate, the catch-all watch and the dashboard see it).
// The read is retried, and a later success clears the error.
func TestDNSPluginInstallerSyncRetriesAndSurfacesFailure(t *testing.T) {
	skipNoShell(t)
	dataDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "fail")
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	writeExec(t, OwnedCaddyPath(dataDir), flakyCaddy(marker, "dns.providers.cloudflare"))
	t.Setenv("PATH", t.TempDir())
	state := NewDNSPlugins([]string{"cloudflare"})
	state.update("cloudflare", func(s *ProviderStatus) { s.OK, s.OnDisk = true, true })
	inst := &DNSPluginInstaller{DataDir: dataDir, Providers: []string{"cloudflare"}, State: state, Log: quietLog(), SyncRetry: 20 * time.Millisecond}
	gen := inst.Launched()
	if state.OK("cloudflare") {
		t.Fatal("a launch on a binary never read clears OK until Sync has read it")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	type result struct{ read, enabled bool }
	res := make(chan result, 1)
	go func() { r, e := inst.Sync(ctx, gen); res <- result{r, e} }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		if m, why := state.KnownMissing("cloudflare"); m && strings.HasPrefix(why, syncErrPrefix) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a failed read must surface on the provider: %+v", state.Status("cloudflare"))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.Remove(marker); err != nil { // the same binary becomes readable
		t.Fatal(err)
	}
	select {
	case r := <-res:
		if !r.read || !r.enabled {
			t.Errorf("Sync read=%v enabled=%v; want both once the retry succeeds", r.read, r.enabled)
		}
	case <-ctx.Done():
		t.Fatal("Sync never retried")
	}
	if st := state.Status("cloudflare"); !st.OK || st.SyncErr != "" || st.Err != "" {
		t.Errorf("after the retry succeeded: %+v; want OK with no error", st)
	}
}

// A failed read, and the good read after it, never hide an install failure: the provider stays known
// missing with the install error.
func TestDNSPluginInstallerReadFailureKeepsInstallError(t *testing.T) {
	skipNoShell(t)
	dataDir := t.TempDir()
	writeExec(t, OwnedCaddyPath(dataDir), fakeCaddy("v2.11.2 h1:x", nil, nil))
	t.Setenv("PATH", t.TempDir())
	state := NewDNSPlugins([]string{"cloudflare"})
	state.update("cloudflare", func(s *ProviderStatus) { s.Err, s.Attempts = "download failed", 3 })
	inst := &DNSPluginInstaller{DataDir: dataDir, Providers: []string{"cloudflare"}, State: state, Log: quietLog()}
	gen := inst.Launched()
	id := statBin(OwnedCaddyPath(dataDir))
	inst.applySync(gen, id, id, nil, errors.New("signal: killed"))
	if m, why := state.KnownMissing("cloudflare"); !m || why != "download failed" || !strings.HasPrefix(state.Status("cloudflare").SyncErr, syncErrPrefix) {
		t.Errorf("after a failed read: missing=%v why=%q status=%+v", m, why, state.Status("cloudflare"))
	}
	inst.applySync(gen, id, id, map[string]bool{}, nil)
	if m, why := state.KnownMissing("cloudflare"); !m || why != "download failed" || state.Status("cloudflare").SyncErr != "" {
		t.Errorf("after a good read without the module: missing=%v why=%q status=%+v", m, why, state.Status("cloudflare"))
	}
}

// A relaunch on the same binary keeps OK, so the config pushed right after it carries the wildcards at
// once; a relaunch on a different file clears it until Sync has read that file.
func TestDNSPluginInstallerRelaunchKeepsOKOnTheSameBinary(t *testing.T) {
	skipNoShell(t)
	dataDir := t.TempDir()
	writeExec(t, OwnedCaddyPath(dataDir), fakeCaddy("v2.11.2 h1:x", []string{"dns.providers.cloudflare"}, nil))
	t.Setenv("PATH", t.TempDir())
	state := NewDNSPlugins([]string{"cloudflare"})
	inst := &DNSPluginInstaller{DataDir: dataDir, Providers: []string{"cloudflare"}, State: state, Log: quietLog()}
	if missing := inst.Check(context.Background()); len(missing) != 0 {
		t.Fatalf("missing = %v", missing)
	}
	gen := inst.Launched()
	if !state.OK("cloudflare") {
		t.Fatal("the first launch of the binary Check read must keep OK")
	}
	if read, enabled := inst.Sync(context.Background(), gen); !read || enabled || !state.OK("cloudflare") {
		t.Errorf("Sync on the same binary: read=%v enabled=%v ok=%v; want read, nothing newly enabled", read, enabled, state.OK("cloudflare"))
	}
	if inst.Launched(); !state.OK("cloudflare") {
		t.Error("a relaunch on the same binary must keep OK")
	}

	tmp := OwnedCaddyPath(dataDir) + ".tmp"
	writeExec(t, tmp, fakeCaddy("v2.11.3 h1:y", []string{"dns.providers.cloudflare"}, nil))
	if err := os.Rename(tmp, OwnedCaddyPath(dataDir)); err != nil {
		t.Fatal(err)
	}
	gen = inst.Launched()
	if state.OK("cloudflare") {
		t.Error("a launch on a different file must clear OK until it is read")
	}
	if read, enabled := inst.Sync(context.Background(), gen); !read || !enabled {
		t.Errorf("Sync on the new file: read=%v enabled=%v; want both", read, enabled)
	}
}

// A relaunch on the binary already read needs no new read: a read that would fail now (a busy host) can't
// switch its wildcards off.
func TestDNSPluginInstallerSameBinaryUnreadableKeepsOK(t *testing.T) {
	skipNoShell(t)
	dataDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "fail")
	writeExec(t, OwnedCaddyPath(dataDir), flakyCaddy(marker, "dns.providers.cloudflare"))
	t.Setenv("PATH", t.TempDir())
	state := NewDNSPlugins([]string{"cloudflare"})
	inst := &DNSPluginInstaller{DataDir: dataDir, Providers: []string{"cloudflare"}, State: state, Log: quietLog(), SyncRetry: time.Millisecond}
	inst.Check(context.Background())
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if read, enabled := inst.Sync(ctx, inst.Launched()); !read || enabled {
		t.Errorf("read=%v enabled=%v; want the known binary taken as read", read, enabled)
	}
	if st := state.Status("cloudflare"); !st.OK || st.SyncErr != "" {
		t.Errorf("status = %+v; want OK kept, no read error", st)
	}
}

// A read of a build swapped in after the launch says nothing about the running child: it is discarded.
func TestDNSPluginInstallerSyncDiscardsABuildSwappedInAfterLaunch(t *testing.T) {
	skipNoShell(t)
	dataDir := t.TempDir()
	writeExec(t, OwnedCaddyPath(dataDir), fakeCaddy("v2.11.2 h1:x", nil, nil))
	t.Setenv("PATH", t.TempDir())
	state := NewDNSPlugins([]string{"cloudflare"})
	inst := &DNSPluginInstaller{DataDir: dataDir, Providers: []string{"cloudflare"}, State: state, Log: quietLog()}
	gen := inst.Launched() // the child runs a build never read, without the module
	tmp := OwnedCaddyPath(dataDir) + ".tmp"
	writeExec(t, tmp, fakeCaddy("v2.11.2 h1:x", []string{"dns.providers.cloudflare"}, nil))
	if err := os.Rename(tmp, OwnedCaddyPath(dataDir)); err != nil {
		t.Fatal(err)
	}
	if read, _ := inst.Sync(context.Background(), gen); read || state.OK("cloudflare") {
		t.Errorf("a build swapped in after the launch must not be credited to the running child: read=%v ok=%v", read, state.OK("cloudflare"))
	}
}

// A module that disappears from the binary (a package upgrade replaced the system caddy) is installed
// again; when Mooring runs as root (no owned build), the provider shows why it stays off.
func TestDNSPluginInstallerReinstallsALostModule(t *testing.T) {
	skipNoShell(t)
	pathDir := t.TempDir()
	sys := filepath.Join(pathDir, "caddy")
	writeExec(t, sys, fakeCaddy("v2.11.2 h1:x", []string{"dns.providers.cloudflare"}, nil))
	t.Setenv("PATH", pathDir)
	replaceSystemCaddy := func() {
		tmp := sys + ".tmp"
		writeExec(t, tmp, fakeCaddy("v2.11.3 h1:y", nil, nil))
		if err := os.Rename(tmp, sys); err != nil {
			t.Fatal(err)
		}
	}

	state := NewDNSPlugins([]string{"cloudflare"})
	var swaps atomic.Int32
	inst := &DNSPluginInstaller{DataDir: t.TempDir(), Providers: []string{"cloudflare"}, State: state, Log: quietLog(),
		OnSwap: func() { swaps.Add(1) },
		Install: func(_ context.Context, opt InstallOptions) (string, error) {
			writeExec(t, OwnedCaddyPath(opt.DataDir), fakeCaddy("v2.11.3 h1:y", []string{"dns.providers.cloudflare"}, nil))
			return OwnedCaddyPath(opt.DataDir), nil
		}}
	if missing := inst.Check(context.Background()); len(missing) != 0 {
		t.Fatalf("missing = %v", missing)
	}
	replaceSystemCaddy()
	if read, _ := inst.Sync(context.Background(), inst.Launched()); !read {
		t.Fatal("the relaunched binary must be read")
	}
	inst.Wait()
	if st := state.Status("cloudflare"); swaps.Load() != 1 || !st.OnDisk {
		t.Errorf("swaps = %d, status = %+v; want the module installed again and the edge restarted", swaps.Load(), st)
	}

	writeExec(t, sys, fakeCaddy("v2.11.2 h1:x", []string{"dns.providers.cloudflare"}, nil))
	rootState := NewDNSPlugins([]string{"cloudflare"})
	root := &DNSPluginInstaller{Providers: []string{"cloudflare"}, State: rootState, Log: quietLog()}
	root.Check(context.Background())
	replaceSystemCaddy()
	root.Sync(context.Background(), root.Launched())
	if m, why := rootState.KnownMissing("cloudflare"); !m || !strings.Contains(why, "running as root") {
		t.Errorf("as root, a lost module must be known missing with the reason: %v %q", m, why)
	}
}

// A Sync for an older launch never writes the state: a newer launch's Sync owns it.
func TestDNSPluginInstallerSyncForAnOlderLaunchIsDiscarded(t *testing.T) {
	skipNoShell(t)
	dataDir := t.TempDir()
	writeExec(t, OwnedCaddyPath(dataDir), fakeCaddy("v2.11.2 h1:x", []string{"dns.providers.cloudflare"}, nil))
	t.Setenv("PATH", t.TempDir())
	state := NewDNSPlugins([]string{"cloudflare"})
	inst := &DNSPluginInstaller{DataDir: dataDir, Providers: []string{"cloudflare"}, State: state, Log: quietLog()}
	old := inst.Launched()
	cur := inst.Launched()
	if read, _ := inst.Sync(context.Background(), old); read || state.OK("cloudflare") {
		t.Error("a superseded Sync must not write the state")
	}
	if read, _ := inst.Sync(context.Background(), cur); !read || !state.OK("cloudflare") {
		t.Error("the current launch's Sync must set OK")
	}
}

// Run never spins on a provider it can't install, even without a prior Check.
func TestDNSPluginInstallerRunSkipsUnknown(t *testing.T) {
	done := make(chan struct{})
	go func() {
		(&DNSPluginInstaller{DataDir: t.TempDir(), Providers: []string{"nosuch"}, State: NewDNSPlugins([]string{"nosuch"}),
			Install: func(context.Context, InstallOptions) (string, error) { return "", nil }}).Run(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run must return when the only provider is unknown (no install loop)")
	}
}

// An install that lands for one provider must not wipe another provider's permanent error: it stays
// known missing, with its reason.
func TestDNSPluginInstallerKeepsPermanentErrorAcrossInstall(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	state := NewDNSPlugins([]string{"cloudflare", "route53"})
	state.MarkUnavailable("route53", "Caddy rejected it")
	inst := &DNSPluginInstaller{DataDir: t.TempDir(), Providers: []string{"cloudflare", "route53"}, State: state, Log: quietLog(),
		Install: func(_ context.Context, opt InstallOptions) (string, error) { return OwnedCaddyPath(opt.DataDir), nil }}
	inst.Run(context.Background())
	if !state.Status("cloudflare").OnDisk {
		t.Fatalf("cloudflare install should have landed: %+v", state.Status("cloudflare"))
	}
	if m, why := state.KnownMissing("route53"); !m || why != "Caddy rejected it" {
		t.Errorf("route53 after another provider's install: missing=%v why=%q; want its permanent error kept", m, why)
	}
}

// A namespace Caddy refused is off on its own: another namespace on the same provider stays active.
func TestDNSPluginsNamespaceRejection(t *testing.T) {
	state := NewDNSPlugins([]string{"cloudflare"})
	state.update("cloudflare", func(s *ProviderStatus) { s.OK = true })
	state.RejectNamespace("Staging.Example.com.", "bad token")
	if state.Active("cloudflare", "staging.example.com") {
		t.Error("a refused namespace must not be active")
	}
	if !state.Active("cloudflare", "shop.example.com") {
		t.Error("another namespace on the same provider must stay active")
	}
	if r, why := state.NamespaceRejected("staging.example.com"); !r || why != "bad token" {
		t.Errorf("NamespaceRejected = %v %q", r, why)
	}
	state.RejectNamespace("a.example.com", "x")
	if got := state.Rejected(); len(got) != 2 || got[0].Apex != "a.example.com" || got[1].Apex != "staging.example.com" {
		t.Errorf("Rejected() = %+v; want both, sorted by apex", got)
	}
	var nilState *DNSPlugins
	nilState.RejectNamespace("x", "y")
	if nilState.Active("cloudflare", "x") || nilState.Rejected() != nil {
		t.Error("a nil *DNSPlugins must be safe and empty")
	}
}

// Restart relaunches the child at once, on the binary BinFn picks now, without the crash backoff.
func TestSupervisorRestartRelaunchesOnTheNewBinary(t *testing.T) {
	skipNoShell(t)
	dir := t.TempDir()
	launches := filepath.Join(dir, "launches")
	child := func(name string) string {
		p := filepath.Join(dir, name)
		writeExec(t, p, []byte("#!/bin/sh\necho "+name+" >> "+launches+"\nexec /bin/sleep 60\n"))
		return p
	}
	oldBin, newBin := child("old"), child("new")
	var bin atomic.Value
	bin.Store(oldBin)
	var logBuf syncBuffer
	launched := make(chan struct{}, 4)
	s := &Supervisor{BinFn: func() string { return bin.Load().(string) }, Log: slog.New(slog.NewTextHandler(&logBuf, nil)),
		OnLaunch: func() { launched <- struct{}{} }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.supervise(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitLaunch := func() {
		t.Helper()
		select {
		case <-launched:
		case <-time.After(10 * time.Second):
			t.Fatal("the child was not (re)launched")
		}
	}
	// The child script records itself before it sleeps; wait for that, so a stop can't land before it.
	waitLaunches := func(want string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			got, _ := os.ReadFile(launches)
			if string(got) == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("launches = %q; want %q", got, want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitLaunch()
	waitLaunches("old\n")
	bin.Store(newBin)
	s.Restart()
	waitLaunch()
	waitLaunches("old\nnew\n") // the old binary, then the new one
	if out := logBuf.String(); !strings.Contains(out, "edge child restarted") || strings.Contains(out, "edge child exited") {
		t.Errorf("a requested restart must relaunch at once, not as a crash:\n%s", out)
	}
}

// The child's stderr goes through Supervisor.Stderr (serve passes a redacting writer), flushed when the
// child exits.
func TestSupervisorRedactsChildStderr(t *testing.T) {
	skipNoShell(t)
	dir := t.TempDir()
	first, quiet := filepath.Join(dir, "caddy"), filepath.Join(dir, "quiet")
	// The first child ends on a line without a newline; later launches print nothing, so only the flush
	// at the first child's exit can write that line out.
	writeExec(t, first, []byte("#!/bin/sh\necho 'provision: API token secret-0123456789 appears invalid' >&2\nprintf 'last secret-0123456789' >&2\n"))
	writeExec(t, quiet, []byte("#!/bin/sh\nexec /bin/sleep 60\n"))
	var launches atomic.Int32
	var out syncBuffer
	s := &Supervisor{Log: quietLog(), Stderr: NewRedactWriter(&out, []string{"secret-0123456789"}),
		BinFn: func() string {
			if launches.Add(1) == 1 {
				return first
			}
			return quiet
		}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.supervise(ctx); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), "last [redacted]") {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("stderr = %q; want both lines, redacted", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if got := out.String(); strings.Contains(got, "0123456789") || !strings.Contains(got, "API token [redacted] appears invalid") {
		t.Errorf("stderr = %q", got)
	}
}

// syncBuffer is a bytes.Buffer safe for a logger writing from another goroutine.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// Nothing is downloaded when the plugins are already present (no regression for a ready host).
func TestDNSPluginInstallerIdempotent(t *testing.T) {
	skipNoShell(t)
	pathDir := t.TempDir()
	writeExec(t, filepath.Join(pathDir, "caddy"), fakeCaddy("v2.11.2 h1:x", []string{"dns.providers.cloudflare"}, nil))
	t.Setenv("PATH", pathDir)
	state := NewDNSPlugins([]string{"cloudflare"})
	inst := &DNSPluginInstaller{DataDir: t.TempDir(), Providers: []string{"cloudflare"}, State: state,
		Install: func(context.Context, InstallOptions) (string, error) { t.Error("must not install"); return "", nil }}
	if missing := inst.Check(context.Background()); len(missing) != 0 || !state.OK("cloudflare") {
		t.Fatalf("missing = %v, ok = %v", missing, state.OK("cloudflare"))
	}
	inst.Run(context.Background()) // returns at once: nothing pending

	// A provider that can't be installed on this host (Mooring running as root) is known-missing for
	// good, with the reason, and never retried.
	state.MarkUnavailable("cloudflare", "Mooring is running as root")
	if m, why := state.KnownMissing("cloudflare"); !m || why != "Mooring is running as root" || state.OK("cloudflare") {
		t.Errorf("after MarkUnavailable: missing=%v why=%q ok=%v", m, why, state.OK("cloudflare"))
	}
	if p := inst.pending(); len(p) != 0 {
		t.Errorf("an unavailable provider must not be retried, pending = %v", p)
	}
	var nilState *DNSPlugins
	if nilState.OK("x") || nilState.Snapshot() != nil {
		t.Error("a nil *DNSPlugins must be safe and empty")
	}
	if m, _ := nilState.KnownMissing("x"); m {
		t.Error("a nil *DNSPlugins knows nothing missing")
	}
}

func TestSupervisorBinResolution(t *testing.T) {
	s := &Supervisor{CaddyBin: "/usr/bin/caddy"}
	if s.bin() != "/usr/bin/caddy" {
		t.Errorf("bin() = %q", s.bin())
	}
	s.BinFn = func() string { return "/var/lib/mooring/bin/caddy" }
	if s.bin() != "/var/lib/mooring/bin/caddy" {
		t.Error("BinFn must win when it returns a path")
	}
	s.BinFn = func() string { return "" }
	if s.bin() != "/usr/bin/caddy" {
		t.Error("an empty BinFn result falls back to CaddyBin")
	}
	if (&Supervisor{}).bin() != "caddy" {
		t.Error("the default binary is caddy")
	}
	(&Supervisor{}).Restart() // no child: a no-op, never a panic
}

func TestReconcilerRendersReactiveWildcards(t *testing.T) {
	a := WildcardCert{Domain: "a.example.com", DNS01Provider: "cloudflare"}
	b := WildcardCert{Domain: "b.example.com", DNS01Provider: "route53"}
	r := &Reconciler{base: BaseConfig{Wildcards: []WildcardCert{a}}}
	if got := r.renderBase().Wildcards; len(got) != 1 || got[0] != a {
		t.Errorf("no hook: wildcards = %v", got)
	}
	active := []WildcardCert{}
	r.SetWildcards(func() []WildcardCert { return active })
	if got := r.renderBase().Wildcards; len(got) != 0 {
		t.Errorf("hook with nothing active: wildcards = %v", got)
	}
	active = []WildcardCert{b}
	if got := r.renderBase().Wildcards; len(got) != 1 || got[0] != b {
		t.Errorf("hook after an install: wildcards = %v", got)
	}
}

// selfSigned returns a cert for names valid until notAfter.
func selfSigned(t *testing.T, notAfter time.Time, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: notAfter.Add(-48 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsEdge is a stand-in edge: it completes handshakes with getCert and closes.
func tlsEdge(t *testing.T, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: getCert})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_ = c.(*tls.Conn).Handshake()
				c.Close()
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestProbeWildcard(t *testing.T) {
	ctx := context.Background()
	future := time.Now().Add(30 * 24 * time.Hour)
	wild := selfSigned(t, future, "*.shop.example.com")
	addr := tlsEdge(t, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &wild, nil })
	if err := ProbeWildcard(ctx, addr, "shop.example.com"); err != nil {
		t.Errorf("a served wildcard must pass: %v", err)
	}

	other := selfSigned(t, future, "admin.shop.example.com")
	addr = tlsEdge(t, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &other, nil })
	if err := ProbeWildcard(ctx, addr, "shop.example.com"); err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Errorf("a certificate for another name must fail, got %v", err)
	}

	expired := selfSigned(t, time.Now().Add(-time.Hour), "*.shop.example.com")
	addr = tlsEdge(t, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &expired, nil })
	if err := ProbeWildcard(ctx, addr, "shop.example.com"); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("an expired wildcard must fail, got %v", err)
	}

	// What the reported outage looked like: no certificate for the caught name at all.
	addr = tlsEdge(t, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, errors.New("no certificate") })
	if err := ProbeWildcard(ctx, addr, "shop.example.com"); err == nil || !strings.Contains(err.Error(), "no certificate served") {
		t.Errorf("a handshake with no certificate must fail, got %v", err)
	}
}

// A root caller (setup) must never follow a `bin` symlink planted in the service user's data_dir out
// of it: every file operation is confined to data_dir.
func TestInstallPluginBuildRefusesSymlinkedBin(t *testing.T) {
	skipNoShell(t)
	dataDir, target := t.TempDir(), t.TempDir()
	if err := os.Symlink(target, filepath.Join(dataDir, "bin")); err != nil {
		t.Fatal(err)
	}
	srv, _ := buildServer(t, http.StatusOK, fakeCaddy("v2.11.2 h1:x", []string{"dns.providers.cloudflare"}, nil))
	_, err := InstallPluginBuild(context.Background(), InstallOptions{DataDir: dataDir, Packages: []string{"github.com/caddy-dns/cloudflare"},
		WantModules: []string{"dns.providers.cloudflare"}, BuildServer: srv.URL, Client: srv.Client(), GOOS: "linux", GOARCH: "amd64"})
	if err == nil {
		t.Fatal("a symlinked bin dir must be refused")
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Errorf("nothing may be written through the symlink, found %v", entries)
	}
}

// A binary another account can write is never executed (it would run with our identity).
func TestRunCaddyRefusesBinaryOthersCanWrite(t *testing.T) {
	skipNoShell(t)
	bin := filepath.Join(t.TempDir(), "caddy")
	writeExec(t, bin, fakeCaddy("v2.11.2 h1:x", nil, nil))
	if err := os.Chmod(bin, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := CaddyVersion(context.Background(), bin); err == nil || !strings.Contains(err.Error(), "another account can write it") {
		t.Errorf("a world-writable caddy must be refused, got %v", err)
	}
	if err := os.Chmod(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := CaddyVersion(context.Background(), bin); err != nil {
		t.Errorf("our own 0700 caddy must run: %v", err)
	}
}
