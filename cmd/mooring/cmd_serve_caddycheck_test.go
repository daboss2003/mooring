package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/edge"
)

// The watcher restarts the edge onto whatever Caddy a package upgrade left on disk only when it would
// accept the rendered config: right major, and the 2.11 minimum when a setting needs it — unless the
// new build is no older than the running one (a patched old build is a security update).
func TestCaddyRelaunchCheck(t *testing.T) {
	plain := &config.Config{}
	plain.Edge.Mode = config.EdgeManaged
	proxied := &config.Config{}
	proxied.Edge.Mode = config.EdgeManaged
	proxied.Edge.TrustedProxies = []string{"cloudflare"}

	cases := []struct {
		name    string
		ver     string // "" = no binary at the path
		running string // version of the running Caddy; "" = unknown
		cfg     *config.Config
		wantErr string
	}{
		{"current official build", "v2.11.3 h1:abc=", "", proxied, ""},
		{"patched distro build, nothing needs 2.11", "2.6.2", "", plain, ""},
		{"next major", "v3.0.0 h1:abc=", "v2.11.3 h1:abc=", plain, "written for Caddy 2"},
		{"below the minimum, running is newer", "2.6.2", "v2.11.3 h1:abc=", proxied, "needed by edge.trusted_proxies"},
		{"below the minimum, running unknown", "2.6.2", "", proxied, "needed by edge.trusted_proxies"},
		{"below the minimum, same version as running (patched)", "2.6.2", "2.6.2", proxied, ""},
		{"unreadable version", "(devel)", "", plain, "unrecognized"},
		{"missing binary", "", "", plain, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "caddy")
			if tc.ver != "" {
				fakeCaddy(t, bin, tc.ver)
			}
			running := ""
			if tc.running != "" {
				running = filepath.Join(dir, "running-caddy")
				fakeCaddy(t, running, tc.running)
			}
			err := caddyRelaunchCheck(context.Background(), bin, running, tc.cfg, nil)
			switch {
			case tc.ver == "":
				if err == nil {
					t.Fatal("a missing binary must fail the check")
				}
			case tc.wantErr == "" && err != nil:
				t.Fatalf("want ok, got %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// After the version checks pass, the binary must also accept the config the edge serves now; a
// rejection blocks the restart, and validate never runs for a binary the version checks refused.
func TestCaddyRelaunchCheckValidates(t *testing.T) {
	cfg := &config.Config{}
	cfg.Edge.Mode = config.EdgeManaged
	bin := filepath.Join(t.TempDir(), "caddy")
	fakeCaddy(t, bin, "v2.11.3 h1:abc=")

	var got string
	refuse := func(_ context.Context, b string) error {
		got = b
		return errors.New("unknown module: dns.providers.cloudflare")
	}
	if err := caddyRelaunchCheck(context.Background(), bin, "", cfg, refuse); err == nil || !strings.Contains(err.Error(), "unknown module") {
		t.Fatalf("a config the new Caddy rejects must block the restart, got %v", err)
	}
	if got != bin {
		t.Fatalf("validate ran on %q, want %q", got, bin)
	}
	if err := caddyRelaunchCheck(context.Background(), bin, "", cfg, func(context.Context, string) error { return nil }); err != nil {
		t.Fatalf("an accepted config must pass, got %v", err)
	}

	next := filepath.Join(t.TempDir(), "caddy")
	fakeCaddy(t, next, "v3.0.0 h1:abc=")
	called := false
	_ = caddyRelaunchCheck(context.Background(), next, "", cfg, func(context.Context, string) error { called = true; return nil })
	if called {
		t.Fatal("validate must not run for a binary the version check refused")
	}
}

// checkRig is a fake `caddy validate`: verdicts maps "<bin>|<config>" to its error (absent: accepted),
// and calls records every validation in order.
type checkRig struct {
	verdicts map[string]error
	calls    []string
}

func (r *checkRig) validate(_ context.Context, bin string, cfg []byte) error {
	k := bin + "|" + string(cfg)
	r.calls = append(r.calls, k)
	return r.verdicts[k]
}

// refusal is a `caddy validate` that ran and refused the config.
func refusal(msg string) error { return fmt.Errorf("%w: %s", edge.ErrValidateRefused, msg) }

// While Caddy refuses the current render, a restart feeds the relaunched Caddy that render again, so the
// check asks whether the new binary fixes the refusal: it must accept the refused render, and the
// running binary must refuse it (the refusal was the binary's). Anything else would trade the config
// the edge serves now for the startup config (every app 404). Nothing accepted yet = the edge already
// serves only the startup config, so the refusal doesn't hold a restart back. The startup config and
// the config accepted last are always checked.
func TestCaddyBuildCheck(t *testing.T) {
	var (
		floor   = []byte(`{"boot":"floor"}`)
		applied = []byte(`{"accepted":"last"}`)
		current = []byte(`{"refused":"trusted_proxies"}`)
	)
	const bin, running = "/usr/bin/caddy", "/proc/4242/exe"
	const why = `edge: admin rejected config (status 400): loading http app module: json: unknown field "trusted_proxies"`
	k := func(b string, cfg []byte) string { return b + "|" + string(cfg) }
	refused := edgeRenders{Initial: floor, LastApplied: applied, Refused: true, RefusedWhy: why, RefusedCfg: current}
	neverAccepted := edgeRenders{Initial: floor, Refused: true, RefusedWhy: why, RefusedCfg: current}
	plain := edgeRenders{Initial: floor, LastApplied: applied}
	oldBinary := refusal(`json: unknown field "trusted_proxies"`)

	cases := []struct {
		name      string
		st        edgeRenders
		running   string
		verdicts  map[string]error
		wantErr   string   // "" = allowed
		wantHeld  bool     // the error says the refusal (not the new files) holds the restart back
		byConfig  bool     // and no build would pass while that config is refused (edge.ErrHeldByConfig)
		wantCalls []string // nil = not checked
	}{
		{name: "refused by the running binary, which the new one fixes", st: refused, running: running,
			verdicts:  map[string]error{k(running, current): oldBinary},
			wantCalls: []string{k(bin, floor), k(bin, current), k(running, current), k(bin, applied)}},
		{name: "the new binary refuses the refused config too", st: refused, running: running,
			verdicts: map[string]error{k(bin, current): refusal("unknown field \"bogus\""), k(running, current): oldBinary},
			wantErr:  `unknown field "bogus"`, wantHeld: true, byConfig: true, wantCalls: []string{k(bin, floor), k(bin, current)}},
		{name: "the new binary can't be checked against the refused config", st: refused, running: running,
			verdicts: map[string]error{k(bin, current): errors.New("`caddy validate` refused the edge config (signal: killed)")},
			wantErr:  "signal: killed", wantHeld: true, wantCalls: []string{k(bin, floor), k(bin, current)}},
		{name: "both binaries accept the refused config", st: refused, running: running,
			wantErr: why, wantHeld: true, byConfig: true, wantCalls: []string{k(bin, floor), k(bin, current), k(running, current)}},
		{name: "no running Caddy to check", st: refused, running: "",
			wantErr: why, wantHeld: true, wantCalls: []string{k(bin, floor), k(bin, current)}},
		{name: "the running Caddy can't be run", st: refused, running: running,
			verdicts: map[string]error{k(running, current): errors.New("fork/exec /proc/4242/exe: permission denied")},
			wantErr:  "permission denied", wantHeld: true},
		{name: "the refused render is unknown", st: edgeRenders{Initial: floor, LastApplied: applied, Refused: true, RefusedWhy: why},
			running: running, wantErr: why, wantHeld: true},
		{name: "the refusal is fixed, but the new binary refuses the config accepted last", st: refused, running: running,
			verdicts: map[string]error{k(running, current): oldBinary, k(bin, applied): refusal("bad last config")},
			wantErr:  "bad last config"},
		{name: "the startup config is checked first, refused or not", st: refused, running: running,
			verdicts: map[string]error{k(bin, floor): refusal("bad floor"), k(running, current): oldBinary},
			wantErr:  "bad floor", wantCalls: []string{k(bin, floor)}},
		{name: "nothing accepted yet: the refusal doesn't hold the restart back", st: neverAccepted, running: running,
			verdicts:  map[string]error{k(bin, current): refusal("still refused")},
			wantCalls: []string{k(bin, floor)}},
		{name: "nothing accepted yet: the startup config is still checked", st: neverAccepted, running: running,
			verdicts: map[string]error{k(bin, floor): refusal("bad floor")}, wantErr: "bad floor"},
		{name: "not refused: the startup config and the config accepted last", st: plain, running: running,
			wantCalls: []string{k(bin, floor), k(bin, applied)}},
		{name: "not refused: the new binary refuses the config accepted last", st: plain, running: running,
			verdicts: map[string]error{k(bin, applied): refusal("bad last config")}, wantErr: "bad last config"},
		{name: "not refused, nothing accepted yet: only the startup config", st: edgeRenders{Initial: floor}, running: running,
			wantCalls: []string{k(bin, floor)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := &checkRig{verdicts: tc.verdicts}
			err := caddyBuildCheck(context.Background(), bin, tc.running, tc.st, rig.validate)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("want the restart allowed, got %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want an error containing %q, got %v", tc.wantErr, err)
			}
			if tc.wantCalls != nil && !slices.Equal(rig.calls, tc.wantCalls) {
				t.Errorf("validated %q; want %q", rig.calls, tc.wantCalls)
			}
			if err == nil {
				return
			}
			// The plugin install loop downloads no further build while this is so: only when the config,
			// not the binary or a check that couldn't run, is the cause.
			if got := errors.Is(err, edge.ErrHeldByConfig); got != tc.byConfig {
				t.Errorf("held by the config = %v; want %v (%v)", got, tc.byConfig, err)
			}
			var held interface{ StaleAdvice() string }
			if isHeld := errors.As(err, &held); isHeld != tc.wantHeld {
				t.Fatalf("held by the refusal = %v; want %v (%v)", isHeld, tc.wantHeld, err)
			}
			if tc.wantHeld {
				// The edge_child_stale alert quotes the error and the advice: neither may claim that a restart
				// of Mooring would not start the edge — it would, on the startup config.
				for _, s := range []string{err.Error(), held.StaleAdvice()} {
					if strings.Contains(s, "would not start") || strings.Contains(s, "dpkg") {
						t.Errorf("a refusal-held restart is not a broken upgrade: %q", s)
					}
				}
				if !strings.Contains(err.Error(), "startup config") {
					t.Errorf("the error must say what a restart would serve: %v", err)
				}
			}
		})
	}
}

// writeVersionedCaddy writes a fake caddy at path that reports ver and, like Caddy before 2.11, refuses
// (exit 1, Caddy's message) any config with a trusted_proxies field when oldFields is set; it accepts
// everything else. Shell builtins only: validate runs in the edge's environment, which has no PATH.
func writeVersionedCaddy(t *testing.T, path, ver string, oldFields bool) {
	t.Helper()
	refuse := ""
	if oldFields {
		refuse = `    if [ "$bad" = 1 ]; then echo 'Error: loading http app module: decoding module config: http: json: unknown field "trusted_proxies"' >&2; exit 1; fi` + "\n"
	}
	script := "#!/bin/sh\ncase \"$1\" in\n" +
		"  version) echo '" + ver + "' ;;\n" +
		"  validate)\n    bad=0\n" +
		"    while IFS= read -r l || [ -n \"$l\" ]; do case \"$l\" in *trusted_proxies*) bad=1 ;; esac; done\n" +
		refuse +
		"    echo 'Valid configuration' ;;\n" +
		"  *) exit 1 ;;\nesac\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
}

// The reported regression, through the real renders and the real `caddy validate` wrapper: Ubuntu's
// Caddy 2.6.2 refuses every reconcile once edge.trusted_proxies is set (the edge serves only the boot
// floor). When `mooring setup --yes` upgrades it to 2.11, the restart onto 2.11 is allowed — whether or
// not some render was accepted before — and a candidate that is just as old is not.
func TestCaddyBuildCheckOldCaddyRefusingTrustedProxies(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	old, cur, otherOld := filepath.Join(dir, "caddy-2.6.2"), filepath.Join(dir, "caddy-2.11"), filepath.Join(dir, "caddy-2.6.3")
	writeVersionedCaddy(t, old, "2.6.2", true)
	writeVersionedCaddy(t, cur, "v2.11.9 h1:abc=", false)
	writeVersionedCaddy(t, otherOld, "2.6.3", true)

	base := edge.BaseConfig{AdminListen: "unix//run/mooring/caddy-admin.sock", ACMEEmail: "ops@example.com", TrustedProxies: []string{"10.0.0.0/8"}}
	floor, err := edge.Render(edge.BootFloor(base), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	render, err := edge.Render(base, []edge.Route{{Hostname: "shop.example.com", Upstream: "web:8080", Pool: []string{"172.18.0.5:8080"}, UpstreamScheme: "http", Enabled: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(render), "trusted_proxies") || strings.Contains(string(floor), "trusted_proxies") {
		t.Fatal("test setup: the render must carry trusted_proxies and the boot floor must not")
	}
	validate := func(c context.Context, bin string, cfg []byte) error { return edge.ValidateConfig(c, bin, cfg, nil) }
	if err := validate(ctx, old, render); !errors.Is(err, edge.ErrValidateRefused) {
		t.Fatalf("test setup: the old Caddy must refuse the render as Caddy does: %v", err)
	}
	why := `edge: admin rejected config (status 400): loading http app module: decoding module config: http: json: unknown field "trusted_proxies"`

	// As on the server: every reconcile refused, nothing ever accepted.
	onBox := edgeRenders{Initial: floor, Refused: true, RefusedWhy: why, RefusedCfg: render}
	if err := caddyBuildCheck(ctx, cur, old, onBox, validate); err != nil {
		t.Errorf("never accepted: the restart onto 2.11 must be allowed, got %v", err)
	}
	// Some earlier render was accepted (it keeps serving): 2.11 fixes the refusal, 2.6.2 is its cause.
	earlier := edgeRenders{Initial: floor, LastApplied: floor, Refused: true, RefusedWhy: why, RefusedCfg: render}
	if err := caddyBuildCheck(ctx, cur, old, earlier, validate); err != nil {
		t.Errorf("refused by the running 2.6.2: the restart onto 2.11 must be allowed, got %v", err)
	}
	// The relaunch check the stale watcher runs (version gates, then this check) agrees.
	cfg := &config.Config{}
	cfg.Edge.Mode = config.EdgeManaged
	cfg.Edge.TrustedProxies = []string{"10.0.0.0/8"}
	check := func(c context.Context, b string) error { return caddyBuildCheck(c, b, old, earlier, validate) }
	if err := caddyRelaunchCheck(ctx, cur, old, cfg, check); err != nil {
		t.Errorf("the stale watcher must restart the edge onto 2.11, got %v", err)
	}
	// A candidate just as old refuses the render too: no restart, and the error says why.
	err = caddyBuildCheck(ctx, otherOld, old, earlier, validate)
	var held interface{ StaleAdvice() string }
	if err == nil || !strings.Contains(err.Error(), `unknown field "trusted_proxies"`) || !errors.As(err, &held) {
		t.Errorf("a candidate that refuses the render too must be refused with Caddy's error, got %v", err)
	}
}
