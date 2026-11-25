package web

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/config"
)

// reloadYAML is the test server's config with another ip_allowlist (and, optionally, a TOTP secret).
func reloadYAML(e *testEnv, allowlist, totpSecret string) string {
	c := e.srv.cfg
	var b strings.Builder
	fmt.Fprintf(&b, "bind_addr: %q\nencryption_key: %q\nip_allowlist:\n  - %q\n", c.BindAddr, c.EncryptionKey, allowlist)
	fmt.Fprintf(&b, "auth:\n  username: %q\n  password_hash: %q\n", c.Auth.Username, c.Auth.PasswordHash)
	if totpSecret != "" {
		fmt.Fprintf(&b, "  totp_secret: %q\n", totpSecret)
	}
	fmt.Fprintf(&b, "edge:\n  mode: \"managed\"\n  acme_email: \"ops@example.com\"\n  acme_ca: \"https://acme.example/directory\"\n")
	fmt.Fprintf(&b, "data_dir: %q\n", c.DataDir)
	return b.String()
}

func reloadEvents(t *testing.T, e *testEnv) []string {
	t.Helper()
	var out []string
	for _, r := range allGapEvents(t, e.srv.db) {
		if r.Action == "config_reload" {
			out = append(out, r.Outcome+": "+r.Detail)
		}
	}
	return out
}

func allowlistInForce(e *testEnv) []netip.Prefix { return e.srv.security().allowlist }

func prefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

// ReloadWith applies the config it is given and never reads config.yaml: the file on disk is
// missing, then holds another list, and the given config is what is in force both times.
func TestReloadWithAppliesTheGivenConfigNotTheFile(t *testing.T) {
	t.Setenv(config.DevInsecurePermsEnv, "1")
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "config.yaml")
	e.srv.configPath = path // no file there

	given, err := config.Parse([]byte(reloadYAML(e, "203.0.113.0/24", "")))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.ReloadWith(ctx, given); err != nil {
		t.Fatalf("ReloadWith with no file on disk: %v", err)
	}
	if got := allowlistInForce(e); !reflect.DeepEqual(got, prefixes("203.0.113.0/24")) {
		t.Errorf("allowlist = %v, want the given config's", got)
	}
	if got := reloadEvents(t, e); !reflect.DeepEqual(got, []string{"ok: allowlist + auth + token CIDR-union reloaded"}) {
		t.Errorf("events = %q", got)
	}

	// A file that holds another list: still the given config.
	if err := os.WriteFile(path, []byte(reloadYAML(e, "198.51.100.0/24", "")), 0o600); err != nil {
		t.Fatal(err)
	}
	given2, err := config.Parse([]byte(reloadYAML(e, "192.0.2.0/24", "")))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.ReloadWith(ctx, given2); err != nil {
		t.Fatal(err)
	}
	if got := allowlistInForce(e); !reflect.DeepEqual(got, prefixes("192.0.2.0/24")) {
		t.Errorf("allowlist = %v, want the given config's, not the file's", got)
	}
}

// A changed auth config given to ReloadWith signs every session out, as a reload from the file does.
func TestReloadWithRevokesSessionsOnAuthChange(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	ctx := context.Background()
	e.srv.reconcileAuthEpoch(ctx) // the fingerprint of the running config, as start-up records it
	rawID, err := e.srv.sessions.Create(ctx, "operator", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}

	same, err := config.Parse([]byte(reloadYAML(e, "127.0.0.1/32", "")))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.ReloadWith(ctx, same); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.sessions.Load(ctx, rawID); err != nil {
		t.Fatalf("an unchanged auth config must not sign anyone out: %v", err)
	}

	withTOTP, err := config.Parse([]byte(reloadYAML(e, "127.0.0.1/32", "JBSWY3DPEHPK3PXP")))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.ReloadWith(ctx, withTOTP); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.sessions.Load(ctx, rawID); err == nil {
		t.Error("a session from before TOTP was enabled is still valid")
	}
	if !e.srv.security().totpEnabled("operator") {
		t.Error("TOTP is not in force after ReloadWith")
	}
}

// ReloadRejected records the refusal and changes nothing.
func TestReloadRejectedAuditsOnly(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	before := e.srv.security()
	e.srv.ReloadRejected(context.Background())
	if e.srv.security() != before {
		t.Error("ReloadRejected replaced the security state")
	}
	if got := reloadEvents(t, e); !reflect.DeepEqual(got, []string{"error: rejected invalid config; keeping previous"}) {
		t.Errorf("events = %q", got)
	}
}

// Reload still reads the file itself: a valid file is applied, a refused one keeps the previous
// state and is audited.
func TestReloadReadsTheFile(t *testing.T) {
	t.Setenv(config.DevInsecurePermsEnv, "1")
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "config.yaml")
	e.srv.configPath = path

	if err := os.WriteFile(path, []byte(reloadYAML(e, "203.0.113.0/24", "")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if got := allowlistInForce(e); !reflect.DeepEqual(got, prefixes("203.0.113.0/24")) {
		t.Errorf("allowlist = %v, want the file's", got)
	}

	if err := os.WriteFile(path, []byte(reloadYAML(e, "not-a-cidr", "")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Reload(ctx); err == nil {
		t.Fatal("Reload accepted an invalid file")
	}
	if got := allowlistInForce(e); !reflect.DeepEqual(got, prefixes("203.0.113.0/24")) {
		t.Errorf("allowlist = %v after a refused reload, want the previous list", got)
	}
	want := []string{"ok: allowlist + auth + token CIDR-union reloaded", "error: rejected invalid config; keeping previous"}
	if got := reloadEvents(t, e); !reflect.DeepEqual(got, want) {
		t.Errorf("events = %q, want %q", got, want)
	}
}
