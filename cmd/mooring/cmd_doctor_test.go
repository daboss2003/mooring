package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestCheckBinary(t *testing.T) {
	// `sh` exists on any Unix dev/CI box; a nonsense name never does.
	if got := checkBinary("sh", "shell", "fix"); got.state != "ok" {
		t.Errorf("sh should be ok, got %q", got.state)
	}
	missing := checkBinary("mooring-no-such-binary-xyz", "thing", "do the fix")
	if missing.state != "fail" {
		t.Errorf("missing binary should fail, got %q", missing.state)
	}
	if missing.fix != "do the fix" {
		t.Errorf("fix not carried through: %q", missing.fix)
	}
}

// A distro-service conflict is reported ONLY when the unit is actually active/enabled.
// An absent unit (or no systemctl, e.g. on the macOS dev box) must report "ok" — never
// a false alarm. (Only an active/enabled unit is a "fail"; can't assert that portably.)
func TestCheckDistroServiceNoFalseAlarm(t *testing.T) {
	r := checkDistroService("mooring-no-such-service-xyz", ":80/:443")
	if r.state != "ok" {
		t.Errorf("absent distro service = %q, want ok (no false alarm)", r.state)
	}
}

func TestReportPrint(t *testing.T) {
	var r report
	r.add(result{"caddy", "fail", "MISSING", "sudo mooring setup --yes"})
	r.add(result{"docker", "ok", "found", ""})
	if !r.hasFail() {
		t.Error("hasFail should be true")
	}
	var buf bytes.Buffer
	r.print(&buf)
	out := buf.String()
	if !strings.Contains(out, "✗ caddy") || !strings.Contains(out, "✓ docker") {
		t.Errorf("missing status icons:\n%s", out)
	}
	if !strings.Contains(out, "→ sudo mooring setup --yes") {
		t.Errorf("fix hint not printed for a failing check:\n%s", out)
	}
	// An ok check must not print a fix arrow.
	if strings.Count(out, "→") != 1 {
		t.Errorf("expected exactly one fix arrow:\n%s", out)
	}
}

func TestDockerLogRotated(t *testing.T) {
	cases := map[string]struct {
		json string
		want bool
	}{
		"absent (default uncapped json-file)": {"", false},
		"json-file no cap":                    {`{"log-driver":"json-file"}`, false},
		"json-file with cap":                  {`{"log-driver":"json-file","log-opts":{"max-size":"10m"}}`, true},
		"implicit json-file with cap":         {`{"log-opts":{"max-size":"10m"}}`, true},
		"journald":                            {`{"log-driver":"journald"}`, true},
		"local (self-rotating)":               {`{"log-driver":"local"}`, true},
		"garbage":                             {`not json`, false},
	}
	for name, c := range cases {
		if got := dockerLogRotated([]byte(c.json)); got != c.want {
			t.Errorf("%s: dockerLogRotated=%v, want %v", name, got, c.want)
		}
	}
}

func TestWithDockerLogCap(t *testing.T) {
	// fresh box (no daemon.json) → cap is added and parses back capped.
	out, changed, err := withDockerLogCap(nil)
	if err != nil || !changed {
		t.Fatalf("empty: changed=%v err=%v", changed, err)
	}
	if !dockerLogRotated(out) {
		t.Errorf("result is still uncapped:\n%s", out)
	}

	// existing unrelated keys are preserved; existing log-opts are merged, not clobbered.
	in := []byte(`{"live-restore":true,"log-opts":{"labels":"app"}}`)
	out, changed, err = withDockerLogCap(in)
	if err != nil || !changed {
		t.Fatalf("merge: changed=%v err=%v", changed, err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if got["live-restore"] != true {
		t.Errorf("dropped live-restore: %v", got)
	}
	opts := got["log-opts"].(map[string]any)
	if opts["labels"] != "app" || opts["max-size"] != "10m" {
		t.Errorf("log-opts not merged correctly: %v", opts)
	}

	// already capped, a non-json-file driver, and garbage → no change / clear error.
	if _, changed, _ := withDockerLogCap([]byte(`{"log-opts":{"max-size":"5m"}}`)); changed {
		t.Error("already-capped should not change")
	}
	if _, changed, _ := withDockerLogCap([]byte(`{"log-driver":"journald"}`)); changed {
		t.Error("non-json-file driver should be left alone")
	}
	if _, _, err := withDockerLogCap([]byte(`not json`)); err == nil {
		t.Error("invalid daemon.json should error (so we never clobber it)")
	}
}

// TestCaddyRepoConstants guards the apt repo wiring against silent typos: the sources
// line must reference the key path via signed-by, and the key must be fetched over TLS.
func TestCaddyRepoConstants(t *testing.T) {
	if !strings.Contains(caddySources, "signed-by="+caddyKeyPath) {
		t.Errorf("sources line must pin the key via signed-by: %q", caddySources)
	}
	if !strings.HasPrefix(caddyKeyURL, "https://") {
		t.Errorf("the signing key must be fetched over HTTPS: %q", caddyKeyURL)
	}
	if !strings.HasSuffix(caddyKeyPath, ".asc") {
		t.Errorf("armored key path should end .asc for apt signed-by: %q", caddyKeyPath)
	}
}

func TestOnlyLoopback(t *testing.T) {
	for _, s := range []string{"", "localhost", "127.0.0.0/8", "127.0.0.1 ::1", "localhost ::1/128"} {
		if !onlyLoopback(s) {
			t.Errorf("%q should be loopback-only", s)
		}
	}
	for _, s := range []string{"localhost 172.16.0.0/12", "10.0.0.0/8", "0.0.0.0/0"} {
		if onlyLoopback(s) {
			t.Errorf("%q has a non-loopback range", s)
		}
	}
}

func TestServiceEnabledResult(t *testing.T) {
	cases := []struct {
		state string
		ok    bool
		want  string
	}{
		{"enabled", true, "ok"},          // the only true boot-enabled state
		{"enabled-runtime", true, "fail"}, // --runtime lives in /run → wiped on reboot
		{"linked-runtime", true, "fail"},
		{"disabled", true, "fail"}, // running-but-not-enabled: the reboot trap
		{"masked", true, "fail"},
		{"masked-runtime", true, "fail"},
		{"static", true, "warn"}, // unusual for a top-level unit — flag, don't fail
		{"", false, "warn"},      // systemctl unavailable
		{"", true, "warn"},       // empty state → can't confirm
	}
	for _, c := range cases {
		got := serviceEnabledResult(c.state, c.ok)
		if got.state != c.want {
			t.Errorf("serviceEnabledResult(%q, %v).state = %q, want %q", c.state, c.ok, got.state, c.want)
		}
		if c.want == "fail" && got.fix == "" {
			t.Errorf("a not-enabled state (%q) must carry a fix command", c.state)
		}
	}
	// The disabled case must name the enable command; the masked case must say to unmask FIRST
	// (a plain `enable` errors on a masked unit).
	if fix := serviceEnabledResult("disabled", true).fix; !strings.Contains(fix, "systemctl enable mooring") {
		t.Errorf("disabled fix should point at `systemctl enable mooring`, got %q", fix)
	}
	if fix := serviceEnabledResult("masked", true).fix; !strings.Contains(fix, "unmask") {
		t.Errorf("masked fix must tell the operator to unmask first, got %q", fix)
	}
}
