package edge

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// readStdin is shell that copies the script's stdin to stdout with builtins only: the child gets the
// edge's environment, which has no PATH.
const readStdin = `while IFS= read -r l || [ -n "$l" ]; do printf '%s\n' "$l"; done`

// ValidateConfig runs `caddy validate --config - --adapter ""` with the config on stdin, in the edge's
// environment (Caddy's storage under /var/lib/caddy) from /, and a config Caddy accepts is no error.
func TestValidateConfigFeedsTheConfigOnStdin(t *testing.T) {
	skipNoShell(t)
	dir := t.TempDir()
	record := filepath.Join(dir, "record")
	bin := filepath.Join(dir, "caddy")
	writeExec(t, bin, []byte("#!/bin/sh\n{\n"+
		"  for a in \"$@\"; do printf 'arg=[%s]\\n' \"$a\"; done\n"+
		"  printf 'env=[HOME=%s XDG_DATA_HOME=%s XDG_CONFIG_HOME=%s canary=%s]\\n' \"$HOME\" \"$XDG_DATA_HOME\" \"$XDG_CONFIG_HOME\" \"${MOORING_TEST_CANARY-unset}\"\n"+
		"  printf 'pwd=[%s]\\n' \"$(pwd)\"\n"+
		"  echo stdin:\n  "+readStdin+"\n"+
		"} > "+record+"\necho 'Valid configuration'\n"))
	t.Setenv("MOORING_TEST_CANARY", "inherited") // the run gets the edge's environment, nothing of Mooring's
	cfg := []byte("{\"apps\":{\"http\":{}},\n\"admin\":{\"listen\":\"unix//run/mooring/caddy-admin.sock\"}}")
	if err := ValidateConfig(context.Background(), bin, cfg, []string{"tok-0123456789"}); err != nil {
		t.Fatalf("a config the binary accepts: %v", err)
	}
	b, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{
		"arg=[validate]\narg=[--config]\narg=[-]\narg=[--adapter]\narg=[]\n",
		"env=[HOME=/var/lib/caddy XDG_DATA_HOME=/var/lib/caddy XDG_CONFIG_HOME=/var/lib/caddy canary=unset]",
		"pwd=[/]",
		"stdin:\n" + string(cfg) + "\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the validate run lacks %q:\n%s", want, got)
		}
	}
}

// realValidateOutput is what Caddy 2.11.9 with caddy-dns/cloudflare printed for `caddy validate` of a
// config whose token the module refuses (the token replaced by %s).
const realValidateOutput = `{"level":"info","ts":1795386734.7512,"msg":"using config from stdin"}
{"level":"info","ts":1795386734.7518,"logger":"tls.cache.maintenance","msg":"started background certificate maintenance","cache":"0x45cb9c8ff680"}
{"level":"info","ts":1795386734.7520,"logger":"tls.cache.maintenance","msg":"stopped background certificate maintenance","cache":"0x45cb9c8ff680"}
{"level":"info","ts":1795386734.7521,"logger":"http","msg":"servers shutting down with eternal grace period"}
{"level":"error","ts":1795386734.752439,"msg":"loading http app module: provision http: getting tls app: loading tls app module: provision tls: provisioning automation policy 0: loading TLS automation management module: position 0: loading module 'acme': provision tls.issuance.acme: loading DNS provider module: loading module 'cloudflare': provision dns.providers.cloudflare: API token '%s' appears invalid; ensure it's correctly entered and not wrapped in braces nor quotes"}
`

// failingCaddy writes a fake caddy that reads its stdin and prints output to stderr, then fails.
func failingCaddy(t *testing.T, output string) string {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	if err := os.WriteFile(out, []byte(output), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "caddy")
	writeExec(t, bin, []byte("#!/bin/sh\n"+readStdin+" > /dev/null\n"+
		`while IFS= read -r l || [ -n "$l" ]; do printf '%s\n' "$l" >&2; done < `+out+"\nexit 1\n"))
	return bin
}

// Caddy logs info lines before the refusal, and an alert quotes only the start of a failed check: the
// error carries Caddy's error message right after the prefix, without the info lines.
func TestValidateConfigReportsCaddysError(t *testing.T) {
	skipNoShell(t)
	tok := "bad token-SECRETxyz"
	bin := failingCaddy(t, strings.Replace(realValidateOutput, "%s", tok, 1))
	err := ValidateConfig(context.Background(), bin, []byte(`{"apps":{}}`), []string{tok})
	if err == nil {
		t.Fatal("a refused config must be an error")
	}
	msg := err.Error()
	if strings.Contains(msg, "using config from stdin") || strings.Contains(msg, "certificate maintenance") || strings.Contains(msg, "SECRETxyz") {
		t.Errorf("the error must carry only Caddy's (redacted) error message:\n%s", msg)
	}
	if want := "`caddy validate` refused the edge config (exit status 1): loading http app module: provision http:"; !strings.HasPrefix(msg, want) {
		t.Errorf("the error must start with Caddy's error message:\n%s", msg)
	}
	if !strings.Contains(msg, "API token '[redacted]' appears invalid") {
		t.Errorf("the error must keep the cause:\n%s", msg)
	}
}

// A DNS provider module echoes a malformed token in its Provision error (caddy-dns/cloudflare: "API token
// '%s' appears invalid"), and this error ends up in an alert: no form of a token may reach it, including
// one that JSON-decoding the log line turns back into the token, and a partial one where the bounded
// tail of non-JSON output cuts a long line inside the token.
func TestValidateConfigRedactsSecretsFromTheError(t *testing.T) {
	skipNoShell(t)
	slashed := "abc/def-SLASHSECRET"
	lines := `{"level":"error","msg":"token 'abc\/def-SLASHSECRET' refused","error":"also ` + `abc\/def-SLASHSECRET` + `"}` + "\n" +
		`{"level":"warn","msg":"not an error line abc\/def-SLASHSECRET"}` + "\n"
	err := ValidateConfig(context.Background(), failingCaddy(t, lines), []byte(`{"apps":{}}`), []string{slashed})
	if err == nil || strings.Contains(err.Error(), "SLASHSECRET") || !strings.Contains(err.Error(), "token '[redacted]' refused: also [redacted]") {
		t.Errorf("a token the raw pass can't match (JSON-escaped as \\/) must be redacted after decoding: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "not an error line") {
		t.Errorf("only error-level lines are reported when there are some: %v", err)
	}
}

// Output that is not Caddy's JSON log is reported as its bounded tail, redacted before the cut.
func TestValidateConfigRedactsBeforeTheTailCut(t *testing.T) {
	skipNoShell(t)
	const tail = "QXJ2WK7MZP4LRT8B"
	tok := `cf"tok<9f8e7d6c5b4a>` + tail
	jb, _ := json.Marshal(tok)
	jsonForm := strings.Trim(string(jb), `"`)
	line1 := `Error: loading module 'cloudflare': provision dns.providers.cloudflare: API token '` + tok + `' appears invalid; ensure it's correctly entered`
	line2 := `echo of the JSON form: ` + jsonForm
	// The tail keeps the last 4096 bytes of " | "-joined lines: put the cut inside the token of a long
	// first line, keeping exactly its last len(tail) bytes when nothing is redacted first.
	after := strings.Repeat("y", 4096-len(tail)-len(" | "+line1+" | "+line2))
	long := strings.Repeat("x", 3000) + tok + after
	if got := tailLines([]byte(long+"\n"+line1+"\n"+line2), errTailLines); !strings.HasPrefix(got, tail) {
		t.Fatalf("test setup: the bounded tail must start inside the token, got %q", got[:40])
	}
	bin := failingCaddy(t, long+"\n"+line1+"\n"+line2+"\n")

	err := ValidateConfig(context.Background(), bin, []byte(`{"apps":{}}`), []string{"", "   ", tok})
	if err == nil {
		t.Fatal("a refused config must be an error")
	}
	msg := err.Error()
	for _, leak := range []string{tok, jsonForm, `cf"tok`, "9f8e7d6c5b4a", "MZP4LRT8B"} {
		if strings.Contains(msg, leak) {
			t.Errorf("token fragment %q leaked into the error:\n%s", leak, msg)
		}
	}
	if !strings.Contains(msg, "[redacted]") || !strings.Contains(msg, "API token '[redacted]' appears invalid; ensure it's correctly entered") {
		t.Errorf("the error must keep Caddy's message, spaces intact (a blank secret redacts nothing):\n%s", msg)
	}
	if !strings.Contains(msg, "validate") || !strings.Contains(msg, "exit status 1") {
		t.Errorf("the error must say the validate run failed and how: %s", msg[:min(len(msg), 200)])
	}
}

// The run is hardened like every short caddy command (a binary another account can write is refused)
// and bounded by ctx; a missing binary or an empty config is an error, never a pass.
func TestValidateConfigIsHardenedAndBounded(t *testing.T) {
	skipNoShell(t)
	dir := t.TempDir()
	bin := filepath.Join(dir, "caddy")
	writeExec(t, bin, []byte("#!/bin/sh\n"+readStdin+" > /dev/null\nexec /bin/sleep 30\n"))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := ValidateConfig(ctx, bin, []byte(`{}`), nil); err == nil {
		t.Error("a validate run past its deadline must be an error")
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("the run took %v; it must stop at the deadline", took)
	}

	if err := os.Chmod(bin, 0o722); err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(context.Background(), bin, []byte(`{}`), nil); err == nil || !strings.Contains(err.Error(), "another account can write it") {
		t.Errorf("a binary others can write must be refused, got %v", err)
	}
	if err := ValidateConfig(context.Background(), "", []byte(`{}`), nil); err == nil {
		t.Error("no binary must be an error")
	}
	if err := ValidateConfig(context.Background(), bin, []byte(" \n"), nil); err == nil {
		t.Error("an empty config must be an error")
	}
}

// Only a Caddy that ran and refused the config is a refusal (ErrValidateRefused): serve's restart gate
// reads "the running binary refuses the refused render" as "the refusal is the binary's", so a check
// that couldn't run the binary at all — missing, not executable, refused by the hardening, past its
// deadline, killed by a signal — must never count as one.
func TestValidateConfigRefusalIsOnlyARefusal(t *testing.T) {
	skipNoShell(t)
	ctx := context.Background()
	cfg := []byte(`{"apps":{}}`)
	refused := failingCaddy(t, `{"level":"error","msg":"loading http app module: json: unknown field \"trusted_proxies\""}`+"\n")
	err := ValidateConfig(ctx, refused, cfg, nil)
	if !errors.Is(err, ErrValidateRefused) {
		t.Fatalf("a Caddy that exits 1 refusing the config must be a refusal: %v", err)
	}
	if want := "`caddy validate` refused the edge config (exit status 1): loading http app module: json: unknown field \"trusted_proxies\""; err.Error() != want {
		t.Errorf("the refusal's text must stay Caddy's error:\n got %q\nwant %q", err.Error(), want)
	}

	dir := t.TempDir()
	notExec := filepath.Join(dir, "not-exec")
	if err := os.WriteFile(notExec, []byte("#!/bin/sh\nexit 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writable := filepath.Join(dir, "writable")
	writeExec(t, writable, []byte("#!/bin/sh\nexit 1\n"))
	if err := os.Chmod(writable, 0o722); err != nil {
		t.Fatal(err)
	}
	signalled := filepath.Join(dir, "signalled")
	writeExec(t, signalled, []byte("#!/bin/sh\n"+readStdin+" > /dev/null\nkill -9 $$\n"))
	slow := filepath.Join(dir, "slow")
	writeExec(t, slow, []byte("#!/bin/sh\n"+readStdin+" > /dev/null\nwhile :; do :; done\n"))

	for name, bin := range map[string]string{
		"no binary":      "",
		"missing":        filepath.Join(dir, "missing"),
		"not executable": notExec,
		"others write":   writable,
		"signalled":      signalled,
	} {
		if err := ValidateConfig(ctx, bin, cfg, nil); err == nil || errors.Is(err, ErrValidateRefused) {
			t.Errorf("%s: %v; want an error that isn't a refusal", name, err)
		}
	}
	tctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	if err := ValidateConfig(tctx, slow, cfg, nil); err == nil || errors.Is(err, ErrValidateRefused) {
		t.Errorf("past its deadline: %v; want an error that isn't a refusal", err)
	}
}
