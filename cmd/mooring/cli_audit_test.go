package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/apitoken"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/crypto"
	"github.com/daboss2003/mooring/internal/store"
)

// cliHost writes a minimal valid config.yaml (0600, dev perms hatch on) and returns its path and
// the data dir the CLI opens mooring.db in.
func cliHost(t *testing.T) (cfgPath, dataDir string) {
	t.Helper()
	t.Setenv(config.DevInsecurePermsEnv, "1")
	hash, err := crypto.HashPassword([]byte("pw-123456789"), crypto.DefaultArgon2Params)
	if err != nil {
		t.Fatal(err)
	}
	dataDir = t.TempDir()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	var b strings.Builder
	fmt.Fprintf(&b, "bind_addr: \"127.0.0.1:9000\"\n")
	fmt.Fprintf(&b, "encryption_key: %q\n", key)
	fmt.Fprintf(&b, "ip_allowlist:\n  - \"127.0.0.1/32\"\n")
	fmt.Fprintf(&b, "auth:\n  username: \"operator\"\n  password_hash: %q\n", hash)
	fmt.Fprintf(&b, "edge:\n  mode: \"managed\"\n  acme_email: \"ops@example.com\"\n  acme_ca: \"https://acme.example/directory\"\n")
	fmt.Fprintf(&b, "data_dir: %q\n", dataDir)
	cfgPath = filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, dataDir
}

type cliRow struct{ Actor, IP, Action, Target, Outcome, Level, Detail string }

func cliRows(t *testing.T, dataDir, action string) []cliRow {
	t.Helper()
	db, err := store.Open(filepath.Join(dataDir, "mooring.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT actor, ip, action, target, outcome, level, detail FROM events WHERE action = ? ORDER BY seq`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []cliRow
	for rows.Next() {
		var r cliRow
		if err := rows.Scan(&r.Actor, &r.IP, &r.Action, &r.Target, &r.Outcome, &r.Level, &r.Detail); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func mintedToken(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(line); strings.HasPrefix(s, "hmt_") {
			return s
		}
	}
	t.Fatalf("no token in mint output:\n%s", out)
	return ""
}

func TestTokenMintAndRevokeAudited(t *testing.T) {
	cfgPath, dataDir := cliHost(t)
	t.Setenv("SUDO_USER", "alice")

	var err error
	out := captureStdout(t, func() {
		err = cmdTokenMint([]string{"--config", cfgPath, "--scopes", "status:read,deploy:write:web",
			"--cidrs", "198.51.100.0/24", "--ttl", "720h", "--label", "ci"})
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	tok := mintedToken(t, out)
	id, secret, ok := apitoken.SplitBearer(tok)
	if !ok {
		t.Fatalf("minted token %q doesn't parse", tok)
	}

	rows := cliRows(t, dataDir, "api_token_mint")
	if len(rows) != 1 {
		t.Fatalf("api_token_mint rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.Actor != "cli:alice" || r.IP != "local" || r.Target != id || r.Outcome != "ok" || r.Level != "security" {
		t.Errorf("api_token_mint row = %+v", r)
	}
	for _, want := range []string{"status:read", "deploy:write:web", "198.51.100.0/24", `"ci"`} {
		if !strings.Contains(r.Detail, want) {
			t.Errorf("mint detail %q lacks %q", r.Detail, want)
		}
	}
	if strings.Contains(r.Detail+r.Target, secret) {
		t.Fatal("the token secret reached the audit row")
	}

	if captureStdout(t, func() { err = cmdTokenRevoke([]string{"--config", cfgPath, "--id", id}) }); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	rev := cliRows(t, dataDir, "api_token_revoke_cli")
	if len(rev) != 1 || rev[0].Target != id || rev[0].Outcome != "ok" || rev[0].Actor != "cli:alice" ||
		rev[0].IP != "local" || rev[0].Level != "security" {
		t.Fatalf("api_token_revoke_cli rows = %+v", rev)
	}

	// The whole token pasted as --id: the revoke fails and the row holds only the id part.
	if captureStdout(t, func() { err = cmdTokenRevoke([]string{"--config", cfgPath, "--id", tok}) }); err == nil {
		t.Fatal("revoking by a full token string must fail (it is not an id)")
	}
	rev = cliRows(t, dataDir, "api_token_revoke_cli")
	if len(rev) != 2 || rev[1].Outcome != "error" {
		t.Fatalf("failed revoke rows = %+v", rev)
	}
	if strings.Contains(rev[1].Target+rev[1].Detail, secret) {
		t.Fatalf("a pasted token's secret reached the audit row: %+v", rev[1])
	}
	if rev[1].Target != id {
		t.Errorf("failed revoke target = %q, want the id part %q", rev[1].Target, id)
	}

	// Anything else that isn't an id is not stored at all.
	if captureStdout(t, func() {
		err = cmdTokenRevoke([]string{"--config", cfgPath, "--id", "not an id\x1b[2J"})
	}); err == nil {
		t.Fatal("revoking a malformed id must fail")
	}
	rev = cliRows(t, dataDir, "api_token_revoke_cli")
	if len(rev) != 3 || rev[2].Target != "" || rev[2].Outcome != "error" {
		t.Fatalf("malformed-id revoke rows = %+v", rev)
	}
}

func TestCLIActorFallsBackToEffectiveUser(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	want := "uid " + strconv.Itoa(os.Geteuid())
	if u, err := user.LookupId(strconv.Itoa(os.Geteuid())); err == nil {
		want = u.Username
	}
	if got := cliActor(); got != "cli:"+want {
		t.Errorf("cliActor() = %q, want %q", got, "cli:"+want)
	}
	// A hostile SUDO_USER can't inject control characters or run long.
	t.Setenv("SUDO_USER", "bob\n\x1b[31m"+strings.Repeat("x", 200))
	got := cliActor()
	if strings.ContainsAny(got, "\n\x1b") || len(got) > len("cli:")+64 || !strings.HasPrefix(got, "cli:bob") {
		t.Errorf("cliActor() with a hostile SUDO_USER = %q", got)
	}
}

func TestSecretImportAudited(t *testing.T) {
	cfgPath, dataDir := cliHost(t)
	t.Setenv("SUDO_USER", "carol")
	const secretVal = "s3cr3t-value-xyz-4f9a"
	envPath := filepath.Join(t.TempDir(), "app.env")
	if err := os.WriteFile(envPath, []byte("DB_PASSWORD="+secretVal+"\nLOG_LEVEL=info\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var err error
	if captureStdout(t, func() {
		err = cmdSecretImport([]string{"--config", cfgPath, "--slug", "shop", "--from", envPath})
	}); err != nil {
		t.Fatalf("import: %v", err)
	}
	rows := cliRows(t, dataDir, "secret_import")
	if len(rows) != 1 {
		t.Fatalf("secret_import rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.Actor != "cli:carol" || r.IP != "local" || r.Target != "shop" || r.Outcome != "ok" || r.Level != "security" {
		t.Errorf("secret_import row = %+v", r)
	}
	if !strings.Contains(r.Detail, "2 added") {
		t.Errorf("secret_import detail %q should count the 2 added keys", r.Detail)
	}
	if strings.Contains(r.Detail, secretVal) || strings.Contains(r.Detail, "info") {
		t.Fatalf("an imported value reached the audit row: %q", r.Detail)
	}
}
