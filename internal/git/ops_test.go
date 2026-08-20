package git

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A private key / known_hosts pasted into a browser <textarea> arrives with CRLF line endings.
// OpenSSH rejects a key file containing '\r' as "invalid format" (surfacing as an opaque
// "authentication failed"), so credEnv must normalize the material to LF before writing it.
func TestCredEnvNormalizesSSHKeyCRLF(t *testing.T) {
	dir := t.TempDir()
	crlfKey := "-----BEGIN OPENSSH PRIVATE KEY-----\r\nb3BlbnNzaC1r\r\n-----END OPENSSH PRIVATE KEY-----"
	if _, err := credEnv(dir, "git@github.com:o/r.git", Creds{SSHKey: crlfKey, KnownHosts: "github.com ssh-ed25519 AAA\r\n"}); err != nil {
		t.Fatal(err)
	}
	key, _ := os.ReadFile(filepath.Join(dir, "id"))
	if strings.Contains(string(key), "\r") {
		t.Error("SSH key file must not contain carriage returns — OpenSSH would reject it as invalid format")
	}
	if !strings.HasSuffix(string(key), "\n") {
		t.Error("SSH key file must end with a newline")
	}
	kh, _ := os.ReadFile(filepath.Join(dir, "known_hosts"))
	if strings.Contains(string(kh), "\r") {
		t.Error("known_hosts must not contain carriage returns")
	}
}

// A token pasted into a <textarea> can carry surrounding whitespace / a trailing newline; the
// askpass helper cat's the file verbatim as the password, so it must be trimmed or auth fails.
func TestCredEnvTrimsToken(t *testing.T) {
	dir := t.TempDir()
	if _, err := credEnv(dir, "https://github.com/o/r.git", Creds{Token: "  ghp_abc123\r\n"}); err != nil {
		t.Fatal(err)
	}
	tok, _ := os.ReadFile(filepath.Join(dir, "token"))
	if string(tok) != "ghp_abc123" {
		t.Errorf("token must be trimmed of surrounding whitespace, got %q", string(tok))
	}
}
