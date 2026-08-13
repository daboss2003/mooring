package web

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// The .deb cleanup must work with just the operator's admin session + CSRF (no password/TOTP
// step-up), never delete the running version, and — the bug the operator hit — reject a POST whose
// CSRF token is missing (handleServer now actually passes CSRFToken to the template).
func TestDebDeleteAdminCSRFOnly(t *testing.T) {
	e := buildGitHubServer(t)
	dir := t.TempDir()
	e.srv.cfg.Server.DebCacheDir = dir
	e.srv.version = "0.12.0"
	old := "mooring_0.11.9_linux_amd64.deb"
	cur := "mooring_0.12.0_linux_amd64.deb" // the running version
	for _, n := range []string{old, cur} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sess, csrf := e.authed(t)
	hdr := map[string]string{"Origin": "https://example.com"}

	// Delete the OLD one: succeeds with admin session + CSRF, NO password.
	if resp := e.req(t, "POST", "/server/debs/delete", "127.0.0.1:1", hdr,
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}, "name": {old}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete old deb = %d, want 303 (no password needed)", resp.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(dir, old)); !os.IsNotExist(err) {
		t.Error("the old .deb should have been deleted")
	}

	// The RUNNING version is refused and stays on disk.
	e.req(t, "POST", "/server/debs/delete", "127.0.0.1:1", hdr,
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}, "name": {cur}})
	if _, err := os.Stat(filepath.Join(dir, cur)); err != nil {
		t.Error("the running-version .deb must never be deleted")
	}

	// A POST WITHOUT the CSRF token is rejected (the "invalid csrf token" case — now the form carries it).
	if resp := e.req(t, "POST", "/server/debs/delete", "127.0.0.1:1", hdr,
		[]*http.Cookie{sess, csrf}, url.Values{"name": {old}}); resp.StatusCode == http.StatusSeeOther {
		t.Error("a POST with no CSRF token must be rejected, not processed")
	}
}
