package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/ops"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/session"
)

// opsConfigEnv is a server with templates, a definition store and an ops config store whose app "shop"
// has the canonical spec and enabled ops settings at http://api:8080.
func opsConfigEnv(t *testing.T, spec string) (*testEnv, *definition.Store, *ops.ConfigStore) {
	t.Helper()
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	cipher, err := secret.NewCipher(make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	ds := definition.NewStore(e.srv.db, make([]byte, 32))
	cs := ops.NewConfigStore(e.srv.db, cipher)
	e.srv.defStore, e.srv.opsStore = ds, cs
	saveOpsDef(t, ds, spec)
	sec := "a-long-enough-secret-value"
	if err := cs.Set("shop", ops.SetInput{Enabled: true, BaseURL: "http://api:8080", SecretHeader: "X-Ops-Secret", NewSecret: &sec, OpsMode: "auto", BasePath: "/ops"}); err != nil {
		t.Fatal(err)
	}
	return e, ds, cs
}

// postOpsConfig drives the dashboard's ops settings save for "shop".
func postOpsConfig(t *testing.T, e *testEnv, form url.Values) (*http.Response, string) {
	t.Helper()
	r := httptest.NewRequest("POST", "/apps/shop/ops-config", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("project", "shop")
	r = r.WithContext(withSession(context.Background(), &session.Session{Username: "operator"}))
	rec := httptest.NewRecorder()
	e.srv.handleOpsConfigPost(rec, r)
	body, _ := io.ReadAll(rec.Result().Body)
	return rec.Result(), string(body)
}

const appOpsSpec = opsSecrets +
	"  ops_interface:\n    enabled: true\n    base_url: http://api:8080\n    base_path: /ops\n" +
	"    secret_header: X-Ops-Secret\n    secret: OPS_SECRET\n"

const appOpsCompose = "  compose:\n    source: generated\n    services:\n      api:\n        image: coredns/coredns:1.11.1\n"

// While the app's mooring.yaml declares alerts on the app-level ops_interface, the dashboard refuses to
// turn the ops interface off: nothing is applied, and the page says what to do.
func TestOpsConfigRefusesDisableWithAlerts(t *testing.T) {
	e, ds, cs := opsConfigEnv(t, appOpsSpec+"    alerts:\n      - "+dropsAlert+"\n"+appOpsCompose)
	versions, _ := ds.List("shop")

	resp, body := postOpsConfig(t, e, url.Values{"base_url": {"http://api:9090"}, "secret_header": {"X-Ops-Secret"}, "ops_mode": {"auto"}, "base_path": {"/ops"}})
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Location") != "" {
		t.Errorf("a refused save must re-render the page, got %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if !strings.Contains(body, "declares ops alerts; remove them from mooring.yaml and deploy before turning the ops interface off.") ||
		!strings.Contains(body, `role="alert"`) {
		t.Errorf("the page must show the refusal:\n%s", body)
	}
	cfg, _, err := cs.Get("shop")
	if err != nil || !cfg.Enabled || cfg.BaseURL != "http://api:8080" {
		t.Errorf("nothing may be applied: ops settings enabled=%v base_url=%q (%v)", cfg.Enabled, cfg.BaseURL, err)
	}
	def, err := ds.Current("shop")
	if err != nil || !def.Spec.OpsInterface.Enabled || len(def.Spec.OpsInterface.Alerts) != 1 || def.Spec.OpsInterface.BaseURL != "http://api:8080" {
		t.Errorf("the canonical must be unchanged: %+v (%v)", def.Spec.OpsInterface, err)
	}
	if after, _ := ds.List("shop"); len(after) != len(versions) {
		t.Errorf("a refused save wrote a definition version: %d → %d", len(versions), len(after))
	}

	// An edit that keeps it on is not refused.
	resp, _ = postOpsConfig(t, e, url.Values{"enabled": {"on"}, "base_url": {"http://api:9090"}, "secret_header": {"X-Ops-Secret"}, "ops_mode": {"auto"}, "base_path": {"/ops"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("an edit that keeps ops on must save, got %d", resp.StatusCode)
	}
	if cfg, _, _ := cs.Get("shop"); !cfg.Enabled || cfg.BaseURL != "http://api:9090" {
		t.Errorf("the edit wasn't applied: %+v", cfg)
	}
	if def, _ := ds.Current("shop"); def.Spec.OpsInterface.BaseURL != "http://api:9090" || len(def.Spec.OpsInterface.Alerts) != 1 {
		t.Errorf("the edit wasn't written back with its alerts: %+v", def.Spec.OpsInterface)
	}
}

// Without alerts on the app-level ops_interface the dashboard turns ops off as before, and writes it back.
func TestOpsConfigDisableWithoutAlerts(t *testing.T) {
	e, ds, cs := opsConfigEnv(t, appOpsSpec+"  compose:\n    source: generated\n    services:\n"+opsService("api", "8080", dropsAlert))

	resp, _ := postOpsConfig(t, e, url.Values{"base_url": {"http://api:8080"}, "secret_header": {"X-Ops-Secret"}, "ops_mode": {"auto"}, "base_path": {"/ops"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("turning ops off without app-level alerts must save, got %d", resp.StatusCode)
	}
	if cfg, _, _ := cs.Get("shop"); cfg.Enabled {
		t.Error("ops is still on in the ops settings")
	}
	def, err := ds.Current("shop")
	if err != nil || def.Spec.OpsInterface.Enabled {
		t.Errorf("the canonical must have ops off: %+v (%v)", def.Spec.OpsInterface, err)
	}
	if svc := def.Spec.Compose.Services["api"].OpsInterface; svc == nil || len(svc.Alerts) != 1 {
		t.Errorf("a service's own ops_interface alerts are not the dashboard's to change: %+v", svc)
	}
}
