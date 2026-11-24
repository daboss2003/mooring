package web

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/ops"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/store"
)

// A dashboard save of the app-level ops config is written back into the canonical mooring.yaml; the
// ops_interface's alerts (which only the yaml declares) must survive it.
func TestOpsWriteBackKeepsAlerts(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cipher, err := secret.NewCipher(make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	ds := definition.NewStore(db, make([]byte, 32))
	os := ops.NewConfigStore(db, cipher)
	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil)), defStore: ds, opsStore: os}

	saveOpsDef(t, ds, opsSecrets+
		"  ops_interface:\n    enabled: true\n    base_url: http://api:8080\n    base_path: /ops\n"+
		"    secret_header: X-Ops-Secret\n    secret: OPS_SECRET\n    alerts:\n      - "+dropsAlert+"\n"+
		"  compose:\n    source: generated\n    services:\n      api:\n        image: coredns/coredns:1.11.1\n")
	sec := "a-long-enough-secret-value"
	if err := os.Set("shop", ops.SetInput{Enabled: true, BaseURL: "http://api:9090", SecretHeader: "X-Ops-Secret", NewSecret: &sec, OpsMode: "auto", BasePath: "/ops"}); err != nil {
		t.Fatal(err)
	}

	s.opsWriteBack(httptest.NewRequest("POST", "/apps/shop/ops", nil).WithContext(context.Background()), "shop")

	def, err := ds.Current("shop")
	if err != nil || def == nil || def.Spec.OpsInterface == nil {
		t.Fatalf("canonical after write-back: %v %+v", err, def)
	}
	oi := def.Spec.OpsInterface
	if oi.BaseURL != "http://api:9090" {
		t.Fatalf("the dashboard change wasn't written back: base_url %q", oi.BaseURL)
	}
	if len(oi.Alerts) != 1 || oi.Alerts[0].Name != "ratelimit-drops" {
		t.Fatalf("the write-back dropped the yaml's alerts: %+v", oi.Alerts)
	}
}
