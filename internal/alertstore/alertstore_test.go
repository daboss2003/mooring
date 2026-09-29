package alertstore

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/store"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cipher, err := secret.NewCipher(make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	return New(db, cipher)
}

// ManagedNtfy returns the subscribe info (base url, topic, read-only username+password)
// but never the write token Mooring publishes with.
func TestManagedNtfyExposesSubscriberCredsNotWriteToken(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	cfg := `{"url":"http://127.0.0.1:2586","topic":"alerts","token":"tk_writeXXXXXXXXXXXXXXXXXXXXXXXXX","sub_user":"phone","sub_pass":"S3cretSubscriberPass","base_url":"https://ntfy.example.com"}`
	if err := s.SaveChannel(ctx, "hosted", "ntfy_managed", []byte(cfg)); err != nil {
		t.Fatal(err)
	}
	info, ok, err := s.ManagedNtfy()
	if err != nil || !ok {
		t.Fatalf("ManagedNtfy: %v ok=%v", err, ok)
	}
	if info.BaseURL != "https://ntfy.example.com" || info.Topic != "alerts" {
		t.Errorf("wrong subscribe info: %+v", info)
	}
	if info.Username != "phone" || info.Password != "S3cretSubscriberPass" {
		t.Errorf("subscriber creds = %q / %q", info.Username, info.Password)
	}
	// The write token must never be reachable through NtfyManagedInfo (no field carries it).
	if strings.Contains(info.Username+info.Password+info.BaseURL+info.Topic, "tk_write") {
		t.Error("the write token must never be exposed via ManagedNtfy")
	}
	// No managed channel → ok=false.
	s2 := newStore(t)
	if _, ok, _ := s2.ManagedNtfy(); ok {
		t.Error("ManagedNtfy must be ok=false when none is configured")
	}
}

func TestChannelEncryptedRoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.SaveChannel(ctx, "hook", "webhook", []byte(`{"url":"https://example.com/h","secret":"top-secret-hmac"}`)); err != nil {
		t.Fatal(err)
	}
	metas, _ := s.ListChannels()
	if len(metas) != 1 || metas[0].Kind != "webhook" {
		t.Fatalf("list channels: %+v", metas)
	}
	var raw []byte
	if err := s.db.QueryRow(`SELECT config_enc FROM alert_channels WHERE name='hook'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "top-secret-hmac") {
		t.Error("channel secret stored in plaintext")
	}
	if _, err := s.ChannelByID(metas[0].ID); err != nil {
		t.Errorf("channel did not rebuild: %v", err)
	}
}

func TestChannelSaveRejectsBadConfig(t *testing.T) {
	s := newStore(t)
	if err := s.SaveChannel(context.Background(), "x", "webhook", []byte(`{"url":"https://x","evil":1}`)); err == nil {
		t.Error("unknown-field config should be rejected")
	}
	if err := s.SaveChannel(context.Background(), "x", "nope", []byte(`{}`)); err == nil {
		t.Error("unknown kind should be rejected")
	}
}

func TestRuleCRUD(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.SaveRule(ctx, alert.Rule{Name: "cpu", Kind: alert.KindHostCPU, Threshold: 90, ForSeconds: 60, Level: alert.LevelWarning, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rules, _ := s.ListRules()
	if len(rules) != 1 || rules[0].Kind != alert.KindHostCPU {
		t.Fatalf("rules: %+v", rules)
	}
	if err := s.SaveRule(ctx, alert.Rule{Name: "bad", Kind: "nonsense"}); err == nil {
		t.Error("unknown kind rule should be rejected")
	}
	_ = s.DeleteRule(ctx, rules[0].ID)
	if rules, _ := s.ListRules(); len(rules) != 0 {
		t.Error("rule not deleted")
	}
}

func TestStatePersistAndPrune(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	states := []alert.State{
		{RuleID: 1, Target: "host", Phase: alert.PhaseFiring, Since: 100, Level: "warning"},
		{RuleID: 1, Target: "shop/web", Phase: alert.PhaseOK},
	}
	if err := s.SaveStates(ctx, states); err != nil {
		t.Fatal(err)
	}
	loaded, _ := s.LoadStates()
	if len(loaded) != 1 || loaded[0].Target != "host" {
		t.Fatalf("expected only the firing row, got %+v", loaded)
	}
	if firing, _ := s.FiringStates(); len(firing) != 1 {
		t.Errorf("firing states: %d", len(firing))
	}
}

func TestOutboxLifecycle(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.EnqueueOutbox(ctx, []alert.Outbox{{RuleID: 1, Target: "host", Kind: "host_cpu", Level: "warning", Transition: "firing", Summary: "hot"}}); err != nil {
		t.Fatal(err)
	}
	pending, _ := s.PendingOutbox(10)
	if len(pending) != 1 {
		t.Fatalf("pending: %d", len(pending))
	}
	s.MarkSent(ctx, pending[0].ID, true, 3)
	if p, _ := s.PendingOutbox(10); len(p) != 0 {
		t.Error("row should be sent")
	}
}

func TestAckAndSilence(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_ = s.SaveStates(ctx, []alert.State{{RuleID: 1, Target: "host", Phase: alert.PhaseFiring, Since: 1}})
	if err := s.Ack(ctx, 1, "host"); err != nil {
		t.Fatal(err)
	}
	fs, _ := s.FiringStates()
	if len(fs) != 1 || !fs[0].Acked {
		t.Errorf("ack not recorded: %+v", fs)
	}
	_ = s.Silence(ctx, 1, "host", 1<<40)
	if !s.IsSilenced(1, "host", 100) {
		t.Error("silence not recorded")
	}
}

// A key whose latest infra row is "firing" is still open; one that was resolved later is not; other
// kinds and rule-based rows are ignored.
func TestOpenInfraAlerts(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, o := range []alert.Outbox{
		{Target: "shop", Kind: "edge_unroutable", Level: alert.LevelWarning, Transition: "firing", DedupeKey: "edge:a.example.com"},
		{Target: "shop", Kind: "edge_unroutable", Level: alert.LevelWarning, Transition: "firing", DedupeKey: "edge:b.example.com"},
		{Target: "shop", Kind: "edge_unroutable", Level: alert.LevelWarning, Transition: "resolved", DedupeKey: "edge:b.example.com"},
		{Target: "", Kind: "docker_daemon_mismatch", Level: alert.LevelCritical, Transition: "firing", DedupeKey: "docker:daemon-mismatch"},
	} {
		if err := s.EnqueueInfra(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.OpenInfraAlerts(ctx, "edge_unroutable")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["edge:a.example.com"] != "shop" {
		t.Fatalf("want only edge:a open, got %v", got)
	}
	if d, _ := s.OpenInfraAlerts(ctx, "docker_daemon_mismatch"); len(d) != 1 {
		t.Fatalf("want the daemon alert open, got %v", d)
	}
}
