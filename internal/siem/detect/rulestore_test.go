package detect

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/store"
)

func findRule(t *testing.T, e *Engine, id string) (siem.Rule, bool) {
	t.Helper()
	rs, err := e.Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.ID == id {
			return r, true
		}
	}
	return siem.Rule{}, false
}

func customRule(slug string) siem.Rule {
	return siem.Rule{ID: CustomPrefix + slug, Name: "Admin from Tor", Description: "x", Type: siem.RuleThreshold,
		Severity: siem.SevHigh, MITRE: []string{"T1078"}, Query: "kind:admin.login list:tor-exit", GroupBy: "ip",
		Count: 1, Window: time.Hour, Enabled: true}
}

func TestRulesListPackThenCustom(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	for _, slug := range []string{"zeta", "alpha"} {
		if err := h.e.SaveRule(ctx, customRule(slug)); err != nil {
			t.Fatal(err)
		}
	}
	rs, _ := h.e.Rules(ctx)
	if len(rs) != len(pack)+2 {
		t.Fatalf("%d rules, want %d", len(rs), len(pack)+2)
	}
	for i, p := range pack {
		if rs[i].ID != p.ID || !rs[i].Builtin || !rs[i].Enabled {
			t.Fatalf("rule %d = %s (builtin %v), want %s", i, rs[i].ID, rs[i].Builtin, p.ID)
		}
	}
	if rs[len(pack)].ID != "custom.alpha" || rs[len(pack)+1].ID != "custom.zeta" || rs[len(pack)].Builtin {
		t.Fatalf("custom order: %s, %s", rs[len(pack)].ID, rs[len(pack)+1].ID)
	}
	// The list is a copy.
	rs[0].MITRE[0] = "changed"
	if r, _ := findRule(t, h.e, pack[0].ID); r.MITRE[0] == "changed" {
		t.Fatal("Rules returned the engine's own slice")
	}
}

func TestSaveBuiltinTakesOnlyTunables(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	r, _ := findRule(t, h.e, "ssh.bruteforce")
	r.Name, r.Query, r.Type, r.GroupBy, r.MITRE, r.Description = "renamed", "kind:log", siem.RuleDistinct, "actor", nil, "d"
	r.Count, r.Window, r.Severity, r.Enabled = 7, 3*time.Minute, siem.SevCritical, false
	r.SnoozedUntil = t0.Add(24 * time.Hour)
	if err := h.e.SaveRule(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, _ := findRule(t, h.e, "ssh.bruteforce")
	p := packByID["ssh.bruteforce"]
	if got.Name != p.Name || got.Query != p.Query || got.Type != p.Type || got.GroupBy != p.GroupBy ||
		len(got.MITRE) != len(p.MITRE) || got.Description != p.Description || !got.Builtin {
		t.Fatalf("non-tunable fields changed: %+v", got)
	}
	if got.Count != 7 || got.Window != 3*time.Minute || got.Severity != siem.SevCritical || got.Enabled ||
		!got.SnoozedUntil.Equal(t0.Add(24*time.Hour)) {
		t.Fatalf("tunables not taken: %+v", got)
	}
	// Stored, so a restart keeps them.
	h.reopen(t)
	got, _ = findRule(t, h.e, "ssh.bruteforce")
	if got.Count != 7 || got.Enabled {
		t.Fatalf("after restart: %+v", got)
	}
	// Reset: back to the pack.
	if err := h.e.ResetRule(ctx, "ssh.bruteforce"); err != nil {
		t.Fatal(err)
	}
	got, _ = findRule(t, h.e, "ssh.bruteforce")
	if got.Count != p.Count || !got.Enabled || got.Severity != p.Severity || !got.SnoozedUntil.IsZero() {
		t.Fatalf("after reset: %+v", got)
	}
	h.reopen(t)
	if got, _ = findRule(t, h.e, "ssh.bruteforce"); got.Count != p.Count {
		t.Fatalf("reset not stored: %+v", got)
	}
	if err := h.e.ResetRule(ctx, "custom.x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reset of a custom rule: %v", err)
	}
	if err := h.e.DeleteRule(ctx, "ssh.bruteforce"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("delete of a built-in rule: %v", err)
	}
}

func TestCustomRuleCRUD(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	r := customRule("admin-tor")
	r.Builtin = true // ignored
	if err := h.e.SaveRule(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, ok := findRule(t, h.e, "custom.admin-tor")
	if !ok || got.Builtin || got.Query != r.Query || got.Name != r.Name {
		t.Fatalf("saved: %+v", got)
	}
	r.Count, r.Name = 3, "Edited"
	if err := h.e.SaveRule(ctx, r); err != nil {
		t.Fatal(err)
	}
	h.reopen(t)
	if got, _ = findRule(t, h.e, "custom.admin-tor"); got.Count != 3 || got.Name != "Edited" {
		t.Fatalf("edited after restart: %+v", got)
	}
	if err := h.e.DeleteRule(ctx, "custom.admin-tor"); err != nil {
		t.Fatal(err)
	}
	if _, ok := findRule(t, h.e, "custom.admin-tor"); ok {
		t.Fatal("deleted rule still listed")
	}
	if err := h.e.DeleteRule(ctx, "custom.admin-tor"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	h.reopen(t)
	if _, ok := findRule(t, h.e, "custom.admin-tor"); ok {
		t.Fatal("deleted rule back after restart")
	}
}

// A custom rule takes effect at once: the evaluation picks up the new set, and an unchanged rule
// keeps its state.
func TestSavedRuleIsEvaluated(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	for i := range 19 {
		h.feed(sshFail(time.Duration(i)*time.Second, "203.0.113.7"))
	}
	if err := h.e.SaveRule(ctx, customRule("tor")); err != nil {
		t.Fatal(err)
	}
	h.feed(sshFail(20*time.Second, "203.0.113.7")) // 20th: ssh.bruteforce kept its 19
	if ds := h.detections(t, "ssh.bruteforce"); len(ds) != 1 {
		t.Fatalf("ssh.bruteforce after another rule was saved: %+v", ds)
	}
	e := ev(21*time.Second, siem.SrcApp, "admin.login", siem.OutSuccess, "198.51.100.9", "a", nil)
	e.Geo = &siem.Geo{Lists: []string{"tor-exit"}}
	h.feed(e)
	if ds := h.detections(t, "custom.tor"); len(ds) != 1 {
		t.Fatalf("custom rule: %+v", ds)
	}
	// Changing a built-in rule's count keeps its state; switching it off stops it.
	r, _ := findRule(t, h.e, "ssh.bruteforce")
	r.Enabled = false
	if err := h.e.SaveRule(ctx, r); err != nil {
		t.Fatal(err)
	}
	for i := range 40 {
		h.feed(sshFail(time.Minute+time.Duration(i)*time.Second, "198.51.100.77"))
	}
	if ds := h.detections(t, "ssh.bruteforce"); len(ds) != 1 {
		t.Fatalf("a switched-off rule fired: %+v", ds)
	}
}

func TestSaveRuleValidation(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	mod := func(f func(*siem.Rule)) siem.Rule {
		r := customRule("v")
		f(&r)
		return r
	}
	bad := map[string]siem.Rule{
		"id prefix":     mod(func(r *siem.Rule) { r.ID = "mine.x" }),
		"id slug":       mod(func(r *siem.Rule) { r.ID = "custom.Bad_Slug" }),
		"id long":       mod(func(r *siem.Rule) { r.ID = "custom." + strings.Repeat("a", 49) }),
		"id dash first": mod(func(r *siem.Rule) { r.ID = "custom.-x" }),
		"type":          mod(func(r *siem.Rule) { r.Type = "regex" }),
		"query":         mod(func(r *siem.Rule) { r.Query = "nosuchfield:x" }),
		"empty query":   mod(func(r *siem.Rule) { r.Query = "  " }),
		"severity":      mod(func(r *siem.Rule) { r.Severity = "urgent" }),
		"count 0":       mod(func(r *siem.Rule) { r.Count = 0 }),
		"count big":     mod(func(r *siem.Rule) { r.Count = maxCount + 1 }),
		"window short":  mod(func(r *siem.Rule) { r.Window = 59 * time.Second }),
		"window long":   mod(func(r *siem.Rule) { r.Window = 8 * 24 * time.Hour }),
		"name empty":    mod(func(r *siem.Rule) { r.Name = " " }),
		"name long":     mod(func(r *siem.Rule) { r.Name = strings.Repeat("n", 81) }),
		"name control":  mod(func(r *siem.Rule) { r.Name = "a\nb" }),
		"description":   mod(func(r *siem.Rule) { r.Description = strings.Repeat("d", 501) }),
		"mitre format":  mod(func(r *siem.Rule) { r.MITRE = []string{"T110"} }),
		"mitre many": mod(func(r *siem.Rule) {
			r.MITRE = strings.Split("T1000 T1001 T1002 T1003 T1004 T1005 T1006 T1007 T1008", " ")
		}),
		"group by":        mod(func(r *siem.Rule) { r.GroupBy = "msg" }),
		"snooze long":     mod(func(r *siem.Rule) { r.SnoozedUntil = t0.Add(31 * 24 * time.Hour) }),
		"distinct field":  mod(func(r *siem.Rule) { r.Type = siem.RuleDistinct }),
		"distinct count":  mod(func(r *siem.Rule) { r.Type, r.Field, r.Count = siem.RuleDistinct, "actor", 1001 }),
		"new_value field": mod(func(r *siem.Rule) { r.Type = siem.RuleNewValue }),
		"learn":           mod(func(r *siem.Rule) { r.Type, r.Field, r.Learn = siem.RuleNewValue, "geo.cc", 31*24*time.Hour }),
		"factor":          mod(func(r *siem.Rule) { r.Type, r.Factor = siem.RuleAnomaly, 1.4 }),
		"anomaly window":  mod(func(r *siem.Rule) { r.Type, r.Factor, r.Window = siem.RuleAnomaly, 2, 25*time.Hour }),
		"speed":           mod(func(r *siem.Rule) { r.Type, r.SpeedKMH = siem.RuleTravel, 99 }),
		"speed nan":       mod(func(r *siem.Rule) { r.Type, r.SpeedKMH = siem.RuleTravel, nan() }),
		"sequence then":   mod(func(r *siem.Rule) { r.Type = siem.RuleSequence }),
		"sequence bad":    mod(func(r *siem.Rule) { r.Type, r.Then = siem.RuleSequence, "x:" }),
		"sequence count":  mod(func(r *siem.Rule) { r.Type, r.Then, r.Count = siem.RuleSequence, "kind:x.y", 1001 }),
	}
	for name, r := range bad {
		if err := h.e.SaveRule(ctx, r); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: SaveRule = %v, want ErrInvalid", name, err)
		}
	}
	good := map[string]siem.Rule{
		"bounds low":  mod(func(r *siem.Rule) { r.Count, r.Window = 1, time.Minute }),
		"bounds high": mod(func(r *siem.Rule) { r.Count, r.Window = maxCount, 7*24*time.Hour }),
		"anomaly": mod(func(r *siem.Rule) {
			r.Type, r.Factor, r.Learn, r.Window = siem.RuleAnomaly, 1.5, 30*24*time.Hour, 24*time.Hour
		}),
		"travel":   mod(func(r *siem.Rule) { r.Type, r.SpeedKMH = siem.RuleTravel, 20000 }),
		"sequence": mod(func(r *siem.Rule) { r.Type, r.Then, r.Count = siem.RuleSequence, "kind:x.y", 1000 }),
		"f field":  mod(func(r *siem.Rule) { r.Type, r.Field, r.GroupBy = siem.RuleDistinct, "f.req.path", "f.host" }),
		"no mitre": mod(func(r *siem.Rule) { r.MITRE = nil }),
	}
	for name, r := range good {
		if err := h.e.SaveRule(ctx, r); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A built-in rule is validated with its tunables applied.
	b, _ := findRule(t, h.e, "edge.error_anomaly")
	b.Factor = 1
	if err := h.e.SaveRule(ctx, b); !errors.Is(err, ErrInvalid) {
		t.Errorf("built-in factor 1: %v", err)
	}
	// A rule the engine refused is not stored.
	h.reopen(t)
	if rs, _ := h.e.Rules(ctx); len(rs) != len(pack)+1 {
		t.Errorf("%d rules after restart, want the pack + custom.v", len(rs))
	}
}

func nan() float64 { var z float64; return z / z }

func TestCustomRuleLimit(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	for i := range MaxCustomRules {
		if err := h.e.SaveRule(ctx, customRule(fmt.Sprint("r", i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.e.SaveRule(ctx, customRule("one-more")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("rule %d: %v", MaxCustomRules+1, err)
	}
	r := customRule("r5") // editing one at the limit works
	r.Count = 9
	if err := h.e.SaveRule(ctx, r); err != nil {
		t.Fatalf("edit at the limit: %v", err)
	}
}

func TestNoRuleStore(t *testing.T) {
	h := newHarness(t, false)
	ctx := context.Background()
	if err := h.e.SaveRule(ctx, customRule("x")); !errors.Is(err, ErrNoStore) {
		t.Fatalf("SaveRule without a database: %v", err)
	}
	if rs, _ := h.e.Rules(ctx); len(rs) != len(pack) {
		t.Fatalf("rules without a database: %d", len(rs))
	}
}

// Stored rows that don't decode or validate never refuse the start: a built-in rule's bad setting
// falls back to the pack's value (that setting only), a bad custom rule is listed switched off.
func TestBadStoredRulesSkipped(t *testing.T) {
	h := newHarness(t, true)
	for id, js := range map[string]string{
		"ssh.bruteforce":   `{"enabled":true,"severity":"bogus","count":5,"window":600000000000}`,
		"edge.scan":        `not json`,
		"custom.broken":    `{"name":"x","type":"threshold","query":"nosuch:1","severity":"low","count":1,"window":60000000000}`,
		"custom.ok":        `{"name":"ok","type":"threshold","query":"kind:x.y","severity":"low","count":1,"window":60000000000,"enabled":true}`,
		"retired.old_rule": `{}`,
	} {
		if _, err := h.main.Exec(`INSERT INTO security_rules(id, json, updated_at) VALUES (?, ?, 1)`, id, js); err != nil {
			t.Fatal(err)
		}
	}
	h.reopen(t)
	if r, _ := findRule(t, h.e, "ssh.bruteforce"); r.Severity != packByID["ssh.bruteforce"].Severity || r.Count != 5 {
		t.Errorf("bad severity: want the pack's severity and the stored count: %+v", r)
	}
	if r, ok := findRule(t, h.e, "custom.broken"); !ok || r.Enabled || !strings.HasPrefix(r.Description, "stored rule is invalid: ") {
		t.Errorf("invalid custom rule: want it listed switched off with the reason: %+v", r)
	}
	if _, ok := h.e.rules.Load().byID["custom.broken"]; ok {
		t.Error("invalid custom rule evaluated")
	}
	if r, ok := findRule(t, h.e, "custom.ok"); !ok || r.ID != "custom.ok" {
		t.Error("valid custom rule not loaded")
	}
}

// Migration 0041 applies on a database an older release left at version 40.
func TestMigration0041OnExistingDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mooring.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE security_rules`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM schema_meta WHERE version = 41`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events(ts, action) VALUES (1, 'kept')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	db, err = store.Open(path)
	if err != nil {
		t.Fatalf("upgrade from 40: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM security_rules`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("security_rules after upgrade: %d, %v", n, err)
	}
	var action string
	if err := db.QueryRow(`SELECT action FROM events WHERE ts = 1`).Scan(&action); err != nil || action != "kept" {
		t.Fatalf("old row: %q, %v", action, err)
	}
	var v int
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_meta`).Scan(&v); err != nil || v < 41 {
		t.Fatalf("version %d, %v", v, err)
	}
	e, err := New(Options{Dir: t.TempDir(), MainDB: db})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.SaveRule(context.Background(), customRule("after-upgrade")); err != nil {
		t.Fatal(err)
	}
	var js string
	if err := db.QueryRow(`SELECT json FROM security_rules WHERE id = 'custom.after-upgrade'`).Scan(&js); err != nil ||
		!strings.Contains(js, `"query":"kind:admin.login list:tor-exit"`) {
		t.Fatalf("stored json %q, %v", js, err)
	}
	_ = sql.ErrNoRows
}
