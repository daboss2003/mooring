package definition

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// CurrentEach returns every app's live canonical like CurrentAll, but a row that fails verification or
// parsing is reported for its app alone and every other app is still returned.
func TestStoreCurrentEach(t *testing.T) {
	s, db := testStore(t)
	ctx := context.Background()
	if defs, bad, err := s.CurrentEach(ctx); err != nil || len(defs) != 0 || len(bad) != 0 {
		t.Fatalf("empty store: %v %v %v", defs, bad, err)
	}
	for _, slug := range []string{"shop", "blog", "wiki"} {
		d := base()
		d.Metadata.Slug = slug
		if _, err := s.SaveCanonical(ctx, d, "first", ""); err != nil {
			t.Fatal(err)
		}
	}
	d2 := base()
	d2.Spec.Scaling = []Scaling{{Service: "web", Max: 4}}
	if _, err := s.SaveCanonical(ctx, d2, "second", ""); err != nil {
		t.Fatal(err)
	}
	defs, bad, err := s.CurrentEach(ctx)
	if err != nil || len(bad) != 0 || len(defs) != 3 {
		t.Fatalf("all good: defs %v bad %v err %v", defs, bad, err)
	}
	if sc := defs["shop"].Spec.Scaling; len(sc) != 1 || sc[0].Max != 4 {
		t.Errorf("shop must be its newest version, got %+v", sc)
	}

	// blog tampered (HMAC mismatch), wiki no longer parses (its HMAC re-signed so only the parse fails).
	if _, err := db.Exec(`UPDATE definition_versions SET yaml=replace(yaml,'web','evil') WHERE slug='blog'`); err != nil {
		t.Fatal(err)
	}
	var wikiYAML string
	if err := db.QueryRow(`SELECT yaml FROM definition_versions WHERE slug='wiki'`).Scan(&wikiYAML); err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(wikiYAML, "kind: App", "kind: Nope", 1)
	if _, err := db.Exec(`UPDATE definition_versions SET yaml=?, hmac=? WHERE slug='wiki'`, broken, s.rowMAC([]byte(broken), "")); err != nil {
		t.Fatal(err)
	}

	defs, bad, err = s.CurrentEach(ctx)
	if err != nil {
		t.Fatalf("a bad row must not fail the whole read: %v", err)
	}
	if len(defs) != 1 || defs["shop"] == nil {
		t.Errorf("the good app must still be returned alone, got %v", defs)
	}
	if len(bad) != 2 || !errors.Is(bad["blog"], ErrTampered) || bad["wiki"] == nil || errors.Is(bad["wiki"], ErrTampered) {
		t.Errorf("bad = %v, want blog tampered and wiki's parse error", bad)
	}
	// CurrentAll, for callers that must fail closed, still fails the whole read.
	if _, err := s.CurrentAll(ctx); err == nil {
		t.Error("CurrentAll must still fail when any row is bad")
	}
}
