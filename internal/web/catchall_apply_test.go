package web

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/edge"
	"github.com/daboss2003/mooring/internal/store"
)

// applyRoutes is the AUTHORITATIVE catch-all gate: dns01 + operator consent are re-checked here on
// EVERY ingest path (an already-expanded `*.apex` hostname arrives via the stored canonical on a
// dashboard/scaling/ops edit, not just via subdomain expansion on the git path). Without this gate a
// later edit after the operator revokes consent would silently re-apply the catch-all. (Security
// review Finding 1.)
func TestApplyRoutesCatchAllConsentGate(t *testing.T) {
	newServer := func(bd config.EdgeBaseDomain) *Server {
		db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return &Server{
			cfg:        &config.Config{Edge: config.EdgeConfig{BaseDomains: []config.EdgeBaseDomain{bd}}},
			edgeRoutes: edge.NewRouteStore(db),
			log:        quietWebLog(),
		}
	}
	// An ALREADY-EXPANDED catch-all route (hostname *.apex), as the stored canonical holds it.
	mkDef := func() *definition.Definition {
		d := &definition.Definition{}
		d.Spec.Edge.Routes = []definition.Route{{Hostname: "*.shop.example.com", Service: "web", Port: 8080}}
		return d
	}
	dns := &config.EdgeDNS01{Provider: "cloudflare", APIToken: "tok"}
	ctx := context.Background()

	// dns01 + consent → applied, stored as a catch-all.
	s := newServer(config.EdgeBaseDomain{Name: "shop", Domain: "shop.example.com", DNS01: dns, CatchAll: true})
	if err := s.applyRoutes(ctx, "shop", mkDef()); err != nil {
		t.Fatalf("catch-all with dns01+consent should apply: %v", err)
	}
	if routes, _ := s.edgeRoutes.List(); len(routes) != 1 || !routes[0].CatchAll {
		t.Fatalf("stored route is not a catch-all: %+v", routes)
	}

	// consent but no dns01 → refused.
	if err := newServer(config.EdgeBaseDomain{Name: "shop", Domain: "shop.example.com", CatchAll: true}).applyRoutes(ctx, "shop", mkDef()); err == nil {
		t.Error("catch-all without dns01 must be refused at applyRoutes")
	}
	// dns01 but no consent → refused (the exact bypass the review flagged — gate is not expand-only).
	if err := newServer(config.EdgeBaseDomain{Name: "shop", Domain: "shop.example.com", DNS01: dns}).applyRoutes(ctx, "shop", mkDef()); err == nil {
		t.Error("catch-all without operator consent must be refused at applyRoutes")
	}
	// apex is not a declared namespace → refused.
	if err := newServer(config.EdgeBaseDomain{Name: "other", Domain: "other.example.com", DNS01: dns, CatchAll: true}).applyRoutes(ctx, "shop", mkDef()); err == nil {
		t.Error("catch-all on an undeclared apex must be refused")
	}
}
