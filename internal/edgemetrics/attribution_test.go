package edgemetrics

import (
	"testing"
	"time"
)

func TestHostIndexLookup(t *testing.T) {
	idx := NewHostIndex()
	idx.Set([]Route{
		{Host: "API.example.com", PathPrefix: "", Key: Key{App: "shop", Service: "api"}},
		{Host: "app.example.com", PathPrefix: "/api", Key: Key{App: "shop", Service: "backend"}},
		{Host: "app.example.com", PathPrefix: "/", Key: Key{App: "shop", Service: "web"}},
		{Host: "bad.example.com", Key: Key{App: "", Service: ""}}, // dropped (incomplete key)
	})

	cases := []struct {
		host, path       string
		wantApp, wantSvc string
		wantOK           bool
	}{
		{"api.example.com", "/anything", "shop", "api", true},   // host match is case-insensitive
		{"app.example.com", "/api/v2/x", "shop", "backend", true}, // longest prefix wins over "/"
		{"app.example.com", "/apiary", "shop", "web", true},       // segment boundary: /apiary is NOT under /api
		{"app.example.com", "/home", "shop", "web", true},         // falls to the "/" (root) route
		{"unknown.example.com", "/", "", "", false},               // unknown host → not attributed
		{"bad.example.com", "/", "", "", false},                   // dropped route → unknown
	}
	for _, c := range cases {
		k, ok := idx.Lookup(c.host, c.path)
		if ok != c.wantOK || k.App != c.wantApp || k.Service != c.wantSvc {
			t.Errorf("Lookup(%q,%q) = (%+v,%v), want (App=%q,Service=%q,%v)", c.host, c.path, k, ok, c.wantApp, c.wantSvc, c.wantOK)
		}
	}
}

func TestCollectorIngest(t *testing.T) {
	base := time.Unix(5_000_000, 0)
	agg := New(30 * time.Second)
	agg.now = func() time.Time { return base }
	idx := NewHostIndex()
	idx.Set([]Route{{Host: "api.example.com", Key: Key{App: "shop", Service: "api"}}})
	col := NewCollector(agg, idx)

	// A matching access line records a sample against (shop, api).
	col.Ingest([]byte(`{"logger":"http.log.access.mooring_access","request":{"host":"api.example.com","uri":"/v1/x"},"duration":0.25,"status":200}`))
	// A hostile Host header that matches no route must NOT record.
	col.Ingest([]byte(`{"logger":"http.log.access.mooring_access","request":{"host":"evil.attacker.test","uri":"/"},"duration":9.9,"status":404}`))
	// Garbage / non-access lines are no-ops.
	col.Ingest([]byte(`not json`))
	col.Ingest([]byte(`{"level":"error","msg":"boom"}`))

	p95, _, present := agg.Stats(Key{App: "shop", Service: "api"})
	if !present {
		t.Fatal("the matching request should have recorded a sample")
	}
	if p95 < 249 || p95 > 251 { // 0.25s → 250ms
		t.Errorf("p95 = %v, want ~250ms", p95)
	}
	if _, _, present := agg.Stats(Key{App: "shop", Service: "attacker"}); present {
		t.Error("a bogus Host header must never be attributed to a service")
	}

	// A nil-safe collector never panics.
	var nc *Collector
	nc.Ingest([]byte(`{}`))
}
