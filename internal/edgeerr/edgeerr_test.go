package edgeerr

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRateBuckets(t *testing.T) {
	now := int64(10000)
	s := newWithClock(filepath.Join(t.TempDir(), "e.jsonl"), func() time.Time { return time.Unix(now, 0) })
	// api errors: two land in the same 300s bucket (9500, 9550), one 5xx in a later bucket (9900).
	s.Record(Entry{At: now - 500, App: "shop", Service: "api", Host: "h", Prefix: "/api", Status: 404})
	s.Record(Entry{At: now - 450, App: "shop", Service: "api", Host: "h", Prefix: "/api", Status: 502})
	s.Record(Entry{At: now - 100, App: "shop", Service: "api", Host: "h", Prefix: "/api", Status: 500})
	// a DIFFERENT service's error must never leak into api's buckets.
	s.Record(Entry{At: now - 100, App: "shop", Service: "web", Host: "h", Prefix: "", Status: 500})

	b := s.RateBuckets("shop", "api", 300, now-900) // 300s buckets over the last 15m
	if len(b) == 0 {
		t.Fatal("expected buckets")
	}
	// Buckets are contiguous and boundary-aligned; the series must be non-decreasing in T.
	var total, total5xx int
	for i, x := range b {
		total += x.Count
		total5xx += x.Count5xx
		if i > 0 && x.T <= b[i-1].T {
			t.Fatalf("buckets not ordered: %d then %d", b[i-1].T, x.T)
		}
	}
	if total != 3 || total5xx != 2 {
		t.Errorf("api totals across buckets: count=%d (want 3), 5xx=%d (want 2)", total, total5xx)
	}
	// Two errors fell in one 300s bucket — at least one bucket must hold 2.
	max := 0
	for _, x := range b {
		if x.Count > max {
			max = x.Count
		}
	}
	if max < 2 {
		t.Errorf("expected a bucket with 2 errors, max was %d", max)
	}
}

func TestStoreRoutesAndFilter(t *testing.T) {
	s := newWithClock(filepath.Join(t.TempDir(), "e.jsonl"), func() time.Time { return time.Unix(10000, 0) })
	// Appended in ascending time order (as real requests arrive); the store returns newest first.
	s.Record(Entry{At: 9998, App: "shop", Service: "web", Host: "shop.com", Prefix: "", Method: "GET", Path: "/", Status: 500, RemoteIP: "3.3.3.3"})
	s.Record(Entry{At: 9999, App: "shop", Service: "api", Host: "shop.com", Prefix: "/api", Method: "POST", Path: "/api/y", Status: 404, RemoteIP: "2.2.2.2"})
	s.Record(Entry{At: 10000, App: "shop", Service: "api", Host: "shop.com", Prefix: "/api", Method: "GET", Path: "/api/x", Status: 502, RemoteIP: "1.1.1.1"})

	routes := s.Routes()
	if len(routes) != 2 {
		t.Fatalf("distinct routes = %d, want 2", len(routes))
	}
	var api *RouteSummary
	for i := range routes {
		if routes[i].Prefix == "/api" {
			api = &routes[i]
		}
	}
	if api == nil || api.Count24h != 2 || api.Count5xx != 1 {
		t.Errorf("/api rollup wrong: %+v", api)
	}
	// Newest-first + text filter.
	if got := s.Errors("shop", "shop.com", "/api", "", 10); len(got) != 2 || got[0].Status != 502 {
		t.Errorf("/api errors newest-first: %+v", got)
	}
	if got := s.Errors("shop", "shop.com", "/api", "404", 10); len(got) != 1 || got[0].Status != 404 {
		t.Errorf("status filter: %+v", got)
	}
	if got := s.Errors("shop", "shop.com", "/api", "post", 10); len(got) != 1 {
		t.Errorf("method filter: %d", len(got))
	}
	// Route scoping: the /api route's filter never returns the whole-host route's entry.
	if got := s.Errors("shop", "shop.com", "", "", 10); len(got) != 1 || got[0].Path != "/" {
		t.Errorf("whole-host route scoping: %+v", got)
	}
}

func TestStoreTTLAndPersist(t *testing.T) {
	now := time.Unix(100000, 0)
	path := filepath.Join(t.TempDir(), "e.jsonl")
	s := newWithClock(path, func() time.Time { return now })
	s.Record(Entry{At: 100000 - int64((25 * time.Hour).Seconds()), App: "a", Host: "h", Status: 500}) // past 24h TTL
	s.Record(Entry{At: 100000 - 100, App: "a", Host: "h", Status: 500})
	if r := s.Routes(); len(r) != 1 || r[0].Count24h != 1 {
		t.Errorf("TTL should drop the >24h entry: %+v", r)
	}
	s.Flush()
	s2 := newWithClock(path, func() time.Time { return now })
	if r := s2.Routes(); len(r) != 1 || r[0].Count24h != 1 {
		t.Errorf("only the within-TTL entry should survive a reopen: %+v", r)
	}
}
