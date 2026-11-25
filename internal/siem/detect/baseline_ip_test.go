package detect

import (
	"fmt"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

func edgeReq(when time.Time, ip, path string, status float64) siem.Event {
	return siem.Event{TS: when.UTC(), Src: siem.SrcEdge, Kind: siem.KindHTTPRequest, IP: ip,
		F: map[string]any{"host": "shop.example.com", "path": path, "status": status}}
}

// learnAddr feeds ip's first day: 240 requests, one every 6 minutes from day 0 00:00; every
// authEvery-th one to /login, one in 30 answered 404.
func learnAddr(h *harness, ip string, authEvery int) {
	for i := range 240 {
		path, st := "/api/v1/items", 200.0
		if i%authEvery == 0 {
			path = "/login"
		}
		if i%30 == 1 {
			st = 404
		}
		h.feed(edgeReq(at(0, 0, 0).Add(time.Duration(i)*6*time.Minute), ip, path, st))
	}
}

func TestBaselineIPMixJump(t *testing.T) {
	type req struct {
		path string
		st   float64
	}
	signIn := func(i int) req {
		if i < 10 {
			return req{"/api/v1/items", 200}
		}
		return req{"/wp-login.php", 200}
	}
	for _, tc := range []struct {
		name      string
		mod       func(*siem.Rule)
		authEvery int
		burst     func(i int) req
		spacing   time.Duration
		want      string // "": nothing fires
	}{
		{"sign-in share jumps", nil, 20, signIn, 5 * time.Second,
			"203.0.113.7 — 40 of 50 requests in 10m to sign-in endpoints (usually 5%)"},
		{"count 100: 50 requests too few", func(r *siem.Rule) { r.Count = 100 }, 20, signIn, 5 * time.Second, ""},
		{"spread over 40 minutes: no 50 in a 10m window", nil, 20, signIn, 48 * time.Second, ""},
		{"window 1h: the same requests in one window", func(r *siem.Rule) { r.Window = time.Hour }, 20, signIn, 48 * time.Second,
			"203.0.113.7 — 40 of 50 requests in 1h to sign-in endpoints (usually 5%)"},
		{"usually 28% sign-ins: 80% isn't 5×", nil, 3, signIn, 5 * time.Second, ""},
		{"usually 28% sign-ins (80 of 240, then 3 of 60), factor 2", func(r *siem.Rule) { r.Factor = 2 }, 3, signIn, 5 * time.Second,
			"203.0.113.7 — 40 of 50 requests in 10m to sign-in endpoints (usually 28%)"},
		{"errors", nil, 20, func(i int) req {
			if i < 10 {
				return req{"/api/v1/items", 200}
			}
			return req{"/api/v1/items", 401}
		}, 5 * time.Second, "203.0.113.7 — 40 of 50 requests in 10m answered with an error (usually 3%)"},
		{"admin paths", nil, 20, func(i int) req { return req{"/wp-admin/setup-config.php", 200} }, 5 * time.Second,
			"203.0.113.7 — 50 of 50 requests in 10m to admin paths (usually 0%)"},
		{"learn 2d: still learning", func(r *siem.Rule) { r.Learn = 2 * day }, 20, signIn, 5 * time.Second, ""},
		{"20% sign-ins, usually under 1%: under half", nil, 1000, func(i int) req {
			if i < 40 {
				return req{"/api/v1/items", 200}
			}
			return req{"/login", 200}
		}, 5 * time.Second, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := blRule("baseline.ip_behaviour")
			if tc.mod != nil {
				tc.mod(&r)
			}
			h := blHarness(t, tokyo, nil, r)
			learnAddr(h, "203.0.113.7", tc.authEvery)
			// While learning, a burst from a new address fires nothing.
			for i := range 60 {
				h.feed(edgeReq(at(0, 23, 50).Add(time.Duration(i)*time.Second), "198.51.100.9", "/wp-login.php", 200))
			}
			// A usual window the next day.
			for i := range 60 {
				p := "/api/v1/items"
				if i%20 == 0 {
					p = "/login"
				}
				h.feed(edgeReq(at(1, 0, 10).Add(time.Duration(i)*5*time.Second), "203.0.113.7", p, 200))
			}
			if ds := h.all(t); len(ds) != 0 {
				t.Fatalf("learning burst or usual window:\n%s", summaries(ds))
			}
			for i := range 50 {
				q := tc.burst(i)
				h.feed(edgeReq(at(1, 1, 0).Add(time.Duration(i)*tc.spacing), "203.0.113.7", q.path, q.st))
			}
			ds := h.all(t)
			switch {
			case tc.want == "" && len(ds) != 0:
				t.Fatalf("fired:\n%s", summaries(ds))
			case tc.want != "" && (len(ds) != 1 || ds[0].Summary != tc.want || ds[0].Count != 50 || ds[0].Severity != siem.SevLow):
				t.Fatalf("got:\n%s\nwant %s", summaries(ds), tc.want)
			}
		})
	}
}

// An IPv6 client's addresses count as its /64; after firing the window starts again.
func TestBaselineIPv6AndRefire(t *testing.T) {
	h := blHarness(t, tokyo, nil, blRule("baseline.ip_behaviour"))
	for i := range 240 {
		ip := fmt.Sprintf("2001:db8:1:2::%x", i)
		h.feed(edgeReq(at(0, 0, 0).Add(time.Duration(i)*6*time.Minute), ip, "/api/v1/items", 200))
	}
	if h.e.bl.ip.len() != 1 || h.e.bl.ip.peek("2001:db8:1:2::/64") == nil {
		t.Fatalf("%d addresses tracked", h.e.bl.ip.len())
	}
	for i := range 100 {
		h.feed(edgeReq(at(1, 1, 0).Add(time.Duration(i)*time.Second), fmt.Sprintf("2001:db8:1:2::%x", 1000+i), "/oauth/token", 200))
	}
	ds := h.all(t)
	if len(ds) != 1 || ds[0].Key != "2001:db8:1:2::/64" || ds[0].Count != 100 {
		t.Fatalf("two windows of 50 in one detection:\n%s", summaries(ds))
	}
	if got := ds[0].Summary; got != "2001:db8:1:2::/64 — 50 of 50 requests in 10m to sign-in endpoints (usually 17%)" {
		t.Fatalf("summary %q (the first window is in the usual mix)", got)
	}
}

func TestBaselinePathKinds(t *testing.T) {
	for p, want := range map[string][2]bool{
		"/login":                   {true, false},
		"/wp-login.php":            {true, false},
		"/api/v1/auth/refresh":     {true, false},
		"/oauth2/authorize":        {true, false},
		"/users/password/reset":    {true, false},
		"/author/jane":             {false, false},
		"/wp-admin/admin-ajax.php": {false, true},
		"/admin/login":             {true, true},
		"/actuator/env":            {false, true},
		"/phpMyAdmin/index.php":    {false, true},
		"/static/app.js":           {false, false},
		"/api/v1/tokenize":         {false, false},
		"":                         {false, false},
		"//":                       {false, false},
	} {
		if a, d := pathKinds(p); a != want[0] || d != want[1] {
			t.Errorf("pathKinds(%q) = %v, %v; want %v", p, a, d, want)
		}
	}
	var x addrMix
	x.add(int64(time.Hour), 10*time.Minute, true, false, true)
	x.add(int64(2*time.Hour), 10*time.Minute, false, true, false)
	y, err := decodeIP(x.encode())
	if err != nil || y.total != 2 || y.auth != 1 || y.admin != 1 || y.errs != 1 || y.first != 3600 {
		t.Fatalf("round trip (the window counted in): %+v %v", y, err)
	}
	for _, bad := range [][]byte{nil, {2}, append(x.encode(), 0), {ipVersion, 2, 1, 5, 0, 0}} {
		if _, err := decodeIP(bad); err == nil {
			t.Errorf("decodeIP(%x) accepted", bad)
		}
	}
}

// An address needs count requests before the window: all of its earlier requests count, also those
// in slots the window has moved past without reusing.
func TestBaselineIPNeedsHistory(t *testing.T) {
	h := blHarness(t, tokyo, nil, blRule("baseline.ip_behaviour"))
	for i := range 5 {
		h.feed(edgeReq(at(0, 0, 0).Add(time.Duration(i)*time.Minute), "203.0.113.5", "/", 200))
	}
	for i := range 50 {
		h.feed(edgeReq(at(0, 0, 10).Add(time.Duration(i)*10*time.Second), "203.0.113.6", "/", 200))
	}
	for i := range 50 {
		h.feed(edgeReq(at(1, 1, 0).Add(time.Duration(i)*5*time.Second), "203.0.113.5", "/login", 200))
		h.feed(edgeReq(at(1, 1, 0).Add(time.Duration(i)*5*time.Second), "203.0.113.6", "/login", 200))
	}
	ds := h.all(t)
	if len(ds) != 1 || ds[0].Summary != "203.0.113.6 — 50 of 50 requests in 10m to sign-in endpoints (usually 0%)" {
		t.Fatalf("5 requests before (no) and 50 (yes):\n%s", summaries(ds))
	}
}
