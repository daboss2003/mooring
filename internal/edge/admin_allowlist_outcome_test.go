package edge

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

var testAppRoute = Route{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true}

// allowState checks AdminAllowlistState.
func allowState(t *testing.T, rec *Reconciler, when string, wantForce []string, wantPending bool) {
	t.Helper()
	force, pending := rec.AdminAllowlistState()
	if !reflect.DeepEqual(force, wantForce) || pending != wantPending {
		t.Fatalf("%s: AdminAllowlistState = %v, pending=%v; want %v, pending=%v", when, force, pending, wantForce, wantPending)
	}
}

// Abuse: a list Render refuses (an entry that admits every address) picked up by a reconcile that also
// carries a route change. The list is given up, never reaches Caddy, and the SAME reconcile applies
// the route with the previous list; the error names the list and says the config was applied.
func TestRenderRefusedAllowlistStillAppliesRouteChange(t *testing.T) {
	ctx := context.Background()
	for _, list := range [][]string{{"0.0.0.0/0"}, {"198.51.100.7/32", "::/0"}, {"nope"}, {}} {
		admin := &fakeCaddyAdmin{reject: func([]byte, int) bool { return false }}
		rec := allowlistReconciler(t, admin)
		told := 0
		rec.SetAdminAllowlistAccepted(func([]string) { told++ })
		if err := rec.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		prev := []string{"203.0.113.0/24"}
		if err := rec.store.Save(ctx, testAppRoute); err != nil {
			t.Fatal(err)
		}
		before, _ := admin.state()
		rec.SetAdminAllowlist(list)
		allowState(t, rec, "set", prev, true)
		err := rec.Reconcile(ctx) // a deploy's reconcile that took the mutex before the reload's
		var dropped *AllowlistDroppedError
		if !errors.As(err, &dropped) || !ConfigApplied(err) {
			t.Fatalf("list %q: Reconcile = %v (%T), want an AllowlistDroppedError", list, err, err)
		}
		if errors.As(err, new(*ConfigRejectedError)) {
			t.Errorf("list %q: Caddy rejected nothing, but the error is a ConfigRejectedError: %v", list, err)
		}
		if !strings.Contains(err.Error(), "ip_allowlist") && !strings.Contains(err.Error(), "IP allowlist") {
			t.Errorf("list %q: the error doesn't name the list: %v", list, err)
		}
		if len(list) > 0 && list[0] != "nope" && !strings.Contains(err.Error(), "admits every address") {
			t.Errorf("list %q: the error doesn't say why: %v", list, err)
		}
		calls, body := admin.state()
		if calls != before+1 {
			t.Fatalf("list %q: want one /load (the previous list's render), got %d", list, calls-before)
		}
		if !strings.Contains(string(body), "app.example.com") || !reflect.DeepEqual(adminRanges(t, body), prev) {
			t.Fatalf("list %q: the route must be live with the previous list after the same reconcile:\n%s", list, body)
		}
		admin.mu.Lock()
		for i, b := range admin.bodies {
			for _, r := range adminRanges(t, b) {
				if p, perr := netip.ParsePrefix(r); perr != nil || p.Bits() == 0 {
					t.Fatalf("list %q: /load %d carried the dashboard range %q", list, i+1, r)
				}
			}
		}
		admin.mu.Unlock()
		allowState(t, rec, "dropped by Render", prev, false)
		if st := rec.RouteStatuses(); len(st) != 1 || st[0].Hostname != "app.example.com" {
			t.Errorf("list %q: the route's status was not committed: %+v", list, st)
		}
		if refused, _, _ := rec.LoadRefused(); refused {
			t.Errorf("list %q: no /load was refused", list)
		}
		if err := rec.Reconcile(ctx); err != nil {
			t.Fatalf("list %q: the next reconcile: %v", list, err)
		}
		if c, _ := admin.state(); c != calls {
			t.Errorf("list %q: the committed render is what Caddy serves: the next reconcile must not load", list)
		}
		if told != 0 {
			t.Errorf("list %q: a refused list was reported as accepted", list)
		}
	}
}

// A list Render refuses with no other change: nothing is loaded (the previous list's render is what
// Caddy serves), and the error still says the config in force is the applied one.
func TestRenderRefusedAllowlistNoChangeLoadsNothing(t *testing.T) {
	ctx := context.Background()
	admin := &fakeCaddyAdmin{reject: func([]byte, int) bool { return false }}
	rec := allowlistReconciler(t, admin)
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	before, _ := admin.state()
	rec.SetAdminAllowlist([]string{"0.0.0.0/0"})
	err := rec.Reconcile(ctx)
	if !errors.As(err, new(*AllowlistDroppedError)) {
		t.Fatalf("Reconcile = %v", err)
	}
	if calls, _ := admin.state(); calls != before {
		t.Fatalf("%d loads for a render Caddy already serves", calls-before)
	}
	allowState(t, rec, "dropped", []string{"203.0.113.0/24"}, false)
}

// A list Render refuses, and the previous list's render then fails for its own reasons (Caddy refuses
// it, or isn't reachable): the list is given up all the same, and the error is the load's — NOT an
// AllowlistDroppedError, nothing was applied — joined with the list's.
func TestRenderRefusedAllowlistPreviousLoadFails(t *testing.T) {
	ctx := context.Background()
	for _, transport := range []bool{false, true} {
		fail := false
		admin := &fakeCaddyAdmin{}
		admin.reject = func([]byte, int) bool { return fail && !transport }
		admin.drop = func([]byte, int) bool { return fail && transport }
		rec := allowlistReconciler(t, admin)
		if err := rec.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		_, served := admin.state()
		if err := rec.store.Save(ctx, testAppRoute); err != nil {
			t.Fatal(err)
		}
		admin.mu.Lock()
		fail = true
		admin.mu.Unlock()
		rec.SetAdminAllowlist([]string{"0.0.0.0/0"})
		err := rec.Reconcile(ctx)
		if err == nil || ConfigApplied(err) || errors.As(err, new(*AllowlistDroppedError)) || errors.As(err, new(*AllowlistPendingError)) {
			t.Fatalf("transport=%v: Reconcile = %v (%T); nothing was applied", transport, err, err)
		}
		if got := errors.As(err, new(*ConfigRejectedError)); got == transport {
			t.Errorf("transport=%v: ConfigRejectedError=%v in %v", transport, got, err)
		}
		if !strings.Contains(err.Error(), "admits every address") {
			t.Errorf("transport=%v: the error doesn't carry the list's: %v", transport, err)
		}
		if _, body := admin.state(); string(body) != string(served) {
			t.Errorf("transport=%v: Caddy's config changed", transport)
		}
		allowState(t, rec, "dropped, load failed", []string{"203.0.113.0/24"}, false)
		if refused, _, render := rec.LoadRefused(); refused == transport {
			t.Errorf("transport=%v: LoadRefused = %v", transport, refused)
		} else if refused && (strings.Contains(string(render), "0.0.0.0/0") || !strings.Contains(string(render), "app.example.com")) {
			t.Errorf("the refused render must be the previous list's:\n%s", render)
		}
		admin.mu.Lock()
		fail = false
		admin.mu.Unlock()
		if err := rec.Reconcile(ctx); err != nil {
			t.Fatalf("transport=%v: the next reconcile: %v", transport, err)
		}
		_, body := admin.state()
		if !strings.Contains(string(body), "app.example.com") || !reflect.DeepEqual(adminRanges(t, body), []string{"203.0.113.0/24"}) {
			t.Errorf("transport=%v: after Caddy is back:\n%s", transport, body)
		}
	}
}

// Which error a reconcile with a pending list returns, and AdminAllowlistState after it, per outcome.
func TestAllowlistOutcomeErrorsAndState(t *testing.T) {
	ctx := context.Background()
	prev := []string{"203.0.113.0/24"}
	const bad = "198.51.100.99/32"
	hasBad := func(b []byte) bool { return strings.Contains(string(b), bad) }

	t.Run("applied", func(t *testing.T) {
		admin := &fakeCaddyAdmin{reject: func([]byte, int) bool { return false }}
		rec := allowlistReconciler(t, admin)
		allowState(t, rec, "before any reconcile", prev, false)
		if err := rec.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		want := []string{"198.51.100.7/32"}
		rec.SetAdminAllowlist(want)
		allowState(t, rec, "set", prev, true)
		if err := rec.Reconcile(ctx); err != nil || !ConfigApplied(err) {
			t.Fatal(err)
		}
		allowState(t, rec, "applied", want, false)
		force, _ := rec.AdminAllowlistState()
		force[0] = "0.0.0.0/0" // a copy
		allowState(t, rec, "after the caller changed its copy", want, false)
	})

	t.Run("pending: the admin API is unreachable", func(t *testing.T) {
		down := false
		admin := &fakeCaddyAdmin{reject: func([]byte, int) bool { return false }}
		admin.drop = func([]byte, int) bool { return down }
		rec := allowlistReconciler(t, admin)
		if err := rec.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		admin.mu.Lock()
		down = true
		admin.mu.Unlock()
		want := []string{"198.51.100.7/32"}
		rec.SetAdminAllowlist(want)
		err := rec.Reconcile(ctx)
		if err == nil || ConfigApplied(err) || errors.As(err, new(*ConfigRejectedError)) {
			t.Fatalf("Reconcile = %v (%T), want a plain transport error", err, err)
		}
		allowState(t, rec, "transport error", prev, true)
		admin.mu.Lock()
		down = false
		admin.mu.Unlock()
		if err := rec.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		allowState(t, rec, "applied later", want, false)
	})

	t.Run("pending: Caddy refuses both renders", func(t *testing.T) {
		settling := false
		admin := &fakeCaddyAdmin{reject: func([]byte, int) bool { return settling }}
		rec := allowlistReconciler(t, admin)
		if err := rec.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		admin.mu.Lock()
		settling = true
		admin.mu.Unlock()
		rec.SetAdminAllowlist([]string{"198.51.100.7/32"})
		err := rec.Reconcile(ctx)
		if !errors.As(err, new(*ConfigRejectedError)) || ConfigApplied(err) || errors.As(err, new(*AllowlistDroppedError)) {
			t.Fatalf("Reconcile = %v (%T), want a bare ConfigRejectedError", err, err)
		}
		allowState(t, rec, "both refused", prev, true)
	})

	t.Run("dropped: Caddy accepts the previous list and refuses the new one", func(t *testing.T) {
		admin := &fakeCaddyAdmin{reject: func(b []byte, _ int) bool { return hasBad(b) }}
		rec := allowlistReconciler(t, admin)
		if err := rec.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		if err := rec.store.Save(ctx, testAppRoute); err != nil {
			t.Fatal(err)
		}
		rec.SetAdminAllowlist([]string{bad})
		err := rec.Reconcile(ctx)
		var dropped *AllowlistDroppedError
		var rej *ConfigRejectedError
		if !errors.As(err, &dropped) || !ConfigApplied(err) {
			t.Fatalf("Reconcile = %v (%T), want an AllowlistDroppedError", err, err)
		}
		if !errors.As(err, &rej) || !errors.As(dropped.Err, new(*ConfigRejectedError)) {
			t.Errorf("the dropped error must carry Caddy's rejection: %v", err)
		}
		if _, body := admin.state(); !strings.Contains(string(body), "app.example.com") {
			t.Errorf("the route was not applied")
		}
		allowState(t, rec, "dropped by Caddy", prev, false)
	})

	t.Run("pending: the previous list loads, the second try doesn't reach Caddy", func(t *testing.T) {
		start := 1 << 30
		admin := &fakeCaddyAdmin{}
		admin.reject = func(b []byte, n int) bool { return n == start+1 }
		admin.drop = func(b []byte, n int) bool { return n == start+3 }
		rec := allowlistReconciler(t, admin)
		if err := rec.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		if err := rec.store.Save(ctx, testAppRoute); err != nil {
			t.Fatal(err)
		}
		calls, _ := admin.state()
		admin.mu.Lock()
		start = calls
		admin.mu.Unlock()
		want := []string{"198.51.100.7/32"}
		rec.SetAdminAllowlist(want)
		err := rec.Reconcile(ctx)
		var pend *AllowlistPendingError
		if !errors.As(err, &pend) || !ConfigApplied(err) || errors.As(err, new(*AllowlistDroppedError)) || errors.As(err, new(*ConfigRejectedError)) {
			t.Fatalf("Reconcile = %v (%T), want an AllowlistPendingError", err, err)
		}
		_, body := admin.state()
		if !strings.Contains(string(body), "app.example.com") || !reflect.DeepEqual(adminRanges(t, body), prev) {
			t.Errorf("the route must be live with the previous list:\n%s", body)
		}
		allowState(t, rec, "unpinned", prev, true)
		if err := rec.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		allowState(t, rec, "applied by the next reconcile", want, false)
	})

	t.Run("consumed by a concurrent reconcile", func(t *testing.T) {
		admin := &fakeCaddyAdmin{reject: func([]byte, int) bool { return false }}
		rec := allowlistReconciler(t, admin)
		if err := rec.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		want := []string{"198.51.100.7/32"}
		rec.SetAdminAllowlist(want)
		if err := rec.Reconcile(ctx); err != nil { // the scaler's, ahead of the reload's
			t.Fatal(err)
		}
		before, _ := admin.state()
		if err := rec.Reconcile(ctx); err != nil { // the reload's own
			t.Fatal(err)
		}
		if calls, _ := admin.state(); calls != before {
			t.Error("the reload's reconcile loaded again")
		}
		allowState(t, rec, "applied by the other reconcile", want, false)

		// The other reconcile gave it up: the reload's own returns nil, the state tells.
		rec.SetAdminAllowlist([]string{"0.0.0.0/0"})
		if err := rec.Reconcile(ctx); !errors.As(err, new(*AllowlistDroppedError)) {
			t.Fatalf("Reconcile = %v", err)
		}
		if err := rec.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		allowState(t, rec, "given up by the other reconcile", want, false)
	})

	t.Run("a real rejection without a pending list", func(t *testing.T) {
		refuse := false
		admin := &fakeCaddyAdmin{reject: func([]byte, int) bool { return refuse }}
		rec := allowlistReconciler(t, admin)
		if err := rec.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		if err := rec.store.Save(ctx, testAppRoute); err != nil {
			t.Fatal(err)
		}
		admin.mu.Lock()
		refuse = true
		admin.mu.Unlock()
		err := rec.Reconcile(ctx)
		if !errors.As(err, new(*ConfigRejectedError)) || ConfigApplied(err) {
			t.Fatalf("Reconcile = %v", err)
		}
	})
}

func TestConfigApplied(t *testing.T) {
	rej := &ConfigRejectedError{Status: 400, Body: "x"}
	for _, c := range []struct {
		err  error
		want bool
	}{
		{nil, true},
		{&AllowlistDroppedError{Err: rej}, true},
		{&AllowlistPendingError{Err: errors.New("x")}, true},
		{rej, false},
		{errors.New("x"), false},
		{errors.Join(rej, &AllowlistDroppedError{Err: errors.New("list")}), true},
	} {
		if got := ConfigApplied(c.err); got != c.want {
			t.Errorf("ConfigApplied(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

// The /load count of one reconcile with a pending list and refused wildcards: the wildcard isolation
// runs once (for the previous list's render) and its result is reused for the second try of the new
// list — 3 loads (new, previous, new again) plus the isolation's own.
func TestPendingAllowlistWithRefusedWildcardsLoadCount(t *testing.T) {
	ctx := context.Background()
	blog := WildcardCert{Domain: "blog.example.com", DNS01Provider: "cloudflare", DNS01Token: "tok-blog-0123456789"}
	api := WildcardCert{Domain: "api.example.com", DNS01Provider: "cloudflare", DNS01Token: "tok-api-0123456789"}
	const newList = "198.51.100.99/32"
	prev := []string{"203.0.113.0/24"}
	for _, c := range []struct {
		name      string
		badWild   []string // token prefixes Caddy refuses
		listBad   bool     // Caddy refuses the new list
		wantLoads int
		wantWild  []string // token prefixes in the served config
	}{
		// new, bare(new) [transient], previous, then bare + full + shop + blog + api×2, new again
		{"one wildcard refused, list fine", []string{"tok-api"}, false, 10, []string{"tok-shop", "tok-blog"}},
		// … every wildcard tried twice (2W = 6)
		{"every wildcard refused, list fine", []string{"tok-shop", "tok-blog", "tok-api"}, false, 12, nil},
		{"one wildcard refused, list refused", []string{"tok-api"}, true, 10, []string{"tok-shop", "tok-blog"}},
		{"every wildcard refused, list refused", []string{"tok-shop", "tok-blog", "tok-api"}, true, 12, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			start := 1 << 30
			admin := &fakeCaddyAdmin{}
			admin.reject = func(body []byte, n int) bool {
				if n <= start {
					return false
				}
				s := string(body)
				if !c.listBad && n <= start+2 {
					return true // a transient refusal of the first render and of its bare form
				}
				if c.listBad && strings.Contains(s, newList) {
					return true
				}
				for _, tok := range c.badWild {
					if strings.Contains(s, tok) {
						return true
					}
				}
				return false
			}
			rec, reports := wildcardReconciler(t, admin)
			rec.base.AdminHostname, rec.base.AdminUpstream = "admin.example.com", "127.0.0.1:9001"
			rec.base.AdminAllowlist = prev
			if err := rec.Reconcile(ctx); err != nil {
				t.Fatal(err)
			}
			rec.SetWildcards(func() []WildcardCert { return []WildcardCert{shopWildcard, blog, api} })
			calls, _ := admin.state()
			admin.mu.Lock()
			start = calls
			admin.mu.Unlock()
			rec.SetAdminAllowlist([]string{newList})
			err := rec.Reconcile(ctx)
			after, body := admin.state()
			if after-calls != c.wantLoads {
				t.Errorf("%d loads, want %d", after-calls, c.wantLoads)
			}
			if max := 3 + 1 + 3 + 2*3; after-calls > max {
				t.Errorf("%d loads, over the bound 3 + the isolation's own (%d)", after-calls, max)
			}
			wantList := []string{newList}
			if c.listBad {
				wantList = prev
				if !errors.As(err, new(*AllowlistDroppedError)) {
					t.Errorf("Reconcile = %v, want an AllowlistDroppedError", err)
				}
			} else if err != nil {
				t.Errorf("Reconcile = %v", err)
			}
			if got := adminRanges(t, body); !reflect.DeepEqual(got, wantList) {
				t.Errorf("served list %v, want %v", got, wantList)
			}
			allowState(t, rec, "after", wantList, false)
			for _, tok := range []string{"tok-shop", "tok-blog", "tok-api"} {
				want := false
				for _, w := range c.wantWild {
					want = want || w == tok
				}
				if got := strings.Contains(string(body), tok); got != want {
					t.Errorf("wildcard %s served=%v, want %v", tok, got, want)
				}
			}
			if len(*reports) != len(c.badWild) {
				t.Errorf("%d wildcard refusals reported, want %d: %v", len(*reports), len(c.badWild), *reports)
			}
			if !strings.Contains(string(body), "app.example.com") {
				t.Errorf("the route is not served")
			}
		})
	}
}
