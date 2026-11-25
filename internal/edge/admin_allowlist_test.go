package edge

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/crypto"
	"github.com/daboss2003/mooring/internal/store"
)

// adminRanges is the dashboard route's remote_ip ranges in a rendered document.
func adminRanges(t *testing.T, out []byte) []string {
	t.Helper()
	for _, r := range blockRoutes(t, out) {
		if len(r.Match) == 1 && len(r.Match[0].Host) == 1 && r.Match[0].Host[0] == "admin.example.com" {
			if r.Match[0].RemoteIP == nil {
				t.Fatalf("the dashboard route has no remote_ip matcher:\n%s", out)
			}
			return r.Match[0].RemoteIP.Ranges
		}
	}
	t.Fatalf("no dashboard route:\n%s", out)
	return nil
}

// The awkward ip_allowlist forms config.yaml accepts.
var awkwardAllowlist = []string{
	"198.51.100.7",     // bare IPv4
	"2001:db8::1",      // bare IPv6
	"203.0.113.77/24",  // host bits set
	"::ffff:192.0.2.9", // IPv4-mapped
	" 192.0.2.200 ",    // space-padded
}

// Abuse: every form config.yaml accepts in ip_allowlist reaches Caddy as a range its remote_ip
// matcher parses (a strict prefix, no spaces, never IPv4-mapped), and the ranges admit exactly the
// addresses the dashboard's own check (config.Allowlist) admits.
func TestRenderAdminAllowlistMatchesDashboard(t *testing.T) {
	hash, err := crypto.HashPassword([]byte("a-strong-password"), crypto.DefaultArgon2Params)
	if err != nil {
		t.Fatal(err)
	}
	y := "encryption_key: \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\nip_allowlist:\n"
	for _, e := range awkwardAllowlist {
		y += "  - \"" + e + "\"\n"
	}
	y += "auth:\n  username: operator\n  password_hash: \"" + hash + "\"\n" +
		"edge:\n  acme_email: ops@example.com\n  acme_ca: https://acme.example/directory\n" +
		"admin:\n  hostname: admin.example.com\n"
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"198.51.100.7/32", "2001:db8::1/128", "203.0.113.0/24", "192.0.2.9/32", "192.0.2.200/32"}
	if got := cfg.AllowlistStrings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("AllowlistStrings = %v, want %v", got, want)
	}
	base := adminBase()
	for name, list := range map[string][]string{"canonical": cfg.AllowlistStrings(), "as written": cfg.IPAllowlist} {
		base.AdminAllowlist = list
		out, err := Render(base, nil, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		ranges := adminRanges(t, out)
		if !reflect.DeepEqual(ranges, want) {
			t.Errorf("%s: ranges = %v, want %v", name, ranges, want)
		}
		var edgeSide []netip.Prefix
		for _, r := range ranges {
			p, err := netip.ParsePrefix(r) // Caddy's own parse of a range with a '/'
			if err != nil || p != p.Masked() || p.Addr().Is4In6() || r != strings.TrimSpace(r) {
				t.Errorf("%s: range %q is not a canonical prefix (%v)", name, r, err)
				continue
			}
			edgeSide = append(edgeSide, p)
		}
		for _, a := range []string{
			"198.51.100.7", "198.51.100.8", "2001:db8::1", "2001:db8::2", "203.0.113.1", "203.0.113.255",
			"203.0.114.1", "192.0.2.9", "192.0.2.10", "192.0.2.200", "192.0.2.201", "10.0.0.1", "::1",
		} {
			addr := netip.MustParseAddr(a)
			in := func(ps []netip.Prefix) bool {
				for _, p := range ps {
					if p.Contains(addr) {
						return true
					}
				}
				return false
			}
			if e, d := in(edgeSide), in(cfg.Allowlist()); e != d {
				t.Errorf("%s: %s: the edge admits=%v, the dashboard admits=%v", name, a, e, d)
			}
		}
	}
}

// An entry that is no address fails the whole render; nothing of it reaches Caddy.
func TestRenderAdminAllowlistRefusesUnparseable(t *testing.T) {
	for _, bad := range []string{"not-an-address", "", "203.0.113.0/33", "::ffff:192.0.2.0/64", "203.0.113.7, 0.0.0.0/0"} {
		base := adminBase()
		base.AdminAllowlist = []string{"203.0.113.0/24", bad}
		if out, err := Render(base, nil, nil); err == nil {
			t.Errorf("entry %q rendered:\n%s", bad, out)
		}
	}
}

func allowlistReconciler(t *testing.T, admin *fakeCaddyAdmin) *Reconciler {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	base := adminBase()
	base.AdminAllowlist = []string{"203.0.113.0/24"}
	return NewReconciler(NewRouteStore(db), NewAdmin(admin.server(t).Listener.Addr().String()), base, quietLog())
}

func (f *fakeCaddyAdmin) state() (calls int, accepted []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.accepted
}

// A list set on a reload is rendered by the next reconcile and becomes the Reconciler's own.
func TestSetAdminAllowlistAppliesOnNextReconcile(t *testing.T) {
	ctx := context.Background()
	admin := &fakeCaddyAdmin{reject: func([]byte, int) bool { return false }}
	rec := allowlistReconciler(t, admin)
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	_, body := admin.state()
	if got := adminRanges(t, body); !reflect.DeepEqual(got, []string{"203.0.113.0/24"}) {
		t.Fatalf("start: %v", got)
	}
	list := []string{"198.51.100.7/32", "2001:db8::/32"}
	rec.SetAdminAllowlist(list)
	list[0] = "0.0.0.0/0" // the caller's slice is not kept
	if _, body = admin.state(); !reflect.DeepEqual(adminRanges(t, body), []string{"203.0.113.0/24"}) {
		t.Fatal("SetAdminAllowlist must not load anything by itself")
	}
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{"198.51.100.7/32", "2001:db8::/32"}
	if _, body = admin.state(); !reflect.DeepEqual(adminRanges(t, body), want) {
		t.Fatalf("after the reload: %v, want %v", adminRanges(t, body), want)
	}
	if !reflect.DeepEqual(rec.base.AdminAllowlist, want) || rec.pendingAdminAllowlist() != nil {
		t.Errorf("accepted list not committed: base=%v pending=%v", rec.base.AdminAllowlist, rec.pendingAdminAllowlist())
	}
	// A Caddy restart is fed the new list, not the one from the start.
	rec.ReloadAfterRestart(ctx)
	if _, body = admin.state(); !reflect.DeepEqual(adminRanges(t, body), want) {
		t.Errorf("after a restart: %v", adminRanges(t, body))
	}
}

// A new list Caddy refuses: the reconcile returns Caddy's error, the previous list stays in force
// and later reconciles (routes, pools) work with it.
func TestSetAdminAllowlistRefusedByCaddyKeepsPrevious(t *testing.T) {
	ctx := context.Background()
	admin := &fakeCaddyAdmin{reject: func(body []byte, _ int) bool { return strings.Contains(string(body), "198.51.100.99/32") }}
	rec := allowlistReconciler(t, admin)
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	rec.SetAdminAllowlist([]string{"198.51.100.99/32"})
	err := rec.Reconcile(ctx)
	if !errors.As(err, new(*ConfigRejectedError)) {
		t.Fatalf("Reconcile = %v, want Caddy's rejection", err)
	}
	if _, body := admin.state(); !reflect.DeepEqual(adminRanges(t, body), []string{"203.0.113.0/24"}) {
		t.Fatalf("Caddy serves %v", adminRanges(t, body))
	}
	if !reflect.DeepEqual(rec.base.AdminAllowlist, []string{"203.0.113.0/24"}) {
		t.Errorf("the refused list became the base: %v", rec.base.AdminAllowlist)
	}
	if err := rec.store.Save(ctx, Route{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatalf("the reconcile after a refused list: %v", err)
	}
	_, body := admin.state()
	if !strings.Contains(string(body), "app.example.com") || !reflect.DeepEqual(adminRanges(t, body), []string{"203.0.113.0/24"}) {
		t.Errorf("the next reconcile must apply the new route with the previous list:\n%s", body)
	}
	if refused, _, _ := rec.LoadRefused(); refused {
		t.Error("the refusal must be over once the previous list renders again")
	}
}

// A list Render refuses (no entry, or one that is no address) never reaches Caddy and is given up;
// with an unrelated render error the list stays pending and applies once that is fixed.
func TestSetAdminAllowlistRefusedByRender(t *testing.T) {
	ctx := context.Background()
	admin := &fakeCaddyAdmin{reject: func([]byte, int) bool { return false }}
	rec := allowlistReconciler(t, admin)
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{nil, {}, {"203.0.113.0/24", "nope"}} {
		before, _ := admin.state()
		rec.SetAdminAllowlist(bad)
		if err := rec.Reconcile(ctx); err == nil {
			t.Fatalf("list %q: Reconcile = nil", bad)
		}
		if calls, _ := admin.state(); calls != before {
			t.Fatalf("list %q reached Caddy", bad)
		}
		if err := rec.Reconcile(ctx); err != nil {
			t.Fatalf("list %q: the next reconcile: %v", bad, err)
		}
		if !reflect.DeepEqual(rec.base.AdminAllowlist, []string{"203.0.113.0/24"}) {
			t.Fatalf("list %q: base = %v", bad, rec.base.AdminAllowlist)
		}
	}

	if _, err := rec.store.db.Exec(`INSERT INTO app_routes(hostname, upstream, upstream_scheme, enabled, created_at) VALUES('x.example.com','127.0.0.1:2019','http',1,0)`); err != nil {
		t.Fatal(err)
	}
	rec.SetAdminAllowlist([]string{"198.51.100.7/32"})
	if err := rec.Reconcile(ctx); err == nil {
		t.Fatal("an unsafe route must fail the reconcile")
	}
	if rec.pendingAdminAllowlist() == nil {
		t.Fatal("a render error that isn't the list's must leave the list pending")
	}
	if _, err := rec.store.db.Exec(`DELETE FROM app_routes WHERE hostname='x.example.com'`); err != nil {
		t.Fatal(err)
	}
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, body := admin.state(); !reflect.DeepEqual(adminRanges(t, body), []string{"198.51.100.7/32"}) {
		t.Errorf("the pending list was not applied: %v", adminRanges(t, body))
	}
}

// SetAdminAllowlist is safe from another goroutine than the reconcile's (run with -race), and the
// last list set is the one that ends up served.
func TestSetAdminAllowlistConcurrent(t *testing.T) {
	ctx := context.Background()
	admin := &fakeCaddyAdmin{reject: func([]byte, int) bool { return false }}
	rec := allowlistReconciler(t, admin)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				rec.SetAdminAllowlist([]string{"198.51.100.0/24", "192.0.2.0/24"})
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = rec.Reconcile(ctx)
			}
		}()
	}
	wg.Wait()
	rec.SetAdminAllowlist([]string{"192.0.2.77/32"})
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, body := admin.state(); !reflect.DeepEqual(adminRanges(t, body), []string{"192.0.2.77/32"}) {
		t.Errorf("served: %v", adminRanges(t, body))
	}
}

// Every spelling of "every address" (an entry whose canonical prefix is /0).
var catchAllSpellings = []string{
	"0.0.0.0/0", "::/0", " 0.0.0.0/0 ", "10.1.2.3/0", "2001:db8::1/0", "0:0:0:0:0:0:0:0/0",
	"::ffff:0.0.0.0/96", "::ffff:0:0/96", "::ffff:203.0.113.7/96", "0::/0",
}

// Abuse: with a dashboard hostname, Render refuses an allowlist entry that admits every address,
// however it is spelled and wherever it is in the list; nothing is rendered.
func TestRenderRefusesCatchAllAdminAllowlist(t *testing.T) {
	for _, bad := range catchAllSpellings {
		for _, list := range [][]string{{bad}, {"203.0.113.0/24", bad}, {bad, "2001:db8::/32"}} {
			base := adminBase()
			base.AdminAllowlist = list
			out, err := Render(base, nil, nil)
			if err == nil {
				t.Errorf("list %q rendered:\n%s", list, out)
				continue
			}
			if out != nil || !strings.Contains(err.Error(), "admits every address") {
				t.Errorf("list %q: out=%q err=%v", list, out, err)
			}
			// The boot floor is the same gate.
			if out, err := Render(BootFloor(base), nil, nil); err == nil {
				t.Errorf("list %q rendered as the boot floor:\n%s", list, out)
			}
		}
	}
	// Without a dashboard hostname there is no dashboard route: the list is not rendered at all.
	base := baseCfg()
	base.AdminAllowlist = []string{"0.0.0.0/0", "::/0"}
	out, err := Render(base, nil, nil)
	if err != nil {
		t.Fatalf("tunnel-only access with a catch-all list must render: %v", err)
	}
	if strings.Contains(string(out), "0.0.0.0/0") || strings.Contains(string(out), `"::/0"`) || strings.Contains(string(out), "admin.example.com") {
		t.Errorf("no dashboard hostname, but the list or a dashboard route was rendered:\n%s", out)
	}
}

// The renderer's width rule is config validation's, no stricter and no looser: with admin exposure,
// whatever config.Parse accepts in ip_allowlist renders, and whatever it refuses for being a
// catch-all doesn't.
func TestRenderAdminAllowlistWidthMatchesConfig(t *testing.T) {
	hash, err := crypto.HashPassword([]byte("a-strong-password"), crypto.DefaultArgon2Params)
	if err != nil {
		t.Fatal(err)
	}
	entries := append([]string{
		"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1", "10.0.0.0/8", "2000::/3", "::ffff:0.0.0.0/97",
		"203.0.113.7", "::1",
	}, catchAllSpellings...)
	accepted, refused := 0, 0
	for _, e := range entries {
		y := "encryption_key: \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\nip_allowlist:\n  - \"" + e + "\"\n" +
			"auth:\n  username: operator\n  password_hash: \"" + hash + "\"\n" +
			"edge:\n  acme_email: ops@example.com\n  acme_ca: https://acme.example/directory\n" +
			"admin:\n  hostname: admin.example.com\n"
		cfg, cerr := config.Parse([]byte(y))
		base := adminBase()
		base.AdminAllowlist = []string{e}
		_, rerr := Render(base, nil, nil)
		if (cerr == nil) != (rerr == nil) {
			t.Errorf("entry %q: config.Parse err=%v, Render err=%v", e, cerr, rerr)
		}
		if cerr == nil {
			accepted++
			base.AdminAllowlist = cfg.AllowlistStrings()
			if _, err := Render(base, nil, nil); err != nil {
				t.Errorf("entry %q: the start-up config doesn't render: %v", e, err)
			}
		} else {
			refused++
		}
	}
	if accepted != 9 || refused != len(catchAllSpellings) {
		t.Errorf("config accepted %d and refused %d entries; want 9 and %d", accepted, refused, len(catchAllSpellings))
	}
}

// Abuse (the reload gap): the operator removes the admin block, sets a catch-all ip_allowlist — valid
// for that file — and reloads. The running edge still serves the dashboard hostname, so the list must
// never reach its route: the reconcile fails, nothing is sent to Caddy, the previous list stays in
// force through later reconciles, a Caddy restart and a revert, and a normal list still applies.
func TestReloadCatchAllAllowlistNeverOpensDashboard(t *testing.T) {
	ctx := context.Background()
	admin := &fakeCaddyAdmin{reject: func([]byte, int) bool { return false }}
	rec := allowlistReconciler(t, admin)
	var told [][]string
	rec.SetAdminAllowlistAccepted(func(l []string) { told = append(told, l) })
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	prev := []string{"203.0.113.0/24"}
	noCatchAll := func(when string) {
		t.Helper()
		admin.mu.Lock()
		defer admin.mu.Unlock()
		for i, b := range admin.bodies {
			for _, r := range adminRanges(t, b) {
				if p, err := netip.ParsePrefix(r); err != nil || p.Bits() == 0 {
					t.Fatalf("%s: /load %d carried the dashboard range %q", when, i+1, r)
				}
			}
		}
	}
	lists := [][]string{{"0.0.0.0/0", "::/0"}}
	for _, s := range catchAllSpellings {
		lists = append(lists, []string{s}, []string{"198.51.100.7/32", s})
	}
	for _, list := range lists {
		before, _ := admin.state()
		rec.SetAdminAllowlist(list)
		err := rec.Reconcile(ctx)
		if err == nil || !strings.Contains(err.Error(), "admits every address") {
			t.Fatalf("list %q: Reconcile = %v, want the catch-all refusal", list, err)
		}
		if calls, _ := admin.state(); calls != before {
			t.Fatalf("list %q: something was sent to Caddy", list)
		}
		if rec.pendingAdminAllowlist() != nil {
			t.Fatalf("list %q stayed pending", list)
		}
		if !reflect.DeepEqual(rec.base.AdminAllowlist, prev) {
			t.Fatalf("list %q became the base: %v", list, rec.base.AdminAllowlist)
		}
		if err := rec.Reconcile(ctx); err != nil {
			t.Fatalf("list %q: the next reconcile: %v", list, err)
		}
	}
	if err := rec.store.Save(ctx, Route{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rec.SetAdminAllowlist([]string{"0.0.0.0/0", "::/0"})
	if err := rec.Reconcile(ctx); err == nil {
		t.Fatal("a catch-all list with a route change must fail the reconcile")
	}
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	_, body := admin.state()
	if !strings.Contains(string(body), "app.example.com") || !reflect.DeepEqual(adminRanges(t, body), prev) {
		t.Fatalf("the route must apply with the previous list:\n%s", body)
	}
	rec.ReloadAfterRestart(ctx)
	if _, body = admin.state(); !reflect.DeepEqual(adminRanges(t, body), prev) {
		t.Errorf("after a Caddy restart: %v", adminRanges(t, body))
	}
	if err := rec.RevertToLastGood(ctx); err != nil {
		t.Fatal(err)
	}
	if _, body = admin.state(); !reflect.DeepEqual(adminRanges(t, body), prev) {
		t.Errorf("after a revert: %v", adminRanges(t, body))
	}
	noCatchAll("refused lists")
	if len(told) != 0 {
		t.Errorf("a refused list was reported as accepted: %v", told)
	}
	rec.SetAdminAllowlist([]string{"198.51.100.0/24"})
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, body = admin.state(); !reflect.DeepEqual(adminRanges(t, body), []string{"198.51.100.0/24"}) {
		t.Errorf("a normal list after the refusals: %v", adminRanges(t, body))
	}
	noCatchAll("end")
}

// The list in force — the one set by a reload, not the start-up one — is what every recovery path
// carries: a Caddy restart, a revert (with and without a last-good config), and the render without
// wildcards.
func TestAcceptedAllowlistCarriedByRecoveryPaths(t *testing.T) {
	ctx := context.Background()
	admin := &fakeCaddyAdmin{reject: func(body []byte, _ int) bool { return strings.Contains(string(body), `"challenges"`) }}
	rec := allowlistReconciler(t, admin)
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{"198.51.100.7/32"}
	rec.SetAdminAllowlist(want)
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	served := func(when string) {
		t.Helper()
		if _, body := admin.state(); !reflect.DeepEqual(adminRanges(t, body), want) {
			t.Errorf("%s: %v, want %v", when, adminRanges(t, body), want)
		}
	}
	served("reload")
	if err := rec.RevertToLastGood(ctx); err != nil {
		t.Fatal(err)
	}
	served("revert to last-good")
	rec.mu.Lock()
	rec.lastGood = nil
	rec.mu.Unlock()
	if err := rec.RevertToLastGood(ctx); err != nil {
		t.Fatal(err)
	}
	served("revert to the base floor")
	rec.ReloadAfterRestart(ctx)
	served("Caddy restart")
	// A wildcard Caddy refuses: the render without wildcards carries the list too.
	rec.SetWildcards(func() []WildcardCert { return []WildcardCert{shopWildcard} })
	before, _ := admin.state()
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if calls, _ := admin.state(); calls == before {
		t.Fatal("the wildcard render was not tried")
	}
	_, body := admin.state()
	if strings.Contains(string(body), `"challenges"`) {
		t.Fatal("the applied config must be the one without wildcards")
	}
	served("render without wildcards")
	// A new list arriving together with the refused wildcard is applied by that fallback as well.
	want = []string{"192.0.2.0/24"}
	rec.SetAdminAllowlist(want)
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	served("new list with a refused wildcard")
}

// SetAdminAllowlist(nil) (or an empty list) with a dashboard hostname fails closed: nothing reaches
// Caddy, the route keeps the previous list, and the hook is not told.
func TestSetAdminAllowlistEmptyFailsClosed(t *testing.T) {
	ctx := context.Background()
	admin := &fakeCaddyAdmin{reject: func([]byte, int) bool { return false }}
	rec := allowlistReconciler(t, admin)
	told := 0
	rec.SetAdminAllowlistAccepted(func([]string) { told++ })
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	for _, empty := range [][]string{nil, {}} {
		before, _ := admin.state()
		rec.SetAdminAllowlist(empty)
		if err := rec.Reconcile(ctx); err == nil || !strings.Contains(err.Error(), "non-empty IP allowlist") {
			t.Fatalf("Reconcile = %v", err)
		}
		calls, body := admin.state()
		if calls != before || !reflect.DeepEqual(adminRanges(t, body), []string{"203.0.113.0/24"}) {
			t.Fatalf("an empty list changed what Caddy serves (calls %d → %d)", before, calls)
		}
	}
	if told != 0 {
		t.Errorf("the hook was told %d times", told)
	}
}

// The accepted hook: once per accepted change, with a copy, outside the reconcile lock; never for a
// refused, pending or unchanged list; also when a later reconcile applies the pending list.
func TestAdminAllowlistAcceptedHook(t *testing.T) {
	ctx := context.Background()
	down := false
	admin := &fakeCaddyAdmin{reject: func(body []byte, _ int) bool {
		return down || strings.Contains(string(body), "198.51.100.99/32")
	}}
	rec := allowlistReconciler(t, admin)
	var told [][]string
	rec.SetAdminAllowlistAccepted(func(l []string) {
		// Would deadlock (and time the test out) if the reconcile lock were held.
		done := make(chan struct{})
		go func() { rec.LoadRefused(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the hook was called with the reconcile lock held")
		}
		told = append(told, l)
	})
	expect := func(when string, want ...[]string) {
		t.Helper()
		if len(told) != len(want) {
			t.Fatalf("%s: told %v, want %v", when, told, want)
		}
		for i := range want {
			if !reflect.DeepEqual(told[i], want[i]) {
				t.Fatalf("%s: told %v, want %v", when, told, want)
			}
		}
	}
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	expect("first reconcile, no list set")

	a := []string{"198.51.100.7/32", "2001:db8::/32"}
	rec.SetAdminAllowlist(a)
	expect("set, not reconciled")
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	expect("accepted", a)
	told[0][0] = "0.0.0.0/0" // the hook's slice is its own
	if rec.base.AdminAllowlist[0] != "198.51.100.7/32" {
		t.Fatal("the hook was handed the Reconciler's own slice")
	}
	told[0][0] = a[0]
	for i := 0; i < 3; i++ {
		if err := rec.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
	}
	rec.ReloadAfterRestart(ctx)
	expect("periodic reconciles and a Caddy restart", a)

	rec.SetAdminAllowlist(a) // a reload that didn't change the list
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	expect("the same list again", a)

	rec.SetAdminAllowlist([]string{"198.51.100.99/32"}) // Caddy refuses it
	if err := rec.Reconcile(ctx); err == nil {
		t.Fatal("want Caddy's rejection")
	}
	rec.SetAdminAllowlist([]string{"0.0.0.0/0"}) // Render refuses it
	if err := rec.Reconcile(ctx); err == nil {
		t.Fatal("want the render refusal")
	}
	expect("refused lists", a)

	// Pending through a failed reconcile (Caddy refuses everything), applied by a later one.
	b := []string{"192.0.2.0/24"}
	admin.mu.Lock()
	down = true
	admin.mu.Unlock()
	rec.SetAdminAllowlist(b)
	if err := rec.Reconcile(ctx); err == nil {
		t.Fatal("want an error while Caddy refuses everything")
	}
	expect("pending", a)
	admin.mu.Lock()
	down = false
	admin.mu.Unlock()
	if err := rec.Reconcile(ctx); err != nil { // the periodic refresh
		t.Fatal(err)
	}
	expect("applied by a later reconcile", a, b)
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	expect("after it", a, b)
}

// Concurrent reloads and reconciles (run with -race): hook calls never overlap, and the last call
// carries the list in force.
func TestAdminAllowlistAcceptedHookConcurrent(t *testing.T) {
	ctx := context.Background()
	admin := &fakeCaddyAdmin{reject: func([]byte, int) bool { return false }}
	rec := allowlistReconciler(t, admin)
	var in atomic.Int32
	var last []string // written only inside the hook; calls must not overlap
	rec.SetAdminAllowlistAccepted(func(l []string) {
		if in.Add(1) != 1 {
			t.Error("overlapping hook calls")
		}
		last = l
		in.Add(-1)
	})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				rec.SetAdminAllowlist([]string{fmt.Sprintf("198.51.%d.%d/32", i, j)})
				_ = rec.Reconcile(ctx)
			}
		}(i)
	}
	wg.Wait()
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	rec.mu.Lock()
	force := append([]string{}, rec.base.AdminAllowlist...)
	rec.mu.Unlock()
	if !reflect.DeepEqual(last, force) {
		t.Errorf("the last hook call carried %v; in force: %v", last, force)
	}
	if _, body := admin.state(); !reflect.DeepEqual(adminRanges(t, body), force) {
		t.Errorf("served %v; in force %v", adminRanges(t, body), force)
	}
}

// Caddy refuses every /load (a just-restarted child's admin API answering 4xx): the rejection isn't
// about the new list, so the list stays pending and the next reconcile applies it.
func TestSetAdminAllowlistKeptWhenPreviousIsRefusedToo(t *testing.T) {
	ctx := context.Background()
	settling := false
	admin := &fakeCaddyAdmin{reject: func([]byte, int) bool { return settling }}
	rec := allowlistReconciler(t, admin)
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{"198.51.100.7/32"}
	admin.mu.Lock()
	settling = true
	admin.mu.Unlock()
	rec.SetAdminAllowlist(want)
	for i := 0; i < 2; i++ {
		before, _ := admin.state()
		err := rec.Reconcile(ctx)
		if !errors.As(err, new(*ConfigRejectedError)) {
			t.Fatalf("Reconcile = %v, want Caddy's rejection", err)
		}
		if calls, _ := admin.state(); calls != before+2 {
			t.Fatalf("want the new list's render and the previous list's tried (2 loads), got %d", calls-before)
		}
		if p := rec.pendingAdminAllowlist(); p == nil || !reflect.DeepEqual(*p, want) {
			t.Fatalf("the list was given up although Caddy refuses the previous one too: %v", p)
		}
		if !reflect.DeepEqual(rec.base.AdminAllowlist, []string{"203.0.113.0/24"}) {
			t.Fatalf("base = %v", rec.base.AdminAllowlist)
		}
	}
	admin.mu.Lock()
	settling = false
	admin.mu.Unlock()
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, body := admin.state(); !reflect.DeepEqual(adminRanges(t, body), want) {
		t.Errorf("the pending list was not applied once Caddy answered: %v", adminRanges(t, body))
	}
	if rec.pendingAdminAllowlist() != nil || !reflect.DeepEqual(rec.base.AdminAllowlist, want) {
		t.Errorf("not committed: base=%v", rec.base.AdminAllowlist)
	}
}

// One transient rejection (only the first /load after the reload is refused): the previous list's
// render loads, the new list's is tried again and accepted — the reload is not lost.
func TestSetAdminAllowlistSurvivesOneTransientRejection(t *testing.T) {
	ctx := context.Background()
	refuseCall := 0
	admin := &fakeCaddyAdmin{reject: func(_ []byte, n int) bool { return n == refuseCall }}
	rec := allowlistReconciler(t, admin)
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	calls, _ := admin.state()
	admin.mu.Lock()
	refuseCall = calls + 1
	admin.mu.Unlock()
	want := []string{"198.51.100.7/32"}
	rec.SetAdminAllowlist(want)
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatalf("a transient rejection must not fail the reload: %v", err)
	}
	if _, body := admin.state(); !reflect.DeepEqual(adminRanges(t, body), want) {
		t.Errorf("served %v, want %v", adminRanges(t, body), want)
	}
	if rec.pendingAdminAllowlist() != nil || !reflect.DeepEqual(rec.base.AdminAllowlist, want) {
		t.Errorf("not committed: base=%v", rec.base.AdminAllowlist)
	}
}

// A list only Caddy objects to (the previous list's render loads, the new one's is refused twice) is
// given up: the reconcile returns Caddy's error, and the route change that came with it is applied
// with the previous list in the same reconcile.
func TestSetAdminAllowlistDroppedWhenPreviousLoads(t *testing.T) {
	ctx := context.Background()
	admin := &fakeCaddyAdmin{reject: func(body []byte, _ int) bool { return strings.Contains(string(body), "198.51.100.99/32") }}
	rec := allowlistReconciler(t, admin)
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if err := rec.store.Save(ctx, Route{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	before, _ := admin.state()
	rec.SetAdminAllowlist([]string{"198.51.100.99/32"})
	err := rec.Reconcile(ctx)
	if !errors.As(err, new(*ConfigRejectedError)) {
		t.Fatalf("Reconcile = %v, want Caddy's rejection", err)
	}
	calls, body := admin.state()
	if calls != before+3 {
		t.Errorf("want 3 loads (new, previous, new again), got %d", calls-before)
	}
	if !strings.Contains(string(body), "app.example.com") || !reflect.DeepEqual(adminRanges(t, body), []string{"203.0.113.0/24"}) {
		t.Errorf("Caddy must serve the new route with the previous list:\n%s", body)
	}
	if rec.pendingAdminAllowlist() != nil {
		t.Error("a list Caddy refuses while the previous one loads must be given up")
	}
	if refused, _, _ := rec.LoadRefused(); refused {
		t.Error("Caddy accepted the render with the previous list: no refusal is outstanding")
	}
	before = calls
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatalf("the next reconcile: %v", err)
	}
	if calls, _ := admin.state(); calls != before {
		t.Error("the committed render is what Caddy serves: the next reconcile must not load again")
	}
}
