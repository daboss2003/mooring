package l4

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/store"
)

// A kernel route is served by Docker's port publish, so nginx renders nothing for it — not even when
// discovery found a pool. Proxy routes ("" or "proxy") still render.
func TestRenderSkipsKernelRoutes(t *testing.T) {
	out, err := Render([]Route{
		{AppID: "dns", Listen: 53, Protocol: "udp", Service: "coredns", Port: 5353, Forward: "kernel", Pool: []string{"172.18.0.5:5353"}},
		{AppID: "dns", Listen: 853, Protocol: "tcp", Service: "coredns", Port: 8853, Forward: "kernel", Pool: []string{"172.18.0.5:8853"}},
		{AppID: "mqtt", Listen: 8883, Protocol: "tcp", Service: "broker", Port: 8883, Forward: "proxy", Pool: []string{"172.19.0.2:8883"}},
		{AppID: "smtp", Listen: 2525, Protocol: "tcp", Service: "mail", Port: 25, Pool: []string{"172.20.0.2:25"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"listen 53", "l4_53_udp", "listen 853", "l4_853_tcp", "172.18.0.5"} {
		if strings.Contains(out, gone) {
			t.Errorf("a kernel route must render nothing, found %q:\n%s", gone, out)
		}
	}
	for _, want := range []string{"listen 8883;", "server 172.19.0.2:8883;", "listen 2525;", "server 172.20.0.2:25;"} {
		if !strings.Contains(out, want) {
			t.Errorf("proxy route missing %q:\n%s", want, out)
		}
	}
	// A kernel route still counts for the duplicate check (one listener, one owner).
	if _, err := Render([]Route{
		{Listen: 53, Protocol: "udp", Service: "a", Port: 53, Forward: "kernel"},
		{Listen: 53, Protocol: "udp", Service: "b", Port: 53, Pool: []string{"172.18.0.9:53"}},
	}); err == nil {
		t.Error("two routes on 53/udp must be refused even when one is kernel")
	}
}

func TestValidateRouteForward(t *testing.T) {
	base := Route{Listen: 53, Protocol: "udp", Service: "coredns", Port: 5353}
	for _, fwd := range []string{"", "proxy", "kernel"} {
		r := base
		r.Forward = fwd
		if err := ValidateRoute(r); err != nil {
			t.Errorf("forward %q must be valid: %v", fwd, err)
		}
	}
	for _, bad := range []string{"nat", "Kernel", "kernel\n"} {
		r := base
		r.Forward = bad
		if err := ValidateRoute(r); err == nil || !strings.Contains(err.Error(), "forward") {
			t.Errorf("forward %q must be refused, got %v", bad, err)
		}
	}
	r := base
	r.Forward, r.LB = "kernel", "least_conn"
	if err := ValidateRoute(r); err == nil || !strings.Contains(err.Error(), "lb") {
		t.Errorf("kernel + lb must be refused, got %v", err)
	}
	r.Forward = "proxy"
	if err := ValidateRoute(r); err != nil {
		t.Errorf("proxy + lb is valid: %v", err)
	}
}

func TestRouteStoreForwardRoundTrip(t *testing.T) {
	s := newRouteStore(t)
	ctx := context.Background()
	if err := s.ReplaceProject(ctx, "dns", []Route{
		{Listen: 53, Protocol: "udp", Service: "coredns", Port: 5353, Forward: "kernel"},
		{Listen: 853, Protocol: "tcp", Service: "coredns", Port: 8853, Forward: "proxy", LB: "least_conn"},
		{Listen: 5353, Protocol: "tcp", Service: "coredns", Port: 5353},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]string{53: "kernel", 853: "proxy", 5353: ""}
	if len(got) != len(want) {
		t.Fatalf("list = %+v", got)
	}
	for _, r := range got {
		if r.Forward != want[r.Listen] {
			t.Errorf("route %d forward = %q, want %q", r.Listen, r.Forward, want[r.Listen])
		}
	}
	if err := s.ReplaceProject(ctx, "dns", []Route{{Listen: 53, Protocol: "udp", Service: "coredns", Port: 5353, Forward: "kernel", LB: "least_conn"}}); err == nil {
		t.Error("the store must refuse kernel + lb")
	}
}

// A database written before forward existed upgrades in place: its routes keep every field and read
// forward "" (proxy).
func TestRouteStoreMigratesExistingRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	migrations, err := filepath.Glob(filepath.Join("..", "store", "migrations", "*.sql"))
	if err != nil || len(migrations) == 0 {
		t.Fatalf("migrations: %v %v", migrations, err)
	}
	sort.Strings(migrations)
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`CREATE TABLE schema_meta (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL DEFAULT (unixepoch()))`); err != nil {
		t.Fatal(err)
	}
	for i, m := range migrations {
		if strings.Contains(filepath.Base(m), "l4_routes_forward") {
			break // stop where this release's migration starts
		}
		b, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := old.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		if _, err := old.Exec(`INSERT INTO schema_meta(version, name) VALUES(?, ?)`, i+1, filepath.Base(m)); err != nil {
			t.Fatal(err)
		}
	}
	var hasForward int
	if err := old.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('app_l4_routes') WHERE name = 'forward'`).Scan(&hasForward); err != nil || hasForward != 0 {
		t.Fatalf("test setup: the old database must not have forward yet (n=%d, %v)", hasForward, err)
	}
	if _, err := old.Exec(`INSERT INTO app_l4_routes(app_id, listen, protocol, service, port, lb, created_at)
		VALUES('dns', 53, 'udp', 'coredns', 5353, 'hash_client_ip', 1)`); err != nil {
		t.Fatal(err)
	}
	old.Close()

	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer db.Close()
	got, err := NewRouteStore(db).List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("list after upgrade = %+v", got)
	}
	if r := got[0]; r.AppID != "dns" || r.Listen != 53 || r.Protocol != "udp" || r.Service != "coredns" || r.Port != 5353 || r.LB != "hash_client_ip" || r.Forward != "" {
		t.Errorf("old row after upgrade = %+v", r)
	}
	if out, err := Render(got); err != nil || strings.Contains(out, "listen 53") {
		t.Errorf("an old pool-less row renders nothing yet: %v\n%s", err, out)
	}
}

func TestCheckProject(t *testing.T) {
	s := newRouteStore(t)
	ctx := context.Background()
	if err := s.ReplaceProject(ctx, "dns", []Route{
		{Listen: 53, Protocol: "udp", Service: "coredns", Port: 5353, Forward: "kernel"},
		{Listen: 853, Protocol: "tcp", Service: "coredns", Port: 8853},
	}); err != nil {
		t.Fatal(err)
	}
	before, _ := s.List()

	// Another app claiming the same listener is refused, naming the owner.
	err := s.CheckProject(ctx, "other", []Route{{Listen: 53, Protocol: "udp", Service: "x", Port: 53}}, nil)
	if err == nil || !strings.Contains(err.Error(), "53/udp") || !strings.Contains(err.Error(), `"dns"`) {
		t.Errorf("a listener another app owns must be refused, got %v", err)
	}
	// The same app re-checking its own routes is fine (a redeploy).
	if err := s.CheckProject(ctx, "dns", before, []HostPort{{Port: 853}}); err != nil {
		t.Errorf("an app's own routes never conflict: %v", err)
	}
	// Another protocol on the same port is a different listener.
	if err := s.CheckProject(ctx, "other", []Route{{Listen: 53, Protocol: "tcp", Service: "x", Port: 53}}, []HostPort{{Port: 53, Protocol: "tcp"}, {Port: 853, Protocol: "udp"}}); err != nil {
		t.Errorf("53/tcp and 853/udp are free: %v", err)
	}
	// Abuse: an app's own published host port can't shadow another app's L4 listener ("" is tcp).
	for _, hp := range []HostPort{{Port: 853}, {Port: 853, Protocol: "tcp"}, {Port: 53, Protocol: "udp"}} {
		err := s.CheckProject(ctx, "other", nil, []HostPort{hp})
		if err == nil || !strings.Contains(err.Error(), `"dns"`) {
			t.Errorf("published %+v on another app's L4 listener must be refused, got %v", hp, err)
		}
	}
	// An invalid route is refused before the deploy goes on.
	if err := s.CheckProject(ctx, "other", []Route{{Listen: 9000, Protocol: "tcp", Service: "x", Port: 80}}, nil); err == nil {
		t.Error("an invalid route must be refused")
	}
	if err := s.CheckProject(ctx, "", nil, nil); err == nil {
		t.Error("an empty project must be refused")
	}
	// It never writes.
	if after, _ := s.List(); len(after) != len(before) {
		t.Errorf("CheckProject changed the store: before %+v after %+v", before, after)
	}
}
