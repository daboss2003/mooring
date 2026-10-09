package edge

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// renderedServer is the part of the rendered "edge" server the trusted-proxy tests inspect.
type renderedServer struct {
	TrustedProxies *struct {
		Source string   `json:"source"`
		Ranges []string `json:"ranges"`
	} `json:"trusted_proxies"`
	ClientIPHeaders      []string `json:"client_ip_headers"`
	TrustedProxiesStrict *int     `json:"trusted_proxies_strict"`
	Routes               []struct {
		Match  []map[string]json.RawMessage `json:"match"`
		Handle []json.RawMessage            `json:"handle"`
	} `json:"routes"`
}

func edgeServer(t *testing.T, out []byte) renderedServer {
	t.Helper()
	var doc struct {
		Apps struct {
			HTTP struct {
				Servers map[string]renderedServer `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	srv, ok := doc.Apps.HTTP.Servers["edge"]
	if !ok {
		t.Fatalf("no edge server in:\n%s", out)
	}
	return srv
}

// proxyRequestSets returns the request header "set" ops of every reverse_proxy handler in a route.
func proxyRequestSets(t *testing.T, handle []json.RawMessage) []map[string][]string {
	t.Helper()
	var sets []map[string][]string
	for _, raw := range handle {
		var h struct {
			Handler string `json:"handler"`
		}
		if err := json.Unmarshal(raw, &h); err != nil {
			t.Fatal(err)
		}
		if h.Handler != "reverse_proxy" {
			continue
		}
		var rp struct {
			Headers *struct {
				Request *struct {
					Set map[string][]string `json:"set"`
				} `json:"request"`
			} `json:"headers"`
		}
		if err := json.Unmarshal(raw, &rp); err != nil {
			t.Fatal(err)
		}
		if rp.Headers == nil || rp.Headers.Request == nil {
			sets = append(sets, nil)
			continue
		}
		sets = append(sets, rp.Headers.Request.Set)
	}
	return sets
}

func compact(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func pooledRoute(host string) Route {
	return Route{AppID: "shop", Hostname: host, Upstream: "web:8080", Pool: []string{"172.18.0.5:8080", "172.18.0.6:8080"}, UpstreamScheme: "http", Enabled: true}
}

// With trusted proxies the edge server trusts exactly the configured ranges, reads the client
// address from X-Forwarded-For by default, and parses it right to left (strict).
func TestRenderTrustedProxiesServerFields(t *testing.T) {
	base := baseCfg()
	base.TrustedProxies = []string{"198.51.100.0/24", "2001:db8:1::/48", "192.0.2.7"}
	out, err := Render(base, []Route{pooledRoute("app.example.com")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := edgeServer(t, out)
	if srv.TrustedProxies == nil || srv.TrustedProxies.Source != "static" {
		t.Fatalf("trusted_proxies must be a static ip source:\n%s", out)
	}
	if want := []string{"198.51.100.0/24", "2001:db8:1::/48", "192.0.2.7/32"}; !reflect.DeepEqual(srv.TrustedProxies.Ranges, want) {
		t.Errorf("ranges = %v, want %v", srv.TrustedProxies.Ranges, want)
	}
	if !reflect.DeepEqual(srv.ClientIPHeaders, []string{"X-Forwarded-For"}) {
		t.Errorf("client_ip_headers = %v, want [X-Forwarded-For]", srv.ClientIPHeaders)
	}
	if srv.TrustedProxiesStrict == nil || *srv.TrustedProxiesStrict != 1 {
		t.Errorf("trusted_proxies_strict must be 1 (rightmost untrusted address):\n%s", out)
	}
}

// The client IP header: an explicit one wins; otherwise CF-Connecting-IP when the cloudflare preset
// is listed, else X-Forwarded-For.
func TestRenderTrustedProxiesClientIPHeaderDefault(t *testing.T) {
	cases := []struct {
		proxies []string
		header  string
		want    string
	}{
		{[]string{"cloudflare"}, "", "CF-Connecting-IP"},
		{[]string{" cloudflare "}, "", "CF-Connecting-IP"},
		{[]string{"198.51.100.0/24", "cloudflare"}, "", "CF-Connecting-IP"},
		{[]string{"cloudflare"}, "X-Forwarded-For", "X-Forwarded-For"},
		{[]string{"cloudflare"}, "True-Client-IP", "True-Client-IP"},
		{[]string{"198.51.100.0/24", "2001:db8::/32"}, "", "X-Forwarded-For"},
		{[]string{"198.51.100.0/24"}, "CF-Connecting-IP", "CF-Connecting-IP"},
	}
	for _, c := range cases {
		base := baseCfg()
		base.TrustedProxies = c.proxies
		base.ClientIPHeader = c.header
		out, err := Render(base, []Route{pooledRoute("app.example.com")}, nil)
		if err != nil {
			t.Fatalf("%v %q: %v", c.proxies, c.header, err)
		}
		if got := edgeServer(t, out).ClientIPHeaders; !reflect.DeepEqual(got, []string{c.want}) {
			t.Errorf("%v %q: client_ip_headers = %v, want [%s]", c.proxies, c.header, got, c.want)
		}
		if got := DefaultClientIPHeader(c.proxies); c.header == "" && got != c.want {
			t.Errorf("DefaultClientIPHeader(%v) = %q, want %q", c.proxies, got, c.want)
		}
	}
}

// With trusted proxies the edge refuses QUIC 0-RTT early data: Caddy derives {http.vars.client_ip}
// from a source address it has not verified yet in early data. Without them the key is absent.
func TestRenderTrustedProxiesRefuse0RTT(t *testing.T) {
	base, routes, certOnly := goldenFixture()
	plain, err := Render(base, routes, certOnly)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "allow_0rtt") || strings.Contains(string(plain), `"protocols"`) {
		t.Errorf("allow_0rtt/protocols must not render without trusted proxies:\n%s", plain)
	}
	base.TrustedProxies = []string{"cloudflare"}
	out, err := Render(base, routes, certOnly)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Apps struct {
			HTTP struct {
				Servers map[string]map[string]json.RawMessage `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	srv := doc.Apps.HTTP.Servers["edge"]
	if got := string(srv["allow_0rtt"]); got != "false" {
		t.Errorf("allow_0rtt = %q, want false:\n%s", got, out)
	}
	if _, ok := srv["protocols"]; ok {
		t.Errorf("a full render keeps Caddy's default protocols (HTTP/3 on):\n%s", out)
	}
}

// The boot floor never carries the trusted-proxy fields (an old Caddy must still boot), and with
// trusted proxies it opens no QUIC listener: Caddy keeps the listener across /load and applies
// allow_0rtt only when it opens it, so the first reconcile must be the one that opens it.
func TestBootFloor(t *testing.T) {
	base, routes, certOnly := goldenFixture()
	base.TrustedProxies = []string{"cloudflare", "198.51.100.0/24"}
	base.ClientIPHeader = "CF-Connecting-IP"
	full, err := Render(base, routes, certOnly)
	if err != nil {
		t.Fatal(err)
	}
	floor := BootFloor(base)
	if len(base.TrustedProxies) != 2 || base.ClientIPHeader != "CF-Connecting-IP" || len(base.Wildcards) != 1 {
		t.Fatal("BootFloor must not modify its argument")
	}
	out, err := Render(floor, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, absent := range []string{"trusted_proxies", "client_ip_headers", "allow_0rtt", "client_ip", "*.apps.example.com"} {
		if strings.Contains(s, absent) {
			t.Errorf("boot floor contains %q:\n%s", absent, s)
		}
	}
	srv := edgeServer(t, out)
	var protocols struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Protocols []string `json:"protocols"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out, &protocols); err != nil {
		t.Fatal(err)
	}
	if got := protocols.Apps.HTTP.Servers["edge"].Protocols; !reflect.DeepEqual(got, []string{"h1", "h2"}) {
		t.Errorf("boot floor protocols = %v, want [h1 h2]", got)
	}
	if a, b := toJSON(edgeServer(t, full).Routes[0]), toJSON(srv.Routes[0]); a != b {
		t.Errorf("boot floor admin route differs from the full render:\nfull:  %s\nfloor: %s", a, b)
	}

	// Without trusted proxies the floor only drops the wildcards (golden-checked byte for byte).
	plainBase, _, _ := goldenFixture()
	plainFloor := BootFloor(plainBase)
	want := plainBase
	want.Wildcards = nil
	if !reflect.DeepEqual(plainFloor, want) {
		t.Errorf("BootFloor without trusted proxies = %+v, want %+v", plainFloor, want)
	}
}

// Every proxied app route passes the client address Caddy derived (the TCP peer unless the peer is
// trusted) as X-Forwarded-For, and still sets X-Forwarded-Proto/-Host from the request the edge
// received, so a trusted proxy can only change the client address.
func TestRenderTrustedProxiesAppRouteHeaders(t *testing.T) {
	routes := []Route{
		pooledRoute("app.example.com"),
		{AppID: "shop", Hostname: "app.example.com", PathPrefix: "/ws", Upstream: "rt:3001", Pool: []string{"172.18.0.7:3001"}, UpstreamScheme: "http", Enabled: true},
		{AppID: "vault", Hostname: "vault.example.com", Upstream: "vault:8200", Pool: []string{"172.19.0.2:8200"}, UpstreamScheme: "https", Enabled: true},
	}
	want := map[string][]string{
		"X-Forwarded-For":   {"{http.vars.client_ip}"},
		"X-Forwarded-Proto": {"{http.request.scheme}"},
		"X-Forwarded-Host":  {"{http.request.hostport}"},
	}
	base := baseCfg()
	base.TrustedProxies = []string{"198.51.100.0/24"}
	out, err := Render(base, routes, nil)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range edgeServer(t, out).Routes {
		for _, set := range proxyRequestSets(t, r.Handle) {
			n++
			if !reflect.DeepEqual(set, want) {
				t.Errorf("app route request headers = %v, want %v", set, want)
			}
		}
	}
	if n != len(routes) {
		t.Fatalf("found %d proxied routes, want %d:\n%s", n, len(routes), out)
	}

	// Without trusted proxies X-Forwarded-For stays the TCP peer and nothing else is set.
	out, err = Render(baseCfg(), routes, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range edgeServer(t, out).Routes {
		for _, set := range proxyRequestSets(t, r.Handle) {
			if !reflect.DeepEqual(set, map[string][]string{"X-Forwarded-For": {"{http.request.remote.host}"}}) {
				t.Errorf("without trusted proxies the request headers = %v", set)
			}
		}
	}
	if s := string(out); strings.Contains(s, "client_ip") || strings.Contains(s, "trusted_proxies") {
		t.Errorf("no trusted-proxy field may render without trusted proxies:\n%s", s)
	}
}

// The cloudflare preset expands in place to the shipped ranges; entries are canonicalised and
// de-duplicated in first-seen order.
func TestRenderTrustedProxiesPresetExpands(t *testing.T) {
	base := baseCfg()
	base.TrustedProxies = []string{"198.51.100.9/24", "cloudflare", "104.16.0.0/13", "::ffff:198.51.100.0/120", "2606:4700::/32"}
	out, err := Render(base, []Route{pooledRoute("app.example.com")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]string{"198.51.100.0/24"}, cloudflareRanges...)
	if got := edgeServer(t, out).TrustedProxies.Ranges; !reflect.DeepEqual(got, want) {
		t.Errorf("ranges = %v\nwant     %v", got, want)
	}
}

// Abuse test: the admin vhost is gated on the TCP peer even when the attacker's own network is a
// trusted proxy. A forged X-Forwarded-For from a trusted peer must neither satisfy the edge's
// allowlist matcher (remote_ip, never client_ip) nor reach the dashboard as the client address
// (the dashboard re-checks ip_allowlist against the single X-Forwarded-For value the edge sends).
func TestRenderTrustedProxiesAdminVhostUsesTCPPeer(t *testing.T) {
	base := baseCfg()
	base.AdminHostname = "admin.example.com"
	base.AdminAllowlist = []string{"203.0.113.0/24"}
	base.AdminUpstream = "127.0.0.1:9001"
	routes := []Route{pooledRoute("app.example.com")}
	plain, err := Render(base, routes, nil)
	if err != nil {
		t.Fatal(err)
	}
	base.TrustedProxies = []string{"cloudflare", "198.51.100.0/24"} // 198.51.100.0/24: the attacker's network
	base.ClientIPHeader = "X-Forwarded-For"
	out, err := Render(base, routes, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := edgeServer(t, out)
	admin := srv.Routes[0]
	if len(admin.Match) != 1 {
		t.Fatalf("admin route must have one matcher set:\n%s", out)
	}
	m := admin.Match[0]
	if compact(t, m["host"]) != `["admin.example.com"]` {
		t.Fatalf("first route is not the admin vhost:\n%s", out)
	}
	if len(m) != 2 || compact(t, m["remote_ip"]) != `{"ranges":["203.0.113.0/24"]}` {
		t.Errorf("admin vhost must match exactly host + remote_ip (TCP peer), got %v", m)
	}
	for i, r := range srv.Routes {
		for _, mm := range r.Match {
			if _, ok := mm["client_ip"]; ok {
				t.Errorf("route %d uses a client_ip matcher (header-derived address):\n%s", i, out)
			}
		}
	}
	sets := proxyRequestSets(t, admin.Handle)
	if len(sets) != 1 || !reflect.DeepEqual(sets[0], map[string][]string{"X-Forwarded-For": {"{http.request.remote.host}"}}) {
		t.Errorf("admin vhost must send the TCP peer as X-Forwarded-For, got %v", sets)
	}
	// The admin route renders exactly as it does without trusted proxies.
	if a, b := toJSON(edgeServer(t, plain).Routes[0]), toJSON(admin); a != b {
		t.Errorf("admin route changed with trusted proxies:\nwithout: %s\nwith:    %s", a, b)
	}
}

func TestRenderTrustedProxiesRejectsInvalid(t *testing.T) {
	route := []Route{pooledRoute("app.example.com")}
	for _, entry := range []string{"0.0.0.0/0", "::/0", "::ffff:0.0.0.0/96", "bogus", "Cloudflare", "", "10.0.0.0/33", "198.51.100.0/24,10.0.0.0/8"} {
		base := baseCfg()
		base.TrustedProxies = []string{"198.51.100.0/24", entry}
		if _, err := Render(base, route, nil); err == nil {
			t.Errorf("trusted proxy entry %q must be rejected", entry)
		}
	}
	for _, h := range []string{"Host", "host", "Forwarded", "Cookie", "Authorization", "X Forwarded For", "X-Forwarded-For\r\nX-Evil: 1", "-Bad", "X_Forwarded_For", strings.Repeat("A", 65)} {
		base := baseCfg()
		base.TrustedProxies = []string{"198.51.100.0/24"}
		base.ClientIPHeader = h
		if _, err := Render(base, route, nil); err == nil {
			t.Errorf("client IP header %q must be rejected", h)
		}
	}
	base := baseCfg()
	base.ClientIPHeader = "X-Forwarded-For"
	if _, err := Render(base, route, nil); err == nil {
		t.Error("a client IP header without trusted proxies must be rejected")
	}
	for _, h := range []string{"X-Forwarded-For", "CF-Connecting-IP", "True-Client-IP", "X-Real-IP", "fastly-client-ip"} {
		base := baseCfg()
		base.TrustedProxies = []string{"198.51.100.0/24"}
		base.ClientIPHeader = h
		if _, err := Render(base, route, nil); err != nil {
			t.Errorf("client IP header %q must be accepted: %v", h, err)
		}
	}
}

// An empty trusted-proxy list is the same as none: the output is byte-identical to the golden
// render from before the feature.
func TestRenderTrustedProxiesEmptyListIsUnset(t *testing.T) {
	base, routes, certOnly := goldenFixture()
	a, err := Render(base, routes, certOnly)
	if err != nil {
		t.Fatal(err)
	}
	base.TrustedProxies = []string{}
	b, err := Render(base, routes, certOnly)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Error("an empty trusted-proxy list must render exactly like an unset one")
	}
}
