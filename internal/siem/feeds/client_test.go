package feeds

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testCert is a self-signed certificate for hosts and a pool that trusts it.
func testCert(t *testing.T, hosts ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hosts[0]}, DNSNames: hosts,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// guardedServer is a TLS server answering as www.spamhaus.org, and a client config that reaches it
// through the real guard: the name resolves to the server's loopback address, which permit allows
// (only here: the production check refuses loopback).
type guardedServer struct {
	srv     *httptest.Server
	port    string
	cfg     clientConfig
	lookups atomic.Int64
	dials   atomic.Int64
}

func newGuardedServer(t *testing.T, h http.Handler) *guardedServer {
	t.Helper()
	cert, pool := testCert(t, "www.spamhaus.org", "evil.example")
	g := &guardedServer{srv: httptest.NewUnstartedServer(h)}
	g.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	g.srv.StartTLS()
	t.Cleanup(g.srv.Close)
	u, _ := url.Parse(g.srv.URL)
	g.port = u.Port()
	loop := netip.MustParseAddr("127.0.0.1")
	g.cfg = clientConfig{
		allow: []string{"www.spamhaus.org:" + g.port},
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			g.lookups.Add(1)
			return []netip.Addr{loop}, nil
		},
		permit: func(a netip.Addr) bool { return a == loop || dialable(a) },
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			g.dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		roots: pool,
	}
	return g
}

func (g *guardedServer) url(host, path string) string { return "https://" + host + ":" + g.port + path }

func get(t *testing.T, c *http.Client, u string) (*http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", "Mooring/test")
	resp, err := c.Do(req)
	if err == nil {
		t.Cleanup(func() { resp.Body.Close() })
	}
	return resp, err
}

// An allowlisted host is reached through the guard, over TLS verified for its name; a proxy in the
// environment is not used.
func TestClientReachesAllowlistedHost(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	var ua atomic.Value
	g := newGuardedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua.Store(r.UserAgent())
		io.WriteString(w, "ok")
	}))
	resp, err := get(t, newClient(g.cfg), g.url("www.spamhaus.org", "/drop/drop_v4.json"))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(resp.Body); string(b) != "ok" || ua.Load() != "Mooring/test" {
		t.Errorf("body %q ua %v", b, ua.Load())
	}
	if g.lookups.Load() != 1 || g.dials.Load() != 1 {
		t.Errorf("lookups %d dials %d, want 1 and 1", g.lookups.Load(), g.dials.Load())
	}
	// The host name is matched without regard to case.
	if _, err := get(t, newClient(g.cfg), g.url("WWW.Spamhaus.ORG", "/")); err != nil {
		t.Errorf("upper-case host: %v", err)
	}
}

// Anything but https to an allowlisted name is refused before a lookup or a dial.
func TestClientRefusesURLs(t *testing.T) {
	g := newGuardedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	c := newClient(g.cfg)
	for _, u := range []string{
		g.url("evil.example", "/"),
		g.url("www.spamhaus.org.evil.example", "/"),
		"http://www.spamhaus.org:" + g.port + "/",
		"https://user:pass@www.spamhaus.org:" + g.port + "/",
		"https://127.0.0.1:" + g.port + "/",
		"https://www.spamhaus.org/", // the allowlist entry has the port: another port is another host
	} {
		if _, err := get(t, c, u); err == nil {
			t.Errorf("%s: reached", u)
		}
	}
	if g.lookups.Load() != 0 || g.dials.Load() != 0 {
		t.Errorf("lookups %d dials %d for refused URLs, want 0", g.lookups.Load(), g.dials.Load())
	}
	// An IP literal is refused even when it is on the allowlist: never looked up or dialed.
	g.cfg.allow = append(g.cfg.allow, "127.0.0.1:"+g.port)
	if _, err := get(t, newClient(g.cfg), "https://127.0.0.1:"+g.port+"/"); err == nil || !errors.Is(err, errNotAllowed) {
		t.Errorf("an IP literal: %v", err)
	}
	if g.lookups.Load() != 0 || g.dials.Load() != 0 {
		t.Errorf("an IP literal was looked up %d / dialed %d times", g.lookups.Load(), g.dials.Load())
	}
}

// The production allowlist is exactly the four feed hosts, on port 443.
func TestClientProductionAllowlist(t *testing.T) {
	want := []string{"download.db-ip.com", "www.spamhaus.org", "check.torproject.org", "feeds.dshield.org"}
	if strings.Join(Hosts, ",") != strings.Join(want, ",") {
		t.Errorf("Hosts %v, want %v", Hosts, want)
	}
	rt := newClient(clientConfig{allow: Hosts}).Transport.(*guardTransport)
	for _, h := range want {
		if !rt.allowed(&url.URL{Scheme: "https", Host: h}) {
			t.Errorf("%s not allowed", h)
		}
	}
	for _, h := range []string{"download.db-ip.com:8443", "db-ip.com", "spamhaus.org", "www.spamhaus.org.", "example.com", ""} {
		if rt.allowed(&url.URL{Scheme: "https", Host: h}) {
			t.Errorf("%q allowed", h)
		}
	}
}

// A name resolving to any non-public address is refused without dialing (DNS rebinding).
func TestClientRefusesNonPublicAddresses(t *testing.T) {
	g := newGuardedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	for _, addrs := range [][]string{
		{"10.0.0.1"}, {"127.0.0.1"}, {"100.64.0.1"}, {"169.254.169.254"}, {"fd00::1"}, {"::1"}, {"0.0.0.0"},
		{"192.168.1.1"}, {"172.16.0.1"}, {"fe80::1"}, {"8.8.8.8", "10.0.0.1"}, {"2001:4860:4860::8888", "::ffff:127.0.0.1"},
		{"64:ff9b::a9fe:a9fe"}, {}, // NAT64 of 169.254.169.254; no address at all
	} {
		cfg := g.cfg
		cfg.permit = nil // the production check
		var dialed atomic.Int64
		cfg.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed.Add(1)
			return nil, errors.New("dialed")
		}
		cfg.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			var out []netip.Addr
			for _, a := range addrs {
				out = append(out, netip.MustParseAddr(a))
			}
			return out, nil
		}
		_, err := get(t, newClient(cfg), g.url("www.spamhaus.org", "/"))
		if err == nil || dialed.Load() != 0 {
			t.Errorf("%v: err %v, dials %d; want refused without a dial", addrs, err, dialed.Load())
		}
		if len(addrs) == 0 && (err == nil || !strings.Contains(err.Error(), "no address")) {
			t.Errorf("no address: %v", err)
		} else if len(addrs) > 0 && !errors.Is(err, errBlocked) {
			t.Errorf("%v: %v, want errBlocked", addrs, err)
		}
	}
	// A public address (and the NAT64 form of one) is dialed, the checked address itself.
	for addr, want := range map[string]string{"8.8.8.8": "8.8.8.8:" + g.port, "64:ff9b::808:808": "[64:ff9b::808:808]:" + g.port} {
		cfg := g.cfg
		cfg.permit = nil
		var got atomic.Value
		cfg.dial = func(ctx context.Context, network, a string) (net.Conn, error) {
			got.Store(a)
			return nil, errors.New("dialed")
		}
		cfg.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr(addr)}, nil
		}
		if _, err := get(t, newClient(cfg), g.url("www.spamhaus.org", "/")); err == nil || got.Load() != want {
			t.Errorf("%s: dialed %v, want %s", addr, got.Load(), want)
		}
	}
}

// A redirect is never followed, even to the same host.
func TestClientRefusesRedirects(t *testing.T) {
	var other atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/b", http.StatusFound) })
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) { other.Add(1) })
	g := newGuardedServer(t, mux)
	if _, err := get(t, newClient(g.cfg), g.url("www.spamhaus.org", "/a")); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Errorf("err %v, want a refused redirect", err)
	}
	if other.Load() != 0 {
		t.Error("the redirect was followed")
	}
}

// The transport's limits.
func TestClientLimits(t *testing.T) {
	c := newClient(clientConfig{allow: Hosts})
	tr := c.Transport.(*guardTransport).next
	if tr.Proxy != nil || !tr.DisableKeepAlives || !tr.DisableCompression || tr.TLSHandshakeTimeout != 15*time.Second ||
		tr.ResponseHeaderTimeout != 60*time.Second || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 || tr.MaxResponseHeaderBytes != 64<<10 {
		t.Errorf("transport %+v", tr)
	}
	if dialTimeout != 30*time.Second {
		t.Errorf("dial timeout %v", dialTimeout)
	}
}
