package feeds

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/siem/enrich"
)

// Hosts are the only hosts the feeds client connects to, over https on port 443 (for an egress
// firewall: see docs/security-logs.md).
var Hosts = []string{"download.db-ip.com", "www.spamhaus.org", "check.torproject.org", "feeds.dshield.org"}

const dialTimeout = 30 * time.Second

var (
	errNotAllowed = errors.New("feeds: not an allowed feed host")
	errBlocked    = errors.New("feeds: the host resolves to a non-public address")
	errRedirect   = errors.New("feeds: redirect refused")
)

// clientConfig builds the feeds client; the zero value of each seam is the production one.
type clientConfig struct {
	allow  []string                                                          // host (port 443) or host:port
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)      // nil: the system resolver
	permit func(netip.Addr) bool                                             // nil: dialable
	dial   func(ctx context.Context, network, addr string) (net.Conn, error) // nil: a net.Dialer (30 s)
	roots  *x509.CertPool                                                    // nil: the system roots
}

// newClient is the feeds' outbound client: https only, to an allowed host name only (no IP
// literal, no user info, no other port), never following a redirect, and dialing only an address
// it checked: the name is resolved for each connection, refused when ANY address is not public
// (private, loopback, link-local, CGNAT, unique-local, …; see enrich.Public), and the checked
// address is dialed, so a DNS answer that changes between the check and the dial can't move it.
// Intentional: no proxy, not even HTTPS_PROXY from the environment: through a proxy the address
// check can't be made.
func newClient(c clientConfig) *http.Client {
	allow := map[string]bool{}
	for _, h := range c.allow {
		allow[strings.ToLower(h)] = true
	}
	d := &guardDialer{allow: allow, lookup: c.lookup, permit: c.permit, dial: c.dial}
	if d.lookup == nil {
		d.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	if d.permit == nil {
		d.permit = dialable
	}
	if d.dial == nil {
		d.dial = (&net.Dialer{Timeout: dialTimeout}).DialContext
	}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            d.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.roots},
		TLSHandshakeTimeout:    15 * time.Second,
		ResponseHeaderTimeout:  60 * time.Second,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 64 << 10,
		ForceAttemptHTTP2:      true,
	}
	return &http.Client{
		Transport:     &guardTransport{allow: allow, next: tr},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect },
	}
}

// guardTransport refuses a request to anything but https://<allowed host>.
type guardTransport struct {
	allow map[string]bool
	next  *http.Transport
}

func (g *guardTransport) allowed(u *url.URL) bool {
	return u.Scheme == "https" && u.User == nil && u.Opaque == "" && u.Host != "" && g.allow[strings.ToLower(u.Host)]
}

func (g *guardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !g.allowed(req.URL) {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, fmt.Errorf("%w: %s://%s", errNotAllowed, req.URL.Scheme, cleanText(req.URL.Host))
	}
	return g.next.RoundTrip(req)
}

type guardDialer struct {
	allow  map[string]bool
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	permit func(netip.Addr) bool
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
}

// DialContext resolves an allowed host, checks every address, and dials the checked ones in turn.
func (d *guardDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	key := strings.ToLower(host)
	if port != "443" {
		key += ":" + port
	}
	if !d.allow[key] {
		return nil, fmt.Errorf("%w: %s", errNotAllowed, cleanText(addr))
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil, fmt.Errorf("%w: an IP address", errNotAllowed)
	}
	addrs, err := d.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("feeds: no address for %s", host)
	}
	for _, a := range addrs {
		if !d.permit(a) {
			return nil, fmt.Errorf("%w (%s)", errBlocked, host)
		}
	}
	var last error
	for _, a := range addrs {
		c, err := d.dial(ctx, network, net.JoinHostPort(a.Unmap().String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// nat64 is the well-known NAT64 prefix (RFC 6052): its addresses stand for the IPv4 address in
// their last 32 bits.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// dialable reports whether the feeds client may connect to a: a public address, or the NAT64 form
// of one.
func dialable(a netip.Addr) bool {
	a = a.Unmap()
	if nat64.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte(b[12:16]))
	}
	return enrich.Public(a)
}
