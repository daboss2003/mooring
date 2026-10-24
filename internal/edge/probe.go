package edge

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// ProbeWildcard checks that the edge at addr (the local edge, e.g. 127.0.0.1:443) serves a valid,
// unexpired certificate covering *.<apex>. It opens a TLS connection with SNI
// "mooring-probe-<random>.<apex>" — a name no route claims, so it can only be answered by the
// namespace wildcard — and requires the leaf certificate to cover that name. On-demand TLS is off
// (SBD-3), so the probe can never cause an issuance: a namespace whose wildcard is missing (DNS plugin
// absent) or failing to issue (e.g. a rejected DNS API token) fails the handshake, because Caddy has
// no certificate for the name.
func ProbeWildcard(ctx context.Context, addr, apex string) error {
	apex = strings.ToLower(strings.TrimSpace(apex))
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	sni := "mooring-probe-" + hex.EncodeToString(b[:]) + "." + apex
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		// Intentional: InsecureSkipVerify. The probe checks that the edge HAS a certificate covering the
		// namespace (hostname + expiry below), not that the chain verifies — a staging or private
		// ACME CA is a valid edge setup and must not read as an outage.
		Config: &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, // #nosec G402 -- coverage check only, see above
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := d.DialContext(cctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("no certificate served for *.%s (%v)", apex, err)
	}
	defer c.Close()
	tc, ok := c.(*tls.Conn)
	if !ok {
		return fmt.Errorf("no TLS connection for *.%s", apex)
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return fmt.Errorf("no certificate served for *.%s", apex)
	}
	leaf := certs[0]
	if err := leaf.VerifyHostname(sni); err != nil {
		return fmt.Errorf("the edge serves a certificate that does not cover *.%s (%v)", apex, err)
	}
	if time.Now().After(leaf.NotAfter) {
		return fmt.Errorf("the certificate for *.%s expired on %s (renewal is failing)", apex, leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}
