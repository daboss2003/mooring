// Package l4 generates the config for Mooring's managed Layer-4 (TCP/UDP) load
// balancer — an nginx `stream {}` proxy that fronts a fixed public port (e.g. DNS
// 53, DoT 853, MQTTS 8883) and fans connections across a service's INTERNAL replica
// pool. It is the L4 analog of the HTTP edge.
//
// Like the HTTP edge, the config is RENDERED from typed structs and is NEVER authored
// by the operator (no nginx.conf to write, no portal field) — the one chokepoint, and
// every value is re-validated at render so a bad route can never reach the datapath.
//
// Phase 1 (this file): the typed model + render + injection-safe validation, fully
// unit-tested. The supervised nginx child, the live replica-pool reconcile, the UDP
// health prober, and the OS-layer slice/firewall land in later phases.
package l4

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Route is one managed L4 listener: a public port the LB owns, forwarded to a
// service's internal replica pool. Service/Port are SELECTORS (never a literal dial
// target the operator types); Pool, when populated by the reconciler, lists the live
// replica host:port endpoints. A route with an empty Pool is skipped (its listener isn't
// bound): the host nginx can't resolve a compose service name, so it is never dialed.
type Route struct {
	AppID    string   // owning project — discovery scopes Service to it (two apps may share a service name)
	Listen   int      // host port the L4 LB binds
	Protocol string   // "tcp" | "udp"
	Service  string   // selector → the service whose replicas receive traffic
	Port     int      // the service's INTERNAL container port
	LB       string   // "" (round_robin) | "least_conn" | "hash_client_ip"
	Pool     []string // host:port of each live replica; EMPTY → route is SKIPPED at render
}

// PoolKey identifies a route's pool slot — one listener is one (port, protocol). The
// reconciler keys discovered replica pools by this to merge them back onto the routes.
func PoolKey(r Route) string { return strconv.Itoa(r.Listen) + "/" + r.Protocol }

var (
	// nameRe bounds a compose service name / upstream host so it can never carry a
	// space or newline that would inject an nginx directive (the L4 analog of the
	// edge's shell/upstream hygiene).
	nameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,253})$`)
	lbOK   = map[string]bool{"": true, "round_robin": true, "least_conn": true, "hash_client_ip": true}
)

func controlPort(p int) bool { return p == 9000 || p == 2019 || p == 2375 }

// ValidateRoute checks one L4 route, fail-closed. It mirrors (defense-in-depth) the
// definition-layer schema validation, and additionally rejects any value that could
// inject text into the generated nginx config.
func ValidateRoute(r Route) error {
	if r.Protocol != "tcp" && r.Protocol != "udp" {
		return fmt.Errorf("l4 route protocol %q must be tcp or udp", r.Protocol)
	}
	if r.Listen < 1 || r.Listen > 65535 {
		return fmt.Errorf("l4 route listen port %d is out of range", r.Listen)
	}
	if r.Listen == 80 || r.Listen == 443 {
		return fmt.Errorf("l4 route listen port %d is reserved for the HTTP edge", r.Listen)
	}
	if controlPort(r.Listen) {
		return fmt.Errorf("l4 route listen port %d is a reserved control-plane port", r.Listen)
	}
	if !nameRe.MatchString(r.Service) {
		return fmt.Errorf("l4 route on %d: service %q is not a valid name", r.Listen, r.Service)
	}
	if r.Port < 1 || r.Port > 65535 || controlPort(r.Port) {
		return fmt.Errorf("l4 route on %d: upstream port %d is invalid or reserved", r.Listen, r.Port)
	}
	if !lbOK[r.LB] {
		return fmt.Errorf("l4 route on %d: lb %q must be round_robin, least_conn, or hash_client_ip", r.Listen, r.LB)
	}
	for _, m := range r.Pool {
		if err := validateMember(m); err != nil {
			return fmt.Errorf("l4 route on %d: pool member %q: %w", r.Listen, m, err)
		}
	}
	return nil
}

// validateMember enforces a strict host:port shape so a pool member can never carry
// a control-plane port, a loopback/unspecified literal, or injection characters.
func validateMember(m string) error {
	host, portStr, ok := strings.Cut(m, ":")
	if !ok {
		return fmt.Errorf("must be host:port")
	}
	if !nameRe.MatchString(host) {
		return fmt.Errorf("host is not a valid name/address")
	}
	if host == "127.0.0.1" || host == "0.0.0.0" || host == "localhost" || host == "::1" {
		return fmt.Errorf("loopback/unspecified upstream is forbidden")
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 1 || p > 65535 || controlPort(p) {
		return fmt.Errorf("port is invalid or reserved")
	}
	return nil
}

// Render produces a complete, valid nginx `stream` config from the routes. It is
// fail-closed: any invalid route, or two routes claiming the same listen+protocol,
// is an error and nothing is emitted. Output is deterministic (routes are sorted).
func Render(routes []Route) (string, error) {
	seen := map[string]bool{}
	sorted := append([]Route(nil), routes...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Listen != sorted[j].Listen {
			return sorted[i].Listen < sorted[j].Listen
		}
		return sorted[i].Protocol < sorted[j].Protocol
	})

	var b strings.Builder
	b.WriteString("# generated by Mooring — do not edit\n")
	// Load dynamically-built modules. Debian/Ubuntu ship the stream module separately
	// (libnginx-mod-stream) and load it from modules-enabled/, which a standalone `-c`
	// config does NOT pick up — without this, nginx rejects the `stream {}` block with
	// "unknown directive stream". A glob include is non-fatal when it matches nothing,
	// so on distros where `stream` is built into nginx this is a harmless no-op.
	b.WriteString("include /etc/nginx/modules-enabled/*.conf;\n")
	b.WriteString("worker_processes auto;\n")
	// Keep nginx's runtime paths inside the Mooring-owned prefix (nginx runs non-root
	// under the sandbox): a RELATIVE pid resolves under `-p <Prefix>` (writable), and
	// errors go to stderr (the supervisor captures it → journald) since the default
	// /var/log/nginx and /run aren't writable by the service.
	b.WriteString("pid nginx.pid;\n")
	b.WriteString("error_log stderr;\n")
	b.WriteString("events {}\n")
	b.WriteString("stream {\n")
	for _, r := range sorted {
		if err := ValidateRoute(r); err != nil {
			return "", err
		}
		key := r.Protocol + ":" + strconv.Itoa(r.Listen)
		if seen[key] {
			return "", fmt.Errorf("l4 route listen %d/%s is declared twice", r.Listen, r.Protocol)
		}
		seen[key] = true

		// No name fallback: the host nginx cannot resolve a compose service name, and a
		// single unresolvable `server` makes `nginx -t` reject the WHOLE config — every
		// listener goes down, including :53. So skip a route with no discovered replica
		// pool until discovery has a live IP for it; an empty stream{} is valid, so the
		// other listeners still bind. (The reconciler logs which services were skipped.)
		if len(r.Pool) == 0 {
			continue
		}

		name := fmt.Sprintf("l4_%d_%s", r.Listen, r.Protocol)
		b.WriteString("    upstream " + name + " {\n")
		switch r.LB {
		case "least_conn":
			b.WriteString("        least_conn;\n")
		case "hash_client_ip":
			b.WriteString("        hash $remote_addr consistent;\n")
		}
		for _, m := range r.Pool {
			b.WriteString("        server " + m + ";\n")
		}
		b.WriteString("    }\n")

		b.WriteString("    server {\n")
		if r.Protocol == "udp" {
			b.WriteString(fmt.Sprintf("        listen %d udp;\n", r.Listen))
			b.WriteString("        proxy_timeout 5s;\n")
		} else {
			b.WriteString(fmt.Sprintf("        listen %d;\n", r.Listen))
		}
		b.WriteString("        proxy_pass " + name + ";\n")
		b.WriteString("    }\n")
	}
	b.WriteString("}\n")
	return b.String(), nil
}
