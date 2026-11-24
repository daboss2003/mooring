// Package parse turns each source's raw lines into normalized siem.Events. Every function is pure
// (no I/O) and never panics on hostile input; redaction happens after parsing (package redact).
package parse

import (
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// window is how far a source's own timestamp may be from the capture time and still be used: an
// app or proxy clock that is further off (or a forged time) gives the capture time instead.
const window = 24 * time.Hour

// within returns src when it is within window of ref, else ref.
func within(src, ref time.Time) time.Time {
	if src.IsZero() {
		return ref
	}
	if d := src.Sub(ref); d > window || d < -window {
		return ref
	}
	return src
}

// notFuture returns ts, or now when ts is more than window ahead of it. Host logs keep their own
// (possibly old) timestamps, since a backlog read after downtime is genuinely old.
func notFuture(ts, now time.Time) time.Time {
	if !now.IsZero() && ts.After(now.Add(window)) {
		return now
	}
	return ts
}

// parseIP returns s as a canonical IP address, or "" when it isn't one. A port, brackets and an
// IPv6 zone are removed and an IPv4-mapped IPv6 address (Node's "::ffff:10.0.0.1") is unmapped;
// the unspecified address doesn't count.
func parseIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 64 {
		return ""
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		ap, err2 := netip.ParseAddrPort(s)
		if err2 != nil {
			if len(s) > 2 && s[0] == '[' && s[len(s)-1] == ']' {
				return parseIP(s[1 : len(s)-1])
			}
			return ""
		}
		a = ap.Addr()
	}
	a = a.Unmap().WithZone("")
	if !a.IsValid() || a.IsUnspecified() {
		return ""
	}
	return a.String()
}

// privateIP reports whether ip (canonical) is a private, loopback or link-local address — on an
// app line, the edge's hop rather than the client.
func privateIP(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && (a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast())
}

// firstIP returns the first word of s that is an IP address ("from 1.2.3.4", "rhost=1.2.3.4",
// "1.2.3.4:22"), or "".
func firstIP(s string) string {
	for len(s) > 0 {
		i := strings.IndexAny(s, " \t")
		w := s
		if i >= 0 {
			w, s = s[:i], s[i+1:]
		} else {
			s = ""
		}
		if j := strings.LastIndexByte(w, '='); j >= 0 {
			w = w[j+1:]
		}
		w = strings.Trim(w, "[](),;:.")
		if len(w) < 2 || strings.IndexAny(w, ".:") < 0 {
			continue
		}
		if ip := parseIP(w); ip != "" {
			return ip
		}
	}
	return ""
}

// epoch converts a Unix timestamp in seconds, milliseconds, microseconds or nanoseconds (told
// apart by magnitude) to a time; zero for a value that can't be one.
func epoch(v float64) time.Time {
	if math.IsNaN(v) || v <= 0 || v >= 1e19 {
		return time.Time{}
	}
	switch {
	case v < 1e11:
		s, frac := math.Modf(v)
		return time.Unix(int64(s), int64(frac*1e9))
	case v < 1e14:
		return time.UnixMicro(int64(v * 1e3))
	case v < 1e17:
		return time.UnixMicro(int64(v))
	}
	return time.Unix(0, int64(v))
}

// number parses a decimal integer for a field (port, pid); ok is false when s isn't one.
func number(s string) (float64, bool) {
	if s == "" || len(s) > 20 {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	return f, err == nil
}
