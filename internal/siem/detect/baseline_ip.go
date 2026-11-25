package detect

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// The address baseline (ip) learns each address's (IPv6: /64's) usual mix of edge requests: how
// many went to sign-in endpoints, to admin paths, and were answered with an error (4xx or 5xx). It
// fires when, in the last Window, at least Count requests came and at least half of them were of
// one of those kinds, at least Factor times that kind's usual share. The usual mix is counted over
// the address's requests before the window; an address fires only once Learn has passed since its
// first request and Count requests are in its usual mix.

const (
	ipSlots    = 5   // the window's slots (Window/ipSlots each)
	minIPShare = 0.5 // a kind's share of the window to fire
	ipHalveAt  = 1 << 24
	// An address with ipSettleN requests in its usual mix, its first an hour ago or more, is worth
	// protecting.
	ipSettleN   = 10
	ipSettleAge = time.Hour
)

type addrMix struct {
	first                    int64  // unix seconds of the first request
	total, auth, admin, errs uint32 // the usual mix: requests before the window
	slotW                    int64  // ns
	win                      [ipSlots]ipSlot
}

type ipSlot struct {
	idx                  int64
	n, auth, admin, errs uint16
}

func (x *addrMix) foldSlot(s *ipSlot) {
	if s.n > 0 {
		x.total = satAdd(x.total, uint32(s.n))
		x.auth = satAdd(x.auth, uint32(s.auth))
		x.admin = satAdd(x.admin, uint32(s.admin))
		x.errs = satAdd(x.errs, uint32(s.errs))
		if x.total >= ipHalveAt {
			x.total, x.auth, x.admin, x.errs = x.total/2, x.auth/2, x.admin/2, x.errs/2
		}
	}
	*s = ipSlot{}
}

func (x *addrMix) foldAll() {
	for i := range x.win {
		x.foldSlot(&x.win[i])
	}
}

// add counts a request at t (unix ns) for a window of the given length; folded reports whether
// the usual mix changed.
func (x *addrMix) add(t int64, window time.Duration, auth, admin, isErr bool) (folded bool) {
	if sec := t / int64(time.Second); x.first == 0 || sec < x.first {
		x.first = sec
	}
	sw := max(int64(window)/ipSlots, int64(time.Second))
	if sw != x.slotW {
		x.foldAll()
		x.slotW, folded = sw, true
	}
	idx := t / sw
	for i := range x.win {
		if s := &x.win[i]; s.n > 0 && s.idx <= idx-ipSlots {
			x.foldSlot(s)
			folded = true
		}
	}
	s := &x.win[((idx%ipSlots)+ipSlots)%ipSlots]
	if s.idx != idx {
		if s.n > 0 && s.idx > idx {
			// Older than the window: part of the usual mix at once.
			x.foldSlot(&ipSlot{n: 1, auth: b16(auth), admin: b16(admin), errs: b16(isErr)})
			return true
		}
		if s.n > 0 {
			x.foldSlot(s)
			folded = true
		}
		*s = ipSlot{idx: idx}
	}
	if s.n == math.MaxUint16 {
		return folded
	}
	s.n++
	s.auth += b16(auth)
	s.admin += b16(admin)
	s.errs += b16(isErr)
	return folded
}

func b16(v bool) uint16 {
	if v {
		return 1
	}
	return 0
}

// window sums the slots in the window ending at t. add has already folded the slots before it
// (the lower bound is a guard).
func (x *addrMix) window(t int64) (n, auth, admin, errs uint32) {
	if x.slotW == 0 {
		return
	}
	idx := t / x.slotW
	for _, s := range x.win {
		if s.n > 0 && s.idx > idx-ipSlots && s.idx <= idx {
			n, auth, admin, errs = n+uint32(s.n), auth+uint32(s.auth), admin+uint32(s.admin), errs+uint32(s.errs)
		}
	}
	return
}

func (x *addrMix) learned(t int64, learn time.Duration, count int) bool {
	return int(x.total) >= count && t/int64(time.Second)-x.first >= int64(learn/time.Second)
}

func (x *addrMix) settled(t int64) bool { return x.learned(t, ipSettleAge, ipSettleN) }

// The path kinds. A path segment (between '/', without a trailing ".ext", lowercased) is a sign-in
// one when it contains login, logon, signin, sign-in, sign_in or password, or is one of
// authSegments; an admin one when it contains admin, or is one of adminSegments.
var (
	authWords     = []string{"login", "logon", "signin", "sign-in", "sign_in", "password"}
	authSegments  = map[string]bool{"auth": true, "oauth": true, "oauth2": true, "authorize": true, "authenticate": true, "token": true, "tokens": true, "session": true, "sessions": true, "mfa": true, "2fa": true, "otp": true, "sso": true}
	adminSegments = map[string]bool{"manager": true, "console": true, "actuator": true}
)

const maxPathSegments = 32

func pathKinds(p string) (auth, admin bool) {
	p = strings.ToLower(siem.Cut(p, siem.MaxFieldValue))
	for n := 0; n < maxPathSegments; n++ {
		p = strings.TrimLeft(p, "/")
		if p == "" {
			break
		}
		var seg string
		seg, p, _ = strings.Cut(p, "/")
		if i := strings.LastIndexByte(seg, '.'); i > 0 {
			seg = seg[:i]
		}
		if !auth && authSegments[seg] {
			auth = true
		}
		for _, w := range authWords {
			if !auth && strings.Contains(seg, w) {
				auth = true
			}
		}
		if !admin && (adminSegments[seg] || strings.Contains(seg, "admin")) {
			admin = true
		}
	}
	return auth, admin
}

func pct(p float64) string {
	switch {
	case p <= 0:
		return "0%"
	case p < 0.01:
		return "under 1%"
	}
	return fmt.Sprintf("%d%%", int(math.Round(p*100)))
}

// ipEvent evaluates an edge request of rule c for address key: with add (the first enabled ip
// rule) it is counted, then every enabled ip rule checks the window.
func (b *baselines) ipEvent(e *Engine, c *compiled, key string, ev *siem.Event, add bool) {
	t := ev.TS.UnixNano()
	x := b.ip.get(key)
	if add {
		if x == nil {
			x = b.ip.add(key)
			b.ip.touch(x)
		}
		path, _ := ev.F["path"].(string)
		st, _ := ev.F["status"].(float64)
		auth, admin := pathKinds(path)
		if x.v.add(t, c.r.Window, auth, admin, st >= 400) {
			b.ip.touch(x)
		}
		if x.v.settled(t) {
			b.ip.protect(x)
		}
	}
	if x == nil || !x.v.learned(t, c.r.Learn, c.r.Count) {
		return
	}
	n, auth, admin, errs := x.v.window(t)
	if n < uint32(c.r.Count) {
		return
	}
	best, bestQ := -1, 0.0
	kinds := [3]struct {
		k, usual uint32
		what     string
	}{{auth, x.v.auth, "to sign-in endpoints"}, {admin, x.v.admin, "to admin paths"}, {errs, x.v.errs, "answered with an error"}}
	for i, k := range kinds {
		q, p := float64(k.k)/float64(n), float64(k.usual)/float64(x.v.total)
		if q >= minIPShare && q >= c.r.Factor*p && q > bestQ {
			best, bestQ = i, q
		}
	}
	if best < 0 {
		return
	}
	k := kinds[best]
	reason := fmt.Sprintf("%d of %d requests in %s %s (usually %s)", k.k, n, fmtDur(c.r.Window), k.what,
		pct(float64(k.usual)/float64(x.v.total)))
	e.fire(c, key, ev, firing{count: int(n), evidence: []siem.Evidence{evidenceOf(ev)}, reasons: []string{reason}})
	// The window it fired on becomes part of the usual mix: the next firing needs Count new requests.
	x.v.foldAll()
	b.ip.touch(x)
}

const ipVersion = 1

// encode: the version, first, then the usual mix with the window's requests in it (a snapshot:
// after a restart the window starts empty).
func (x *addrMix) encode() []byte {
	y := *x
	y.foldAll()
	b := make([]byte, 0, 24)
	b = append(b, ipVersion)
	b = binary.AppendVarint(b, y.first)
	for _, v := range []uint32{y.total, y.auth, y.admin, y.errs} {
		b = binary.AppendUvarint(b, uint64(v))
	}
	return b
}

func decodeIP(b []byte) (addrMix, error) {
	var x addrMix
	if len(b) == 0 || b[0] != ipVersion {
		return x, errState
	}
	r := &reader{b: b[1:]}
	x.first = r.varint()
	var v [4]uint64
	for i := range v {
		v[i] = r.uvarint()
	}
	if r.err != nil || len(r.b) != 0 || x.first < 0 || v[0] > math.MaxUint32 || v[1] > v[0] || v[2] > v[0] || v[3] > v[0] {
		return x, errState
	}
	x.total, x.auth, x.admin, x.errs = uint32(v[0]), uint32(v[1]), uint32(v[2]), uint32(v[3])
	return x, nil
}
