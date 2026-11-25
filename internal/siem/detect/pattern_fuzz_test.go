package detect

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// FuzzPatternMine mines hostile lines: tokenizing, masking, inserting, saving a template's state
// and reading it back never panic, and every bound of the miner holds.
func FuzzPatternMine(f *testing.F) {
	for _, s := range []string{
		"GET /api/users/42 200 15ms from 203.0.113.7:51234",
		`msg="a \"quoted\" b" k='v w' x= =y ==`,
		"\x1b[31m\x1b[\x1b" + strings.Repeat("a ", 80),
		"[2001:db8::1]:99999 ::: 1.2.3.4/33 2026-02-30T25:61:61.9+99:99 h:0123456789abcdef",
		strings.Repeat("(", 100) + "1e+" + strings.Repeat(")", 100),
		"\xff\xfe µs 1µs 1μs 1h1m1s1ms1us1ns 0x 0xZ" + strings.Repeat("=", 40),
		"a\nb c\n\nd e f",
	} {
		f.Add(s, "shop", "web", uint8(1), false, int64(0))
	}
	f.Add("", "", "", uint8(9), true, int64(-1<<40))
	h := patHarness(f, nil)
	m := h.pm()
	m.lim = patLimits{scopes: 4, scopeTemplates: 12, templates: 30, newPerMin: 1000, newPerHour: 100000, leafClusters: 4,
		kids: 5, cache: 60}
	f.Fuzz(func(t *testing.T, msg, app, svc string, lvl uint8, host bool, dt int64) {
		var toks [maxPatTokens]tok
		cut := msg
		if len(cut) > maxPatLine {
			cut = cut[:maxPatLine]
		}
		n := tokenize(msg, &toks)
		if n > maxPatTokens {
			t.Fatalf("%d tokens", n)
		}
		for i := range n {
			k := toks[i]
			if k.ps > k.pe || k.pe > k.ss || k.ss > k.se || int(k.se) > len(cut) || int(k.ps)+int(k.kv) > len(cut) || k.code > mRest {
				t.Fatalf("token %d: %+v over %d bytes", i, k, len(cut))
			}
			if s := tokText(cut, k); len(s) > maxTokText || s == "" {
				t.Fatalf("token %q", s)
			}
		}
		_ = fingerprint(cut, toks[:n])
		h.clk.advance(time.Second)
		now := h.clk.now()
		ts := now.Add(time.Duration(dt % int64(48*time.Hour)))
		if host {
			app, svc = "", "" // as offer hands a host line over
		}
		var batch []patLine
		for _, l := range strings.Split(msg, "\n") {
			batch = append(batch, patLine{ts: ts.UnixNano(), host: host, lvl: lvl % 5, app: siem.Cut(app, 64),
				svc: siem.Cut(svc, 64), msg: siem.Cut(l, maxPatLine)})
		}
		m.step(batch)
		m.mu.Lock()
		m.tick(now)
		for _, tp := range m.byID {
			got, err := decodeTemplate(tp.encode())
			if err != nil || !slices.Equal(got.toks, tp.toks) || got.count != tp.count || got.hours != tp.hours {
				m.mu.Unlock()
				t.Fatalf("template %s doesn't read back: %v", tp.id, err)
			}
		}
		m.mu.Unlock()
		_, _ = decodeTemplate([]byte(msg))
		_, _, _ = decodeMeta([]byte(msg))
		checkPatBounds(t, m)
	})
}
