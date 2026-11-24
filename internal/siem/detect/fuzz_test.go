package detect

import (
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// FuzzEvent feeds hostile events through the pack and a rule of every type: nothing panics and the
// state stays within its bounds.
func FuzzEvent(f *testing.F) {
	f.Add("host", "ssh.login", "failure", "203.0.113.7", "root", "repeated", "5", 5.0, 6.45, 3.39, int64(0))
	f.Add("app", "auth.login", "success", "::1", "h:0123456789abcdef", "host", "x", -1.0, 91.0, 181.0, int64(-1))
	f.Add("edge", "http.request", "", "", "", "status", "500", 1e300, 0.0, 0.0, int64(1<<62))
	f.Add("siem", "siem.detection", "", "a\x00b", "<@>", "jail", "\xff", 0.0, -90.0, -180.0, int64(1))
	h := newHarness(f, false)
	rules := []siem.Rule{
		thresholdRule(2, time.Minute), distinctRule(2, time.Minute), newValueRule(0), anomalyRule(),
		travelRule(), sequenceRule(),
		{ID: "custom.all", Type: siem.RuleThreshold, Query: "lvl>=debug", GroupBy: "f.host", Count: 1, Window: time.Minute},
	}
	for _, p := range pack {
		rules = append(rules, p.Rule)
	}
	h.only(f, rules...)
	f.Fuzz(func(t *testing.T, src, kind, out, ip, actor, fk, fv string, rep, lat, lon float64, dt int64) {
		e := siem.Event{TS: h.clk.now().Add(time.Duration(dt % int64(48*time.Hour))), Src: src, Kind: kind, Out: out,
			IP: ip, Actor: actor, Msg: fv, F: map[string]any{fk: fv, "repeated": rep, "status": rep, "host": fv},
			Geo: &siem.Geo{Country: fv, City: fv, Lat: lat, Lon: lon, ASN: uint32(dt), Org: fv, Lists: []string{fv, "tor-exit"}}}
		h.clk.advance(time.Second)
		h.feedRaw(e)
		h.e.report(siem.Detection{RuleID: fk, RuleName: fv, Severity: siem.Severity(out), Key: actor, App: src,
			Summary: fv, Count: int(dt), Last: e.TS, Geo: e.Geo, MITRE: []string{fv}})
		h.e.flush(false)
		for _, st := range h.e.states {
			if len(st.keys) > maxKeys || st.entries > maxEntries {
				t.Fatalf("bounds: %d keys %d entries", len(st.keys), st.entries)
			}
		}
	})
}
