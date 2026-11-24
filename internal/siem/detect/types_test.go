package detect

import (
	"fmt"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

func thresholdRule(count int, window time.Duration) siem.Rule {
	return siem.Rule{ID: "custom.t", Type: siem.RuleThreshold, Query: "kind:ssh.login out:failure",
		GroupBy: "ip", Count: count, Window: window}
}

func TestThresholdFiresAtExactlyCount(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, thresholdRule(5, 10*time.Minute))
	for i := range 4 {
		h.feed(sshFail(time.Duration(i)*time.Minute, "203.0.113.7"))
	}
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("4 of 5: %d detections", len(ds))
	}
	h.feed(sshFail(4*time.Minute, "203.0.113.7"))
	ds := h.all(t)
	if len(ds) != 1 || ds[0].Count != 5 || ds[0].Key != "203.0.113.7" || ds[0].RuleID != "custom.t" {
		t.Fatalf("at 5: %+v", ds)
	}
	// Another address on its own doesn't add up with the first.
	for i := range 4 {
		h.feed(sshFail(5*time.Minute+time.Duration(i)*time.Second, "198.51.100.1"))
	}
	if ds := h.all(t); len(ds) != 1 {
		t.Fatalf("second key fired early: %+v", ds)
	}
}

func TestThresholdWindowEdge(t *testing.T) {
	for _, tc := range []struct {
		last time.Duration
		want int
	}{{10 * time.Minute, 0}, {10*time.Minute - time.Second, 1}} {
		t.Run(tc.last.String(), func(t *testing.T) {
			h := newHarness(t, false)
			h.only(t, thresholdRule(5, 10*time.Minute))
			for _, at := range []time.Duration{0, time.Minute, 2 * time.Minute, 3 * time.Minute, tc.last} {
				h.feed(sshFail(at, "203.0.113.7"))
			}
			if ds := h.all(t); len(ds) != tc.want {
				t.Fatalf("5th event at %s: %d detections, want %d", tc.last, len(ds), tc.want)
			}
		})
	}
}

func TestThresholdWeightsRepeatedLines(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, thresholdRule(5, 10*time.Minute))
	e := sshFail(0, "203.0.113.7")
	e.F["repeated"] = float64(4)
	h.feed(e)
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("weight 4 of 5 fired: %+v", ds)
	}
	h.feed(sshFail(time.Second, "203.0.113.7"))
	if ds := h.all(t); len(ds) != 1 || ds[0].Count != 5 {
		t.Fatalf("4+1: %+v", ds)
	}

	// The weight is capped at 1000.
	h2 := newHarness(t, false)
	h2.only(t, thresholdRule(1001, 10*time.Minute))
	big := sshFail(0, "203.0.113.8")
	big.F["repeated"] = float64(1e6)
	h2.feed(big)
	if ds := h2.all(t); len(ds) != 0 {
		t.Fatalf("repeated=1e6 counted past the cap: %+v", ds)
	}
	h2.feed(sshFail(time.Second, "203.0.113.8"))
	if ds := h2.all(t); len(ds) != 1 || ds[0].Count != 1001 {
		t.Fatalf("1000+1: %+v", ds)
	}
}

func TestThresholdNeedsTheKey(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, thresholdRule(1, 10*time.Minute))
	h.feed(sshFail(0, "")) // no IP
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("event without the group-by field fired: %+v", ds)
	}
}

// After firing, the window starts again: the next update needs Count more events, and it updates
// the same detection.
func TestThresholdRearmsAndCoalesces(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, thresholdRule(3, 10*time.Minute))
	for i := range 5 {
		h.feed(sshFail(time.Duration(i)*time.Second, "203.0.113.7"))
	}
	ds := h.all(t)
	if len(ds) != 1 || ds[0].Count != 3 {
		t.Fatalf("after 5 events: %+v", ds)
	}
	h.feed(sshFail(6*time.Second, "203.0.113.7"))
	ds = h.all(t)
	if len(ds) != 1 || ds[0].Count != 6 {
		t.Fatalf("after 6 events: %+v", ds)
	}
}

func distinctRule(count int, window time.Duration) siem.Rule {
	return siem.Rule{ID: "custom.d", Type: siem.RuleDistinct, Query: "kind:ssh.invalid_user", GroupBy: "ip",
		Field: "actor", Count: count, Window: window}
}

func invalidUser(at time.Duration, ip, user string) siem.Event {
	return ev(at, siem.SrcHost, siem.KindSSHInvalidUser, "", ip, user, map[string]any{"user": user})
}

func TestDistinctCountsValues(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, distinctRule(3, 10*time.Minute))
	h.feed(invalidUser(0, "203.0.113.7", "a"), invalidUser(time.Second, "203.0.113.7", "a"),
		invalidUser(2*time.Second, "203.0.113.7", "b"))
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("2 distinct of 3: %+v", ds)
	}
	h.feed(invalidUser(3*time.Second, "203.0.113.7", "c"))
	if ds := h.all(t); len(ds) != 1 || ds[0].Count != 3 {
		t.Fatalf("3 distinct: %+v", ds)
	}
}

func TestDistinctWindowEdge(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, distinctRule(3, 10*time.Minute))
	h.feed(invalidUser(0, "203.0.113.7", "a"), invalidUser(5*time.Minute, "203.0.113.7", "b"),
		invalidUser(10*time.Minute, "203.0.113.7", "c")) // a is exactly one window old: out
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("a value one window old still counted: %+v", ds)
	}
	h.feed(invalidUser(10*time.Minute+time.Second, "203.0.113.7", "d"))
	if ds := h.all(t); len(ds) != 1 {
		t.Fatalf("b, c, d: %+v", ds)
	}
}

func TestDistinctSetIsCapped(t *testing.T) {
	d := &distinct{}
	for i := range 1500 {
		d.add(uint64(i), int64(i), time.Hour)
	}
	if len(d.m) != maxDistinctValues {
		t.Fatalf("set holds %d values, cap %d", len(d.m), maxDistinctValues)
	}
	// One value seen over and over keeps the list bounded by the set.
	d2 := &distinct{}
	for i := range 100000 {
		d2.add(7, int64(i+1), time.Hour)
	}
	if d2.cost() > 2*len(d2.m)+64+1+len(d2.m) {
		t.Fatalf("repeated value: cost %d for %d values", d2.cost(), len(d2.m))
	}
}

func newValueRule(learn time.Duration) siem.Rule {
	return siem.Rule{ID: "custom.nv", Type: siem.RuleNewValue, Query: "kind:ssh.login out:success",
		GroupBy: "actor", Field: "geo.cc", Learn: learn}
}

func sshOK(at time.Duration, ip, user string, g *siem.Geo) siem.Event {
	e := ev(at, siem.SrcHost, siem.KindSSHLogin, siem.OutSuccess, ip, user, map[string]any{"method": "publickey", "user": user})
	e.Geo = g
	return e
}

func TestNewValueLearnsThenFires(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, newValueRule(time.Hour))
	ng, de, fr, us, gb := geo("NG", "Lagos", 6.45, 3.39), geo("DE", "Berlin", 52.52, 13.40),
		geo("FR", "Paris", 48.86, 2.35), geo("US", "Ashburn", 39.04, -77.49), geo("GB", "London", 51.5, -0.12)
	h.feed(sshOK(0, "198.51.100.1", "alice", ng))
	h.feed(sshOK(30*time.Minute, "198.51.100.2", "alice", de)) // still learning
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("fired while learning: %+v", ds)
	}
	h.feed(sshOK(time.Hour, "198.51.100.3", "alice", fr)) // exactly the learning period: fires
	ds := h.all(t)
	if len(ds) != 1 || ds[0].Key != "alice" || ds[0].Summary != "alice — new country FR" {
		t.Fatalf("new country after learning: %+v", ds)
	}
	h.feed(sshOK(2*time.Hour, "198.51.100.3", "alice", fr), sshOK(2*time.Hour, "198.51.100.4", "alice", ng))
	if ds := h.all(t); len(ds) != 1 {
		t.Fatalf("a value already seen fired: %+v", ds)
	}
	// A key seen for the first time is learned, not reported.
	h.feed(sshOK(3*time.Hour, "198.51.100.5", "bob", us))
	if ds := h.all(t); len(ds) != 1 {
		t.Fatalf("first value of a new key fired: %+v", ds)
	}
	h.feed(sshOK(4*time.Hour, "198.51.100.6", "bob", gb))
	if ds := h.all(t); len(ds) != 2 {
		t.Fatalf("bob's second country: %+v", ds)
	}
	// Without a location the field is missing: skipped.
	h.feed(sshOK(5*time.Hour, "198.51.100.7", "bob", nil))
	if ds := h.all(t); len(ds) != 2 {
		t.Fatalf("event without geo: %+v", ds)
	}
}

func TestNewValueSeenSetBounded(t *testing.T) {
	s := newSeen()
	for i := range maxSeen + 5000 {
		s.observe(fmt.Sprint("k", i), "v", int64(i)*int64(time.Second), 0)
	}
	if len(s.pairs) > maxSeen || len(s.keys) > maxSeen {
		t.Fatalf("seen sets: %d pairs, %d keys (cap %d)", len(s.pairs), len(s.keys), maxSeen)
	}
}

func anomalyRule() siem.Rule {
	return siem.Rule{ID: "custom.an", Type: siem.RuleAnomaly, Query: "kind:http.request f.status>=500",
		GroupBy: "f.host", Count: 10, Window: 10 * time.Minute, Factor: 3, Learn: 24 * time.Hour}
}

func errorReq(at time.Duration, host string) siem.Event {
	return ev(at, siem.SrcEdge, siem.KindHTTPRequest, "", "203.0.113.9", "", map[string]any{"status": float64(502), "host": host})
}

// history feeds perHour errors spread over each of hours hours, starting at t0.
func history(h *harness, host string, hours, perHour int) {
	for hr := range hours {
		for i := range perHour {
			h.feed(errorReq(time.Duration(hr)*time.Hour+time.Duration(i)*time.Hour/time.Duration(perHour), host))
		}
	}
}

func spike(h *harness, host string, at time.Duration, n int) {
	for i := range n {
		h.feed(errorReq(at+time.Duration(i)*time.Second, host))
	}
}

func TestAnomalyFiresAboveUsual(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, anomalyRule())
	history(h, "shop.example.com", 30, 2)
	spike(h, "shop.example.com", 30*time.Hour+30*time.Minute, 20)
	ds := h.all(t)
	if len(ds) != 1 || ds[0].Key != "shop.example.com" {
		t.Fatalf("spike after 30h of 2/h: %+v", ds)
	}
}

// The current window's events are not part of the usual rate (a short history isn't drowned by
// the surge itself).
func TestAnomalyCurrentWindowNotInHistory(t *testing.T) {
	h := newHarness(t, false)
	r := anomalyRule()
	r.Learn, r.Factor = 2*time.Hour, 20
	h.only(t, r)
	history(h, "shop.example.com", 2, 6) // 1 per 10 minutes
	spike(h, "shop.example.com", 2*time.Hour+30*time.Minute, 40)
	if ds := h.all(t); len(ds) != 1 {
		t.Fatalf("40 in 10m against a usual 1 (factor 20): %+v", ds)
	}
}

func TestAnomalyWarmUp(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, anomalyRule())
	history(h, "shop.example.com", 5, 2)
	spike(h, "shop.example.com", 5*time.Hour+30*time.Minute, 40)
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("fired before the learning period: %+v", ds)
	}
}

func TestAnomalyFloor(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, anomalyRule())
	history(h, "shop.example.com", 30, 1)
	spike(h, "shop.example.com", 30*time.Hour+30*time.Minute, 9) // far above usual, under Count
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("fired under the floor: %+v", ds)
	}
}

func TestAnomalyFactor(t *testing.T) {
	// 60 an hour = 10 per 10-minute window; ×3 = 30.
	for _, tc := range []struct {
		n    int
		want int
	}{{25, 0}, {40, 1}} {
		t.Run(fmt.Sprint(tc.n), func(t *testing.T) {
			h := newHarness(t, false)
			h.only(t, anomalyRule())
			history(h, "shop.example.com", 26, 60)
			spike(h, "shop.example.com", 26*time.Hour+30*time.Minute, tc.n)
			if ds := h.all(t); len(ds) != tc.want {
				t.Fatalf("%d in the window against a usual 10: %d detections, want %d", tc.n, len(ds), tc.want)
			}
		})
	}
}

func travelRule() siem.Rule {
	return siem.Rule{ID: "custom.tr", Type: siem.RuleTravel, Query: "kind:ssh.login out:success", GroupBy: "actor",
		SpeedKMH: 1000}
}

func TestTravel(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, travelRule())
	lagos, ibadan := geo("NG", "Lagos", 6.45, 3.39), geo("NG", "Ibadan", 7.38, 3.95)
	berlin, paris := geo("DE", "Berlin", 52.52, 13.40), geo("FR", "Paris", 48.86, 2.35)
	h.feed(sshOK(0, "198.51.100.1", "alice", lagos))
	h.feed(sshOK(time.Minute, "198.51.100.2", "alice", ibadan)) // fast but under 500 km
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("short hop fired: %+v", ds)
	}
	h.feed(sshOK(time.Minute+30*time.Second, "198.51.100.3", "alice", nil)) // no location: skipped
	h.feed(sshOK(61*time.Minute, "198.51.100.4", "alice", berlin))          // ~5000 km in an hour
	ds := h.all(t)
	if len(ds) != 1 || ds[0].Key != "alice" {
		t.Fatalf("Ibadan → Berlin in 1h: %+v", ds)
	}
	want := "alice — matching events from Ibadan, NG and Berlin, DE 1h apart (5093 km)"
	if ds[0].Summary != want {
		t.Errorf("summary %q, want %q", ds[0].Summary, want)
	}
	h.feed(sshOK(11*time.Hour+61*time.Minute, "198.51.100.5", "alice", paris)) // ~880 km in 11h
	if ds := h.all(t); len(ds) != 1 {
		t.Fatalf("slow trip fired: %+v", ds)
	}
}

func TestTravelSpeedBoundary(t *testing.T) {
	berlin, paris := geo("DE", "Berlin", 52.52, 13.40), geo("FR", "Paris", 48.86, 2.35)
	dist := haversineKM(berlin.Lat, berlin.Lon, paris.Lat, paris.Lon) // ~880 km
	for _, tc := range []struct {
		speed float64
		want  int
	}{{dist * 1.1, 0}, {dist * 0.9, 1}} {
		h := newHarness(t, false)
		r := travelRule()
		r.SpeedKMH = tc.speed
		h.only(t, r)
		h.feed(sshOK(0, "198.51.100.1", "alice", berlin), sshOK(time.Hour, "198.51.100.2", "alice", paris))
		if ds := h.all(t); len(ds) != tc.want {
			t.Errorf("speed limit %.0f km/h for %.0f km in 1h: %d detections, want %d", tc.speed, dist, len(ds), tc.want)
		}
	}
}

func sequenceRule() siem.Rule {
	return siem.Rule{ID: "custom.seq", Type: siem.RuleSequence, Query: "kind:ssh.login out:failure",
		Then: "kind:ssh.login out:success", GroupBy: "ip", Count: 3, Window: time.Hour}
}

func TestSequence(t *testing.T) {
	ip := "203.0.113.7"
	fail := func(at time.Duration) siem.Event { return sshFail(at, ip) }
	ok := func(at time.Duration) siem.Event { return sshOK(at, ip, "root", nil) }

	t.Run("too few", func(t *testing.T) {
		h := newHarness(t, false)
		h.only(t, sequenceRule())
		h.feed(fail(0), fail(time.Minute), ok(2*time.Minute), ok(3*time.Minute))
		if ds := h.all(t); len(ds) != 0 {
			t.Fatalf("2 failures then successes (a closing event is not a preceding one): %+v", ds)
		}
	})
	t.Run("count then closing", func(t *testing.T) {
		h := newHarness(t, false)
		h.only(t, sequenceRule())
		h.feed(fail(0), fail(time.Minute), fail(2*time.Minute), ok(3*time.Minute))
		ds := h.all(t)
		if len(ds) != 1 || ds[0].Count != 3 || len(ds[0].Evidence) != 4 {
			t.Fatalf("3 failures then success: %+v", ds)
		}
		h.feed(ok(4 * time.Minute)) // the sequence was consumed
		if ds := h.all(t); len(ds) != 1 || ds[0].Count != 3 {
			t.Fatalf("second success fired again: %+v", ds)
		}
	})
	t.Run("order", func(t *testing.T) {
		h := newHarness(t, false)
		h.only(t, sequenceRule())
		h.feed(ok(0), fail(time.Minute), fail(2*time.Minute), fail(3*time.Minute))
		if ds := h.all(t); len(ds) != 0 {
			t.Fatalf("success before the failures: %+v", ds)
		}
	})
	t.Run("window", func(t *testing.T) {
		h := newHarness(t, false)
		h.only(t, sequenceRule())
		h.feed(fail(0), fail(10*time.Minute), fail(20*time.Minute), ok(time.Hour))
		if ds := h.all(t); len(ds) != 0 {
			t.Fatalf("first failure one window before the success counted: %+v", ds)
		}
		h2 := newHarness(t, false)
		h2.only(t, sequenceRule())
		h2.feed(fail(time.Second), fail(10*time.Minute), fail(20*time.Minute), ok(time.Hour))
		if ds := h2.all(t); len(ds) != 1 {
			t.Fatalf("all three inside the window: %+v", ds)
		}
	})
	t.Run("other key", func(t *testing.T) {
		h := newHarness(t, false)
		h.only(t, sequenceRule())
		h.feed(fail(0), fail(time.Minute), fail(2*time.Minute), sshOK(3*time.Minute, "198.51.100.1", "root", nil))
		if ds := h.all(t); len(ds) != 0 {
			t.Fatalf("success from another address: %+v", ds)
		}
	})
}
