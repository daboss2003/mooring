package detect

import (
	"slices"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// sentReq is an edge request to a sign-in path with what sent it: fetch metadata (site), a
// User-Agent (ua).
func sentReq(when time.Time, ip, site, ua string) siem.Event {
	e := edgeReq(when, ip, "/wp-login.php", 200)
	if site != "" {
		e.F["fetch_site"] = site
	}
	if ua != "" {
		e.F["ua"] = ua
	}
	return e
}

// learnAddrOn is learnAddr on day d (10 requests an hour, every authEvery-th to /login).
func learnAddrOn(h *harness, ip string, d, authEvery int) {
	for i := range 240 {
		path := "/api/v1/items"
		if i%authEvery == 0 {
			path = "/login"
		}
		h.feed(edgeReq(at(d, 0, 0).Add(time.Duration(i)*6*time.Minute), ip, path, 200))
	}
}

// ipRespHarness evaluates baseline.ip_behaviour alone, with a block response (the pack gives it
// none), and returns the block requests made.
func ipRespHarness(t *testing.T) (*harness, *fakeResponder) {
	t.Helper()
	h, fr := respHarness(t, false)
	h.only(t, blRule("baseline.ip_behaviour", func(r *siem.Rule) { r.Response = blockResp(time.Hour) }))
	return h, fr
}

// Owner decision: the address baseline's block follows what sent the requests its firing counted,
// like the other counting rules': fetch metadata or a browser's agent on any of them → a
// recommendation; else automatic. (Fetch metadata meant no request before v0.33.1: a scanner can
// send the header too.)
func TestBaselineIPBlockFollowsSenders(t *testing.T) {
	if p := packByID["baseline.ip_behaviour"]; p.Response.Action != "" {
		t.Fatalf("the pack gives baseline.ip_behaviour a response: %+v", p.Response)
	}
	h, fr := ipRespHarness(t)
	if c := h.e.rules.Load().byID["baseline.ip_behaviour"]; !c.autoBlock || len(c.respOK) != 1 || c.respOK[0] != siem.ResponseBlock {
		t.Fatalf("autoBlock %v, responses %v", c.autoBlock, c.respOK)
	}
	for i, tc := range []struct {
		name string
		// Request which of the burst's 50 (-1: none) came with fetch metadata, with a browser's agent.
		site, agent int
		want        string
	}{
		{"scripted requests", -1, -1, "auto"},
		{"a browser's agent on one counted request", -1, 7, "recommend"},
		{"the last one with a browser's agent", -1, 49, "recommend"},
		{"fetch metadata on one counted request", 7, -1, "recommend"},
		{"fetch metadata on the last", 49, -1, "recommend"},
		{"fetch metadata and a browser's agent", 3, 30, "recommend"},
		{"a browser's agent in the first slot counted", -1, 0, "recommend"},
		{"fetch metadata in the first slot counted", 0, -1, "recommend"},
	} {
		ip, d := ipv4(i+1), 2*i // each address on days of its own
		learnAddrOn(h, ip, d, 20)
		for j := range 50 {
			site, ua := "", "curl/8.5.0"
			if j == tc.site {
				site = "cross-site"
			}
			if j == tc.agent {
				ua = chromeWin
			}
			h.feed(sentReq(at(d+1, 1, 0).Add(time.Duration(j)*5*time.Second), ip, site, ua))
		}
		h.e.flush(false)
		if ds := h.detections(t, "baseline.ip_behaviour"); len(ds) != i+1 {
			t.Fatalf("%s: %d detections", tc.name, len(ds))
		}
		var got []siem.ResponseRequest
		for _, r := range fr.all() {
			if r.Target == ip {
				got = append(got, r)
			}
		}
		if len(got) != 1 || got[0].Action != siem.ResponseBlock || got[0].Automatic != (tc.want == "auto") ||
			got[0].Duration != time.Hour {
			t.Errorf("%s: want %s, got %+v", tc.name, tc.want, got)
		}
	}
}

// Only the requests the firing counted say: a browser's request before the window (now part of the
// usual mix) doesn't hold the block back, and after a firing the next one is judged on its own
// requests.
func TestBaselineIPSendersOfTheWindowOnly(t *testing.T) {
	h, fr := ipRespHarness(t)
	ip := "203.0.113.7"
	learnAddr(h, ip, 20)
	// 12 minutes before the burst: outside its 10-minute window.
	h.feed(sentReq(at(1, 0, 48), ip, "same-origin", chromeWin), sentReq(at(1, 0, 48).Add(time.Second), ip, "", chromeWin))
	for j := range 50 {
		h.feed(sentReq(at(1, 1, 0).Add(time.Duration(j)*5*time.Second), ip, "", ""))
	}
	h.e.flush(false)
	if got := fr.all(); len(got) != 1 || !got[0].Automatic || got[0].Target != ip {
		t.Fatalf("browser requests before the window: %+v", got)
	}

	// A firing a browser's request was counted in only recommends; the window it fired on is folded
	// into the usual mix, so the next 50 scripted requests fire on their own and block. The requests
	// are 7 s apart so the second firing is past blockAskEvery after the first.
	ip = "198.51.100.9"
	learnAddrOn(h, ip, 2, 1000) // 1 of 240: with the first window folded in, 51 of 290
	for j := range 100 {
		site := ""
		if j == 20 {
			site = "cross-site"
		}
		h.feed(sentReq(at(3, 2, 0).Add(time.Duration(j)*7*time.Second), ip, site, ""))
		h.e.flush(false)
		var auto []bool
		for _, r := range fr.all() {
			if r.Target == ip {
				auto = append(auto, r.Automatic)
			}
		}
		want := []bool(nil)
		switch {
		case j == 99:
			want = []bool{false, true}
		case j >= 49:
			want = []bool{false}
		}
		if !slices.Equal(auto, want) {
			t.Fatalf("after request %d: block requests (automatic) %v, want %v", j, auto, want)
		}
	}
	for _, d := range h.detections(t, "baseline.ip_behaviour") {
		if d.Key == ip && d.Count != 100 {
			t.Fatalf("two firings of 50 in one detection: %+v", d)
		}
	}
}

// A restart keeps the window's requests in the usual mix only (encode): the count of a browser's
// request isn't kept as a counted one while what sent it is forgotten. The firing after a restart
// needs Count new requests, each judged.
func TestBaselineIPSendersAcrossRestart(t *testing.T) {
	h, fr := ipRespHarness(t)
	rule := h.e.rules.Load().byID["baseline.ip_behaviour"].r
	for i, site := range []string{"", "cross-site"} {
		ip, d := ipv4(i+1), 2*i
		learnAddrOn(h, ip, d, 20)
		burst := at(d+1, 1, 0)
		h.feed(sentReq(burst, ip, "cross-site", chromeWin))
		for j := 1; j < 40; j++ {
			h.feed(sentReq(burst.Add(time.Duration(j)*time.Second), ip, "", ""))
		}
		h.reopen(t)
		h.only(t, rule)
		// 10 more would have made the 50 before the restart.
		for j := 40; j < 89; j++ {
			h.feed(sentReq(burst.Add(time.Duration(j)*time.Second), ip, "", ""))
		}
		h.e.flush(false)
		if ds := h.detections(t, "baseline.ip_behaviour"); len(ds) != i || len(fr.all()) != i {
			t.Fatalf("49 requests after the restart: %d detections, requests %+v", len(ds), fr.all())
		}
		h.feed(sentReq(burst.Add(89*time.Second), ip, site, ""))
		h.e.flush(false)
		got := fr.all()
		// The 50th scripted: automatic; with fetch metadata: a recommendation.
		if len(got) != i+1 || got[i].Automatic != (site == "") || got[i].Target != ip {
			t.Fatalf("the 50th request after the restart (fetch metadata %q): %+v", site, got)
		}
	}
}

// A slot that can count no more still records what sent a request.
func TestBaselineIPSenderInAFullSlot(t *testing.T) {
	var x addrMix
	w := 10 * time.Minute
	t1 := int64(100 * time.Hour)
	x.add(t1, w, true, false, false)
	x.win[(t1/x.slotW)%ipSlots].n = 1<<16 - 1
	x.add(t1+1, w, true, false, false)
	x.mark(t1+1, true, false)
	x.add(t1+2, w, true, false, false)
	x.mark(t1+2, false, true)
	if n, _, _, _, browser, agent := x.window(t1 + 2); n != 1<<16-1 || !browser || !agent {
		t.Fatalf("n %d browser %v agent %v", n, browser, agent)
	}
	// A request older than the window goes to the usual mix at once: it is not one of the counted.
	var y addrMix
	y.add(t1, w, true, false, false)
	old := t1 - int64(w)
	y.add(old, w, true, false, false)
	y.mark(old, true, true)
	if n, _, _, _, browser, agent := y.window(t1); n != 1 || browser || agent {
		t.Fatalf("n %d browser %v agent %v", n, browser, agent)
	}
}
