package detect

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
)

// The baseline tests run on a non-UTC server zone: hours of the week are local.
var tokyo = time.FixedZone("JST", 9*3600)

// blBase is a Monday 00:00 in tokyo, after the harness's t0 (events are fed in order from it).
var blBase = time.Date(2026, 11, 30, 0, 0, 0, 0, tokyo)

// at is day d (0: blBase's Monday), hh:mm in tokyo.
func at(d, hh, mm int) time.Time {
	return blBase.AddDate(0, 0, d).Add(time.Duration(hh)*time.Hour + time.Duration(mm)*time.Minute)
}

// blRule is a built-in baseline rule from the pack, changed by mods.
func blRule(id string, mods ...func(*siem.Rule)) siem.Rule {
	r := cloneRule(packByID[id].Rule)
	for _, m := range mods {
		m(&r)
	}
	return r
}

// hostFn is an Options.KnownHost.
type hostFn = func(string) (string, bool, bool)

// blHarness evaluates only rs, with hours in loc and known as Options.KnownHost.
func blHarness(t *testing.T, loc *time.Location, known hostFn, rs ...siem.Rule) *harness {
	t.Helper()
	h := newHarness(t, false, func(o *Options) { o.KnownHost = known })
	h.e.bl.loc = loc
	h.only(t, rs...)
	return h
}

// blReopen restarts the engine (saving as at shutdown) and puts loc and rs back.
func (h *harness) blReopen(t *testing.T, loc *time.Location, rs ...siem.Rule) {
	t.Helper()
	h.reopen(t)
	h.e.bl.loc = loc
	h.only(t, rs...)
}

var (
	chromeWin = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	chromeNew = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.1.0 Safari/537.36"
	firefoxLx = "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"
	safariIOS = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
	jpKDDI    = &siem.Geo{Country: "JP", City: "Tokyo", ASN: 2516, Org: "KDDI"}
	jpSoft    = &siem.Geo{Country: "JP", City: "Tokyo", ASN: 17676, Org: "SoftBank"}
	ngExample = &siem.Geo{Country: "NG", City: "Lagos", ASN: 37148, Org: "Example ISP"}
	deExample = &siem.Geo{Country: "DE", City: "Berlin", ASN: 3320, Org: "DTAG"}
	usExample = &siem.Geo{Country: "US", City: "Ashburn", ASN: 14618, Org: "Amazon"}
)

// mooringSignIn is a successful Mooring sign-in at when.
func mooringSignIn(when time.Time, actor string, g *siem.Geo, ua string) siem.Event {
	f := map[string]any{}
	if ua != "" {
		f["ua"] = ua
	}
	var geo *siem.Geo
	if g != nil {
		c := *g
		geo = &c
	}
	return siem.Event{TS: when.UTC(), Src: siem.SrcMooring, Kind: "mooring.login", Out: siem.OutSuccess,
		IP: "203.0.113.10", Actor: actor, F: f, Geo: geo}
}

func summaries(ds []siem.Detection) string {
	var s []string
	for _, d := range ds {
		s = append(s, fmt.Sprintf("%s [%d]: %s", d.RuleID, d.Count, d.Summary))
	}
	return strings.Join(s, "\n")
}

// weekdaySignIns signs alice in at 09:10 tokyo on the weekdays of days [from, to).
func weekdaySignIns(h *harness, from, to int, g *siem.Geo, ua string) {
	for d := from; d < to; d++ {
		if d%7 < 5 {
			h.feed(mooringSignIn(at(d, 9, 10), "alice", g, ua))
		}
	}
}

func TestBaselineSignInLearnsThenFires(t *testing.T) {
	r := blRule("baseline.signin_unusual")
	h := blHarness(t, tokyo, nil, r)
	weekdaySignIns(h, 0, 3, jpKDDI, chromeWin)
	// Learning: a sign-in departing in every way fires nothing (and is learned).
	h.feed(mooringSignIn(at(5, 3, 0), "alice", usExample, "curl/8.5.0")) // a Saturday
	weekdaySignIns(h, 3, 28, jpKDDI, chromeWin)                          // 21 sign-ins in all
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("while learning:\n%s", summaries(ds))
	}
	// A quiet day: the usual hour, country, network and client (a newer browser version).
	weekdaySignIns(h, 28, 29, jpKDDI, chromeNew)
	// One departure (a new network) is below count 2; so is a trip (a new country and network).
	h.feed(mooringSignIn(at(29, 9, 20), "alice", jpSoft, chromeWin))
	h.feed(mooringSignIn(at(30, 9, 20), "alice", deExample, chromeWin))
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("usual sign-ins and one departure:\n%s", summaries(ds))
	}
	h.feed(mooringSignIn(at(31, 9, 30), "alice", ngExample, firefoxLx))
	ds := h.detections(t, "baseline.signin_unusual")
	if len(ds) != 1 || ds[0].Key != "alice" || ds[0].Severity != siem.SevMedium ||
		ds[0].Summary != "alice — unusual sign-in: new country NG, new network AS37148 (Example ISP), new client Firefox on Linux" {
		t.Fatalf("a trip and a new client:\n%s", summaries(ds))
	}
	weekdaySignIns(h, 32, 36, jpKDDI, chromeWin)
	if ds := h.all(t); len(ds) != 1 {
		t.Fatalf("quiet days after:\n%s", summaries(ds))
	}
	// 03:00 Tuesday local (18:00 Monday UTC), a new client.
	h.feed(mooringSignIn(at(36, 3, 0), "alice", jpKDDI, safariIOS))
	ds = h.detections(t, "baseline.signin_unusual")
	if len(ds) != 2 || ds[0].Summary != "alice — unusual sign-in: new client Safari on iOS, unusual hour (03:00 Tue)" {
		t.Fatalf("new client at an unusual hour:\n%s", summaries(ds))
	}
	if a := h.alerts(); len(a) != 0 {
		t.Fatalf("a medium detection alerted: %+v", a)
	}
}

// signInsAt signs alice in at hh:10 tokyo on the days of [from, to) that keep (nil: every day).
func signInsAt(h *harness, from, to, hh int, keep func(d int) bool, g *siem.Geo, ua string) int {
	n := 0
	for d := from; d < to; d++ {
		if keep == nil || keep(d) {
			h.feed(mooringSignIn(at(d, hh, 10), "alice", g, ua))
			n++
		}
	}
	return n
}

// Owner decision: an hour is usual or unusual only once the account has minHourEvents sign-ins in
// its hours; hours are of the day, weekdays and weekends apart (not of the week), and a kind of day
// without minHourEvents of its own is compared by the hour of both kinds.
func TestBaselineSignInHours(t *testing.T) {
	monToWed := func(d int) bool { return d%7 < 3 }
	h := blHarness(t, tokyo, nil, blRule("baseline.signin_unusual", func(r *siem.Rule) { r.Count = 1; r.Learn = day }))
	if n := signInsAt(h, 0, 43, 9, monToWed, jpKDDI, chromeWin); n != minHourEvents-1 {
		t.Fatalf("setup: %d sign-ins", n)
	}
	// 19 sign-ins: no hour is unusual yet (03:00 is learned: 20 now).
	h.feed(mooringSignIn(at(44, 3, 0), "alice", jpKDDI, chromeWin))
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("an unusual hour with %d sign-ins:\n%s", minHourEvents-1, summaries(ds))
	}
	// A Thursday at the hour of the Monday to Wednesday sign-ins: a weekday's usual hour.
	h.feed(mooringSignIn(at(45, 9, 30), "alice", jpKDDI, chromeWin))
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("Thursday 09:30, usual on weekdays:\n%s", summaries(ds))
	}
	// 15:00 on a weekday: never seen. On a Saturday (no weekend history yet) the usual hour of the
	// weekdays is usual, 20:00 not.
	h.feed(mooringSignIn(at(45, 15, 0), "alice", jpKDDI, chromeWin))
	h.feed(mooringSignIn(at(47, 9, 30), "alice", jpKDDI, chromeWin))
	h.feed(mooringSignIn(at(47, 20, 30), "alice", jpKDDI, chromeWin))
	ds := h.all(t)
	if len(ds) != 2 || ds[0].Summary != "alice — unusual sign-in: unusual hour (20:00 Sat)" ||
		ds[1].Summary != "alice — unusual sign-in: unusual hour (15:00 Thu)" {
		t.Fatalf("unusual hours:\n%s", summaries(ds))
	}
}

// Owner decision: a new country and a new network from one sign-in are one departure (one trip).
func TestBaselineSignInTripIsOneDeparture(t *testing.T) {
	h := blHarness(t, tokyo, nil, blRule("baseline.signin_unusual"))
	weekdaySignIns(h, 0, 15, jpKDDI, chromeWin)
	h.feed(mooringSignIn(at(15, 9, 20), "alice", ngExample, chromeWin))
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("a trip counted as two departures:\n%s", summaries(ds))
	}
	h.feed(mooringSignIn(at(16, 9, 20), "alice", deExample, firefoxLx))
	if ds := h.all(t); len(ds) != 1 ||
		ds[0].Summary != "alice — unusual sign-in: new country DE, new network AS3320 (DTAG), new client Firefox on Linux" {
		t.Fatalf("a trip and a new client:\n%s", summaries(ds))
	}
}

// Office hours on weekdays, as a real history: an ordinary session is rarely at an "unusual hour".
func TestBaselineOfficeHoursRarelyUnusual(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	office := func(d int) (time.Time, int) {
		for (d+1)%7 == 0 || (d+1)%7 == 6 { // blBase is a Monday: weekends skipped
			d++
		}
		ts := at(d, 9+rng.Intn(9), rng.Intn(60))
		return ts, hourSlot(ts, tokyo)
	}
	for _, perDay := range []int{1, 2, 4} {
		fired, total := 0, 0
		for range 200 {
			var p habit
			for d := range 14 {
				for range perDay {
					ts, s := office(d)
					p.learn(ts, s, [maxSets]blValue{}, adminCaps)
				}
			}
			for d := 14; d < 21; d++ {
				ts, _ := office(d)
				total++
				if p.unusual(ts, tokyo) {
					fired++
				}
			}
		}
		if rate := float64(fired) / float64(total); rate > 0.02 {
			t.Errorf("%d sessions a day for two weeks: %.1f%% of the next week's at an unusual hour", perDay, 100*rate)
		}
	}
}

// learnAt learns an event at ts in p (sign-in caps, no values).
func learnAt(p *habit, ts time.Time) {
	p.learn(ts, hourSlot(ts, tokyo), [maxSets]blValue{}, signinCaps)
}

// isWeekend: blBase is a Monday, so day d is a Saturday at d%7 == 5 and a Sunday at 6.
func isWeekend(d int) bool { return d%7 >= 5 }

// Owner decision: an hour's share is measured within its own kind of day (weekday or weekend); while
// that kind has fewer than minHourEvents, the same hour of both kinds is a share of all events.
func TestBaselineHoursPerKindOfDay(t *testing.T) {
	// A heavy weekday user with a light but steady weekend habit (one session per weekend day,
	// 10:00–16:00): the weekend sessions are usual.
	rng := rand.New(rand.NewSource(7))
	for _, perWeekday := range []int{2, 6, 12} {
		fired, total := 0, 0
		for range 100 {
			var p habit
			for d := range 7 * 12 {
				if isWeekend(d) {
					learnAt(&p, at(d, 10+rng.Intn(6), rng.Intn(60)))
					continue
				}
				for range perWeekday {
					learnAt(&p, at(d, 9+rng.Intn(9), rng.Intn(60)))
				}
			}
			for d := 7 * 12; d < 7*12+7; d++ {
				if isWeekend(d) {
					total++
					if p.unusual(at(d, 10+rng.Intn(6), rng.Intn(60)), tokyo) {
						fired++
					}
				}
			}
		}
		if rate := float64(fired) / float64(total); rate > 0.02 {
			t.Errorf("%d weekday sessions a day: %.0f%% of the usual weekend sessions at an unusual hour", perWeekday, 100*rate)
		}
	}
	// 300 weekday sign-ins 09:00–14:00 and 19 on Saturdays at 15:10: the weekend has too few of its
	// own, so a Saturday hour is the same hour of both kinds of day: 10:30 is usual (the weekdays'),
	// 15:30 too (the Saturdays'), 03:30 not.
	var p habit
	for d := range 7 * 12 {
		if !isWeekend(d) {
			for i := range 5 {
				learnAt(&p, at(d, 9+i, 10))
			}
		}
	}
	for w := range 19 {
		learnAt(&p, at(7*w+5, 15, 10))
	}
	sat := at(7*20+5, 0, 0)
	if p.unusual(sat.Add(10*time.Hour+30*time.Minute), tokyo) || p.unusual(sat.Add(15*time.Hour+30*time.Minute), tokyo) ||
		!p.unusual(sat.Add(3*time.Hour+30*time.Minute), tokyo) {
		t.Error("19 weekend sign-ins: Saturday compared by the hour of both kinds of day")
	}
	// The 20th: the weekend is compared within itself, where 10:00 is unusual.
	learnAt(&p, at(7*19+5, 15, 10))
	if !p.unusual(sat.Add(10*time.Hour+30*time.Minute), tokyo) || p.unusual(sat.Add(15*time.Hour+30*time.Minute), tokyo) {
		t.Error("20 weekend sign-ins: Saturday 10:30 not unusual, or 15:30 not usual")
	}
	// A weekday user's only weekend hour, below 20 weekend events: usual (the reviewer's case).
	var q habit
	for _, s := range []int{9, 10, 11, 12} {
		q.hours[s] = 250
	}
	q.hours[24+10] = 19
	for _, c := range q.hours {
		q.hn += uint32(c)
	}
	if q.unusual(time.Date(2025, 11, 1, 10, 30, 0, 0, time.UTC), time.UTC) {
		t.Error("a habitual Saturday hour unusual below 20 weekend events")
	}
}

// When daylight saving time ends the repeated hour has the hour before and the hour after it as
// neighbours, like any other (three distinct hours, the repeated one counted once).
func TestBaselineHoursAcrossDST(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip(err)
	}
	var p habit
	p.hours[24+2] = 10   // weekend 02:xx
	p.hours[24+10] = 200 // weekend 10:xx
	p.hours[10] = 200    // weekdays 10:xx
	for _, c := range p.hours {
		p.hn += uint32(c)
	}
	ordinary := time.Date(2025, 10, 26, 1, 30, 0, 0, ny)    // a Sunday without a clock change
	first := time.Date(2025, 11, 2, 5, 30, 0, 0, time.UTC)  // Sunday 01:30 EDT, the first of two
	second := time.Date(2025, 11, 2, 6, 30, 0, 0, time.UTC) // Sunday 01:30 EST
	if p.unusual(ordinary, ny) || p.unusual(first, ny) || p.unusual(second, ny) {
		t.Fatalf("01:30: ordinary %v, first %v, second %v", p.unusual(ordinary, ny), p.unusual(first, ny), p.unusual(second, ny))
	}
	if got := nearSlots(first, ny); got != [3]int{24, 25, 26} {
		t.Fatalf("near slots %v", got)
	}
}

// Owner decision: at midnight the neighbouring hour may be of the other kind of day: Friday 23:00
// is next to Saturday 00:00, Sunday 23:00 to Monday 00:00.
func TestBaselineHoursAcrossMidnight(t *testing.T) {
	// A Monday-to-Friday late worker (23:10 every weekday night, 00:30 after it Tuesday to
	// Friday) who also works weekend afternoons (14:10, 20 of them).
	var p habit
	for d := range 70 {
		switch {
		case isWeekend(d):
			learnAt(&p, at(d, 14, 10))
		default:
			learnAt(&p, at(d, 23, 10))
			if d%7 != 0 {
				learnAt(&p, at(d, 0, 30))
			}
		}
	}
	if sat := at(75, 0, 30); sat.Weekday() != time.Saturday || p.unusual(sat, tokyo) || p.unusual(at(71, 0, 30), tokyo) {
		t.Error("Friday night going on past midnight (Saturday 00:30), or Tuesday 00:30, unusual")
	}
	if !p.unusual(at(75, 3, 30), tokyo) {
		t.Error("Saturday 03:30 usual")
	}
	// A Sunday 23:10 habit: Monday 00:30 is next to it.
	var q habit
	for w := range 25 {
		learnAt(&q, at(7*w+6, 23, 10))
		for d := range 5 {
			learnAt(&q, at(7*w+d, 10, 10))
		}
	}
	if mon := at(7*25, 0, 30); mon.Weekday() != time.Monday || q.unusual(mon, tokyo) || !q.unusual(at(7*25+1, 0, 30), tokyo) {
		t.Error("Monday 00:30 after the Sunday 23:00 habit unusual, or Tuesday 00:30 not")
	}
}

// count is the number of departures needed; learn the account's warm-up.
func TestBaselineSignInCountAndLearn(t *testing.T) {
	one := blRule("baseline.signin_unusual", func(r *siem.Rule) { r.Count = 1; r.Learn = 21 * day })
	h := blHarness(t, tokyo, nil, one)
	weekdaySignIns(h, 0, 15, jpKDDI, chromeWin)
	h.feed(mooringSignIn(at(15, 9, 20), "alice", jpSoft, chromeWin))
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("one departure within learn 21d:\n%s", summaries(ds))
	}
	weekdaySignIns(h, 16, 22, jpKDDI, chromeWin)
	h.feed(mooringSignIn(at(22, 9, 20), "alice", deExample, chromeWin))
	ds := h.all(t)
	if len(ds) != 1 || ds[0].Summary != "alice — unusual sign-in: new country DE, new network AS3320 (DTAG)" {
		t.Fatalf("count 1 after learn:\n%s", summaries(ds))
	}
	weekdaySignIns(h, 23, 24, jpKDDI, chromeWin)
	h.feed(mooringSignIn(at(23, 9, 25), "alice", jpKDDI, firefoxLx))
	if ds := h.all(t); len(ds) != 2 {
		t.Fatalf("count 1: a new client alone fires:\n%s", summaries(ds))
	}
}

// An account with too few sign-ins never fires; values an account never had (no location, no
// client) are learned without firing.
func TestBaselineSignInNeedsHistory(t *testing.T) {
	h := blHarness(t, tokyo, nil, blRule("baseline.signin_unusual", func(r *siem.Rule) { r.Count = 1 }))
	h.feed(mooringSignIn(at(0, 9, 0), "bob", nil, ""))
	h.feed(mooringSignIn(at(1, 9, 0), "bob", nil, ""))
	h.feed(mooringSignIn(at(20, 3, 0), "bob", ngExample, firefoxLx)) // 2 sign-ins learned
	h.feed(mooringSignIn(at(20, 9, 0), "carol", nil, ""))
	for d := 0; d < 16; d++ {
		h.feed(mooringSignIn(at(21+d, 9, 0), "dave", nil, ""))
	}
	h.feed(mooringSignIn(at(37, 9, 5), "dave", ngExample, firefoxLx)) // first location and client
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("no history to depart from:\n%s", summaries(ds))
	}
	h.feed(mooringSignIn(at(37, 9, 10), "dave", deExample, firefoxLx))
	if ds := h.all(t); len(ds) != 1 || !strings.Contains(ds[0].Summary, "new country DE") {
		t.Fatalf("departure from learned values:\n%s", summaries(ds))
	}
}

// Accounts of different systems are learned apart: an app's alice is not Mooring's alice.
func TestBaselineSignInScopes(t *testing.T) {
	h := blHarness(t, tokyo, nil, blRule("baseline.signin_unusual"))
	weekdaySignIns(h, 0, 15, jpKDDI, chromeWin)
	app := func(when time.Time, app string, g *siem.Geo) siem.Event {
		e := siem.Event{TS: when.UTC(), Src: siem.SrcApp, App: app, Kind: "auth.login", Out: siem.OutSuccess,
			IP: "198.51.100.7", Actor: "alice", F: map[string]any{"ua": firefoxLx}, Geo: g}
		return e
	}
	// The shop app's alice signs in from Nigeria at night: her own first sign-ins.
	for d := 15; d < 18; d++ {
		h.feed(app(at(d, 2, 0), "shop", ngExample))
	}
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("another system's account compared with Mooring's:\n%s", summaries(ds))
	}
	if h.e.bl.signin.peek("mooring|alice") == nil || h.e.bl.signinApp.peek("app:shop|alice") == nil {
		t.Fatal("scoped keys missing")
	}
	// The shop app's alice keeps signing in from Nigeria for two weeks: Nigeria is hers, not
	// Mooring's alice's, whose first sign-in from there still departs (new country and network).
	for d := 18; d < 34; d++ {
		h.feed(app(at(d, 2, 0), "shop", ngExample))
		weekdaySignIns(h, d, d+1, jpKDDI, chromeWin)
	}
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("the app account's learned pattern:\n%s", summaries(ds))
	}
	h.feed(mooringSignIn(at(35, 9, 15), "alice", ngExample, firefoxLx))
	ds := h.all(t)
	if len(ds) != 1 || ds[0].Key != "alice" || ds[0].App != "" ||
		ds[0].Summary != "alice — unusual sign-in: new country NG, new network AS37148 (Example ISP), new client Firefox on Linux" {
		t.Fatalf("Mooring alice compared with the app account's history:\n%s", summaries(ds))
	}
	// SSH and app logins match the query too; lockouts and other .login_ kinds don't.
	for _, e := range []siem.Event{
		{Src: siem.SrcHost, Kind: siem.KindSSHLogin, Out: siem.OutSuccess, Actor: "root"},
		{Src: siem.SrcApp, App: "shop", Kind: "admin.login", Out: siem.OutSuccess, Actor: "staff"},
		{Src: siem.SrcMooring, Kind: "mooring.login_lockout", Out: siem.OutSuccess, Actor: "x1"},
		{Src: siem.SrcMooring, Kind: "mooring.login", Out: siem.OutFailure, Actor: "x2"},
		{Src: siem.SrcHost, Kind: siem.KindSSHLogin, Out: siem.OutSuccess, Actor: "x3", F: map[string]any{"sender_mismatch": true}},
	} {
		e.TS = at(35, 10, 0).UTC()
		h.feed(e)
	}
	if h.e.bl.signin.peek("host|root") == nil || h.e.bl.signinApp.peek("app:shop|staff") == nil {
		t.Error("an SSH or app login not learned in its table")
	}
	for _, k := range []string{"mooring|x1", "mooring|x2", "host|x3"} {
		if h.e.bl.signin.peek(k) != nil || h.e.bl.signinApp.peek(k) != nil {
			t.Errorf("%s learned: not a sign-in", k)
		}
	}
}

func TestBaselineHourOfWeekIsLocal(t *testing.T) {
	ts := time.Date(2026, 12, 7, 18, 30, 0, 0, time.UTC) // Monday 18:30 UTC = Tuesday 03:30 in tokyo
	if got, want := slotOf(ts, tokyo), 2*24+3; got != want {
		t.Fatalf("slot in tokyo %d, want %d", got, want)
	}
	if got, want := slotOf(ts, time.UTC), 1*24+18; got != want {
		t.Fatalf("slot in UTC %d, want %d", got, want)
	}
	if hourName(ts, tokyo) != "03:00 Tue" || hourSpan(ts.Truncate(time.Hour), tokyo) != "03:00–04:00 Tue" {
		t.Fatalf("names: %s, %s", hourName(ts, tokyo), hourSpan(ts.Truncate(time.Hour), tokyo))
	}
	// The hours of the sign-in and admin baselines: of the day, weekend days after the weekdays.
	sat := time.Date(2026, 12, 12, 2, 30, 0, 0, time.UTC) // Saturday 11:30 in tokyo
	if hourSlot(ts, tokyo) != 3 || hourSlot(ts, time.UTC) != 18 || hourSlot(sat, tokyo) != 24+11 ||
		hourSlot(sat.Add(-12*time.Hour), tokyo) != 23 {
		t.Fatalf("hour slots %d %d %d %d", hourSlot(ts, tokyo), hourSlot(ts, time.UTC), hourSlot(sat, tokyo),
			hourSlot(sat.Add(-12*time.Hour), tokyo))
	}
	// Weeks run Sunday to Saturday in the zone.
	sat = time.Date(2026, 12, 12, 23, 0, 0, 0, tokyo)
	if weekOf(sat, tokyo) != weekOf(time.Date(2026, 12, 6, 0, 0, 0, 0, tokyo), tokyo) ||
		weekOf(sat.Add(time.Hour), tokyo) != weekOf(sat, tokyo)+1 {
		t.Fatal("week boundaries")
	}
	if weekOf(sat.UTC(), time.UTC) != weekOf(sat.Add(time.Hour), time.UTC) {
		t.Fatal("UTC weeks: Sunday 00:00 tokyo is Saturday 15:00 UTC, the same UTC week as the hour before")
	}
	_ = weekOf(time.Date(1960, 1, 1, 0, 0, 0, 0, time.UTC), time.UTC) // before 1970: floor division
	if weekOf(time.Date(1969, 12, 27, 0, 0, 0, 0, time.UTC), time.UTC) != weekOf(time.Date(1969, 12, 28, 0, 0, 0, 0, time.UTC), time.UTC)-1 {
		t.Fatal("week numbering before 1970")
	}
}

func TestBaselineUAFamily(t *testing.T) {
	for ua, want := range map[string]string{
		chromeWin: "Chrome on Windows",
		firefoxLx: "Firefox on Linux",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36":                   "Chrome on Android",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1": "Safari on iOS",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.86": "Edge on macOS",
		"curl/8.5.0":                     "curl",
		"python-requests/2.32.3":         "Python",
		"Go-http-client/2.0":             "Go",
		"okhttp/4.12.0":                  "okhttp",
		"MyApp/1.2 (iPhone; iOS 17.0)":   "myapp on iOS",
		"<@everyone>":                    "other",
		"":                               "",
		strings.Repeat("a", 30) + "/1.0": "other",
	} {
		if got := uaFamily(ua); got != want {
			t.Errorf("uaFamily(%.40q) = %q, want %q", ua, got, want)
		}
	}
	if programOf("/usr/bin/systemctl restart web") != "systemctl" || programOf("  nc -l 4444") != "nc" || programOf("/") != "" {
		t.Error("programOf")
	}
	if safeToken("nc", 32) != "nc" || safeToken("<@x>", 32) != "" || safeToken(strings.Repeat("a", 33), 32) != "" {
		t.Error("safeToken")
	}
}

// A value set full of values forgets the one seen least recently; the hours halve at 255.
func TestBaselineHabitBounds(t *testing.T) {
	var p habit
	t1 := at(0, 9, 0)
	for i := range 1000 {
		v := [maxSets]blValue{valueOf("cc", fmt.Sprint("C", i)), valueOf("asn", fmt.Sprint(i)), valueOf("ua", fmt.Sprint("u", i))}
		p.learn(t1.Add(time.Duration(i)*time.Hour), hourSlot(t1, tokyo), v, signinCaps)
	}
	for i, c := range signinCaps {
		if len(p.sets[i]) != c {
			t.Errorf("set %d holds %d values, cap %d", i, len(p.sets[i]), c)
		}
	}
	if !p.known(0, valueOf("cc", "C999").h) || p.known(0, valueOf("cc", "C0").h) {
		t.Error("the least recently seen value is the one forgotten")
	}
	if p.hours[hourSlot(t1, tokyo)] > 255 || p.hn > 255 || p.n != 1000 {
		t.Errorf("hours %d, sum %d, n %d", p.hours[hourSlot(t1, tokyo)], p.hn, p.n)
	}
	got, err := decodeHabit(p.encode(), signinCaps)
	if err != nil || got.n != p.n || got.hn != p.hn || got.first != p.first || len(got.sets[1]) != maxNetworks {
		t.Fatalf("round trip: %v", err)
	}
	for _, bad := range [][]byte{nil, {2}, p.encode()[:20], append(p.encode(), 0)} {
		if _, err := decodeHabit(bad, signinCaps); err == nil {
			t.Errorf("decodeHabit(%x…) accepted", bad[:min(len(bad), 4)])
		}
	}
	// A set saved under a higher cap (a cap lowered since) keeps the values seen most recently.
	small, err := decodeHabit(p.encode(), [maxSets]int{4, 2, 0})
	if err != nil || len(small.sets[0]) != 4 || len(small.sets[1]) != 2 || small.sets[2] != nil || small.n != p.n || small.hn != p.hn {
		t.Fatalf("trimmed: %v, sets %d %d %d", err, len(small.sets[0]), len(small.sets[1]), len(small.sets[2]))
	}
	for i := 996; i < 1000; i++ {
		if !small.known(0, valueOf("cc", fmt.Sprint("C", i)).h) {
			t.Errorf("C%d (seen recently) trimmed", i)
		}
	}
	if !small.known(1, valueOf("asn", "999").h) || !small.known(1, valueOf("asn", "998").h) {
		t.Error("the networks seen most recently trimmed")
	}
}

// sudo runs a sudo command as alice at when, through the real auth.log parser.
func sudo(t *testing.T, h *harness, when time.Time, target, cmd string) {
	t.Helper()
	h.host(t, when.Sub(t0), "sudo", fmt.Sprintf("   alice : TTY=pts/0 ; PWD=/home/alice ; USER=%s ; COMMAND=%s", target, cmd), nil)
}

func TestBaselineAdminLearnsThenFires(t *testing.T) {
	h := blHarness(t, tokyo, nil, blRule("baseline.admin_unusual"))
	work := func(d int) {
		sudo(t, h, at(d, 10, 0), "root", "/usr/bin/systemctl restart web")
		sudo(t, h, at(d, 10, 5), "root", "/usr/bin/journalctl -u web")
	}
	for d := range 14 {
		if d%7 < 5 {
			work(d)
		}
		if d == 5 {
			sudo(t, h, at(d, 3, 0), "postgres", "/usr/bin/apt upgrade") // learning (a Saturday): learned, silent
		}
	}
	work(14)
	h.host(t, at(14, 10, 30).Sub(t0), "su[42]", "pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)", nil)
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("learning and a usual day:\n%s", summaries(ds))
	}
	sudo(t, h, at(14, 10, 40), "root", "/usr/bin/nc -l 4444")
	ds := h.detections(t, "baseline.admin_unusual")
	if len(ds) != 1 || ds[0].Severity != siem.SevHigh || ds[0].Key != "alice" ||
		ds[0].Summary != "server user alice — unusual sudo or su: new program nc" {
		t.Fatalf("new program:\n%s", summaries(ds))
	}
	if a := h.alerts(); len(a) != 1 || a[0].Level != alert.LevelWarning ||
		!strings.HasPrefix(a[0].Summary, "Unusual sudo or su: server user alice — unusual sudo or su: new program nc") {
		t.Fatalf("high detection alert: %+v", a)
	}
	sudo(t, h, at(15, 10, 0), "www-data", "/usr/bin/systemctl status web")
	if ds := h.all(t); len(ds) != 2 || ds[0].Summary != "server user alice — unusual sudo or su: new target user www-data" {
		t.Fatalf("new target user:\n%s", summaries(ds))
	}
	// A new program as root at an hour alice never used sudo at on a weekday: the hour is told too.
	sudo(t, h, at(16, 3, 30), "root", "/usr/bin/tcpdump -i any")
	if ds := h.all(t); len(ds) != 3 ||
		ds[0].Summary != "server user alice — unusual sudo or su: new program tcpdump, root at an unusual hour (03:00 Wed)" {
		t.Fatalf("new program, root at an unusual hour:\n%s", summaries(ds))
	}
	// Owner decision: root at an unusual hour alone (a known program) never fires.
	sudo(t, h, at(17, 1, 0), "root", "/usr/bin/journalctl -u web")
	// A known program for a known non-root target at night.
	sudo(t, h, at(17, 5, 40), "postgres", "/usr/bin/apt upgrade")
	if ds := h.all(t); len(ds) != 3 {
		t.Fatalf("root at an unusual hour alone, or a known program and target at night:\n%s", summaries(ds))
	}
	// Forged lines (a non-root sender wrote "sudo") are not taken.
	h.feed(siem.Event{TS: at(17, 10, 0).UTC(), Src: siem.SrcHost, Kind: siem.KindSudo, Out: siem.OutSuccess, Actor: "alice",
		F: map[string]any{"command": "/tmp/evil", "target_user": "root", "sender_mismatch": true}})
	// An ambiguous line has no program or target: only its hour is learned.
	h.feed(siem.Event{TS: at(17, 10, 1).UTC(), Src: siem.SrcHost, Kind: siem.KindSudo, Out: siem.OutSuccess, Actor: "alice",
		F: map[string]any{"ambiguous": true}})
	if ds := h.all(t); len(ds) != 3 {
		t.Fatalf("forged or ambiguous lines:\n%s", summaries(ds))
	}
}

func TestBaselineAdminLearnPeriod(t *testing.T) {
	h := blHarness(t, tokyo, nil, blRule("baseline.admin_unusual", func(r *siem.Rule) { r.Learn = 3 * day }))
	for d := range 3 {
		sudo(t, h, at(d, 10, 0), "root", "/usr/bin/systemctl restart web")
	}
	sudo(t, h, at(2, 11, 0), "root", "/usr/bin/vim /etc/hosts") // under 3 days since the first
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("within learn:\n%s", summaries(ds))
	}
	sudo(t, h, at(3, 10, 0), "root", "/usr/bin/curl http://x")
	// 4 sudo commands: too few for an hour to be unusual.
	if ds := h.all(t); len(ds) != 1 || !strings.HasSuffix(ds[0].Summary, ": new program curl") {
		t.Fatalf("after learn 3d:\n%s", summaries(ds))
	}
	// A program name that isn't a plain token is not shown.
	sudo(t, h, at(3, 12, 0), "root", "/tmp/<@everyone>")
	if ds := h.all(t); !strings.HasSuffix(ds[0].Summary, ": new program") || strings.Contains(ds[0].Summary, "everyone") {
		t.Fatalf("unsafe program name shown:\n%s", summaries(ds))
	}
}

// Owner decision: an admin's evening sign-in from home (a new network; the hours not counted yet)
// and the usual sudo as root at that hour fire nothing (so no account-takeover incident either).
func TestBaselineEveningAdminIsNoIncident(t *testing.T) {
	h := blHarness(t, tokyo, nil, blRule("baseline.signin_unusual"), blRule("baseline.admin_unusual"))
	h.e.lim.incidents = true
	ssh := func(when time.Time, g *siem.Geo) {
		c := *g
		h.feed(siem.Event{TS: when.UTC(), Src: siem.SrcHost, Kind: siem.KindSSHLogin, Out: siem.OutSuccess,
			IP: "203.0.113.50", Actor: "alice", F: map[string]any{"method": "publickey", "user": "alice"}, Geo: &c})
	}
	for d := range 15 {
		if d%7 < 5 {
			ssh(at(d, 9, 10), jpKDDI)
			sudo(t, h, at(d, 9, 20), "root", "/usr/bin/systemctl restart web")
		}
	}
	h.alerts()
	// Day 15 (a Tuesday), 21:00 from home (another Japanese ISP), then the usual command as root.
	ssh(at(15, 21, 0), jpSoft)
	sudo(t, h, at(15, 21, 5), "root", "/usr/bin/systemctl restart web")
	h.e.flush(true)
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("an admin's evening:\n%s", summaries(ds))
	}
	if a := h.alerts(); len(a) != 0 {
		t.Fatalf("alerts: %+v", a)
	}
	// Two weeks on, the hours count: root at 03:00 alone still doesn't fire.
	for d := 16; d < 29; d++ {
		if d%7 < 5 {
			sudo(t, h, at(d, 9, 20), "root", "/usr/bin/systemctl restart web")
		}
	}
	if x := h.e.bl.admin.peek("alice"); x == nil || !x.v.unusual(at(29, 3, 5), tokyo) {
		t.Fatal("setup: 03:00 not an unusual hour for alice")
	}
	sudo(t, h, at(29, 3, 5), "root", "/usr/bin/systemctl restart web")
	if ds := h.detections(t, "baseline.admin_unusual"); len(ds) != 0 {
		t.Fatalf("root at an unusual hour alone:\n%s", summaries(ds))
	}
}
