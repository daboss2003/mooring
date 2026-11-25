package detect

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// The sign-in and server-admin baselines learn a habit per account or server user: the hours of
// the day it acts in, weekdays and weekend days apart, and a few sets of values seen (countries,
// networks and clients of its sign-ins; programs and target users of its sudo and su). Values are
// 64-bit hashes with the hour last seen; a full set forgets the value seen least recently.

const (
	daySlots   = 2 * 24 // the hours of a weekday (Monday to Friday), then of a weekend day
	minLearned = 3      // events an account or server user needs before it can fire
	// Events an account or server user needs in its hours (since they were last reset: a time-zone
	// change) before an hour can be unusual.
	minHourEvents = 20

	// Values kept per account (signin) and per server user (admin), by set.
	maxCountries = 16
	maxNetworks  = 32
	maxClients   = 16
	maxPrograms  = 128
	maxTargets   = 16
	maxSets      = 3

	// An hour is unusual when fewer than 1 in unusualShare of the learned events fell within an
	// hour of it (the hour before, the hour, the hour after), each hour's as a share of its kind
	// of day's events (habit.unusual).
	unusualShare = 50
)

var (
	signinCaps = [maxSets]int{maxCountries, maxNetworks, maxClients}
	adminCaps  = [maxSets]int{maxPrograms, maxTargets, 0}
)

type habit struct {
	first int64  // unix seconds of the first event learned
	n     uint32 // events learned
	hn    uint32 // the sum of hours
	hours [daySlots]uint8
	sets  [maxSets][]seenVal
}

type seenVal struct {
	h uint64
	t int32 // unix hours, last seen
}

// blValue is one value of an event for a set: its hash (0: the event has none) and how a reason
// names it.
type blValue struct {
	h     uint64
	shown string
}

func valueOf(set, v string) blValue {
	if v == "" {
		return blValue{}
	}
	h := hash64("baseline", set, v)
	if h == 0 {
		h = 1
	}
	return blValue{h: h}
}

// hourSlot is t's hour of the day in loc, at weekends after the weekdays': 0–23 Monday to Friday,
// 24–47 Saturday and Sunday.
func hourSlot(t time.Time, loc *time.Location) int {
	l := t.In(loc)
	return daySlot(l.Weekday(), l.Hour())
}

// daySlot is the hour slot of hour h on a weekday wd.
func daySlot(wd time.Weekday, h int) int {
	if wd == time.Saturday || wd == time.Sunday {
		return 24 + h
	}
	return h
}

// nearSlots are the hour slots of the local hour before t's, t's and the one after, the day before
// or after at midnight (Friday 23:00, Saturday 00:00, Saturday 01:00): three distinct slots, also
// in the hour a clock change repeats or skips.
func nearSlots(t time.Time, loc *time.Location) [3]int {
	l := t.In(loc)
	wd, h := l.Weekday(), l.Hour()
	prev, next := daySlot(wd, h-1), daySlot(wd, h+1)
	if h == 0 {
		prev = daySlot((wd+6)%7, 23)
	}
	if h == 23 {
		next = daySlot((wd+1)%7, 0)
	}
	return [3]int{prev, daySlot(wd, h), next}
}

// slotOf is t's hour of the week in loc: 0 is Sunday 00:00–01:00.
func slotOf(t time.Time, loc *time.Location) int {
	l := t.In(loc)
	return int(l.Weekday())*24 + l.Hour()
}

// weekOf numbers the weeks (Sunday to Saturday) of loc's calendar.
func weekOf(t time.Time, loc *time.Location) int64 {
	y, m, d := t.In(loc).Date()
	day := time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Unix() / 86400
	w := day + 4 // 1970-01-01 was a Thursday
	if w < 0 {
		return (w - 6) / 7
	}
	return w / 7
}

// hourName is "03:00 Tue": t's hour of the week in loc.
func hourName(t time.Time, loc *time.Location) string {
	l := t.In(loc)
	return fmt.Sprintf("%02d:00 %s", l.Hour(), l.Format("Mon"))
}

func unixHour(t time.Time) int32 {
	h := t.Unix() / 3600
	return int32(min(max(h, 0), 1<<31-1))
}

func (p *habit) learned(t time.Time, learn time.Duration) bool {
	return p.n >= minLearned && t.Unix()-p.first >= int64(learn/time.Second)
}

// settled: worth protecting (minLearned events over at least a day; the shortest learning period).
func (p *habit) settled(t time.Time) bool { return p.learned(t, day) }

// unusual reports whether few of the learned events fell within an hour of t in loc: the local
// hour before, the hour, the hour after (nearSlots: at midnight of the other kind of day, Friday
// 23:00 next to Saturday 00:00, Sunday 23:00 to Monday 00:00), each hour's events as a share of its
// own kind of day's (weekdays', or weekend days'). While that kind of day has fewer than
// minHourEvents, the hour is the same hour of both kinds, as a share of all events: a 10:00 habit is
// usual on a Saturday until the weekend has a history of its own. Never before minHourEvents are
// learned.
func (p *habit) unusual(t time.Time, loc *time.Location) bool {
	if p.hn < minHourEvents {
		return false
	}
	var kind [2]uint32 // the events of weekdays, of weekend days
	for i, c := range p.hours {
		kind[i/24] += uint32(c)
	}
	share := 0.0
	for _, s := range nearSlots(t, loc) {
		if n := kind[s/24]; n >= minHourEvents {
			share += float64(p.hours[s]) / float64(n)
		} else {
			h := s % 24
			share += float64(uint32(p.hours[h])+uint32(p.hours[24+h])) / float64(p.hn)
		}
	}
	return share*unusualShare < 1
}

// resetHours forgets the hours learned (the server's time zone changed); the values are kept.
func (p *habit) resetHours() { p.hours, p.hn = [daySlots]uint8{}, 0 }

func (p *habit) known(set int, h uint64) bool {
	for _, v := range p.sets[set] {
		if v.h == h {
			return true
		}
	}
	return false
}

// isNew reports whether v departs from what set holds: the event has the value, the set holds
// values (a set never filled, say an app that doesn't log a client, learns its first value without
// firing), and v isn't one of them.
func (p *habit) isNew(set int, v blValue) bool {
	return v.h != 0 && len(p.sets[set]) > 0 && !p.known(set, v.h)
}

// learn adds an event at t in slot with its values.
func (p *habit) learn(t time.Time, slot int, vals [maxSets]blValue, caps [maxSets]int) {
	if ts := t.Unix(); p.n == 0 || ts < p.first {
		p.first = ts
	}
	if p.n < 1<<31 {
		p.n++
	}
	if p.hours[slot] == 255 {
		// Halved when an hour is full: old habits weigh less.
		p.hn = 0
		for i := range p.hours {
			p.hours[i] /= 2
			p.hn += uint32(p.hours[i])
		}
	}
	p.hours[slot]++
	p.hn++
	now := unixHour(t)
	for i, v := range vals {
		if v.h == 0 || caps[i] == 0 {
			continue
		}
		s := p.sets[i]
		found := false
		for j := range s {
			if s[j].h == v.h {
				s[j].t = max(s[j].t, now)
				found = true
				break
			}
		}
		if found {
			continue
		}
		if len(s) < caps[i] {
			p.sets[i] = append(s, seenVal{h: v.h, t: now})
			continue
		}
		old := 0
		for j := range s {
			if s[j].t < s[old].t {
				old = j
			}
		}
		s[old] = seenVal{h: v.h, t: now}
	}
}

const habitVersion = 1

// encode: the version, first, n, the 48 hourly counts, then each set's values (hash, hour).
func (p *habit) encode() []byte {
	b := make([]byte, 0, 16+daySlots+12*(len(p.sets[0])+len(p.sets[1])+len(p.sets[2])))
	b = append(b, habitVersion)
	b = binary.AppendVarint(b, p.first)
	b = binary.AppendUvarint(b, uint64(p.n))
	b = append(b, p.hours[:]...)
	for _, s := range p.sets {
		b = binary.AppendUvarint(b, uint64(len(s)))
		for _, v := range s {
			b = binary.LittleEndian.AppendUint64(b, v.h)
			b = binary.AppendVarint(b, int64(v.t))
		}
	}
	return b
}

func decodeHabit(b []byte, caps [maxSets]int) (habit, error) {
	var p habit
	if len(b) == 0 || b[0] != habitVersion {
		return p, errState
	}
	r := &reader{b: b[1:]}
	p.first = r.varint()
	n := r.uvarint()
	if n > 1<<31 {
		return p, errState
	}
	p.n = uint32(n)
	copy(p.hours[:], r.bytes(daySlots))
	for i := range p.sets {
		k := r.uvarint()
		for j := uint64(0); j < k && r.err == nil; j++ {
			h, t := r.u64(), r.varint()
			if t < 0 || t > 1<<31-1 {
				return p, errState
			}
			p.sets[i] = append(p.sets[i], seenVal{h: h, t: int32(t)})
		}
		if len(p.sets[i]) > caps[i] {
			// A set saved under a higher cap keeps the values seen most recently: the rest of the
			// habit is still good.
			slices.SortStableFunc(p.sets[i], func(a, b seenVal) int { return cmp.Compare(b.t, a.t) })
			p.sets[i] = slices.Clip(p.sets[i][:caps[i]])
			if caps[i] == 0 {
				p.sets[i] = nil
			}
		}
	}
	if r.err != nil || len(r.b) != 0 {
		return p, errState
	}
	for _, c := range p.hours {
		p.hn += uint32(c)
	}
	return p, nil
}

// signinScope separates accounts of different systems: a server user alice (SSH) is not the
// Mooring user alice, nor an app's account alice.
func signinScope(ev *siem.Event) string {
	if ev.Src == siem.SrcApp {
		return appScope(ev.App)
	}
	return ev.Src
}

// appScope is the sign-in scope of the accounts of the app slug.
func appScope(slug string) string { return "app:" + strings.ReplaceAll(slug, "|", "_") }

// signinValues are a sign-in's country, network and client.
func signinValues(ev *siem.Event) [maxSets]blValue {
	var v [maxSets]blValue
	if g := ev.Geo; g != nil {
		if cc := clean(g.Country, 8); cc != "" {
			v[0] = valueOf("cc", cc)
			v[0].shown = cc
		}
		if g.ASN != 0 {
			as := strconv.FormatUint(uint64(g.ASN), 10)
			v[1] = valueOf("asn", as)
			v[1].shown = "AS" + as
			if org := clean(g.Org, 40); org != "" {
				v[1].shown += " (" + org + ")"
			}
		}
	}
	if ua, _ := ev.F["ua"].(string); ua != "" {
		if fam := uaFamily(ua); fam != "" {
			v[2] = valueOf("ua", fam)
			v[2].shown = fam
		}
	}
	return v
}

// adminValues are a sudo or su line's program (the command's first word, without its directory)
// and target user.
func adminValues(ev *siem.Event) [maxSets]blValue {
	var v [maxSets]blValue
	if cmd, _ := ev.F["command"].(string); cmd != "" {
		if prog := programOf(cmd); prog != "" {
			v[0] = valueOf("prog", prog)
			v[0].shown = safeToken(prog, 32)
		}
	}
	if tu, _ := ev.F["target_user"].(string); tu != "" {
		tu = siem.Cut(tu, siem.MaxShort)
		v[1] = valueOf("target", tu)
		v[1].shown = safeToken(tu, 32)
	}
	return v
}

func programOf(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if i := strings.IndexAny(cmd, " \t"); i >= 0 {
		cmd = cmd[:i]
	}
	if i := strings.LastIndexByte(cmd, '/'); i >= 0 {
		cmd = cmd[i+1:]
	}
	return siem.Cut(cmd, 64)
}

// safeToken returns s when it is 1–n bytes of letters, digits and . _ + -, else "": a name from an
// event shown in a summary (a program, a user, a client) is never free text.
func safeToken(s string, n int) string {
	if s == "" || len(s) > n {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '+' || c == '-') {
			return ""
		}
	}
	return s
}

// uaFamily is a User-Agent's client family, without versions: "Firefox on Linux", "curl",
// "okhttp" … A User-Agent of no known family is its first product name (letters, digits and
// . _ + - only, at most 24 bytes), else "other".
func uaFamily(ua string) string {
	s := strings.ToLower(siem.Cut(strings.TrimSpace(ua), 512))
	if s == "" {
		return ""
	}
	has := func(subs ...string) bool {
		for _, x := range subs {
			if strings.Contains(s, x) {
				return true
			}
		}
		return false
	}
	os := ""
	switch {
	case has("android"):
		os = "Android"
	case has("iphone", "ipad", "ipod", "cpu os "):
		os = "iOS"
	case has("windows"):
		os = "Windows"
	case has("cros "):
		os = "ChromeOS"
	case has("mac os x", "macintosh"):
		os = "macOS"
	case has("linux"):
		os = "Linux"
	}
	name := ""
	switch {
	case has("edg/", "edge/", "edga/", "edgios/"):
		name = "Edge"
	case has("opr/", "opera"):
		name = "Opera"
	case has("samsungbrowser"):
		name = "Samsung Internet"
	case has("firefox/", "fxios/"):
		name = "Firefox"
	case has("chrome/", "crios/", "chromium/"):
		name = "Chrome"
	case has("safari/") && has("version/"):
		name = "Safari"
	default:
		switch {
		case strings.HasPrefix(s, "curl/"):
			name = "curl"
		case strings.HasPrefix(s, "wget/"):
			name = "Wget"
		case has("python-requests", "python-urllib", "aiohttp", "python-httpx"):
			name = "Python"
		case strings.HasPrefix(s, "go-http-client"):
			name = "Go"
		case has("okhttp"):
			name = "okhttp"
		case has("postmanruntime"):
			name = "Postman"
		case strings.HasPrefix(s, "axios"):
			name = "axios"
		case has("node-fetch", "undici"):
			name = "Node.js"
		case strings.HasPrefix(s, "java/"), has("apache-httpclient"):
			name = "Java"
		case strings.HasPrefix(s, "dart/"):
			name = "Dart"
		case has("cfnetwork"):
			name = "CFNetwork"
		default:
			tok := s
			if i := strings.IndexAny(tok, "/ ;("); i >= 0 {
				tok = tok[:i]
			}
			if name = safeToken(tok, 24); name == "" {
				name = "other"
			}
		}
	}
	if os != "" {
		return name + " on " + os
	}
	return name
}

// The sign-in baseline (signin): reasons a sign-in departs from its account's habit, and how many
// departures they count for. A new country and a new network are one departure (one trip: a
// sign-in from somewhere new usually has both), a new client one, an unusual hour one.
func (p *habit) signinReasons(vals [maxSets]blValue, t time.Time, loc *time.Location) (r []string, n int) {
	cc, asn := p.isNew(0, vals[0]), p.isNew(1, vals[1])
	if cc {
		r = append(r, "new country "+vals[0].shown)
	}
	if asn {
		r = append(r, "new network "+vals[1].shown)
	}
	if cc || asn {
		n++
	}
	if p.isNew(2, vals[2]) {
		r = append(r, "new client "+vals[2].shown)
		n++
	}
	if p.unusual(t, loc) {
		r = append(r, "unusual hour ("+hourName(t, loc)+")")
		n++
	}
	return r, n
}

// The server-admin baseline (admin): reasons a sudo or su departs from its user's habit.
func (p *habit) adminReasons(vals [maxSets]blValue, t time.Time, loc *time.Location) []string {
	var r []string
	if p.isNew(0, vals[0]) {
		s := "new program"
		if vals[0].shown != "" {
			s += " " + vals[0].shown
		}
		r = append(r, s)
	}
	if p.isNew(1, vals[1]) {
		s := "new target user"
		if vals[1].shown != "" {
			s += " " + vals[1].shown
		}
		r = append(r, s)
	}
	// Intentional: root at an unusual hour is never a departure alone (owner decision 2026-11-25:
	// an admin working late is no reason for a high-severity detection); it is told with a new
	// program or target user.
	if len(r) > 0 && vals[1].h != 0 && vals[1].h == rootTarget.h && p.unusual(t, loc) {
		r = append(r, "root at an unusual hour ("+hourName(t, loc)+")")
	}
	return r
}

var rootTarget = valueOf("target", "root")

// habitEvent evaluates one sign-in (signin) or sudo/su (admin) of rule c for key: it fires when
// the key has learned for c.r.Learn and the event departs from its habit (at least c.r.Count
// departures for signin, any for admin); with learn, the event is then learned (the last enabled
// rule of the kind does that, so every rule compares with the same habit).
func (b *baselines) habitEvent(e *Engine, c *compiled, key string, ev *siem.Event, learn bool) {
	signin := c.r.Baseline == siem.BaselineSignIn
	tab, caps, vals, k := b.admin, adminCaps, adminValues(ev), key
	if signin {
		scope := signinScope(ev)
		if b.appIsGone(scope, e.now()) {
			return // an app deleted lately (its sign-ins still queued)
		}
		tab, caps, vals, k = b.signinTable(scope), signinCaps, signinValues(ev), scope+"|"+key
	}
	x := tab.get(k)
	if x != nil && x.v.learned(ev.TS, c.r.Learn) {
		var reasons []string
		n, need := 0, 1
		if signin {
			reasons, n = x.v.signinReasons(vals, ev.TS, b.loc)
			need = max(c.r.Count, 1)
		} else {
			reasons = x.v.adminReasons(vals, ev.TS, b.loc)
			n = len(reasons)
		}
		if n >= need {
			e.fire(c, key, ev, firing{count: 1, evidence: []siem.Evidence{evidenceOf(ev)}, reasons: reasons})
		}
	}
	if !learn {
		return
	}
	if x == nil {
		x = tab.add(k)
	}
	x.v.learn(ev.TS, hourSlot(ev.TS, b.loc), vals, caps)
	tab.touch(x)
	if x.v.settled(ev.TS) {
		tab.protect(x)
	}
}
