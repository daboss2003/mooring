package detect

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

func blRows(t *testing.T, h *harness, kind string) map[string][]byte {
	t.Helper()
	rows, _, err := h.e.db.loadBaselineRows(context.Background(), kind, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, r := range rows {
		out[r.key] = r.data
	}
	return out
}

func setCap[T any](tb *table[T], n int) { tb.max, tb.maxProt = n, n/4*3 }

// A flood of keys an attacker chooses stays within each kind's cap, and the keys with a learned
// history stay.
func TestBaselineBoundedUnderFlood(t *testing.T) {
	h := blHarness(t, tokyo, served(func(string) bool { return true }),
		blRule("baseline.signin_unusual"), blRule("baseline.admin_unusual"), blRule("baseline.ip_behaviour"),
		blRule(ruleTrafficSurge), blRule(ruleTrafficDrop))
	b := h.e.bl
	setCap(b.signin, 100)
	setCap(b.admin, 100)
	setCap(b.ip, 100)
	setCap(b.traffic, 40)

	// History: 50 accounts with 3 sign-ins over 2 days, 50 addresses with 12 requests over 2 hours,
	// 20 host names with a counted hour.
	for d := range 3 {
		for i := range 50 {
			h.feed(mooringSignIn(at(d, 9, 0), fmt.Sprint("user", i), jpKDDI, chromeWin))
		}
	}
	for j := range 12 {
		for i := range 50 {
			h.feed(edgeReq(at(3, 0, 0).Add(time.Duration(j)*10*time.Minute), fmt.Sprint("10.0.0.", i), "/", 200))
		}
	}
	idle(h, at(3, 2, 0), 1)
	for i := range 20 {
		h.feed(edgeReq(at(3, 2, 10), "203.0.113.1", "/", 200))
		h.feed(siem.Event{TS: at(3, 2, 10).UTC(), Src: siem.SrcEdge, Kind: siem.KindHTTPRequest,
			F: map[string]any{"host": fmt.Sprintf("app%d.example.com", i), "status": 200.0}})
	}
	idle(h, at(3, 2, 11), 49) // 02:00 is the hour they were first seen in: not counted
	runTraffic(h, at(3, 3, 0), 1, func(time.Time) map[string]load {
		m := map[string]load{}
		for i := range 20 {
			m[fmt.Sprintf("app%d.example.com", i)] = load{10, 0}
		}
		return m
	})
	idle(h, at(3, 4, 0), 5) // 03:00 closes at 04:02
	for i := range 20 {
		if x := b.traffic.peek(fmt.Sprintf("app%d.example.com", i)); x == nil || !x.prot {
			t.Fatalf("host %d not protected", i)
		}
	}

	// The flood: 5000 accounts, addresses and host names, each seen once; one server user with
	// 1000 programs and 1000 target users; one account with 1000 countries, networks and clients.
	for i := range 5000 {
		ts := at(3, 5, 0).Add(time.Duration(i) * time.Millisecond)
		h.feed(mooringSignIn(ts, fmt.Sprint("flood", i), nil, ""))
		h.feed(edgeReq(ts, fmt.Sprintf("198.51.%d.%d", i/250, i%250), "/x", 404))
		h.feed(siem.Event{TS: ts.UTC(), Src: siem.SrcEdge, Kind: siem.KindHTTPRequest,
			F: map[string]any{"host": fmt.Sprintf("r%d.example.com", i), "status": 200.0}})
		h.feed(siem.Event{TS: ts.UTC(), Src: siem.SrcHost, Kind: siem.KindSudo, Out: siem.OutSuccess, Actor: fmt.Sprint("u", i)})
	}
	for i := range 1000 {
		ts := at(3, 6, 0).Add(time.Duration(i) * time.Millisecond)
		h.feed(siem.Event{TS: ts.UTC(), Src: siem.SrcHost, Kind: siem.KindSudo, Out: siem.OutSuccess, Actor: "mallory",
			F: map[string]any{"command": fmt.Sprint("/tmp/p", i), "target_user": fmt.Sprint("t", i)}})
		g := &siem.Geo{Country: fmt.Sprint("C", i), ASN: uint32(i + 1)}
		h.feed(mooringSignIn(ts, "user0", g, fmt.Sprintf("client%d/1.0", i)))
	}
	for name, n := range map[string]int{"signin": b.signin.len(), "admin": b.admin.len(), "ip": b.ip.len()} {
		if n > 100 {
			t.Errorf("%s: %d entities, cap 100", name, n)
		}
	}
	if n := b.traffic.len(); n > 40 {
		t.Errorf("traffic: %d hosts, cap 40", n)
	}
	for i := range 50 {
		if b.signin.peek(fmt.Sprint("mooring|user", i)) == nil {
			t.Fatalf("learned account %d dropped by the flood", i)
		}
		if b.ip.peek(fmt.Sprint("10.0.0.", i)) == nil {
			t.Fatalf("learned address %d dropped by the flood", i)
		}
	}
	for i := range 20 {
		if b.traffic.peek(fmt.Sprintf("app%d.example.com", i)) == nil {
			t.Fatalf("host %d with history dropped by the flood", i)
		}
	}
	if b.signin.plru.Len() > 75 || b.ip.plru.Len() > 75 || b.traffic.plru.Len() > 30 {
		t.Errorf("protected: %d %d %d", b.signin.plru.Len(), b.ip.plru.Len(), b.traffic.plru.Len())
	}
	m := b.admin.peek("mallory")
	u0 := b.signin.peek("mooring|user0")
	if m == nil || u0 == nil {
		t.Fatal("value flood keys missing")
	}
	if len(m.v.sets[0]) != maxPrograms || len(m.v.sets[1]) != maxTargets ||
		len(u0.v.sets[0]) != maxCountries || len(u0.v.sets[1]) != maxNetworks || len(u0.v.sets[2]) != maxClients {
		t.Errorf("values: programs %d targets %d countries %d networks %d clients %d", len(m.v.sets[0]), len(m.v.sets[1]),
			len(u0.v.sets[0]), len(u0.v.sets[1]), len(u0.v.sets[2]))
	}
	if n := len(b.ip.dq) - b.ip.dqHd; n > 2*len(b.ip.dirty)+1024 {
		t.Errorf("dirty queue %d for %d dirty", n, len(b.ip.dirty))
	}
}

func TestBaselineTableProtection(t *testing.T) {
	tb := newTable("x", 10, func(*int) []byte { return nil })
	for i := range 5 {
		x := tb.add(fmt.Sprint("p", i))
		x.saved = true
		tb.protect(x)
	}
	for i := range 100 {
		tb.add(fmt.Sprint("f", i))
	}
	if tb.len() != 10 || tb.plru.Len() != 5 {
		t.Fatalf("%d entities, %d protected", tb.len(), tb.plru.Len())
	}
	for i := range 5 {
		if tb.peek(fmt.Sprint("p", i)) == nil {
			t.Fatalf("protected p%d dropped", i)
		}
	}
	// Past maxProt (6), the protected used least recently go back to the others.
	for i := range 4 {
		tb.protect(tb.add(fmt.Sprint("q", i)))
	}
	if tb.plru.Len() != tb.maxProt || tb.len() != 10 {
		t.Fatalf("%d protected (max %d), %d in all", tb.plru.Len(), tb.maxProt, tb.len())
	}
	// Only protected left: the one used least recently goes.
	all := newTable("y", 2, func(*int) []byte { return nil })
	all.maxProt = 2
	all.protect(all.add("a"))
	all.protect(all.add("b"))
	all.add("c")
	if all.len() != 2 || all.peek("c") == nil || all.peek("a") != nil {
		t.Fatalf("all protected: %d", all.len())
	}
	// Saved entities dropped: their rows go with the next save; past max of them, a rewrite.
	if g := tb.takeGone(-1); len(g) != 0 {
		t.Fatalf("unsaved flood entries noted gone: %v", g)
	}
	for i := range 5 {
		tb.drop(tb.peek(fmt.Sprint("p", i)))
	}
	if g := tb.takeGone(-1); len(g) != 5 {
		t.Fatalf("gone %v", g)
	}
	for i := range 30 { // 20 or more saved entities dropped, past max (10)
		x := tb.add(fmt.Sprint("s", i))
		x.saved = true
	}
	if !tb.resync || len(tb.gone) != 0 {
		t.Fatalf("resync %v, gone %d", tb.resync, len(tb.gone))
	}
}

// Learned state survives a restart: changed entities are saved on the tick (a bounded number per
// tick) and all of them on persist and at shutdown.
func TestBaselineStateSurvivesRestart(t *testing.T) {
	rs := []siem.Rule{blRule("baseline.signin_unusual"), blRule("baseline.admin_unusual"), blRule("baseline.ip_behaviour")}
	h := blHarness(t, tokyo, nil, rs...)
	learnAddr(h, "203.0.113.7", 20)
	for d := range 15 {
		weekdaySignIns(h, d, d+1, jpKDDI, chromeWin)
		sudo(t, h, at(d, 10, 0), "root", "/usr/bin/systemctl restart web")
	}
	if n := len(blRows(t, h, "signin")); n != 0 {
		t.Fatalf("%d rows before any save", n)
	}
	h.e.baselineTick()
	if blRows(t, h, "signin")["mooring|alice"] == nil || blRows(t, h, "admin")["alice"] == nil ||
		blRows(t, h, "ip")["203.0.113.7"] == nil {
		t.Fatal("not saved on the tick")
	}
	h.blReopen(t, tokyo, rs...)
	h.feed(mooringSignIn(at(15, 9, 30), "alice", ngExample, firefoxLx))
	sudo(t, h, at(15, 10, 5), "root", "/usr/bin/nc -l 1")
	for i := range 50 {
		h.feed(edgeReq(at(15, 11, 0).Add(time.Duration(i)*time.Second), "203.0.113.7", "/login", 200))
	}
	got := ruleIDs(h.all(t))
	if got["baseline.signin_unusual"] != 1 || got["baseline.admin_unusual"] != 1 || got["baseline.ip_behaviour"] != 1 {
		t.Fatalf("after a restart: %v", got)
	}
}

func TestBaselineTickSavesInSlices(t *testing.T) {
	h := blHarness(t, tokyo, nil, blRule("baseline.ip_behaviour"))
	for i := range 300 {
		h.feed(edgeReq(at(0, 0, 0).Add(time.Duration(i)*time.Millisecond), fmt.Sprintf("10.1.%d.%d", i/250, i%250), "/", 200))
	}
	for i, want := range []int{blTickRows, 2 * blTickRows, 300, 300} {
		h.e.baselineTick()
		if n := len(blRows(t, h, "ip")); n != want {
			t.Fatalf("tick %d: %d rows, want %d", i+1, n, want)
		}
	}
	// A full save takes every change at once.
	for i := range 300 {
		h.feed(edgeReq(at(0, 1, 0).Add(time.Duration(i)*time.Millisecond), fmt.Sprintf("10.2.%d.%d", i/250, i%250), "/", 200))
	}
	h.e.saveBaselines()
	if n := len(blRows(t, h, "ip")); n != 600 {
		t.Fatalf("full save: %d rows", n)
	}
	if h.e.bl.ip.pending() {
		t.Fatal("still pending after a full save")
	}
	// A failed write keeps the changes (and the ticks back off).
	for i := range 3 {
		h.feed(edgeReq(at(0, 2, 0).Add(time.Duration(i)*time.Millisecond), fmt.Sprint("10.3.0.", i), "/", 200))
	}
	if _, err := h.e.db.w.Exec(`ALTER TABLE baselines RENAME TO baselines_x`); err != nil {
		t.Fatal(err)
	}
	h.e.baselineTick()
	if !h.e.bl.ip.pending() || h.e.bl.backoff == 0 || h.e.Stats().WriteErrors == 0 {
		t.Fatal("a failed save lost its changes")
	}
	if _, err := h.e.db.w.Exec(`ALTER TABLE baselines_x RENAME TO baselines`); err != nil {
		t.Fatal(err)
	}
	h.e.baselineTick() // backing off
	if n := len(blRows(t, h, "ip")); n != 600 {
		t.Fatalf("saved during the backoff: %d", n)
	}
	h.e.saveBaselines()
	if n := len(blRows(t, h, "ip")); n != 603 || h.e.bl.backoff != 0 {
		t.Fatalf("after the failure: %d rows", n)
	}
}

// A row that doesn't decode is dropped (and deleted); a kind whose definition changed starts again.
func TestBaselineDamagedAndChangedState(t *testing.T) {
	rs := []siem.Rule{blRule("baseline.signin_unusual"), blRule("baseline.admin_unusual")}
	h := blHarness(t, tokyo, nil, rs...)
	for d := range 15 {
		weekdaySignIns(h, d, d+1, jpKDDI, chromeWin)
		h.feed(mooringSignIn(at(d, 9, 30), "bob", jpKDDI, chromeWin))
		sudo(t, h, at(d, 10, 0), "root", "/usr/bin/systemctl restart web")
	}
	h.e.saveBaselines()
	w := h.e.db.w
	if _, err := w.Exec(`UPDATE baselines SET data = x'01ffff' WHERE kind = 'signin' AND key = 'mooring|alice'`); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Exec(`INSERT INTO baselines(kind, key, data, updated_ns) VALUES ('signin', ?, x'01', 1)`,
		strings.Repeat("k", maxBaselineKey+1)); err != nil {
		t.Fatal(err)
	}
	h.blReopen(t, tokyo, rs...)
	if h.e.bl.signin.peek("mooring|alice") != nil || h.e.bl.signin.peek("mooring|bob") == nil || h.e.bl.admin.peek("alice") == nil {
		t.Fatal("damaged row kept, or a good one lost")
	}
	h.feed(mooringSignIn(at(15, 9, 40), "alice", ngExample, firefoxLx))
	h.feed(mooringSignIn(at(15, 9, 45), "bob", ngExample, firefoxLx))
	if got := ruleIDs(h.all(t)); got["baseline.signin_unusual"] != 1 {
		t.Fatalf("alice (damaged: learning again) and bob (kept): %v", got)
	}
	h.e.saveBaselines()
	if rows := blRows(t, h, "signin"); len(rows) != 2 || rows[strings.Repeat("k", maxBaselineKey+1)] != nil {
		t.Fatalf("rows after the next save: %d", len(rows))
	}

	if _, err := h.e.db.w.Exec(`UPDATE baseline_kinds SET sig = 'older' WHERE kind = 'admin'`); err != nil {
		t.Fatal(err)
	}
	h.blReopen(t, tokyo, rs...)
	if h.e.bl.admin.len() != 0 || len(blRows(t, h, "admin")) != 0 || h.e.bl.signin.len() != 2 {
		t.Fatalf("changed definition: admin %d kept", h.e.bl.admin.len())
	}
	var sig string
	if err := h.e.db.w.QueryRow(`SELECT sig FROM baseline_kinds WHERE kind = 'admin'`).Scan(&sig); err != nil ||
		sig != signature(packByID["baseline.admin_unusual"].Rule)+"/v1" {
		t.Fatalf("sig %q, %v", sig, err)
	}
}

// Past a kind's cap of rows (a lowered cap, or rows left by a crash), the most recently saved are
// loaded and the kind is rewritten at the next full save; dropped saved entities' rows are deleted.
func TestBaselineRowsBounded(t *testing.T) {
	h := blHarness(t, tokyo, nil, blRule("baseline.ip_behaviour"))
	for i := range 30 {
		h.feed(edgeReq(at(0, 0, 0).Add(time.Duration(i)*time.Second), fmt.Sprint("10.0.0.", i), "/", 200))
	}
	h.e.saveBaselines()
	setCap(h.e.bl.ip, 20)
	for i := range 5 {
		h.feed(edgeReq(at(0, 1, 0).Add(time.Duration(i)*time.Second), fmt.Sprint("10.9.0.", i), "/", 200))
	}
	h.e.baselineTick()
	rows := blRows(t, h, "ip")
	if len(rows) != 20 || rows["10.0.0.0"] != nil || rows["10.9.0.4"] == nil {
		t.Fatalf("rows after dropping: %d", len(rows))
	}
	// A restart with a cap of 10: the 10 rows saved most recently are loaded, the rest deleted at
	// the next full save.
	h.reopen(t)
	if _, err := h.e.db.w.Exec(`UPDATE baselines SET updated_ns = ? WHERE key LIKE '10.9.%'`, int64(1)<<62); err != nil {
		t.Fatal(err)
	}
	b := h.e.bl
	b.ip = newTable("ip", 10, (*addrMix).encode)
	b.stores[4] = b.ip
	if err := loadKind(h.e, b.ip, decodeIP, func(*addrMix) bool { return false }); err != nil {
		t.Fatal(err)
	}
	if !b.ip.resync || b.ip.len() != 10 || b.ip.peek("10.9.0.0") == nil {
		t.Fatalf("resync %v, %d loaded", b.ip.resync, b.ip.len())
	}
	h.e.saveBaselines()
	if rows := blRows(t, h, "ip"); len(rows) != 10 || rows["10.9.0.4"] == nil {
		t.Fatalf("after the rewrite: %d rows", len(rows))
	}
}

// Migration 0006 applies on a detect.db an earlier release left at version 5.
func TestBaselineMigrationOnExistingDB(t *testing.T) {
	h := newHarness(t, false)
	w := h.e.db.w
	if _, err := w.Exec(`DROP TABLE baselines; DROP TABLE baseline_kinds; DELETE FROM schema_version WHERE version = 6`); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Exec(`INSERT INTO detections(source, rule_id, rule_name, severity, sev_rank, key, first_ns, last_ns,
		count, summary) VALUES ('siem', 'r', 'r', 'low', 1, 'k', 1, 1, 1, 'kept')`); err != nil {
		t.Fatal(err)
	}
	if err := h.e.Close(); err != nil {
		t.Fatal(err)
	}
	h.open(t)
	h.e.bl.loc = tokyo
	h.only(t, blRule("baseline.signin_unusual"))
	weekdaySignIns(h, 0, 2, jpKDDI, chromeWin)
	h.e.baselineTick()
	if blRows(t, h, "signin")["mooring|alice"] == nil {
		t.Fatal("no baseline row after the migration")
	}
	var n, v int
	if err := h.e.db.w.QueryRow(`SELECT COUNT(*) FROM detections WHERE summary = 'kept'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("old detection: %d, %v", n, err)
	}
	if err := h.e.db.w.QueryRow(`SELECT COUNT(*) FROM schema_version WHERE version = 6`).Scan(&v); err != nil || v != 1 {
		t.Fatalf("version 6 recorded %d, %v", v, err)
	}
}

func TestValidateBaseline(t *testing.T) {
	now := t0
	for _, tc := range []struct {
		id   string
		mod  func(*siem.Rule)
		want string // "" valid
	}{
		{"baseline.signin_unusual", func(r *siem.Rule) { r.Count = 3; r.Learn = day }, ""},
		{"baseline.signin_unusual", func(r *siem.Rule) { r.Count = 0 }, "the count must be between 1 and 3"},
		{"baseline.signin_unusual", func(r *siem.Rule) { r.Count = 4 }, "the count must be between 1 and 3"},
		{"baseline.signin_unusual", func(r *siem.Rule) { r.Learn = 12 * hour }, "the learning period must be between 1d and 30d"},
		{"baseline.signin_unusual", func(r *siem.Rule) { r.GroupBy = "ip" }, "a signin baseline groups by actor"},
		{"baseline.admin_unusual", func(r *siem.Rule) { r.Learn = 31 * day }, "the learning period must be between 1d and 30d"},
		{"baseline.traffic_surge", func(r *siem.Rule) { r.Learn = 6 * day }, "the learning period must be between 7d and 28d"},
		{"baseline.traffic_surge", func(r *siem.Rule) { r.Learn = 29 * day }, "the learning period must be between 7d and 28d"},
		{"baseline.traffic_drop", func(r *siem.Rule) { r.Factor = 1 }, "the factor must be between 1.5 and 1000"},
		{"baseline.traffic_drop", func(r *siem.Rule) { r.Count = 0 }, "the count must be between 1 and 100000"},
		{"baseline.ip_behaviour", func(r *siem.Rule) { r.Count = 9 }, "the count must be between 10 and 100000"},
		{"baseline.ip_behaviour", func(r *siem.Rule) { r.Window = 25 * hour }, "the window must be between 1m and 1d"},
		{"baseline.ip_behaviour", func(r *siem.Rule) { r.Window = 30 * time.Second }, "the window must be between 1m and 1d"},
		{"baseline.ip_behaviour", func(r *siem.Rule) { r.Learn = 30 * minute }, "the learning period must be between 1h and 30d"},
		{"baseline.ip_behaviour", func(r *siem.Rule) { r.Factor = 1001 }, "the factor must be between 1.5 and 1000"},
		{"baseline.ip_behaviour", func(r *siem.Rule) { r.Baseline = "nope" }, `unknown baseline "nope"`},
		{"baseline.ip_behaviour", func(r *siem.Rule) { r.Builtin = false }, "type baseline is for the built-in rules only"},
	} {
		r := blRule(tc.id, tc.mod)
		err := validate(&r, now)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.id, err)
		case tc.want != "" && (err == nil || !errors.Is(err, siem.ErrInvalidRule) || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: %v, want %q", tc.id, err, tc.want)
		}
	}
	// What a kind doesn't use is cleared.
	r := blRule("baseline.signin_unusual", func(r *siem.Rule) { r.Window, r.Factor, r.Field, r.SpeedKMH = hour, 3, "f.x", 900 })
	if err := validate(&r, now); err != nil || r.Window != 0 || r.Factor != 0 || r.Field != "" || r.SpeedKMH != 0 {
		t.Fatalf("signin cleared: %+v %v", r, err)
	}
	r = blRule("baseline.admin_unusual", func(r *siem.Rule) { r.Count, r.Factor = 3, 2 })
	if err := validate(&r, now); err != nil || r.Count != 0 || r.Factor != 0 {
		t.Fatalf("admin cleared: %+v %v", r, err)
	}
	r = blRule(ruleTrafficSurge, func(r *siem.Rule) { r.Window = hour })
	if err := validate(&r, now); err != nil || r.Window != 0 {
		t.Fatalf("traffic cleared: %+v %v", r, err)
	}
}

// Through the rule store: a custom rule can't be a baseline (saved or stored); the built-in ones
// take their tunables within the ranges.
func TestBaselineRulesInTheStore(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	custom := siem.Rule{ID: "custom.mine", Name: "mine", Type: siem.RuleBaseline, Baseline: siem.BaselineSignIn,
		Severity: siem.SevMedium, Query: "kind:x.login", GroupBy: "actor", Count: 2, Learn: 14 * day, Builtin: true}
	err := h.e.SaveRule(ctx, custom)
	if !errors.Is(err, siem.ErrInvalidRule) || !strings.Contains(err.Error(), "built-in rules only") {
		t.Fatalf("custom baseline saved: %v", err)
	}
	r := blRule("baseline.signin_unusual", func(r *siem.Rule) { r.Count = 3 })
	if err := h.e.SaveRule(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.Count = 5
	if err := h.e.SaveRule(ctx, r); !errors.Is(err, siem.ErrInvalidRule) {
		t.Fatalf("count 5 saved: %v", err)
	}
	if got, _ := findRule(t, h.e, "baseline.signin_unusual"); got.Count != 3 || got.Type != siem.RuleBaseline || got.Baseline != siem.BaselineSignIn {
		t.Fatalf("stored tunable: %+v", got)
	}
	// A custom baseline rule stored by other means is listed switched off, with the reason.
	b, _ := json.Marshal(custom)
	if _, err := h.main.Exec(`INSERT INTO security_rules(id, json, updated_at) VALUES ('custom.mine', ?, 1)`, string(b)); err != nil {
		t.Fatal(err)
	}
	h.reopen(t)
	got, ok := findRule(t, h.e, "custom.mine")
	if !ok || got.Enabled || !strings.Contains(got.Description, "stored rule is invalid: type baseline is for the built-in rules only") {
		t.Fatalf("stored custom baseline: %+v", got)
	}
	if h.e.rules.Load().byID["custom.mine"] != nil {
		t.Fatal("a stored custom baseline rule is evaluated")
	}
}

// Entities with a learned history come back protected after a restart: a flood right after it
// doesn't drop them.
func TestBaselineProtectedAfterRestart(t *testing.T) {
	rs := []siem.Rule{blRule("baseline.signin_unusual"), blRule("baseline.ip_behaviour")}
	h := blHarness(t, tokyo, nil, rs...)
	for d := range 3 {
		for i := range 30 {
			h.feed(mooringSignIn(at(d, 9, 0), fmt.Sprint("user", i), jpKDDI, chromeWin))
		}
	}
	for j := range 12 {
		for i := range 30 {
			h.feed(edgeReq(at(3, 0, 0).Add(time.Duration(j)*10*time.Minute), fmt.Sprint("10.0.0.", i), "/", 200))
		}
	}
	h.blReopen(t, tokyo, rs...)
	b := h.e.bl
	if b.signin.plru.Len() != 30 || b.ip.plru.Len() != 30 {
		t.Fatalf("protected after the restart: %d accounts, %d addresses", b.signin.plru.Len(), b.ip.plru.Len())
	}
	setCap(b.signin, 40)
	setCap(b.ip, 40)
	for i := range 500 {
		ts := at(3, 3, 0).Add(time.Duration(i) * time.Millisecond)
		h.feed(mooringSignIn(ts, fmt.Sprint("flood", i), nil, ""))
		h.feed(edgeReq(ts, fmt.Sprintf("198.51.100.%d", i%250)+fmt.Sprint(i/250), "/", 200))
	}
	for i := range 30 {
		if b.signin.peek(fmt.Sprint("mooring|user", i)) == nil || b.ip.peek(fmt.Sprint("10.0.0.", i)) == nil {
			t.Fatalf("learned entity %d dropped after a restart", i)
		}
	}
}

// A saved entity dropped and back before the save keeps its row: the stale key to delete is
// forgotten when it comes back, and its row counts as saved (dropped again, the row is deleted).
func TestBaselineReaddedEntityKeepsItsRow(t *testing.T) {
	h := blHarness(t, tokyo, nil, blRule("baseline.ip_behaviour"))
	tb := h.e.bl.ip
	setCap(tb, 3)
	add := func(k string, total uint32) {
		x := tb.add(k)
		x.v.first, x.v.total = 1, total
		tb.touch(x)
	}
	add("K", 42)
	h.e.saveBaselines()
	for i := range 3 { // K, used least recently, is dropped: its row is to be deleted
		add(fmt.Sprint("E", i), 1)
	}
	if tb.peek("K") != nil {
		t.Fatal("setup: K kept")
	}
	add("K", 99) // back, changed
	if _, ok := tb.gone["K"]; ok || !tb.peek("K").saved {
		t.Fatal("K back: still to delete, or its row not counted as saved")
	}
	// Its new row saved first, the deletions after (a later tick, or a later part of a full save).
	if err := h.e.db.writeBaselines(context.Background(), tb.takeDirty(-1), nil, 1, nil); err != nil {
		t.Fatal(err)
	}
	h.e.saveBaselines()
	x, err := decodeIP(blRows(t, h, "ip")["K"])
	if err != nil || x.total != 99 {
		t.Fatalf("K's row: %+v %v", x, err)
	}
	// Dropped again before any save: its row (there) is deleted.
	for i := range 3 {
		add(fmt.Sprint("F", i), 1)
	}
	h.e.saveBaselines()
	if blRows(t, h, "ip")["K"] != nil {
		t.Fatal("K dropped again: its row kept")
	}
}

// Mooring's and the server's accounts have their own table: an app with many accounts can't push
// them out.
func TestBaselineSigninTables(t *testing.T) {
	h := blHarness(t, tokyo, nil, blRule("baseline.signin_unusual"))
	b := h.e.bl
	setCap(b.signin, 20)
	setCap(b.signinApp, 100)
	weekdaySignIns(h, 0, 21, jpKDDI, chromeWin)
	h.feed(siem.Event{TS: at(20, 9, 0).UTC(), Src: siem.SrcHost, Kind: siem.KindSSHLogin, Out: siem.OutSuccess,
		Actor: "deploy", F: map[string]any{"method": "publickey"}})
	// The app: 300 accounts sign in on 3 days in a row, then 250 new ones (alice is away).
	appIn := func(when time.Time, actor string) siem.Event {
		return siem.Event{TS: when.UTC(), Src: siem.SrcApp, App: "shop", Kind: "auth.login", Out: siem.OutSuccess,
			IP: "198.51.100.20", Actor: actor, Geo: &siem.Geo{Country: "JP", ASN: 2516}}
	}
	for d := 21; d < 24; d++ {
		for i := range 300 {
			h.feed(appIn(at(d, 8, 0).Add(time.Duration(i)*time.Millisecond), fmt.Sprint("u", i)))
		}
	}
	for i := range 250 {
		h.feed(appIn(at(24, 8, 0).Add(time.Duration(i)*time.Millisecond), fmt.Sprint("new", i)))
	}
	if b.signinApp.len() != 100 || b.signin.peek("mooring|alice") == nil || b.signin.peek("host|deploy") == nil {
		t.Fatalf("app accounts %d; Mooring and SSH accounts kept: %v %v", b.signinApp.len(),
			b.signin.peek("mooring|alice") != nil, b.signin.peek("host|deploy") != nil)
	}
	// alice's account is used from Lagos with a new client: compared with her habit.
	h.feed(mooringSignIn(at(25, 9, 10), "alice", ngExample, firefoxLx))
	if ds := h.all(t); len(ds) != 1 || ds[0].Key != "alice" {
		t.Fatalf("after the app's sign-ins:\n%s", summaries(ds))
	}
	h.e.saveBaselines()
	if blRows(t, h, "signin")["mooring|alice"] == nil || len(blRows(t, h, "signin_app")) != 100 {
		t.Fatal("rows of the two tables")
	}
}

// The server's time zone changes: the hours learned are reset (in every kind that learns per hour),
// the values learned kept, and the zone recorded with the kind's rewrite.
func TestBaselineZoneChangeResetsHours(t *testing.T) {
	rs := []siem.Rule{blRule("baseline.signin_unusual", func(r *siem.Rule) { r.Count = 1 }), blRule("baseline.admin_unusual"),
		blRule(ruleTrafficSurge)}
	h := blHarness(t, time.UTC, knownHosts("shop.example.com"), rs...)
	// alice signs in at 09:10 UTC on 21 weekdays, and runs one sudo; shop has a counted hour.
	for d := range 29 {
		if d%7 < 5 {
			h.feed(mooringSignIn(at(d, 9, 10).In(time.UTC).Add(9*time.Hour), "alice", jpKDDI, chromeWin))
		}
	}
	sudo(t, h, at(28, 18, 30), "root", "/usr/bin/systemctl restart web")
	runTraffic(h, at(28, 19, 0), 3, func(time.Time) map[string]load { return map[string]load{"shop.example.com": {60, 0}} })
	if x := h.e.bl.traffic.peek("shop.example.com"); x == nil || !x.v.hasHistory() {
		t.Fatal("setup: no traffic history")
	}
	h.blReopen(t, tokyo, rs...) // timedatectl set-timezone Asia/Tokyo, then a restart
	b := h.e.bl
	h.e.baselineTick()
	al, ad := b.signin.peek("mooring|alice"), b.admin.peek("alice")
	if al == nil || al.v.hn != 0 || al.v.n != 21 || ad == nil || ad.v.hn != 0 || b.traffic.peek("shop.example.com").v.hasHistory() {
		t.Fatal("hours not reset, or the entities lost")
	}
	if !al.v.known(0, valueOf("cc", "JP").h) || !al.v.known(1, valueOf("asn", "2516").h) ||
		!al.v.known(2, valueOf("ua", "Chrome on Windows").h) || !ad.v.known(0, valueOf("prog", "systemctl").h) {
		t.Fatal("values lost with the hours")
	}
	// Her usual sign-in (09:10 UTC is 18:10 in tokyo): the old zone's hours would make it unusual.
	h.feed(mooringSignIn(at(29, 18, 10), "alice", jpKDDI, chromeWin))
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("hours of the old zone compared:\n%s", summaries(ds))
	}
	// The values are kept: a new country departs, the known ones don't.
	h.feed(mooringSignIn(at(29, 9, 20), "alice", deExample, chromeWin))
	sudo(t, h, at(29, 9, 30), "root", "/usr/bin/systemctl restart web")
	if ds := h.all(t); len(ds) != 1 || !strings.Contains(ds[0].Summary, "new country DE") {
		t.Fatalf("values after the reset:\n%s", summaries(ds))
	}
	var zone string
	if err := h.e.db.w.QueryRow(`SELECT zone FROM baseline_kinds WHERE kind = 'signin'`).Scan(&zone); err != nil || zone != zoneSig(time.UTC) {
		t.Fatalf("zone before the rewrite %q, %v", zone, err)
	}
	h.e.saveBaselines()
	for _, k := range []string{kindSignin, kindSigninApp, kindAdmin, kindTraffic} {
		if err := h.e.db.w.QueryRow(`SELECT zone FROM baseline_kinds WHERE kind = ?`, k).Scan(&zone); err != nil || zone != zoneSig(tokyo) {
			t.Fatalf("%s: zone after the rewrite %q, %v", k, zone, err)
		}
	}
	// Restarted in the same zone: nothing reset again.
	h.blReopen(t, tokyo, rs...)
	if x := h.e.bl.signin.peek("mooring|alice"); x == nil || x.v.hn != 2 {
		t.Fatalf("hours after a restart in the same zone: %+v", x)
	}
	if zoneSig(tokyo) != zoneSig(time.FixedZone("other", 9*3600)) || zoneSig(tokyo) == zoneSig(time.UTC) {
		t.Fatal("zoneSig: zones with the same offsets are one")
	}
}

// A kind's rewrite goes in transactions of blChunk rows; the rows it doesn't write are deleted with
// the last, so a failure part-way loses no stored row and the rewrite is done again later.
func TestBaselineRewriteInChunks(t *testing.T) {
	h := blHarness(t, tokyo, nil, blRule("baseline.ip_behaviour"))
	tb := h.e.bl.ip
	h.e.saveBaselines() // the zone rewrites of the other kinds
	n := 2*blChunk + 5
	for i := range n {
		x := tb.add(fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255))
		x.v.first, x.v.total = 1, 10
		tb.touch(x)
	}
	h.e.saveBaselines()
	for i := range 3 { // stale rows: entities no longer here
		x := tb.peek(fmt.Sprintf("10.0.0.%d", i))
		tb.lru.Remove(tb.m[x.key])
		delete(tb.m, x.key)
	}
	tb.setResync()
	h.clk.advance(time.Second)
	last := fmt.Sprintf("10.%d.%d.%d", (n-1)>>16, ((n-1)>>8)&255, (n-1)&255) // in the last chunk
	if _, err := h.e.db.w.Exec(`CREATE TRIGGER fail_last BEFORE UPDATE ON baselines WHEN NEW.key = '` + last +
		`' BEGIN SELECT RAISE(FAIL, 'injected'); END`); err != nil {
		t.Fatal(err)
	}
	h.e.saveBaselines()
	var fresh, all int
	stamp := h.clk.now().UnixNano()
	if err := h.e.db.w.QueryRow(`SELECT COUNT(*), SUM(updated_ns >= ?) FROM baselines WHERE kind = 'ip'`, stamp).Scan(&all, &fresh); err != nil {
		t.Fatal(err)
	}
	if !tb.resync || all != n || fresh != 2*blChunk || h.e.bl.backoff == 0 {
		t.Fatalf("after a failed last part: resync %v, %d rows, %d rewritten", tb.resync, all, fresh)
	}
	if _, err := h.e.db.w.Exec(`DROP TRIGGER fail_last`); err != nil {
		t.Fatal(err)
	}
	h.clk.advance(time.Second)
	h.e.saveBaselines()
	rows := blRows(t, h, "ip")
	if tb.resync || len(rows) != n-3 || rows["10.0.0.0"] != nil || rows[last] == nil {
		t.Fatalf("after the rewrite: resync %v, %d rows", tb.resync, len(rows))
	}
}

// Raising a kind's version discards its rows (what its state means changed); the others are kept.
func TestBaselineKindVersion(t *testing.T) {
	rs := []siem.Rule{blRule("baseline.signin_unusual"), blRule("baseline.admin_unusual")}
	h := blHarness(t, tokyo, nil, rs...)
	weekdaySignIns(h, 0, 3, jpKDDI, chromeWin)
	sudo(t, h, at(2, 10, 0), "root", "/usr/bin/systemctl restart web")
	h.e.saveBaselines()
	blVersions[kindSignin]++
	t.Cleanup(func() { blVersions[kindSignin]-- })
	h.blReopen(t, tokyo, rs...)
	if h.e.bl.signin.len() != 0 || len(blRows(t, h, "signin")) != 0 || h.e.bl.admin.peek("alice") == nil {
		t.Fatalf("after a version change: %d accounts, admin kept %v", h.e.bl.signin.len(), h.e.bl.admin.peek("alice") != nil)
	}
}

// A stored row longer than any valid one is discarded unread (and deleted).
func TestBaselineRowSizeBound(t *testing.T) {
	h := blHarness(t, tokyo, nil, blRule("baseline.signin_unusual"))
	h.e.saveBaselines() // the zone recorded (a rewrite would delete the row below anyway)
	var p habit
	for i := range 2000 { // a valid encoding (trimmed when read) of 26 KB
		p.sets[0] = append(p.sets[0], seenVal{h: uint64(i + 1), t: int32(i)})
	}
	p.n, p.first = 5, 1
	big := p.encode()
	if _, err := decodeHabit(big, signinCaps); err != nil || len(big) <= maxBlData {
		t.Fatalf("setup: %d bytes, %v", len(big), err)
	}
	if _, err := h.e.db.w.Exec(`INSERT INTO baselines(kind, key, data, updated_ns) VALUES ('signin', 'mooring|big', ?, 1)`, big); err != nil {
		t.Fatal(err)
	}
	h.blReopen(t, tokyo, blRule("baseline.signin_unusual"))
	if h.e.bl.signin.peek("mooring|big") != nil || blRows(t, h, "signin")["mooring|big"] != nil {
		t.Fatal("an oversized row loaded or kept")
	}
}

// tzif is a zone (TZif version 1) at UTC until at (before 2038), then off seconds east of UTC.
func tzif(t *testing.T, at time.Time, off int32) *time.Location {
	t.Helper()
	b := append([]byte("TZif"), make([]byte, 16)...) // version 1
	for _, n := range []uint32{0, 0, 0, 1, 2, 8} {   // UTC/local, std/wall, leap, times, types, chars
		b = binary.BigEndian.AppendUint32(b, n)
	}
	b = binary.BigEndian.AppendUint32(b, uint32(int32(at.Unix())))
	b = append(b, 1)
	b = append(binary.BigEndian.AppendUint32(b, 0), 0, 0)
	b = append(binary.BigEndian.AppendUint32(b, uint32(off)), 0, 4)
	b = append(b, "AAA\x00BBB\x00"...)
	loc, err := time.LoadLocationFromTZData("test", b)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// zoneSig looks at 2025 to 2035: a zone that departs from another within those years is another
// zone, one that departs later is the same.
func TestBaselineZoneSigSpan(t *testing.T) {
	in2030 := tzif(t, time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC), 3600)
	in2037 := tzif(t, time.Date(2037, 6, 1, 0, 0, 0, 0, time.UTC), 3600) // TZif version 1 times end in 2038
	if _, off := time.Date(2037, 7, 1, 0, 0, 0, 0, time.UTC).In(in2037).Zone(); off != 3600 {
		t.Fatal("setup: the 2037 change not read")
	}
	if zoneSig(in2030) == zoneSig(time.UTC) || zoneSig(in2037) != zoneSig(time.UTC) {
		t.Fatalf("zoneSig: a change in 2030 %v, in 2037 %v", zoneSig(in2030) != zoneSig(time.UTC), zoneSig(in2037) != zoneSig(time.UTC))
	}
}

// appSignIn is a successful sign-in of actor to app at when.
func appSignIn(when time.Time, app, actor string) siem.Event {
	return siem.Event{TS: when.UTC(), Src: siem.SrcApp, App: app, Kind: "auth.login", Out: siem.OutSuccess,
		IP: "198.51.100.20", Actor: actor, Geo: &siem.Geo{Country: "JP", ASN: 2516}}
}

func appRows(t *testing.T, h *harness, app string) []string {
	t.Helper()
	var out []string
	for k := range blRows(t, h, kindSigninApp) {
		if strings.HasPrefix(k, "app:"+app+"|") {
			out = append(out, k)
		}
	}
	return out
}

// DeleteAppBaselines forgets an app's accounts: the saved rows at once, the entries in memory at
// the engine goroutine's next step (with any row of them it saved in between); other apps' (one
// whose slug starts the same), Mooring's and SSH accounts are kept.
func TestBaselineDeleteAppBaselines(t *testing.T) {
	ctx := context.Background()
	h := blHarness(t, tokyo, nil, blRule("baseline.signin_unusual"))
	b := h.e.bl
	for d := range 3 {
		for _, app := range []string{"shop", "shopx"} {
			h.feed(appSignIn(at(d, 9, 0), app, "alice"), appSignIn(at(d, 9, 1), app, "bob"))
		}
		h.feed(mooringSignIn(at(d, 9, 2), "alice", jpKDDI, chromeWin))
	}
	h.e.saveBaselines()
	h.feed(appSignIn(at(3, 9, 0), "shop", "carol")) // not saved yet
	if err := h.e.DeleteAppBaselines(ctx, "shop"); err != nil {
		t.Fatal(err)
	}
	if rows := appRows(t, h, "shop"); len(rows) != 0 || len(appRows(t, h, "shopx")) != 2 {
		t.Fatalf("rows after the call: shop %v, shopx %d", rows, len(appRows(t, h, "shopx")))
	}
	// The engine saved carol's row before its next step took the deletion.
	if err := h.e.db.writeBaselines(ctx, b.signinApp.takeDirty(-1), nil, 1, nil); err != nil {
		t.Fatal(err)
	}
	h.e.baselineTick()
	for _, k := range []string{"app:shop|alice", "app:shop|bob", "app:shop|carol"} {
		if b.signinApp.peek(k) != nil {
			t.Errorf("%s kept in memory", k)
		}
	}
	if b.signinApp.peek("app:shopx|alice") == nil || b.signin.peek("mooring|alice") == nil {
		t.Fatal("another app's or Mooring's account dropped")
	}
	if rows := appRows(t, h, "shop"); len(rows) != 0 || blRows(t, h, kindSignin)["mooring|alice"] == nil {
		t.Fatalf("rows after the engine's step: %v", rows)
	}
	h.blReopen(t, tokyo, blRule("baseline.signin_unusual"))
	if h.e.bl.signinApp.peek("app:shop|alice") != nil || h.e.bl.signinApp.peek("app:shopx|alice") == nil {
		t.Fatal("after a restart")
	}
	// Again (idempotent), and for an app with no entries.
	if err := errors.Join(h.e.DeleteAppBaselines(ctx, "shop"), h.e.DeleteAppBaselines(ctx, "none")); err != nil {
		t.Fatal(err)
	}
	if err := h.e.DeleteAppBaselines(ctx, ""); !errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("empty slug: %v", err)
	}
	if err := h.e.DeleteAppBaselines(ctx, strings.Repeat("s", siem.MaxShort+1)); !errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("long slug: %v", err)
	}
	if err := h.e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.e.DeleteAppBaselines(ctx, "shopx"); !errors.Is(err, errClosed) {
		t.Fatalf("closed engine: %v", err)
	}
}

// For appGoneFor after DeleteAppBaselines, the app's sign-ins (still queued) don't make its
// baselines again; after that an app of that slug (made again) learns.
func TestBaselineDeletedAppStaysGone(t *testing.T) {
	ctx := context.Background()
	h := blHarness(t, tokyo, nil, blRule("baseline.signin_unusual"))
	b := h.e.bl
	for d := range 3 {
		h.feed(appSignIn(at(d, 9, 0), "shop", "alice"), appSignIn(at(d, 9, 0), "other", "alice"))
	}
	del := h.clk.now()
	if err := h.e.DeleteAppBaselines(ctx, "shop"); err != nil {
		t.Fatal(err)
	}
	h.feed(appSignIn(at(2, 9, 5), "shop", "alice"), appSignIn(at(2, 9, 5), "shop", "bob"))
	h.clk.set(del.Add(appGoneFor - time.Second))
	h.feed(appSignIn(h.clk.now(), "shop", "carol"), appSignIn(h.clk.now(), "other", "bob"))
	h.e.saveBaselines()
	if n := b.signinApp.len(); n != 2 || len(appRows(t, h, "shop")) != 0 || b.signinApp.peek("app:other|bob") == nil {
		t.Fatalf("within %v of the delete: %d entries, %d shop rows", appGoneFor, n, len(appRows(t, h, "shop")))
	}
	h.clk.set(del.Add(appGoneFor + time.Second))
	h.feed(appSignIn(h.clk.now(), "shop", "dave"))
	if b.signinApp.peek("app:shop|dave") == nil || len(b.appGone) != 0 {
		t.Fatal("an app of the slug made again doesn't learn")
	}
	// The apps deleted lately are bounded.
	for i := range maxAppDeletes + 10 {
		b.markAppGone(fmt.Sprintf("app:a%d|", i), h.clk.now().Add(time.Duration(i+1)*time.Second), h.clk.now())
	}
	if len(b.appGone) != maxAppDeletes || b.appGone["app:a0|"] != (time.Time{}) || b.appGone[fmt.Sprintf("app:a%d|", maxAppDeletes+9)].IsZero() {
		t.Fatalf("%d apps deleted lately kept", len(b.appGone))
	}
}

// KeepAppBaselines forgets every app not in the list (memory and rows), and none of another source;
// an empty list forgets every app's.
func TestBaselineKeepAppBaselines(t *testing.T) {
	ctx := context.Background()
	h := blHarness(t, tokyo, nil, blRule("baseline.signin_unusual"))
	b := h.e.bl
	for d := range 3 {
		for _, app := range []string{"shop", "shopx", "old"} {
			h.feed(appSignIn(at(d, 9, 0), app, "alice"))
		}
		h.feed(mooringSignIn(at(d, 9, 1), "alice", jpKDDI, chromeWin))
	}
	x := b.signinApp.add("edge|eve") // a sign-in of another source than an app
	b.signinApp.touch(x)
	h.e.saveBaselines()
	h.feed(appSignIn(at(3, 9, 0), "old", "carol")) // learned, not saved yet
	if err := h.e.KeepAppBaselines(ctx, []string{"shop", "shopx"}); err != nil {
		t.Fatal(err)
	}
	if len(appRows(t, h, "old")) != 0 || len(appRows(t, h, "shop")) != 1 || len(appRows(t, h, "shopx")) != 1 ||
		blRows(t, h, kindSigninApp)["edge|eve"] == nil {
		t.Fatalf("rows after the call: old %d", len(appRows(t, h, "old")))
	}
	h.e.baselineTick()
	if b.signinApp.peek("app:old|alice") != nil || b.signinApp.peek("app:old|carol") != nil ||
		b.signinApp.peek("app:shop|alice") == nil || b.signinApp.peek("app:shopx|alice") == nil ||
		b.signinApp.peek("edge|eve") == nil || b.signin.peek("mooring|alice") == nil {
		t.Fatal("entries after the engine's step")
	}
	h.e.saveBaselines()
	if len(appRows(t, h, "old")) != 0 {
		t.Fatal("old's rows saved again")
	}
	// No apps: every app's go.
	if err := h.e.KeepAppBaselines(ctx, nil); err != nil {
		t.Fatal(err)
	}
	h.e.baselineTick()
	h.e.saveBaselines()
	rows := blRows(t, h, kindSigninApp)
	if len(rows) != 1 || rows["edge|eve"] == nil || b.signinApp.len() != 1 || b.signin.peek("mooring|alice") == nil {
		t.Fatalf("after keeping no app: %d rows, %d entries", len(rows), b.signinApp.len())
	}
	if err := h.e.KeepAppBaselines(ctx, []string{"shop", ""}); !errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("an empty slug: %v", err)
	}
}

// While Run runs, DeleteAppBaselines is called from another goroutine (the dashboard's): nothing
// is shared unguarded (go test -race), and the app's entries are gone once the engine stopped.
func TestBaselineDeleteAppBaselinesWhileRunning(t *testing.T) {
	h := blHarness(t, tokyo, nil, blRule("baseline.signin_unusual"))
	for d := range 3 {
		h.feed(appSignIn(at(d, 9, 0), "shop", "alice"), appSignIn(at(d, 9, 0), "other", "alice"))
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.e.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	sub := h.e.Subscriber()
	now := h.clk.now()
	for i := range 50 {
		sub(appSignIn(now, "shop", fmt.Sprint("u", i)))
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(appRows(t, h, "shop")) < 51 { // saved by the write ticks
		if time.Now().After(deadline) {
			t.Fatalf("the engine saved %d rows", len(appRows(t, h, "shop")))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := h.e.DeleteAppBaselines(context.Background(), "shop"); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-done
	if n := len(appRows(t, h, "shop")); n != 0 || len(appRows(t, h, "other")) != 1 {
		t.Fatalf("rows after the engine stopped: shop %d", n)
	}
	h.e.bl.signinApp.each(func(x *tent[habit]) {
		if strings.HasPrefix(x.key, "app:shop|") {
			t.Errorf("%s kept in memory", x.key)
		}
	})
}
