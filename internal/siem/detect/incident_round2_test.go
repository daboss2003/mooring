package detect

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
)

// Review round 2 of the incidents (phase 3): one test per fix.

func countRows(t *testing.T, h *harness, q string, args ...any) int {
	t.Helper()
	var n int
	if err := h.e.db.w.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func alertKinds(al []alert.Outbox) string {
	var ks []string
	for _, a := range al {
		ks = append(ks, a.Kind+"/"+a.Level)
	}
	return strings.Join(ks, ",")
}

// Decision 1: a detection joins or opens incidents only through its key entity. A shared carrier
// address in the evidence of account detections doesn't chain them; an attacker-typed user name
// in a spray's evidence doesn't pull that account's later takeover into the attacker's (already
// alerted) incident; brute-forcers all trying root aren't merged through host:root. Each of those
// detections alerts through an incident of its own.
func TestJoinOnlyThroughTheKey(t *testing.T) {
	t.Run("shared address", func(t *testing.T) {
		h := incHarness(t, false)
		h.only(t, incRule("custom.acct", siem.SevHigh, "actor", "kind:t.acct"),
			incRule("custom.crit", siem.SevCritical, "actor", "kind:t.crit"))
		const nat = "100.64.1.1"
		h.feed(incEv(0, siem.SrcMooring, "t.acct", nat, "u0", nil))
		h.feed(incEv(time.Minute, siem.SrcMooring, "t.crit", nat, "u0", nil))
		h.flushAlerts()
		for i := 1; i <= 5; i++ {
			h.feed(incEv(time.Duration(i)*time.Hour/4, siem.SrcMooring, "t.crit", nat, fmt.Sprintf("victim%d", i), nil))
		}
		later := h.flushAlerts()
		if len(later) != 5 || alertKinds(later) != strings.Repeat(IncidentAlertKind+"/critical,", 4)+IncidentAlertKind+"/critical" {
			t.Fatalf("each victim's critical detection alerts: %s", alertKinds(later))
		}
		if n := len(h.incList(t)); n != 6 {
			t.Fatalf("incidents %d, want 6", n)
		}
		rs, list, _, err := h.e.Entity(context.Background(), acct("mooring", "victim5"))
		if err != nil || rs.OpenIncidents != 1 || len(list) != 1 || list[0].Entities[0] != acct("mooring", "victim5") {
			t.Fatalf("victim5: %+v %+v %v", rs, list, err)
		}
	})
	t.Run("user name in the evidence", func(t *testing.T) {
		h := incHarness(t, false)
		h.only(t, incRule("custom.spray", siem.SevHigh, "ip", "kind:t.spray"),
			incRule("custom.crit", siem.SevCritical, "ip", "kind:t.crit"),
			incRule("custom.take", siem.SevCritical, "actor", "kind:t.take"))
		h.feed(incEv(0, siem.SrcMooring, "t.spray", addrX, "owner", nil))
		h.feed(incEv(time.Minute, siem.SrcMooring, "t.crit", addrX, "", nil))
		if a1 := h.flushAlerts(); len(a1) != 1 {
			t.Fatalf("attacker: %s", alertKinds(a1))
		}
		h.feed(incEv(5*time.Hour, siem.SrcMooring, "t.take", addrY, "owner", nil))
		a2 := h.flushAlerts()
		id := h.detIncident(t, "custom.take", "owner")
		if len(a2) != 1 || a2[0].Level != alert.LevelCritical || a2[0].DedupeKey != "siem-incident:"+itoa(id) || id == 1 {
			t.Fatalf("the takeover alerts in its own incident (%d): %+v", id, a2)
		}
	})
	t.Run("ssh root", func(t *testing.T) {
		h := incHarness(t, false)
		h.only(t, packByID["ssh.bruteforce"].Rule, packByID["ssh.success_after_failures"].Rule)
		attack := func(at time.Duration, ip string, succeed bool) {
			for i := 0; i < 20; i++ {
				h.feed(sshFail(at+time.Duration(i)*time.Second, ip))
			}
			if succeed {
				h.feed(ev(at+30*time.Second, siem.SrcHost, siem.KindSSHLogin, siem.OutSuccess, ip, "root",
					map[string]any{"method": "password", "user": "root"}))
			}
		}
		attack(0, "198.51.100.1", false)
		h.flushAlerts()
		attack(time.Hour, "198.51.100.2", true)
		a1 := h.flushAlerts()
		attack(5*time.Hour, "203.0.113.3", true)
		a2 := h.flushAlerts()
		for i, al := range [][]alert.Outbox{a1, a2} {
			if len(al) != 1 || al[0].Level != alert.LevelCritical || !strings.HasPrefix(al[0].Summary, "Brute force then sign-in: ") {
				t.Fatalf("compromise %d: %+v", i+1, al)
			}
		}
		incs := h.incList(t)
		keys := map[siem.Entity]bool{}
		for _, inc := range incs {
			keys[inc.Entities[0]] = true
			if !hasEntity(inc.Entities, acct("host", "root")) {
				t.Errorf("root listed as context: %+v", inc.Entities)
			}
		}
		if len(incs) != 3 || len(keys) != 3 {
			t.Fatalf("one incident per attacker: %+v", incs)
		}
	})
	t.Run("entities past the listed 50", func(t *testing.T) {
		h := incHarness(t, false)
		h.only(t, incRule("custom.ip", siem.SevLow, "ip", "kind:t.ip"), incRule("custom.act", siem.SevLow, "actor", "kind:t.act"))
		for i := range 60 {
			h.feed(incEv(time.Duration(i)*time.Second, siem.SrcMooring, "t.ip", addrX, fmt.Sprint("a", i), nil))
		}
		inc := h.only1(t)
		if len(inc.Entities) != maxIncEntities || hasEntity(inc.Entities, acct("mooring", "a55")) {
			t.Fatalf("listed: %d", len(inc.Entities))
		}
		for _, a := range []string{"a5", "a55"} { // listed, and not listed
			h.feed(incEv(2*time.Minute, siem.SrcMooring, "t.act", addrY, a, nil))
			if id := h.detIncident(t, "custom.act", a); id == inc.ID || id == 0 {
				t.Fatalf("%s: joined %d (X's is %d)", a, id, inc.ID)
			}
		}
		if n := len(h.incList(t)); n != 3 {
			t.Fatalf("incidents %d, want 3", n)
		}
	})
}

// Decision 2: moving a false positive to open, acknowledged or resolved lifts the mutes it made
// (Mooring's database and the set in force), recorded in the timeline; the incident lists its mutes
// in force until then. Another incident's mutes stay.
func TestReopenLiftsTheIncidentsMutes(t *testing.T) {
	h := incHarness(t, true)
	h.only(t, incRule("custom.fa", siem.SevHigh, "ip", "kind:t.a"))
	h.feed(incEv(0, siem.SrcMooring, "t.a", addrX, "", nil))
	h.feed(incEv(time.Minute, siem.SrcMooring, "t.a", addrY, "", nil))
	h.feed(incEv(2*time.Minute, siem.SrcMooring, "t.a", addrZ, "", nil))
	h.flushAlerts()
	idX, idY, idZ := h.detIncident(t, "custom.fa", addrX), h.detIncident(t, "custom.fa", addrY), h.detIncident(t, "custom.fa", addrZ)
	stop := h.run(t)
	ctx := context.Background()
	for _, id := range []int64{idX, idY, idZ} {
		if err := h.e.MarkFalsePositive(ctx, id, "owner", true, ""); err != nil {
			t.Fatal(err)
		}
	}
	if inc, _, _ := h.e.Incident(ctx, idX); len(inc.Mutes) != 1 || inc.Mutes[0].IncidentID != idX || inc.Mutes[0].Entity != addr(addrX) {
		t.Fatalf("mutes listed while a false positive: %+v", inc.Mutes)
	}
	if err := errors.Join(h.e.SetState(ctx, idX, siem.IncidentOpen, "owner", "real after all"),
		h.e.SetState(ctx, idZ, siem.IncidentResolved, "owner", "")); err != nil {
		t.Fatal(err)
	}
	_, _, mx, _ := h.e.Entity(ctx, addr(addrX))
	_, _, my, _ := h.e.Entity(ctx, addr(addrY))
	_, _, mz, _ := h.e.Entity(ctx, addr(addrZ))
	inc, _, _ := h.e.Incident(ctx, idX)
	incZ, _, _ := h.e.Incident(ctx, idZ)
	stop()
	now := h.clk.now()
	if len(mx) != 0 || len(my) != 1 || len(mz) != 0 || len(inc.Mutes) != 0 || len(incZ.Mutes) != 0 ||
		h.e.isMuted("custom.fa", entOf(addr(addrX)), now) || h.e.isMuted("custom.fa", entOf(addr(addrZ)), now) ||
		!h.e.isMuted("custom.fa", entOf(addr(addrY)), now) {
		t.Fatalf("after reopening X and resolving Z: X %+v, Y %+v, Z %+v, incident %+v", mx, my, mz, inc.Mutes)
	}
	if z := h.incGet(t, idZ); timelineKinds(z) != "opened,detection,state,muted,state,muted" || z.State != siem.IncidentResolved ||
		z.Timeline[5].Text != "1 rule and entity pair unmuted: no longer a false positive" {
		t.Fatalf("resolved false positive: %s %+v", timelineKinds(z), z)
	}
	var stored int
	if err := h.main.QueryRow(`SELECT COUNT(*) FROM security_mutes`).Scan(&stored); err != nil || stored != 1 {
		t.Fatalf("stored mutes %d, %v", stored, err)
	}
	inc = h.incGet(t, idX)
	if k := timelineKinds(inc); k != "opened,detection,state,muted,state,muted,note" ||
		inc.Timeline[5].Text != "1 rule and entity pair unmuted: no longer a false positive" || inc.Timeline[5].Actor != "owner" {
		t.Fatalf("timeline %s: %+v", k, inc.Timeline)
	}
	var unmuted bool
	for _, e := range incEvents(h) {
		unmuted = unmuted || (e.F["incident_id"] == float64(idX) && e.F["change"] == changeUnmuted)
	}
	if !unmuted {
		t.Fatal("no unmuted event")
	}
	// The attacker comes back: the detection joins the reopened incident, unmuted.
	h.feed(incEv(2*time.Hour, siem.SrcMooring, "t.a", addrX, "", nil))
	if ds := h.detections(t, "custom.fa"); ds[0].Muted || h.detIncident(t, "custom.fa", addrX) != idX || h.incGet(t, idX).Detections != 2 {
		t.Fatalf("after reopening: %+v", ds[0])
	}
}

// Decision 3: past the size cap, with only open incidents' records left, the oldest open incidents
// go whole (detections, entities, timeline), oldest first, until under the cap.
func TestSizeCapRemovesTheOldestOpenIncidents(t *testing.T) {
	h := incHarness(t, false)
	h.e.lim.newPerHour = 1 << 30
	h.e.db.chunk = 10 // one incident a pass
	h.only(t, incRule("custom.inc", siem.SevLow, "ip", "kind:t.inc"))
	pad := strings.Repeat("p", 250)
	const n = 300
	for i := range n {
		e := incEv(time.Duration(i)*time.Millisecond, siem.SrcEdge, "t.inc", ipv4(i+1), "", nil)
		e.App = fmt.Sprint(i, pad)
		h.feed(e)
	}
	h.e.flush(true)
	used, _ := h.e.db.used(context.Background())
	h.e.lim.dbBytes = used / 10 * 8
	h.e.capSize()
	left := countRows(t, h, `SELECT COUNT(*) FROM incidents`)
	if left == 0 || left == n {
		t.Fatalf("incidents left: %d of %d", left, n)
	}
	if after, _ := h.e.db.used(context.Background()); after > h.e.lim.dbBytes {
		t.Fatalf("still over the cap: %d > %d", after, h.e.lim.dbBytes)
	}
	// The removed ones are the oldest (the first IDs), with everything of theirs.
	minLeft := int64(countRows(t, h, `SELECT MIN(id) FROM incidents`))
	if minLeft != int64(n-left+1) {
		t.Fatalf("oldest left %d, want %d", minLeft, n-left+1)
	}
	for _, q := range []string{`SELECT COUNT(*) FROM detections WHERE incident_id < ?`,
		`SELECT COUNT(*) FROM incident_entities WHERE incident_id < ?`, `SELECT COUNT(*) FROM incident_timeline WHERE incident_id < ?`} {
		if c := countRows(t, h, q, minLeft); c != 0 {
			t.Fatalf("%s: %d", q, c)
		}
	}
	if c := countRows(t, h, `SELECT COUNT(*) FROM detections`); c != left {
		t.Fatalf("detections %d, want %d", c, left)
	}
	for id := int64(1); id < minLeft; id++ {
		if h.e.incs[id] != nil {
			t.Fatalf("removed incident %d kept in memory", id)
		}
	}
	if _, ok := h.e.entIdx[incEnt{kind: siem.EntityAddress, key: ipv4(1)}]; ok {
		t.Fatal("removed incident still indexed")
	}
}

// Fix 5: while detect.db writes fail, a detection that opens an incident (which can't alert
// without its ID) alerts on its own; once the incident is written it doesn't alert that rank again.
func TestDetectionAlertsOnItsOwnWhileIncidentsCantBeWritten(t *testing.T) {
	failWrites := func(t *testing.T, h *harness, on bool) {
		t.Helper()
		q := `DROP TRIGGER fail_incidents`
		if on {
			q = `CREATE TRIGGER fail_incidents BEFORE INSERT ON incidents BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END`
		}
		if _, err := h.e.db.w.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	h := incHarness(t, false)
	h.only(t, incRule("custom.crit", siem.SevCritical, "ip", "kind:t.c"), incRule("custom.h", siem.SevHigh, "ip", "kind:t.h"))
	failWrites(t, h, true)
	h.feed(incEv(0, siem.SrcHost, "t.c", addrX, "", nil))
	h.e.flush(false)
	al := h.alerts()
	if len(al) != 1 || al[0].Kind != AlertKind || al[0].Level != alert.LevelCritical || al[0].DedupeKey != "siem:custom.crit:"+addrX {
		t.Fatalf("while writes fail: %+v (write errors %d)", al, h.e.writeErrors.Load())
	}
	// Opened while the flush waits out its backoff after the failure: alerted at the next tick.
	h.feed(incEv(time.Second, siem.SrcHost, "t.c", addrY, "", nil))
	h.e.flush(false)
	if al := h.alerts(); len(al) != 1 || al[0].DedupeKey != "siem:custom.crit:"+addrY {
		t.Fatalf("during the backoff: %+v", al)
	}
	h.clk.advance(time.Minute)
	h.e.flush(false)
	if al := h.alerts(); len(al) != 0 {
		t.Fatalf("alerted twice while writes fail: %+v", al)
	}
	failWrites(t, h, false)
	h.clk.advance(writeBackoffMax)
	h.e.flush(false)
	if al := h.alerts(); len(al) != 0 {
		t.Fatalf("written: no incident alert for what its detection alerted: %+v", al)
	}
	if r := countRows(t, h, `SELECT MIN(alerted_rank) FROM incidents`); r != 4 || countRows(t, h, `SELECT COUNT(*) FROM incidents`) != 2 {
		t.Fatalf("alerted rank %d", r)
	}
	h.feed(incEv(5*time.Minute, siem.SrcHost, "t.h", addrX, "", nil))
	if al := h.flushAlerts(); len(al) != 0 {
		t.Fatalf("a later high detection: %+v", al)
	}

	// A high one: its own warning while writes fail, then the incident's critical when it rises.
	h = incHarness(t, false)
	h.only(t, incRule("custom.crit", siem.SevCritical, "ip", "kind:t.c"), incRule("custom.h", siem.SevHigh, "ip", "kind:t.h"))
	failWrites(t, h, true)
	h.feed(incEv(0, siem.SrcHost, "t.h", addrX, "", nil))
	h.clk.advance(incNoIDAlert)
	h.e.flush(false)
	if al := h.alerts(); len(al) != 1 || al[0].Kind != AlertKind || al[0].Level != alert.LevelWarning {
		t.Fatalf("high while writes fail: %+v", al)
	}
	failWrites(t, h, false)
	h.clk.advance(writeBackoffMax)
	h.e.flush(false)
	if al := h.alerts(); len(al) != 0 {
		t.Fatalf("written: %+v", al)
	}
	h.feed(incEv(10*time.Minute, siem.SrcHost, "t.c", addrX, "", nil))
	if al := h.flushAlerts(); len(al) != 1 || al[0].Kind != IncidentAlertKind || al[0].Level != alert.LevelCritical {
		t.Fatalf("rise to critical: %+v", al)
	}
}

// Fix 6: a lookup never evicts an incident from memory (one a caller holds stays the one there,
// so no second copy is read), a cached one found for an entity counts as used, and the flush keeps
// the cache within maxIncCache.
func TestIncidentCacheKeepsOneCopy(t *testing.T) {
	h := incHarness(t, false)
	h.e.lim.newPerHour = 1 << 30
	h.only(t, incRule("custom.ip", siem.SevLow, "ip", "kind:t.ip"))
	const n = maxIncCache + 300
	for i := range n {
		h.feed(incEv(time.Duration(i)*time.Millisecond, siem.SrcEdge, "t.ip", ipv4(i+1), "", nil))
		if i%1000 == 999 {
			h.e.flush(true) // at most maxIncNew not written
		}
	}
	h.e.flush(true)
	if len(h.e.incs) > maxIncCache {
		t.Fatalf("the flush kept %d incidents", len(h.e.incs))
	}
	var held *incident
	for _, inc := range h.e.incs {
		held = inc
		break
	}
	// A cached incident found through an entity's reference is used now.
	h.clk.advance(time.Minute)
	held.used = t0
	if inc, gone := h.e.refIncident(&entRef{inc: held, id: held.id}); inc != held || gone || !held.used.Equal(h.clk.now()) {
		t.Fatalf("cache hit: %p %v, used %v", inc, gone, held.used)
	}
	held.used = t0 // the least recently used
	for id := int64(1); id <= n; id++ {
		if h.e.incs[id] == nil {
			if _, ok, err := h.e.incident(id); !ok || err != nil {
				t.Fatal(id, ok, err)
			}
		}
	}
	if h.e.incs[held.id] != held || len(h.e.incs) != n {
		t.Fatalf("a lookup evicted: held kept %v, %d in memory", h.e.incs[held.id] == held, len(h.e.incs))
	}
	h.e.flush(false)
	if len(h.e.incs) > maxIncCache {
		t.Fatalf("after the flush: %d", len(h.e.incs))
	}
}

// Fix 7: the queries of an incident's detections use the partial index detections_incident.
func TestIncidentQueriesUseThePartialIndex(t *testing.T) {
	h := incHarness(t, false)
	plan := func(q string, args ...any) string {
		rows, err := h.e.db.w.Query("EXPLAIN QUERY PLAN "+q, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var id, parent, notused int
			var detail string
			if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
				t.Fatal(err)
			}
			out = append(out, detail)
		}
		return strings.Join(out, " | ")
	}
	for name, p := range map[string]string{
		"incidentSpans":    plan(spansSQL, int64(5), 512),
		"mutePairs":        plan(mutePairsSQL, int64(5), "address", addrX, "", 1001),
		"incidentKeyed":    plan(keyedSQL, int64(5), "account", "alice", "mooring"),
		"unlink":           plan(unlinkSQL+"(?, ?)", int64(5), int64(6)),
		"delete with dets": plan(deleteDetsSQL+"(?, ?)", int64(5), int64(6)),
	} {
		if !strings.Contains(p, "USING INDEX detections_incident") {
			t.Errorf("%s: %s", name, p)
		}
	}
}

// Fix 8: a change its caller gave up on (context ended, or busy) before the engine took it is
// never applied.
func TestAbandonedRequestNotApplied(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.h", siem.SevHigh, "ip", "kind:t.h"))
	h.feed(incEv(0, siem.SrcEdge, "t.h", addrX, "", nil))
	id := h.only1(t).ID
	h.e.running.Store(true) // the engine goroutine is busy elsewhere (not reading reqs)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := h.e.AddNote(ctx, id, "owner", "first try"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("caller: %v", err)
	}
	select {
	case r := <-h.e.reqs:
		h.e.serve(r)
	default:
		t.Fatal("nothing queued")
	}
	if k := timelineKinds(h.incGet(t, id)); k != "opened,detection" {
		t.Fatalf("abandoned note applied: %s", k)
	}
}

// Fix 9: a host.user_change detection keyed by a name a group line and a user line share (useradd
// logs both) alerts once, whichever line comes first and whether its alert was reported back yet.
func TestUserChangeKindFlipAlertsOnce(t *testing.T) {
	line := func(at time.Duration, which string) siem.Event {
		prog := map[string]string{"group": "groupadd", "user": "useradd"}[which]
		return incEv(at, siem.SrcHost, siem.KindUserChange, "", "", map[string]any{"program": prog, which: "alice"})
	}
	for _, order := range [][2]string{{"group", "user"}, {"user", "group"}} {
		for _, drained := range []bool{true, false} {
			h := incHarness(t, false)
			h.only(t, packByID["host.user_change"].Rule)
			h.feed(line(0, order[0]))
			var al []alert.Outbox
			if drained {
				al = append(al, h.flushAlerts()...)
			}
			h.feed(line(time.Second, order[1]))
			al = append(al, h.flushAlerts()...)
			al = append(al, h.flushAlerts()...)
			h.feed(line(time.Minute, order[0]))
			al = append(al, h.flushAlerts()...)
			if len(al) != 1 || len(h.incList(t)) != 1 {
				t.Fatalf("%v (drained %v): alerts %s, incidents %d", order, drained, alertKinds(al), len(h.incList(t)))
			}
		}
	}
}

// Fix 11: an incident alert whose result never comes back counts as in flight for inflightTTL
// only.
func TestIncidentAlertInFlightExpires(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.h", siem.SevHigh, "ip", "kind:t.h"), incRule("custom.c", siem.SevCritical, "ip", "kind:t.c"))
	h.feed(incEv(0, siem.SrcEdge, "t.h", addrX, "", nil))
	h.e.flush(true)
	<-h.e.alerts // taken, never reported back
	h.feed(incEv(time.Minute, siem.SrcEdge, "t.c", addrX, "", nil))
	if al := h.flushAlerts(); len(al) != 0 {
		t.Fatalf("while the first is in flight: %+v", al)
	}
	h.clk.advance(inflightTTL)
	if al := h.flushAlerts(); len(al) != 1 || al[0].Level != alert.LevelCritical {
		t.Fatalf("after inflightTTL: %+v", al)
	}
}

// Fix 12: a detection joins its key's older open incident within the join window, also when the
// key's latest incident is resolved.
func TestDetectionJoinsAnOlderOpenIncidentOfItsKey(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.a", siem.SevLow, "ip", "kind:t.a"), incRule("custom.b", siem.SevLow, "ip", "kind:t.b"),
		incRule("custom.c", siem.SevLow, "ip", "kind:t.c"))
	state := func(id int64, s string) { // as the engine goroutine serves SetState
		t.Helper()
		rep := make(chan incReply, 1)
		h.e.serve(&incReq{op: opState, id: id, state: s, actor: "owner", reply: rep})
		if r := <-rep; r.err != nil {
			t.Fatal(r.err)
		}
	}
	h.feed(incEv(0, siem.SrcEdge, "t.a", addrX, "", nil))
	i1 := h.only1(t).ID
	state(i1, siem.IncidentResolved)
	h.feed(incEv(time.Hour, siem.SrcEdge, "t.b", addrX, "", nil))
	i2 := h.detIncident(t, "custom.b", addrX)
	state(i1, siem.IncidentOpen)
	state(i2, siem.IncidentResolved)
	h.feed(incEv(2*time.Hour, siem.SrcEdge, "t.c", addrX, "", nil))
	if id := h.detIncident(t, "custom.c", addrX); id != i1 || len(h.incList(t)) != 2 {
		t.Fatalf("joined %d (want %d), incidents %d", id, i1, len(h.incList(t)))
	}
}

// Fix 13: user names up to siem.MaxShort bytes can act and be assigned.
func TestLongUserNamesAct(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.h", siem.SevHigh, "ip", "kind:t.h"))
	h.feed(incEv(0, siem.SrcEdge, "t.h", addrX, "", nil))
	id := h.only1(t).ID
	h.run(t)
	long := strings.Repeat("u", 200)
	ctx := context.Background()
	if err := errors.Join(h.e.Assign(ctx, id, long, long), h.e.AddNote(ctx, id, long, "x"),
		h.e.SetState(ctx, id, siem.IncidentAcknowledged, long, "")); err != nil {
		t.Fatal(err)
	}
	mustInvalid(t, "too long", h.e.Assign(ctx, id, strings.Repeat("u", siem.MaxShort+1), "owner"))
}

// Fix 14: a (rule, entity) pair whose key holds a control character or invalid UTF-8 (an app's
// logged user name) isn't muted: every stored mute can be listed and removed.
func TestUnmutablePairsAreSkipped(t *testing.T) {
	for _, key := range []string{"bob�", "bob\x07", "bob\nadmin", "bob"} {
		h := incHarness(t, true)
		h.only(t, incRule("custom.fb", siem.SevHigh, "actor", "kind:t.b"), incRule("custom.fc", siem.SevHigh, "actor", "kind:t.c"))
		h.feed(incEv(0, siem.SrcApp, "t.b", addrX, key, nil))
		h.flushAlerts()
		id := h.only1(t).ID
		// One not written yet: from memory.
		h.feed(incEv(time.Minute, siem.SrcApp, "t.c", addrX, key, nil))
		rep := make(chan incReply, 1)
		h.e.serve(&incReq{op: opFPPairs, id: id, reply: rep})
		r := <-rep
		want := 0
		if key == "bob" {
			want = 2
		}
		if r.err != nil || len(r.pairs) != want {
			t.Fatalf("%q: pairs %+v %v", key, r.pairs, r.err)
		}
		stop := h.run(t)
		if err := h.e.MarkFalsePositive(context.Background(), id, "owner", true, ""); err != nil {
			t.Fatal(err)
		}
		stop()
		var n int
		if err := h.main.QueryRow(`SELECT COUNT(*) FROM security_mutes`).Scan(&n); err != nil || n != want {
			t.Fatalf("%q: stored mutes %d, %v", key, n, err)
		}
	}
}

// Fix 15: deleting an app removes the mutes of its accounts (Mooring's database and in force),
// not those of another app, of Mooring or of addresses.
func TestDeleteAppMutes(t *testing.T) {
	h := incHarness(t, true)
	h.only(t, incRule("custom.fb", siem.SevHigh, "actor", "kind:t.b"), incRule("custom.fa", siem.SevHigh, "ip", "kind:t.a"))
	for i, app := range []string{"shop", "shop-2", ""} { // three detections (2h apart), three scopes
		e := incEv(time.Duration(i)*2*time.Hour, siem.SrcApp, "t.b", "", "alice", nil)
		if app == "" {
			e.Src = siem.SrcMooring
		}
		e.App = app
		h.feed(e)
	}
	h.feed(incEv(5*time.Hour, siem.SrcEdge, "t.a", addrX, "", nil))
	incs := h.incList(t)
	stop := h.run(t)
	ctx := context.Background()
	for _, inc := range incs {
		if err := h.e.MarkFalsePositive(ctx, inc.ID, "owner", true, ""); err != nil {
			t.Fatal(err)
		}
	}
	stop()
	if err := h.e.DeleteAppMutes(ctx, "shop"); err != nil {
		t.Fatal(err)
	}
	mustInvalid(t, "no app", h.e.DeleteAppMutes(ctx, ""))
	mustInvalid(t, "two lines", h.e.DeleteAppMutes(ctx, "a\nb"))
	rows, err := h.main.Query(`SELECT kind, scope, key FROM security_mutes ORDER BY scope`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var k, s, key string
		if err := rows.Scan(&k, &s, &key); err != nil {
			t.Fatal(err)
		}
		got = append(got, k+"|"+s+"|"+key)
	}
	rows.Close()
	if strings.Join(got, ",") != "address||"+addrX+",account|app:shop-2|alice,account|mooring|alice" {
		t.Fatalf("stored %v", got)
	}
	now := h.clk.now()
	if h.e.isMuted("custom.fb", incEnt{siem.EntityAccount, "app:shop", "alice"}, now) ||
		!h.e.isMuted("custom.fb", incEnt{siem.EntityAccount, "app:shop-2", "alice"}, now) ||
		!h.e.isMuted("custom.fb", incEnt{siem.EntityAccount, "mooring", "alice"}, now) {
		t.Fatal("in force")
	}
	if n := len(h.incList(t)); n != 4 {
		t.Fatalf("incidents kept: %d", n)
	}
}

// Fix 16a: a detection whose incident can't be read alerts on its own rather than not at all.
func TestUnreadableIncidentDetectionAlertsOnItsOwn(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.h", siem.SevHigh, "ip", "kind:t.h"))
	h.feed(incEv(0, siem.SrcEdge, "t.h", addrX, "", nil))
	if al := h.flushAlerts(); len(al) != 1 || al[0].Kind != IncidentAlertKind {
		t.Fatalf("first: %+v", al)
	}
	id := h.detIncident(t, "custom.h", addrX)
	delete(h.e.incs, id) // left memory
	for _, refs := range h.e.entIdx {
		for _, r := range refs {
			r.inc = nil
		}
	}
	_ = h.e.db.w.Close() // and detect.db can't be read
	h.feed(incEv(time.Minute, siem.SrcEdge, "t.h", addrX, "", nil))
	if al := h.alerts(); len(al) != 1 || al[0].Kind != AlertKind || al[0].DedupeKey != "siem:custom.h:"+addrX {
		t.Fatalf("unreadable incident: %+v", al)
	}
}

// Fix 16b: an incident removed while its alert was in flight isn't stored again when the result
// comes back.
func TestRemovedIncidentNotWrittenBack(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.h", siem.SevHigh, "ip", "kind:t.h"))
	h.feed(incEv(0, siem.SrcEdge, "t.h", addrX, "", nil))
	h.e.flush(true)
	j := <-h.e.alerts
	h.clk.set(t0.Add(keepFor + time.Hour))
	h.e.prune()
	if n := countRows(t, h, `SELECT COUNT(*) FROM incidents`); n != 0 {
		t.Fatalf("not pruned: %d", n)
	}
	h.e.finishAlert(alertResult{job: j, ok: true})
	h.e.flush(true)
	if n := countRows(t, h, `SELECT COUNT(*) FROM incidents`); n != 0 {
		t.Fatalf("stored again: %d", n)
	}
}
