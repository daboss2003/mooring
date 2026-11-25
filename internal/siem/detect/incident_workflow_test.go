package detect

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/store"
)

// run starts the engine's goroutine (the dashboard's changes go through it); stop waits for its
// shutdown. Events are fed before or after, never while it runs.
func (h *harness) run(t *testing.T) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.e.Run(ctx) }()
	waitFor(t, "engine running", h.e.running.Load)
	var once sync.Once
	stop = func() { once.Do(func() { cancel(); <-done }) }
	t.Cleanup(stop)
	return stop
}

func timelineKinds(inc siem.Incident) string {
	var ks []string
	for _, x := range inc.Timeline {
		ks = append(ks, x.Kind)
	}
	return strings.Join(ks, ",")
}

func mustInvalid(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("%s: want ErrInvalidInput, got %v", what, err)
	}
}

func TestIncidentWorkflow(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.h", siem.SevHigh, "ip", "kind:t.h"))
	h.feed(incEv(0, siem.SrcEdge, "t.h", addrX, "", nil))
	id := h.only1(t).ID
	stop := h.run(t)
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(h.e.SetState(ctx, id, siem.IncidentAcknowledged, "owner", "looking"))
	must(h.e.Assign(ctx, id, "alice", "owner"))
	must(h.e.Assign(ctx, id, "alice", "owner")) // unchanged: nothing recorded
	must(h.e.AddNote(ctx, id, "owner", "called the ISP"))
	must(h.e.SetState(ctx, id, siem.IncidentResolved, "bob", ""))
	must(h.e.SetState(ctx, id, siem.IncidentOpen, "owner", "it came back"))
	must(h.e.Assign(ctx, id, "", "owner"))
	must(h.e.AddNote(ctx, id, "owner", strings.Repeat("n", siem.MaxNote)))

	mustInvalid(t, "unknown state", h.e.SetState(ctx, id, "closed", "owner", ""))
	mustInvalid(t, "false positive through SetState", h.e.SetState(ctx, id, siem.IncidentFalsePositive, "owner", ""))
	mustInvalid(t, "empty note", h.e.AddNote(ctx, id, "owner", ""))
	mustInvalid(t, "blank note", h.e.AddNote(ctx, id, "owner", "  \n"))
	mustInvalid(t, "long note", h.e.AddNote(ctx, id, "owner", strings.Repeat("n", siem.MaxNote+1)))
	mustInvalid(t, "long state note", h.e.SetState(ctx, id, siem.IncidentOpen, "owner", strings.Repeat("n", siem.MaxNote+1)))
	mustInvalid(t, "control character", h.e.AddNote(ctx, id, "owner", "a\x00b"))
	mustInvalid(t, "bad UTF-8", h.e.AddNote(ctx, id, "owner", "a\xffb"))
	mustInvalid(t, "unknown incident", h.e.AddNote(ctx, id+100, "owner", "x"))
	mustInvalid(t, "unknown incident (state)", h.e.SetState(ctx, id+100, siem.IncidentResolved, "owner", ""))
	mustInvalid(t, "id 0", h.e.Assign(ctx, 0, "alice", "owner"))
	mustInvalid(t, "assignee on two lines", h.e.Assign(ctx, id, "a\nb", "owner"))
	mustInvalid(t, "long assignee", h.e.Assign(ctx, id, strings.Repeat("a", maxAssignee+1), "owner"))
	mustInvalid(t, "long actor", h.e.AddNote(ctx, id, strings.Repeat("a", maxActor+1), "x"))
	mustInvalid(t, "filter state", func() error { _, err := h.e.Incidents(ctx, siem.IncidentFilter{States: []string{"x"}}); return err }())
	mustInvalid(t, "filter severity", func() error {
		_, err := h.e.Incidents(ctx, siem.IncidentFilter{MinSeverity: "huge"})
		return err
	}())
	mustInvalid(t, "entity kind", func() error { _, _, _, err := h.e.Entity(ctx, siem.Entity{Kind: "x", Key: "y"}); return err }())
	mustInvalid(t, "address with a scope", func() error {
		_, _, _, err := h.e.Entity(ctx, siem.Entity{Kind: siem.EntityAddress, Key: addrX, Scope: "host"})
		return err
	}())
	stop()

	inc := h.incGet(t, id)
	if inc.State != siem.IncidentOpen || inc.Assignee != "" {
		t.Fatalf("incident %+v", inc)
	}
	if k := timelineKinds(inc); k != "opened,detection,state,note,assigned,note,state,state,note,assigned,note" {
		t.Fatalf("timeline %s", k)
	}
	tl := inc.Timeline
	if tl[2].Text != "acknowledged" || tl[2].Actor != "owner" || tl[3].Text != "looking" || tl[4].Text != "alice" ||
		tl[6].Text != "resolved" || tl[6].Actor != "bob" || tl[9].Text != "" || len(tl[10].Text) != siem.MaxNote {
		t.Fatalf("timeline %+v", tl)
	}
	for i := 1; i < len(tl); i++ {
		if tl[i].TS.Before(tl[i-1].TS) {
			t.Fatal("timeline not oldest first")
		}
	}
	// Filters.
	f := func(f siem.IncidentFilter) int {
		incs, err := h.e.Incidents(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		return len(incs)
	}
	x := addr(addrX)
	if f(siem.IncidentFilter{States: []string{"open"}}) != 1 || f(siem.IncidentFilter{States: []string{"resolved"}}) != 0 ||
		f(siem.IncidentFilter{MinSeverity: siem.SevCritical}) != 0 || f(siem.IncidentFilter{MinSeverity: siem.SevHigh}) != 1 ||
		f(siem.IncidentFilter{Entity: &x}) != 1 || f(siem.IncidentFilter{Assignee: "alice"}) != 0 {
		t.Fatal("filters")
	}

	// Every change is a siem.incident event; a note's text is its message.
	var got []string
	for _, e := range incEvents(h) {
		got = append(got, fmt.Sprint(e.F["change"], "/", e.F["actor"], "/", e.F["state"]))
		if e.F["change"] == changeNote && e.Msg != "looking" && e.Msg != "called the ISP" && e.Msg != "it came back" && len(e.Msg) != siem.MaxNote {
			t.Fatalf("note event message %q", e.Msg)
		}
		if e.F["change"] == changeAssigned && e.F["actor"] != "owner" {
			t.Fatalf("assigned event %+v", e)
		}
	}
	want := "opened/<nil>/open,state/owner/acknowledged,note/owner/acknowledged,assigned/owner/acknowledged," +
		"note/owner/acknowledged,state/bob/resolved,state/owner/open,note/owner/open,assigned/owner/open,note/owner/open"
	if strings.Join(got, ",") != want {
		t.Fatalf("events\n%s\nwant\n%s", strings.Join(got, ","), want)
	}
}

// Changes from many goroutines go through the engine goroutine one at a time while it evaluates
// events (run with -race).
func TestIncidentConcurrentChanges(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.h", siem.SevLow, "ip", "kind:t.h"))
	h.feed(incEv(0, siem.SrcEdge, "t.h", addrX, "", nil))
	id := h.only1(t).ID
	h.run(t)
	ctx := context.Background()
	sub := h.e.Subscriber()
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 25 {
				if err := h.e.AddNote(ctx, id, "owner", fmt.Sprint("note ", g, " ", i)); err != nil {
					t.Error(err)
					return
				}
				sub(incEv(time.Duration(i)*time.Millisecond, siem.SrcEdge, "t.h", addrX, "", nil))
				if _, err := h.e.Incidents(ctx, siem.IncidentFilter{}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	inc, _, err := h.e.Incident(ctx, id)
	if err != nil || strings.Count(timelineKinds(inc), "note") != 200 {
		t.Fatalf("notes: %d, %v", strings.Count(timelineKinds(inc), "note"), err)
	}
}

func TestIncidentServiceNeedsRun(t *testing.T) {
	h := incHarness(t, false)
	if err := h.e.AddNote(context.Background(), 1, "owner", "x"); !errors.Is(err, errNotRunning) {
		t.Fatalf("before Run: %v", err)
	}
	stop := h.run(t)
	stop()
	if err := h.e.AddNote(context.Background(), 1, "owner", "x"); !errors.Is(err, errClosed) {
		t.Fatalf("after Run: %v", err)
	}
}

// A resolved incident takes no new detection (a new one opens), and the updates of its own
// detections change nothing and alert nothing.
func TestResolvedIncidentNotJoined(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.a", siem.SevHigh, "ip", "kind:t.a"), incRule("custom.b", siem.SevHigh, "ip", "kind:t.b"))
	h.feed(incEv(0, siem.SrcEdge, "t.a", addrX, "", nil))
	h.flushAlerts()
	id := h.only1(t).ID
	stop := h.run(t)
	if err := h.e.SetState(context.Background(), id, siem.IncidentResolved, "owner", "blocked"); err != nil {
		t.Fatal(err)
	}
	stop()
	h.feed(incEv(10*time.Minute, siem.SrcEdge, "t.a", addrX, "", nil)) // its detection, updated
	if al := h.flushAlerts(); len(al) != 0 {
		t.Fatalf("update of a resolved incident's detection: %+v", al)
	}
	if inc := h.incGet(t, id); inc.Detections != 1 || inc.State != siem.IncidentResolved || !inc.Last.Equal(t0) {
		t.Fatalf("resolved incident changed: %+v", inc)
	}
	h.feed(incEv(11*time.Minute, siem.SrcEdge, "t.b", addrX, "", nil))
	al := h.flushAlerts()
	incs := h.incList(t)
	if len(incs) != 2 || incs[0].State != siem.IncidentOpen || incs[0].Detections != 1 || len(al) != 1 ||
		al[0].DedupeKey != "siem-incident:"+itoa(incs[0].ID) {
		t.Fatalf("a new detection after resolving: %+v %+v", incs, al)
	}
}

// A false positive with mute mutes each (rule, key entity) of the incident for 30 days in Mooring's
// database: those detections are recorded marked muted, alert nothing and join no incident; the
// mute shows on the entity, survives a restart and a rule rebuild, can be removed, and ends.
func TestFalsePositiveMute(t *testing.T) {
	h := incHarness(t, true)
	rA, rB := incRule("custom.fa", siem.SevHigh, "ip", "kind:t.a"), incRule("custom.fb", siem.SevHigh, "ip", "kind:t.b")
	h.only(t, rA, rB)
	h.feed(incEv(0, siem.SrcMooring, "t.a", addrX, "", nil))
	h.feed(incEv(time.Minute, siem.SrcMooring, "t.b", addrX, "alice", nil))
	h.flushAlerts()
	id := h.only1(t).ID
	stop := h.run(t)
	ctx := context.Background()
	marked := h.clk.now()
	if err := h.e.MarkFalsePositive(ctx, id, "owner", true, "our scanner"); err != nil {
		t.Fatal(err)
	}
	mustInvalid(t, "unknown incident", h.e.MarkFalsePositive(ctx, id+9, "owner", true, ""))
	_, _, mutes, err := h.e.Entity(ctx, addr(addrX))
	if err != nil || len(mutes) != 2 || mutes[0].RuleID != "custom.fa" || mutes[0].By != "owner" || mutes[0].IncidentID != id ||
		!mutes[0].Until.Equal(marked.Add(muteFor).Truncate(time.Second)) || mutes[1].RuleID != "custom.fb" {
		t.Fatalf("entity mutes: %+v %v", mutes, err)
	}
	// The incident lists the mutes it made that are in force.
	if inc, _, err := h.e.Incident(ctx, id); err != nil || len(inc.Mutes) != 2 || inc.Mutes[0] != mutes[0] || inc.Mutes[1] != mutes[1] {
		t.Fatalf("incident mutes: %+v %v", inc.Mutes, err)
	}
	stop()
	rows, err := h.main.Query(`SELECT rule_id, kind, scope, key, until_at, by_user, incident_id FROM security_mutes ORDER BY rule_id`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var r, k, s, key, by string
		var until, inc int64
		if err := rows.Scan(&r, &k, &s, &key, &until, &by, &inc); err != nil {
			t.Fatal(err)
		}
		got = append(got, fmt.Sprint(r, "|", k, "|", s, "|", key, "|", until-marked.Unix(), "|", by, "|", inc))
	}
	rows.Close()
	want := fmt.Sprint("custom.fa|address||", addrX, "|2592000|owner|", id, ",custom.fb|address||", addrX, "|2592000|owner|", id)
	if strings.Join(got, ",") != want {
		t.Fatalf("stored mutes\n%s\nwant\n%s", strings.Join(got, ","), want)
	}
	inc := h.incGet(t, id)
	if inc.State != siem.IncidentFalsePositive || timelineKinds(inc) != "opened,detection,detection,state,muted,note" ||
		inc.Timeline[4].Text != "2 rule and entity pairs muted until "+marked.Add(muteFor).Format("2006-01-02 15:04 UTC") {
		t.Fatalf("incident %+v", inc)
	}

	// Recorded, muted, no alert, no incident.
	h.feed(incEv(2*time.Hour, siem.SrcMooring, "t.a", addrX, "", nil))
	if al := h.flushAlerts(); len(al) != 0 {
		t.Fatalf("muted detection alerted: %+v", al)
	}
	ds := h.detections(t, "custom.fa")
	if len(ds) != 2 || !ds[0].Muted || ds[1].Muted || h.detIncident(t, "custom.fa", addrX) != 0 || len(h.incList(t)) != 1 {
		t.Fatalf("muted detection: %+v", ds)
	}
	var mutedEv bool
	for _, e := range h.out.events() {
		mutedEv = mutedEv || (e.Kind == KindDetection && e.F["muted"] == true)
	}
	if !mutedEv {
		t.Fatal("the muted detection's event isn't marked muted")
	}
	// Another address isn't muted.
	h.feed(incEv(2*time.Hour+time.Second, siem.SrcMooring, "t.a", addrY, "", nil))
	if al := h.flushAlerts(); len(al) != 1 || len(h.incList(t)) != 2 {
		t.Fatalf("another address: %+v", al)
	}

	// Applied on a rebuild, and after a restart (read back from Mooring's database).
	if err := h.e.SaveRule(ctx, customRule("other")); err != nil {
		t.Fatal(err)
	}
	if !h.e.isMuted("custom.fa", incEnt{kind: siem.EntityAddress, key: addrX}, h.clk.now()) {
		t.Fatal("mute lost by a rule rebuild")
	}
	h.reopen(t)
	h.e.lim.incidents = true
	h.only(t, rA, rB)
	h.feed(incEv(4*time.Hour, siem.SrcMooring, "t.a", addrX, "", nil))
	if ds := h.detections(t, "custom.fa"); !ds[0].Muted {
		t.Fatalf("mute lost by a restart: %+v", ds[0])
	}

	// Removed: its incident's timeline says so.
	stop = h.run(t)
	if err := h.e.RemoveMute(ctx, "custom.fa", addr(addrX), "owner"); err != nil {
		t.Fatal(err)
	}
	mustInvalid(t, "removed twice", h.e.RemoveMute(ctx, "custom.fa", addr(addrX), "owner"))
	mustInvalid(t, "never muted", h.e.RemoveMute(ctx, "custom.fb", addr(addrY), "owner"))
	stop()
	h.feed(incEv(6*time.Hour, siem.SrcMooring, "t.a", addrX, "", nil))
	if ds := h.detections(t, "custom.fa"); ds[0].Muted || h.detIncident(t, "custom.fa", addrX) == 0 {
		t.Fatalf("after RemoveMute: %+v", ds[0])
	}
	if inc := h.incGet(t, id); !strings.HasSuffix(timelineKinds(inc), "muted") ||
		inc.Timeline[len(inc.Timeline)-1].Text != "mute removed: custom.fa for "+addrX {
		t.Fatalf("timeline %+v", inc.Timeline)
	}
	var changes []string
	for _, e := range incEvents(h) {
		if e.F["incident_id"] == float64(id) {
			changes = append(changes, fmt.Sprint(e.F["change"]))
		}
	}
	if strings.Join(changes, ",") != "opened,state,muted,note,unmuted" {
		t.Fatalf("events %v", changes)
	}

	// The other mute ends after 30 days.
	if !h.e.isMuted("custom.fb", incEnt{kind: siem.EntityAddress, key: addrX}, marked.Add(muteFor-time.Second)) ||
		h.e.isMuted("custom.fb", incEnt{kind: siem.EntityAddress, key: addrX}, marked.Add(muteFor)) {
		t.Fatal("30 days")
	}
}

func TestFalsePositiveWithoutMuteOrStore(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.a", siem.SevHigh, "ip", "kind:t.a"))
	h.feed(incEv(0, siem.SrcEdge, "t.a", addrX, "", nil))
	id := h.only1(t).ID
	stop := h.run(t)
	ctx := context.Background()
	if err := h.e.MarkFalsePositive(ctx, id, "owner", true, ""); !errors.Is(err, ErrNoStore) {
		t.Fatalf("mute without Mooring's database: %v", err)
	}
	if err := h.e.MarkFalsePositive(ctx, id, "owner", false, ""); err != nil {
		t.Fatal(err)
	}
	stop()
	if inc := h.incGet(t, id); inc.State != siem.IncidentFalsePositive || timelineKinds(inc) != "opened,detection,state" {
		t.Fatalf("%+v", inc)
	}
}

// At most maxManual dashboard entries an incident; the timeline keeps maxTimeline entries,
// dropping the oldest detection entries, never the others.
func TestIncidentTimelineBounds(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.a", siem.SevLow, "ip", "kind:t.a"))
	h.feed(incEv(0, siem.SrcMooring, "t.a", "10.0.0.1", "alice", nil))
	id := h.only1(t).ID
	stop := h.run(t)
	ctx := context.Background()
	if err := h.e.AddNote(ctx, id, "owner", "first note"); err != nil {
		t.Fatal(err)
	}
	stop()
	// Detections of one key, each a new one (more than its rule's coalescing hour after the last),
	// each within the join window of the one before.
	for i := range maxTimeline + 20 {
		h.feed(incEv(time.Duration(i+1)*61*time.Minute, siem.SrcMooring, "t.a", "10.0.0.1", "alice", nil))
	}
	inc := h.incGet(t, id)
	if inc.Detections != maxTimeline+21 || len(inc.Timeline) != maxTimeline || inc.Timeline[0].Kind != siem.TimelineOpened ||
		inc.Timeline[1].Kind != siem.TimelineNote {
		t.Fatalf("detections %d, timeline %d: %s…", inc.Detections, len(inc.Timeline), timelineKinds(siem.Incident{Timeline: inc.Timeline[:3]}))
	}
	newest := h.detections(t, "custom.a")[0]
	if last := inc.Timeline[len(inc.Timeline)-1]; last.DetectionID != newest.ID || last.RuleName != "custom.a" {
		t.Fatalf("newest entry %+v, want detection %d", last, newest.ID)
	}

	h2 := incHarness(t, false)
	h2.only(t, incRule("custom.a", siem.SevLow, "ip", "kind:t.a"))
	h2.feed(incEv(0, siem.SrcEdge, "t.a", addrX, "", nil))
	id = h2.only1(t).ID
	h2.run(t)
	for i := range maxManual {
		if err := h2.e.AddNote(ctx, id, "owner", fmt.Sprint(i)); err != nil {
			t.Fatal(i, err)
		}
	}
	mustInvalid(t, "past maxManual", h2.e.AddNote(ctx, id, "owner", "one more"))
}

// Incidents whose last detection is older than the retention go with their timeline and
// entities; the size cap removes open incidents (whole) only when nothing else is left.
func TestIncidentRetentionAndSizeCap(t *testing.T) {
	h := incHarness(t, false)
	h.only(t, incRule("custom.a", siem.SevLow, "ip", "kind:t.a"))
	h.feed(incEv(0, siem.SrcEdge, "t.a", addrX, "", nil))
	id := h.only1(t).ID
	h.clk.set(t0.Add(keepFor + time.Hour))
	h.e.prune()
	if _, ok, _ := h.e.Incident(context.Background(), id); ok {
		t.Fatal("old incident kept")
	}
	for _, tbl := range []string{"incident_timeline", "incident_entities", "incidents", "detections"} {
		var n int
		if err := h.e.db.w.QueryRow(`SELECT COUNT(*) FROM ` + tbl).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s: %d rows, %v", tbl, n, err)
		}
	}
	if _, ok := h.e.incs[id]; ok {
		t.Fatal("pruned incident kept in memory")
	}

	h = incHarness(t, false)
	h.e.lim.newPerHour = 10000
	h.e.db.chunk = 10
	h.only(t, incRule("custom.inc", siem.SevLow, "ip", "kind:t.inc"), incRule("custom.jail", siem.SevLow, "f.jail", "kind:t.jail"))
	pad := strings.Repeat("x", 300)
	for i := range 50 {
		h.feed(incEv(time.Duration(i)*time.Millisecond, siem.SrcHost, "t.inc", ipv4(i), "alice", nil))
	}
	for i := range 200 {
		h.feed(incEv(time.Second+time.Duration(i)*time.Millisecond, siem.SrcHost, "t.jail", "", "", map[string]any{"jail": fmt.Sprint(i, pad)}))
	}
	h.e.flush(true)
	count := func(where string) int {
		var n int
		if err := h.e.db.w.QueryRow(`SELECT COUNT(*) FROM detections WHERE ` + where).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count("incident_id > 0") != 50 || len(h.incList(t)) != 50 {
		t.Fatalf("setup: %d in incidents", count("incident_id > 0"))
	}
	used, _ := h.e.db.used(context.Background())
	h.e.lim.dbBytes = used / 10 * 7
	h.e.capSize()
	if n := count("incident_id = 0"); n == 200 || n == 0 {
		t.Fatalf("detections outside incidents after the cap: %d", n)
	}
	if n := count("incident_id > 0"); n != 50 {
		t.Fatalf("the open incidents' detections went first: %d left", n)
	}
	h.e.lim.dbBytes = 1
	h.e.capSize()
	rows := func(tbl string) int {
		var n int
		if err := h.e.db.w.QueryRow(`SELECT COUNT(*) FROM ` + tbl).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n, m, k, d := rows("incidents"), rows("incident_entities"), rows("incident_timeline"), rows("detections"); n+m+k+d != 0 {
		t.Fatalf("the cap doesn't hold once only open incidents are left: %d incidents, %d entities, %d timeline, %d detections",
			n, m, k, d)
	}
	if len(h.e.incs) != 0 || len(h.e.entIdx) != 0 {
		t.Fatalf("removed incidents kept in memory: %d, %d entities", len(h.e.incs), len(h.e.entIdx))
	}
}

// Migration 0005 applies on a detect.db an older release left at version 4.
func TestMigration0005OnExistingDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, dbFile)
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`CREATE TABLE schema_version (version INTEGER PRIMARY KEY, name TEXT NOT NULL,
		applied_at INTEGER NOT NULL DEFAULT (unixepoch()))`); err != nil {
		t.Fatal(err)
	}
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms[:4] {
		if _, err := old.Exec(m.sql); err != nil {
			t.Fatal(m.name, err)
		}
		if _, err := old.Exec(`INSERT INTO schema_version(version, name) VALUES (?, ?)`, m.version, m.name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := old.Exec(`INSERT INTO detections(source, rule_id, rule_name, severity, sev_rank, key, first_ns, last_ns,
		count, summary) VALUES ('siem', 'ssh.bruteforce', 'SSH brute force', 'medium', 2, ?, 1, 2, 20, 's')`, addrX); err != nil {
		t.Fatal(err)
	}
	old.Close()
	d, err := openDB(dir)
	if err != nil {
		t.Fatalf("upgrade from 4: %v", err)
	}
	defer d.close()
	s, err := scanDetection(d.w.QueryRow(`SELECT ` + detCols + ` FROM detections`))
	if err != nil || s.d.Key != addrX || s.incID != 0 || s.entKind != "" || s.d.Muted {
		t.Fatalf("old row after the upgrade: %+v %v", s, err)
	}
	for _, tbl := range []string{"incidents", "incident_entities", "incident_timeline", "entity_risk"} {
		var n int
		if err := d.w.QueryRow(`SELECT COUNT(*) FROM ` + tbl).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s: %d, %v", tbl, n, err)
		}
	}
}

// Migration 0042 applies on a Mooring database an older release left at version 41.
func TestMigration0042OnExistingDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mooring.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE security_mutes; ` + dropAfter42 + ` DELETE FROM schema_meta WHERE version >= 42;
		INSERT INTO security_rules(id, json, updated_at) VALUES ('custom.kept', '{}', 1)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db, err = store.Open(path)
	if err != nil {
		t.Fatalf("upgrade from 41: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM security_mutes`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("security_mutes after the upgrade: %d, %v", n, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM security_rules WHERE id = 'custom.kept'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("security_rules row: %d, %v", n, err)
	}
	ms := &muteStore{db: db.DB}
	now := time.Unix(1_800_000_000, 0)
	m := siem.Mute{RuleID: "r", Entity: addr(addrX), Until: now.Add(time.Hour), By: "owner", Created: now}
	if err := ms.put(context.Background(), []siem.Mute{m, {RuleID: "old", Entity: addr(addrY), Until: now.Add(-time.Hour), Created: now}},
		now); err != nil {
		t.Fatal(err)
	}
	got, err := ms.load(context.Background(), now)
	if err != nil || len(got) != 1 || got[muteKey{"r", entOf(addr(addrX))}].By != "owner" {
		t.Fatalf("load: %+v %v", got, err)
	}
	got, _ = ms.load(context.Background(), now.Add(2*time.Hour))
	if len(got) != 0 {
		t.Fatalf("ended mutes kept: %+v", got)
	}
}
