package alertengine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/alertstore"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/store"
)

// rig is an Engine over a real single-connection store whose only channel is a managed-ntfy channel
// pointed at a loopback test server, which records each delivered message (title and body). Quiet hours
// are 22:00–06:59 UTC on the rig's clock.
type rig struct {
	e  *Engine
	st *alertstore.Store
	db *store.DB

	mu        sync.Mutex
	clock     time.Time
	delivered []string // bodies
	titles    []string
	fail      int         // the next n deliveries fail with HTTP 500
	onDeliver func(n int) // called after the n-th delivery is recorded (from the server goroutine)
	failed    int         // failed deliveries
}

func newRig(t *testing.T) *rig {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	c, err := secret.NewCipher(make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Intentional: the clock starts 40 hours in the past, so every row a test raises is older than the
	// real time (the store prunes by it) and younger than the 48-hour limit on unsent rows.
	r := &rig{st: alertstore.New(db, c), db: db, clock: time.Now().UTC().Add(-40 * time.Hour).Truncate(time.Hour)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		if r.fail > 0 {
			r.fail--
			r.failed++
			r.mu.Unlock()
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		r.delivered = append(r.delivered, string(b))
		r.titles = append(r.titles, req.Header.Get("X-Title"))
		n, hook := len(r.delivered), r.onDeliver
		r.mu.Unlock()
		if hook != nil {
			hook(n)
		}
	}))
	t.Cleanup(srv.Close)
	if err := r.st.SaveChannel(context.Background(), "push", "ntfy_managed",
		[]byte(fmt.Sprintf(`{"url":%q,"topic":"t"}`, srv.URL))); err != nil {
		t.Fatal(err)
	}
	r.e = New(r.st, nil, Config{NotifyMinInterval: time.Millisecond, QuietStartHour: 22, QuietEndHour: 7},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.e.now = r.now
	return r
}

func (r *rig) now() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.clock
}

// at moves the clock forward to the next h:m.
func (r *rig) at(h int, m ...int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	min := 0
	if len(m) > 0 {
		min = m[0]
	}
	c := r.clock
	next := time.Date(c.Year(), c.Month(), c.Day(), h, min, 0, 0, time.UTC)
	if next.Before(c) {
		next = next.Add(24 * time.Hour)
	}
	r.clock = next
}

// advance moves the clock forward by d.
func (r *rig) advance(d time.Duration) {
	r.mu.Lock()
	r.clock = r.clock.Add(d)
	r.mu.Unlock()
}

// addBrokenChannel adds a second channel that always fails; it returns the count of tries it received.
func (r *rig) addBrokenChannel(t *testing.T) *atomic.Int32 {
	t.Helper()
	var tries atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tries.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	if err := r.st.SaveChannel(context.Background(), "zz-broken", "ntfy_managed",
		[]byte(fmt.Sprintf(`{"url":%q,"topic":"t"}`, srv.URL))); err != nil {
		t.Fatal(err)
	}
	return &tries
}

func (r *rig) failures() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failed
}

func (r *rig) failNext(n int) {
	r.mu.Lock()
	r.fail = n
	r.mu.Unlock()
}

func (r *rig) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.delivered...)
}

// summaries returns each delivered body without the note on combined notifications.
func (r *rig) summaries() []string {
	var out []string
	for _, b := range r.got() {
		s, _, _ := strings.Cut(b, "\n\n")
		out = append(out, s)
	}
	return out
}

func (r *rig) gotTitles() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.titles...)
}

// stamp sets created_at of the rows added since maxID to the rig's clock.
func (r *rig) stamp(t *testing.T, maxID int64) {
	t.Helper()
	if _, err := r.db.Exec(`UPDATE alert_outbox SET created_at=? WHERE id>?`, r.now().Unix(), maxID); err != nil {
		t.Fatal(err)
	}
}

func (r *rig) maxID(t *testing.T) int64 {
	t.Helper()
	var id int64
	if err := r.db.QueryRow(`SELECT COALESCE(MAX(id),0) FROM alert_outbox`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (r *rig) enqueue(t *testing.T, key, level, transition, summary string) {
	t.Helper()
	before := r.maxID(t)
	if err := r.st.EnqueueInfra(context.Background(), alert.Outbox{Target: "host", Kind: "test_kind", Level: level,
		Transition: transition, Summary: summary, DedupeKey: key}); err != nil {
		t.Fatal(err)
	}
	r.stamp(t, before)
}

func (r *rig) enqueueRule(t *testing.T, ruleID int64, target, transition, summary string) {
	t.Helper()
	before := r.maxID(t)
	if err := r.st.EnqueueOutbox(context.Background(), []alert.Outbox{{RuleID: ruleID, Target: target,
		Kind: alert.KindContainerDown, Level: alert.LevelWarning, Transition: transition, Summary: summary,
		DedupeKey: fmt.Sprintf("%d:%s:%s", ruleID, alert.KindContainerDown, target)}}); err != nil {
		t.Fatal(err)
	}
	r.stamp(t, before)
}

func (r *rig) pending(t *testing.T) int {
	t.Helper()
	var n int
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM alert_outbox WHERE sent_at=0`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// drainAll drains until nothing deliverable is left (a drain sends at most 100 messages).
func (r *rig) drainAll(t *testing.T) {
	t.Helper()
	for i := 0; i < 10; i++ {
		before := len(r.got())
		r.e.drain(context.Background())
		if len(r.got()) == before {
			return
		}
	}
}

func TestInQuietHours(t *testing.T) {
	cases := []struct {
		start, end int
		on         []int
		off        []int
	}{
		{22, 7, []int{22, 23, 0, 3, 6}, []int{7, 12, 21}}, // wraps midnight
		{1, 5, []int{1, 2, 4}, []int{0, 5, 23}},
		{-1, -1, nil, []int{0, 12, 23}},
		{3, 3, nil, []int{2, 3, 4}},    // an empty window is never quiet
		{0, 24, nil, []int{0, 12, 23}}, // out of range (config turns it off): never quiet, never "all day"
		{24, 7, nil, []int{0, 3, 12}},  // out of range
		{-2, 7, nil, []int{0, 3, 12}},  // out of range
	}
	for _, c := range cases {
		e := &Engine{cfg: Config{QuietStartHour: c.start, QuietEndHour: c.end}}
		for _, h := range c.on {
			if !e.inQuietHours(time.Date(2026, 1, 1, h, 30, 0, 0, time.UTC)) {
				t.Errorf("%d→%d: %02d:30 must be quiet", c.start, c.end, h)
			}
		}
		for _, h := range c.off {
			if e.inQuietHours(time.Date(2026, 1, 1, h, 30, 0, 0, time.UTC)) {
				t.Errorf("%d→%d: %02d:30 must not be quiet", c.start, c.end, h)
			}
		}
	}
}

// During quiet hours a critical row is delivered at once and a warning is held: left unsent, not counted
// as a failed attempt, not pruned while younger than 48 hours. It is delivered when quiet hours end.
func TestQuietHoursHoldWarningsUntilTheyEnd(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.at(23)
	r.enqueue(t, "w", alert.LevelWarning, "firing", "warning-1")
	r.enqueue(t, "c", alert.LevelCritical, "firing", "critical-1")

	r.e.drain(ctx)
	if got := r.got(); !slices.Equal(got, []string{"critical-1"}) {
		t.Fatalf("during quiet hours: delivered %q, want only the critical row", got)
	}
	var sentAt, attempts int64
	if err := r.db.QueryRow(`SELECT sent_at, attempts FROM alert_outbox WHERE dedupe_key='w'`).Scan(&sentAt, &attempts); err != nil {
		t.Fatal(err)
	}
	if sentAt != 0 || attempts != 0 {
		t.Fatalf("a held warning must stay unsent with no failed attempt: sent_at=%d attempts=%d", sentAt, attempts)
	}
	r.st.PruneOutbox(ctx, r.now().Add(24*time.Hour))
	if r.pending(t) != 1 {
		t.Fatal("pruning must never delete a held row younger than 48 hours")
	}

	r.at(3)
	r.e.drain(ctx)
	if len(r.got()) != 1 {
		t.Fatalf("still quiet at 03:00: delivered %q", r.got())
	}

	r.at(7)
	r.e.drain(ctx)
	if got := r.got(); !slices.Equal(got, []string{"critical-1", "warning-1"}) {
		t.Fatalf("after quiet hours: delivered %q, want the held warning too", got)
	}
	if r.pending(t) != 0 {
		t.Error("the delivered warning must be marked sent")
	}
}

// Many held warnings never keep a critical row out of the quiet-hours batch, and every held alert is
// delivered, oldest first, after quiet hours.
func TestQuietHoursManyHeldWarningsDontBlockCritical(t *testing.T) {
	r := newRig(t)
	r.at(23)
	var want []string
	for i := 0; i < 150; i++ {
		s := fmt.Sprintf("warning-%03d", i)
		r.enqueue(t, s, alert.LevelWarning, "firing", s)
		want = append(want, s)
	}
	r.enqueue(t, "c", alert.LevelCritical, "firing", "critical")

	r.e.drain(context.Background())
	if got := r.got(); !slices.Equal(got, []string{"critical"}) {
		t.Fatalf("one quiet-hours drain with 150 held warnings: delivered %d rows %q, want the critical", len(got), got)
	}

	r.at(7)
	r.drainAll(t)
	if got := r.got(); !slices.Equal(got, append([]string{"critical"}, want...)) {
		t.Fatalf("after quiet hours: %d delivered, want the critical then all 150 warnings in order", len(got))
	}
}

// The owner's rule: held notifications of one alert go out as ONE message with the latest state and a
// note on how many changes were combined since when. A re-fire behind a held "resolved" is not lost.
func TestQuietHoursHeldRowsOfOneAlertAreCombined(t *testing.T) {
	r := newRig(t)
	r.at(23, 4)
	r.enqueue(t, "deploy:shop", alert.LevelWarning, "firing", "fired")
	r.e.drain(context.Background())
	r.at(23, 30)
	r.enqueue(t, "deploy:shop", alert.LevelWarning, "resolved", "resolved")
	r.enqueue(t, "deploy:shop", alert.LevelWarning, "firing", "fired again")
	r.enqueue(t, "deploy:shop", alert.LevelWarning, "firing", "fired again") // re-raised: deduped
	r.e.drain(context.Background())
	if len(r.got()) != 0 {
		t.Fatalf("all warnings are held: %q", r.got())
	}
	r.at(7)
	r.drainAll(t)
	want := "fired again\n\nFired twice and recovered once since 23:04."
	if got := r.got(); !slices.Equal(got, []string{want}) {
		t.Fatalf("delivered %q, want one message %q", got, want)
	}
	if got := r.gotTitles(); !slices.Equal(got, []string{"[WARNING] FIRING — test_kind (host)"}) {
		t.Fatalf("titles %q", got)
	}
	if r.pending(t) != 0 {
		t.Error("every combined row must be closed")
	}
}

// A critical raised under a held warning's key pages at once, as one message that also closes the held
// warning; nothing about it arrives in the morning, and a later row is delivered normally.
func TestQuietHoursHeldWarningCombinedIntoCritical(t *testing.T) {
	r := newRig(t)
	r.at(23)
	r.enqueue(t, "selfheal:shop/web", alert.LevelWarning, "firing", "waiting on db")
	r.at(23, 10)
	r.enqueue(t, "selfheal:shop/web", alert.LevelCritical, "firing", "gave up")
	r.e.drain(context.Background())
	if got := r.got(); !slices.Equal(got, []string{"gave up\n\nFired twice since 23:00."}) {
		t.Fatalf("the critical row under the held warning's key must page now, combined: %q", got)
	}
	if got := r.gotTitles(); !strings.HasPrefix(got[0], "[CRITICAL] FIRING") {
		t.Fatalf("title %q", got[0])
	}
	r.at(7)
	r.drainAll(t)
	if len(r.got()) != 1 {
		t.Fatalf("the combined warning must not be delivered again: %q", r.got())
	}
	if r.pending(t) != 0 {
		t.Error("the combined row must be closed, not left pending")
	}
	r.enqueue(t, "selfheal:shop/web", alert.LevelWarning, "resolved", "recovered")
	r.e.drain(context.Background())
	if got := r.summaries(); !slices.Equal(got, []string{"gave up", "recovered"}) {
		t.Fatalf("a newer row is delivered normally: %q", got)
	}
}

// Outside quiet hours nothing is held, and critical alerts go first.
func TestNoQuietHoursDeliversEverythingCriticalFirst(t *testing.T) {
	r := newRig(t)
	r.e.cfg.QuietStartHour, r.e.cfg.QuietEndHour = -1, -1
	r.at(23)
	r.enqueue(t, "w", alert.LevelWarning, "firing", "w")
	r.enqueue(t, "c", alert.LevelCritical, "firing", "c")
	r.e.drain(context.Background())
	if got := r.got(); !slices.Equal(got, []string{"c", "w"}) {
		t.Fatalf("delivered %q", got)
	}
}

// Item 2: a critical raised after quiet hours end goes out before the overnight backlog (it used to wait
// behind every held warning: ~21 minutes for 250 at notify_min_interval 5s).
func TestCriticalGoesBeforeTheOvernightBacklog(t *testing.T) {
	r := newRig(t)
	r.at(23)
	for i := 0; i < 250; i++ {
		s := fmt.Sprintf("w-%03d", i)
		r.enqueue(t, s, alert.LevelWarning, "firing", s)
	}
	r.e.drain(context.Background())
	if len(r.got()) != 0 {
		t.Fatal("warnings are held overnight")
	}
	r.at(7)
	r.enqueue(t, "crit", alert.LevelCritical, "firing", "CRIT")
	r.e.drain(context.Background())
	got := r.got()
	if len(got) == 0 || got[0] != "CRIT" {
		t.Fatalf("the critical must be the first message of the morning drain, got %d messages starting %q", len(got), got[:min(3, len(got))])
	}
	if len(got) != 100 {
		t.Fatalf("a drain sends at most 100 messages: %d", len(got))
	}
}

// Item 2: a critical raised while a drain is sending non-critical alerts goes out next, not after the
// rest of the batch.
func TestCriticalRaisedMidDrainGoesNext(t *testing.T) {
	r := newRig(t)
	r.at(12)
	for i := 0; i < 3; i++ {
		s := fmt.Sprintf("w%d", i)
		r.enqueue(t, s, alert.LevelWarning, "firing", s)
	}
	r.mu.Lock()
	r.onDeliver = func(n int) {
		if n != 1 {
			return
		}
		if err := r.st.EnqueueInfra(context.Background(), alert.Outbox{Target: "host", Kind: "test_kind",
			Level: alert.LevelCritical, Transition: "firing", Summary: "CRIT", DedupeKey: "crit"}); err != nil {
			t.Errorf("enqueue from the channel: %v", err)
		}
	}
	r.mu.Unlock()
	r.e.drain(context.Background())
	if got := r.got(); !slices.Equal(got, []string{"w0", "CRIT", "w1", "w2"}) {
		t.Fatalf("delivered %q, want the critical right after the message being sent when it was raised", got)
	}
}

// The morning after: many transitions overnight become one message per alert, with the count and the
// time of the first; a critical among them pages at night and is never lost.
func TestMorningCollapseOneMessagePerAlert(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if err := r.st.SaveRule(ctx, alert.Rule{Name: "down", Kind: alert.KindContainerDown, Level: alert.LevelWarning, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rules, _ := r.st.ListRules()
	ruleID := rules[0].ID

	r.at(23, 4)
	for i := 0; i < 14; i++ {
		r.enqueue(t, "scale:shop/web", alert.LevelWarning, "firing", "needs capacity")
		r.enqueue(t, "scale:shop/web", alert.LevelWarning, "resolved", "capacity ok")
	}
	r.e.drain(ctx)
	r.at(0, 10)
	r.enqueueRule(t, ruleID, "shop/web", "firing", "shop/web is exited")
	r.enqueueRule(t, ruleID, "shop/web", "resolved", "recovered")
	r.enqueueRule(t, ruleID, "shop/web", "firing", "shop/web is exited again")
	r.enqueueRule(t, ruleID, "shop/api", "firing", "shop/api is exited")
	r.e.drain(ctx)
	r.at(1)
	r.enqueue(t, "deploy:shop", alert.LevelWarning, "firing", "deploy problems")
	r.at(2)
	r.enqueue(t, "diskgc", alert.LevelWarning, "firing", "disk 91%")
	r.e.drain(ctx)
	r.at(2, 30)
	r.enqueue(t, "diskgc", alert.LevelCritical, "firing", "disk 97%")
	r.e.drain(ctx)
	r.at(5)
	r.e.drain(ctx)
	if got := r.got(); !slices.Equal(got, []string{"disk 97%\n\nFired twice since 02:00."}) {
		t.Fatalf("overnight: delivered %q, want only the disk critical (combined with its held warning)", got)
	}

	r.at(7)
	r.drainAll(t)
	wantBodies := []string{
		"disk 97%\n\nFired twice since 02:00.",
		"capacity ok\n\nFired and recovered 14 times since 23:04.",
		"shop/web is exited again\n\nFired twice and recovered once since 00:10.",
		"shop/api is exited",
		"deploy problems",
	}
	if got := r.got(); !slices.Equal(got, wantBodies) {
		t.Fatalf("morning: delivered\n%q\nwant\n%q", got, wantBodies)
	}
	wantTitles := []string{
		"[CRITICAL] FIRING — test_kind (host)",
		"[WARNING] RESOLVED — test_kind (host)",
		"[WARNING] FIRING — container_down (shop/web)",
		"[WARNING] FIRING — container_down (shop/api)",
		"[WARNING] FIRING — test_kind (host)",
	}
	if got := r.gotTitles(); !slices.Equal(got, wantTitles) {
		t.Fatalf("titles\n%q\nwant\n%q", got, wantTitles)
	}
	if r.pending(t) != 0 {
		t.Errorf("%d rows left pending", r.pending(t))
	}
}

// Item 5A: an older critical still being retried after a failed send is never closed by a newer warning
// of the same alert: the combined message goes out at critical level (inside quiet hours too).
func TestCombinedMessageKeepsAnUndeliveredCritical(t *testing.T) {
	r := newRig(t)
	r.at(23, 10)
	r.enqueue(t, "selfheal:shop/web", alert.LevelCritical, "firing", "gave up")
	r.failNext(1)
	r.e.drain(context.Background())
	if len(r.got()) != 0 {
		t.Fatal("the first send failed")
	}
	r.at(23, 20)
	r.enqueue(t, "selfheal:shop/web", alert.LevelWarning, "resolved", "recovered")
	r.e.drain(context.Background())
	want := "recovered\n\nFired and recovered once since 23:10. It was critical at least once in that time."
	if got := r.got(); !slices.Equal(got, []string{want}) {
		t.Fatalf("delivered %q, want %q", got, want)
	}
	if got := r.gotTitles(); !slices.Equal(got, []string{"[CRITICAL] RESOLVED — test_kind (host)"}) {
		t.Fatalf("titles %q", got)
	}
	if r.pending(t) != 0 {
		t.Error("both rows must be closed")
	}
}

// Item 5B: a held warning is not closed because a newer critical of the same alert couldn't be delivered.
// The critical is retried with a backoff through the night (never straight away), and once a channel
// works the message reports the critical's state at critical level, combined with the held warning.
func TestUndeliveredCriticalIsReportedWithTheHeldWarning(t *testing.T) {
	r := newRig(t)
	r.at(23)
	r.enqueue(t, "selfheal:shop/web", alert.LevelWarning, "firing", "waiting on db")
	r.e.drain(context.Background())
	r.at(1)
	r.enqueue(t, "selfheal:shop/web", alert.LevelCritical, "firing", "gave up")
	r.failNext(100)
	for i := 0; i < 5; i++ {
		r.e.drain(context.Background())
	}
	if f := r.failures(); f != 1 {
		t.Fatalf("a failed critical backs off; it isn't retried by the next drains straight away: %d tries", f)
	}
	r.advance(15 * time.Second)
	r.e.drain(context.Background())
	if f := r.failures(); f != 2 {
		t.Fatalf("retried 15 seconds later: %d tries", f)
	}
	r.mu.Lock()
	r.fail = 0
	r.mu.Unlock()
	r.at(7)
	r.drainAll(t)
	if got := r.got(); !slices.Equal(got, []string{"gave up\n\nFired twice since 23:00."}) {
		t.Fatalf("morning: delivered %q", got)
	}
	if got := r.gotTitles(); !slices.Equal(got, []string{"[CRITICAL] FIRING — test_kind (host)"}) {
		t.Fatalf("titles %q", got)
	}
	if r.pending(t) != 0 {
		t.Error("the held warning must be closed by the delivery")
	}
}

// Item 1, end to end: a held "firing", a critical "resolved" for the same key whose delivery keeps
// failing, then the service fails again. The re-fire must be recorded and be what the operator gets: the
// old dedupe compared it with the held firing, dropped it, and the morning message said "recovered".
func TestRefireAfterAnUndeliveredResolveIsDelivered(t *testing.T) {
	r := newRig(t)
	r.at(23)
	r.enqueue(t, "selfheal:shop/web", alert.LevelWarning, "firing", "unhealthy 23:00")
	r.e.drain(context.Background())
	r.at(0)
	r.enqueue(t, "selfheal:shop/web", alert.LevelCritical, "resolved", "recovered 00:00")
	r.failNext(1 << 20)
	for i := 0; i < 4; i++ {
		r.e.drain(context.Background())
	}
	r.at(3)
	r.enqueue(t, "selfheal:shop/web", alert.LevelWarning, "firing", "unhealthy AGAIN 03:00")
	r.e.drain(context.Background())
	r.mu.Lock()
	r.fail = 0
	r.mu.Unlock()
	r.at(7)
	r.drainAll(t)
	got := r.summaries()
	if len(got) != 1 || got[0] != "unhealthy AGAIN 03:00" {
		t.Fatalf("delivered %q, want one message reporting the 03:00 failure", r.got())
	}
	if titles := r.gotTitles(); !strings.HasPrefix(titles[0], "[CRITICAL] FIRING") {
		t.Fatalf("the undelivered critical keeps the message critical: %q", titles)
	}
	if r.pending(t) != 0 {
		t.Error("nothing left pending")
	}
}

// Item 3: with alerting off for days nothing drained the outbox. Enabling it must not replay the
// history: rows older than 48 hours are closed unsent first, and the rest of each alert is one message.
func TestEnablingAlertingLaterSendsOneMessagePerAlert(t *testing.T) {
	r := newRig(t)
	r.at(12)
	for i := 0; i < 250; i++ {
		r.enqueue(t, "scale:shop/web", alert.LevelWarning, "firing", "needs capacity")
		r.enqueue(t, "scale:shop/web", alert.LevelWarning, "resolved", "capacity ok")
	}
	r.enqueue(t, "deploy:old", alert.LevelWarning, "firing", "stale only")
	r.enqueue(t, "deploy:new", alert.LevelWarning, "firing", "recent deploy problem")
	// The first 300 rows of the flapping key and the deploy:old row are from three days ago.
	stale := time.Now().Add(-72 * time.Hour).Unix()
	if _, err := r.db.Exec(`UPDATE alert_outbox SET created_at=? WHERE id<=300 OR dedupe_key='deploy:old'`, stale); err != nil {
		t.Fatal(err)
	}
	r.at(12, 30)
	r.e.notifyOnce(context.Background())
	// One drain: the flapping alert's 200 rows don't fill the batch and keep the other alert waiting.
	want := []string{"capacity ok\n\nFired and recovered 100 times since 12:00.", "recent deploy problem"}
	if got := r.got(); !slices.Equal(got, want) {
		t.Fatalf("delivered %d messages %q, want %q", len(got), got[:min(3, len(got))], want)
	}
	var total int
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM alert_outbox`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 502 || r.pending(t) != 0 {
		t.Fatalf("rows older than 48 hours must be closed unsent before the drain: %d rows, %d pending", total, r.pending(t))
	}
}

// The re-audit's E1 (item 1): one of two channels permanently failing. Each held row of the alert got its
// own 3 tries, so the working channel received the combined message 3 x N times (20 rows: 60 copies). A
// failure now counts against every combined row, and a retry goes only to the channels that didn't take
// the message: the working channel gets it once, the broken one is tried 3 times.
func TestBrokenChannelDoesntDuplicateTheMessage(t *testing.T) {
	r := newRig(t)
	broken := r.addBrokenChannel(t)
	r.at(23)
	for i := 0; i < 10; i++ {
		r.enqueue(t, "scale:shop/web", alert.LevelWarning, "firing", "needs capacity")
		r.enqueue(t, "scale:shop/web", alert.LevelWarning, "resolved", "capacity ok")
	}
	r.at(7)
	for i := 0; i < 200; i++ {
		r.e.drain(context.Background())
	}
	if got := r.got(); len(got) != 1 {
		t.Fatalf("the working channel received %d copies, want 1", len(got))
	}
	if n := broken.Load(); n != 3 {
		t.Fatalf("the broken channel was tried %d times, want 3", n)
	}
	if r.pending(t) != 0 {
		t.Fatalf("%d rows left pending", r.pending(t))
	}
}

// A critical message keeps being retried on the broken channel, never re-sent to the working one, and a
// new state of the alert goes to every channel again.
func TestBrokenChannelCriticalRetriesOnlyTheFailedChannel(t *testing.T) {
	r := newRig(t)
	broken := r.addBrokenChannel(t)
	r.at(12)
	r.enqueue(t, "diskgc", alert.LevelCritical, "firing", "disk 97%")
	for i := 0; i < 6; i++ {
		r.e.drain(context.Background())
		r.advance(time.Hour)
	}
	if got := r.got(); !slices.Equal(got, []string{"disk 97%"}) {
		t.Fatalf("working channel: %q, want the critical once", got)
	}
	if n := broken.Load(); n != 6 {
		t.Fatalf("the broken channel was tried %d times, want 6 (one per hourly drain)", n)
	}
	r.enqueue(t, "diskgc", alert.LevelWarning, "resolved", "disk ok")
	r.e.drain(context.Background())
	if got := r.summaries(); !slices.Equal(got, []string{"disk 97%", "disk ok"}) {
		t.Fatalf("a new state goes to every channel: %q", got)
	}
}

// The re-audit's E2 (item 3): a critical raised for an alert already handled earlier in the same drain
// waited for the whole drain to end (up to 100 messages x channels x notify_min_interval). It goes next.
func TestCriticalForAnAlertSentEarlierInTheDrainGoesNext(t *testing.T) {
	r := newRig(t)
	r.at(23)
	r.enqueue(t, "selfheal:shop/web", alert.LevelWarning, "firing", "dependency wait")
	for i := 0; i < 20; i++ {
		s := fmt.Sprintf("w-%02d", i)
		r.enqueue(t, s, alert.LevelWarning, "firing", s)
	}
	r.mu.Lock()
	r.onDeliver = func(n int) {
		if n != 1 {
			return
		}
		if err := r.st.EnqueueInfra(context.Background(), alert.Outbox{Target: "host", Kind: "test_kind",
			Level: alert.LevelCritical, Transition: "firing", Summary: "CRIT gave up", DedupeKey: "selfheal:shop/web"}); err != nil {
			t.Errorf("enqueue from the channel: %v", err)
		}
	}
	r.mu.Unlock()
	r.at(7)
	r.e.drain(context.Background())
	got := r.summaries()
	if len(got) < 2 || got[0] != "dependency wait" || got[1] != "CRIT gave up" {
		t.Fatalf("delivered %q, want the critical right after the first message", got[:min(3, len(got))])
	}
	if len(got) != 22 || r.pending(t) != 0 {
		t.Fatalf("every alert goes out in the same drain: %d messages, %d pending", len(got), r.pending(t))
	}
}

// Only a failed attempt keeps a critical from being retried within the drain.
func TestFailedCriticalIsNotRetriedInTheSameDrain(t *testing.T) {
	r := newRig(t)
	r.at(12)
	r.enqueue(t, "crit", alert.LevelCritical, "firing", "CRIT")
	for i := 0; i < 3; i++ {
		s := fmt.Sprintf("w%d", i)
		r.enqueue(t, s, alert.LevelWarning, "firing", s)
	}
	r.failNext(1)
	r.mu.Lock()
	r.onDeliver = func(int) { r.advance(time.Minute) } // a slow drain: the critical's backoff runs out mid-drain
	r.mu.Unlock()
	r.e.drain(context.Background())
	if got := r.got(); !slices.Equal(got, []string{"w0", "w1", "w2"}) || r.failures() != 1 {
		t.Fatalf("delivered %q after %d failure(s): the failed critical waits for the next drain", got, r.failures())
	}
	r.e.drain(context.Background())
	if got := r.got(); len(got) != 4 || got[3] != "CRIT" {
		t.Fatalf("the next drain retries it: %q", got)
	}
}

// The re-audit's E4 (item 5): a task failing at 23:00, 03:00 and 06:55 used to report only the 23:00
// failure in the morning. The newest is reported and all three are counted.
func TestHeldRepeatedFiringsReportTheNewest(t *testing.T) {
	r := newRig(t)
	r.at(23)
	r.enqueue(t, "cron:shop:report", alert.LevelWarning, "firing", "task failed at 23:00: disk full")
	r.at(3)
	r.enqueue(t, "cron:shop:report", alert.LevelWarning, "firing", "task failed at 03:00: db down")
	r.at(6, 55)
	r.enqueue(t, "cron:shop:report", alert.LevelWarning, "firing", "task failed at 06:55: timeout")
	r.at(7)
	r.drainAll(t)
	want := "task failed at 06:55: timeout\n\nFired 3 times since 23:00."
	if got := r.got(); !slices.Equal(got, []string{want}) {
		t.Fatalf("morning: %q, want %q", got, want)
	}
}

// The re-audit's E5 (item 6): a critical given up (24 hours of failed sends) before a warning of the same
// alert was held was left out of the morning message, which went out as a plain warning.
//
// Round 4, item 2 (owner decision): that message is critical, but the given-up critical doesn't make it
// page at night. Only an unsent critical row pages during quiet hours; the warning is held until they end.
func TestGivenUpCriticalBeforeAHeldRowKeepsTheMessageCritical(t *testing.T) {
	r := newRig(t)
	r.at(23)
	r.enqueue(t, "diskgc", alert.LevelCritical, "firing", "disk 97%")
	r.failNext(1 << 20)
	r.e.drain(context.Background())
	r.advance(24 * time.Hour)
	r.e.drain(context.Background())
	if r.pending(t) != 0 || r.failures() != 2 {
		t.Fatalf("setup: the critical must be given up after 24 hours: %d pending, %d tries", r.pending(t), r.failures())
	}
	r.mu.Lock()
	r.fail = 0
	r.mu.Unlock()
	r.at(23, 30)
	r.enqueue(t, "diskgc", alert.LevelWarning, "firing", "disk 91%")
	r.e.drain(context.Background())
	r.at(3)
	r.e.drain(context.Background())
	if got := r.got(); len(got) != 0 {
		t.Fatalf("a message critical only because of a given-up critical is held during quiet hours: %q", got)
	}
	r.at(7)
	r.drainAll(t)
	got, titles := r.got(), r.gotTitles()
	if len(got) != 1 || !strings.HasPrefix(got[0], "disk 91%\n\nFired twice since ") ||
		!strings.HasSuffix(got[0], "It was critical at least once in that time.") {
		t.Fatalf("morning: %q", got)
	}
	if titles[0] != "[CRITICAL] FIRING — test_kind (host)" {
		t.Fatalf("title %q", titles[0])
	}
}

// Round 4, item 1: when the write that closes a delivered message failed (a full disk fails writes while
// reads still work), its rows stayed unsent and due, and the drain, which looks for pending criticals
// before every message, sent the same critical again before each warning: 6 times in this drain. A close
// that fails counts as a failed attempt for the rest of the drain, and is logged.
func TestFailedCloseIsNotSentAgainInTheSameDrain(t *testing.T) {
	r := newRig(t)
	var logs bytes.Buffer
	r.e.log = slog.New(slog.NewTextHandler(&logs, nil))
	r.at(12)
	r.enqueue(t, "crit", alert.LevelCritical, "firing", "CRIT")
	want := []string{"CRIT"}
	for i := 0; i < 5; i++ {
		s := fmt.Sprintf("w%d", i)
		r.enqueue(t, s, alert.LevelWarning, "firing", s)
		want = append(want, s)
	}
	r.mu.Lock()
	r.onDeliver = func(n int) {
		if n != 1 {
			return
		}
		// The store's writes fail from the first delivery on; its reads keep working.
		if _, err := r.db.Exec(`PRAGMA query_only=ON`); err != nil {
			t.Errorf("query_only: %v", err)
		}
	}
	r.mu.Unlock()
	r.e.drain(context.Background())
	if got := r.got(); !slices.Equal(got, want) {
		t.Fatalf("delivered %q, want each alert once: %q", got, want)
	}
	if r.pending(t) != 6 {
		t.Fatalf("setup: no delivery could be recorded: %d pending", r.pending(t))
	}
	if !strings.Contains(logs.String(), "recording a delivery's outcome failed") {
		t.Fatalf("the failed close must be logged: %s", logs.String())
	}
}

// A message that every channel took but whose delivery couldn't be recorded stays unsent in the store.
// The next drains must not send it again: they only retry the record, which closes it once the store
// takes writes again.
func TestFailedCloseIsNotSentAgainByTheNextDrains(t *testing.T) {
	r := newRig(t)
	r.at(12)
	r.enqueue(t, "crit", alert.LevelCritical, "firing", "CRIT")
	r.mu.Lock()
	r.onDeliver = func(n int) {
		if n != 1 {
			return
		}
		if _, err := r.db.Exec(`PRAGMA query_only=ON`); err != nil {
			t.Errorf("query_only: %v", err)
		}
	}
	r.mu.Unlock()
	r.e.drain(context.Background())
	for i := 0; i < 3; i++ {
		r.advance(time.Minute)
		r.e.drain(context.Background())
	}
	if got := r.got(); !slices.Equal(got, []string{"CRIT"}) {
		t.Fatalf("delivered %q while the close kept failing, want it once", got)
	}
	if r.pending(t) != 1 {
		t.Fatalf("setup: the delivery must still be unrecorded: %d pending", r.pending(t))
	}
	if _, err := r.db.Exec(`PRAGMA query_only=OFF`); err != nil {
		t.Fatal(err)
	}
	r.advance(time.Minute)
	r.e.drain(context.Background())
	if got := r.got(); !slices.Equal(got, []string{"CRIT"}) {
		t.Fatalf("delivered %q once writes work again, want no resend", got)
	}
	if r.pending(t) != 0 {
		t.Fatalf("the retried record must close the delivered rows: %d pending", r.pending(t))
	}
	// A new state of the alert is a new message and goes to every channel.
	r.enqueue(t, "crit", alert.LevelCritical, "resolved", "OK")
	r.e.drain(context.Background())
	if got := r.summaries(); !slices.Equal(got, []string{"CRIT", "OK"}) {
		t.Fatalf("delivered %q, want the new state sent", got)
	}
}

// A pending alert that can't be read counts as a failed attempt for the rest of the drain. Counted as
// done, a critical one was listed again before every other message and read again each time, using up
// the drain's message budget.
func TestUnreadablePendingAlertIsNotRetriedInTheSameDrain(t *testing.T) {
	r := newRig(t)
	var logs bytes.Buffer
	r.e.log = slog.New(slog.NewTextHandler(&logs, nil))
	r.at(12)
	r.enqueue(t, "crit", alert.LevelCritical, "firing", "CRIT")
	var want []string
	for i := 0; i < 5; i++ {
		s := fmt.Sprintf("w%d", i)
		r.enqueue(t, s, alert.LevelWarning, "firing", s)
		want = append(want, s)
	}
	reads := 0
	r.e.pendingAlert = func(row alertstore.OutboxRow, criticalOnly bool) (alertstore.PendingAlert, bool, error) {
		if row.DedupeKey == "crit" {
			reads++
			return alertstore.PendingAlert{}, false, fmt.Errorf("disk I/O error")
		}
		return r.st.PendingAlert(row, criticalOnly)
	}
	r.e.drain(context.Background())
	if reads != 1 {
		t.Fatalf("the unreadable critical was read %d times in one drain, want 1", reads)
	}
	if got := r.got(); !slices.Equal(got, want) {
		t.Fatalf("delivered %q, want the other alerts: %q", got, want)
	}
	if !strings.Contains(logs.String(), "reading a pending alert failed") {
		t.Fatalf("the failed read must be logged: %s", logs.String())
	}
	if r.pending(t) != 1 {
		t.Fatalf("the unreadable critical must stay pending: %d pending", r.pending(t))
	}
}

// The re-audit's E6 (item 1): one permanently failing channel and an alert with 20 held rows took 60
// failed sends to exhaust; a non-critical message is tried 3 times in all.
func TestFailingChannelTriesAWarningThreeTimes(t *testing.T) {
	r := newRig(t)
	r.at(23)
	for i := 0; i < 10; i++ {
		r.enqueue(t, "scale:shop/web", alert.LevelWarning, "firing", "needs capacity")
		r.enqueue(t, "scale:shop/web", alert.LevelWarning, "resolved", "capacity ok")
	}
	r.at(7)
	r.failNext(1 << 20)
	drains := 0
	for r.pending(t) > 0 && drains < 1000 {
		r.e.drain(context.Background())
		drains++
	}
	if f := r.failures(); f != 3 || drains != 3 {
		t.Fatalf("%d failed sends over %d drains, want 3 and 3", f, drains)
	}
}

// Owner decision: an undelivered critical keeps being retried, 15 seconds after the first failure and
// doubling (at most an hour apart), instead of being given up after 3 attempts.
func TestUndeliveredCriticalKeepsRetrying(t *testing.T) {
	r := newRig(t)
	r.at(12)
	r.enqueue(t, "selfheal:shop/web", alert.LevelCritical, "firing", "gave up")
	r.failNext(5)
	r.e.drain(context.Background())
	for i, wait := range []time.Duration{15, 30, 60, 120, 240} {
		r.advance((wait - 1) * time.Second)
		r.e.drain(context.Background())
		if f := r.failures(); f != i+1 || len(r.got()) != 0 {
			t.Fatalf("%ds after failure %d: retried too early (%d tries)", wait-1, i+1, f)
		}
		r.advance(time.Second)
		r.e.drain(context.Background())
	}
	if got := r.got(); !slices.Equal(got, []string{"gave up"}) || r.failures() != 5 {
		t.Fatalf("delivered %q after %d failures, want the critical once after 5", got, r.failures())
	}
	if r.pending(t) != 0 {
		t.Error("the delivered critical must be closed")
	}
}

// After 24 hours of failed sends a critical is given up.
func TestUndeliveredCriticalIsGivenUpAfterADay(t *testing.T) {
	r := newRig(t)
	r.at(12)
	r.enqueue(t, "selfheal:shop/web", alert.LevelCritical, "firing", "gave up")
	r.failNext(1 << 20)
	for i := 0; i < 30; i++ {
		r.e.drain(context.Background())
		r.advance(time.Hour)
	}
	if f := r.failures(); f != 25 {
		t.Fatalf("%d tries, want hourly tries for 24 hours (25)", f)
	}
	if r.pending(t) != 0 {
		t.Error("the critical must be given up after 24 hours")
	}
}

// The re-audit's E7 (item 4): an operator silences a held rule alert at night; it resolves and its state
// row is deleted. The morning message used to go out because the silence was checked at send time.
func TestSilencedHeldAlertStaysSilentAfterItsStateClears(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if err := r.st.SaveRule(ctx, alert.Rule{Name: "down", Kind: alert.KindContainerDown, Level: alert.LevelWarning, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rules, _ := r.st.ListRules()
	id := rules[0].ID
	r.at(23)
	r.enqueueRule(t, id, "shop/web", "firing", "shop/web is exited")
	if err := r.st.SaveStates(ctx, []alert.State{{RuleID: id, Target: "shop/web", Phase: alert.PhaseFiring, Since: r.now().Unix()}}); err != nil {
		t.Fatal(err)
	}
	r.e.drain(ctx)
	if err := r.st.Silence(ctx, id, "shop/web", time.Now().Add(24*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	r.at(1)
	if err := r.st.SaveStates(ctx, []alert.State{{RuleID: id, Target: "shop/web", Phase: alert.PhaseResolved,
		Since: r.now().Unix(), SilencedUntil: time.Now().Add(24 * time.Hour).Unix()}}); err != nil {
		t.Fatal(err)
	}
	r.enqueueRule(t, id, "shop/web", "resolved", "recovered")
	if err := r.st.SaveStates(ctx, []alert.State{{RuleID: id, Target: "shop/web", Phase: alert.PhaseOK}}); err != nil {
		t.Fatal(err)
	}
	r.at(7)
	r.drainAll(t)
	if got := r.got(); len(got) != 0 {
		t.Fatalf("a silenced alert must stay silent: %q", got)
	}
	if r.pending(t) != 0 {
		t.Error("the silenced rows must be closed")
	}
}

// Low item a: a message whose first combined change is a recovery said "Fired and recovered once since
// <the recovery's time>". It names the first change.
func TestCombinedNoteNamesTheFirstChange(t *testing.T) {
	r := newRig(t)
	r.at(12)
	r.enqueue(t, "deploy:shop", alert.LevelWarning, "firing", "fired")
	r.e.drain(context.Background())
	r.at(23)
	r.enqueue(t, "deploy:shop", alert.LevelWarning, "resolved", "ok")
	r.at(23, 30)
	r.enqueue(t, "deploy:shop", alert.LevelWarning, "firing", "fired again")
	r.at(7)
	r.drainAll(t)
	r.at(23)
	r.enqueue(t, "deploy:shop", alert.LevelWarning, "resolved", "ok 2")
	r.enqueue(t, "deploy:shop", alert.LevelWarning, "firing", "fired 2")
	r.enqueue(t, "deploy:shop", alert.LevelWarning, "resolved", "ok 3")
	r.enqueue(t, "deploy:shop", alert.LevelWarning, "firing", "fired 3")
	r.at(7)
	r.drainAll(t)
	want := []string{"fired", "fired again\n\nRecovered at 23:00, then fired once.",
		"fired 3\n\nRecovered at 23:00, then fired twice and recovered once."}
	if got := r.got(); !slices.Equal(got, want) {
		t.Fatalf("delivered %q, want %q", got, want)
	}
}

// The notifier checks a silence on its own clock, like quiet hours and retries. On the real clock a silence
// that still runs on the notifier's clock read as over (the rig's clock is 40 hours behind the real one).
func TestSilenceIsCheckedOnTheNotifiersClock(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if err := r.st.SaveRule(ctx, alert.Rule{Name: "down", Kind: alert.KindContainerDown, Level: alert.LevelWarning, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rules, _ := r.st.ListRules()
	id := rules[0].ID
	r.at(12)
	r.enqueueRule(t, id, "shop/web", "firing", "shop/web is exited")
	if err := r.st.SaveStates(ctx, []alert.State{{RuleID: id, Target: "shop/web", Phase: alert.PhaseFiring, Since: r.now().Unix()}}); err != nil {
		t.Fatal(err)
	}
	// Silenced for an hour on the notifier's clock (already over on the real one, so Silence closes nothing).
	if err := r.st.Silence(ctx, id, "shop/web", r.now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	r.e.drain(ctx)
	if got := r.got(); len(got) != 0 {
		t.Fatalf("delivered %q inside the silence", got)
	}
}
