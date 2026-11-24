package alertstore

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/store"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cipher, err := secret.NewCipher(make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	return New(db, cipher)
}

// ManagedNtfy returns the subscribe info (base url, topic, read-only username+password)
// but never the write token Mooring publishes with.
func TestManagedNtfyExposesSubscriberCredsNotWriteToken(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	cfg := `{"url":"http://127.0.0.1:2586","topic":"alerts","token":"tk_writeXXXXXXXXXXXXXXXXXXXXXXXXX","sub_user":"phone","sub_pass":"S3cretSubscriberPass","base_url":"https://ntfy.example.com"}`
	if err := s.SaveChannel(ctx, "hosted", "ntfy_managed", []byte(cfg)); err != nil {
		t.Fatal(err)
	}
	info, ok, err := s.ManagedNtfy()
	if err != nil || !ok {
		t.Fatalf("ManagedNtfy: %v ok=%v", err, ok)
	}
	if info.BaseURL != "https://ntfy.example.com" || info.Topic != "alerts" {
		t.Errorf("wrong subscribe info: %+v", info)
	}
	if info.Username != "phone" || info.Password != "S3cretSubscriberPass" {
		t.Errorf("subscriber creds = %q / %q", info.Username, info.Password)
	}
	// The write token must never be reachable through NtfyManagedInfo (no field carries it).
	if strings.Contains(info.Username+info.Password+info.BaseURL+info.Topic, "tk_write") {
		t.Error("the write token must never be exposed via ManagedNtfy")
	}
	// No managed channel → ok=false.
	s2 := newStore(t)
	if _, ok, _ := s2.ManagedNtfy(); ok {
		t.Error("ManagedNtfy must be ok=false when none is configured")
	}
}

func TestChannelEncryptedRoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.SaveChannel(ctx, "hook", "webhook", []byte(`{"url":"https://example.com/h","secret":"top-secret-hmac"}`)); err != nil {
		t.Fatal(err)
	}
	metas, _ := s.ListChannels()
	if len(metas) != 1 || metas[0].Kind != "webhook" {
		t.Fatalf("list channels: %+v", metas)
	}
	var raw []byte
	if err := s.db.QueryRow(`SELECT config_enc FROM alert_channels WHERE name='hook'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "top-secret-hmac") {
		t.Error("channel secret stored in plaintext")
	}
	if _, err := s.ChannelByID(metas[0].ID); err != nil {
		t.Errorf("channel did not rebuild: %v", err)
	}
}

func TestChannelSaveRejectsBadConfig(t *testing.T) {
	s := newStore(t)
	if err := s.SaveChannel(context.Background(), "x", "webhook", []byte(`{"url":"https://x","evil":1}`)); err == nil {
		t.Error("unknown-field config should be rejected")
	}
	if err := s.SaveChannel(context.Background(), "x", "nope", []byte(`{}`)); err == nil {
		t.Error("unknown kind should be rejected")
	}
}

func TestRuleCRUD(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.SaveRule(ctx, alert.Rule{Name: "cpu", Kind: alert.KindHostCPU, Threshold: 90, ForSeconds: 60, Level: alert.LevelWarning, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rules, _ := s.ListRules()
	if len(rules) != 1 || rules[0].Kind != alert.KindHostCPU {
		t.Fatalf("rules: %+v", rules)
	}
	if err := s.SaveRule(ctx, alert.Rule{Name: "bad", Kind: "nonsense"}); err == nil {
		t.Error("unknown kind rule should be rejected")
	}
	_ = s.DeleteRule(ctx, rules[0].ID)
	if rules, _ := s.ListRules(); len(rules) != 0 {
		t.Error("rule not deleted")
	}
}

func TestStatePersistAndPrune(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	states := []alert.State{
		{RuleID: 1, Target: "host", Phase: alert.PhaseFiring, Since: 100, Level: "warning"},
		{RuleID: 1, Target: "shop/web", Phase: alert.PhaseOK},
	}
	if err := s.SaveStates(ctx, states); err != nil {
		t.Fatal(err)
	}
	loaded, _ := s.LoadStates()
	if len(loaded) != 1 || loaded[0].Target != "host" {
		t.Fatalf("expected only the firing row, got %+v", loaded)
	}
	if firing, _ := s.FiringStates(); len(firing) != 1 {
		t.Errorf("firing states: %d", len(firing))
	}
}

func TestOutboxLifecycle(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.EnqueueOutbox(ctx, []alert.Outbox{{RuleID: 1, Target: "host", Kind: "host_cpu", Level: "warning", Transition: "firing", Summary: "hot"}}); err != nil {
		t.Fatal(err)
	}
	pending, _ := s.PendingOutbox(10)
	if len(pending) != 1 {
		t.Fatalf("pending: %d", len(pending))
	}
	p, ok, err := s.PendingAlert(pending[0], false)
	if err != nil || !ok {
		t.Fatalf("PendingAlert: ok=%v err=%v", ok, err)
	}
	s.FinishAlert(ctx, p, true, time.Now())
	if p, _ := s.PendingOutbox(10); len(p) != 0 {
		t.Error("row should be sent")
	}
}

func TestAckAndSilence(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_ = s.SaveStates(ctx, []alert.State{{RuleID: 1, Target: "host", Phase: alert.PhaseFiring, Since: 1}})
	if err := s.Ack(ctx, 1, "host"); err != nil {
		t.Fatal(err)
	}
	fs, _ := s.FiringStates()
	if len(fs) != 1 || !fs[0].Acked {
		t.Errorf("ack not recorded: %+v", fs)
	}
	_ = s.Silence(ctx, 1, "host", 1<<40)
	if !s.IsSilenced(1, "host", 100) {
		t.Error("silence not recorded")
	}
}

// The evaluator saves the states it loaded before evaluating. An ack or silence the operator set in
// between must survive that save: the states it writes back carry the values from before.
func TestSaveStatesKeepsAnAckAndSilenceSetSinceTheLoad(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.SaveStates(ctx, []alert.State{{RuleID: 1, Target: "host", Phase: alert.PhaseFiring, Since: 1}}); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.LoadStates()
	if err != nil || len(loaded) != 1 {
		t.Fatalf("load: %v %+v", err, loaded)
	}
	if err := s.Ack(ctx, 1, "host"); err != nil {
		t.Fatal(err)
	}
	if err := s.Silence(ctx, 1, "host", 1<<40); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveStates(ctx, loaded); err != nil { // the same episode, still firing
		t.Fatal(err)
	}
	if !s.IsSilenced(1, "host", 100) {
		t.Error("the save dropped a silence set after the load")
	}
	if fs, _ := s.FiringStates(); len(fs) != 1 || !fs[0].Acked {
		t.Errorf("the save dropped an ack set after the load: %+v", fs)
	}

	// The episode ends: the evaluator clears the ack on purpose, and the silence stays until it expires.
	resolved := loaded[0]
	resolved.Phase, resolved.Since, resolved.Acked = alert.PhaseResolved, 2, false
	if err := s.SaveStates(ctx, []alert.State{resolved}); err != nil {
		t.Fatal(err)
	}
	all, _ := s.LoadStates()
	if len(all) != 1 || all[0].Acked {
		t.Errorf("a new phase must clear the ack: %+v", all)
	}
	if !s.IsSilenced(1, "host", 100) {
		t.Error("a new phase must keep the silence")
	}
	// Lifting the silence (an until in the past) isn't undone by the next save either.
	loaded, _ = s.LoadStates()
	if err := s.Silence(ctx, 1, "host", 0); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveStates(ctx, loaded); err != nil {
		t.Fatal(err)
	}
	if s.IsSilenced(1, "host", 100) {
		t.Error("the save restored a silence lifted after the load")
	}
}

func pendingCount(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM alert_outbox WHERE sent_at=0`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func enqInfra(t *testing.T, s *Store, key, level, transition, summary string) {
	t.Helper()
	if err := s.EnqueueInfra(context.Background(), alert.Outbox{Target: "shop/web", Kind: "k", Level: level,
		Transition: transition, Summary: summary, DedupeKey: key}); err != nil {
		t.Fatal(err)
	}
}

func rowCount(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM alert_outbox`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func newestID(t *testing.T, s *Store) int64 {
	t.Helper()
	var id int64
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(id),0) FROM alert_outbox`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func exec(t *testing.T, s *Store, q string, args ...any) {
	t.Helper()
	if _, err := s.db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

// The re-audit's repro: a warning "firing" is held (23:00), a critical "resolved" for the same key is
// delivered (00:00), the service fails again (03:00). The 03:00 "firing" must be recorded: comparing it
// with the newest UNSENT row (the held 23:00 one) dropped it, so the operator's last message said
// "recovered" while the service was failing.
func TestEnqueueInfraComparesWithTheNewestRowSentOrNot(t *testing.T) {
	s := newStore(t)
	enqInfra(t, s, "selfheal:shop/web", alert.LevelWarning, "firing", "23:00")
	enqInfra(t, s, "selfheal:shop/web", alert.LevelCritical, "resolved", "00:00")
	exec(t, s, `UPDATE alert_outbox SET sent_at=1 WHERE id=?`, newestID(t, s))
	enqInfra(t, s, "selfheal:shop/web", alert.LevelWarning, "firing", "03:00")
	if n := rowCount(t, s); n != 3 {
		t.Fatalf("the 03:00 re-fire was dropped as a duplicate of the held 23:00 row: %d rows, want 3", n)
	}
	enqInfra(t, s, "selfheal:shop/web", alert.LevelWarning, "firing", "03:00")
	if n := rowCount(t, s); n != 3 {
		t.Fatalf("a re-raise of the newest pending row must be skipped: %d rows, want 3", n)
	}
	// A newest row that was given up (closed after failed attempts) doesn't stop a re-raise either.
	exec(t, s, `UPDATE alert_outbox SET sent_at=1, attempts=3, given_up=1 WHERE id=?`, newestID(t, s))
	enqInfra(t, s, "selfheal:shop/web", alert.LevelWarning, "firing", "03:00")
	if n := rowCount(t, s); n != 4 {
		t.Fatalf("after a given-up row: %d rows, want 4", n)
	}
}

// EnqueueInfra skips a row only when the newest row for its key is unsent with the same transition and
// level. Quiet hours hold rows unsent for hours, so comparing with ANY unsent row would drop a re-fire
// queued behind a held "resolved", and a held warning would swallow a critical raised under the same key.
func TestEnqueueInfraDedupesAgainstNewestRow(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	enq := func(transition, level string) {
		t.Helper()
		if err := s.EnqueueInfra(ctx, alert.Outbox{Target: "shop/web", Kind: "dependency_wait", Level: level,
			Transition: transition, DedupeKey: "selfheal:shop/web"}); err != nil {
			t.Fatal(err)
		}
	}
	steps := []struct {
		transition, level string
		want              int
	}{
		{"firing", alert.LevelWarning, 1},
		{"firing", alert.LevelWarning, 1}, // re-raised each tick: no pile-up
		{"resolved", alert.LevelWarning, 2},
		{"resolved", alert.LevelWarning, 2},
		{"firing", alert.LevelWarning, 3},  // re-fire behind a held resolved is kept
		{"firing", alert.LevelCritical, 4}, // a held warning never swallows a critical
		{"firing", alert.LevelCritical, 4},
	}
	for i, st := range steps {
		enq(st.transition, st.level)
		if got := pendingCount(t, s); got != st.want {
			t.Fatalf("step %d (%s %s): %d pending rows, want %d", i, st.transition, st.level, got, st.want)
		}
	}
	// Once delivered, the same condition can be queued again.
	if _, err := s.db.Exec(`UPDATE alert_outbox SET sent_at=1`); err != nil {
		t.Fatal(err)
	}
	enq("firing", alert.LevelCritical)
	if got := pendingCount(t, s); got != 1 {
		t.Fatalf("after delivery: %d pending, want 1", got)
	}
}

// PendingAlerts(critical only) filters in the query: any number of older non-critical rows can't keep a
// critical alert out of the batch.
func TestPendingCriticalAlertsSkipHeldRowsBeforeLimit(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for i := 0; i < 150; i++ {
		if err := s.EnqueueInfra(ctx, alert.Outbox{Target: "host", Kind: "k", Level: alert.LevelWarning,
			Transition: "firing", DedupeKey: fmt.Sprintf("w%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range []string{"c1", "c2"} {
		if err := s.EnqueueInfra(ctx, alert.Outbox{Target: "host", Kind: "k", Level: alert.LevelCritical,
			Transition: "firing", DedupeKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	crit, err := s.PendingAlerts(100, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(crit) != 2 || crit[0].DedupeKey != "c1" || crit[1].DedupeKey != "c2" {
		t.Fatalf("want the two critical rows oldest first, got %+v", crit)
	}
	if one, _ := s.PendingAlerts(1, true, time.Now()); len(one) != 1 || one[0].DedupeKey != "c1" {
		t.Fatalf("limit 1: %+v", one)
	}
	if all, _ := s.PendingAlerts(100, false, time.Now()); len(all) != 100 || all[0].DedupeKey != "w0" {
		t.Fatalf("every level, oldest first: %d rows", len(all))
	}
}

// PendingAlerts returns one row per alert — the alert's oldest unsent row — so one alert with many rows
// can't fill the batch and keep the other alerts waiting.
func TestPendingAlertsOneRowPerAlert(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for i := 0; i < 150; i++ {
		enqInfra(t, s, "flap", alert.LevelWarning, "firing", "")
		enqInfra(t, s, "flap", alert.LevelWarning, "resolved", "")
	}
	enqInfra(t, s, "other", alert.LevelWarning, "firing", "other")
	enqInfra(t, s, "flap", alert.LevelCritical, "firing", "crit")
	if err := s.EnqueueOutbox(ctx, []alert.Outbox{
		{RuleID: 1, Target: "shop/web", Kind: "container_down", Level: "warning", Transition: "firing"},
		{RuleID: 1, Target: "shop/web", Kind: "container_down", Level: "warning", Transition: "resolved"},
		{RuleID: 1, Target: "shop/api", Kind: "container_down", Level: "warning", Transition: "firing"},
		{RuleID: 2, Target: "shop/web", Kind: "restart_storm", Level: "warning", Transition: "firing"},
	}); err != nil {
		t.Fatal(err)
	}
	exec(t, s, `INSERT INTO alert_outbox(rule_id, target, kind, level, transition, summary, dedupe_key, created_at)
		VALUES(0,'x','k','warning','firing','a','',1), (0,'x','k','warning','firing','b','',2)`)
	all, err := s.PendingAlerts(100, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, r := range all {
		keys = append(keys, r.AlertKey())
	}
	want := []string{"infra:flap", "infra:other", "rule:1:shop/web", "rule:1:shop/api", "rule:2:shop/web"}
	if len(keys) != 7 || strings.Join(keys[:5], ",") != strings.Join(want, ",") || keys[5] == keys[6] {
		t.Fatalf("one row per alert, oldest first: %v", keys)
	}
	if all[0].ID != 1 {
		t.Fatalf("an alert's entry is its oldest unsent row: %+v", all[0])
	}
	crit, _ := s.PendingAlerts(100, true, time.Now())
	if len(crit) != 1 || crit[0].Summary != "crit" {
		t.Fatalf("critical only: the alert's oldest critical row: %+v", crit)
	}
}

// One alert is one dedupe key for infra rows, and one (rule, target) for a rule's rows; an infra row
// without a key is an alert of its own. PendingAlert combines every unsent row of the row's alert: the
// newest is the state reported, the level is critical when any row is.
func TestPendingAlertCombinesTheRowsOfOneAlert(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	enqInfra(t, s, "selfheal:shop/web", alert.LevelWarning, "firing", "w-fire")
	enqInfra(t, s, "selfheal:shop/web", alert.LevelWarning, "resolved", "w-ok")
	enqInfra(t, s, "other", alert.LevelWarning, "firing", "other")
	enqInfra(t, s, "selfheal:shop/web", alert.LevelCritical, "firing", "c-fire")
	enqInfra(t, s, "selfheal:shop/web", alert.LevelWarning, "resolved", "w-ok-2")
	exec(t, s, `UPDATE alert_outbox SET created_at=id*100`)
	if err := s.EnqueueOutbox(ctx, []alert.Outbox{
		{RuleID: 1, Target: "shop/web", Kind: "container_down", Level: "warning", Transition: "firing", DedupeKey: "1:container_down:shop/web"},
		{RuleID: 1, Target: "shop/api", Kind: "container_down", Level: "warning", Transition: "firing", DedupeKey: "1:container_down:shop/api"},
		{RuleID: 2, Target: "shop/web", Kind: "restart_storm", Level: "warning", Transition: "firing", DedupeKey: "2:restart_storm:shop/web"},
		{RuleID: 1, Target: "shop/web", Kind: "container_down", Level: "warning", Transition: "resolved", Summary: "recovered", DedupeKey: "1:container_down:shop/web"},
	}); err != nil {
		t.Fatal(err)
	}
	// Two keyless infra rows (no producer sends one today): each is its own alert.
	exec(t, s, `INSERT INTO alert_outbox(rule_id, target, kind, level, transition, summary, dedupe_key, created_at)
		VALUES(0,'x','k','warning','firing','a','',1), (0,'x','k','warning','firing','b','',2)`)
	rows, err := s.PendingOutbox(100)
	if err != nil || len(rows) != 11 {
		t.Fatalf("rows: %d %v", len(rows), err)
	}
	get := func(r OutboxRow) PendingAlert {
		t.Helper()
		p, ok, err := s.PendingAlert(r, false)
		if err != nil || !ok {
			t.Fatalf("PendingAlert(%+v): ok=%v err=%v", r, ok, err)
		}
		return p
	}
	sh := get(rows[0])
	if sh.Count != 4 || sh.Fired != 2 || sh.Resolved != 2 || sh.Level != alert.LevelCritical ||
		sh.Latest.Summary != "w-ok-2" || sh.Since != rows[0].ID*100 {
		t.Fatalf("selfheal alert: %+v", sh)
	}
	if again := get(rows[3]); again.Latest.ID != sh.Latest.ID || again.Count != 4 {
		t.Fatalf("any row of the alert gives the same combination: %+v", again)
	}
	if o := get(rows[2]); o.Count != 1 || o.Latest.Summary != "other" || o.Level != alert.LevelWarning {
		t.Fatalf("another key is another alert: %+v", o)
	}
	web := get(rows[5])
	if web.Count != 2 || web.Fired != 1 || web.Resolved != 1 || web.Latest.Transition != "resolved" {
		t.Fatalf("rule 1 on shop/web: %+v", web)
	}
	if api := get(rows[6]); api.Count != 1 {
		t.Fatalf("rule 1 on another target is another alert: %+v", api)
	}
	if r2 := get(rows[7]); r2.Count != 1 {
		t.Fatalf("another rule on the same target is another alert: %+v", r2)
	}
	if a := get(rows[9]); a.Count != 1 || a.Latest.Summary != "a" {
		t.Fatalf("keyless row a: %+v", a)
	}
	if b := get(rows[10]); b.Count != 1 || b.Latest.Summary != "b" {
		t.Fatalf("keyless row b: %+v", b)
	}
	keys := map[string]bool{}
	for _, i := range []int{0, 2, 5, 6, 7, 9, 10} {
		keys[rows[i].AlertKey()] = true
	}
	if len(keys) != 7 || rows[0].AlertKey() != rows[4].AlertKey() || rows[5].AlertKey() != rows[8].AlertKey() {
		t.Fatalf("AlertKey must match the alert identity: %v", keys)
	}
}

// outboxRow is one row's delivery bookkeeping.
type outboxRow struct {
	sentAt, attempts, nextTry int64
	givenUp                   bool
}

func readRow(t *testing.T, s *Store, id int64) outboxRow {
	t.Helper()
	var r outboxRow
	var g int
	if err := s.db.QueryRow(`SELECT sent_at, attempts, next_try_at, given_up FROM alert_outbox WHERE id=?`, id).
		Scan(&r.sentAt, &r.attempts, &r.nextTry, &g); err != nil {
		t.Fatal(err)
	}
	r.givenUp = g == 1
	return r
}

func pendingAlert(t *testing.T, s *Store, r OutboxRow, criticalOnly bool) PendingAlert {
	t.Helper()
	p, ok, err := s.PendingAlert(r, criticalOnly)
	if err != nil || !ok {
		t.Fatalf("PendingAlert(%+v): ok=%v err=%v", r, ok, err)
	}
	return p
}

// A delivered message closes every row it combined, never a row raised after it was read.
func TestFinishAlertDeliveredClosesOnlyTheCombinedRows(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	enqInfra(t, s, "k", alert.LevelWarning, "firing", "held warning")
	enqInfra(t, s, "k", alert.LevelCritical, "firing", "critical")
	rows, _ := s.PendingOutbox(10)
	p := pendingAlert(t, s, rows[0], false)
	enqInfra(t, s, "k", alert.LevelWarning, "resolved", "after the read")
	s.FinishAlert(ctx, p, true, time.Now())
	pending, _ := s.PendingOutbox(10)
	if len(pending) != 1 || pending[0].Summary != "after the read" {
		t.Fatalf("a delivery closes only the rows it combined: %+v", pending)
	}
	if r := readRow(t, s, rows[1].ID); r.sentAt == 0 || r.givenUp {
		t.Fatalf("a delivered row is closed and not given up: %+v", r)
	}
	if _, ok, _ := s.PendingAlert(rows[0], false); !ok {
		t.Fatal("the newer row is still a pending alert")
	}
}

// Round 4, item 1: FinishAlert discarded its write's error, so the notifier couldn't tell a delivery it had
// recorded from one it hadn't (and sent the latter again). It returns the error; the rows stay as they were.
func TestFinishAlertReportsAFailedWrite(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	enqInfra(t, s, "diskgc", alert.LevelCritical, "firing", "disk 97%")
	rows, _ := s.PendingOutbox(10)
	p := pendingAlert(t, s, rows[0], false)
	exec(t, s, `PRAGMA query_only=ON`)
	for _, delivered := range []bool{true, false} {
		if err := s.FinishAlert(ctx, p, delivered, time.Now()); err == nil {
			t.Fatalf("delivered=%v: a failed write must be reported", delivered)
		}
	}
	if r := readRow(t, s, rows[0].ID); r != (outboxRow{}) {
		t.Fatalf("the row must be left as it was: %+v", r)
	}
	exec(t, s, `PRAGMA query_only=OFF`)
	if err := s.FinishAlert(ctx, p, true, time.Now()); err != nil {
		t.Fatalf("a recorded delivery reports no error: %v", err)
	}
	if n := pendingCount(t, s); n != 0 {
		t.Fatalf("the delivery closes the row: %d pending", n)
	}
}

// The re-audit's repro (item 1): a failed send counted an attempt only against the newest unsent row, so
// each older row of the alert got 3 tries of its own and one broken channel made the message go out 3 x N
// times. A failure now counts against every unsent row the message combined: after 3 failed attempts of
// a non-critical message all of them are given up.
func TestFailedDeliveryCountsAgainstEveryCombinedRow(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		enqInfra(t, s, "scale:shop/web", alert.LevelWarning, "firing", "needs capacity")
		enqInfra(t, s, "scale:shop/web", alert.LevelWarning, "resolved", "capacity ok")
	}
	rows, _ := s.PendingOutbox(100)
	if len(rows) != 20 {
		t.Fatalf("rows: %d", len(rows))
	}
	now := time.Now()
	for i := 1; i <= 3; i++ {
		p := pendingAlert(t, s, rows[0], false)
		s.FinishAlert(ctx, p, false, now)
		for _, r := range rows {
			got := readRow(t, s, r.ID)
			if got.attempts != int64(i) || got.nextTry != 0 {
				t.Fatalf("failure %d: row %d %+v, want %d attempts and a retry on the next drain", i, r.ID, got, i)
			}
			if gaveUp := got.sentAt != 0; gaveUp != (i == 3) || got.givenUp != (i == 3) {
				t.Fatalf("failure %d: row %d %+v: a warning is given up after its third failed attempt", i, r.ID, got)
			}
		}
	}
	if _, ok, _ := s.PendingAlert(rows[0], false); ok {
		t.Fatal("every row was given up: nothing is left to send")
	}
}

// In the quiet-hours pass (criticals only) a failure counts only against the alert's critical rows: a held
// warning keeps every attempt for the morning.
func TestQuietHoursFailureCountsOnlyAgainstCriticalRows(t *testing.T) {
	s := newStore(t)
	enqInfra(t, s, "selfheal:shop/web", alert.LevelWarning, "firing", "held")
	enqInfra(t, s, "selfheal:shop/web", alert.LevelCritical, "firing", "gave up")
	rows, _ := s.PendingOutbox(10)
	now := time.Now()
	s.FinishAlert(context.Background(), pendingAlert(t, s, rows[1], true), false, now)
	if w := readRow(t, s, rows[0].ID); w.attempts != 0 || w.nextTry != 0 || w.sentAt != 0 {
		t.Fatalf("the held warning must keep its attempts: %+v", w)
	}
	if c := readRow(t, s, rows[1].ID); c.attempts != 1 || c.nextTry != now.Unix()+15 {
		t.Fatalf("the critical row counts the attempt and backs off 15s: %+v", c)
	}
}

// Owner decision: a critical message that can't be delivered is retried with a backoff (15 s, doubling,
// at most an hour apart) until its rows are 24 hours old, not given up after 3 attempts. A row in backoff
// isn't offered to the notifier before its next try. Every row of a critical message follows that policy,
// its warnings too.
func TestUndeliveredCriticalBacksOffForADay(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	t0 := time.Now().Add(-30 * time.Hour).Truncate(time.Second)
	enqInfra(t, s, "diskgc", alert.LevelWarning, "firing", "disk 91%")
	enqInfra(t, s, "diskgc", alert.LevelCritical, "firing", "disk 97%")
	exec(t, s, `UPDATE alert_outbox SET created_at=?`, t0.Unix())
	rows, _ := s.PendingOutbox(10)
	now := t0
	for i, want := range []int64{15, 30, 60, 120, 240, 480, 960, 1920, 3600, 3600, 3600} {
		due, err := s.PendingAlerts(10, true, now)
		if err != nil || len(due) != 1 {
			t.Fatalf("try %d at +%v: the critical must be due: %+v %v", i+1, now.Sub(t0), due, err)
		}
		s.FinishAlert(ctx, pendingAlert(t, s, due[0], false), false, now)
		for _, r := range rows {
			got := readRow(t, s, r.ID)
			if got.sentAt != 0 || got.nextTry != now.Unix()+want {
				t.Fatalf("try %d: row %d %+v, want unsent with the next try %ds later", i+1, r.ID, got, want)
			}
		}
		if early, _ := s.PendingAlerts(10, false, now.Add(time.Duration(want-1)*time.Second)); len(early) != 0 {
			t.Fatalf("try %d: in backoff the alert must not be offered: %+v", i+1, early)
		}
		now = now.Add(time.Duration(want) * time.Second)
	}
	// 23h59m old: still retried. 24h old: given up.
	now = t0.Add(24*time.Hour - time.Minute)
	s.FinishAlert(ctx, pendingAlert(t, s, rows[0], false), false, now)
	if r := readRow(t, s, rows[1].ID); r.sentAt != 0 {
		t.Fatalf("a critical younger than 24h is never given up: %+v", r)
	}
	now = t0.Add(24 * time.Hour)
	s.FinishAlert(ctx, pendingAlert(t, s, rows[0], false), false, now)
	for _, r := range rows {
		if got := readRow(t, s, r.ID); got.sentAt != now.Unix() || !got.givenUp {
			t.Fatalf("row %d %+v: given up once 24 hours old", r.ID, got)
		}
	}
}

// Item 6: the rows a message combines start after the alert's last row closed by a delivery (or dropped on
// purpose), so a critical given up before a warning was held is still reported — the morning message was
// "[WARNING] …" without a word about the critical.
func TestCombinedRowsStartAfterTheLastDelivery(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	t0 := time.Now().Add(-30 * time.Hour)
	enqInfra(t, s, "diskgc", alert.LevelWarning, "firing", "delivered earlier")
	rows, _ := s.PendingOutbox(10)
	s.FinishAlert(ctx, pendingAlert(t, s, rows[0], false), true, t0)
	enqInfra(t, s, "diskgc", alert.LevelCritical, "firing", "disk 97%")
	exec(t, s, `UPDATE alert_outbox SET created_at=? WHERE id=?`, t0.Unix(), newestID(t, s))
	crit, _ := s.PendingOutbox(10)
	s.FinishAlert(ctx, pendingAlert(t, s, crit[0], false), false, t0.Add(24*time.Hour)) // given up
	if r := readRow(t, s, crit[0].ID); !r.givenUp {
		t.Fatalf("setup: the critical must be given up: %+v", r)
	}
	enqInfra(t, s, "diskgc", alert.LevelWarning, "firing", "disk 91%")
	held, _ := s.PendingOutbox(10)
	p := pendingAlert(t, s, held[0], false)
	if p.Count != 2 || p.Level != alert.LevelCritical || p.Latest.Summary != "disk 91%" || p.Since != t0.Unix() || p.First != "firing" {
		t.Fatalf("the given-up critical must be combined with the held warning: %+v", p)
	}
	s.FinishAlert(ctx, p, true, time.Now())
	enqInfra(t, s, "diskgc", alert.LevelWarning, "resolved", "disk ok")
	next, _ := s.PendingOutbox(10)
	if p := pendingAlert(t, s, next[0], false); p.Count != 1 || p.Level != alert.LevelWarning {
		t.Fatalf("a delivery ends the combination: %+v", p)
	}
}

// Item 5: the dedupe compared only transition and level, so while rows were held the morning message kept
// the OLDEST summary and dropped the newer states uncounted (a task failing at 23:00, 03:00 and 06:55
// reported only "23:00: disk full"). A new summary or kind is a new row; the newest is reported and every
// one is counted.
func TestEnqueueInfraDedupeComparesSummaryAndKind(t *testing.T) {
	s := newStore(t)
	key := "cron:shop:report"
	enqInfra(t, s, key, alert.LevelWarning, "firing", "failed at 23:00: disk full")
	enqInfra(t, s, key, alert.LevelWarning, "firing", "failed at 23:00: disk full") // re-raised: skipped
	enqInfra(t, s, key, alert.LevelWarning, "firing", "failed at 03:00: db down")
	enqInfra(t, s, key, alert.LevelWarning, "firing", "failed at 06:55: timeout")
	if n := pendingCount(t, s); n != 3 {
		t.Fatalf("%d rows, want one per distinct state", n)
	}
	if err := s.EnqueueInfra(context.Background(), alert.Outbox{Target: "shop/web", Kind: "other_kind", Level: alert.LevelWarning,
		Transition: "firing", Summary: "failed at 06:55: timeout", DedupeKey: key}); err != nil {
		t.Fatal(err)
	}
	if n := pendingCount(t, s); n != 4 {
		t.Fatalf("another kind under the key is a new row: %d", n)
	}
	rows, _ := s.PendingOutbox(10)
	if p := pendingAlert(t, s, rows[0], false); p.Count != 4 || p.Latest.Kind != "other_kind" {
		t.Fatalf("one message reports the newest and counts all: %+v", p)
	}
}

// Item 4: with held alerts the silence was checked at send time, in the morning, when the state row that
// holds silenced_until could be gone (resolved and cleared) or the silence over. Silencing now closes the
// alert's unsent rows, and a row raised while its state is silenced is recorded closed.
func TestSilenceClosesHeldRowsAndRowsRaisedWhileSilenced(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now()
	enqRule := func(target, transition string) {
		t.Helper()
		if err := s.EnqueueOutbox(ctx, []alert.Outbox{{RuleID: 1, Target: target, Kind: alert.KindContainerDown,
			Level: alert.LevelWarning, Transition: transition, Summary: transition}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SaveStates(ctx, []alert.State{{RuleID: 1, Target: "shop/web", Phase: alert.PhaseFiring, Since: 1}}); err != nil {
		t.Fatal(err)
	}
	enqRule("shop/web", "firing")
	enqRule("shop/api", "firing")
	enqInfra(t, s, "selfheal:shop/web", alert.LevelWarning, "firing", "infra") // target shop/web, rule 0
	if err := s.Silence(ctx, 1, "shop/web", now.Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.PendingOutbox(10)
	if len(rows) != 2 || rows[0].Target != "shop/api" || rows[1].RuleID != 0 {
		t.Fatalf("silencing closes only that rule and target's rows: %+v", rows)
	}
	if r := readRow(t, s, 1); r.sentAt == 0 || r.givenUp {
		t.Fatalf("a silenced row is closed, not given up: %+v", r)
	}
	enqRule("shop/web", "resolved")
	if n := pendingCount(t, s); n != 2 {
		t.Fatalf("a row raised while silenced is recorded closed: %d pending", n)
	}
	if err := s.Silence(ctx, 0, "shop/web", now.Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if n := pendingCount(t, s); n != 2 {
		t.Fatalf("Mooring's own alerts can't be silenced: %d pending", n)
	}
	exec(t, s, `UPDATE alert_state SET silenced_until=?`, now.Add(-time.Second).Unix()) // the silence is over
	enqRule("shop/web", "firing")
	rows, _ = s.PendingOutbox(10)
	if len(rows) != 3 || rows[2].Target != "shop/web" {
		t.Fatalf("after the silence rows are recorded unsent: %+v", rows)
	}
	if p := pendingAlert(t, s, rows[2], false); p.Count != 1 {
		t.Fatalf("silenced rows are never combined into a later message: %+v", p)
	}
}

// Item 2: an alert can end without a resolve worth sending — the operator cleared the self-heal circuit,
// or the app went away. CloseInfraAlert records a closed "resolved" row and closes the key's unsent rows,
// so the next episode starts clean (its resolve takes only its own level) and nothing is sent.
func TestCloseInfraAlert(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	key := "selfheal:shop/web"
	marker := alert.Outbox{Target: "shop/web", Kind: "circuit_cleared", Level: alert.LevelWarning, Transition: "resolved",
		Summary: "cleared", DedupeKey: key}
	if err := s.CloseInfraAlert(ctx, marker); err != nil {
		t.Fatal(err)
	}
	if n := rowCount(t, s); n != 0 {
		t.Fatalf("no alert under the key: nothing to close, %d rows", n)
	}
	enqInfra(t, s, key, alert.LevelCritical, "firing", "crashloop capped")
	exec(t, s, `UPDATE alert_outbox SET sent_at=1`)
	enqInfra(t, s, key, alert.LevelWarning, "firing", "held")
	if err := s.CloseInfraAlert(ctx, marker); err != nil {
		t.Fatal(err)
	}
	if n := pendingCount(t, s); n != 0 {
		t.Fatalf("the key's unsent rows are closed: %d pending", n)
	}
	if r := readRow(t, s, newestID(t, s)); r.sentAt == 0 || r.givenUp {
		t.Fatalf("the closing row is recorded closed, never sent: %+v", r)
	}
	if _, ok := s.InfraResolveLevel(ctx, key); ok {
		t.Fatal("after the close the key has no open firing")
	}
	if err := s.CloseInfraAlert(ctx, marker); err != nil {
		t.Fatal(err)
	}
	if n := rowCount(t, s); n != 3 {
		t.Fatalf("an alert already closed isn't closed again: %d rows", n)
	}
	enqInfra(t, s, key, alert.LevelWarning, "firing", "dependency wait")
	if l, _ := s.InfraResolveLevel(ctx, key); l != alert.LevelWarning {
		t.Fatalf("the next episode resolves at its own level: %q", l)
	}
}

// Delivered and closed rows are kept 7 days. A row still unsent 48 hours after it was raised is closed
// without being sent and kept like a closed row (quiet hours hold a row less than a day).
func TestPruneOutbox(t *testing.T) {
	s := newStore(t)
	now := time.Now()
	for i, r := range []struct {
		sent, created time.Time
	}{
		{sent: now.Add(-8 * 24 * time.Hour)},
		{sent: now.Add(-6 * 24 * time.Hour)},
		{created: now.Add(-49 * time.Hour)},
		{created: now.Add(-47 * time.Hour)},
	} {
		var sent int64
		if !r.sent.IsZero() {
			sent = r.sent.Unix()
		}
		exec(t, s, `INSERT INTO alert_outbox(rule_id, target, kind, level, transition, summary, dedupe_key, created_at, sent_at)
			VALUES(0,'x','k','warning','firing',?,'',?,?)`, fmt.Sprint(i), r.created.Unix(), sent)
	}
	s.PruneOutbox(context.Background(), now)
	var kept []string
	rows, err := s.db.Query(`SELECT summary FROM alert_outbox ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var k string
		_ = rows.Scan(&k)
		kept = append(kept, k)
	}
	rows.Close()
	if strings.Join(kept, ",") != "1,2,3" {
		t.Fatalf("kept %v, want the 6-day-old sent row and both unsent rows", kept)
	}
	if r := readRow(t, s, 3); r.sentAt != now.Unix() || r.givenUp {
		t.Fatalf("the 49-hour-old row is closed unsent: %+v", r)
	}
	if r := readRow(t, s, 4); r.sentAt != 0 {
		t.Fatalf("the 47-hour-old row is still pending: %+v", r)
	}
}

// Low item b: a stale unsent row was deleted after 48 hours while the sent row before it was kept 7 days,
// so an alert whose "resolved" was never sent looked open again (OpenInfraAlerts) and a later resolve took
// the old episode's level. The stale row is closed instead and outlives the rows before it.
func TestPruneKeepsAStaleResolve(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now()
	exec(t, s, `INSERT INTO alert_outbox(rule_id, target, kind, level, transition, summary, dedupe_key, created_at, sent_at)
		VALUES(0,'shop','deploy_problems','critical','firing','', 'deploy:shop', ?, ?),
		      (0,'shop','deploy_problems','warning','resolved','', 'deploy:shop', ?, 0)`,
		now.Add(-6*24*time.Hour).Unix(), now.Add(-6*24*time.Hour).Unix(), now.Add(-49*time.Hour).Unix())
	check := func(when string) {
		t.Helper()
		open, err := s.OpenInfraAlerts(ctx, "deploy_problems")
		if err != nil {
			t.Fatal(err)
		}
		if len(open) != 0 {
			t.Fatalf("%s: a resolved alert must not look open: %v", when, open)
		}
		if _, ok := s.InfraResolveLevel(ctx, "deploy:shop"); ok {
			t.Fatalf("%s: no firing since the resolve", when)
		}
	}
	s.PruneOutbox(ctx, now)
	check("after the 48-hour prune")
	s.PruneOutbox(ctx, now.Add(2*24*time.Hour)) // the sent firing row is past its 7 days now
	check("after the firing row is pruned")
	if n := rowCount(t, s); n != 1 {
		t.Fatalf("the closed resolve outlives the firing row before it: %d rows", n)
	}
}

// With alerting disabled nothing drains the outbox, but producers still enqueue: EnqueueInfra itself closes
// unsent rows older than 48 hours (at most every 10 minutes), and closed rows are deleted after 7 days, so
// a flapping condition can't grow the table without bound.
func TestEnqueueInfraPrunesStaleUnsentRows(t *testing.T) {
	s := newStore(t)
	for i := 0; i < 300; i++ {
		enqInfra(t, s, "scale:shop/web", alert.LevelWarning, "firing", "")
		enqInfra(t, s, "scale:shop/web", alert.LevelWarning, "resolved", "")
	}
	if n := rowCount(t, s); n != 600 {
		t.Fatalf("every transition is a row: %d", n)
	}
	exec(t, s, `UPDATE alert_outbox SET created_at=?`, time.Now().Add(-72*time.Hour).Unix())
	enqInfra(t, s, "scale:shop/web", alert.LevelWarning, "firing", "")
	if n := pendingCount(t, s); n != 601 {
		t.Fatalf("pruning is throttled: %d pending, want 601", n)
	}
	s.nextPrune.Store(0) // the throttle window has passed
	enqInfra(t, s, "scale:shop/web", alert.LevelWarning, "resolved", "")
	if n := pendingCount(t, s); n != 2 {
		t.Fatalf("stale unsent rows must be closed on enqueue: %d pending, want 2", n)
	}
	s.PruneOutbox(context.Background(), time.Now().Add(8*24*time.Hour))
	if n := rowCount(t, s); n != 2 {
		t.Fatalf("closed rows are deleted after 7 days: %d rows, want 2", n)
	}
}

// A slow prune never spends the caller's deadline: EnqueueInfra records the row first (the detection
// engine gives each alert 3 seconds), then prunes on a context of its own, which outlives the caller's.
func TestEnqueueInfraPruneOffTheCallersDeadline(t *testing.T) {
	s := newStore(t)
	exec(t, s, `INSERT INTO alert_outbox(rule_id, target, kind, level, transition, summary, dedupe_key, created_at, sent_at)
		VALUES(0,'x','k','warning','firing','stale','old',?,0)`, time.Now().Add(-72*time.Hour).Unix())
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	var callerErr, pruneCtxErr error
	ran := false
	s.beforePrune = func(pctx context.Context) {
		ran = true
		<-ctx.Done() // the prune takes longer than the caller's deadline
		callerErr, pruneCtxErr = ctx.Err(), pctx.Err()
	}
	err := s.EnqueueInfra(ctx, alert.Outbox{Target: "security-logs", Kind: "security_detection", Level: alert.LevelWarning,
		Transition: "firing", Summary: "x", DedupeKey: "siem:r:k"})
	if err != nil {
		t.Fatalf("the insert failed on a slow prune: %v", err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM alert_outbox WHERE dedupe_key='siem:r:k' AND sent_at=0`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the enqueued row: %d (%v)", n, err)
	}
	if !ran || callerErr == nil || pruneCtxErr != nil {
		t.Fatalf("prune ran %v; caller's context %v, prune's context %v (want the prune's alive past the caller's deadline)",
			ran, callerErr, pruneCtxErr)
	}
	if r := readRow(t, s, 1); r.sentAt == 0 {
		t.Fatalf("the prune still runs: the 72-hour-old unsent row is closed: %+v", r)
	}
}

// A resolve takes the level of the alert it closes: the highest level among the key's "firing" rows
// since its last "resolved" row.
func TestInfraResolveLevel(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, ok := s.InfraResolveLevel(ctx, "selfheal:shop/web"); ok {
		t.Fatal("nothing recorded: ok must be false")
	}
	enqInfra(t, s, "selfheal:shop/web", alert.LevelWarning, "firing", "")
	enqInfra(t, s, "selfheal:other", alert.LevelCritical, "firing", "")
	if l, ok := s.InfraResolveLevel(ctx, "selfheal:shop/web"); !ok || l != alert.LevelWarning {
		t.Fatalf("warning episode: %q %v", l, ok)
	}
	exec(t, s, `UPDATE alert_outbox SET sent_at=1`) // delivered or not, a firing row counts
	if l, ok := s.InfraResolveLevel(ctx, "selfheal:shop/web"); !ok || l != alert.LevelWarning {
		t.Fatalf("delivered warning episode: %q %v", l, ok)
	}
	enqInfra(t, s, "selfheal:shop/web", alert.LevelCritical, "firing", "")
	if l, _ := s.InfraResolveLevel(ctx, "selfheal:shop/web"); l != alert.LevelCritical {
		t.Fatalf("escalated episode: %q", l)
	}
	enqInfra(t, s, "selfheal:shop/web", alert.LevelCritical, "resolved", "")
	if _, ok := s.InfraResolveLevel(ctx, "selfheal:shop/web"); ok {
		t.Fatal("after its resolve the key has no open firing")
	}
	enqInfra(t, s, "selfheal:shop/web", alert.LevelWarning, "firing", "")
	if l, _ := s.InfraResolveLevel(ctx, "selfheal:shop/web"); l != alert.LevelWarning {
		t.Fatalf("a new episode counts only its own rows: %q", l)
	}
}

// A key whose latest infra row is "firing" is still open; one that was resolved later is not; other
// kinds and rule-based rows are ignored.
func TestOpenInfraAlerts(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, o := range []alert.Outbox{
		{Target: "shop", Kind: "edge_unroutable", Level: alert.LevelWarning, Transition: "firing", DedupeKey: "edge:a.example.com"},
		{Target: "shop", Kind: "edge_unroutable", Level: alert.LevelWarning, Transition: "firing", DedupeKey: "edge:b.example.com"},
		{Target: "shop", Kind: "edge_unroutable", Level: alert.LevelWarning, Transition: "resolved", DedupeKey: "edge:b.example.com"},
		{Target: "", Kind: "docker_daemon_mismatch", Level: alert.LevelCritical, Transition: "firing", DedupeKey: "docker:daemon-mismatch"},
	} {
		if err := s.EnqueueInfra(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.OpenInfraAlerts(ctx, "edge_unroutable")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["edge:a.example.com"] != "shop" {
		t.Fatalf("want only edge:a open, got %v", got)
	}
	if d, _ := s.OpenInfraAlerts(ctx, "docker_daemon_mismatch"); len(d) != 1 {
		t.Fatalf("want the daemon alert open, got %v", d)
	}
}

// Round 5, finding 1: whether a firing of an infra alert's current episode may be recorded. "No" must be a
// positive answer — no firing since the key's last resolve, and none old enough to have been pruned — so a
// read error, and rows that may have been pruned, answer "yes".
func TestInfraFiringRecorded(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	key := "selfheal:shop/web"
	recent, old := time.Now().Add(-time.Hour).Unix(), time.Now().Add(-8*24*time.Hour).Unix()
	check := func(since int64, want bool, why string) {
		t.Helper()
		got, err := s.InfraFiringRecorded(ctx, key, since)
		if err != nil || got != want {
			t.Fatalf("%s: recorded %v (%v), want %v", why, got, err, want)
		}
	}
	check(recent, false, "nothing recorded, in an episode that began inside the retention")
	check(0, true, "nothing recorded, but the episode's start is unknown")
	check(old, true, "nothing recorded, but the episode began before the retention")
	enqInfra(t, s, "selfheal:other", alert.LevelCritical, "firing", "")
	check(recent, false, "another key's firing")
	enqInfra(t, s, key, alert.LevelWarning, "firing", "")
	check(recent, true, "a firing since the start")
	exec(t, s, `UPDATE alert_outbox SET sent_at=1`)
	check(recent, true, "delivered or not")
	enqInfra(t, s, key, alert.LevelWarning, "resolved", "")
	check(0, false, "resolved since: its resolve bounds the episode")
	check(old, false, "resolved since: its resolve bounds the episode")
	exec(t, s, `UPDATE alert_outbox SET created_at=? WHERE transition='resolved'`, old)
	check(0, true, "a resolve older than the retention doesn't bound it")
	check(recent, false, "the episode's start does")
	enqInfra(t, s, key, alert.LevelCritical, "firing", "")
	check(recent, true, "a new firing since the resolve")

	exec(t, s, `ALTER TABLE alert_outbox RENAME TO alert_outbox_off`)
	if got, err := s.InfraFiringRecorded(ctx, "selfheal:none", recent); err == nil || !got {
		t.Fatalf("a read error: recorded %v (%v), want true with the error", got, err)
	}
}

// Round 5, finding 3: SaveStates deleted a state row once it reached ok, and its silence with it, so an
// alert silenced for an hour that resolved, cleared and fired again inside the hour paged. A row whose
// silence hasn't ended is kept at ok, its ack cleared, until the first save after the silence ends.
func TestSaveStatesKeepsASilencedRowAtOK(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	until := time.Now().Add(time.Hour).Unix()
	firing := alert.State{RuleID: 1, Target: "host", Phase: alert.PhaseFiring, Since: 1, Level: alert.LevelWarning}
	if err := s.SaveStates(ctx, []alert.State{firing}); err != nil {
		t.Fatal(err)
	}
	if err := s.Ack(ctx, 1, "host"); err != nil {
		t.Fatal(err)
	}
	loaded, _ := s.LoadStates()
	if err := s.Silence(ctx, 1, "host", until); err != nil { // after the load: the save must not lose it
		t.Fatal(err)
	}
	ok := loaded[0]
	ok.Phase, ok.Since = alert.PhaseOK, 5
	if err := s.SaveStates(ctx, []alert.State{ok, {RuleID: 1, Target: "shop/web", Phase: alert.PhaseOK}}); err != nil {
		t.Fatal(err)
	}
	all, _ := s.LoadStates()
	if len(all) != 1 || all[0].Target != "host" || all[0].Phase != alert.PhaseOK || all[0].Acked || all[0].SilencedUntil != until {
		t.Fatalf("the silenced row is kept at ok with its ack cleared, and no other ok row is written: %+v", all)
	}
	if fs, _ := s.FiringStates(); len(fs) != 0 {
		t.Fatalf("an ok row is no open alert: %+v", fs)
	}
	if err := s.EnqueueOutbox(ctx, []alert.Outbox{{RuleID: 1, Target: "host", Kind: alert.KindHostCPU,
		Level: alert.LevelWarning, Transition: "firing", Summary: "hot again"}}); err != nil {
		t.Fatal(err)
	}
	if n := pendingCount(t, s); n != 0 {
		t.Fatalf("a firing raised while still silenced is recorded closed: %d pending", n)
	}

	exec(t, s, `UPDATE alert_state SET silenced_until=?`, time.Now().Add(-time.Second).Unix()) // the silence ended
	// The state still carries the silence from its load: the row's own silenced_until decides.
	if err := s.SaveStates(ctx, []alert.State{all[0]}); err != nil {
		t.Fatal(err)
	}
	if all, _ := s.LoadStates(); len(all) != 0 {
		t.Fatalf("the first save after the silence deletes the ok row: %+v", all)
	}
}

// The evaluator end to end: silence an alert, let it resolve and clear, and it fires again inside the
// silence without a message; once the silence is over it pages again.
func TestSilenceOutlivesTheAlertClearing(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.SaveRule(ctx, alert.Rule{Name: "down", Kind: alert.KindContainerDown, Level: alert.LevelWarning, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rules, _ := s.ListRules()
	eval := func(state string) {
		t.Helper()
		snap := &monitor.Snapshot{DockerOK: true}
		if state != "" {
			snap.Apps = []monitor.App{{Project: "shop", Services: []monitor.ServiceStatus{{Service: "web", State: state}}}}
		}
		prior, err := s.LoadStates()
		if err != nil {
			t.Fatal(err)
		}
		states, ob := alert.Evaluate(time.Now().Unix(), rules, snap, prior)
		if err := s.SaveStates(ctx, states); err != nil {
			t.Fatal(err)
		}
		if err := s.EnqueueOutbox(ctx, ob); err != nil {
			t.Fatal(err)
		}
	}
	phase := func() alert.Phase {
		t.Helper()
		all, _ := s.LoadStates()
		if len(all) == 0 {
			return ""
		}
		return all[0].Phase
	}
	eval("exited")
	eval("exited")
	if n := pendingCount(t, s); n != 1 || phase() != alert.PhaseFiring {
		t.Fatalf("the alert fires: %d pending, %s", n, phase())
	}
	if err := s.Silence(ctx, rules[0].ID, "shop/web", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	eval("running")
	eval("running")
	eval("running")
	if phase() != alert.PhaseOK {
		t.Errorf("resolved and cleared: %s", phase())
	}
	eval("") // not evaluated this time (the app is missing from the snapshot): carried forward
	if phase() != alert.PhaseOK {
		t.Errorf("carried forward: %s", phase())
	}
	eval("exited")
	eval("exited")
	if n := pendingCount(t, s); n != 0 || phase() != alert.PhaseFiring {
		t.Fatalf("firing again inside the silence sends nothing: %d pending, %s", n, phase())
	}

	exec(t, s, `UPDATE alert_state SET silenced_until=?`, time.Now().Add(-time.Second).Unix())
	eval("running")
	eval("running")
	if phase() != "" {
		t.Fatalf("after the silence an ok row is deleted: %s", phase())
	}
	eval("exited")
	eval("exited")
	if n := pendingCount(t, s); n != 2 {
		t.Fatalf("after the silence the alert pages again (its resolve, then the firing): %d pending", n)
	}
}
