package respond

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/blocklist"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/store"
)

var t0 = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

type clock struct{ ns atomic.Int64 }

func (c *clock) now() time.Time          { return time.Unix(0, c.ns.Load()).UTC() }
func (c *clock) advance(d time.Duration) { c.ns.Add(int64(d)) }

// fakeBlocks is a block list: it places every block for its duration (unless refuse names the
// prefix or err is set) and records what it was asked.
type fakeBlocks struct {
	mu        sync.Mutex
	now       func() time.Time
	reqs      []blocklist.Request
	refuse    map[string]*blocklist.RefusedError
	err       error
	lifts     []string // by + " " + why
	liftN     int
	liftErr   error
	incidents []int64
	exempts   []time.Duration
	incN      int
	onBlock   func() // called by Block, before it answers
	// onUnblockIncident is called by UnblockIncident, before it answers.
	onUnblockIncident func()
	// held is what Get answers; with keep, every block placed is held.
	keep   bool
	held   map[netip.Prefix]blocklist.Block
	getErr error
}

func (f *fakeBlocks) Block(_ context.Context, r blocklist.Request) (blocklist.Block, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, r)
	if f.onBlock != nil {
		f.onBlock()
	}
	if re := f.refuse[r.Prefix]; re != nil {
		return blocklist.Block{}, re
	}
	if f.err != nil {
		return blocklist.Block{}, f.err
	}
	p := netip.MustParsePrefix(r.Prefix)
	b := blocklist.Block{Prefix: p, Source: r.Source, Created: f.now(), Until: f.now().Add(r.Duration), State: blocklist.StateActive}
	if f.keep {
		if f.held == nil {
			f.held = map[netip.Prefix]blocklist.Block{}
		}
		f.held[p] = b
	}
	return b, nil
}
func (f *fakeBlocks) Unblock(context.Context, netip.Prefix, string) error { return nil }
func (f *fakeBlocks) UnblockIncident(_ context.Context, id int64, by string, exempt time.Duration) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.incidents, f.exempts = append(f.incidents, id), append(f.exempts, exempt)
	if f.onUnblockIncident != nil {
		f.onUnblockIncident()
	}
	return f.incN, nil
}
func (f *fakeBlocks) LiftAutomatic(_ context.Context, by, why string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lifts = append(f.lifts, by+" "+why)
	return f.liftN, f.liftErr
}
func (f *fakeBlocks) List(context.Context, blocklist.Filter) ([]blocklist.Block, error) {
	return nil, nil
}
func (f *fakeBlocks) Get(_ context.Context, p netip.Prefix) (blocklist.Block, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.held[p]
	return b, ok, f.getErr
}
func (f *fakeBlocks) Refusals(context.Context, int) ([]blocklist.Refusal, error) { return nil, nil }
func (f *fakeBlocks) Blocked(netip.Addr) bool                                    { return false }
func (f *fakeBlocks) Status() blocklist.Status                                   { return blocklist.Status{} }

func (f *fakeBlocks) requests() []blocklist.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]blocklist.Request(nil), f.reqs...)
}

type revokeResult struct {
	user string
	n    int64
	err  error
}

type fakeRevoker struct {
	mu    sync.Mutex
	by    map[string]revokeResult
	calls []string
}

func (f *fakeRevoker) Revoke(_ context.Context, actor string) (string, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, actor)
	r, ok := f.by[actor]
	if !ok {
		return "", 0, siem.ErrUnknownAccount
	}
	return r.user, r.n, r.err
}

type note struct {
	id int64
	ev siem.IncidentEvent
}

type env struct {
	t      *testing.T
	db     *store.DB
	clk    *clock
	blocks *fakeBlocks
	rev    *fakeRevoker
	mu     sync.Mutex
	notes  []note
	alerts []alert.Outbox
	audits []audit.Event
	events []siem.Event
	opts   Options
	r      *Responder
}

func (e *env) EnqueueInfra(_ context.Context, o alert.Outbox) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.alerts = append(e.alerts, o)
	return nil
}

func newEnv(t *testing.T, mode string, mod ...func(*Options)) *env {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "mooring.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &env{t: t, db: db, clk: &clock{}}
	e.clk.ns.Store(t0.UnixNano())
	e.blocks = &fakeBlocks{now: e.clk.now, refuse: map[string]*blocklist.RefusedError{}}
	e.rev = &fakeRevoker{by: map[string]revokeResult{"alice": {"alice", 3, nil}, "h:0123456789abcdef": {"alice@example.com", 1, nil},
		"bob": {"bob", 0, nil}, "carol": {"carol", 2, nil}}}
	e.opts = Options{DB: db, Mode: mode, MaxBlocksPerHour: 60, MaxRevokesPerHour: 3, Blocks: e.blocks,
		Timeline: func(_ context.Context, id int64, ev siem.IncidentEvent) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.notes = append(e.notes, note{id, ev})
			return nil
		},
		Alerter: e,
		Audit: func(_ context.Context, ev audit.Event) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.audits = append(e.audits, ev)
			return nil
		},
		Emit: func(ev siem.Event) bool {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.events = append(e.events, ev)
			return true
		},
		Now: e.clk.now}
	for _, m := range mod {
		m(&e.opts)
	}
	e.open()
	return e
}

func (e *env) open() {
	e.t.Helper()
	r, err := Open(context.Background(), e.opts)
	if err != nil {
		e.t.Fatal(err)
	}
	e.r = r
	r.SetRevoker(e.rev)
	e.t.Cleanup(r.Close)
}

// reopen opens a new responder on the same database (a restart).
func (e *env) reopen() {
	e.t.Helper()
	e.r.Close()
	e.open()
}

func (e *env) take() (notes []note, alerts []alert.Outbox, audits []audit.Event, events []siem.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	notes, alerts, audits, events = e.notes, e.alerts, e.audits, e.events
	e.notes, e.alerts, e.audits, e.events = nil, nil, nil, nil
	return
}

func (e *env) list(f siem.ResponseFilter) []siem.Response {
	e.t.Helper()
	rs, err := e.r.Responses(context.Background(), f)
	if err != nil {
		e.t.Fatal(err)
	}
	return rs
}

func (e *env) only() siem.Response {
	e.t.Helper()
	rs := e.list(siem.ResponseFilter{})
	if len(rs) != 1 {
		e.t.Fatalf("responses %+v", rs)
	}
	return rs[0]
}

func blockReq(target string, auto bool) siem.ResponseRequest {
	return siem.ResponseRequest{Action: siem.ResponseBlock, Target: target, Duration: time.Hour, Automatic: auto,
		RuleID: "edge.scan", RuleName: "Web scan", Severity: siem.SevLow, DetectionID: 11, IncidentID: 5,
		Summary: target + " — 100 requests answered 404 in 5m", At: t0}
}

func revokeReq(actor string) siem.ResponseRequest {
	return siem.ResponseRequest{Action: siem.ResponseRevoke, Target: actor, Automatic: true,
		RuleID: "mooring.login_tor", RuleName: "Mooring sign-in over Tor", Severity: siem.SevMedium, DetectionID: 12,
		IncidentID: 6, Summary: "203.0.113.9 — 1 sign-ins over Tor in 1h", At: t0}
}

func TestEnforceAppliesAutomaticBlock(t *testing.T) {
	e := newEnv(t, siem.ResponseModeEnforce)
	e.r.handle(blockReq("203.0.113.7", true))
	x := e.only()
	if x.Action != siem.ResponseBlock || x.Target != "203.0.113.7/32" || x.State != siem.ResponseApplied || x.Reason != "" ||
		!x.Automatic || x.RuleID != "edge.scan" || x.DetectionID != 11 || x.IncidentID != 5 || x.Duration != time.Hour ||
		x.By != "" || !x.Created.Equal(t0) || !x.Updated.Equal(t0) || !strings.HasPrefix(x.Summary, "203.0.113.7 ") {
		t.Fatalf("response %+v", x)
	}
	reqs := e.blocks.requests()
	if len(reqs) != 1 {
		t.Fatal(reqs)
	}
	b := reqs[0]
	if b.Prefix != "203.0.113.7/32" || b.Source != blocklist.SourceAuto || b.Duration != time.Hour || b.RuleID != "edge.scan" ||
		b.DetectionID != 11 || b.IncidentID != 5 || b.ResponseID != x.ID || b.By != "" || b.Reason != x.Summary {
		t.Fatalf("block request %+v", b)
	}
	notes, alerts, audits, events := e.take()
	if len(notes) != 1 || notes[0].id != 5 || notes[0].ev.Kind != siem.TimelineResponse || notes[0].ev.Text != "blocked 203.0.113.7/32 for 1h" ||
		notes[0].ev.DetectionID != 11 || notes[0].ev.RuleID != "edge.scan" || notes[0].ev.RuleName != "Web scan" || notes[0].ev.Actor != "" {
		t.Fatalf("timeline %+v", notes)
	}
	if len(alerts) != 0 {
		t.Fatalf("a block alerted: %+v", alerts)
	}
	if len(audits) != 1 || audits[0] != (audit.Event{Actor: "siem", Action: "security_response", Target: "203.0.113.7/32",
		Outcome: audit.OK, Level: audit.Security,
		Detail: "action=block target=203.0.113.7/32 state=applied rule=edge.scan duration=1h"}) {
		t.Fatalf("audit %+v", audits)
	}
	if len(events) != 1 {
		t.Fatalf("events %+v", events)
	}
	ev := events[0]
	if ev.Src != siem.SrcSIEM || ev.Kind != "siem.response" || ev.IP != "203.0.113.7" || ev.F["action"] != "block" ||
		ev.F["target"] != "203.0.113.7/32" || ev.F["state"] != "applied" || ev.F["rule"] != "edge.scan" ||
		ev.F["duration_s"] != 3600.0 || ev.F["response_id"] != float64(x.ID) || ev.F["incident_id"] != 5.0 ||
		ev.F["detection_id"] != 11.0 || ev.F["automatic"] != true || ev.Msg != "blocked 203.0.113.7/32 for 1h" {
		t.Fatalf("event %+v", ev)
	}
	if _, ok := ev.F["reason"]; ok {
		t.Fatalf("reason on an applied response: %+v", ev.F)
	}

	// An IPv6 /64 is blocked as it is; a malformed target is refused, never sent on.
	e.r.handle(blockReq("2001:db8:1:2::/64", true))
	e.r.handle(blockReq("2001:db8:1:2::/48", true))
	e.r.handle(blockReq("not an address", true))
	rs := e.list(siem.ResponseFilter{})
	if len(rs) != 4 || rs[2].Target != "2001:db8:1:2::/64" || rs[2].State != siem.ResponseApplied ||
		rs[1].State != siem.ResponseRefused || rs[1].Reason != blocklist.RefuseInvalid ||
		rs[0].State != siem.ResponseRefused || rs[0].Reason != blocklist.RefuseInvalid || rs[0].Target != "not an address" {
		t.Fatalf("responses %+v", rs)
	}
	if n := len(e.blocks.requests()); n != 2 {
		t.Fatalf("%d block requests", n)
	}
}

func TestBlockAppliedDurationIsTheListsAfterEscalation(t *testing.T) {
	e := newEnv(t, siem.ResponseModeEnforce)
	e.opts.Blocks = escalating{e.blocks}
	e.reopen()
	e.r.handle(blockReq("203.0.113.7", true))
	if x := e.only(); x.Duration != 4*time.Hour {
		t.Fatalf("duration %s", x.Duration)
	}
	if notes, _, _, _ := e.take(); len(notes) != 1 || notes[0].ev.Text != "blocked 203.0.113.7/32 for 4h" {
		t.Fatalf("timeline %+v", notes)
	}
}

// escalating places a block four times as long as asked (a repeat).
type escalating struct{ *fakeBlocks }

func (f escalating) Block(ctx context.Context, r blocklist.Request) (blocklist.Block, error) {
	r.Duration *= 4
	return f.fakeBlocks.Block(ctx, r)
}

func TestRecommendMode(t *testing.T) {
	e := newEnv(t, siem.ResponseModeRecommend)
	e.r.handle(blockReq("203.0.113.7", true))
	e.r.handle(revokeReq("alice"))
	rs := e.list(siem.ResponseFilter{})
	if len(rs) != 2 || rs[1].State != siem.ResponseRecommended || rs[1].Target != "203.0.113.7/32" || !rs[1].Automatic ||
		rs[0].State != siem.ResponseRecommended || rs[0].Target != "alice" || rs[0].Action != siem.ResponseRevoke {
		t.Fatalf("responses %+v", rs)
	}
	if len(e.blocks.requests()) != 0 || len(e.rev.calls) != 0 {
		t.Fatalf("applied in recommend mode: %+v %v", e.blocks.requests(), e.rev.calls)
	}
	notes, alerts, audits, _ := e.take()
	if len(notes) != 2 || notes[0].ev.Text != "recommended blocking 203.0.113.7/32 for 1h" || notes[1].ev.Text != "recommended signing alice out" {
		t.Fatalf("timeline %+v", notes)
	}
	if len(alerts) != 0 || len(audits) != 0 {
		t.Fatalf("a recommendation alerted or was audited: %+v %+v", alerts, audits)
	}
}

// A recommend-only request (an app's address) stays a recommendation in enforce mode.
func TestEnforceRecommendOnly(t *testing.T) {
	e := newEnv(t, siem.ResponseModeEnforce)
	e.r.handle(blockReq("198.51.100.9", false))
	if x := e.only(); x.State != siem.ResponseRecommended || x.Automatic {
		t.Fatalf("response %+v", x)
	}
	if len(e.blocks.requests()) != 0 {
		t.Fatal("applied")
	}
}

func TestModeOffAndPause(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, siem.ResponseModeOff)
	if len(e.blocks.lifts) != 1 || e.blocks.lifts[0] != "siem automated response is off" {
		t.Fatalf("mode off at open: %v", e.blocks.lifts)
	}
	e.r.handle(blockReq("203.0.113.7", true))
	if rs := e.list(siem.ResponseFilter{}); len(rs) != 0 {
		t.Fatalf("mode off recorded %+v", rs)
	}
	if st, _ := e.r.Status(ctx); st.Mode != siem.ResponseModeOff || st.Effective != siem.ResponseModeOff {
		t.Fatalf("status %+v", st)
	}
	// A pause above the mode doesn't raise it.
	if err := e.r.SetPause(ctx, siem.ResponseModeRecommend, "owner"); err != nil {
		t.Fatal(err)
	}
	e.r.handle(blockReq("203.0.113.7", true))
	if rs := e.list(siem.ResponseFilter{}); len(rs) != 0 {
		t.Fatalf("a pause raised mode off: %+v", rs)
	}
	if st, _ := e.r.Status(ctx); st.Effective != siem.ResponseModeOff || st.Paused != siem.ResponseModeRecommend {
		t.Fatalf("status %+v", st)
	}

	e = newEnv(t, siem.ResponseModeEnforce)
	if len(e.blocks.lifts) != 0 {
		t.Fatalf("lifted in enforce mode: %v", e.blocks.lifts)
	}
	if err := e.r.SetPause(ctx, siem.ResponseModeRecommend, "owner"); err != nil {
		t.Fatal(err)
	}
	e.r.handle(blockReq("203.0.113.7", true))
	if x := e.only(); x.State != siem.ResponseRecommended {
		t.Fatalf("paused to recommend: %+v", x)
	}
	st, err := e.r.Status(ctx)
	if err != nil || st.Mode != siem.ResponseModeEnforce || st.Paused != siem.ResponseModeRecommend || st.PausedBy != "owner" ||
		!st.PausedAt.Equal(t0) || st.Effective != siem.ResponseModeRecommend {
		t.Fatalf("status %+v %v", st, err)
	}
	// Kept across a restart.
	e.reopen()
	if st, _ := e.r.Status(ctx); st.Paused != siem.ResponseModeRecommend || st.Effective != siem.ResponseModeRecommend {
		t.Fatalf("after restart %+v", st)
	}
	e.blocks.liftN = 2
	if err := e.r.SetPause(ctx, siem.ResponseModeOff, "owner"); err != nil {
		t.Fatal(err)
	}
	if len(e.blocks.lifts) != 1 || e.blocks.lifts[0] != "owner automated response paused" {
		t.Fatalf("pause off: %v", e.blocks.lifts)
	}
	e.r.handle(blockReq("198.51.100.9", true))
	if rs := e.list(siem.ResponseFilter{}); len(rs) != 1 {
		t.Fatalf("paused off recorded %+v", rs)
	}
	if err := e.r.SetPause(ctx, "", "owner"); err != nil {
		t.Fatal(err)
	}
	e.r.handle(blockReq("198.51.100.9", true))
	if rs := e.list(siem.ResponseFilter{}); len(rs) != 2 || rs[0].State != siem.ResponseApplied {
		t.Fatalf("pause lifted: %+v", rs)
	}
	e.reopen()
	if st, _ := e.r.Status(ctx); st.Paused != "" || st.Effective != siem.ResponseModeEnforce {
		t.Fatalf("lifted, after restart %+v", st)
	}
	if err := e.r.SetPause(ctx, "enforce", "owner"); !errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("pause to enforce: %v", err)
	}
	if err := e.r.SetPause(ctx, siem.ResponseModeOff, ""); !errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("no actor: %v", err)
	}

	// A pause never raises the mode.
	e = newEnv(t, siem.ResponseModeRecommend)
	if err := e.r.SetPause(ctx, siem.ResponseModeRecommend, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := e.r.SetPause(ctx, "", "owner"); err != nil {
		t.Fatal(err)
	}
	e.r.handle(blockReq("203.0.113.7", true))
	if x := e.only(); x.State != siem.ResponseRecommended {
		t.Fatalf("recommend mode, pause lifted: %+v", x)
	}
}

// Lifting the automatic blocks when the mode is off at start is tried again until it works.
func TestModeOffLiftRetried(t *testing.T) {
	e := newEnv(t, siem.ResponseModeOff, func(o *Options) {})
	e.blocks.liftErr = errors.New("database is locked")
	e.reopen()
	e.blocks.liftErr = nil
	e.r.maintain(context.Background())
	e.r.maintain(context.Background())
	if len(e.blocks.lifts) != 3 {
		t.Fatalf("lifts %v", e.blocks.lifts)
	}
}

func TestCapsFromTheDatabase(t *testing.T) {
	e := newEnv(t, siem.ResponseModeEnforce, func(o *Options) { o.MaxBlocksPerHour = 2 })
	for i := range 3 {
		e.r.handle(blockReq(fmt.Sprintf("203.0.113.%d", i+1), true))
	}
	rs := e.list(siem.ResponseFilter{})
	if len(rs) != 3 || rs[0].State != siem.ResponseRefused || rs[0].Reason != "hourly_cap" || rs[1].State != siem.ResponseApplied {
		t.Fatalf("responses %+v", rs)
	}
	_, alerts, audits, _ := e.take()
	if len(alerts) != 1 || alerts[0].Kind != AlertKind || alerts[0].Level != alert.LevelWarning ||
		alerts[0].DedupeKey != "siem-response-cap:block" || !strings.Contains(alerts[0].Summary, "hourly cap (2)") {
		t.Fatalf("cap alert %+v", alerts)
	}
	if len(audits) != 3 || audits[2].Outcome != audit.Deny ||
		audits[2].Detail != "action=block target=203.0.113.3/32 state=refused reason=hourly_cap rule=edge.scan" {
		t.Fatalf("audits %+v", audits)
	}
	// Counted from the database: a restart doesn't give the hour back, and doesn't warn again.
	e.reopen()
	e.clk.advance(30 * time.Minute)
	e.r.handle(blockReq("203.0.113.4", true))
	if rs := e.list(siem.ResponseFilter{}); rs[0].Reason != "hourly_cap" {
		t.Fatalf("after restart %+v", rs[0])
	}
	if _, alerts, _, _ := e.take(); len(alerts) != 0 {
		t.Fatalf("warned again within the hour: %+v", alerts)
	}
	st, _ := e.r.Status(context.Background())
	if st.BlocksThisHour != 2 || st.MaxBlocksPerHour != 2 || st.MaxRevokesPerHour != 3 {
		t.Fatalf("status %+v", st)
	}
	// An hour after the first ones: room again.
	e.clk.advance(31 * time.Minute)
	e.r.handle(blockReq("203.0.113.5", true))
	if rs := e.list(siem.ResponseFilter{}); rs[0].State != siem.ResponseApplied {
		t.Fatalf("an hour later %+v", rs[0])
	}
	// Refused blocks don't count.
	e.blocks.refuse["203.0.113.6/32"] = &blocklist.RefusedError{Code: blocklist.RefuseAllowlist, Detail: "overlaps ip_allowlist"}
	e.r.handle(blockReq("203.0.113.6", true))
	e.r.handle(blockReq("203.0.113.7", true))
	if rs := e.list(siem.ResponseFilter{}); rs[0].State != siem.ResponseApplied {
		t.Fatalf("after a refusal %+v", rs[0])
	}
}

func TestBlockRefusalsAndFailures(t *testing.T) {
	e := newEnv(t, siem.ResponseModeEnforce)
	e.blocks.refuse["203.0.113.7/32"] = &blocklist.RefusedError{Code: blocklist.RefuseAllowlist, Detail: "overlaps ip_allowlist"}
	e.r.handle(blockReq("203.0.113.7", true))
	x := e.only()
	if x.State != siem.ResponseRefused || x.Reason != blocklist.RefuseAllowlist || x.Duration != time.Hour {
		t.Fatalf("refused %+v", x)
	}
	notes, _, audits, events := e.take()
	if len(notes) != 1 || notes[0].ev.Text != "block of 203.0.113.7/32 refused: allowlist" {
		t.Fatalf("timeline %+v", notes)
	}
	if len(audits) != 1 || audits[0].Outcome != audit.Deny ||
		audits[0].Detail != "action=block target=203.0.113.7/32 state=refused reason=allowlist rule=edge.scan" {
		t.Fatalf("audit %+v", audits)
	}
	if events[0].F["reason"] != "allowlist" || events[0].F["state"] != "refused" {
		t.Fatalf("event %+v", events[0].F)
	}
	// A code that isn't a fixed word is recorded as one.
	e.blocks.refuse["203.0.113.8/32"] = &blocklist.RefusedError{Code: "bad code <@x>"}
	e.r.handle(blockReq("203.0.113.8", true))
	if rs := e.list(siem.ResponseFilter{}); rs[0].Reason != "refused" {
		t.Fatalf("odd code %+v", rs[0])
	}
	e.blocks.err = errors.New("disk I/O error")
	e.r.handle(blockReq("203.0.113.9", true))
	x = e.list(siem.ResponseFilter{})[0]
	if x.State != siem.ResponseFailed || x.Reason != "error" {
		t.Fatalf("failed %+v", x)
	}
	if notes, _, audits, _ := e.take(); notes[len(notes)-1].ev.Text != "block of 203.0.113.9/32 failed" ||
		audits[len(audits)-1].Outcome != audit.Error {
		t.Fatalf("timeline %+v audits %+v", notes, audits)
	}
	// No edge: refused.
	e.opts.Blocks = nil
	e.reopen()
	e.r.handle(blockReq("203.0.113.10", true))
	if x := e.list(siem.ResponseFilter{})[0]; x.State != siem.ResponseRefused || x.Reason != blocklist.RefuseNoEdge {
		t.Fatalf("no edge %+v", x)
	}
}

func TestRevokeApplied(t *testing.T) {
	e := newEnv(t, siem.ResponseModeEnforce)
	req := revokeReq("alice")
	req.Summary = "<!channel> @everyone `x`\n" + strings.Repeat("y", 400)
	e.r.handle(req)
	x := e.only()
	if x.Action != siem.ResponseRevoke || x.Target != "alice" || x.State != siem.ResponseApplied || x.Duration != 0 ||
		!x.Automatic || x.RuleID != "mooring.login_tor" {
		t.Fatalf("response %+v", x)
	}
	if len(x.Summary) > MaxSummary || strings.ContainsAny(x.Summary, "\n<>@`") {
		t.Fatalf("stored summary %q", x.Summary)
	}
	notes, alerts, audits, events := e.take()
	if len(notes) != 1 || notes[0].id != 6 || notes[0].ev.Text != "signed alice out (3 sessions)" {
		t.Fatalf("timeline %+v", notes)
	}
	if len(alerts) != 1 {
		t.Fatalf("alerts %+v", alerts)
	}
	a := alerts[0]
	if a.Kind != AlertKind || a.Level != alert.LevelCritical || a.Transition != "firing" || a.RuleID != 0 ||
		a.DedupeKey != fmt.Sprintf("siem-response:%d", x.ID) || len(a.Summary) > MaxSummary ||
		!strings.HasPrefix(a.Summary, "Mooring signed alice out of 3 sessions: Mooring sign-in over Tor — !channel everyone x yyy") ||
		strings.ContainsAny(a.Summary, "<>@`") {
		t.Fatalf("alert %+v", a)
	}
	if len(audits) != 1 || audits[0].Detail != "action=revoke target=alice state=applied rule=mooring.login_tor sessions=3" ||
		audits[0].Actor != "siem" || audits[0].IP != "" || audits[0].Outcome != audit.OK {
		t.Fatalf("audit %+v", audits)
	}
	if events[0].Actor != "alice" || events[0].F["action"] != "revoke" || events[0].IP != "" {
		t.Fatalf("event %+v", events[0])
	}
	// A username with characters that notify a chat channel: kept on the response, left out of the
	// alert.
	e.rev.by["h:feedfacefeedface"] = revokeResult{"<!here>@ops`x`", 2, nil}
	e.r.handle(revokeReq("h:feedfacefeedface"))
	if x := e.list(siem.ResponseFilter{})[0]; x.Target != "<!here>@ops`x`" {
		t.Fatalf("username %+v", x)
	}
	if _, alerts, _, _ := e.take(); len(alerts) != 1 || !strings.HasPrefix(alerts[0].Summary, "Mooring signed !hereopsx out of 2 sessions") ||
		strings.ContainsAny(alerts[0].Summary, "<>@`") {
		t.Fatalf("alert %+v", alerts)
	}
	// One session reads as one.
	e.rev.by["dave"] = revokeResult{"dave", 1, nil}
	e.r.handle(revokeReq("dave"))
	if notes, alerts, _, _ := e.take(); notes[0].ev.Text != "signed dave out (1 session)" ||
		!strings.HasPrefix(alerts[0].Summary, "Mooring signed dave out of 1 session:") {
		t.Fatalf("one session: %+v %+v", notes, alerts)
	}
}

func TestRevokeCooldownCapsAndRefusals(t *testing.T) {
	e := newEnv(t, siem.ResponseModeEnforce, func(o *Options) { o.MaxRevokesPerHour = 3 })
	e.r.handle(revokeReq("alice"))
	e.clk.advance(10 * time.Minute)
	e.r.handle(revokeReq("alice"))
	if x := e.list(siem.ResponseFilter{})[0]; x.State != siem.ResponseRefused || x.Reason != "cooldown" || x.Target != "alice" {
		t.Fatalf("cooldown %+v", x)
	}
	// An account stored as a keyed hash: its cooldown holds by the hash too.
	e.r.handle(revokeReq("h:0123456789abcdef"))
	if x := e.list(siem.ResponseFilter{})[0]; x.State != siem.ResponseApplied || x.Target != "alice@example.com" {
		t.Fatalf("hashed actor %+v", x)
	}
	e.r.handle(revokeReq("h:0123456789abcdef"))
	if x := e.list(siem.ResponseFilter{})[0]; x.Reason != "cooldown" || x.Target != "h:0123456789abcdef" {
		t.Fatalf("hashed actor's cooldown %+v", x)
	}
	// The cooldown survives a restart (for an account stored by name).
	e.reopen()
	e.r.handle(revokeReq("alice"))
	if x := e.list(siem.ResponseFilter{})[0]; x.Reason != "cooldown" {
		t.Fatalf("after restart %+v", x)
	}
	// Unknown account; then the hourly cap (alice, alice@example.com, carol = 3).
	e.r.handle(revokeReq("mallory"))
	if x := e.list(siem.ResponseFilter{})[0]; x.State != siem.ResponseRefused || x.Reason != "unknown_account" {
		t.Fatalf("unknown %+v", x)
	}
	e.take()
	e.r.handle(revokeReq("carol"))
	e.r.handle(revokeReq("bob"))
	rs := e.list(siem.ResponseFilter{})
	if rs[1].State != siem.ResponseApplied || rs[0].State != siem.ResponseRefused || rs[0].Reason != "hourly_cap" {
		t.Fatalf("cap %+v", rs[:2])
	}
	_, alerts, _, _ := e.take()
	if len(alerts) != 2 || alerts[0].Level != alert.LevelCritical || alerts[1].Level != alert.LevelWarning ||
		alerts[1].DedupeKey != "siem-response-cap:revoke" {
		t.Fatalf("alerts %+v", alerts)
	}
	// Past the cooldown and the hour.
	e.clk.advance(time.Hour)
	e.r.handle(revokeReq("alice"))
	if x := e.list(siem.ResponseFilter{})[0]; x.State != siem.ResponseApplied {
		t.Fatalf("an hour later %+v", x)
	}
	// A revoker error that isn't an unknown account: failed.
	e.rev.by["erin"] = revokeResult{"", 0, errors.New("database is locked")}
	e.r.handle(revokeReq("erin"))
	if x := e.list(siem.ResponseFilter{})[0]; x.State != siem.ResponseFailed || x.Reason != "error" || x.Target != "erin" {
		t.Fatalf("failed %+v", x)
	}
}

// A revoke's target goes to the revoker exactly as the event stored it: one that isn't a plain
// account name is dropped, never rewritten into another account.
func TestMalformedRequestsDropped(t *testing.T) {
	e := newEnv(t, siem.ResponseModeEnforce)
	for _, target := range []string{"", " \n", "\x00"} {
		e.r.handle(revokeReq(target))
	}
	bad := blockReq("203.0.113.7", true)
	bad.Action = "lock"
	e.r.handle(bad)
	if rs := e.list(siem.ResponseFilter{}); len(rs) != 0 || len(e.rev.calls) != 0 {
		t.Fatalf("recorded %+v, revoker called %v", rs, e.rev.calls)
	}
	for _, actor := range []string{"own\ner", strings.Repeat("o", siem.MaxShort+1)} {
		if err := e.r.SetPause(context.Background(), siem.ResponseModeOff, actor); !errors.Is(err, siem.ErrInvalidInput) {
			t.Fatalf("actor %q: %v", actor, err)
		}
	}
	if len(e.blocks.lifts) != 0 {
		t.Fatalf("paused by a bad actor: %v", e.blocks.lifts)
	}
}

// Requests still queued when the responder stops are applied before Run returns.
func TestQueuedRequestsAppliedAtStop(t *testing.T) {
	e := newEnv(t, siem.ResponseModeEnforce)
	for i := range 20 {
		if !e.r.Respond(blockReq(fmt.Sprintf("203.0.113.%d", i+1), true)) {
			t.Fatal("not taken")
		}
	}
	// Stopped before the worker ran: Close doesn't wait for a Run that hasn't started.
	e.r.closed.Store(true)
	e.r.closeOnce.Do(func() { close(e.r.quit) })
	e.r.Run(context.Background())
	if rs := e.list(siem.ResponseFilter{Limit: 200}); len(rs) != 20 {
		t.Fatalf("%d of 20 applied", len(rs))
	}
}

func TestNoRevoker(t *testing.T) {
	e := newEnv(t, siem.ResponseModeEnforce)
	e.r.SetRevoker(nil)
	if st, _ := e.r.Status(context.Background()); st.Revoker {
		t.Fatal("revoker reported before it is set")
	}
	e.r.handle(revokeReq("alice"))
	if x := e.only(); x.State != siem.ResponseRefused || x.Reason != "no_revoker" {
		t.Fatalf("response %+v", x)
	}
	e.r.SetRevoker(e.rev)
	if st, _ := e.r.Status(context.Background()); !st.Revoker {
		t.Fatal("revoker not reported")
	}
}

func TestApplyDismissExpireDedupe(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, siem.ResponseModeRecommend)
	e.r.handle(blockReq("203.0.113.7", true))
	later := blockReq("203.0.113.7", true)
	later.DetectionID, later.RuleID, later.Summary = 21, "custom.later", "the latest"
	e.clk.advance(time.Minute)
	e.r.handle(later)
	x := e.only()
	if x.DetectionID != 21 || x.IncidentID != 5 || x.RuleID != "custom.later" || x.Summary != "the latest" ||
		!x.Created.Equal(t0) || !x.Updated.Equal(t0.Add(time.Minute)) {
		t.Fatalf("deduped %+v", x)
	}
	e.take()
	if err := e.r.Apply(ctx, x.ID, "owner"); err != nil {
		t.Fatal(err)
	}
	reqs := e.blocks.requests()
	if len(reqs) != 1 || reqs[0].Source != blocklist.SourceManual || reqs[0].By != "owner" || reqs[0].Duration != time.Hour ||
		reqs[0].ResponseID != x.ID || reqs[0].Prefix != "203.0.113.7/32" {
		t.Fatalf("block %+v", reqs)
	}
	got, ok, err := e.r.Response(ctx, x.ID)
	if err != nil || !ok || got.State != siem.ResponseApplied || got.By != "owner" {
		t.Fatalf("applied %+v %v %v", got, ok, err)
	}
	notes, _, audits, _ := e.take()
	if len(notes) != 1 || notes[0].ev.Actor != "owner" || notes[0].ev.Text != "blocked 203.0.113.7/32 for 1h" || len(audits) != 0 {
		t.Fatalf("timeline %+v audits %+v", notes, audits)
	}
	if err := e.r.Apply(ctx, x.ID, "owner"); !errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("applied twice: %v", err)
	}
	if err := e.r.Dismiss(ctx, x.ID, "owner"); !errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("dismissed an applied one: %v", err)
	}
	// Owner-applied blocks don't count toward the automatic cap.
	if st, _ := e.r.Status(ctx); st.BlocksThisHour != 0 {
		t.Fatalf("status %+v", st)
	}

	// A new request for the target is a new recommendation; dismissed.
	e.r.handle(blockReq("203.0.113.7", true))
	y := e.list(siem.ResponseFilter{States: []string{siem.ResponseRecommended}})
	if len(y) != 1 || y[0].ID == x.ID {
		t.Fatalf("new recommendation %+v", y)
	}
	if err := e.r.Dismiss(ctx, y[0].ID, "owner"); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := e.r.Response(ctx, y[0].ID); got.State != siem.ResponseDismissed || got.By != "owner" {
		t.Fatalf("dismissed %+v", got)
	}

	// A refused application: recorded, and the error says why.
	e.r.handle(blockReq("198.51.100.9", true))
	z := e.list(siem.ResponseFilter{States: []string{siem.ResponseRecommended}})[0]
	e.blocks.refuse["198.51.100.9/32"] = &blocklist.RefusedError{Code: blocklist.RefuseSession, Detail: "a signed-in session uses it"}
	err = e.r.Apply(ctx, z.ID, "owner")
	if !errors.Is(err, siem.ErrInvalidInput) || !strings.Contains(err.Error(), "a signed-in session uses it") {
		t.Fatalf("refused apply: %v", err)
	}
	if got, _, _ := e.r.Response(ctx, z.ID); got.State != siem.ResponseRefused || got.Reason != blocklist.RefuseSession || got.By != "owner" {
		t.Fatalf("refused %+v", got)
	}

	// A revoke recommendation applied by the owner: not cooled down, critical alert.
	e.r.handle(revokeReq("alice"))
	v := e.list(siem.ResponseFilter{States: []string{siem.ResponseRecommended}})[0]
	e.take()
	if err := e.r.Apply(ctx, v.ID, "owner"); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := e.r.Response(ctx, v.ID); got.State != siem.ResponseApplied || got.Target != "alice" {
		t.Fatalf("revoke applied %+v", got)
	}
	if _, alerts, _, _ := e.take(); len(alerts) != 1 || alerts[0].Level != alert.LevelCritical ||
		!strings.HasPrefix(alerts[0].Summary, "Mooring signed alice out of 3 sessions (applied by owner): mooring.login_tor — ") {
		t.Fatalf("alerts %+v", alerts)
	}

	// Expiry: a week without action.
	e.r.handle(blockReq("192.0.2.1", true))
	w := e.list(siem.ResponseFilter{States: []string{siem.ResponseRecommended}})[0]
	e.clk.advance(RecommendTTL + time.Minute)
	if err := e.r.Apply(ctx, w.ID, "owner"); !errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("applied an expired one: %v", err)
	}
	e.r.handle(blockReq("192.0.2.2", true))
	e.clk.advance(RecommendTTL + time.Minute)
	e.r.maintain(ctx)
	for _, s := range e.list(siem.ResponseFilter{}) {
		if s.State == siem.ResponseRecommended {
			t.Fatalf("not expired %+v", s)
		}
	}
	if got := e.list(siem.ResponseFilter{States: []string{siem.ResponseExpired}}); len(got) != 2 {
		t.Fatalf("expired %+v", got)
	}
	if err := e.r.Apply(ctx, 9999, "owner"); !errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("unknown: %v", err)
	}
	if err := e.r.Dismiss(ctx, w.ID, ""); !errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("no actor: %v", err)
	}
}

func TestLiftForIncident(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, siem.ResponseModeRecommend)
	e.r.handle(blockReq("203.0.113.7", true)) // incident 5
	other := blockReq("198.51.100.9", true)
	other.IncidentID = 9
	e.r.handle(other)
	e.take()
	e.blocks.incN = 2
	n, err := e.r.LiftForIncident(ctx, 5, "owner")
	if err != nil || n != 2 {
		t.Fatal(n, err)
	}
	if len(e.blocks.incidents) != 1 || e.blocks.incidents[0] != 5 || e.blocks.exempts[0] != ExemptFalsePos {
		t.Fatalf("unblock %v %v", e.blocks.incidents, e.blocks.exempts)
	}
	rs := e.list(siem.ResponseFilter{})
	if rs[1].State != siem.ResponseDismissed || rs[1].By != "owner" || rs[0].State != siem.ResponseRecommended {
		t.Fatalf("its recommendations %+v", rs)
	}
	notes, _, _, _ := e.take()
	if len(notes) != 1 || notes[0].id != 5 || notes[0].ev.Actor != "owner" ||
		notes[0].ev.Text != "false positive: lifted 2 automatic blocks, dismissed 1 recommendation" {
		t.Fatalf("timeline %+v", notes)
	}
	if _, err := e.r.LiftForIncident(ctx, 0, "owner"); !errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("incident 0: %v", err)
	}
}

func TestRespondNeverBlocks(t *testing.T) {
	e := newEnv(t, siem.ResponseModeEnforce)
	for i := range QueueSize {
		if !e.r.Respond(blockReq(fmt.Sprintf("203.0.%d.%d", i/250, i%250+1), true)) {
			t.Fatalf("request %d not taken", i)
		}
	}
	done := make(chan bool)
	go func() { done <- e.r.Respond(blockReq("192.0.2.1", true)) }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("a full queue took the request")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Respond blocked")
	}
	if e.r.dropped.Load() != 1 {
		t.Fatalf("dropped %d", e.r.dropped.Load())
	}
}

// Run applies queued requests; Close stops it and later requests aren't taken.
func TestRunAndClose(t *testing.T) {
	e := newEnv(t, siem.ResponseModeEnforce)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); e.r.Run(ctx) }()
	if !e.r.Respond(blockReq("203.0.113.7", true)) {
		t.Fatal("not taken")
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(e.list(siem.ResponseFilter{})) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("not applied")
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.r.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run didn't stop")
	}
	if e.r.Respond(blockReq("203.0.113.8", true)) {
		t.Fatal("taken after Close")
	}
	e.r.Close() // twice is fine
}

func TestResponsesFilterAndPaging(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, siem.ResponseModeEnforce)
	for i := range 5 {
		r := blockReq(fmt.Sprintf("203.0.113.%d", i+1), i%2 == 0)
		r.IncidentID = int64(i % 2)
		e.r.handle(r)
	}
	e.r.handle(revokeReq("alice"))
	if rs := e.list(siem.ResponseFilter{Action: siem.ResponseRevoke}); len(rs) != 1 || rs[0].Target != "alice" {
		t.Fatalf("revokes %+v", rs)
	}
	if rs := e.list(siem.ResponseFilter{States: []string{siem.ResponseRecommended}}); len(rs) != 2 {
		t.Fatalf("recommended %+v", rs)
	}
	if rs := e.list(siem.ResponseFilter{IncidentID: 1}); len(rs) != 2 {
		t.Fatalf("incident 1 %+v", rs)
	}
	page := e.list(siem.ResponseFilter{Limit: 4})
	if len(page) != 4 || page[0].ID <= page[3].ID {
		t.Fatalf("page %+v", page)
	}
	next := e.list(siem.ResponseFilter{Limit: 4, Before: page[3].ID})
	if len(next) != 2 || next[0].ID >= page[3].ID {
		t.Fatalf("next %+v", next)
	}
	for _, f := range []siem.ResponseFilter{{States: []string{"lifted"}}, {Action: "lock"}, {IncidentID: -1}, {Before: -1}} {
		if _, err := e.r.Responses(ctx, f); !errors.Is(err, siem.ErrInvalidInput) {
			t.Fatalf("%+v: %v", f, err)
		}
	}
	if _, ok, err := e.r.Response(ctx, 9999); ok || err != nil {
		t.Fatal(ok, err)
	}
}

func TestRetention(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, siem.ResponseModeEnforce)
	e.r.handle(blockReq("203.0.113.7", true))
	e.clk.advance(Retention - time.Hour)
	e.r.handle(blockReq("203.0.113.8", true))
	e.clk.advance(2 * time.Hour)
	e.r.prune(ctx)
	if rs := e.list(siem.ResponseFilter{}); len(rs) != 1 || rs[0].Target != "203.0.113.8/32" {
		t.Fatalf("after prune %+v", rs)
	}
}

func TestOpenNeedsTheDatabase(t *testing.T) {
	if _, err := Open(context.Background(), Options{}); err == nil {
		t.Fatal("no database: no error")
	}
}
