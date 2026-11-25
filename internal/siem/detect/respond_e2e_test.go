package detect

import (
	"context"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/blocklist"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/respond"
	"github.com/daboss2003/mooring/internal/store"
)

// relay hands the engine's requests to the responder in use and counts those it took.
type relay struct {
	mu   sync.Mutex
	r    *respond.Responder
	sent int
}

func (x *relay) Respond(req siem.ResponseRequest) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	ok := x.r.Respond(req)
	if ok {
		x.sent++
	}
	return ok
}

// stack is the engine with the real responder and the real block list on one mooring.db.
type stack struct {
	t       *testing.T
	h       *harness
	db      *store.DB
	maxAuto time.Duration
	bl      *blocklist.Blocker
	r       *respond.Responder
	rel     *relay
	stop    func()
	mu      sync.Mutex
	audits  []audit.Event
	events  []siem.Event
}

func newStack(t *testing.T, maxAuto time.Duration) *stack {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "mooring.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := &stack{t: t, db: db, maxAuto: maxAuto, rel: &relay{}}
	s.h = newHarness(t, false, func(o *Options) { o.Responder = s.rel })
	s.h.incidents = true
	s.h.e.lim.incidents = true
	s.open()
	t.Cleanup(func() { s.close() })
	return s
}

func (s *stack) open() {
	s.t.Helper()
	ctx := context.Background()
	bl, err := blocklist.Open(ctx, blocklist.Options{DB: s.db, EdgeOwned: true, Now: s.h.clk.now, MaxAutoDuration: s.maxAuto})
	if err != nil {
		s.t.Fatal(err)
	}
	r, err := respond.Open(ctx, respond.Options{DB: s.db, Mode: siem.ResponseModeEnforce, Blocks: bl, Now: s.h.clk.now,
		Audit: func(_ context.Context, ev audit.Event) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.audits = append(s.audits, ev)
			return nil
		},
		Emit: func(ev siem.Event) bool {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.events = append(s.events, ev)
			return true
		}})
	if err != nil {
		s.t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); r.Run(context.Background()) }()
	s.bl, s.r = bl, r
	s.rel.mu.Lock()
	s.rel.r, s.rel.sent = r, len(s.rows())
	s.rel.mu.Unlock()
	s.stop = func() { r.Close(); <-done; bl.Close() }
}

func (s *stack) close() {
	if s.stop != nil {
		s.stop()
		s.stop = nil
	}
}

func (s *stack) rows() []siem.Response {
	s.t.Helper()
	rs, err := s.r.Responses(context.Background(), siem.ResponseFilter{Limit: 200})
	if err != nil {
		s.t.Fatal(err)
	}
	return rs
}

// settle waits until the responder is done with every request the engine made: each one is a
// skipped request or a recorded response with its outcome, audited (the last thing that follows).
func (s *stack) settle() {
	s.t.Helper()
	waitFor(s.t, "the responder", func() bool {
		s.rel.mu.Lock()
		sent := s.rel.sent
		s.rel.mu.Unlock()
		rows := s.rows()
		if len(rows)+int(s.r.Skipped()) != sent || (len(rows) > 0 && rows[0].Reason == "interrupted") {
			return false
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.audits) == len(rows)
	})
}

// restart closes and reopens the engine, the responder and the block list (as a restart of Mooring).
func (s *stack) restart(rs ...siem.Rule) {
	s.t.Helper()
	s.settle()
	s.close()
	s.h.reopen(s.t)
	s.h.e.lim.incidents = true
	s.h.only(s.t, rs...)
	s.open()
}

// blockEnd is when addr's block in force ends, by the block list's own record (zero: none in force).
func (s *stack) blockEnd(addr string) time.Time {
	s.t.Helper()
	b, ok, err := s.bl.Get(context.Background(), netip.MustParsePrefix(addr+"/32"))
	if err != nil {
		s.t.Fatal(err)
	}
	if !ok || b.State != blocklist.StateActive || !b.Until.After(s.h.clk.now()) {
		return time.Time{}
	}
	return b.Until
}

func (s *stack) blocked(addr string) bool { return !s.blockEnd(addr).IsZero() }

type placed struct {
	at  time.Duration // since t0
	dur time.Duration
}

// keepFiring fires rule for addrX every 4 minutes until end (restarting everything before the
// firings at restartAt). It returns the blocks placed, oldest first, and the longest time between
// the end of one and the start of the next; it fails when the block list, asked after each firing,
// has the address unblocked for more than maxOpen since its last block ended.
func (s *stack) keepFiring(rule siem.Rule, end, maxOpen time.Duration, restartAt ...time.Duration) (blocks []placed, gap time.Duration) {
	s.t.Helper()
	s.h.only(s.t, rule)
	var lastEnd time.Time
	for at := time.Duration(0); at <= end; at += 4 * time.Minute {
		if slices.Contains(restartAt, at) {
			s.restart(rule)
		}
		s.h.feed(edgeHit(at, addrX, ""))
		s.h.e.flush(false)
		s.settle()
		if until := s.blockEnd(addrX); !until.IsZero() {
			lastEnd = until
		} else if open := s.h.clk.now().Sub(lastEnd); lastEnd.IsZero() || open > maxOpen {
			s.t.Fatalf("at %s: not blocked for %s", at, open)
		}
	}
	if ds := s.h.all(s.t); len(ds) != 1 {
		s.t.Fatalf("detections %+v", ds)
	}
	rows := s.rows()
	for i := len(rows) - 1; i >= 0; i-- {
		x := rows[i]
		if x.State != siem.ResponseApplied || x.Action != siem.ResponseBlock || x.Target != addrX+"/32" || !x.Automatic || x.Reason != "" {
			s.t.Fatalf("response %+v (of %d)", x, len(rows))
		}
		p := placed{x.Created.Sub(t0), x.Duration}
		if n := len(blocks); n > 0 {
			gap = max(gap, p.at-blocks[n-1].at-blocks[n-1].dur)
		}
		blocks = append(blocks, p)
	}
	// Nothing else was recorded, audited or emitted than the blocks placed.
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.audits) != len(blocks) || len(s.events) != len(blocks) {
		s.t.Fatalf("%d blocks, %d audit records, %d events", len(blocks), len(s.audits), len(s.events))
	}
	return blocks, gap
}

func samePlaced(got, want []placed) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// End to end with the real responder and the real block list: a 10-minute rule whose address keeps
// firing every 4 minutes for 2.5 hours is blocked along the block list's ladder (10m, 40m, 160m),
// one applied response per block and nothing else recorded, and is never left unblocked for more
// than 7 minutes between two blocks.
func TestEndToEndRepeatBlocksFollowTheLadder(t *testing.T) {
	rule := edgeRule(1)
	rule.Response = blockResp(10 * time.Minute)
	const m = time.Minute

	s := newStack(t, 7*24*time.Hour)
	blocks, gap := s.keepFiring(rule, 150*m, 7*m)
	// Asked every 8 minutes (every second firing). Blocked 0–10m; the request at 8m is skipped (2m to
	// go), the one at 16m places 40m (to 56m), the one at 56m places 160m.
	if want := []placed{{0, 10 * m}, {16 * m, 40 * m}, {56 * m, 160 * m}}; !samePlaced(blocks, want) {
		t.Fatalf("blocks %+v, want %+v", blocks, want)
	}
	if gap != 6*m {
		t.Fatalf("longest time between blocks %s", gap)
	}
	if n := s.r.Skipped(); n != 19-3 {
		t.Fatalf("%d of the 19 requests skipped", n)
	}
	if !s.blocked(addrX) {
		t.Fatal("not blocked at the end")
	}

	// The same across a restart of the engine, the responder and the block list while the second
	// block is in force. The detection read back asks at its first firing (36m: skipped, 20m to go)
	// and every 8 minutes from there, so the third block is placed at 60m.
	s = newStack(t, 7*24*time.Hour)
	blocks, gap = s.keepFiring(rule, 150*m, 7*m, 36*m)
	if want := []placed{{0, 10 * m}, {16 * m, 40 * m}, {60 * m, 160 * m}}; !samePlaced(blocks, want) {
		t.Fatalf("with a restart: blocks %+v, want %+v", blocks, want)
	}
	if gap != 6*m || !s.blocked(addrX) {
		t.Fatalf("with a restart: longest time between blocks %s, blocked at the end %v", gap, s.blocked(addrX))
	}
	// And across one right after the first block ended, before it was asked for again: the detection
	// read back asks at once.
	s = newStack(t, 7*24*time.Hour)
	blocks, gap = s.keepFiring(rule, 150*m, 7*m, 12*m)
	if want := []placed{{0, 10 * m}, {12 * m, 40 * m}, {52 * m, 160 * m}}; !samePlaced(blocks, want) {
		t.Fatalf("with a restart between blocks: blocks %+v, want %+v", blocks, want)
	}
	if gap != 2*m || !s.blocked(addrX) {
		t.Fatalf("with a restart between blocks: longest time between blocks %s, blocked at the end %v", gap, s.blocked(addrX))
	}
}

// A rule's block longer than the longest automatic block (3 days, 24 hours) is placed for the
// longest, and placed again when that ends while the address still fires.
func TestEndToEndBlockLongerThanTheMaximumIsRepeated(t *testing.T) {
	rule := edgeRule(1)
	rule.Response = blockResp(3 * 24 * time.Hour)
	s := newStack(t, 24*time.Hour)
	blocks, gap := s.keepFiring(rule, 24*time.Hour+8*time.Minute, 7*time.Minute)
	if want := []placed{{0, 24 * time.Hour}, {24 * time.Hour, 24 * time.Hour}}; !samePlaced(blocks, want) {
		t.Fatalf("blocks %+v, want %+v", blocks, want)
	}
	if gap != 0 || !s.blocked(addrX) {
		t.Fatalf("longest time between blocks %s, blocked at the end %v", gap, s.blocked(addrX))
	}
}
