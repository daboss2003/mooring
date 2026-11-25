package blocklist

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/store"
)

func TestMain(m *testing.M) {
	// Tests read this server's own addresses from fixtures only (never the host's /proc).
	procFibTrie = filepath.Join("testdata", "fib_trie")
	procIfInet6 = filepath.Join("testdata", "if_inet6")
	os.Exit(m.Run())
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type alerts struct {
	mu      sync.Mutex
	got     []alert.Outbox
	err     error
	openErr error
}

func (a *alerts) EnqueueInfra(_ context.Context, o alert.Outbox) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	a.got = append(a.got, o)
	return nil
}

// OpenInfraAlerts is the alert store's: the keys of kind whose newest alert is firing.
func (a *alerts) OpenInfraAlerts(_ context.Context, kind string) (map[string]string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.openErr != nil {
		return nil, a.openErr
	}
	out := map[string]string{}
	for _, o := range a.got {
		if o.Kind != kind {
			continue
		}
		if o.Transition == "firing" {
			out[o.DedupeKey] = o.Target
		} else {
			delete(out, o.DedupeKey)
		}
	}
	return out, nil
}

func (a *alerts) setErr(err error) {
	a.mu.Lock()
	a.err = err
	a.mu.Unlock()
}

// plainAlerter is an Alerter that can't say which alerts are open.
type plainAlerter struct{ a *alerts }

func (p plainAlerter) EnqueueInfra(ctx context.Context, o alert.Outbox) error {
	return p.a.EnqueueInfra(ctx, o)
}

func (a *alerts) list() []alert.Outbox {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]alert.Outbox(nil), a.got...)
}

func (a *alerts) count(key, transition string) int {
	n := 0
	for _, o := range a.list() {
		if o.DedupeKey == key && o.Transition == transition {
			n++
		}
	}
	return n
}

type events struct {
	mu  sync.Mutex
	evs []siem.Event
}

func (e *events) emit(ev siem.Event) bool {
	e.mu.Lock()
	e.evs = append(e.evs, ev)
	e.mu.Unlock()
	return true
}

// actions returns the F.action of every siem.block event (kind siem.block) for prefix.
func (e *events) actions(prefix string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, ev := range e.evs {
		if ev.Kind == kindBlock && ev.F["prefix"] == prefix {
			out = append(out, ev.F["action"].(string))
		}
	}
	return out
}

func (e *events) kind(k string) []siem.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []siem.Event
	for _, ev := range e.evs {
		if ev.Kind == k {
			out = append(out, ev)
		}
	}
	return out
}

// guardState is the mutable protected set a test hands the Blocker.
type guardState struct {
	mu       sync.Mutex
	allow    []netip.Prefix
	tokens   []netip.Prefix
	sessions []netip.Addr
}

func (g *guardState) setAllow(ps ...string) {
	g.mu.Lock()
	g.allow = pfx(ps...)
	g.mu.Unlock()
}

type harness struct {
	t      *testing.T
	db     *store.DB
	clk    *clock
	alerts *alerts
	ev     *events
	g      *guardState
	opts   Options
	b      *Blocker
	caddy  struct {
		sync.Mutex
		ok  bool
		why string
	}
}

var t0 = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

func pfx(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// newHarness opens a Blocker on a fresh database with a fake clock, alerter and event sink:
// allowlist 203.0.113.0/24, proxies 192.0.2.128/25, CDN 104.16.0.0/13, never_block 198.51.100.64/26.
func newHarness(t *testing.T, mod ...func(*Options)) *harness {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "mooring.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	h := &harness{t: t, db: db, clk: &clock{t: t0}, alerts: &alerts{}, ev: &events{}, g: &guardState{}}
	h.g.setAllow("203.0.113.0/24")
	h.caddy.ok = true
	h.opts = Options{
		DB: db,
		Guard: Guard{
			Allowlist:  func() []netip.Prefix { h.g.mu.Lock(); defer h.g.mu.Unlock(); return h.g.allow },
			TokenCIDRs: func() []netip.Prefix { h.g.mu.Lock(); defer h.g.mu.Unlock(); return h.g.tokens },
			Proxies:    pfx("192.0.2.128/25"),
			CDN:        pfx("104.16.0.0/13", "2606:4700::/32"),
			Configured: pfx("198.51.100.64/26"),
			Sessions: func(context.Context) []netip.Addr {
				h.g.mu.Lock()
				defer h.g.mu.Unlock()
				return h.g.sessions
			},
		},
		EdgeOwned:         true,
		CaddyOK:           func() (bool, string) { h.caddy.Lock(); defer h.caddy.Unlock(); return h.caddy.ok, h.caddy.why },
		MaxAuto:           1000,
		MaxAutoDuration:   24 * time.Hour,
		ManualMaxDuration: 30 * 24 * time.Hour,
		Alerter:           h.alerts,
		Emit:              h.ev.emit,
		Now:               h.clk.now,
	}
	for _, m := range mod {
		m(&h.opts)
	}
	h.reopen()
	return h
}

// reopen opens a new Blocker on the same database (a restart).
func (h *harness) reopen() {
	h.t.Helper()
	if h.b != nil {
		h.b.Close()
	}
	b, err := Open(context.Background(), h.opts)
	if err != nil {
		h.t.Fatal(err)
	}
	b.SetApply(func(context.Context) error { return nil })
	h.b = b
	h.t.Cleanup(b.Close)
}

// release publishes the current list now (what Run does at most once a minute).
func (h *harness) release() { h.b.release(context.Background(), h.clk.now()) }

func (h *harness) snapshot() []string {
	var out []string
	for _, p := range h.b.Snapshot() {
		out = append(out, p.String())
	}
	return out
}

func (h *harness) auto(prefix string, d time.Duration) (Block, error) {
	return h.b.Block(context.Background(), Request{Prefix: prefix, Source: SourceAuto, Duration: d, RuleID: "edge.scan", Reason: "scanning"})
}

func (h *harness) manual(prefix string, d time.Duration, self string) (Block, error) {
	return h.b.Block(context.Background(), Request{Prefix: prefix, Source: SourceManual, Duration: d, By: "owner", Self: self, Reason: "abuse"})
}

func (h *harness) mustBlock(blk Block, err error) Block {
	h.t.Helper()
	if err != nil {
		h.t.Fatalf("block: %v", err)
	}
	return blk
}

// refused asserts err is a *RefusedError with code.
func refused(t *testing.T, err error, code string) {
	t.Helper()
	var re *RefusedError
	if !errors.As(err, &re) {
		t.Fatalf("want refusal %q, got %v", code, err)
	}
	if re.Code != code {
		t.Fatalf("want refusal %q, got %q (%s)", code, re.Code, re.Detail)
	}
}
