package audit

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/store"
)

func openDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

type sunk struct {
	ts time.Time
	e  Event
}

type sinkRec struct {
	mu  sync.Mutex
	got []sunk
}

func (s *sinkRec) fn(ts time.Time, e Event) {
	s.mu.Lock()
	s.got = append(s.got, sunk{ts, e})
	s.mu.Unlock()
}

func (s *sinkRec) all() []sunk {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sunk(nil), s.got...)
}

// The sink sees every event Log records, as stored (defaults applied), with the row's timestamp.
func TestSinkGetsEveryEventWithRowTimestamp(t *testing.T) {
	db := openDB(t)
	l := New(db, nil)
	fixed := time.Unix(1_800_000_000, 123_000_000)
	l.now = func() time.Time { return fixed }
	var rec sinkRec
	l.SetSink(rec.fn)

	if err := l.Log(context.Background(), Event{Actor: "a", Action: "one"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Log(context.Background(), Event{Actor: "b", Action: "two", Level: Security, Outcome: Deny}); err != nil {
		t.Fatal(err)
	}
	got := rec.all()
	if len(got) != 2 {
		t.Fatalf("sink got %d events, want 2", len(got))
	}
	if !got[0].ts.Equal(fixed) || got[0].e.Action != "one" || got[1].e.Action != "two" {
		t.Fatalf("sink got %+v", got)
	}
	// Defaults are applied before the sink sees the event, as they are for the row.
	if got[0].e.Level != Info || got[0].e.Outcome != OK {
		t.Errorf("sink event defaults: level=%q outcome=%q", got[0].e.Level, got[0].e.Outcome)
	}
	var ts int64
	if err := db.QueryRow(`SELECT ts FROM events WHERE action = 'one'`).Scan(&ts); err != nil {
		t.Fatal(err)
	}
	if ts != fixed.Unix() {
		t.Errorf("row ts = %d, sink ts = %d: they must match", ts, fixed.Unix())
	}
}

// A security event must reach the SIEM even when the events INSERT fails.
func TestSinkCalledWhenInsertFails(t *testing.T) {
	db := openDB(t)
	l := New(db, nil)
	var rec sinkRec
	l.SetSink(rec.fn)
	if _, err := db.Exec(`DROP TABLE events`); err != nil {
		t.Fatal(err)
	}
	err := l.Log(context.Background(), Event{Action: "login", Outcome: Deny, Level: Security, UA: "x"})
	if err == nil {
		t.Fatal("Log must return the insert error")
	}
	got := rec.all()
	if len(got) != 1 || got[0].e.Action != "login" || got[0].e.UA != "x" {
		t.Fatalf("sink after a failed insert got %+v, want the login event", got)
	}
}

// A cancelled request context fails the insert; the sink still gets the event.
func TestSinkCalledWhenContextCancelled(t *testing.T) {
	l := New(openDB(t), nil)
	var rec sinkRec
	l.SetSink(rec.fn)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = l.Log(ctx, Event{Action: "rbac_deny"})
	if len(rec.all()) != 1 {
		t.Fatalf("sink got %d events for a cancelled context, want 1", len(rec.all()))
	}
}

func TestSinkNilSafe(t *testing.T) {
	l := New(openDB(t), nil)
	// No sink set.
	if err := l.Log(context.Background(), Event{Action: "a"}); err != nil {
		t.Fatal(err)
	}
	var rec sinkRec
	l.SetSink(rec.fn)
	l.SetSink(nil) // clearing it
	if err := l.Log(context.Background(), Event{Action: "b"}); err != nil {
		t.Fatal(err)
	}
	if len(rec.all()) != 0 {
		t.Error("a cleared sink was still called")
	}
	var nl *Logger
	nl.SetSink(rec.fn) // must not panic
}

// A sink that itself logs must not deadlock (the sink runs outside any lock).
func TestSinkMayLog(t *testing.T) {
	l := New(openDB(t), nil)
	var nested atomic.Bool
	var rec sinkRec
	l.SetSink(func(ts time.Time, e Event) {
		rec.fn(ts, e)
		if nested.CompareAndSwap(false, true) {
			_ = l.Log(context.Background(), Event{Action: "from_sink"})
		}
	})
	done := make(chan struct{})
	go func() {
		_ = l.Log(context.Background(), Event{Action: "outer"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Log deadlocked when the sink logged")
	}
	if n := len(rec.all()); n != 2 {
		t.Errorf("sink got %d events, want 2 (outer + from_sink)", n)
	}
}

// SetSink racing Log is safe (run with -race).
func TestSinkSetConcurrentWithLog(t *testing.T) {
	l := New(openDB(t), nil)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = l.Log(context.Background(), Event{Action: "x"})
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				l.SetSink(func(time.Time, Event) {})
				l.SetSink(nil)
			}
		}()
	}
	wg.Wait()
}

func storedUA(t *testing.T, db *store.DB, action string) string {
	t.Helper()
	var ua string
	if err := db.QueryRow(`SELECT user_agent FROM events WHERE action = ?`, action).Scan(&ua); err != nil {
		t.Fatal(err)
	}
	return ua
}

// The actor can come from the request (the username a login attempt sends, up to 64 KiB): it is
// cleaned and cut like the User-Agent, in the row and in what the sink gets.
func TestActorStoredCutAndCleaned(t *testing.T) {
	db := openDB(t)
	l := New(db, nil)
	var rec sinkRec
	l.SetSink(rec.fn)
	if err := l.Log(context.Background(), Event{Action: "login", Actor: strings.Repeat("x", 64<<10) + "\r\nforged"}); err != nil {
		t.Fatal(err)
	}
	var actor string
	if err := db.QueryRow(`SELECT actor FROM events WHERE action = 'login'`).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	if actor != strings.Repeat("x", maxActor) {
		t.Errorf("actor stored with %d bytes (%q…), want %d x's", len(actor), actor[:min(len(actor), 20)], maxActor)
	}
	evs := rec.all()
	if len(evs) != 1 || evs[0].e.Actor != actor {
		t.Errorf("sink got a different actor than the row")
	}
	if err := l.Log(context.Background(), Event{Action: "ctl", Actor: "ad\x1bmin\n"}); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT actor FROM events WHERE action = 'ctl'`).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	if actor != "admin" {
		t.Errorf("control characters kept in the actor: %q", actor)
	}
}

func TestUserAgentStoredCutAndCleaned(t *testing.T) {
	db := openDB(t)
	l := New(db, nil)
	var rec sinkRec
	l.SetSink(rec.fn)
	ctx := context.Background()

	if err := l.Log(ctx, Event{Action: "plain", UA: "Mozilla/5.0 (X11; Linux x86_64)"}); err != nil {
		t.Fatal(err)
	}
	if got := storedUA(t, db, "plain"); got != "Mozilla/5.0 (X11; Linux x86_64)" {
		t.Errorf("plain UA stored as %q", got)
	}

	// Control characters (incl. newline/ESC/DEL/C1) and bidi/format characters are removed.
	if err := l.Log(ctx, Event{Action: "ctrl", UA: "curl/8\r\nX-Forged: 1\x1b[31m\x7f\u0085‮evil​"}); err != nil {
		t.Fatal(err)
	}
	if got := storedUA(t, db, "ctrl"); got != "curl/8X-Forged: 1[31mevil" {
		t.Errorf("control chars not stripped: %q", got)
	}

	// Cut to 256 bytes.
	if err := l.Log(ctx, Event{Action: "long", UA: strings.Repeat("a", 5000)}); err != nil {
		t.Fatal(err)
	}
	if got := storedUA(t, db, "long"); got != strings.Repeat("a", maxUserAgent) {
		t.Errorf("long UA stored with %d bytes, want %d", len(got), maxUserAgent)
	}

	// The cut never splits a UTF-8 sequence, and invalid bytes don't survive as raw bytes.
	if err := l.Log(ctx, Event{Action: "utf8", UA: "a" + strings.Repeat("é", 200) + "\xff"}); err != nil {
		t.Fatal(err)
	}
	got := storedUA(t, db, "utf8")
	if len(got) > maxUserAgent || !utf8Valid(got) {
		t.Errorf("utf8 UA cut badly: %d bytes, valid=%v", len(got), utf8Valid(got))
	}
	if want := "a" + strings.Repeat("é", 127); got != want { // 1 + 127*2 = 255 bytes; one more é would be 257
		t.Errorf("utf8 UA = %q, want %q", got, want)
	}

	// The sink sees the cleaned value.
	for _, s := range rec.all() {
		if s.e.Action == "ctrl" && s.e.UA != "curl/8X-Forged: 1[31mevil" {
			t.Errorf("sink saw uncleaned UA %q", s.e.UA)
		}
	}
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "") == s }

// An event without a UA takes the one the request context carries; an explicit UA wins.
func TestUserAgentFromContext(t *testing.T) {
	db := openDB(t)
	l := New(db, nil)
	ctx := WithUserAgent(context.Background(), "ctx-agent/1")
	if err := l.Log(ctx, Event{Action: "from_ctx"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Log(ctx, Event{Action: "explicit", UA: "explicit/2"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Log(context.Background(), Event{Action: "none"}); err != nil {
		t.Fatal(err)
	}
	if got := storedUA(t, db, "from_ctx"); got != "ctx-agent/1" {
		t.Errorf("from_ctx UA = %q", got)
	}
	if got := storedUA(t, db, "explicit"); got != "explicit/2" {
		t.Errorf("explicit UA = %q", got)
	}
	if got := storedUA(t, db, "none"); got != "" {
		t.Errorf("none UA = %q", got)
	}
}
