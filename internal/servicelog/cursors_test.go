package servicelog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type mutClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *mutClock) now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *mutClock) set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *logBuf) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// runManager runs m until the returned stop is called; stop waits for Run to return.
func runManager(t *testing.T, m *Manager, targets []Target) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	go func() { m.Run(ctx, 10*time.Millisecond, func() []Target { return targets }); close(done) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Run did not return")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func readCursorState(t *testing.T, path string) cursorState {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st cursorState
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatalf("cursor file: %v: %s", err, b)
	}
	return st
}

// Output written while Mooring is stopped is read on the next start: the cursor saved at shutdown is
// where the first attach after the restart begins, with the boundary dedupe of a re-attach.
func TestCursorsSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log-cursors.json")
	tg := []Target{{ContainerID: cid, App: "shop", Service: "api"}}
	clk := &mutClock{t: stamp(0)}

	f1 := newFakeStreamer(func(string, int) ([]stampedLine, bool) {
		return []stampedLine{{stamp(1), "a"}, {stamp(2), "b"}, {stamp(3), "c"}}, true
	})
	m1 := NewManager(nil, f1, discard)
	m1.now = clk.now
	m1.SetCursorFile(path)
	stop1 := runManager(t, m1, tg)
	waitCursor(t, m1, cid, stamp(3))
	clk.set(stamp(10))
	stop1()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("no cursor file after shutdown: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("cursor file mode %v, want 0600", fi.Mode().Perm())
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("a temporary file was left behind: %v", err)
	}

	// Mooring comes back later; the container kept writing meanwhile.
	clk.set(stamp(1000))
	f2 := newFakeStreamer(func(string, int) ([]stampedLine, bool) {
		return []stampedLine{{stamp(2), "b"}, {stamp(3), "c"}, {stamp(500), "written while Mooring was down"}, {stamp(900), "e"}}, true
	})
	m2 := NewManager(nil, f2, discard)
	m2.now = clk.now
	m2.SetCursorFile(path)
	var rec sinkRec
	m2.SetLineSink(rec.add)
	runManager(t, m2, tg)
	waitLines(t, f2, cid, 1)
	waitCursor(t, m2, cid, stamp(900))
	calls := f2.callsFor(cid)
	if !calls[0].since.Equal(stamp(3)) || calls[0].tail != backfillTail {
		t.Fatalf("first attach after the restart: since %v tail %d, want the saved cursor %v and tail %d", calls[0].since, calls[0].tail, stamp(3), backfillTail)
	}
	var texts []string
	for _, l := range rec.get() {
		texts = append(texts, l.Text)
	}
	if strings.Join(texts, ",") != "written while Mooring was down,e" {
		t.Errorf("lines after the restart: %q", texts)
	}
}

// While running, the file is saved periodically, so a crash (no shutdown save) loses at most one
// interval of positions.
func TestCursorsSavedWhileRunning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log-cursors.json")
	var clkMu sync.Mutex
	now := stamp(0)
	clock := func() time.Time { clkMu.Lock(); defer clkMu.Unlock(); now = now.Add(time.Second); return now }
	f := newFakeStreamer(func(string, int) ([]stampedLine, bool) { return []stampedLine{{stamp(1), "a"}}, true })
	m := NewManager(nil, f, discard)
	m.now = clock
	m.saveInterval = 20 * time.Millisecond
	m.SetCursorFile(path)
	runManager(t, m, []Target{{ContainerID: cid, App: "shop", Service: "api"}})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if b, err := os.ReadFile(path); err == nil && strings.Contains(string(b), strconv.FormatInt(stamp(1).UnixNano(), 10)) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the cursor file was never written while the manager ran")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The final save waits for the tailers, so a line a stream delivers while it is being stopped is in
// the saved cursor (and never read again).
func TestShutdownSaveIncludesTheLastLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log-cursors.json")
	f := newFakeStreamer(func(string, int) ([]stampedLine, bool) { return []stampedLine{{stamp(1), "a"}}, true })
	f.afterCancel = []stampedLine{{stamp(2), "flushed as the stream closed"}}
	m := NewManager(nil, f, discard)
	m.now = func() time.Time { return stamp(0) }
	m.SetCursorFile(path)
	stop := runManager(t, m, []Target{{ContainerID: cid, App: "shop", Service: "api"}})
	waitCursor(t, m, cid, stamp(1))
	stop()
	st := readCursorState(t, path)
	if got := st.Cursors[cid].TS; got != stamp(2).UnixNano() {
		t.Fatalf("saved cursor %v, want the last line's %v", time.Unix(0, got).UTC(), stamp(2))
	}
}

// The file is written through a fresh temporary file and a rename: a planted symlink at either path
// is replaced, never written through.
func TestCursorFileWriteIsPrivateAndAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log-cursors.json")
	sentinel := filepath.Join(dir, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sentinel, path+".tmp"); err != nil {
		t.Skip("symlinks unsupported:", err)
	}
	if err := os.Symlink(sentinel, path); err != nil {
		t.Fatal(err)
	}
	m := NewManager(nil, newFakeStreamer(nil), discard)
	m.SetCursorFile(path)
	c := &cursor{}
	c.last.Store(stamp(5).UnixNano())
	m.cursors[cid] = c
	m.saveCursors(stamp(10), true)

	if b, _ := os.ReadFile(sentinel); string(b) != "keep" {
		t.Fatalf("a symlink was written through: sentinel now %q", b)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("cursor file mode %v, want a regular 0600 file", fi.Mode())
	}
	if st := readCursorState(t, path); st.V != cursorFileVersion || st.Cursors[cid].TS != stamp(5).UnixNano() || st.Cursors[cid].Seen != stamp(10).UnixNano() {
		t.Errorf("cursor file content: %+v", st)
	}
}

// A file that can't be trusted is ignored with a warning, or only its bad entries are: a container
// whose cursor isn't usable gets the first-attach rule (from the manager's start).
func TestBadCursorFileIsIgnored(t *testing.T) {
	now := stamp(100_000)
	valid := func(ts, seen time.Time) string {
		return fmt.Sprintf(`{"v":1,"cursors":{%q:{"ts":%d,"seen":%d}}}`, cid, ts.UnixNano(), seen.UnixNano())
	}
	cases := []struct {
		name, content string
		warn          bool
	}{
		{"garbage", "\x00\xffnot json", true},
		{"wrong shape", `{"v":1,"cursors":{"` + cid + `":"yesterday"}}`, true},
		{"array", `[1,2,3]`, true},
		{"other version", strings.Replace(valid(now.Add(-time.Minute), now.Add(-time.Minute)), `"v":1`, `"v":2`, 1), true},
		{"too large", `{"v":1,"cursors":{}}` + strings.Repeat(" ", maxCursorFileBytes), true},
		{"future line time", valid(now.Add(time.Hour), now.Add(-time.Minute)), false},
		{"future seen time", valid(now.Add(-time.Minute), now.Add(time.Hour)), false},
		{"gone too long", valid(now.Add(-48*time.Hour), now.Add(-cursorTTL-time.Minute)), false},
		{"zero line time", valid(time.Unix(0, 0), now.Add(-time.Minute)), false},
		{"negative line time", fmt.Sprintf(`{"v":1,"cursors":{%q:{"ts":-5,"seen":%d}}}`, cid, now.Add(-time.Minute).UnixNano()), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "log-cursors.json")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			var logs logBuf
			f := newFakeStreamer(func(string, int) ([]stampedLine, bool) { return nil, false })
			m := NewManager(nil, f, slog.New(slog.NewTextHandler(&logs, nil)))
			m.now = func() time.Time { return now }
			m.SetCursorFile(path)
			ctx, cancel := context.WithCancel(bg)
			defer func() { cancel(); waitIdle(t, m) }()
			m.begin(ctx)
			m.reconcile([]Target{{ContainerID: cid, App: "shop", Service: "api"}})
			waitIdle(t, m)
			if calls := f.callsFor(cid); len(calls) != 1 || !calls[0].since.Equal(now) {
				t.Fatalf("attach: %+v, want since the manager start %v", calls, now)
			}
			if warned := strings.Contains(logs.String(), "level=WARN"); warned != tc.warn {
				t.Errorf("warning logged = %v, want %v: %s", warned, tc.warn, logs.String())
			}
		})
	}

	// A bad entry costs only itself: a valid one beside it is used, and names that aren't container
	// ids are dropped.
	path := filepath.Join(t.TempDir(), "log-cursors.json")
	other := strings.Repeat("ab", 32)
	content := fmt.Sprintf(`{"v":1,"cursors":{%q:{"ts":%d,"seen":%d},%q:{"ts":%d,"seen":%d},"../../etc/passwd":{"ts":%d,"seen":%d}}}`,
		cid, now.Add(-time.Hour).UnixNano(), now.Add(-time.Minute).UnixNano(),
		other, now.Add(time.Hour).UnixNano(), now.Add(-time.Minute).UnixNano(),
		now.Add(-time.Hour).UnixNano(), now.Add(-time.Minute).UnixNano())
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(nil, newFakeStreamer(nil), discard)
	m.now = func() time.Time { return now }
	m.SetCursorFile(path)
	m.loadCursors(now)
	if len(m.cursors) != 1 || m.cursors[cid] == nil || m.cursors[cid].last.Load() != now.Add(-time.Hour).UnixNano() {
		t.Errorf("loaded cursors: %d (want only the valid one)", len(m.cursors))
	}
}

// Loading keeps at most maxCursors entries, the most recently seen first.
func TestCursorFileLoadIsBounded(t *testing.T) {
	now := stamp(100_000)
	var b strings.Builder
	b.WriteString(`{"v":1,"cursors":{`)
	for i := 0; i < maxCursors+50; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"%064x":{"ts":%d,"seen":%d}`, i, now.Add(-time.Hour).UnixNano(), now.Add(-time.Duration(i)*time.Second).UnixNano())
	}
	b.WriteString(`}}`)
	path := filepath.Join(t.TempDir(), "log-cursors.json")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(nil, newFakeStreamer(nil), discard)
	m.SetCursorFile(path)
	m.loadCursors(now)
	if len(m.cursors) != maxCursors {
		t.Fatalf("loaded %d cursors, want %d", len(m.cursors), maxCursors)
	}
	if m.cursors[fmt.Sprintf("%064x", 0)] == nil || m.cursors[fmt.Sprintf("%064x", maxCursors+49)] != nil {
		t.Error("the most recently seen cursors must be the ones kept")
	}
}

// The file is written at most every saveEvery, only when a cursor moved (or hourly, to keep the seen
// times current), and always at shutdown.
func TestCursorSaveCadence(t *testing.T) {
	m := NewManager(nil, newFakeStreamer(nil), discard)
	m.SetCursorFile(filepath.Join(t.TempDir(), "log-cursors.json"))
	writes := 0
	m.writeState = func(path string, b []byte) error { writes++; return writeFileAtomic(path, b) }
	c := &cursor{}
	c.last.Store(stamp(1).UnixNano())
	m.cursors[cid] = c
	t0 := stamp(1000)

	m.saveCursors(t0, false)
	if writes != 1 {
		t.Fatalf("first save: %d writes", writes)
	}
	c.last.Store(stamp(2).UnixNano())
	m.saveCursors(t0.Add(5*time.Second), false)
	if writes != 1 {
		t.Fatalf("written again within %v", saveEvery)
	}
	m.saveCursors(t0.Add(saveEvery), false)
	if writes != 2 {
		t.Fatalf("a moved cursor must be written after %v: %d writes", saveEvery, writes)
	}
	m.saveCursors(t0.Add(30*time.Minute), false)
	if writes != 2 {
		t.Fatalf("written with nothing changed: %d writes", writes)
	}
	m.saveCursors(t0.Add(saveEvery+cursorRefresh), false)
	if writes != 3 {
		t.Fatalf("an unchanged file must be refreshed after %v: %d writes", cursorRefresh, writes)
	}
	m.saveCursors(t0.Add(saveEvery+cursorRefresh+time.Second), true)
	if writes != 4 {
		t.Fatalf("shutdown must always write: %d writes", writes)
	}
	// A new container is a change too, and so is one forgotten.
	c2 := &cursor{}
	c2.last.Store(stamp(3).UnixNano())
	m.cursors[strings.Repeat("cd", 32)] = c2
	m.saveCursors(t0.Add(2*saveEvery+cursorRefresh+time.Second), false)
	if writes != 5 {
		t.Fatalf("a new cursor must be written: %d writes", writes)
	}
	delete(m.cursors, cid)
	m.saveCursors(t0.Add(3*saveEvery+cursorRefresh+time.Second), false)
	if writes != 6 {
		t.Fatalf("a forgotten cursor must be written out: %d writes", writes)
	}
}

// A failed write is logged once and retried at the next save.
func TestCursorWriteFailureIsLoggedOnce(t *testing.T) {
	var logs logBuf
	m := NewManager(nil, newFakeStreamer(nil), slog.New(slog.NewTextHandler(&logs, nil)))
	m.SetCursorFile(filepath.Join(t.TempDir(), "missing-dir", "log-cursors.json"))
	c := &cursor{}
	c.last.Store(stamp(1).UnixNano())
	m.cursors[cid] = c
	for i := 0; i < 3; i++ {
		m.saveCursors(stamp(int64(1000+i*20)), false)
	}
	if n := strings.Count(logs.String(), "level=WARN"); n != 1 {
		t.Errorf("%d warnings for repeated write failures, want 1: %s", n, logs.String())
	}
}

// Without a cursor file Run works as before and saving is a no-op.
func TestNoCursorFile(t *testing.T) {
	m := NewManager(nil, newFakeStreamer(func(string, int) ([]stampedLine, bool) { return []stampedLine{{stamp(1), "x"}}, true }), discard)
	m.now = func() time.Time { return stamp(0) }
	m.writeState = func(string, []byte) error { t.Error("written without a cursor file"); return nil }
	stop := runManager(t, m, []Target{{ContainerID: cid, App: "shop", Service: "api"}})
	waitCursor(t, m, cid, stamp(1))
	stop()
}
