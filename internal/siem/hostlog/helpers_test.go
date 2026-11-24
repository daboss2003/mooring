package hostlog

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

var quietLog = slog.New(slog.DiscardHandler)

// sink collects emitted lines.
type sink struct {
	mu    sync.Mutex
	lines []Line
}

func (s *sink) emit(l Line) {
	s.mu.Lock()
	s.lines = append(s.lines, l)
	s.mu.Unlock()
}

func (s *sink) texts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.lines))
	for _, l := range s.lines {
		out = append(out, l.Text)
	}
	return out
}

// waitFor polls until at least n lines arrived or d passed, and returns the texts.
func (s *sink) waitFor(n int, d time.Duration) []string {
	deadline := time.Now().Add(d)
	for {
		got := s.texts()
		if len(got) >= n || time.Now().After(deadline) {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// clock is a settable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// testFollower builds a Follower on a fake clock with a state dir under the test's temp dir.
func testFollower(t *testing.T, cfg Config) (*Follower, *clock) {
	t.Helper()
	if cfg.StateDir == "" {
		cfg.StateDir = filepath.Join(t.TempDir(), "state")
	}
	if cfg.Log == nil {
		cfg.Log = quietLog
	}
	f := New(cfg)
	ck := &clock{t: time.Unix(1_700_000_000, 0)}
	f.now = ck.Now
	return f, ck
}

// authFile builds a step-driven follower of cfg.AuthLog.
func authFile(t *testing.T, cfg Config) (*fileFollower, *Follower, *clock, *sink) {
	t.Helper()
	f, ck := testFollower(t, cfg)
	s := &sink{}
	ff := f.newFile(f.files[0], s.emit)
	t.Cleanup(ff.close)
	return ff, f, ck, s
}

func writeFile(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	w, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func wantLines(t *testing.T, got []string, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("lines = %q, want %q", got, want)
	}
}

// statusOf returns the named source's status.
func statusOf(t *testing.T, f *Follower, name string) (st struct {
	OK  bool
	Err string
	N   int64
}) {
	t.Helper()
	for _, s := range f.Status() {
		if s.Name == name {
			st.OK, st.Err, st.N = s.OK, s.Err, s.Events
			return st
		}
	}
	t.Fatalf("no status for %s in %+v", name, f.Status())
	return st
}

// runFollower runs f in the background; the returned stop cancels it and fails the test when Run
// doesn't return promptly.
func runFollower(t *testing.T, f *Follower, emit func(Line)) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		f.Run(ctx, emit)
		close(done)
	}()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Errorf("Run did not return within 5s of ctx cancel")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

// setVarLog points the default-log directory at dir for the test.
func setVarLog(t *testing.T, dir string) {
	t.Helper()
	old := varLog
	varLog = dir
	t.Cleanup(func() { varLog = old })
}
