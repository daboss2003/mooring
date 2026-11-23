package hostproc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
)

type sink struct {
	mu          sync.Mutex
	got         []alert.Outbox
	noDeadline  bool
	failEnqueue bool
}

func (s *sink) EnqueueInfra(ctx context.Context, o alert.Outbox) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := ctx.Deadline(); !ok {
		s.noDeadline = true
	}
	s.got = append(s.got, o)
	if s.failEnqueue {
		return errors.New("db locked")
	}
	return nil
}

func (s *sink) kinds() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, o := range s.got {
		out = append(out, o.Kind)
	}
	return out
}

func (s *sink) last() alert.Outbox {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.got) == 0 {
		return alert.Outbox{}
	}
	return s.got[len(s.got)-1]
}

// fakeChild is one supervised child: its pid, the files Stale reports for each pid, and the restarts.
type fakeChild struct {
	pid         int
	stale       map[int][]string
	staleErr    error
	validateErr error
	validated   int
	restarts    int
	noDeadline  bool
}

func (c *fakeChild) child(name, target string) Child {
	return Child{
		Name: name, Target: target,
		PID: func() int { return c.pid },
		Validate: func(ctx context.Context) error {
			c.validated++
			if _, ok := ctx.Deadline(); !ok {
				c.noDeadline = true
			}
			return c.validateErr
		},
		Restart: func() { c.restarts++ },
	}
}

// rig is a Watcher over fake children with a hand-driven clock.
type rig struct {
	w   *Watcher
	now time.Time
	out *sink
	log *bytes.Buffer
}

func newRig(children map[string]*fakeChild) *rig {
	r := &rig{now: time.Date(2026, 11, 22, 3, 0, 0, 0, time.UTC), out: &sink{}, log: &bytes.Buffer{}}
	w := &Watcher{Alerts: r.out, Log: slog.New(slog.NewTextHandler(r.log, nil))}
	byPID := func(pid int) ([]string, error) {
		for _, c := range children {
			if c.pid == pid {
				if c.staleErr != nil {
					return nil, c.staleErr
				}
				return c.stale[pid], nil
			}
		}
		return nil, fs.ErrNotExist
	}
	for _, target := range []string{"caddy", "nginx-l4"} {
		if c, ok := children[target]; ok {
			name := map[string]string{"caddy": "Caddy", "nginx-l4": "L4 nginx"}[target]
			w.Children = append(w.Children, c.child(name, target))
		}
	}
	w.stale = byPID
	w.now = func() time.Time { return r.now }
	r.w = w
	return r
}

// at advances the clock to d after the start and runs one check.
func (r *rig) at(start time.Time, d time.Duration) {
	r.now = start.Add(d)
	r.w.tick(context.Background())
}

var upgraded = []string{"/usr/lib/x86_64-linux-gnu/libssl.so.3", "/usr/sbin/nginx"}

// The restart waits until the same pid has shown the same replaced files for Settle (2m by default):
// an upgrade replaces files over several seconds, and a child started half-way would not come up.
func TestWatcherWaitsForTheFilesToSettle(t *testing.T) {
	c := &fakeChild{pid: 100, stale: map[int][]string{100: upgraded}}
	r := newRig(map[string]*fakeChild{"nginx-l4": c})
	t0 := r.now
	r.at(t0, 0)
	r.at(t0, time.Minute)
	r.at(t0, 2*time.Minute-time.Second)
	if c.restarts != 0 || c.validated != 0 {
		t.Fatalf("restarted %d times (validated %d) before the files settled", c.restarts, c.validated)
	}
	r.at(t0, 2*time.Minute)
	if c.restarts != 1 || c.validated != 1 {
		t.Fatalf("restarts=%d validated=%d after Settle; want one validated restart", c.restarts, c.validated)
	}
	if c.noDeadline {
		t.Error("Validate must run on a bounded context")
	}
	o := r.out.last()
	if o.Kind != KindRestarted || o.Level != "warning" || o.Target != "nginx-l4" || o.Transition != "firing" ||
		o.RuleID != 0 || o.DedupeKey != "stalerestart:nginx-l4:100" {
		t.Errorf("restart alert = %+v", o)
	}
	for _, want := range []string{"L4 nginx", "pid 100", "/usr/sbin/nginx", "libssl.so.3", "sudo mooring doctor"} {
		if !strings.Contains(o.Summary, want) {
			t.Errorf("restart summary %q lacks %q", o.Summary, want)
		}
	}
	if r.out.noDeadline {
		t.Error("alerts must be enqueued on a bounded context")
	}
	if !strings.Contains(r.log.String(), "restarting it on the updated files") {
		t.Errorf("the restart must be logged:\n%s", r.log)
	}

	// The old process lingers for a moment while it stops: no second restart and no "stale" alert for it.
	r.at(t0, 3*time.Minute)
	if c.restarts != 1 || len(r.out.kinds()) != 1 {
		t.Errorf("restarts=%d alerts=%v while the restarted pid is still there", c.restarts, r.out.kinds())
	}
	// The relaunched child runs the new files.
	c.pid = 101
	r.at(t0, 4*time.Minute)
	r.at(t0, 10*time.Minute)
	if c.restarts != 1 || len(r.out.kinds()) != 1 {
		t.Errorf("restarts=%d alerts=%v for a current child", c.restarts, r.out.kinds())
	}
}

// More files replaced (the upgrade is still running) restart the settle wait.
func TestWatcherSettleRestartsWhenTheFilesChange(t *testing.T) {
	c := &fakeChild{pid: 100, stale: map[int][]string{100: {"/usr/sbin/nginx"}}}
	r := newRig(map[string]*fakeChild{"nginx-l4": c})
	t0 := r.now
	r.at(t0, 0)
	r.at(t0, time.Minute)
	c.stale[100] = upgraded
	r.at(t0, 2*time.Minute)
	if c.restarts != 0 {
		t.Fatal("restarted while the set of replaced files was still changing")
	}
	r.at(t0, 3*time.Minute)
	r.at(t0, 4*time.Minute)
	if c.restarts != 1 {
		t.Fatalf("restarts = %d; want one, Settle after the last change", c.restarts)
	}
}

// The replaced files must be seen continuously: a check that reads nothing (or can't read /proc)
// starts the wait over.
func TestWatcherSettleNeedsAContinuousSighting(t *testing.T) {
	c := &fakeChild{pid: 100, stale: map[int][]string{100: upgraded}}
	r := newRig(map[string]*fakeChild{"caddy": c})
	t0 := r.now
	r.at(t0, 0)
	c.staleErr = fs.ErrNotExist // the process was exiting
	r.at(t0, time.Minute)
	c.staleErr = nil
	r.at(t0, 2*time.Minute)
	r.at(t0, 3*time.Minute)
	if c.restarts != 0 {
		t.Fatal("a sighting broken by a failed read must start the wait over")
	}
	r.at(t0, 4*time.Minute)
	if c.restarts != 1 {
		t.Fatalf("restarts = %d", c.restarts)
	}
}

// A new pid (the child crashed and was relaunched) is tracked from scratch.
func TestWatcherNewPIDStartsOver(t *testing.T) {
	c := &fakeChild{pid: 100, stale: map[int][]string{100: upgraded, 200: upgraded}}
	r := newRig(map[string]*fakeChild{"caddy": c})
	t0 := r.now
	r.at(t0, 0)
	r.at(t0, time.Minute)
	c.pid = 200
	r.at(t0, 2*time.Minute)
	r.at(t0, 3*time.Minute)
	if c.restarts != 0 {
		t.Fatal("a new pid must wait Settle on its own")
	}
	r.at(t0, 4*time.Minute)
	if c.restarts != 1 {
		t.Fatalf("restarts = %d", c.restarts)
	}
}

// Updated files that fail the check keep the old process running and alert once per pid; a later
// check that passes restarts it.
func TestWatcherValidateFailureKeepsTheOldProcess(t *testing.T) {
	c := &fakeChild{pid: 100, stale: map[int][]string{100: upgraded},
		validateErr: errors.New("nginx: [emerg] module \"/usr/lib/nginx/modules/ngx_stream_module.so\" is not binary compatible\nline two")}
	r := newRig(map[string]*fakeChild{"nginx-l4": c})
	t0 := r.now
	r.at(t0, 0)
	r.at(t0, 2*time.Minute)
	r.at(t0, 3*time.Minute)
	r.at(t0, 4*time.Minute)
	if c.restarts != 0 {
		t.Fatal("a child whose updated files fail the check must not be restarted")
	}
	if c.validated != 3 {
		t.Errorf("validated %d times; want a check on every settled tick", c.validated)
	}
	if k := r.out.kinds(); len(k) != 1 || k[0] != KindStale {
		t.Fatalf("alerts = %v; want one %s", k, KindStale)
	}
	o := r.out.last()
	if o.Level != "warning" || o.Target != "nginx-l4" || o.DedupeKey != "stale:nginx-l4:100:check" || o.RuleID != 0 || o.Transition != "firing" {
		t.Errorf("stale alert = %+v", o)
	}
	for _, want := range []string{"L4 nginx", "not binary compatible", "sudo mooring doctor", "sudo dpkg --configure -a"} {
		if !strings.Contains(o.Summary, want) {
			t.Errorf("stale summary %q lacks %q", o.Summary, want)
		}
	}
	// A restart now would fail the same way: the advice must not be to restart Mooring.
	if strings.Contains(o.Summary, "systemctl restart") {
		t.Errorf("a failed check must not advise restarting Mooring: %q", o.Summary)
	}
	if strings.Contains(o.Summary, "\n") {
		t.Errorf("the summary must be one line: %q", o.Summary)
	}
	c.validateErr = nil
	r.at(t0, 5*time.Minute)
	if c.restarts != 1 || r.out.last().Kind != KindRestarted {
		t.Errorf("restarts=%d alerts=%v once the check passes", c.restarts, r.out.kinds())
	}
}

// Caddy's refusal is a long chain of module errors with the cause at its end (`caddy validate` of the
// served config): the alert quotes it whole, and a runaway error is still bounded.
func TestWatcherQuotesALongCheckFailure(t *testing.T) {
	cause := "`caddy validate` refused the edge config (exit status 1): loading http app module: provision http: getting tls app: " +
		"loading tls app module: provision tls: provisioning automation policy 0: loading TLS automation management module: position 0: " +
		"loading module 'acme': provision tls.issuance.acme: loading DNS provider module: loading module 'cloudflare': provision " +
		"dns.providers.cloudflare: API token '[redacted]' appears invalid; ensure it's correctly entered and not wrapped in braces nor quotes"
	c := &fakeChild{pid: 100, stale: map[int][]string{100: {"/usr/bin/caddy"}}, validateErr: errors.New("/usr/bin/caddy: " + cause)}
	r := newRig(map[string]*fakeChild{"caddy": c})
	t0 := r.now
	r.at(t0, 0)
	r.at(t0, 2*time.Minute)
	if s := r.out.last().Summary; !strings.Contains(s, "appears invalid; ensure it's correctly entered") {
		t.Errorf("the alert must quote the whole failure, cause included:\n%s", s)
	}
	if got := oneLine(strings.Repeat("x", 5000), maxErrText); len([]rune(got)) != maxErrText+1 || maxErrText > 2000 {
		t.Errorf("a runaway error must stay bounded: %d characters (bound %d)", len([]rune(got)), maxErrText)
	}
}

// At most one automatic restart per child within MinGap (30m by default): a child that is stale again
// right after a restart (a second upgrade) waits, with one alert, and is restarted after the gap.
func TestWatcherMinGapBetweenRestarts(t *testing.T) {
	c := &fakeChild{pid: 100, stale: map[int][]string{100: upgraded, 101: {"/usr/lib/x86_64-linux-gnu/libcrypto.so.3"}}}
	r := newRig(map[string]*fakeChild{"nginx-l4": c})
	t0 := r.now
	r.at(t0, 0)
	r.at(t0, 2*time.Minute)
	if c.restarts != 1 {
		t.Fatalf("first restart: %d", c.restarts)
	}
	c.pid = 101
	r.at(t0, 5*time.Minute)
	r.at(t0, 7*time.Minute)
	r.at(t0, 20*time.Minute)
	if c.restarts != 1 {
		t.Fatalf("restarts = %d; a second automatic restart inside MinGap must wait", c.restarts)
	}
	if k := r.out.kinds(); len(k) != 2 || k[1] != KindStale || r.out.last().DedupeKey != "stale:nginx-l4:101:recent" {
		t.Fatalf("alerts = %v (%+v); want restarted, then one stale alert for pid 101", k, r.out.last())
	}
	if s := r.out.last().Summary; !strings.Contains(s, "30 minutes") || !strings.Contains(s, "libcrypto.so.3") ||
		!strings.Contains(s, "sudo systemctl restart mooring") {
		t.Errorf("stale summary %q; want the gap, the files and how to restart now", s)
	}
	r.at(t0, 2*time.Minute+30*time.Minute)
	if c.restarts != 2 {
		t.Errorf("restarts = %d; want the second restart once MinGap has passed", c.restarts)
	}
}

// Inside MinGap the check still runs first: updated files that fail it get the "check" alert (no
// restart advice: a restart would fail the same way), never the "recent" alert, whose advice is to
// restart Mooring now. Once the check passes the "recent" alert follows, and the restart after the gap.
func TestWatcherChecksBeforeTheMinGapAlert(t *testing.T) {
	c := &fakeChild{pid: 100, stale: map[int][]string{100: upgraded, 101: {"/usr/lib/x86_64-linux-gnu/libcrypto.so.3"}}}
	r := newRig(map[string]*fakeChild{"nginx-l4": c})
	t0 := r.now
	r.at(t0, 0)
	r.at(t0, 2*time.Minute) // restarted; MinGap runs until 32m
	c.pid = 101
	c.validateErr = errors.New("nginx: [emerg] dlopen() \"/usr/lib/nginx/modules/ngx_stream_module.so\" failed")
	r.at(t0, 5*time.Minute)
	r.at(t0, 7*time.Minute) // settled inside MinGap, the check fails
	r.at(t0, 8*time.Minute)
	r.out.mu.Lock()
	got := append([]alert.Outbox(nil), r.out.got...)
	r.out.mu.Unlock()
	if len(got) != 2 || got[1].DedupeKey != "stale:nginx-l4:101:check" {
		t.Fatalf("alerts = %+v; want restarted, then the failed check's alert for pid 101", got)
	}
	if s := got[1].Summary; strings.Contains(s, "systemctl restart") || !strings.Contains(s, "dlopen()") {
		t.Errorf("a failed check inside MinGap must not advise a restart: %q", s)
	}
	if c.validated != 3 { // the restart at 2m, then 7m and 8m
		t.Errorf("validated %d times; the check must run on every settled tick, MinGap or not", c.validated)
	}

	c.validateErr = nil
	r.at(t0, 10*time.Minute)
	if c.restarts != 1 {
		t.Fatalf("restarts = %d inside MinGap", c.restarts)
	}
	if o := r.out.last(); o.DedupeKey != "stale:nginx-l4:101:recent" || !strings.Contains(o.Summary, "sudo systemctl restart mooring") {
		t.Errorf("once the check passes inside MinGap: %+v; want the 'recent' alert with how to restart now", o)
	}
	r.at(t0, 32*time.Minute)
	if c.restarts != 2 {
		t.Errorf("restarts = %d; want the restart once MinGap has passed", c.restarts)
	}
}

// One alert per process and reason: a "restarted recently" alert doesn't hide a later failed check for
// the same process, and neither repeats.
func TestWatcherAlertsOncePerReason(t *testing.T) {
	c := &fakeChild{pid: 100, stale: map[int][]string{100: upgraded, 101: {"/usr/lib/x86_64-linux-gnu/libcrypto.so.3"}}}
	r := newRig(map[string]*fakeChild{"nginx-l4": c})
	t0 := r.now
	r.at(t0, 0)
	r.at(t0, 2*time.Minute) // restarted; MinGap runs until 32m
	c.pid = 101
	r.at(t0, 5*time.Minute)
	r.at(t0, 7*time.Minute)  // settled inside MinGap
	r.at(t0, 20*time.Minute) // still inside: no second alert
	c.validateErr = errors.New("nginx: [emerg] dlopen() \"/usr/lib/nginx/modules/ngx_stream_module.so\" failed")
	r.at(t0, 33*time.Minute)
	r.at(t0, 34*time.Minute)
	r.at(t0, 35*time.Minute)
	if c.restarts != 1 {
		t.Fatalf("restarts = %d; a failed check must not restart", c.restarts)
	}
	r.out.mu.Lock()
	got := append([]alert.Outbox(nil), r.out.got...)
	r.out.mu.Unlock()
	if len(got) != 3 || got[1].DedupeKey != "stale:nginx-l4:101:recent" || got[2].DedupeKey != "stale:nginx-l4:101:check" ||
		got[2].Kind != KindStale {
		t.Fatalf("alerts = %+v; want restarted, one 'recent' and one 'check' stale alert for pid 101", got)
	}
	if s := got[2].Summary; !strings.Contains(s, "dlopen()") || !strings.Contains(s, "sudo mooring doctor") || strings.Contains(s, "systemctl restart") {
		t.Errorf("check-failed summary %q", s)
	}
	if n := strings.Count(r.log.String(), "not restarting it"); n != 2 {
		t.Errorf("the 'not restarting' line must be logged once per reason, got %d:\n%s", n, r.log)
	}
}

// Each child is tracked on its own: a restart of one never blocks or triggers the other.
func TestWatcherChildrenAreIndependent(t *testing.T) {
	caddy := &fakeChild{pid: 10, stale: map[int][]string{10: {"/usr/bin/caddy"}}}
	nginx := &fakeChild{pid: 20, stale: map[int][]string{}}
	r := newRig(map[string]*fakeChild{"caddy": caddy, "nginx-l4": nginx})
	t0 := r.now
	r.at(t0, 0)
	r.at(t0, 2*time.Minute)
	nginx.stale[20] = upgraded
	r.at(t0, 3*time.Minute)
	r.at(t0, 5*time.Minute)
	if caddy.restarts != 1 || nginx.restarts != 1 {
		t.Errorf("caddy restarts=%d nginx restarts=%d; want one each", caddy.restarts, nginx.restarts)
	}
	if o := r.out.got[0]; o.Target != "caddy" || o.DedupeKey != "stalerestart:caddy:10" || !strings.Contains(o.Summary, "Caddy") {
		t.Errorf("caddy alert = %+v", o)
	}
}

// No child, a current child, a child whose /proc can't be read: never a restart or an alert.
func TestWatcherNothingToDo(t *testing.T) {
	gone := &fakeChild{pid: 0, stale: map[int][]string{0: upgraded}}
	current := &fakeChild{pid: 30, stale: map[int][]string{}}
	r := newRig(map[string]*fakeChild{"caddy": gone, "nginx-l4": current})
	t0 := r.now
	for m := 0; m < 10; m++ {
		r.at(t0, time.Duration(m)*time.Minute)
	}
	current.staleErr = errors.New("permission denied")
	for m := 10; m < 20; m++ {
		r.at(t0, time.Duration(m)*time.Minute)
	}
	if gone.restarts+current.restarts != 0 || len(r.out.kinds()) != 0 {
		t.Errorf("restarts=%d alerts=%v", gone.restarts+current.restarts, r.out.kinds())
	}
	if n := strings.Count(r.log.String(), "can't read which files"); n != 1 {
		t.Errorf("an unreadable /proc must be logged once per pid, got %d:\n%s", n, r.log)
	}
}

// Without an alert sink or a check, the restart still happens (and is logged).
func TestWatcherWithoutAlertsOrValidate(t *testing.T) {
	restarts := 0
	var log bytes.Buffer
	now := time.Now()
	w := &Watcher{
		Log:      slog.New(slog.NewTextHandler(&log, nil)),
		Children: []Child{{Name: "Caddy", Target: "caddy", PID: func() int { return 5 }, Restart: func() { restarts++ }}},
		stale:    func(int) ([]string, error) { return []string{"/usr/bin/caddy"}, nil },
		now:      func() time.Time { return now },
	}
	w.tick(context.Background())
	now = now.Add(w.settle())
	w.tick(context.Background())
	if restarts != 1 || !strings.Contains(log.String(), "restarting it on the updated files") {
		t.Errorf("restarts=%d log:\n%s", restarts, log.String())
	}
	// An alert store that fails doesn't stop the restart either.
	out := &sink{failEnqueue: true}
	c := &fakeChild{pid: 9, stale: map[int][]string{9: upgraded}}
	r := newRig(map[string]*fakeChild{"caddy": c})
	r.w.Alerts = out
	t0 := r.now
	r.at(t0, 0)
	r.at(t0, 2*time.Minute)
	if c.restarts != 1 || len(out.kinds()) != 1 {
		t.Errorf("restarts=%d alerts=%v with a failing alert store", c.restarts, out.kinds())
	}
}

func TestWatcherDefaults(t *testing.T) {
	w := &Watcher{}
	if w.interval() != time.Minute || w.settle() != 2*time.Minute || w.minGap() != 30*time.Minute {
		t.Errorf("defaults: interval=%v settle=%v minGap=%v", w.interval(), w.settle(), w.minGap())
	}
	w = &Watcher{Interval: time.Second, Settle: 3 * time.Second, MinGap: time.Hour}
	if w.interval() != time.Second || w.settle() != 3*time.Second || w.minGap() != time.Hour {
		t.Error("set values must be used")
	}
}

func TestListFiles(t *testing.T) {
	if got := listFiles([]string{"/a"}); got != "/a" {
		t.Errorf("one: %q", got)
	}
	if got := listFiles([]string{"/a", "/b", "/c"}); got != "/a, /b, /c" {
		t.Errorf("three: %q", got)
	}
	if got := listFiles([]string{"/a", "/b", "/c", "/d", "/e"}); got != "/a, /b, /c and 2 more" {
		t.Errorf("five: %q", got)
	}
}

// Run checks every Interval until ctx ends.
func TestWatcherRun(t *testing.T) {
	var mu sync.Mutex
	checks := 0
	w := &Watcher{
		Log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), Interval: 5 * time.Millisecond,
		Children: []Child{{Name: "Caddy", Target: "caddy", PID: func() int { mu.Lock(); checks++; mu.Unlock(); return 1 }}},
		stale:    func(int) ([]string, error) { return nil, nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := checks
		mu.Unlock()
		if n >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Run checked %d times", n)
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run must return when ctx ends")
	}
}

// heldCheck is a check error that holds the restart back for a reason other than the updated files.
type heldCheck struct{}

func (heldCheck) Error() string {
	return "Caddy refuses the current edge config and so does the Caddy at /usr/bin/caddy"
}
func (heldCheck) StaleAdvice() string { return "Fix what Caddy reports in the edge config." }

// A check error with its own advice (serve's Caddy check held back by a refused edge config) replaces
// the broken-upgrade advice: the updated files are fine, so the alert must not claim a restart of
// Mooring would not start the child, nor point at dpkg.
func TestWatcherHeldCheckGivesItsOwnAdvice(t *testing.T) {
	c := &fakeChild{pid: 100, stale: map[int][]string{100: {"/usr/bin/caddy"}}, validateErr: fmt.Errorf("wrapped: %w", heldCheck{})}
	r := newRig(map[string]*fakeChild{"caddy": c})
	t0 := r.now
	r.at(t0, 0)
	r.at(t0, 2*time.Minute)
	s := r.out.last().Summary
	if !strings.Contains(s, "the restart is held back (wrapped: Caddy refuses the current edge config") || !strings.Contains(s, "Fix what Caddy reports in the edge config.") {
		t.Errorf("the alert must quote the check and give its advice:\n%s", s)
	}
	if strings.Contains(s, "would not start it") || strings.Contains(s, "dpkg") {
		t.Errorf("a held restart is not a broken upgrade:\n%s", s)
	}
}
