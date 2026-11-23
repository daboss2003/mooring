package l4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAvailableFailClosed(t *testing.T) {
	// On this (non-Linux) box the L4 LB must be unavailable, fail-closed.
	if runtime.GOOS == "linux" {
		t.Skip("running on Linux; off-Linux fail-closed path not exercised")
	}
	ok, why := Available()
	if ok {
		t.Fatal("off Linux the L4 LB must be unavailable")
	}
	if !strings.Contains(why, "Linux") {
		t.Errorf("expected a Linux requirement reason, got %q", why)
	}
}

func TestVerifyDigest(t *testing.T) {
	f := filepath.Join(t.TempDir(), "nginx")
	body := []byte("fake-binary")
	if err := os.WriteFile(f, body, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	good := hex.EncodeToString(sum[:])

	if err := VerifyDigest(f, ""); err != nil {
		t.Errorf("empty want must skip the check: %v", err)
	}
	if err := VerifyDigest(f, good); err != nil {
		t.Errorf("matching digest must pass: %v", err)
	}
	if err := VerifyDigest(f, "deadbeef"); err == nil {
		t.Error("a wrong digest must be rejected")
	}
}

func newSup(t *testing.T) *Supervisor {
	t.Helper()
	return &Supervisor{
		ConfigPath: filepath.Join(t.TempDir(), "nginx.conf"),
		Prefix:     t.TempDir(),
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// A good render passes nginx -t (stubbed) → the live config is written + reloaded.
func TestReconcileWritesAndReloads(t *testing.T) {
	s := newSup(t)
	tested, reloaded := false, false
	s.testConf = func(ctx context.Context, p string) error { tested = true; return nil }
	s.sighup = func(p *os.Process) error { reloaded = true; return nil }

	if err := s.Reconcile(context.Background(), []Route{
		{Listen: 53, Protocol: "udp", Service: "coredns", Port: 5353, Pool: []string{"10.0.0.7:5353"}},
	}); err != nil {
		t.Fatal(err)
	}
	if !tested {
		t.Error("nginx -t must run before swapping the live config")
	}
	if reloaded {
		t.Error("no reload expected when the master isn't running yet")
	}
	got, err := os.ReadFile(s.ConfigPath)
	if err != nil {
		t.Fatalf("live config not written: %v", err)
	}
	if !strings.Contains(string(got), "listen 53 udp;") {
		t.Errorf("live config missing the rendered route:\n%s", got)
	}
	if _, err := os.Stat(s.ConfigPath + ".new"); !os.IsNotExist(err) {
		t.Error("temp config should be renamed away, not left behind")
	}
}

// nginx -t rejecting the new config must NOT replace the live (last-good) config.
func TestReconcileKeepsLastGoodOnTestFailure(t *testing.T) {
	s := newSup(t)
	// Seed a known-good live config.
	if err := os.WriteFile(s.ConfigPath, []byte("GOOD-CONFIG"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.testConf = func(ctx context.Context, p string) error { return errors.New("bad config") }

	err := s.Reconcile(context.Background(), []Route{
		{Listen: 853, Protocol: "tcp", Service: "coredns", Port: 8853},
	})
	if err == nil || !strings.Contains(err.Error(), "last-good") {
		t.Fatalf("a rejected render must error mentioning last-good, got %v", err)
	}
	got, _ := os.ReadFile(s.ConfigPath)
	if string(got) != "GOOD-CONFIG" {
		t.Errorf("live config was replaced despite nginx -t failure: %q", got)
	}
	if _, err := os.Stat(s.ConfigPath + ".new"); !os.IsNotExist(err) {
		t.Error("the rejected temp config must be cleaned up")
	}
}

// An invalid route makes Render fail → Reconcile changes nothing (fail-closed).
func TestReconcileRejectsBadRoute(t *testing.T) {
	s := newSup(t)
	if err := os.WriteFile(s.ConfigPath, []byte("GOOD"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.testConf = func(ctx context.Context, p string) error { return nil }
	if err := s.Reconcile(context.Background(), []Route{
		{Listen: 443, Protocol: "tcp", Service: "x", Port: 1}, // 443 is the HTTP edge's
	}); err == nil {
		t.Fatal("a route on a reserved port must be rejected before any write")
	}
	if got, _ := os.ReadFile(s.ConfigPath); string(got) != "GOOD" {
		t.Errorf("live config must be untouched on a render error: %q", got)
	}
}

func TestParseModulesPath(t *testing.T) {
	// real `nginx -V` shape (Ubuntu): config args on one line, space-separated.
	const v = `nginx version: nginx/1.24.0 (Ubuntu)
built with OpenSSL 3.0.13
TLS SNI support enabled
configure arguments: --prefix=/usr/share/nginx --modules-path=/usr/lib/nginx/modules --conf-path=/etc/nginx/nginx.conf`
	if got := parseModulesPath(v); got != "/usr/lib/nginx/modules" {
		t.Errorf("got %q, want /usr/lib/nginx/modules", got)
	}
	// stream built into nginx (no separate module dir advertised) → empty, so the
	// caller skips the symlink and the bare stream{} block just works.
	if got := parseModulesPath("configure arguments: --prefix=/etc/nginx --with-stream"); got != "" {
		t.Errorf("got %q, want empty when no --modules-path", got)
	}
}

// syncBuffer is a bytes.Buffer safe for a logger writing from another goroutine.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// fakeMaster makes the supervisor launch a script that records each launch and then sleeps, in place
// of nginx.
func fakeMaster(t *testing.T, s *Supervisor) (launches string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	dir := t.TempDir()
	launches = filepath.Join(dir, "launches")
	bin := filepath.Join(dir, "nginx")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho x >> "+launches+"\nexec /bin/sleep 60\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	s.command = func(ctx context.Context) *exec.Cmd { return exec.CommandContext(ctx, bin) }
	return launches
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Restart stops the master and the loop relaunches it at once, without the crash backoff; PID follows
// the running master.
func TestSupervisorRestartRelaunchesAtOnce(t *testing.T) {
	s := newSup(t)
	var logBuf syncBuffer
	s.Log = slog.New(slog.NewTextHandler(&logBuf, nil))
	launches := fakeMaster(t, s)
	if s.PID() != 0 {
		t.Fatal("no master yet: PID must be 0")
	}
	s.Restart() // no master: a no-op
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.supervise(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	count := func() int { b, _ := os.ReadFile(launches); return strings.Count(string(b), "x") }
	waitFor(t, "the first launch", func() bool { return count() == 1 && s.PID() != 0 })
	first := s.PID()
	start := time.Now()
	s.Restart()
	waitFor(t, "the relaunch", func() bool { return count() == 2 && s.PID() != 0 && s.PID() != first })
	if took := time.Since(start); took > 900*time.Millisecond {
		t.Errorf("the relaunch took %v; a requested restart must not wait out a backoff", took)
	}
	if out := logBuf.String(); !strings.Contains(out, "l4 child restarted") || strings.Contains(out, "l4 child exited") {
		t.Errorf("a requested restart must relaunch at once, not as a crash:\n%s", out)
	}
	cancel()
	<-done
	if s.PID() != 0 {
		t.Error("once supervision stops, PID must be 0")
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// replaceFile puts body at path the way a package upgrade does (a new file renamed over the old one).
func replaceFile(t *testing.T, path string, body []byte) {
	t.Helper()
	tmp := path + ".dpkg-new"
	if err := os.WriteFile(tmp, body, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// With edge.l4_nginx_digest set, Validate (the stale watcher's check before a restart) refuses an nginx
// on PATH that no longer matches the pin, before running `nginx -t` with it.
func TestValidateChecksTheDigestPin(t *testing.T) {
	skipNoShell(t)
	dir := t.TempDir()
	nginx := filepath.Join(dir, "nginx")
	orig := []byte("#!/bin/sh\nexit 0\n")
	if err := os.WriteFile(nginx, orig, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	s := newSup(t)
	tests := 0
	s.testConf = func(context.Context, string) error { tests++; return nil }
	s.Digest = sha256Hex(orig)
	if err := s.Validate(context.Background()); err != nil || tests != 1 {
		t.Fatalf("the pinned binary: err=%v tests=%d; want nginx -t run and passed", err, tests)
	}

	replaceFile(t, nginx, []byte("#!/bin/sh\n# upgraded\nexit 0\n"))
	err := s.Validate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "edge.l4_nginx_digest") || !strings.Contains(err.Error(), nginx) {
		t.Fatalf("an nginx that doesn't match the pin: err=%v; want a digest error naming the binary", err)
	}
	if tests != 1 {
		t.Errorf("nginx -t ran %d times; a binary that fails the pin must not be run", tests)
	}

	s.Digest = ""
	if err := s.Validate(context.Background()); err != nil || tests != 2 {
		t.Errorf("no pin: err=%v tests=%d; want only nginx -t", err, tests)
	}
}

// With edge.l4_nginx_digest set, every launch checks the binary it is about to start: a relaunch (a
// Restart, a crash) onto an nginx a package upgrade replaced is refused and retried with backoff, and
// starts again once the binary matches the pin.
func TestLaunchChecksTheDigestPin(t *testing.T) {
	s := newSup(t)
	var logBuf syncBuffer
	s.Log = slog.New(slog.NewTextHandler(&logBuf, nil))
	launches := fakeMaster(t, s)
	bin := s.command(context.Background()).Path
	orig, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	s.Digest = sha256Hex(orig)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.supervise(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	count := func() int { b, _ := os.ReadFile(launches); return strings.Count(string(b), "x") }
	waitFor(t, "the first launch", func() bool { return count() == 1 && s.PID() != 0 })

	replaceFile(t, bin, append(append([]byte(nil), orig...), []byte("# upgraded\n")...))
	s.Restart()
	waitFor(t, "the refused relaunch", func() bool {
		return strings.Contains(logBuf.String(), "edge.l4_nginx_digest") && s.PID() == 0
	})
	time.Sleep(200 * time.Millisecond)
	if count() != 1 {
		t.Fatalf("launches = %d; a binary that fails the pin must never start", count())
	}
	if out := logBuf.String(); !strings.Contains(out, "l4: not starting nginx") || !strings.Contains(out, bin) {
		t.Errorf("the refusal must be logged clearly:\n%s", out)
	}
	// The pin is read only when Mooring starts (SIGHUP doesn't reload edge.*): a new pin needs a restart.
	if out := logBuf.String(); !strings.Contains(out, "set edge.l4_nginx_digest") || !strings.Contains(out, "sudo systemctl restart mooring") {
		t.Errorf("the refusal must say how to run the new binary (update the pin, restart Mooring):\n%s", out)
	}

	replaceFile(t, bin, orig) // the pinned binary is back
	waitFor(t, "the relaunch on the pinned binary", func() bool { return count() == 2 && s.PID() != 0 })
}

// With edge.l4_nginx_digest set, the real `nginx -t` (Reconcile's, every few seconds from serve's
// reconcile loop, and Validate's) never runs an nginx that fails the pin: Reconcile keeps the last-good
// config, and once the binary matches it tests and swaps as usual.
func TestNginxTestNeverRunsABinaryThatFailsThePin(t *testing.T) {
	skipNoShell(t)
	bin := t.TempDir()
	ran := filepath.Join(t.TempDir(), "ran")
	script := []byte("#!/bin/sh\necho \"$@\" >> " + ran + "\nexit 0\n")
	nginx := filepath.Join(bin, "nginx")
	if err := os.WriteFile(nginx, script, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	s := newSup(t) // no testConf seam: the real runTest
	s.Digest = sha256Hex([]byte("the nginx that was pinned"))
	if err := os.WriteFile(s.ConfigPath, []byte("GOOD-CONFIG"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := s.Reconcile(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "edge.l4_nginx_digest") || !strings.Contains(err.Error(), "last-good") ||
		!strings.Contains(err.Error(), nginx) {
		t.Fatalf("Reconcile with an nginx that fails the pin: err=%v; want a digest error naming the binary, keeping last-good", err)
	}
	if strings.Contains(err.Error(), "rejected by nginx -t") {
		t.Errorf("nginx -t never ran, so the config was not rejected by it: %v", err)
	}
	if err := s.Validate(context.Background()); err == nil || !strings.Contains(err.Error(), "edge.l4_nginx_digest") {
		t.Fatalf("Validate with an nginx that fails the pin: err=%v", err)
	}
	if b, _ := os.ReadFile(ran); len(b) != 0 {
		t.Fatalf("the nginx that fails the pin was run: %q", b)
	}
	if got, _ := os.ReadFile(s.ConfigPath); string(got) != "GOOD-CONFIG" {
		t.Errorf("the live config must stay last-good: %q", got)
	}
	if _, err := os.Stat(s.ConfigPath + ".new"); !os.IsNotExist(err) {
		t.Error("the untested config must be cleaned up")
	}

	s.Digest = sha256Hex(script) // the operator pinned this binary
	if err := s.Reconcile(context.Background(), nil); err != nil {
		t.Fatalf("Reconcile with the pinned nginx: %v", err)
	}
	b, _ := os.ReadFile(ran)
	if want := "-t -c " + s.ConfigPath + ".new -p " + s.Prefix; !strings.Contains(string(b), want) {
		t.Errorf("nginx invocations %q; want %q", b, want)
	}
	if got, _ := os.ReadFile(s.ConfigPath); string(got) == "GOOD-CONFIG" {
		t.Error("a config the pinned nginx accepted must be swapped in")
	}
}

func skipNoShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
}

// Every refusal by the digest pin — Reconcile's, Validate's and a launch's — matches ErrPinRefused, so
// serve's reconcile loop can tell it from a failure worth a fast retry: the binary stays refused until
// the pinned one is put back (or a new pin and a Mooring restart). An `nginx -t` rejection, or no nginx
// at all, is not a pin refusal.
func TestPinRefusalIsErrPinRefused(t *testing.T) {
	skipNoShell(t)
	dir := t.TempDir()
	script := []byte("#!/bin/sh\nexit 0\n")
	if err := os.WriteFile(filepath.Join(dir, "nginx"), script, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	s := newSup(t)
	s.Digest = sha256Hex([]byte("the nginx that was pinned"))
	ctx := context.Background()
	if err := s.Reconcile(ctx, nil); !errors.Is(err, ErrPinRefused) {
		t.Errorf("Reconcile with an nginx that fails the pin: err=%v; want ErrPinRefused", err)
	}
	if err := s.Validate(ctx); !errors.Is(err, ErrPinRefused) {
		t.Errorf("Validate with an nginx that fails the pin: err=%v; want ErrPinRefused", err)
	}
	if err := s.launch(ctx); !errors.Is(err, ErrPinRefused) {
		t.Errorf("a launch of an nginx that fails the pin: err=%v; want ErrPinRefused", err)
	}

	s.Digest = sha256Hex(script)
	s.testConf = func(context.Context, string) error { return errors.New("nginx: [emerg] unknown directive") }
	if err := s.Reconcile(ctx, nil); err == nil || errors.Is(err, ErrPinRefused) {
		t.Errorf("nginx -t rejecting the config: err=%v; want an error that is not ErrPinRefused", err)
	}
	s.testConf = nil
	t.Setenv("PATH", t.TempDir()) // no nginx at all
	if err := s.Validate(ctx); err == nil || errors.Is(err, ErrPinRefused) {
		t.Errorf("no nginx on PATH: err=%v; want an error that is not ErrPinRefused", err)
	}
}

// Validate runs `nginx -t` on the live config, never at the same time as a Reconcile's test-and-swap.
func TestValidateTestsTheLiveConfigUnderTheLock(t *testing.T) {
	s := newSup(t)
	var mu sync.Mutex
	active, maxActive := 0, 0
	var paths []string
	s.testConf = func(ctx context.Context, p string) error {
		mu.Lock()
		active++
		maxActive = max(maxActive, active)
		paths = append(paths, p)
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		active--
		mu.Unlock()
		if strings.HasSuffix(p, ".new") {
			return nil
		}
		return errors.New("nginx: [emerg] module is not binary compatible")
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = s.Reconcile(context.Background(), nil) }()
	var verr error
	go func() { defer wg.Done(); time.Sleep(10 * time.Millisecond); verr = s.Validate(context.Background()) }()
	wg.Wait()
	if maxActive != 1 {
		t.Errorf("Validate ran nginx -t alongside a Reconcile (%d at once)", maxActive)
	}
	if verr == nil || !strings.Contains(verr.Error(), "binary compatible") {
		t.Errorf("Validate must return the nginx -t failure, got %v", verr)
	}
	if !slices.Contains(paths, s.ConfigPath) {
		t.Errorf("Validate must test the live config %s; tested %v", s.ConfigPath, paths)
	}
}
