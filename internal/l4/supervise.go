package l4

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// nginxBin is fixed (never operator-supplied): the binary is invoked with the `-c`
// config flag, and the static-shell-exec lint (SEC-1) only permits `-c` on a literal,
// allowlisted command — a dynamic binary name + `-c` is exactly the shell-injection
// shape it forbids. Mooring pins the binary by digest (VerifyDigest), not by path.
const nginxBin = "nginx"

// Available reports whether this host can OWN the managed L4 load balancer — a
// supervised child nginx (stream module) with its own systemd slice +
// CAP_NET_BIND_SERVICE + egress firewall (the L4 analog of the edge, plan §6),
// Linux-only. Off Linux, or with no nginx binary, it is FAIL-CLOSED unavailable.
func Available() (bool, string) {
	if runtime.GOOS != "linux" {
		return false, "managed L4 LB requires Linux (got " + runtime.GOOS + ")"
	}
	if _, err := exec.LookPath(nginxBin); err != nil {
		return false, "nginx binary not found on PATH"
	}
	return true, ""
}

// VerifyDigest checks the nginx binary's SHA-256 against a pinned digest (supply
// chain — refuse on mismatch, plan §6). An empty want skips the check.
func VerifyDigest(nginxPath, want string) error {
	if want == "" {
		return nil
	}
	f, err := os.Open(nginxPath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("l4: nginx binary digest mismatch (refusing to run it): %s doesn't match edge.l4_nginx_digest; its SHA-256 is %s", nginxPath, got)
	}
	return nil
}

// verifyNginxOnPath checks the nginx a command named "nginx" runs now against the pin (none: nil).
func (s *Supervisor) verifyNginxOnPath() error {
	if s.Digest == "" {
		return nil
	}
	path, err := exec.LookPath(nginxBin)
	if err != nil {
		return fmt.Errorf("l4: %w", err)
	}
	return VerifyDigest(path, s.Digest)
}

// Supervisor owns the child nginx that serves the L4 stream proxy. Config lives in a
// Mooring-owned file; the operator never authors it. Reconcile renders from typed
// routes, validates with `nginx -t`, and only then swaps the live config + reloads —
// a rejected render keeps the last-good config serving (fail-closed). The testConf /
// signal seams let the reconcile state machine be unit-tested without a real nginx.
type Supervisor struct {
	ConfigPath string // the live config file the master reads (Mooring-owned)
	Prefix     string // nginx -p prefix dir (Mooring-owned, e.g. /var/lib/mooring/l4)
	Digest     string // pinned SHA-256 of the nginx binary (optional)
	Log        *slog.Logger

	mu         sync.Mutex
	proc       *os.Process // running master, for a SIGHUP reload (nil when not running)
	restarting bool        // the current master is being stopped by Restart

	// dmu guards deny and denyErr (separately from mu, which is held while nginx -t runs).
	dmu     sync.Mutex
	deny    func() []netip.Prefix
	denyErr string

	// Seams (nil → real implementation): testConf runs `nginx -t`; sighup signals reload; command builds
	// the master's command.
	testConf func(ctx context.Context, configPath string) error
	sighup   func(p *os.Process) error
	command  func(ctx context.Context) *exec.Cmd
}

// PID is the running master's pid, 0 when none is running.
func (s *Supervisor) PID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proc == nil {
		return 0
	}
	return s.proc.Pid
}

// Restart stops the running master so Run relaunches it at once — no backoff, on the nginx binary and
// libraries now on disk (used after a package upgrade replaced them). SIGTERM first (nginx's fast
// shutdown), SIGKILL if it's still running 5s later. A no-op when no master is running.
func (s *Supervisor) Restart() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proc == nil {
		return
	}
	s.restarting = true
	p := s.proc
	_ = p.Signal(syscall.SIGTERM)
	// Safe after the process is reaped: os.Process.Kill then returns os.ErrProcessDone.
	time.AfterFunc(5*time.Second, func() { _ = p.Kill() })
}

// Validate reports whether a relaunch would come up on the nginx now on disk: `nginx -t` on the live
// config, which with a Digest first checks that nginx against it (runTest: a binary that fails the pin
// is never run). The test holds the lock Reconcile holds, so it never tests a config while a Reconcile
// swaps it.
func (s *Supervisor) Validate(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runTest(ctx, s.ConfigPath)
}

// SetDeny sets the block list every Reconcile renders (RenderDeny): blocklist.Blocker.L4Snapshot.
// fn must be quick and lock-free, and the slice it returns is never modified.
func (s *Supervisor) SetDeny(fn func() []netip.Prefix) {
	s.dmu.Lock()
	s.deny = fn
	s.dmu.Unlock()
}

// DenyErr is why the listeners serve without the block list: nginx -t refused the config with its
// deny lines and accepted it without them ("" when the last Reconcile applied the block list, or had
// none to apply).
func (s *Supervisor) DenyErr() string {
	s.dmu.Lock()
	defer s.dmu.Unlock()
	return s.denyErr
}

// setDenyErr sets DenyErr and returns what it was.
func (s *Supervisor) setDenyErr(e string) (was string) {
	s.dmu.Lock()
	was, s.denyErr = s.denyErr, e
	s.dmu.Unlock()
	return was
}

// maxDenyErr bounds DenyErr (nginx -t output).
const maxDenyErr = 512

// Reconcile renders the routes and the block list (SetDeny), validates the rendered config, and
// atomically swaps it in + reloads. It is fail-closed and serialized: a render error, an nginx that
// fails the Digest pin or an `nginx -t` rejection leaves the live config untouched (last-good keeps
// serving). When nginx -t refuses the config only with its deny lines, the config without them is
// applied and DenyErr says why.
func (s *Supervisor) Reconcile(ctx context.Context, routes []Route) error {
	s.dmu.Lock()
	denyFn := s.deny
	s.dmu.Unlock()
	var deny []netip.Prefix
	if denyFn != nil {
		deny = denyRanges(denyFn())
	}
	cfg, err := RenderDeny(routes, deny) // bad routes → nothing changes
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err = s.applyLocked(ctx, cfg)
	if err == nil || len(deny) == 0 {
		if err == nil && s.setDenyErr("") != "" {
			s.Log.Info("l4: nginx takes the block list again")
		}
		return err
	}
	if errors.Is(err, ErrPinRefused) {
		return err
	}
	// Intentional: the listeners matter more than the block list (one bad line takes every listener
	// down, :53 included), so a config nginx refuses only with its deny lines is applied without them.
	plain, perr := Render(routes)
	if perr != nil {
		return err
	}
	if perr := s.applyLocked(ctx, plain); perr != nil {
		return err
	}
	why := err.Error()
	if len(why) > maxDenyErr {
		why = strings.ToValidUTF8(why[:maxDenyErr], "")
	}
	// Logged when the reason changes, not on every reconcile (one runs every 15 s); DenyErr keeps it.
	if s.setDenyErr(why) != why {
		s.Log.Warn("l4: nginx refused the block list; the listeners serve without it", "err", why)
	}
	return nil
}

// applyLocked writes cfg next to the live config, tests it with nginx -t, swaps it in and reloads the
// master. Called under s.mu.
func (s *Supervisor) applyLocked(ctx context.Context, cfg string) error {
	if err := os.MkdirAll(filepath.Dir(s.ConfigPath), 0o755); err != nil {
		return err
	}
	tmp := s.ConfigPath + ".new"
	if err := os.WriteFile(tmp, []byte(cfg), 0o644); err != nil {
		return err
	}
	if err := s.runTest(ctx, tmp); err != nil {
		os.Remove(tmp)
		if errors.As(err, new(pinRefusedError)) {
			return fmt.Errorf("l4: rendered config not tested or applied (keeping last-good): %w", err)
		}
		return fmt.Errorf("l4: rendered config rejected by nginx -t (keeping last-good): %w", err)
	}
	if err := os.Rename(tmp, s.ConfigPath); err != nil { // atomic swap
		os.Remove(tmp)
		return err
	}
	if s.proc != nil {
		if err := s.doSighup(s.proc); err != nil {
			s.Log.Warn("l4: reload signal failed", "err", err)
		}
	}
	return nil
}

// runTest runs `nginx -t` on configPath. With a Digest, the nginx the command resolved to is checked
// first, as at every launch: serve reconciles before Run's own check and every few seconds after, also
// once Run has refused to start the binary, so without it a package upgrade's unpinned nginx would run.
func (s *Supervisor) runTest(ctx context.Context, configPath string) error {
	cmd := exec.CommandContext(ctx, "nginx", "-t", "-c", configPath, "-p", s.Prefix) // literal: SEC-1 requires it
	// cmd.Err (no nginx on PATH) fails the run below.
	if s.Digest != "" && cmd.Err == nil {
		if err := VerifyDigest(cmd.Path, s.Digest); err != nil {
			return pinRefusedError{err}
		}
	}
	if s.testConf != nil {
		return s.testConf(ctx, configPath)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

func (s *Supervisor) doSighup(p *os.Process) error {
	if s.sighup != nil {
		return s.sighup(p)
	}
	return p.Signal(syscall.SIGHUP)
}

// ensureModuleDir points <Prefix>/modules at nginx's real module directory. Because
// nginx runs with `-p <Prefix>`, the relative `load_module modules/ngx_stream_module.so`
// that Debian/Ubuntu's /etc/nginx/modules-enabled emits resolves under <Prefix> — so
// without this it dlopens <Prefix>/modules/… and the stream module is "not found".
// Best-effort: if nginx's module dir can't be determined (stream built into nginx, or
// no nginx) it's a no-op, and `nginx -t` surfaces any genuine problem.
func (s *Supervisor) ensureModuleDir() {
	dir := nginxModulesDir()
	if dir == "" {
		return
	}
	link := filepath.Join(s.Prefix, "modules")
	if cur, err := os.Readlink(link); err == nil && cur == dir {
		return // already correct
	}
	if err := os.MkdirAll(s.Prefix, 0o755); err != nil {
		s.Log.Warn("l4: could not create prefix dir for the module link", "err", err)
		return
	}
	_ = os.Remove(link) // replace a stale/wrong link (no-op if absent)
	if err := os.Symlink(dir, link); err != nil {
		s.Log.Warn("l4: could not link nginx module dir", "link", link, "target", dir, "err", err)
	}
}

// nginxModulesDir returns nginx's compiled --modules-path (from `nginx -V`), or "" if
// nginx is absent or the path can't be parsed.
func nginxModulesDir() string {
	out, err := exec.Command(nginxBin, "-V").CombinedOutput() // nginx -V prints config to stderr; literal binary (SEC-1)
	if err != nil {
		return ""
	}
	return parseModulesPath(string(out))
}

// parseModulesPath extracts --modules-path=<dir> from `nginx -V` output.
func parseModulesPath(nginxV string) string {
	for _, tok := range strings.Fields(nginxV) {
		if v, ok := strings.CutPrefix(tok, "--modules-path="); ok {
			return v
		}
	}
	return ""
}

// Run supervises the child nginx with capped backoff until ctx is cancelled. It is
// fail-closed: if the host can't own the L4 LB (non-Linux, no binary, digest
// mismatch) it logs and returns without starting anything. The systemd slice / user
// / caps / egress firewall are the OS deployment layer (plan §6); this owns the
// lifecycle. Not exercised off-Linux.
func (s *Supervisor) Run(ctx context.Context) {
	if ok, why := Available(); !ok {
		s.Log.Warn("managed L4 LB not started", "reason", why)
		return
	}
	if err := s.verifyNginxOnPath(); err != nil {
		s.Log.Error("managed L4 LB not started", "err", err)
		return
	}
	// Make the prefix-relative `load_module modules/…` (from /etc/nginx/modules-enabled
	// on Debian/Ubuntu) resolve, since we run nginx with `-p <Prefix>`.
	s.ensureModuleDir()
	// Ensure a valid config exists before the first launch (an empty stream block
	// is a valid floor; routes are pushed via Reconcile).
	if _, err := os.Stat(s.ConfigPath); err != nil {
		if rerr := s.Reconcile(ctx, nil); rerr != nil {
			s.Log.Error("l4: could not write initial config", "err", rerr)
			return
		}
	}
	s.supervise(ctx)
}

// supervise is Run's launch loop, without the host checks.
func (s *Supervisor) supervise(ctx context.Context) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		start := time.Now()
		err := s.launch(ctx)
		s.mu.Lock()
		restarted := s.restarting
		s.restarting = false
		s.mu.Unlock()
		if restarted && ctx.Err() == nil {
			s.Log.Info("l4 child restarted")
			backoff = time.Second
			continue // relaunch immediately on the nginx now on disk
		}
		switch {
		case err == nil || ctx.Err() != nil:
		case errors.As(err, new(pinRefusedError)):
			// The pin is read only at startup (SIGHUP doesn't reload edge.*), so a new pin needs a restart.
			s.Log.Error("l4: not starting nginx: the binary fails the edge.l4_nginx_digest check; retrying with backoff, so it starts if the pinned binary is put back. To run this binary, set edge.l4_nginx_digest to its SHA-256 (in err) and run `sudo systemctl restart mooring`", "err", err.Error())
		default:
			s.Log.Error("l4 child exited", "err", err)
		}
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > 30*time.Second {
			backoff = time.Second
		} else if backoff < 30*time.Second {
			backoff *= 2
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

// ErrPinRefused matches (errors.Is) every error Reconcile, Validate and a launch return because the nginx
// on PATH fails the Digest pin. Retrying soon doesn't help: it stays refused until the pinned binary is
// put back, or the pin is changed and Mooring restarted.
var ErrPinRefused = errors.New("l4: the nginx binary fails the edge.l4_nginx_digest pin")

// pinRefusedError: a binary that fails the Digest check was refused (err is VerifyDigest's).
type pinRefusedError struct{ err error }

func (e pinRefusedError) Error() string        { return e.err.Error() }
func (e pinRefusedError) Unwrap() error        { return e.err }
func (e pinRefusedError) Is(target error) bool { return target == ErrPinRefused }

// launch runs nginx in the foreground (daemon off) so this supervisor owns its
// lifecycle and can SIGHUP it for a graceful reload. The resource set / slice / caps
// are pinned by the OS layer. With a Digest, the binary the command resolved to is
// checked first at every launch, not only at Run's start: a package upgrade can replace
// nginx while Mooring runs, and a relaunch (Restart, a crash) would start it unchecked.
func (s *Supervisor) launch(ctx context.Context) error {
	var cmd *exec.Cmd
	if s.command != nil {
		cmd = s.command(ctx)
	} else {
		cmd = exec.CommandContext(ctx, "nginx", "-c", s.ConfigPath, "-p", s.Prefix, "-g", "daemon off;") // literal: SEC-1 requires it
		cmd.Env = []string{"HOME=" + s.Prefix}
	}
	if s.Digest != "" && cmd.Err == nil { // cmd.Err (no nginx on PATH) fails Start below
		if err := VerifyDigest(cmd.Path, s.Digest); err != nil {
			return pinRefusedError{err}
		}
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr // surface nginx errors in journald (not /dev/null)
	cmd.WaitDelay = 5 * time.Second
	// Start and record the master under ONE lock: a Restart racing this launch then stops this master
	// or lands before it, never in between where it would find no master and leave the old one running.
	s.mu.Lock()
	err := cmd.Start()
	if err == nil {
		s.proc = cmd.Process
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	err = cmd.Wait()
	s.mu.Lock()
	s.proc = nil
	s.mu.Unlock()
	return err
}
