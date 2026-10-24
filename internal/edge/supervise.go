package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// Available reports whether this host can OWN the managed edge. The edge is a
// supervised child Caddy with a systemd slice + CAP_NET_BIND_SERVICE + an egress
// firewall (plan §6) — Linux-only. On any other OS, or with no caddy binary, the
// edge is FAIL-CLOSED unavailable (managed mode degrades to an "edge not owned"
// banner; Mooring's control plane still serves).
func Available(caddyBin string) (bool, string) {
	if runtime.GOOS != "linux" {
		return false, "managed edge requires Linux (got " + runtime.GOOS + ")"
	}
	if caddyBin == "" {
		caddyBin = "caddy"
	}
	if _, err := exec.LookPath(caddyBin); err != nil {
		return false, "caddy binary not found on PATH"
	}
	return true, ""
}

// VerifyDigest checks the caddy binary's SHA-256 against a pinned digest (supply
// chain — refuse on mismatch, plan §6). An empty want skips the check.
func VerifyDigest(caddyPath, want string) error {
	if want == "" {
		return nil
	}
	f, err := os.Open(caddyPath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("edge: caddy binary digest mismatch (refusing to launch)")
	}
	return nil
}

// Supervisor launches + supervises the child Caddy. It is fail-closed: if the
// host can't own the edge, Run logs and returns without starting anything.
type Supervisor struct {
	CaddyBin string
	// BinFn, when set, picks the binary at EACH launch (the Mooring-owned plugin build once it exists,
	// else the system caddy), so a swapped binary takes effect on the next (re)launch. A "" result
	// falls back to CaddyBin.
	BinFn       func() string
	AdminListen string
	InitialCfg  []byte // the typed base render (Layer 0) — the recovery floor
	Log         *slog.Logger
	// AccessLine, when set, captures Caddy's STDOUT line-by-line and hands each raw line here (the
	// per-request JSON access log, when the render opted into it — see BaseConfig.AccessLog). It
	// feeds the in-process latency aggregator for edge-measured autoscaling. The callback MUST NOT
	// retain the slice and MUST NOT block (it runs on the single stdout-drain goroutine). nil keeps
	// stdout on os.Stdout as before. Caddy's own logs + errors always stay on STDERR (→ journald),
	// so nothing here affects error visibility.
	AccessLine func(line []byte)
	// Stderr receives Caddy's own logs and errors (nil = os.Stderr → journald). Serve passes a
	// NewRedactWriter so the dns01 tokens Caddy echoes when it refuses a provider config never reach the
	// journal. A writer with a Flush() error method is flushed when the child exits.
	Stderr io.Writer
	// OnLaunch, when set, runs (in its own goroutine) each time a Caddy child has been started. A
	// (re)launched child boots on InitialCfg — the route-less base — so the owner must push the full
	// config again (see Reconciler.ReloadAfterRestart); otherwise every app host answers 404 until the
	// render next changes.
	OnLaunch func()

	mu         sync.Mutex
	cur        *os.Process // the running child, nil between launches
	restarting bool        // the current child is being stopped by Restart
}

// bin is the binary for the next launch.
func (s *Supervisor) bin() string {
	if s.BinFn != nil {
		if b := s.BinFn(); b != "" {
			return b
		}
	}
	if s.CaddyBin != "" {
		return s.CaddyBin
	}
	return "caddy"
}

// Restart stops the running child so Run relaunches it at once — no backoff, on whatever binary is
// current (used after the Mooring-owned Caddy is swapped for a build with a new DNS plugin). SIGTERM
// first so Caddy shuts down gracefully, SIGKILL if it's still running 5s later. A no-op when no
// child is running.
func (s *Supervisor) Restart() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return
	}
	s.restarting = true
	p := s.cur
	_ = p.Signal(syscall.SIGTERM)
	// Safe after the process is reaped: os.Process.Kill then returns os.ErrProcessDone.
	time.AfterFunc(5*time.Second, func() { _ = p.Kill() })
}

// Run supervises the child with capped backoff until ctx is cancelled. NOTE: the
// actual process launch + its systemd slice/user/caps/egress-firewall are the OS
// deployment layer (plan §6); this owns the lifecycle. Not exercised off-Linux.
func (s *Supervisor) Run(ctx context.Context) {
	if ok, why := Available(s.bin()); !ok {
		s.Log.Warn("managed edge not started", "reason", why)
		return
	}
	s.supervise(ctx)
}

// supervise is Run's launch loop, without the host check.
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
			s.Log.Info("edge child restarted", "caddy", s.bin())
			backoff = time.Second
			continue // relaunch immediately on the current binary
		}
		if err != nil && ctx.Err() == nil {
			s.Log.Error("edge child exited", "err", err)
		}
		if ctx.Err() != nil {
			return
		}
		// Reset backoff if the child ran a healthy while; else grow it (capped).
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

// launch runs `caddy run` with the resource set the OS layer pins. The admin API
// is the only control surface; the initial config is the safe base (SBD-8 floor).
func (s *Supervisor) launch(ctx context.Context) error {
	// STDOUT: normally straight to journald. When an access-log sink is set (edge-measured
	// autoscaling), pipe stdout into a drain goroutine that hands each line to AccessLine instead.
	// The access log flows to STDOUT (BaseConfig.AccessLog); errors stay on STDERR, so capturing
	// stdout never hides an error.
	var stdout io.Writer = os.Stdout
	var pw *os.File
	drained := make(chan struct{})
	if s.AccessLine != nil {
		if pr, w, err := os.Pipe(); err == nil {
			pw = w
			stdout = pw
			go func() {
				defer close(drained)
				s.drainAccess(pr)
				pr.Close()
			}()
		} else {
			// Fail SAFE without breaking the secret-hygiene invariant: a reconcile can turn the
			// access log ON later (via /load) with no relaunch, and access lines carry request URIs
			// (query strings). If we can't capture them, we must NOT let them reach journald — so
			// DISCARD stdout rather than routing it to os.Stdout. The signal is disabled this run;
			// the next launch retries the pipe.
			s.Log.Warn("edge: access-log capture unavailable; latency signal disabled this run", "err", err.Error())
			stdout = io.Discard
			close(drained)
		}
	} else {
		close(drained)
	}

	// Resolve the binary, start it and record it under ONE lock: a Restart() racing this launch then
	// lands either before (this launch already runs the swapped binary) or after (it stops this child)
	// — never in between, where it would miss the child and leave the old binary running.
	s.mu.Lock()
	cmd := exec.CommandContext(ctx, s.bin(), "run", "--config", "-", "--adapter", "")
	cmd.Stdin = bytes.NewReader(s.InitialCfg)
	// Pin all of Caddy's storage under the writable /var/lib/caddy: HOME +
	// XDG_DATA_HOME (certs) + XDG_CONFIG_HOME (autosave config) — otherwise autosave
	// falls back to $HOME/.config and is fragile under the sandbox.
	cmd.Env = []string{"HOME=/var/lib/caddy", "XDG_DATA_HOME=/var/lib/caddy", "XDG_CONFIG_HOME=/var/lib/caddy"}
	cmd.Stderr = os.Stderr // Caddy's own logs + errors always surface in journald (not /dev/null)
	if s.Stderr != nil {
		cmd.Stderr = s.Stderr
	}
	cmd.Stdout = stdout
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Start()
	if err == nil {
		s.cur = cmd.Process
	}
	s.mu.Unlock()
	if err == nil {
		if s.OnLaunch != nil {
			go s.OnLaunch()
		}
		err = cmd.Wait()
		s.mu.Lock()
		s.cur = nil
		s.mu.Unlock()
		if f, ok := s.Stderr.(interface{ Flush() error }); ok {
			_ = f.Flush() // Wait has copied all of the child's stderr; write out a final partial line
		}
	}
	if pw != nil {
		pw.Close() // close our write end so the drain goroutine sees EOF and exits
		<-drained  // and finish draining before we loop/backoff (bounded: pipe EOF)
	}
	return err
}

// drainAccessBuf bounds the per-line buffer. A normal access entry is well under 2 KiB; 1 MiB is
// slack for a pathological URI/header set. A line LONGER than this is dropped, but — unlike a
// bufio.Scanner, which returns ErrTooLong and stops forever — draining CONTINUES with the next line.
const drainAccessBuf = 1 << 20

// drainAccess reads Caddy's captured stdout line-by-line and hands each line to AccessLine. It MUST
// keep draining until the pipe hits EOF (the child exited / the pipe closed): if it ever returned
// early while Caddy is still writing, the closed read end would SIGPIPE-kill Caddy (crash-looping
// the whole edge). So a single over-long line is discarded up to its next newline and the loop goes
// on — one attacker request with ~1 MiB of headers can drop its own log entry but can never wedge
// the edge. The sink parses synchronously and cheaply; it must not retain the slice.
func (s *Supervisor) drainAccess(r io.Reader) {
	br := bufio.NewReaderSize(r, drainAccessBuf)
	skipping := false // currently discarding the tail of an over-long line
	for {
		frag, err := br.ReadSlice('\n') // slice into br's buffer, valid until the next read
		switch err {
		case nil:
			// A complete line (frag ends in '\n'). If we were skipping, this frag is the final
			// chunk of the over-long line — drop it and resume normal delivery.
			if skipping {
				skipping = false
			} else {
				s.AccessLine(dropTrailingNL(frag))
			}
		case bufio.ErrBufferFull:
			// The line is longer than the buffer and has no newline yet — drop it and keep
			// consuming (bounded memory: we never accumulate past the buffer).
			skipping = true
		default:
			// io.EOF or a read error: deliver a trailing partial line (no newline) if any, then stop.
			if len(frag) > 0 && !skipping {
				s.AccessLine(frag)
			}
			return
		}
	}
}

// dropTrailingNL trims the line terminator (\n or \r\n) ReadSlice leaves on a complete line.
func dropTrailingNL(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
		if n = len(b); n > 0 && b[n-1] == '\r' {
			b = b[:n-1]
		}
	}
	return b
}
