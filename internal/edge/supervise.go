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
	CaddyBin    string
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
}

// Run supervises the child with capped backoff until ctx is cancelled. NOTE: the
// actual process launch + its systemd slice/user/caps/egress-firewall are the OS
// deployment layer (plan §6); this owns the lifecycle. Not exercised off-Linux.
func (s *Supervisor) Run(ctx context.Context) {
	if ok, why := Available(s.CaddyBin); !ok {
		s.Log.Warn("managed edge not started", "reason", why)
		return
	}
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		start := time.Now()
		if err := s.launch(ctx); err != nil && ctx.Err() == nil {
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
	cmd := exec.CommandContext(ctx, s.CaddyBin, "run", "--config", "-", "--adapter", "")
	cmd.Stdin = bytes.NewReader(s.InitialCfg)
	// Pin all of Caddy's storage under the writable /var/lib/caddy: HOME +
	// XDG_DATA_HOME (certs) + XDG_CONFIG_HOME (autosave config) — otherwise autosave
	// falls back to $HOME/.config and is fragile under the sandbox.
	cmd.Env = []string{"HOME=/var/lib/caddy", "XDG_DATA_HOME=/var/lib/caddy", "XDG_CONFIG_HOME=/var/lib/caddy"}
	cmd.Stderr = os.Stderr // Caddy's own logs + errors always surface in journald (not /dev/null)
	cmd.WaitDelay = 5 * time.Second

	// STDOUT: normally straight to journald. When an access-log sink is set (edge-measured
	// autoscaling), pipe stdout into a drain goroutine that hands each line to AccessLine instead.
	// The access log flows to STDOUT (BaseConfig.AccessLog); errors stay on STDERR, so capturing
	// stdout never hides an error.
	var pw *os.File
	drained := make(chan struct{})
	if s.AccessLine != nil {
		if pr, w, err := os.Pipe(); err == nil {
			pw = w
			cmd.Stdout = pw
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
			cmd.Stdout = io.Discard
			close(drained)
		}
	} else {
		cmd.Stdout = os.Stdout
		close(drained)
	}

	err := cmd.Run()
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
