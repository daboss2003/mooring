package web

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/docker"
	"github.com/daboss2003/mooring/internal/dockerexec"
)

// The read plane (the socket-proxy container, which bind-mounts the docker socket of whichever daemon
// created it) and the write plane (the `docker` CLI) must reach the SAME Docker daemon. With two Docker
// installations on one host they can split silently: deploys land on one daemon while the dashboard,
// self-heal, the scaler and the edge's container discovery watch the other — and the edge keeps serving
// a stale container while every check says healthy. These checks compare the two daemon IDs.

const daemonMismatchKey = "docker:daemon-mismatch"

// errReadPlaneInfo marks a failure to read the daemon identity through the socket-proxy.
var errReadPlaneInfo = errors.New("read plane (socket-proxy)")

// daemonIdentities reads the daemon ID behind each plane. blocking queues for the one docker slot (the
// deploy pre-check); otherwise a busy slot returns dockerexec.ErrBusy and the caller skips this round.
func (s *Server) daemonIdentities(ctx context.Context, blocking bool) (docker.Info, string, error) {
	var read docker.Info
	if s.docker == nil {
		return read, "", errors.New("read plane: no socket-proxy client")
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	read, err := s.docker.Info(rctx)
	cancel()
	if err != nil {
		return read, "", fmt.Errorf("%w: %w", errReadPlaneInfo, err)
	}
	if s.runner == nil {
		return read, "", errors.New("write plane unavailable")
	}
	argv := []string{"info", "--format", "{{.ID}}"}
	var out string
	if blocking {
		// Waits for the docker slot like the deploy's own build/up would (bounded by the caller's
		// deadline): a deploy started while a scheduled task holds the slot waits, it isn't refused.
		var buf bytes.Buffer
		err = s.runner.RunStream(ctx, argv, &buf, nil)
		out = buf.String()
	} else {
		wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
		out, err = s.runner.CaptureTry(wctx, argv)
		wcancel()
	}
	if err != nil {
		return read, "", fmt.Errorf("write plane (docker CLI): %w", err)
	}
	return read, strings.TrimSpace(out), nil
}

// daemonLabel renders a daemon for messages: "ID (name, data root)".
func daemonLabel(i docker.Info) string {
	var extra []string
	if i.Name != "" {
		extra = append(extra, i.Name)
	}
	if i.DockerRootDir != "" {
		extra = append(extra, i.DockerRootDir)
	}
	if len(extra) == 0 {
		return i.ID
	}
	return i.ID + " (" + strings.Join(extra, ", ") + ")"
}

// recordDaemonCheck stores a comparison's outcome and raises (or resolves) the CRITICAL infra alert on
// a change. While the planes differ, DaemonMismatch is true: deploys refuse and the scaler and self-heal
// pause their writes, since they act on containers the read plane sees but the write plane can't.
func (s *Server) recordDaemonCheck(ctx context.Context, read docker.Info, writeID string) {
	if read.ID == "" || writeID == "" {
		return // nothing comparable: keep the last verdict
	}
	mismatch := read.ID != writeID
	detail := ""
	if mismatch {
		detail = "the socket-proxy (read plane) sees Docker daemon " + daemonLabel(read) + " but the docker CLI (write plane) reaches " + writeID
	}
	bg := context.WithoutCancel(ctx)
	s.daemonMu.Lock()
	seeded := s.daemonSeeded
	s.daemonMu.Unlock()
	if !seeded && s.alertStore != nil {
		// First comparison since boot: re-adopt an alert raised before a restart (the documented fix
		// for a mismatch ends with restarting mooring), so it still gets resolved.
		if open, err := s.alertStore.OpenInfraAlerts(bg, "docker_daemon_mismatch"); err == nil {
			s.daemonMu.Lock()
			if !s.daemonSeeded {
				_, s.daemonAlerted = open[daemonMismatchKey]
				s.daemonSeeded = true
			}
			s.daemonMu.Unlock()
		}
	}
	s.daemonMu.Lock()
	was := s.daemonMismatch
	s.daemonMismatch, s.daemonDetail = mismatch, detail
	fire := mismatch && !s.daemonAlerted
	resolve := !mismatch && s.daemonAlerted
	if fire {
		s.daemonAlerted = true
	}
	if resolve {
		s.daemonAlerted = false
	}
	s.daemonMu.Unlock()

	if mismatch != was && s.log != nil {
		if mismatch {
			s.log.Error("docker read and write planes reach different daemons; deploys refused and automatic restarts/scaling paused", "detail", detail)
		} else {
			s.log.Info("docker read and write planes reach the same daemon again; writes resumed", "daemon", daemonLabel(read))
		}
	}
	if s.alertStore == nil {
		return
	}
	if fire {
		_ = s.alertStore.EnqueueInfra(bg, alert.Outbox{
			Kind: "docker_daemon_mismatch", Level: alert.LevelCritical, Transition: "firing", DedupeKey: daemonMismatchKey,
			Summary: detail + ". Two Docker installations, or a socket-proxy bound to another daemon's socket. Run `mooring doctor`.",
		})
	}
	if resolve {
		_ = s.alertStore.EnqueueInfra(bg, alert.Outbox{
			Kind: "docker_daemon_mismatch", Level: alert.LevelCritical, Transition: "resolved", DedupeKey: daemonMismatchKey,
			Summary: "the docker read and write planes reach the same daemon again (" + read.ID + ")",
		})
	}
}

// DaemonMismatch reports whether the last comparison found the two planes on different daemons.
func (s *Server) DaemonMismatch() bool {
	s.daemonMu.Lock()
	defer s.daemonMu.Unlock()
	return s.daemonMismatch
}

// CheckDaemonIdentity runs one background comparison (at boot and periodically) and reports whether both
// sides were read. It never queues for the docker slot and leaves the verdict unchanged when either side
// can't be read.
func (s *Server) CheckDaemonIdentity(ctx context.Context) bool {
	read, writeID, err := s.daemonIdentities(ctx, false)
	if err != nil {
		if s.log != nil && !errors.Is(err, dockerexec.ErrBusy) && !errors.Is(err, dockerexec.ErrWritePlaneDisabled) {
			s.log.Debug("docker daemon identity check skipped", "err", err)
		}
		return false
	}
	s.recordDaemonCheck(ctx, read, writeID)
	return read.ID != "" && writeID != ""
}

// preDeployPlaneCheck refuses a deploy that could not be observed or verified: the container view must
// be current (the deploy's edge verification reads it) and both planes must reach the same Docker daemon.
// With no read plane configured at all (tests, a dev build) it is skipped; a disarmed write plane is
// left for the build/up to report.
func (s *Server) preDeployPlaneCheck(ctx context.Context, onLine func(string)) error {
	if s.docker == nil {
		return nil
	}
	if s.mon != nil {
		snap := s.snapshot()
		// A healthy but slow poll can leave the published snapshot up to about interval + 2× the poll
		// budget old (the budget is max(2×interval, 30s)); only well past that is the view stale.
		stale := 6 * s.cfg.Monitor.PollInterval.D()
		if stale < 90*time.Second {
			stale = 90 * time.Second
		}
		switch {
		case snap == nil:
			return errors.New("the container view isn't ready yet (the first poll hasn't finished); try again in a few seconds")
		case !snap.DockerOK:
			return fmt.Errorf("the container view is unavailable (socket-proxy: %s); refusing to deploy until it recovers — run `mooring doctor`", snap.DockerErr)
		case time.Since(snap.At) > stale:
			return fmt.Errorf("the container view is stale (last poll %s ago); refusing to deploy until it recovers — run `mooring doctor`", time.Since(snap.At).Round(time.Second))
		}
	}
	read, writeID, err := s.daemonIdentities(ctx, true)
	if err != nil {
		if errors.Is(err, dockerexec.ErrWritePlaneDisabled) {
			return nil
		}
		if errors.Is(err, errReadPlaneInfo) && s.cfg != nil && s.cfg.Docker.ExternalProxy {
			// An operator-run proxy need not allow /info (Mooring's container view doesn't use it).
			onLine("docker daemon not compared: the external socket-proxy does not answer /info")
			return nil
		}
		return fmt.Errorf("could not confirm which Docker daemon this deploy targets: %w", err)
	}
	s.recordDaemonCheck(ctx, read, writeID)
	if read.ID != "" && writeID != "" && read.ID != writeID {
		return fmt.Errorf("refusing to deploy: the socket-proxy (read plane) sees Docker daemon %s but the docker CLI (write plane) reaches %s — two Docker installations, or a socket-proxy bound to another daemon's socket; run `mooring doctor`", daemonLabel(read), writeID)
	}
	if read.ID != "" {
		id := read.ID
		if len(id) > 12 {
			id = id[:12]
		}
		onLine("docker daemon " + id + " (read and write planes agree)")
	}
	return nil
}
