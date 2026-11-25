package imagescan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// minimalEnv is the tight environment the docker CLI runs with (mirrors
// dockerexec/sandbox): only what docker needs to find the daemon + config.
func minimalEnv() []string {
	var env []string
	for _, k := range []string{"PATH", "HOME", "TMPDIR", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "XDG_RUNTIME_DIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// tailWriter keeps the last max bytes written to it (the end of the scanner's stderr, where the error
// is), so stderr of any size can't exhaust memory.
type tailWriter struct {
	buf []byte
	max int
}

func (w *tailWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	if over := len(w.buf) - w.max; over > 0 {
		w.buf = append(w.buf[:0], w.buf[over:]...)
	}
	return len(p), nil // report full consumption so the child never blocks
}

func (w *tailWriter) String() string { return string(w.buf) }

// scanNamePrefix starts the name of every scan container; scanNameRE is the only shape such a name has.
const scanNamePrefix = "mooring-scan-"

var scanNameRE = regexp.MustCompile(`^mooring-scan-[0-9a-f]{16}$`)

// newScanName returns the name for one scan container: the fixed prefix plus 16 hex digits from
// crypto/rand. It is generated for every run and built from nothing else (no image reference, label
// or path), so the removal after a stopped scan can only name a container this process started.
func newScanName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("imagescan: no random container name: %w", err)
	}
	return scanNamePrefix + hex.EncodeToString(b[:]), nil
}

// removeTimeout bounds the removal of a scan container.
const removeTimeout = 30 * time.Second

// removeArgs is the whole docker argv of a removal.
func removeArgs(name string) []string { return []string{"rm", "-f", name} }

// removeContainer force-removes the scan container called name (`docker rm -f <name>`) with the same
// docker binary and minimal environment as the scan. It runs after a scan that was stopped or whose
// `docker run` failed, so that no scanner keeps running until Trivy's own --timeout. A container that
// is already gone is success. A failure is logged with the container name and returned to nobody:
// the scan's own error is what the operator sees.
//
// Intentional: like the scan itself this does not take the dockerexec one-docker-child semaphore. A
// stop must not wait behind a deploy or build that holds the slot for many minutes, and the command
// can only remove a container whose name this process generated (scanNameRE is checked here again).
func (s *Scanner) removeContainer(ctx context.Context, name string) {
	log := s.log
	if log == nil {
		log = slog.Default()
	}
	if !scanNameRE.MatchString(name) {
		log.Warn("imagescan: scan container not removed: not a name Mooring generated", "container", name)
		return
	}
	wait := removeTimeout
	if s.rmWait > 0 {
		wait = s.rmWait
	}
	// Intentional: detached from the caller's context, which has usually ended when this runs (the
	// scan timed out or Mooring is shutting down), and bounded by its own timeout.
	rc, cancel := context.WithTimeout(context.WithoutCancel(ctx), wait)
	defer cancel()
	cmd := exec.CommandContext(rc, s.binary, removeArgs(name)...)
	cmd.Env = minimalEnv()
	cmd.WaitDelay = 2 * time.Second // a child of a killed docker CLI that holds stderr can't hang Wait
	stderr := &tailWriter{max: 4 << 10}
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil {
		return
	}
	msg := strings.TrimSpace(tail(stderr.String(), 400))
	if rc.Err() == nil && (strings.Contains(msg, "No such container") || strings.Contains(msg, "is already in progress")) {
		return // --rm (or an earlier removal) got there first
	}
	log.Warn("imagescan: scan container not removed; it can run until the scanner's own timeout",
		"container", name, "err", err, "docker_stderr", msg)
}
