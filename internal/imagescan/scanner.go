package imagescan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// TrivyImage is the digest-pinned Trivy scanner image (supply-chain posture, like
// the other managed-infra images). Run with `docker run` via the host CLI — the
// SAME write-plane docker access deploys use — but the Docker socket is NEVER
// mounted INTO Trivy: it scans registry refs, a read-only checkout mount, or read-only
// bind mounts of single host files (ScanHost), so the scanner container has no path to
// Docker. To bump: Trivy's own release pipeline was hijacked in March 2026 (GHSA-69fq-xp46-6x23:
// malicious 0.69.4, 0.69.5 and 0.69.6 images), so pin only an index digest that is identical on
// Docker Hub, ghcr.io and public.ecr.aws and whose cosign signature names the release workflow
// (reusable-release.yaml@refs/tags/vX.Y.Z) — then re-run the host-scan checks in host_test.go.
const TrivyImage = "aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb"

// severities is the set Trivy reports on (we bucket + alert by CRITICAL/HIGH).
const severities = "CRITICAL,HIGH,MEDIUM,LOW"

// cacheVolume persists Trivy's vulnerability DB across runs so it isn't re-downloaded
// (hundreds of MB) every scan.
const cacheVolume = "mooring-trivy-cache"

// Scanner runs Trivy one-shot containers and parses their JSON.
type Scanner struct {
	binary  string        // docker CLI, default "docker"
	image   string        // pinned trivy image
	timeout time.Duration // per-scan wall clock

	// Test seams: lstat inspects host paths before they are mounted (nil = os.Lstat); execFn runs
	// the docker argv and returns its stdout (nil = run); lim replaces defaultLimits when set;
	// grace replaces stopGrace when set; rmWait replaces removeTimeout when set; log receives the
	// scanner's own warnings (nil = slog.Default(); NewRunner sets its logger).
	lstat  func(string) (fs.FileInfo, error)
	execFn func(ctx context.Context, args []string) ([]byte, error)
	lim    limits
	grace  time.Duration
	rmWait time.Duration
	log    *slog.Logger
}

// stopGrace is how long a stopped scanner gets to exit after SIGTERM before it is killed.
const stopGrace = 10 * time.Second

// New builds a Scanner. binary/image default to "docker"/TrivyImage; timeout floors
// at 2m.
func New(binary, image string, timeout time.Duration) *Scanner {
	if binary == "" {
		binary = "docker"
	}
	if image == "" {
		image = TrivyImage
	}
	if timeout < 2*time.Minute {
		timeout = 5 * time.Minute
	}
	return &Scanner{binary: binary, image: image, timeout: timeout}
}

// ScanImage scans an image reference pulled from its REGISTRY (no local Docker
// access — Trivy resolves the ref itself). Good for upstream `image:` services and
// pinned base images.
func (s *Scanner) ScanImage(ctx context.Context, ref string) (Report, error) {
	name, err := newScanName()
	if err != nil {
		return Report{}, err
	}
	args := append(s.trivyArgs(s.runArgs(name), "image"), ref)
	var rep Report
	err = s.scan(ctx, name, args, func(r io.Reader) (err error) {
		rep, err = readReport(ref, r, s.limits())
		return err
	})
	return rep, err
}

// ScanFS scans a build-service checkout for language-dependency CVEs (npm/go/pip …).
// hostDir is bind-mounted READ-ONLY into the scanner; nothing is written back. Only
// the vuln scanner runs (never the secret scanner) so mounted config/secrets aren't
// inspected.
func (s *Scanner) ScanFS(ctx context.Context, hostDir, label string) (Report, error) {
	name, err := newScanName()
	if err != nil {
		return Report{}, err
	}
	args := append(s.trivyArgs(s.runArgs(name, "-v", hostDir+":/scan:ro"), "fs"), "/scan")
	var rep Report
	err = s.scan(ctx, name, args, func(r io.Reader) (err error) {
		rep, err = readReport(label, r, s.limits())
		return err
	})
	return rep, err
}

// runArgs are the hardened `docker run` flags common to every scan (network ON — Trivy must reach
// the registry + DB mirror — but cap-dropped, no-new-privileges, and with NO docker socket
// mounted) and the container name Mooring generated for this run (newScanName), then the scan's own
// mount flags, then the image (Docker requires mount flags ahead of the image name).
func (s *Scanner) runArgs(name string, mounts ...string) []string {
	args := []string{
		"run", "--rm",
		"--name", name,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--network", "bridge",
		"-v", cacheVolume + ":/root/.cache/trivy",
	}
	args = append(args, mounts...)
	return append(args, s.image)
}

// trivyArgs appends the Trivy subcommand and the flags every scan passes: JSON on stdout, only the vuln
// scanner, Trivy's own timeout, findings only (newer Trivy lists every installed package by default,
// with each package's file list on an rpm host), and no usage telemetry or update check (without both
// of those flags Trivy, since 0.69, sends an installation ID, its version, the OS and the scan options
// to check.trivy.dev on every run).
func (s *Scanner) trivyArgs(args []string, cmd string) []string {
	return append(args, cmd, "--quiet", "--format", "json", "--scanners", "vuln", "--severity", severities,
		"--timeout", s.trivyTimeout(), "--list-all-pkgs=false", "--disable-telemetry", "--skip-version-check")
}

func (s *Scanner) trivyTimeout() string { return s.timeout.String() }

func (s *Scanner) limits() limits {
	if s.lim != (limits{}) {
		return s.lim
	}
	return defaultLimits
}

// scan runs the docker argv and hands the scanner's stdout (the JSON report) to read. name is the
// container name in args (--name), which run removes when the scan does not end by itself.
func (s *Scanner) scan(ctx context.Context, name string, args []string, read func(io.Reader) error) error {
	if s.execFn != nil {
		out, err := s.execFn(ctx, args)
		if err != nil {
			return err
		}
		return read(bytes.NewReader(out))
	}
	return s.run(ctx, name, args, read)
}

func (s *Scanner) lstatPath(p string) (fs.FileInfo, error) {
	if s.lstat != nil {
		return s.lstat(p)
	}
	return os.Lstat(p)
}

// run executes the docker argv and streams its stdout (the JSON report) to read, which must not hold
// it whole: the report is never buffered here (a hostile or huge scan can't exhaust memory). A non-zero
// exit wins over read's error and includes the end of stderr for diagnosis (never the scan output).
// When read fails on a limit the scanner is stopped; on any other error its remaining output is
// discarded so that it can exit and its status be reported, but no more of it than the report limit
// allows in total: past that the scanner is stopped too. When the scan was stopped, or `docker run`
// ended with an error by itself, the container named name (the --name in args) is force-removed before run
// returns; that never changes the error returned.
func (s *Scanner) run(ctx context.Context, name string, args []string, read func(io.Reader) error) error {
	rc, cancel := context.WithTimeout(ctx, s.timeout+30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(rc, s.binary, args...)
	cmd.Env = minimalEnv()
	// Intentional: a stop (a limit, the timeout, shutdown) is SIGTERM, not exec's default SIGKILL.
	// `docker run` passes SIGTERM on to the container, so Trivy stops with it; a killed docker CLI
	// can pass nothing on and leaves the container running until Trivy's own --timeout.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	// After the grace the docker CLI is killed and its pipes are closed, so Wait can't hang on a
	// CLI that ignores SIGTERM or on a child of it that holds stderr.
	cmd.WaitDelay = stopGrace
	if s.grace > 0 {
		cmd.WaitDelay = s.grace
	}
	stderr := &tailWriter{max: 64 << 10}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("trivy scan failed: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("trivy scan failed: %w", err)
	}
	out := &countReader{r: stdout}
	readErr := read(out)
	var oe *outputError
	stopped := errors.As(readErr, &oe) && oe.limit
	if !stopped {
		// One byte more than the allowance left tells an exhausted allowance from a scanner that
		// ended exactly on it.
		left := max(s.limits().report-out.n, 0)
		if _, err := io.CopyN(io.Discard, stdout, left+1); err == nil {
			stopped = true
		}
	}
	if stopped {
		cancel()
	}
	waitErr := cmd.Wait()
	if waitErr != nil {
		// Wait fails for every scan that did not end by itself with status 0: one Mooring stopped
		// (the limit, the timeout, shutdown; also when the CLI then exits 0) and one whose docker CLI
		// failed. Neither says the container is gone: Trivy can ignore SIGTERM, and a killed CLI
		// passes no signal on. A run that exited 0 by itself was removed by --rm.
		s.removeContainer(ctx, name)
	}
	if err := waitErr; err != nil && !stopped {
		return fmt.Errorf("trivy scan failed: %w: %s", err, strings.TrimSpace(tail(stderr.String(), 400)))
	}
	return readErr
}

// countReader counts the bytes read through it.
type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	k, err := c.r.Read(p)
	c.n += int64(k)
	return k, err
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
