package imagescan

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
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
	// the docker argv (nil = run).
	lstat  func(string) (fs.FileInfo, error)
	execFn func(ctx context.Context, args []string) ([]byte, error)
}

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
	args := append(s.trivyArgs(s.runArgs(), "image"), ref)
	out, err := s.exec(ctx, args)
	if err != nil {
		return Report{}, err
	}
	return parseReport(ref, out)
}

// ScanFS scans a build-service checkout for language-dependency CVEs (npm/go/pip …).
// hostDir is bind-mounted READ-ONLY into the scanner; nothing is written back. Only
// the vuln scanner runs (never the secret scanner) so mounted config/secrets aren't
// inspected.
func (s *Scanner) ScanFS(ctx context.Context, hostDir, label string) (Report, error) {
	args := append(s.trivyArgs(s.runArgs("-v", hostDir+":/scan:ro"), "fs"), "/scan")
	out, err := s.exec(ctx, args)
	if err != nil {
		return Report{}, err
	}
	return parseReport(label, out)
}

// runArgs are the hardened `docker run` flags common to every scan (network ON — Trivy must reach
// the registry + DB mirror — but cap-dropped, no-new-privileges, and with NO docker socket
// mounted), then the scan's own mount flags, then the image (Docker requires mount flags ahead of
// the image name).
func (s *Scanner) runArgs(mounts ...string) []string {
	args := []string{
		"run", "--rm",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--network", "bridge",
		"-v", cacheVolume + ":/root/.cache/trivy",
	}
	args = append(args, mounts...)
	return append(args, s.image)
}

// trivyArgs appends the Trivy subcommand and the flags every scan passes: JSON on stdout, only the vuln
// scanner, Trivy's own timeout, findings only (newer Trivy lists every installed package by default —
// with each package's file list on an rpm host, enough to pass run's 32 MiB stdout cap), and no usage
// telemetry or update check (without both of those flags Trivy, since 0.69, sends an installation ID,
// its version, the OS and the scan options to check.trivy.dev on every run).
func (s *Scanner) trivyArgs(args []string, cmd string) []string {
	return append(args, cmd, "--quiet", "--format", "json", "--scanners", "vuln", "--severity", severities,
		"--timeout", s.trivyTimeout(), "--list-all-pkgs=false", "--disable-telemetry", "--skip-version-check")
}

func (s *Scanner) trivyTimeout() string { return s.timeout.String() }

func (s *Scanner) exec(ctx context.Context, args []string) ([]byte, error) {
	if s.execFn != nil {
		return s.execFn(ctx, args)
	}
	return s.run(ctx, args)
}

func (s *Scanner) lstatPath(p string) (fs.FileInfo, error) {
	if s.lstat != nil {
		return s.lstat(p)
	}
	return os.Lstat(p)
}

// run executes the docker argv, returning captured stdout (the JSON). A non-zero
// exit includes a trimmed stderr tail for diagnosis (never the full scan output).
func (s *Scanner) run(ctx context.Context, args []string) ([]byte, error) {
	rc, cancel := context.WithTimeout(ctx, s.timeout+30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(rc, s.binary, args...)
	cmd.Env = minimalEnv()
	var stdout, stderr bytes.Buffer
	// Bound the JSON we accept (a hostile/huge image can't OOM the box).
	cmd.Stdout = &cappedWriter{buf: &stdout, cap: 32 << 20}
	cmd.Stderr = &cappedWriter{buf: &stderr, cap: 64 << 10}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy scan failed: %w: %s", err, strings.TrimSpace(tail(stderr.String(), 400)))
	}
	return stdout.Bytes(), nil
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
