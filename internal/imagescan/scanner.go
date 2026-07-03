package imagescan

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// TrivyImage is the digest-pinned Trivy scanner image (supply-chain posture, like
// the other managed-infra images). Run with `docker run` via the host CLI — the
// SAME write-plane docker access deploys use — but the Docker socket is NEVER
// mounted INTO Trivy: it scans registry refs + a read-only checkout mount, so the
// scanner container has no path to Docker. To bump: re-resolve the digest.
const TrivyImage = "aquasec/trivy:0.58.1@sha256:ab70a02200597efa04748f210f793936eb647cbcdb0ea69cc30b226d6f5a22c7"

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
	args := append(s.baseRunArgs(), "image", "--quiet", "--format", "json",
		"--scanners", "vuln", "--severity", severities, "--timeout", s.trivyTimeout(), ref)
	out, err := s.run(ctx, args)
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
	args := append(s.mountRunArgs(hostDir), "fs", "--quiet", "--format", "json",
		"--scanners", "vuln", "--severity", severities, "--timeout", s.trivyTimeout(), "/scan")
	out, err := s.run(ctx, args)
	if err != nil {
		return Report{}, err
	}
	return parseReport(label, out)
}

// baseRunArgs are the hardened `docker run` flags common to every scan (network ON —
// Trivy must reach the registry + DB mirror — but cap-dropped, no-new-privileges,
// and with NO docker socket mounted).
func (s *Scanner) baseRunArgs() []string {
	return []string{
		"run", "--rm",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--network", "bridge",
		"-v", cacheVolume + ":/root/.cache/trivy",
		s.image,
	}
}

// mountRunArgs is baseRunArgs with a read-only checkout mount inserted before the
// image (Docker requires -v flags ahead of the image name).
func (s *Scanner) mountRunArgs(hostDir string) []string {
	return []string{
		"run", "--rm",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--network", "bridge",
		"-v", cacheVolume + ":/root/.cache/trivy",
		"-v", hostDir + ":/scan:ro",
		s.image,
	}
}

func (s *Scanner) trivyTimeout() string { return s.timeout.String() }

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
