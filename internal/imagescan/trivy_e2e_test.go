package imagescan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestTrivyE2E runs the pinned TrivyImage for real, through Scanner's own argv, against the release
// files and package databases of real distribution images (extracted with docker, symlinks resolved
// inside the image) and a real Go binary, plus one app image scan and one dependency scan. It pins the
// Trivy behaviour the host scan depends on, so run it after every TrivyImage bump:
//
//	MOORING_TRIVY_E2E=1 go test -run TestTrivyE2E -v ./internal/imagescan/
//
// Needs docker and network (Docker Hub, Trivy's DB mirrors). The cache volume is
// MOORING_TRIVY_E2E_CACHE (default mooring-trivy-e2e), never the production one; a first run downloads
// the vulnerability DB, which must finish within the scanner's 5m timeout.
func TestTrivyE2E(t *testing.T) {
	if os.Getenv("MOORING_TRIVY_E2E") != "1" {
		t.Skip("set MOORING_TRIVY_E2E=1 to run the pinned Trivy image for real (needs docker and network)")
	}
	cache := os.Getenv("MOORING_TRIVY_E2E_CACHE")
	if cache == "" {
		cache = "mooring-trivy-e2e"
	}
	// A Go binary with known fixable findings (Caddy 2.6.2 is built with Go 1.19).
	binRoot := t.TempDir()
	dockerCp(t, "caddy:2.6.2", "/usr/bin/caddy", filepath.Join(binRoot, "usr/bin/caddy"))

	for _, c := range []struct {
		image, os      string
		eosl           bool
		osReleaseAlone bool // Trivy identifies the OS from os-release without the distribution's release file
	}{
		{"ubuntu:24.04", "ubuntu 24.04", false, false},
		{"debian:12", "debian 12.", false, false},
		{"almalinux:9", "alma 9.", false, true}, // since Trivy 0.6x (0.58.1: not detected)
		{"amazonlinux:2023", "amazon 2023", false, false},
		{"debian:10", "debian 10.", true, false},
	} {
		t.Run(c.image, func(t *testing.T) {
			root := t.TempDir()
			resolved := extractHostFiles(t, c.image, root)
			plan := defaultHostPlan(rootedPlanFS(root, resolved), "")
			plan.Binaries = []HostBinary{{Label: "caddy (system)", Path: "/usr/bin/caddy"}}
			copyFile(t, filepath.Join(binRoot, "usr/bin/caddy"), filepath.Join(root, "usr/bin/caddy"))

			h, raw := e2eScanHost(t, root, cache, plan)
			if !strings.HasPrefix(h.OS, c.os) || h.EOSL != c.eosl || h.Reports[0].Error != "" {
				t.Fatalf("OS %q EOSL %v, OS report %+v; want %q… EOSL %v scanned", h.OS, h.EOSL, h.Reports[0], c.os, c.eosl)
			}
			if !hasResult(raw, "/host ("+h.OS+")", "os-pkgs", "") || !hasResult(raw, "usr/bin/caddy", "lang-pkgs", "gobinary") {
				t.Errorf("Trivy result targets changed: %s", resultTargets(raw))
			}
			if bytes.Contains(raw, []byte(`"Packages"`)) {
				t.Error("--list-all-pkgs=false must keep the package list out of the JSON")
			}
			if caddy := h.Reports[1]; caddy.Target != "caddy (system)" || caddy.FixableHigh+caddy.FixableCritical == 0 {
				t.Errorf("the Go binary's findings were not mapped to its report: %+v", caddy)
			}

			// os-release alone does not identify most distributions: their release file is needed.
			var osReleaseOnly, noDB HostPlan
			for _, m := range plan.Mounts {
				if isPackageDB(m.Host) || m.Host == resolved["/etc/os-release"] {
					osReleaseOnly.Mounts = append(osReleaseOnly.Mounts, m)
				}
				if !isPackageDB(m.Host) {
					noDB.Mounts = append(noDB.Mounts, m)
				}
			}
			if h, raw := e2eScanHost(t, root, cache, osReleaseOnly); (h.OS != "") != c.osReleaseAlone || (h.Reports[0].Error == "") != c.osReleaseAlone {
				t.Errorf("os-release only: OS %q, OS report %+v (results %s); want detected=%v", h.OS, h.Reports[0], resultTargets(raw), c.osReleaseAlone)
			}
			// No package database: the OS is still detected, and the OS report is "not scanned", never clean.
			if h, _ := e2eScanHost(t, root, cache, noDB); !strings.HasPrefix(h.OS, c.os) || !strings.Contains(h.Reports[0].Error, "no package database") {
				t.Errorf("no package database: OS %q, OS report %+v", h.OS, h.Reports[0])
			}
		})
	}

	t.Run("app scans", func(t *testing.T) {
		sc := e2eScanner(t, "", cache, nil)
		rep, err := sc.ScanImage(context.Background(), "alpine:3.19.0")
		if err != nil || rep.Total() == 0 {
			t.Errorf("image scan of alpine:3.19.0: %+v, %v; want findings", rep, err)
		}
		dir := t.TempDir()
		lock := `{"name":"x","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"x","version":"1.0.0","dependencies":{"lodash":"4.17.15"}},"node_modules/lodash":{"version":"4.17.15","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"}}}`
		if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
			t.Fatal(err)
		}
		rep, err = sc.ScanFS(context.Background(), dir, "x dependencies")
		if err != nil || rep.High+rep.Critical == 0 {
			t.Errorf("dependency scan of lodash 4.17.15: %+v, %v; want High/Critical findings", rep, err)
		}
	})
}

// e2eScanner is a Scanner whose docker argv is Mooring's own, except that each --mount src is moved
// under root and the cache volume is the test's.
func e2eScanner(t *testing.T, root, cache string, raw *[]byte) *Scanner {
	sc := New("docker", TrivyImage, 5*time.Minute)
	sc.lstat = func(p string) (fs.FileInfo, error) { return os.Lstat(root + p) }
	sc.execFn = func(ctx context.Context, args []string) ([]byte, error) {
		args = append([]string(nil), args...)
		for i := range args {
			switch {
			case i > 0 && args[i-1] == "--mount":
				args[i] = strings.Replace(args[i], ",src=/", ",src="+root+"/", 1)
			case args[i] == cacheVolume+":/root/.cache/trivy":
				args[i] = cache + ":/root/.cache/trivy"
			}
		}
		name := ""
		for i := range args {
			if i > 0 && args[i-1] == "--name" {
				name = args[i]
			}
		}
		var out []byte
		err := sc.run(ctx, name, args, func(r io.Reader) (err error) {
			out, err = io.ReadAll(r)
			return err
		})
		if raw != nil {
			*raw = out
		}
		return out, err
	}
	return sc
}

func e2eScanHost(t *testing.T, root, cache string, plan HostPlan) (HostScan, []byte) {
	t.Helper()
	var raw []byte
	h, err := e2eScanner(t, root, cache, &raw).ScanHost(context.Background(), plan)
	if err != nil {
		t.Fatalf("host scan: %v", err)
	}
	if len(h.skipped) != 0 {
		t.Errorf("plan entries refused: %q", h.skipped)
	}
	return h, raw
}

type rawResult struct{ Target, Class, Type string }

func rawResults(raw []byte) []rawResult {
	var out struct{ Results []rawResult }
	_ = json.Unmarshal(raw, &out)
	return out.Results
}

func hasResult(raw []byte, target, class, typ string) bool {
	for _, r := range rawResults(raw) {
		if r.Target == target && r.Class == class && (typ == "" || r.Type == typ) {
			return true
		}
	}
	return false
}

func resultTargets(raw []byte) string {
	b, _ := json.Marshal(rawResults(raw))
	return string(b)
}

// extractHostFiles copies the files DefaultHostPlan looks for (release files, the dpkg status file, the
// rpm database) out of image into root, each at its path resolved inside the image, and returns
// path → resolved path for those that exist.
func extractHostFiles(t *testing.T, image, root string) map[string]string {
	t.Helper()
	paths := append(append(append([]string(nil), releaseFiles...), dpkgStatus), rpmDBDirs...)
	script := `for p in "$@"; do if [ -e "$p" ]; then echo "$p $(readlink -f "$p")"; fi; done`
	out := dockerOut(t, append([]string{"run", "--rm", "--network", "none", "--entrypoint", "/bin/sh", image, "-c", script, "sh"}, paths...)...)
	resolved := map[string]string{}
	id := strings.TrimSpace(dockerOut(t, "create", image, "/bin/true"))
	defer dockerOut(t, "rm", id)
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		p, r, ok := strings.Cut(line, " ")
		if !ok || !cleanAbs(r) {
			continue
		}
		resolved[p] = r
		dst := filepath.Join(root, r)
		if _, err := os.Lstat(dst); err == nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		dockerOut(t, "cp", id+":"+r, dst)
	}
	// docker cp keeps the image's modes; the host scan needs world-readable files.
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			_ = os.Chmod(p, 0o644)
		} else if err == nil {
			_ = os.Chmod(p, 0o755)
		}
		return nil
	})
	return resolved
}

// rootedPlanFS is the planFS of a host whose files live under root, with symlinks resolved as listed.
func rootedPlanFS(root string, resolved map[string]string) planFS {
	return planFS{
		lookPath: func(string) (string, error) { return "", errors.New("not on PATH") },
		evalSymlinks: func(p string) (string, error) {
			if r, ok := resolved[p]; ok {
				return r, nil
			}
			if _, err := os.Lstat(root + p); err != nil {
				return "", err
			}
			return p, nil
		},
		stat:       func(p string) (fs.FileInfo, error) { return os.Stat(root + p) },
		executable: func() (string, error) { return "", errors.New("none") },
	}
}

func dockerCp(t *testing.T, image, src, dst string) {
	t.Helper()
	id := strings.TrimSpace(dockerOut(t, "create", image))
	defer dockerOut(t, "rm", id)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	dockerOut(t, "cp", "-L", id+":"+src, dst)
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err == nil {
		err = os.MkdirAll(filepath.Dir(dst), 0o755)
	}
	if err == nil {
		err = os.WriteFile(dst, b, 0o755)
	}
	if err == nil {
		err = os.Chmod(dst, 0o755)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func dockerOut(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("docker", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker %s: %v: %s", strings.Join(args, " "), err, stderr.String())
	}
	return string(out)
}
