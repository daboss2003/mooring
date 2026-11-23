package imagescan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

// Mount is one read-only bind mount of a host path into the host-scan container.
type Mount struct {
	Host      string // absolute host path (file or dir), symlinks resolved
	Container string // always "/host" + Host
}

// RoleOwnedCaddy marks the Mooring-owned Caddy build (<data_dir>/bin/caddy) in a HostPlan and in
// its Report.
const RoleOwnedCaddy = "caddy-owned"

// HostBinary is one Go binary the host scan checks.
type HostBinary struct {
	Label string // Server-tab label: "caddy (system)", "caddy (Mooring-owned build)", "dockerd", "mooring", …
	Path  string // absolute host path, symlinks resolved, regular file
	Role  string // RoleOwnedCaddy for the Mooring-owned Caddy build, else ""
}

// HostPlan is what one host scan mounts.
type HostPlan struct {
	Mounts   []Mount      // OS release files + package database
	Binaries []HostBinary // Go binaries Mooring runs
}

// OSReportTarget is the Target of the host's OS-package report (always HostScan.Reports[0]).
const OSReportTarget = "OS packages"

// HostScan is the host's latest scan: totals over every report, plus the per-target detail.
type HostScan struct {
	ScannedAt                                               int64
	OS                                                      string // "ubuntu 24.04"; "" if none detected
	EOSL                                                    bool   // the detected OS release is past its end of support (no more fixes)
	Critical, High, Medium, Low                             int
	FixableCritical, FixableHigh, FixableMedium, FixableLow int
	Reports                                                 []Report // "OS packages" first, then one per binary (Target = HostBinary.Label)
	Error                                                   string

	skipped []string // plan entries ScanHost refused, with the reason (logged by the Runner)
}

// Total counts all findings; Fixable counts those with a fixed version.
func (h HostScan) Total() int { return h.Critical + h.High + h.Medium + h.Low }
func (h HostScan) Fixable() int {
	return h.FixableCritical + h.FixableHigh + h.FixableMedium + h.FixableLow
}

// Actionable reports whether a fixable High or Critical finding exists (the host alert bar).
func (h HostScan) Actionable() bool { return h.FixableCritical > 0 || h.FixableHigh > 0 }

// sum recomputes the totals from the reports.
func (h *HostScan) sum() {
	h.Critical, h.High, h.Medium, h.Low = 0, 0, 0, 0
	h.FixableCritical, h.FixableHigh, h.FixableMedium, h.FixableLow = 0, 0, 0, 0
	for _, r := range h.Reports {
		h.Critical += r.Critical
		h.High += r.High
		h.Medium += r.Medium
		h.Low += r.Low
		h.FixableCritical += r.FixableCritical
		h.FixableHigh += r.FixableHigh
		h.FixableMedium += r.FixableMedium
		h.FixableLow += r.FixableLow
	}
}

// hostRoot is where the host's files appear inside the scan container.
const hostRoot = "/host"

// releaseFiles are the files Trivy detects the OS from. os-release alone is not enough (verified
// against Trivy 0.58.1 and 0.76.2, see TestTrivyE2E; 0.76.2 identifies AlmaLinux from it, the others
// not): Ubuntu is detected from lsb-release, Debian from debian_version, the RHEL family from its
// <distro>-release file and Amazon Linux from system-release. Missing ones are skipped. A symlinked one
// is mounted at its resolved path: on Amazon Linux 2023 /etc/system-release links to
// /usr/lib/system-release, which Trivy also reads (verified, see TestDefaultHostPlanAmazonLinux2023).
var releaseFiles = []string{
	"/etc/os-release", "/etc/lsb-release", "/etc/debian_version",
	"/etc/redhat-release", "/etc/centos-release", "/etc/fedora-release", "/etc/rocky-release",
	"/etc/almalinux-release", "/etc/oracle-release", "/etc/system-release",
}

// dpkgStatus is the dpkg database (a single file); rpmDBDirs are the rpm database locations, in
// lookup order. The rpm database is the only directory a host scan mounts.
const dpkgStatus = "/var/lib/dpkg/status"

var rpmDBDirs = []string{"/var/lib/rpm", "/usr/lib/sysimage/rpm"}

// rpmDBFiles are the files one of which an rpm database directory holds.
var rpmDBFiles = []string{"rpmdb.sqlite", "Packages", "Packages.db"}

// cliPluginDirs are where the docker CLI plugins (compose, buildx) are installed, in lookup order.
var cliPluginDirs = []string{
	"/usr/libexec/docker/cli-plugins",
	"/usr/lib/docker/cli-plugins",
	"/usr/local/lib/docker/cli-plugins",
}

// dockerProxyDirs are where dockerd also looks for docker-proxy when it is not on PATH, in lookup order.
var dockerProxyDirs = []string{"/usr/libexec/docker", "/usr/lib/docker"}

// labelMooring is the running mooring binary's label in a HostPlan.
const labelMooring = "mooring"

// dockerBinaryLabels are the labels DefaultHostPlan gives Docker's own binaries.
var dockerBinaryLabels = map[string]bool{
	"docker": true, "dockerd": true, "containerd": true, "containerd-shim-runc-v2": true, "runc": true,
	"docker-proxy": true, "docker compose": true, "docker buildx": true,
}

// planFS is the filesystem access DefaultHostPlan uses (injected in tests).
type planFS struct {
	lookPath     func(string) (string, error)
	evalSymlinks func(string) (string, error)
	stat         func(string) (fs.FileInfo, error)
	executable   func() (string, error)
}

var osPlanFS = planFS{lookPath: exec.LookPath, evalSymlinks: filepath.EvalSymlinks, stat: os.Stat, executable: os.Executable}

// DefaultHostPlan discovers what to scan: /etc/os-release (resolved), the dpkg status file or the rpm
// database, and the Go binaries Mooring runs — caddy (system, via PATH), ownedCaddy when non-empty and
// present, docker, dockerd, containerd, containerd-shim-runc-v2, runc, docker-proxy (PATH, else
// /usr/libexec/docker or /usr/lib/docker), the docker compose and buildx CLI plugins and the running
// mooring binary (os.Executable). Missing ones, snap paths, non-regular files and paths --mount's CSV
// syntax can't carry are skipped. The distro release files Trivy needs to detect the OS (lsb-release,
// debian_version, <distro>-release) are mounted with os-release when present.
func DefaultHostPlan(ownedCaddy string) HostPlan { return defaultHostPlan(osPlanFS, ownedCaddy) }

func defaultHostPlan(fsys planFS, ownedCaddy string) HostPlan {
	var plan HostPlan
	seenMount := map[string]bool{}
	addMount := func(p string, dir bool) bool {
		r, ok := resolveHostPath(fsys, p, dir)
		if !ok || seenMount[r] {
			return ok
		}
		seenMount[r] = true
		plan.Mounts = append(plan.Mounts, Mount{Host: r, Container: hostRoot + r})
		return true
	}
	for _, f := range releaseFiles {
		addMount(f, false)
	}
	if !addMount(dpkgStatus, false) {
		for _, d := range rpmDBDirs {
			if r, ok := resolveHostPath(fsys, d, true); ok && hasRPMDB(fsys, r) && addMount(d, true) {
				break
			}
		}
	}

	seenBin := map[string]bool{}
	addBin := func(label, p, role string) {
		r, ok := resolveHostPath(fsys, p, false)
		if !ok || seenBin[r] {
			return
		}
		seenBin[r] = true
		plan.Binaries = append(plan.Binaries, HostBinary{Label: label, Path: r, Role: role})
	}
	lookup := func(label, name string) bool {
		if p, err := fsys.lookPath(name); err == nil {
			addBin(label, p, "")
			return true
		}
		return false
	}
	// firstIn adds the first mountable dir/name.
	firstIn := func(label, name string, dirs []string) {
		for _, d := range dirs {
			p := d + "/" + name
			if _, ok := resolveHostPath(fsys, p, false); ok {
				addBin(label, p, "")
				return
			}
		}
	}
	// The owned build goes first so that, should PATH's caddy resolve to the same file, it keeps
	// its role.
	if ownedCaddy != "" {
		addBin("caddy (Mooring-owned build)", ownedCaddy, RoleOwnedCaddy)
	}
	lookup("caddy (system)", "caddy")
	for _, name := range []string{"docker", "dockerd", "containerd", "containerd-shim-runc-v2", "runc"} {
		lookup(name, name)
	}
	if !lookup("docker-proxy", "docker-proxy") {
		firstIn("docker-proxy", "docker-proxy", dockerProxyDirs)
	}
	firstIn("docker compose", "docker-compose", cliPluginDirs)
	firstIn("docker buildx", "docker-buildx", cliPluginDirs)
	if p, err := fsys.executable(); err == nil {
		addBin(labelMooring, p, "")
	}
	return plan
}

// resolveHostPath resolves p's symlinks and reports the result when it is a mountable regular file
// (or, with dir, a directory): absolute, clean, CSV-safe and not under /snap/.
func resolveHostPath(fsys planFS, p string, dir bool) (string, bool) {
	if !filepath.IsAbs(p) || isSnap(p) {
		return "", false
	}
	r, err := fsys.evalSymlinks(p)
	if err != nil || !cleanAbs(r) || !csvSafe(r) || isSnap(r) {
		return "", false
	}
	fi, err := fsys.stat(r)
	if err != nil {
		return "", false
	}
	if dir {
		return r, fi.IsDir()
	}
	return r, fi.Mode().IsRegular()
}

func hasRPMDB(fsys planFS, dir string) bool {
	for _, f := range rpmDBFiles {
		if fi, err := fsys.stat(filepath.Join(dir, f)); err == nil && fi.Mode().IsRegular() {
			return true
		}
	}
	return false
}

func isSnap(p string) bool { return p == "/snap" || strings.HasPrefix(p, "/snap/") }

// cleanAbs reports whether p is an absolute, already-clean path other than "/".
func cleanAbs(p string) bool {
	return p != "" && p != "/" && filepath.IsAbs(p) && filepath.Clean(p) == p
}

// csvSafe reports whether p can sit inside a `--mount` value. docker parses that value as one CSV
// record, so a comma would start a new key (e.g. ",readonly=false") and a quote is a CSV error;
// control characters (newline, CR, NUL, tab) are refused outright.
func csvSafe(p string) bool {
	for _, r := range p {
		if r == ',' || r == '"' || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// isPackageDB reports whether a host path is one of the package databases a host scan reads.
func isPackageDB(p string) bool {
	if p == dpkgStatus {
		return true
	}
	for _, d := range rpmDBDirs {
		if p == d {
			return true
		}
	}
	return false
}

// checkMount returns why m can't be mounted into the scan container, or "" when it can. It never
// rewrites a mount: a refused one is skipped. binary requires a regular file.
func (s *Scanner) checkMount(m Mount, binary bool) string {
	switch {
	case !cleanAbs(m.Host):
		return "the host path is not absolute and clean"
	case !csvSafe(m.Host):
		return "the host path has a character a --mount option can't carry"
	case m.Container != hostRoot+m.Host:
		return "the container path is not /host followed by the host path"
	}
	fi, err := s.lstatPath(m.Host)
	if err != nil {
		return "the file is missing"
	}
	mode := fi.Mode()
	switch {
	case mode&fs.ModeSymlink != 0:
		return "the host path is a symlink"
	case mode.IsRegular():
	case mode.IsDir() && !binary && isPackageDB(m.Host):
		// Intentional: the rpm database is the only directory ever mounted; anything else must be a
		// single regular file, so a bad plan can't expose a whole tree (the data dir, /etc) to Trivy.
	default:
		return "only regular files (and the rpm database directory) are mounted"
	}
	if !scannerCanRead(fi) {
		return fmt.Sprintf("the scanner can't read it (mode %04o; it must be world-readable)", mode.Perm())
	}
	return ""
}

// scannerCanRead reports whether Trivy can read fi. Trivy runs as root with every capability
// dropped, so the kernel applies plain permission bits for uid 0 / gid 0: the owner bits if root
// owns the file, else the group bits if its group is root, else the "other" bits. A directory also
// needs the search bit. Trivy silently skips a file it can't read, so this must be checked here.
func scannerCanRead(fi fs.FileInfo) bool {
	perm := fi.Mode().Perm()
	need := fs.FileMode(0o4)
	if fi.IsDir() {
		need = 0o5
	}
	if uid, gid, ok := fileOwner(fi); ok {
		switch {
		case uid == 0:
			return (perm>>6)&need == need
		case gid == 0:
			return (perm>>3)&need == need
		}
	}
	return perm&need == need
}

func mountArg(m Mount) string {
	return "type=bind,src=" + m.Host + ",dst=" + m.Container + ",readonly"
}

// ScanHost scans the host in ONE `docker run`: every plan mount and binary is bind-mounted
// read-only under /host and `trivy rootfs /host` checks the OS package database and the Go
// binaries. Same hardening as the app scans (no Docker socket, every capability dropped,
// no-new-privileges). A mount that fails validation is skipped, never passed through; a binary that
// can't be mounted or read gets a Report with Error instead of a clean one. Nothing on the host is
// written.
func (s *Scanner) ScanHost(ctx context.Context, plan HostPlan) (HostScan, error) {
	var (
		mounts   []string
		seen     = map[string]bool{}
		skipped  []string
		hasPkgDB bool
		binErr   = map[int]string{}
	)
	add := func(m Mount) {
		if !seen[m.Container] {
			seen[m.Container] = true
			mounts = append(mounts, "--mount", mountArg(m))
		}
	}
	for _, m := range plan.Mounts {
		if why := s.checkMount(m, false); why != "" {
			skipped = append(skipped, fmt.Sprintf("%q: %s", m.Host, why))
			continue
		}
		add(m)
		if isPackageDB(m.Host) {
			hasPkgDB = true
		}
	}
	for i, b := range plan.Binaries {
		m := Mount{Host: b.Path, Container: hostRoot + b.Path}
		if why := s.checkMount(m, true); why != "" {
			skipped = append(skipped, fmt.Sprintf("%s %q: %s", b.Label, b.Path, why))
			binErr[i] = "not scanned: " + why
			continue
		}
		add(m)
	}
	if len(seen) == 0 {
		return HostScan{skipped: skipped}, errors.New("imagescan: nothing on the host can be scanned")
	}
	args := append(s.trivyArgs(s.runArgs(mounts...), "rootfs"), hostRoot)
	out, err := s.exec(ctx, args)
	if err != nil {
		return HostScan{skipped: skipped}, err
	}
	h, err := parseHostReport(out, plan.Binaries, binErr, hasPkgDB)
	h.skipped = skipped
	return h, err
}

// parseHostReport turns one `trivy rootfs` JSON into the OS-package report plus one report per
// binary (in plan order). A binary Trivy reported nothing for is clean; a lang-pkgs result that maps
// to no planned binary is kept under its host path so no finding is dropped.
func parseHostReport(data []byte, bins []HostBinary, binErr map[int]string, hasPkgDB bool) (HostScan, error) {
	var out trivyOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return HostScan{}, err
	}
	var h HostScan
	// Trivy reports Family "none" when the release files don't identify the OS.
	if o := out.Metadata.OS; o != nil && strings.TrimSpace(o.Family) != "" && !strings.EqualFold(strings.TrimSpace(o.Family), "none") {
		h.OS = strings.TrimSpace(o.Family + " " + o.Name)
		h.EOSL = o.EOSL
	}
	var osVulns []trivyVuln
	byPath := map[string][]trivyVuln{}
	var order []string
	for _, r := range out.Results {
		if r.Class == "os-pkgs" {
			osVulns = append(osVulns, r.Vulnerabilities...)
			continue
		}
		p := hostPathOf(r.Target)
		if _, ok := byPath[p]; !ok {
			order = append(order, p)
		}
		byPath[p] = append(byPath[p], r.Vulnerabilities...)
	}
	osRep := buildReport(OSReportTarget, osVulns)
	switch {
	case h.OS == "":
		osRep.Error = "not scanned: the operating system was not detected"
	case !hasPkgDB:
		// Intentional: Trivy still emits an empty os-pkgs result without a package database; that
		// is "not scanned", never clean.
		osRep.Error = "not scanned: no package database (dpkg or rpm) was found"
	}
	h.Reports = append(h.Reports, osRep)
	used := map[string]bool{}
	for i, b := range bins {
		if e, ok := binErr[i]; ok {
			h.Reports = append(h.Reports, Report{Target: b.Label, Role: b.Role, Error: e})
			continue
		}
		rep := buildReport(b.Label, byPath[b.Path])
		rep.Role = b.Role
		used[b.Path] = true
		h.Reports = append(h.Reports, rep)
	}
	for _, p := range order {
		if !used[p] {
			h.Reports = append(h.Reports, buildReport(p, byPath[p]))
		}
	}
	h.sum()
	return h, nil
}

// hostPathOf maps a Trivy rootfs Target back to the host path. Trivy reports a file relative to the
// scanned root ("usr/bin/caddy"); "/usr/bin/caddy" and "/host/usr/bin/caddy" are accepted too.
func hostPathOf(target string) string {
	t := strings.TrimSpace(target)
	if strings.HasPrefix(t, "/") {
		if t == hostRoot || strings.HasPrefix(t, hostRoot+"/") {
			t = t[len(hostRoot):]
		}
	}
	return path.Clean("/" + strings.TrimLeft(t, "/"))
}
