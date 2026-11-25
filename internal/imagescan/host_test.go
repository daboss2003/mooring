package imagescan

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"
)

// fakeFI is a synthetic stat result (Sys() == nil, so only the "other" permission bits count).
type fakeFI struct {
	name string
	mode fs.FileMode
}

func (f fakeFI) Name() string       { return f.name }
func (f fakeFI) Size() int64        { return 0 }
func (f fakeFI) Mode() fs.FileMode  { return f.mode }
func (f fakeFI) ModTime() time.Time { return time.Time{} }
func (f fakeFI) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFI) Sys() any           { return nil }

func fakeLstat(files map[string]fs.FileMode) func(string) (fs.FileInfo, error) {
	return func(p string) (fs.FileInfo, error) {
		m, ok := files[p]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return fakeFI{name: p, mode: m}, nil
	}
}

func loadFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/trivy_rootfs_ubuntu.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ubuntuPlan matches the real Trivy rootfs fixture (testdata/trivy_rootfs_ubuntu.json): an Ubuntu
// 24.04 package database plus two Go binaries Trivy reported as "usr/bin/caddy" and
// "usr/local/bin/gofmt", and one binary Trivy found nothing in. The fixture is the output of the pinned
// TrivyImage (0.76.2, DB of 2026-11-23) run with Scanner's argv on ubuntu:24.04's release files, a dpkg
// status holding libssl3t64, nginx and openssl at their 24.04 release versions, caddy 2.7.6's
// /usr/bin/caddy, golang:1.25's gofmt and a non-Go ELF at /usr/sbin/runc; only the per-finding fields
// were cut down with jq (every finding is kept).
func ubuntuPlan() (HostPlan, map[string]fs.FileMode) {
	plan := HostPlan{
		Mounts: []Mount{
			{Host: "/usr/lib/os-release", Container: "/host/usr/lib/os-release"},
			{Host: "/etc/lsb-release", Container: "/host/etc/lsb-release"},
			{Host: "/etc/debian_version", Container: "/host/etc/debian_version"},
			{Host: "/var/lib/dpkg/status", Container: "/host/var/lib/dpkg/status"},
		},
		Binaries: []HostBinary{
			{Label: "caddy (Mooring-owned build)", Path: "/usr/bin/caddy", Role: RoleOwnedCaddy},
			{Label: "gofmt", Path: "/usr/local/bin/gofmt"},
			{Label: "runc", Path: "/usr/sbin/runc"},
		},
	}
	files := map[string]fs.FileMode{
		"/usr/lib/os-release":  0o644,
		"/etc/lsb-release":     0o644,
		"/etc/debian_version":  0o644,
		"/var/lib/dpkg/status": 0o644,
		"/usr/bin/caddy":       0o755,
		"/usr/local/bin/gofmt": 0o755,
		"/usr/sbin/runc":       0o755,
	}
	return plan, files
}

func testScanner(files map[string]fs.FileMode, out []byte, outErr error, gotArgs *[]string) *Scanner {
	sc := New("docker", "", 5*time.Minute)
	sc.lstat = fakeLstat(files)
	sc.execFn = func(_ context.Context, args []string) ([]byte, error) {
		if gotArgs != nil {
			*gotArgs = append([]string(nil), args...)
		}
		return out, outErr
	}
	return sc
}

// mountValues returns every --mount value in argv.
func mountValues(args []string) []string {
	var out []string
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--mount" {
			out = append(out, args[i+1])
		}
	}
	return out
}

func TestScanHostArgvShape(t *testing.T) {
	plan, files := ubuntuPlan()
	var args []string
	sc := testScanner(files, loadFixture(t), nil, &args)
	if _, err := sc.ScanHost(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if len(args) < 4 || args[2] != "--name" || !wantScanName.MatchString(args[3]) {
		t.Fatalf("argv must start with run --rm --name <generated name>: %q", args)
	}
	args = append(args[:2:2], args[4:]...) // the rest is fixed
	wantHead := []string{"run", "--rm", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--network", "bridge", "-v", cacheVolume + ":/root/.cache/trivy"}
	if len(args) < len(wantHead) || strings.Join(args[:len(wantHead)], " ") != strings.Join(wantHead, " ") {
		t.Fatalf("argv head = %q, want %q", args, wantHead)
	}
	img := -1
	for i, a := range args {
		if a == TrivyImage {
			img = i
		}
	}
	if img < 0 {
		t.Fatalf("image missing from argv: %q", args)
	}
	// Every docker flag comes before the image; after it only Trivy's own argv.
	wantTail := []string{TrivyImage, "rootfs", "--quiet", "--format", "json", "--scanners", "vuln",
		"--severity", severities, "--timeout", "5m0s", "--list-all-pkgs=false", "--disable-telemetry", "--skip-version-check", "/host"}
	if strings.Join(args[img:], " ") != strings.Join(wantTail, " ") {
		t.Errorf("argv tail = %q, want %q", args[img:], wantTail)
	}
	for _, a := range args[:img] {
		if strings.Contains(a, "docker.sock") || a == "--privileged" || a == "--cap-add" || a == "--pid" || strings.HasPrefix(a, "--userns") {
			t.Errorf("forbidden docker flag %q in %q", a, args)
		}
	}
	// Only the cache volume uses -v; every host path is a read-only bind mount under /host.
	vCount := 0
	for _, a := range args[:img] {
		if a == "-v" {
			vCount++
		}
	}
	if vCount != 1 {
		t.Errorf("want exactly one -v (the cache volume), got %d", vCount)
	}
	mounts := mountValues(args[:img])
	if len(mounts) != 7 {
		t.Fatalf("want 7 mounts (4 files + 3 binaries), got %d: %q", len(mounts), mounts)
	}
	for _, m := range mounts {
		f := strings.Split(m, ",")
		if len(f) != 4 || f[0] != "type=bind" || !strings.HasPrefix(f[1], "src=/") || f[3] != "readonly" {
			t.Errorf("mount %q is not type=bind,src=<abs>,dst=/host<abs>,readonly", m)
			continue
		}
		src, dst := strings.TrimPrefix(f[1], "src="), strings.TrimPrefix(f[2], "dst=")
		if dst != "/host"+src {
			t.Errorf("mount %q: dst must be /host + src", m)
		}
	}
	if got := strings.Join(mounts, " "); !strings.Contains(got, "src=/usr/bin/caddy,dst=/host/usr/bin/caddy,readonly") {
		t.Errorf("binary mount missing: %s", got)
	}
}

// The app scans use the same hardened docker flags. Every scan turns off Trivy's package listing
// (default on since 0.6x: every installed package, with its file list on rpm hosts, which can push the
// JSON past the 32 MiB stdout cap) and its usage telemetry and update check (Trivy >= 0.69 calls
// check.trivy.dev on every run unless both flags are set).
func TestScanImageAndFSArgv(t *testing.T) {
	var got [][]string
	sc := New("docker", "", 5*time.Minute)
	sc.execFn = func(_ context.Context, args []string) ([]byte, error) {
		got = append(got, append([]string(nil), args...))
		return []byte(`{"Results":[]}`), nil
	}
	if _, err := sc.ScanImage(context.Background(), "nginx:1.27"); err != nil {
		t.Fatal(err)
	}
	if _, err := sc.ScanFS(context.Background(), "/var/lib/mooring-apps/blog", "blog dependencies"); err != nil {
		t.Fatal(err)
	}
	head := "run --rm --cap-drop ALL --security-opt no-new-privileges --network bridge -v " + cacheVolume + ":/root/.cache/trivy "
	trivy := "--quiet --format json --scanners vuln --severity " + severities + " --timeout 5m0s --list-all-pkgs=false --disable-telemetry --skip-version-check "
	want := []string{
		head + TrivyImage + " image " + trivy + "nginx:1.27",
		head + "-v /var/lib/mooring-apps/blog:/scan:ro " + TrivyImage + " fs " + trivy + "/scan",
	}
	if len(got) != 2 {
		t.Fatalf("want 2 docker runs, got %q", got)
	}
	for i := range want {
		if len(got[i]) < 4 || got[i][2] != "--name" || !wantScanName.MatchString(got[i][3]) {
			t.Fatalf("argv %d must start with run --rm --name <generated name>: %q", i, got[i])
		}
		got[i] = append(got[i][:2:2], got[i][4:]...) // the rest is fixed
		if s := strings.Join(got[i], " "); s != want[i] {
			t.Errorf("argv %d =\n  %s\nwant\n  %s", i, s, want[i])
		}
	}
	if !strings.HasPrefix(TrivyImage, "aquasec/trivy:") || !strings.Contains(TrivyImage, "@sha256:") || len(TrivyImage[strings.Index(TrivyImage, "@sha256:")+8:]) != 64 {
		t.Errorf("TrivyImage must be pinned by a full digest: %q", TrivyImage)
	}
}

func TestScanHostParsesRealTrivyRootfs(t *testing.T) {
	plan, files := ubuntuPlan()
	sc := testScanner(files, loadFixture(t), nil, nil)
	h, err := sc.ScanHost(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if h.OS != "ubuntu 24.04" {
		t.Errorf("OS = %q, want ubuntu 24.04", h.OS)
	}
	if h.EOSL {
		t.Error("Ubuntu 24.04 is supported: Trivy omits EOSL, so it must read false")
	}
	if len(h.Reports) != 4 {
		t.Fatalf("want OS + 3 binary reports, got %d: %+v", len(h.Reports), h.Reports)
	}
	osr, caddy, gofmt, runc := h.Reports[0], h.Reports[1], h.Reports[2], h.Reports[3]

	if osr.Target != OSReportTarget || osr.Role != "" || osr.Error != "" {
		t.Errorf("OS report = %+v", osr)
	}
	if osr.Critical != 0 || osr.High != 9 || osr.Medium != 43 || osr.Low != 66 {
		t.Errorf("OS counts = %d/%d/%d/%d, want 0/9/43/66", osr.Critical, osr.High, osr.Medium, osr.Low)
	}
	if osr.FixableHigh != 9 || osr.FixableMedium != 43 || osr.FixableLow != 66 {
		t.Errorf("OS fixable = %+v", osr)
	}
	if len(osr.Top) != maxTop {
		t.Errorf("OS Top = %d, want the %d cap", len(osr.Top), maxTop)
	}

	if caddy.Target != "caddy (Mooring-owned build)" || caddy.Role != RoleOwnedCaddy {
		t.Errorf("caddy report target/role = %q/%q", caddy.Target, caddy.Role)
	}
	if caddy.Critical != 5 || caddy.High != 70 || caddy.Medium != 88 || caddy.Low != 11 {
		t.Errorf("caddy counts = %d/%d/%d/%d, want 5/70/88/11", caddy.Critical, caddy.High, caddy.Medium, caddy.Low)
	}
	if caddy.FixableCritical != 5 || caddy.FixableHigh != 69 || caddy.FixableMedium != 87 || caddy.FixableLow != 10 {
		t.Errorf("caddy fixable = %d/%d/%d/%d, want 5/69/87/10", caddy.FixableCritical, caddy.FixableHigh, caddy.FixableMedium, caddy.FixableLow)
	}
	// Worst first; within a severity, findings with a fix before those without: the 69 fixable Highs
	// fill the rest of the capped list, so the one unfixable High (CVE-2026-32286) is not in it.
	for i := 0; i < 5; i++ {
		if caddy.Top[i].Severity != sevCritical {
			t.Errorf("Top[%d] = %s, want CRITICAL", i, caddy.Top[i].Severity)
		}
	}
	for i := 5; i < maxTop; i++ {
		if caddy.Top[i].Severity != sevHigh || caddy.Top[i].Fixed == "" || caddy.Top[i].ID == "CVE-2026-32286" {
			t.Errorf("Top[%d] = %+v, want a fixable HIGH", i, caddy.Top[i])
		}
	}

	if gofmt.Target != "gofmt" || gofmt.Role != "" || gofmt.High != 4 || gofmt.Medium != 10 || gofmt.Low != 1 || gofmt.FixableHigh != 4 {
		t.Errorf("gofmt report = %+v", gofmt)
	}
	if runc.Target != "runc" || runc.Total() != 0 || runc.Error != "" {
		t.Errorf("a binary Trivy reports nothing for is a clean report: %+v", runc)
	}

	if h.Critical != 5 || h.High != 83 || h.Medium != 141 || h.Low != 78 {
		t.Errorf("host totals = %d/%d/%d/%d, want 5/83/141/78", h.Critical, h.High, h.Medium, h.Low)
	}
	if h.FixableCritical != 5 || h.FixableHigh != 82 || h.FixableMedium != 140 || h.FixableLow != 77 {
		t.Errorf("host fixable = %d/%d/%d/%d, want 5/82/140/77", h.FixableCritical, h.FixableHigh, h.FixableMedium, h.FixableLow)
	}
	if !h.Actionable() {
		t.Error("fixable High/Critical present → actionable")
	}
	// The identity list behind the alert signature counts every fixable High/Critical (9+74+4).
	n := 0
	for _, r := range h.Reports {
		n += len(r.fixableHC)
	}
	if n != 87 {
		t.Errorf("fixable High/Critical identities = %d, want 87", n)
	}
	// The alert's advice on real output: the three OS packages (libssl3t64 is openssl's library), the
	// owned build left to Mooring, gofmt to its package; runc has no finding, so no Docker warning.
	const advice = "Upgrade the affected OS packages: sudo apt-get update && sudo apt-get install --only-upgrade libssl3t64 nginx openssl. " +
		"The affected binary gofmt is fixed by upgrading the package that installed it, once that ships a rebuilt version. " +
		"Mooring refreshes its own Caddy build automatically."
	if got := fixAdvice(h); got != advice {
		t.Errorf("advice on the real scan =\n  %s\nwant\n  %s", got, advice)
	}
}

// Trivy sets Metadata.OS.EOSL (omitted when false) for a release past its end of support: such a host
// gets no more fixes, so few findings don't mean it is safe.
func TestScanHostEOSL(t *testing.T) {
	plan, files := ubuntuPlan()
	fixture := loadFixture(t)
	eol := bytes.Replace(fixture, []byte(`"Name": "24.04"`), []byte(`"Name": "24.04",
      "EOSL": true`), 1)
	if bytes.Equal(eol, fixture) {
		t.Fatal("fixture shape changed: Metadata.OS.Name not found")
	}
	h, err := testScanner(files, eol, nil, nil).ScanHost(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !h.EOSL || h.OS != "ubuntu 24.04" {
		t.Errorf("EOSL=%v OS=%q, want true / ubuntu 24.04", h.EOSL, h.OS)
	}
	// No OS detected → never EOSL.
	h, err = testScanner(files, []byte(`{"Metadata":{"OS":{"Family":"","EOSL":true}},"Results":[]}`), nil, nil).ScanHost(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if h.EOSL {
		t.Error("EOSL without a detected OS must not be reported")
	}
}

func TestScanHostTargetForms(t *testing.T) {
	data := []byte(`{"Metadata":{"OS":{"Family":"debian","Name":"12.5"}},"Results":[
	  {"Target":"/host (debian 12.5)","Class":"os-pkgs","Type":"debian"},
	  {"Target":"/host/usr/bin/a","Class":"lang-pkgs","Type":"gobinary","Vulnerabilities":[{"VulnerabilityID":"CVE-A","PkgName":"stdlib","Severity":"HIGH","FixedVersion":"1.2"}]},
	  {"Target":"/usr/bin/b","Class":"lang-pkgs","Type":"gobinary","Vulnerabilities":[{"VulnerabilityID":"CVE-B","PkgName":"stdlib","Severity":"LOW"}]},
	  {"Target":"usr/bin/c","Class":"lang-pkgs","Type":"gobinary","Vulnerabilities":[{"VulnerabilityID":"CVE-C","PkgName":"stdlib","Severity":"CRITICAL","FixedVersion":"1.3"}]}
	]}`)
	plan := HostPlan{
		Mounts: []Mount{{Host: "/var/lib/dpkg/status", Container: "/host/var/lib/dpkg/status"}},
		Binaries: []HostBinary{
			{Label: "a", Path: "/usr/bin/a"}, {Label: "b", Path: "/usr/bin/b"}, {Label: "c", Path: "/usr/bin/c"},
		},
	}
	files := map[string]fs.FileMode{"/var/lib/dpkg/status": 0o644, "/usr/bin/a": 0o755, "/usr/bin/b": 0o755, "/usr/bin/c": 0o755}
	h, err := testScanner(files, data, nil, nil).ScanHost(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if h.OS != "debian 12.5" || len(h.Reports) != 4 {
		t.Fatalf("got OS %q, %d reports", h.OS, len(h.Reports))
	}
	if a := h.Reports[1]; a.Target != "a" || a.High != 1 || a.FixableHigh != 1 {
		t.Errorf("/host/usr/bin/a not mapped: %+v", a)
	}
	if b := h.Reports[2]; b.Target != "b" || b.Low != 1 || b.FixableLow != 0 {
		t.Errorf("/usr/bin/b not mapped: %+v", b)
	}
	if c := h.Reports[3]; c.Target != "c" || c.Critical != 1 || c.FixableCritical != 1 {
		t.Errorf("usr/bin/c not mapped: %+v", c)
	}
	if h.Reports[0].Total() != 0 || h.Reports[0].Error != "" {
		t.Errorf("clean OS report expected: %+v", h.Reports[0])
	}
}

// Trivy still emits an (empty) os-pkgs result when no package database is mounted; that must read
// as "not scanned", never as clean. Same when no OS was detected.
func TestScanHostOSNotScannedIsNotClean(t *testing.T) {
	files := map[string]fs.FileMode{"/etc/lsb-release": 0o644, "/usr/bin/x": 0o755}
	noDB := HostPlan{Mounts: []Mount{{Host: "/etc/lsb-release", Container: "/host/etc/lsb-release"}}}
	data := []byte(`{"Metadata":{"OS":{"Family":"ubuntu","Name":"24.04"}},"Results":[{"Target":"/host (ubuntu 24.04)","Class":"os-pkgs","Type":"ubuntu"}]}`)
	h, err := testScanner(files, data, nil, nil).ScanHost(context.Background(), noDB)
	if err != nil {
		t.Fatal(err)
	}
	if h.Reports[0].Error == "" {
		t.Error("no package database mounted → the OS report must carry an error")
	}

	noOS := HostPlan{Binaries: []HostBinary{{Label: "x", Path: "/usr/bin/x"}}}
	h, err = testScanner(files, []byte(`{"Results":[]}`), nil, nil).ScanHost(context.Background(), noOS)
	if err != nil {
		t.Fatal(err)
	}
	if h.OS != "" || h.Reports[0].Error == "" {
		t.Errorf("no OS detected → OS report error, got OS %q report %+v", h.OS, h.Reports[0])
	}

	// What Trivy (0.58.1 and 0.76.2) really prints when the release files don't identify the OS, here
	// with the package database mounted: Family "none". That is "not detected", never a clean OS report.
	files["/usr/lib/os-release"], files["/var/lib/dpkg/status"] = 0o644, 0o644
	withDB := HostPlan{Mounts: []Mount{
		{Host: "/usr/lib/os-release", Container: "/host/usr/lib/os-release"},
		{Host: "/var/lib/dpkg/status", Container: "/host/var/lib/dpkg/status"},
	}}
	for _, fam := range []string{"none", "NONE", " none "} {
		data := []byte(`{"SchemaVersion":2,"ArtifactName":"/host","ArtifactType":"filesystem","Metadata":{"OS":{"Family":"` + fam + `","Name":"","EOSL":true}},"Results":null}`)
		h, err = testScanner(files, data, nil, nil).ScanHost(context.Background(), withDB)
		if err != nil {
			t.Fatal(err)
		}
		if h.OS != "" || h.EOSL || !strings.Contains(h.Reports[0].Error, "not detected") {
			t.Errorf("Family %q: OS %q EOSL %v report %+v; want not detected", fam, h.OS, h.EOSL, h.Reports[0])
		}
	}
}

// A binary the scanner can't read (Trivy runs as root with every capability dropped, so it can't
// read a 0700 file it doesn't own, and then silently reports nothing) is "not scanned", never clean,
// and is not mounted.
func TestScanHostUnreadableBinaryNotScanned(t *testing.T) {
	plan, files := ubuntuPlan()
	files["/usr/bin/caddy"] = 0o700
	var args []string
	h, err := testScanner(files, loadFixture(t), nil, &args).ScanHost(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range mountValues(args) {
		if strings.Contains(m, "/usr/bin/caddy") {
			t.Errorf("unreadable binary was mounted: %s", m)
		}
	}
	caddy := h.Reports[1]
	if caddy.Error == "" || caddy.Total() != 0 || caddy.Role != RoleOwnedCaddy {
		t.Errorf("unreadable binary report = %+v, want an error, no findings, role kept", caddy)
	}
	if len(h.skipped) == 0 {
		t.Error("the skip must be recorded for the log")
	}
}

func TestScanHostErrors(t *testing.T) {
	plan, files := ubuntuPlan()
	if _, err := testScanner(files, nil, errors.New("boom"), nil).ScanHost(context.Background(), plan); err == nil {
		t.Error("a failed trivy run must return an error")
	}
	if _, err := testScanner(files, []byte("not json"), nil, nil).ScanHost(context.Background(), plan); err == nil {
		t.Error("unparseable output must return an error")
	}
	called := false
	sc := testScanner(files, nil, nil, nil)
	sc.execFn = func(context.Context, []string) ([]byte, error) { called = true; return nil, nil }
	if _, err := sc.ScanHost(context.Background(), HostPlan{}); err == nil || called {
		t.Errorf("an empty plan must fail without running docker (err=%v called=%v)", err, called)
	}
}

// Abuse test: mount validation is the only thing between the plan and `docker run --mount`.
// Every refused mount is skipped (never passed through, never "fixed up"). Each bad path EXISTS as
// a readable regular file unless the case is about its type or mode, so the named rule (not a
// missing file) is what refuses it.
func TestScanHostRefusesUnsafeMounts(t *testing.T) {
	const (
		notClean  = "absolute and clean"
		badChar   = "character"
		container = "container path"
		symlink   = "symlink"
		notFile   = "only regular files"
		unread    = "can't read"
		missing   = "missing"
	)
	cases := []struct {
		m    Mount
		mode fs.FileMode // 0 = a readable regular file
		why  string
	}{
		{Mount{Host: "", Container: "/host"}, 0, notClean},
		{Mount{Host: "/", Container: "/host/"}, fs.ModeDir | 0o755, notClean},
		{Mount{Host: "/", Container: "/host"}, fs.ModeDir | 0o755, notClean},
		{Mount{Host: "relative/os-release", Container: "/hostrelative/os-release"}, 0, notClean},
		{Mount{Host: "/etc/../etc/shadow", Container: "/host/etc/../etc/shadow"}, 0, notClean},
		{Mount{Host: "/etc/os-release/", Container: "/host/etc/os-release/"}, 0, notClean},
		{Mount{Host: "/etc//os-release", Container: "/host/etc//os-release"}, 0, notClean},
		{Mount{Host: "/etc/os-release", Container: "/host/etc/shadow"}, 0, container},
		{Mount{Host: "/etc/os-release", Container: "/etc/os-release"}, 0, container},
		{Mount{Host: "/etc/os-release", Container: "/hostetc/os-release"}, 0, container},
		{Mount{Host: "/etc/os-release", Container: ""}, 0, container},
		{Mount{Host: "/etc/os-release", Container: "/host/etc/os-release,readonly=false"}, 0, container},
		{Mount{Host: "/tmp/a,dst=/host/etc,readonly=false", Container: "/host/tmp/a,dst=/host/etc,readonly=false"}, 0, badChar},
		{Mount{Host: "/tmp/b,readonly=false", Container: "/host/tmp/b,readonly=false"}, 0, badChar},
		{Mount{Host: `/tmp/c"d`, Container: `/host/tmp/c"d`}, 0, badChar},
		{Mount{Host: "/tmp/e\nf", Container: "/host/tmp/e\nf"}, 0, badChar},
		{Mount{Host: "/tmp/g\rh", Container: "/host/tmp/g\rh"}, 0, badChar},
		{Mount{Host: "/tmp/i\x00j", Container: "/host/tmp/i\x00j"}, 0, badChar},
		{Mount{Host: "/tmp/k\tl", Container: "/host/tmp/k\tl"}, 0, badChar},
		{Mount{Host: "/tmp/m\x7fn", Container: "/host/tmp/m\x7fn"}, 0, badChar},
		{Mount{Host: "/var/run/docker.sock", Container: "/host/var/run/docker.sock"}, fs.ModeSocket | 0o666, notFile},
		{Mount{Host: "/run/docker.sock", Container: "/host/run/docker.sock"}, fs.ModeSocket | 0o666, notFile},
		{Mount{Host: "/var/lib/mooring", Container: "/host/var/lib/mooring"}, fs.ModeDir | 0o755, notFile},
		{Mount{Host: "/etc", Container: "/host/etc"}, fs.ModeDir | 0o755, notFile},
		{Mount{Host: "/dev/sda", Container: "/host/dev/sda"}, fs.ModeDevice | 0o666, notFile},
		{Mount{Host: "/etc/link", Container: "/host/etc/link"}, fs.ModeSymlink | 0o777, symlink},
		{Mount{Host: "/etc/shadow", Container: "/host/etc/shadow"}, 0o640, unread},
		{Mount{Host: "/does/not/exist", Container: "/host/does/not/exist"}, fs.ModeIrregular, missing},
	}
	const safe = "/var/lib/dpkg/status"
	for _, c := range cases {
		files := map[string]fs.FileMode{safe: 0o644}
		switch c.mode {
		case 0:
			files[c.m.Host] = 0o644
		case fs.ModeIrregular: // marker: leave it out of the filesystem
		default:
			files[c.m.Host] = c.mode
		}
		var args []string
		h, err := testScanner(files, []byte(`{"Results":[]}`), nil, &args).ScanHost(context.Background(),
			HostPlan{Mounts: []Mount{{Host: safe, Container: "/host" + safe}, c.m}})
		if err != nil {
			t.Fatalf("%q: %v", c.m.Host, err)
		}
		if mounts := mountValues(args); len(mounts) != 1 || mounts[0] != "type=bind,src="+safe+",dst=/host"+safe+",readonly" {
			t.Errorf("%+v: only the safe mount may pass, got %q", c.m, mounts)
		}
		if len(h.skipped) != 1 || !strings.Contains(h.skipped[0], c.why) {
			t.Errorf("%+v: want refused for %q, got %q", c.m, c.why, h.skipped)
		}
		for _, a := range args {
			if strings.Contains(a, "src="+c.m.Host+",") || strings.Contains(a, "readonly=false") || strings.Contains(a, "docker.sock") {
				t.Errorf("%+v: refused path leaked into argv: %q", c.m, a)
			}
		}
	}

	// The rpm database is the one directory that may be mounted.
	for _, dir := range []string{"/var/lib/rpm", "/usr/lib/sysimage/rpm"} {
		var a []string
		_, err := testScanner(map[string]fs.FileMode{dir: fs.ModeDir | 0o755}, []byte(`{"Results":[]}`), nil, &a).ScanHost(context.Background(),
			HostPlan{Mounts: []Mount{{Host: dir, Container: "/host" + dir}}})
		if err != nil {
			t.Fatal(err)
		}
		if m := mountValues(a); len(m) != 1 || m[0] != "type=bind,src="+dir+",dst=/host"+dir+",readonly" {
			t.Errorf("rpm database dir %s not mounted: %q", dir, m)
		}
	}

	// A binary must be a mountable regular file: a directory (even the rpm db), the docker socket or a
	// CSV-injection path as a "binary" is refused and reported as not scanned.
	files := map[string]fs.FileMode{
		safe: 0o644, "/var/lib/rpm": fs.ModeDir | 0o755, "/var/run/docker.sock": fs.ModeSocket | 0o666, "/x,dst=/host/etc": 0o755,
	}
	var a []string
	h, err := testScanner(files, []byte(`{"Results":[]}`), nil, &a).ScanHost(context.Background(), HostPlan{
		Mounts:   []Mount{{Host: safe, Container: "/host" + safe}},
		Binaries: []HostBinary{{Label: "rpm", Path: "/var/lib/rpm"}, {Label: "sock", Path: "/var/run/docker.sock"}, {Label: "evil", Path: "/x,dst=/host/etc"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if m := mountValues(a); len(m) != 1 {
		t.Errorf("binaries that aren't mountable regular files must not be mounted: %q", m)
	}
	for _, r := range h.Reports[1:] {
		if r.Error == "" {
			t.Errorf("refused binary %q must be reported as not scanned", r.Target)
		}
	}
}

func TestScannerCanRead(t *testing.T) {
	cases := []struct {
		mode fs.FileMode
		want bool
	}{
		{0o644, true}, {0o755, true}, {0o604, true}, {0o700, false}, {0o640, false}, {0o600, false},
		{fs.ModeDir | 0o755, true}, {fs.ModeDir | 0o751, false}, {fs.ModeDir | 0o700, false},
	}
	for _, c := range cases {
		if got := scannerCanRead(fakeFI{name: "x", mode: c.mode}); got != c.want {
			t.Errorf("scannerCanRead(%v) = %v, want %v", c.mode, got, c.want)
		}
	}
	// A real file owned by this (non-root) test user with mode 0700 is unreadable to root without
	// capabilities; 0644 is readable.
	if os.Geteuid() != 0 {
		p := t.TempDir() + "/bin"
		if err := os.WriteFile(p, []byte("x"), 0o700); err != nil {
			t.Fatal(err)
		}
		fi, _ := os.Lstat(p)
		if scannerCanRead(fi) {
			t.Error("a 0700 file owned by another uid must be unreadable to the scanner")
		}
		_ = os.Chmod(p, 0o644)
		fi, _ = os.Lstat(p)
		if !scannerCanRead(fi) {
			t.Error("a 0644 file is readable")
		}
	}
}

// --- DefaultHostPlan ---

type fakePlanFS struct {
	files map[string]fs.FileMode // resolved paths
	links map[string]string      // path → target (absolute)
	path  map[string]string      // LookPath name → path
	exe   string
}

func (f fakePlanFS) fs() planFS {
	return planFS{
		lookPath: func(name string) (string, error) {
			if p, ok := f.path[name]; ok {
				return p, nil
			}
			return "", errors.New("not found")
		},
		evalSymlinks: func(p string) (string, error) {
			for i := 0; i < 10; i++ {
				if t, ok := f.links[p]; ok {
					p = t
					continue
				}
				if _, ok := f.files[p]; ok {
					return p, nil
				}
				return "", fs.ErrNotExist
			}
			return "", errors.New("loop")
		},
		stat: func(p string) (fs.FileInfo, error) {
			if m, ok := f.files[p]; ok {
				return fakeFI{name: p, mode: m}, nil
			}
			return nil, fs.ErrNotExist
		},
		executable: func() (string, error) {
			if f.exe == "" {
				return "", errors.New("no exe")
			}
			return f.exe, nil
		},
	}
}

func TestDefaultHostPlanUbuntu(t *testing.T) {
	f := fakePlanFS{
		files: map[string]fs.FileMode{
			"/usr/lib/os-release":                            0o644,
			"/etc/lsb-release":                               0o644,
			"/etc/debian_version":                            0o644,
			"/var/lib/dpkg/status":                           0o644,
			"/usr/bin/caddy":                                 0o755,
			"/usr/bin/docker":                                0o755,
			"/usr/bin/dockerd":                               0o755,
			"/usr/bin/containerd":                            0o755,
			"/usr/bin/containerd-shim-runc-v2":               0o755,
			"/usr/sbin/runc":                                 0o755,
			"/usr/bin/docker-proxy":                          0o755,
			"/usr/libexec/docker/cli-plugins/docker-compose": 0o755,
			"/usr/libexec/docker/cli-plugins/docker-buildx":  0o755,
			"/usr/libexec/docker/docker-proxy":               0o755, // PATH wins over the fallback dirs
			"/usr/local/bin/mooring":                         0o755,
			"/var/lib/mooring/bin/caddy":                     0o700,
		},
		links: map[string]string{
			"/etc/os-release": "/usr/lib/os-release",
			"/usr/bin/runc":   "/usr/sbin/runc",
		},
		path: map[string]string{
			"caddy": "/usr/bin/caddy", "docker": "/usr/bin/docker", "dockerd": "/usr/bin/dockerd",
			"containerd": "/usr/bin/containerd", "containerd-shim-runc-v2": "/usr/bin/containerd-shim-runc-v2",
			"runc": "/usr/bin/runc", "docker-proxy": "/usr/bin/docker-proxy",
		},
		exe: "/usr/local/bin/mooring",
	}
	p := defaultHostPlan(f.fs(), "/var/lib/mooring/bin/caddy")
	gotMounts := map[string]string{}
	for _, m := range p.Mounts {
		gotMounts[m.Host] = m.Container
		if m.Container != "/host"+m.Host {
			t.Errorf("mount %+v: Container must be /host + Host", m)
		}
	}
	for _, want := range []string{"/usr/lib/os-release", "/etc/lsb-release", "/etc/debian_version", "/var/lib/dpkg/status"} {
		if _, ok := gotMounts[want]; !ok {
			t.Errorf("missing mount %s in %+v", want, p.Mounts)
		}
	}
	if len(p.Mounts) != 4 {
		t.Errorf("want 4 mounts, got %+v", p.Mounts)
	}
	byLabel := map[string]HostBinary{}
	for _, b := range p.Binaries {
		byLabel[b.Label] = b
	}
	want := map[string]string{
		"caddy (system)":              "/usr/bin/caddy",
		"caddy (Mooring-owned build)": "/var/lib/mooring/bin/caddy",
		"docker":                      "/usr/bin/docker",
		"dockerd":                     "/usr/bin/dockerd",
		"containerd":                  "/usr/bin/containerd",
		"containerd-shim-runc-v2":     "/usr/bin/containerd-shim-runc-v2",
		"runc":                        "/usr/sbin/runc",
		"docker-proxy":                "/usr/bin/docker-proxy",
		"docker compose":              "/usr/libexec/docker/cli-plugins/docker-compose",
		"docker buildx":               "/usr/libexec/docker/cli-plugins/docker-buildx",
		"mooring":                     "/usr/local/bin/mooring",
	}
	if len(p.Binaries) != len(want) {
		t.Errorf("want %d binaries, got %+v", len(want), p.Binaries)
	}
	for label, path := range want {
		b, ok := byLabel[label]
		if !ok || b.Path != path {
			t.Errorf("binary %q = %+v, want path %s", label, b, path)
		}
	}
	if byLabel["caddy (Mooring-owned build)"].Role != RoleOwnedCaddy || byLabel["caddy (system)"].Role != "" {
		t.Error("only the Mooring-owned build carries RoleOwnedCaddy")
	}
	// The host alert's advice tells Docker's binaries (and mooring) apart by these labels.
	for label := range want {
		notDocker := label == "caddy (system)" || label == "caddy (Mooring-owned build)" || label == labelMooring
		if dockerBinaryLabels[label] == notDocker {
			t.Errorf("dockerBinaryLabels[%q] = %v", label, dockerBinaryLabels[label])
		}
	}
	if len(dockerBinaryLabels) != len(want)-3 {
		t.Errorf("dockerBinaryLabels has a label the plan never uses: %v", dockerBinaryLabels)
	}
}

// docker-proxy not on PATH is found in Docker's libexec/lib dirs (first match wins); the CLI plugins are
// found in any of the cli-plugins dirs.
func TestDefaultHostPlanDockerProxyAndPluginFallbacks(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		want  map[string]string // label → path
	}{
		{"libexec", []string{"/usr/libexec/docker/docker-proxy", "/usr/lib/docker/docker-proxy",
			"/usr/lib/docker/cli-plugins/docker-buildx", "/usr/local/lib/docker/cli-plugins/docker-compose"},
			map[string]string{"docker-proxy": "/usr/libexec/docker/docker-proxy",
				"docker buildx": "/usr/lib/docker/cli-plugins/docker-buildx", "docker compose": "/usr/local/lib/docker/cli-plugins/docker-compose"}},
		{"lib", []string{"/usr/lib/docker/docker-proxy", "/usr/local/lib/docker/cli-plugins/docker-buildx"},
			map[string]string{"docker-proxy": "/usr/lib/docker/docker-proxy", "docker buildx": "/usr/local/lib/docker/cli-plugins/docker-buildx"}},
		{"none", nil, map[string]string{}},
	}
	for _, c := range cases {
		f := fakePlanFS{files: map[string]fs.FileMode{}}
		for _, p := range c.files {
			f.files[p] = 0o755
		}
		got := map[string]string{}
		for _, b := range defaultHostPlan(f.fs(), "").Binaries {
			got[b.Label] = b.Path
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: binaries = %v, want %v", c.name, got, c.want)
		}
		for label, p := range c.want {
			if got[label] != p {
				t.Errorf("%s: %s = %q, want %q", c.name, label, got[label], p)
			}
		}
	}
}

func TestDefaultHostPlanSkipsAndDedupes(t *testing.T) {
	f := fakePlanFS{
		files: map[string]fs.FileMode{
			"/usr/lib/os-release":                0o644,
			"/etc/almalinux-release":             0o644,
			"/usr/lib/sysimage/rpm":              fs.ModeDir | 0o755,
			"/usr/lib/sysimage/rpm/rpmdb.sqlite": 0o644,
			"/usr/bin/snap":                      0o755,
			"/snap/docker/current/bin/dockerd":   0o755,
			"/usr/bin/containerd":                0o755,
			"/opt/caddy":                         fs.ModeDir | 0o755,
			"/srv/a,b/mooring":                   0o755,
		},
		links: map[string]string{
			"/etc/os-release":     "/usr/lib/os-release",
			"/etc/redhat-release": "/etc/almalinux-release",
			"/etc/system-release": "/etc/almalinux-release",
			"/var/lib/rpm":        "/usr/lib/sysimage/rpm",
			"/snap/bin/docker":    "/usr/bin/snap",
			"/usr/bin/runc":       "/usr/bin/containerd", // nonsense, but proves dedupe by resolved path
		},
		path: map[string]string{
			"caddy":      "/opt/caddy", // a directory
			"docker":     "/snap/bin/docker",
			"dockerd":    "/snap/docker/current/bin/dockerd",
			"containerd": "/usr/bin/containerd",
			"runc":       "/usr/bin/runc",
		},
		exe: "/srv/a,b/mooring",
	}
	p := defaultHostPlan(f.fs(), "/var/lib/mooring/bin/caddy") // owned build missing
	var hosts []string
	for _, m := range p.Mounts {
		hosts = append(hosts, m.Host)
	}
	if strings.Join(hosts, " ") != "/usr/lib/os-release /etc/almalinux-release /usr/lib/sysimage/rpm" {
		t.Errorf("mounts = %q, want os-release, the deduped release file and the rpm db", hosts)
	}
	if len(p.Binaries) != 1 || p.Binaries[0].Label != "containerd" {
		t.Errorf("want only containerd (snap, dir, missing, CSV-unsafe and duplicate paths skipped), got %+v", p.Binaries)
	}
	if p := defaultHostPlan(f.fs(), ""); len(p.Binaries) != 1 {
		t.Errorf("empty ownedCaddy adds nothing: %+v", p.Binaries)
	}
}

// Amazon Linux 2023 (every release checked, 2023.0.20230315.0 to 2023.12.20261117): /etc/system-release,
// /etc/amazon-linux-release and /etc/os-release are symlinks into /usr/lib, and the rpm database is the
// directory /var/lib/rpm. Each release file is mounted at its resolved path, which Trivy reads: its
// Amazon Linux analyzer reads usr/lib/system-release as well as etc/system-release (verified 2026-11-22
// with 0.58.1 on the GA release's files: family "amazon", version "2023 (Amazon Linux)", 590 fixable
// OS-package findings; re-verified 2026-11-23 with 0.76.2 and 0.58.1 on amazonlinux:2023
// 2023.12.20261117: version "2023.12.20261117 (Amazon Linux)"; TestTrivyE2E runs it). No mount needs a
// container path other than /host + host path.
func TestDefaultHostPlanAmazonLinux2023(t *testing.T) {
	files := map[string]fs.FileMode{
		"/usr/lib/os-release":       0o644,
		"/usr/lib/system-release":   0o644,
		"/var/lib/rpm":              fs.ModeDir | 0o755,
		"/var/lib/rpm/rpmdb.sqlite": 0o644,
	}
	f := fakePlanFS{
		files: files,
		links: map[string]string{
			"/etc/os-release":           "/usr/lib/os-release",
			"/etc/system-release":       "/usr/lib/system-release",
			"/etc/amazon-linux-release": "/usr/lib/system-release",
		},
	}
	p := defaultHostPlan(f.fs(), "")
	want := []Mount{
		{Host: "/usr/lib/os-release", Container: "/host/usr/lib/os-release"},
		{Host: "/usr/lib/system-release", Container: "/host/usr/lib/system-release"},
		{Host: "/var/lib/rpm", Container: "/host/var/lib/rpm"},
	}
	if len(p.Mounts) != len(want) {
		t.Fatalf("mounts = %+v, want %+v", p.Mounts, want)
	}
	for i := range want {
		if p.Mounts[i] != want[i] {
			t.Errorf("mount %d = %+v, want %+v", i, p.Mounts[i], want[i])
		}
	}

	// The plan passes mount validation unchanged, and Trivy's Amazon Linux result (shape and values from
	// the real run) is a scanned OS report.
	data := []byte(`{"SchemaVersion":2,"ArtifactName":"/host","ArtifactType":"filesystem",
	  "Metadata":{"OS":{"Family":"amazon","Name":"2023 (Amazon Linux)"}},
	  "Results":[{"Target":"/host (amazon 2023 (Amazon Linux))","Class":"os-pkgs","Type":"amazon","Vulnerabilities":[
	    {"VulnerabilityID":"CVE-2023-5363","PkgName":"openssl-libs","InstalledVersion":"1:3.0.8-1.amzn2023.0.1","FixedVersion":"1:3.0.8-1.amzn2023.0.9","Severity":"HIGH","Status":"fixed"},
	    {"VulnerabilityID":"CVE-2026-113470","PkgName":"ca-certificates","InstalledVersion":"2023.2.60-1.0.amzn2023.0.1","FixedVersion":"2025.2.76-1.0.amzn2023.0.4","Severity":"MEDIUM","Status":"fixed"}]}]}`)
	var args []string
	h, err := testScanner(files, data, nil, &args).ScanHost(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.skipped) != 0 || len(mountValues(args)) != len(want) {
		t.Errorf("every planned mount must pass validation: skipped %q, mounts %q", h.skipped, mountValues(args))
	}
	osr := h.Reports[0]
	if h.OS != "amazon 2023 (Amazon Linux)" || osr.Error != "" || osr.FixableHigh != 1 || osr.FixableMedium != 1 {
		t.Errorf("OS %q, OS report %+v; want amazon 2023 scanned with 1 fixable High and 1 fixable Medium", h.OS, osr)
	}
}
