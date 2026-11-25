package imagescan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/alert"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// hostScanOf builds a HostScan the way ScanHost does (reports from Trivy findings, totals summed).
func hostScanOf(os string, reports ...Report) HostScan {
	h := HostScan{OS: os, Reports: reports}
	h.sum()
	return h
}

func fixable(id, pkg, sev, fixed string) trivyVuln {
	return trivyVuln{VulnerabilityID: id, PkgName: pkg, Severity: sev, FixedVersion: fixed, InstalledVersion: "old"}
}

func noReboot() (bool, []string) { return false, nil }

func newHostRunner(t *testing.T, sc *fakeScanner, sink *fakeSink, targets func(context.Context) []Target, hook func(context.Context)) (*Runner, *HostStore) {
	t.Helper()
	db := testDB(t)
	hs := NewHostStore(db)
	r := NewRunner(sc, NewStore(db), sink, targets, 0, quietLog()).WithHost(func(context.Context) HostPlan { return HostPlan{} }, hs, hook)
	r.reboot = noReboot
	return r, hs
}

func TestHostStoreRoundTrip(t *testing.T) {
	hs := NewHostStore(testDB(t))
	ctx := context.Background()
	if _, ok, err := hs.Get(ctx); ok || err != nil {
		t.Fatalf("empty store: ok=%v err=%v, want ok=false, nil", ok, err)
	}
	in := hostScanOf("ubuntu 24.04",
		buildReport(OSReportTarget, []trivyVuln{fixable("CVE-1", "nginx", "HIGH", "1.2"), {VulnerabilityID: "CVE-2", PkgName: "zlib", Severity: "LOW"}}),
		Report{Target: "caddy (Mooring-owned build)", Role: RoleOwnedCaddy, Error: "not scanned: x"})
	in.ScannedAt = 1700000000
	in.Error = "partial"
	in.EOSL = true
	if err := hs.Save(ctx, in); err != nil {
		t.Fatal(err)
	}
	// Saving again overwrites the single row.
	in.Low = 7
	if err := hs.Save(ctx, in); err != nil {
		t.Fatal(err)
	}
	got, ok, err := hs.Get(ctx)
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.ScannedAt != 1700000000 || got.OS != "ubuntu 24.04" || got.High != 1 || got.Low != 7 || got.FixableHigh != 1 || got.FixableLow != 0 || got.Error != "partial" || !got.EOSL {
		t.Errorf("round-trip = %+v", got)
	}
	// A later scan of a supported release clears the flag.
	in.EOSL = false
	if err := hs.Save(ctx, in); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := hs.Get(ctx); got.EOSL {
		t.Error("EOSL must be overwritten by the next scan")
	}
	if len(got.Reports) != 2 || got.Reports[0].Target != OSReportTarget || got.Reports[0].Top[0].Fixed != "1.2" ||
		got.Reports[1].Role != RoleOwnedCaddy || got.Reports[1].Error != "not scanned: x" {
		t.Errorf("reports round-trip = %+v", got.Reports)
	}
	var n int
	if err := hs.db.QueryRow(`SELECT COUNT(*) FROM host_scans`).Scan(&n); err != nil || n != 1 {
		t.Errorf("host_scans must hold one row, got %d (%v)", n, err)
	}
	if _, err := hs.db.Exec(`INSERT INTO host_scans(id) VALUES(2)`); err == nil {
		t.Error("the table must refuse a second row")
	}
}

func TestRunnerHostBeforeApps(t *testing.T) {
	sc := &fakeScanner{host: hostScanOf("ubuntu 24.04", Report{Target: OSReportTarget})}
	targets := func(context.Context) []Target {
		return []Target{{Project: "blog", Kind: KindImage, Ref: "nginx:1", Label: "nginx"}}
	}
	r, hs := newHostRunner(t, sc, &fakeSink{}, targets, nil)
	r.ScanAll(context.Background())
	if strings.Join(sc.calls, ",") != "host,image:nginx:1" {
		t.Errorf("calls = %v, want the host first then the apps", sc.calls)
	}
	got, ok, err := hs.Get(context.Background())
	if err != nil || !ok || got.OS != "ubuntu 24.04" || got.ScannedAt == 0 {
		t.Errorf("host scan not stored: %+v ok=%v err=%v", got, ok, err)
	}

	// Image scanning off: a nil targets func scans the host only.
	sc2 := &fakeScanner{host: hostScanOf("")}
	r2, _ := newHostRunner(t, sc2, &fakeSink{}, nil, nil)
	r2.ScanAll(context.Background())
	if strings.Join(sc2.calls, ",") != "host" {
		t.Errorf("calls = %v, want host only", sc2.calls)
	}

	// Without WithHost the runner never scans the host.
	sc3 := &fakeScanner{}
	NewRunner(sc3, NewStore(testDB(t)), &fakeSink{}, targets, 0, quietLog()).ScanAll(context.Background())
	if strings.Join(sc3.calls, ",") != "image:nginx:1" {
		t.Errorf("calls = %v, want apps only", sc3.calls)
	}
}

func TestRunnerHostScanFailureKeepsGoing(t *testing.T) {
	sc := &fakeScanner{hostErr: errors.New("trivy exploded")}
	targets := func(context.Context) []Target {
		return []Target{{Project: "blog", Kind: KindImage, Ref: "nginx:1", Label: "nginx"}}
	}
	sink := &fakeSink{}
	r, hs := newHostRunner(t, sc, sink, targets, nil)
	r.ScanAll(context.Background())
	got, ok, _ := hs.Get(context.Background())
	if !ok || got.Error == "" || got.ScannedAt == 0 {
		t.Errorf("a failed scan saves an error row: %+v ok=%v", got, ok)
	}
	if strings.Contains(got.Error, "exploded") {
		t.Errorf("the stored error is generic (details go to the log): %q", got.Error)
	}
	if len(sc.calls) != 2 {
		t.Errorf("the apps are still scanned after a host failure: %v", sc.calls)
	}

	// A later failure keeps the previous findings visible, with the error.
	sc.hostErr = nil
	sc.host = hostScanOf("ubuntu 24.04", buildReport(OSReportTarget, []trivyVuln{{VulnerabilityID: "CVE-9", PkgName: "x", Severity: "LOW"}}))
	r.ScanAll(context.Background())
	good, _, _ := hs.Get(context.Background())
	sc.hostErr = errors.New("db download failed")
	r.ScanAll(context.Background())
	got, _, _ = hs.Get(context.Background())
	if got.Low != 1 || got.OS != "ubuntu 24.04" || len(got.Reports) != 1 || got.Error == "" || got.ScannedAt != good.ScannedAt {
		t.Errorf("failure after a good scan must keep its results + add the error: %+v", got)
	}
}

func TestRunnerHostAlerts(t *testing.T) {
	nginx := fixable("CVE-2026-123007", "nginx", "HIGH", "1.24.0-2ubuntu7.6")
	libc := fixable("CVE-2026-7", "libc6", "CRITICAL", "2.39-0ubuntu8.4")
	curl := fixable("CVE-2026-8", "curl", "HIGH", "8.5.0-2ubuntu10.7")
	osRep := buildReport(OSReportTarget, []trivyVuln{
		nginx,
		fixable("CVE-2026-5", "openssl", "MEDIUM", "3.0.13-0ubuntu3.4"),
		{VulnerabilityID: "CVE-2026-6", PkgName: "libx", Severity: "CRITICAL"}, // no fix: never pages
	})
	sc := &fakeScanner{host: hostScanOf("ubuntu 24.04", osRep)}
	sink := &fakeSink{}
	r, _ := newHostRunner(t, sc, sink, nil, nil)
	scan := func(vulns ...trivyVuln) {
		t.Helper()
		sc.host = hostScanOf("ubuntu 24.04", buildReport(OSReportTarget, vulns))
		r.ScanAll(context.Background())
	}
	r.ScanAll(context.Background())
	if len(sink.sent) != 1 {
		t.Fatalf("want one host alert, got %+v", sink.sent)
	}
	o := sink.sent[0]
	if o.Kind != "host_vulnerabilities" || o.Target != "host" || o.Level != alert.LevelWarning || o.Transition != "firing" || o.RuleID != 0 {
		t.Errorf("alert = %+v (an unfixable Critical must not make it critical)", o)
	}
	if !strings.HasPrefix(o.DedupeKey, "hostvuln:") || len(strings.TrimPrefix(o.DedupeKey, "hostvuln:")) != 12 {
		t.Errorf("dedupe key = %q", o.DedupeKey)
	}
	for _, want := range []string{"1 new host vulnerability with a fix available (0 critical, 1 high)",
		"nginx CVE-2026-123007 → 1.24.0-2ubuntu7.6",
		". Upgrade the affected OS packages: sudo apt-get update && sudo apt-get install --only-upgrade nginx. ",
		"The Server tab lists the worst findings for each target and their fixed versions."} {
		if !strings.Contains(o.Summary, want) {
			t.Errorf("summary missing %q: %s", want, o.Summary)
		}
	}
	if strings.Contains(o.Summary, "CVE-2026-6") || strings.Contains(o.Summary, "every finding") {
		t.Errorf("an unfixable finding is not an example, and the tab lists only the worst findings: %s", o.Summary)
	}
	if strings.Contains(o.Summary, "apt-get upgrade") || strings.Contains(o.Summary, "openssl") || strings.Contains(o.Summary, "libx") {
		t.Errorf("never a full upgrade; only packages with a fixable High/Critical are named: %s", o.Summary)
	}

	// Same set again → no new page.
	r.ScanAll(context.Background())
	if len(sink.sent) != 1 {
		t.Errorf("a steady state re-paged: %d", len(sink.sent))
	}

	// A fixable Critical appears → a page about it alone, level critical.
	scan(nginx, libc)
	if len(sink.sent) != 2 || sink.sent[1].Level != alert.LevelCritical || sink.sent[1].DedupeKey == o.DedupeKey {
		t.Fatalf("a new fixable Critical → a new critical page: %+v", sink.sent)
	}
	s2 := sink.sent[1].Summary
	if !strings.Contains(s2, "1 new host vulnerability with a fix available (1 critical, 0 high)") ||
		!strings.Contains(s2, "libc6 CVE-2026-7") || strings.Contains(s2, "CVE-2026-123007") {
		t.Errorf("the summary counts and names only the new finding: %s", s2)
	}
	if !strings.Contains(s2, "With a fix in total: 1 critical, 1 high") || !strings.Contains(s2, "all findings: 1 critical, 1 high, 0 medium, 0 low") {
		t.Errorf("the summary gives the totals: %s", s2)
	}
	// The command covers every package with a fixable High/Critical in this scan, not only the new one.
	if !strings.Contains(s2, "--only-upgrade libc6 nginx.") {
		t.Errorf("the command names the whole scan's fixable set: %s", s2)
	}

	// Shrinking sets — including one never seen before as a whole — stay quiet.
	scan(nginx)
	scan(libc)
	sc.host = hostScanOf("ubuntu 24.04", osRep)
	r.ScanAll(context.Background())
	if len(sink.sent) != 2 {
		t.Fatalf("a shrinking or already-alerted set must not page: %+v", sink.sent[2:])
	}

	// A new High next to an already-alerted Critical → a warning about the High only.
	scan(nginx, libc, curl)
	if len(sink.sent) != 3 {
		t.Fatalf("a new fixable High must page: %d", len(sink.sent))
	}
	if o3 := sink.sent[2]; o3.Level != alert.LevelWarning || !strings.Contains(o3.Summary, "1 new host vulnerability with a fix available (0 critical, 1 high)") ||
		!strings.Contains(o3.Summary, "curl CVE-2026-8") {
		t.Errorf("level follows the NEW findings only: %+v", o3)
	}
	// The same finding under another target is a new identity.
	sc.host = hostScanOf("ubuntu 24.04", buildReport(OSReportTarget, []trivyVuln{nginx, libc, curl}),
		buildReport("caddy (system)", []trivyVuln{fixable("CVE-2026-8", "curl", "HIGH", "8.5.0-2ubuntu10.7")}))
	r.ScanAll(context.Background())
	if len(sink.sent) != 4 || !strings.Contains(sink.sent[3].Summary, "(caddy (system))") {
		t.Fatalf("a finding in a new target pages: %+v", sink.sent[3:])
	}
	r.ScanAll(context.Background())
	if len(sink.sent) != 4 {
		t.Errorf("a steady state re-paged: %d", len(sink.sent))
	}

	// Two new findings → the count is plural.
	scan(nginx, libc, curl, fixable("CVE-2026-9", "zlib1g", "HIGH", "1:1.3"), fixable("CVE-2026-10", "tar", "CRITICAL", "1.35+dfsg-3.1"))
	if len(sink.sent) != 5 || sink.sent[4].Level != alert.LevelCritical ||
		!strings.Contains(sink.sent[4].Summary, "2 new host vulnerabilities with a fix available (1 critical, 1 high)") {
		t.Errorf("two new findings: %+v", sink.sent[4:])
	}
}

// The upgrade command names only the OS packages with a fixable High/Critical finding (never a full
// `apt-get upgrade`, which would also upgrade docker-ce/containerd.io): de-duplicated and sorted.
func TestFixAdviceAptNamesOnlyFixableHighCritical(t *testing.T) {
	h := hostScanOf("ubuntu 24.04", buildReport(OSReportTarget, []trivyVuln{
		fixable("CVE-1", "nginx", "HIGH", "1.24.0-2ubuntu7.6"),
		fixable("CVE-2", "libc6", "CRITICAL", "2.39-0ubuntu8.4"),
		fixable("CVE-3", "nginx", "CRITICAL", "1.24.0-2ubuntu7.6"), // second finding, same package
		fixable("CVE-4", "curl", "HIGH", "8.5.0-2ubuntu10.7"),
		fixable("CVE-5", "openssl", "MEDIUM", "3.0.13-0ubuntu3.4"),            // not High/Critical
		fixable("CVE-6", "zlib1g", "LOW", "1:1.3"),                            // not High/Critical
		{VulnerabilityID: "CVE-7", PkgName: "libx11-6", Severity: "CRITICAL"}, // no fix
	}))
	got := fixAdvice(h)
	const want = "Upgrade the affected OS packages: sudo apt-get update && sudo apt-get install --only-upgrade curl libc6 nginx."
	if !strings.HasPrefix(got, want) {
		t.Errorf("advice = %q\nwant it to start with %q", got, want)
	}
	for _, bad := range []string{"apt-get upgrade", "openssl", "zlib1g", "libx11-6", "more", "Docker", "dnf"} {
		if strings.Contains(got, bad) {
			t.Errorf("advice must not contain %q: %q", bad, got)
		}
	}
	if got := fixAdvice(hostScanOf("debian 12.5", h.Reports...)); !strings.Contains(got, "sudo apt-get install --only-upgrade curl libc6 nginx.") {
		t.Errorf("debian uses apt-get too: %q", got)
	}
}

// Package names come from the host's package database through Trivy: only the package-name charset
// passes (no leading '-', which apt/dnf would read as an option, and no trailing '-', which apt-get
// install reads as "remove"). A dropped name is counted in "and N more", never printed.
func TestFixAdviceSanitizesPackageNames(t *testing.T) {
	var vs []trivyVuln
	for i, p := range []string{
		"libstdc++6", "g++", "python3.12", "libc6:i386", "Foo_Bar", "a-b.c+d",
		"-oAPT::Get::AllowUnauthenticated=true", "--purge", "foo-", "bad;rm -rf /", "x$(id)", "a b", "a\nb",
		"`id`", "pkg|other", "pkg/unstable", "pkg=1.0", "*", "", "é", "@group",
	} {
		vs = append(vs, fixable("CVE-"+strconv.Itoa(i), p, "HIGH", "2"))
	}
	got := fixAdvice(hostScanOf("ubuntu 24.04", buildReport(OSReportTarget, vs)))
	const want = "sudo apt-get update && sudo apt-get install --only-upgrade Foo_Bar a-b.c+d g++ libc6:i386 libstdc++6 python3.12 (and 15 more — see the Server tab)."
	if !strings.Contains(got, want) {
		t.Errorf("advice = %q\nwant %q", got, want)
	}
	for _, bad := range []string{"-oAPT", "--purge", "foo-", ";", "$(", "`", "|", "/unstable", "=1.0", "*", "é", "@", "\n"} {
		if strings.Contains(got, bad) {
			t.Errorf("unsafe name %q leaked into the advice: %q", bad, got)
		}
	}
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"curl", true}, {"libc6:amd64", true}, {"0ad", true}, {"a", true},
		{"-x", false}, {"x-", false}, {"", false}, {"a b", false}, {"a,b", false}, {"ä", false}, {strings.Repeat("a", 129), false},
		// apt-get reads a name that matches no package and has '.' or '+' as a regular expression: "."
		// would match every package, Docker's included. dpkg names start with a letter or digit.
		{".", false}, {"+x", false}, {":x", false}, {"_x", false}, {".x", false},
	} {
		if got := safePkgName(c.name); got != c.ok {
			t.Errorf("safePkgName(%q) = %v, want %v", c.name, got, c.ok)
		}
	}
}

// Every name dropped by the sanitizer leaves the command without names: the advice points at the
// Server tab instead of printing an empty command.
func TestFixAdviceAllNamesDropped(t *testing.T) {
	got := fixAdvice(hostScanOf("ubuntu 24.04", buildReport(OSReportTarget, []trivyVuln{fixable("CVE-1", "-bad", "HIGH", "2")})))
	if !strings.Contains(got, "Upgrade the affected OS packages listed on the Server tab.") || strings.Contains(got, "--only-upgrade") || strings.Contains(got, "-bad") {
		t.Errorf("advice = %q", got)
	}
}

// The command lists at most maxHintPkgs names (the first in sorted order); the rest are counted.
func TestFixAdviceCapsPackageCount(t *testing.T) {
	var vs []trivyVuln
	var names []string
	for i := 0; i < maxHintPkgs+5; i++ {
		n := fmt.Sprintf("pkg%02d", i)
		names = append(names, n)
		vs = append(vs, fixable("CVE-"+strconv.Itoa(i), n, "CRITICAL", "2"))
	}
	got := fixAdvice(hostScanOf("ubuntu 24.04", buildReport(OSReportTarget, vs)))
	want := "--only-upgrade " + strings.Join(names[:maxHintPkgs], " ") + " (and 5 more — see the Server tab)."
	if !strings.Contains(got, want) {
		t.Errorf("advice = %q\nwant %q", got, want)
	}
	if strings.Contains(got, names[maxHintPkgs]) {
		t.Errorf("a name past the cap was listed: %q", got)
	}
	// Exactly at the cap: no "more".
	got = fixAdvice(hostScanOf("ubuntu 24.04", buildReport(OSReportTarget, vs[:maxHintPkgs])))
	if strings.Contains(got, "more") || !strings.Contains(got, strings.Join(names[:maxHintPkgs], " ")+".") {
		t.Errorf("at the cap = %q", got)
	}
}

// Upgrading a Docker or container-runtime package restarts Docker and every container: the advice
// says so, for a package in the command and for a Docker binary with a fix.
func TestFixAdviceDockerRestartWarning(t *testing.T) {
	const warn = "Upgrading Docker or the container runtime restarts Docker and every container on the host, so pick a quiet moment."
	for _, p := range []string{"docker-ce", "docker-ce-cli", "docker-ce-rootless-extras", "containerd.io", "docker-buildx-plugin",
		"docker-compose-plugin", "docker.io", "containerd", "runc", "moby-engine", "moby-containerd", "containerd.io:amd64"} {
		got := fixAdvice(hostScanOf("ubuntu 24.04", buildReport(OSReportTarget, []trivyVuln{
			fixable("CVE-1", "curl", "HIGH", "2"), fixable("CVE-2", p, "HIGH", "2"),
		})))
		if !strings.Contains(got, warn) {
			t.Errorf("%s: missing the Docker restart warning: %q", p, got)
		}
	}
	for _, p := range []string{"curl", "docker-ce-foo", "mydocker-ce", "containerd-tools", "moby", "runc2"} {
		got := fixAdvice(hostScanOf("ubuntu 24.04", buildReport(OSReportTarget, []trivyVuln{fixable("CVE-1", p, "HIGH", "2")})))
		if strings.Contains(got, "restarts Docker") {
			t.Errorf("%s is not a Docker package: %q", p, got)
		}
	}
	// A Docker package past the cap is still upgraded by an operator following "see the Server tab".
	var vs []trivyVuln
	for i := 0; i < maxHintPkgs; i++ {
		vs = append(vs, fixable("CVE-"+strconv.Itoa(i), fmt.Sprintf("a%02d", i), "HIGH", "2"))
	}
	vs = append(vs, fixable("CVE-X", "runc", "HIGH", "2"))
	if got := fixAdvice(hostScanOf("ubuntu 24.04", buildReport(OSReportTarget, vs))); !strings.Contains(got, warn) || strings.Contains(got, " runc ") {
		t.Errorf("Docker package past the cap: %q", got)
	}
	// A Docker binary with a fixable finding, no OS package findings.
	got := fixAdvice(hostScanOf("ubuntu 24.04", Report{Target: OSReportTarget},
		buildReport("dockerd", []trivyVuln{fixable("CVE-1", "stdlib", "HIGH", "1.25.7")})))
	if !strings.Contains(got, warn) {
		t.Errorf("Docker binary: missing the warning: %q", got)
	}
	// A Docker binary with only a fixable Medium is not in the advice.
	got = fixAdvice(hostScanOf("ubuntu 24.04", buildReport(OSReportTarget, []trivyVuln{fixable("CVE-1", "curl", "HIGH", "2")}),
		buildReport("dockerd", []trivyVuln{fixable("CVE-2", "stdlib", "MEDIUM", "1.25.7")})))
	if strings.Contains(got, "Docker") || strings.Contains(got, "dockerd") {
		t.Errorf("a Medium binary finding is not in the advice: %q", got)
	}
}

// The RHEL family, Fedora and Amazon Linux use dnf; releases without dnf (Amazon Linux 2, release 7)
// use yum.
func TestFixAdviceRPMFamilies(t *testing.T) {
	rep := buildReport(OSReportTarget, []trivyVuln{fixable("CVE-1", "openssl-libs", "HIGH", "1:3.0.8-1.amzn2023.0.9"), fixable("CVE-2", "curl", "CRITICAL", "2")})
	for os, want := range map[string]string{
		"redhat 9.4":                 "sudo dnf upgrade curl openssl-libs.",
		"centos 8.5.2111":            "sudo dnf upgrade curl openssl-libs.",
		"rocky 9.3":                  "sudo dnf upgrade curl openssl-libs.",
		"alma 9.4":                   "sudo dnf upgrade curl openssl-libs.",
		"oracle 8.9":                 "sudo dnf upgrade curl openssl-libs.",
		"fedora 40":                  "sudo dnf upgrade curl openssl-libs.",
		"amazon 2023 (Amazon Linux)": "sudo dnf upgrade curl openssl-libs.",
		"amazon 2 (Karoo)":           "sudo yum upgrade curl openssl-libs.",
		"redhat 7.9":                 "sudo yum upgrade curl openssl-libs.",
		"centos 7.9.2009":            "sudo yum upgrade curl openssl-libs.",
		"oracle 7.9":                 "sudo yum upgrade curl openssl-libs.",
	} {
		got := fixAdvice(hostScanOf(os, rep))
		if !strings.Contains(got, "Upgrade the affected OS packages: "+want) || strings.Contains(got, "apt-get") {
			t.Errorf("%s: advice = %q, want %q", os, got, want)
		}
	}
}

// An OS family without a known package-manager command gets the package names without a command.
func TestFixAdviceUnknownOS(t *testing.T) {
	rep := buildReport(OSReportTarget, []trivyVuln{fixable("CVE-1", "musl", "HIGH", "1.2.5-r1"), fixable("CVE-2", "busybox", "HIGH", "2")})
	for _, os := range []string{"alpine 3.20.3", "suse linux enterprise server 15.6", "photon 5.0"} {
		got := fixAdvice(hostScanOf(os, rep))
		if !strings.HasPrefix(got, "Upgrade the affected OS packages with the host's package manager: busybox musl.") ||
			strings.Contains(got, "sudo") {
			t.Errorf("%s: advice = %q", os, got)
		}
	}
}

// Binary findings: the Mooring-owned Caddy build is refreshed by Mooring (never "upgrade a package"),
// mooring needs a Mooring release, and any other binary updates with the package that installed it.
// None of them is ever named in the OS-package command.
func TestFixAdviceBinaries(t *testing.T) {
	owned := buildReport("caddy (Mooring-owned build)", []trivyVuln{fixable("CVE-1", "golang.org/x/net", "HIGH", "0.33.0")})
	owned.Role = RoleOwnedCaddy
	got := fixAdvice(hostScanOf("ubuntu 24.04", Report{Target: OSReportTarget}, owned))
	if got != "Mooring refreshes its own Caddy build automatically." {
		t.Errorf("owned build only: %q", got)
	}

	got = fixAdvice(hostScanOf("ubuntu 24.04",
		buildReport(OSReportTarget, []trivyVuln{fixable("CVE-9", "curl", "HIGH", "2")}),
		owned,
		buildReport("caddy (system)", []trivyVuln{fixable("CVE-2", "stdlib", "CRITICAL", "1.25.7")}),
		buildReport("mooring", []trivyVuln{fixable("CVE-3", "stdlib", "HIGH", "1.25.7")}),
		buildReport("containerd", []trivyVuln{fixable("CVE-4", "stdlib", "HIGH", "1.25.7")}),
		buildReport("/usr/local/bin/other", []trivyVuln{fixable("CVE-5", "stdlib", "HIGH", "1.25.7")}),
		buildReport("runc", []trivyVuln{{VulnerabilityID: "CVE-6", PkgName: "stdlib", Severity: "CRITICAL"}}), // no fix
		Report{Target: "docker", Error: "not scanned: x"},
	))
	for _, want := range []string{
		"Upgrade the affected OS packages: sudo apt-get update && sudo apt-get install --only-upgrade curl.",
		"The affected binaries caddy (system), containerd and /usr/local/bin/other are fixed by upgrading the packages that installed them, once those ship a rebuilt version.",
		"mooring is fixed by a newer Mooring release.",
		"Mooring refreshes its own Caddy build automatically.",
		"Upgrading Docker or the container runtime restarts Docker",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("advice missing %q: %q", want, got)
		}
	}
	if strings.Contains(got, "runc") || strings.Contains(got, "docker ") || strings.Contains(got, "Mooring-owned build") {
		t.Errorf("an unfixable or unscanned binary and the owned build's label are not named: %q", got)
	}
	// A single packaged binary reads in the singular.
	got = fixAdvice(hostScanOf("ubuntu 24.04", Report{Target: OSReportTarget},
		buildReport("caddy (system)", []trivyVuln{fixable("CVE-2", "stdlib", "CRITICAL", "1.25.7")})))
	if got != "The affected binary caddy (system) is fixed by upgrading the package that installed it, once that ships a rebuilt version." {
		t.Errorf("one binary: %q", got)
	}
	// The binary list is capped like the package list.
	reps := []Report{{Target: OSReportTarget}}
	for i := 0; i < maxHintPkgs+5; i++ {
		reps = append(reps, buildReport(fmt.Sprintf("/opt/b%02d", i), []trivyVuln{fixable("CVE-1", "stdlib", "HIGH", "1.25.7")}))
	}
	got = fixAdvice(hostScanOf("ubuntu 24.04", reps...))
	if !strings.Contains(got, fmt.Sprintf("/opt/b%02d and 5 more are fixed", maxHintPkgs-1)) || strings.Contains(got, fmt.Sprintf("/opt/b%02d", maxHintPkgs)) {
		t.Errorf("binary cap: %q", got)
	}
}

// Identities are marked as alerted only once the alert is queued: a failed enqueue pages again on the
// next scan, with the same key.
func TestRunnerHostAlertRetriesAfterEnqueueFailure(t *testing.T) {
	sc := &fakeScanner{host: hostScanOf("ubuntu 24.04", buildReport(OSReportTarget, []trivyVuln{
		fixable("CVE-2026-123007", "nginx", "HIGH", "1.24.0-2ubuntu7.6"),
	}))}
	sink := &fakeSink{err: errors.New("database is locked")}
	r, _ := newHostRunner(t, sc, sink, nil, nil)
	r.ScanAll(context.Background())
	sink.err = nil
	r.ScanAll(context.Background())
	if len(sink.sent) != 1 {
		t.Fatalf("a failed enqueue must not mark the findings as alerted: %+v", sink.sent)
	}
	key := sink.sent[0].DedupeKey
	r.ScanAll(context.Background())
	if len(sink.sent) != 1 || key == "" {
		t.Errorf("after a successful enqueue the set is alerted: %+v", sink.sent)
	}
}

func TestRunnerHostNoPageWhenOnlyUnfixable(t *testing.T) {
	sc := &fakeScanner{host: hostScanOf("ubuntu 24.04", buildReport(OSReportTarget, []trivyVuln{
		{VulnerabilityID: "CVE-1", PkgName: "a", Severity: "CRITICAL"},
		{VulnerabilityID: "CVE-2", PkgName: "b", Severity: "HIGH"},
		fixable("CVE-3", "c", "MEDIUM", "2"),
		fixable("CVE-4", "d", "LOW", "2"),
	}))}
	sink := &fakeSink{}
	r, _ := newHostRunner(t, sc, sink, nil, nil)
	r.ScanAll(context.Background())
	if len(sink.sent) != 0 {
		t.Errorf("unfixable High/Critical and fixable Medium/Low must not page: %+v", sink.sent)
	}
}

func TestRunnerOwnedCaddyHook(t *testing.T) {
	cases := []struct {
		name string
		rep  Report
		want bool
	}{
		{"owned, fixable low", func() Report {
			r := buildReport("caddy (Mooring-owned build)", []trivyVuln{fixable("CVE-1", "golang.org/x/net", "LOW", "0.33.0")})
			r.Role = RoleOwnedCaddy
			return r
		}(), true},
		{"owned, unfixable only", func() Report {
			r := buildReport("caddy (Mooring-owned build)", []trivyVuln{{VulnerabilityID: "CVE-1", PkgName: "x", Severity: "CRITICAL"}})
			r.Role = RoleOwnedCaddy
			return r
		}(), false},
		{"owned, not scanned", Report{Target: "caddy (Mooring-owned build)", Role: RoleOwnedCaddy, Error: "not scanned"}, false},
		{"system caddy, fixable critical", buildReport("caddy (system)", []trivyVuln{fixable("CVE-1", "stdlib", "CRITICAL", "1.25.7")}), false},
	}
	for _, c := range cases {
		calls := 0
		sc := &fakeScanner{host: hostScanOf("ubuntu 24.04", Report{Target: OSReportTarget}, c.rep)}
		r, _ := newHostRunner(t, sc, &fakeSink{}, nil, func(context.Context) { calls++ })
		r.ScanAll(context.Background())
		if (calls == 1) != c.want || calls > 1 {
			t.Errorf("%s: hook calls = %d, want called=%v", c.name, calls, c.want)
		}
	}
	// A nil hook is fine.
	sc := &fakeScanner{host: hostScanOf("", cases[0].rep)}
	r, _ := newHostRunner(t, sc, &fakeSink{}, nil, nil)
	r.ScanAll(context.Background())
}

func TestRunnerRebootAlert(t *testing.T) {
	sc := &fakeScanner{host: hostScanOf("ubuntu 24.04", Report{Target: OSReportTarget})}
	sink := &fakeSink{}
	r, _ := newHostRunner(t, sc, sink, nil, nil)
	pkgs := []string{"linux-image-6.8.0-49-generic", "libc6"}
	r.reboot = func() (bool, []string) { return true, pkgs }
	r.ScanAll(context.Background())
	if len(sink.sent) != 1 {
		t.Fatalf("want one reboot alert, got %+v", sink.sent)
	}
	o := sink.sent[0]
	if o.Kind != "host_reboot_required" || o.Level != alert.LevelWarning || o.Target != "host" || !strings.HasPrefix(o.DedupeKey, "reboot:") ||
		len(strings.TrimPrefix(o.DedupeKey, "reboot:")) != 12 || !strings.Contains(o.Summary, "libc6") {
		t.Errorf("reboot alert = %+v", o)
	}
	r.ScanAll(context.Background())
	if len(sink.sent) != 1 {
		t.Error("the same package list must not re-page")
	}
	pkgs = []string{"linux-image-6.8.0-50-generic"}
	r.ScanAll(context.Background())
	if len(sink.sent) != 2 || sink.sent[1].DedupeKey == o.DedupeKey {
		t.Errorf("a new package list pages again: %+v", sink.sent)
	}
	// The reboot check runs after a failed scan too.
	sc.hostErr = errors.New("x")
	pkgs = []string{"systemd"}
	r.ScanAll(context.Background())
	if len(sink.sent) != 3 {
		t.Errorf("reboot alert after a failed scan: %d", len(sink.sent))
	}
	// No reboot needed → nothing.
	sink2 := &fakeSink{}
	r2, _ := newHostRunner(t, &fakeScanner{host: hostScanOf("")}, sink2, nil, nil)
	r2.ScanAll(context.Background())
	if len(sink2.sent) != 0 {
		t.Errorf("no reboot flag → no alert: %+v", sink2.sent)
	}
}

func TestRunnerHostCancelledScanNotSaved(t *testing.T) {
	sc := &fakeScanner{hostErr: context.Canceled}
	r, hs := newHostRunner(t, sc, &fakeSink{}, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.ScanAll(ctx)
	if _, ok, _ := hs.Get(context.Background()); ok {
		t.Error("a scan cut short by shutdown must not store a failure")
	}
}

// A scan whose report could not be used stores the reason itself for the Server tab; any other
// failure (the scanner's stderr) stays in the log.
func TestRunnerHostScanFailureReason(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{errNoOutput, "the last host scan failed: the scanner returned no output"},
		{fmt.Errorf("wrapped: %w", errReportTooLarge(defaultLimits)), "the last host scan failed: the scan report is larger than 1024 MiB"},
		{&outputError{reason: "the scan report is incomplete", cause: errors.New("it ends after 33554432 bytes")}, "the last host scan failed: the scan report is incomplete"},
		{errors.New("trivy scan failed: exit status 1: FATAL token=abc"), hostScanFailed},
	} {
		sc := &fakeScanner{hostErr: c.err}
		r, hs := newHostRunner(t, sc, &fakeSink{}, nil, nil)
		r.ScanAll(context.Background())
		got, ok, _ := hs.Get(context.Background())
		if !ok || got.Error != c.want {
			t.Errorf("%v: stored error %q; want %q", c.err, got.Error, c.want)
		}
		if len(got.Reports) != 0 || got.OS != "" || got.Total() != 0 {
			t.Errorf("a failed first scan stores no result: %+v", got)
		}
	}
}

// A row without reports is an earlier failure: the next failure replaces it (its time is the latest
// attempt's), while a completed scan's results and time survive later failures.
func TestRunnerHostScanFailureRowTimes(t *testing.T) {
	ctx := context.Background()
	sc := &fakeScanner{hostErr: errNoOutput}
	r, hs := newHostRunner(t, sc, &fakeSink{}, nil, nil)
	if err := hs.Save(ctx, HostScan{ScannedAt: 1000, Error: hostScanFailed}); err != nil {
		t.Fatal(err)
	}
	r.ScanAll(ctx)
	got, _, _ := hs.Get(ctx)
	if got.ScannedAt <= 1000 || got.Error != "the last host scan failed: the scanner returned no output" {
		t.Errorf("a failure after a failure must store this attempt's time and reason: %+v", got)
	}

	good := hostScanOf("ubuntu 24.04", buildReport(OSReportTarget, []trivyVuln{{VulnerabilityID: "CVE-9", PkgName: "x", Severity: "LOW"}}))
	good.ScannedAt = 2000
	if err := hs.Save(ctx, good); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		r.ScanAll(ctx)
		got, _, _ = hs.Get(ctx)
		if got.ScannedAt != 2000 || got.Low != 1 || len(got.Reports) != 1 || got.Error == "" {
			t.Errorf("failure %d after a completed scan must keep its results and time: %+v", i+1, got)
		}
	}
}
