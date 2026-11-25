package web

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/imagescan"
)

func serverPage(t *testing.T, e *testEnv) string {
	t.Helper()
	sess, _ := e.authed(t)
	resp := e.req(t, "GET", "/server", "127.0.0.1:1", nil, []*http.Cookie{sess}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /server = %d", resp.StatusCode)
	}
	return readBody(resp)
}

func withReboot(t *testing.T, req bool, pkgs []string) {
	t.Helper()
	prev := rebootRequired
	rebootRequired = func() (bool, []string) { return req, pkgs }
	t.Cleanup(func() { rebootRequired = prev })
}

func TestServerTabHostScanStates(t *testing.T) {
	withReboot(t, false, nil)
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")

	// Off.
	off := false
	e.srv.cfg.Server.HostScanEnabled = &off
	page := serverPage(t, e)
	if !strings.Contains(page, "Host vulnerabilities") || !strings.Contains(page, "server.host_scan_enabled") {
		t.Error("off state must name the key that turns the host scan back on")
	}

	// On, no store wired / no scan yet.
	e.srv.cfg.Server.HostScanEnabled = nil
	page = serverPage(t, e)
	if !strings.Contains(page, "after the first host scan") {
		t.Error("waiting text missing before the first scan")
	}

	// The app scan's off-state text names the false setting (it is on by default, not opt-in).
	e.srv.cfg.Server.ImageScanEnabled = &off
	page = serverPage(t, e)
	if strings.Contains(page, "set <code>server.image_scan_enabled: true</code>") || !strings.Contains(page, "<code>server.image_scan_enabled: false</code>") {
		t.Error("the app-scan off text must say it is turned off by the false setting")
	}
}

func TestServerTabHostScanResults(t *testing.T) {
	withReboot(t, true, []string{"libc6", "linux-image-6.8.0-49-generic"})
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	// Deps.HostScans is copied by New.
	hs := imagescan.NewHostStore(e.srv.db)
	srv, err := New(e.srv.cfg, Deps{DB: e.srv.db, HostScans: hs})
	if err != nil {
		t.Fatal(err)
	}
	if srv.hostScans != hs {
		t.Fatal("New must wire Deps.HostScans")
	}
	e.srv.hostScans = hs

	h := imagescan.HostScan{
		ScannedAt: 1700000000, OS: "ubuntu 24.04",
		High: 4, Medium: 1, FixableHigh: 3,
		Reports: []imagescan.Report{
			{Target: imagescan.OSReportTarget, High: 4, Medium: 1, FixableHigh: 3, Top: []imagescan.Vuln{
				{ID: "CVE-2026-123007", Package: "nginx", Installed: "1.24.0-2ubuntu7", Fixed: "1.24.0-2ubuntu7.6", Severity: "HIGH"},
				{ID: "CVE-2026-777", Package: "libfoo", Installed: "1.0", Severity: "HIGH"},
			}},
			{Target: "caddy (Mooring-owned build)", Role: imagescan.RoleOwnedCaddy, Error: "not scanned: the scanner can't read it"},
			{Target: "dockerd"},
		},
	}
	if err := hs.Save(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	page := serverPage(t, e)
	for _, want := range []string{
		"ubuntu 24.04",
		"4 (3 fixable)",
		"CVE-2026-123007",
		"→ fixed 1.24.0-2ubuntu7.6",
		"no fix yet",
		"caddy (Mooring-owned build)",
		"not scanned: the scanner can&#39;t read it",
		"dockerd",
		"needs a reboot",
		"libc6, linux-image-6.8.0-49-generic",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("server page missing %q", want)
		}
	}
	start, end := strings.Index(page, "<h2>Host vulnerabilities"), strings.Index(page, "<h2>Image updates")
	if start < 0 || end < start {
		t.Fatal("host section not found before the image-updates section")
	}
	if sec := page[start:end]; strings.Contains(sec, "style=") || strings.Contains(sec, "<script") {
		t.Error("the host section must use CSS classes only (CSP: no inline style/script)")
	}
	if strings.Contains(page, "end of life") {
		t.Error("no end-of-life notice for a supported release")
	}
}

// An end-of-life OS release gets a notice: few or no findings don't mean it's safe.
func TestServerTabHostScanEOSLNotice(t *testing.T) {
	withReboot(t, false, nil)
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	hs := imagescan.NewHostStore(e.srv.db)
	e.srv.hostScans = hs
	h := imagescan.HostScan{ScannedAt: 1700000000, OS: "ubuntu 20.04", EOSL: true,
		Reports: []imagescan.Report{{Target: imagescan.OSReportTarget}}}
	if err := hs.Save(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	page := serverPage(t, e)
	start, end := strings.Index(page, "<h2>Host vulnerabilities"), strings.Index(page, "<h2>Image updates")
	if start < 0 || end < start {
		t.Fatal("host section not found")
	}
	if !strings.Contains(page[start:end], "This OS release is end of life: it gets no more security fixes, so a clean result doesn't mean it's safe") {
		t.Errorf("end-of-life notice missing from the host section:\n%s", page[start:end])
	}
}

func TestServerTabRebootNoticeHidden(t *testing.T) {
	withReboot(t, false, nil)
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	if strings.Contains(serverPage(t, e), "needs a reboot") {
		t.Error("no reboot notice unless /run/reboot-required exists")
	}
}

func hostSection(t *testing.T, e *testEnv) string {
	t.Helper()
	page := serverPage(t, e)
	start, end := strings.Index(page, "<h2>Host vulnerabilities"), strings.Index(page, "<h2>Image updates")
	if start < 0 || end < start {
		t.Fatal("host section not found")
	}
	return page[start:end]
}

// A failed scan with no completed scan before it is not a result: the page shows the failure and its
// reason, never "Operating system not detected · 0 findings" or an empty findings table.
func TestServerTabHostScanFailedWithoutResults(t *testing.T) {
	withReboot(t, false, nil)
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	hs := imagescan.NewHostStore(e.srv.db)
	e.srv.hostScans = hs
	for _, msg := range []string{
		"the last host scan failed: the scan report is larger than 1024 MiB",
		// The row a release before this one stored.
		"the last host scan failed; the Mooring log (journalctl -u mooring) has the cause",
	} {
		if err := hs.Save(context.Background(), imagescan.HostScan{ScannedAt: 1700000000, Error: msg}); err != nil {
			t.Fatal(err)
		}
		sec := hostSection(t, e)
		for _, want := range []string{msg, "No host scan has completed yet, so there are no results to show", "last attempt", `data-ts="1700000000"`} {
			if !strings.Contains(sec, want) {
				t.Errorf("failed-scan section missing %q:\n%s", want, sec)
			}
		}
		for _, not := range []string{"Operating system not detected", "0 findings", "<table", "with a fix", "Fix by upgrading"} {
			if strings.Contains(sec, not) {
				t.Errorf("failed-scan section must not show %q as if it were a result:\n%s", not, sec)
			}
		}
	}
}

// A failed scan after a completed one shows the failure first, then the earlier results marked as such.
func TestServerTabHostScanFailedKeepsEarlierResults(t *testing.T) {
	withReboot(t, false, nil)
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	hs := imagescan.NewHostStore(e.srv.db)
	e.srv.hostScans = hs
	h := imagescan.HostScan{
		ScannedAt: 1700000000, OS: "ubuntu 24.04", High: 1, FixableHigh: 1,
		Reports: []imagescan.Report{{Target: imagescan.OSReportTarget, High: 1, FixableHigh: 1, Top: []imagescan.Vuln{
			{ID: "CVE-2026-123007", Package: "nginx", Installed: "1.24.0-2ubuntu7", Fixed: "1.24.0-2ubuntu7.6", Severity: "HIGH"},
		}}},
	}
	const marker = "Results of the last scan that completed, not of the failed one:"
	if err := hs.Save(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if sec := hostSection(t, e); strings.Contains(sec, marker) || strings.Contains(sec, `role="alert"`) || !strings.Contains(sec, "ubuntu 24.04") {
		t.Errorf("a completed scan has no failure text:\n%s", sec)
	}
	h.Error = "the last host scan failed: the scanner returned no output"
	if err := hs.Save(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	sec := hostSection(t, e)
	for _, want := range []string{h.Error, marker, "ubuntu 24.04", `data-ts="1700000000"`, "1 findings, 1 with a fix", "CVE-2026-123007"} {
		if !strings.Contains(sec, want) {
			t.Errorf("section missing %q:\n%s", want, sec)
		}
	}
	if strings.Contains(sec, "No host scan has completed yet") {
		t.Error("the earlier results exist, so the page must not say no scan completed")
	}
	if strings.Index(sec, h.Error) > strings.Index(sec, marker) {
		t.Error("the failure comes before the earlier results")
	}
}
