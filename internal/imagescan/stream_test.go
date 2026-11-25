package imagescan

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// buildReport aggregates vulns into a Report for target, as one scan result would.
func buildReport(target string, vulns []trivyVuln) Report {
	b := newReportBuilder(nil)
	for _, v := range vulns {
		_ = b.add(v)
	}
	return b.report(target)
}

func parseReport(target string, data []byte) (Report, error) {
	return readReport(target, bytes.NewReader(data), defaultLimits)
}

// fakeDocker writes an executable that stands in for the docker CLI: a shell script with body. It
// answers `docker rm` (the removal after a stopped or failed scan) with success, without running body.
func fakeDocker(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nif [ \"$1\" = rm ]; then exit 0; fi\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// scanAll runs the three scans through the real run (no execFn) against a fake docker.
func scanAll(t *testing.T, body string, lim limits) map[string]error {
	t.Helper()
	plan, files := ubuntuPlan()
	sc := New(fakeDocker(t, body), "", 5*time.Minute)
	sc.lstat = fakeLstat(files)
	sc.lim = lim
	out := map[string]error{}
	_, out["host"] = sc.ScanHost(context.Background(), plan)
	_, out["image"] = sc.ScanImage(context.Background(), "nginx:1")
	_, out["fs"] = sc.ScanFS(context.Background(), t.TempDir(), "x dependencies")
	return out
}

func wantReason(t *testing.T, name string, err error, reason string) {
	t.Helper()
	var oe *outputError
	if !errors.As(err, &oe) || oe.reason != reason {
		t.Errorf("%s: err = %v; want the reason %q", name, err, reason)
	}
	if err != nil && strings.Contains(err.Error(), "unexpected end of JSON input") {
		t.Errorf("%s: a bare JSON error must not reach the operator: %v", name, err)
	}
}

// The production report: the scanner exits 0 and writes nothing.
func TestScanNoOutputIsExplicit(t *testing.T) {
	for _, body := range []string{"exit 0", "echo; echo '  '"} {
		for name, err := range scanAll(t, body, limits{}) {
			wantReason(t, name+" ("+body+")", err, "the scanner returned no output")
		}
	}
	// The same through the execFn seam.
	plan, files := ubuntuPlan()
	_, err := testScanner(files, nil, nil, nil).ScanHost(context.Background(), plan)
	wantReason(t, "seam", err, "the scanner returned no output")
}

// A scanner that fails says why with its exit status and stderr, whatever it wrote to stdout.
func TestScanExitStatusWinsOverOutput(t *testing.T) {
	for _, body := range []string{
		`echo "FATAL db download failed" >&2; exit 3`,
		`printf '{"Results":[{"Target":"x"'; echo "FATAL db download failed" >&2; exit 3`,
		// Not JSON from the first byte: the scanner is still left to finish, so its own error is reported.
		`printf 'Error: x'; sleep 0.3; echo "FATAL db download failed" >&2; exit 3`,
	} {
		for name, err := range scanAll(t, body, limits{}) {
			if err == nil || !strings.Contains(err.Error(), "trivy scan failed: exit status 3: FATAL db download failed") {
				t.Errorf("%s: err = %v; want the exit status and stderr", name, err)
			}
			var oe *outputError
			if errors.As(err, &oe) {
				t.Errorf("%s: a failed scanner is not a report problem: %v", name, err)
			}
		}
	}
}

func TestScanCutOffReportIsExplicit(t *testing.T) {
	full := `{"SchemaVersion":2,"Metadata":{"OS":{"Family":"ubuntu","Name":"24.04"}},"Results":[{"Target":"/host (ubuntu 24.04)","Class":"os-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"a","Severity":"HIGH","Description":"long text"}]}]}`
	// Every proper prefix is a cut-off report (or, when only white space is left, no output).
	for cut := 1; cut < len(full); cut++ {
		_, err := readHostReport(strings.NewReader(full[:cut]), defaultLimits, nil, nil, true)
		wantReason(t, fmt.Sprintf("cut at %d", cut), err, "the scan report is incomplete")
		_, err = readReport("x", strings.NewReader(full[:cut]), defaultLimits)
		wantReason(t, fmt.Sprintf("image cut at %d", cut), err, "the scan report is incomplete")
	}
	if _, err := readHostReport(strings.NewReader(full), defaultLimits, nil, nil, true); err != nil {
		t.Fatalf("the whole report: %v", err)
	}
	// Through the real run.
	f := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(f, []byte(full[:len(full)-40]), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, err := range scanAll(t, "cat '"+f+"'", limits{}) {
		wantReason(t, name, err, "the scan report is incomplete")
		if err != nil && !strings.Contains(err.Error(), fmt.Sprintf("it ends after %d bytes", len(full)-40)) {
			t.Errorf("%s: the log line names where the report ends: %v", name, err)
		}
	}
}

func TestScanInvalidReportIsExplicit(t *testing.T) {
	for in, reason := range map[string]string{
		`Error: something`:                    "the scan report is not valid JSON",
		`{"Results":[]} trailing`:             "the scan report is not valid JSON",
		`{"Results":[]}{"Results":[]}`:        "the scan report is not valid JSON",
		`{"Results":[{"Target":"x",]}`:        "the scan report is not valid JSON",
		`[]`:                                  "the scan report is not in the format Mooring reads",
		`"report"`:                            "the scan report is not in the format Mooring reads",
		`{"Results":{}}`:                      "the scan report is not in the format Mooring reads",
		`{"Results":[{"Target":7}]}`:          "the scan report is not in the format Mooring reads",
		`{"Results":[{"Vulnerabilities":3}]}`: "the scan report is not in the format Mooring reads",
		`{"Results":[{"Vulnerabilities":[{"Severity":3133731337}]}]}`: "the scan report is not in the format Mooring reads",
	} {
		_, err := readHostReport(strings.NewReader(in), defaultLimits, nil, nil, true)
		wantReason(t, in, err, reason)
	}
}

// What json.Unmarshal accepted before is still accepted: nulls, keys in any order, unknown keys of any
// size, a repeated target.
func TestDecodeTrivyShapes(t *testing.T) {
	bins := []HostBinary{{Label: "caddy", Path: "/usr/bin/caddy"}}
	in := `
	{"Extra":{"deep":[1,{"x":[null,true,"s"]}]},
	 "Results":[
	  {"Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"a","Severity":"HIGH","FixedVersion":"2"}],"Packages":[{"Name":"a"}],"Class":"os-pkgs","Target":"/host (ubuntu 24.04)"},
	  {"Target":"usr/bin/caddy","Class":"lang-pkgs","Vulnerabilities":null},
	  {"Target":"usr/bin/caddy","Class":"lang-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-2","PkgName":"stdlib","Severity":"LOW"}]},
	  {"Target":"usr/bin/caddy","Class":"lang-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-3","PkgName":"stdlib","Severity":"CRITICAL","FixedVersion":"1.25"}]},
	  {"Class":"os-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-4","PkgName":"b","Severity":"MEDIUM"}]}
	 ],
	 "Metadata":{"ImageConfig":{"history":[{"a":1}]},"OS":{"Family":"ubuntu","Name":"24.04","EOSL":true},"Size":3}}
	`
	h, err := readHostReport(strings.NewReader(in), defaultLimits, bins, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if h.OS != "ubuntu 24.04" || !h.EOSL || len(h.Reports) != 2 {
		t.Fatalf("host = %+v", h)
	}
	osRep, caddy := h.Reports[0], h.Reports[1]
	if osRep.High != 1 || osRep.Medium != 1 || osRep.FixableHigh != 1 || len(osRep.Top) != 2 || osRep.Top[0].ID != "CVE-1" || !osRep.fixablePkgs["a"] {
		t.Errorf("OS report = %+v", osRep)
	}
	if caddy.Target != "caddy" || caddy.Critical != 1 || caddy.Low != 1 || len(caddy.Top) != 2 || caddy.Top[0].ID != "CVE-3" {
		t.Errorf("results of one target must be merged: %+v", caddy)
	}
	if crit, ok := caddy.fixableHC["CVE-3|stdlib"]; !ok || !crit {
		t.Errorf("a merged result keeps its fixable identities: %v", caddy.fixableHC)
	}
	for _, in := range []string{`{}`, `{"Results":null,"Metadata":null}`, `{"Metadata":{"OS":null},"Results":[]}` + "\n\n"} {
		h, err := readHostReport(strings.NewReader(in), defaultLimits, nil, nil, true)
		if err != nil || h.OS != "" || len(h.Reports) != 1 || h.Reports[0].Error == "" {
			t.Errorf("%s: %+v, %v; want an OS report that was not scanned", in, h, err)
		}
	}
}

// reportGen writes a valid `trivy rootfs` report of any size without holding it.
type reportGen struct {
	w        *bufio.Writer
	written  int64
	first    bool
	want     Report // the expected OS totals
	pad      string
	packages int // entries of a Packages array Mooring doesn't read
}

func (g *reportGen) printf(format string, a ...any) {
	n, _ := fmt.Fprintf(g.w, format, a...)
	g.written += int64(n)
}

func (g *reportGen) open() {
	g.first = true
	g.pad = strings.Repeat("An issue was discovered in the Linux kernel. ", 80)
	g.printf(`{"SchemaVersion":2,"ArtifactName":"/host","Metadata":{"OS":{"Family":"ubuntu","Name":"24.04"}},"Results":[{"Target":"/host (ubuntu 24.04)","Class":"os-pkgs","Type":"ubuntu","Packages":[`)
	for i := 0; i < g.packages; i++ {
		if i > 0 {
			g.printf(",")
		}
		g.printf(`{"ID":"pkg%d@1.0","Name":"pkg%d","InstalledFiles":["/usr/bin/a%d","/usr/share/doc/a%d"]}`, i, i, i, i)
	}
	g.printf(`],"Vulnerabilities":[`)
}

// finding writes one finding the way Trivy does: the fields Mooring reads plus the bulk it doesn't.
func (g *reportGen) finding(i int) {
	sev := []string{"MEDIUM", "LOW", "MEDIUM", "HIGH", "MEDIUM", "CRITICAL", "LOW", "UNKNOWN"}[i%8]
	fixed := ""
	if i%3 == 0 {
		fixed = "6.8.0-60.63"
	}
	if !g.first {
		g.printf(",")
	}
	g.first = false
	g.printf(`{"VulnerabilityID":"CVE-2026-%d","PkgID":"linux-image@6.8.0","PkgName":"linux-image-6.8.0-%d-generic","InstalledVersion":"6.8.0-49.49","FixedVersion":%q,"Status":"affected","Severity":%q,"Title":"kernel: finding %d","PrimaryURL":"https://avd.aquasec.com/nvd/cve-2026-%d","Description":%q,"CVSS":{"nvd":{"V3Score":5.5}},"References":[`,
		i, i%6, fixed, sev, i, i, g.pad)
	for r := 0; r < 20; r++ {
		if r > 0 {
			g.printf(",")
		}
		g.printf(`"https://git.kernel.org/stable/c/%040d"`, i*100+r)
	}
	g.printf(`]}`)
	fix := 0
	if fixed != "" {
		fix = 1
	}
	switch sev {
	case "CRITICAL":
		g.want.Critical++
		g.want.FixableCritical += fix
	case "HIGH":
		g.want.High++
		g.want.FixableHigh += fix
	case "MEDIUM":
		g.want.Medium++
		g.want.FixableMedium += fix
	case "LOW":
		g.want.Low++
		g.want.FixableLow += fix
	}
}

func (g *reportGen) close() {
	g.printf(`]}]}` + "\n")
	_ = g.w.Flush()
}

func checkTotals(t *testing.T, h HostScan, want Report) {
	t.Helper()
	if h.OS != "ubuntu 24.04" || len(h.Reports) != 1 {
		t.Fatalf("host = %+v", h)
	}
	got := h.Reports[0]
	if got.Critical != want.Critical || got.High != want.High || got.Medium != want.Medium || got.Low != want.Low ||
		got.FixableCritical != want.FixableCritical || got.FixableHigh != want.FixableHigh ||
		got.FixableMedium != want.FixableMedium || got.FixableLow != want.FixableLow {
		t.Errorf("totals = %+v; want %+v", got, want)
	}
	if want.Critical == 0 || want.Low == 0 || want.FixableHigh == 0 {
		t.Fatal("the generated report must have findings of every kind")
	}
	if len(got.Top) != maxTop || got.Top[0].Severity != sevCritical || got.Top[0].Fixed == "" {
		t.Errorf("Top = %d findings, first %+v; want the worst %d, a fixable Critical first", len(got.Top), got.Top[0], maxTop)
	}
	if len(got.fixableHC) != want.FixableCritical+want.FixableHigh {
		t.Errorf("fixable High/Critical identities = %d; want %d", len(got.fixableHC), want.FixableCritical+want.FixableHigh)
	}
}

// The second production case: a valid report larger than the old 32 MiB stdout cap, as an Ubuntu host
// with several kernel packages produces. It must decode, and without being held in memory: the peak of
// live heap while decoding stays far below the report's size.
func TestLargeHostReportDecodesInBoundedMemory(t *testing.T) {
	const oldCap = 32 << 20
	for _, size := range []int64{oldCap - 1<<20, oldCap + 16<<20} {
		t.Run(fmt.Sprintf("%dMiB", size>>20), func(t *testing.T) {
			pr, pw := io.Pipe()
			gen := &reportGen{w: bufio.NewWriterSize(pw, 64<<10), packages: 20000}
			var base, peak uint64
			sample := func() uint64 {
				runtime.GC()
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				return m.HeapAlloc
			}
			base = sample()
			done := make(chan struct{})
			go func() {
				defer close(done)
				gen.open()
				next := int64(4 << 20)
				for i := 0; gen.written < size; i++ {
					gen.finding(i)
					if gen.written >= next {
						next += 4 << 20
						_ = gen.w.Flush()
						if h := sample(); h > peak {
							peak = h
						}
					}
				}
				gen.close()
				_ = pw.Close()
			}()
			h, err := readHostReport(pr, defaultLimits, nil, nil, true)
			_, _ = io.Copy(io.Discard, pr)
			<-done
			if err != nil {
				t.Fatalf("a valid %d-byte report: %v", gen.written, err)
			}
			if gen.written < size {
				t.Fatalf("generated %d bytes; want at least %d", gen.written, size)
			}
			checkTotals(t, h, gen.want)
			grown := int64(peak) - int64(base)
			t.Logf("report %d bytes, %d findings; live heap grew by at most %d bytes while decoding", gen.written, h.Total(), grown)
			if limit := int64(8 << 20); grown > limit {
				t.Errorf("live heap grew by %d bytes decoding a %d-byte report; want under %d (the report must not be held)", grown, gen.written, limit)
			}
		})
	}
}

// The same through the real run: what failed in production with "unexpected end of JSON input".
func TestScanHostReportOverOldCap(t *testing.T) {
	f := filepath.Join(t.TempDir(), "report.json")
	fh, err := os.Create(f)
	if err != nil {
		t.Fatal(err)
	}
	gen := &reportGen{w: bufio.NewWriter(fh)}
	gen.open()
	for i := 0; gen.written < 34<<20; i++ {
		gen.finding(i)
	}
	gen.close()
	if err := fh.Close(); err != nil {
		t.Fatal(err)
	}
	plan, files := ubuntuPlan()
	plan.Binaries = nil
	sc := New(fakeDocker(t, "cat '"+f+"'"), "", 5*time.Minute)
	sc.lstat = fakeLstat(files)
	h, err := sc.ScanHost(context.Background(), plan)
	if err != nil {
		t.Fatalf("a valid %d-byte report: %v", gen.written, err)
	}
	checkTotals(t, h, gen.want)
	rep, err := sc.ScanImage(context.Background(), "nginx:1")
	if err != nil || rep.Total() != h.Total() {
		t.Errorf("image scan of the same report: %d findings, %v; want %d", rep.Total(), err, h.Total())
	}
}

// A report past the limit is refused with the limit in the text, and the scanner is stopped rather
// than left writing until the timeout.
func TestScanReportOverLimitStopsTheScanner(t *testing.T) {
	lim := limits{report: 2 << 20, entry: 64 << 10, kept: 1 << 20}
	body := `printf '{"Results":[{"Target":"/host","Class":"os-pkgs","Vulnerabilities":['
exec yes '{"VulnerabilityID":"CVE-1","PkgName":"a","Severity":"LOW","Description":"an endless report"},'`
	start := time.Now()
	for name, err := range scanAll(t, body, lim) {
		wantReason(t, name, err, "the scan report is larger than 2 MiB")
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Errorf("three endless scans took %v; the scanner must be stopped at the limit", d)
	}
	if r := errReportTooLarge(defaultLimits).Error(); r != "the scan report is larger than 1024 MiB" {
		t.Errorf("default limit text = %q", r)
	}
}

func TestReportLimitIsExact(t *testing.T) {
	in := `{"Results":[]}`
	lim := limits{report: int64(len(in)), entry: 1 << 20, kept: 1 << 20}
	if _, err := readReport("x", strings.NewReader(in), lim); err != nil {
		t.Errorf("a report of exactly the limit: %v", err)
	}
	lim.report--
	_, err := readReport("x", strings.NewReader(in), lim)
	var oe *outputError
	if !errors.As(err, &oe) || !oe.limit || !strings.HasPrefix(oe.reason, "the scan report is larger than") {
		t.Errorf("one byte over the limit: %v", err)
	}
}

// One value can't make the decoder hold more than the entry limit, whether Mooring reads it or skips it.
func TestScanEntryLimit(t *testing.T) {
	lim := limits{report: 64 << 20, entry: 1 << 20, kept: 1 << 20}
	big := strings.Repeat("x", 3<<20)
	for name, in := range map[string]string{
		"finding":       `{"Results":[{"Target":"t","Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"LOW","Description":"` + big + `"}]}]}`,
		"skipped value": `{"Results":[{"Target":"t","Packages":[{"Name":"` + big + `"}]}]}`,
		"target":        `{"Results":[{"Target":"` + big + `"}]}`,
		"key":           `{"` + big + `":1}`,
	} {
		_, err := readHostReport(strings.NewReader(in), lim, nil, nil, true)
		wantReason(t, name, err, "one entry of the scan report is larger than 1 MiB")
	}
	// A skipped value made of many small ones is not one entry.
	in := `{"Results":[{"Target":"t","Packages":[` + strings.TrimSuffix(strings.Repeat(`{"Name":"p","Files":["a","b"]},`, 100000), ",") + `]}]}`
	if int64(len(in)) < 2*lim.entry {
		t.Fatal("the package list must be larger than the entry limit")
	}
	if _, err := readHostReport(strings.NewReader(in), lim, nil, nil, true); err != nil {
		t.Errorf("a large skipped array of small values: %v", err)
	}
}

// What is kept while aggregating is bounded too: identities of fixable High/Critical findings and
// result targets grow with a hostile report.
func TestScanKeptLimit(t *testing.T) {
	lim := limits{report: 64 << 20, entry: 1 << 20, kept: 256 << 10}
	var ids, targets strings.Builder
	ids.WriteString(`{"Results":[{"Target":"t","Class":"os-pkgs","Vulnerabilities":[`)
	targets.WriteString(`{"Results":[`)
	for i := 0; i < 20000; i++ {
		if i > 0 {
			ids.WriteByte(',')
			targets.WriteByte(',')
		}
		fmt.Fprintf(&ids, `{"VulnerabilityID":"CVE-%d","PkgName":"pkg-%d","Severity":"HIGH","FixedVersion":"2"}`, i, i)
		fmt.Fprintf(&targets, `{"Target":"usr/bin/tool-%d","Class":"lang-pkgs"}`, i)
	}
	ids.WriteString(`]}]}`)
	targets.WriteString(`]}`)
	for name, in := range map[string]string{"identities": ids.String(), "targets": targets.String()} {
		_, err := readHostReport(strings.NewReader(in), lim, nil, nil, true)
		wantReason(t, name, err, "the scan report has more findings than Mooring keeps (0 MiB)")
	}
	if r := errTooManyFindings(defaultLimits.kept).Error(); r != "the scan report has more findings than Mooring keeps (32 MiB)" {
		t.Errorf("default limit text = %q", r)
	}
	// Findings that are only counted cost nothing once dropped from the worst-25 candidates.
	var low strings.Builder
	low.WriteString(`{"Results":[{"Target":"t","Class":"os-pkgs","Vulnerabilities":[`)
	for i := 0; i < 20000; i++ {
		if i > 0 {
			low.WriteByte(',')
		}
		fmt.Fprintf(&low, `{"VulnerabilityID":"CVE-%d","PkgName":"pkg-%d","Severity":"LOW","Title":"a title of some length %d"}`, i, i, i)
	}
	low.WriteString(`]}]}`)
	h, err := readHostReport(strings.NewReader(low.String()), lim, nil, nil, true)
	if err != nil || h.Low != 20000 {
		t.Errorf("20000 unfixable Low findings: low=%d, %v; want them counted within the kept limit", h.Low, err)
	}
}

// naiveReport is the aggregation before streaming: sort every finding, keep the first maxTop.
func naiveTop(vulns []trivyVuln) []Vuln {
	var all []Vuln
	for _, v := range vulns {
		sev := strings.ToUpper(strings.TrimSpace(v.Severity))
		if sevRank(sev) == 0 {
			continue
		}
		all = append(all, Vuln{ID: v.VulnerabilityID, Package: v.PkgName, Installed: v.InstalledVersion,
			Fixed: strings.TrimSpace(v.FixedVersion), Severity: sev, Title: v.Title, URL: v.PrimaryURL})
	}
	sort.SliceStable(all, func(i, j int) bool {
		if ri, rj := sevRank(all[i].Severity), sevRank(all[j].Severity); ri != rj {
			return ri > rj
		}
		return all[i].Fixed != "" && all[j].Fixed == ""
	})
	if len(all) > maxTop {
		all = all[:maxTop]
	}
	return all
}

// Dropping candidates early and merging results must give exactly the list a full sort gives.
func TestReportBuilderTopMatchesFullSort(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	sevs := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "low", "UNKNOWN", " high "}
	for round := 0; round < 200; round++ {
		n := rng.Intn(6 * topSlack)
		var vulns []trivyVuln
		for i := 0; i < n; i++ {
			v := trivyVuln{VulnerabilityID: fmt.Sprintf("CVE-%d", i), PkgName: fmt.Sprintf("p%d", rng.Intn(9)), Severity: sevs[rng.Intn(len(sevs))]}
			if rng.Intn(3) == 0 {
				v.FixedVersion = "1.1"
			}
			vulns = append(vulns, v)
		}
		want := naiveTop(vulns)
		if got := buildReport("t", vulns).Top; !reflect.DeepEqual(got, want) && (len(got) != 0 || len(want) != 0) {
			t.Fatalf("round %d (%d findings): Top differs from a full sort\n got %v\nwant %v", round, n, got, want)
		}
		// The same findings split over several results of one target.
		kept := newBudget(limits{kept: 1 << 30})
		all := newReportBuilder(kept)
		for start := 0; start < n; {
			end := start + 1 + rng.Intn(2*topSlack)
			if end > n {
				end = n
			}
			part := newReportBuilder(kept)
			for _, v := range vulns[start:end] {
				if err := part.add(v); err != nil {
					t.Fatal(err)
				}
			}
			all.merge(part)
			start = end
		}
		rep := all.report("t")
		if !reflect.DeepEqual(rep.Top, want) && (len(rep.Top) != 0 || len(want) != 0) {
			t.Fatalf("round %d: merged Top differs from a full sort\n got %v\nwant %v", round, rep.Top, want)
		}
		whole := buildReport("t", vulns)
		if rep.Total() != whole.Total() || rep.Fixable() != whole.Fixable() || !reflect.DeepEqual(rep.fixableHC, whole.fixableHC) || !reflect.DeepEqual(rep.fixablePkgs, whole.fixablePkgs) {
			t.Fatalf("round %d: merged counts or identities differ", round)
		}
		// Only the kept list and the identities still count against the budget.
		var held int64
		for _, v := range rep.Top {
			held += vulnCost(v)
		}
		if used := kept.limit - kept.left; used < held || used > held+int64(n+len(vulns))*400 {
			t.Fatalf("round %d: budget used %d for %d held bytes", round, used, held)
		}
	}
}

func TestTailWriterKeepsTheEnd(t *testing.T) {
	w := &tailWriter{max: 10}
	for _, s := range []string{"0123", "456789abc", "", "de", strings.Repeat("x", 25) + "the end.."} {
		if n, err := w.Write([]byte(s)); n != len(s) || err != nil {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	if got := w.String(); got != "xthe end.." {
		t.Errorf("tail = %q; want the last 10 bytes", got)
	}
	// The end of a long stderr is where the scanner's error is.
	body := `i=0; while [ $i -lt 3000 ]; do echo "progress line $i padding padding padding padding" >&2; i=$((i+1)); done; echo "FATAL the real cause" >&2; exit 1`
	for name, err := range scanAll(t, body, limits{}) {
		if err == nil || !strings.HasSuffix(err.Error(), "FATAL the real cause") {
			t.Errorf("%s: err = %.200v; want the end of stderr", name, err)
		}
	}
}
