package imagescan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestParseReportAggregatesAndSorts(t *testing.T) {
	data := []byte(`{
	  "Results": [
	    {"Target": "app (alpine 3.19)", "Vulnerabilities": [
	      {"VulnerabilityID": "CVE-1", "PkgName": "libssl", "InstalledVersion": "1.0", "FixedVersion": "1.1", "Severity": "MEDIUM", "Title": "m", "PrimaryURL": "u1"},
	      {"VulnerabilityID": "CVE-2", "PkgName": "zlib", "InstalledVersion": "2.0", "FixedVersion": "2.1", "Severity": "CRITICAL", "Title": "c", "PrimaryURL": "u2"}
	    ]},
	    {"Target": "package-lock.json (npm)", "Vulnerabilities": [
	      {"VulnerabilityID": "CVE-3", "PkgName": "lodash", "Severity": "HIGH"},
	      {"VulnerabilityID": "CVE-4", "PkgName": "minimist", "Severity": "low"},
	      {"VulnerabilityID": "CVE-5", "PkgName": "x", "Severity": "UNKNOWN"}
	    ]}
	  ]
	}`)
	rep, err := parseReport("credlock-api", data)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Critical != 1 || rep.High != 1 || rep.Medium != 1 || rep.Low != 1 {
		t.Errorf("counts wrong: %+v", rep)
	}
	if rep.Total() != 4 {
		t.Errorf("total = %d, want 4 (UNKNOWN ignored)", rep.Total())
	}
	if !rep.Actionable() {
		t.Error("critical/high present → actionable")
	}
	// Worst-first: CRITICAL then HIGH then MEDIUM then LOW.
	if len(rep.Top) != 4 || rep.Top[0].Severity != "CRITICAL" || rep.Top[1].Severity != "HIGH" {
		t.Errorf("sort wrong: %+v", rep.Top)
	}
}

func TestParseReportClean(t *testing.T) {
	rep, err := parseReport("x", []byte(`{"Results": []}`))
	if err != nil || rep.Total() != 0 || rep.Actionable() {
		t.Errorf("clean scan should be empty/non-actionable: %+v err=%v", rep, err)
	}
}

// Within a severity, findings with a fixed version sort before those without (app reports too),
// and the fixable counts are kept per severity.
func TestParseReportFixableFirstAndCounts(t *testing.T) {
	data := []byte(`{"Results": [{"Target": "x", "Vulnerabilities": [
	  {"VulnerabilityID": "H-nofix", "PkgName": "a", "Severity": "HIGH"},
	  {"VulnerabilityID": "L-fix", "PkgName": "b", "Severity": "LOW", "FixedVersion": "2"},
	  {"VulnerabilityID": "H-fix", "PkgName": "c", "Severity": "HIGH", "FixedVersion": "3"},
	  {"VulnerabilityID": "C-nofix", "PkgName": "d", "Severity": "CRITICAL", "FixedVersion": "  "},
	  {"VulnerabilityID": "C-fix", "PkgName": "e", "Severity": "CRITICAL", "FixedVersion": "4"}
	]}]}`)
	rep, err := parseReport("app", data)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, v := range rep.Top {
		ids = append(ids, v.ID)
	}
	if got := strings.Join(ids, " "); got != "C-fix C-nofix H-fix H-nofix L-fix" {
		t.Errorf("order = %s", got)
	}
	if rep.FixableCritical != 1 || rep.FixableHigh != 1 || rep.FixableMedium != 0 || rep.FixableLow != 1 || rep.Fixable() != 3 {
		t.Errorf("fixable counts wrong: %+v", rep)
	}
}

// The alert identities cover every fixable High/Critical (not only the capped Top list) as
// "ID|Package|ReportTarget", flag the Critical ones, and ignore unfixable and Medium/Low findings.
func TestHostFindings(t *testing.T) {
	mk := func(extra ...trivyVuln) []Report {
		var vs []trivyVuln
		for i := 0; i < 40; i++ { // more than maxTop, all fixable HIGH
			vs = append(vs, trivyVuln{VulnerabilityID: fmt.Sprintf("CVE-%02d", i), PkgName: "p", Severity: "HIGH", FixedVersion: "1"})
		}
		vs = append(vs, extra...)
		return []Report{buildReport(OSReportTarget, vs)}
	}
	if got := mk(); len(got[0].Top) != maxTop || len(got[0].fixableHC) != 40 || len(hostFindings(got)) != 40 {
		t.Fatalf("Top capped at %d but all 40 identities kept: top=%d ids=%d", maxTop, len(got[0].Top), len(got[0].fixableHC))
	}
	f := hostFindings(mk(
		trivyVuln{VulnerabilityID: "N", PkgName: "q", Severity: "HIGH"},                         // no fix
		trivyVuln{VulnerabilityID: "M", PkgName: "q", Severity: "MEDIUM", FixedVersion: "2"},    // not High/Critical
		trivyVuln{VulnerabilityID: "CVE-00", PkgName: "p", Severity: "HIGH", FixedVersion: "1"}, // duplicate
		trivyVuln{VulnerabilityID: "C", PkgName: "z", Severity: "CRITICAL", FixedVersion: "9"},
		trivyVuln{VulnerabilityID: "CVE-01", PkgName: "p", Severity: "CRITICAL", FixedVersion: "1"}, // same identity, worse
	))
	if len(f) != 41 {
		t.Fatalf("want the 40 Highs + one Critical, got %d", len(f))
	}
	if crit, ok := f["C|z|"+OSReportTarget]; !ok || !crit {
		t.Errorf("a fixable Critical is an identity flagged critical: %v %v", crit, ok)
	}
	if !f["CVE-01|p|"+OSReportTarget] || f["CVE-02|p|"+OSReportTarget] {
		t.Error("an identity seen as Critical anywhere is critical; a High stays high")
	}
	moved := mk()
	moved[0].Target = "caddy (system)"
	if _, ok := hostFindings(moved)["CVE-00|p|caddy (system)"]; !ok {
		t.Error("the report target is part of the identity")
	}
	if len(hostFindings(nil)) != 0 {
		t.Error("no reports → no identities")
	}
}

// The dedupe-key signature is 12 hex chars, independent of order, and "" for no identities.
func TestIdentitySig(t *testing.T) {
	a := identitySig([]string{"CVE-1|p|OS packages", "CVE-2|q|caddy (system)"})
	if len(a) != 12 || a != identitySig([]string{"CVE-2|q|caddy (system)", "CVE-1|p|OS packages"}) {
		t.Errorf("signature %q must be 12 hex chars and order-independent", a)
	}
	if a == identitySig([]string{"CVE-1|p|OS packages"}) {
		t.Error("a different set must give a different signature")
	}
	if identitySig(nil) != "" {
		t.Error("no identities → empty signature")
	}
}

// Rows stored before the fixable/role fields existed still decode (the new fields are omitempty and
// zero when absent).
func TestOldAppReportJSONDecodes(t *testing.T) {
	db := testDB(t)
	old := `[{"target":"nginx:1","critical":1,"high":2,"medium":0,"low":0,"top":[{"id":"CVE-1","package":"zlib","installed":"1","fixed":"2","severity":"CRITICAL","title":"t","url":"u"}]}]`
	if _, err := db.Exec(`INSERT INTO image_scans(project, scanned_at, critical, high, medium, low, report_json, error) VALUES('blog', 1, 1, 2, 0, 0, ?, '')`, []byte(old)); err != nil {
		t.Fatal(err)
	}
	got, ok, err := NewStore(db).Get(context.Background(), "blog")
	if err != nil || !ok {
		t.Fatalf("get: %v ok=%v", err, ok)
	}
	if len(got.Reports) != 1 || got.Reports[0].Target != "nginx:1" || got.Reports[0].High != 2 || len(got.Reports[0].Top) != 1 {
		t.Fatalf("old row did not decode: %+v", got.Reports)
	}
	if r := got.Reports[0]; r.FixableCritical != 0 || r.Role != "" || r.Error != "" {
		t.Errorf("absent new fields must be zero: %+v", r)
	}
	// And a new report round-trips its new fields.
	nr := Report{Target: "x", High: 1, FixableHigh: 1, Role: RoleOwnedCaddy}
	b, _ := json.Marshal(nr)
	var back Report
	if err := json.Unmarshal(b, &back); err != nil || back.FixableHigh != 1 || back.Role != RoleOwnedCaddy {
		t.Errorf("round-trip lost fields: %s → %+v (%v)", b, back, err)
	}
	if strings.Contains(string(b), "fixableHC") || strings.Contains(string(b), "fixable_hc") {
		t.Errorf("the signature identities must never be serialized: %s", b)
	}
}
