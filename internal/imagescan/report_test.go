package imagescan

import "testing"

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
