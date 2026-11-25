package imagescan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

// The parser before the report was decoded as a stream (json.Unmarshal of the whole report, then one
// sort of every finding), kept as the reference: a valid Trivy report must decode exactly as it did.

type wholeTrivyOutput struct {
	Metadata struct {
		OS *trivyOS `json:"OS"`
	} `json:"Metadata"`
	Results []struct {
		Target          string      `json:"Target"`
		Class           string      `json:"Class"`
		Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
	} `json:"Results"`
}

func wholeBuildReport(target string, vulns []trivyVuln) Report {
	rep := Report{Target: target, fixableHC: map[string]bool{}, fixablePkgs: map[string]bool{}}
	for _, v := range vulns {
		sev := strings.ToUpper(strings.TrimSpace(v.Severity))
		fix := 0
		if strings.TrimSpace(v.FixedVersion) != "" {
			fix = 1
		}
		switch sev {
		case sevCritical:
			rep.Critical++
			rep.FixableCritical += fix
		case sevHigh:
			rep.High++
			rep.FixableHigh += fix
		case sevMedium:
			rep.Medium++
			rep.FixableMedium += fix
		case sevLow:
			rep.Low++
			rep.FixableLow += fix
		default:
			continue
		}
		if fix == 1 && (sev == sevCritical || sev == sevHigh) {
			k := v.VulnerabilityID + "|" + v.PkgName
			rep.fixableHC[k] = rep.fixableHC[k] || sev == sevCritical
			rep.fixablePkgs[v.PkgName] = true
		}
	}
	rep.Top = naiveTop(vulns)
	return rep
}

func wholeParseReport(target string, data []byte) (Report, error) {
	var out wholeTrivyOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return Report{}, err
	}
	var all []trivyVuln
	for _, r := range out.Results {
		all = append(all, r.Vulnerabilities...)
	}
	return wholeBuildReport(target, all), nil
}

func wholeParseHostReport(data []byte, bins []HostBinary, binErr map[int]string, hasPkgDB bool) (HostScan, error) {
	var out wholeTrivyOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return HostScan{}, err
	}
	var h HostScan
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
	osRep := wholeBuildReport(OSReportTarget, osVulns)
	switch {
	case h.OS == "":
		osRep.Error = "not scanned: the operating system was not detected"
	case !hasPkgDB:
		osRep.Error = "not scanned: no package database (dpkg or rpm) was found"
	}
	h.Reports = append(h.Reports, osRep)
	used := map[string]bool{}
	for i, b := range bins {
		if e, ok := binErr[i]; ok {
			h.Reports = append(h.Reports, Report{Target: b.Label, Role: b.Role, Error: e})
			continue
		}
		rep := wholeBuildReport(b.Label, byPath[b.Path])
		rep.Role = b.Role
		used[b.Path] = true
		h.Reports = append(h.Reports, rep)
	}
	for _, p := range order {
		if !used[p] {
			h.Reports = append(h.Reports, wholeBuildReport(p, byPath[p]))
		}
	}
	h.sum()
	return h, nil
}

// sameShape levels what is not part of a result: an empty Top list and maps that were never filled.
func sameShape(r Report) Report {
	if len(r.Top) == 0 {
		r.Top = nil
	}
	if r.fixableHC == nil {
		r.fixableHC = map[string]bool{}
	}
	if r.fixablePkgs == nil {
		r.fixablePkgs = map[string]bool{}
	}
	return r
}

func sameShapeHost(h HostScan) HostScan {
	for i := range h.Reports {
		h.Reports[i] = sameShape(h.Reports[i])
	}
	return h
}

var diffBins = []HostBinary{
	{Label: "caddy (system)", Path: "/usr/bin/caddy"}, {Label: "dockerd", Path: "/usr/bin/dockerd"},
	{Label: "mooring", Path: "/usr/local/bin/mooring"},
	{Label: "caddy (Mooring-owned build)", Path: "/var/lib/mooring/bin/caddy", Role: RoleOwnedCaddy},
}

// differs describes how the stream decoder and the reference disagree on data, "" when they don't:
// one accepts what the other refuses, or both accept and the results differ.
func differs(data []byte) string {
	binErr := map[int]string{1: "not scanned: x"}
	or, oerr := wholeParseReport("T", data)
	nr, nerr := readReport("T", bytes.NewReader(data), defaultLimits)
	oh, oherr := wholeParseHostReport(data, diffBins, binErr, true)
	nh, nherr := readHostReport(bytes.NewReader(data), defaultLimits, diffBins, binErr, true)
	switch {
	case (oerr == nil) != (nerr == nil) || (oherr == nil) != (nherr == nil):
		return fmt.Sprintf("accepted by one only: reference image=%v host=%v, stream image=%v host=%v", oerr, oherr, nerr, nherr)
	case oerr != nil:
		return ""
	case !reflect.DeepEqual(sameShape(or), sameShape(nr)):
		return fmt.Sprintf("image report: reference %+v, stream %+v", or, nr)
	case !reflect.DeepEqual(sameShapeHost(oh), sameShapeHost(nh)):
		return fmt.Sprintf("host report: reference %+v, stream %+v", oh, nh)
	case !reflect.DeepEqual(hostFindings(oh.Reports), hostFindings(nh.Reports)):
		return "host alert identities differ"
	}
	return ""
}

func TestStreamDecoderMatchesWholeReportParser(t *testing.T) {
	if d := differs(loadFixture(t)); d != "" {
		t.Errorf("the real Trivy report: %s", d)
	}
	deep := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	finding := `{"VulnerabilityID":"CVE-1","PkgName":"p","Severity":"HIGH","FixedVersion":"1"}`
	same := map[string]string{
		"empty object":            `{}`,
		"results null":            `{"Results":null}`,
		"results empty":           `{"Results":[]}`,
		"no results":              `{"SchemaVersion":2,"Metadata":{"OS":{"Family":"ubuntu","Name":"24.04"}}}`,
		"vulns null":              `{"Results":[{"Target":"x","Class":"os-pkgs","Vulnerabilities":null}]}`,
		"vulns missing":           `{"Results":[{"Target":"usr/bin/caddy","Class":"lang-pkgs","Type":"gobinary"}]}`,
		"null elements":           `{"Results":[null,{"Target":"a","Class":"os-pkgs","Vulnerabilities":[null]}]}`,
		"results before meta":     `{"Results":[{"Target":"t","Class":"os-pkgs","Vulnerabilities":[` + finding + `]}],"Metadata":{"OS":{"Family":"debian","Name":"12","EOSL":true}}}`,
		"meta null":               `{"Metadata":null,"Results":[]}`,
		"os null":                 `{"Metadata":{"OS":null,"ImageConfig":{"a":[1,2,{"b":null}]}},"Results":[]}`,
		"os none":                 `{"Metadata":{"OS":{"Family":"none"}},"Results":[]}`,
		"unknown values":          `{"X":{"a":[[[{"k":[1,"s",true,null,1e400,-0.5]}]]]},"Results":[{"Target":"t","Class":"os-pkgs","Packages":[{"Name":"a","InstalledFiles":["/x"]}],"Vulnerabilities":[{"VulnerabilityID":"CVE-2","PkgName":"q","Severity":"critical","FixedVersion":" 2 ","CVSS":{"nvd":{"V3Score":9.8}},"References":["a","b"],"Layer":{},"DataSource":{"ID":"x"}}],"MisconfSummary":{"Successes":1}}]}`,
		"number out of range":     `{"X":1e400,"Results":[]}`,
		"number of 100000 digits": `{"X":` + strings.Repeat("9", 100000) + `,"Results":[]}`,
		"white space around":      "\n  {\"Results\":[]}\n\n \t\r\n",
		"byte order mark":         "\xef\xbb\xbf{\"Results\":[]}",
		"two reports":             "{\"Results\":[]}\n{\"Results\":[]}\n",
		"trailing text":           `{"Results":[]} x`,
		"trailing brace":          `{"Results":[]}}`,
		"top array":               `[]`,
		"top string":              `"x"`,
		"top number":              `5`,
		"repeated target":         `{"Results":[{"Target":"a","Target":"usr/bin/caddy","Class":"x","Class":"lang-pkgs","Vulnerabilities":[` + finding + `]}]}`,
		"repeated metadata":       `{"Metadata":{"OS":{"Family":"ubuntu","Name":"1"}},"Metadata":{"OS":{"Name":"2"}},"Results":[]}`,
		"repeated os":             `{"Metadata":{"OS":{"Family":"ubuntu","Name":"1"},"OS":{"Name":"2"}},"Results":[]}`,
		"repeated os, null":       `{"Metadata":{"OS":{"Family":"ubuntu","Name":"1"},"OS":null},"Results":[]}`,
		"repeated metadata, null": `{"Metadata":{"OS":{"Family":"ubuntu","Name":"1"}},"Metadata":null,"Results":[]}`,
		"severity number":         `{"Results":[{"Target":"a","Vulnerabilities":[{"Severity":5}]}]}`,
		"target number":           `{"Results":[{"Target":5}]}`,
		"eosl string":             `{"Metadata":{"OS":{"Family":"u","EOSL":"true"}}}`,
		"os string":               `{"Metadata":{"OS":"ubuntu"}}`,
		"metadata array":          `{"Metadata":[]}`,
		"results object":          `{"Results":{}}`,
		"vulns object":            `{"Results":[{"Vulnerabilities":{}}]}`,
		"result is an array":      `{"Results":[[]]}`,
		"finding is a string":     `{"Results":[{"Vulnerabilities":["x"]}]}`,
		"trailing comma":          `{"Results":[{"Target":"a"},]}`,
		"missing comma":           `{"Results":[] "X":1}`,
		"skipped: missing comma":  `{"X":[1 2],"Results":[]}`,
		"skipped: bad object":     `{"X":{"a":1 "b":2},"Results":[]}`,
		"skipped: number key":     `{"X":{1:2},"Results":[]}`,
		"skipped: mismatched":     `{"X":[1,2},"Results":[]}`,
		"skipped: bad literal":    `{"X":tru,"Results":[]}`,
		"skipped: bad number":     `{"X":01,"Results":[]}`,
		"skipped: bad escape":     `{"X":"\q","Results":[]}`,
		"invalid utf-8":           "{\"X\":\"\xff\xfe\",\"Results\":[{\"Target\":\"\xff\",\"Class\":\"os-pkgs\",\"Vulnerabilities\":[{\"VulnerabilityID\":\"\xffCVE\",\"PkgName\":\"p\xc0\",\"Severity\":\"HIGH\",\"FixedVersion\":\"1\"}]}]}",
		"lone surrogate":          `{"Results":[{"Target":"\ud800","Class":"os-pkgs","Vulnerabilities":[{"VulnerabilityID":"\udc00","PkgName":"p","Severity":"HIGH","FixedVersion":"1"}]}]}`,
		"empty key":               `{"":{"":[]},"Results":[]}`,
		"cut off":                 `{"Results":[{"Target":"a"}]`,
		"skipped: nested 500":     `{"X":` + deep(500) + `,"Results":[]}`,
		"skipped: nested 10001":   `{"X":` + deep(10001) + `,"Results":[]}`,
		"finding: nested 10001":   `{"Results":[{"Vulnerabilities":[{"Severity":"HIGH","Z":` + deep(10001) + `}]}]}`,
		"host paths":              `{"Metadata":{"OS":{"Family":"ubuntu","Name":"24.04"}},"Results":[{"Target":"/host/usr/bin/caddy","Class":"lang-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"stdlib","Severity":"CRITICAL","FixedVersion":"1.2"}]},{"Target":"usr/bin/caddy","Class":"lang-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"stdlib","Severity":"HIGH","FixedVersion":"1.2"}]},{"Target":"opt/other","Class":"lang-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-3","PkgName":"x","Severity":"LOW"}]},{"Target":"usr/bin/dockerd","Class":"lang-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-4","PkgName":"y","Severity":"HIGH","FixedVersion":"9"}]},{"Target":"ubuntu","Class":"os-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-5","PkgName":"libc","Severity":"HIGH","FixedVersion":"9"}]},{"Target":"ubuntu2","Class":"os-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-5","PkgName":"libc","Severity":"CRITICAL","FixedVersion":"9"}]}]}`,
	}
	for name, in := range same {
		if d := differs([]byte(in)); d != "" {
			t.Errorf("%s: %.600s", name, d)
		}
	}
	// The decided differences (TestDecodeTrivyDecidedBehaviour, the depth limit): if one of these
	// stops differing, a decision was undone.
	for name, in := range map[string]string{
		"top-level null":           `null`,
		"keys in another case":     `{"results":[{"Target":"a","Class":"os-pkgs","Vulnerabilities":[` + finding + `]}]}`,
		"repeated Results":         `{"Results":[{"Target":"a","Class":"os-pkgs","Vulnerabilities":[` + finding + `]}],"Results":[]}`,
		"repeated Vulnerabilities": `{"Results":[{"Target":"a","Class":"os-pkgs","Vulnerabilities":[` + finding + `],"Vulnerabilities":[]}]}`,
		"nested 513 to 10000":      `{"X":` + deep(9000) + `,"Results":[]}`,
	} {
		if differs([]byte(in)) == "" {
			t.Errorf("%s: decodes as the whole-report parser did; the difference is decided behaviour", name)
		}
	}
}

func genFinding(r *rand.Rand) map[string]any {
	sevs := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "high", " Critical ", "", "NEGLIGIBLE"}
	fixed := []string{"", "", "1.2.3", " ", " 2.0 ", "9"}
	v := map[string]any{
		"VulnerabilityID":  fmt.Sprintf("CVE-%d", r.Intn(40)),
		"PkgName":          fmt.Sprintf("pkg%d", r.Intn(12)),
		"InstalledVersion": fmt.Sprintf("%d.0", r.Intn(5)),
		"Severity":         sevs[r.Intn(len(sevs))],
		"Title":            strings.Repeat("t", r.Intn(30)),
		"Description":      strings.Repeat("d", r.Intn(500)) + ` [see {the} "advisory"] \`,
		"References":       []string{"http://a", "http://b"},
		"CVSS":             map[string]any{"nvd": map[string]any{"V3Score": 7.5}},
	}
	if f := fixed[r.Intn(len(fixed))]; f != "" || r.Intn(2) == 0 {
		v["FixedVersion"] = f
	}
	if r.Intn(3) == 0 {
		v["PrimaryURL"] = "https://avd/" + fmt.Sprint(r.Intn(100))
	}
	return v
}

func genTrivyReport(r *rand.Rand) []byte {
	doc := map[string]any{"SchemaVersion": 2, "ArtifactName": "/host", "ArtifactType": "filesystem"}
	switch r.Intn(5) {
	case 0:
	case 1:
		doc["Metadata"] = map[string]any{"ImageConfig": map[string]any{"architecture": "", "rootfs": map[string]any{"diff_ids": nil}}}
	case 2:
		doc["Metadata"] = map[string]any{"OS": map[string]any{"Family": "none", "Name": ""}}
	default:
		doc["Metadata"] = map[string]any{"OS": map[string]any{"Family": "ubuntu", "Name": "24.04", "EOSL": r.Intn(2) == 0}}
	}
	targets := []string{"ubuntu", "usr/bin/caddy", "/usr/bin/caddy", "/host/usr/bin/dockerd", "usr/local/bin/mooring", "var/lib/mooring/bin/caddy", "opt/x", "", "/host", "Node.js"}
	classes := []string{"os-pkgs", "lang-pkgs", "lang-pkgs", "", "config"}
	if r.Intn(6) != 0 {
		results := []any{}
		for i, n := 0, r.Intn(8); i < n; i++ {
			res := map[string]any{"Target": targets[r.Intn(len(targets))], "Class": classes[r.Intn(len(classes))], "Type": "gobinary"}
			nv := []int{0, r.Intn(5), r.Intn(60), topSlack - 10 + r.Intn(30), r.Intn(400)}[r.Intn(5)]
			switch {
			case nv == 0 && r.Intn(3) == 0:
				res["Vulnerabilities"] = nil
			case nv == 0 && r.Intn(2) == 0:
			default:
				vs := make([]any, nv)
				for j := range vs {
					vs[j] = genFinding(r)
				}
				res["Vulnerabilities"] = vs
			}
			results = append(results, res)
		}
		doc["Results"] = results
	}
	var b []byte
	if r.Intn(2) == 0 {
		b, _ = json.MarshalIndent(doc, "", "  ")
	} else {
		b, _ = json.Marshal(doc)
	}
	return b
}

// Generated reports in Trivy's layout, compact and indented, with results around the size where the
// worst-25 candidates are compacted.
func TestStreamDecoderMatchesWholeReportParserGenerated(t *testing.T) {
	rounds := 600
	if testing.Short() {
		rounds = 200
	}
	r := rand.New(rand.NewSource(20261125))
	names := map[bool]int{}
	for i := 0; i < rounds; i++ {
		data := genTrivyReport(r)
		if d := differs(data); d != "" {
			t.Fatalf("generated report %d: %.600s\n input=%.300q", i, d, data)
		}
		_, err := wholeParseReport("T", data)
		names[err == nil]++
	}
	if names[true] != rounds {
		t.Fatalf("%d of %d generated reports were valid; want all", names[true], rounds)
	}
}
