// Package imagescan runs Trivy to surface known CVEs, WITHOUT ever handing Trivy the Docker socket
// (Mooring's core read-only-socket invariant). App scans: upstream `image:` refs are scanned from the
// REGISTRY (`trivy image`) and build-service checkouts as a filesystem (`trivy fs`) for language
// deps. Host scan: the host's OS package database and the Go binaries Mooring runs are bind-mounted
// read-only into one `trivy rootfs` run. Findings are stored (per app; one row for the host) and
// High/Critical findings raise an alert. On by default, serialized (Trivy is heavy).
package imagescan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// Severity buckets (Trivy's uppercase names).
const (
	sevCritical = "CRITICAL"
	sevHigh     = "HIGH"
	sevMedium   = "MEDIUM"
	sevLow      = "LOW"
)

// Vuln is one finding, trimmed to what the dashboard shows.
type Vuln struct {
	ID        string `json:"id"`
	Package   string `json:"package"`
	Installed string `json:"installed"`
	Fixed     string `json:"fixed"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	URL       string `json:"url"`
}

// Report is the aggregate for one scanned target (an image ref, a checkout, the host's OS packages
// or one host binary). The Fixable* counts are findings with a fixed version. New fields are
// omitempty so rows stored before they existed still decode.
type Report struct {
	Target          string `json:"target"`
	Role            string `json:"role,omitempty"` // HostBinary.Role for a host binary report
	Critical        int    `json:"critical"`
	High            int    `json:"high"`
	Medium          int    `json:"medium"`
	Low             int    `json:"low"`
	FixableCritical int    `json:"fixable_critical,omitempty"`
	FixableHigh     int    `json:"fixable_high,omitempty"`
	FixableMedium   int    `json:"fixable_medium,omitempty"`
	FixableLow      int    `json:"fixable_low,omitempty"`
	Top             []Vuln `json:"top"`             // worst-first, fixable before unfixable, capped
	Error           string `json:"error,omitempty"` // the target was not scanned (a host report only)

	// fixableHC maps "ID|Package" of every fixable High/Critical finding, taken before the Top cap,
	// to whether it is Critical; fixablePkgs holds the Package of each. They feed the host alert and
	// are never stored.
	fixableHC   map[string]bool
	fixablePkgs map[string]bool
}

// trivyVuln is the subset of one Trivy finding we read.
type trivyVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	PrimaryURL       string `json:"PrimaryURL"`
}

// trivyOutput is the subset of Trivy's JSON we read. Class is "os-pkgs" for the OS package result
// and "lang-pkgs" for language packages (Type "gobinary" for a Go binary); Metadata.OS is set when
// Trivy detected the operating system, with EOSL true (omitted when false) for a release past its
// end of support.
type trivyOutput struct {
	Metadata struct {
		OS *struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
			EOSL   bool   `json:"EOSL"`
		} `json:"OS"`
	} `json:"Metadata"`
	Results []struct {
		Target          string      `json:"Target"`
		Class           string      `json:"Class"`
		Type            string      `json:"Type"`
		Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
	} `json:"Results"`
}

const maxTop = 25

// parseReport aggregates Trivy JSON into a Report for target. Unknown severities are
// ignored; the Top list is worst-first and capped.
func parseReport(target string, data []byte) (Report, error) {
	var out trivyOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return Report{}, err
	}
	var all []trivyVuln
	for _, r := range out.Results {
		all = append(all, r.Vulnerabilities...)
	}
	return buildReport(target, all), nil
}

// buildReport counts vulns by severity (and how many have a fixed version), keeps the fixable
// High/Critical identities, and keeps the worst maxTop findings: by severity, then fixable first.
func buildReport(target string, vulns []trivyVuln) Report {
	rep := Report{Target: target}
	var all []Vuln
	hc, pkgs := map[string]bool{}, map[string]bool{}
	for _, v := range vulns {
		sev := strings.ToUpper(strings.TrimSpace(v.Severity))
		fixed := strings.TrimSpace(v.FixedVersion)
		fix := 0
		if fixed != "" {
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
			hc[k] = hc[k] || sev == sevCritical
			pkgs[v.PkgName] = true
		}
		all = append(all, Vuln{
			ID: v.VulnerabilityID, Package: v.PkgName, Installed: v.InstalledVersion,
			Fixed: fixed, Severity: sev, Title: v.Title, URL: v.PrimaryURL,
		})
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
	rep.Top = all
	rep.fixableHC, rep.fixablePkgs = hc, pkgs
	return rep
}

func sevRank(s string) int {
	switch s {
	case sevCritical:
		return 4
	case sevHigh:
		return 3
	case sevMedium:
		return 2
	case sevLow:
		return 1
	}
	return 0
}

// Total is the count of all findings in the report.
func (r Report) Total() int { return r.Critical + r.High + r.Medium + r.Low }

// Fixable is the count of findings that have a fixed version.
func (r Report) Fixable() int {
	return r.FixableCritical + r.FixableHigh + r.FixableMedium + r.FixableLow
}

// Actionable reports whether the report has High or Critical findings (the alert bar).
func (r Report) Actionable() bool { return r.Critical > 0 || r.High > 0 }

// hostFindings maps the identity "ID|Package|ReportTarget" of every fixable High/Critical host
// finding to whether it is Critical.
func hostFindings(reports []Report) map[string]bool {
	out := map[string]bool{}
	for _, r := range reports {
		for id, crit := range r.fixableHC {
			k := id + "|" + r.Target
			out[k] = out[k] || crit
		}
	}
	return out
}

// identitySig is the first 12 hex of the sha256 over the sorted identities, one per line; "" for none.
func identitySig(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	keys := append([]string(nil), ids...)
	sort.Strings(keys)
	sum := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	return hex.EncodeToString(sum[:])[:12]
}
