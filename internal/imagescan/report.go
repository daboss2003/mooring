// Package imagescan runs Trivy against a deployed app's images + dependency
// manifests to surface known CVEs, WITHOUT ever handing Trivy the Docker socket
// (Mooring's core read-only-socket invariant): upstream `image:` refs are scanned
// from the REGISTRY (`trivy image`), and build-service checkouts are scanned as a
// filesystem (`trivy fs`) for language deps. Findings are stored per app and
// High/Critical totals raise an alert. OPT-IN + serialized (Trivy is heavy).
package imagescan

import (
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

// Report is the aggregate for one scanned target (an image ref or a checkout).
type Report struct {
	Target   string `json:"target"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Top      []Vuln `json:"top"` // worst-first, capped
}

// trivyOutput is the subset of Trivy's JSON we read.
type trivyOutput struct {
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			PrimaryURL       string `json:"PrimaryURL"`
		} `json:"Vulnerabilities"`
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
	rep := Report{Target: target}
	var all []Vuln
	for _, r := range out.Results {
		for _, v := range r.Vulnerabilities {
			switch strings.ToUpper(v.Severity) {
			case sevCritical:
				rep.Critical++
			case sevHigh:
				rep.High++
			case sevMedium:
				rep.Medium++
			case sevLow:
				rep.Low++
			default:
				continue
			}
			all = append(all, Vuln{
				ID: v.VulnerabilityID, Package: v.PkgName, Installed: v.InstalledVersion,
				Fixed: v.FixedVersion, Severity: strings.ToUpper(v.Severity), Title: v.Title, URL: v.PrimaryURL,
			})
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		return sevRank(all[i].Severity) > sevRank(all[j].Severity)
	})
	if len(all) > maxTop {
		all = all[:maxTop]
	}
	rep.Top = all
	return rep, nil
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

// Actionable reports whether the report has High or Critical findings (the alert bar).
func (r Report) Actionable() bool { return r.Critical > 0 || r.High > 0 }
