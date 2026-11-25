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
	"io"
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

// trivyOS is Trivy's Metadata.OS: set when it detected the operating system, with EOSL true (omitted
// when false) for a release past its end of support.
type trivyOS struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
	EOSL   bool   `json:"EOSL"`
}

// trivyResult is one entry of Trivy's Results with its findings already aggregated. Class is
// "os-pkgs" for the OS package result and "lang-pkgs" for language packages (a Go binary among them).
type trivyResult struct {
	Target string
	Class  string
	vulns  *reportBuilder
}

const maxTop = 25

// readReport aggregates one Trivy JSON report read from r into a Report for target. Unknown
// severities are ignored; the Top list is worst-first and capped.
func readReport(target string, r io.Reader, lim limits) (Report, error) {
	kept := newBudget(lim)
	all := newReportBuilder(kept)
	_, err := decodeTrivy(r, lim, kept, func(res trivyResult) error {
		all.merge(res.vulns)
		return nil
	})
	if err != nil {
		return Report{}, err
	}
	return all.report(target), nil
}

// topSlack is how many findings a reportBuilder holds before it sorts them and drops all but maxTop.
const topSlack = 4 * maxTop

// reportBuilder aggregates one target's findings as they are decoded, so a report with any number of
// findings costs the counts, the worst maxTop findings and the fixable High/Critical identities — not
// one entry per finding. kept (may be nil) bounds what it holds.
type reportBuilder struct {
	rep  Report
	top  []Vuln // unsorted between compactions; the worst maxTop are always among them
	kept *budget
}

func newReportBuilder(kept *budget) *reportBuilder {
	return &reportBuilder{kept: kept, rep: Report{fixableHC: map[string]bool{}, fixablePkgs: map[string]bool{}}}
}

// add counts one finding by severity (and whether it has a fixed version), keeps the identity of a
// fixable High/Critical one, and holds it as a candidate for the worst maxTop. A finding with an
// unknown severity is ignored.
func (b *reportBuilder) add(v trivyVuln) error {
	sev := strings.ToUpper(strings.TrimSpace(v.Severity))
	fixed := strings.TrimSpace(v.FixedVersion)
	fix := 0
	if fixed != "" {
		fix = 1
	}
	rep := &b.rep
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
		return nil
	}
	if fix == 1 && (sev == sevCritical || sev == sevHigh) {
		if err := b.keepIdentity(v.VulnerabilityID+"|"+v.PkgName, v.PkgName, sev == sevCritical); err != nil {
			return err
		}
	}
	return b.hold(Vuln{
		ID: v.VulnerabilityID, Package: v.PkgName, Installed: v.InstalledVersion,
		Fixed: fixed, Severity: sev, Title: v.Title, URL: v.PrimaryURL,
	})
}

func (b *reportBuilder) keepIdentity(id, pkg string, critical bool) error {
	if _, ok := b.rep.fixableHC[id]; !ok {
		if err := b.kept.take(keyCost(id)); err != nil {
			return err
		}
	}
	b.rep.fixableHC[id] = b.rep.fixableHC[id] || critical
	if !b.rep.fixablePkgs[pkg] {
		if err := b.kept.take(keyCost(pkg)); err != nil {
			return err
		}
		b.rep.fixablePkgs[pkg] = true
	}
	return nil
}

func (b *reportBuilder) hold(v Vuln) error {
	if err := b.kept.take(vulnCost(v)); err != nil {
		return err
	}
	b.top = append(b.top, v)
	if len(b.top) >= topSlack {
		b.compact()
	}
	return nil
}

// compact sorts the held findings worst-first (by severity, then fixable first, then the order they
// were added) and drops all but maxTop. Dropping early never changes the final list: a dropped finding
// already has maxTop findings ahead of it.
func (b *reportBuilder) compact() {
	sort.SliceStable(b.top, func(i, j int) bool {
		if ri, rj := sevRank(b.top[i].Severity), sevRank(b.top[j].Severity); ri != rj {
			return ri > rj
		}
		return b.top[i].Fixed != "" && b.top[j].Fixed == ""
	})
	if len(b.top) > maxTop {
		for _, v := range b.top[maxTop:] {
			b.kept.give(vulnCost(v))
		}
		clear(b.top[maxTop:]) // release the dropped findings' strings
		b.top = b.top[:maxTop]
	}
}

// merge adds o's findings after b's own (several Trivy results can belong to one target). Both share
// one budget, which o's findings are already counted against; o is not used afterwards.
func (b *reportBuilder) merge(o *reportBuilder) {
	b.rep.Critical += o.rep.Critical
	b.rep.High += o.rep.High
	b.rep.Medium += o.rep.Medium
	b.rep.Low += o.rep.Low
	b.rep.FixableCritical += o.rep.FixableCritical
	b.rep.FixableHigh += o.rep.FixableHigh
	b.rep.FixableMedium += o.rep.FixableMedium
	b.rep.FixableLow += o.rep.FixableLow
	for id, crit := range o.rep.fixableHC {
		b.rep.fixableHC[id] = b.rep.fixableHC[id] || crit
	}
	for p := range o.rep.fixablePkgs {
		b.rep.fixablePkgs[p] = true
	}
	b.top = append(b.top, o.top...)
	if len(b.top) >= topSlack {
		b.compact()
	}
}

// report is the finished Report for target.
func (b *reportBuilder) report(target string) Report {
	b.compact()
	rep := b.rep
	rep.Target = target
	if len(b.top) > 0 {
		rep.Top = b.top
	}
	return rep
}

// vulnCost and keyCost are what one held finding and one kept identity count against the budget:
// their strings plus a flat allowance for the headers and the map slot.
func vulnCost(v Vuln) int64 {
	return int64(len(v.ID)+len(v.Package)+len(v.Installed)+len(v.Fixed)+len(v.Severity)+len(v.Title)+len(v.URL)) + 128
}

func keyCost(k string) int64 { return int64(len(k)) + 64 }

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
