package imagescan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
)

// hostScanFailed is what the Server tab shows when a host scan run fails for a reason that is only
// safe in the log (the scanner's stderr).
const hostScanFailed = "the last host scan failed; the Mooring log (journalctl -u mooring) has the cause"

// hostFailure is the Server tab's text for a failed host scan: the reason itself when the scanner ran
// but its report could not be used, else hostScanFailed.
func hostFailure(err error) string {
	var oe *outputError
	if errors.As(err, &oe) {
		return "the last host scan failed: " + oe.reason
	}
	return hostScanFailed
}

// scanHost runs one host scan, stores it, raises the host alerts, hands a fixable Mooring-owned
// Caddy build to the refresh hook, and checks whether the host needs a reboot.
func (r *Runner) scanHost(ctx context.Context) {
	h, err := r.scanner.ScanHost(ctx, r.hostPlan(ctx))
	for _, s := range h.skipped {
		r.log.Warn("imagescan: host path not scanned", "detail", s)
	}
	if err != nil {
		if ctx.Err() != nil {
			return // shutting down: not a scan failure
		}
		r.log.Warn("imagescan: host scan failed", "err", err)
		// Keep the last completed scan's findings (and its time) next to the error rather than
		// blanking them. A row without reports is an earlier failure, not a result: it is replaced,
		// so its time is this attempt's.
		prev, ok, gerr := r.hostStore.Get(ctx)
		if gerr != nil || !ok || len(prev.Reports) == 0 {
			prev = HostScan{ScannedAt: time.Now().Unix()}
		}
		prev.Error = hostFailure(err)
		h = prev
	} else {
		h.ScannedAt = time.Now().Unix()
	}
	if serr := r.hostStore.Save(ctx, h); serr != nil {
		r.log.Warn("imagescan: host scan save failed", "err", serr)
	}
	if err == nil {
		r.maybePageHost(ctx, h)
		if r.onOwnedCaddyFixable != nil && ownedCaddyFixable(h) {
			r.onOwnedCaddyFixable(ctx)
		}
	}
	r.maybePageReboot(ctx)
}

// ownedCaddyFixable reports whether the Mooring-owned Caddy build has any finding with a fix.
func ownedCaddyFixable(h HostScan) bool {
	for _, rep := range h.Reports {
		if rep.Role == RoleOwnedCaddy && rep.Fixable() > 0 {
			return true
		}
	}
	return false
}

// maybePageHost alerts when a fixable High/Critical host finding appears that no earlier
// host_vulnerabilities alert in this process included. A shrinking or unchanged set stays quiet.
func (r *Runner) maybePageHost(ctx context.Context, h HostScan) {
	if r.alerts == nil || !h.Actionable() {
		return
	}
	var fresh []string
	newCrit := 0
	only := map[string]bool{}
	for id, crit := range hostFindings(h.Reports) {
		if r.hostAlerted[id] {
			continue
		}
		fresh = append(fresh, id)
		only[id] = true
		if crit {
			newCrit++
		}
	}
	if len(fresh) == 0 {
		return
	}
	level := alert.LevelWarning
	if newCrit > 0 {
		level = alert.LevelCritical
	}
	noun := "vulnerabilities"
	if len(fresh) == 1 {
		noun = "vulnerability"
	}
	summary := fmt.Sprintf("%d new host %s with a fix available (%d critical, %d high). With a fix in total: %d critical, %d high; all findings: %d critical, %d high, %d medium, %d low.",
		len(fresh), noun, newCrit, len(fresh)-newCrit, h.FixableCritical, h.FixableHigh, h.Critical, h.High, h.Medium, h.Low)
	if ex := hostExamples(h, 3, only); len(ex) > 0 {
		summary += " " + strings.Join(ex, "; ") + "."
	}
	if adv := fixAdvice(h); adv != "" {
		summary += " " + adv
	}
	summary += " The Server tab lists the worst findings for each target and their fixed versions."
	o := alert.Outbox{
		RuleID:     0,
		Target:     "host",
		Kind:       "host_vulnerabilities",
		Level:      level,
		Transition: "firing",
		Summary:    summary,
		DedupeKey:  "hostvuln:" + identitySig(fresh),
	}
	if err := r.alerts.EnqueueInfra(ctx, o); err != nil {
		r.log.Warn("imagescan: could not enqueue host vuln alert", "err", err)
		return
	}
	for _, id := range fresh {
		r.hostAlerted[id] = true
	}
}

// hostExamples lists up to n fixable findings whose identity is in only, Critical before High, as
// "pkg ID → fixed" (with the binary's label for a binary report). Only the stored worst findings
// (Report.Top) can be named.
func hostExamples(h HostScan, n int, only map[string]bool) []string {
	var out []string
	for _, sev := range []string{sevCritical, sevHigh} {
		for _, rep := range h.Reports {
			for _, v := range rep.Top {
				if len(out) == n {
					return out
				}
				if v.Severity != sev || v.Fixed == "" || !only[v.ID+"|"+v.Package+"|"+rep.Target] {
					continue
				}
				e := v.Package + " " + v.ID + " → " + v.Fixed
				if rep.Target != OSReportTarget {
					e += " (" + rep.Target + ")"
				}
				out = append(out, e)
			}
		}
	}
	return out
}

// maxHintPkgs caps how many package (and binary) names the host alert's fix advice lists.
const maxHintPkgs = 20

// fixAdvice tells the operator how to clear the fixable High/Critical findings in h (all of them, not
// only the new ones): an upgrade command naming only the affected OS packages, what clears each
// affected binary, and a warning when the fix restarts Docker. It reads the identities buildReport
// keeps, so it needs a fresh scan, not one loaded from the store.
func fixAdvice(h HostScan) string {
	var (
		pkgs, binaries       []string
		dropped              int
		osFixable            bool
		mooring, owned, dock bool
	)
	for _, rep := range h.Reports {
		if len(rep.fixableHC) == 0 { // also every report that was not scanned
			continue
		}
		switch {
		case rep.Target == OSReportTarget:
			osFixable = true
			for p := range rep.fixablePkgs {
				if !safePkgName(p) {
					dropped++
					continue
				}
				pkgs = append(pkgs, p)
				dock = dock || dockerPackage(p)
			}
		case rep.Role == RoleOwnedCaddy:
			owned = true
		case rep.Target == labelMooring:
			mooring = true
		default:
			binaries = append(binaries, rep.Target)
			dock = dock || dockerBinaryLabels[rep.Target]
		}
	}
	var out []string
	if osFixable {
		sort.Strings(pkgs)
		out = append(out, osUpgradeAdvice(h.OS, pkgs, dropped))
	}
	if len(binaries) > maxHintPkgs {
		binaries = append(binaries[:maxHintPkgs:maxHintPkgs], fmt.Sprintf("%d more", len(binaries)-maxHintPkgs))
	}
	switch len(binaries) {
	case 0:
	case 1:
		out = append(out, "The affected binary "+binaries[0]+" is fixed by upgrading the package that installed it, once that ships a rebuilt version.")
	default:
		out = append(out, "The affected binaries "+joinAnd(binaries)+" are fixed by upgrading the packages that installed them, once those ship a rebuilt version.")
	}
	if mooring {
		out = append(out, "mooring is fixed by a newer Mooring release.")
	}
	if owned {
		out = append(out, "Mooring refreshes its own Caddy build automatically.")
	}
	if dock {
		out = append(out, "Upgrading Docker or the container runtime restarts Docker and every container on the host, so pick a quiet moment.")
	}
	return strings.Join(out, " ")
}

// osUpgradeAdvice is the upgrade command for the detected OS family naming the first maxHintPkgs of
// pkgs (sorted, sanitized); dropped counts the names safePkgName refused, which are never printed.
func osUpgradeAdvice(osName string, pkgs []string, dropped int) string {
	if len(pkgs) == 0 {
		return "Upgrade the affected OS packages listed on the Server tab."
	}
	more := dropped
	if len(pkgs) > maxHintPkgs {
		more += len(pkgs) - maxHintPkgs
		pkgs = pkgs[:maxHintPkgs]
	}
	tail := "."
	if more > 0 {
		tail = fmt.Sprintf(" (and %d more — see the Server tab).", more)
	}
	cmd := upgradeCommand(osName)
	if cmd == "" {
		return "Upgrade the affected OS packages with the host's package manager: " + strings.Join(pkgs, " ") + tail
	}
	return "Upgrade the affected OS packages: " + cmd + " " + strings.Join(pkgs, " ") + tail
}

// upgradeCommand is the command that upgrades named packages (and nothing else) on the detected OS
// family, "" when unknown. Intentional: never a full `apt-get upgrade` / `dnf upgrade` — that can also
// upgrade docker-ce or containerd.io, which restarts Docker and every container on the host.
func upgradeCommand(osName string) string {
	family, version, _ := strings.Cut(osName, " ")
	switch family {
	case "ubuntu", "debian":
		return "sudo apt-get update && sudo apt-get install --only-upgrade"
	case "redhat", "centos", "rocky", "alma", "oracle", "fedora", "amazon":
		if usesYum(family, version) {
			return "sudo yum upgrade"
		}
		return "sudo dnf upgrade"
	}
	return ""
}

// usesYum reports whether the release predates dnf: Amazon Linux 1 and 2 (Trivy names them by year
// and "2"; Amazon Linux 2023 is "2023") and release 7 of RHEL, CentOS and Oracle Linux.
func usesYum(family, version string) bool {
	major := leadingInt(version)
	switch family {
	case "amazon":
		return major > 0 && major < 2022
	case "redhat", "centos", "oracle":
		return major > 0 && major < 8
	}
	return false
}

// leadingInt parses the digits that start s (at most 9), 0 when there are none.
func leadingInt(s string) int {
	n := 0
	for i := 0; i < len(s) && i < 9 && s[i] >= '0' && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}

// safePkgName reports whether a package name from the host's package database (via Trivy) may be
// printed in the upgrade command: 1–128 characters of the package-name charset [A-Za-z0-9.+_:-], not
// starting with '-' (apt-get and dnf would read an option) and not ending with '-' (apt-get install
// reads "pkg-" as "remove pkg").
func safePkgName(p string) bool {
	if p == "" || len(p) > 128 || !isAlnum(p[0]) || p[len(p)-1] == '-' {
		return false // dpkg and rpm names start with a letter or digit; apt reads "." or "+x" as a pattern
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case isAlnum(c):
		case c == '.', c == '+', c == '_', c == ':', c == '-':
		default:
			return false
		}
	}
	return true
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// dockerPackages are the Docker and container-runtime packages (Docker's repository, the distro
// packages, Microsoft's moby-*): upgrading one restarts Docker and every container on the host.
var dockerPackages = map[string]bool{
	"docker-ce": true, "docker-ce-cli": true, "docker-ce-rootless-extras": true, "containerd.io": true,
	"docker-buildx-plugin": true, "docker-compose-plugin": true, "docker.io": true, "containerd": true, "runc": true,
}

func dockerPackage(p string) bool {
	name, _, _ := strings.Cut(p, ":") // an arch-qualified name (containerd.io:amd64)
	return dockerPackages[name] || strings.HasPrefix(name, "moby-")
}

// joinAnd joins names as "a", "a and b", "a, b and c".
func joinAnd(names []string) string {
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// maybePageReboot alerts when the host flags a pending reboot (/run/reboot-required), once per
// package list per process.
func (r *Runner) maybePageReboot(ctx context.Context) {
	if r.alerts == nil || r.reboot == nil {
		return
	}
	required, pkgs := r.reboot()
	if !required {
		return
	}
	sum := sha256.Sum256([]byte(strings.Join(pkgs, ",")))
	sig := hex.EncodeToString(sum[:])[:12]
	if r.rebootAlerted[sig] {
		return
	}
	summary := "The host needs a reboot to finish installing updates."
	if len(pkgs) > 0 {
		summary = "The host needs a reboot to finish installing updates (" + strings.Join(pkgs, ", ") + ")."
	}
	o := alert.Outbox{
		RuleID:     0,
		Target:     "host",
		Kind:       "host_reboot_required",
		Level:      alert.LevelWarning,
		Transition: "firing",
		Summary:    summary,
		DedupeKey:  "reboot:" + sig,
	}
	if err := r.alerts.EnqueueInfra(ctx, o); err != nil {
		r.log.Warn("imagescan: could not enqueue reboot alert", "err", err)
		return
	}
	r.rebootAlerted[sig] = true
}
