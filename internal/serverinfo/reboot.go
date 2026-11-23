package serverinfo

import (
	"bufio"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Debian/Ubuntu (update-notifier-common) create these when an installed update needs a reboot: the
// flag file, and the names of the packages that asked for it, one per line.
const (
	rebootFlagPath = "/run/reboot-required"
	rebootPkgsPath = "/run/reboot-required.pkgs"
	rebootPkgsMax  = 20
	rebootPkgsCap  = 64 << 10
)

// rebootPkgRe accepts a Debian package name, optionally arch-qualified ("libssl3t64:amd64"); any
// other line is dropped (the names end up in the dashboard and in alert text).
var rebootPkgRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._~:-]{0,127}$`)

// RebootRequired reports whether /run/reboot-required exists (Debian/Ubuntu) and the packages in
// /run/reboot-required.pkgs (deduped, sorted, at most 20).
func RebootRequired() (required bool, pkgs []string) {
	return rebootRequired(rebootFlagPath, rebootPkgsPath)
}

func rebootRequired(flag, list string) (bool, []string) {
	if _, err := os.Stat(flag); err != nil {
		return false, nil
	}
	f, err := os.Open(list)
	if err != nil {
		return true, nil
	}
	defer f.Close()
	seen := map[string]bool{}
	var pkgs []string
	sc := bufio.NewScanner(io.LimitReader(f, rebootPkgsCap))
	for sc.Scan() {
		p := strings.TrimSpace(sc.Text())
		if !rebootPkgRe.MatchString(p) || seen[p] {
			continue
		}
		seen[p] = true
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	if len(pkgs) > rebootPkgsMax {
		pkgs = pkgs[:rebootPkgsMax]
	}
	return true, pkgs
}
