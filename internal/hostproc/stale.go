// Package hostproc finds the processes Mooring supervises (the edge Caddy, the L4 nginx) still running
// files that a package upgrade replaced on disk, and restarts them on the updated files.
//
// A package upgrade (apt, unattended-upgrades) replaces /usr/bin/caddy, /usr/sbin/nginx or a library
// they load (libssl, an nginx module) and restarts only the package's own service, which Mooring keeps
// disabled. Mooring's children keep the old, possibly vulnerable, code mapped until they restart. The
// kernel marks those files " (deleted)" in /proc/<pid>/exe and /proc/<pid>/maps. A deleted library
// counts at once; the executable counts once a new file is at its path.
package hostproc

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// deletedSuffix is what the kernel appends to a /proc path whose file was unlinked or renamed over.
const deletedSuffix = " (deleted)"

// maxMapsBytes bounds the read of /proc/<pid>/maps (Caddy and nginx have a few hundred lines). A
// variable only so a test can lower it.
var maxMapsBytes = 4 << 20

// stalePrefixes are the directories a replaced mapping must be under to count. Shared-memory mappings
// ("/dev/zero (deleted)" for nginx's zones, "/memfd:…", "/SYSV…") and scratch files elsewhere are
// "deleted" too, but no upgrade replaced them.
var stalePrefixes = []string{"/usr/", "/lib/", "/lib32/", "/lib64/", "/bin/", "/sbin/", "/opt/", "/var/lib/"}

// parseExeLink reads a /proc/<pid>/exe link: the executable's path and whether it was replaced.
func parseExeLink(link string) (string, bool) {
	return strings.CutSuffix(link, deletedSuffix)
}

// parseMaps returns the paths (without the suffix) of the replaced files mapped in a /proc/<pid>/maps
// text that are under one of prefixes, in file order and possibly repeated.
func parseMaps(data []byte, prefixes []string) []string {
	var out []string
	for len(data) > 0 {
		line := data
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			data = nil
		}
		p, ok := mapsPath(string(line))
		if !ok {
			continue
		}
		if p, deleted := strings.CutSuffix(p, deletedSuffix); deleted && underAny(p, prefixes) {
			out = append(out, p)
		}
	}
	return out
}

// mapsPath returns the pathname column of one maps line: everything after the fifth field (address,
// perms, offset, dev, inode), which may itself contain spaces. ok=false for an anonymous mapping.
func mapsPath(line string) (string, bool) {
	rest := line
	for range 5 {
		rest = strings.TrimLeft(rest, " \t")
		j := strings.IndexAny(rest, " \t")
		if j < 0 {
			return "", false
		}
		rest = rest[j:]
	}
	p := strings.TrimLeft(rest, " \t")
	return p, p != ""
}

func underAny(p string, prefixes []string) bool {
	for _, pre := range prefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// replacedOnDisk reports whether a regular file (a symlink to one included) is at p: the new version of
// a deleted executable a process still runs.
func replacedOnDisk(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// staleFrom is Stale on the proc filesystem at procRoot: the deleted executable, counted wherever it
// lives (the Mooring-owned Caddy is under data_dir) but only when present reports a new file at its
// path, and the deleted files mapped under prefixes.
func staleFrom(procRoot string, pid int, prefixes []string, present func(string) bool) ([]string, error) {
	if pid <= 0 {
		return nil, errors.New("hostproc: invalid pid " + strconv.Itoa(pid))
	}
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	link, err := os.Readlink(filepath.Join(dir, "exe"))
	if err != nil {
		return nil, err
	}
	exe, exeDeleted := parseExeLink(link)
	f, err := os.Open(filepath.Join(dir, "maps"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(maxMapsBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxMapsBytes {
		// Keep only the whole lines inside the bound: a line cut short is never read as a path.
		data = data[:maxMapsBytes]
		data = data[:bytes.LastIndexByte(data, '\n')+1]
	}
	// An executable deleted with nothing at its path yet was removed, not replaced: `sudo rm
	// <data_dir>/bin/caddy && sudo mooring setup --yes` leaves the edge's so while setup downloads, and a
	// restart then would start the system caddy without the DNS plugins. It counts (also as a maps line:
	// the kernel maps the executable) once the new file is there.
	// Intentional: a mapped library counts without that rule. An upgrade that changes a library's file
	// name (Ubuntu's nginx maps libpcre2-8.so.0.11.2, libz.so.1.3) leaves nothing at the old path; one
	// removed for good makes the restart check (`nginx -t`) fail, so it never causes a bad restart.
	var out []string
	if exeDeleted {
		out = append(out, exe)
	}
	out = append(out, parseMaps(data, prefixes)...)
	exePresent := !exeDeleted || present(exe)
	var stale []string
	for _, p := range sortedUnique(out) {
		if p != exe || exePresent {
			stale = append(stale, p)
		}
	}
	return stale, nil
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	sort.Strings(in)
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}
