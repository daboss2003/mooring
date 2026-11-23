package hostproc

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestParseExeLink(t *testing.T) {
	if p, ok := parseExeLink("/usr/sbin/nginx (deleted)"); !ok || p != "/usr/sbin/nginx" {
		t.Errorf("a replaced executable: %q %v", p, ok)
	}
	if p, ok := parseExeLink("/usr/sbin/nginx"); ok || p != "/usr/sbin/nginx" {
		t.Errorf("a current executable: %q %v", p, ok)
	}
	if _, ok := parseExeLink(""); ok {
		t.Error("an empty link is not stale")
	}
}

// A real nginx master's maps after `apt upgrade` replaced nginx and libssl: the shared-memory zones
// ("/dev/zero (deleted)"), memfd and SysV segments, and scratch files are not upgrades.
const nginxMaps = `5581c0a00000-5581c0a2f000 r--p 00000000 fc:01 1835106                    /usr/sbin/nginx (deleted)
5581c0a2f000-5581c0b39000 r-xp 0002f000 fc:01 1835106                    /usr/sbin/nginx (deleted)
5581c2a4b000-5581c2c8d000 rw-p 00000000 00:00 0                          [heap]
7f1c3b200000-7f1c3b400000 rw-s 00000000 00:01 3072                       /dev/zero (deleted)
7f1c3b400000-7f1c3b401000 rw-s 00000000 00:01 3073                       /SYSV00000000 (deleted)
7f1c3b500000-7f1c3b501000 rw-s 00000000 00:01 3074                       /memfd:nginx (deleted)
7f1c3b600000-7f1c3b601000 rw-p 00000000 fc:01 99                         /tmp/scratch (deleted)
7f1c3b6a0000-7f1c3b6c0000 r-xp 00000000 fc:01 1835200                    /usr/lib/nginx/modules/ngx_stream_module.so
7f1c3b800000-7f1c3b8b0000 r--p 00000000 fc:01 1836117                    /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)
7f1c3b8b0000-7f1c3ba00000 r-xp 000b0000 fc:01 1836117                    /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)
7f1c3bb00000-7f1c3bb20000 r-xp 00000000 fc:01 1836200                    /lib/x86_64-linux-gnu/libz.so.1 (deleted)
7f1c3bc00000-7f1c3bc20000 r-xp 00000000 fc:01 1836300                    /opt/vendor/lib with space.so (deleted)
7f1c3bd00000-7f1c3bd20000 r-xp 00000000 fc:01 1836400                    /usr/lib/x86_64-linux-gnu/libc.so.6
7ffc8a5f4000-7ffc8a615000 rw-p 00000000 00:00 0                          [stack]
7ffc8a7d9000-7ffc8a7db000 r-xp 00000000 00:00 0                          [vdso]
7ffc8a7db000-7ffc8a7dc000 r-xp 00000000 00:00 0
garbage line
`

func TestParseMaps(t *testing.T) {
	got := sortedUnique(parseMaps([]byte(nginxMaps), stalePrefixes))
	want := []string{
		"/lib/x86_64-linux-gnu/libz.so.1",
		"/opt/vendor/lib with space.so",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/sbin/nginx",
	}
	if !slices.Equal(got, want) {
		t.Errorf("stale mappings = %q\nwant %q", got, want)
	}
	if got := parseMaps([]byte(nginxMaps), []string{"/tmp/"}); !slices.Equal(got, []string{"/tmp/scratch"}) {
		t.Errorf("with prefix /tmp/: %q", got)
	}
	if got := parseMaps(nil, stalePrefixes); len(got) != 0 {
		t.Errorf("empty maps: %q", got)
	}
}

// fakeProc writes a /proc/<pid> with an exe link to exe and a maps file.
func fakeProc(t *testing.T, pid int, exe, maps string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs symlinks")
	}
	root := t.TempDir()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "maps"), []byte(maps), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

// everyPathReplaced is a present func for which every deleted file has a new file at its path.
func everyPathReplaced(string) bool { return true }

func TestStaleFromProc(t *testing.T) {
	root := fakeProc(t, 42, "/usr/sbin/nginx (deleted)", nginxMaps)
	got, err := staleFrom(root, 42, stalePrefixes, everyPathReplaced)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/lib/x86_64-linux-gnu/libz.so.1", "/opt/vendor/lib with space.so",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3", "/usr/sbin/nginx"}
	if !slices.Equal(got, want) {
		t.Errorf("stale = %q\nwant %q (sorted, the executable listed once)", got, want)
	}

	// The executable counts wherever it lives (the Mooring-owned Caddy is under data_dir).
	root = fakeProc(t, 7, "/srv/mooring/bin/caddy (deleted)", "")
	if got, err := staleFrom(root, 7, stalePrefixes, everyPathReplaced); err != nil || !slices.Equal(got, []string{"/srv/mooring/bin/caddy"}) {
		t.Errorf("replaced executable outside the prefixes: %q %v", got, err)
	}

	root = fakeProc(t, 8, "/usr/bin/caddy", "00400000-00500000 r-xp 00000000 fc:01 12 /usr/bin/caddy\n")
	if got, err := staleFrom(root, 8, stalePrefixes, everyPathReplaced); err != nil || len(got) != 0 {
		t.Errorf("a current process: %q %v", got, err)
	}

	if _, err := staleFrom(root, 9, stalePrefixes, everyPathReplaced); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a process that is gone must be an error (not stale), got %v", err)
	}
	if _, err := staleFrom(root, 0, stalePrefixes, everyPathReplaced); err == nil {
		t.Error("pid 0 must be an error")
	}
}

// The executable counts only once a file is at its path again. `sudo rm <data_dir>/bin/caddy && sudo
// mooring setup --yes` leaves the running edge's executable deleted with nothing in its place while
// setup downloads; restarting then would start the system caddy without the DNS plugins. Its maps line
// (the owned build is under /var/lib/) follows the same rule. A mapped library counts as soon as it is
// deleted: an upgrade that changes a library's file name (Ubuntu 24.04's nginx maps
// libpcre2-8.so.0.11.2, libcrypt.so.1.1.0, libz.so.1.3) leaves nothing at the old path.
func TestStaleFromExecutableCountsOnlyWithAReplacement(t *testing.T) {
	const owned = "/var/lib/mooring/bin/caddy"
	const renamed = "/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2"
	ownedMaps := "00400000-00500000 r-xp 00000000 fc:01 12 " + owned + " (deleted)\n" +
		"00500000-00600000 r--p 00100000 fc:01 12 " + owned + " (deleted)\n" +
		"7f00-7f01 r-xp 00000000 fc:01 13 " + renamed + " (deleted)\n" +
		"7f00-7f01 r-xp 00000000 fc:01 14 /usr/lib/libssl.so.3 (deleted)\n"
	root := fakeProc(t, 11, owned+" (deleted)", ownedMaps)
	onDiskNow := map[string]bool{}
	present := func(p string) bool { return onDiskNow[p] }

	got, err := staleFrom(root, 11, stalePrefixes, present)
	if err != nil || !slices.Equal(got, []string{"/usr/lib/libssl.so.3", renamed}) {
		t.Errorf("nothing at any path: stale=%q err=%v; want both libraries, not the executable", got, err)
	}
	onDiskNow["/usr/lib/libssl.so.3"] = true // an upgrade renamed a new libssl over the old one
	if got, err := staleFrom(root, 11, stalePrefixes, present); err != nil || !slices.Equal(got, []string{"/usr/lib/libssl.so.3", renamed}) {
		t.Errorf("a replaced library: stale=%q err=%v", got, err)
	}
	onDiskNow[owned] = true // setup installed the new build
	if got, err := staleFrom(root, 11, stalePrefixes, present); err != nil || !slices.Equal(got, []string{"/usr/lib/libssl.so.3", renamed, owned}) {
		t.Errorf("once the new build is in place: stale=%q err=%v", got, err)
	}

	// The executable's rule never applies to a library at another path, and a current executable's
	// path is not special.
	root = fakeProc(t, 12, "/usr/sbin/nginx", "7f00-7f01 r-xp 00000000 fc:01 13 "+renamed+" (deleted)\n")
	if got, err := staleFrom(root, 12, stalePrefixes, func(string) bool { return false }); err != nil || !slices.Equal(got, []string{renamed}) {
		t.Errorf("a current nginx on a library an upgrade renamed: stale=%q err=%v", got, err)
	}
}

func TestReplacedOnDisk(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "caddy")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !replacedOnDisk(file) {
		t.Error("a regular file is a replacement")
	}
	if replacedOnDisk(filepath.Join(dir, "missing")) {
		t.Error("nothing at the path is not a replacement")
	}
	if replacedOnDisk(dir) {
		t.Error("a directory is not a replacement")
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(dir, "link")
		if err := os.Symlink(file, link); err != nil {
			t.Fatal(err)
		}
		if !replacedOnDisk(link) {
			t.Error("a symlink to a regular file is a replacement (library paths are often symlinked)")
		}
	}
}

// The maps read is bounded; a line cut at the bound is dropped, never read as a shorter path.
func TestStaleFromBoundsTheMapsRead(t *testing.T) {
	head := "7f00-7f01 r-xp 00000000 fc:01 1 /usr/lib/libssl.so.3 (deleted)\n" +
		"7f00-7f01 r-xp 00000000 fc:01 1 /usr/lib/a.so (deleted)\n" +
		"7f00-7f01 r-xp 00000000 fc:01 1 /usr/lib/b.so (deleted)\n"
	cutLine := "7f00-7f01 r-xp 00000000 fc:01 1 /usr/lib/libcrypto.so.3 (deleted)\n"
	tail := strings.Repeat("7f00-7f01 r-xp 00000000 fc:01 1 /usr/lib/later.so (deleted)\n", 10)
	old := maxMapsBytes
	maxMapsBytes = len(head) + len(cutLine) - 1 // the bound falls just before the fourth line's newline
	t.Cleanup(func() { maxMapsBytes = old })
	root := fakeProc(t, 5, "/usr/sbin/nginx", head+cutLine+tail)
	got, err := staleFrom(root, 5, stalePrefixes, everyPathReplaced)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"/usr/lib/a.so", "/usr/lib/b.so", "/usr/lib/libssl.so.3"}) {
		t.Errorf("bounded read = %q; want only the whole lines inside the bound", got)
	}
}

func TestStaleOffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux has /proc")
	}
	if got, err := Stale(os.Getpid()); got != nil || err != nil {
		t.Errorf("off Linux Stale must be nil, nil; got %q %v", got, err)
	}
}
