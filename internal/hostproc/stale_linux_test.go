//go:build linux

package hostproc

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func copyFile(t *testing.T, src, dst string, mode os.FileMode) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// A process started from a binary that is then replaced the way a package upgrade replaces it (a new
// file renamed over the old path) is stale; a process started from the new file is not. A binary
// deleted with nothing in its place (`rm` of the owned Caddy before `mooring setup` installs a new
// one) is not stale until the new file is there.
func TestStaleRealProcess(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "sleep")
	copyFile(t, sleep, bin, 0o755)
	start := func() *exec.Cmd {
		t.Helper()
		cmd := exec.Command(bin, "60")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		return cmd
	}
	old := start()
	if got, err := Stale(old.Process.Pid); err != nil || len(got) != 0 {
		t.Fatalf("a fresh process: stale=%q err=%v; want none", got, err)
	}

	// Watching the binary's directory too puts its own maps lines (the kernel maps the executable)
	// under the prefixes, as for the owned Caddy under /var/lib/: they follow the executable's rule.
	watched := []string{dir + "/"}
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	if got, err := Stale(old.Process.Pid); err != nil || len(got) != 0 {
		t.Fatalf("a binary deleted with nothing in its place: stale=%q err=%v; want none", got, err)
	}
	maps, err := os.ReadFile("/proc/" + strconv.Itoa(old.Process.Pid) + "/maps")
	if err != nil || !strings.Contains(string(maps), bin+" (deleted)") {
		t.Fatalf("the deleted binary is not in the process's maps (err=%v):\n%s", err, maps)
	}
	if got, err := staleFrom("/proc", old.Process.Pid, watched, replacedOnDisk); err != nil || len(got) != 0 {
		t.Fatalf("a binary deleted with nothing in its place, its directory watched: stale=%q err=%v; want none", got, err)
	}

	next := filepath.Join(dir, "sleep.new")
	copyFile(t, sleep, next, 0o755)
	if err := os.Rename(next, bin); err != nil { // what dpkg (and setup's install) does
		t.Fatal(err)
	}
	got, err := Stale(old.Process.Pid)
	if err != nil || !slices.Equal(got, []string{bin}) {
		t.Errorf("after the binary was replaced: stale=%q err=%v; want [%s]", got, err, bin)
	}
	if got, err := staleFrom("/proc", old.Process.Pid, watched, replacedOnDisk); err != nil || !slices.Equal(got, []string{bin}) {
		t.Errorf("after the binary was replaced, its directory watched: stale=%q err=%v; want [%s]", got, err, bin)
	}
	fresh := start()
	if got, err := Stale(fresh.Process.Pid); err != nil || len(got) != 0 {
		t.Errorf("a process started on the new binary: stale=%q err=%v; want none", got, err)
	}

	// A process that has exited is an error, never stale.
	_ = old.Process.Kill()
	_ = old.Wait()
	if got, err := Stale(old.Process.Pid); err == nil {
		t.Errorf("an exited process: stale=%q, want an error", got)
	}
}

// A mapped library under a watched directory is stale once it is deleted, whether or not a file is at
// its path again (an upgrade that renames a library leaves nothing there). Shared-memory mappings
// ("/dev/zero (deleted)", what nginx's zones look like) and files elsewhere are not.
func TestStaleRealMappings(t *testing.T) {
	dir := t.TempDir()
	lib := filepath.Join(dir, "libfake.so")
	if err := os.WriteFile(lib, make([]byte, 8192), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(lib)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := syscall.Mmap(int(f.Fd()), 0, 4096, syscall.PROT_READ, syscall.MAP_PRIVATE)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Munmap(mapped)
	shm, err := syscall.Mmap(-1, 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED|syscall.MAP_ANON)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Munmap(shm)
	if err := os.Remove(lib); err != nil {
		t.Fatal(err)
	}

	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(maps), lib+" (deleted)") || !strings.Contains(string(maps), "/dev/zero (deleted)") {
		t.Fatalf("the test mappings are not in /proc/self/maps:\n%s", maps)
	}
	pid := os.Getpid()
	got, err := staleFrom("/proc", pid, []string{dir + "/"}, replacedOnDisk)
	if err != nil || !slices.Contains(got, lib) {
		t.Errorf("a library deleted with nothing in its place: stale=%q err=%v; want it listed", got, err)
	}
	if err := os.WriteFile(lib, make([]byte, 8192), 0o644); err != nil { // the upgraded library
		t.Fatal(err)
	}
	got, err = staleFrom("/proc", pid, []string{dir + "/"}, replacedOnDisk)
	if err != nil || !slices.Contains(got, lib) {
		t.Errorf("a replaced library under a watched directory: stale=%q err=%v; want it listed", got, err)
	}
	if slices.Contains(got, "/dev/zero") {
		t.Errorf("shared memory must never count: %q", got)
	}
	got, err = Stale(pid)
	if err != nil || slices.Contains(got, lib) || slices.Contains(got, "/dev/zero") {
		t.Errorf("a temp file and shared memory are outside the watched directories: stale=%q err=%v", got, err)
	}
	if _, err := Stale(1 << 30); err == nil {
		t.Error("a pid that doesn't exist must be an error")
	}
}
