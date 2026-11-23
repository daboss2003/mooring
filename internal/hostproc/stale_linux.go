//go:build linux

package hostproc

// Stale returns the replaced files pid still runs: every mapped file under /usr/, /lib/, /lib32/,
// /lib64/, /bin/, /sbin/, /opt/ or /var/lib/ whose /proc entry ends in " (deleted)", and its executable
// when it is deleted and a regular file is at its path again (paths without the suffix, sorted,
// deduped). An executable deleted with nothing in its place doesn't count until a new file is there.
// Empty = current. A process that has exited, or whose /proc entries can't be read, is an error.
func Stale(pid int) ([]string, error) {
	return staleFrom("/proc", pid, stalePrefixes, replacedOnDisk)
}
