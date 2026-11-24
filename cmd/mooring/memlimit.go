package main

import (
	"log/slog"
	"runtime/debug"
	"strconv"
	"strings"
)

// clampMemoryLimit keeps the Go soft memory limit (GOMEMLIMIT, from the unit) under the cgroup's
// hard limit (MemoryMax): an operator drop-in that lowers MemoryMax below the unit's GOMEMLIMIT
// would otherwise get the service killed by the cgroup before the garbage collector reacts. The
// soft limit is lowered to 70% of the cgroup limit when it is above that; it is never raised.
// read is os.ReadFile (a test seam).
func clampMemoryLimit(log *slog.Logger, read func(string) ([]byte, error)) {
	max, ok := cgroupMemoryMax(read)
	if !ok {
		return
	}
	want := max / 10 * 7
	if want < 64<<20 {
		return // no usable soft limit under a cap this small (0 would run the GC continuously)
	}
	if cur := debug.SetMemoryLimit(-1); cur > want {
		debug.SetMemoryLimit(want)
		log.Warn("GOMEMLIMIT lowered under the service's memory cap", "memory_max", max, "was", cur, "now", want)
	}
}

// cgroupMemoryMax reads this process's cgroup v2 memory.max ("max" or unreadable → not ok).
func cgroupMemoryMax(read func(string) ([]byte, error)) (int64, bool) {
	b, err := read("/proc/self/cgroup")
	if err != nil {
		return 0, false
	}
	var rel string
	for _, line := range strings.Split(string(b), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok { // the cgroup v2 unified hierarchy
			rel = strings.TrimSpace(p)
			break
		}
	}
	if rel == "" || strings.Contains(rel, "..") || !strings.HasPrefix(rel, "/") {
		return 0, false
	}
	v, err := read("/sys/fs/cgroup" + rel + "/memory.max")
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64)
	if err != nil || n <= 0 {
		return 0, false // "max" = no limit
	}
	return n, true
}
