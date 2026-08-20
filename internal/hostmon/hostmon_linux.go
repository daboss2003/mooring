//go:build linux

package hostmon

import (
	"os"
	"strconv"
	"syscall"
)

func readCPUTimes() (busy, total uint64, err error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	return parseProcStat(string(data))
}

func readMem() (total, used uint64, err error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	return parseMemInfo(string(data))
}

// readSwapTotal returns total swap in bytes (0 if none / unreadable — swap is optional).
func readSwapTotal() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	return parseSwapTotal(string(data))
}

func readLoad1() (float64, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, err
	}
	return parseLoadAvg(string(data))
}

func readDisk(path string) (total, used uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bsize := uint64(st.Bsize)
	total = st.Blocks * bsize
	free := st.Bfree * bsize
	if free > total {
		free = total
	}
	return total, total - free, nil
}

// readProcesses walks /proc, reading each numeric PID's status for name + RSS, and
// returns the top-N by resident memory. It is a single pass with NO goroutine per
// pid (so a box with thousands of PIDs can't explode); per-pid read errors (the
// process exited mid-scan, or EACCES) are skipped, never fatal.
func readProcesses(topN int) ([]Process, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := make([]Process, 0, 128)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a pid dir
		}
		data, err := os.ReadFile("/proc/" + e.Name() + "/status")
		if err != nil {
			continue // raced with exit, or unreadable
		}
		if p, ok := parseProcStatus(pid, string(data)); ok {
			out = append(out, p)
		}
	}
	return topByRSS(out, topN), nil
}
