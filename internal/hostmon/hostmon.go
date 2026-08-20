// Package hostmon samples host CPU/RAM/disk for the read plane (plan §4). The
// parsing is pure and unit-tested cross-platform; the actual /proc + statfs reads
// are Linux-specific (the deploy target), with a no-op stub elsewhere so the
// binary still builds on a dev machine.
package hostmon

import (
	"errors"
	"sort"
	"strconv"
	"strings"
)

// ErrUnsupported is returned by Sample on non-Linux platforms.
var ErrUnsupported = errors.New("hostmon: host metrics not supported on this platform")

// Sample is one host metrics reading.
type Sample struct {
	CPUPercent float64
	Load1      float64
	MemTotal   uint64
	MemUsed    uint64
	SwapTotal  uint64 // total swap in bytes (0 if none); counted toward the write-plane resource gate
	DiskTotal  uint64
	DiskUsed   uint64
}

// Sampler holds the previous CPU counters so it can compute instantaneous CPU%
// from the delta between successive Sample calls.
type Sampler struct {
	diskPath  string
	prevBusy  uint64
	prevTotal uint64
	havePrev  bool
}

// New returns a Sampler that measures disk usage at diskPath.
func New(diskPath string) *Sampler { return &Sampler{diskPath: diskPath} }

// Sample reads current host metrics. CPU% is 0 on the first call (no prior
// counters to diff against).
func (s *Sampler) Sample() (Sample, error) {
	busy, total, err := readCPUTimes()
	if err != nil {
		return Sample{}, err
	}
	cpu := cpuPercent(s.havePrev, s.prevBusy, s.prevTotal, busy, total)
	s.prevBusy, s.prevTotal, s.havePrev = busy, total, true

	memTotal, memUsed, err := readMem()
	if err != nil {
		return Sample{}, err
	}
	load1, _ := readLoad1() // non-fatal
	diskTotal, diskUsed, err := readDisk(s.diskPath)
	if err != nil {
		return Sample{}, err
	}
	return Sample{
		CPUPercent: cpu, Load1: load1,
		MemTotal: memTotal, MemUsed: memUsed, SwapTotal: readSwapTotal(),
		DiskTotal: diskTotal, DiskUsed: diskUsed,
	}, nil
}

// cpuPercent computes CPU% from busy/total jiffy counters versus the previous
// sample. The subtraction is done in float64 (NOT uint64) and the numerator is
// clamped at 0 so a non-monotonic counter (iowait can decrease, CPU hotplug) can
// never underflow into an astronomical value (review #2/#6); the result is
// clamped to [0,100] (aggregate host CPU is already total-normalized).
func cpuPercent(havePrev bool, prevBusy, prevTotal, busy, total uint64) float64 {
	if !havePrev {
		return 0
	}
	db := float64(busy) - float64(prevBusy)
	dt := float64(total) - float64(prevTotal)
	if db < 0 {
		db = 0
	}
	if dt <= 0 {
		return 0
	}
	cpu := db / dt * 100.0
	if cpu > 100 {
		cpu = 100
	}
	return cpu
}

// parseProcStat parses the aggregate "cpu" line of /proc/stat into busy/total
// jiffies. total = sum of all fields; busy = total - (idle + iowait).
func parseProcStat(data string) (busy, total uint64, err error) {
	for _, line := range strings.Split(data, "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:] // drop "cpu"
		var idle uint64
		for i, f := range fields {
			v, perr := strconv.ParseUint(f, 10, 64)
			if perr != nil {
				return 0, 0, perr
			}
			total += v
			if i == 3 || i == 4 { // idle, iowait
				idle += v
			}
		}
		return total - idle, total, nil
	}
	return 0, 0, errors.New("hostmon: no cpu line in /proc/stat")
}

// parseMemInfo parses /proc/meminfo into total/used bytes (used = total -
// available).
func parseMemInfo(data string) (total, used uint64, err error) {
	var memTotal, memAvail uint64
	var haveTotal, haveAvail bool
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, perr := strconv.ParseUint(fields[1], 10, 64)
		if perr != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			memTotal, haveTotal = v*1024, true
		case "MemAvailable:":
			memAvail, haveAvail = v*1024, true
		}
	}
	if !haveTotal || !haveAvail {
		return 0, 0, errors.New("hostmon: missing MemTotal/MemAvailable")
	}
	if memAvail > memTotal {
		memAvail = memTotal
	}
	return memTotal, memTotal - memAvail, nil
}

// parseSwapTotal extracts SwapTotal (bytes) from /proc/meminfo contents; 0 if absent.
func parseSwapTotal(data string) uint64 {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "SwapTotal:" {
			if v, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				return v * 1024
			}
		}
	}
	return 0
}

// parseLoadAvg parses the 1-minute load from /proc/loadavg.
func parseLoadAvg(data string) (float64, error) {
	fields := strings.Fields(data)
	if len(fields) == 0 {
		return 0, errors.New("hostmon: empty loadavg")
	}
	return strconv.ParseFloat(fields[0], 64)
}

// Process is one host process, for the read-only "task manager" view. Only the
// fields needed to answer "what's using the memory" are collected — no cmdline
// (which can leak secrets passed as args) and no signalling capability.
type Process struct {
	PID   int
	PPID  int
	Name  string
	State string
	RSS   uint64 // resident set size in bytes
}

// Processes returns the top-N host processes by resident memory (descending).
// It is a READ-ONLY snapshot for the UI; it never signals or mutates anything.
// Kernel threads (and anything with no resident memory) are skipped so the list
// is the userspace memory users an operator cares about. Per-pid read errors are
// tolerated (a process can exit mid-scan) — they're skipped, never fatal.
func Processes(topN int) ([]Process, error) { return readProcesses(topN) }

// parseProcStatus parses one /proc/[pid]/status into a Process. ok=false when the
// entry has no resident memory (kernel thread or already-reaped) and should be
// skipped. Name is capped and stripped of control bytes by the caller's template
// auto-escaping; here we only bound its length so a hostile comm can't bloat the
// row or the audit log.
func parseProcStatus(pid int, data string) (p Process, ok bool) {
	p.PID = pid
	var haveRSS bool
	for _, line := range strings.Split(data, "\n") {
		name, val, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		val = strings.TrimSpace(val)
		switch name {
		case "Name":
			if len(val) > 64 {
				val = val[:64]
			}
			p.Name = val
		case "State":
			if f := strings.Fields(val); len(f) > 0 {
				p.State = f[0]
			}
		case "PPid":
			p.PPID, _ = strconv.Atoi(val)
		case "VmRSS":
			// "12345 kB"
			f := strings.Fields(val)
			if len(f) >= 1 {
				if kb, err := strconv.ParseUint(f[0], 10, 64); err == nil {
					p.RSS = kb * 1024
					haveRSS = true
				}
			}
		}
	}
	return p, haveRSS && p.RSS > 0
}

// topByRSS sorts processes by RSS descending and truncates to topN (topN<=0 → all).
func topByRSS(ps []Process, topN int) []Process {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].RSS != ps[j].RSS {
			return ps[i].RSS > ps[j].RSS
		}
		return ps[i].PID < ps[j].PID
	})
	if topN > 0 && len(ps) > topN {
		ps = ps[:topN]
	}
	return ps
}
