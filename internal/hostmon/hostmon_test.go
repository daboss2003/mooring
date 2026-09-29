package hostmon

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestParseProcStatus(t *testing.T) {
	data := "Name:\tnginx\nState:\tS (sleeping)\nPid:\t42\nPPid:\t1\nVmRSS:\t   12345 kB\n"
	p, ok := parseProcStatus(42, data)
	if !ok {
		t.Fatal("expected ok for a process with RSS")
	}
	if p.PID != 42 || p.PPID != 1 || p.Name != "nginx" || p.State != "S" || p.RSS != 12345*1024 {
		t.Errorf("bad parse: %+v", p)
	}

	// A kernel thread (no VmRSS) must be skipped.
	if _, ok := parseProcStatus(2, "Name:\tkthreadd\nState:\tS\nPPid:\t0\n"); ok {
		t.Error("a process with no RSS should be skipped (ok=false)")
	}

	// An overlong name is bounded.
	long := "Name:\t" + string(make([]byte, 200)) + "\nVmRSS:\t1 kB\n"
	if p, _ := parseProcStatus(3, long); len(p.Name) > 64 {
		t.Errorf("name not bounded: len=%d", len(p.Name))
	}
}

func TestTopByRSS(t *testing.T) {
	in := []Process{{PID: 1, RSS: 100}, {PID: 2, RSS: 300}, {PID: 3, RSS: 200}}
	got := topByRSS(in, 2)
	if len(got) != 2 || got[0].PID != 2 || got[1].PID != 3 {
		t.Errorf("topByRSS wrong order/len: %+v", got)
	}
}

func TestParseProcStat(t *testing.T) {
	// user=100 nice=0 system=50 idle=800 iowait=50 irq=0 softirq=0 steal=0
	data := "cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 ...\nintr 123\n"
	busy, total, err := parseProcStat(data)
	if err != nil {
		t.Fatal(err)
	}
	// total = 100+0+50+800+50 = 1000; idle = idle+iowait = 850; busy = 150
	if total != 1000 || busy != 150 {
		t.Errorf("busy=%d total=%d, want 150/1000", busy, total)
	}
}

func TestParseMemInfo(t *testing.T) {
	data := "MemTotal:       2048 kB\nMemFree:  100 kB\nMemAvailable:    512 kB\nBuffers: 1 kB\n"
	total, used, err := parseMemInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2048*1024 {
		t.Errorf("total=%d, want %d", total, 2048*1024)
	}
	// used = total - available = (2048-512)*1024
	if used != (2048-512)*1024 {
		t.Errorf("used=%d, want %d", used, (2048-512)*1024)
	}
}

func TestParseMemInfoMissingFieldsFails(t *testing.T) {
	if _, _, err := parseMemInfo("MemTotal: 100 kB\n"); err == nil {
		t.Error("expected error when MemAvailable missing")
	}
}

func TestParseLoadAvg(t *testing.T) {
	l, err := parseLoadAvg("0.42 0.31 0.10 1/234 5678")
	if err != nil || l != 0.42 {
		t.Errorf("load=%v err=%v, want 0.42", l, err)
	}
}

func TestCPUPercent(t *testing.T) {
	// first sample (no prev) → 0
	if got := cpuPercent(false, 0, 0, 100, 200); got != 0 {
		t.Errorf("first sample = %v, want 0", got)
	}
	// normal: busy +50, total +100 → 50%
	if got := cpuPercent(true, 100, 1000, 150, 1100); got != 50 {
		t.Errorf("normal = %v, want 50", got)
	}
	// review #2/#6: busy DECREASES while total increases — must NOT underflow.
	if got := cpuPercent(true, 500, 1000, 480, 1100); got != 0 {
		t.Errorf("busy regression = %v, want 0 (no uint64 underflow)", got)
	}
	// dt <= 0 → 0
	if got := cpuPercent(true, 100, 1000, 150, 1000); got != 0 {
		t.Errorf("zero total delta = %v, want 0", got)
	}
	// clamp to 100 if busy delta somehow exceeds total delta
	if got := cpuPercent(true, 0, 0, 200, 100); got != 100 {
		t.Errorf("over-100 = %v, want clamp 100", got)
	}
}

func TestSamplerCPUDelta(t *testing.T) {
	// On a platform without /proc this returns ErrUnsupported, which is fine —
	// the delta math itself is covered by parseProcStat. Just ensure New works.
	s := New("/")
	if s == nil {
		t.Fatal("New returned nil")
	}
}

// steppingCPU is a fake counter source that advances busy by 5 and total by 10
// jiffies on every read: consecutive reads are exactly 50% apart.
func steppingCPU() func() (uint64, uint64, error) {
	var reads atomic.Uint64
	return func() (uint64, uint64, error) {
		n := reads.Add(1)
		return n * 5, n * 10, nil
	}
}

func TestSamplerConcurrentUse(t *testing.T) {
	// Run with -race. The read and the baseline update happen under one lock, so
	// every call's window is exactly one step of the fake counters (50%): never a
	// read diffed against a newer baseline stored by another goroutine.
	s := New("/")
	s.readCPU = steppingCPU()
	if cpu, err := s.sampleCPU(); err != nil || cpu != 0 {
		t.Fatalf("first sample = %v, %v; want 0, nil", cpu, err)
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if i%4 == 0 {
					// The public entry point; past the CPU read it needs /proc (Linux).
					if smp, err := s.Sample(); err == nil && smp.CPUPercent != 50 {
						t.Errorf("Sample CPU = %v, want 50", smp.CPUPercent)
					}
					continue
				}
				if cpu, err := s.sampleCPU(); err != nil || cpu != 50 {
					t.Errorf("sampleCPU = %v, %v; want 50, nil", cpu, err)
				}
			}
		}()
	}
	wg.Wait()
}

func TestSamplersAreIndependent(t *testing.T) {
	// Two Samplers read one host: each keeps its own window, so sampling one never
	// shifts the other's (a shared Sampler reports 0% for a's second call here).
	reads := [][2]uint64{{0, 0}, {100, 100}, {100, 200}} // busy, total per read
	next := 0
	read := func() (uint64, uint64, error) {
		r := reads[next]
		next++
		return r[0], r[1], nil
	}
	a, b := New("/"), New("/")
	a.readCPU, b.readCPU = read, read
	if cpu, _ := a.sampleCPU(); cpu != 0 {
		t.Errorf("a first = %v, want 0", cpu)
	}
	if cpu, _ := b.sampleCPU(); cpu != 0 {
		t.Errorf("b first = %v, want 0 (its own first sample, not a delta on a's)", cpu)
	}
	if cpu, _ := a.sampleCPU(); cpu != 50 {
		t.Errorf("a second = %v, want 50 over a's own window", cpu)
	}
}
