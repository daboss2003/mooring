package main

import (
	"errors"
	"runtime/debug"
	"testing"
)

func fakeFS(files map[string]string) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		if v, ok := files[p]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("no such file")
	}
}

func TestCgroupMemoryMax(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  int64
		ok    bool
	}{
		{"v2 limit", map[string]string{"/proc/self/cgroup": "0::/system.slice/mooring.service\n",
			"/sys/fs/cgroup/system.slice/mooring.service/memory.max": "536870912\n"}, 536870912, true},
		{"no limit", map[string]string{"/proc/self/cgroup": "0::/system.slice/mooring.service\n",
			"/sys/fs/cgroup/system.slice/mooring.service/memory.max": "max\n"}, 0, false},
		{"cgroup v1 only", map[string]string{"/proc/self/cgroup": "12:memory:/system.slice/mooring.service\n"}, 0, false},
		{"path escape", map[string]string{"/proc/self/cgroup": "0::/../../etc\n"}, 0, false},
		{"unreadable", map[string]string{}, 0, false},
	} {
		got, ok := cgroupMemoryMax(fakeFS(tc.files))
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: got %d %v, want %d %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

// A GOMEMLIMIT above the cgroup cap is lowered to 70% of it; one already under it is left alone.
func TestClampMemoryLimit(t *testing.T) {
	prev := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(prev)
	fs := fakeFS(map[string]string{"/proc/self/cgroup": "0::/m\n", "/sys/fs/cgroup/m/memory.max": "1000000000"})

	debug.SetMemoryLimit(900_000_000)
	clampMemoryLimit(serveQuietLog(), fs)
	if got := debug.SetMemoryLimit(-1); got != 700_000_000 {
		t.Errorf("limit = %d, want 700000000 (70%% of the cap)", got)
	}
	debug.SetMemoryLimit(600_000_000)
	clampMemoryLimit(serveQuietLog(), fs)
	if got := debug.SetMemoryLimit(-1); got != 600_000_000 {
		t.Errorf("a limit under the cap was changed to %d", got)
	}
}

// A cgroup cap too small to leave a usable soft limit is ignored: a limit of 0 would make the
// garbage collector run continuously.
func TestClampMemoryLimitIgnoresATinyCap(t *testing.T) {
	prev := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(prev)
	debug.SetMemoryLimit(600_000_000)
	clampMemoryLimit(serveQuietLog(), fakeFS(map[string]string{"/proc/self/cgroup": "0::/m\n", "/sys/fs/cgroup/m/memory.max": "9"}))
	if got := debug.SetMemoryLimit(-1); got != 600_000_000 {
		t.Errorf("limit = %d after a 9-byte cap, want it unchanged", got)
	}
}
