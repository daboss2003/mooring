//go:build unix

package enrich

import (
	"os"
	"syscall"
)

// mapFile maps size bytes of f read-only. The mapping outlives f. Mooring never rewrites a database
// file in place (a new one is renamed over it), so the mapped pages never change under a lookup.
func mapFile(f *os.File, size int) ([]byte, func([]byte) error, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	var data []byte
	var merr error
	if err := rc.Control(func(fd uintptr) {
		data, merr = syscall.Mmap(int(fd), 0, size, syscall.PROT_READ, syscall.MAP_SHARED)
	}); err != nil {
		return nil, nil, err
	}
	if merr != nil {
		return nil, nil, merr
	}
	return data, syscall.Munmap, nil
}
