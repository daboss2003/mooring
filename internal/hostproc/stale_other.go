//go:build !linux

package hostproc

// Stale needs /proc (Linux); elsewhere no process is ever stale.
func Stale(pid int) ([]string, error) { return nil, nil }
