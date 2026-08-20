//go:build !linux

package hostmon

// Non-Linux stubs (Mooring targets Linux/systemd). These keep the binary
// building on dev machines; Sample surfaces ErrUnsupported, which the monitor
// logs once and treats as "host metrics unavailable" without failing app polling.

func readCPUTimes() (busy, total uint64, err error)        { return 0, 0, ErrUnsupported }
func readMem() (total, used uint64, err error)             { return 0, 0, ErrUnsupported }
func readSwapTotal() uint64                                { return 0 }
func readLoad1() (float64, error)                          { return 0, ErrUnsupported }
func readDisk(path string) (total, used uint64, err error) { return 0, 0, ErrUnsupported }
func readProcesses(topN int) ([]Process, error)            { return nil, ErrUnsupported }
