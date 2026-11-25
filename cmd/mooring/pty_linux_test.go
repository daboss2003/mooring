//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// openPTY opens a pseudo-terminal: its master, and the path of its slave.
func openPTY() (*os.File, string, error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, "", err
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		m.Close()
		return nil, "", err
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		m.Close()
		return nil, "", err
	}
	return m, fmt.Sprintf("/dev/pts/%d", n), nil
}
