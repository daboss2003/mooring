//go:build darwin

package main

import (
	"bytes"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// openPTY opens a pseudo-terminal: its master, and the path of its slave.
func openPTY() (*os.File, string, error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, "", err
	}
	fd := m.Fd()
	var name [128]byte
	for _, c := range []struct {
		req uintptr
		arg uintptr
	}{{unix.TIOCPTYGRANT, 0}, {unix.TIOCPTYUNLK, 0}, {unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0]))}} {
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, c.req, c.arg); errno != 0 {
			m.Close()
			return nil, "", errno
		}
	}
	return m, string(name[:bytes.IndexByte(name[:], 0)]), nil
}
