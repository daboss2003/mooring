//go:build unix

package store

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// oNoFollow makes an open fail when the final path component is a symlink.
const oNoFollow = syscall.O_NOFOLLOW

// lockDir takes an exclusive lock on dir/.lock for as long as the returned file stays open. A
// second store on the same directory (another process, or a second Open in this one) would seal
// the first one's open segments under it.
func lockDir(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR|os.O_CREATE|oNoFollow, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("store: " + dir + " is in use by another security-log store")
	}
	return f, nil
}
