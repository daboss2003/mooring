//go:build unix

package imagescan

import (
	"io/fs"
	"syscall"
)

// fileOwner returns the owner uid/gid of a stat result on unix.
func fileOwner(fi fs.FileInfo) (uid, gid uint32, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0, false
	}
	return st.Uid, st.Gid, true
}
