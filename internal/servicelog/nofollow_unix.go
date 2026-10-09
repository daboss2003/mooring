//go:build unix

package servicelog

import "syscall"

// oNoFollow makes an open fail when the final path component is a symlink, so a segment path can
// never be redirected outside the log directory.
const oNoFollow = syscall.O_NOFOLLOW
