//go:build unix

package detect

import "syscall"

// oNoFollow makes an open fail when the final path component is a symlink.
const oNoFollow = syscall.O_NOFOLLOW
