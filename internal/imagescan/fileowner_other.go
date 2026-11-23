//go:build !unix

package imagescan

import "io/fs"

// fileOwner cannot determine ownership on non-unix platforms; scannerCanRead then uses only the
// "other" permission bits (Mooring targets Linux).
func fileOwner(fs.FileInfo) (uid, gid uint32, ok bool) { return 0, 0, false }
