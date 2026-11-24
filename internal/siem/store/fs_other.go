//go:build !unix

package store

import (
	"os"
	"path/filepath"
)

// oNoFollow is unavailable off-unix; segment files are checked to be regular after opening.
const oNoFollow = 0

// lockDir opens dir/.lock without locking it (Mooring runs on Linux; this keeps other builds green).
func lockDir(dir string) (*os.File, error) {
	return os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR|os.O_CREATE, 0o600)
}
