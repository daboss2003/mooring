//go:build !unix

package enrich

import (
	"io"
	"os"
)

// mapFile reads the file into memory where mmap isn't available.
func mapFile(f *os.File, size int) ([]byte, func([]byte) error, error) {
	data := make([]byte, size)
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, nil, err
	}
	return data, func([]byte) error { return nil }, nil
}
