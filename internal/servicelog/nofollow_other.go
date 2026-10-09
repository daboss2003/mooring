//go:build !unix

package servicelog

// oNoFollow is unavailable off-unix; loading skips non-regular entries instead.
const oNoFollow = 0
