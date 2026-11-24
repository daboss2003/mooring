//go:build !unix

package detect

// oNoFollow is unavailable off-unix; the database file is checked to be regular before opening.
const oNoFollow = 0
