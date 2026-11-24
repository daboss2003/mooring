package store

import (
	"os"
	"testing"
	"time"
)

// Most tests move the clock by days between calls to stand for time passing; the clock-jump latch
// would read that as a jump. It is switched off here and on again by the tests of the latch.
func TestMain(m *testing.M) {
	jumpAfter = 1 << 62
	os.Exit(m.Run())
}

func withJumpLatch(t *testing.T) {
	t.Helper()
	jumpAfter = defaultJumpAfter
	t.Cleanup(func() { jumpAfter = time.Duration(1 << 62) })
}
