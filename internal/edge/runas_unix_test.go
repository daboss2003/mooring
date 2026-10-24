//go:build unix

package edge

import (
	"os"
	"testing"
)

// A non-root process (the service itself) runs caddy as-is. The root path — switching to the mooring
// user before running a binary that user can rewrite — needs a root test run.
func TestDropRootIsANoOpWhenNotRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs a non-root test user")
	}
	if attr, ok := dropRoot(); attr != nil || !ok {
		t.Error("a non-root process needs no privilege drop")
	}
}
