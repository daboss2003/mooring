//go:build !unix

package edge

import (
	"os/exec"
	"time"
)

// hardenCaddyCmd only bounds the wait off Unix (the managed edge is Linux-only).
func hardenCaddyCmd(cmd *exec.Cmd) error {
	cmd.WaitDelay = 5 * time.Second
	return nil
}
