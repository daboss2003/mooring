//go:build unix

package edge

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"
)

// unprivilegedUsers are the accounts a ROOT caller (`mooring doctor` / `mooring setup` under sudo)
// runs a Caddy binary as. The Mooring-owned build is writable by the service user, so executing it
// as root would let a compromised service escalate to root; the commands run this way (version,
// list-modules) need no privilege, and that user can already rewrite the file, so running it as them
// grants nothing.
var unprivilegedUsers = []string{"mooring", "nobody"}

// dropRoot returns process attributes that run a child as the first unprivileged account found (never
// uid or gid 0), with no supplementary groups, when this process is root; nil when it isn't root.
// ok=false when it is root and no such account exists — the caller must then refuse to run the binary.
func dropRoot() (*syscall.SysProcAttr, bool) {
	if os.Geteuid() != 0 {
		return nil, true
	}
	for _, name := range unprivilegedUsers {
		u, err := user.Lookup(name)
		if err != nil {
			continue
		}
		uid, uerr := strconv.ParseUint(u.Uid, 10, 32)
		gid, gerr := strconv.ParseUint(u.Gid, 10, 32)
		if uerr != nil || gerr != nil || uid == 0 || gid == 0 {
			continue
		}
		return &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}, true
	}
	return nil, false
}

// hardenCaddyCmd prepares a short caddy command (version, list-modules) on a binary Mooring did not
// necessarily write itself:
//   - as root it runs as an unprivileged account (dropRoot), never as root;
//   - in its own session (Setsid), so it has no controlling terminal: a child started from
//     `sudo mooring doctor` can't reach the operator's TTY;
//   - a timeout kills its whole process group, and WaitDelay bounds a descendant holding the pipes;
//   - a binary another non-root account could have written is refused (it would run as us).
func hardenCaddyCmd(cmd *exec.Cmd) error {
	attr, ok := dropRoot()
	if !ok {
		return fmt.Errorf("refusing to run caddy as root: no unprivileged account (%v) to run it as", unprivilegedUsers)
	}
	runAs := uint32(os.Geteuid())
	if attr == nil {
		attr = &syscall.SysProcAttr{}
	} else {
		runAs = attr.Credential.Uid
	}
	if fi, err := os.Stat(cmd.Path); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && ((st.Uid != 0 && st.Uid != runAs) || fi.Mode().Perm()&0o022 != 0) {
			return fmt.Errorf("refusing to run %s: another account can write it", cmd.Path)
		}
	}
	attr.Setsid = true
	cmd.SysProcAttr = attr
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // the whole group (Setsid made the child its leader)
	}
	cmd.WaitDelay = 5 * time.Second
	return nil
}
