//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/daboss2003/mooring/internal/config"
)

// serviceProbeTimeout bounds the child that reads the file as the service.
const serviceProbeTimeout = 5 * time.Second

// unitIdentity is who the unit runs as: User=mooring, Group=mooring and the user's groups.
type unitIdentity struct {
	uid, gid uint32
	groups   []uint32
}

// serviceViewer judges a config file as the service would, for root. Its fields are the host
// (tests inject them).
type serviceViewer struct {
	euid    func() int
	groupID func(name string) (int, bool)
	// account is the service's user (false: there is none).
	account func() (unitIdentity, bool)
	// owner is the file's mode, uid and gid (false: unknown).
	owner func(path string) (perm fs.FileMode, uid, gid int, ok bool)
	// probe reads the file as the service in a child process: its exit status, its stdout (at
	// most a little over maxProbeLine bytes) and why it did not run to an exit, if it didn't.
	probe func(path string, a unitIdentity) (code int, out []byte, err error)
	// closedDir is the first directory above path the mode bits close to the service ("": none).
	closedDir func(path string, a unitIdentity) string
}

func defaultServiceViewer() serviceViewer {
	return serviceViewer{
		euid:    os.Geteuid,
		groupID: lookupGroupID,
		account: lookupUnitIdentity,
		owner:   fileOwnerMode,
		probe: func(path string, a unitIdentity) (int, []byte, error) {
			// On Linux a binary that was replaced or removed while this command runs (a package
			// upgrade) reads back as "<path> (deleted)": the child does not start, and the
			// mode-bit rule answers. The package script runs the new binary by its path.
			exe, err := os.Executable()
			if err != nil {
				return -1, nil, err
			}
			return runServiceProbe(exe, path, a)
		},
		closedDir: closedDir,
	}
}

// serviceView judges the file at path as the service would. It answers only for root on a host
// that has the service's group (the unit's Group=mooring); for anyone else config.Load already
// applied the rule, or can't tell. nil: nothing to report.
func serviceView(path string) error { return defaultServiceViewer().view(path) }

// view is serviceView. With the service's user on the host the answer is the read itself, made as
// that user in a child process: mode bits can't see an ACL or a directory the service can't enter.
// The mode-bit rule (serviceViewOf) words the refusals it explains, and decides alone when there is
// no such user or the child gave no answer.
func (v serviceViewer) view(path string) error {
	if v.euid() != 0 {
		return nil
	}
	gid, ok := v.groupID(serviceGroup)
	if !ok {
		return nil
	}
	perm, uid, fileGID, ok := v.owner(path)
	if !ok {
		return nil // Load reports a file that can't be reached
	}
	byMode := serviceViewOf(path, perm, uid, fileGID, gid)
	acct, ok := v.account()
	if !ok {
		return byMode
	}
	switch verdict, reason := judgeProbe(v.probe(path, acct)); verdict {
	case probeUsable:
		// Intentional: a file the mode-bit rule refuses and the service reads (an ACL grants it)
		// is not refused. The child ran serve's own checks and read, as the service.
		return nil
	case probeRefused:
		if byMode != nil {
			return byMode
		}
		e := &serviceCantUseError{msg: fmt.Sprintf("%s can't be used by the service (user %s): %s", path, serviceGroup, reason)}
		switch dir := v.closedDir(path, acct); {
		case dir == "":
			e.advice = "to see the file as the service does"
			e.command = fmt.Sprintf("sudo runuser -u %s -g %s -- mooring config check --config %s", serviceGroup, serviceGroup, path)
		case dir == filepath.Dir(absPath(path)):
			// What the packages give /etc/mooring (deploy/nfpm/postinstall.sh).
			e.advice = "the service must be able to enter " + dir
			e.command = fmt.Sprintf("sudo chown root:%s %s && sudo chmod 0750 %s", serviceGroup, dir, dir)
		default:
			e.advice = "the service must be able to enter " + dir
		}
		return e
	}
	// Intentional: no answer from the child is never an OK of its own. The rule of before decides.
	return byMode
}

type probeVerdict int

const (
	probeUnknown probeVerdict = iota // no answer: the child did not run, or not by the protocol
	probeUsable
	probeRefused
)

// judgeProbe reads the child's answer: exit 0 and no output, or config.ExitInvalid and one plain
// line (the reason). Everything else is no answer.
func judgeProbe(code int, out []byte, err error) (probeVerdict, string) {
	if err != nil {
		return probeUnknown, ""
	}
	switch code {
	case 0:
		if len(out) == 0 {
			return probeUsable, ""
		}
	case config.ExitInvalid:
		if line, ok := probeLine(out); ok {
			return probeRefused, line
		}
	}
	return probeUnknown, ""
}

// runServiceProbe runs `exe config probe-as-service -- path` as the service account.
func runServiceProbe(exe, path string, a unitIdentity) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), serviceProbeTimeout)
	defer cancel()
	cmd, err := newServiceProbeCmd(ctx, exe, path, a)
	if err != nil {
		return -1, nil, err
	}
	return runServiceProbeCmd(cmd)
}

// newServiceProbeCmd is the child root starts to read the config file as the service: this binary,
// a fixed argv ending in the absolute path, and the service's uid, gid and groups, set before the
// exec. It gets nothing of root's: an empty environment (so no MOORING_DEV_INSECURE_PERMS either,
// as in the unit), no stdin and no stderr (/dev/null), no descriptor beyond the stdout pipe (Go
// opens files close-on-exec; ExtraFiles stays empty), its own session (no controlling terminal:
// another process of the service's user can't reach the operator's TTY through it), and "/" as its
// directory. The path is not interpreted by a shell or as a flag.
func newServiceProbeCmd(ctx context.Context, exe, path string, a unitIdentity) (*exec.Cmd, error) {
	if !filepath.IsAbs(exe) {
		return nil, fmt.Errorf("the mooring binary's path %q is not absolute", exe)
	}
	if a.uid == 0 {
		return nil, errors.New("the service account is root")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, exe, "config", serviceProbeCommand, "--", abs)
	cmd.Env = []string{} // Intentional: empty, not nil (nil would pass root's environment on).
	cmd.Dir = "/"
	cmd.WaitDelay = time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:     true,
		Credential: &syscall.Credential{Uid: a.uid, Gid: a.gid, Groups: slices.Clone(a.groups)},
	}
	return cmd, nil
}

// runServiceProbeCmd runs cmd to its exit and returns its status and the start of its stdout.
// err: it did not start, was stopped (the deadline) or was killed by a signal.
func runServiceProbeCmd(cmd *exec.Cmd) (int, []byte, error) {
	out := &headWriter{max: maxProbeLine + 2} // the line, its newline, and one byte that shows there was more
	cmd.Stdout = out
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, out.buf, nil
	case errors.As(err, &ee) && ee.Exited():
		return ee.ExitCode(), out.buf, nil
	}
	return -1, out.buf, err
}

// headWriter keeps the first max bytes written to it and drops the rest, so a child that writes
// without end fills no memory and never blocks on the pipe.
type headWriter struct {
	buf []byte
	max int
}

func (w *headWriter) Write(p []byte) (int, error) {
	if room := w.max - len(w.buf); room > 0 {
		w.buf = append(w.buf, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

// lookupUnitIdentity is the account the unit runs as (deploy/systemd/mooring.service): user
// mooring, Group=mooring (not the user's primary group from passwd, which need not be the same),
// the groups the account database lists for the user, as systemd's initgroups does, and
// SupplementaryGroups=docker when that group exists. Release builds have CGO disabled, so os/user
// reads /etc/passwd and /etc/group itself: enough for a local system user, and an account that
// lives only in LDAP or sssd is not found (then the mode-bit rule answers).
func lookupUnitIdentity() (unitIdentity, bool) {
	u, err := user.Lookup(serviceGroup)
	if err != nil {
		return unitIdentity{}, false
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	gid, ok := lookupGroupID(serviceGroup)
	if err != nil || !ok || uid == 0 || gid < 0 {
		return unitIdentity{}, false
	}
	a := unitIdentity{uid: uint32(uid), gid: uint32(gid), groups: []uint32{uint32(gid)}}
	add := func(id uint64) {
		if !slices.Contains(a.groups, uint32(id)) {
			a.groups = append(a.groups, uint32(id))
		}
	}
	if ids, err := u.GroupIds(); err == nil {
		for _, s := range ids {
			if id, err := strconv.ParseUint(s, 10, 32); err == nil {
				add(id)
			}
		}
	}
	if id, ok := lookupGroupID("docker"); ok && id >= 0 {
		add(uint64(id))
	}
	return a, true
}

func fileOwnerMode(path string) (fs.FileMode, int, int, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, 0, 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, false
	}
	return fi.Mode().Perm(), int(st.Uid), int(st.Gid), true
}

func absPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// closedDir is the first directory above path, from the root down, that the service may not enter
// going by its owner, group and mode ("": none, or one of them can't be looked at). It only picks
// the directory a refusal names; the refusal itself is the child's.
func closedDir(path string, a unitIdentity) string {
	var dirs []string
	for dir := filepath.Dir(absPath(path)); ; dir = filepath.Dir(dir) {
		dirs = append(dirs, dir)
		if dir == filepath.Dir(dir) {
			break
		}
	}
	slices.Reverse(dirs)
	for _, dir := range dirs {
		fi, err := os.Stat(dir)
		if err != nil {
			return ""
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return ""
		}
		if !modeLetsEnter(fi.Mode().Perm(), st.Uid, st.Gid, a) {
			return dir
		}
	}
	return ""
}

// modeLetsEnter reports whether a directory of mode perm owned by uid:gid can be entered by the
// account: the execute bit of the one class that applies to it (owner, else group, else others).
func modeLetsEnter(perm fs.FileMode, uid, gid uint32, a unitIdentity) bool {
	switch {
	case uid == a.uid:
		return perm&0o100 != 0
	case gid == a.gid || slices.Contains(a.groups, gid):
		return perm&0o010 != 0
	}
	return perm&0o001 != 0
}

// serviceViewOf is the mode-bit rule for a file of mode perm owned by uid:gid, with serviceGID the
// service group's id. Only a root-owned file without group-write and world bits is judged: Load
// refuses every other one for everybody, root included.
func serviceViewOf(path string, perm fs.FileMode, uid, gid, serviceGID int) error {
	if uid != 0 || perm&0o037 != 0 {
		return nil
	}
	switch {
	case perm&0o040 == 0:
		return &serviceCantUseError{msg: fmt.Sprintf("%s is readable by root only (mode %#o): the service (user %s) can't read it", path, perm, serviceGroup)}
	case gid != serviceGID:
		return &serviceCantUseError{msg: fmt.Sprintf("%s belongs to group id %d, not to the service's group %s (id %d): the service (user %s) can't read it, or refuses it for its group", path, gid, serviceGroup, serviceGID, serviceGroup)}
	}
	return nil
}
