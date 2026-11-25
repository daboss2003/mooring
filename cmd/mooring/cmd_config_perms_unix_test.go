//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/config"
)

// The service-view tests run without root: the uid, the accounts, the file's owner and the child
// that reads the file as the service are injected. TestServiceViewAsRoot runs the real child.

const (
	viewPath   = "/etc/mooring/config.yaml"
	viewSvcGID = 990
)

var viewAccount = unitIdentity{uid: 991, gid: viewSvcGID, groups: []uint32{viewSvcGID, 995}}

// viewFixture is root on a host with the service's user and group, looking at a root-owned file of
// mode perm and group gid, with a child that answers (code, out, err).
type viewFixture struct {
	v      serviceViewer
	probed []string
}

func newViewFixture(perm fs.FileMode, gid int, code int, out string, err error) *viewFixture {
	fx := &viewFixture{}
	fx.v = serviceViewer{
		euid:    func() int { return 0 },
		groupID: func(string) (int, bool) { return viewSvcGID, true },
		account: func() (unitIdentity, bool) { return viewAccount, true },
		owner:   func(string) (fs.FileMode, int, int, bool) { return perm, 0, gid, true },
		probe: func(path string, a unitIdentity) (int, []byte, error) {
			fx.probed = append(fx.probed, fmt.Sprintf("%s as %d:%d %v", path, a.uid, a.gid, a.groups))
			return code, []byte(out), err
		},
		closedDir: func(string, unitIdentity) string { return "" },
	}
	return fx
}

const (
	msgRootOnly   = viewPath + " is readable by root only (mode 0600): the service (user mooring) can't read it"
	msgOtherGroup = viewPath + " belongs to group id 0, not to the service's group mooring (id 990): the service (user mooring) can't read it, or refuses it for its group"
)

// A file the mode bits say the service can't use, and that the service reads (a POSIX ACL grants
// it): not refused. The answer is the read, not the bits.
func TestServiceViewTheReadDecidesOverTheModeBits(t *testing.T) {
	for _, c := range []struct {
		name string
		perm fs.FileMode
		gid  int
	}{
		{"root:root 0640 with an ACL", 0o640, 0},
		{"root:staff 0640", 0o640, 20},
		{"root:root 0600", 0o600, 0},
	} {
		fx := newViewFixture(c.perm, c.gid, 0, "", nil)
		if err := fx.v.view(viewPath); err != nil {
			t.Errorf("%s: the service read the file, got %v", c.name, err)
		}
		if want := []string{viewPath + " as 991:990 [990 995]"}; !slices.Equal(fx.probed, want) {
			t.Errorf("%s: asked %v, want %v", c.name, fx.probed, want)
		}
	}
}

// A file whose mode and group are right, and that the service can't reach (its directory is
// closed): refused, with the child's reason and the directory to open.
func TestServiceViewRefusedForTheDirectory(t *testing.T) {
	const reason = "stat " + viewPath + ": permission denied"
	fx := newViewFixture(0o640, viewSvcGID, config.ExitInvalid, reason+"\n", nil)
	fx.v.closedDir = func(path string, a unitIdentity) string {
		if path != viewPath || a.uid != viewAccount.uid {
			t.Errorf("closedDir(%q, %+v)", path, a)
		}
		return "/etc/mooring"
	}
	err := fx.v.view(viewPath)
	var e *serviceCantUseError
	if !errors.As(err, &e) {
		t.Fatalf("got %v, want a serviceCantUseError", err)
	}
	if want := viewPath + " can't be used by the service (user mooring): " + reason; e.Error() != want {
		t.Errorf("message %q\nwant    %q", e.Error(), want)
	}
	if e.advice != "the service must be able to enter /etc/mooring" || e.command != "sudo chown root:mooring /etc/mooring && sudo chmod 0750 /etc/mooring" {
		t.Errorf("advice %q, command %q", e.advice, e.command)
	}

	// A directory further up is named without a command: its owner and mode are not Mooring's to set.
	fx.v.closedDir = func(string, unitIdentity) string { return "/etc" }
	if !errors.As(fx.v.view(viewPath), &e) || e.advice != "the service must be able to enter /etc" || e.command != "" {
		t.Errorf("a directory further up: advice %q, command %q", e.advice, e.command)
	}
	// No directory the mode bits explain (an ACL, a mount): the check to run as the service.
	fx.v.closedDir = func(string, unitIdentity) string { return "" }
	if !errors.As(fx.v.view(viewPath), &e) || e.advice != "to see the file as the service does" ||
		e.command != "sudo runuser -u mooring -g mooring -- mooring config check --config "+viewPath {
		t.Errorf("nothing found: advice %q, command %q", e.advice, e.command)
	}
}

// When the mode-bit rule explains the child's refusal, its message (and so the chown/chmod fix)
// is the one shown.
func TestServiceViewKeepsTheModeBitMessages(t *testing.T) {
	for _, c := range []struct {
		perm fs.FileMode
		gid  int
		out  string
		want string
	}{
		{0o600, 0, "open " + viewPath + ": permission denied\n", msgRootOnly},
		{0o640, 0, "open " + viewPath + ": permission denied\n", msgOtherGroup},
	} {
		fx := newViewFixture(c.perm, c.gid, config.ExitInvalid, c.out, nil)
		err := fx.v.view(viewPath)
		var e *serviceCantUseError
		if !errors.As(err, &e) || e.Error() != c.want || e.advice != "" || e.command != "" {
			t.Errorf("mode %#o gid %d: got %v (%+v), want %q with the default fix", c.perm, c.gid, err, e, c.want)
		}
	}
}

// A child that could not be judged (it did not run, ran out of time, exited with a status that is
// not part of the protocol, or printed something that is not one clean line) decides nothing: the
// mode-bit rule does, exactly as before the child existed.
func TestServiceViewFallsBackToTheModeBits(t *testing.T) {
	long := strings.Repeat("x", maxProbeLine+1)
	for _, c := range []struct {
		name string
		code int
		out  string
		err  error
	}{
		{"did not start", -1, "", errors.New("fork/exec /usr/local/bin/mooring (deleted): no such file or directory")},
		{"timed out", -1, "", context.DeadlineExceeded},
		{"killed with output", config.ExitInvalid, "open: permission denied\n", errors.New("signal: killed")},
		{"cannot judge (2)", 2, "", nil},
		{"unknown command in an older binary (2)", 2, "mooring: unknown command\n", nil},
		{"exit 1", 1, "panic\n", nil},
		{"exit 77", 77, "x\n", nil},
		{"usable with output", 0, "OK\n", nil},
		{"refused without a reason", config.ExitInvalid, "", nil},
		{"refused with a blank reason", config.ExitInvalid, " \n", nil},
		{"refused with two lines", config.ExitInvalid, "one\ntwo\n", nil},
		{"refused with an escape sequence", config.ExitInvalid, "\x1b]0;owned\x07 denied\n", nil},
		{"refused with a carriage return", config.ExitInvalid, "denied\rOK: valid\n", nil},
		{"refused with a bidi override", config.ExitInvalid, "denied ‮\n", nil},
		{"refused with invalid UTF-8", config.ExitInvalid, "denied \xff\n", nil},
		{"refused with a NUL", config.ExitInvalid, "denied\x00\n", nil},
		{"refused with too long a line", config.ExitInvalid, long + "\n", nil},
	} {
		// Mode bits fine: nothing to report (never a refusal made up from garbage).
		fx := newViewFixture(0o640, viewSvcGID, c.code, c.out, c.err)
		if err := fx.v.view(viewPath); err != nil {
			t.Errorf("%s, mode bits fine: %v", c.name, err)
		}
		// Mode bits wrong: today's refusal (never an OK the child did not give).
		fx = newViewFixture(0o600, 0, c.code, c.out, c.err)
		if err := fx.v.view(viewPath); err == nil || err.Error() != msgRootOnly {
			t.Errorf("%s, root-only file: got %v, want %q", c.name, err, msgRootOnly)
		}
		if len(fx.probed) != 1 {
			t.Errorf("%s: the child ran %d times", c.name, len(fx.probed))
		}
	}
	// The longest line that is still one.
	fx := newViewFixture(0o640, viewSvcGID, config.ExitInvalid, strings.Repeat("x", maxProbeLine)+"\n", nil)
	if err := fx.v.view(viewPath); err == nil {
		t.Error("a reason of maxProbeLine bytes is a reason")
	}
}

// Who is asked: only root, only on a host with the service's group. Without the service's user the
// mode-bit rule answers alone and no child runs.
func TestServiceViewWithoutTheServiceAccount(t *testing.T) {
	noChild := func(fx *viewFixture) {
		fx.v.probe = func(string, unitIdentity) (int, []byte, error) {
			t.Error("a child ran")
			return 0, nil, nil
		}
	}
	// No group: no judgement, whatever the file.
	fx := newViewFixture(0o600, 0, 0, "", nil)
	noChild(fx)
	fx.v.groupID = func(string) (int, bool) { return 0, false }
	if err := fx.v.view(viewPath); err != nil {
		t.Errorf("no service group: %v", err)
	}
	// The group and no user: the mode-bit rule.
	fx = newViewFixture(0o600, 0, 0, "", nil)
	noChild(fx)
	fx.v.account = func() (unitIdentity, bool) { return unitIdentity{}, false }
	if err := fx.v.view(viewPath); err == nil || err.Error() != msgRootOnly {
		t.Errorf("no service user: got %v, want %q", err, msgRootOnly)
	}
	fx = newViewFixture(0o640, viewSvcGID, 0, "", nil)
	noChild(fx)
	fx.v.account = func() (unitIdentity, bool) { return unitIdentity{}, false }
	if err := fx.v.view(viewPath); err != nil {
		t.Errorf("no service user, file fine: %v", err)
	}
	// Not root: Load applied the rule already.
	fx = newViewFixture(0o600, 0, config.ExitInvalid, "x\n", nil)
	noChild(fx)
	fx.v.euid = func() int { return 1000 }
	if err := fx.v.view(viewPath); err != nil {
		t.Errorf("not root: %v", err)
	}
	// A file that can't be looked at is Load's to report.
	fx = newViewFixture(0o600, 0, config.ExitInvalid, "x\n", nil)
	noChild(fx)
	fx.v.owner = func(string) (fs.FileMode, int, int, bool) { return 0, 0, 0, false }
	if err := fx.v.view(viewPath); err != nil {
		t.Errorf("no owner: %v", err)
	}
}

// Abuse: what root starts. The argv is fixed apart from the path, which is made absolute and comes
// after "--" (a path that looks like a flag is a path); the child gets the service's uid, gid and
// groups, no environment, no stdin, no stderr, no extra descriptor, no terminal.
func TestServiceProbeCmd(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/etc/mooring/config.yaml", "--config", "-rf", "--", "a b;$(id)\n.yaml", "../x.yaml"} {
		cmd, err := newServiceProbeCmd(context.Background(), "/usr/local/bin/mooring", path, viewAccount)
		if err != nil {
			t.Fatalf("%q: %v", path, err)
		}
		abs := path
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(wd, path)
		}
		if want := []string{"/usr/local/bin/mooring", "config", "probe-as-service", "--", abs}; !slices.Equal(cmd.Args, want) || cmd.Path != want[0] {
			t.Errorf("%q: argv %q (path %q), want %q", path, cmd.Args, cmd.Path, want)
		}
		if !strings.HasPrefix(cmd.Args[4], "/") {
			t.Errorf("%q: the path argument %q is not absolute", path, cmd.Args[4])
		}
		if cmd.Env == nil || len(cmd.Env) != 0 {
			t.Errorf("%q: the environment is %q, want an empty one (nil inherits root's)", path, cmd.Env)
		}
		if cmd.Stdin != nil || cmd.Stderr != nil || len(cmd.ExtraFiles) != 0 {
			t.Errorf("%q: stdin %v stderr %v extra files %d", path, cmd.Stdin, cmd.Stderr, len(cmd.ExtraFiles))
		}
		if cmd.Dir != "/" || cmd.WaitDelay <= 0 {
			t.Errorf("%q: dir %q, wait delay %v", path, cmd.Dir, cmd.WaitDelay)
		}
		a := cmd.SysProcAttr
		if a == nil || a.Credential == nil || !a.Setsid {
			t.Fatalf("%q: no credential or no new session: %+v", path, a)
		}
		if c := a.Credential; c.Uid != 991 || c.Gid != 990 || !slices.Equal(c.Groups, []uint32{990, 995}) || c.NoSetGroups {
			t.Errorf("%q: credential %+v", path, c)
		}
	}
	// A binary that is not at an absolute path (os.Executable could not say) is not looked up in PATH.
	if _, err := newServiceProbeCmd(context.Background(), "mooring", viewPath, viewAccount); err == nil {
		t.Error("a relative binary was accepted")
	}
	// Never root's uid, even if the account database says the service is root.
	if _, err := newServiceProbeCmd(context.Background(), "/usr/local/bin/mooring", viewPath, unitIdentity{uid: 0, gid: 990}); err == nil {
		t.Error("a uid 0 service account was accepted")
	}
}

const probeHelperEnv = "MOORING_TEST_PROBE_HELPER"

// TestServiceProbeHelper is not a test: TestRunServiceProbeBoundsTheChild runs it as the child.
func TestServiceProbeHelper(t *testing.T) {
	switch os.Getenv(probeHelperEnv) {
	case "":
		return
	case "usable":
		os.Exit(0)
	case "refused":
		fmt.Println("stat /etc/mooring/config.yaml: permission denied")
		os.Exit(config.ExitInvalid)
	case "flood":
		line := bytes.Repeat([]byte("A"), 4096)
		for i := 0; i < 2048; i++ {
			os.Stdout.Write(line)
		}
		os.Exit(config.ExitInvalid)
	case "stderr":
		fmt.Fprintln(os.Stderr, "secret-on-stderr")
		os.Exit(config.ExitInvalid)
	case "hang":
		time.Sleep(time.Minute)
	}
	os.Exit(3)
}

// Abuse: a real child. What is kept of its output is bounded, its stderr is not read, and a child
// that does not end is stopped at the deadline. None of them is a verdict.
func TestRunServiceProbeBoundsTheChild(t *testing.T) {
	run := func(mode string, timeout time.Duration) (int, []byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		cmd, err := newServiceProbeCmd(ctx, os.Args[0], viewPath, viewAccount)
		if err != nil {
			t.Fatal(err)
		}
		// The test is not root: the child keeps this user. Everything else is the real command.
		cmd.SysProcAttr.Credential = nil
		cmd.Args = []string{os.Args[0], "-test.run=^TestServiceProbeHelper$", "-test.count=1"}
		cmd.Env = []string{probeHelperEnv + "=" + mode}
		return runServiceProbeCmd(cmd)
	}
	if code, out, err := run("usable", time.Minute); code != 0 || len(out) != 0 || err != nil {
		t.Errorf("usable: %d %q %v", code, out, err)
	} else if v, _ := judgeProbe(code, out, err); v != probeUsable {
		t.Errorf("usable judged %v", v)
	}
	code, out, err := run("refused", time.Minute)
	if v, reason := judgeProbe(code, out, err); v != probeRefused || reason != "stat /etc/mooring/config.yaml: permission denied" {
		t.Errorf("refused: %d %q %v → %v %q", code, out, err, v, reason)
	}
	code, out, err = run("flood", time.Minute)
	if len(out) > maxProbeLine+2 {
		t.Errorf("flood: kept %d bytes of output", len(out))
	}
	if v, _ := judgeProbe(code, out, err); v != probeUnknown {
		t.Errorf("flood (exit %d, %d bytes, %v) judged %v, want unknown", code, len(out), err, v)
	}
	code, out, err = run("stderr", time.Minute)
	if v, _ := judgeProbe(code, out, err); v != probeUnknown || bytes.Contains(out, []byte("secret")) {
		t.Errorf("stderr: %d %q %v judged %v", code, out, err, v)
	}
	start := time.Now()
	code, out, err = run("hang", 300*time.Millisecond)
	if err == nil || time.Since(start) > 20*time.Second {
		t.Errorf("hang: exit %d, err %v after %v", code, err, time.Since(start))
	}
	if v, _ := judgeProbe(code, out, err); v != probeUnknown {
		t.Errorf("hang judged %v", v)
	}
}

// The directory the mode bits close to the service, top down.
func TestClosedDir(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "a"), filepath.Join(root, "a", "b")
	if err := os.MkdirAll(b, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(b, "config.yaml")
	me := unitIdentity{uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
	if got := closedDir(file, me); got != "" {
		t.Fatalf("every directory is open to its owner, got %q", got)
	}
	if err := os.Chmod(b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(a, 0o700); _ = os.Chmod(b, 0o700) })
	if got := closedDir(file, me); got != b {
		t.Errorf("got %q, want %q", got, b)
	}
	if err := os.Chmod(b, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(a, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := closedDir(file, me); got != a {
		t.Errorf("got %q, want the first closed one %q", got, a)
	}

	acct := unitIdentity{uid: 991, gid: 990, groups: []uint32{990, 995}}
	for _, c := range []struct {
		perm     fs.FileMode
		uid, gid uint32
		want     bool
	}{
		{0o750, 0, 990, true},    // the package's /etc/mooring
		{0o700, 0, 0, false},     // root only
		{0o750, 0, 0, false},     // another group
		{0o750, 0, 995, true},    // a supplementary group
		{0o755, 0, 0, true},      // everyone
		{0o700, 991, 0, true},    // its own
		{0o070, 991, 990, false}, // the owner class is the one that applies
		{0o705, 0, 990, false},   // the group class applies before others
		{0o640, 0, 990, false},   // readable is not enterable
	} {
		if got := modeLetsEnter(c.perm, c.uid, c.gid, acct); got != c.want {
			t.Errorf("mode %#o owner %d:%d: enter=%v, want %v", c.perm, c.uid, c.gid, got, c.want)
		}
	}
}

// The child's side: what `mooring config probe-as-service -- PATH` does with what Load returns.
func TestConfigProbeChild(t *testing.T) {
	const p = "/etc/mooring/config.yaml"
	run := func(loadErr error, args ...string) (int, string, int) {
		var out, errb bytes.Buffer
		loads := 0
		err := runConfigProbe(args, &out, func(path string) (*config.Config, error) {
			loads++
			if path != p {
				t.Errorf("loaded %q", path)
			}
			return nil, loadErr
		})
		code := exitStatus("config", err, &errb)
		if errb.Len() != 0 {
			t.Errorf("%v: main would print %q", args, errb.String())
		}
		return code, out.String(), loads
	}
	if code, out, loads := run(nil, "--", p); code != 0 || out != "" || loads != 1 {
		t.Errorf("usable: exit %d, %q, %d loads", code, out, loads)
	}
	denied := fmt.Errorf("config: stat %s: %w", p, &fs.PathError{Op: "stat", Path: p, Err: syscall.EACCES})
	if code, out, _ := run(denied, "--", p); code != config.ExitInvalid || out != "stat "+p+": permission denied\n" {
		t.Errorf("permission denied: exit %d, %q", code, out)
	}
	group := fmt.Errorf("config: %s is group-readable by gid 20, not the service group 990: %w", p, config.ErrOtherGroup)
	if code, out, _ := run(group, "--", p); code != config.ExitInvalid || !strings.HasPrefix(out, "config: "+p+" is group-readable by gid 20") {
		t.Errorf("another group: exit %d, %q", code, out)
	}
	d := testDiag(p)
	if code, out, _ := run(d, "--", p); code != config.ExitInvalid || strings.Count(out, "\n") != 1 || out != strings.Join(strings.Fields(d.Error()), " ")+"\n" {
		t.Errorf("refused content: exit %d, %q (want the one-line form)", code, out)
	}
	// More than one line is still one line.
	if code, out, _ := run(errors.New("config: refusing to boot:\n  - a\n  - b"), "--", p); code != config.ExitInvalid || out != "config: refusing to boot: - a - b\n" {
		t.Errorf("multi-line: exit %d, %q", code, out)
	}
	// A file that is not there, or an I/O error, is not a verdict about the service.
	gone := fmt.Errorf("config: stat %s: %w", p, &fs.PathError{Op: "stat", Path: p, Err: syscall.ENOENT})
	if code, out, _ := run(gone, "--", p); code != 2 || out != "" {
		t.Errorf("missing: exit %d, %q", code, out)
	}
	// Abuse: nothing but `-- /absolute/path` is accepted, and nothing else is loaded.
	for _, args := range [][]string{nil, {p}, {"--"}, {"--config", p}, {"--", "config.yaml"}, {"--", p, "extra"}, {"--", "-x"}, {"--config=" + p}, {"--", ""}} {
		if code, out, loads := run(nil, args...); code != 2 || out != "" || loads != 0 {
			t.Errorf("args %q: exit %d, %q, %d loads (want 2, nothing, none)", args, code, out, loads)
		}
	}
}

// The hidden subcommand is dispatched by `mooring config`, and is in no usage text.
func TestConfigProbeIsDispatchedAndHidden(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "none.yaml")
	err := cmdConfig([]string{serviceProbeCommand, "--", missing})
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 2 || !ee.printed {
		t.Errorf("got %v, want a silent exit 2 for a file that is not there", err)
	}
	if strings.Contains(usage, serviceProbeCommand) {
		t.Error("the hidden subcommand is in the usage")
	}
	uerr := cmdConfig([]string{"no-such"})
	if uerr == nil || strings.Contains(uerr.Error(), serviceProbeCommand) {
		t.Errorf("the config usage names the hidden subcommand: %v", uerr)
	}
}

// After an install, a file the service can't reach is warned about with what opens it, not with
// the file's chown/chmod.
func TestConfigEditWarnsAboutAClosedDirectory(t *testing.T) {
	fx := newEditFixture(t, 0o640, writeEditor(editNew), "")
	msg := fx.path + " can't be used by the service (user mooring): stat " + fx.path + ": permission denied"
	fx.e.serveRefusal = func(string) error {
		return &serviceCantUseError{msg: msg, advice: "the service must be able to enter " + fx.dir,
			command: "sudo chown root:mooring " + fx.dir + " && sudo chmod 0750 " + fx.dir}
	}
	code, out := fx.run()
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	want := "warning: mooring serve will not start with " + fx.path + " as it is now, whatever is in it: " + msg + "\n" +
		"  The service must be able to enter " + fx.dir + ":\n  sudo chown root:mooring " + fx.dir + " && sudo chmod 0750 " + fx.dir + "\n"
	if !strings.Contains(out, want) {
		t.Errorf("got:\n%s\nwant it to contain:\n%s", out, want)
	}
	if strings.Contains(out, "chmod 0640") || strings.Contains(out, "Its owner and mode were kept") {
		t.Errorf("the file's own fix is not the fix here:\n%s", out)
	}
}

// End to end, for real: root, a `mooring` user, the built binary re-executed as that user. Skipped
// anywhere else (run it in a throwaway container: see the test's skip message).
func TestServiceViewAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root and a mooring user (throwaway container: useradd -r mooring && go test ./cmd/mooring -run TestServiceViewAsRoot)")
	}
	acct, ok := lookupUnitIdentity()
	gid, gok := lookupGroupID(serviceGroup)
	if !ok || !gok {
		t.Skip("no mooring user and group on this host")
	}
	if u, err := user.Lookup(serviceGroup); err != nil || fmt.Sprint(acct.uid) != u.Uid || int(acct.gid) != gid || !slices.Contains(acct.groups, acct.gid) {
		t.Fatalf("account %+v, user %+v (%v), group id %d", acct, u, err, gid)
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go tool to build the binary with")
	}
	// Not t.TempDir: its parent is 0700, and the service must reach the binary and the test's files.
	base, err := os.MkdirTemp("", "mooring-view-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(base, "mooring")
	if out, err := exec.Command(goTool, "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	src, _ := cliHost(t)
	// Intentional: the hatch cliHost sets is taken away again. Root's own load must judge the file
	// as it does on a server, and the child never sees the variable anyway.
	t.Setenv(config.DevInsecurePermsEnv, "")
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "etc")
	path := filepath.Join(dir, "config.yaml")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	set := func(p string, uid, g int, mode fs.FileMode) {
		t.Helper()
		if err := os.Chown(p, uid, g); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	v := defaultServiceViewer()
	v.probe = func(p string, a unitIdentity) (int, []byte, error) { return runServiceProbe(bin, p, a) }
	check := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		err := runConfigCheck(append(args, "--config", path), configCheckEnv{stdout: &out, stderr: &errb, load: config.Load, serviceView: v.view})
		return exitStatus("config", err, &errb), out.String(), errb.String()
	}
	dirFix := "sudo chown root:mooring " + dir + " && sudo chmod 0750 " + dir

	// 1. The file is right (root:mooring 0640) and its directory is root's alone: root loads it,
	// the service can't reach it.
	set(path, 0, gid, 0o640)
	set(dir, 0, 0, 0o700)
	if _, err := config.Load(path); err != nil {
		t.Fatalf("root's own load: %v", err)
	}
	if err := serviceViewOf(path, 0o640, 0, gid, gid); err != nil {
		t.Fatalf("the mode-bit rule sees nothing wrong with the file: %v", err)
	}
	code, out, errOut := check()
	wantMsg := path + " can't be used by the service (user mooring): stat " + path + ": permission denied"
	if code != config.ExitInvalid || out != "" || !strings.HasPrefix(errOut, wantMsg+"\n") || !strings.Contains(errOut, "The service must be able to enter "+dir+":\n  "+dirFix+"\n") {
		t.Errorf("closed directory: exit %d, stdout %q\nstderr:\n%s", code, out, errOut)
	}
	t.Logf("closed directory:\n%s", errOut)
	if x, ok := doctorServiceViewResult(path, v.view(path)); !ok || x.state != "fail" || !strings.HasPrefix(x.detail, wantMsg) || !strings.Contains(x.fix, dirFix) {
		t.Errorf("doctor, closed directory: %+v", x)
	}

	// 2. The package's directory (root:mooring 0750): OK.
	set(dir, 0, gid, 0o750)
	if code, out, errOut := check(); code != 0 || !strings.HasPrefix(out, "OK: "+path+" is valid\n") {
		t.Errorf("root:mooring 0750 directory: exit %d\n%s%s", code, out, errOut)
	}
	if x, ok := doctorServiceViewResult(path, v.view(path)); ok {
		t.Errorf("doctor, open directory: %+v", x)
	}

	// 3. The two mode-bit refusals keep their messages, now because the service was refused.
	set(path, 0, 0, 0o600)
	if code, _, errOut := check(); code != config.ExitInvalid || !strings.HasPrefix(errOut, path+" is readable by root only (mode 0600): the service (user mooring) can't read it\n") || !strings.Contains(errOut, permsFixCommand(path)) {
		t.Errorf("root:root 0600: exit %d\n%s", code, errOut)
	}
	set(path, 0, 0, 0o640)
	if code, _, errOut := check(); code != config.ExitInvalid || !strings.HasPrefix(errOut, path+" belongs to group id 0, not to the service's group mooring") {
		t.Errorf("root:root 0640: exit %d\n%s", code, errOut)
	}

	// 4. The same root:root 0640 file with an ACL that lets the service read it: OK.
	setfacl, err := exec.LookPath("setfacl")
	if err != nil {
		t.Log("ACL case not run: no setfacl here")
	} else if aout, err := exec.Command(setfacl, "-m", "u:"+serviceGroup+":r", path).CombinedOutput(); err != nil {
		t.Logf("ACL case not run: setfacl: %v: %s", err, aout)
	} else {
		fi, _ := os.Stat(path)
		st := fi.Sys().(*syscall.Stat_t)
		if serviceViewOf(path, fi.Mode().Perm(), int(st.Uid), int(st.Gid), gid) == nil {
			t.Errorf("the mode-bit rule was expected to refuse the ACL file (mode %#o, gid %d)", fi.Mode().Perm(), st.Gid)
		}
		code, out, errOut := check()
		if code != 0 || !strings.HasPrefix(out, "OK: "+path+" is valid\n") {
			t.Errorf("ACL file: exit %d\n%s%s", code, out, errOut)
		}
		t.Logf("ACL case ran: mode %#o root:root + u:mooring:r → exit %d", fi.Mode().Perm(), code)
	}

	// 5. A child that is not there (the binary was replaced under a running command) decides nothing.
	v.probe = func(p string, a unitIdentity) (int, []byte, error) { return runServiceProbe(bin+" (deleted)", p, a) }
	set(path, 0, gid, 0o640)
	set(dir, 0, 0, 0o700)
	if code, out, _ := check(); code != 0 || !strings.HasPrefix(out, "OK: ") {
		t.Errorf("no child, mode bits fine: exit %d (the mode-bit rule can't see the directory)", code)
	}
	set(path, 0, 0, 0o600)
	if code, _, _ := check(); code != config.ExitInvalid {
		t.Errorf("no child, root-only file: exit %d, want 78 from the mode-bit rule", code)
	}
}
