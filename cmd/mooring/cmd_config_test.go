package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/yamldiag"
)

// testDiag is a refusal as config.Load returns it: two problems shown, one more counted.
func testDiag(file string) *yamldiag.Diagnostics {
	return &yamldiag.Diagnostics{
		File: file,
		Problems: []yamldiag.Problem{
			{Pos: yamldiag.Pos{Line: 12, Col: 3}, Kind: yamldiag.KindUnknownKey, Path: "egde", Msg: "unknown key egde", Hint: "did you mean edge?", Excerpt: "egde:"},
			{Pos: yamldiag.Pos{Line: 20, Col: 9}, Kind: yamldiag.KindType, Path: "trust_proxy", Msg: "must be true or false without quotes", Excerpt: "trust_proxy: …"},
		},
		More:  1,
		Cause: errors.New("config: parse: field egde not found"),
	}
}

// diagRendered reports whether internal/yamldiag renders yet (false: it is still the contract stub,
// and the assertions on its text are skipped).
func diagRendered() bool { return testDiag("f").Terminal() != "" }

func runCheck(t *testing.T, load func(string) (*config.Config, error), args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	err := runConfigCheck(args, configCheckEnv{stdout: &out, stderr: &errb, load: load, serviceUser: func() bool { return false },
		serviceView: func(string) error { return nil }})
	code = exitStatus("config", err, &errb)
	return code, out.String(), errb.String()
}

func TestConfigCheckValid(t *testing.T) {
	path, _ := cliHost(t)
	code, out, errOut := runCheck(t, config.Load, "--config", path)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if !strings.HasPrefix(out, "OK: "+path+" is valid\n") {
		t.Errorf("stdout must start with the OK line:\n%s", out)
	}
	if errOut != "" {
		t.Errorf("a valid file prints nothing on stderr: %q", errOut)
	}
	raw, _ := os.ReadFile(path)
	for _, line := range strings.Split(string(raw), "\n") {
		// No value of the file is echoed: not the key, not the password hash.
		if k, v, ok := strings.Cut(line, ": "); ok && (strings.Contains(k, "encryption_key") || strings.Contains(k, "password_hash")) {
			if strings.Contains(out, strings.Trim(v, `"`)) {
				t.Errorf("config check printed the value of %s", strings.TrimSpace(k))
			}
		}
	}

	// --quiet: the exit status only.
	code, out, errOut = runCheck(t, config.Load, "--quiet", "--config", path)
	if code != 0 || out != "" || errOut != "" {
		t.Errorf("--quiet on a valid file: exit %d stdout %q stderr %q", code, out, errOut)
	}

	// --json: one object.
	code, out, _ = runCheck(t, config.Load, "--json", "--config", path)
	var rep configCheckReport
	if code != 0 || json.Unmarshal([]byte(out), &rep) != nil || !rep.OK || rep.File != path {
		t.Errorf("--json on a valid file: exit %d, %q", code, out)
	}
}

// The load warnings and the certificate hostnames are printed for a valid file.
func TestConfigCheckWarningsAndHostnames(t *testing.T) {
	path, _ := cliHost(t)
	load := func(p string) (*config.Config, error) {
		cfg, err := config.Load(p)
		if err == nil {
			cfg.LoadWarnings = append(cfg.LoadWarnings, "alerting.quiet_start_hour is out of range")
		}
		return cfg, err
	}
	code, out, _ := runCheck(t, load, "--config", path)
	if code != 0 || !strings.Contains(out, "warning: alerting.quiet_start_hour is out of range\n") {
		t.Errorf("exit %d, the load warning must be printed:\n%s", code, out)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	names := cfg.CertHostnames()
	if len(names) == 0 {
		if strings.Contains(out, "Certificates are requested") {
			t.Errorf("no hostnames, yet the section is printed:\n%s", out)
		}
		return
	}
	if !strings.Contains(out, "Certificates are requested for (plus one per app route with its own hostname):\n") {
		t.Errorf("hostname section missing:\n%s", out)
	}
	for _, n := range names {
		if !strings.Contains(out, n.Host) || !strings.Contains(out, n.Why) {
			t.Errorf("hostname %s (%s) not printed:\n%s", n.Host, n.Why, out)
		}
	}
}

func TestConfigCheckRefused(t *testing.T) {
	d := testDiag("/etc/mooring/config.yaml")
	load := func(string) (*config.Config, error) { return nil, fmt.Errorf("wrapped: %w", d) }

	code, out, errOut := runCheck(t, load)
	if config.ExitInvalid != 78 || code != 78 {
		t.Fatalf("a refused file must exit 78, got %d", code)
	}
	if out != "" {
		t.Errorf("a refusal prints nothing on stdout: %q", out)
	}
	if !strings.Contains(errOut, "is refused") {
		t.Errorf("stderr must say the file is refused:\n%s", errOut)
	}
	if strings.Contains(errOut, "mooring config:") {
		t.Errorf("the diagnostics are the message; main must not print the error again:\n%s", errOut)
	}
	if diagRendered() && !strings.Contains(errOut, strings.TrimRight(d.Terminal(), "\n")) {
		t.Errorf("stderr must carry Diagnostics.Terminal():\n%s", errOut)
	}

	code, out, errOut = runCheck(t, load, "--quiet")
	if code != 78 || out != "" || errOut != "" {
		t.Errorf("--quiet on a refused file: exit %d stdout %q stderr %q (want 78 and silence)", code, out, errOut)
	}

	code, out, errOut = runCheck(t, load, "--json")
	var got struct {
		File     string            `json:"file"`
		Problems []json.RawMessage `json:"problems"`
	}
	if code != 78 || errOut != "" || json.Unmarshal([]byte(out), &got) != nil || got.File != d.File {
		t.Fatalf("--json on a refused file: exit %d stderr %q stdout %q", code, errOut, out)
	}
	if diagRendered() && (len(got.Problems) != 2 || strings.TrimSpace(out) != string(d.JSON())) {
		t.Errorf("--json must be Diagnostics.JSON(): %q", out)
	}
}

// A refusal that isn't a Diagnostics (the file's owner or mode) is still exit 78, with its message.
func TestConfigCheckRefusedPermissions(t *testing.T) {
	path, _ := cliHost(t)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCheck(t, config.Load, "--config", path)
	if code != 78 || !strings.Contains(errOut, "world-accessible") {
		t.Errorf("a world-readable config.yaml: exit %d, stderr %q", code, errOut)
	}
	code, out, _ := runCheck(t, config.Load, "--json", "--config", path)
	var got struct {
		Problems []struct{ Msg string } `json:"problems"`
	}
	if code != 78 || json.Unmarshal([]byte(out), &got) != nil {
		t.Fatalf("--json: exit %d, %q", code, out)
	}
}

// A real file serve refuses is refused here too (the same Load).
func TestConfigCheckRefusedRealFile(t *testing.T) {
	path, _ := cliHost(t)
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append(raw, []byte("no_such_key: 1\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCheck(t, config.Load, "--config", path)
	if code != 78 {
		t.Fatalf("an unknown key must exit 78, got %d (%s)", code, errOut)
	}
	// Intentional: an unknown key is not echoed (a secret typed where a key belongs stays out of
	// the terminal); the line number and "unknown key on this line" say where it is.
	if !strings.Contains(errOut, "unknown key on this line") || strings.Contains(errOut, "no_such_key") {
		t.Errorf("the message must point at the unknown key without printing it:\n%s", errOut)
	}
	raw, _ = os.ReadFile(path)
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, ": "); ok && (strings.Contains(k, "encryption_key") || strings.Contains(k, "password_hash")) {
			if strings.Contains(errOut, strings.Trim(v, `"`)) {
				t.Errorf("the refusal printed the value of %s", strings.TrimSpace(k))
			}
		}
	}
}

func TestConfigCheckUnreadableAndUsage(t *testing.T) {
	t.Setenv(config.DevInsecurePermsEnv, "1")
	missing := filepath.Join(t.TempDir(), "config.yaml")
	code, out, errOut := runCheck(t, config.Load, "--config", missing)
	if code != 2 || out != "" || !strings.Contains(errOut, missing) {
		t.Errorf("a missing file: exit %d stdout %q stderr %q (want 2)", code, out, errOut)
	}
	code, out, errOut = runCheck(t, config.Load, "--quiet", "--config", missing)
	if code != 2 || out != "" || errOut != "" {
		t.Errorf("--quiet on a missing file: exit %d stdout %q stderr %q (want 2 and silence)", code, out, errOut)
	}
	// --json: an object on stdout (the one `validate --json` prints), nothing on stderr.
	code, out, errOut = runCheck(t, config.Load, "--json", "--config", missing)
	var unjudged struct {
		OK    *bool  `json:"ok"`
		File  string `json:"file"`
		Error string `json:"error"`
	}
	if code != 2 || errOut != "" || json.Unmarshal([]byte(out), &unjudged) != nil || unjudged.OK == nil || *unjudged.OK || unjudged.File != missing || !strings.Contains(unjudged.Error, "no such file") {
		t.Errorf("--json on a missing file: exit %d stdout %q stderr %q (want 2 and an error object)", code, out, errOut)
	}
	// --errors-only: the error is still printed.
	if code, out, errOut := runCheck(t, config.Load, "--errors-only", "--config", missing); code != 2 || out != "" || !strings.Contains(errOut, missing) {
		t.Errorf("--errors-only on a missing file: exit %d stdout %q stderr %q", code, out, errOut)
	}
	for _, args := range [][]string{{"--no-such-flag"}, {"extra"}, {"--quiet", "--json"}, {"--quiet", "--errors-only"}} {
		if code, _, _ := runCheck(t, config.Load, args...); code != 2 {
			t.Errorf("config check %v: exit %d, want 2", args, code)
		}
	}
	// The subcommand dispatch: nothing or an unknown name is a usage error.
	for _, args := range [][]string{nil, {"bogus"}} {
		if code := exitStatus("config", cmdConfig(args), &bytes.Buffer{}); code != 2 {
			t.Errorf("mooring config %v: exit %d, want 2", args, code)
		}
	}
	// A read error is not a refusal, and a Diagnostics is never "unreadable".
	if !configUnreadable(fmt.Errorf("config: stat x: %w", &fs.PathError{Op: "stat", Path: "x", Err: fs.ErrPermission})) {
		t.Error("a permission error reading the file is unreadable (exit 2)")
	}
	if configUnreadable(testDiag("x")) || configUnreadable(errors.New("config: x must be owned by root")) {
		t.Error("a refusal is not an unreadable file")
	}
}

// With a .last-good beside the file (config edit writes it), the changed keys are listed by how
// they take effect.
func TestConfigCheckChangedSinceLastGood(t *testing.T) {
	path, _ := cliHost(t)
	raw, _ := os.ReadFile(path)
	prev := strings.Replace(string(raw), `"127.0.0.1/32"`, `"203.0.113.9/32"`, 1)
	if prev == string(raw) {
		t.Fatal("fixture: allowlist entry not found")
	}
	if err := os.WriteFile(lastGoodPath(path), []byte(prev), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runCheck(t, config.Load, "--config", path)
	if code != 0 || !strings.Contains(out, "Changed since "+lastGoodPath(path)+":\n") {
		t.Fatalf("exit %d, the changed section is missing:\n%s", code, out)
	}
	a, _ := config.Parse([]byte(prev))
	b, _ := config.Parse(raw)
	if rl, rs := config.DiffApply(a, b); len(rl)+len(rs) == 0 {
		t.Log("config.DiffApply is still the contract stub: key assertions skipped")
	} else if !strings.Contains(out, "  reload  ("+reloadCommand+"): ip_allowlist\n") {
		t.Errorf("ip_allowlist must be listed under reload:\n%s", out)
	}

	// A .last-good that no longer loads is said, not fatal.
	if err := os.WriteFile(lastGoodPath(path), []byte("no_such_key: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = runCheck(t, config.Load, "--config", path)
	if code != 0 || !strings.Contains(out, "does not load") || strings.Contains(out, "Changed since") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

func TestWriteApplyLines(t *testing.T) {
	var b bytes.Buffer
	writeApplyLines(&b, []string{"ip_allowlist", "retention"}, []string{"edge"})
	want := "  reload  (sudo systemctl reload mooring): ip_allowlist, retention\n" +
		"  restart (sudo systemctl restart mooring): edge\n" +
		"  a restart applies both\n"
	if b.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", b.String(), want)
	}
	b.Reset()
	writeApplyLines(&b, nil, nil)
	if b.String() != "  no setting changed; nothing to apply\n" {
		t.Errorf("no change: %q", b.String())
	}
}

func TestExitStatus(t *testing.T) {
	var w bytes.Buffer
	if got := exitStatus("x", nil, &w); got != 0 || w.Len() != 0 {
		t.Errorf("nil: %d %q", got, w.String())
	}
	if got := exitStatus("token", errors.New("boom"), &w); got != 1 || w.String() != "mooring token: boom\n" {
		t.Errorf("a plain error exits 1 and is printed: %d %q", got, w.String())
	}
	w.Reset()
	wrapped := fmt.Errorf("outer: %w", &exitError{code: 78, err: errors.New("bad"), printed: true})
	if got := exitStatus("serve", wrapped, &w); got != 78 || w.Len() != 0 {
		t.Errorf("a printed exitError keeps its code and prints nothing: %d %q", got, w.String())
	}
	if got := exitStatus("config", usageError("nope"), &w); got != 2 || w.String() != "mooring config: nope\n" {
		t.Errorf("usage error: %d %q", got, w.String())
	}
	if got := exitStatus("x", &exitError{code: 0, err: errors.New("e")}, &w); got != 1 {
		t.Errorf("an error never exits 0, got %d", got)
	}
}

var refusedLine = regexp.MustCompile(`^time=\S+ level=ERROR msg="config\.yaml is not valid; not starting" file=/etc/mooring/config\.yaml line=12 problems=3 detail=.* hint="run: sudo mooring config check"\n$`)

func TestLogConfigRefused(t *testing.T) {
	var b bytes.Buffer
	log := slog.New(slog.NewTextHandler(&b, &slog.HandlerOptions{Level: slog.LevelInfo}))
	d := testDiag("/etc/mooring/config.yaml")
	logConfigRefused(log, "/etc/mooring/config.yaml", fmt.Errorf("x: %w", d))
	if !refusedLine.MatchString(b.String()) {
		t.Errorf("the refusal line:\n%s", b.String())
	}
	if diagRendered() && !strings.Contains(b.String(), "unknown key egde") {
		t.Errorf("detail must be the one-line Error():\n%s", b.String())
	}

	// An error that isn't a Diagnostics, of several lines: still ONE line, one problem, no line=.
	b.Reset()
	logConfigRefused(log, "/c.yaml", errors.New("config: invalid:\n  - a\n  - b"))
	got := b.String()
	if strings.Count(got, "\n") != 1 || !strings.Contains(got, " file=/c.yaml problems=1 detail=") || strings.Contains(got, " line=") {
		t.Errorf("a plain refusal:\n%s", got)
	}
}

// serve exits 78 for a config.yaml it refuses or may not read, and 1 (restarted by the unit) for
// one that isn't there: the file may be on a volume that attaches late (owner decision). main
// prints nothing after the log line either way.
func TestServeConfigRefusedExit(t *testing.T) {
	t.Setenv(config.DevInsecurePermsEnv, "1")
	dir := t.TempDir()
	bad := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(bad, []byte("no_such_key: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unreadable := filepath.Join(dir, "unreadable.yaml")
	if err := os.WriteFile(unreadable, []byte("x: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, path, msg string
		code            int
		skip            bool
	}{
		{"refused", bad, "config.yaml is not valid; not starting", config.ExitInvalid, false},
		{"missing", filepath.Join(dir, "missing.yaml"), "config.yaml not found; not starting", 1, false},
		{"missing directory", filepath.Join(dir, "no-such-dir", "config.yaml"), "config.yaml not found; not starting", 1, false},
		{"permission denied", unreadable, "config.yaml can't be read; not starting", config.ExitInvalid, os.Geteuid() == 0},
	}
	for _, c := range cases {
		if c.skip {
			continue
		}
		log := captureServeLog(t)
		wantStartExit(t, c.name, cmdServe([]string{"--config", c.path}), log, c.msg, c.code)
		if retried := strings.Contains(log.String(), "starts the service again every 2s"); retried != (c.code == 1) {
			t.Errorf("%s: the line promises a retry = %v, exit %d:\n%s", c.name, retried, c.code, log.String())
		}
	}
	// Any other start-up error keeps exit 1 (and is restarted by the unit).
	if got := exitStatus("serve", errors.New("open db: disk I/O error"), &bytes.Buffer{}); got != 1 {
		t.Errorf("a non-config failure must exit 1, got %d", got)
	}
}

// configStartExit: 78 only for what a restart can't fix.
func TestConfigStartExit(t *testing.T) {
	pathErr := func(e error) error {
		return fmt.Errorf("config: stat /etc/mooring/config.yaml: %w", &fs.PathError{Op: "stat", Path: "/etc/mooring/config.yaml", Err: e})
	}
	for _, c := range []struct {
		name string
		err  error
		want int
	}{
		{"not there", pathErr(fs.ErrNotExist), 1},
		{"a parent is not a directory yet", pathErr(syscall.ENOTDIR), 1},
		{"I/O error", pathErr(syscall.EIO), 1},
		{"permission denied", pathErr(fs.ErrPermission), 78},
		{"EACCES", pathErr(syscall.EACCES), 78},
		{"refused content", testDiag("/etc/mooring/config.yaml"), 78},
		{"refused owner", errors.New("config: /etc/mooring/config.yaml must be owned by root"), 78},
		{"another group", fmt.Errorf("config: group: %w", config.ErrOtherGroup), 78},
	} {
		if got := configStartExit(c.err); got != c.want {
			t.Errorf("%s: exit %d, want %d", c.name, got, c.want)
		}
	}
}

type fakeAllowlistEdge struct {
	calls       []string
	list        []string
	hadDeadline bool
	err         error
	// state is the edge's state after the reconcile, given the list that was set (nil: applied).
	state func(set []string) (inForce []string, pending bool)
}

func (f *fakeAllowlistEdge) AdminAllowlistState() ([]string, bool) {
	f.calls = append(f.calls, "state")
	if f.state == nil {
		return f.list, false
	}
	return f.state(f.list)
}

func (f *fakeAllowlistEdge) SetAdminAllowlist(l []string) {
	f.calls = append(f.calls, "set")
	f.list = l
}

func (f *fakeAllowlistEdge) Reconcile(ctx context.Context) error {
	f.calls = append(f.calls, "reconcile")
	_, f.hadDeadline = ctx.Deadline()
	return f.err
}

func TestPushAdminAllowlist(t *testing.T) {
	var b bytes.Buffer
	log := slog.New(slog.NewTextHandler(&b, nil))
	f := &fakeAllowlistEdge{}
	pushAdminAllowlist(context.Background(), f, []string{"203.0.113.7/32"}, log)
	if strings.Join(f.calls, ",") != "set,reconcile,state" || len(f.list) != 1 || f.list[0] != "203.0.113.7/32" {
		t.Errorf("the list is set, then reconciled, then the edge is asked what it serves: %v %v", f.calls, f.list)
	}
	if !f.hadDeadline {
		t.Error("the reconcile must run on a bounded context")
	}
	if strings.Contains(b.String(), "level=WARN") {
		t.Errorf("no warning on success:\n%s", b.String())
	}
	b.Reset()
	f = &fakeAllowlistEdge{err: errors.New("caddy refused the load"), state: func([]string) ([]string, bool) { return []string{"198.51.100.1/32"}, false }}
	pushAdminAllowlist(context.Background(), f, []string{"203.0.113.7/32"}, log)
	if !strings.Contains(b.String(), "level=WARN") || !strings.Contains(b.String(), "caddy refused the load") {
		t.Errorf("an edge that refuses the list is a warning:\n%s", b.String())
	}
}

// The edge gets the canonical allowlist: a bare address as /32.
func TestEdgeBaseConfigCanonicalAllowlist(t *testing.T) {
	path, _ := cliHost(t)
	raw, _ := os.ReadFile(path)
	y := strings.Replace(string(raw), `"127.0.0.1/32"`, `"198.51.100.7"`+"\n  - \"203.0.113.0/24\"", 1)
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	got := edgeBaseConfig(cfg).AdminAllowlist
	if strings.Join(got, " ") != "198.51.100.7/32 203.0.113.0/24" {
		t.Errorf("AdminAllowlist = %v, want the canonical prefixes", got)
	}
}

func TestDoctorConfigResult(t *testing.T) {
	if _, ok := doctorConfigResult("/c", nil); ok {
		t.Error("a loaded config adds no line")
	}
	d := testDiag("/etc/mooring/config.yaml")
	r, ok := doctorConfigResult("/etc/mooring/config.yaml", d)
	if !ok || r.state != "fail" || !strings.Contains(r.fix, "sudo mooring config check") {
		t.Errorf("a refused config.yaml is a fail with the check command: %+v", r)
	}
	if diagRendered() && !strings.Contains(r.detail, strings.TrimRight(d.Terminal(), "\n")) {
		t.Errorf("the fail shows Diagnostics.Terminal():\n%s", r.detail)
	}
	if r, _ := doctorConfigResult("/c", errors.New("config: /c must be owned by root (uid 0); got uid 501")); r.state != "fail" || !strings.Contains(r.detail, "owned by root") {
		t.Errorf("a refused owner is a fail: %+v", r)
	}
	missing := fmt.Errorf("config: stat /c: %w", &fs.PathError{Op: "stat", Path: "/c", Err: fs.ErrNotExist})
	if r, ok := doctorConfigResult("/c", missing); !ok || r.state != "warn" {
		t.Errorf("no config.yaml yet is a warn: %+v", r)
	}
	denied := fmt.Errorf("config: read /c: %w", &fs.PathError{Op: "open", Path: "/c", Err: fs.ErrPermission})
	if r, ok := doctorConfigResult("/c", denied); !ok || r.state != "warn" || !strings.Contains(r.fix, "sudo") {
		t.Errorf("a file this user may not read is a warn: %+v", r)
	}
}

// A file root loads and the service can't use is a fail in doctor too, with the fix command.
func TestDoctorServiceViewResult(t *testing.T) {
	if _, ok := doctorServiceViewResult("/c", nil); ok {
		t.Error("nothing to report adds no line")
	}
	r, ok := doctorServiceViewResult("/etc/mooring/config.yaml", errors.New("/etc/mooring/config.yaml is readable by root only (mode 0600): the service (user mooring) can't read it"))
	if !ok || r.state != "fail" || !strings.Contains(r.detail, "can't read it") || !strings.Contains(r.detail, "will not start") ||
		r.fix != "run: sudo chown root:mooring /etc/mooring/config.yaml && sudo chmod 0640 /etc/mooring/config.yaml" {
		t.Errorf("%+v", r)
	}
	var rep report
	rep.add(r)
	if doctorExit(rep) == nil {
		t.Error("doctor must exit non-zero for it")
	}
}

func TestDoctorExit(t *testing.T) {
	var rep report
	rep.add(result{"docker", "ok", "found", ""})
	rep.add(result{"logs", "warn", "uncapped", "cap them"})
	if err := doctorExit(rep); err != nil {
		t.Errorf("warnings alone exit 0: %v", err)
	}
	rep.add(result{"config", "fail", "refused:\nconfig.yaml:3:1: unknown key", "fix it"})
	var w bytes.Buffer
	if got := exitStatus("doctor", doctorExit(rep), &w); got != 1 || w.Len() != 0 {
		t.Errorf("a failed check exits 1 without a second message: %d %q", got, w.String())
	}
	// A detail of several lines stays under its check.
	w.Reset()
	rep.print(&w)
	if !strings.Contains(w.String(), "refused:\n      config.yaml:3:1: unknown key\n      → fix it\n") {
		t.Errorf("multi-line detail:\n%s", w.String())
	}
}

func validDefinition(t *testing.T) []byte {
	t.Helper()
	d := &definition.Definition{
		APIVersion: definition.APIVersion, Kind: "App", Metadata: definition.Metadata{Slug: "shop"},
		Spec: definition.Spec{Compose: definition.Compose{Source: definition.SourceGenerated,
			Services: map[string]definition.Service{"web": {Image: "nginx:1.27"}}}},
	}
	raw, err := definition.Canonical(d)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestValidateOutput(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "mooring.yaml")
	if err := os.WriteFile(good, validDefinition(t), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if err := runValidate(good, "", false, &out, &errb); err != nil || !strings.HasPrefix(out.String(), "OK: shop (kind=App") {
		t.Fatalf("valid: %v %q", err, out.String())
	}
	out.Reset()
	var rep validateReport
	if err := runValidate(good, "", true, &out, &errb); err != nil || json.Unmarshal(out.Bytes(), &rep) != nil || !rep.OK || rep.Slug != "shop" || rep.Kind != "App" || rep.File != good {
		t.Fatalf("valid --json: %v %q", err, out.String())
	}

	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, append(validDefinition(t), []byte("no_such_key: 1\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	err := runValidate(bad, "", false, &out, &errb)
	if err == nil || out.Len() != 0 {
		t.Fatalf("a refused definition must fail and print no OK: %v %q", err, out.String())
	}
	var d *yamldiag.Diagnostics
	if errors.As(err, &d) && diagRendered() {
		var w bytes.Buffer
		if got := exitStatus("validate", err, &w); got != 1 || w.Len() != 0 {
			t.Errorf("a Diagnostics is printed once, by validate: exit %d, main printed %q", got, w.String())
		}
		if !strings.Contains(errb.String(), strings.TrimRight(d.Terminal(), "\n")) {
			t.Errorf("stderr must carry Diagnostics.Terminal():\n%s", errb.String())
		}
	} else {
		t.Log("definition.Parse does not return a rendered Diagnostics yet: Terminal() assertions skipped")
	}

	out.Reset()
	errb.Reset()
	err = runValidate(bad, "", true, &out, &errb)
	var got struct {
		File     string            `json:"file"`
		Problems []json.RawMessage `json:"problems"`
	}
	if code := exitStatus("validate", err, &errb); code != 1 || errb.Len() != 0 || json.Unmarshal(out.Bytes(), &got) != nil || len(got.Problems) == 0 {
		t.Errorf("refused --json: exit %d stderr %q stdout %q", code, errb.String(), out.String())
	}
}

func TestGenKeyHint(t *testing.T) {
	raw, err := os.ReadFile("cmd_keys.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "0600 root:root") || !strings.Contains(string(raw), "(root:mooring, mode 0640)") {
		t.Error("gen-key must name the supported owner and mode, root:mooring 0640")
	}
}

// --- the unit and the package script ---

func TestUnitReloadChecksConfigFirst(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/systemd/mooring.service")
	if err != nil {
		t.Fatal(err)
	}
	var reloads []string
	prevent := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "ExecReload="); ok {
			reloads = append(reloads, v)
		}
		if v, ok := strings.CutPrefix(line, "RestartPreventExitStatus="); ok {
			prevent = v
		}
	}
	// --errors-only: a reload of a valid file writes nothing of the check to the journal.
	want := []string{"/usr/local/bin/mooring config check --errors-only --config /etc/mooring/config.yaml", "/bin/kill -HUP $MAINPID"}
	if strings.Join(reloads, "|") != strings.Join(want, "|") {
		t.Errorf("ExecReload lines = %q, want the check and then the SIGHUP", reloads)
	}
	if prevent != fmt.Sprint(config.ExitInvalid) {
		t.Errorf("RestartPreventExitStatus = %q, want %d", prevent, config.ExitInvalid)
	}
	for _, keep := range []string{"Restart=on-failure", "NoNewPrivileges=true", "ProtectSystem=strict", "SystemCallFilter=~@privileged @obsolete", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE", "ExecStart=/usr/local/bin/mooring serve --config /etc/mooring/config.yaml"} {
		if !strings.Contains(string(raw), "\n"+keep+"\n") {
			t.Errorf("the unit lost %q", keep)
		}
	}
}

// postinstallRestartBlock is the upgrade block of the package's postinstall script with the binary
// and the config pointed at a temp dir, under the script's own `set -e`.
func postinstallRestartBlock(t *testing.T, bin, cfg string) string {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/nfpm/postinstall.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, "\nset -e\n") {
		t.Fatal("postinstall.sh must run under set -e (the test assumes it)")
	}
	_, rest, ok := strings.Cut(s, "# upgrade-restart: begin\n")
	block, _, ok2 := strings.Cut(rest, "# upgrade-restart: end\n")
	if !ok || !ok2 {
		t.Fatal("postinstall.sh: upgrade-restart markers not found")
	}
	for from, to := range map[string]string{
		"MOORING_BIN=/usr/local/bin/mooring\n":      "MOORING_BIN='" + bin + "'\n",
		"MOORING_CONFIG=/etc/mooring/config.yaml\n": "MOORING_CONFIG='" + cfg + "'\n",
	} {
		if !strings.Contains(block, from) {
			t.Fatalf("postinstall.sh: %q not found", from)
		}
		block = strings.Replace(block, from, to, 1)
	}
	return "set -e\n" + block + "echo REACHED-END\n"
}

func TestPostinstallChecksConfigBeforeRestart(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	cases := []struct {
		name        string
		config      bool
		checkRC     string // the fake binary's exit status; "" = there is no binary
		systemctlRC string
		wantRestart bool
		wantCheck   bool
		wantRefused bool
		asService   bool // runuser and the mooring user exist: the check runs as the service user
		inactive    bool // the unit is not running
		noGroupFlag bool // this runuser doesn't take -g
	}{
		{name: "valid config: restarted", config: true, checkRC: "0", wantRestart: true, wantCheck: true},
		{name: "refused config: not restarted, problem printed", config: true, checkRC: "78", wantCheck: true, wantRefused: true},
		{name: "unreadable (2): restarted as before", config: true, checkRC: "2", wantRestart: true, wantCheck: true},
		{name: "check crashed (1): restarted as before", config: true, checkRC: "1", wantRestart: true, wantCheck: true},
		{name: "no binary: restarted as before", config: true, checkRC: "", wantRestart: true},
		{name: "no config yet: nothing started, nothing checked", config: false, checkRC: "0"},
		{name: "systemctl failing never fails the install", config: true, checkRC: "0", systemctlRC: "1", wantRestart: true, wantCheck: true},
		{name: "refused config and systemctl failing", config: true, checkRC: "78", systemctlRC: "1", wantCheck: true, wantRefused: true, inactive: true},
		{name: "refused config, nothing was running", config: true, checkRC: "78", wantCheck: true, wantRefused: true, inactive: true},
		{name: "as the service user, valid: restarted", config: true, checkRC: "0", wantRestart: true, wantCheck: true, asService: true},
		{name: "as the service user, refused: not restarted", config: true, checkRC: "78", wantCheck: true, wantRefused: true, asService: true},
		{name: "as the service user, the file can't be read (2): not restarted", config: true, checkRC: "2", wantCheck: true, wantRefused: true, asService: true},
		{name: "as the service user, check crashed (1): restarted as before", config: true, checkRC: "1", wantRestart: true, wantCheck: true, asService: true},
		// A runuser without -g can't give the check the unit's group: the check runs as root, for
		// which 2 is not a refusal.
		{name: "runuser without -g, valid: checked as root, restarted", config: true, checkRC: "0", wantRestart: true, wantCheck: true, asService: true, noGroupFlag: true},
		{name: "runuser without -g, refused: not restarted", config: true, checkRC: "78", wantCheck: true, wantRefused: true, asService: true, noGroupFlag: true},
		{name: "runuser without -g, unreadable (2): restarted as before", config: true, checkRC: "2", wantRestart: true, wantCheck: true, asService: true, noGroupFlag: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			binDir := filepath.Join(dir, "bin")
			if err := os.Mkdir(binDir, 0o755); err != nil {
				t.Fatal(err)
			}
			calls := filepath.Join(dir, "calls")
			cfg := filepath.Join(dir, "config.yaml")
			if c.config {
				if err := os.WriteFile(cfg, []byte("x: 1\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			rc := c.systemctlRC
			if rc == "" {
				rc = "0"
			}
			activeRC := "0"
			if c.inactive {
				activeRC = "3"
			}
			fakeSystemctl := "#!/bin/sh\necho \"systemctl $*\" >> '" + calls + "'\n[ \"$1\" = is-active ] && exit " + activeRC + "\nexit " + rc + "\n"
			if c.asService {
				// runuser runs what follows "--"; id knows the mooring user. One without -g fails
				// as util-linux does for an option it doesn't know.
				fakeRunuser := "#!/bin/sh\necho \"runuser $1 $2 $3 $4 $5 $6\" >> '" + calls + "'\n[ \"$5\" = -- ] || exit 1\nshift 5\nexec \"$@\"\n"
				if c.noGroupFlag {
					fakeRunuser = "#!/bin/sh\necho \"runuser $1 $2 $3 $4 $5 $6\" >> '" + calls + "'\n[ \"$3\" = -g ] && { echo \"runuser: invalid option -- 'g'\" >&2; exit 1; }\nshift 3\nexec \"$@\"\n"
				}
				if err := os.WriteFile(filepath.Join(binDir, "runuser"), []byte(fakeRunuser), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(binDir, "id"), []byte("#!/bin/sh\necho 999\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(binDir, "systemctl"), []byte(fakeSystemctl), 0o755); err != nil {
				t.Fatal(err)
			}
			bin := filepath.Join(binDir, "mooring")
			if c.checkRC != "" {
				fake := "#!/bin/sh\necho \"mooring $*\" >> '" + calls + "'\ncase \" $* \" in *\" --quiet \"*) ;; *) echo 'config.yaml:3:1: unknown key egde' >&2 ;; esac\nexit " + c.checkRC + "\n"
				if err := os.WriteFile(bin, []byte(fake), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(sh, "-c", postinstallRestartBlock(t, bin, cfg))
			cmd.Env = []string{"PATH=" + binDir + ":/usr/bin:/bin"}
			outB, err := cmd.CombinedOutput()
			out := string(outB)
			if err != nil || !strings.Contains(out, "REACHED-END") {
				t.Fatalf("the script must never abort the install: %v\n%s", err, out)
			}
			logB, _ := os.ReadFile(calls)
			log := string(logB)
			if got := strings.Contains(log, "systemctl restart mooring\n"); got != c.wantRestart {
				t.Errorf("restarted = %v, want %v\ncalls:\n%s", got, c.wantRestart, log)
			}
			if got := strings.Contains(log, "mooring config check --quiet --config "+cfg+"\n"); got != c.wantCheck {
				t.Errorf("checked = %v, want %v\ncalls:\n%s", got, c.wantCheck, log)
			}
			// The check runs as the service user exactly when runuser and the user exist: every run of
			// the binary is then preceded by runuser's.
			// ... and with the unit's group (-g mooring), never with the passwd primary group alone.
			viaRunuser := c.asService && !c.noGroupFlag
			if got := strings.Count(log, "runuser -u mooring -g mooring -- "+bin+"\n"); viaRunuser && (got == 0 || got != strings.Count(log, "mooring config check")) || !viaRunuser && got != 0 {
				t.Errorf("checks run through runuser with the group = %d (as the service user: %v)\ncalls:\n%s", got, viaRunuser, log)
			}
			if strings.Contains(log, "runuser -u mooring -- ") {
				t.Errorf("runuser must be given the unit's group:\n%s", log)
			}
			if c.asService && !strings.Contains(log, "runuser -u mooring -g mooring -- true\n") {
				t.Errorf("runuser is probed with the group before it is used:\n%s", log)
			}
			if c.wantCheck && strings.Index(log, "mooring config check") > strings.Index(log+"systemctl restart", "systemctl restart") {
				t.Errorf("the check must come before the restart:\n%s", log)
			}
			if c.config != strings.Contains(log, "systemctl enable mooring\n") {
				t.Errorf("enable only with a config:\n%s", log)
			}
			refused := strings.Contains(out, "NOT restarted")
			if refused != c.wantRefused {
				t.Errorf("refusal message printed = %v, want %v:\n%s", refused, c.wantRefused, out)
			}
			if c.wantRefused {
				for _, s := range []string{"config.yaml:3:1: unknown key egde", "  sudo mooring config check\n", "  sudo systemctl restart mooring\n", cfg} {
					if !strings.Contains(out, s) {
						t.Errorf("the refusal message must contain %q:\n%s", s, out)
					}
				}
				// What it says about the running service is true: nothing "keeps running" when nothing ran.
				if keeps := strings.Contains(out, "keeps running on the previous version"); keeps == c.inactive {
					t.Errorf("unit running = %v, but the message says:\n%s", !c.inactive, out)
				}
				if c.inactive && !strings.Contains(out, "The service is not running") {
					t.Errorf("an inactive unit must be said:\n%s", out)
				}
			} else if strings.TrimSpace(out) != "REACHED-END" {
				t.Errorf("nothing is printed unless the config is refused:\n%s", out)
			}
		})
	}
}

// Without systemctl (a container build) the block does nothing and succeeds.
func TestPostinstallWithoutSystemctl(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sh, "-c", postinstallRestartBlock(t, filepath.Join(dir, "mooring"), filepath.Join(dir, "config.yaml")))
	cmd.Env = []string{"PATH=" + empty}
	if out, err := cmd.CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "REACHED-END" {
		t.Errorf("%v\n%s", err, out)
	}
}

// A caller who is neither root nor in the file's group as its primary group can't judge the file:
// that is "run it with sudo" (exit 2), not a refusal (78). The unit's ExecReload and root never
// get this error.
func TestConfigCheckOtherGroup(t *testing.T) {
	const path = "/etc/mooring/config.yaml"
	load := func(p string) (*config.Config, error) {
		return nil, fmt.Errorf("config: %s is group-readable by gid 996, not the service group 1000: %w", p, config.ErrOtherGroup)
	}
	code, out, errOut := runCheck(t, load, "--config", path)
	want := "mooring config: can't judge " + path + " as this user (the file belongs to another group): run sudo mooring config check\n"
	if code != 2 || out != "" || errOut != want {
		t.Errorf("exit %d stdout %q stderr %q\nwant exit 2 and %q", code, out, errOut, want)
	}
	if strings.Contains(errOut, "refused") {
		t.Errorf("a file this user can't judge is not called refused: %q", errOut)
	}
	if code, out, errOut := runCheck(t, load, "--quiet", "--config", path); code != 2 || out+errOut != "" {
		t.Errorf("--quiet: exit %d, %q %q (want 2 and silence)", code, out, errOut)
	}
	// --json: the "not judged" object, never the refusal's problem list.
	code, out, errOut = runCheck(t, load, "--json", "--config", path)
	var obj struct {
		OK       *bool           `json:"ok"`
		Error    string          `json:"error"`
		Problems json.RawMessage `json:"problems"`
	}
	if code != 2 || errOut != "" || json.Unmarshal([]byte(out), &obj) != nil || obj.OK == nil || *obj.OK || obj.Problems != nil || !strings.Contains(obj.Error, "can't judge "+path) {
		t.Errorf("--json: exit %d, stdout %q stderr %q (want 2 and an error object, no refusal JSON)", code, out, errOut)
	}

	// The service user is who the rule is for: its check (the unit's ExecReload) refuses the file.
	var out2, err2 bytes.Buffer
	rerr := runConfigCheck([]string{"--config", path}, configCheckEnv{stdout: &out2, stderr: &err2, load: load, serviceUser: func() bool { return true }})
	if got := exitStatus("config", rerr, &err2); got != config.ExitInvalid || !strings.Contains(err2.String(), "is refused") {
		t.Errorf("as the service user: exit %d, %q (want 78, refused)", got, err2.String())
	}

	// doctor: a warn with the same advice, and no failed exit.
	r, ok := doctorConfigResult(path, load2err(load, path))
	if !ok || r.state != "warn" || !strings.Contains(r.detail, "can't judge "+path+" as this user") || !strings.Contains(r.fix, "sudo mooring config check") {
		t.Errorf("doctor: %+v", r)
	}
	var rep report
	rep.add(r)
	if err := doctorExit(rep); err != nil {
		t.Errorf("doctor must not fail for a file it can't judge: %v", err)
	}
}

func load2err(load func(string) (*config.Config, error), path string) error {
	_, err := load(path)
	return err
}

// serve's one line says which it is: no file, a file it can't read, or a file it refuses.
func TestLogConfigRefusedByCause(t *testing.T) {
	line := func(err error) string {
		var b bytes.Buffer
		logConfigRefused(slog.New(slog.NewTextHandler(&b, nil)), "/etc/mooring/config.yaml", err)
		if strings.Count(b.String(), "\n") != 1 {
			t.Errorf("one line, got:\n%s", b.String())
		}
		return b.String()
	}
	missing := fmt.Errorf("config: stat /etc/mooring/config.yaml: %w", &fs.PathError{Op: "stat", Path: "/etc/mooring/config.yaml", Err: fs.ErrNotExist})
	if got := line(missing); !strings.Contains(got, `level=ERROR msg="config.yaml not found; not starting" file=/etc/mooring/config.yaml`) || strings.Contains(got, "not valid") || !strings.Contains(got, "sudo mooring config edit") ||
		!strings.Contains(got, "the unit starts the service again every 2s, so a volume that attaches late is picked up without a restart") {
		t.Errorf("a missing file:\n%s", got)
	}
	ioErr := fmt.Errorf("config: read /etc/mooring/config.yaml: %w", &fs.PathError{Op: "read", Path: "/etc/mooring/config.yaml", Err: syscall.EIO})
	if got := line(ioErr); !strings.Contains(got, `msg="config.yaml can't be read; not starting"`) || !strings.Contains(got, "starts the service again every 2s") || strings.Contains(got, "chown") {
		t.Errorf("a read error that isn't about permissions:\n%s", got)
	}
	const fix = "sudo chown root:mooring /etc/mooring/config.yaml && sudo chmod 0640 /etc/mooring/config.yaml"
	group := fmt.Errorf("config: /etc/mooring/config.yaml is group-readable by another group: %w", config.ErrOtherGroup)
	if got := line(group); !strings.Contains(got, `level=ERROR msg="config.yaml belongs to another group than the service's; not starting" file=/etc/mooring/config.yaml`) ||
		!strings.Contains(got, fix) || strings.Contains(got, "sudo mooring config check") || strings.Contains(got, "every 2s") {
		t.Errorf("a file of another group gets the command that fixes it:\n%s", got)
	}
	denied := fmt.Errorf("config: read /etc/mooring/config.yaml: %w", &fs.PathError{Op: "open", Path: "/etc/mooring/config.yaml", Err: fs.ErrPermission})
	if got := line(denied); !strings.Contains(got, `level=ERROR msg="config.yaml can't be read; not starting"`) || strings.Contains(got, "not valid") ||
		!strings.Contains(got, fix) || strings.Contains(got, "every 2s") {
		t.Errorf("an unreadable file:\n%s", got)
	}
	if got := line(testDiag("/etc/mooring/config.yaml")); !strings.Contains(got, `msg="config.yaml is not valid; not starting"`) {
		t.Errorf("a refused file:\n%s", got)
	}
	if got := line(errors.New("config: /etc/mooring/config.yaml must be owned by root")); !strings.Contains(got, `msg="config.yaml is not valid; not starting"`) {
		t.Errorf("a refused owner:\n%s", got)
	}
}

// As the service user (the unit's ExecReload) .last-good can't be read: the check says nothing
// about it, in text or JSON.
func TestConfigCheckUnreadableLastGoodIsSilent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	path, _ := cliHost(t)
	if err := os.WriteFile(lastGoodPath(path), []byte("no_such_key: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lastGoodPath(path), 0); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCheck(t, config.Load, "--config", path)
	if code != 0 || errOut != "" || strings.Contains(out, "last-good") || strings.Contains(out, "note:") || strings.Contains(out, "Changed since") {
		t.Errorf("exit %d stderr %q:\n%s", code, errOut, out)
	}
	code, out, _ = runCheck(t, config.Load, "--json", "--config", path)
	if code != 0 || strings.Contains(out, "last-good") || strings.Contains(out, `"changed"`) {
		t.Errorf("--json: exit %d: %s", code, out)
	}
}

// An edit `config edit` kept instead of installing is mentioned (never read: it is root's).
func TestConfigCheckMentionsRejectedEdit(t *testing.T) {
	path, _ := cliHost(t)
	if _, out, _ := runCheck(t, config.Load, "--config", path); strings.Contains(out, "rejected-edit") {
		t.Fatalf("nothing kept yet:\n%s", out)
	}
	if err := os.WriteFile(rejectedEditPath(path), []byte("x"), 0); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runCheck(t, config.Load, "--config", path)
	if code != 0 || !strings.Contains(out, "note: an edit that was not installed is kept at "+path+".rejected-edit (root only)") {
		t.Errorf("exit %d:\n%s", code, out)
	}
	code, out, _ = runCheck(t, config.Load, "--json", "--config", path)
	var got struct {
		RejectedEdit string `json:"rejected_edit"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &got) != nil || got.RejectedEdit != path+".rejected-edit" {
		t.Errorf("--json: exit %d: %s", code, out)
	}
}

// A definition that is missing or can't be read was not judged: exit 2 (a refusal is 1), with a
// JSON object under --json.
func TestValidateUnreadable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "mooring.yaml")
	var out, errb bytes.Buffer
	err := runValidate(missing, "", false, &out, &errb)
	if code := exitStatus("validate", err, &errb); code != 2 || out.Len() != 0 || !strings.Contains(errb.String(), missing) {
		t.Errorf("exit %d stdout %q stderr %q (want 2)", code, out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	err = runValidate(missing, "", true, &out, &errb)
	var got struct {
		OK    *bool  `json:"ok"`
		File  string `json:"file"`
		Error string `json:"error"`
	}
	if code := exitStatus("validate", err, &errb); code != 2 || errb.Len() != 0 {
		t.Errorf("--json: exit %d stderr %q (want 2 and nothing on stderr)", code, errb.String())
	}
	if json.Unmarshal(out.Bytes(), &got) != nil || got.OK == nil || *got.OK || got.File != missing || !strings.Contains(got.Error, "no such file") {
		t.Errorf("--json: %q", out.String())
	}
}

// --errors-only (the unit's ExecReload): nothing for a valid file, the diagnostics and the refusal
// line for a refused one; the exit statuses are those of the plain command.
func TestConfigCheckErrorsOnly(t *testing.T) {
	path, _ := cliHost(t)
	if err := os.WriteFile(rejectedEditPath(path), []byte("x"), 0); err != nil { // a note the plain command prints
		t.Fatal(err)
	}
	if code, out, _ := runCheck(t, config.Load, "--config", path); code != 0 || !strings.Contains(out, "OK: ") || !strings.Contains(out, "note: ") {
		t.Fatalf("the plain command prints the report: exit %d\n%s", code, out)
	}
	code, out, errOut := runCheck(t, config.Load, "--errors-only", "--config", path)
	if code != 0 || out != "" || errOut != "" {
		t.Errorf("--errors-only on a valid file: exit %d stdout %q stderr %q (want 0 and nothing)", code, out, errOut)
	}
	if code, out, errOut := runCheck(t, config.Load, "--errors-only", "--json", "--config", path); code != 0 || out+errOut != "" {
		t.Errorf("--errors-only --json on a valid file: exit %d, %q %q", code, out, errOut)
	}

	d := testDiag(path)
	refuse := func(string) (*config.Config, error) { return nil, d }
	code, out, errOut = runCheck(t, refuse, "--errors-only", "--config", path)
	_, _, plain := runCheck(t, refuse, "--config", path)
	if code != config.ExitInvalid || out != "" || errOut != plain || !strings.Contains(errOut, path+" is refused: mooring will not start or reload with it.") {
		t.Errorf("--errors-only on a refused file: exit %d stdout %q\nstderr %q\nplain  %q", code, out, errOut, plain)
	}
	if diagRendered() && !strings.Contains(errOut, strings.TrimRight(d.Terminal(), "\n")) {
		t.Errorf("the diagnostics are printed:\n%s", errOut)
	}
	if code, out, errOut := runCheck(t, refuse, "--errors-only", "--json", "--config", path); code != config.ExitInvalid || errOut != "" || !strings.Contains(out, `"problems"`) {
		t.Errorf("--errors-only --json on a refused file: exit %d, %q %q", code, out, errOut)
	}
	// --quiet still prints nothing at all.
	if code, out, errOut := runCheck(t, refuse, "--quiet", "--config", path); code != config.ExitInvalid || out+errOut != "" {
		t.Errorf("--quiet: exit %d, %q %q", code, out, errOut)
	}
	// The two can't be combined: which one is meant is not guessed.
	if code, _, errOut := runCheck(t, config.Load, "--quiet", "--errors-only", "--config", path); code != 2 || !strings.Contains(errOut, "--quiet can't be combined with --json or --errors-only") {
		t.Errorf("--quiet --errors-only on a valid file: exit %d, %q (want 2)", code, errOut)
	}
}

// Run by root, the load can't see a file the service can't read or refuses for its group. The
// check judges the file as the service would and refuses it (78) with the command that fixes it,
// instead of printing OK.
func TestConfigCheckServiceView(t *testing.T) {
	path, _ := cliHost(t)
	problem := errors.New(path + " is readable by root only (mode 0600): the service (user mooring) can't read it")
	check := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		err := runConfigCheck(append(args, "--config", path), configCheckEnv{stdout: &out, stderr: &errb, load: config.Load,
			serviceUser: func() bool { return false }, serviceView: func(p string) error {
				if p != path {
					t.Errorf("judged %q, want %q", p, path)
				}
				return problem
			}})
		return exitStatus("config", err, &errb), out.String(), errb.String()
	}
	fix := "sudo chown root:mooring " + path + " && sudo chmod 0640 " + path
	code, out, errOut := check()
	want := problem.Error() + "\nWhat is in the file is valid. To fix its owner and mode:\n  " + fix + "\n\n" + path + " is refused: mooring will not start or reload with it.\n"
	if code != config.ExitInvalid || out != "" || errOut != want {
		t.Errorf("exit %d stdout %q\nstderr %q\nwant   %q", code, out, errOut, want)
	}
	if strings.Contains(out+errOut, "OK:") {
		t.Errorf("a file the service can't use is never OK:\n%s%s", out, errOut)
	}
	if code, out, errOut := check("--errors-only"); code != config.ExitInvalid || out != "" || errOut != want {
		t.Errorf("--errors-only: exit %d, %q %q", code, out, errOut)
	}
	if code, out, errOut := check("--quiet"); code != config.ExitInvalid || out+errOut != "" {
		t.Errorf("--quiet: exit %d, %q %q", code, out, errOut)
	}
	code, out, errOut = check("--json")
	var got struct {
		File     string `json:"file"`
		Problems []struct {
			Msg  string `json:"msg"`
			Hint string `json:"hint"`
		} `json:"problems"`
	}
	if code != config.ExitInvalid || errOut != "" || json.Unmarshal([]byte(out), &got) != nil {
		t.Fatalf("--json: exit %d, %q %q", code, out, errOut)
	}
	if diagRendered() && (len(got.Problems) != 1 || got.Problems[0].Msg != problem.Error() || !strings.Contains(got.Problems[0].Hint, fix)) {
		t.Errorf("--json: %s", out)
	}

	// A file that doesn't load is reported for that; the service's view is not asked.
	var errb bytes.Buffer
	err := runConfigCheck([]string{"--config", path}, configCheckEnv{stdout: &bytes.Buffer{}, stderr: &errb,
		load:        func(string) (*config.Config, error) { return nil, testDiag(path) },
		serviceUser: func() bool { return false },
		serviceView: func(string) error { t.Error("asked about a file that did not load"); return nil }})
	if code := exitStatus("config", err, &errb); code != config.ExitInvalid {
		t.Errorf("exit %d", code)
	}
}

// A file the service can't use for another reason than its own owner and mode (its directory is
// closed to the service) is refused with what opens it, never with the file's chown/chmod.
func TestConfigCheckServiceViewOtherReason(t *testing.T) {
	path, _ := cliHost(t)
	dir := filepath.Dir(path)
	msg := path + " can't be used by the service (user mooring): stat " + path + ": permission denied"
	dirFix := "sudo chown root:mooring " + dir + " && sudo chmod 0750 " + dir
	check := func(verr error, args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		err := runConfigCheck(append(args, "--config", path), configCheckEnv{stdout: &out, stderr: &errb, load: config.Load,
			serviceUser: func() bool { return false }, serviceView: func(string) error { return verr }})
		return exitStatus("config", err, &errb), out.String(), errb.String()
	}
	type problems struct {
		File     string `json:"file"`
		Problems []struct {
			Msg  string `json:"msg"`
			Hint string `json:"hint"`
		} `json:"problems"`
	}
	refusedLine := "\n" + path + " is refused: mooring will not start or reload with it.\n"
	for _, c := range []struct {
		name               string
		verr               error
		text, hint, doctor string
	}{
		{"the file's directory", &serviceCantUseError{msg: msg, advice: "the service must be able to enter " + dir, command: dirFix},
			"What is in the file is valid. The service must be able to enter " + dir + ":\n  " + dirFix + "\n",
			"the service must be able to enter " + dir + ": " + dirFix,
			"the service must be able to enter " + dir + ": " + dirFix},
		{"a directory further up", &serviceCantUseError{msg: msg, advice: "the service must be able to enter /srv"},
			"What is in the file is valid. The service must be able to enter /srv.\n",
			"the service must be able to enter /srv",
			"the service must be able to enter /srv"},
		{"the file's owner and mode", &serviceCantUseError{msg: path + " is readable by root only (mode 0600): the service (user mooring) can't read it"},
			"What is in the file is valid. To fix its owner and mode:\n  " + permsFixCommand(path) + "\n",
			"run: " + permsFixCommand(path),
			"run: " + permsFixCommand(path)},
	} {
		code, out, errOut := check(c.verr)
		if want := c.verr.Error() + "\n" + c.text + refusedLine; code != config.ExitInvalid || out != "" || errOut != want {
			t.Errorf("%s: exit %d stdout %q\nstderr %q\nwant   %q", c.name, code, out, errOut, want)
		}
		if code, out, errOut2 := check(c.verr, "--errors-only"); code != config.ExitInvalid || out != "" || errOut2 != errOut {
			t.Errorf("%s --errors-only: exit %d, %q %q", c.name, code, out, errOut2)
		}
		if code, out, errOut := check(c.verr, "--quiet"); code != config.ExitInvalid || out+errOut != "" {
			t.Errorf("%s --quiet: exit %d, %q %q", c.name, code, out, errOut)
		}
		code, out, errOut = check(c.verr, "--json")
		var got problems
		if code != config.ExitInvalid || errOut != "" || json.Unmarshal([]byte(out), &got) != nil {
			t.Fatalf("%s --json: exit %d, %q %q", c.name, code, out, errOut)
		}
		if diagRendered() && (got.File != path || len(got.Problems) != 1 || got.Problems[0].Msg != c.verr.Error() || got.Problems[0].Hint != c.hint) {
			t.Errorf("%s --json: %s\nwant hint %q", c.name, out, c.hint)
		}
		r, ok := doctorServiceViewResult(path, c.verr)
		if !ok || r.name != "config" || r.state != "fail" || r.fix != c.doctor ||
			r.detail != c.verr.Error()+"; the service will not start with it (what is in the file is valid)" {
			t.Errorf("%s, doctor: %+v\nwant fix %q", c.name, r, c.doctor)
		}
	}
	// The service reads the file: nothing to report, in either command.
	if code, out, _ := check(nil); code != 0 || !strings.HasPrefix(out, "OK: "+path+" is valid\n") {
		t.Errorf("usable: exit %d, %q", code, out)
	}
	if r, ok := doctorServiceViewResult(path, nil); ok {
		t.Errorf("doctor, usable: %+v", r)
	}
	// An error of another type (an injected seam) keeps the file's own fix.
	if r, _ := doctorServiceViewResult(path, errors.New("x")); r.fix != "run: "+permsFixCommand(path) {
		t.Errorf("doctor, plain error: fix %q", r.fix)
	}
}

// A wrong flag is a wrong invocation: exit 2, as `config check`.
func TestValidateUsageExit(t *testing.T) {
	for _, args := range [][]string{{"--no-such-flag"}, {"--json=maybe"}} {
		var w bytes.Buffer
		if code := exitStatus("validate", cmdValidate(args), &w); code != 2 || w.Len() != 0 {
			t.Errorf("validate %v: exit %d, main printed %q (want 2; the flag parser printed the error)", args, code, w.String())
		}
	}
}
