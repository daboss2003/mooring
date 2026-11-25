package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/docker"
	"github.com/daboss2003/mooring/internal/edge"
	"github.com/daboss2003/mooring/internal/siem/hostlog"
)

func TestCheckBinary(t *testing.T) {
	// `sh` exists on any Unix dev/CI box; a nonsense name never does.
	if got := checkBinary("sh", "shell", "fix"); got.state != "ok" {
		t.Errorf("sh should be ok, got %q", got.state)
	}
	missing := checkBinary("mooring-no-such-binary-xyz", "thing", "do the fix")
	if missing.state != "fail" {
		t.Errorf("missing binary should fail, got %q", missing.state)
	}
	if missing.fix != "do the fix" {
		t.Errorf("fix not carried through: %q", missing.fix)
	}
}

// A distro-service conflict is reported ONLY when the unit is actually active/enabled.
// An absent unit (or no systemctl, e.g. on the macOS dev box) must report "ok" — never
// a false alarm. (Only an active/enabled unit is a "fail"; can't assert that portably.)
func TestCheckDistroServiceNoFalseAlarm(t *testing.T) {
	r := checkDistroService("mooring-no-such-service-xyz", ":80/:443")
	if r.state != "ok" {
		t.Errorf("absent distro service = %q, want ok (no false alarm)", r.state)
	}
}

func TestReportPrint(t *testing.T) {
	var r report
	r.add(result{"caddy", "fail", "MISSING", "sudo mooring setup --yes"})
	r.add(result{"docker", "ok", "found", ""})
	if !r.hasFail() {
		t.Error("hasFail should be true")
	}
	var buf bytes.Buffer
	r.print(&buf)
	out := buf.String()
	if !strings.Contains(out, "✗ caddy") || !strings.Contains(out, "✓ docker") {
		t.Errorf("missing status icons:\n%s", out)
	}
	if !strings.Contains(out, "→ sudo mooring setup --yes") {
		t.Errorf("fix hint not printed for a failing check:\n%s", out)
	}
	// An ok check must not print a fix arrow.
	if strings.Count(out, "→") != 1 {
		t.Errorf("expected exactly one fix arrow:\n%s", out)
	}
}

func TestDockerLogRotated(t *testing.T) {
	cases := map[string]struct {
		json string
		want bool
	}{
		"absent (default uncapped json-file)": {"", false},
		"json-file no cap":                    {`{"log-driver":"json-file"}`, false},
		"json-file with cap":                  {`{"log-driver":"json-file","log-opts":{"max-size":"10m"}}`, true},
		"implicit json-file with cap":         {`{"log-opts":{"max-size":"10m"}}`, true},
		"journald":                            {`{"log-driver":"journald"}`, true},
		"local (self-rotating)":               {`{"log-driver":"local"}`, true},
		"garbage":                             {`not json`, false},
	}
	for name, c := range cases {
		if got := dockerLogRotated([]byte(c.json)); got != c.want {
			t.Errorf("%s: dockerLogRotated=%v, want %v", name, got, c.want)
		}
	}
}

func TestWithDockerLogCap(t *testing.T) {
	// fresh box (no daemon.json) → cap is added and parses back capped.
	out, changed, err := withDockerLogCap(nil)
	if err != nil || !changed {
		t.Fatalf("empty: changed=%v err=%v", changed, err)
	}
	if !dockerLogRotated(out) {
		t.Errorf("result is still uncapped:\n%s", out)
	}

	// existing unrelated keys are preserved; existing log-opts are merged, not clobbered.
	in := []byte(`{"live-restore":true,"log-opts":{"labels":"app"}}`)
	out, changed, err = withDockerLogCap(in)
	if err != nil || !changed {
		t.Fatalf("merge: changed=%v err=%v", changed, err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if got["live-restore"] != true {
		t.Errorf("dropped live-restore: %v", got)
	}
	opts := got["log-opts"].(map[string]any)
	if opts["labels"] != "app" || opts["max-size"] != "10m" {
		t.Errorf("log-opts not merged correctly: %v", opts)
	}

	// already capped, a non-json-file driver, and garbage → no change / clear error.
	if _, changed, _ := withDockerLogCap([]byte(`{"log-opts":{"max-size":"5m"}}`)); changed {
		t.Error("already-capped should not change")
	}
	if _, changed, _ := withDockerLogCap([]byte(`{"log-driver":"journald"}`)); changed {
		t.Error("non-json-file driver should be left alone")
	}
	if _, _, err := withDockerLogCap([]byte(`not json`)); err == nil {
		t.Error("invalid daemon.json should error (so we never clobber it)")
	}
}

// TestCaddyRepoConstants guards the apt repo wiring against silent typos: the sources
// line must reference the key path via signed-by, and the key must be fetched over TLS.
func TestCaddyRepoConstants(t *testing.T) {
	if !strings.Contains(caddySources, "signed-by="+caddyKeyPath) {
		t.Errorf("sources line must pin the key via signed-by: %q", caddySources)
	}
	if !strings.HasPrefix(caddyKeyURL, "https://") {
		t.Errorf("the signing key must be fetched over HTTPS: %q", caddyKeyURL)
	}
	if !strings.HasSuffix(caddyKeyPath, ".asc") {
		t.Errorf("armored key path should end .asc for apt signed-by: %q", caddyKeyPath)
	}
}

func TestOnlyLoopback(t *testing.T) {
	for _, s := range []string{"", "localhost", "127.0.0.0/8", "127.0.0.1 ::1", "localhost ::1/128"} {
		if !onlyLoopback(s) {
			t.Errorf("%q should be loopback-only", s)
		}
	}
	for _, s := range []string{"localhost 172.16.0.0/12", "10.0.0.0/8", "0.0.0.0/0"} {
		if onlyLoopback(s) {
			t.Errorf("%q has a non-loopback range", s)
		}
	}
}

func TestServiceEnabledResult(t *testing.T) {
	cases := []struct {
		state string
		ok    bool
		want  string
	}{
		{"enabled", true, "ok"},           // the only true boot-enabled state
		{"enabled-runtime", true, "fail"}, // --runtime lives in /run → wiped on reboot
		{"linked-runtime", true, "fail"},
		{"disabled", true, "fail"}, // running-but-not-enabled: the reboot trap
		{"masked", true, "fail"},
		{"masked-runtime", true, "fail"},
		{"static", true, "warn"}, // unusual for a top-level unit — flag, don't fail
		{"", false, "warn"},      // systemctl unavailable
		{"", true, "warn"},       // empty state → can't confirm
	}
	for _, c := range cases {
		got := serviceEnabledResult(c.state, c.ok)
		if got.state != c.want {
			t.Errorf("serviceEnabledResult(%q, %v).state = %q, want %q", c.state, c.ok, got.state, c.want)
		}
		if c.want == "fail" && got.fix == "" {
			t.Errorf("a not-enabled state (%q) must carry a fix command", c.state)
		}
	}
	// The disabled case must name the enable command; the masked case must say to unmask FIRST
	// (a plain `enable` errors on a masked unit).
	if fix := serviceEnabledResult("disabled", true).fix; !strings.Contains(fix, "systemctl enable mooring") {
		t.Errorf("disabled fix should point at `systemctl enable mooring`, got %q", fix)
	}
	if fix := serviceEnabledResult("masked", true).fix; !strings.Contains(fix, "unmask") {
		t.Errorf("masked fix must tell the operator to unmask first, got %q", fix)
	}
}

// A "skip" result prints its own icon, carries no fix arrow, and is not a failure.
func TestReportPrintSkip(t *testing.T) {
	var r report
	r.add(result{"docker daemons", "skip", "not checked (the dockerd scan reads Linux /proc)", ""})
	if r.hasFail() {
		t.Error("a skipped check must not count as a failure")
	}
	var buf bytes.Buffer
	r.print(&buf)
	if out := buf.String(); !strings.Contains(out, "- docker daemons") || strings.Contains(out, "→") {
		t.Errorf("skip line wrong:\n%s", out)
	}
}

func TestEvalDockerDaemons(t *testing.T) {
	apt := dockerdProc{pid: 812, exe: "/usr/bin/dockerd", unit: "docker.service", uid: 0}
	snap := dockerdProc{pid: 1044, exe: "/snap/docker/2932/bin/dockerd", unit: "snap.docker.dockerd.service", uid: 0}
	dind := dockerdProc{pid: 2210, unit: "docker-4c1e.scope", uid: 0, nested: true}
	rootless := dockerdProc{pid: 3300, exe: "/usr/bin/dockerd", unit: "docker.service", uid: 1000}
	unknown := dockerdProc{pid: 4400, uid: -1} // exe, cgroup and status all unreadable

	cases := []struct {
		name  string
		procs []dockerdProc
		want  string
	}{
		{"none running", nil, "warn"},
		{"one host daemon", []dockerdProc{apt}, "ok"},
		{"apt + snap (the split-plane incident)", []dockerdProc{apt, snap}, "fail"},
		{"daemon inside a container not counted", []dockerdProc{apt, dind}, "ok"},
		{"rootless daemon not counted", []dockerdProc{apt, rootless}, "ok"},
		{"only a container's daemon", []dockerdProc{dind}, "warn"},
		{"unknown uid still counts", []dockerdProc{apt, unknown}, "fail"},
	}
	for _, c := range cases {
		got := evalDockerDaemons(c.procs)
		if got.state != c.want {
			t.Errorf("%s: state = %q, want %q (%s)", c.name, got.state, c.want, got.detail)
		}
		if c.want != "ok" && got.fix == "" {
			t.Errorf("%s: a %s must carry a fix", c.name, c.want)
		}
	}

	// The failure says how many daemons, lists each one's pid/binary/unit, and says why
	// that matters; the fix is removal guidance for both install kinds.
	r := evalDockerDaemons([]dockerdProc{apt, snap, dind})
	for _, s := range []string{
		"2 Docker daemons are running",
		"pid 812 /usr/bin/dockerd (docker.service)",
		"pid 1044 /snap/docker/2932/bin/dockerd (snap.docker.dockerd.service)",
		"exactly one",
		"(ignoring 1 dockerd inside a container or rootless)",
	} {
		if !strings.Contains(r.detail, s) {
			t.Errorf("fail detail missing %q:\n%s", s, r.detail)
		}
	}
	for _, s := range []string{"sudo snap remove docker", "sudo apt remove docker.io", "keep the install the mooring service uses"} {
		if !strings.Contains(r.fix, s) {
			t.Errorf("fix missing %q:\n%s", s, r.fix)
		}
	}
	// A dockerd whose exe link was unreadable (doctor not run as root) still shows pid + unit.
	if got := (dockerdProc{pid: 9, unit: "docker.service"}).label(); got != "pid 9 (docker.service)" {
		t.Errorf("label without exe = %q", got)
	}
}

// scanDockerdProcs over a fixture /proc: only dockerd pids are returned (sorted by pid),
// with exe/unit/uid/nested read from the pid dir; other programs, pids that exited
// mid-scan, and non-pid entries are skipped.
func TestScanDockerdProcs(t *testing.T) {
	root := t.TempDir()
	mk := func(pid, exe string, files map[string]string) {
		t.Helper()
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if exe != "" {
			if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk("1", "/usr/lib/systemd/systemd", map[string]string{"comm": "systemd\n"})
	mk("812", "/usr/bin/dockerd", map[string]string{ // apt docker.io, cgroup v2
		"comm":   "dockerd\n",
		"cgroup": "0::/system.slice/docker.service\n",
		"status": "Name:\tdockerd\nUid:\t0\t0\t0\t0\nNSpid:\t812\n",
	})
	mk("1044", "/snap/docker/2932/bin/dockerd", map[string]string{ // the docker snap, cgroup v1
		"comm":   "dockerd\n",
		"cgroup": "12:pids:/system.slice/snap.docker.dockerd.service\n1:name=systemd:/system.slice/snap.docker.dockerd.service\n",
		"status": "Name:\tdockerd\nUid:\t0\t0\t0\t0\nNSpid:\t1044\n",
	})
	mk("2210", "", map[string]string{ // docker-in-docker: exe unreadable, child PID namespace
		"comm":   "dockerd\n",
		"cgroup": "0::/system.slice/docker-4c1e.scope/init\n",
		"status": "Name:\tdockerd\nUid:\t0\t0\t0\t0\nNSpid:\t2210\t57\n",
	})
	mk("3300", "/usr/bin/containerd", map[string]string{"comm": "containerd\n"})
	mk("77", "", nil) // exited mid-scan: no comm left
	if err := os.MkdirAll(filepath.Join(root, "sys"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "99"), []byte("not a pid dir"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := scanDockerdProcs(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []dockerdProc{
		{pid: 812, exe: "/usr/bin/dockerd", unit: "docker.service", uid: 0},
		{pid: 1044, exe: "/snap/docker/2932/bin/dockerd", unit: "snap.docker.dockerd.service", uid: 0},
		{pid: 2210, unit: "docker-4c1e.scope", uid: 0, nested: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("scan:\n got %+v\nwant %+v", got, want)
	}
	if r := evalDockerDaemons(got); r.state != "fail" || !strings.Contains(r.detail, "2 Docker daemons") {
		t.Errorf("fixture host = %q %q, want a 2-daemon fail", r.state, r.detail)
	}

	if _, err := scanDockerdProcs(filepath.Join(root, "no-such-proc")); err == nil {
		t.Error("an unreadable proc root must return an error")
	}
}

func TestCgroupUnit(t *testing.T) {
	cases := map[string]string{
		"0::/system.slice/docker.service\n":                                                   "docker.service",
		"0::/system.slice/snap.docker.dockerd.service\n":                                      "snap.docker.dockerd.service",
		"12:pids:/system.slice/docker.service\n1:name=systemd:/system.slice/docker.service\n": "docker.service",
		"0::/system.slice/docker-4c1e.scope/init\n":                                           "docker-4c1e.scope",
		"0::/user.slice/user-1000.slice/user@1000.service/app.slice/docker.service\n":         "docker.service",
		"12:pids:/system.slice/docker.service\n":                                              "", // no systemd line
		"0::/\n":                                                                              "",
		"":                                                                                    "",
	}
	for in, want := range cases {
		if got := cgroupUnit(in); got != want {
			t.Errorf("cgroupUnit(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseStatusIDs(t *testing.T) {
	cases := []struct {
		status string
		uid    int
		nested bool
	}{
		{"Name:\tdockerd\nUid:\t0\t0\t0\t0\nNSpid:\t812\n", 0, false},
		{"Uid:\t1000\t1000\t1000\t1000\nNSpid:\t3300\n", 1000, false}, // rootless
		{"Uid:\t0\t0\t0\t0\nNSpid:\t2210\t57\n", 0, true},             // inside a container
		{"Name:\tdockerd\n", -1, false},                               // no Uid / no NSpid
	}
	for _, c := range cases {
		uid, nested := parseStatusIDs(c.status)
		if uid != c.uid || nested != c.nested {
			t.Errorf("parseStatusIDs(%q) = %d, %v; want %d, %v", c.status, uid, nested, c.uid, c.nested)
		}
	}
}

func TestEvalDockerInstalls(t *testing.T) {
	apt := dockerCLI{path: "/usr/bin/docker", real: "/usr/bin/docker"}
	local := dockerCLI{path: "/usr/local/bin/docker", real: "/usr/local/bin/docker"}
	localToApt := dockerCLI{path: "/usr/local/bin/docker", real: "/usr/bin/docker"}
	snapCLI := dockerCLI{path: "/snap/bin/docker", real: "/usr/bin/snap"} // snapd's command links
	localToSnap := dockerCLI{path: "/usr/local/bin/docker", real: "/usr/bin/snap"}
	localIntoSnap := dockerCLI{path: "/usr/local/bin/docker", real: "/snap/docker/2932/bin/docker"}

	cases := []struct {
		name string
		clis []dockerCLI
		snap bool
		want string
	}{
		{"nothing installed", nil, false, "ok"},
		{"apt only", []dockerCLI{apt}, false, "ok"},
		{"snap only", []dockerCLI{snapCLI}, true, "ok"},
		{"snap without its /snap/bin link", nil, true, "ok"},
		{"apt + snap (the split-plane incident)", []dockerCLI{apt, snapCLI}, true, "fail"},
		{"apt + snap dir, no /snap/bin link", []dockerCLI{apt}, true, "fail"},
		{"/usr/local link to the apt CLI", []dockerCLI{apt, localToApt}, false, "ok"},
		{"two distinct CLIs", []dockerCLI{apt, local}, false, "fail"},
		{"/usr/local link to the snap", []dockerCLI{localToSnap, snapCLI}, true, "ok"},
		{"/usr/local link into the snap mount", []dockerCLI{localIntoSnap}, true, "ok"},
	}
	for _, c := range cases {
		got := evalDockerInstalls(c.clis, c.snap)
		if got.state != c.want {
			t.Errorf("%s: state = %q, want %q (%s)", c.name, got.state, c.want, got.detail)
		}
	}

	r := evalDockerInstalls([]dockerCLI{apt, snapCLI}, true)
	if want := "2 Docker installations: /usr/bin/docker, /snap/bin/docker (snap)"; !strings.Contains(r.detail, want) {
		t.Errorf("fail detail = %q, want it to contain %q", r.detail, want)
	}
	if r.fix != dockerDedupeFix {
		t.Errorf("fail fix = %q, want the shared removal guidance", r.fix)
	}
	if r := evalDockerInstalls([]dockerCLI{apt}, true); !strings.Contains(r.detail, "the docker snap (/snap/docker)") {
		t.Errorf("a snap with no /snap/bin link must still be named: %q", r.detail)
	}
}

// findDockerInstalls over a fixture root: symlinks are resolved (so a link to the apt CLI
// shares its real path), the snap dir is detected, and a dangling link or a directory
// named docker is not an install.
func TestFindDockerInstalls(t *testing.T) {
	root := t.TempDir()
	file := func(rel string) string {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	link := func(target, rel string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	aptCLI := file("usr/bin/docker")
	snapd := file("usr/bin/snap")
	link(aptCLI, "usr/local/bin/docker") // same install as /usr/bin/docker
	link(snapd, "snap/bin/docker")       // how snapd exposes every snap command
	if err := os.MkdirAll(filepath.Join(root, "snap", "docker", "2932"), 0o755); err != nil {
		t.Fatal(err)
	}

	clis, snap := findDockerInstalls(root)
	var paths []string
	for _, c := range clis {
		paths = append(paths, c.path)
	}
	if want := []string{"/usr/bin/docker", "/usr/local/bin/docker", "/snap/bin/docker"}; !reflect.DeepEqual(paths, want) {
		t.Fatalf("found %v, want %v", paths, want)
	}
	if clis[0].real != clis[1].real {
		t.Errorf("a link to /usr/bin/docker must resolve to its real path: %q vs %q", clis[1].real, clis[0].real)
	}
	if !snap {
		t.Error("/snap/docker should mark the snap installed")
	}
	if r := evalDockerInstalls(clis, snap); r.state != "fail" || !strings.Contains(r.detail, "2 Docker installations") {
		t.Errorf("fixture host = %q %q, want a 2-install fail", r.state, r.detail)
	}

	root = t.TempDir()
	link(filepath.Join(root, "gone", "snap"), "snap/bin/docker") // dangling: snapd removed
	if err := os.MkdirAll(filepath.Join(root, "usr", "bin", "docker"), 0o755); err != nil {
		t.Fatal(err)
	}
	if clis, snap := findDockerInstalls(root); len(clis) != 0 || snap {
		t.Errorf("dangling link / directory counted as an install: %+v snap=%v", clis, snap)
	}
}

func TestEvalDaemonMatch(t *testing.T) {
	aptD := docker.Info{ID: "4f2b8d0e-3c1a-4e8b-9d6f-0a7c5e2b1d93", Name: "vps-1", DockerRootDir: "/var/lib/docker"}
	snapD := docker.Info{ID: "9a7c1e55-0b2d-4f8a-8e6c-3d4b5a697081", Name: "vps-1", DockerRootDir: "/var/snap/docker/common/var-lib-docker"}

	if r := evalDaemonMatch(aptD, nil, aptD.ID, nil); r.state != "ok" {
		t.Errorf("same daemon = %q (%s), want ok", r.state, r.detail)
	}

	r := evalDaemonMatch(snapD, nil, aptD.ID, nil)
	if r.state != "fail" {
		t.Fatalf("different daemons = %q, want fail", r.state)
	}
	want := "the socket-proxy (read plane) and the docker CLI (write plane) talk to different Docker daemons: " +
		snapD.ID + " (vps-1, /var/snap/docker/common/var-lib-docker) vs " + aptD.ID
	if r.detail != want {
		t.Errorf("fail detail:\n got %q\nwant %q", r.detail, want)
	}
	for _, s := range []string{"two Docker installs", "stale socket-proxy", "remove the extra install", "sudo systemctl restart mooring"} {
		if !strings.Contains(r.fix, s) {
			t.Errorf("fix missing %q: %s", s, r.fix)
		}
	}

	// Either side unreadable → warn with the reason, and no comparison.
	cases := []struct {
		name   string
		read   docker.Info
		rerr   error
		wid    string
		werr   error
		reason string
	}{
		{"proxy down", docker.Info{}, errors.New("socket-proxy on 127.0.0.1:2375: connection refused"), aptD.ID, nil, "read plane: socket-proxy on 127.0.0.1:2375: connection refused"},
		{"proxy /info without an ID", docker.Info{Name: "vps-1"}, nil, aptD.ID, nil, "read plane: the socket-proxy's /info has no daemon ID"},
		{"docker CLI can't connect", aptD, nil, "", errors.New("docker info: permission denied while trying to connect"), "write plane: docker info: permission denied"},
		{"docker CLI printed nothing", aptD, nil, "", nil, "write plane: docker info printed no daemon ID"},
	}
	for _, c := range cases {
		got := evalDaemonMatch(c.read, c.rerr, c.wid, c.werr)
		if got.state != "warn" || !strings.Contains(got.detail, c.reason) {
			t.Errorf("%s: = %q %q, want warn naming %q", c.name, got.state, got.detail, c.reason)
		}
	}
	both := evalDaemonMatch(docker.Info{}, errors.New("proxy down"), "", errors.New("cli down"))
	if !strings.Contains(both.detail, "proxy down") || !strings.Contains(both.detail, "cli down") {
		t.Errorf("both sides failing should report both reasons: %q", both.detail)
	}
}

// fakeCaddy writes a #!/bin/sh stand-in for caddy at path: `version` prints ver, and `list-modules`
// prints mods one per line, then a blank line and a summary, like the real command.
func fakeCaddy(t *testing.T, path, ver string, mods ...string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("#!/bin/sh\ncase \"$1\" in\nversion) echo '" + ver + "' ;;\nlist-modules)\n")
	for _, m := range mods {
		b.WriteString("  echo '" + m + "'\n")
	}
	b.WriteString("  echo ''\n  echo '  Standard modules: 1'\n  ;;\n*) exit 1 ;;\nesac\n")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o700); err != nil {
		t.Fatal(err)
	}
}

// caddyHost isolates a test from the host's caddy and data dir: PATH is an empty temp dir (put a
// system caddy at filepath.Join(pathDir, "caddy")) and cfg.DataDir is another temp dir.
func caddyHost(t *testing.T) (pathDir string, cfg *config.Config) {
	t.Helper()
	pathDir = t.TempDir()
	t.Setenv("PATH", pathDir)
	return pathDir, &config.Config{DataDir: t.TempDir(), Edge: config.EdgeConfig{Mode: config.EdgeManaged}}
}

// withDNS01 configures the default namespace with providers[0] and a named namespace for each other
// provider.
func withDNS01(cfg *config.Config, providers ...string) {
	cfg.Edge.BaseDomain = "example.com"
	cfg.Edge.DNS01 = &config.EdgeDNS01{Provider: providers[0], APIToken: "token"}
	for i, p := range providers[1:] {
		name := string(rune('a' + i))
		cfg.Edge.BaseDomains = append(cfg.Edge.BaseDomains, config.EdgeBaseDomain{
			Name: "ns" + name, Domain: "ns" + name + ".example.net", DNS01: &config.EdgeDNS01{Provider: p, APIToken: "token"},
		})
	}
}

// stubBuildServer replaces the caddyserver.com dial for the test and returns its call count.
func stubBuildServer(t *testing.T, reachable bool) *int {
	t.Helper()
	calls := 0
	orig := buildServerReachable
	buildServerReachable = func() bool { calls++; return reachable }
	t.Cleanup(func() { buildServerReachable = orig })
	return &calls
}

func TestCheckCaddy(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		_, cfg := caddyHost(t)
		r := checkCaddy(cfg)
		if r.name != "caddy" || r.state != "fail" || !strings.Contains(r.detail, "MISSING") || r.fix != "sudo mooring setup --yes" {
			t.Errorf("no caddy = %+v, want a MISSING fail with the setup fix", r)
		}
	})

	// setup installs no Caddy with edge.mode external, so doctor mustn't send the operator there.
	t.Run("missing in external mode: not needed", func(t *testing.T) {
		_, cfg := caddyHost(t)
		cfg.Edge.Mode = config.EdgeExternal
		if r := checkCaddy(cfg); r.name != "caddy" || r.state != "skip" || !strings.Contains(r.detail, "edge.mode is external") || r.fix != "" {
			t.Errorf("external mode, no caddy = %+v, want a skip without a fix", r)
		}
	})

	t.Run("current system caddy", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "v2.11.2 h1:x")
		r := checkCaddy(cfg)
		if r.state != "ok" || !strings.Contains(r.detail, "v2.11.2") || !strings.Contains(r.detail, filepath.Join(dir, "caddy")) {
			t.Errorf("2.11.2 = %+v, want ok naming the version and path", r)
		}
	})

	t.Run("old caddy fails only when a setting needs 2.11", func(t *testing.T) {
		cases := []struct {
			name string
			set  func(*config.Config)
			want string
		}{
			{"nothing needs it", func(*config.Config) {}, "warn"},
			{"trusted_proxies", func(c *config.Config) { c.Edge.TrustedProxies = []string{"cloudflare"} }, "fail"},
			{"default dns01", func(c *config.Config) { withDNS01(c, "cloudflare") }, "fail"},
			{"named namespace dns01", func(c *config.Config) {
				c.Edge.BaseDomains = []config.EdgeBaseDomain{{Name: "staging", Domain: "staging.example.com", DNS01: &config.EdgeDNS01{Provider: "cloudflare", APIToken: "token"}}}
			}, "fail"},
			{"edge.catch_all", func(c *config.Config) { c.Edge.CatchAll = true }, "fail"},
			{"base_domains catch_all", func(c *config.Config) {
				c.Edge.BaseDomains = []config.EdgeBaseDomain{{Name: "staging", Domain: "staging.example.com", CatchAll: true}}
			}, "fail"},
		}
		for _, c := range cases {
			dir, cfg := caddyHost(t)
			fakeCaddy(t, filepath.Join(dir, "caddy"), "2.6.2")
			c.set(cfg)
			r := checkCaddy(cfg)
			if r.state != c.want {
				t.Errorf("%s: 2.6.2 = %q (%s), want %q", c.name, r.state, r.detail, c.want)
			}
			if !strings.Contains(r.detail, "2.6.2") || !strings.Contains(r.detail, filepath.Join(dir, "caddy")) {
				t.Errorf("%s: %+v must name the version and the path", c.name, r)
			}
			// setup upgrades a system caddy below the minimum whatever the config says.
			if r.fix != "sudo mooring setup --yes (upgrades it to Caddy's official release)" {
				t.Errorf("%s: fix = %q, want the in-place upgrade", c.name, r.fix)
			}
		}
	})

	t.Run("old caddy in external mode: setup leaves it alone, so no setup fix", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "2.6.2")
		cfg.Edge.Mode = config.EdgeExternal
		if r := checkCaddy(cfg); r.state != "warn" || !strings.Contains(r.detail, "2.6.2") || r.fix != "" {
			t.Errorf("external mode, 2.6.2 = %+v, want a warn without a setup fix", r)
		}
	})

	t.Run("old owned build: setup installs a current one", func(t *testing.T) {
		for _, needs := range []bool{false, true} {
			_, cfg := caddyHost(t)
			owned := edge.OwnedCaddyPath(cfg.DataDir)
			fakeCaddy(t, owned, "2.6.2")
			want := "warn"
			if needs {
				cfg.Edge.TrustedProxies = []string{"cloudflare"}
				want = "fail"
			}
			r := checkCaddy(cfg)
			if r.state != want || !strings.Contains(r.detail, owned+" (Mooring-owned build)") || !strings.Contains(r.fix, "installs a current Caddy as "+owned) {
				t.Errorf("needs=%v: old owned build = %+v, want a %s with the owned-build fix", needs, r, want)
			}
		}
	})

	t.Run("owned build is preferred", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "2.6.2")
		owned := edge.OwnedCaddyPath(cfg.DataDir)
		fakeCaddy(t, owned, "v2.11.2 h1:x")
		cfg.Edge.TrustedProxies = []string{"cloudflare"}
		r := checkCaddy(cfg)
		if r.state != "ok" || !strings.Contains(r.detail, owned+" (Mooring-owned build)") {
			t.Errorf("owned build = %+v, want ok naming the Mooring-owned build", r)
		}
	})

	t.Run("stale owned build", func(t *testing.T) {
		_, cfg := caddyHost(t)
		owned := edge.OwnedCaddyPath(cfg.DataDir)
		fakeCaddy(t, owned, "v2.11.2 h1:x")
		old := time.Now().Add(-200 * 24 * time.Hour)
		if err := os.Chtimes(owned, old, old); err != nil {
			t.Fatal(err)
		}
		r := checkCaddy(cfg)
		if r.state != "warn" || !strings.Contains(r.detail, "Mooring-owned build") || r.fix != "refresh it: sudo rm "+owned+" && sudo mooring setup --yes" {
			t.Errorf("200-day-old owned build = %+v, want a refresh warn", r)
		}
	})

	t.Run("unreadable version", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "(devel)")
		if r := checkCaddy(cfg); r.state != "warn" || !strings.Contains(r.detail, "could not read its version") {
			t.Errorf("(devel) build = %+v, want a warn", r)
		}
	})
}

// With the Mooring-owned build in front, an old system caddy is still the edge's fallback: doctor
// warns about it on its own line.
func TestCheckSystemCaddyFallback(t *testing.T) {
	cases := []struct {
		name          string
		system, owned string // `caddy version` output; "" = not installed
		external      bool   // edge.mode: external
		want          bool
	}{
		{"owned build + distro 2.6.2", "2.6.2", "v2.11.2 h1:x", false, true},
		{"owned build + current system caddy", "v2.11.2 h1:x", "v2.11.2 h1:x", false, false},
		{"owned build, no system caddy", "", "v2.11.2 h1:x", false, false},
		{"owned build + unreadable system version", "(devel)", "v2.11.2 h1:x", false, false},
		{"no owned build (checkCaddy reports the system caddy)", "2.6.2", "", false, false},
		{"external mode: Mooring runs no Caddy and setup doesn't upgrade it", "2.6.2", "v2.11.2 h1:x", true, false},
	}
	for _, c := range cases {
		dir, cfg := caddyHost(t)
		sys := filepath.Join(dir, "caddy")
		if c.system != "" {
			fakeCaddy(t, sys, c.system)
		}
		if c.owned != "" {
			fakeCaddy(t, edge.OwnedCaddyPath(cfg.DataDir), c.owned)
		}
		if c.external {
			cfg.Edge.Mode = config.EdgeExternal
		}
		r, ok := checkSystemCaddyFallback(cfg)
		if ok != c.want {
			t.Errorf("%s: ok = %v (%+v), want %v", c.name, ok, r, c.want)
			continue
		}
		if !ok {
			continue
		}
		want := result{"caddy (system)", "warn",
			"the fallback system Caddy is v2.6.2 at " + sys + ", older than " + edge.MinCaddyVersion.String(),
			"sudo mooring setup --yes (upgrades it to Caddy's official release)"}
		if r != want {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, r, want)
		}
	}
}

func TestCaddyMinNeeds(t *testing.T) {
	if got := caddyMinNeeds(nil); len(got) != 0 {
		t.Errorf("nil config needs %v, want nothing (doctor warns)", got)
	}
	cfg := &config.Config{}
	if got := caddyMinNeeds(cfg); len(got) != 0 {
		t.Errorf("empty config needs %v", got)
	}
	cfg.Edge.TrustedProxies = []string{"192.0.2.0/24"}
	withDNS01(cfg, "cloudflare")
	cfg.Edge.CatchAll = true
	if got, want := caddyMinNeeds(cfg), []string{"edge.trusted_proxies", "dns01", "catch_all"}; !reflect.DeepEqual(got, want) {
		t.Errorf("caddyMinNeeds = %v, want %v", got, want)
	}
	// Automated response refuses QUIC 0-RTT (Caddy 2.11); off (the default) needs nothing.
	resp := &config.Config{}
	resp.SecurityLogs.Response.Mode = "recommend"
	if got := caddyMinNeeds(resp); !reflect.DeepEqual(got, []string{"security_logs.response"}) {
		t.Errorf("response mode recommend: caddyMinNeeds = %v", got)
	}
	resp.SecurityLogs.Detection.Enabled = new(bool) // detection off: the mode can't act
	if got := caddyMinNeeds(resp); len(got) != 0 {
		t.Errorf("detection off: caddyMinNeeds = %v", got)
	}
}

func TestCheckDNSPlugins(t *testing.T) {
	t.Run("no dns01", func(t *testing.T) {
		_, cfg := caddyHost(t)
		calls := stubBuildServer(t, true)
		if got := checkDNSPlugins(cfg); len(got) != 0 || *calls != 0 {
			t.Errorf("no dns01 = %+v (dials %d), want no results and no dial", got, *calls)
		}
	})

	t.Run("present", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "v2.11.2 h1:x", "http", "dns.providers.cloudflare")
		withDNS01(cfg, "cloudflare")
		calls := stubBuildServer(t, false)
		got := checkDNSPlugins(cfg)
		if len(got) != 1 || got[0].name != "dns plugin cloudflare" || got[0].state != "ok" {
			t.Fatalf("present = %+v, want one ok", got)
		}
		if *calls != 0 {
			t.Errorf("caddyserver.com dialed %d times with every plugin present", *calls)
		}
	})

	t.Run("present in the owned build", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "2.6.2")
		owned := edge.OwnedCaddyPath(cfg.DataDir)
		fakeCaddy(t, owned, "v2.11.2 h1:x", "dns.providers.cloudflare")
		withDNS01(cfg, "cloudflare")
		stubBuildServer(t, false)
		if got := checkDNSPlugins(cfg); len(got) != 1 || got[0].state != "ok" || !strings.Contains(got[0].detail, owned) {
			t.Errorf("owned build with the module = %+v, want ok naming %s", got, owned)
		}
	})

	t.Run("missing, build server reachable", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "v2.11.2 h1:x", "http")
		withDNS01(cfg, "cloudflare")
		stubBuildServer(t, true)
		got := checkDNSPlugins(cfg)
		if len(got) != 1 || got[0].state != "warn" {
			t.Fatalf("missing+reachable = %+v, want one warn", got)
		}
		if want := "Mooring installs it at startup as " + edge.OwnedCaddyPath(cfg.DataDir); !strings.Contains(got[0].detail, want) {
			t.Errorf("detail %q, want it to contain %q", got[0].detail, want)
		}
		if got[0].fix != "or install it now: sudo mooring setup --yes" {
			t.Errorf("fix = %q", got[0].fix)
		}
	})

	t.Run("missing, build server unreachable, dialed once", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "v2.11.2 h1:x", "http")
		withDNS01(cfg, "cloudflare", "route53")
		calls := stubBuildServer(t, false)
		got := checkDNSPlugins(cfg)
		if len(got) != 2 || got[0].name != "dns plugin cloudflare" || got[1].name != "dns plugin route53" {
			t.Fatalf("got %+v, want one result per provider", got)
		}
		for _, r := range got {
			if r.state != "fail" || !strings.Contains(r.detail, "caddyserver.com:443 is unreachable") || r.fix != "allow outbound HTTPS to caddyserver.com, then restart mooring" {
				t.Errorf("missing+unreachable = %+v, want a fail naming caddyserver.com", r)
			}
		}
		if *calls != 1 {
			t.Errorf("caddyserver.com dialed %d times, want once per preflight", *calls)
		}
	})

	t.Run("no caddy at all", func(t *testing.T) {
		_, cfg := caddyHost(t)
		withDNS01(cfg, "cloudflare")
		stubBuildServer(t, true)
		if got := checkDNSPlugins(cfg); len(got) != 1 || got[0].state != "warn" || !strings.Contains(got[0].fix, "sudo mooring setup --yes") {
			t.Errorf("no caddy = %+v, want a warn pointing at setup", got)
		}
	})

	t.Run("unknown provider", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "v2.11.2 h1:x")
		withDNS01(cfg, "nosuchdns")
		calls := stubBuildServer(t, true)
		got := checkDNSPlugins(cfg)
		if len(got) != 1 || got[0].name != "dns plugin nosuchdns" || got[0].state != "fail" || !strings.Contains(got[0].detail, "cloudflare") {
			t.Errorf("unknown provider = %+v, want a fail listing the supported providers", got)
		}
		if *calls != 0 {
			t.Errorf("an unknown provider must not dial the build server (%d dials)", *calls)
		}
	})

	t.Run("providers are deduplicated case-insensitively", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "v2.11.2 h1:x", "dns.providers.cloudflare")
		withDNS01(cfg, "Cloudflare", "cloudflare")
		stubBuildServer(t, true)
		if got := checkDNSPlugins(cfg); len(got) != 1 || got[0].name != "dns plugin cloudflare" || got[0].state != "ok" {
			t.Errorf("got %+v, want one ok for cloudflare", got)
		}
	})
}

// ownedStep returns the plan's Mooring-owned Caddy build step and its index (-1 when absent).
func ownedStep(steps []step) (step, int) {
	for i, s := range steps {
		if strings.HasPrefix(s.desc, ownedCaddyStepPrefix) {
			return s, i
		}
	}
	return step{}, -1
}

func stepIndex(steps []step, desc string) int {
	for i, s := range steps {
		if s.desc == desc {
			return i
		}
	}
	return -1
}

func TestPlanOwnedCaddyBuild(t *testing.T) {
	t.Run("system caddy already has the module", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		// The edge runs this caddy (no owned build) and it has both modules: nothing to download,
		// matching doctor and the runtime installer.
		fakeCaddy(t, filepath.Join(dir, "caddy"), "v2.11.2 h1:x", "dns.providers.cloudflare", "dns.providers.route53")
		withDNS01(cfg, "cloudflare", "route53")
		if _, i := ownedStep(planned(false, false, cfg)); i >= 0 {
			t.Error("the caddy the edge runs has the modules: no owned build expected")
		}
	})

	t.Run("dns01 module missing from the caddy the edge runs", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "v2.11.2 h1:x", "dns.providers.route53")
		withDNS01(cfg, "cloudflare", "route53")
		steps := planned(false, false, cfg)
		s, i := ownedStep(steps)
		if i < 0 {
			t.Fatalf("no owned-build step in %v", steps)
		}
		owned := edge.OwnedCaddyPath(cfg.DataDir)
		want := "install a Caddy build with dns.providers.cloudflare, dns.providers.route53 as " + owned + " (from caddyserver.com; checked before use, the previous build kept as .bak)"
		if s.desc != want {
			t.Errorf("desc:\n got %q\nwant %q", s.desc, want)
		}
		if stepIndex(steps, "install caddy") >= 0 {
			t.Error("a caddy is installed: the apt steps must not be planned")
		}
		// The dry run prints only: nothing is downloaded or written.
		if err := s.do(); err != nil {
			t.Fatalf("dry-run do() = %v", err)
		}
		if _, err := os.Stat(filepath.Dir(owned)); !os.IsNotExist(err) {
			t.Errorf("the dry run created %s (err=%v)", filepath.Dir(owned), err)
		}
	})

	t.Run("owned build already has the module", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "2.6.2")
		fakeCaddy(t, edge.OwnedCaddyPath(cfg.DataDir), "v2.11.2 h1:x", "dns.providers.cloudflare")
		withDNS01(cfg, "cloudflare")
		if _, i := ownedStep(planned(false, false, cfg)); i >= 0 {
			t.Error("owned build has the module and a current version: no step expected")
		}
	})

	t.Run("no caddy at all: apt first, then the plugin build", func(t *testing.T) {
		_, cfg := caddyHost(t)
		withDNS01(cfg, "cloudflare")
		steps := planned(false, false, cfg)
		apt := stepIndex(steps, "install caddy")
		_, i := ownedStep(steps)
		if apt < 0 || i < 0 || i != apt+1 {
			t.Errorf("want the owned-build step right after the apt install, got apt=%d owned=%d", apt, i)
		}
	})

	t.Run("old system caddy and a setting that needs 2.11: the owned build waits for the upgrade", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "2.6.2")
		cfg.Edge.TrustedProxies = []string{"cloudflare"}
		steps := planned(false, false, cfg)
		if _, i := ownedStep(steps); i >= 0 {
			t.Errorf("2.6.2 + trusted_proxies: no unconditional owned build expected: %v", edgeSteps(steps))
		}
		up := stepIndex(steps, descUpgradeDistro)
		owned := edge.OwnedCaddyPath(cfg.DataDir)
		want := "install a current Caddy build as " + owned + " if the system Caddy is still older than 2.11.0 after the upgrade (from caddyserver.com; checked before use)"
		cond := stepIndex(steps, want)
		if up < 0 || cond != up+1 {
			t.Errorf("want the upgrade, then the conditional owned build %q; got %q", want, edgeSteps(steps))
		}
	})

	t.Run("old owned build and a setting that needs 2.11", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "v2.11.2 h1:x")
		fakeCaddy(t, edge.OwnedCaddyPath(cfg.DataDir), "2.6.2")
		cfg.Edge.TrustedProxies = []string{"cloudflare"}
		s, i := ownedStep(planned(false, false, cfg))
		if i < 0 || !strings.HasPrefix(s.desc, ownedCaddyStepPrefix+"no plugins as ") {
			t.Errorf("owned 2.6.2 + trusted_proxies: want a plain owned build, got %q", s.desc)
		}
	})

	t.Run("old caddy, nothing needs 2.11", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "2.6.2")
		if _, i := ownedStep(planned(false, false, cfg)); i >= 0 {
			t.Error("the distro caddy is enough here: no owned build expected")
		}
	})

	t.Run("no dns01 and a current caddy", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "v2.11.2 h1:x")
		steps := planned(false, false, cfg)
		if _, i := ownedStep(steps); i >= 0 || stepIndex(steps, "install caddy") >= 0 {
			t.Errorf("nothing caddy-related to do, got %v", steps)
		}
	})

	t.Run("external edge mode never plans a plugin build", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "v2.11.2 h1:x")
		cfg.Edge.Mode = config.EdgeExternal
		withDNS01(cfg, "cloudflare")
		if _, i := ownedStep(planned(false, false, cfg)); i >= 0 {
			t.Error("Mooring runs no Caddy in external mode: no plugin build expected")
		}
	})
}

const (
	descRepo          = "add the Caddy apt repo + signing key"
	descAptUpdate     = "apt-get update"
	descInstallCaddy  = "install caddy"
	descUpgradeDistro = "upgrade caddy v2.6.2 (the distribution's build) to Caddy's official release"
	descDisableCaddy  = "disable the distro caddy.service (Mooring supervises its own child)"
	descInstallNginx  = "install nginx + the stream module"
	descDisableNginx  = "disable the distro nginx.service (Mooring supervises its own child)"
	descOwnedCF       = ownedCaddyStepPrefix + "dns.providers.cloudflare"
	descOwnedPlain    = ownedCaddyStepPrefix + "no plugins"
	descOwnedIfOld    = "install a current Caddy build" // ownedCaddyIfOldStepPrefix, cut before " as "
)

// aptEnvPrefix is how stubRunCmd records the environment setup adds to its apt-get commands.
const aptEnvPrefix = "DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l "

// planned is setup's plan for cfg (nil: there is no config.yaml), without --restart.
func planned(apply, l4 bool, cfg *config.Config) []step {
	return plan(apply, l4, false, cfg, setupEdgeModeOf(cfg, cfg != nil))
}

// edgeOnly drops the Docker log-cap and mooring-unit steps: they depend on the host running the test,
// and the applied log cap writes /etc/docker/daemon.json.
func edgeOnly(steps []step) []step {
	var out []step
	for _, s := range steps {
		d := s.desc
		if strings.HasPrefix(d, "cap Docker") || strings.HasPrefix(d, "restart docker") || strings.Contains(d, "the mooring service") {
			continue
		}
		out = append(out, s)
	}
	return out
}

// edgeSteps returns the descs of the plan's Caddy and nginx steps in order, an owned-build desc cut
// before " as <path>".
func edgeSteps(steps []step) []string {
	var out []string
	for _, s := range edgeOnly(steps) {
		d := s.desc
		if strings.HasPrefix(d, ownedCaddyStepPrefix) || strings.HasPrefix(d, ownedCaddyIfOldStepPrefix) {
			d, _, _ = strings.Cut(d, " as ")
		}
		out = append(out, d)
	}
	return out
}

// stubUnits makes unitExists report exactly units as installed. The returned map can be changed
// mid-test (a unit an apt step installed).
func stubUnits(t *testing.T, units ...string) map[string]bool {
	t.Helper()
	installed := map[string]bool{}
	for _, u := range units {
		installed[u] = true
	}
	orig := unitExists
	unitExists = func(unit string) bool { return installed[unit] }
	t.Cleanup(func() { unitExists = orig })
	return installed
}

// stubRunCmd replaces the command runner behind run() and records every command as typed: the added
// environment, then argv. fn (may be nil) is called with each one.
func stubRunCmd(t *testing.T, fn func(argv []string) error) *[][]string {
	t.Helper()
	var calls [][]string
	orig := runCmd
	runCmd = func(env []string, name string, arg ...string) error {
		argv := append(append(append([]string(nil), env...), name), arg...)
		calls = append(calls, argv)
		if fn != nil {
			return fn(argv)
		}
		return nil
	}
	t.Cleanup(func() { runCmd = orig })
	return &calls
}

// joined is each recorded command as one string.
func joined(calls [][]string) []string {
	var out []string
	for _, c := range calls {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

// stubWriteCaddyRepo stands in for adding the Caddy apt repo (a download and root-owned files): an
// applied call returns err. It returns the applied call count.
func stubWriteCaddyRepo(t *testing.T, err error) *int {
	t.Helper()
	calls := 0
	orig := writeCaddyRepo
	writeCaddyRepo = func(apply bool) error {
		if !apply {
			return nil
		}
		calls++
		return err
	}
	t.Cleanup(func() { writeCaddyRepo = orig })
	return &calls
}

// stubInstallOwnedCaddy stands in for downloading and installing the Mooring-owned build: an applied
// call returns err. It returns the applied call count.
func stubInstallOwnedCaddy(t *testing.T, err error) *int {
	t.Helper()
	calls := 0
	orig := installOwnedCaddy
	installOwnedCaddy = func(apply bool, _ *config.Config, _, _ []string) error {
		if !apply {
			return nil
		}
		calls++
		return err
	}
	t.Cleanup(func() { installOwnedCaddy = orig })
	return &calls
}

// captureStdout returns what fn prints to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	out := make(chan string)
	go func() { b, _ := io.ReadAll(r); out <- string(b) }()
	fn()
	_ = w.Close()
	return <-out
}

func TestPlanSystemCaddyAndDistroUnits(t *testing.T) {
	needs211 := func(c *config.Config) { c.Edge.TrustedProxies = []string{"cloudflare"} }
	external := func(c *config.Config) { c.Edge.Mode = config.EdgeExternal }
	cases := []struct {
		name          string
		system, owned string   // `caddy version` output; "" = not installed
		units         []string // installed systemd units
		nginx, l4     bool     // nginx on PATH; setup --l4
		set           func(*config.Config)
		config        string // "" = config.yaml loaded; "absent" = there is none; "unloadable" = it didn't load
		want          []string
	}{
		{name: "fresh host: install caddy, then disable the caddy.service the package brings",
			want: []string{descRepo, descAptUpdate, descInstallCaddy, descDisableCaddy}},
		{name: "distro 2.6.2: upgrade it from Caddy's repo", system: "2.6.2", units: []string{"caddy.service"},
			want: []string{descRepo, descAptUpdate, descUpgradeDistro, descDisableCaddy}},
		{name: "distro 2.6.2 without a caddy.service: the disable step is still planned", system: "2.6.2",
			want: []string{descRepo, descAptUpdate, descUpgradeDistro, descDisableCaddy}},
		{name: "official v2.11.2: nothing to install", system: "v2.11.2 h1:x", units: []string{"caddy.service"},
			want: []string{descDisableCaddy}},
		{name: "official v2.11.0, no unit: nothing at all", system: "v2.11.0 h1:x"},
		{name: "unreadable version: nothing planned for it", system: "(devel)"},
		{name: "owned build, no system caddy: the package is installed as the fallback", owned: "v2.11.2 h1:x",
			want: []string{descRepo, descAptUpdate, descInstallCaddy, descDisableCaddy}},
		{name: "owned build + distro 2.6.2: the system caddy is upgraded, the owned build kept", owned: "v2.11.2 h1:x", system: "2.6.2", set: needs211,
			want: []string{descRepo, descAptUpdate, descUpgradeDistro, descDisableCaddy}},
		{name: "distro 2.6.2 + trusted_proxies: upgrade, then an owned build only if it is still old", system: "2.6.2", set: needs211,
			want: []string{descRepo, descAptUpdate, descUpgradeDistro, descOwnedIfOld, descDisableCaddy}},
		// With edge.mode external the operator's own proxy fronts Mooring, often as caddy.service or
		// nginx.service: setup never installs, upgrades or disables Caddy or nginx there.
		{name: "external mode + distro 2.6.2: the operator's caddy is left alone", system: "2.6.2", set: external},
		{name: "external mode + distro 2.6.2 and the operator's caddy.service: left alone", system: "2.6.2", set: external, units: []string{"caddy.service"}},
		{name: "external mode + current caddy and the operator's caddy.service: left alone", system: "v2.11.2 h1:x", set: external, units: []string{"caddy.service"}},
		{name: "external mode, no caddy: nothing installed", set: external},
		{name: "external mode, no caddy on PATH but a caddy.service: left alone", set: external, units: []string{"caddy.service"}},
		{name: "external mode + --l4, nginx and the operator's nginx.service: left alone", system: "v2.11.2 h1:x", set: external, l4: true, nginx: true,
			units: []string{"caddy.service", "nginx.service"}},
		{name: "external mode + --l4, no nginx: nothing installed", set: external, l4: true},
		{name: "external mode + dns01: no plugin build", system: "v2.11.2 h1:x", set: func(c *config.Config) { external(c); withDNS01(c, "cloudflare") }},
		// No config.yaml yet (setup runs before it is written): the default, managed.
		{name: "no config.yaml yet + distro 2.6.2 and its unit: upgraded and disabled", config: "absent", system: "2.6.2", units: []string{"caddy.service"},
			want: []string{descRepo, descAptUpdate, descUpgradeDistro, descDisableCaddy}},
		{name: "no config.yaml yet, no caddy: installed", config: "absent",
			want: []string{descRepo, descAptUpdate, descInstallCaddy, descDisableCaddy}},
		{name: "no config.yaml yet + --l4, nginx and its unit: disabled", config: "absent", system: "v2.11.2 h1:x", l4: true, nginx: true, units: []string{"nginx.service"},
			want: []string{descDisableNginx}},
		// config.yaml exists but didn't load (an external config that fails validation looks the same):
		// the mode isn't known, so the edge is left alone.
		{name: "config.yaml didn't load + distro 2.6.2 and its unit: left alone", config: "unloadable", system: "2.6.2", units: []string{"caddy.service"}},
		{name: "config.yaml didn't load, no caddy: nothing installed", config: "unloadable"},
		{name: "config.yaml didn't load + --l4, nginx and its unit: left alone", config: "unloadable", system: "v2.11.2 h1:x", l4: true, nginx: true,
			units: []string{"caddy.service", "nginx.service"}},
		{name: "no caddy + trusted_proxies: no owned build for the version", set: needs211,
			want: []string{descRepo, descAptUpdate, descInstallCaddy, descDisableCaddy}},
		{name: "distro 2.6.2 + dns01: upgrade, then the plugin build", system: "2.6.2", set: func(c *config.Config) { withDNS01(c, "cloudflare") },
			want: []string{descRepo, descAptUpdate, descUpgradeDistro, descOwnedCF, descDisableCaddy}},
		{name: "old owned build + trusted_proxies: rebuilt as before", owned: "2.6.2", system: "v2.11.2 h1:x", set: needs211,
			want: []string{descOwnedPlain}},
		{name: "l4, no nginx: install it, then disable the nginx.service it brings", system: "v2.11.2 h1:x", l4: true,
			want: []string{descInstallNginx, descDisableNginx}},
		{name: "l4, nginx and its unit present", system: "v2.11.2 h1:x", l4: true, nginx: true, units: []string{"nginx.service"},
			want: []string{descDisableNginx}},
		{name: "l4, nginx present without a unit", system: "v2.11.2 h1:x", l4: true, nginx: true},
		{name: "no l4: nginx untouched", system: "v2.11.2 h1:x", units: []string{"nginx.service"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, cfg := caddyHost(t)
			if c.system != "" {
				fakeCaddy(t, filepath.Join(dir, "caddy"), c.system)
			}
			if c.owned != "" {
				fakeCaddy(t, edge.OwnedCaddyPath(cfg.DataDir), c.owned)
			}
			if c.nginx {
				if err := os.WriteFile(filepath.Join(dir, "nginx"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if c.set != nil {
				c.set(cfg)
			}
			stubUnits(t, c.units...)
			calls := stubRunCmd(t, nil)
			mode := setupEdgeModeOf(cfg, true)
			if c.config != "" {
				cfg, mode = nil, setupEdgeModeOf(nil, c.config == "unloadable")
			}
			got := edgeSteps(plan(false, c.l4, false, cfg, mode))
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("plan:\n got %q\nwant %q", got, c.want)
			}
			if len(*calls) != 0 {
				t.Errorf("planning ran commands: %v", *calls)
			}
		})
	}
}

// The disable step is planned before the apt step that brings the unit, so it checks again when it
// runs: a unit that still isn't there is skipped, not a failed `systemctl disable`.
func TestDisableDistroUnitStepRechecksAtRunTime(t *testing.T) {
	for _, c := range []struct {
		unit, desc string
		l4         bool
	}{
		{"caddy", descDisableCaddy, false},
		{"nginx", descDisableNginx, true},
	} {
		t.Run(c.unit, func(t *testing.T) {
			_, cfg := caddyHost(t) // no caddy, no nginx: both get installed
			units := stubUnits(t)  // and neither unit exists yet
			calls := stubRunCmd(t, nil)
			disable := func(apply bool) step {
				t.Helper()
				steps := planned(apply, c.l4, cfg)
				i := stepIndex(steps, c.desc)
				if i < 0 {
					t.Fatalf("no %q step in %q", c.desc, edgeSteps(steps))
				}
				return steps[i]
			}

			s := disable(true)
			out := captureStdout(t, func() {
				if err := s.do(); err != nil {
					t.Errorf("unit missing at run time: do() = %v, want a skip", err)
				}
			})
			if len(*calls) != 0 || !strings.Contains(out, "skipped: "+c.unit+".service isn't installed") {
				t.Errorf("unit missing at run time: ran %v, printed %q; want a printed skip and no command", *calls, out)
			}

			units[c.unit+".service"] = true // the install step brought it
			if err := s.do(); err != nil {
				t.Fatal(err)
			}
			if want := [][]string{{"systemctl", "disable", "--now", c.unit}}; !reflect.DeepEqual(*calls, want) {
				t.Errorf("unit present at run time: ran %v, want %v", *calls, want)
			}

			// The dry run prints the command; the unit doesn't exist yet because nothing was installed.
			units[c.unit+".service"] = false
			*calls = nil
			out = captureStdout(t, func() { _ = disable(false).do() })
			if len(*calls) != 0 || !strings.Contains(out, "$ systemctl disable --now "+c.unit) {
				t.Errorf("dry run: ran %v, printed %q", *calls, out)
			}
		})
	}
}

// setup runs before config.yaml exists (onboarding): the edge mode is then the default, managed. A
// config.yaml that exists but doesn't load (bad permissions, a typo, an external config without
// trusted_proxies) leaves the mode unknown.
func TestSetupEdgeModeOf(t *testing.T) {
	external := &config.Config{Edge: config.EdgeConfig{Mode: config.EdgeExternal}}
	managed := &config.Config{Edge: config.EdgeConfig{Mode: config.EdgeManaged}}
	cases := []struct {
		name   string
		cfg    *config.Config
		exists bool
		want   setupEdgeMode
	}{
		{"no config.yaml yet", nil, false, setupEdgeManaged},
		{"config.yaml didn't load", nil, true, setupEdgeUnknown},
		{"edge.mode managed", managed, true, setupEdgeManaged},
		{"edge.mode external", external, true, setupEdgeExternal},
	}
	for _, c := range cases {
		if got := setupEdgeModeOf(c.cfg, c.exists); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}

	dir := t.TempDir()
	file := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "dangling.yaml")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{file: true, dangling: true, filepath.Join(dir, "missing.yaml"): false} {
		if got := configFileExists(path); got != want {
			t.Errorf("configFileExists(%s) = %v, want %v", filepath.Base(path), got, want)
		}
	}
}

// Without config.yaml the distribution's caddy is upgraded, as for edge.mode managed.
func TestPlanWithoutConfigUpgradesCaddy(t *testing.T) {
	dir, _ := caddyHost(t)
	fakeCaddy(t, filepath.Join(dir, "caddy"), "2.6.2")
	stubUnits(t)
	if steps := planned(false, false, nil); stepIndex(steps, descUpgradeDistro) < 0 {
		t.Errorf("no config: steps=%q, want the upgrade", edgeSteps(steps))
	}
}

// `sudo mooring setup --yes` (with --l4) where the operator's own caddy.service or nginx.service fronts
// Mooring (edge.mode external), or where config.yaml doesn't load: no apt command, no Caddy repo, no
// owned build, no systemctl. The managed run on the same host is the control: it disables both units.
func TestApplySetupLeavesTheOperatorsEdgeAlone(t *testing.T) {
	cases := []struct {
		name         string
		system       string // `caddy version` output; "" = no caddy on PATH
		nginx        bool
		config       string // "managed", "external" or "unloadable"
		wantCommands []string
		wantOwned    int // owned-build installs
	}{
		{"external, the operator's caddy and nginx", "v2.10.0 h1:x", true, "external", nil, 0},
		{"external, distro 2.6.2", "2.6.2", true, "external", nil, 0},
		{"external, no caddy or nginx on PATH", "", false, "external", nil, 0},
		{"config.yaml didn't load, distro 2.6.2", "2.6.2", true, "unloadable", nil, 0},
		{"config.yaml didn't load, no caddy or nginx on PATH", "", false, "unloadable", nil, 0},
		{"managed control", "v2.11.2 h1:x", true, "managed", []string{"systemctl disable --now caddy", "systemctl disable --now nginx"}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, cfg := caddyHost(t)
			if c.system != "" {
				fakeCaddy(t, filepath.Join(dir, "caddy"), c.system)
			}
			if c.nginx {
				if err := os.WriteFile(filepath.Join(dir, "nginx"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			withDNS01(cfg, "cloudflare") // no caddy here has the module: managed mode plans the plugin build
			stubUnits(t, "caddy.service", "nginx.service")
			repo := stubWriteCaddyRepo(t, nil)
			owned := stubInstallOwnedCaddy(t, nil)
			calls := stubRunCmd(t, nil)
			mode := setupEdgeModeOf(cfg, true)
			switch c.config {
			case "external":
				cfg.Edge.Mode = config.EdgeExternal
				mode = setupEdgeModeOf(cfg, true)
			case "unloadable":
				cfg, mode = nil, setupEdgeModeOf(nil, true)
			}
			var err error
			captureStdout(t, func() { _, err = applySteps(os.Stdout, edgeOnly(plan(true, true, false, cfg, mode))) })
			if err != nil {
				t.Fatal(err)
			}
			if got := joined(*calls); !reflect.DeepEqual(got, c.wantCommands) {
				t.Errorf("ran %q, want %q", got, c.wantCommands)
			}
			if *repo != 0 || *owned != c.wantOwned {
				t.Errorf("Caddy repo added %d times, owned build installed %d times (want %d)", *repo, *owned, c.wantOwned)
			}
		})
	}
}

// serve runs the L4 load balancer only with edge.mode managed, and setup plans no nginx step otherwise:
// `doctor --l4` in external mode says so instead of checking (and offering to fix) nginx.
func TestL4Checks(t *testing.T) {
	got := l4Checks(false)
	if len(got) != 1 || got[0].name != "l4" || got[0].state != "skip" || !strings.Contains(got[0].detail, "edge.mode is external") || got[0].fix != "" {
		t.Errorf("external: %+v, want one skip", got)
	}
	var names []string
	for _, r := range l4Checks(true) {
		names = append(names, r.name)
	}
	if want := []string{"nginx", "nginx conflict", "nginx stream", "port 53"}; !reflect.DeepEqual(names, want) {
		t.Errorf("managed: checks %q, want %q", names, want)
	}
}

// When the Mooring-owned build fails to install, the hint says how it gets retried: Mooring retries a
// build for a dns01 provider's plugin at startup, but never installs the plugin-less build for the
// 2.11 minimum itself, so only re-running setup retries that one.
func TestOwnedBuildFailureHint(t *testing.T) {
	const startupRetry = "Mooring retries it at startup"
	const setupRetry = "run `sudo mooring setup --yes` again to retry"
	stubOwnedInstall := func(t *testing.T) *[]edge.InstallOptions {
		t.Helper()
		var got []edge.InstallOptions
		origInstall, origOwner := installPluginBuild, serviceUserOwner
		installPluginBuild = func(_ context.Context, opt edge.InstallOptions) (string, error) {
			got = append(got, opt)
			return "", errors.New("download: no route to host")
		}
		serviceUserOwner = func() (*edge.Owner, error) { return &edge.Owner{Uid: os.Getuid(), Gid: os.Getgid()}, nil }
		t.Cleanup(func() { installPluginBuild, serviceUserOwner = origInstall, origOwner })
		return &got
	}

	// The upgrade fails and the system caddy stays 2.6.2 with trusted_proxies set: the plugin-less build.
	t.Run("plugin-less build for 2.11, after a failed upgrade", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "2.6.2")
		cfg.Edge.TrustedProxies = []string{"cloudflare"}
		stubUnits(t, "caddy.service")
		stubWriteCaddyRepo(t, nil)
		stubRunCmd(t, func(argv []string) error {
			if strings.Contains(strings.Join(argv, " "), "apt-get install") {
				return errors.New("exit status 100")
			}
			return nil
		})
		opts := stubOwnedInstall(t)
		done, err, out := applyEdgeSteps(t, false, cfg)
		if err != nil || done != (applied{}) || len(*opts) != 1 || len((*opts)[0].WantModules) != 0 {
			t.Fatalf("err=%v done=%+v installs=%+v; want one failed plugin-less install", err, done, *opts)
		}
		if (*opts)[0].Check == nil {
			t.Error("the plugin-less build must be checked against the edge config too")
		}
		if !strings.Contains(out, "WARNING: the Caddy build wasn't installed: download: no route to host\n       "+setupRetry) || strings.Contains(out, startupRetry) {
			t.Errorf("output %q should tell the operator to re-run setup, not that Mooring retries it", out)
		}
	})

	t.Run("dns01 plugin build", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "v2.11.2 h1:x")
		withDNS01(cfg, "cloudflare")
		stubUnits(t)
		stubRunCmd(t, nil)
		opts := stubOwnedInstall(t)
		done, err, out := applyEdgeSteps(t, false, cfg)
		if err != nil || done != (applied{}) || len(*opts) != 1 || !reflect.DeepEqual((*opts)[0].WantModules, []string{"dns.providers.cloudflare"}) {
			t.Fatalf("err=%v done=%+v installs=%+v; want one failed plugin build", err, done, *opts)
		}
		if (*opts)[0].Check == nil {
			t.Error("the plugin build must be checked against the edge config")
		}
		if !strings.Contains(out, "WARNING: the Caddy build wasn't installed: download: no route to host\n       "+startupRetry) {
			t.Errorf("output %q should say Mooring retries the plugin build at startup", out)
		}
	})
}

// validateCall is one `caddy validate` run by setup's build check (validateEdgeConfig).
type validateCall struct {
	bin, cfg string
	redact   []string
}

// stubValidateEdgeConfig stands in for `caddy validate`: verdict (nil: every config accepted) decides
// each call, and every call is recorded.
func stubValidateEdgeConfig(t *testing.T, verdict func(bin string, cfg []byte) error) *[]validateCall {
	t.Helper()
	var calls []validateCall
	orig := validateEdgeConfig
	validateEdgeConfig = func(_ context.Context, bin string, cfg []byte, redact []string) error {
		calls = append(calls, validateCall{bin, string(cfg), append([]string(nil), redact...)})
		if verdict != nil {
			return verdict(bin, cfg)
		}
		return nil
	}
	t.Cleanup(func() { validateEdgeConfig = orig })
	return &calls
}

const (
	tokCF  = "tok-cf-0123456789"
	tokR53 = "tok-r53-0123456789"
)

// setupCheckConfig is a config.yaml with the edge settings setup's check renders: trusted proxies with a
// client IP header, the admin vhost and a private CA, plus two dns01 namespaces, one on a provider whose
// module takes other credentials than api_token (route53).
func setupCheckConfig(t *testing.T) *config.Config {
	t.Helper()
	_, cfg := caddyHost(t)
	cfg.EncryptionKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	cfg.IPAllowlist = []string{"203.0.113.0/24"}
	cfg.Admin.Subdomain = "admin"
	cfg.Edge.ACMEEmail = "ops@example.com"
	cfg.Edge.CAs = []config.EdgeCA{{Name: "corp", DirectoryURL: "https://ca.corp.example/acme"}}
	cfg.Edge.TrustedProxies = []string{"10.0.0.0/8"}
	cfg.Edge.ClientIPHeader = "CF-Connecting-IP"
	withDNS01(cfg, "cloudflare", "route53")
	cfg.Edge.DNS01.APIToken = tokCF
	cfg.Edge.BaseDomains[0].DNS01.APIToken = tokR53
	// Intentional: the error is ignored. Validate is called only because it parses ip_allowlist
	// into the canonical list the edge is rendered with (a loaded config always has it); this
	// hand-built fixture isn't a complete config.yaml.
	_ = cfg.Validate()
	if len(cfg.AllowlistStrings()) != 1 {
		t.Fatalf("fixture: ip_allowlist not parsed: %v", cfg.AllowlistStrings())
	}
	return cfg
}

// The build setup installs must accept the edge's startup config and the config.yaml edge settings
// rendered as serve renders them (trusted proxies, admin vhost, CAs): `caddy validate` of each, in that
// order, with the dns01 tokens to redact. setup has no database, so there are no app routes, and no
// DNS-01 wildcard is rendered: a provider whose module takes other credentials than api_token (route53)
// is refused by every build, and serve keeps serving without that namespace's wildcard.
func TestSetupBuildCheck(t *testing.T) {
	ctx := context.Background()
	cfg := setupCheckConfig(t)
	var refuse func(cfg []byte) error
	calls := stubValidateEdgeConfig(t, func(_ string, c []byte) error {
		if refuse != nil {
			return refuse(c)
		}
		return nil
	})
	check := setupBuildCheck(cfg)
	if check == nil {
		t.Fatal("a loaded config.yaml must give a check")
	}
	const bin = "/var/lib/mooring/bin/caddy.new.0123456789ab"
	if err := check(ctx, bin); err != nil {
		t.Fatalf("every config accepted: %v", err)
	}
	base := edgeBaseConfig(cfg)
	floor, err := edge.Render(edge.BootFloor(base), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	full, err := edge.Render(base, nil, []edge.CertHost{{Hostname: "mooring-setup-check-1.invalid", CA: "corp"}})
	if err != nil {
		t.Fatal(err)
	}
	tokens := []string{tokCF, tokR53}
	if want := []validateCall{{bin, string(floor), tokens}, {bin, string(full), tokens}}; !reflect.DeepEqual(*calls, want) {
		t.Fatalf("validated:\n%+v\nwant the startup config, then the edge settings:\n%+v", *calls, want)
	}
	for _, s := range []string{`"trusted_proxies"`, "CF-Connecting-IP", "admin.example.com", "ops@example.com", "203.0.113.0/24", "https://ca.corp.example/acme"} {
		if !strings.Contains(string(full), s) {
			t.Errorf("the config.yaml render must carry %s", s)
		}
	}
	for _, c := range []validateCall{{cfg: string(floor)}, {cfg: string(full)}} {
		for _, s := range []string{`"challenges"`, "route53", tokCF, tokR53, "*.example.com", "*.nsa.example.net"} {
			if strings.Contains(c.cfg, s) {
				t.Errorf("no DNS-01 wildcard may be rendered for setup's check, found %s", s)
			}
		}
	}

	// The edge settings refused: the error names that config and carries Caddy's report.
	*calls = nil
	refuse = func(c []byte) error {
		if string(c) == string(full) {
			return fmt.Errorf("%w: json: unknown field %q", edge.ErrValidateRefused, "trusted_proxies")
		}
		return nil
	}
	err = check(ctx, bin)
	if err == nil || !strings.Contains(err.Error(), "the edge settings in config.yaml") || !strings.Contains(err.Error(), `unknown field "trusted_proxies"`) || !errors.Is(err, edge.ErrValidateRefused) {
		t.Errorf("edge settings refused: %v", err)
	}
	// The startup config refused: the edge settings aren't checked.
	*calls = nil
	refuse = func(c []byte) error {
		if string(c) == string(floor) {
			return fmt.Errorf("%w: bad floor", edge.ErrValidateRefused)
		}
		return nil
	}
	if err := check(ctx, bin); err == nil || !strings.Contains(err.Error(), "the startup config") || len(*calls) != 1 {
		t.Errorf("startup config refused: err=%v after %d validations; want the startup config named, nothing else validated", err, len(*calls))
	}

	if setupBuildCheck(nil) != nil {
		t.Error("no config.yaml: no check")
	}
}

// renderedPolicy is one TLS automation policy of a rendered edge config: its subjects and its ACME issuer.
type renderedPolicy struct {
	Subjects []string `json:"subjects"`
	Issuers  []struct {
		CA           string   `json:"ca"`
		Email        string   `json:"email"`
		TrustedRoots []string `json:"trusted_roots_pem_files"`
	} `json:"issuers"`
}

// renderedPolicies decodes the TLS automation policies of a rendered edge config.
func renderedPolicies(t *testing.T, render string) []renderedPolicy {
	t.Helper()
	var doc struct {
		Apps struct {
			TLS *struct {
				Automation struct {
					Policies []renderedPolicy `json:"policies"`
				} `json:"automation"`
			} `json:"tls"`
		} `json:"apps"`
	}
	if err := json.Unmarshal([]byte(render), &doc); err != nil {
		t.Fatalf("the render isn't JSON: %v", err)
	}
	if doc.Apps.TLS == nil {
		return nil
	}
	return doc.Apps.TLS.Automation.Policies
}

// Render emits a named CA's issuer only for a subject that uses it, and setup has no routes or cert
// bindings, so setup's check gives every edge.cas CA a subject under .invalid: the config.yaml render
// carries each CA's issuer (directory URL, email or the acme_email fallback, trusted root). The startup
// config is unchanged, and with no edge.cas the render is the plain one.
func TestSetupBuildCheckRendersEveryCA(t *testing.T) {
	ctx := context.Background()
	const bin = "/var/lib/mooring/bin/caddy.new.0123456789ab"
	cfg := setupCheckConfig(t)
	cfg.Edge.CAs = []config.EdgeCA{
		{Name: "corp", DirectoryURL: "https://ca.corp.example/acme"},
		{Name: "lab", DirectoryURL: "https://ca.lab.example/acme/acme/directory", Email: "pki@lab.example", TrustedRoot: "/etc/mooring/lab-root.pem"},
	}
	calls := stubValidateEdgeConfig(t, nil)
	if err := setupBuildCheck(cfg)(ctx, bin); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 2 {
		t.Fatalf("validated %d configs, want the startup config and the edge settings", len(*calls))
	}
	floor, err := edge.Render(edge.BootFloor(edgeBaseConfig(cfg)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if (*calls)[0].cfg != string(floor) {
		t.Errorf("the startup config must be rendered as serve boots it:\n%s", (*calls)[0].cfg)
	}
	policies := renderedPolicies(t, (*calls)[1].cfg)
	subjects := map[string]bool{}
	for _, ca := range []struct{ url, email, root string }{
		{"https://ca.corp.example/acme", "ops@example.com", ""},
		{"https://ca.lab.example/acme/acme/directory", "pki@lab.example", "/etc/mooring/lab-root.pem"},
	} {
		found := 0
		for _, p := range policies {
			if len(p.Issuers) != 1 || p.Issuers[0].CA != ca.url {
				continue
			}
			found++
			iss := p.Issuers[0]
			var roots []string
			if ca.root != "" {
				roots = []string{ca.root}
			}
			if iss.Email != ca.email || !reflect.DeepEqual(iss.TrustedRoots, roots) {
				t.Errorf("CA %s: issuer email=%q roots=%q, want %q %q", ca.url, iss.Email, iss.TrustedRoots, ca.email, roots)
			}
			if len(p.Subjects) != 1 || !strings.HasSuffix(p.Subjects[0], ".invalid") || subjects[p.Subjects[0]] {
				t.Errorf("CA %s: subjects %q, want one name of its own under .invalid", ca.url, p.Subjects)
			}
			for _, s := range p.Subjects {
				subjects[s] = true
			}
		}
		if found != 1 {
			t.Errorf("the edge settings render has %d policies for CA %s, want 1:\n%s", found, ca.url, (*calls)[1].cfg)
		}
	}
	if !strings.Contains((*calls)[1].cfg, "admin.example.com") {
		t.Error("the admin vhost must still be rendered with the CAs")
	}

	cfg.Edge.CAs = nil
	*calls = nil
	if err := setupBuildCheck(cfg)(ctx, bin); err != nil {
		t.Fatal(err)
	}
	full, err := edge.Render(edgeBaseConfig(cfg), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 2 || (*calls)[1].cfg != string(full) || strings.Contains((*calls)[1].cfg, ".invalid") {
		t.Errorf("no edge.cas: the edge settings must render as serve renders them, no extra subject:\n%+v", *calls)
	}
}

// fileState is one path's owner, mode, size and modification time (fileStates).
type fileState struct {
	uid        uint32
	mode       os.FileMode
	size       int64
	modUnixSec int64
}

// fileStates walks each root (a missing one is skipped) and records every path in it.
func fileStates(t *testing.T, roots ...string) map[string]fileState {
	t.Helper()
	out := map[string]fileState{}
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			fi, ierr := d.Info()
			if ierr != nil {
				return nil
			}
			st := fileState{mode: fi.Mode(), size: fi.Size(), modUnixSec: fi.ModTime().Unix()}
			if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
				st.uid = sys.Uid
			}
			out[p] = st
			return nil
		})
	}
	return out
}

// setup's config check against a real Caddy, the way `sudo mooring setup --yes` runs it: as root it runs
// Caddy as the mooring user. Opt-in (Linux, in a throwaway container): MOORING_TEST_REAL_CADDY is the
// candidate (a Caddy >= 2.11, e.g. a copy at <data_dir>/bin/caddy.new.x owned by mooring), which must
// pass; MOORING_TEST_OLD_CADDY, if set, a Caddy < 2.11, which must refuse edge.trusted_proxies. Nothing
// in the edge's storage (/var/lib/caddy) or next to the candidate may be created or changed as root. The
// candidate must refuse an edge.cas CA whose trusted root file is missing.
func TestSetupBuildCheckRealCaddy(t *testing.T) {
	bin := os.Getenv("MOORING_TEST_REAL_CADDY")
	if bin == "" {
		t.Skip("set MOORING_TEST_REAL_CADDY to a Caddy >= 2.11 binary")
	}
	ctx := context.Background()
	cfg := setupCheckConfig(t)
	cfg.Edge.TrustedProxies = []string{"cloudflare", "10.0.0.0/8"}
	check := setupBuildCheck(cfg)
	// run runs the check on b and reports what it created, changed or removed in the edge's storage and
	// next to the candidate.
	run := func(b string) error {
		t.Helper()
		watch := []string{"/var/lib/caddy", filepath.Dir(bin)}
		before := fileStates(t, watch...)
		err := check(ctx, b)
		after := fileStates(t, watch...)
		for p, st := range after {
			if prev, ok := before[p]; ok && prev == st {
				continue
			}
			t.Logf("%s: created or changed %s uid=%d mode=%v", filepath.Base(b), p, st.uid, st.mode)
			if os.Geteuid() == 0 && st.uid == 0 {
				t.Errorf("the check of %s created or changed %s as root", b, p)
			}
		}
		for p := range before {
			if _, ok := after[p]; !ok {
				t.Errorf("the check of %s removed %s", b, p)
			}
		}
		t.Logf("%s as uid %d: %d paths before, %d after", filepath.Base(b), os.Geteuid(), len(before), len(after))
		return err
	}
	if err := run(bin); err != nil {
		t.Errorf("a current Caddy must accept the startup config and the edge settings: %v", err)
	}
	if old := os.Getenv("MOORING_TEST_OLD_CADDY"); old != "" {
		err := run(old)
		if err == nil || !errors.Is(err, edge.ErrValidateRefused) || !strings.Contains(err.Error(), `unknown field "trusted_proxies"`) ||
			!strings.Contains(err.Error(), "the edge settings in config.yaml") {
			t.Errorf("a Caddy older than 2.11 must refuse the trusted-proxy settings: %v", err)
		} else {
			t.Logf("old Caddy refused as expected: %v", err)
		}
	}
	// An edge.cas CA whose trusted root Caddy can't read is refused, though no route uses the CA.
	cfg.Edge.CAs[0].TrustedRoot = filepath.Join(t.TempDir(), "missing-root.pem")
	err := setupBuildCheck(cfg)(ctx, bin)
	if err == nil || !errors.Is(err, edge.ErrValidateRefused) || !strings.Contains(err.Error(), "the edge settings in config.yaml") ||
		!strings.Contains(err.Error(), "missing-root.pem") {
		t.Errorf("a CA with an unreadable trusted root must be refused: %v", err)
	} else {
		t.Logf("broken CA refused as expected: %v", err)
	}
}

// configCheckCaddy writes a fake Caddy that answers `validate` like Caddy (a JSON error line, exit 1): it
// refuses any config with a trusted_proxies field when refuse is set, quoting token in its error the way
// a DNS provider module quotes a malformed one. Shell builtins only (validate runs with no PATH).
func configCheckCaddy(t *testing.T, path, token string, refuse bool) {
	t.Helper()
	verdict := "    echo 'Valid configuration' ;;\n"
	if refuse {
		verdict = `    if [ "$bad" = 1 ]; then echo '{"level":"error","msg":"loading http app module: json: unknown field \"trusted_proxies\" near ` + token + `"}' >&2; exit 1; fi` + "\n" + verdict
	}
	script := "#!/bin/sh\ncase \"$1\" in\n  validate)\n    bad=0\n" +
		"    while IFS= read -r l || [ -n \"$l\" ]; do case \"$l\" in *trusted_proxies*) bad=1 ;; esac; done\n" +
		verdict + "  *) exit 1 ;;\nesac\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
}

// `setup --yes` installs a Mooring-owned build only if it passes the config check (the real `caddy
// validate` wrapper on the download, as InstallPluginBuild runs InstallOptions.Check before the swap). A
// build that fails it isn't installed: setup warns with Caddy's report, the dns01 tokens redacted, says
// how to retry, and goes on.
func TestOwnedCaddyInstallChecksTheEdgeConfig(t *testing.T) {
	for _, refuse := range []bool{true, false} {
		t.Run(fmt.Sprintf("refused=%v", refuse), func(t *testing.T) {
			dir, cfg := caddyHost(t)
			fakeCaddy(t, filepath.Join(dir, "caddy"), "v2.11.2 h1:x") // no dns.providers.cloudflare: a build is planned
			withDNS01(cfg, "cloudflare")
			cfg.Edge.DNS01.APIToken = tokCF
			cfg.Edge.TrustedProxies = []string{"10.0.0.0/8"}
			stubUnits(t)
			stubRunCmd(t, nil)
			origInstall, origOwner := installPluginBuild, serviceUserOwner
			t.Cleanup(func() { installPluginBuild, serviceUserOwner = origInstall, origOwner })
			serviceUserOwner = func() (*edge.Owner, error) { return &edge.Owner{Uid: os.Getuid(), Gid: os.Getgid()}, nil }
			checked := 0
			installPluginBuild = func(ctx context.Context, opt edge.InstallOptions) (string, error) {
				// Like edge.InstallPluginBuild: the download, then opt.Check on it before the swap.
				cand := filepath.Join(opt.DataDir, "bin", "caddy.new.0123456789ab")
				configCheckCaddy(t, cand, tokCF, refuse)
				if opt.Check == nil {
					return "", errors.New("no config check")
				}
				checked++
				if err := opt.Check(ctx, cand); err != nil {
					_ = os.Remove(cand)
					return "", fmt.Errorf("%w (Caddy v2.12.0), keeping the current binary: %w", edge.ErrBuildCheckFailed, err)
				}
				owned := edge.OwnedCaddyPath(opt.DataDir)
				return owned, os.Rename(cand, owned)
			}
			done, err, out := applyEdgeSteps(t, false, cfg)
			if err != nil || checked != 1 {
				t.Fatalf("err=%v checked=%d; want setup to go on after checking the build once", err, checked)
			}
			_, statErr := os.Stat(edge.OwnedCaddyPath(cfg.DataDir))
			if !refuse {
				if !done.ownedCaddy || statErr != nil || !strings.Contains(out, "installed "+edge.OwnedCaddyPath(cfg.DataDir)) {
					t.Errorf("a build that passes the check: done=%+v stat=%v output:\n%s", done, statErr, out)
				}
				return
			}
			if done.ownedCaddy || !errors.Is(statErr, os.ErrNotExist) {
				t.Errorf("a build that fails the check must not be installed: done=%+v stat=%v", done, statErr)
			}
			for _, want := range []string{
				"WARNING: the Caddy build wasn't installed: edge: the downloaded Caddy build failed its check",
				"the edge config check failed on the edge settings in config.yaml",
				`unknown field "trusted_proxies" near [redacted]`,
				"then run `sudo mooring setup --yes` again",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("the warning lacks %q:\n%s", want, out)
				}
			}
			if strings.Contains(out, tokCF) {
				t.Errorf("the dns01 token leaked into setup's output:\n%s", out)
			}
			if strings.Contains(out, "Mooring retries it at startup") {
				t.Errorf("a build refused by the config check isn't fixed by Mooring's retry:\n%s", out)
			}
		})
	}
}

// configCheckLine is the dry-run line for setup's config check.
const configCheckLine = "       check it accepts the edge's startup config and the edge settings in config.yaml (caddy validate, without app routes or DNS-01 wildcards)\n"

// The dry run says the build is checked against the edge config, for the plugin build and for the
// build for 2.11 that waits for the upgrade, and runs nothing.
func TestOwnedCaddyDryRunPrintsTheConfigCheck(t *testing.T) {
	calls := stubValidateEdgeConfig(t, nil)
	t.Run("plugin build", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "v2.11.2 h1:x")
		withDNS01(cfg, "cloudflare")
		s, i := ownedStep(planned(false, false, cfg))
		if i < 0 {
			t.Fatal("no owned-build step")
		}
		out := captureStdout(t, func() { _ = s.do() })
		if !strings.Contains(out, "check it runs, is at least 2.11.0 and has dns.providers.cloudflare;") || !strings.Contains(out, configCheckLine) {
			t.Errorf("dry run:\n%s\nwant the version/module check and %q", out, configCheckLine)
		}
	})
	t.Run("plugin build with edge.cas", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "v2.11.2 h1:x")
		withDNS01(cfg, "cloudflare")
		cfg.Edge.CAs = []config.EdgeCA{{Name: "corp", DirectoryURL: "https://ca.corp.example/acme"}}
		s, i := ownedStep(planned(false, false, cfg))
		if i < 0 {
			t.Fatal("no owned-build step")
		}
		const want = "       check it accepts the edge's startup config and the edge settings in config.yaml with each edge.cas CA (caddy validate, without app routes or DNS-01 wildcards)\n"
		if out := captureStdout(t, func() { _ = s.do() }); !strings.Contains(out, want) {
			t.Errorf("dry run:\n%s\nwant %q", out, want)
		}
	})
	t.Run("build for 2.11 after the upgrade", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "2.6.2")
		cfg.Edge.TrustedProxies = []string{"cloudflare"}
		stubUnits(t)
		var s *step
		steps := planned(false, false, cfg)
		for i := range steps {
			if strings.HasPrefix(steps[i].desc, ownedCaddyIfOldStepPrefix) {
				s = &steps[i]
			}
		}
		if s == nil {
			t.Fatalf("no conditional owned-build step in %q", edgeSteps(steps))
		}
		if out := captureStdout(t, func() { _ = s.do() }); !strings.Contains(out, configCheckLine) {
			t.Errorf("dry run:\n%s\nwant %q", out, configCheckLine)
		}
	})
	if len(*calls) != 0 {
		t.Errorf("the dry run validated %d configs; want none", len(*calls))
	}
}

// setup says why it plans no Caddy or nginx step when the edge isn't Mooring's, or isn't known to be.
func TestSetupEdgeNote(t *testing.T) {
	if r, ok := setupEdgeNote(setupEdgeManaged); ok {
		t.Errorf("managed: %+v, want no note", r)
	}
	r, ok := setupEdgeNote(setupEdgeExternal)
	if !ok || r.name != "edge" || r.state != "skip" || !strings.Contains(r.detail, "edge.mode is external") || r.fix != "" {
		t.Errorf("external: %+v ok=%v", r, ok)
	}
	r, ok = setupEdgeNote(setupEdgeUnknown)
	if !ok || r.name != "edge" || r.state != "warn" || !strings.Contains(r.detail, "config.yaml didn't load") ||
		!strings.Contains(r.fix, "sudo mooring doctor") || !strings.Contains(r.fix, "sudo mooring setup") {
		t.Errorf("unknown: %+v ok=%v", r, ok)
	}
}

func TestUpgradeSystemCaddyStep(t *testing.T) {
	wantArgv := []string{"DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l",
		"apt-get", "install", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "caddy"}
	upgrade := func(t *testing.T, apply bool, apt func(sys string) error) (error, [][]string, string) {
		t.Helper()
		dir, cfg := caddyHost(t)
		sys := filepath.Join(dir, "caddy")
		fakeCaddy(t, sys, "2.6.2")
		stubUnits(t, "caddy.service")
		calls := stubRunCmd(t, func([]string) error { return apt(sys) })
		steps := planned(apply, false, cfg)
		i := stepIndex(steps, descUpgradeDistro)
		if i < 0 {
			t.Fatalf("no upgrade step in %q", edgeSteps(steps))
		}
		var err error
		out := captureStdout(t, func() { err = steps[i].do() })
		return err, *calls, out
	}

	t.Run("upgraded", func(t *testing.T) {
		err, calls, out := upgrade(t, true, func(sys string) error {
			fakeCaddy(t, sys, "v2.11.2 h1:x") // apt replaced the distribution's build
			return nil
		})
		if err != nil {
			t.Errorf("do() = %v", err)
		}
		if !reflect.DeepEqual(calls, [][]string{wantArgv}) {
			t.Errorf("ran %v, want %v", calls, wantArgv)
		}
		if !strings.Contains(out, "is now v2.11.2") {
			t.Errorf("output %q should report the new version", out)
		}
	})

	t.Run("apt kept the distribution's build", func(t *testing.T) {
		err, _, _ := upgrade(t, true, func(string) error { return nil })
		var warn stepWarning
		if !errors.As(err, &warn) {
			t.Fatalf("do() = %v, want a stepWarning", err)
		}
		if !strings.Contains(warn.err.Error(), "2.6.2") || !strings.Contains(warn.hint, "apt-cache policy caddy") {
			t.Errorf("warning = %v / %q, want the version and the apt-cache policy hint", warn.err, warn.hint)
		}
	})

	// The upgrade is optional: apt failing (its lock held by unattended-upgrades, the repo unreachable, a
	// held package) leaves the old Caddy in place and must not stop the rest of setup.
	t.Run("apt failed", func(t *testing.T) {
		err, _, _ := upgrade(t, true, func(string) error { return errors.New("exit status 100") })
		var warn stepWarning
		if !errors.As(err, &warn) {
			t.Fatalf("do() = %v, want a stepWarning", err)
		}
		if warn.err.Error() != "apt-get install caddy: exit status 100" || warn.hint != "the host keeps its current Caddy; retry `sudo mooring setup --yes` once apt is free" {
			t.Errorf("warning = %q / %q, want the apt error and the retry hint", warn.err, warn.hint)
		}
	})

	t.Run("dry run", func(t *testing.T) {
		err, calls, out := upgrade(t, false, func(string) error { t.Error("the dry run ran apt"); return nil })
		if err != nil || len(calls) != 0 {
			t.Errorf("dry run: err=%v ran %v", err, calls)
		}
		if !strings.Contains(out, "$ "+strings.Join(wantArgv, " ")) {
			t.Errorf("dry run printed %q, want the apt-get command", out)
		}
	})
}

func TestSetupRestartHint(t *testing.T) {
	const startMsg = "Restart Mooring so the edge starts: sudo systemctl restart mooring"
	const ownedMsg = "Restart Mooring so the edge switches to it: sudo systemctl restart mooring"
	const watcherMsg = "Mooring restarts its edge on the new Caddy within a few minutes; to switch now: sudo systemctl restart mooring"
	installed := applied{systemCaddyInstalled: true}
	upgraded := applied{systemCaddyUpgraded: true}
	cases := []struct {
		name    string
		done    applied
		restart bool
		running runningEdge
		want    string
	}{
		{"nothing Caddy-related", applied{}, false, edgeOnSystem, ""},
		{"nothing Caddy-related, no edge", applied{}, false, edgeNoCaddy, ""},
		{"owned build installed", applied{ownedCaddy: true}, false, edgeOnSystem, ownedMsg},
		{"owned build installed, service not running", applied{ownedCaddy: true}, false, edgeNotRunning, ownedMsg},
		// serve found no Caddy at its start, so it runs no edge and nothing watches for one.
		{"caddy installed while the service runs without an edge", installed, false, edgeNoCaddy, startMsg},
		{"caddy and the owned build installed while the service runs without an edge", applied{systemCaddyInstalled: true, ownedCaddy: true}, false, edgeNoCaddy, startMsg},
		{"caddy installed before Mooring was started", installed, false, edgeNotRunning, ""},
		{"caddy installed as the fallback behind the running owned build", installed, false, edgeOnOwned, ""},
		{"system caddy upgraded under the running edge", upgraded, false, edgeOnSystem, watcherMsg},
		{"system caddy upgraded behind the running owned build", upgraded, false, edgeOnOwned, ""},
		{"system caddy upgraded before Mooring was started", upgraded, false, edgeNotRunning, ""},
		{"upgrade + owned build: the owned build needs the restart", applied{ownedCaddy: true, systemCaddyUpgraded: true}, false, edgeOnSystem, ownedMsg},
		{"--restart already restarts it", applied{ownedCaddy: true, systemCaddyInstalled: true}, true, edgeNoCaddy, ""},
		{"--restart after an upgrade", upgraded, true, edgeOnSystem, ""},
	}
	for _, c := range cases {
		if got := setupRestartHint(c.done, c.restart, c.running); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// What the running service's edge runs on is read before setup applies its steps.
func TestServiceRunningEdge(t *testing.T) {
	cases := []struct {
		name          string
		active        bool
		system, owned bool
		external      bool
		want          runningEdge
	}{
		{"stopped", false, true, false, false, edgeNotRunning},
		{"running, no caddy at all", true, false, false, false, edgeNoCaddy},
		{"running on the system caddy", true, true, false, false, edgeOnSystem},
		{"running on the owned build", true, true, true, false, edgeOnOwned},
		{"running on the owned build, no system caddy", true, false, true, false, edgeOnOwned},
		{"external mode: Mooring runs no edge", true, false, false, true, edgeNotRunning},
	}
	for _, c := range cases {
		dir, cfg := caddyHost(t)
		if c.system {
			fakeCaddy(t, filepath.Join(dir, "caddy"), "v2.11.2 h1:x")
		}
		if c.owned {
			fakeCaddy(t, edge.OwnedCaddyPath(cfg.DataDir), "v2.11.2 h1:x")
		}
		if c.external {
			cfg.Edge.Mode = config.EdgeExternal
		}
		if got := serviceRunningEdge(c.active, cfg); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// applyEdgeSteps applies the Caddy and nginx steps of `setup --yes` with apt, systemctl, the Caddy repo
// and the owned-build download stood in for, and returns what applySteps reported and printed.
func applyEdgeSteps(t *testing.T, l4 bool, cfg *config.Config) (applied, error, string) {
	t.Helper()
	var done applied
	var err error
	out := captureStdout(t, func() { done, err = applySteps(os.Stdout, edgeOnly(planned(true, l4, cfg))) })
	return done, err, out
}

// `setup --yes` on a host with the distribution's 2.6.2 and edge.trusted_proxies set. The upgrade is
// optional: a failure of any of its steps is a warning and the steps after it still run. Whether the
// Mooring-owned build is needed for the version is known only once the upgrade ran.
func TestApplyCaddyUpgrade(t *testing.T) {
	const (
		retryHint  = "the host keeps its current Caddy; retry `sudo mooring setup --yes` once apt is free"
		aptUpdate  = aptEnvPrefix + "apt-get update"
		aptUpgrade = aptEnvPrefix + "apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold caddy"
		disable    = "systemctl disable --now caddy"
	)
	// host returns the system caddy's path, the recorded commands and the owned-build install count.
	host := func(t *testing.T, repoErr error, apt func(sys, cmd string) error) (*config.Config, string, *[][]string, *int) {
		t.Helper()
		dir, cfg := caddyHost(t)
		sys := filepath.Join(dir, "caddy")
		fakeCaddy(t, sys, "2.6.2")
		cfg.Edge.TrustedProxies = []string{"cloudflare"}
		stubUnits(t, "caddy.service")
		stubWriteCaddyRepo(t, repoErr)
		owned := stubInstallOwnedCaddy(t, nil)
		calls := stubRunCmd(t, func(argv []string) error {
			if cmd := strings.Join(argv, " "); strings.Contains(cmd, "apt-get") && apt != nil {
				return apt(sys, cmd)
			}
			return nil
		})
		return cfg, sys, calls, owned
	}

	t.Run("upgraded to 2.11: the owned build is skipped", func(t *testing.T) {
		cfg, sys, calls, owned := host(t, nil, func(sys, cmd string) error {
			if cmd == aptUpgrade {
				fakeCaddy(t, sys, "v2.11.2 h1:x")
			}
			return nil
		})
		done, err, out := applyEdgeSteps(t, false, cfg)
		if err != nil || done != (applied{systemCaddyUpgraded: true}) || *owned != 0 {
			t.Errorf("err=%v done=%+v owned installs=%d; want the upgrade counted and no owned build", err, done, *owned)
		}
		if !strings.Contains(out, "skipped: "+sys+" is v2.11.2 after the upgrade") {
			t.Errorf("output %q should say why the owned build was skipped", out)
		}
		if got, want := joined(*calls), []string{aptUpdate, aptUpgrade, disable}; !reflect.DeepEqual(got, want) {
			t.Errorf("ran\n %q\nwant\n %q", got, want)
		}
	})

	t.Run("apt kept 2.6.2: the owned build is installed", func(t *testing.T) {
		cfg, _, _, owned := host(t, nil, nil)
		done, err, out := applyEdgeSteps(t, false, cfg)
		if err != nil || done != (applied{ownedCaddy: true}) || *owned != 1 {
			t.Errorf("err=%v done=%+v owned installs=%d; want only the owned build counted", err, done, *owned)
		}
		if !strings.Contains(out, "WARNING: ") || !strings.Contains(out, "is still v2.6.2 after the upgrade") {
			t.Errorf("output %q should warn that the upgrade kept 2.6.2", out)
		}
	})

	t.Run("apt-get install failed: a warning, and setup goes on", func(t *testing.T) {
		cfg, _, calls, owned := host(t, nil, func(_, cmd string) error {
			if cmd == aptUpgrade {
				return errors.New("exit status 100")
			}
			return nil
		})
		done, err, out := applyEdgeSteps(t, false, cfg)
		if err != nil || done != (applied{ownedCaddy: true}) || *owned != 1 {
			t.Errorf("err=%v done=%+v owned installs=%d; want setup to go on to the owned build", err, done, *owned)
		}
		if !strings.Contains(out, "WARNING: apt-get install caddy: exit status 100\n       "+retryHint) {
			t.Errorf("output %q should warn with the apt error and the retry hint", out)
		}
		if got, want := joined(*calls), []string{aptUpdate, aptUpgrade, disable}; !reflect.DeepEqual(got, want) {
			t.Errorf("ran\n %q\nwant\n %q (the disable step must still run)", got, want)
		}
	})

	t.Run("the Caddy repo couldn't be added: the upgrade is skipped, setup goes on", func(t *testing.T) {
		cfg, _, calls, owned := host(t, errors.New("fetch Caddy signing key: dial tcp: i/o timeout"), nil)
		done, err, out := applyEdgeSteps(t, false, cfg)
		if err != nil || done != (applied{ownedCaddy: true}) || *owned != 1 {
			t.Errorf("err=%v done=%+v owned installs=%d", err, done, *owned)
		}
		if !strings.Contains(out, "WARNING: fetch Caddy signing key: dial tcp: i/o timeout\n       "+retryHint) ||
			strings.Count(out, "skipped: an earlier step of the Caddy upgrade failed") != 2 {
			t.Errorf("output %q should warn once and skip apt-get update and the upgrade", out)
		}
		if got, want := joined(*calls), []string{disable}; !reflect.DeepEqual(got, want) {
			t.Errorf("ran %q, want %q", got, want)
		}
	})

	t.Run("apt-get update failed: the upgrade is skipped, setup goes on", func(t *testing.T) {
		cfg, _, calls, owned := host(t, nil, func(_, cmd string) error {
			if cmd == aptUpdate {
				return errors.New("exit status 100")
			}
			return nil
		})
		done, err, out := applyEdgeSteps(t, false, cfg)
		if err != nil || done != (applied{ownedCaddy: true}) || *owned != 1 {
			t.Errorf("err=%v done=%+v owned installs=%d", err, done, *owned)
		}
		if !strings.Contains(out, "WARNING: apt-get update: exit status 100\n       "+retryHint) || strings.Count(out, "skipped: an earlier step of the Caddy upgrade failed") != 1 {
			t.Errorf("output %q should warn and skip the upgrade", out)
		}
		if got, want := joined(*calls), []string{aptUpdate, disable}; !reflect.DeepEqual(got, want) {
			t.Errorf("ran %q, want %q", got, want)
		}
	})

	t.Run("the owned build failed too", func(t *testing.T) {
		cfg, _, _, _ := host(t, nil, nil)
		failed := stubInstallOwnedCaddy(t, stepWarning{errors.New("download: no route to host"), "Mooring retries it at startup."})
		done, err, _ := applyEdgeSteps(t, false, cfg)
		if err != nil || done != (applied{}) || *failed != 1 {
			t.Errorf("err=%v done=%+v attempts=%d; a failed build must not count as installed", err, done, *failed)
		}
	})
}

// A fresh install is not optional: without it there is no Caddy at all, so its failure stops setup.
func TestApplyCaddyInstallFailureStopsSetup(t *testing.T) {
	_, cfg := caddyHost(t)
	stubUnits(t, "caddy.service") // so the disable step would run a command if it were reached
	stubWriteCaddyRepo(t, nil)
	calls := stubRunCmd(t, func(argv []string) error {
		if strings.Join(argv, " ") == aptEnvPrefix+"apt-get install -y caddy" {
			return errors.New("exit status 100")
		}
		return nil
	})
	_, err, _ := applyEdgeSteps(t, false, cfg)
	if err == nil || !strings.Contains(err.Error(), `step "install caddy" failed: exit status 100`) {
		t.Errorf("err = %v, want the install to stop setup", err)
	}
	if got, want := joined(*calls), []string{aptEnvPrefix + "apt-get update", aptEnvPrefix + "apt-get install -y caddy"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ran %q, want %q (nothing after the failed install)", got, want)
	}
}

// needrestart (Ubuntu 24.04) can stop `setup --yes` with a dialog, or restart mooring.service, whose
// Caddy child runs the binary apt replaced: every apt-get command runs non-interactive, needrestart
// listing only. systemctl gets the environment unchanged.
func TestSetupAptCommandsAreNonInteractive(t *testing.T) {
	_, cfg := caddyHost(t) // no caddy, no nginx: both get installed
	stubUnits(t, "caddy.service", "nginx.service")
	stubWriteCaddyRepo(t, nil)
	calls := stubRunCmd(t, nil)
	if _, err, _ := applyEdgeSteps(t, true, cfg); err != nil {
		t.Fatal(err)
	}
	want := []string{
		aptEnvPrefix + "apt-get update",
		aptEnvPrefix + "apt-get install -y caddy",
		"systemctl disable --now caddy",
		aptEnvPrefix + "apt-get install -y nginx libnginx-mod-stream",
		"systemctl disable --now nginx",
	}
	if got := joined(*calls); !reflect.DeepEqual(got, want) {
		t.Errorf("ran\n %q\nwant\n %q", got, want)
	}
}

// runCmd adds env to the inherited environment (an added variable wins over an inherited one) and keeps
// the rest of it.
func TestRunCmdAddsEnv(t *testing.T) {
	t.Setenv("MOORING_TEST_INHERITED", "kept")
	t.Setenv("DEBIAN_FRONTEND", "dialog")
	var err error
	out := captureStdout(t, func() {
		err = runCmd(aptEnv, "/bin/sh", "-c", `printf '%s %s %s' "$MOORING_TEST_INHERITED" "$DEBIAN_FRONTEND" "$NEEDRESTART_MODE"`)
	})
	if err != nil || out != "kept noninteractive l" {
		t.Errorf("err=%v, the child saw %q; want %q", err, out, "kept noninteractive l")
	}
	out = captureStdout(t, func() { err = runCmd(nil, "/bin/sh", "-c", `printf '%s' "$DEBIAN_FRONTEND"`) })
	if err != nil || out != "dialog" {
		t.Errorf("no added env: err=%v, the child saw %q; want the inherited %q", err, out, "dialog")
	}
}

// Caddy is only a Suggests of the package. The distribution's Caddy is too old, and apt installs
// Recommends by default. Dropping it altogether would let `apt autoremove` remove a caddy that an older
// package's Recommends installed as automatic; apt keeps a package that something Suggests.
func TestPackageOnlySuggestsCaddy(t *testing.T) {
	b, err := os.ReadFile("../../.goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Nfpms []struct {
			ID         string   `yaml:"id"`
			Depends    []string `yaml:"depends"`
			Recommends []string `yaml:"recommends"`
			Suggests   []string `yaml:"suggests"`
		} `yaml:"nfpms"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Nfpms) == 0 {
		t.Fatal("no nfpms in .goreleaser.yaml")
	}
	for _, p := range cfg.Nfpms {
		if slices.Contains(p.Depends, "caddy") || slices.Contains(p.Recommends, "caddy") {
			t.Errorf("%s: caddy is in depends %v / recommends %v; apt would install the distribution's old Caddy", p.ID, p.Depends, p.Recommends)
		}
		for _, s := range []string{"caddy", "nginx", "libnginx-mod-stream"} {
			if !slices.Contains(p.Suggests, s) {
				t.Errorf("%s: suggests = %v, want %s in it", p.ID, p.Suggests, s)
			}
		}
	}
}

// The reachability probe dials the build server InstallPluginBuild downloads from.
func TestCaddyBuildServerAddr(t *testing.T) {
	host := strings.TrimSuffix(caddyBuildServerAddr, ":443")
	if !strings.HasPrefix(edge.DefaultBuildServer, "https://"+host+"/") {
		t.Errorf("probe dials %s but builds come from %s", caddyBuildServerAddr, edge.DefaultBuildServer)
	}
}

// A failed Caddy build is a warning (the next steps still run) and is not counted as installed, so
// setup doesn't tell the operator to restart onto a build that isn't there. Any other step error stops
// setup.
func TestApplyStepsWarningIsNotAnInstall(t *testing.T) {
	var ran []string
	mark := func(name string, err error) func() error {
		return func() error { ran = append(ran, name); return err }
	}
	failedBuild := stepWarning{errors.New("download: dial tcp: no route to host"), "Mooring retries it at startup."}
	var out bytes.Buffer
	done, err := applySteps(&out, []step{
		{ownedCaddyStepPrefix + "dns.providers.cloudflare as /x", mark("build", failedBuild)},
		{"enable the mooring service (start on boot)", mark("enable", nil)},
	})
	if err != nil || done != (applied{}) {
		t.Errorf("done=%+v err=%v; want a warning, not an install", done, err)
	}
	if strings.Join(ran, ",") != "build,enable" {
		t.Errorf("ran %v; the step after a warning must still run", ran)
	}
	if !strings.Contains(out.String(), "WARNING: download: dial tcp: no route to host") || !strings.Contains(out.String(), "Mooring retries it at startup.") {
		t.Errorf("output = %q", out.String())
	}

	done, err = applySteps(io.Discard, []step{{ownedCaddyStepPrefix + "dns.providers.cloudflare as /x", mark("build", nil)}})
	if err != nil || done != (applied{ownedCaddy: true}) {
		t.Errorf("a build that installed must count: done=%+v err=%v", done, err)
	}

	// The system caddy package counts as installed or upgraded, not when the upgrade left the old version
	// in place (a warning).
	for desc, want := range map[string]applied{
		descInstallCaddy:  {systemCaddyInstalled: true},
		descUpgradeDistro: {systemCaddyUpgraded: true},
		ownedCaddyIfOldStepPrefix + "/x if the system Caddy is still older than 2.11.0 after the upgrade": {ownedCaddy: true},
	} {
		done, err = applySteps(io.Discard, []step{{desc, mark("apt", nil)}})
		if err != nil || done != want {
			t.Errorf("%q ran: done=%+v err=%v, want %+v", desc, done, err, want)
		}
	}
	keptOld := stepWarning{errors.New("still v2.6.2"), "check `apt-cache policy caddy`"}
	done, err = applySteps(io.Discard, []step{{descUpgradeDistro, mark("apt", keptOld)}})
	if err != nil || done != (applied{}) {
		t.Errorf("an upgrade that kept 2.6.2: done=%+v err=%v, want nothing counted", done, err)
	}

	// A step that finds at run time it has nothing to do prints why, isn't counted, and the next step runs.
	ran = nil
	out.Reset()
	done, err = applySteps(&out, []step{
		{ownedCaddyIfOldStepPrefix + "/x if the system Caddy is still older than 2.11.0 after the upgrade", mark("cond", stepSkipped{"/usr/bin/caddy is v2.11.2 after the upgrade"})},
		{"later", mark("later", nil)},
	})
	if err != nil || done != (applied{}) || strings.Join(ran, ",") != "cond,later" {
		t.Errorf("a skipped step: done=%+v err=%v ran=%v", done, err, ran)
	}
	if !strings.Contains(out.String(), "       skipped: /usr/bin/caddy is v2.11.2 after the upgrade\n") || strings.Contains(out.String(), "WARNING") {
		t.Errorf("a skipped step printed %q", out.String())
	}

	ran = nil
	if _, err := applySteps(io.Discard, []step{{"apt-get update", mark("apt", errors.New("exit 100"))}, {"later", mark("later", nil)}}); err == nil || len(ran) != 1 {
		t.Errorf("a real failure must stop setup: err=%v ran=%v", err, ran)
	}
}

// A config.yaml value Mooring corrected instead of refusing to boot shows up in doctor.
func TestConfigWarnings(t *testing.T) {
	if got := configWarnings(&config.Config{}); len(got) != 0 {
		t.Fatalf("no load warnings → no results, got %+v", got)
	}
	cfg := &config.Config{LoadWarnings: []string{"alerting.quiet_start_hour / quiet_end_hour must be hours from 0 to 23"}}
	got := configWarnings(cfg)
	if len(got) != 1 || got[0].name != "config" || got[0].state != "warn" || !strings.Contains(got[0].detail, "quiet_start_hour") {
		t.Fatalf("want one config warn carrying the warning, got %+v", got)
	}
}

// --- security logs: the adm group, host log access, the archive, the unit's memory cap ---

// siemHost is the host the security-log checks and the adm setup step read.
type siemHost struct {
	groups  map[string]string // groups that exist: name → gid
	account *serviceAccount   // the mooring user; nil: there is none
	unit    map[string]string // `systemctl show mooring` properties; nil: systemctl unavailable
	proc    []string          // the running service's supplementary gids; nil: not running
	logs    hostlog.Config    // what security logs follow
}

func stubSIEMHost(t *testing.T, h siemHost) {
	t.Helper()
	origGroup, origAcct, origShow, origProc, origLogs := lookupGroupGID, lookupServiceAccount, systemctlShow, serviceProcessGroups, resolveHostLogs
	lookupGroupGID = func(name string) (string, bool) { g, ok := h.groups[name]; return g, ok }
	lookupServiceAccount = func() (serviceAccount, bool) {
		if h.account == nil {
			return serviceAccount{}, false
		}
		return *h.account, true
	}
	systemctlShow = func(prop string) (string, bool) {
		if h.unit == nil {
			return "", false
		}
		return h.unit[prop], true
	}
	serviceProcessGroups = func() ([]string, bool) { return h.proc, h.proc != nil }
	resolveHostLogs = func(config.SecurityLogsHost) hostlog.Config { return h.logs }
	t.Cleanup(func() {
		lookupGroupGID, lookupServiceAccount, systemctlShow, serviceProcessGroups, resolveHostLogs = origGroup, origAcct, origShow, origProc, origLogs
	})
}

// siemConfig is a loaded config with security logs at their defaults; set may change it.
func siemConfig(set func(*config.SecurityLogsConfig)) *config.Config {
	cfg := &config.Config{DataDir: "/var/lib/mooring"}
	if set != nil {
		set(&cfg.SecurityLogs)
	}
	return cfg
}

func off() *bool { b := false; return &b }

// resultNamed is the result called name, ok=false when there is none.
func resultNamed(rs []result, name string) (result, bool) {
	for _, r := range rs {
		if r.name == name {
			return r, true
		}
	}
	return result{}, false
}

const admFix = "sudo usermod -aG adm mooring && sudo systemctl restart mooring   (or: sudo mooring setup --yes)"

func TestAdmGroupCheck(t *testing.T) {
	member := &serviceAccount{uid: "998", gid: "998", groups: []string{"998", "999", "4"}}
	outsider := &serviceAccount{uid: "998", gid: "998", groups: []string{"998", "999"}}
	groups := map[string]string{"adm": "4", "docker": "999"}
	cases := []struct {
		name         string
		host         siemHost
		runtime      bool
		state        string
		detail, fix  string
		stepExpected bool
	}{
		{name: "no adm group on the host", host: siemHost{groups: map[string]string{"docker": "999"}, account: outsider},
			state: "skip", detail: "this host has no adm group"},
		{name: "no mooring user", host: siemHost{groups: groups}, state: "skip", detail: "no mooring user"},
		{name: "not in adm", host: siemHost{groups: groups, account: outsider}, runtime: true,
			state: "warn", detail: "the mooring user isn't in the adm group", fix: admFix, stepExpected: true},
		{name: "not in adm, the running service has it from the unit", host: siemHost{groups: groups, account: outsider, proc: []string{"999", "4"}}, runtime: true,
			state: "warn", detail: "the running service has it from a SupplementaryGroups= setting", fix: admFix, stepExpected: true},
		{name: "in adm, the running service started without it", host: siemHost{groups: groups, account: member, proc: []string{"999"}}, runtime: true,
			state: "warn", detail: "the running service started without it", fix: "sudo systemctl restart mooring"},
		{name: "in adm, setup doesn't look at the running service", host: siemHost{groups: groups, account: member, proc: []string{"999"}},
			state: "ok", detail: "the mooring user is in the adm group"},
		{name: "in adm, running with it", host: siemHost{groups: groups, account: member, proc: []string{"999", "4"}}, runtime: true,
			state: "ok", detail: "the mooring user is in the adm group"},
		{name: "in adm, not running", host: siemHost{groups: groups, account: member}, runtime: true,
			state: "ok", detail: "the mooring user is in the adm group"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubSIEMHost(t, c.host)
			got := checkAdmGroup(c.runtime)
			if got.name != "adm group" || got.state != c.state || !strings.Contains(got.detail, c.detail) || got.fix != c.fix {
				t.Errorf("got %+v\nwant state %q, detail containing %q, fix %q", got, c.state, c.detail, c.fix)
			}
			_, planned := admGroupStep(false, siemConfig(nil))
			if planned != c.stepExpected {
				t.Errorf("adm setup step planned=%v, want %v", planned, c.stepExpected)
			}
		})
	}
}

// setup adds mooring to adm with usermod, only when security logs read host logs, the group exists and
// the user isn't in it yet. The step is part of the plan, before enabling the service.
func TestAdmGroupSetupStep(t *testing.T) {
	outsider := &serviceAccount{uid: "998", gid: "998", groups: []string{"998"}}
	stubSIEMHost(t, siemHost{groups: map[string]string{"adm": "4"}, account: outsider})
	stubUnits(t)
	calls := stubRunCmd(t, nil)

	for _, c := range []struct {
		name string
		cfg  *config.Config
		want bool
	}{
		{"defaults", siemConfig(nil), true},
		{"no config.yaml (security logs are on by default)", nil, true},
		{"security logs off", siemConfig(func(s *config.SecurityLogsConfig) { s.Enabled = off() }), false},
		{"host logs off", siemConfig(func(s *config.SecurityLogsConfig) { s.HostLogs.Enabled = off() }), false},
	} {
		s, ok := admGroupStep(false, c.cfg)
		if ok != c.want {
			t.Errorf("%s: planned=%v, want %v", c.name, ok, c.want)
			continue
		}
		if ok && s.desc != admGroupStepDesc {
			t.Errorf("%s: desc %q", c.name, s.desc)
		}
		if got := stepIndex(plan(false, false, false, c.cfg, setupEdgeExternal), admGroupStepDesc) >= 0; got != c.want {
			t.Errorf("%s: in the plan=%v, want %v", c.name, got, c.want)
		}
	}

	s, _ := admGroupStep(false, siemConfig(nil))
	out := captureStdout(t, func() {
		if err := s.do(); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "$ usermod -aG adm mooring") || len(*calls) != 0 {
		t.Errorf("dry run printed %q and ran %v; want the command printed, nothing run", out, *calls)
	}
	s, _ = admGroupStep(true, siemConfig(nil))
	var done applied
	var err error
	captureStdout(t, func() { done, err = applySteps(os.Stdout, []step{s}) })
	if err != nil || !done.admGroupAdded {
		t.Errorf("applied: done=%+v err=%v", done, err)
	}
	if got := joined(*calls); !reflect.DeepEqual(got, []string{"usermod -aG adm mooring"}) {
		t.Errorf("ran %q", got)
	}

	// Planned before `enable the mooring service` and the --restart step.
	stubSIEMHost(t, siemHost{groups: map[string]string{"adm": "4"}, account: outsider, unit: map[string]string{"UnitFileState": "disabled"}})
	steps := plan(false, false, true, siemConfig(nil), setupEdgeExternal)
	adm, enable, restart := stepIndex(steps, admGroupStepDesc), stepIndex(steps, "enable the mooring service (start on boot)"), stepIndex(steps, "restart the mooring service")
	if adm < 0 || enable < 0 || restart < 0 || adm > enable || adm > restart {
		t.Errorf("order: adm %d, enable %d, restart %d", adm, enable, restart)
	}
}

func TestAdmRestartHint(t *testing.T) {
	const msg = "Restart Mooring so the service gets the adm group: sudo systemctl restart mooring"
	for _, c := range []struct {
		name            string
		done            applied
		restart, active bool
		want            string
	}{
		{"added while running", applied{admGroupAdded: true}, false, true, msg},
		{"added, --restart restarts it", applied{admGroupAdded: true}, true, true, ""},
		{"added, not running", applied{admGroupAdded: true}, false, false, ""},
		{"nothing added", applied{ownedCaddy: true}, false, true, ""},
	} {
		if got := admRestartHint(c.done, c.restart, c.active); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// With security logs off, doctor has no security-log line and setup no adm step. With host logs off,
// only the archive and memory lines remain.
func TestSecurityLogChecksOff(t *testing.T) {
	stubSIEMHost(t, siemHost{groups: map[string]string{"adm": "4"}, account: &serviceAccount{uid: "998", gid: "998", groups: []string{"998"}},
		unit: map[string]string{"MemoryMax": "402653184"}})
	cfg := siemConfig(func(s *config.SecurityLogsConfig) { s.Enabled = off() })
	if got := securityLogChecks(cfg, true); len(got) != 0 {
		t.Errorf("security logs off: %+v, want no checks", got)
	}
	if stepIndex(plan(false, false, false, cfg, setupEdgeExternal), admGroupStepDesc) >= 0 {
		t.Error("security logs off: the adm step is planned")
	}
	var names []string
	for _, r := range securityLogChecks(siemConfig(func(s *config.SecurityLogsConfig) { s.HostLogs.Enabled = off() }), true) {
		names = append(names, r.name)
	}
	if want := []string{"security archive", "memory max"}; !reflect.DeepEqual(names, want) {
		t.Errorf("host logs off: checks %q, want %q", names, want)
	}
}

// Every line on a default host, in order; config.yaml unreadable keeps the host checks but has no
// archive line (whether one is set isn't known).
func TestSecurityLogChecksOrder(t *testing.T) {
	dir := t.TempDir()
	auth := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(auth, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	stubSIEMHost(t, siemHost{groups: map[string]string{"adm": "4"}, account: &serviceAccount{uid: "998", gid: "998", groups: []string{"998", "4"}},
		unit: map[string]string{"MemoryMax": "1073741824"}, logs: hostlog.Config{AuthLog: auth, Fail2BanLog: filepath.Join(dir, "fail2ban.log")}})
	names := func(rs []result) []string {
		var out []string
		for _, r := range rs {
			out = append(out, r.name)
		}
		return out
	}
	if got, want := names(securityLogChecks(siemConfig(nil), true)), []string{"adm group", "auth log", "fail2ban log", "security archive", "memory max"}; !reflect.DeepEqual(got, want) {
		t.Errorf("checks %q, want %q", got, want)
	}
	if got, want := names(securityLogChecks(nil, true)), []string{"adm group", "auth log", "fail2ban log", "memory max"}; !reflect.DeepEqual(got, want) {
		t.Errorf("no config: checks %q, want %q", got, want)
	}
}

func TestMemoryMaxResult(t *testing.T) {
	for _, c := range []struct {
		value  string
		ok     bool
		state  string
		detail string
	}{
		{"402653184", true, "warn", "the unit's MemoryMax is 384M; the shipped unit sets 1G"},
		{"536870912", true, "warn", "MemoryMax is 512M"},
		{"1073741823", true, "warn", "MemoryMax is 1073741823 bytes"},
		{"1073741824", true, "ok", "MemoryMax is 1G"},
		{"2147483648", true, "ok", "MemoryMax is 2G"},
		{"infinity", true, "ok", "the unit sets no MemoryMax"},
		{"", true, "warn", "could not read the unit's MemoryMax"},
		{"lots", true, "warn", "could not read the unit's MemoryMax"},
		{"", false, "warn", "could not read the unit's MemoryMax"},
	} {
		got := memoryMaxResult(c.value, c.ok)
		if got.name != "memory max" || got.state != c.state || !strings.Contains(got.detail, c.detail) {
			t.Errorf("%q ok=%v: %+v, want %s containing %q", c.value, c.ok, got, c.state, c.detail)
		}
		if c.state == "warn" && c.ok && c.value != "" && c.value != "lots" && !strings.Contains(got.fix, "sudo systemctl daemon-reload && sudo systemctl restart mooring") {
			t.Errorf("%q: fix %q", c.value, got.fix)
		}
	}
}

// The doctor's MemoryMax floor is what the shipped unit sets, GOMEMLIMIT is under it, and the unit adds
// only the docker group: a SupplementaryGroups= group the host lacks stops the unit from starting, so
// adm comes from postinstall's group membership.
func TestShippedUnitMatchesDoctor(t *testing.T) {
	b, err := os.ReadFile("../../deploy/systemd/mooring.service")
	if err != nil {
		t.Fatal(err)
	}
	props := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok && !strings.HasPrefix(l, "#") {
			if k == "Environment" {
				if ek, ev, ok := strings.Cut(v, "="); ok {
					k, v = ek, ev
				}
			}
			props[k] = v
		}
	}
	size := func(s string) uint64 {
		mult := map[string]uint64{"K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30}
		for _, suf := range []string{"KiB", "MiB", "GiB", "K", "M", "G"} {
			if n, ok := strings.CutSuffix(s, suf); ok {
				v, err := strconv.ParseUint(n, 10, 64)
				if err != nil {
					t.Fatalf("size %q: %v", s, err)
				}
				return v * mult[suf]
			}
		}
		t.Fatalf("size %q has no unit", s)
		return 0
	}
	memMax, goLimit := size(props["MemoryMax"]), size(props["GOMEMLIMIT"])
	if memMax != minServiceMemoryMax || memoryMaxResult(strconv.FormatUint(memMax, 10), true).state != "ok" {
		t.Errorf("unit MemoryMax %d, doctor floor %d", memMax, uint64(minServiceMemoryMax))
	}
	if goLimit == 0 || goLimit >= memMax {
		t.Errorf("GOMEMLIMIT %d must be under MemoryMax %d", goLimit, memMax)
	}
	if got := strings.Fields(props["SupplementaryGroups"]); !reflect.DeepEqual(got, []string{"docker"}) {
		t.Errorf("SupplementaryGroups %q, want only docker", got)
	}
}

// postinstall adds mooring to adm once: when the group exists and the marker doesn't, before the
// service is reloaded; then it writes the marker (0600), so an upgrade never re-adds a membership the
// operator removed. A user already in adm only gets the marker; a failed usermod leaves none. Every
// command that changes the host is stood in for, and the marker is moved into a temp dir.
func TestPostinstallAddsAdmOnce(t *testing.T) {
	const markerPath = "/etc/mooring/.adm-group-added"
	script, err := os.ReadFile("../../deploy/nfpm/postinstall.sh")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(script), markerPath); n != 1 {
		t.Fatalf("postinstall names %s %d times, want once (ADM_MARKER)", markerPath, n)
	}
	cases := []struct {
		name                        string
		admGroup, member, markerSet bool
		usermodFails                bool
		wantUsermod, wantMarker     bool
	}{
		{name: "first install: added, marker written", admGroup: true, wantUsermod: true, wantMarker: true},
		{name: "marker present (the operator removed it later): not re-added", admGroup: true, markerSet: true, wantMarker: true},
		{name: "already in adm: marker only", admGroup: true, member: true, wantMarker: true},
		{name: "no adm group: nothing", admGroup: false},
		{name: "usermod failed: no marker, the next upgrade tries again", admGroup: true, usermodFails: true, wantUsermod: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Not t.TempDir(): its path holds the subtest name, which the shell would read as syntax.
			dir, err := os.MkdirTemp("", "postinstall")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			logf, marker := filepath.Join(dir, "calls"), filepath.Join(dir, "adm-marker")
			if c.markerSet {
				if err := os.WriteFile(marker, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			copyPath := filepath.Join(dir, "postinstall.sh")
			if err := os.WriteFile(copyPath, []byte(strings.Replace(string(script), markerPath, marker, 1)), 0o700); err != nil {
				t.Fatal(err)
			}
			stub := "#!/bin/sh\necho \"$(basename \"$0\") $*\" >> " + logf + "\n"
			for name, body := range map[string]string{
				"groupadd": stub, "useradd": stub, "install": stub, "systemctl": stub,
				"usermod": stub + "[ \"$2\" = adm ] && [ \"$MOORING_TEST_USERMOD_FAIL\" = yes ] && exit 1\nexit 0\n",
				"getent":  stub + "[ \"$1 $2\" = \"group adm\" ] && [ \"$MOORING_TEST_ADM\" != yes ] && exit 2\nexit 0\n",
				"id":      stub + "if [ \"$MOORING_TEST_MEMBER\" = yes ]; then echo mooring docker adm; else echo mooring docker; fi\n",
			} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			yes := map[bool]string{true: "yes", false: "no"}
			cmd := exec.Command("/bin/sh", copyPath)
			cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "MOORING_TEST_ADM=" + yes[c.admGroup],
				"MOORING_TEST_MEMBER=" + yes[c.member], "MOORING_TEST_USERMOD_FAIL=" + yes[c.usermodFails]}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("postinstall failed: %v\n%s", err, out)
			}
			b, err := os.ReadFile(logf)
			if err != nil {
				t.Fatal(err)
			}
			calls := strings.Split(strings.TrimSpace(string(b)), "\n")
			usermod, reload := slices.Index(calls, "usermod -aG adm mooring"), slices.Index(calls, "systemctl daemon-reload")
			if (usermod >= 0) != c.wantUsermod || (usermod >= 0 && usermod > reload) {
				t.Errorf("calls %q: usermod -aG adm mooring at %d (want it=%v, before daemon-reload at %d)", calls, usermod, c.wantUsermod, reload)
			}
			if !slices.Contains(calls, "usermod -aG docker mooring") {
				t.Errorf("calls %q: the docker group is no longer added", calls)
			}
			fi, err := os.Stat(marker)
			if (err == nil) != c.wantMarker {
				t.Fatalf("marker exists=%v, want %v", err == nil, c.wantMarker)
			}
			if err == nil && !c.markerSet && fi.Mode().Perm() != 0o600 {
				t.Errorf("marker mode %o, want 600", fi.Mode().Perm())
			}
		})
	}
}

// hostLogFile writes a file with perm in a temp dir and returns its path and group id.
func hostLogFile(t *testing.T, dir, name string, perm os.FileMode) (string, string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, perm); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, strconv.FormatUint(uint64(fi.Sys().(*syscall.Stat_t).Gid), 10)
}

// The file checks go by the file's owner, group and mode against the user and the groups the service
// gets: its own, the group database's, and the unit's SupplementaryGroups.
func TestHostLogFileChecks(t *testing.T) {
	dir := t.TempDir()
	me := strconv.Itoa(os.Getuid())
	groupRead, fileGID := hostLogFile(t, dir, "auth.log", 0o640)
	private, _ := hostLogFile(t, dir, "secure", 0o600)
	world, _ := hostLogFile(t, dir, "world.log", 0o644)
	ownerOnly, _ := hostLogFile(t, dir, "owner.log", 0o400)
	missing := filepath.Join(dir, "none.log")
	other := func(groups ...string) *serviceAccount {
		return &serviceAccount{uid: "424242", gid: "424242", groups: append([]string{"424242"}, groups...)}
	}

	cases := []struct {
		name         string
		account      *serviceAccount
		unitGroups   string
		groups       map[string]string
		logs         hostlog.Config
		check, state string
		detail, fix  string
	}{
		{name: "group-readable, the user is in its group", account: other(fileGID), logs: hostlog.Config{AuthLog: groupRead},
			check: "auth log", state: "ok", detail: "security logs read " + groupRead},
		{name: "group-readable through the unit's SupplementaryGroups", account: other(), unitGroups: "docker loggrp", groups: map[string]string{"loggrp": fileGID, "docker": "999"},
			logs: hostlog.Config{AuthLog: groupRead}, check: "auth log", state: "ok", detail: "through the "},
		{name: "group-readable, not in its group", account: other(), groups: map[string]string{"adm": "4"}, logs: hostlog.Config{AuthLog: groupRead},
			check: "auth log", state: "warn", detail: "the mooring service can't read " + groupRead, fix: "sudo chgrp adm " + groupRead},
		{name: "group-readable, not in its group, no adm group", account: other(), logs: hostlog.Config{AuthLog: groupRead},
			check: "auth log", state: "warn", detail: "the mooring service can't read " + groupRead, fix: "readable by one of the mooring service's groups"},
		{name: "group-readable by adm, not in adm", account: other(), groups: map[string]string{"adm": fileGID}, logs: hostlog.Config{AuthLog: groupRead},
			check: "auth log", state: "warn", detail: "the mooring service can't read", fix: admFix},
		{name: "owner-only (RHEL's /var/log/secure)", account: other(fileGID), logs: hostlog.Config{AuthLog: private},
			check: "auth log", state: "warn", detail: "the mooring service can't read " + private, fix: "security_logs.host_logs.journal: true"},
		{name: "world-readable", account: other(), logs: hostlog.Config{AuthLog: world}, check: "auth log", state: "ok", detail: "security logs read " + world},
		{name: "the service user owns it", account: &serviceAccount{uid: me, gid: "424242", groups: []string{"424242"}}, logs: hostlog.Config{AuthLog: ownerOnly},
			check: "auth log", state: "ok", detail: "through its owner"},
		{name: "owner bits apply to the owner, not the group's", account: &serviceAccount{uid: me, gid: fileGID, groups: []string{fileGID}}, logs: hostlog.Config{AuthLog: hostLogPerm(t, dir, "noowner.log", 0o040)},
			check: "auth log", state: "warn", detail: "can't read"},
		{name: "auth log missing", account: other(), logs: hostlog.Config{AuthLog: missing}, check: "auth log", state: "warn", detail: missing + " doesn't exist"},
		{name: "no auth log and no journal", account: other(), logs: hostlog.Config{}, check: "auth log", state: "warn", detail: "no sshd/sudo/su events"},
		{name: "fail2ban log missing", account: other(), logs: hostlog.Config{AuthLog: world, Fail2BanLog: missing}, check: "fail2ban log", state: "skip", detail: missing + " isn't there"},
		{name: "fail2ban log readable", account: other(fileGID), logs: hostlog.Config{AuthLog: world, Fail2BanLog: groupRead}, check: "fail2ban log", state: "ok", detail: groupRead},
		{name: "fail2ban log unreadable", account: other(), logs: hostlog.Config{AuthLog: world, Fail2BanLog: private}, check: "fail2ban log", state: "warn", detail: "can't read " + private},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubSIEMHost(t, siemHost{groups: c.groups, account: c.account, unit: map[string]string{"SupplementaryGroups": c.unitGroups}, logs: c.logs})
			got, ok := resultNamed(checkHostLogs(siemConfig(nil)), c.check)
			if !ok || got.state != c.state || !strings.Contains(got.detail, c.detail) || !strings.Contains(got.fix, c.fix) {
				t.Errorf("got %+v (found %v)\nwant %s, detail containing %q, fix containing %q", got, ok, c.state, c.detail, c.fix)
			}
		})
	}
}

// hostLogPerm writes a file with perm and returns its path.
func hostLogPerm(t *testing.T, dir, name string, perm os.FileMode) string {
	p, _ := hostLogFile(t, dir, name, perm)
	return p
}

// The journal is readable to members of systemd-journal (its files' group) and of adm and wheel (systemd's
// read ACLs on it).
func TestJournalCheck(t *testing.T) {
	jdir := t.TempDir()
	orig := journalDirs
	t.Cleanup(func() { journalDirs = orig })
	groups := map[string]string{"adm": "4", "systemd-journal": "101", "wheel": "10"}
	cases := []struct {
		name   string
		dirs   []string
		member []string
		state  string
		detail string
	}{
		{"in adm", []string{jdir}, []string{"4"}, "ok", "through the adm group"},
		{"in systemd-journal", []string{jdir}, []string{"101"}, "ok", "through the systemd-journal group"},
		{"in wheel", []string{jdir}, []string{"10"}, "ok", "through the wheel group"},
		{"in none of them", []string{jdir}, nil, "warn", "isn't in the adm or systemd-journal group"},
		{"no journal on the host", []string{filepath.Join(jdir, "nope")}, []string{"4"}, "warn", "no systemd journal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			journalDirs = c.dirs
			stubSIEMHost(t, siemHost{groups: groups, account: &serviceAccount{uid: "998", gid: "998", groups: append([]string{"998"}, c.member...)},
				unit: map[string]string{}, logs: hostlog.Config{Journal: true}})
			rs := checkHostLogs(siemConfig(nil))
			got, ok := resultNamed(rs, "journal")
			if !ok || got.state != c.state || !strings.Contains(got.detail, c.detail) {
				t.Errorf("got %+v (found %v), want %s containing %q", got, ok, c.state, c.detail)
			}
			if _, ok := resultNamed(rs, "auth log"); ok {
				t.Errorf("an auth log line without an auth log: %+v", rs)
			}
			if c.state == "warn" && got.fix == "" {
				t.Error("a journal warning has no fix")
			}
		})
	}
}

func TestSecurityArchiveCheck(t *testing.T) {
	got := checkSecurityArchive(siemConfig(nil))
	if got.name != "security archive" || got.state != "warn" ||
		got.detail != "security_logs.archive.s3 isn't set — security logs are kept only on this host (14 days)" || !strings.Contains(got.fix, "security_logs.archive.s3") {
		t.Errorf("no archive: %+v", got)
	}
	got = checkSecurityArchive(siemConfig(func(s *config.SecurityLogsConfig) { s.HotRetention = config.Duration(36 * time.Hour) }))
	if !strings.Contains(got.detail, "(36h)") {
		t.Errorf("36h: %+v", got)
	}
	got = checkSecurityArchive(siemConfig(func(s *config.SecurityLogsConfig) {
		s.Archive.S3 = &config.BackupS3{Bucket: "sec", Endpoint: "s3.eu-west-1.amazonaws.com", Region: "eu-west-1", Prefix: "mooring/", AccessKeyID: "AKIA", SecretAccessKey: "s3cr3t"}
	}))
	if got.state != "ok" || got.detail != "security logs are archived to s3.eu-west-1.amazonaws.com/sec/mooring/ and kept 365 days there" {
		t.Errorf("archive: %+v", got)
	}
	if strings.Contains(got.detail+got.fix, "s3cr3t") || strings.Contains(got.detail+got.fix, "AKIA") {
		t.Errorf("the archive line shows a credential: %+v", got)
	}
}

// The load warning about no archive is doctor's security archive line, not a second config line.
func TestConfigWarningsLeaveTheArchiveToItsCheck(t *testing.T) {
	cfg := &config.Config{LoadWarnings: []string{
		config.WarnSecurityLogsNoArchive + " — security logs are kept only on this host (14 days)",
		"security_logs.hot_max_disk_mb 100 is below the minimum 256; using 256",
	}}
	got := configWarnings(cfg)
	if len(got) != 1 || !strings.Contains(got[0].detail, "hot_max_disk_mb") {
		t.Errorf("config lines %+v, want only the hot_max_disk_mb warning", got)
	}
}

func TestParseStatusGroups(t *testing.T) {
	for in, want := range map[string][]string{
		"Name:\tmooring\nUid:\t998\t998\t998\t998\nGroups:\t4 999 \nNSpid:\t1\n": {"4", "999"},
		"Groups:\t\n":            nil,
		"Uid:\t1\n":              nil,
		"Groups:\t4 x 999\n":     {"4", "999"},
		"Groups:\t4\nGroups:\t5": {"4"},
	} {
		if got := parseStatusGroups(in); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// The running service's groups are read from its MainPID's /proc status: a group the user joined after
// the service started isn't there. MainPID 0 (stopped) or unreadable is "not running".
func TestServiceProcessGroupsReadsProc(t *testing.T) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		t.Skip("no /proc")
	}
	orig := systemctlShow
	t.Cleanup(func() { systemctlShow = orig })
	pid := strconv.Itoa(os.Getpid())
	systemctlShow = func(prop string) (string, bool) { return map[string]string{"MainPID": pid}[prop], true }
	got, ok := serviceProcessGroups()
	gids, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, g := range gids {
		want = append(want, strconv.Itoa(g))
	}
	slices.Sort(got)
	slices.Sort(want)
	if !ok || !slices.Equal(got, want) {
		t.Errorf("groups %q ok=%v, want this process's %q", got, ok, want)
	}
	for _, v := range []string{"0", "", "x", "-3"} {
		systemctlShow = func(string) (string, bool) { return v, true }
		if _, ok := serviceProcessGroups(); ok {
			t.Errorf("MainPID %q: reported running", v)
		}
	}
}
