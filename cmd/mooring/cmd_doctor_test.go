package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/docker"
	"github.com/daboss2003/mooring/internal/edge"
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
			if !strings.Contains(r.detail, "2.6.2") || !strings.Contains(r.detail, filepath.Join(dir, "caddy")) || !strings.Contains(r.fix, edge.OwnedCaddyPath(cfg.DataDir)) {
				t.Errorf("%s: %+v must name the version, the path and the owned build in the fix", c.name, r)
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
		if _, i := ownedStep(plan(false, false, false, cfg)); i >= 0 {
			t.Error("the caddy the edge runs has the modules: no owned build expected")
		}
	})

	t.Run("dns01 module missing from the caddy the edge runs", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "v2.11.2 h1:x", "dns.providers.route53")
		withDNS01(cfg, "cloudflare", "route53")
		steps := plan(false, false, false, cfg)
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
		if _, i := ownedStep(plan(false, false, false, cfg)); i >= 0 {
			t.Error("owned build has the module and a current version: no step expected")
		}
	})

	t.Run("no caddy at all: apt first, then the plugin build", func(t *testing.T) {
		_, cfg := caddyHost(t)
		withDNS01(cfg, "cloudflare")
		steps := plan(false, false, false, cfg)
		apt := stepIndex(steps, "install caddy")
		_, i := ownedStep(steps)
		if apt < 0 || i < 0 || i != apt+1 {
			t.Errorf("want the owned-build step right after the apt install, got apt=%d owned=%d", apt, i)
		}
	})

	t.Run("old caddy and a setting that needs 2.11", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "2.6.2")
		cfg.Edge.TrustedProxies = []string{"cloudflare"}
		s, i := ownedStep(plan(false, false, false, cfg))
		if i < 0 || !strings.HasPrefix(s.desc, ownedCaddyStepPrefix+"no plugins as ") {
			t.Errorf("2.6.2 + trusted_proxies: want a plain owned build, got %q", s.desc)
		}
	})

	t.Run("old caddy, nothing needs 2.11", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "2.6.2")
		if _, i := ownedStep(plan(false, false, false, cfg)); i >= 0 {
			t.Error("the distro caddy is enough here: no owned build expected")
		}
	})

	t.Run("no dns01 and a current caddy", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "v2.11.2 h1:x")
		steps := plan(false, false, false, cfg)
		if _, i := ownedStep(steps); i >= 0 || stepIndex(steps, "install caddy") >= 0 {
			t.Errorf("nothing caddy-related to do, got %v", steps)
		}
	})

	t.Run("external edge mode never plans a plugin build", func(t *testing.T) {
		dir, cfg := caddyHost(t)
		fakeCaddy(t, filepath.Join(dir, "caddy"), "v2.11.2 h1:x")
		cfg.Edge.Mode = config.EdgeExternal
		withDNS01(cfg, "cloudflare")
		if _, i := ownedStep(plan(false, false, false, cfg)); i >= 0 {
			t.Error("Mooring runs no Caddy in external mode: no plugin build expected")
		}
	})
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
	swapped, err := applySteps(&out, []step{
		{ownedCaddyStepPrefix + "dns.providers.cloudflare as /x", mark("build", failedBuild)},
		{"enable the mooring service (start on boot)", mark("enable", nil)},
	})
	if err != nil || swapped {
		t.Errorf("swapped=%v err=%v; want a warning, not an install", swapped, err)
	}
	if strings.Join(ran, ",") != "build,enable" {
		t.Errorf("ran %v; the step after a warning must still run", ran)
	}
	if !strings.Contains(out.String(), "WARNING: download: dial tcp: no route to host") || !strings.Contains(out.String(), "Mooring retries it at startup.") {
		t.Errorf("output = %q", out.String())
	}

	swapped, err = applySteps(io.Discard, []step{{ownedCaddyStepPrefix + "dns.providers.cloudflare as /x", mark("build", nil)}})
	if err != nil || !swapped {
		t.Errorf("a build that installed must count: swapped=%v err=%v", swapped, err)
	}

	ran = nil
	if _, err := applySteps(io.Discard, []step{{"apt-get update", mark("apt", errors.New("exit 100"))}, {"later", mark("later", nil)}}); err == nil || len(ran) != 1 {
		t.Errorf("a real failure must stop setup: err=%v ran=%v", err, ran)
	}
}
