package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/docker"
)

// cmd_doctor.go is the host-prerequisites helper. Mooring's RUNTIME service is
// deliberately unprivileged — it can't install packages, edit host DNS, or grant
// capabilities (that's the security model: a compromised dashboard must not be able
// to either). So prerequisites are an explicit, admin-run, root, install-time job —
// which this makes one command instead of a scavenger hunt:
//
//	mooring doctor   — read-only: report what's missing + the exact fix (any user).
//	mooring setup    — print a fix PLAN (dry run); `--yes` applies it (root, apt).
//
// `setup` only performs SAFE, idempotent, well-understood mutations (install Caddy /
// nginx+stream, cap Docker's logs). It NEVER auto-rewrites host DNS or frees :53 —
// that broke a box once already — it prints those steps for you to run. The bind
// capability + runtime/state dirs are provided by the unit + postinstall, not setup.
const (
	caddyKeyURL   = "https://dl.cloudsmith.io/public/caddy/stable/gpg.key"
	caddyKeyPath  = "/usr/share/keyrings/caddy-stable-archive-keyring.asc"
	caddyListPath = "/etc/apt/sources.list.d/caddy-stable.list"
	caddySources  = "deb [signed-by=" + caddyKeyPath + "] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main\n"
	// Legacy drop-in path: the base unit now grants CAP_NET_BIND_SERVICE by default, so
	// setup no longer installs this. checkCapsActive still reads it as a fallback signal.
	capsDst = "/etc/systemd/system/mooring.service.d/mooring-privileged-ports.conf"
)

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	l4 := fs.Bool("l4", false, "also check the L4 (nginx stream) prerequisites")
	configPath := fs.String("config", config.DefaultPath, "config.yaml to drive the runtime checks")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		fmt.Println("mooring doctor: host checks run on Linux only.")
		return nil
	}
	cfg, cfgWarn := loadDoctorConfig(*configPath)
	rep := preflight(*l4, cfg, true)
	if cfgWarn != "" {
		rep.add(result{"config", "warn", cfgWarn, "pass --config, or run where /etc/mooring/config.yaml is readable (runtime checks fall back to defaults)"})
	}
	rep.print(os.Stdout)
	if rep.hasFail() {
		fmt.Println("\nRun `sudo mooring setup` to review a fix plan, then `sudo mooring setup --yes` to apply it.")
	} else {
		fmt.Println("\nRequired prerequisites are present.")
	}
	printGuidance(rep, *l4)
	return nil
}

// loadDoctorConfig best-effort loads the config for the runtime checks. A failure is
// non-fatal: the checks fall back to documented defaults and the caller surfaces a warn.
func loadDoctorConfig(path string) (*config.Config, string) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, "could not load " + path + " (" + err.Error() + ")"
	}
	return cfg, ""
}

func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "apply the changes (default: print the plan only)")
	l4 := fs.Bool("l4", false, "also install the L4 prerequisites (nginx + stream module)")
	restart := fs.Bool("restart", false, "restart the mooring service after applying")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("setup runs on Linux only")
	}
	if !have("apt-get") {
		fmt.Println("mooring setup auto-installs via apt (Debian/Ubuntu). On other distros, install")
		fmt.Println("Caddy (and nginx + the stream module for L4) per docs/installation.md, then `mooring doctor`.")
		return nil
	}
	if *yes && os.Geteuid() != 0 {
		return fmt.Errorf("applying changes needs root — run: sudo mooring setup --yes")
	}

	// setup runs at onboarding (before config/service start), so skip the runtime-state
	// checks (run dir / egress / socket-proxy / daemon match) — they need a running service.
	rep := preflight(*l4, nil, false)
	rep.print(os.Stdout)

	steps := plan(*yes, *l4, *restart)
	if len(steps) == 0 {
		fmt.Println("\nNothing to install — all prerequisites are already in place.")
		printDNSGuidance(*l4)
		return nil
	}
	fmt.Printf("\nPlan — %d step(s):\n", len(steps))
	for i, s := range steps {
		fmt.Printf("  %d. %s\n", i+1, s.desc)
	}
	if !*yes {
		fmt.Println("\nThis was a DRY RUN — nothing changed. Re-run as `sudo mooring setup --yes` to apply.")
		printDNSGuidance(*l4)
		return nil
	}
	fmt.Println("\nApplying:")
	for i, s := range steps {
		fmt.Printf("\n  %d. %s\n", i+1, s.desc)
		if err := s.do(); err != nil {
			return fmt.Errorf("step %q failed: %w", s.desc, err)
		}
	}
	fmt.Println("\nDone.")
	printDNSGuidance(*l4)
	return nil
}

// step is one planned host mutation; do() prints the action and (when apply) runs it.
type step struct {
	desc string
	do   func() error
}

// plan builds the ordered fix steps for whatever is missing. apply=false makes each
// do() print-only, so the SAME list drives the dry run and the real run.
func plan(apply, l4, restart bool) []step {
	var steps []step
	if !have("caddy") {
		steps = append(steps,
			step{"add the Caddy apt repo + signing key", func() error { return writeCaddyRepo(apply) }},
			step{"apt-get update", func() error { return run(apply, "apt-get", "update") }},
			step{"install caddy", func() error { return run(apply, "apt-get", "install", "-y", "caddy") }},
		)
	}
	// ALWAYS disable the packaged caddy.service when it exists — Mooring supervises its
	// OWN Caddy child; the distro unit squats :80/:443 and crash-loops the edge. This is
	// NOT gated on a fresh install (that was the bug: a host where caddy was already
	// present skipped the disable). Idempotent; skipped when the unit isn't installed.
	if unitExists("caddy.service") {
		steps = append(steps, step{"disable the distro caddy.service (Mooring supervises its own child)",
			func() error { return run(apply, "systemctl", "disable", "--now", "caddy") }})
	}
	if l4 && !have("nginx") {
		steps = append(steps,
			step{"install nginx + the stream module", func() error { return run(apply, "apt-get", "install", "-y", "nginx", "libnginx-mod-stream") }},
		)
	}
	if l4 && unitExists("nginx.service") {
		steps = append(steps, step{"disable the distro nginx.service (Mooring supervises its own child)",
			func() error { return run(apply, "systemctl", "disable", "--now", "nginx") }})
	}
	// CAP_NET_BIND_SERVICE is granted by the base unit now (no drop-in step needed).
	if dockerLogsNeedCap() {
		steps = append(steps,
			step{"cap Docker container logs (json-file max-size=10m) in /etc/docker/daemon.json", func() error { return applyDockerLogCap(apply) }},
			step{"restart docker to apply the log cap — BOUNCES running containers (run setup before deploying apps)", func() error { return run(apply, "systemctl", "restart", "docker") }},
		)
	}
	// Enable the mooring service so it survives a reboot. The package intentionally does NOT
	// auto-enable on install (it can't boot without a config yet), so an operator who only ran
	// `systemctl start` silently loses Mooring on the next reboot. ALLOWLIST the states where
	// `systemctl enable` both applies and can succeed: `disabled` (the trap) and the runtime-only
	// enablements (make them persistent). NEVER masked/static/generated — `enable` fails there and
	// would abort the whole setup run; masking is a deliberate operator choice we don't undo.
	if st, ok := systemctlShow("UnitFileState"); ok && (st == "disabled" || st == "enabled-runtime" || st == "linked-runtime") {
		steps = append(steps, step{"enable the mooring service (start on boot)",
			func() error { return run(apply, "systemctl", "enable", "mooring") }})
	}
	if restart {
		steps = append(steps, step{"restart the mooring service", func() error { return run(apply, "systemctl", "restart", "mooring") }})
	}
	return steps
}

// --- checks ---

type result struct{ name, state, detail, fix string }

type report struct{ results []result }

func (r *report) add(x result) { r.results = append(r.results, x) }
func (r report) hasFail() bool {
	for _, x := range r.results {
		if x.state == "fail" {
			return true
		}
	}
	return false
}

func (r report) state(name string) string {
	for _, x := range r.results {
		if x.name == name {
			return x.state
		}
	}
	return ""
}

// printGuidance prints the copy-paste steps for the host changes Mooring won't make
// automatically (they're global/disruptive): Docker log rotation when uncapped, and
// freeing :53 from systemd-resolved when L4 is in play.
func printGuidance(rep report, l4 bool) {
	if rep.state("docker logs") == "warn" {
		printDockerLogGuidance()
	}
	printDNSGuidance(l4) // no-op unless l4
}

func (r report) print(w io.Writer) {
	icon := map[string]string{"ok": "✓", "warn": "!", "fail": "✗", "skip": "-"}
	for _, x := range r.results {
		fmt.Fprintf(w, "  %s %-16s %s\n", icon[x.state], x.name, x.detail)
		if x.state != "ok" && x.fix != "" {
			fmt.Fprintf(w, "      → %s\n", x.fix)
		}
	}
}

// preflight runs the checks. cfg may be nil (config not loaded → defaults used).
// runtimeChecks adds the checks that need a configured + running service (run dir,
// egress, socket-proxy, daemon match); setup skips them since it runs before the
// service starts.
func preflight(l4 bool, cfg *config.Config, runtimeChecks bool) report {
	managed := cfg == nil || cfg.Edge.Mode == config.EdgeManaged // default mode is managed
	var r report
	r.add(checkBinary("caddy", "managed HTTPS edge (:80/:443 + ACME)", "sudo mooring setup --yes"))
	if managed {
		r.add(checkDistroService("caddy", ":80/:443 (edge)"))
	}
	r.add(checkBinary("docker", "container read/write plane", "install Docker + the compose plugin"))
	r.add(checkDockerDaemons())
	r.add(checkDockerInstalls())
	r.add(checkDockerLogRotation())
	r.add(checkDNS())
	r.add(checkCapsActive(managed || l4))
	r.add(checkStateDirs(cfg, managed))
	if cfg != nil {
		r.add(checkTOTP(cfg))
	}
	if l4 {
		r.add(checkBinary("nginx", "L4 (TCP/UDP) load balancer", "sudo mooring setup --l4 --yes"))
		r.add(checkDistroService("nginx", ":53/:853 + :80 (L4)"))
		r.add(checkStreamModule())
		r.add(checkResolvedStub())
	}
	if runtimeChecks {
		r.add(checkServiceEnabled()) // will it survive a reboot? (setup skips this — it does the enabling)
		if managed {
			r.add(checkRunDir(cfg))
			r.add(checkEgress())
		}
		r.add(checkDeployEnv())
		r.add(checkSocketProxy(cfg))
		r.add(checkDaemonMatch(cfg))
	}
	return r
}

// --- doctor helpers: resolve cfg-or-default + read the live unit (all read-only) ---

func doctorDataDir(cfg *config.Config) string {
	if cfg != nil && cfg.DataDir != "" {
		return cfg.DataDir
	}
	return "/var/lib/mooring"
}

func doctorAdminListen(cfg *config.Config) string {
	if cfg != nil {
		return edgeAdminListen(cfg)
	}
	return "unix//run/mooring/caddy-admin.sock"
}

func doctorProxyAddr(cfg *config.Config) string {
	if cfg != nil && cfg.Docker.ProxyAddr != "" {
		return cfg.Docker.ProxyAddr
	}
	return "127.0.0.1:2375"
}

// systemctlShow reads one property of the live mooring unit. ok=false when systemctl
// is unavailable (so callers degrade rather than false-alarm).
func systemctlShow(prop string) (string, bool) {
	out, err := exec.Command("systemctl", "show", "mooring", "-p", prop, "--value").Output() // literal: SEC-1 safe (no -c)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

func checkBinary(bin, what, fix string) result {
	if p, err := exec.LookPath(bin); err == nil {
		return result{bin, "ok", "found at " + p + " — " + what, ""}
	}
	return result{bin, "fail", "MISSING — " + what, fix}
}

// checkDistroService flags a packaged caddy/nginx unit that is active or enabled — it
// fights Mooring's supervised child for its ports (the #1 "edge child exited: address
// already in use" cause, which otherwise shows up only as a mysterious cert failure at
// deploy time). Literal binary, no shell — SEC-1 safe.
func checkDistroService(name, ports string) result {
	active, _ := exec.Command("systemctl", "is-active", name).Output()
	enabled, _ := exec.Command("systemctl", "is-enabled", name).Output()
	a, e := strings.TrimSpace(string(active)), strings.TrimSpace(string(enabled))
	if a == "active" || e == "enabled" {
		return result{name + " conflict", "fail",
			"distro " + name + ".service is " + a + "/" + e + " — it squats " + ports + " and crash-loops Mooring's supervised child",
			"sudo systemctl disable --now " + name + "   (or: sudo mooring setup --yes)"}
	}
	return result{name + " conflict", "ok", "no conflicting distro " + name + ".service", ""}
}

// checkServiceEnabled verifies the mooring service is ENABLED to start on boot. A service that is
// running but NOT enabled silently vanishes after a reboot — the package deliberately does not
// auto-enable (it can't start without a config at install time), so an operator who ran only
// `systemctl start` (not `enable`) loses Mooring on the next reboot with no earlier warning. Read
// via UnitFileState; degrades to a warn when systemctl is unavailable (non-systemd host).
func checkServiceEnabled() result {
	state, ok := systemctlShow("UnitFileState")
	return serviceEnabledResult(state, ok)
}

// serviceEnabledResult is the pure state→result mapping (unit-tested; checkServiceEnabled just
// feeds it the live UnitFileState).
func serviceEnabledResult(state string, ok bool) result {
	if !ok || state == "" {
		return result{"boot-enabled", "warn", "could not confirm the mooring service is enabled for boot",
			"verify: systemctl is-enabled mooring   (enable with: sudo systemctl enable mooring)"}
	}
	switch state {
	case "enabled":
		return result{"boot-enabled", "ok", "mooring is enabled — it will start automatically after a reboot", ""}
	case "enabled-runtime", "linked-runtime":
		// --runtime enablement lives in /run (tmpfs) and is WIPED on reboot — the exact trap.
		return result{"boot-enabled", "fail",
			"mooring is " + state + " — enabled only for THIS boot (--runtime, in /run); it will NOT start after a reboot",
			"sudo systemctl enable mooring   (persistent — no --runtime)"}
	case "masked", "masked-runtime":
		return result{"boot-enabled", "fail",
			"mooring is " + state + " — masked, so systemd will not start it at all",
			"sudo systemctl unmask mooring && sudo systemctl enable --now mooring"}
	case "static", "indirect", "alias", "generated", "linked":
		// Unusual for Mooring's top-level unit; can't assert boot behavior — flag, don't fail.
		return result{"boot-enabled", "warn", "mooring reports " + state + " — confirm it starts on boot",
			"verify: systemctl is-enabled mooring"}
	default: // disabled, transient, bad, …
		return result{"boot-enabled", "fail",
			"mooring is " + state + " — it will NOT start after a reboot (it's running now, but a reboot loses it)",
			"sudo systemctl enable mooring   (or: sudo mooring setup --yes)"}
	}
}

func checkDNS() result {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := net.DefaultResolver.LookupHost(ctx, "github.com"); err != nil {
		return result{"dns", "fail", "name resolution is broken (" + err.Error() + ")",
			"check /etc/resolv.conf has a working nameserver — see installation docs"}
	}
	return result{"dns", "ok", "host name resolution works", ""}
}

// checkCapsActive verifies CAP_NET_BIND_SERVICE is ACTIVE in the live unit (not just
// that the drop-in file is on disk — a file present but not daemon-reloaded is a real
// trap). need=true (managed edge / L4) makes a missing cap a fail; else a warn.
func checkCapsActive(need bool) result {
	miss := "warn"
	if need {
		miss = "fail"
	}
	if amb, ok := systemctlShow("AmbientCapabilities"); ok {
		if strings.Contains(strings.ToLower(amb), "cap_net_bind_service") {
			return result{"net-bind cap", "ok", "CAP_NET_BIND_SERVICE is active in the unit", ""}
		}
		// The base unit grants it by default; if it's not active the installed unit is
		// stale (pre-upgrade) or overridden — reload + restart, don't reinstall.
		return result{"net-bind cap", miss, "CAP_NET_BIND_SERVICE not active — the edge/L4 can't bind :80/:443/:53",
			"sudo systemctl daemon-reload && sudo systemctl restart mooring (the base unit grants it)"}
	}
	// systemctl unavailable → can't confirm; the base unit grants it by default.
	return result{"net-bind cap", "warn", "could not confirm CAP_NET_BIND_SERVICE is active",
		"verify: systemctl show mooring -p AmbientCapabilities"}
}

func checkStreamModule() result {
	if m, _ := filepath.Glob("/etc/nginx/modules-enabled/*stream*.conf"); len(m) > 0 {
		return result{"nginx stream", "ok", "stream module is enabled", ""}
	}
	return result{"nginx stream", "warn", "stream module not found in /etc/nginx/modules-enabled/",
		"sudo apt install libnginx-mod-stream (else nginx rejects the L4 config)"}
}

// checkStateDirs verifies the writable state dirs exist, are mooring-owned, and are
// in the unit's ReadWritePaths — the silent "deploy hangs / edge won't start" trap
// when a dir is missing, root-owned, or data_dir was changed without updating the unit.
func checkStateDirs(cfg *config.Config, managed bool) result {
	dd := doctorDataDir(cfg)
	dirs := []string{dd, dd + "-apps"}
	if managed {
		dirs = append(dirs, "/var/lib/caddy")
	}
	var bad []string
	for _, d := range dirs {
		fi, err := os.Stat(d)
		if err != nil || !fi.IsDir() {
			bad = append(bad, d+" (missing)")
			continue
		}
		if !ownedByMooring(fi) {
			bad = append(bad, d+" (not owned by mooring)")
		}
	}
	if len(bad) > 0 {
		return result{"state dirs", "fail", "writable-dir problem: " + strings.Join(bad, ", "),
			"sudo install -d -o mooring -g mooring -m0700 <dir> (and add it to the unit's ReadWritePaths)"}
	}
	if rwp, ok := systemctlShow("ReadWritePaths"); ok {
		for _, d := range []string{dd, dd + "-apps"} {
			if !strings.Contains(rwp, d) {
				return result{"state dirs", "warn", d + " is not in the unit's ReadWritePaths — writes fail under the sandbox",
					"add " + d + " to ReadWritePaths= in the unit (a non-default data_dir must be added by hand)"}
			}
		}
	}
	return result{"state dirs", "ok", "state dirs exist, mooring-owned, in ReadWritePaths", ""}
}

// checkRunDir verifies the parent dir of the Caddy admin unix socket exists (the
// /run/mooring crash-loop), and that it is backed by RuntimeDirectory (a hand-mkdir
// under /run vanishes on reboot).
func checkRunDir(cfg *config.Config) result {
	listen := doctorAdminListen(cfg)
	if !strings.HasPrefix(listen, "unix/") {
		return result{"run dir", "ok", "admin endpoint is loopback TCP (no runtime dir needed)", ""}
	}
	dir := filepath.Dir(strings.TrimPrefix(listen, "unix/")) // "unix//run/mooring/x" → "/run/mooring"
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return result{"run dir", "fail", dir + " is missing — the edge can't bind its admin socket (crash-loop)",
			"add RuntimeDirectory=mooring to the unit, then daemon-reload + restart"}
	}
	if rd, ok := systemctlShow("RuntimeDirectory"); ok && strings.HasPrefix(dir, "/run/") && !strings.Contains(rd, "mooring") {
		return result{"run dir", "warn", dir + " exists but the unit has no RuntimeDirectory= (lost on reboot)",
			"add RuntimeDirectory=mooring to the unit"}
	}
	return result{"run dir", "ok", dir + " present for the admin socket", ""}
}

// checkEgress warns when the cgroup egress filter is locked to loopback while the
// managed edge needs to reach ACME + app upstreams (the silent "certs won't issue /
// proxy refused" trap). Reads the LIVE unit (a doctor-process dial wouldn't exercise
// the unit's cgroup filter, so it would mislead).
func checkEgress() result {
	deny, ok := systemctlShow("IPAddressDeny")
	if !ok {
		return result{"egress", "warn", "could not read the unit's egress filter",
			"systemctl show mooring -p IPAddressDeny -p IPAddressAllow"}
	}
	if !strings.Contains(deny, "any") && !strings.Contains(deny, "0.0.0.0/0") && !strings.Contains(deny, "::/0") {
		return result{"egress", "ok", "no cgroup egress lockdown (in-process dialers guard SSRF)", ""}
	}
	allow, _ := systemctlShow("IPAddressAllow")
	if onlyLoopback(allow) {
		return result{"egress", "fail", "IPAddressDeny=any with only loopback allowed — blocks ACME + app proxying",
			"add the docker subnet + an ACME-reachable path to IPAddressAllow=, or remove the lockdown (the in-process dialers still guard SSRF)"}
	}
	return result{"egress", "ok", "egress locked down with a non-loopback allow-set", ""}
}

// checkTOTP reports the login's two-factor posture from the config (read-only). A
// disabled state is a warn — login is password-only — with the exact enable steps.
// This reads the config FILE; the running process reflects it after a reload (the
// serve startup log is the runtime-authoritative signal).
func checkTOTP(cfg *config.Config) result {
	if cfg.Auth.TOTPSecret != "" {
		return result{"2fa (totp)", "ok", "two-factor auth is enabled in the config", ""}
	}
	return result{"2fa (totp)", "warn", "two-factor auth is DISABLED — login is password-only",
		"mooring gen-totp → paste the printed totp_secret under `auth:` in config.yaml → sudo systemctl reload mooring"}
}

// checkDeployEnv verifies the live unit exports a writable HOME. Deploys AND the
// managed socket-proxy run `docker compose` through the same env path (minimalEnv),
// and buildx/BuildKit + the docker CLI write under $HOME — a stale unit without it
// makes `compose up --build` / the proxy fail with exit 125. Catches "installed unit
// != shipped unit" (didn't daemon-reload after upgrade).
func checkDeployEnv() result {
	env, ok := systemctlShow("Environment")
	if !ok {
		return result{"deploy env", "warn", "could not read the unit's Environment", "systemctl show mooring -p Environment"}
	}
	if strings.Contains(env, "HOME=") {
		return result{"deploy env", "ok", "unit sets a writable HOME for compose/build children", ""}
	}
	return result{"deploy env", "fail", "unit has no HOME — `docker compose --build` and the socket-proxy will exit 125",
		"upgrade, then sudo systemctl daemon-reload && sudo systemctl restart mooring (the shipped unit sets HOME)"}
}

// checkSocketProxy probes the read-plane loopback endpoint (liveness, not security).
func checkSocketProxy(cfg *config.Config) result {
	if cfg != nil && cfg.Docker.ExternalProxy {
		return result{"socket-proxy", "ok", "external proxy (operator-managed, not checked)", ""}
	}
	addr := doctorProxyAddr(cfg)
	c := &http.Client{Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get("http://" + addr + "/version")
	if err != nil {
		return result{"socket-proxy", "warn", "not answering on " + addr + " — the read plane (container view) is unavailable",
			"check `docker compose -f <data_dir>/socket-proxy/docker-compose.yml ps` + the journal (often a DNS/image-pull issue)"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return result{"socket-proxy", "warn", fmt.Sprintf("%s returned HTTP %d", addr, resp.StatusCode), "check the socket-proxy container"}
	}
	return result{"socket-proxy", "ok", "managed socket-proxy answering on " + addr, ""}
}

// --- one Docker daemon behind both planes ---
//
// Two Docker installs on one host (e.g. apt docker.io + the docker snap) each run a
// daemon. The socket-proxy container (read plane) keeps the socket of the daemon it was
// started against, while the docker CLI (write plane) follows /var/run/docker.sock to
// whichever daemon owns it now. The planes then split silently: deploys land on one
// daemon, the dashboard and edge watch the other, and every other check stays green.
// These checks name the extra install; they never remove one (which install holds the
// apps' images and volumes is the operator's call).

// dockerDedupeFix is the fix for more than one Docker daemon/installation.
const dockerDedupeFix = "keep the install the mooring service uses (sudo docker info -f '{{.DockerRootDir}}' shows its data dir; /var/snap/docker/... is the snap) and remove the other: sudo snap remove docker, or sudo apt remove docker.io (docker-ce if installed from Docker's repo); then sudo systemctl restart docker mooring"

// dockerdProc is one running dockerd found in /proc.
type dockerdProc struct {
	pid    int
	exe    string // /proc/<pid>/exe target; "" when unreadable (another user's exe link needs root)
	unit   string // systemd unit from /proc/<pid>/cgroup: docker.service, snap.docker.dockerd.service, …
	uid    int    // real UID from /proc/<pid>/status; -1 when unknown
	nested bool   // in a child PID namespace (NSpid lists >1 pid): a daemon inside a container
}

// label renders the process for the report: "pid 812 /usr/bin/dockerd (docker.service)".
func (p dockerdProc) label() string {
	s := "pid " + strconv.Itoa(p.pid)
	if p.exe != "" {
		s += " " + p.exe
	}
	if p.unit != "" {
		s += " (" + p.unit + ")"
	}
	return s
}

// checkDockerDaemons counts the Docker daemons running on the host. Linux only: it
// scans /proc (CGO-free).
func checkDockerDaemons() result {
	if runtime.GOOS != "linux" {
		return result{"docker daemons", "skip", "not checked (the dockerd scan reads Linux /proc)", ""}
	}
	procs, err := scanDockerdProcs("/proc")
	if err != nil {
		return result{"docker daemons", "warn", "could not scan /proc for dockerd (" + err.Error() + ")", ""}
	}
	return evalDockerDaemons(procs)
}

// scanDockerdProcs lists the dockerd processes under procRoot (/proc on the host, a
// fixture tree in tests), sorted by pid. Per-pid errors are tolerated: a pid that exits
// mid-scan is skipped, and a dockerd whose exe, cgroup or status can't be read is still
// listed with that field unknown.
func scanDockerdProcs(procRoot string) ([]dockerdProc, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	var out []dockerdProc
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !e.IsDir() {
			continue // not a pid dir
		}
		dir := filepath.Join(procRoot, e.Name())
		comm, err := os.ReadFile(filepath.Join(dir, "comm"))
		if err != nil || strings.TrimSpace(string(comm)) != "dockerd" {
			continue // exited mid-scan, or another program
		}
		p := dockerdProc{pid: pid, uid: -1}
		p.exe, _ = os.Readlink(filepath.Join(dir, "exe")) // EACCES unless root: leave "" and still count it
		if b, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
			p.unit = cgroupUnit(string(b))
		}
		if b, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
			p.uid, p.nested = parseStatusIDs(string(b))
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pid < out[j].pid })
	return out, nil
}

// cgroupUnit returns the systemd unit in /proc/<pid>/cgroup contents: the last *.service
// or *.scope element of the cgroup path, from the v2 "0::" line or the v1 name=systemd
// line (both carry the systemd path). "" when there is none.
func cgroupUnit(data string) string {
	for _, line := range strings.Split(data, "\n") {
		f := strings.SplitN(line, ":", 3)
		if len(f) != 3 {
			continue
		}
		if v2 := f[0] == "0" && f[1] == ""; !v2 && f[1] != "name=systemd" {
			continue
		}
		parts := strings.Split(f[2], "/")
		for i := len(parts) - 1; i >= 0; i-- {
			if strings.HasSuffix(parts[i], ".service") || strings.HasSuffix(parts[i], ".scope") {
				return parts[i]
			}
		}
	}
	return ""
}

// parseStatusIDs reads the real UID and whether the process is in a child PID namespace
// (NSpid lists more than one pid) from /proc/<pid>/status contents. uid is -1 when the
// Uid line is missing; a kernel without NSpid reports nested=false.
func parseStatusIDs(data string) (uid int, nested bool) {
	uid = -1
	for _, line := range strings.Split(data, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(val)
		switch key {
		case "Uid":
			if len(f) > 0 {
				if n, err := strconv.Atoi(f[0]); err == nil {
					uid = n
				}
			}
		case "NSpid":
			nested = len(f) > 1
		}
	}
	return uid, nested
}

// evalDockerDaemons maps the dockerds found to a result: none → warn, one → ok, more →
// fail. Only host daemons count: one inside a container (child PID namespace) or a
// rootless one (non-root UID) doesn't serve /var/run/docker.sock, so it can't split the
// planes. An unknown UID counts. Pure — unit-tested.
func evalDockerDaemons(procs []dockerdProc) result {
	var host []string
	other := 0
	for _, p := range procs {
		if p.nested || p.uid > 0 {
			other++
			continue
		}
		host = append(host, p.label())
	}
	note := ""
	if other > 0 {
		note = fmt.Sprintf(" (ignoring %d dockerd inside a container or rootless)", other)
	}
	switch len(host) {
	case 0:
		return result{"docker daemons", "warn", "no Docker daemon (dockerd) is running" + note,
			"sudo systemctl start docker   (if it is running, re-run as root: /proc can hide other users' processes)"}
	case 1:
		return result{"docker daemons", "ok", "one Docker daemon: " + host[0] + note, ""}
	default:
		return result{"docker daemons", "fail",
			fmt.Sprintf("%d Docker daemons are running: %s — Mooring must talk to exactly one; with more, the socket-proxy (read plane) and the docker CLI (write plane) can reach different daemons%s",
				len(host), strings.Join(host, "; "), note),
			dockerDedupeFix}
	}
}

// dockerCLIPaths are where packages (/usr/bin), manual or static installs
// (/usr/local/bin) and the snap (/snap/bin) put the docker CLI.
var dockerCLIPaths = []string{"/usr/bin/docker", "/usr/local/bin/docker", "/snap/bin/docker"}

// dockerCLI is one docker CLI found at a standard path.
type dockerCLI struct {
	path string // where it was found, e.g. /usr/bin/docker
	real string // symlinks resolved; paths that share it are one install
}

// checkDockerInstalls looks for more than one Docker installation on disk. Unlike the
// dockerd scan, it also sees a second install whose daemon is stopped right now.
func checkDockerInstalls() result {
	clis, snap := findDockerInstalls("/")
	return evalDockerInstalls(clis, snap)
}

// findDockerInstalls stats the standard docker CLI paths and the snap's mount dir
// (/snap/docker) under root ("/" on the host, a fixture tree in tests). A missing path
// or a dangling symlink is not an install.
func findDockerInstalls(root string) (clis []dockerCLI, snap bool) {
	for _, p := range dockerCLIPaths {
		full := filepath.Join(root, p)
		if fi, err := os.Stat(full); err != nil || fi.IsDir() {
			continue
		}
		real, err := filepath.EvalSymlinks(full)
		if err != nil {
			real = full
		}
		clis = append(clis, dockerCLI{path: p, real: real})
	}
	fi, err := os.Stat(filepath.Join(root, "snap", "docker"))
	return clis, err == nil && fi.IsDir()
}

// isSnapCLI reports whether a docker CLI leads into the docker snap: /snap/bin/docker
// itself, or a link to it (which resolves to snapd's launcher, /usr/bin/snap) or into
// the snap's mount (/snap/docker/...).
func isSnapCLI(c dockerCLI) bool {
	return strings.HasPrefix(c.path, "/snap/") || strings.HasPrefix(c.real, "/snap/") || filepath.Base(c.real) == "snap"
}

// evalDockerInstalls fails on more than one Docker installation: two distinct docker
// CLIs (deduped by real path), or the docker snap next to an apt or /usr/local CLI.
// Every path into the snap is the one snap install; without a CLI link the snap still
// counts through snapInstalled (/snap/docker). Pure — unit-tested.
func evalDockerInstalls(clis []dockerCLI, snapInstalled bool) result {
	var found []string
	seen := map[string]bool{}
	snapLabel := ""
	for _, c := range clis {
		if isSnapCLI(c) {
			if snapLabel == "" {
				snapLabel = c.path + " (snap)"
			}
			continue
		}
		if !seen[c.real] { // a symlink to a CLI already counted is the same install
			seen[c.real] = true
			found = append(found, c.path)
		}
	}
	if snapLabel == "" && snapInstalled {
		snapLabel = "the docker snap (/snap/docker)"
	}
	if snapLabel != "" {
		found = append(found, snapLabel)
	}
	switch len(found) {
	case 0:
		return result{"docker installs", "ok", "no docker CLI in /usr/bin, /usr/local/bin or /snap/bin", ""}
	case 1:
		return result{"docker installs", "ok", "one Docker installation: " + found[0], ""}
	default:
		return result{"docker installs", "fail",
			fmt.Sprintf("%d Docker installations: %s — Mooring must talk to exactly one Docker daemon", len(found), strings.Join(found, ", ")),
			dockerDedupeFix}
	}
}

// checkDaemonMatch confirms the socket-proxy (read plane) and the docker CLI (write
// plane) reach the same Docker daemon, by daemon ID. The read side is GET /info on the
// proxy address the socket-proxy check probes, through the read plane's own client.
func checkDaemonMatch(cfg *config.Config) result {
	addr := doctorProxyAddr(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	read, rerr := docker.New(addr).Info(ctx)
	cancel()
	if rerr != nil {
		if cfg != nil && cfg.Docker.ExternalProxy {
			// An operator-run proxy need not allow INFO (Mooring's read plane doesn't use it).
			return result{"daemon match", "skip", "external proxy on " + addr + " did not answer /info (" + rerr.Error() + ") — not compared", ""}
		}
		rerr = fmt.Errorf("socket-proxy on %s: %w", addr, rerr)
	}
	writeID, werr := dockerCLIDaemonID()
	return evalDaemonMatch(read, rerr, writeID, werr)
}

// dockerCLIDaemonID returns the ID of the daemon the docker CLI reaches — the daemon the
// write plane's docker / docker compose children act on. Static argv, no shell (SEC-1).
func dockerCLIDaemonID() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ID}}")
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.Output()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", errors.New("docker info did not answer within 10s")
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			if msg := firstLine(ee.Stderr); msg != "" {
				return "", errors.New("docker info: " + msg)
			}
		}
		return "", fmt.Errorf("docker info: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// firstLine returns the first non-empty line of b, trimmed.
func firstLine(b []byte) string {
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}

// evalDaemonMatch compares the daemon behind the socket-proxy (read) with the one the
// docker CLI reports (write): same ID → ok, different → fail. If either side can't be
// read it warns with the reason and skips the comparison. Pure — unit-tested.
func evalDaemonMatch(read docker.Info, readErr error, writeID string, writeErr error) result {
	var why []string
	switch {
	case readErr != nil:
		why = append(why, "read plane: "+readErr.Error())
	case read.ID == "":
		why = append(why, "read plane: the socket-proxy's /info has no daemon ID")
	}
	switch {
	case writeErr != nil:
		why = append(why, "write plane: "+writeErr.Error())
	case writeID == "":
		why = append(why, "write plane: docker info printed no daemon ID")
	}
	if len(why) > 0 {
		return result{"daemon match", "warn", "could not compare the read- and write-plane daemons — " + strings.Join(why, "; "),
			"re-run as root while the mooring service and its socket-proxy are running"}
	}
	if read.ID != writeID {
		return result{"daemon match", "fail",
			"the socket-proxy (read plane) and the docker CLI (write plane) talk to different Docker daemons: " + daemonLabel(read) + " vs " + writeID,
			"two Docker installs, or a stale socket-proxy container bound to another daemon's socket: remove the extra install (see docker daemons / docker installs), then sudo docker rm -f mooring-socket-proxy; sudo systemctl restart mooring (recreates the proxy on the remaining daemon)"}
	}
	return result{"daemon match", "ok", "the socket-proxy and the docker CLI reach the same Docker daemon (" + read.ID + ")", ""}
}

// daemonLabel renders a daemon as "ID (name, data root)", leaving out empty fields.
func daemonLabel(i docker.Info) string {
	var extra []string
	for _, s := range []string{i.Name, i.DockerRootDir} {
		if s != "" {
			extra = append(extra, s)
		}
	}
	if len(extra) == 0 {
		return i.ID
	}
	return i.ID + " (" + strings.Join(extra, ", ") + ")"
}

// ownedByMooring reports whether fi is owned by the mooring user. If the user can't
// be resolved (e.g. doctor run on a dev box), it returns true (don't false-alarm).
func ownedByMooring(fi os.FileInfo) bool {
	u, err := user.Lookup("mooring")
	if err != nil {
		return true
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	return fmt.Sprint(st.Uid) == u.Uid
}

// onlyLoopback reports whether an IPAddressAllow set contains only loopback entries.
func onlyLoopback(allow string) bool {
	for _, tok := range strings.Fields(allow) {
		switch tok {
		case "", "localhost", "127.0.0.0/8", "127.0.0.1", "::1", "::1/128":
			// loopback — fine
		default:
			return false
		}
	}
	return true
}

func checkResolvedStub() result {
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil && strings.Contains(string(b), "127.0.0.53") {
		return result{"port 53", "warn", "systemd-resolved holds 127.0.0.53:53 — collides with a DNS l4_route",
			"free :53 before deploying a :53 resolver (printed below / see L4 docs)"}
	}
	return result{"port 53", "ok", "no systemd-resolved stub on 127.0.0.53", ""}
}

// checkDockerLogRotation flags the one place container logs CAN grow unbounded:
// Docker's default json-file driver keeps every container's stdout on disk forever
// unless log-opts.max-size is set. Mooring streams logs (it never stores them), so
// this is a host/disk concern, not a Mooring-memory one — but it's the gap worth
// catching on a small VPS.
func checkDockerLogRotation() result {
	b, _ := os.ReadFile("/etc/docker/daemon.json") // absent → Docker's uncapped json-file default
	if dockerLogRotated(b) {
		return result{"docker logs", "ok", "container log rotation is configured", ""}
	}
	return result{"docker logs", "warn", "json-file driver has no size cap — container logs can fill the disk",
		"sudo mooring setup --yes (caps it), or set log-opts.max-size by hand (snippet below)"}
}

// dockerLogRotated reports whether Docker's container-log driver bounds on-disk size.
// The default json-file driver does NOT unless log-opts.max-size is set; journald and
// the local driver self-rotate, and any other explicit driver is assumed
// operator-managed. Absent/invalid JSON → the uncapped json-file default.
func dockerLogRotated(daemonJSON []byte) bool {
	var cfg struct {
		LogDriver string            `json:"log-driver"`
		LogOpts   map[string]string `json:"log-opts"`
	}
	_ = json.Unmarshal(daemonJSON, &cfg)
	switch cfg.LogDriver {
	case "", "json-file":
		return cfg.LogOpts["max-size"] != ""
	default:
		return true // journald/local/syslog/none/… — self-rotating or externally managed
	}
}

// printDockerLogGuidance prints a copy-paste fix for the json-file size cap — used by
// the read-only `doctor`. (`setup` applies it as a reviewable plan step instead.)
func printDockerLogGuidance() {
	fmt.Println("\nDocker log rotation — the default json-file driver never caps container logs,")
	fmt.Println("so on a small VPS they can fill the disk. `sudo mooring setup --yes` caps it, or add")
	fmt.Println("to /etc/docker/daemon.json by hand:")
	fmt.Println(`  { "log-driver": "json-file", "log-opts": { "max-size": "10m", "max-file": "3" } }`)
	fmt.Println("  sudo systemctl restart docker   # applies to newly created containers")
}

const dockerDaemonJSON = "/etc/docker/daemon.json"

// dockerLogsNeedCap reports whether setup should add a json-file size cap (the file's
// driver is json-file/unset with no max-size).
func dockerLogsNeedCap() bool {
	b, _ := os.ReadFile(dockerDaemonJSON)
	return !dockerLogRotated(b)
}

// applyDockerLogCap merges a json-file size cap into /etc/docker/daemon.json, keeping
// every other key intact and backing up the original. A daemon RESTART (a separate
// plan step) is needed to apply it. A daemon.json that can't be parsed is left alone
// (warn, don't fail the run — Docker config is the operator's, we won't clobber it).
func applyDockerLogCap(apply bool) error {
	cur, _ := os.ReadFile(dockerDaemonJSON)
	out, changed, err := withDockerLogCap(cur)
	if err != nil {
		fmt.Printf("       skipping: %v — set log-opts.max-size by hand\n", err)
		return nil
	}
	if !changed {
		fmt.Println("       already capped (or a non-json-file driver) — nothing to do")
		return nil
	}
	fmt.Printf("       write %s (+ %s.mooring.bak)\n", dockerDaemonJSON, dockerDaemonJSON)
	if !apply {
		return nil
	}
	if len(cur) > 0 {
		if err := writeRootFile(dockerDaemonJSON+".mooring.bak", cur); err != nil {
			return err
		}
	}
	tmp := dockerDaemonJSON + ".mooring.tmp"
	if err := writeRootFile(tmp, out); err != nil {
		return err
	}
	return os.Rename(tmp, dockerDaemonJSON) // atomic swap
}

// withDockerLogCap returns daemon.json with a json-file max-size/max-file cap merged
// in, preserving all other keys. changed=false when it's already capped or uses a
// non-json-file (self-rotating/managed) driver. Pure — unit-tested.
func withDockerLogCap(daemonJSON []byte) (out []byte, changed bool, err error) {
	cfg := map[string]any{}
	if len(bytes.TrimSpace(daemonJSON)) > 0 {
		if err := json.Unmarshal(daemonJSON, &cfg); err != nil {
			return nil, false, fmt.Errorf("daemon.json is not valid JSON")
		}
	}
	if d, _ := cfg["log-driver"].(string); d != "" && d != "json-file" {
		return daemonJSON, false, nil // operator chose another driver — leave it
	}
	opts, _ := cfg["log-opts"].(map[string]any)
	if opts == nil {
		opts = map[string]any{}
	}
	if _, ok := opts["max-size"]; ok {
		return daemonJSON, false, nil // already capped
	}
	cfg["log-driver"] = "json-file"
	opts["max-size"] = "10m"
	if _, ok := opts["max-file"]; !ok {
		opts["max-file"] = "3"
	}
	cfg["log-opts"] = opts
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, false, err
	}
	return append(b, '\n'), true, nil
}

// --- actions ---

func run(apply bool, name string, arg ...string) error {
	fmt.Printf("       $ %s %s\n", name, strings.Join(arg, " "))
	if !apply {
		return nil
	}
	cmd := exec.Command(name, arg...) // fixed binary + args; no shell (SEC-1)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func writeCaddyRepo(apply bool) error {
	fmt.Printf("       write %s (Caddy signing key, fetched over HTTPS)\n", caddyKeyPath)
	fmt.Printf("       write %s\n", caddyListPath)
	if !apply {
		return nil
	}
	key, err := httpGet(caddyKeyURL)
	if err != nil {
		return fmt.Errorf("fetch Caddy signing key: %w", err)
	}
	if err := writeRootFile(caddyKeyPath, key); err != nil {
		return err
	}
	return writeRootFile(caddyListPath, []byte(caddySources))
}

func writeRootFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func httpGet(url string) ([]byte, error) {
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func printDNSGuidance(l4 bool) {
	if !l4 {
		return
	}
	fmt.Println("\nDNS resolver on :53? systemd-resolved holds 127.0.0.53:53 by default. `setup` does")
	fmt.Println("NOT touch host DNS (rewriting it unattended is too risky) — if you bind :53, run:")
	fmt.Println("  printf '[Resolve]\\nDNSStubListener=no\\n' | sudo tee /etc/systemd/resolved.conf.d/no-stub.conf")
	fmt.Println("  sudo systemctl restart systemd-resolved")
	fmt.Println("  sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf   # NOT stub-resolv.conf")
}

func have(bin string) bool { _, err := exec.LookPath(bin); return err == nil }

// unitExists reports whether a systemd unit is installed on the host, so a "disable
// the distro service" step is a no-op (skipped) rather than an error on hosts that
// don't have it. Literal binary, no shell — SEC-1 safe.
func unitExists(unit string) bool {
	out, err := exec.Command("systemctl", "list-unit-files", unit, "--no-legend").Output()
	return err == nil && strings.TrimSpace(string(out)) != ""
}
