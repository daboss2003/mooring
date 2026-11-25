package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/docker"
	"github.com/daboss2003/mooring/internal/edge"
	"github.com/daboss2003/mooring/internal/siem/hostlog"
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
// nginx+stream, upgrade a system caddy older than 2.11 from Caddy's apt repo, install the
// Mooring-owned Caddy build at <data_dir>/bin/caddy when config.yaml needs one — those for the
// managed edge only — cap Docker's logs, and add the mooring user to the adm group for security
// logs). It NEVER auto-rewrites host DNS or frees :53 —
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
	cfg, cfgErr := config.Load(*configPath)
	if cfgErr != nil {
		cfg = nil
	}
	rep := preflight(*l4, cfg, true)
	if x, ok := doctorConfigResult(*configPath, cfgErr); ok {
		rep.add(x)
	} else if x, ok := doctorServiceViewResult(*configPath, serviceView(*configPath)); ok {
		rep.add(x)
	}
	rep.print(os.Stdout)
	if rep.hasFail() {
		fmt.Println("\nRun `sudo mooring setup` to review a fix plan, then `sudo mooring setup --yes` to apply it.")
	} else {
		fmt.Println("\nRequired prerequisites are present.")
	}
	printGuidance(rep, *l4)
	return doctorExit(rep)
}

// doctorConfigResult is doctor's line for a config.yaml that didn't load (ok=false: it loaded).
// A file that is there and refused is a fail, shown with the offending lines: the service will
// not start with it. A file that isn't there yet, or that this user may not read, is a warn: the
// runtime checks then use the defaults.
func doctorConfigResult(path string, err error) (result, bool) {
	switch {
	case err == nil:
		return result{}, false
	// Intentional: a warn, not a fail. The group rule is about the caller's primary group; only the
	// service user (and root, who is exempt) can judge the file by it.
	case errors.Is(err, config.ErrOtherGroup):
		return result{"config", "warn", otherGroupAdvice(path) + "; runtime checks use the defaults", "run: " + checkCommand + " (and doctor with sudo)"}, true
	case errors.Is(err, fs.ErrNotExist):
		return result{"config", "warn", "there is no " + path + " yet (runtime checks use the defaults)", "write it (template: /usr/share/mooring/config.example.yaml), or pass --config"}, true
	case configUnreadable(err):
		return result{"config", "warn", "could not read " + path + " (" + err.Error() + "); runtime checks use the defaults", "run doctor with sudo, or pass --config"}, true
	}
	return result{"config", "fail", path + " is refused; the service will not start with it:\n" + strings.TrimRight(refusalText(err), "\n"),
		"fix the file, then check it again: " + checkCommand + " (doctor's other checks used the defaults)"}, true
}

// doctorServiceViewResult is doctor's line for a config.yaml that loads for root and that the
// service can't use (verr, from serviceView; nil: no line): a fail, like a refused file, because
// the service will not start with it. Root's own load can't see it.
func doctorServiceViewResult(path string, verr error) (result, bool) {
	if verr == nil {
		return result{}, false
	}
	_, hint := serviceViewFix(path, verr)
	return result{"config", "fail", verr.Error() + "; the service will not start with it (what is in the file is valid)", hint}, true
}

// doctorExit is doctor's exit status: 1 when any check failed. The report is already printed.
func doctorExit(rep report) error {
	if rep.hasFail() {
		return &exitError{code: 1, err: errors.New("one or more checks failed"), printed: true}
	}
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
	configPath := fs.String("config", config.DefaultPath, "config.yaml whose edge settings decide whether a Mooring-owned Caddy build is needed")
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

	// setup can run before config.yaml exists, so the config is best-effort: without it no
	// DNS plugin build is planned.
	cfg, cfgWarn := loadDoctorConfig(*configPath)
	mode := setupEdgeModeOf(cfg, cfg != nil || configFileExists(*configPath))
	// setup runs at onboarding (before config/service start), so skip the runtime-state
	// checks (run dir / egress / socket-proxy / daemon match) — they need a running service.
	rep := preflight(*l4, cfg, false)
	if cfgWarn != "" {
		rep.add(result{"config", "warn", cfgWarn, "pass --config so the plan covers the Caddy build that edge.dns01 / edge.trusted_proxies / catch_all need"})
	}
	if x, ok := setupEdgeNote(mode); ok {
		rep.add(x)
	}
	rep.print(os.Stdout)

	steps := plan(*yes, *l4, *restart, cfg, mode)
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
	// Read before applying: whether the running service has an edge depends on the Caddy it found.
	active, _ := systemctlShow("ActiveState")
	running := serviceRunningEdge(active == "active", cfg)
	done, err := applySteps(os.Stdout, steps)
	if err != nil {
		return err
	}
	fmt.Println("\nDone.")
	if hint := setupRestartHint(done, *restart, running); hint != "" {
		fmt.Println(hint)
	}
	if hint := admRestartHint(done, *restart, active == "active"); hint != "" {
		fmt.Println(hint)
	}
	printDNSGuidance(*l4)
	return nil
}

// applied is what applySteps installed.
type applied struct {
	ownedCaddy           bool // a Mooring-owned Caddy build
	systemCaddyInstalled bool // the system caddy package, where there was none
	systemCaddyUpgraded  bool // the system caddy package, over an older one
	admGroupAdded        bool // the mooring user joined the adm group
}

// runningEdge is what the mooring service's edge ran on before setup applied its steps.
type runningEdge int

const (
	edgeNotRunning runningEdge = iota // the service is stopped, or edge.mode is external (no edge)
	edgeNoCaddy                       // the service runs but found no Caddy, so it started no edge
	edgeOnSystem                      // the edge runs the system caddy
	edgeOnOwned                       // the edge runs the Mooring-owned build
)

// serviceRunningEdge reads what the edge of the mooring service runs on; active: the service is running.
func serviceRunningEdge(active bool, cfg *config.Config) runningEdge {
	if !active || (cfg != nil && cfg.Edge.Mode == config.EdgeExternal) {
		return edgeNotRunning
	}
	dataDir := doctorDataDir(cfg)
	switch edge.ResolveCaddy(dataDir) {
	case "":
		return edgeNoCaddy
	case edge.OwnedCaddyPath(dataDir):
		return edgeOnOwned
	}
	return edgeOnSystem
}

// setupRestartHint is the line setup prints after applying: how the edge gets onto the Caddy it
// installed. running is what the service's edge ran on before. "" when nothing needs saying
// (--restart restarts Mooring itself; a stopped service picks the new Caddy up when it starts).
func setupRestartHint(done applied, restart bool, running runningEdge) string {
	if restart {
		return ""
	}
	switch {
	case running == edgeNoCaddy && (done.systemCaddyInstalled || done.ownedCaddy):
		// serve builds the edge only when it finds a Caddy at startup, so nothing in the running service
		// starts one now.
		return "Restart Mooring so the edge starts: sudo systemctl restart mooring"
	case done.ownedCaddy:
		return "Restart Mooring so the edge switches to it: sudo systemctl restart mooring"
	case done.systemCaddyUpgraded && running == edgeOnSystem:
		// The running edge's binary was replaced: Mooring's stale-child watcher restarts the edge on it.
		// Behind the owned build the upgrade didn't touch the running edge.
		return "Mooring restarts its edge on the new Caddy within a few minutes; to switch now: sudo systemctl restart mooring"
	}
	return ""
}

// applySteps runs steps in order and reports what they installed. A step that returns a stepWarning
// is printed and skipped over (it counts as nothing installed), as is one that returns stepSkipped;
// any other error stops setup.
func applySteps(w io.Writer, steps []step) (applied, error) {
	var done applied
	for i, s := range steps {
		fmt.Fprintf(w, "\n  %d. %s\n", i+1, s.desc)
		var warn stepWarning
		var skip stepSkipped
		err := s.do()
		switch {
		case errors.As(err, &warn):
			fmt.Fprintf(w, "       WARNING: %v\n", warn.err)
			fmt.Fprintf(w, "       %s\n", warn.hint)
			continue
		case errors.As(err, &skip):
			fmt.Fprintf(w, "       skipped: %s\n", skip.why)
			continue
		case err != nil:
			return done, fmt.Errorf("step %q failed: %w", s.desc, err)
		}
		done.ownedCaddy = done.ownedCaddy || strings.HasPrefix(s.desc, ownedCaddyStepPrefix) || strings.HasPrefix(s.desc, ownedCaddyIfOldStepPrefix)
		done.systemCaddyInstalled = done.systemCaddyInstalled || s.desc == caddyInstallStepDesc
		done.systemCaddyUpgraded = done.systemCaddyUpgraded || strings.HasPrefix(s.desc, caddyUpgradeStepPrefix)
		done.admGroupAdded = done.admGroupAdded || s.desc == admGroupStepDesc
	}
	return done, nil
}

// step is one planned host mutation; do() prints the action and (when apply) runs it.
type step struct {
	desc string
	do   func() error
}

// stepWarning is a step failure that doesn't stop setup: it is printed with hint and the next step runs.
type stepWarning struct {
	err  error
	hint string
}

func (w stepWarning) Error() string { return w.err.Error() }

// stepSkipped is returned by a step that found when it ran that it had nothing to do: applySteps prints
// why, doesn't count it as installed, and runs the next step.
type stepSkipped struct{ why string }

func (s stepSkipped) Error() string { return "skipped: " + s.why }

// setupEdgeMode is who runs the edge, as setup plans its Caddy and nginx steps.
type setupEdgeMode int

const (
	setupEdgeManaged  setupEdgeMode = iota // edge.mode managed, or no config.yaml yet (managed is the default)
	setupEdgeExternal                      // edge.mode external: the operator's own proxy fronts Mooring
	setupEdgeUnknown                       // config.yaml exists but didn't load
)

// setupEdgeModeOf is the edge mode setup plans for: cfg's, or with cfg nil (config.yaml didn't load)
// managed when there is no config.yaml (configExists false) and unknown when there is one.
func setupEdgeModeOf(cfg *config.Config, configExists bool) setupEdgeMode {
	switch {
	case cfg != nil && cfg.Edge.Mode == config.EdgeExternal:
		return setupEdgeExternal
	case cfg != nil || !configExists:
		return setupEdgeManaged
	}
	return setupEdgeUnknown
}

// configFileExists reports whether anything is at path (a dangling symlink counts).
func configFileExists(path string) bool {
	_, err := os.Lstat(path)
	return !errors.Is(err, fs.ErrNotExist)
}

// setupEdgeNote is the report line that says why the plan has no Caddy or nginx step. ok=false with
// the managed edge.
func setupEdgeNote(mode setupEdgeMode) (result, bool) {
	switch mode {
	case setupEdgeExternal:
		return result{"edge", "skip", "edge.mode is external: setup doesn't install, upgrade or disable Caddy or nginx, or their services", ""}, true
	case setupEdgeUnknown:
		return result{"edge", "warn", "config.yaml didn't load, so edge.mode isn't known: setup doesn't install, upgrade or disable Caddy or nginx, or their services",
			"fix config.yaml (sudo mooring doctor shows the error), then run sudo mooring setup again"}, true
	}
	return result{}, false
}

// plan builds the ordered fix steps for whatever is missing. apply=false makes each
// do() print-only, so the SAME list drives the dry run and the real run. cfg may be nil
// (config.yaml not loaded): then no Mooring-owned Caddy build is planned. mode is
// setupEdgeModeOf(cfg, …).
func plan(apply, l4, restart bool, cfg *config.Config, mode setupEdgeMode) []step {
	var steps []step
	// Intentional: the Caddy and nginx steps are planned only for the managed edge. With edge.mode
	// external the operator's own proxy fronts Mooring, often as caddy.service or nginx.service, and
	// serve starts neither an edge nor the L4 load balancer: disabling that unit takes every site down,
	// and an install or upgrade restarts it. --l4 doesn't change that. A config.yaml that exists but
	// doesn't load leaves the mode unknown (an external config missing trusted_proxies fails validation),
	// and Mooring can't start on it anyway, so the edge is left alone until it loads. With no config.yaml
	// at all (setup runs before it is written) the default, managed, applies.
	if mode == setupEdgeManaged {
		steps = managedEdgeSteps(apply, l4, cfg)
	}
	// CAP_NET_BIND_SERVICE is granted by the base unit now (no drop-in step needed).
	if dockerLogsNeedCap() {
		steps = append(steps,
			step{"cap Docker container logs (json-file max-size=10m) in /etc/docker/daemon.json", func() error { return applyDockerLogCap(apply) }},
			step{"restart docker to apply the log cap — BOUNCES running containers (run setup before deploying apps)", func() error { return run(apply, "systemctl", "restart", "docker") }},
		)
	}
	if s, ok := admGroupStep(apply, cfg); ok {
		steps = append(steps, s)
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

// managedEdgeSteps plans Caddy, the Mooring-owned build, nginx for --l4, and disabling the distro units
// that would squat the managed edge's ports.
func managedEdgeSteps(apply, l4 bool, cfg *config.Config) []step {
	steps, caddyChange := systemCaddySteps(apply)
	if s, ok := ownedCaddyStep(apply, cfg, edge.ResolveCaddy(doctorDataDir(cfg)), caddyChange); ok {
		steps = append(steps, s)
	}
	// Disable the packaged caddy.service whenever it exists, and whenever this plan installs or
	// upgrades caddy: Mooring supervises its OWN Caddy child, and the distro unit squats :80/:443 and
	// crash-loops the edge. On a fresh host the unit doesn't exist yet at plan time (the package
	// brings it and starts it), so the step is planned anyway and checks for the unit when it runs.
	if unitExists("caddy.service") || caddyChange != caddyPkgKept {
		steps = append(steps, disableDistroUnitStep(apply, "caddy"))
	}
	installNginx := l4 && !have("nginx")
	if installNginx {
		steps = append(steps,
			step{"install nginx + the stream module", func() error { return aptGet(apply, "install", "-y", "nginx", "libnginx-mod-stream") }},
		)
	}
	if l4 && (unitExists("nginx.service") || installNginx) {
		steps = append(steps, disableDistroUnitStep(apply, "nginx"))
	}
	return steps
}

// The step descs cmdSetup reads (through applySteps) to tell the operator how the edge picks up the
// Caddy that was installed.
const (
	ownedCaddyStepPrefix      = "install a Caddy build with "
	ownedCaddyIfOldStepPrefix = "install a current Caddy build as "
	caddyInstallStepDesc      = "install caddy"
	caddyUpgradeStepPrefix    = "upgrade caddy v"
)

// caddyPkgChange is what a plan does to the system caddy package.
type caddyPkgChange int

const (
	caddyPkgKept    caddyPkgChange = iota // left as it is
	caddyPkgInstall                       // installed: there is none on PATH
	caddyPkgUpgrade                       // upgraded: it is older than edge.MinCaddyVersion
)

// upgradeRetryHint follows a failed step of the system caddy upgrade.
const upgradeRetryHint = "the host keeps its current Caddy; retry `sudo mooring setup --yes` once apt is free"

// systemCaddySteps plans the system caddy package (the edge's fallback when a Mooring-owned build
// exists, so that build doesn't count): install it from Caddy's apt repo when none is on PATH, or
// upgrade it from that repo when it is older than edge.MinCaddyVersion (Ubuntu and Debian ship
// 2.6.2). A version that can't be read plans nothing; doctor reports it. Managed edge only (plan).
func systemCaddySteps(apply bool) ([]step, caddyPkgChange) {
	const repoDesc, updateDesc = "add the Caddy apt repo + signing key", "apt-get update"
	bin := systemCaddy()
	if bin == "" {
		return []step{
			{repoDesc, func() error { return writeCaddyRepo(apply) }},
			{updateDesc, func() error { return aptGet(apply, "update") }},
			{caddyInstallStepDesc, func() error { return aptGet(apply, "install", "-y", "caddy") }},
		}, caddyPkgInstall
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	v, err := edge.CaddyVersion(ctx, bin)
	if err != nil || v.AtLeast(edge.MinCaddyVersion) {
		return nil, caddyPkgKept
	}
	// Intentional: unlike a fresh install, the upgrade is optional (the host keeps a working Caddy), so a
	// failure of any of its steps (apt's lock held by unattended-upgrades, the repo unreachable, a held
	// package) is a stepWarning: setup still disables caddy.service, caps Docker's logs and enables
	// mooring. The upgrade's later steps are skipped once one fails.
	failed := false
	optional := func(what string, do func() error) func() error {
		return func() error {
			if failed {
				return stepSkipped{"an earlier step of the Caddy upgrade failed"}
			}
			err := do()
			var warn stepWarning
			if err == nil || errors.As(err, &warn) {
				return err
			}
			failed = true
			if what != "" {
				err = fmt.Errorf("%s: %w", what, err)
			}
			return stepWarning{err, upgradeRetryHint}
		}
	}
	desc := caddyUpgradeStepPrefix + v.String() + " (the distribution's build) to Caddy's official release"
	return []step{
		{repoDesc, optional("", func() error { return writeCaddyRepo(apply) })},
		{updateDesc, optional("apt-get update", func() error { return aptGet(apply, "update") })},
		{desc, optional("", func() error { return upgradeSystemCaddy(apply) })},
	}, caddyPkgUpgrade
}

// systemCaddy is the caddy on PATH (absolute path), "" when there is none. Never the Mooring-owned
// build.
func systemCaddy() string {
	p, err := exec.LookPath("caddy")
	if err != nil {
		return ""
	}
	return p
}

// upgradeSystemCaddy installs Caddy's official release over the system caddy, then reads the new
// version. apt failing, or a version still below edge.MinCaddyVersion (apt preferred another
// candidate, or the caddy on PATH isn't the packaged one), is a stepWarning.
func upgradeSystemCaddy(apply bool) error {
	// Intentional: --force-confold keeps a locally edited /etc/caddy/Caddyfile (Mooring doesn't use it),
	// and with --force-confdef dpkg never stops setup to ask about it.
	err := aptGet(apply, "install", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "caddy")
	if err != nil {
		return stepWarning{fmt.Errorf("apt-get install caddy: %w", err), upgradeRetryHint}
	}
	if !apply {
		return nil
	}
	const hint = "apt kept the distribution's build — check `apt-cache policy caddy`"
	bin := systemCaddy()
	if bin == "" {
		return stepWarning{errors.New("no caddy on PATH after the upgrade"), hint}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	v, err := edge.CaddyVersion(ctx, bin)
	if err != nil {
		return stepWarning{fmt.Errorf("could not read the version of %s after the upgrade: %w", bin, err), "check that it runs: " + bin + " version"}
	}
	if !v.AtLeast(edge.MinCaddyVersion) {
		return stepWarning{fmt.Errorf("%s is still v%s after the upgrade (%s or later is needed)", bin, v, edge.MinCaddyVersion), hint}
	}
	fmt.Printf("       %s is now v%s\n", bin, v)
	return nil
}

// disableDistroUnitStep stops and disables the packaged <name>.service. It may be planned before the
// install step that brings the unit, so it checks for the unit again when it runs and skips one that
// isn't installed. The dry run only prints the command.
func disableDistroUnitStep(apply bool, name string) step {
	unit := name + ".service"
	return step{"disable the distro " + unit + " (Mooring supervises its own child)", func() error {
		if apply && !unitExists(unit) {
			fmt.Printf("       skipped: %s isn't installed\n", unit)
			return nil
		}
		return run(apply, "systemctl", "disable", "--now", name)
	}}
}

// ownedCaddyStep plans the Mooring-owned Caddy build (<data_dir>/bin/caddy) when config.yaml needs
// one: a dns01 provider's module is missing from caddyBin, the Caddy the edge will run
// (edge.ResolveCaddy), or caddyBin is older than edge.MinCaddyVersion while a setting that needs it is
// configured. systemCaddy is what this plan does to the system caddy: installed or upgraded, the edge
// will run Caddy's official release (no plugins) rather than caddyBin unless an owned build is in
// front. A fresh install brings a current release; whether an upgrade reached the minimum is known only
// after it ran, so that case gets a step that decides when it runs. ok=false: not needed.
func ownedCaddyStep(apply bool, cfg *config.Config, caddyBin string, systemCaddy caddyPkgChange) (step, bool) {
	dataDir := doctorDataDir(cfg)
	owned := edge.OwnedCaddyPath(dataDir)
	var pkgs, want []string
	if cfg != nil && cfg.Edge.Mode == config.EdgeManaged {
		pkgs, want = dnsPluginPackages(dnsProviders(cfg))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	replaced := caddyBin == "" || (systemCaddy != caddyPkgKept && caddyBin != owned)
	need := false
	if len(want) > 0 {
		// Check the binary the edge will run, as doctor and the runtime installer do. When the apt step
		// planned above brings it, it is the plugin-less official build, so the plugin build is needed.
		var mods map[string]bool
		if !replaced {
			mods, _ = edge.CaddyModules(ctx, caddyBin) // unreadable → no modules → (re)install
		}
		for _, m := range want {
			need = need || !mods[m]
		}
	}
	if !need && len(caddyMinNeeds(cfg)) > 0 {
		switch {
		case systemCaddy == caddyPkgUpgrade && caddyBin != owned:
			desc := ownedCaddyIfOldStepPrefix + owned + " if the system Caddy is still older than " + edge.MinCaddyVersion.String() +
				" after the upgrade (from caddyserver.com; checked before use)"
			return step{desc, func() error { return installOwnedCaddyIfOld(apply, cfg) }}, true
		case !replaced:
			if v, err := edge.CaddyVersion(ctx, caddyBin); err == nil && !v.AtLeast(edge.MinCaddyVersion) {
				need = true
			}
		}
	}
	if !need {
		return step{}, false
	}
	mods := "no plugins"
	if len(want) > 0 {
		mods = strings.Join(want, ", ")
	}
	desc := ownedCaddyStepPrefix + mods + " as " + owned + " (from caddyserver.com; checked before use, the previous build kept as .bak)"
	return step{desc, func() error { return installOwnedCaddy(apply, cfg, pkgs, want) }}, true
}

// installOwnedCaddyIfOld installs a plugin-less Mooring-owned build when the system caddy is still
// older than edge.MinCaddyVersion after the upgrade step before it ran (apt kept the distribution's
// build, or the upgrade failed). It reads that version when it runs; the dry run prints the condition.
func installOwnedCaddyIfOld(apply bool, cfg *config.Config) error {
	if !apply {
		fmt.Printf("       only if the system caddy is still older than %s after the upgrade:\n", edge.MinCaddyVersion)
		return installOwnedCaddy(false, cfg, nil, nil)
	}
	bin := systemCaddy()
	if bin == "" {
		return stepSkipped{"no caddy on PATH after the upgrade"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	v, err := edge.CaddyVersion(ctx, bin)
	if err != nil {
		return stepSkipped{fmt.Sprintf("could not read the version of %s (%v)", bin, err)}
	}
	if v.AtLeast(edge.MinCaddyVersion) {
		return stepSkipped{fmt.Sprintf("%s is v%s after the upgrade", bin, v)}
	}
	fmt.Printf("       %s is still v%s\n", bin, v)
	return installOwnedCaddy(true, cfg, nil, nil)
}

// installOwnedCaddy downloads a Caddy with dnsPkgs (plus any plugins the current caddy already
// carries) from the build server and installs it as the Mooring-owned build in cfg's data_dir, owned by
// the mooring service user, once it passes setupBuildCheck(cfg). apply=false prints what it would do. A
// var so tests can stand in for the download.
var installOwnedCaddy = func(apply bool, cfg *config.Config, dnsPkgs, want []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	dataDir := doctorDataDir(cfg)
	pkgs := dnsPkgs
	// Carry plugins over only from the root-owned system caddy (looked up now: an apt step may have just
	// installed it) — never from the Mooring-owned build, which the service user can rewrite.
	if bin, lerr := exec.LookPath("caddy"); lerr == nil {
		extras, err := edge.CaddyExtraPackages(ctx, bin)
		if err != nil {
			fmt.Printf("       note: can't read the plugins built into %s (%v) — the new build has only the DNS providers\n", bin, err)
		}
		pkgs = mergePackages(dnsPkgs, extras)
	}
	src, err := edge.BuildServerURL("", runtime.GOOS, runtime.GOARCH, pkgs)
	if err != nil {
		return err
	}
	owned := edge.OwnedCaddyPath(dataDir)
	check := "has " + strings.Join(want, ", ")
	if len(want) == 0 {
		check = "lists its modules"
	}
	configCheck := setupBuildCheck(cfg)
	fmt.Printf("       download %s\n", src)
	fmt.Printf("       check it runs, is at least %s and %s; keep the current build as %s.bak\n", edge.MinCaddyVersion, check, owned)
	if configCheck != nil {
		settings := "the edge settings in config.yaml"
		if len(cfg.Edge.CAs) > 0 {
			settings += " with each edge.cas CA"
		}
		fmt.Printf("       check it accepts the edge's startup config and %s (caddy validate, without app routes or DNS-01 wildcards)\n", settings)
	}
	fmt.Printf("       install it as %s, owned by the mooring user\n", owned)
	if !apply {
		return nil
	}
	if fi, err := os.Stat(dataDir); err != nil || !fi.IsDir() {
		return fmt.Errorf("data_dir %s doesn't exist — install the mooring package first", dataDir)
	}
	owner, err := serviceUserOwner()
	if err != nil {
		return err
	}
	path, err := installPluginBuild(ctx, edge.InstallOptions{DataDir: dataDir, Packages: pkgs, WantModules: want, Owner: owner, Check: configCheck})
	if err != nil {
		// Intentional: not fatal: failing here would abort the setup steps after this one (disabling the
		// distro caddy.service, enabling mooring). Only a build for a dns01 provider's plugin is retried
		// by Mooring at startup; the plugin-less build (for the 2.11 minimum) only by re-running setup.
		hint := "Mooring retries it at startup; `sudo mooring doctor` shows the plugin's state."
		switch {
		case errors.Is(err, edge.ErrBuildCheckFailed):
			// Mooring's own retry checks a build against the same configs, so it would be refused too.
			hint = "The current Caddy stays in use. Fix what Caddy reports in config.yaml's edge settings, then run `sudo mooring setup --yes` again."
		case len(want) == 0:
			hint = "run `sudo mooring setup --yes` again to retry; `sudo mooring doctor` shows the Caddy version."
		}
		return stepWarning{fmt.Errorf("the Caddy build wasn't installed: %w", err), hint}
	}
	fmt.Printf("       installed %s\n", path)
	return nil
}

// installPluginBuild downloads, checks and installs the Mooring-owned build. A var so tests can stand in
// for the download.
var installPluginBuild = edge.InstallPluginBuild

// validateEdgeConfig is `caddy validate` of an edge config (edge.ValidateConfig; as root it runs as the
// mooring user). A var so tests can stand in for Caddy.
var validateEdgeConfig = edge.ValidateConfig

// setupBuildCheck is the config check (InstallOptions.Check) of a Caddy build setup installs: `caddy
// validate` of the edge's startup config, then of the edge config rendered from config.yaml's edge
// settings (trusted proxies, admin vhost, ACME), both as serve renders them, with every edge.cas CA's
// issuer. setup has no database, so neither has app routes or cert-only hosts; serve checks every build
// it downloads against the config it serves. nil when cfg is nil.
func setupBuildCheck(cfg *config.Config) func(ctx context.Context, bin string) error {
	if cfg == nil {
		return nil
	}
	base := edgeBaseConfig(cfg)
	// Intentional: no DNS-01 wildcards. Render passes the dns01 token as the provider's `api_token`, so a
	// provider whose module takes other credentials (route53, digitalocean) is refused by EVERY build; serve
	// leaves that namespace's wildcard out and serves the rest, so setup must not refuse the build for it.
	// The providers' modules are checked by WantModules.
	base.Wildcards = nil
	var tokens []string
	for _, w := range edgeWildcards(cfg) {
		tokens = append(tokens, w.DNS01Token)
	}
	// Intentional: one cert-only subject under .invalid (RFC 6761: never resolves) per edge.cas CA. Render
	// emits a CA's issuer only for a subject that uses it, and setup has no routes or cert bindings, so
	// without these Caddy would never load the CAs (directory URL, trusted root read as the mooring user).
	// `caddy validate` provisions the issuers but obtains no certificate and contacts no CA.
	caHosts := make([]edge.CertHost, 0, len(base.CAs))
	for i, ca := range base.CAs {
		caHosts = append(caHosts, edge.CertHost{Hostname: fmt.Sprintf("mooring-setup-check-%d.invalid", i+1), CA: ca.Name})
	}
	floor, floorErr := edge.Render(edge.BootFloor(base), nil, nil)
	full, fullErr := edge.Render(base, nil, caHosts)
	configs := []struct {
		what   string
		render []byte
		err    error
	}{
		{"the startup config", floor, floorErr},
		{"the edge settings in config.yaml", full, fullErr},
	}
	return func(ctx context.Context, bin string) error {
		for _, c := range configs {
			if c.err != nil {
				return fmt.Errorf("the edge config check can't render %s: %w", c.what, c.err)
			}
			if err := validateEdgeConfig(ctx, bin, c.render, tokens); err != nil {
				return fmt.Errorf("the edge config check failed on %s: %w", c.what, err)
			}
		}
		return nil
	}
}

// serviceUserOwner is the mooring service user as an install owner (setup runs as root; the edge runs
// the binary as mooring). The user is looked up before anything is downloaded. A var so tests can stand
// in for the user.
var serviceUserOwner = func() (*edge.Owner, error) {
	u, err := user.Lookup("mooring")
	if err != nil {
		return nil, errors.New("the mooring service user doesn't exist — install the mooring package first")
	}
	uid, uerr := strconv.Atoi(u.Uid)
	gid, gerr := strconv.Atoi(u.Gid)
	if uerr != nil || gerr != nil {
		return nil, fmt.Errorf("the mooring service user has a non-numeric uid/gid (%s/%s)", u.Uid, u.Gid)
	}
	return &edge.Owner{Uid: uid, Gid: gid}, nil
}

// dnsProviders returns the distinct dns01 providers (lowercased) of the configured namespaces, in
// config order.
func dnsProviders(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, w := range edgeWildcards(cfg) {
		if p := strings.ToLower(strings.TrimSpace(w.DNS01Provider)); p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// dnsPluginPackages maps the known providers to their Go module paths and Caddy module IDs; an
// unknown provider is skipped (doctor reports it).
func dnsPluginPackages(providers []string) (pkgs, moduleIDs []string) {
	for _, p := range providers {
		if mod, ok := edge.DNSProviderModule(p); ok {
			pkgs = append(pkgs, mod)
			moduleIDs = append(moduleIDs, edge.DNSModuleID(p))
		}
	}
	return pkgs, moduleIDs
}

// mergePackages returns the distinct packages of a and b, sorted.
func mergePackages(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range append(append([]string(nil), a...), b...) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
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
		// A detail of several lines (a refused config.yaml's diagnostics) keeps its lines indented.
		fmt.Fprintf(w, "  %s %-16s %s\n", icon[x.state], x.name, strings.ReplaceAll(x.detail, "\n", "\n      "))
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
	r.add(checkCaddy(cfg))
	if x, ok := checkSystemCaddyFallback(cfg); ok {
		r.add(x)
	}
	if managed {
		r.add(checkDistroService("caddy", ":80/:443 (edge)"))
	}
	if cfg != nil && cfg.Edge.Mode == config.EdgeManaged {
		for _, x := range checkDNSPlugins(cfg) {
			r.add(x)
		}
	}
	r.add(checkBinary("docker", "container read/write plane", "install Docker + the compose plugin"))
	r.add(checkDockerDaemons())
	r.add(checkDockerInstalls())
	r.add(checkDockerLogRotation())
	r.add(checkDNS())
	r.add(checkCapsActive(managed)) // L4 runs only under the managed edge, so --l4 adds no need of its own
	r.add(checkStateDirs(cfg, managed))
	if cfg != nil {
		r.add(checkTOTP(cfg))
		for _, x := range configWarnings(cfg) {
			r.add(x)
		}
	}
	for _, x := range securityLogChecks(cfg, runtimeChecks) {
		r.add(x)
	}
	if l4 {
		for _, x := range l4Checks(managed) {
			r.add(x)
		}
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

// l4Checks are the --l4 checks. serve runs the L4 load balancer only with the managed edge, and setup
// plans no nginx step otherwise, so with edge.mode external there is one skip line instead.
func l4Checks(managed bool) []result {
	if !managed {
		return []result{{"l4", "skip", "edge.mode is external: Mooring runs no L4 load balancer (it needs edge.mode managed)", ""}}
	}
	return []result{
		checkBinary("nginx", "L4 (TCP/UDP) load balancer", "sudo mooring setup --l4 --yes"),
		checkDistroService("nginx", ":53/:853 + :80 (L4)"),
		checkStreamModule(),
		checkResolvedStub(),
	}
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
// is unavailable (so callers degrade rather than false-alarm). A var so tests can stand in for it.
var systemctlShow = func(prop string) (string, bool) {
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

// ownedCaddyMaxAge is when doctor suggests refreshing the Mooring-owned Caddy build, which no
// package manager updates.
const ownedCaddyMaxAge = 180 * 24 * time.Hour

// caddyMinSettings names the settings that need edge.MinCaddyVersion (see caddyMinNeeds).
const caddyMinSettings = "edge.trusted_proxies, dns01, catch_all and security_logs.response"

// caddyMinNeeds lists the configured settings that need Caddy >= edge.MinCaddyVersion; empty when
// none is set or cfg is nil.
func caddyMinNeeds(cfg *config.Config) []string {
	if cfg == nil || cfg.Edge.Mode == config.EdgeExternal {
		return nil // external mode: Mooring runs no Caddy, so nothing needs its version
	}
	var why []string
	if len(cfg.Edge.TrustedProxies) > 0 {
		why = append(why, "edge.trusted_proxies")
	}
	if len(edgeWildcards(cfg)) > 0 {
		why = append(why, "dns01")
	}
	catchAll := cfg.Edge.CatchAll
	for _, b := range cfg.Edge.BaseDomains {
		catchAll = catchAll || b.CatchAll
	}
	if catchAll {
		why = append(why, "catch_all")
	}
	// Automated response refuses QUIC 0-RTT at the edge (allow_0rtt), which needs Caddy 2.11.
	if cfg.SecurityResponseMode() != "off" {
		why = append(why, "security_logs.response")
	}
	return why
}

// checkCaddy reports the Caddy the edge runs (edge.ResolveCaddy: the Mooring-owned build when
// present, else the system caddy) and its version. Below edge.MinCaddyVersion it fails only when a
// setting that needs it is configured.
func checkCaddy(cfg *config.Config) result {
	dataDir := doctorDataDir(cfg)
	bin := edge.ResolveCaddy(dataDir)
	if bin == "" {
		if cfg != nil && cfg.Edge.Mode == config.EdgeExternal {
			return result{"caddy", "skip", "not installed — not needed: edge.mode is external, so Mooring runs no Caddy", ""}
		}
		return result{"caddy", "fail", "MISSING — managed HTTPS edge (:80/:443 + ACME)", "sudo mooring setup --yes"}
	}
	owned := edge.OwnedCaddyPath(dataDir)
	where := bin
	if bin == owned {
		where += " (Mooring-owned build)"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	v, err := edge.CaddyVersion(ctx, bin)
	if err != nil {
		return result{"caddy", "warn", "found at " + where + " but could not read its version (" + err.Error() + ")",
			"check that it runs: " + bin + " version"}
	}
	if !v.AtLeast(edge.MinCaddyVersion) {
		detail := fmt.Sprintf("v%s at %s is older than %s", v, where, edge.MinCaddyVersion)
		// setup upgrades a system caddy below the minimum whatever the config says, except with
		// edge.mode external (no setup fix then); it reinstalls the owned build only when a setting
		// needs the minimum.
		fix, warnFix := systemCaddyUpgradeFix, systemCaddyUpgradeFix
		switch {
		case bin == owned:
			fix = "sudo mooring setup --yes (installs a current Caddy as " + owned + ")"
			warnFix = "if config.yaml sets one of those: " + fix
		case cfg != nil && cfg.Edge.Mode == config.EdgeExternal:
			fix, warnFix = "", ""
		}
		if needs := caddyMinNeeds(cfg); len(needs) > 0 {
			return result{"caddy", "fail", detail + " — needed by the configured " + strings.Join(needs, ", "), fix}
		}
		why := "nothing configured needs it"
		if cfg == nil {
			why = "config.yaml unreadable, so not known whether anything needs it"
		}
		return result{"caddy", "warn", detail + " — " + why + " (" + caddyMinSettings + " need " + edge.MinCaddyVersion.String() + "+)", warnFix}
	}
	if bin == owned {
		if fi, err := os.Stat(bin); err == nil {
			if age := time.Since(fi.ModTime()); age > ownedCaddyMaxAge {
				return result{"caddy", "warn", fmt.Sprintf("found at %s — v%s, installed %d days ago (no package manager updates it)", where, v, int(age.Hours()/24)),
					"refresh it: sudo rm " + bin + " && sudo mooring setup --yes"}
			}
		}
	}
	return result{"caddy", "ok", "found at " + where + " — v" + v.String() + ", managed HTTPS edge (:80/:443 + ACME)", ""}
}

// systemCaddyUpgradeFix is the fix for a system caddy older than edge.MinCaddyVersion.
const systemCaddyUpgradeFix = "sudo mooring setup --yes (upgrades it to Caddy's official release)"

// checkSystemCaddyFallback reports a system caddy older than edge.MinCaddyVersion that checkCaddy
// doesn't show because the edge runs the Mooring-owned build: it is the edge's fallback when that build
// is removed. ok=false when there is nothing to report (no owned build, no system caddy, a current one,
// a version that can't be read, or edge.mode external: Mooring runs no Caddy and setup doesn't upgrade
// it).
func checkSystemCaddyFallback(cfg *config.Config) (result, bool) {
	dataDir := doctorDataDir(cfg)
	sys := systemCaddy()
	if sys == "" || edge.ResolveCaddy(dataDir) != edge.OwnedCaddyPath(dataDir) || (cfg != nil && cfg.Edge.Mode == config.EdgeExternal) {
		return result{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	v, err := edge.CaddyVersion(ctx, sys)
	if err != nil || v.AtLeast(edge.MinCaddyVersion) {
		return result{}, false
	}
	return result{"caddy (system)", "warn",
		fmt.Sprintf("the fallback system Caddy is v%s at %s, older than %s", v, sys, edge.MinCaddyVersion),
		systemCaddyUpgradeFix}, true
}

// caddyBuildServerAddr is edge.DefaultBuildServer's host, where plugin builds are downloaded from.
const caddyBuildServerAddr = "caddyserver.com:443"

// buildServerReachable reports whether a TLS connection to Caddy's build server succeeds. A var so
// tests can stub it.
var buildServerReachable = func() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Intentional: a TLS dial, never a GET — requesting the download endpoint starts a build.
	conn, err := (&tls.Dialer{}).DialContext(ctx, "tcp", caddyBuildServerAddr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// checkDNSPlugins reports, per distinct dns01 provider, whether its Caddy module is in the binary the
// edge runs. A missing one is a warn when caddyserver.com is reachable (Mooring installs a plugin
// build at startup) and a fail when it isn't. caddyserver.com is dialed at most once.
func checkDNSPlugins(cfg *config.Config) []result {
	providers := dnsProviders(cfg)
	if len(providers) == 0 {
		return nil
	}
	dataDir := doctorDataDir(cfg)
	owned := edge.OwnedCaddyPath(dataDir)
	bin := edge.ResolveCaddy(dataDir)
	var mods map[string]bool
	var modErr error
	if bin != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		mods, modErr = edge.CaddyModules(ctx, bin)
		cancel()
	}
	reachable, probed := false, false
	var out []result
	for _, p := range providers {
		name := "dns plugin " + p
		if _, ok := edge.DNSProviderModule(p); !ok {
			out = append(out, result{name, "fail", "unknown DNS provider " + strconv.Quote(p) + " — supported: " + strings.Join(edge.KnownDNSProviders(), ", "),
				"set dns01.provider in config.yaml to a supported provider"})
			continue
		}
		id := edge.DNSModuleID(p)
		if mods[id] {
			out = append(out, result{name, "ok", id + " is in " + bin, ""})
			continue
		}
		if !probed {
			reachable, probed = buildServerReachable(), true
		}
		where := "not in " + bin
		switch {
		case bin == "":
			where = "no caddy is installed"
		case modErr != nil:
			where = "could not list the modules of " + bin + ": " + modErr.Error()
		}
		switch {
		case !reachable:
			fix := "allow outbound HTTPS to caddyserver.com, then restart mooring"
			if bin == "" {
				fix = "allow outbound HTTPS to caddyserver.com, then sudo mooring setup --yes"
			}
			out = append(out, result{name, "fail", id + " missing (" + where + "), and " + caddyBuildServerAddr + " is unreachable (the plugin build is downloaded from there)", fix})
		case bin == "":
			// The edge (and its plugin installer) doesn't start without a caddy, so setup installs both.
			out = append(out, result{name, "warn", id + " missing (" + where + ")",
				"sudo mooring setup --yes (installs Caddy, then a build with this plugin as " + owned + ")"})
		default:
			out = append(out, result{name, "warn", id + " missing (" + where + ") — Mooring installs it at startup as " + owned,
				"or install it now: sudo mooring setup --yes"})
		}
	}
	return out
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

// configWarnings reports each config.yaml value Mooring corrected instead of refusing to boot
// (config.LoadWarnings, e.g. out-of-range quiet hours turned off) as a warn. Security logs without an
// archive are the security archive line instead (checkSecurityArchive).
func configWarnings(cfg *config.Config) []result {
	var out []result
	for _, w := range cfg.LoadWarnings {
		if strings.HasPrefix(w, config.WarnSecurityLogsNoArchive) {
			continue
		}
		out = append(out, result{"config", "warn", w, "fix it in " + config.DefaultPath + ", then sudo systemctl restart mooring"})
	}
	return out
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

// --- security logs: the adm group, host log access, the archive, the unit's memory cap ---
//
// Security logs (docs/security-logs.md) read the host's auth and Fail2Ban logs and the journal with the
// service's groups: the mooring user's own (the group database), plus the unit's SupplementaryGroups.
// Whether a file is readable is worked out from those groups and the file's owner, group and mode, the
// same way for root and for any other user running doctor. (Running a child as mooring, as the Caddy
// checks do, wouldn't answer it: that child gets no supplementary groups.)

// admGroupStepDesc is setup's step that adds the mooring user to adm (applySteps reads it).
const admGroupStepDesc = "add the mooring service user to the adm group (security logs read the host's auth and Fail2Ban logs)"

// admGroupFix adds the mooring user to adm and restarts the service so it runs with the group.
const admGroupFix = "sudo usermod -aG adm mooring && sudo systemctl restart mooring   (or: sudo mooring setup --yes)"

// minServiceMemoryMax is the MemoryMax the shipped unit sets (1G); a lower one in the loaded unit is a warn.
const minServiceMemoryMax = 1 << 30

// serviceAccount is the mooring user as the group database has it.
type serviceAccount struct {
	uid, gid string
	groups   []string // every gid the user is in, the primary one included
}

// lookupGroupGID is the gid of the host group name; ok=false when there is none. A var so tests can
// stand in for the group database.
var lookupGroupGID = func(name string) (string, bool) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return "", false
	}
	return g.Gid, true
}

// lookupServiceAccount reads the mooring user; ok=false when there is none. A var so tests can stand in
// for it.
var lookupServiceAccount = func() (serviceAccount, bool) {
	u, err := user.Lookup("mooring")
	if err != nil {
		return serviceAccount{}, false
	}
	gids, _ := u.GroupIds()
	if !slices.Contains(gids, u.Gid) {
		gids = append(gids, u.Gid)
	}
	return serviceAccount{uid: u.Uid, gid: u.Gid, groups: gids}, true
}

// serviceProcessGroups is the supplementary gids of the running mooring service (its MainPID's /proc
// status); ok=false when it isn't running or can't be read. A var so tests can stand in for it.
var serviceProcessGroups = func() ([]string, bool) {
	pid, ok := systemctlShow("MainPID")
	if n, err := strconv.Atoi(pid); !ok || err != nil || n <= 0 {
		return nil, false
	}
	b, err := os.ReadFile(filepath.Join("/proc", pid, "status"))
	if err != nil {
		return nil, false
	}
	return parseStatusGroups(string(b)), true
}

// parseStatusGroups reads the gids of the first Groups line of /proc/<pid>/status contents.
func parseStatusGroups(data string) []string {
	for _, line := range strings.Split(data, "\n") {
		if v, ok := strings.CutPrefix(line, "Groups:"); ok {
			var out []string
			for _, f := range strings.Fields(v) {
				if _, err := strconv.ParseUint(f, 10, 32); err == nil {
					out = append(out, f)
				}
			}
			return out
		}
	}
	return nil
}

// resolveHostLogs is what security logs follow with config.yaml's host_logs (the follower's own
// resolution). A var so tests can stand in for the host's files.
var resolveHostLogs = func(h config.SecurityLogsHost) hostlog.Config {
	return hostlog.FromConfig(h, "", slog.New(slog.DiscardHandler))
}

// journalDirs are where journald keeps the system journal: persistent, then volatile.
var journalDirs = []string{"/var/log/journal", "/run/log/journal"}

// securityLogChecks are doctor's security-log lines. cfg nil (config.yaml not loaded): the defaults,
// without the archive line. None when security logs are off; with host logs off, only the archive and
// the memory cap. runtime adds the running service's groups to the adm check.
func securityLogChecks(cfg *config.Config, runtime bool) []result {
	if cfg != nil && !cfg.SecurityLogs.On() {
		return nil
	}
	var out []result
	if cfg == nil || cfg.SecurityLogs.HostLogs.On() {
		out = append(out, checkAdmGroup(runtime))
		out = append(out, checkHostLogs(cfg)...)
	}
	if cfg != nil {
		out = append(out, checkSecurityArchive(cfg))
	}
	v, ok := systemctlShow("MemoryMax")
	return append(out, memoryMaxResult(v, ok))
}

// checkAdmGroup reports whether the mooring user is in the adm group (the group of the host's auth and
// Fail2Ban logs, with a read ACL on the journal) and, with runtime, whether the running service has it:
// its MainPID's groups, so a membership added since it started shows as needing a restart.
func checkAdmGroup(runtime bool) result {
	const name = "adm group"
	adm, ok := lookupGroupGID("adm")
	if !ok {
		return result{name, "skip", "this host has no adm group: security logs read only the host logs whose own mode lets the mooring service read them", ""}
	}
	acct, ok := lookupServiceAccount()
	if !ok {
		return result{name, "skip", "no mooring user on this host (install the mooring package)", ""}
	}
	var running, procHas bool
	if runtime {
		var groups []string
		groups, running = serviceProcessGroups()
		procHas = slices.Contains(groups, adm)
	}
	switch {
	case !slices.Contains(acct.groups, adm) && running && procHas:
		return result{name, "warn", "the mooring user isn't in the adm group (the running service has it from a SupplementaryGroups= setting)", admGroupFix}
	case !slices.Contains(acct.groups, adm):
		return result{name, "warn", "the mooring user isn't in the adm group — security logs can't read the host's auth and Fail2Ban logs or the journal", admGroupFix}
	case running && !procHas:
		return result{name, "warn", "the mooring user is in the adm group, but the running service started without it", "sudo systemctl restart mooring"}
	}
	return result{name, "ok", "the mooring user is in the adm group (host auth and Fail2Ban logs, the journal)", ""}
}

// admGroupStep is setup's step that adds the mooring user to adm: planned when security logs read host
// logs (cfg nil: the default, on), the host has an adm group, and the user exists and isn't in it.
func admGroupStep(apply bool, cfg *config.Config) (step, bool) {
	if cfg != nil && (!cfg.SecurityLogs.On() || !cfg.SecurityLogs.HostLogs.On()) {
		return step{}, false
	}
	adm, ok := lookupGroupGID("adm")
	if !ok {
		return step{}, false
	}
	if acct, ok := lookupServiceAccount(); !ok || slices.Contains(acct.groups, adm) {
		return step{}, false
	}
	return step{admGroupStepDesc, func() error { return run(apply, "usermod", "-aG", "adm", "mooring") }}, true
}

// admRestartHint is the line setup prints when it added the mooring user to adm while the service runs
// (active) without --restart: the running service gets the group only when it restarts.
func admRestartHint(done applied, restart, active bool) string {
	if !done.admGroupAdded || restart || !active {
		return ""
	}
	return "Restart Mooring so the service gets the adm group: sudo systemctl restart mooring"
}

// serviceGroups is the uid and the gids the mooring service runs with: the account's groups and the
// unit's SupplementaryGroups (names that don't exist are left out). ok=false without a mooring user.
func serviceGroups() (uint32, map[uint32]bool, bool) {
	acct, ok := lookupServiceAccount()
	if !ok {
		return 0, nil, false
	}
	uid, err := strconv.ParseUint(acct.uid, 10, 32)
	if err != nil {
		return 0, nil, false
	}
	ids := map[uint32]bool{}
	add := func(gid string) {
		if n, err := strconv.ParseUint(gid, 10, 32); err == nil {
			ids[uint32(n)] = true
		}
	}
	for _, g := range acct.groups {
		add(g)
	}
	if v, ok := systemctlShow("SupplementaryGroups"); ok {
		for _, name := range strings.Fields(v) {
			if gid, ok := lookupGroupGID(name); ok {
				add(gid)
			} else {
				add(name) // a numeric gid
			}
		}
	}
	return uint32(uid), ids, true
}

// checkHostLogs reports, for each host log security logs follow, whether the mooring service can read
// it. Nothing without a mooring user (the adm line says so).
func checkHostLogs(cfg *config.Config) []result {
	var h config.SecurityLogsHost
	if cfg != nil {
		h = cfg.SecurityLogs.HostLogs
	}
	follow := resolveHostLogs(h)
	uid, groups, ok := serviceGroups()
	if !ok {
		return nil
	}
	var out []result
	switch {
	case follow.AuthLog != "":
		out = append(out, checkHostLogFile("auth log", follow.AuthLog, uid, groups, true))
	case !follow.Journal:
		out = append(out, result{"auth log", "warn", "no auth log file, and the journal isn't read: security logs collect no sshd/sudo/su events",
			"set security_logs.host_logs.auth_log in " + config.DefaultPath + ", or remove host_logs.journal: false"})
	}
	if follow.Fail2BanLog != "" {
		out = append(out, checkHostLogFile("fail2ban log", follow.Fail2BanLog, uid, groups, false))
	}
	if follow.Journal {
		out = append(out, checkJournal(groups))
	}
	return out
}

// checkHostLogFile reports whether uid with groups can read the log at path. A missing auth log
// (required) is a warn; a missing Fail2Ban log is a skip (Fail2Ban isn't installed). A file readable
// only through a POSIX ACL is reported as unreadable.
func checkHostLogFile(name, path string, uid uint32, groups map[uint32]bool, required bool) result {
	fi, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist) && !required:
		return result{name, "skip", path + " isn't there (Fail2Ban isn't installed, or logs elsewhere: security_logs.host_logs.fail2ban_log)", ""}
	case errors.Is(err, fs.ErrNotExist):
		return result{name, "warn", path + " doesn't exist: security logs collect no sshd/sudo/su events from it",
			"set security_logs.host_logs.auth_log to the host's auth log in " + config.DefaultPath}
	case err != nil:
		return result{name, "warn", "could not check " + path + " (" + err.Error() + ")", "re-run as root: sudo mooring doctor"}
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return result{name, "warn", "could not read the owner of " + path, ""}
	}
	perm := fi.Mode().Perm()
	desc := fmt.Sprintf("%s (%s:%s %04o)", path, userName(st.Uid), groupName(st.Gid), perm)
	if readable, via := readableBy(uid, groups, st.Uid, st.Gid, perm); readable {
		return result{name, "ok", "security logs read " + desc + " through " + via, ""}
	}
	return result{name, "warn", "the mooring service can't read " + desc, hostLogFileFix(path, st.Gid, perm, required)}
}

// hostLogFileFix is the fix for a host log the service can't read: join adm when the file is adm's and
// group-readable, else make it adm's (or, without an adm group, one of the service's groups); for the
// auth log, or read sshd/sudo/su from the journal as well.
func hostLogFileFix(path string, fgid uint32, perm fs.FileMode, auth bool) string {
	adm, admOK := lookupGroupGID("adm")
	if admOK && adm == strconv.FormatUint(uint64(fgid), 10) && perm&0o040 != 0 {
		return admGroupFix
	}
	fix := "make it readable by one of the mooring service's groups"
	if admOK {
		fix = "sudo chgrp adm " + path + " && sudo chmod g+r " + path + " (and the same mode in its logrotate `create` line)"
	}
	if auth {
		fix += "; or also read sshd/sudo/su from the journal: security_logs.host_logs.journal: true"
	}
	return fix
}

// readableBy reports whether uid with groups may read a file owned by fuid:fgid with perm, by the Unix
// rule (the owner bits for the owner, else the group bits for a member, else the others bits), and
// through what.
func readableBy(uid uint32, groups map[uint32]bool, fuid, fgid uint32, perm fs.FileMode) (bool, string) {
	switch {
	case fuid == uid:
		return perm&0o400 != 0, "its owner"
	case groups[fgid]:
		return perm&0o040 != 0, "the " + groupName(fgid) + " group"
	}
	return perm&0o004 != 0, "its mode (readable by everyone)"
}

// checkJournal reports whether the service can read the system journal: as a member of systemd-journal
// (the journal files' group), adm or wheel.
func checkJournal(groups map[uint32]bool) result {
	dir := ""
	for _, d := range journalDirs {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			dir = d
			break
		}
	}
	if dir == "" {
		return result{"journal", "warn", "no systemd journal in " + strings.Join(journalDirs, " or ") + ": security logs collect no sshd/sudo/su events",
			"install rsyslog (it writes /var/log/auth.log), or set security_logs.host_logs.auth_log"}
	}
	// Intentional: by group, not by the files' mode. The journal files are root:systemd-journal 0640, and
	// systemd's tmpfiles give adm and wheel a read ACL on them, which the mode doesn't show (reading an ACL
	// needs getxattr, not in the standard library on every platform this builds for).
	for _, g := range []string{"systemd-journal", "adm", "wheel"} {
		if gid, ok := lookupGroupGID(g); ok {
			if n, err := strconv.ParseUint(gid, 10, 32); err == nil && groups[uint32(n)] {
				return result{"journal", "ok", "security logs read sshd/sudo/su from the journal (" + dir + ") through the " + g + " group", ""}
			}
		}
	}
	return result{"journal", "warn", "the mooring service isn't in the adm or systemd-journal group, so journalctl shows it none of the host's sshd/sudo/su entries", admGroupFix}
}

// checkSecurityArchive reports where security logs are archived, or that they stay on this host only.
func checkSecurityArchive(cfg *config.Config) result {
	s := cfg.SecurityLogs
	s3 := s.Archive.S3
	if s3 == nil {
		return result{"security archive", "warn", "security_logs.archive.s3 isn't set — security logs are kept only on this host (" + daysText(s.HotRetentionOrDefault()) + ")",
			"add an S3 bucket as security_logs.archive.s3 in " + config.DefaultPath + ", then sudo systemctl restart mooring (docs/security-logs.md)"}
	}
	endpoint := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(s3.Endpoint, "https://"), "http://"), "/")
	return result{"security archive", "ok", "security logs are archived to " + endpoint + "/" + s3.Bucket + "/" + s3.Prefix +
		" and kept " + daysText(s.Archive.RetentionOrDefault()) + " there", ""}
}

// daysText writes d as "14 days" ("1 day"), or as a duration when it isn't whole days.
func daysText(d time.Duration) string {
	switch n := d / (24 * time.Hour); {
	case d%(24*time.Hour) != 0 && d%time.Hour == 0:
		return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
	case d%(24*time.Hour) != 0:
		return d.String()
	case n == 1:
		return "1 day"
	default:
		return strconv.FormatInt(int64(n), 10) + " days"
	}
}

// memoryMaxResult maps the loaded unit's MemoryMax (bytes, "infinity") to a result: below what the
// shipped unit sets is a warn (the upgrade's unit isn't loaded, or a drop-in lowers it).
func memoryMaxResult(v string, ok bool) result {
	const name = "memory max"
	if v == "infinity" && ok {
		return result{name, "ok", "the unit sets no MemoryMax", ""}
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if !ok || err != nil {
		return result{name, "warn", "could not read the unit's MemoryMax", "verify: systemctl show mooring -p MemoryMax"}
	}
	if n < minServiceMemoryMax {
		return result{name, "warn", "the unit's MemoryMax is " + sizeText(n) + "; the shipped unit sets " + sizeText(minServiceMemoryMax),
			"sudo systemctl daemon-reload && sudo systemctl restart mooring; if it stays low, a drop-in or a copy in /etc/systemd/system sets it (systemctl cat mooring)"}
	}
	return result{name, "ok", "MemoryMax is " + sizeText(n), ""}
}

// sizeText writes a byte count as systemd does: "1G", "384M", else "N bytes".
func sizeText(n uint64) string {
	switch {
	case n > 0 && n%(1<<30) == 0:
		return strconv.FormatUint(n>>30, 10) + "G"
	case n > 0 && n%(1<<20) == 0:
		return strconv.FormatUint(n>>20, 10) + "M"
	}
	return strconv.FormatUint(n, 10) + " bytes"
}

// userName and groupName are an id's name, or the id when it has none.
func userName(uid uint32) string {
	id := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(id); err == nil {
		return u.Username
	}
	return id
}

func groupName(gid uint32) string {
	id := strconv.FormatUint(uint64(gid), 10)
	if g, err := user.LookupGroupId(id); err == nil {
		return g.Name
	}
	return id
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

func run(apply bool, name string, arg ...string) error { return runWithEnv(apply, nil, name, arg...) }

// aptEnv is added to the environment of setup's apt-get commands.
// Intentional: needrestart (Ubuntu 24.04 ships it) runs after every apt install. Interactive, it can
// stop `setup --yes` with a dialog; automatic, it restarts mooring.service mid-setup, because the edge's
// Caddy child still runs the binary apt replaced. List-only mode leaves the restart to Mooring's own
// watcher (or --restart). noninteractive keeps debconf from prompting too.
var aptEnv = []string{"DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l"}

// aptGet runs apt-get with aptEnv.
func aptGet(apply bool, arg ...string) error { return runWithEnv(apply, aptEnv, "apt-get", arg...) }

// runWithEnv prints the command (env first, as it would be typed) and, when apply, runs it with env
// added to the inherited environment.
func runWithEnv(apply bool, env []string, name string, arg ...string) error {
	fmt.Printf("       $ %s\n", strings.Join(append(append(append([]string(nil), env...), name), arg...), " "))
	if !apply {
		return nil
	}
	return runCmd(env, name, arg...)
}

// runCmd runs one host command with the terminal's output, env (KEY=value) added to the inherited
// environment; an added variable replaces an inherited one. A var so tests can stand in for apt and
// systemctl.
var runCmd = func(env []string, name string, arg ...string) error {
	cmd := exec.Command(name, arg...) // fixed binary + args; no shell (SEC-1)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...) // os/exec keeps the last value of a duplicated key
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// writeCaddyRepo adds Caddy's apt repo and its signing key (fetched over HTTPS). A var so tests can
// stand in for the download and the root-owned files.
var writeCaddyRepo = func(apply bool) error {
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
// don't have it. Literal binary, no shell — SEC-1 safe. A var so tests can stub it.
var unitExists = func(unit string) bool {
	out, err := exec.Command("systemctl", "list-unit-files", unit, "--no-legend").Output()
	return err == nil && strings.TrimSpace(string(out)) != ""
}
