// Package dockerexec is the write-plane exec wrapper: it shells out to
// `docker compose` with STATIC ARGV only — never a shell, never string
// interpolation, always a `--` terminator before service names (plan §3, §5.6).
// It enforces the global one-docker-child semaphore and the ≥1 GB write-plane
// gate, and reaps the whole process group on context cancellation.
package dockerexec

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrWritePlaneDisabled is returned when the host is below the §0 resource gate (RAM + swap).
var ErrWritePlaneDisabled = errors.New("dockerexec: write plane disabled (host below the RAM+swap resource gate)")

// ErrBusy is returned when the one-docker-child semaphore could not be acquired.
var ErrBusy = errors.New("dockerexec: another docker operation is in progress")

const maxLineBytes = 8 << 10 // truncate pathological lines (plan §M4 bufio truncation)

// Semaphore caps concurrent `docker` children at 1 across the whole process
// (poller stats go through the proxy and don't count; only exec children do).
// Remediation/scale-up use TryAcquire (never queue — queuing children IS the OOM
// vector, plan §4).
type Semaphore struct{ ch chan struct{} }

// NewSemaphore returns the global one-docker-child semaphore.
func NewSemaphore() *Semaphore { return &Semaphore{ch: make(chan struct{}, 1)} }

// Acquire blocks until the slot is free or ctx is done.
func (s *Semaphore) Acquire(ctx context.Context) error {
	select {
	case s.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TryAcquire grabs the slot without blocking; false means held.
func (s *Semaphore) TryAcquire() bool {
	select {
	case s.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release frees the slot.
func (s *Semaphore) Release() { <-s.ch }

// Job is one `docker compose` invocation. Project/Dir/ConfigFiles come from the
// app's compose labels; they are passed as discrete argv elements (no shell), so
// they cannot inject commands.
type Job struct {
	Project     string
	Dir         string
	ConfigFiles []string
	EnvFile     string   // optional 0600 --env-file rendered from the env store
	Action      []string // e.g. ["up","-d","--force-recreate"]
	Service     string   // optional; appended after a "--" terminator
}

// defaultWritePlaneFloor is the §0 write-plane resource gate, against RAM + swap. It is 900 MiB, NOT
// 1 GiB: a VPS sold as "1 GB" reports MemTotal a little under 1 GiB (~970–1015 MiB) after the kernel's
// reservation, and the old 1-GiB floor tripped on essentially every genuine 1 GB box. 900 MiB sits
// comfortably below that, and swap counts on top — so a 1 GB box (with or without swap) clears it,
// while a truly tiny (≤ 512 MiB, no swap) box is still gated unless the operator overrides.
const defaultWritePlaneFloor = 900 << 20 // 900 MiB

// WritePlaneGate decides whether the write plane is armed from the host's addressable memory
// (RAM + swap). memTotal==0 means unknown (non-Linux dev) → armed, with a caveat note. floorBytes
// overrides the default floor when non-zero (operator's `docker.write_plane_min_mb`), so an operator
// who accepts the risk can run on a smaller box. Counting swap is what lets a 1 GB + swap VPS deploy.
func WritePlaneGate(memTotal, swapTotal, floorBytes uint64) (bool, string) {
	if memTotal == 0 {
		return true, "host RAM unknown; write plane armed (ensure enough RAM/swap on the real host)"
	}
	floor := floorBytes
	if floor == 0 {
		floor = defaultWritePlaneFloor
	}
	if memTotal+swapTotal < floor {
		return false, "host has less than 1 GB of RAM + swap; the write plane is disabled (§0 resource gate). Add swap, or lower docker.write_plane_min_mb if you accept the risk. Note: on-box image builds still need real headroom."
	}
	return true, ""
}

// Runner executes Jobs under the gate + semaphore.
type Runner struct {
	sem          *Semaphore
	writeAllowed bool
	writeReason  string
	binary       string // "docker"; overridable in tests

	keepFlagOnce sync.Once // memoizes the build-cache keep-size flag name (see keepStorageFlag)
	keepFlag     string
}

// NewRunner builds a Runner. writeAllowed/writeReason come from the §0 gate.
func NewRunner(sem *Semaphore, writeAllowed bool, writeReason string) *Runner {
	return &Runner{sem: sem, writeAllowed: writeAllowed, writeReason: writeReason, binary: "docker"}
}

// WriteAllowed reports whether the write plane is armed, and why not if not.
func (r *Runner) WriteAllowed() (bool, string) { return r.writeAllowed, r.writeReason }

// argv builds the static argument vector. No element is ever a shell string.
func (j Job) argv() []string {
	argv := []string{"compose", "-p", j.Project}
	if j.Dir != "" {
		argv = append(argv, "--project-directory", j.Dir)
	}
	for _, f := range j.ConfigFiles {
		argv = append(argv, "-f", f)
	}
	if j.EnvFile != "" {
		argv = append(argv, "--env-file", j.EnvFile) // global flag, before the subcommand action
	}
	argv = append(argv, j.Action...)
	if j.Service != "" {
		argv = append(argv, "--", j.Service) // -- terminator before the service
	}
	return argv
}

// Run executes the job, invoking onLine for each (truncated) output line. It
// acquires the semaphore (blocking on ctx), and on ctx cancellation kills the
// whole process group and reaps it. Returns the command error (incl. non-zero
// exit) or a gate/semaphore error.
func (r *Runner) Run(ctx context.Context, job Job, onLine func(string)) error {
	if !r.writeAllowed {
		return ErrWritePlaneDisabled
	}
	if err := r.sem.Acquire(ctx); err != nil {
		return err
	}
	defer r.sem.Release()
	return r.runHeld(ctx, job, onLine)
}

// RunHeld is Run for a caller that ALREADY HOLDS the one-docker-child semaphore
// (the self-healing supervisor, which acquires it non-blocking via its safety gate
// so it never queues a docker child). It must not be called without holding the
// semaphore.
func (r *Runner) RunHeld(ctx context.Context, job Job, onLine func(string)) error {
	if !r.writeAllowed {
		return ErrWritePlaneDisabled
	}
	return r.runHeld(ctx, job, onLine)
}

// RunInternal runs a Mooring-OWNED infrastructure job (bringing up the embedded
// read-only socket-proxy) REGARDLESS of the §0 write-plane resource gate — the read
// plane must come up even on a sub-1 GB box. It is NOT for app workloads: the caller
// passes a fixed, embedded, Mooring-authored compose (never operator input), so it
// bypasses the RAM gate while keeping the static-argv discipline, the
// one-docker-child semaphore, and process-group reaping. It acquires the semaphore
// (blocking on ctx) like Run.
func (r *Runner) RunInternal(ctx context.Context, job Job, onLine func(string)) error {
	if err := r.sem.Acquire(ctx); err != nil {
		return err
	}
	defer r.sem.Release()
	return r.runHeld(ctx, job, onLine)
}

func (r *Runner) runHeld(ctx context.Context, job Job, onLine func(string)) error {
	return r.runArgv(ctx, job.Dir, job.argv(), onLine)
}

// PruneBuildCache reclaims BuildKit build cache, keeping at most `keep` of the
// most-recently-used cache (LRU eviction): `docker builder prune -a -f --keep-storage
// <keep>`. It runs under the §0 write gate + the one-docker-child semaphore, exactly like
// a deploy. `keep` is a validated size (e.g. "5GB") passed as a discrete argv element (no
// shell). Best-effort by design — callers log the outcome and never fail a deploy on error.
func (r *Runner) PruneBuildCache(ctx context.Context, keep string, onLine func(string)) error {
	if !r.writeAllowed {
		return ErrWritePlaneDisabled
	}
	if err := r.sem.Acquire(ctx); err != nil {
		return err
	}
	defer r.sem.Release()
	return r.pruneBuildCacheHeld(ctx, keep, onLine)
}

// PruneBuildCacheHeld is PruneBuildCache for a caller that ALREADY HOLDS the one-docker-child
// semaphore (the disk-pressure auto-GC, which holds the slot across the image + cache prune —
// calling the non-Held PruneBuildCache there would self-deadlock re-acquiring the one slot).
func (r *Runner) PruneBuildCacheHeld(ctx context.Context, keep string, onLine func(string)) error {
	if !r.writeAllowed {
		return ErrWritePlaneDisabled
	}
	return r.pruneBuildCacheHeld(ctx, keep, onLine)
}

func (r *Runner) pruneBuildCacheHeld(ctx context.Context, keep string, onLine func(string)) error {
	return r.runArgv(ctx, "", []string{"builder", "prune", "-a", "-f", r.keepStorageFlag(ctx), keep}, onLine)
}

// reconcileHelperImage is the tiny throwaway image (busybox has stat + chown) used to read and fix a
// data volume's ownership. Pinned to the same version as the backup helper.
const reconcileHelperImage = "busybox:1.36"

// ReconcileVolumeOwner ensures a named docker volume's root is owned by uid (recursively), but only
// when it currently differs — STAT-FIRST, so an already-correct volume costs one cheap helper-container
// run and no tree walk. It exists to heal the UID-drift class: a build image's user UID could shift
// when a package was added, and since Docker copies ownership onto a volume only while it is empty, a
// shifted UID left the app unable to write its own data. Running just before `up`, this restores the
// volume to the image's (now pinned) UID. Runs throwaway helper containers with STATIC argv (never a
// shell) under the §0 write gate + one-docker-child semaphore, like a deploy. `volName` is a
// compose-derived name and `uid` a fixed number — both are discrete argv elements. Returns whether it
// chowned. Best-effort by contract: the caller logs failures and never fails a deploy on them.
func (r *Runner) ReconcileVolumeOwner(ctx context.Context, volName string, uid int, onLine func(string)) (prevUID int, changed bool, err error) {
	if !r.writeAllowed {
		return 0, false, ErrWritePlaneDisabled
	}
	if uid <= 0 || !validVolumeName(volName) {
		return 0, false, fmt.Errorf("reconcile: invalid volume %q or uid %d", volName, uid)
	}
	if err := r.sem.Acquire(ctx); err != nil {
		return 0, false, err
	}
	defer r.sem.Release()

	// Read the current owner UID of the volume root (read-only mount; --network none — no network is
	// needed to stat/chown, only the volume is exposed, so the blast radius is that one volume).
	var out bytes.Buffer
	statArgv := []string{"run", "--rm", "--network", "none", "-v", volName + ":/v:ro", reconcileHelperImage, "stat", "-c", "%u", "/v"}
	if err := r.runStreamHeld(ctx, statArgv, &out, func(string) {}); err != nil {
		return 0, false, err
	}
	cur, err := strconv.Atoi(strings.TrimSpace(out.String()))
	if err != nil {
		return 0, false, fmt.Errorf("reconcile: could not read owner of volume %q: %v", volName, err)
	}
	if cur == uid {
		return cur, false, nil // already correct — the common case, no tree walk
	}
	chownArgv := []string{"run", "--rm", "--network", "none", "-v", volName + ":/v", reconcileHelperImage, "chown", "-R", fmt.Sprintf("%d:%d", uid, uid), "/v"}
	if err := r.runStreamHeld(ctx, chownArgv, io.Discard, onLine); err != nil {
		return cur, false, err // chown failed — ownership is unchanged (still cur)
	}
	return cur, true, nil // returns the PRIOR owner so the caller can roll back if the deploy then fails
}

// validVolumeName bounds a docker volume name to the safe character set docker itself allows
// ([a-zA-Z0-9][a-zA-Z0-9_.-]*), so a compose-derived name can never smuggle an argv/option.
func validVolumeName(s string) bool {
	if s == "" || len(s) > 255 || strings.HasPrefix(s, "-") {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// RunStream execs `docker <argv...>` and streams its RAW stdout bytes to `stdout` (an
// io.Writer — e.g. the tar→gzip→encrypt backup pipeline), while stderr is line-truncated to
// onErrLine for logging. Unlike Run, stdout is NOT line-buffered or merged with stderr, so a
// binary dump/tar stream passes through byte-for-byte. Static argv only (Mooring-authored,
// never operator input); it runs under the §0 write gate + the one-docker-child semaphore and
// reaps the process group on ctx cancel. Used for backup SIDECARS (`docker run --rm … pg_dump`
// / `… tar`) — a fresh one-shot container, never an exec into a running one.
func (r *Runner) RunStream(ctx context.Context, argv []string, stdout io.Writer, onErrLine func(string)) error {
	if !r.writeAllowed {
		return ErrWritePlaneDisabled
	}
	if err := r.sem.Acquire(ctx); err != nil {
		return err
	}
	defer r.sem.Release()
	return r.runStreamHeld(ctx, argv, stdout, onErrLine)
}

// RunStreamHeld is RunStream for a caller that ALREADY HOLDS the one-docker-child semaphore
// (the backup scheduler, which TryAcquires so it never queues a docker child). It must not be
// called without holding the semaphore.
func (r *Runner) RunStreamHeld(ctx context.Context, argv []string, stdout io.Writer, onErrLine func(string)) error {
	if !r.writeAllowed {
		return ErrWritePlaneDisabled
	}
	return r.runStreamHeld(ctx, argv, stdout, onErrLine)
}

func (r *Runner) runStreamHeld(ctx context.Context, argv []string, stdout io.Writer, onErrLine func(string)) error {
	cmd := exec.CommandContext(ctx, r.binary, argv...)
	cmd.Env = minimalEnv()
	setPgid(cmd)                                        // own process group (unix)
	cmd.Cancel = func() error { return killGroup(cmd) } // kill the group on ctx cancel
	cmd.WaitDelay = 5 * time.Second

	cmd.Stdout = stdout // raw bytes straight to the sink (no truncation, no line-buffering)
	pr, pw := io.Pipe()
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		pw.Close()
		return err
	}
	// Drain stderr line-by-line with truncation, off the command goroutine.
	done := make(chan struct{})
	go func() {
		defer close(done)
		reader := bufio.NewReaderSize(pr, maxLineBytes)
		for {
			line, err := readLineTruncated(reader)
			if line != "" && onErrLine != nil {
				onErrLine(line)
			}
			if err != nil {
				return
			}
		}
	}()

	waitErr := cmd.Wait()
	pw.Close() // unblock the stderr reader
	<-done
	return waitErr
}

// CaptureTry runs `docker <argv...>` and returns its captured stdout, WITHOUT ever queuing: if the
// one-docker-child slot is held it returns ErrBusy immediately (skip-don't-queue, like the
// cron/backup/GC paths) so a slow child — e.g. a registry round-trip — can never stall a deploy that
// is waiting on the slot. stderr is discarded (metadata reads don't need it). Static argv only
// (Mooring-authored, never operator input); runs under the §0 write gate and reaps the process group
// on ctx cancel. The caller MUST bound ctx with a timeout. Used by the image-update checker to read
// the local + registry image digests (`docker image inspect` / `docker buildx imagetools inspect`).
func (r *Runner) CaptureTry(ctx context.Context, argv []string) (string, error) {
	if !r.writeAllowed {
		return "", ErrWritePlaneDisabled
	}
	if !r.sem.TryAcquire() {
		return "", ErrBusy
	}
	defer r.sem.Release()
	var out bytes.Buffer
	err := r.runStreamHeld(ctx, argv, &out, nil)
	return out.String(), err
}

// RunStreamStdin execs `docker <argv...>` feeding `stdin` to the child's STDIN (e.g. a
// decrypted+gunzipped tar stream piped into a `docker run -i … tar -x` restore sidecar),
// while stdout+stderr are line-truncated to onLine. Static argv only (Mooring-authored); runs
// under the §0 write gate + the one-docker-child semaphore and reaps the process group on ctx
// cancel. The counterpart of RunStream for the RESTORE direction.
func (r *Runner) RunStreamStdin(ctx context.Context, argv []string, stdin io.Reader, onLine func(string)) error {
	if !r.writeAllowed {
		return ErrWritePlaneDisabled
	}
	if err := r.sem.Acquire(ctx); err != nil {
		return err
	}
	defer r.sem.Release()
	return r.runStreamStdinHeld(ctx, argv, stdin, onLine)
}

// RunStreamStdinHeld is RunStreamStdin for a caller that ALREADY HOLDS the semaphore.
func (r *Runner) RunStreamStdinHeld(ctx context.Context, argv []string, stdin io.Reader, onLine func(string)) error {
	if !r.writeAllowed {
		return ErrWritePlaneDisabled
	}
	return r.runStreamStdinHeld(ctx, argv, stdin, onLine)
}

func (r *Runner) runStreamStdinHeld(ctx context.Context, argv []string, stdin io.Reader, onLine func(string)) error {
	cmd := exec.CommandContext(ctx, r.binary, argv...)
	cmd.Env = minimalEnv()
	setPgid(cmd)
	cmd.Cancel = func() error { return killGroup(cmd) }
	cmd.WaitDelay = 5 * time.Second
	cmd.Stdin = stdin

	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		pw.Close()
		return err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		reader := bufio.NewReaderSize(pr, maxLineBytes)
		for {
			line, err := readLineTruncated(reader)
			if line != "" && onLine != nil {
				onLine(line)
			}
			if err != nil {
				return
			}
		}
	}()
	waitErr := cmd.Wait()
	pw.Close()
	<-done
	return waitErr
}

// PruneImages reclaims DANGLING (untagged, unreferenced) images — the superseded builds that
// pile up as apps redeploy and are the usual disk hog. `docker image prune -f` NEVER removes
// an image referenced by a container (running OR stopped) or a tagged image, so it frees only
// genuine garbage; and since a Mooring rollback rebuilds its image, this can't break rollback.
// Runs under the §0 write gate + the one-docker-child semaphore. Output (incl. "Total
// reclaimed space") streams to onLine.
func (r *Runner) PruneImages(ctx context.Context, onLine func(string)) error {
	if !r.writeAllowed {
		return ErrWritePlaneDisabled
	}
	if err := r.sem.Acquire(ctx); err != nil {
		return err
	}
	defer r.sem.Release()
	return r.runArgv(ctx, "", []string{"image", "prune", "-f"}, onLine)
}

// PruneImagesHeld is PruneImages for a caller that ALREADY HOLDS the one-docker-child
// semaphore (the disk-pressure auto-GC, which TryAcquires so it never queues a docker child).
func (r *Runner) PruneImagesHeld(ctx context.Context, onLine func(string)) error {
	if !r.writeAllowed {
		return ErrWritePlaneDisabled
	}
	return r.runArgv(ctx, "", []string{"image", "prune", "-f"}, onLine)
}

// ReapOneOffHeld force-removes any orphaned ONE-SHOT (`compose run`) containers of a project —
// the leftovers a KILLED `run --rm` CLI (timeout/shutdown) couldn't remove itself. Best-effort:
// all errors are ignored. The CALLER must hold the one-docker-child semaphore (the cron
// scheduler, which runs one task at a time, so no live one-shot is being reaped).
func (r *Runner) ReapOneOffHeld(ctx context.Context, project string) {
	if !r.writeAllowed || project == "" {
		return
	}
	var out strings.Builder
	_ = r.runStreamHeld(ctx, []string{"ps", "-aq", "--no-trunc",
		"--filter", "label=com.docker.compose.project=" + project,
		"--filter", "label=com.docker.compose.oneoff=True"}, &out, nil)
	var ids []string
	for _, line := range strings.Split(out.String(), "\n") {
		if id := strings.TrimSpace(line); id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return
	}
	_ = r.runArgv(ctx, "", append([]string{"rm", "-f"}, ids...), nil)
}

// RemoveContainers force-removes containers by id (`docker rm -f <id>...`) — write-plane, §0
// resource-gated, acquiring the one-docker-child semaphore. It does NO scoping of its own: the
// CALLER must pass only ids it has already verified belong to the intended project (the web-layer
// conflict reconcile resolves each id's compose project/service label over the READ plane first,
// so a foreign or system container is never passed here). Returns the rm exit error (if any).
func (r *Runner) RemoveContainers(ctx context.Context, ids []string, onLine func(string)) error {
	if !r.writeAllowed {
		return ErrWritePlaneDisabled
	}
	if len(ids) == 0 {
		return nil
	}
	if err := r.sem.Acquire(ctx); err != nil {
		return err
	}
	defer r.sem.Release()
	return r.RemoveContainersHeld(ctx, ids, onLine)
}

// RemoveContainersHeld is RemoveContainers for a caller that ALREADY HOLDS the one-docker-child
// semaphore (e.g. the self-heal remediation path, which runs its `up` via RunHeld). It must not
// be called without holding the semaphore. Same no-scoping contract as RemoveContainers.
func (r *Runner) RemoveContainersHeld(ctx context.Context, ids []string, onLine func(string)) error {
	if !r.writeAllowed {
		return ErrWritePlaneDisabled
	}
	if len(ids) == 0 {
		return nil
	}
	return r.runArgv(ctx, "", append([]string{"rm", "-f"}, ids...), onLine)
}

// keepStorageFlag returns the correct "keep this much cache" flag for `docker builder
// prune` on this host. Newer BuildKit renamed --keep-storage → --reserved-space (the old
// name prints a deprecation warning and will be removed); older Docker only knows
// --keep-storage. Probed once from `--help` — a daemon-less, instant CLI call — and cached.
func (r *Runner) keepStorageFlag(ctx context.Context) string {
	r.keepFlagOnce.Do(func() {
		r.keepFlag = "--keep-storage" // older Docker default
		out, err := exec.CommandContext(ctx, r.binary, "builder", "prune", "--help").CombinedOutput()
		if err == nil && strings.Contains(string(out), "--reserved-space") {
			r.keepFlag = "--reserved-space"
		}
	})
	return r.keepFlag
}

// runArgv execs `docker <argv...>` in dir, streaming truncated output to onLine, with a
// dedicated process group reaped on ctx cancel. Shared by compose jobs and maintenance
// commands (build-cache prune). The argv is always static (no shell), keeping the
// no-command-injection discipline.
func (r *Runner) runArgv(ctx context.Context, dir string, argv []string, onLine func(string)) error {
	cmd := exec.CommandContext(ctx, r.binary, argv...)
	cmd.Dir = dir
	cmd.Env = minimalEnv()
	setPgid(cmd)                                        // own process group (unix)
	cmd.Cancel = func() error { return killGroup(cmd) } // kill the group on ctx cancel
	cmd.WaitDelay = 5 * time.Second

	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		pw.Close()
		return err
	}
	// Drain output line-by-line with truncation, off the command goroutine.
	done := make(chan struct{})
	go func() {
		defer close(done)
		reader := bufio.NewReaderSize(pr, maxLineBytes)
		for {
			line, err := readLineTruncated(reader)
			if line != "" && onLine != nil {
				onLine(line)
			}
			if err != nil {
				return
			}
		}
	}()

	waitErr := cmd.Wait()
	pw.Close() // unblock the reader
	<-done
	return waitErr
}

// readLineTruncated reads one line, discarding the remainder of any line longer
// than the reader's buffer so a hostile/huge log line can't be buffered whole.
func readLineTruncated(r *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		chunk, isPrefix, err := r.ReadLine()
		sb.Write(chunk)
		if sb.Len() > maxLineBytes {
			// keep only the cap; drain the rest of this physical line
			truncated := sb.String()[:maxLineBytes] + "…"
			for isPrefix && err == nil {
				_, isPrefix, err = r.ReadLine()
			}
			return truncated, err
		}
		if !isPrefix || err != nil {
			return sb.String(), err
		}
	}
}

// minimalEnv passes only what `docker compose` needs, never Mooring's full env
// (which could leak GOMEMLIMIT et al. or, later, secrets) to the child.
func minimalEnv() []string {
	var env []string
	for _, k := range []string{"PATH", "HOME", "TMPDIR", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "XDG_RUNTIME_DIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	// Disable BuildKit's default provenance/SBOM attestations. Without this, even a
	// FULLY-CACHED `compose up --build` re-exports the image wrapped in a fresh
	// attestation manifest (it embeds a build timestamp), which changes the image's
	// manifest-list digest every deploy — so Compose sees "the image changed" and
	// RECREATES the container of a service that didn't change at all (only its build
	// dir is cache-keyed, so the layers are CACHED, but the attestation churns the
	// digest). Turning attestations off makes a cached build reproduce the identical
	// digest, so unchanged build-services stay running across deploys. Provenance for a
	// locally-built app image (that never leaves the host) adds no supply-chain value
	// here; upstream-image integrity is handled by digest-pinning instead.
	env = append(env, "BUILDX_NO_DEFAULT_ATTESTATIONS=1")
	return env
}
