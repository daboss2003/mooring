package web

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/docker"
)

// conflictRe matches Docker's "container name already in use" daemon error and captures the id of
// the container HOLDING the name. Both the plain and the "Error when allocating new name" variants
// end in `... is already in use by container "<id>"`. We key on the immutable hex id, never the
// (reusable, ambiguous) name.
var conflictRe = regexp.MustCompile(`is already in use by container "([0-9a-f]{12,64})"`)

// hexIDRe validates a docker container id (short or full) before it's ever used.
var hexIDRe = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

// recreateArtifactRe matches Compose's recreate BACKUP name shape `<id[:12]>_<name>` — the strand
// an interrupted `--force-recreate` leaves behind. It carries NO slug/service (so it can't collide
// across apps); the compose project LABEL is the authoritative scope. Used only as an ADDITIONAL
// signal on top of a positive label match, never as an alternative to it.
var recreateArtifactRe = regexp.MustCompile(`^[0-9a-f]{8,}_`)

// runUp runs the `up` job with the given onLine — either runner.Run or runner.RunHeld, chosen by
// the caller so the one-docker-child semaphore is acquired (or not) correctly for its path.
type runUp func(ctx context.Context, onLine func(string)) error

// removeContainers force-removes verified container ids — runner.RemoveContainers or
// RemoveContainersHeld, matching runUp's semaphore flavor.
type removeContainers func(ctx context.Context, ids []string, onLine func(string)) error

// runUpWithConflictReap runs an `up` and, if it fails with a docker "name already in use" conflict
// caused by THIS app's OWN stranded container (an interrupted --force-recreate strand), reaps the
// offending container(s) and retries the up ONCE. Strictly scoped and fail-closed: it only removes
// containers whose LIVE compose labels prove project==slug AND service∈declared (never a protected
// project, never a foreign/unlabeled squatter), and it reaps by the immutable id, never the parsed
// name. On a second failure — or when nothing is safely reapable — it returns the original up error
// (recovery already attempted; a human must look).
//
// The reap runs AFTER up returns (never inside onLine, which fires while the docker-child semaphore
// is held — reaping there would self-deadlock). `declared` is this app's set of service names.
func (s *Server) runUpWithConflictReap(ctx context.Context, slug string, declared map[string]bool, up runUp, remove removeContainers, onLine func(string)) error {
	var conflictID string
	scan := func(line string) {
		if onLine != nil {
			onLine(line)
		}
		if conflictID == "" {
			if m := conflictRe.FindStringSubmatch(line); m != nil {
				conflictID = m[1]
			}
		}
	}
	err := up(ctx, scan)
	if err == nil || conflictID == "" {
		return err // success, or a failure that isn't a name conflict → nothing to reconcile
	}
	ids, names, rerr := s.conflictReapSet(ctx, slug, declared, conflictID)
	if rerr != nil {
		emit(onLine, "could not auto-recover the name conflict ("+rerr.Error()+") — not touching anything; resolve it and redeploy")
		return err
	}
	if len(ids) == 0 {
		emit(onLine, "the name conflict isn't from a reclaimable Mooring container (foreign or unlabeled) — left untouched; `docker rm -f` it and redeploy")
		return err
	}
	emit(onLine, "reclaimed stuck container(s) left by an interrupted recreate: "+strings.Join(names, ", ")+" — retrying the deploy")
	// Best-effort removal: `docker rm -f` on an already-removing/dead sibling can error harmlessly
	// ("already in progress" / "No such container"), and one batched non-zero exit must NOT suppress
	// the recovery when the actual name-holder was removed. The retry up() is the real test of
	// whether the conflicting name is now free (and it's bounded — a still-blocked up just fails).
	if remErr := remove(ctx, ids, onLine); remErr != nil {
		emit(onLine, "note: some stuck containers reported a removal error ("+remErr.Error()+") — retrying anyway")
	}
	return up(ctx, onLine) // one bounded retry
}

// conflictReapSet resolves — over the READ plane only — the SAFE set of container ids to reap for a
// name conflict, STRICTLY within project==slug: the container holding the conflicting name (by id)
// PLUS this project's other terminal recreate strands (so a multi-service strand clears in one
// pass). Every id requires a positive live-label match (project + declared service); protected
// projects are refused. The preventive sweep of NON-holder siblings only removes clearly
// un-reconcilable strands (Dead/Removing, or a non-running recreate artifact) — it never SIGKILLs a
// running sibling. If the actual blocker isn't one of this app's labeled containers (a foreign or
// unlabeled squatter), it returns an empty set — reaping unrelated strands wouldn't clear the
// conflict, so the deploy correctly surfaces the original error.
func (s *Server) conflictReapSet(ctx context.Context, slug string, declared map[string]bool, conflictID string) (ids, names []string, err error) {
	if s.docker == nil || s.runner == nil {
		return nil, nil, fmt.Errorf("read or write plane unavailable")
	}
	if s.cfg != nil && s.cfg.IsProtectedProject(slug) {
		return nil, nil, fmt.Errorf("%q is a protected project", slug)
	}
	if !hexIDRe.MatchString(conflictID) {
		return nil, nil, fmt.Errorf("no well-formed container id in the conflict error")
	}
	all, lerr := s.docker.ListContainers(ctx, true) // all=true: include stopped/dead strands
	if lerr != nil {
		return nil, nil, lerr
	}
	ids, names, holderFound := selectConflictReap(all, slug, declared, conflictID)
	if !holderFound {
		// The name-holder is not one of our labeled containers — we can't safely clear THIS
		// conflict, and reaping unrelated strands wouldn't help. Fail closed (surface the error).
		return nil, nil, nil
	}
	return ids, names, nil
}

// selectConflictReap is the pure scoping decision: given the live container list, pick the ids
// (and names, for logging) that are SAFE to force-remove for a name conflict in `slug`, and report
// whether the conflicting name-holder itself was found among this app's own containers. Every
// selected container must satisfy the MANDATORY label gate (project==slug AND service∈declared) —
// so the cross-app name-collision seam is closed by the LABEL, never the (ambiguous) name. The
// holder (matched by immutable id) is always selected; other siblings only if they're
// un-reconcilable strands (reapableStrand), never a running instance.
func selectConflictReap(all []docker.Container, slug string, declared map[string]bool, conflictID string) (ids, names []string, holderFound bool) {
	for _, c := range all {
		if c.Project() != slug || !declared[c.Service()] {
			continue
		}
		if idMatch(c.ID, conflictID) {
			holderFound = true // the blocker itself — reaped regardless of state; the retry recreates it
		} else if !reapableStrand(c) {
			continue // a healthy/intended sibling — leave it for compose to reconcile
		}
		ids = append(ids, c.ID)
		names = append(names, c.Name())
	}
	return ids, names, holderFound
}

// reapableStrand reports whether a NON-holder sibling of this project is an un-reconcilable strand
// safe to force-remove preventively: a Dead/Removing container, or a non-running recreate artifact.
// A running container is never swept (never SIGKILL a live instance).
func reapableStrand(c docker.Container) bool {
	st := strings.ToLower(strings.TrimSpace(c.State))
	if st == "dead" {
		return true // docker can't reconcile a dead container; force-removing it frees the name
	}
	// A non-running recreate BACKUP artifact is a strand worth sweeping. A `removing` container is
	// self-clearing (rm -f would only error), and running/restarting are live — never swept.
	return recreateArtifactRe.MatchString(c.Name()) && !isRunning(c) && st != "removing"
}

// idMatch reports whether a full container id matches the (possibly short) id from the daemon
// error — either is a hex prefix of the other.
func idMatch(fullID, errID string) bool {
	if fullID == "" || errID == "" {
		return false
	}
	return fullID == errID || strings.HasPrefix(fullID, errID) || strings.HasPrefix(errID, fullID)
}

func emit(onLine func(string), msg string) {
	if onLine != nil {
		onLine(msg)
	}
}

// streamOOMHint inspects THIS app's service containers over the READ plane after a failed deploy
// and, if any was OOM-killed (State.OOMKilled, or the canonical 137 exit), streams a one-line hint
// so the operator fixes the real cause (a memory-tight box) instead of re-triggering the same
// interrupted-recreate strand. Best-effort and read-only — never blocks or fails the deploy, and
// never touches the write plane.
func (s *Server) streamOOMHint(ctx context.Context, slug string, declared map[string]bool, onLine func(string)) {
	if s.docker == nil || onLine == nil {
		return
	}
	// Bounded: an advisory line must never dominate the failure path. Cap total time and the number
	// of inspects, and skip running containers (an OOM-killed one isn't running).
	octx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	all, err := s.docker.ListContainers(octx, true)
	if err != nil {
		return
	}
	const maxInspect = 12
	n := 0
	for _, c := range all {
		if c.Project() != slug || !declared[c.Service()] || isRunning(c) {
			continue
		}
		if n >= maxInspect {
			return
		}
		n++
		ci, ierr := s.docker.InspectContainer(octx, c.ID)
		if ierr != nil {
			continue
		}
		// OOMKilled is Docker's authoritative OOM signal. Exit 137 alone is any SIGKILL (stop-timeout
		// escalation, `docker kill`, our own rm -f), so it must NOT be treated as OOM on its own.
		if ci.State.OOMKilled {
			onLine(fmt.Sprintf("⚠ a container was OOM-killed (%s) — this box looks memory-tight, which is what strands a mid-recreate container. Add/free RAM or lower the service's mem_limit, then redeploy.", c.Name()))
			return
		}
	}
}

// isRunning reports whether a container is live (so the preventive sweep / OOM scan skips it).
func isRunning(c docker.Container) bool {
	st := strings.ToLower(strings.TrimSpace(c.State))
	return st == "running" || st == "restarting"
}

// declaredServiceSet returns the set of service names an app declares (its compose services) —
// the scope a conflict reap is confined to (only THIS app's own services may ever be reaped).
func declaredServiceSet(def *definition.Definition) map[string]bool {
	out := make(map[string]bool, len(def.Spec.Compose.Services))
	for name := range def.Spec.Compose.Services {
		out[name] = true
	}
	return out
}

// reapScope returns the service-name scope for a conflict reap on a path that doesn't carry the
// definition (lifecycle redeploy, self-heal): the canonical def's services when available, else
// the services THIS project currently has containers for. Either way it stays confined to the
// project (project==slug is still enforced in conflictReapSet); this only bounds WHICH of the
// app's own services may be reaped.
func (s *Server) reapScope(ctx context.Context, slug string) map[string]bool {
	if s.defStore != nil {
		if def, err := s.defStore.Current(slug); err == nil && def != nil {
			if d := declaredServiceSet(def); len(d) > 0 {
				return d
			}
		}
	}
	out := map[string]bool{}
	if s.docker != nil {
		if all, err := s.docker.ListContainers(ctx, true); err == nil {
			for _, c := range all {
				if c.Project() == slug {
					if svc := c.Service(); svc != "" {
						out[svc] = true
					}
				}
			}
		}
	}
	return out
}
