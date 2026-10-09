package web

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/definition"
)

// buildServiceNames returns every service that has a build: block, sorted — INCLUDING scheduled-only
// services. `up --build` builds only the services it brings up, and scheduled services are kept out of
// `up` by their compose profile, so a deploy that relied on `up --build` never rebuilt them: their
// image froze at the first `compose run` and kept running old code. The deploy builds this whole list
// explicitly instead (see deployRepoApp).
func buildServiceNames(def *definition.Definition) []string {
	var out []string
	for name, svc := range def.Spec.Compose.Services {
		if svc.Build != nil {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// buildAction is the compose argv (after the global flags) that builds exactly svcs. The services go
// after a `--` terminator; naming a profiled (scheduled) service enables its profile for this command
// only, which is what builds it. `--profile` is NOT used: it is a root flag that dockerexec would render
// after the subcommand, where compose rejects it.
func buildAction(svcs []string) []string {
	return append([]string{"build", "--"}, svcs...)
}

// withoutScheduled drops scheduled-only services from svcs. Naming a profiled service in
// `up … -- <svc>` enables its profile and STARTS it as a long-running container — the exact thing the
// profile exists to prevent — so no recreate path may ever name one.
func withoutScheduled(def *definition.Definition, svcs []string) []string {
	if def == nil || len(svcs) == 0 {
		return svcs
	}
	sched := def.Spec.ScheduledServiceSet()
	if len(sched) == 0 {
		return svcs
	}
	out := make([]string, 0, len(svcs))
	for _, s := range svcs {
		if !sched[s] {
			out = append(out, s)
		}
	}
	return out
}

// isScheduledService reports whether svc is a scheduled-only service in def.
func isScheduledService(def *definition.Definition, svc string) bool {
	if def == nil || svc == "" {
		return false
	}
	return def.Spec.ScheduledServiceSet()[svc]
}

// imageRef is compose's default image name for a build service with no `image:` key: <project>-<service>.
// The generator never sets `image:` on build services, and the project name is the slug.
func imageRef(slug, svc string) string { return slug + "-" + svc }

// imageInspectArgv is the static docker argv that reports, for each build image, its id, creation time and
// tags: `docker image inspect --format '{{.Id}} {{.Created}} {{join .RepoTags ","}}' -- <slug>-<svc>...`.
// The refs come only from validated slug and service names.
func imageInspectArgv(slug string, svcs []string) []string {
	argv := []string{"image", "inspect", "--format", `{{.Id}} {{.Created}} {{join .RepoTags ","}}`, "--"}
	for _, s := range svcs {
		argv = append(argv, imageRef(slug, s))
	}
	return argv
}

var imageIDRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// serviceImageRef is the image a service's containers run: compose's <slug>-<service> for a build service,
// else the definition's image.
func serviceImageRef(slug, name string, svc definition.Service) string {
	if svc.Build != nil {
		return imageRef(slug, name)
	}
	return svc.Image
}

// imageIDArgv is the static docker argv that prints one image's id: `docker image inspect --format
// {{.Id}} -- <ref>`. The ref comes from a validated slug and service name, or the definition's image.
func imageIDArgv(ref string) []string {
	return []string{"image", "inspect", "--format", "{{.Id}}", "--", ref}
}

// parseImageID returns the image id printed by imageIDArgv, or "" unless the output is exactly one id.
func parseImageID(out string) string {
	if f := strings.Fields(out); len(f) == 1 && imageIDRe.MatchString(f[0]) {
		return f[0]
	}
	return ""
}

// serviceImageIDs returns the local image id each service's containers would run now (serviceImageRef,
// inspected once per distinct ref). A service whose image can't be inspected has no entry.
func (s *Server) serviceImageIDs(ctx context.Context, slug string, def *definition.Definition, services []string) map[string]string {
	ids := map[string]string{}
	byRef := map[string]string{}
	for _, name := range services {
		ref := serviceImageRef(slug, name, def.Spec.Compose.Services[name])
		if ref == "" {
			continue
		}
		id, done := byRef[ref]
		if !done {
			var out bytes.Buffer
			ictx, cancel := context.WithTimeout(ctx, 30*time.Second)
			if err := s.runner.RunStream(ictx, imageIDArgv(ref), &out, nil); err == nil {
				id = parseImageID(out.String())
			}
			cancel()
			byRef[ref] = id
		}
		if id != "" {
			ids[name] = id
		}
	}
	return ids
}

// imageIDHeld returns the local image id ref points at, or "" when no such image exists (a service never built
// yet). Any other failure is an error. The caller holds the docker slot.
func (s *Server) imageIDHeld(ctx context.Context, ref string) (string, error) {
	var out bytes.Buffer
	var stderr []string
	if err := s.runner.RunStreamHeld(ctx, imageIDArgv(ref), &out, func(l string) { stderr = append(stderr, l) }); err != nil {
		for _, l := range stderr {
			if strings.Contains(strings.ToLower(l), "no such image") {
				return "", nil
			}
		}
		if len(stderr) > 0 {
			return "", fmt.Errorf("%w: %s", err, deployText(stderr[len(stderr)-1], 300))
		}
		return "", err
	}
	id := parseImageID(out.String())
	if id == "" {
		return "", fmt.Errorf("unexpected docker image inspect output %q", deployText(out.String(), 200))
	}
	return id, nil
}

type imageInfo struct {
	ID      string
	Created time.Time
}

// parseImageReport maps each build service to its image from `docker image inspect` output (one line per
// image found; a missing ref just has no line). Lines are matched to services by tag, never by position,
// and anything malformed is ignored — the output is advisory.
func parseImageReport(out, slug string, svcs []string) map[string]imageInfo {
	want := make(map[string]string, len(svcs)*2)
	for _, s := range svcs {
		want[imageRef(slug, s)] = s
		want[imageRef(slug, s)+":latest"] = s
	}
	res := map[string]imageInfo{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) != 3 || !imageIDRe.MatchString(f[0]) {
			continue
		}
		created, err := time.Parse(time.RFC3339Nano, f[1])
		if err != nil {
			continue
		}
		for _, tag := range strings.Split(f[2], ",") {
			if svc, ok := want[tag]; ok {
				if _, seen := res[svc]; !seen {
					res[svc] = imageInfo{ID: f[0], Created: created}
				}
			}
		}
	}
	return res
}

// imageReportLines renders one deploy-log line per build service: its image id and creation time, marked
// as rebuilt by this deploy or unchanged (a full build-cache hit keeps the original creation time and id).
func imageReportLines(slug string, svcs []string, got map[string]imageInfo, buildStart time.Time) []string {
	lines := make([]string, 0, len(svcs))
	for _, s := range svcs {
		info, ok := got[s]
		if !ok {
			lines = append(lines, fmt.Sprintf("image %s: not found (expected %s)", s, imageRef(slug, s)))
			continue
		}
		state := "built by this deploy"
		if info.Created.Before(buildStart) {
			state = "unchanged, build cache"
		}
		lines = append(lines, fmt.Sprintf("image %s: %s created %s (%s)", s,
			strings.TrimPrefix(info.ID, "sha256:")[:12], info.Created.UTC().Format("2006-01-02 15:04:05 UTC"), state))
	}
	return lines
}

// reportBuiltImages streams the per-service image report after a build. Best-effort: any error only skips
// the report (it never fails a deploy). Uses the blocking runner so it can't be randomly skipped the way a
// TryAcquire capture would be while other docker work is queued.
func (s *Server) reportBuiltImages(ctx context.Context, slug string, svcs []string, buildStart time.Time, onLine func(string)) {
	if s.runner == nil || len(svcs) == 0 {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out bytes.Buffer
	// A missing ref makes the CLI exit non-zero while still printing the images it found, so the error
	// is ignored and whatever parsed is reported.
	_ = s.runner.RunStream(rctx, imageInspectArgv(slug, svcs), &out, nil)
	for _, l := range imageReportLines(slug, svcs, parseImageReport(out.String(), slug, svcs), buildStart) {
		onLine(l)
	}
}
