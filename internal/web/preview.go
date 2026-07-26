package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/envstore"
)

// preview.go implements per-PR ephemeral environments: a GitHub `pull_request` webhook spins up
// a throwaway app instance for a pull request (its own subdomain + HTTPS via the base_domain
// wildcard), and tears it down when the PR closes. Everything here is OPT-IN per base app and
// deliberately scoped: an unattended webhook can only create/destroy PREVIEW apps derived from
// its own base app (never a real app).

// previewSlugRe matches a generated preview slug (same shape as a connect slug).
var previewSlugRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)

// verifyGitHubSig verifies GitHub's `X-Hub-Signature-256: sha256=<hex>` HMAC over the RAW
// request body with the shared webhook secret. Constant-time; fail-closed on any malformed
// header. This is the whole trust boundary for the PR webhook — get it exactly right.
func verifyGitHubSig(secret, body []byte, header string) bool {
	const prefix = "sha256="
	if len(secret) == 0 || !strings.HasPrefix(header, prefix) {
		return false
	}
	want, err := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil || len(want) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), want)
}

// prEvent is the slice of a GitHub pull_request webhook payload we act on.
type prEvent struct {
	Action string // "opened" | "reopened" | "synchronize" | "closed" | …
	Number int    // the PR number
	Ref    string // head branch name (informational)
}

// parsePREvent extracts the fields we need from a pull_request webhook body. ok=false if it's
// not a well-formed pull_request event with a positive number.
func parsePREvent(body []byte) (prEvent, bool) {
	var p struct {
		Action      string `json:"action"`
		Number      int    `json:"number"`
		PullRequest struct {
			Head struct {
				Ref string `json:"ref"`
			} `json:"head"`
		} `json:"pull_request"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return prEvent{}, false
	}
	if p.Action == "" || p.Number <= 0 {
		return prEvent{}, false
	}
	return prEvent{Action: p.Action, Number: p.Number, Ref: p.PullRequest.Head.Ref}, true
}

// prIsOpen reports whether an action means the PR is open/updated (deploy) vs closed (teardown).
func prIsOpen(action string) bool {
	switch action {
	case "opened", "reopened", "synchronize", "ready_for_review":
		return true
	default:
		return false
	}
}

// previewSlug derives the deterministic slug for a base app's PR preview: "<base>-pr<n>". It
// fails (ok=false) if the result isn't a valid slug (e.g. the base is too long) or the number
// is out of range — so a preview is never created under a malformed/oversized name.
func previewSlug(base string, number int) (string, bool) {
	if number <= 0 || number > 9_999_999 {
		return "", false
	}
	slug := fmt.Sprintf("%s-pr%d", base, number)
	if !previewSlugRe.MatchString(slug) {
		return "", false
	}
	return slug, true
}

// previewRef is the git ref a PR preview deploys — GitHub exposes the PR head under
// refs/pull/<n>/head, which is fetchable without the fork's write access.
func previewRef(number int) string {
	return fmt.Sprintf("refs/pull/%d/head", number)
}

// applyPreviewPrefix rewrites a preview app's EDGE ROUTES to unique subdomains derived from its
// slug, so a preview can NEVER collide with production regardless of how the base app exposed
// itself (subdomain OR fixed hostname). One exposed route → "<slug>"; multiple → "<slug>-<i>"
// (index-based, so the label is always valid). The namespace wildcard cert covers them, so
// HTTPS is automatic. Cert-bindings (an app terminating its own TLS on a fixed hostname) are
// left untouched — such an app can't have a preview and fails closed on the route-collision
// check rather than ever affecting production.
//
// baseNamespace PINS the preview to the BASE app's edge namespace (config.yaml
// edge.base_domains name, or "" for the default base_domain). The whole def comes from the
// untrusted PR head, so we OVERWRITE its app-level base_domain and CLEAR every per-item
// base_domain — a fork PR must not be able to aim its preview at a different namespace's
// wildcard than the base app uses.
func applyPreviewPrefix(def *definition.Definition, slug, baseNamespace string) {
	routes := def.Spec.Edge.Routes
	multi := len(routes) > 1
	for i := range routes {
		sub := slug
		if multi {
			sub = fmt.Sprintf("%s-%d", slug, i)
		}
		routes[i].Subdomain = sub
		routes[i].Hostname = ""   // drop any fixed hostname so it can't collide with prod
		routes[i].BaseDomain = "" // drop any per-route namespace the fork chose
	}
	// Pin the whole preview to the base app's namespace (never the fork's choice).
	def.Spec.Edge.BaseDomain = baseNamespace
	// The whole mooring.yaml comes from the (untrusted) PR head, so STRIP anything a fork could
	// aim at production: cert_bindings (which would copy an already-issued TLS private key — for
	// ANY hostname the edge has a cert for — into the fork's container) and L4 routes (which
	// claim a real host listener). A preview is reachable ONLY via its wildcard subdomain, so it
	// needs neither.
	for name := range def.Spec.Compose.Services {
		svc := def.Spec.Compose.Services[name] // map value: mutate a copy, write it back
		svc.CertBindings = nil
		// Also drop host-port publishing: a fork PR could otherwise bind a raw 0.0.0.0 host port
		// (bypassing the edge/TLS) or squat a fixed host port a production app needs. A preview is
		// reachable ONLY via its wildcard subdomain, so no service publishes to the host.
		for i := range svc.Ports {
			svc.Ports[i].Publish = false
			svc.Ports[i].Public = false
			svc.Ports[i].Published = 0
		}
		def.Spec.Compose.Services[name] = svc
	}
	def.Spec.Edge.L4Routes = nil
}

// basePreviewNamespace resolves which edge namespace a preview of `base` must be PINNED to — the
// base app's own namespace, never the fork PR's choice. It is fail-CLOSED: if the base app's
// canonical can't be loaded (not deployed yet, or a store error) it returns an error so the
// preview is REFUSED, rather than silently homing fork code on the production default apex. When
// the base has no app-level default it recovers the namespace from the base's (already-expanded,
// literal) route/cert hostnames; a base spanning multiple namespaces is an error (ambiguous).
func (s *Server) basePreviewNamespace(base string) (string, error) {
	if s.defStore == nil {
		return "", fmt.Errorf("preview: definition store unavailable")
	}
	bdef, err := s.defStore.Current(base)
	if err != nil {
		return "", fmt.Errorf("preview: cannot read base app %q definition: %w", base, err)
	}
	if bdef == nil {
		return "", fmt.Errorf("preview: base app %q has not been deployed yet — deploy it before previews can pin a namespace", base)
	}
	if ns := strings.TrimSpace(bdef.Spec.Edge.BaseDomain); ns != "" {
		return ns, nil // the app-level default namespace
	}
	// No app-level default: recover the namespace from the base's expanded hostnames.
	seen := map[string]bool{}
	var names []string
	consider := func(host string) {
		if host == "" {
			return
		}
		if name, ok := s.cfg.NamespaceForHost(host); ok && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	for _, r := range bdef.Spec.Edge.Routes {
		consider(r.Hostname)
	}
	for _, svc := range bdef.Spec.Compose.Services {
		for _, cb := range svc.CertBindings {
			consider(cb.Hostname)
		}
	}
	switch len(names) {
	case 0:
		return "", nil // base uses no namespaced subdomain → the default namespace
	case 1:
		return names[0], nil
	default:
		return "", fmt.Errorf("preview: base app %q spans multiple namespaces — set spec.edge.base_domain on it to pin previews", base)
	}
}

// prWebhookBodyLimit caps the PR webhook body (GitHub payloads are tens of KB; this is slack).
const prWebhookBodyLimit = 1 << 20

// previewTTL reaps a preview whose PR activity (last deploy/register) is older than this — a
// backstop for a "closed" event that never arrived.
const previewTTL = 14 * 24 * time.Hour

// maxPreviewsPerBase caps how many live previews one base app can accrue (a flood of PRs can't
// exhaust the host); refreshing an existing preview is always allowed.
const maxPreviewsPerBase = 10

// handlePreviewToggle turns per-PR preview environments on/off for a base app. Admin-gated:
// enabling it grants the app's webhook unattended authority to create + destroy preview apps.
func (s *Server) handlePreviewToggle(w http.ResponseWriter, r *http.Request) {
	if s.gitStore == nil {
		http.Error(w, "gitops unavailable", http.StatusServiceUnavailable)
		return
	}
	project := r.PathValue("project")
	if _, ok, _ := s.gitStore.Get(project); !ok {
		notFound(w)
		return
	}
	enabled := r.PostFormValue("enabled") == "on" || r.PostFormValue("enabled") == "1"
	if err := s.gitStore.SetPreviewEnabled(r.Context(), project, enabled); err != nil {
		http.Error(w, "could not update", http.StatusInternalServerError)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{
		Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "preview_toggle",
		Target: project, Outcome: audit.OK, Level: audit.Security, Detail: fmt.Sprintf("enabled=%v", enabled),
	})
	http.Redirect(w, r, "/apps/"+project+"/git", http.StatusSeeOther)
}

// handlePRWebhook is the GitHub `pull_request` webhook: allowlist- and auth-EXEMPT but gated by
// the app's HMAC secret over the raw body (GitHub's X-Hub-Signature-256), and only for a base
// app that opted into previews. On open/synchronize it (re)deploys a `pr-<n>` app; on close it
// tears that preview down. The teardown is SCOPED — it only ever touches an app that is a
// preview of THIS base — so a webhook can never destroy a real app.
func (s *Server) handlePRWebhook(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if s.gitStore == nil || token == "" {
		notFound(w) // never reveal whether the feature/token exists
		return
	}
	if !s.webhookRL.allow("pr:" + token) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	base, secret, ok := s.gitStore.WebhookLookup(token)
	if !ok {
		s.auditWebhook(r, "", audit.Deny, "unknown token")
		notFound(w)
		return
	}
	cfg, exists, _ := s.gitStore.Get(base)
	if !exists || !cfg.PreviewEnabled {
		s.auditWebhook(r, base, audit.Deny, "previews not enabled")
		notFound(w)
		return
	}
	// GitHub signs the RAW body — read it capped, then verify BEFORE trusting anything in it.
	body, err := io.ReadAll(io.LimitReader(r.Body, prWebhookBodyLimit))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !verifyGitHubSig(secret, body, r.Header.Get("X-Hub-Signature-256")) {
		s.auditWebhook(r, base, audit.Deny, "bad signature")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Only act on pull_request events (ignore ping/others with a 204 so GitHub shows success).
	if r.Header.Get("X-GitHub-Event") != "pull_request" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	ev, ok := parsePREvent(body)
	if !ok || (!prIsOpen(ev.Action) && ev.Action != "closed") {
		w.WriteHeader(http.StatusAccepted) // well-formed but nothing to do for this action
		return
	}
	// Only the DEPLOY path holds the single-flight gate (deployRepoApp is caller-holds-the-gate,
	// and it prevents a flood piling up). The TEARDOWN path must NOT hold it here: teardownApp
	// acquires the same non-reentrant docker semaphore ITSELF, so holding it across teardown
	// would self-deadlock (45s timeout, nothing deleted).
	open := prIsOpen(ev.Action)
	if open && !s.gitDeploy.TryAcquire() {
		s.auditWebhook(r, base, audit.OK, "busy; another git op in progress")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("busy\n"))
		return
	}
	s.auditWebhook(r, base, audit.OK, "pr #"+fmt.Sprint(ev.Number)+" "+ev.Action)
	go func() {
		if open {
			defer s.gitDeploy.Release()
		}
		defer func() {
			if rec := recover(); rec != nil { // a webhook processes untrusted input — never crash on it
				s.log.Error("preview webhook panic recovered", "base", base, "pr", ev.Number, "panic", rec)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), gitDeployTimeout)
		defer cancel()
		onLine := func(l string) { s.log.Info("preview", "base", base, "pr", ev.Number, "line", l) }
		if open {
			if err := s.createOrUpdatePreview(ctx, base, ev.Number, onLine); err != nil {
				s.log.Warn("preview deploy failed", "base", base, "pr", ev.Number, "err", err)
			}
		} else { // closed — teardownApp takes the docker gate itself
			if err := s.teardownPreview(ctx, base, ev.Number); err != nil {
				s.log.Warn("preview teardown failed", "base", base, "pr", ev.Number, "err", err)
			}
		}
	}()
	w.WriteHeader(http.StatusAccepted)
}

// createOrUpdatePreview registers (or refreshes) the ephemeral pr-<n> app, inherits the base
// app's env/secrets, fetches the PR head, and deploys it. The caller holds the gitDeploy gate.
func (s *Server) createOrUpdatePreview(ctx context.Context, base string, number int, onLine func(string)) error {
	// Write-plane guards, mirroring every other deploy path — a nil runner would otherwise panic
	// (crashing the process on one webhook), and a write lockout must be honoured.
	if s.runner == nil {
		return fmt.Errorf("preview: write plane unavailable")
	}
	if ok, reason := s.runner.WriteAllowed(); !ok {
		return fmt.Errorf("preview: %s", reason)
	}
	slug, ok := previewSlug(base, number)
	if !ok {
		return fmt.Errorf("preview: cannot form a valid slug for %q PR %d", base, number)
	}
	// Cap live previews per base (accretion guard); refreshing an EXISTING preview is always fine.
	if _, exists, _ := s.gitStore.Get(slug); !exists {
		if n, _ := s.gitStore.CountPreviews(base); n >= maxPreviewsPerBase {
			return fmt.Errorf("preview: %q is at its limit of %d live previews", base, maxPreviewsPerBase)
		}
	}
	if err := s.gitStore.RegisterPreview(ctx, base, slug, previewRef(number)); err != nil {
		return err
	}
	// Inherit only NON-secret env (literals/config) — NEVER the operator's pasted secrets, which
	// would otherwise be readable by arbitrary fork PR code. `generate:` secrets are minted fresh
	// per preview at deploy, so a preview's own internal DB still gets its own password.
	if s.envStore != nil {
		if entries, _, err := s.envStore.Current(base); err == nil {
			var safe []envstore.Entry
			for _, e := range entries {
				if !e.Secret {
					safe = append(safe, e)
				}
			}
			if len(safe) > 0 {
				_, _ = s.envStore.Save(ctx, slug, safe, "preview:"+base)
			}
		}
	}
	cfg, sha, err := s.doFetch(ctx, slug)
	if err != nil {
		return err
	}
	return s.deployRepoApp(ctx, cfg, sha, "preview", "webhook", false, onLine)
}

// teardownPreview removes the pr-<n> preview app — but ONLY if it is actually a preview of THIS
// base (the preview_of scope check). A real app, or a preview of a different base, is never
// touched: an unattended webhook can't delete production.
func (s *Server) teardownPreview(ctx context.Context, base string, number int) error {
	slug, ok := previewSlug(base, number)
	if !ok {
		return nil
	}
	cfg, exists, err := s.gitStore.Get(slug)
	if err != nil {
		return err
	}
	if !exists {
		return nil // already gone
	}
	if cfg.PreviewOf != base {
		return fmt.Errorf("preview: %q is not a preview of %q — refusing teardown", slug, base)
	}
	if gateErr, errs := s.teardownApp(ctx, slug); gateErr != nil {
		return gateErr
	} else if len(errs) > 0 {
		return fmt.Errorf("preview teardown: %d store(s) failed", len(errs))
	}
	return nil
}

// RunPreviewReaper is a daily backstop that tears down previews whose PR activity is older than
// previewTTL — so an abandoned PR (a "closed" event that never arrived) can't linger forever.
func (s *Server) RunPreviewReaper(ctx context.Context) {
	if s.gitStore == nil {
		return
	}
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.reapStalePreviews(ctx)
		}
	}
}

func (s *Server) reapStalePreviews(ctx context.Context) {
	before := time.Now().Add(-previewTTL).Unix()
	stale, err := s.gitStore.StalePreviews(before)
	if err != nil {
		return
	}
	for _, slug := range stale {
		if ctx.Err() != nil {
			return
		}
		cfg, exists, err := s.gitStore.Get(slug)
		if err != nil || !exists || cfg.PreviewOf == "" {
			continue // scope guard: only reap genuine previews
		}
		// teardownApp acquires the docker gate ITSELF — pre-acquiring here would self-deadlock on
		// the non-reentrant semaphore. Surface the gate error instead of logging a false success.
		if gateErr, _ := s.teardownApp(ctx, slug); gateErr != nil {
			s.log.Warn("preview reap: could not tear down", "slug", slug, "err", gateErr)
			continue
		}
		s.log.Info("preview reaped (stale)", "slug", slug, "preview_of", cfg.PreviewOf)
	}
}
