// Package web implements the HTTP control plane: the fail-closed request
// pipeline (plan §5), the auth/session handlers, and the admin UI shell. It
// binds loopback only (plan §3); the managed edge fronts the public ports.
package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daboss2003/mooring/internal/alertstore"
	"github.com/daboss2003/mooring/internal/apitoken"
	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/backupstore"
	"github.com/daboss2003/mooring/internal/cfgstore"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/crypto"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/docker"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/edge"
	"github.com/daboss2003/mooring/internal/envstore"
	"github.com/daboss2003/mooring/internal/github"
	"github.com/daboss2003/mooring/internal/gitstore"
	"github.com/daboss2003/mooring/internal/imagescan"
	"github.com/daboss2003/mooring/internal/l4"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/ops"
	"github.com/daboss2003/mooring/internal/provstore"
	"github.com/daboss2003/mooring/internal/scale"
	"github.com/daboss2003/mooring/internal/selfheal"
	"github.com/daboss2003/mooring/internal/session"
	"github.com/daboss2003/mooring/internal/setupstore"
	"github.com/daboss2003/mooring/internal/store"
	"github.com/daboss2003/mooring/internal/updatecheck"
)

// maxConcurrentLogStreams caps simultaneous live log streams (each holds a
// socket-proxy connection); excess returns 503.
const maxConcurrentLogStreams = 8

// secState is the slice of config that SIGHUP can hot-reload (plan §5.1:
// allowlist + auth, never keys/bind). It is swapped atomically so the request
// hot path never races a reload.
type secState struct {
	trustProxy     bool
	allowlist      []netip.Prefix
	trustedProxies []netip.Prefix
	username       string
	passwordHash   string
	totpSecret     string
	dummyHash      string
	// tokenCIDRUnion is the precomputed union of every ACTIVE API token's CIDR set.
	// The IP gate checks the unspoofable peer against this BEFORE any bearer is
	// parsed (so a token id is never an enumeration oracle and an unknown bearer
	// never triggers a DB lookup before the peer is admitted). It admits ONLY the
	// /api/v1 surface — never the browser admin plane — and the presented token is
	// still re-bound to its OWN CIDR at auth time (the union is a coarse gate, not
	// the grant). Recomputed on construction + SIGHUP; minting a token therefore
	// requires a reload to widen the gate (fail-closed: stale = narrower).
	tokenCIDRUnion []netip.Prefix
}

// loginVerifyConcurrency caps simultaneous argon2id verifications so a burst of
// concurrent logins can't OOM a tiny box (plan §5.1; review #10).
const loginVerifyConcurrency = 2

// apiVerifyConcurrency caps simultaneous API-token argon2id verifications. It is a
// SEPARATE pool from login so that a flood of junk-bearer API requests (each of which
// now pays a decoy verify for timing parity) can never starve operator logins.
const apiVerifyConcurrency = 2

// loginBodyLimit bounds the POST /login + logout request body — username +
// password + totp + csrf_token never approach this (review #11).
const loginBodyLimit = 64 << 10

// Deps are the (mostly optional) collaborators a Server uses. Anything nil
// degrades gracefully (e.g. nil mon → "collecting…"; nil runner → write plane
// shown disabled).
type Deps struct {
	DB          *store.DB
	ConfigPath  string               // for SIGHUP allowlist+auth reload
	Version     string               // the running Mooring build version (for the Server tab's .deb cleanup)
	UpdateCheck *updatecheck.Checker // self-update / security-advisory posture (nil when disabled)
	ImageScans  *imagescan.Store     // per-app Trivy scan results (surface on the Server tab)
	Log         *slog.Logger
	Monitor     *monitor.Monitor
	OpsStore    *ops.ConfigStore
	Prober      *ops.Prober
	Runner      *dockerexec.Runner
	Docker      *docker.Client
	EnvStore    *envstore.Store
	CfgStore    *cfgstore.Store
	GitStore    *gitstore.Store
	ProvStore   *provstore.Store
	SetupStore  *setupstore.Store
	AlertStore  *alertstore.Store
	EdgeRoutes  *edge.RouteStore
	EdgeRecon   *edge.Reconciler            // nil when the edge isn't owned (external/unavailable)
	EdgeReason  string                      // why the edge isn't owned (banner), "" when owned
	L4Routes    *l4.RouteStore              // managed L4 (TCP/UDP) routes (nil when L4 LB disabled)
	L4Reconcile func(context.Context) error // push the L4 route set to the nginx-stream LB (nil when disabled)
	DefStore    *definition.Store           // canonical mooring.yaml store (source of truth; may be nil)
	SelfHeal    *selfheal.Store             // supervisor FSM + expected_down leases (may be nil)
	Scaling     *scale.Store                // auto-scaling policies + state (may be nil)
	DockerSem   *dockerexec.Semaphore       // global one-docker-child semaphore (shared with Runner)
	APITokens   *apitoken.Store             // scoped read/deploy API tokens (M19; may be nil → /api/v1 disabled)
	Backups     *backupstore.Store          // encrypted Mooring-state backups (may be nil)
}

// Server holds everything the request pipeline needs. Construct with New.
type Server struct {
	cfg            *config.Config // immutable parts (bind, cookie, edge, session)
	configPath     string
	version        string // running Mooring build version (Server tab .deb cleanup)
	db             *store.DB
	sessions       *session.Manager
	audit          *audit.Logger
	limiter        *rateLimiter
	templates      *template.Template
	log            *slog.Logger
	verifySem      chan struct{}
	apiVerifySem   chan struct{}                 // separate argon2 pool for /api/v1 (never starves login)
	apiDummyHash   string                        // decoy argon2id hash (token params) for timing parity
	mon            *monitor.Monitor              // read-plane snapshots (may be nil)
	opsStore       *ops.ConfigStore              // ops config (may be nil)
	prober         *ops.Prober                   // ops queue actions (may be nil)
	runner         *dockerexec.Runner            // write-plane exec (may be nil)
	docker         *docker.Client                // read-plane log streaming (may be nil)
	envStore       *envstore.Store               // encrypted env store (may be nil)
	cfgStore       *cfgstore.Store               // managed config files + cert bindings (may be nil)
	gitStore       *gitstore.Store               // repo-path GitOps (may be nil)
	provStore      *provstore.Store              // provisioned apps (modes 1/2; may be nil)
	setupStore     *setupstore.Store             // setup scripts (Mode 3; may be nil)
	alertStore     *alertstore.Store             // alerting channels/rules/state (may be nil)
	edgeRoutes     *edge.RouteStore              // managed-edge routes (may be nil)
	edgeRecon      *edge.Reconciler              // edge config reconciler (nil when edge unowned)
	edgeReason     string                        // why the edge isn't owned (banner)
	l4Routes       *l4.RouteStore                // managed L4 (TCP/UDP) routes (nil when L4 LB disabled)
	l4Reconcile    func(context.Context) error   // push the L4 route set to the LB (nil when disabled)
	defStore       *definition.Store             // canonical mooring.yaml (source of truth; may be nil)
	selfHeal       *selfheal.Store               // supervisor FSM + expected_down leases (may be nil)
	scaling        *scale.Store                  // auto-scaling policies + state (may be nil)
	circuitClearer func(project, service string) // supervisor clear-circuit (set post-construction)
	apiTokens      *apitoken.Store               // scoped API tokens (M19; nil → /api/v1 disabled)
	backups        *backupstore.Store            // encrypted Mooring-state backups (may be nil)
	githubClient   *github.Client                // GitHub connect (M20; nil → feature off)
	dockerSem      *dockerexec.Semaphore         // global one-docker-child semaphore (may be nil)
	setupConfirm   *confirmStore                 // single-use setup confirm tokens
	caddyCertRoot  string                        // edge cert store root (cert_bindings sync); default below
	lastActive     atomic.Int64                  // unix-nano of the last focused-dashboard heartbeat (git-poll gate)
	webhookRL      *rateLimiter                  // per-token webhook rate limit
	webhookSeen    *nonceCache                   // webhook replay (timestamp+nonce) defense
	webhookFlash   *tokenFlash                   // one-time rotated-token hand-off (never in URL)
	discoFlash     *discoveryFlash               // short-lived multi-file connect stash (creds never round-trip the browser)
	gitDeploy      *dockerexec.Semaphore         // single-flight repo deploy (1 at a time)
	logStreams     chan struct{}                 // concurrency cap on live log streams
	sec            atomic.Pointer[secState]
	footprintOnce  sync.Once                    // lazily builds the Server-tab disk-footprint cache
	footprintC     *footprintCache              // cached on-disk footprint (off-request refresh)
	updateCheck    *updatecheck.Checker         // self-update / security-advisory posture (may be nil)
	imageScans     *imagescan.Store             // per-app Trivy scan results (may be nil)
	pendingApps    atomic.Pointer[[]pendingApp] // undeployed mooring.*.yaml siblings found in connected repos
}

// New builds a Server from a validated config and its dependencies.
func New(cfg *config.Config, d Deps) (*Server, error) {
	tmpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	log := d.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Server{
		cfg:           cfg,
		configPath:    d.ConfigPath,
		version:       d.Version,
		updateCheck:   d.UpdateCheck,
		imageScans:    d.ImageScans,
		db:            d.DB,
		sessions:      session.New(d.DB, cfg.Session.IdleTimeout.D(), cfg.Session.AbsoluteTimeout.D()),
		audit:         audit.New(d.DB, log),
		limiter:       newRateLimiter(300, time.Minute),
		templates:     tmpl,
		log:           log,
		verifySem:     make(chan struct{}, loginVerifyConcurrency),
		apiVerifySem:  make(chan struct{}, apiVerifyConcurrency),
		mon:           d.Monitor,
		opsStore:      d.OpsStore,
		prober:        d.Prober,
		runner:        d.Runner,
		docker:        d.Docker,
		envStore:      d.EnvStore,
		cfgStore:      d.CfgStore,
		gitStore:      d.GitStore,
		provStore:     d.ProvStore,
		setupStore:    d.SetupStore,
		alertStore:    d.AlertStore,
		edgeRoutes:    d.EdgeRoutes,
		edgeRecon:     d.EdgeRecon,
		l4Routes:      d.L4Routes,
		l4Reconcile:   d.L4Reconcile,
		defStore:      d.DefStore,
		edgeReason:    d.EdgeReason,
		selfHeal:      d.SelfHeal,
		scaling:       d.Scaling,
		apiTokens:     d.APITokens,
		backups:       d.Backups,
		dockerSem:     d.DockerSem,
		setupConfirm:  newConfirmStore(5 * time.Minute),
		caddyCertRoot: defaultCaddyCertRoot,
		webhookRL:     newRateLimiter(30, time.Minute),
		webhookSeen:   newNonceCache(webhookNonceTTL),
		webhookFlash:  newTokenFlash(2 * time.Minute),
		discoFlash:    newDiscoveryFlash(5 * time.Minute),
		gitDeploy:     dockerexec.NewSemaphore(),
		logStreams:    make(chan struct{}, maxConcurrentLogStreams),
	}
	s.sweepDiscoveryScratch() // clear any orphaned multi-file-connect scratch dirs from a prior run
	sec, err := buildSecState(cfg)
	if err != nil {
		return nil, err
	}
	sec.tokenCIDRUnion = s.activeTokenUnion(context.Background())
	s.sec.Store(sec)
	// A decoy argon2id hash with the SAME params a real token uses, so the not-found
	// path can pay an equal-cost verify (timing parity — an unknown/expired/revoked id
	// must be latency-indistinguishable from a live one; M19 review).
	apiDummy, err := crypto.HashPassword([]byte("\x00mooring-api-decoy"), crypto.DefaultArgon2Params)
	if err != nil {
		return nil, fmt.Errorf("web: build api decoy hash: %w", err)
	}
	s.apiDummyHash = apiDummy
	// "Connect with GitHub" is on only when the operator configured an OAuth App. The
	// HTTP client has a bounded timeout; outbound egress to GitHub is the operator's
	// systemd egress-allowlist concern.
	if cfg.GitHub.Enabled() {
		s.githubClient = github.New(&http.Client{Timeout: 30 * time.Second}, "", "")
	}
	// Revoke any session that predates the current auth config (password/TOTP) — at
	// STARTUP, so enabling TOTP (or changing the password) forces re-auth even when
	// applied via `systemctl restart`, not only via reload. Closes the gap where a
	// pre-TOTP session kept full access after TOTP was turned on.
	s.reconcileAuthEpoch(context.Background())
	return s, nil
}

// authEpochKey stores a fingerprint of the auth config (username + password hash +
// TOTP secret). When it changes, every existing session is revoked.
const authEpochKey = "auth_epoch"

// authFingerprint is a one-way hash of the auth-relevant config. It never exposes the
// secrets (sha256, and the password is already a hash); it only needs to CHANGE when
// any of them change.
func authFingerprint(sec *secState) string {
	h := sha256.New()
	h.Write([]byte(sec.username))
	h.Write([]byte{0})
	h.Write([]byte(sec.passwordHash))
	h.Write([]byte{0})
	h.Write([]byte(sec.totpSecret))
	return hex.EncodeToString(h.Sum(nil))
}

// reconcileAuthEpoch revokes ALL sessions whenever the auth config has changed since
// the sessions were issued (detected via a persisted fingerprint), via ANY path —
// reload OR restart. First boot just records the fingerprint (nothing to revoke).
func (s *Server) reconcileAuthEpoch(ctx context.Context) {
	fp := authFingerprint(s.security())
	if s.getSetting(ctx, authEpochKey) == fp {
		return
	}
	// Fingerprint differs (auth config changed) OR no epoch is stored yet (first boot
	// on this version — we can't prove existing sessions satisfied the current factors,
	// so revoke once). A fresh install simply has 0 sessions, so this is a harmless
	// no-op there. On a normal restart with unchanged config the fingerprint matches
	// and we return above, so sessions are NOT dropped every restart.
	if n, err := s.sessions.DeleteAll(ctx); err == nil && n > 0 {
		s.log.Warn("auth config changed or first boot on this version — revoked all sessions; re-login required", "revoked", n)
	}
	_ = s.setSetting(ctx, authEpochKey, fp)
}

// activeTokenUnion recomputes the union of every active API token's CIDR set. On any
// store error it returns nil (admitting NO token CIDRs) — a read failure must never
// widen the IP gate, only narrow it (fail-closed).
func (s *Server) activeTokenUnion(ctx context.Context) []netip.Prefix {
	if s.apiTokens == nil {
		return nil
	}
	union, err := s.apiTokens.ActiveCIDRUnion(ctx, time.Now())
	if err != nil {
		s.log.Warn("apitoken: CIDR-union recompute failed; admitting no token CIDRs (fail-closed)", "err", err)
		return nil
	}
	return union
}

func buildSecState(cfg *config.Config) (*secState, error) {
	// Precompute a dummy argon2id hash with the SAME params as the operator's
	// real hash, so a username miss runs an equal-cost verify (timing parity).
	params, _, _, err := crypto.ParseArgon2(cfg.Auth.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("web: parse password hash: %w", err)
	}
	dummy, err := crypto.HashPassword([]byte("\x00mooring-dummy"), params)
	if err != nil {
		return nil, fmt.Errorf("web: build dummy hash: %w", err)
	}
	return &secState{
		trustProxy:     cfg.TrustProxy,
		allowlist:      cfg.Allowlist(),
		trustedProxies: cfg.TrustedProxyPrefixes(),
		username:       cfg.Auth.Username,
		passwordHash:   cfg.Auth.PasswordHash,
		totpSecret:     cfg.Auth.TOTPSecret,
		dummyHash:      dummy,
	}, nil
}

func (s *Server) security() *secState { return s.sec.Load() }

// Reload re-reads the config file and hot-swaps the allowlist + auth (plan §5.1).
// On any validation error the current state is kept (fail-closed: a bad edit
// never widens or breaks the running policy).
func (s *Server) Reload(ctx context.Context) error {
	cfg, err := config.Load(s.configPath)
	if err != nil {
		_ = s.audit.Log(ctx, audit.Event{
			Action: "config_reload", Outcome: audit.Error, Level: audit.Security,
			Detail: "rejected invalid config; keeping previous",
		})
		return err
	}
	sec, err := buildSecState(cfg)
	if err != nil {
		return err
	}
	sec.tokenCIDRUnion = s.activeTokenUnion(ctx)
	s.sec.Store(sec)
	// Revoke all sessions if the auth config (password / TOTP / username) changed, so a
	// session minted under the OLD config can't bypass the new one — the "I enabled 2FA
	// but I'm still in" trap. Same fingerprint mechanism as startup, so it holds via
	// reload OR restart.
	s.reconcileAuthEpoch(ctx)
	s.log.Info("config reloaded", "two_factor_totp", sec.totpSecret != "")
	_ = s.audit.Log(ctx, audit.Event{
		Action: "config_reload", Outcome: audit.OK, Level: audit.Security,
		Detail: "allowlist + auth + token CIDR-union reloaded",
	})
	return nil
}

// Handler assembles the full middleware chain in pipeline order.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public (auth-exempt) routes.
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	// Webhook: allowlist-exempt (CI egress) + auth-exempt, but HMAC-gated,
	// replay-protected, per-token rate-limited, and FETCH-ONLY (plan §5.7).
	mux.HandleFunc("POST /webhook/{token}", capBody(1<<20, s.handleWebhook))
	mux.HandleFunc("GET /login", s.withCSRFToken(s.handleLoginGet))
	// capBody is OUTERMOST so the body is bounded before requireCSRF parses it.
	mux.HandleFunc("POST /login", capBody(loginBodyLimit, s.requireCSRF(s.handleLoginPost)))
	mux.HandleFunc("POST /logout", capBody(loginBodyLimit, s.requireCSRF(s.handleLogout)))

	// Static assets (behind the allowlist, but no auth — the login page needs CSS).
	// The operator theme overlay (M7) is a more-specific route that takes
	// precedence over the embedded FileServer; it reads a fixed data-dir file.
	mux.HandleFunc("GET /static/theme.css", s.handleThemeCSS)
	staticFS, _ := fs.Sub(embeddedAssets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheControl(http.FileServer(http.FS(staticFS)))))

	// Protected routes.
	mux.HandleFunc("GET /{$}", s.requireAuth(s.withCSRFToken(s.handleHome)))
	mux.HandleFunc("GET /partials/overview", s.requireAuth(s.handleOverviewPartial))
	mux.HandleFunc("GET /incidents", s.requireAuth(s.withCSRFToken(s.handleIncidents)))
	// Server tab: read-only host inspection (monitor/processes/disk) + gated .deb cleanup.
	mux.HandleFunc("GET /server", s.requireAuth(s.withCSRFToken(s.handleServer)))
	mux.HandleFunc("GET /partials/server", s.requireAuth(s.handleServerPartial))
	mux.HandleFunc("GET /server/files", s.requireAuth(s.withCSRFToken(s.handleServerFiles)))
	mux.HandleFunc("POST /server/debs/delete", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleDebDelete))))
	mux.HandleFunc("GET /apps", s.requireAuth(s.withCSRFToken(s.handleAppsList)))
	// Host metric series for the live dashboard charts (read plane; cookie-authed).
	mux.HandleFunc("GET /partials/metrics.json", s.requireAuth(s.handleMetricsHistory))
	// Focused-dashboard heartbeat — gates the git poller (only fetch while someone's looking).
	mux.HandleFunc("GET /dash/ping", s.requireAuth(s.handleDashPing))
	// Non-refreshing session liveness probe (auth-exempt: returns 204/401 itself, never
	// 302). The focus-loss watchdog polls it to surface an idle-out as a redirect to /login.
	// Literal pattern (not sessionStatusPath) so the authz-posture AST check can see it;
	// the path string must stay equal to sessionStatusPath (asserted in a test).
	mux.HandleFunc("GET /session/status", s.handleSessionStatus)
	// Export the app's deployed definition as mooring.yaml (to commit into your repo;
	// Mooring never pushes — git access is fetch-only).
	mux.HandleFunc("GET /apps/{project}/definition.yaml", s.requireAuth(s.handleDefinitionYAML))
	mux.HandleFunc("GET /apps/{project}", s.requireAuth(s.withCSRFToken(s.handleApp)))
	// Permanent app delete: full teardown (stop+remove containers/volumes, run dir, repo,
	// and all per-app state). Re-authenticates with the operator password in the handler.
	mux.HandleFunc("POST /apps/{project}/delete", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleAppDelete))))
	mux.HandleFunc("GET /partials/app/{project}", s.requireAuth(s.withCSRFToken(s.handleAppPartial)))
	// App Ops Interface (M3): config form + server-side-proxied queue actions.
	mux.HandleFunc("GET /apps/{project}/ops-config", s.requireAuth(s.withCSRFToken(s.handleOpsConfigGet)))
	mux.HandleFunc("POST /apps/{project}/ops-config", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleOpsConfigPost))))
	mux.HandleFunc("POST /apps/{project}/queues/{queue}/{action}", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleQueueAction))))
	// Lifecycle (M4 write plane): whole-project + per-service. Literal sub-routes
	// (ops-config, queues) are more specific and take precedence over {action}.
	mux.HandleFunc("POST /apps/{project}/{action}", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleAppAction))))
	mux.HandleFunc("POST /apps/{project}/services/{service}/{action}", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleServiceAction))))
	mux.HandleFunc("POST /apps/{project}/supervisor/clear", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleSupervisorClear))))
	mux.HandleFunc("POST /apps/{project}/scaling", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleScalingSave))))
	mux.HandleFunc("GET /apps/{project}/services/{service}/logs", s.requireAuth(s.handleServiceLogs))
	// withCSRFToken so the live-polled ops fragment carries a CSRF token for its
	// per-service queue-action forms (re-injected on every poll, never stale).
	mux.HandleFunc("GET /partials/service/{project}/{service}/ops", s.requireAuth(s.withCSRFToken(s.handleServiceOpsPartial)))
	// Per-service queue actions: routed to THIS service's own ops endpoint (not the
	// project-level target). More specific than /services/{service}/{action}.
	mux.HandleFunc("POST /apps/{project}/services/{service}/queues/{queue}/{action}", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleServiceQueueAction))))
	mux.HandleFunc("GET /apps/{project}/services/{service}", s.requireAuth(s.withCSRFToken(s.handleServiceGet)))
	// Env settings (M5): literals + write-only secrets, masked reveal, history.
	mux.HandleFunc("GET /apps/{project}/env", s.requireAuth(s.withCSRFToken(s.handleEnvGet)))
	mux.HandleFunc("POST /apps/{project}/env", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleEnvSaveLiterals))))
	mux.HandleFunc("POST /apps/{project}/env/literal", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleEnvAddLiteral))))
	mux.HandleFunc("POST /apps/{project}/env/literal/remove", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleEnvRemoveLiteral))))
	mux.HandleFunc("POST /apps/{project}/env/import", capBody(512<<10, s.requireAuth(s.requireCSRF(s.handleEnvImport))))
	mux.HandleFunc("POST /apps/{project}/env/secret", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleEnvSetSecret))))
	mux.HandleFunc("POST /apps/{project}/env/secret/remove", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleEnvRemoveSecret))))
	mux.HandleFunc("POST /apps/{project}/env/reveal", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleEnvReveal))))
	mux.HandleFunc("POST /apps/{project}/env/rollback", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleEnvRollback))))
	// Managed config files + cert bindings (M5b).
	mux.HandleFunc("GET /apps/{project}/config-files", s.requireAuth(s.withCSRFToken(s.handleConfigFilesGet)))
	mux.HandleFunc("POST /apps/{project}/config-files", capBody(256<<10, s.requireAuth(s.requireCSRF(s.handleConfigFileSave))))
	mux.HandleFunc("POST /apps/{project}/config-files/preview", capBody(256<<10, s.requireAuth(s.requireCSRF(s.handleConfigFilePreview))))
	mux.HandleFunc("POST /apps/{project}/config-files/delete", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleConfigFileDelete))))
	mux.HandleFunc("POST /apps/{project}/config-files/migrate", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleConfigFileMigrate))))
	mux.HandleFunc("POST /apps/{project}/cert-bindings", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleCertBindingSave))))
	mux.HandleFunc("POST /apps/{project}/cert-bindings/delete", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleCertBindingDelete))))
	// App provisioning wizard (M8, modes 1 & 2). validate is a dry preview;
	// commit/deploy are §0-gated write-plane actions.
	// "New app" is now the repo-connect flow: GET /apps/new redirects to /git/new (the
	// single-service provision FORM was retired — a repo's mooring.yaml is the source of
	// truth). The deploy/delete lifecycle routes stay for any legacy provisioned apps.
	mux.HandleFunc("GET /apps/new", s.requireAuth(s.handleProvisionNew))
	mux.HandleFunc("POST /apps/{project}/provision-deploy", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleProvisionDeploy))))
	mux.HandleFunc("POST /apps/{project}/provision-delete", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleProvisionDelete))))
	// Setup-script sandbox (M9, Mode 3 — OFF by default, hard-gated). The run is
	// confirm-token-gated and fail-closed; it never runs from an auto path.
	mux.HandleFunc("GET /apps/{project}/setup", s.requireAuth(s.withCSRFToken(s.handleSetupGet)))
	mux.HandleFunc("POST /apps/{project}/setup/sync", capBody(1<<20, s.requireAuth(s.requireCSRF(s.handleSetupSync))))
	mux.HandleFunc("POST /apps/{project}/setup/run", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleSetupRun))))
	mux.HandleFunc("POST /apps/{project}/setup/delete", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleSetupDelete))))
	// Repo-path GitOps (M6).
	mux.HandleFunc("GET /git/new", s.requireAuth(s.withCSRFToken(s.handleGitNew)))
	// Connect-new runs repo discovery (mooring.yaml + variants → one app each); the
	// chooser posts the picked file back to /git/choose. Editing an EXISTING app's repo
	// config stays on /apps/{project}/git (handleGitSave) — no discovery, slug fixed.
	mux.HandleFunc("POST /git", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleGitConnect))))
	mux.HandleFunc("POST /git/choose", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleGitChoose))))
	// Add a mooring.*.yaml found in a connected repo (but not yet deployed) as its own app.
	mux.HandleFunc("POST /git/add-definition", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleAddDefinition))))
	mux.HandleFunc("GET /apps/{project}/git", s.requireAuth(s.withCSRFToken(s.handleGitGet)))
	mux.HandleFunc("POST /apps/{project}/git", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleGitSave))))
	mux.HandleFunc("POST /apps/{project}/git/fetch", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleGitFetch))))
	mux.HandleFunc("POST /apps/{project}/git/deploy", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleGitDeploy))))
	mux.HandleFunc("POST /apps/{project}/versions/{id}/rollback", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleVersionRollback))))
	mux.HandleFunc("POST /apps/{project}/versions/{id}/delete", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleVersionDelete))))
	mux.HandleFunc("POST /apps/{project}/git/webhook-rotate", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleGitWebhookRotate))))
	// Connect with GitHub (M20): OAuth web flow → repo picker → auto deploy-key.
	// The callback is a cross-site navigation back from github.com, so the Strict
	// session cookie isn't sent — it is authenticated by the single-use Lax OAuth
	// state cookie instead (set only by the authenticated+CSRF'd connect action).
	mux.HandleFunc("POST /github/connect", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleGitHubConnect))))
	mux.HandleFunc("GET /github/callback", s.handleGitHubCallback)
	mux.HandleFunc("GET /github/repos", s.requireAuth(s.withCSRFToken(s.handleGitHubRepos)))
	mux.HandleFunc("POST /github/connect-repo", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleGitHubConnectRepo))))
	mux.HandleFunc("POST /github/disconnect", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleGitHubDisconnect))))
	// Managed edge (M11): per-app public routes (Caddy/ACME). The whole config is
	// re-rendered + pushed on every change; the operator never edits Caddy.
	mux.HandleFunc("GET /edge", s.requireAuth(s.withCSRFToken(s.handleEdge)))
	// Edge routes are READ-ONLY in the dashboard — declared in the app's mooring.yaml
	// (source of truth) and reconciled on deploy. No POST /edge/routes write-back.
	// Alerting (M10): channels + rules + open alerts. Read-and-notify only.
	mux.HandleFunc("GET /alerts", s.requireAuth(s.withCSRFToken(s.handleAlerts)))
	mux.HandleFunc("GET /alerts/channels", s.requireAuth(s.withCSRFToken(s.handleChannelsPage)))
	mux.HandleFunc("GET /alerts/rules", s.requireAuth(s.withCSRFToken(s.handleRulesPage)))
	mux.HandleFunc("POST /alerts/channels", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleAlertChannelSave))))
	mux.HandleFunc("POST /alerts/channels/delete", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleAlertChannelDelete))))
	mux.HandleFunc("POST /alerts/channels/test", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleAlertChannelTest))))
	mux.HandleFunc("POST /alerts/rules", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleAlertRuleSave))))
	mux.HandleFunc("POST /alerts/rules/delete", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleAlertRuleDelete))))
	mux.HandleFunc("POST /alerts/ack", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleAlertAck))))
	mux.HandleFunc("POST /alerts/silence", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleAlertSilence))))
	mux.HandleFunc("GET /events", s.requireAuth(s.withCSRFToken(s.handleEvents)))
	// Operator UI prefs (M7): persisted tile order. UI-only, never Tier-1.
	mux.HandleFunc("POST /settings/tile-order", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleTileOrder))))
	// API tokens (M19): read-only view + revoke. Minting stays CLI-only by design.
	mux.HandleFunc("GET /settings/api-tokens", s.requireAuth(s.withCSRFToken(s.handleAPITokens)))
	mux.HandleFunc("POST /settings/api-tokens/revoke", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleAPITokenRevoke))))
	// Backups: encrypted Mooring-state snapshots — view, create, download, delete.
	mux.HandleFunc("GET /settings/backups", s.requireAuth(s.withCSRFToken(s.handleBackups)))
	mux.HandleFunc("GET /settings/backups/download", s.requireAuth(s.handleBackupDownload))
	mux.HandleFunc("POST /settings/backups/create", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleBackupCreate))))
	mux.HandleFunc("POST /settings/backups/delete", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleBackupDelete))))

	// Scoped machine API (M19, plan §17.1): bearer-ONLY, cookie-REJECTING,
	// CSRF-EXEMPT (no ambient credential to abuse). requireToken is the sole gate —
	// these routes are deliberately NOT wrapped in requireAuth/requireCSRF. A token
	// can carry only the read scopes + deploy:write:<slug>; nothing here can express
	// a Tier-1 / reveal / setup / mint capability.
	mux.HandleFunc("GET /api/v1/status", s.requireToken(fixedScope("status:read"), s.handleAPIStatus))
	mux.HandleFunc("GET /api/v1/metrics", s.requireToken(fixedScope("metrics:read"), s.handleAPIMetrics))
	mux.HandleFunc("GET /api/v1/events", s.requireToken(fixedScope("events:read"), s.handleAPIEvents))
	mux.HandleFunc("GET /api/v1/audit", s.requireToken(fixedScope("audit:read"), s.handleAPIAudit))
	mux.HandleFunc("POST /api/v1/apps/{project}/deploy", capBody(1<<20, s.requireToken(deployScope, s.handleAPIDeploy)))

	// Pipeline order: allowlist → headers → rate limit → session loader → router.
	// (auth + CSRF are applied per-route inside the mux.)
	var h http.Handler = mux
	h = s.sessionMiddleware(h)
	h = s.rateLimitMiddleware(h)
	h = s.securityHeadersMiddleware(h)
	h = s.allowlistMiddleware(h)
	return h
}

// Run starts the loopback admin HTTP server (the SSH-tunnel path) and blocks until ctx is
// cancelled. When the admin is exposed through the managed edge, it ALSO starts a second
// dedicated loopback listener (admin.edge_listen) that the edge proxies to: requests on it
// are marked fromEdge, so the allowlist middleware requires an X-Forwarded-For and gates the
// REAL client — the two paths thus carry different trust without a config contradiction.
func (s *Server) Run(ctx context.Context) error {
	handler := s.Handler()
	newSrv := func(addr string, h http.Handler) *http.Server {
		return &http.Server{
			Addr:              addr,
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}
	}
	srvs := []*http.Server{newSrv(s.cfg.BindAddr, handler)}
	if s.cfg.AdminExposed() {
		// The edge listener wraps the SAME pipeline but stamps fromEdge FIRST (before the
		// allowlist middleware runs), forcing the XFF-required branch for this path only.
		edgeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler.ServeHTTP(w, r.WithContext(withFromEdge(r.Context())))
		})
		srvs = append(srvs, newSrv(s.cfg.AdminEdgeListen(), edgeHandler))
		s.log.Warn("admin dashboard is EXPOSED through the managed edge — internet-reachable, gated by ip_allowlist + password + TOTP",
			"hostname", s.cfg.AdminHostnameResolved(), "edge_listen", s.cfg.AdminEdgeListen())
	}
	errCh := make(chan error, len(srvs))
	for _, srv := range srvs {
		srv := srv
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
	}
	select {
	case <-ctx.Done():
	case err := <-errCh:
		// One listener failed (e.g. address in use) — tear the other(s) down too, then
		// return the error so boot fails cleanly instead of leaving a half-up server.
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		for _, srv := range srvs {
			_ = srv.Shutdown(shutCtx)
		}
		cancel()
		return err
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range srvs {
		_ = srv.Shutdown(shutCtx)
	}
	return nil
}

// --- cookie helpers (plan §5.3) ---

func (s *Server) cookieName() string { return s.cfg.Cookie.Prefix + "session" }

func (s *Server) cookiePath() string {
	if s.cfg.Cookie.Prefix == "__Secure-" && s.cfg.Cookie.BasePath != "" {
		return s.cfg.Cookie.BasePath
	}
	return "/"
}

func (s *Server) setSessionCookie(w http.ResponseWriter, rawID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(),
		Value:    rawID,
		Path:     s.cookiePath(),
		HttpOnly: true,
		Secure:   true, // __Host-/__Secure- prefixes require it; localhost is a secure context
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(),
		Value:    "",
		Path:     s.cookiePath(),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func cacheControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		next.ServeHTTP(w, r)
	})
}

// clearWriteDeadline removes the server's WriteTimeout (server.go: 60s) for THIS
// response. A deploy/log/setup stream legitimately runs for minutes (e.g. the deploy
// now waits up to 150s for ACME), and the absolute write deadline would otherwise cut
// the connection mid-stream — the client sees "network error" and, since the deploy
// runs on the request context, the deploy aborts. Per-response only; other handlers
// keep the 60s slow-client protection.
func clearWriteDeadline(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
}

// auditDeny records an allowlist denial (called from the allowlist middleware).
func (s *Server) auditDeny(r *http.Request, peer, client netip.Addr) {
	_ = s.audit.Log(r.Context(), audit.Event{
		IP: peer.String(), Action: "allowlist_deny", Outcome: audit.Deny, Level: audit.Security,
		Target: r.URL.Path, Detail: "resolved client " + client.String(),
	})
}
