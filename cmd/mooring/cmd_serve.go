package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/alertengine"
	"github.com/daboss2003/mooring/internal/alertstore"
	"github.com/daboss2003/mooring/internal/apitoken"
	"github.com/daboss2003/mooring/internal/backupsched"
	"github.com/daboss2003/mooring/internal/backupstore"
	"github.com/daboss2003/mooring/internal/cfgstore"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/diskgc"
	"github.com/daboss2003/mooring/internal/docker"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/edge"
	"github.com/daboss2003/mooring/internal/envstore"
	"github.com/daboss2003/mooring/internal/github"
	"github.com/daboss2003/mooring/internal/gitstore"
	"github.com/daboss2003/mooring/internal/hostmon"
	"github.com/daboss2003/mooring/internal/imagescan"
	"github.com/daboss2003/mooring/internal/l4"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/ntfy"
	"github.com/daboss2003/mooring/internal/ops"
	"github.com/daboss2003/mooring/internal/opsclient"
	"github.com/daboss2003/mooring/internal/provision"
	"github.com/daboss2003/mooring/internal/provstore"
	"github.com/daboss2003/mooring/internal/retention"
	"github.com/daboss2003/mooring/internal/s3"
	"github.com/daboss2003/mooring/internal/sandbox"
	"github.com/daboss2003/mooring/internal/scale"
	"github.com/daboss2003/mooring/internal/selfheal"
	"github.com/daboss2003/mooring/internal/setupstore"
	"github.com/daboss2003/mooring/internal/socketproxy"
	"github.com/daboss2003/mooring/internal/store"
	"github.com/daboss2003/mooring/internal/updatecheck"
	"github.com/daboss2003/mooring/internal/web"
)

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultPath, "path to config.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err // fail-closed: refuse to boot
	}

	// Fail-closed: probe that the sandbox actually lets us write the dirs we need,
	// BEFORE the first deploy/edge-start EROFS's lazily. A missing ReadWritePaths
	// entry (e.g. a changed data_dir, or no RuntimeDirectory) becomes a clear boot
	// error naming the path, not a mysterious "deploy hangs / edge crash-loops".
	if err := checkWritablePaths(cfg, log); err != nil {
		return err
	}

	db, err := store.Open(filepath.Join(cfg.DataDir, "mooring.db"))
	if err != nil {
		return err
	}
	defer db.Close()

	// Fail-closed key/DB sentinel check (plan §5.1; review #21): if a key-check
	// sentinel exists, the configured key MUST open it, else refuse to boot rather
	// than seal future writes under a key that can't read existing rows.
	if err := checkKeySentinel(cfg, db); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Master cipher for secrets at rest (ops shared secrets in M3, env in M5).
	cipher, err := openCipher(cfg)
	if err != nil {
		return err
	}

	// Read plane (M2/M3): poll Docker via the loopback socket-proxy, sample host,
	// and probe the App Ops Interface (M3). The poller is joined before the
	// deferred db.Close() so no DB write can race the close (review #8).
	dockerCli := docker.New(cfg.Docker.ProxyAddr)
	hostSampler := hostmon.New(cfg.DataDir)
	opsStore := ops.NewConfigStore(db, cipher)
	// The ops prober dials a service-name base_url (http://api:3000), but the control
	// plane is a host process that can't resolve compose names — so resolve the name to a
	// running replica's bridge IP via the read-only socket-proxy before dialing.
	prober := ops.NewProber(opsStore, opsclient.New(), db, func(c context.Context, project, service string) (string, bool) {
		return web.ServiceIP(c, dockerCli, project, service)
	})
	envStore := envstore.New(db, cipher)
	cfgStore := cfgstore.New(db, cipher)
	gitStore := gitstore.New(db, cipher)
	provStore := provstore.New(db)
	// Canonical definition store (the single source of truth: mooring.yaml). Both
	// the deploy (file edit) and the dashboard editors write to it; the runtime
	// stores (scale, edge routes) are reconciled FROM it. HMAC-keyed off the master key.
	var defStore *definition.Store
	if dk, derr := config.DecodeKey(cfg.EncryptionKey); derr == nil {
		defStore = definition.NewStore(db, dk)
	}
	// Clear any stale staging/aside dirs from an interrupted provision commit
	// (plan §7 boot-time sweep). The apps root is a sibling of DataDir.
	provision.SweepStaging(cfg.DataDir + "-apps")
	mon := monitor.New(db, dockerCli, hostSampler, cfg.Monitor.PollInterval.D(),
		cfg.Monitor.MetricsRetention.D(), log, prober)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); mon.Run(ctx) }()

	// Write plane (M4): the §0 ≥1 GB resource gate + the global one-docker-child
	// semaphore + static-argv exec wrapper.
	var memTotal uint64
	if hs, herr := hostSampler.Sample(); herr == nil {
		memTotal = hs.MemTotal
	}
	writeAllowed, writeReason := dockerexec.WritePlaneGate(memTotal)
	if !writeAllowed {
		log.Warn("write plane disabled", "reason", writeReason)
	} else if writeReason != "" {
		log.Info("write plane armed", "note", writeReason)
	}
	// The global one-docker-child semaphore is SHARED by the write-plane runner and
	// the setup sandbox (plan §4: one docker child across poller+deploy+sandbox).
	dockerSem := dockerexec.NewSemaphore()
	runner := dockerexec.NewRunner(dockerSem, writeAllowed, writeReason)

	// Mooring MANAGES its own read-only socket-proxy (plan §3) so the operator never
	// runs a docker command — they only ever write mooring.yaml. Bring it up in the
	// background (the first run may pull the image) and ungated (the read plane must
	// work even on a sub-1 GB box). Best-effort: a failure just leaves the read plane
	// "unavailable" until it is up. Set docker.external_proxy to opt out (you run your
	// own proxy/endpoint at docker.proxy_addr).
	// The managed proxy is the read-plane SECURITY BOUNDARY, and because Mooring now
	// runs it as a compose project it shows up as a normal app in the snapshot. Protect
	// it from EVERY write path (lifecycle stop/redeploy, self-heal restart, auto-scale)
	// exactly like the edge — it must never be a target. This must not depend on the
	// operator remembering to list it, so seed it BEFORE the web server and the
	// self-heal watcher read cfg.ProtectedProjects (review finding).
	protectManagedProxy(cfg)
	// Reserve the managed-ntfy project name so it can never become an operator app or a
	// lifecycle/self-heal target. The container itself is only run when the operator
	// configures a Mooring-hosted ntfy alert channel.
	protectProject(cfg, ntfy.Project)

	if !cfg.Docker.ExternalProxy {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ec, cancel := context.WithTimeout(ctx, 90*time.Second) // allow a first-run image pull
			defer cancel()
			log.Info("ensuring the managed read-only docker socket-proxy is running")
			// Capture the compose output so a FAILURE surfaces the REAL reason (e.g. an
			// image-pull DNS error), not a bare "exit status 125". It was previously
			// Debug-only, which is why the failure looked like a mystery.
			var out []string
			err := socketproxy.EnsureRunning(ec, runner, cfg.DataDir, func(line string) {
				log.Debug("socket-proxy", "out", line)
				if l := strings.TrimSpace(line); l != "" {
					out = append(out, l)
				}
			})
			if err != nil {
				tail := out
				if len(tail) > 8 {
					tail = tail[len(tail)-8:]
				}
				log.Warn("could not start the managed socket-proxy; the read plane (container view) stays unavailable",
					"err", err, "output", strings.Join(tail, " | "),
					"hint", "usually the daemon can't PULL the proxy image — check host DNS (getent hosts ghcr.io) then `docker pull` it; it retries on a mooring restart")
			} else {
				log.Info("managed read-only docker socket-proxy is up", "addr", cfg.Docker.ProxyAddr)
			}
		}()
	} else {
		log.Info("docker.external_proxy set; Mooring will NOT manage the socket-proxy", "addr", cfg.Docker.ProxyAddr)
	}

	// Setup sandbox (M9, Mode 3 — OFF by default, hard-gated). Fail-closed boot
	// precondition: if setup is enabled the host MUST provide a working sandbox
	// (plan §5.1) or we refuse to boot.
	setupStore := setupstore.New(db, cipher)
	if cfg.Setup.Enabled {
		if ok, why := sandbox.Available(); !ok {
			return fmt.Errorf("setup.enabled but no working sandbox: %s", why)
		}
	}

	// Audit/events retention (M7, plan §16.1): bounds the events table so it can
	// never wedge the disk, while NEVER silently dropping a security row. Joined
	// before the deferred db.Close() (review #8).
	retentionRunner := retention.New(db, log, cfg.DataDir, toRetentionConfig(cfg))
	wg.Add(1)
	go func() { defer wg.Done(); retentionRunner.Run(ctx) }()

	// Alert engine (M10, plan §8): read-and-notify only. Runs only when enabled;
	// the evaluator + notifier + heartbeat are joined before the deferred db.Close.
	alertStore := alertstore.New(db, cipher)

	// If a Mooring-hosted ntfy alert channel is configured, reconcile its protected
	// container to running at boot (best-effort, ungated). restart:unless-stopped covers
	// reboots; this also recovers from a manual `docker rm`. It ups the EXISTING on-disk
	// compose (no re-materialize), so it needs no tokens.
	if _, ok, err := alertStore.ManagedNtfy(); ok && err == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ec, cancel := context.WithTimeout(ctx, 90*time.Second)
			defer cancel()
			if err := ntfy.Up(ec, runner, cfg.DataDir, func(string) {}); err != nil {
				log.Warn("could not reconcile the managed ntfy container at boot", "err", err)
			} else {
				log.Info("managed ntfy container reconciled")
			}
		}()
	}
	// Self-update + security-advisory check (OPT-IN). Polls the GitHub API for a newer
	// release + published advisories affecting THIS version → a dashboard banner, and a
	// CRITICAL alert (pages regardless of quiet hours) when the running version is
	// itself vulnerable. Runs unconditionally (not gated on a watching operator) so a
	// Mooring compromise surfaces even on an unattended box. Contacts only api.github.com.
	var updateChecker *updatecheck.Checker
	if cfg.Server.VersionCheckOn() {
		// A hardened, non-redirect-following client for unauthenticated public GETs —
		// NOT the OAuth client (which follows redirects for the connect flow).
		ucHTTP := &http.Client{
			Timeout:       20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport:     &http.Transport{DisableKeepAlives: true, TLSHandshakeTimeout: 5 * time.Second},
		}
		iv := cfg.Server.VersionCheckInterval.D()
		if iv <= 0 {
			iv = 6 * time.Hour
		}
		updateChecker = updatecheck.New(github.New(ucHTTP, github.DefaultAPIBase, ""), "daboss2003", "mooring", Version, iv, alertStore, log)
		wg.Add(1)
		go func() { defer wg.Done(); updateChecker.Run(ctx) }()
		log.Info("self-update check enabled", "interval", iv)
	}

	// App-image / dependency vulnerability scanning (OPT-IN, HEAVY). Trivy scans each
	// deployed app's upstream images (from the registry) + build checkouts (as a
	// filesystem) — NEVER via the docker socket — and alerts on High/Critical. Results
	// surface on the Server tab.
	scanStore := imagescan.NewStore(db)
	if cfg.Server.ImageScanOn() {
		iv := cfg.Server.ImageScanInterval.D()
		if iv <= 0 {
			iv = 24 * time.Hour
		}
		appsRoot := cfg.DataDir + "-apps"
		targetsFn := func(context.Context) []imagescan.Target {
			var out []imagescan.Target
			apps, _ := gitStore.List()
			for _, app := range apps {
				def, err := defStore.Current(app.Project)
				if err != nil || def == nil {
					continue
				}
				hasBuild := false
				for _, svc := range def.Spec.Compose.Services {
					if svc.Build != nil {
						hasBuild = true
						continue
					}
					if svc.Image != "" {
						out = append(out, imagescan.Target{Project: app.Project, Kind: imagescan.KindImage, Ref: svc.Image, Label: svc.Image})
					}
				}
				if hasBuild {
					out = append(out, imagescan.Target{Project: app.Project, Kind: imagescan.KindFS, Ref: filepath.Join(appsRoot, app.Project), Label: app.Project + " dependencies"})
				}
			}
			return out
		}
		scanRunner := imagescan.NewRunner(imagescan.New("docker", imagescan.TrivyImage, 5*time.Minute), scanStore, alertStore, targetsFn, iv, log)
		wg.Add(1)
		go func() { defer wg.Done(); scanRunner.Run(ctx) }()
		log.Info("image vulnerability scanning enabled", "interval", iv)
	}

	// Disk-pressure auto-reclaim (ON by default). When disk usage crosses the threshold,
	// reclaim DANGLING docker images + build cache — the superseded builds that pile up as apps
	// redeploy — and alert. Only garbage is removed (never a tagged/in-use image, a rollback
	// which rebuilds, or app data). Rides the one-docker-child slot via TryAcquire, so it never
	// delays a deploy/self-heal.
	if cfg.Server.DiskGCOn() {
		gc := diskgc.New(
			func() (uint64, uint64, bool) {
				hs, herr := hostSampler.Sample()
				if herr != nil {
					return 0, 0, false
				}
				return hs.DiskUsed, hs.DiskTotal, true
			},
			runner, dockerSem, cfg.Server.DiskGCThresholdPct(), 15*time.Minute, cfg.Server.BuildCacheKeepSize(),
			func(level, title, detail string) {
				_ = alertStore.EnqueueInfra(context.Background(), alert.Outbox{
					Target: "disk", Kind: "disk_pressure", Level: level, Transition: "firing",
					Summary: title + ": " + detail, DedupeKey: "diskgc",
				})
			},
			log,
		)
		wg.Add(1)
		go func() { defer wg.Done(); gc.Run(ctx) }()
		log.Info("disk-pressure auto-reclaim enabled", "threshold_pct", cfg.Server.DiskGCThresholdPct())
	}

	if cfg.Alerting.Enabled {
		// The "open in dashboard" link in notifications is derived from admin.hostname
		// (we already know where the dashboard lives) — no separate admin_url.
		adminURL := ""
		if h := cfg.AdminHostnameResolved(); h != "" {
			adminURL = "https://" + h
		}
		eng := alertengine.New(alertStore, mon.Snapshot, alertengine.Config{
			EvalInterval:      cfg.Alerting.EvalInterval.D(),
			NotifyMinInterval: cfg.Alerting.NotifyMinInterval.D(),
			QuietStartHour:    cfg.Alerting.QuietStartHour,
			QuietEndHour:      cfg.Alerting.QuietEndHour,
			DeadMansURL:       cfg.Alerting.DeadMansURL,
			DeadMansInterval:  cfg.Alerting.DeadMansInterval.D(),
			AdminURL:          adminURL,
		}, log)
		wg.Add(3)
		go func() { defer wg.Done(); eng.RunEvaluator(ctx) }()
		go func() { defer wg.Done(); eng.RunNotifier(ctx) }()
		go func() { defer wg.Done(); eng.RunHeartbeat(ctx) }()
		log.Info("alert engine started", "eval_interval", cfg.Alerting.EvalInterval.D())
	}

	// Managed edge (M11, plan §6): Mooring owns a child Caddy. The route set is
	// declarative; the whole Caddy config is rendered from typed structs + pushed
	// via the admin API. Fail-closed: in external mode, or on a host that can't own
	// the edge (non-Linux / no caddy), the edge isn't started — routes still save
	// and apply once the edge is up. The supervisor is joined before db.Close.
	edgeRoutes := edge.NewRouteStore(db)
	selfHealStore := selfheal.NewStore(db)
	scalingStore := scale.NewStore(db)
	apiTokenStore := apitoken.NewStore(db)
	// Encrypted Mooring-state backups (master key reused as the AES-256 key; restore
	// needs the same key, which the operator already backs up out-of-band).
	var backupStore *backupstore.Store
	if key, kerr := config.DecodeKey(cfg.EncryptionKey); kerr == nil {
		backupStore = backupstore.New(db, filepath.Join(cfg.DataDir, "backups"), key)

		// Scheduled, encrypted app-data backups (opt-in). Snapshots every app's data volumes
		// on a fixed interval, keeps N per target, and — when an S3 destination is configured —
		// uploads each snapshot off-box. Rides the one-docker-child semaphore via TryAcquire
		// (never queues a docker child, so it can't delay a deploy/self-heal).
		if cfg.BackupsOn() && backupStore.Available() {
			var uploader backupsched.Uploader
			s3prefix := ""
			if sc := cfg.Backups.S3; sc != nil {
				pathStyle := true
				if sc.PathStyle != nil {
					pathStyle = *sc.PathStyle
				}
				cl, serr := s3.New(s3.Config{
					Endpoint: sc.Endpoint, Region: sc.Region, Bucket: sc.Bucket,
					AccessKeyID: sc.AccessKeyID, SecretAccessKey: sc.SecretAccessKey,
					UsePathStyle: pathStyle, Insecure: sc.Insecure,
				}, nil)
				if serr != nil {
					log.Warn("backups: S3 destination misconfigured; backing up locally only", "err", serr)
				} else {
					uploader = cl
					s3prefix = sc.Prefix
				}
			}
			appsFn := func() []string {
				apps, _ := gitStore.List()
				out := make([]string, 0, len(apps))
				for _, a := range apps {
					out = append(out, a.Project)
				}
				return out
			}
			alertCb := func(level, title, detail string) {
				_ = alertStore.EnqueueInfra(context.Background(), alert.Outbox{
					Target: "backups", Kind: "backup", Level: level, Transition: "firing",
					Summary: title + ": " + detail, DedupeKey: "backup:" + title + ":" + detail,
				})
			}
			bsCfg := backupsched.Config{
				Interval: cfg.BackupSchedule(), Retention: cfg.BackupRetention(),
				HelperImage: cfg.BackupHelperImage(), Key: key,
				EnvFileDir: filepath.Join(cfg.DataDir, "backups", ".creds"), S3Prefix: s3prefix,
			}
			backupRunner := backupsched.New(runner, dockerSem, backupStore, appsFn, uploader, bsCfg, alertCb, log)
			wg.Add(1)
			go func() { defer wg.Done(); backupRunner.Run(ctx) }()
			log.Info("scheduled app-data backups enabled", "interval", cfg.BackupSchedule(), "retention", cfg.BackupRetention(), "off_box", uploader != nil)
		}
	}
	var edgeRecon *edge.Reconciler
	edgeReason := ""
	if cfg.Edge.Mode == config.EdgeManaged {
		base := edge.BaseConfig{
			AdminListen:    edgeAdminListen(cfg),
			ACMEEmail:      cfg.Edge.ACMEEmail,
			ACMECA:         cfg.Edge.ACMECA,
			CAs:            edgeCAs(cfg),
			AdminHostname:  cfg.AdminHostnameResolved(), // "" unless admin is exposed; admin.subdomain expanded
			AdminAllowlist: cfg.IPAllowlist,             // becomes the edge's remote_ip gate for the admin vhost
			AdminUpstream:  cfg.AdminEdgeListen(),       // the dedicated edge listener (not the SSH-tunnel bind)
			BaseDomain:     cfg.Edge.BaseDomain,
		}
		if d := cfg.Edge.DNS01; d != nil { // opt-in *.<base_domain> wildcard via DNS-01
			base.DNS01Provider, base.DNS01Token = d.Provider, d.APIToken
			log.Info("edge: issuing a *."+cfg.Edge.BaseDomain+" wildcard cert via ACME DNS-01", "provider", d.Provider)
			// Install the provider's Caddy DNS plugin automatically (no manual xcaddy build).
			// Best-effort: if it can't install, the edge still comes up on the module-free boot
			// floor and only the wildcard reconcile fails visibly.
			if ierr := edge.EnsureDNSProvider(ctx, "caddy", d.Provider, log); ierr != nil {
				log.Warn("edge: could not auto-install the Caddy DNS plugin — the wildcard cert won't issue until it's present",
					"provider", d.Provider, "err", ierr.Error())
			}
		}
		if ok, why := edge.Available(""); ok {
			admin := edge.NewAdmin(base.AdminListen)
			edgeRecon = edge.NewReconciler(edgeRoutes, admin, base, log)
			// cert_bindings: the edge issues a cert-only ACME subject per hostname, from
			// the binding's chosen CA (default issuer when unset).
			edgeRecon.SetCertHosts(func() []edge.CertHost {
				hosts := cfgStore.AllCertHosts()
				out := make([]edge.CertHost, len(hosts))
				for i, h := range hosts {
					out[i] = edge.CertHost{Hostname: h.Hostname, CA: h.CA}
				}
				return out
			})
			sup := &edge.Supervisor{CaddyBin: "caddy", AdminListen: base.AdminListen, Log: log}
			// Boot floor WITHOUT the DNS-01 wildcard policy: if the operator's caddy lacks the
			// DNS provider module, it must fail the first (transactional) reconcile — not the
			// boot — so a missing module never bricks the whole edge (:80/:443 + all HTTP-01
			// apps + the admin vhost). The wildcard is then introduced by the first Reconcile.
			floor := base
			floor.DNS01Provider, floor.DNS01Token = "", ""
			if initCfg, rerr := edge.Render(floor, nil, nil); rerr == nil {
				sup.InitialCfg = initCfg
			}
			wg.Add(1)
			go func() { defer wg.Done(); sup.Run(ctx) }()
			log.Info("managed edge started", "admin", base.AdminListen)
		} else {
			edgeReason = why
			log.Warn("managed edge not owned on this host", "reason", why)
		}
	} else {
		edgeReason = "external edge mode — Mooring does not own the edge"
	}

	// Managed L4 (TCP/UDP) load balancer (opt-in via edge.l4_enabled): a supervised
	// child nginx-stream fronting fixed public ports (DNS/DoT/MQTTS) for internal
	// replica pools. Off by default; fail-closed if the host can't own it.
	var l4Routes *l4.RouteStore
	var l4Reconcile func(context.Context) error
	if cfg.Edge.Mode == config.EdgeManaged && cfg.Edge.L4Enabled {
		if ok, why := l4.Available(); ok {
			l4Routes = l4.NewRouteStore(db)
			l4dir := filepath.Join(cfg.DataDir, "l4")
			sup := &l4.Supervisor{
				ConfigPath: filepath.Join(l4dir, "nginx.conf"),
				Prefix:     l4dir,
				Digest:     cfg.Edge.L4NginxDigest,
				Log:        log,
			}
			l4Reconcile = func(c context.Context) error {
				rs, lerr := l4Routes.List()
				if lerr != nil {
					return lerr
				}
				// Dial discovered bridge IPs, not the compose service name: the host nginx
				// can't resolve it, and one unresolvable upstream makes `nginx -t` reject the
				// WHOLE config (every listener down). A route with no live replica is left
				// pool-less → the renderer skips it (its listener binds once a replica is up).
				pools := web.DiscoverL4Pools(c, dockerCli, log, rs)
				for i := range rs {
					if p, ok := pools[l4.PoolKey(rs[i])]; ok {
						rs[i].Pool = p
					} else {
						log.Debug("l4: route has no live replica yet; listener not bound until one is up",
							"listen", rs[i].Listen, "protocol", rs[i].Protocol, "service", rs[i].Service)
					}
				}
				return sup.Reconcile(c, rs)
			}
			if rerr := l4Reconcile(ctx); rerr != nil { // write the initial config from the store
				log.Warn("l4: initial reconcile failed", "err", rerr)
			}
			wg.Add(1)
			go func() { defer wg.Done(); sup.Run(ctx) }()
			// Periodic re-discovery (mirrors the edge): a container recreate changes a
			// replica's IP with no scale/deploy event; this rebinds the listener within ~15s.
			wg.Add(1)
			go func() { defer wg.Done(); runReconcileLoop(ctx, "l4", l4Reconcile, log) }()
			log.Info("managed L4 LB started")
		} else {
			log.Warn("managed L4 LB not owned on this host", "reason", why)
		}
	}

	srv, err := web.New(cfg, web.Deps{
		DB:          db,
		ConfigPath:  *configPath,
		Version:     Version,
		UpdateCheck: updateChecker,
		ImageScans:  scanStore,
		Log:         log,
		Monitor:     mon,
		OpsStore:    opsStore,
		Prober:      prober,
		Runner:      runner,
		Docker:      dockerCli,
		EnvStore:    envStore,
		CfgStore:    cfgStore,
		GitStore:    gitStore,
		ProvStore:   provStore,
		SetupStore:  setupStore,
		AlertStore:  alertStore,
		EdgeRoutes:  edgeRoutes,
		EdgeRecon:   edgeRecon,
		EdgeReason:  edgeReason,
		L4Routes:    l4Routes,
		L4Reconcile: l4Reconcile,
		DefStore:    defStore,
		SelfHeal:    selfHealStore,
		Scaling:     scalingStore,
		DockerSem:   dockerSem,
		APITokens:   apiTokenStore,
		Backups:     backupStore,
	})
	if err != nil {
		return err
	}

	// Wire the auto-scaling edge pool (plan §8A): each edge reconcile now discovers the
	// live replica endpoints for every route via the read-only socket-proxy and dials
	// that pool (least-conn + passive health) instead of a single service-name upstream.
	// Discovery is fail-safe — an error/empty result keeps the single dial. Only when the
	// edge is owned (edgeRecon != nil); leaving scale.Config.Edge nil otherwise (a typed
	// nil would defeat the watcher's nil check and panic on a method call).
	var edgePool scale.EdgeReconciler
	if edgeRecon != nil {
		edgeRecon.SetPoolDiscoverer(srv.DiscoverEdgePools)
		edgePool = edgeRecon
	}

	// Self-healing supervisor (M13, plan §8.5): a bounded watcher at the poll cadence
	// that acts ONLY through the gated write path (srv.Remediate via RunHeld) behind
	// the four safety gates — it can only reduce pressure or page. Joined before the
	// deferred db.Close(). Infra alerts route through the engine only when alerting is
	// enabled; otherwise a give-up is logged.
	shPolicy := selfheal.DefaultPolicy()
	protected := map[string]bool{}
	for _, p := range cfg.ProtectedProjects {
		protected[p] = true
	}
	var shAlerts *alertstore.Store
	if cfg.Alerting.Enabled {
		shAlerts = alertStore
	}
	watcher := selfheal.New(selfheal.Config{
		Store:  selfHealStore,
		Alerts: shAlerts,
		Snap:   mon.Snapshot,
		Sem:    dockerSem,
		Act:    srv,
		Policy: shPolicy,
		// Per-app override from mooring.yaml spec.self_healing (falls back to the
		// built-in default for an app with no tuned policy / on a read error).
		PolicyFor: func(app string) selfheal.Policy {
			if p, ok, err := selfHealStore.PolicyFor(app); err == nil && ok {
				return p
			}
			return shPolicy
		},
		Log:          log,
		Interval:     cfg.Monitor.PollInterval.D(),
		FloorBytes:   256 << 20, // memory-headroom floor for a momentary old+new during a restart
		WritePlaneOK: writeAllowed,
		Protected:    protected,
	})
	srv.SetCircuitClearer(func(p, svc string) { watcher.ClearCircuit(selfheal.Key{App: p, Service: svc}) })
	wg.Add(1)
	go func() { defer wg.Done(); watcher.Run(ctx) }()

	// Opt-in auto-scaler (M14, plan §8A): one controller goroutine. OFF unless a
	// per-service policy is enabled; the host-capacity guard caps every decision and
	// collapses to effective_max=1 on a near-OOM box. Scaler = the gated web write
	// path (srv via RunHeld); Edge re-renders the edge config after a scale change so
	// the new/removed replica is added to / dropped from the route's live dial pool.
	// Joined before the deferred db.Close.
	scaler := scale.New(scale.Config{
		Store:        scalingStore,
		Alerts:       shAlerts,
		Snap:         mon.Snapshot,
		Sem:          dockerSem,
		Scaler:       srv,
		Edge:         edgePool,
		Log:          log,
		Interval:     cfg.Monitor.PollInterval.D(),
		WritePlaneOK: writeAllowed,
		HostCPUMilli: uint64(runtime.NumCPU() * 1000),
		// Runtime candidacy re-check (C3/C4) from docker inspect, every tick: a
		// service that gains a shared RW volume or now runs a stateful image loses
		// candidacy and is scaled back to the floor (closes a post-enable compose
		// change). C1/C2/C6 stay operator-attested at enable time (full compose-
		// derived candidacy lands with the typed model in M15).
		IsCandidate: func(app, service string) (scale.ServiceSpec, bool) {
			spec := scale.ServiceSpec{EdgeUpstream: true, StatelessContract: true}
			if snap := mon.Snapshot(); snap != nil {
				if a := snap.AppByProject(app); a != nil {
					for _, svc := range a.Services {
						if svc.Service == service {
							spec.RWVolume = svc.HasRWVolume
							spec.Stateful = scale.StatefulImage(svc.Image)
						}
					}
				}
			}
			return spec, true
		},
		Reserves: scale.Reserves{
			MemReserveBytes:    384 << 20, // control plane + edge slice + headroom
			MemFreeFloor:       256 << 20,
			NearOOMFreeBytes:   256 << 20,
			PerReplicaMemFloor: 16 << 20,
			CPUReserveMilli:    500,
		},
	})
	wg.Add(1)
	go func() { defer wg.Done(); scaler.Run(ctx) }()

	// Edge reconcile/refresh loop (managed edge only). Two jobs:
	//   1. Boot: the edge child starts on a base-only floor (routes live in SQLite but
	//      aren't pushed at startup, unlike L4), so without an initial pass the edge 404s
	//      every app hostname after a Mooring restart until the next deploy/route-edit.
	//   2. Steady: re-discover each route's live replica pool on a cadence, so a container
	//      RECREATE that changes a replica's IP (self-heal restart, manual `docker compose
	//      up`) — neither of which fires a scale or deploy event — is still picked up.
	// Reconcile is idempotent (it reloads Caddy only when the rendered config changed), so
	// a stable replica set costs one read-plane container list per tick and no reload.
	if edgeRecon != nil {
		wg.Add(1)
		go func() { defer wg.Done(); runReconcileLoop(ctx, "edge", edgeRecon.Reconcile, log) }()
	}

	// Connected-repo auto-fetch poller (Netlify-style): a repo connected in the
	// dashboard "just works" with no webhook — Mooring FETCHES every connected repo on
	// a cadence (read-plane only; it never deploys, it surfaces an "update available"
	// the operator deploys with a click). Joined before db.Close.
	wg.Add(1)
	go func() { defer wg.Done(); srv.RunGitPoller(ctx, cfg.Git.PollIntervalD()) }()

	// Cert-renewal watcher: when the managed edge renews a leaf, re-sync each app's
	// cert_bindings + recreate the affected TLS services so they pick it up WITHOUT a
	// manual redeploy. Write-plane + managed-edge only (the edge is the renewer).
	if writeAllowed && cfg.Edge.Mode == config.EdgeManaged {
		wg.Add(1)
		go func() { defer wg.Done(); srv.RunCertRenewWatcher(ctx, time.Hour) }()
	}

	// SIGHUP hot-reloads the allowlist + auth (plan §5.1), never keys/bind.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if err := srv.Reload(ctx); err != nil {
					log.Error("config reload rejected; keeping previous", "err", err)
				} else {
					log.Info("config reloaded (allowlist + auth)")
					// srv.Reload already validated the file; re-read it to hot-swap the
					// Tier-1 retention policy too (plan §16.1 SIGHUP-reloadable).
					if newCfg, lerr := config.Load(*configPath); lerr == nil {
						retentionRunner.SetConfig(toRetentionConfig(newCfg))
						log.Info("retention policy reloaded")
					}
				}
			}
		}
	}()

	log.Info("mooring serving",
		"bind", cfg.BindAddr, "edge_mode", string(cfg.Edge.Mode), "db", db.Path)
	// Authoritative, visible signal of the login posture — so "I enabled 2FA but it
	// isn't enforced" can't go unnoticed (set auth.totp_secret + reload to enable).
	if cfg.Auth.TOTPSecret != "" {
		log.Info("login: two-factor auth (TOTP) is ENABLED")
	} else {
		log.Warn("login: two-factor auth (TOTP) is DISABLED — password only; set auth.totp_secret to enable")
	}
	runErr := srv.Run(ctx)
	// Cancel ctx (idempotent if a signal already did) so the poller exits, then
	// join it before the deferred db.Close() runs (review #8).
	stop()
	wg.Wait()
	if runErr != nil {
		return fmt.Errorf("server: %w", runErr)
	}
	log.Info("mooring stopped")
	return nil
}

// protectManagedProxy seeds the managed socket-proxy's compose project into the
// protected set so it can never be a lifecycle/self-heal/scale target. It is a no-op
// when the operator runs their own proxy (external_proxy) or when the project is
// already listed (idempotent). The proxy is the read-plane security boundary;
// protection must not depend on the operator remembering to list it.
func protectManagedProxy(cfg *config.Config) {
	if cfg.Docker.ExternalProxy {
		return
	}
	protectProject(cfg, socketproxy.Project)
}

// edgeCAs maps the configured private CAs to the edge render's CA type (the trusted-root
// PEM is passed by FILE PATH — Caddy reads it for the CA's own https).
func edgeCAs(cfg *config.Config) []edge.CA {
	if len(cfg.Edge.CAs) == 0 {
		return nil
	}
	out := make([]edge.CA, 0, len(cfg.Edge.CAs))
	for _, c := range cfg.Edge.CAs {
		var roots []string
		if c.TrustedRoot != "" {
			roots = []string{c.TrustedRoot}
		}
		out = append(out, edge.CA{Name: c.Name, DirectoryURL: c.DirectoryURL, Email: c.Email, TrustedRoots: roots})
	}
	return out
}

// protectProject idempotently adds a Mooring-managed project name to the protected set
// (so it can never be a lifecycle/self-heal/scale target or collide with an operator app).
func protectProject(cfg *config.Config, project string) {
	for _, p := range cfg.ProtectedProjects {
		if p == project {
			return
		}
	}
	cfg.ProtectedProjects = append(cfg.ProtectedProjects, project)
}

// checkWritablePaths fail-closes the boot if a required writable dir is missing or
// read-only under the hardened sandbox — turning a lazy EROFS on the first deploy /
// edge start into a clear startup error that names the path. The data dirs are fatal
// (DB, deploys, certs depend on them); a missing/unwritable admin-socket dir is a loud
// warning only (the dashboard still runs without the edge).
func checkWritablePaths(cfg *config.Config, log *slog.Logger) error {
	dirs := []string{cfg.DataDir, cfg.DataDir + "-apps"}
	managed := cfg.Edge.Mode == config.EdgeManaged
	if managed {
		dirs = append(dirs, "/var/lib/caddy")
	}
	for _, d := range dirs {
		if err := probeWritable(d); err != nil {
			return fmt.Errorf("required directory %q is not writable — check the unit's ReadWritePaths and that it is provisioned mooring-owned (a non-default data_dir must be added to ReadWritePaths): %w", d, err)
		}
	}
	if managed {
		if listen := edgeAdminListen(cfg); strings.HasPrefix(listen, "unix/") {
			dir := filepath.Dir(strings.TrimPrefix(listen, "unix/"))
			if err := probeWritable(dir); err != nil {
				log.Warn("edge admin socket dir is not writable — the managed edge will fail to start",
					"dir", dir, "err", err,
					"hint", "add RuntimeDirectory=mooring to the unit (daemon-reload + restart), or point admin.listen at a writable dir")
			}
		}
	}
	return nil
}

// probeWritable confirms dir exists and is writable by creating + removing a temp file
// (which surfaces both "missing" and "read-only under ProtectSystem=strict").
func probeWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".hm-probe-")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// edgeAdminListen returns the Caddy admin listen address — the operator's
// admin.listen if set (must be a unix socket / loopback, validated at boot), else
// the preferred unix socket (SBD-2).
func edgeAdminListen(cfg *config.Config) string {
	if cfg.Admin.Listen != "" {
		return cfg.Admin.Listen
	}
	return "unix//run/mooring/caddy-admin.sock"
}

// runReconcileLoop drives a managed plane's (edge or L4) reconcile lifecycle until ctx
// is done. It reconciles shortly after boot — retrying on a fast cadence until it first
// succeeds (the child proxy's control surface may not be up yet) — then settles to a
// steady cadence that re-discovers each route's live replica pool, so a container-recreate
// IP change is picked up with no scale/deploy event. Reconcile is expected to be cheap
// when nothing changed (the edge skips an unchanged /load; nginx -t + reload is fast), and
// a failure drops back to the fast cadence until it recovers. name labels the debug log.
func runReconcileLoop(ctx context.Context, name string, reconcile func(context.Context) error, log *slog.Logger) {
	const fast, steady = 3 * time.Second, 15 * time.Second
	interval := fast
	t := time.NewTimer(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			err := reconcile(rctx)
			cancel()
			if err != nil {
				log.Debug(name+" reconcile/pool refresh failed", "err", err)
				interval = fast // control surface not ready (or a blip) — retry soon
			} else {
				interval = steady
			}
			t.Reset(interval)
		}
	}
}

// toRetentionConfig maps the validated Tier-1 config block to the runner's policy
// (durations unwrapped, archive cap converted MB→bytes).
func toRetentionConfig(cfg *config.Config) retention.Config {
	return retention.Config{
		Interval:        cfg.Retention.Interval.D(),
		EventsMaxAge:    cfg.Retention.EventsMaxAge.D(),
		EventsMaxRows:   cfg.Retention.EventsMaxRows,
		ArchiveMaxBytes: int64(cfg.Retention.ArchiveMaxMB) << 20,
	}
}
