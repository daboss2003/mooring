package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/builder"
	"github.com/daboss2003/mooring/internal/cfgfile"
	"github.com/daboss2003/mooring/internal/cfgstore"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/envstore"
	"github.com/daboss2003/mooring/internal/git"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/secretgen"
)

// configBindingResolver resolves {{hm.KEY}} tokens in one config file against its
// explicit bindings (the superset model). A binding is a literal, or a reference to:
//   - secret: an encrypted secret value (marks the file secret-bearing)
//   - env:    the SAME service's env value (literal, or secret-backed → secret-bearing)
//   - app:    a safe app field (currently `slug`)
//   - cert:   the CONTAINER path to a same-service cert binding's tls.crt|key|ca
//
// Unknown keys fail closed (cfgfile.ErrUnknownBinding). The cert path is the mount the
// cert dir is bind-mounted at (what the container sees), never a host path.
func (s *Server) configBindingResolver(project, service string, svc definition.Service, bindings map[string]definition.Binding) cfgfile.Resolver {
	certMount := map[string]string{}
	for _, cb := range svc.CertBindings {
		certMount[cb.Hostname] = cb.Mount
	}
	revealSecret := func(name, via string) (string, bool, error) {
		if s.envStore == nil {
			return "", false, fmt.Errorf("secret store unavailable")
		}
		v, ok, err := s.envStore.Reveal(project, name)
		if err != nil {
			return "", false, err
		}
		if !ok {
			return "", false, fmt.Errorf("secret %q%s has no value — set it before deploying", name, via)
		}
		return v, true, nil
	}
	return func(key string) (string, bool, error) {
		b, ok := bindings[key]
		if !ok {
			return "", false, cfgfile.ErrUnknownBinding
		}
		switch {
		case b.Secret != "":
			return revealSecret(b.Secret, "")
		case b.Env != "":
			ev, ok := svc.Env[b.Env]
			if !ok {
				return "", false, fmt.Errorf("env key %q is not set on service %q", b.Env, service)
			}
			if ev.Secret != "" {
				return revealSecret(ev.Secret, fmt.Sprintf(" (via env %q)", b.Env))
			}
			return ev.Value, false, nil // an empty literal is a legitimate value
		case b.App != "":
			if b.App == "slug" {
				return project, false, nil
			}
			return "", false, fmt.Errorf("app field %q is not available", b.App)
		case b.Cert != "":
			// Field is the last dot-segment (crt|key|ca); the hostname is the rest.
			i := strings.LastIndexByte(b.Cert, '.')
			if i <= 0 || i == len(b.Cert)-1 {
				return "", false, fmt.Errorf("cert source %q must be HOSTNAME.crt|key|ca", b.Cert)
			}
			host, field := b.Cert[:i], b.Cert[i+1:]
			mount, ok := certMount[host]
			if !ok {
				return "", false, fmt.Errorf("cert binding %q not defined on service %q", host, service)
			}
			fn := map[string]string{"crt": "tls.crt", "key": "tls.key", "ca": "tls.ca"}[field]
			if fn == "" {
				return "", false, fmt.Errorf("cert field %q must be crt|key|ca", field)
			}
			return path.Join(mount, fn), false, nil // container-visible path (read-only bind)
		default:
			return b.Value, false, nil
		}
	}
}

// loadRepoDefinition reads this app's mooring file at the pinned commit and parses it
// (Mooring generates the compose from it — the repo never supplies a compose). The file
// is mooring.yaml by default, or a variant (mooring.staging.yaml / mooring.prod.yaml)
// when the repo holds several and this app instance was connected to one of them. If the
// file is absent, it scaffolds a default from the repo's detected stack so "connect a
// repo" still works. The app's identity is its REGISTRATION slug (chosen at connect from
// the file's metadata.slug), so the parsed slug is overridden here — editing the file's
// slug afterwards can't rename or hijack the app.
func (s *Server) loadRepoDefinition(ctx context.Context, repo *git.Repo, sha, slug, mooringFile string) (*definition.Definition, bool, error) {
	if mooringFile == "" {
		mooringFile = "mooring.yaml"
	}
	if b, err := repo.CatFile(ctx, sha, mooringFile); err == nil {
		d, perr := definition.Parse(b)
		if perr != nil {
			return nil, false, fmt.Errorf("%s: %w", mooringFile, perr)
		}
		d.Metadata.Slug = slug
		return d, false, nil
	}
	// The CatFile failed (the file is absent, or it's a symlink/gitlink/wrong mode).
	// Scaffolding a generic default is the right "connect a repo that has no config
	// yet" behavior ONLY for the plain mooring.yaml. An app explicitly connected to a
	// NAMED variant (mooring.prod.yaml, …) exists BECAUSE of that file — if it's gone
	// at the deployed commit, fail closed rather than silently replacing the operator's
	// real config with a guessed single-service app under the same slug.
	if mooringFile != "mooring.yaml" {
		return nil, false, fmt.Errorf("the mooring file %q this app was connected to is missing (or not a regular file) at %s — restore it in the repo, or reconnect the app to a different file", mooringFile, shortSha(sha))
	}
	// No mooring.yaml — scaffold a single build service from the detected stack.
	files, err := repo.LsFiles(ctx, sha)
	if err != nil {
		return nil, false, fmt.Errorf("list repo files: %w", err)
	}
	b, derr := builder.Resolve(builder.Spec{Language: "auto"}, topLevelSet(files))
	if derr != nil {
		return nil, false, fmt.Errorf("no %s in the repo and %w — add a %s", mooringFile, derr, mooringFile)
	}
	d := &definition.Definition{
		APIVersion: definition.APIVersion,
		Kind:       "App",
		Metadata:   definition.Metadata{Slug: slug},
		Spec: definition.Spec{
			Compose: definition.Compose{
				Source:   definition.SourceGenerated,
				Services: map[string]definition.Service{"app": {Build: &definition.Build{Language: b.Name()}}},
			},
		},
	}
	return d, true, nil
}

// writeGeneratedDockerfiles renders the Mooring-owned Dockerfile for each build
// service and writes it under the run dir at builder.DockerfilePath (confined,
// symlink-safe). Detection (language: auto) reads the repo's top-level file list at
// the pinned commit.
// writeGeneratedDockerfiles generates + writes each build service's Dockerfile and returns the set
// of service names whose generated image runs as the pinned non-root UID (from the actual generated
// Dockerfile, so an auto-detected php build that runs as www-data is correctly excluded). The caller
// uses that set to reconcile only those services' data-volume ownership to the pinned UID.
func (s *Server) writeGeneratedDockerfiles(ctx context.Context, repo *git.Repo, sha, rd string, def *definition.Definition, onLine func(string)) (map[string]bool, error) {
	if defHasBuild(def) {
		// CRITICAL: the build context is the run dir, which also holds .mooring/
		// (rendered config + secret VALUES). Exclude it so `COPY . .` can never bake
		// a secret into an image layer.
		if err := ensureDockerignore(rd); err != nil {
			return nil, fmt.Errorf("write .dockerignore: %w", err)
		}
	}
	nonrootSvcs := map[string]bool{}
	var files []string
	names := make([]string, 0, len(def.Spec.Compose.Services))
	for n := range def.Spec.Compose.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		svc := def.Spec.Compose.Services[name]
		if svc.Build == nil {
			continue
		}
		if files == nil {
			var err error
			if files, err = repo.LsFiles(ctx, sha); err != nil {
				return nil, fmt.Errorf("list repo files: %w", err)
			}
		}
		// Auto-detection (language: auto) reads the files in the service's build dir
		// (the repo root when build.dir is unset), so a Go service in a subdir of a
		// Node repo detects correctly.
		dockerfile, err := builder.Generate(buildSpecFor(name, svc), filesInDir(files, svc.Build.Dir))
		if err != nil {
			return nil, fmt.Errorf("service %q: %w", name, err)
		}
		if builder.RunsAsNonroot(dockerfile) {
			nonrootSvcs[name] = true
		}
		dest := filepath.Join(rd, filepath.FromSlash(builder.DockerfilePath(name)))
		if !confinedUnder(dest, rd) {
			return nil, fmt.Errorf("service %q: generated Dockerfile path escapes the run dir", name)
		}
		// Symlink-safe write (temp + rename; ancestors checked) — see atomicWrite.
		if err := atomicWrite(dest, []byte(dockerfile), 0o644, rd); err != nil {
			return nil, fmt.Errorf("service %q: write Dockerfile: %w", name, err)
		}
		onLine("generated Dockerfile for " + name)
	}
	return nonrootSvcs, nil
}

// reconciledVol records a volume whose ownership reconcileVolumeOwnership changed, and the UID it
// previously had — so the deploy can roll it back if the subsequent `up` fails.
type reconciledVol struct {
	name    string
	prevUID int
}

// reconcileVolumeOwnership restores each eligible named, writable data volume to the pinned non-root
// UID before `up` — healing the UID-drift class (see internal/builder.NonrootUID). A volume is
// eligible ONLY when EVERY service that mounts it runs as the pinned UID (nonrootSvcs, derived from
// the real generated Dockerfile so an auto-detected php/root build is excluded): a volume shared with
// a service that runs as a different UID (a stock postgres at 999, php at www-data) is left
// untouched, so we never rewrite a co-consumer's ownership. Read-only-only volumes are skipped
// (nothing writes them). BEST-EFFORT — a reconcile failure is logged and never fails the deploy. It
// returns the volumes it actually changed (with their prior UID) so the caller can roll ownership
// back if the deploy then fails (otherwise a chowned volume + a failed `up` would leave the still-
// running OLD container unable to write its own data).
func (s *Server) reconcileVolumeOwnership(ctx context.Context, slug string, def *definition.Definition, nonrootSvcs map[string]bool, onLine func(string)) []reconciledVol {
	if s.runner == nil || len(nonrootSvcs) == 0 {
		return nil
	}
	var changed []reconciledVol
	for _, volShort := range eligibleReconcileVolumes(def, nonrootSvcs) {
		volName := slug + "_" + volShort // compose's default naming: <project>_<volume>
		prev, did, err := s.runner.ReconcileVolumeOwner(ctx, volName, builder.NonrootUID, onLine)
		if err != nil {
			s.log.Warn("volume ownership reconcile failed (continuing deploy)", "app", slug, "volume", volName, "err", err)
			continue
		}
		if did {
			changed = append(changed, reconciledVol{name: volName, prevUID: prev})
			onLine(fmt.Sprintf("• healed UID drift: reconciled volume %s to uid %d", volName, builder.NonrootUID))
			s.log.Info("reconciled volume ownership", "app", slug, "volume", volName, "from_uid", prev, "to_uid", builder.NonrootUID)
		}
	}
	return changed
}

// eligibleReconcileVolumes returns the short names of named volumes safe to reconcile to the pinned
// non-root UID: writable (something writes it), and mounted ONLY by services that run as that UID
// (all consumers ∈ nonrootSvcs). A volume shared with a service that runs as a different UID (a stock
// postgres at 999, php at www-data, a root build) is EXCLUDED, so the chown never rewrites a
// co-consumer's ownership. Pure + sorted for deterministic order and unit testing.
func eligibleReconcileVolumes(def *definition.Definition, nonrootSvcs map[string]bool) []string {
	type volUse struct {
		consumers map[string]bool
		writable  bool
	}
	uses := map[string]*volUse{}
	for name, svc := range def.Spec.Compose.Services {
		for _, v := range svc.Volumes {
			if v.Name == "" { // a run-dir bind, not a named volume
				continue
			}
			u := uses[v.Name]
			if u == nil {
				u = &volUse{consumers: map[string]bool{}}
				uses[v.Name] = u
			}
			u.consumers[name] = true
			if !v.ReadOnly {
				u.writable = true
			}
		}
	}
	var out []string
	for volShort, u := range uses {
		if !u.writable {
			continue // never written → no drift to heal
		}
		allPinned, anyPinned := true, false
		for c := range u.consumers {
			if nonrootSvcs[c] {
				anyPinned = true
			} else {
				allPinned = false
			}
		}
		if anyPinned && allPinned {
			out = append(out, volShort)
		}
	}
	sort.Strings(out)
	return out
}

// rollbackVolumeOwnership restores volumes reconcileVolumeOwnership changed back to their prior UID —
// called when the deploy's `up` fails, so a chowned volume plus a still-running OLD container never
// leaves that container unable to write its own data. Best-effort + detached (a cancelled deploy
// still rolls back).
func (s *Server) rollbackVolumeOwnership(ctx context.Context, changed []reconciledVol, onLine func(string)) {
	if s.runner == nil {
		return
	}
	for _, v := range changed {
		if _, _, err := s.runner.ReconcileVolumeOwner(ctx, v.name, v.prevUID, onLine); err != nil {
			s.log.Warn("volume ownership rollback failed", "volume", v.name, "to_uid", v.prevUID, "err", err)
			continue
		}
		onLine(fmt.Sprintf("• deploy failed — rolled volume %s ownership back to uid %d", v.name, v.prevUID))
		s.log.Info("rolled back volume ownership after failed deploy", "volume", v.name, "to_uid", v.prevUID)
	}
}

// buildSpecFor projects a definition build onto the builder spec (non-root defaults on).
func buildSpecFor(name string, svc definition.Service) builder.Spec {
	b := svc.Build
	nonroot := true
	if b.Nonroot != nil {
		nonroot = *b.Nonroot
	}
	return builder.Spec{
		Service:  name,
		Language: b.Language,
		Dir:      b.Dir,
		Version:  b.Version,
		Base:     b.Base,
		Install:  b.Install,
		Build:    b.BuildCmd,
		Start:    b.Start,
		Env:      b.Env,
		Packages: b.Packages,
		Output:   b.Output,
		Nonroot:  nonroot,
	}
}

// ensureGeneratedSecrets mints any `spec.secrets[].generate` value that does not
// yet exist in the app's encrypted store, then persists the additions as a new
// version. It is the declarative replacement for a bootstrap script's `openssl
// rand`/`genrsa` lines: minted server-side, stored encrypted, never displayed.
//
// It is strictly idempotent — a name that already has a value is left untouched,
// so re-deploys never rotate a live secret out from under a running app. A keypair
// generate (rsa/ed25519) mints two entries: the private key under <NAME> and the
// derived public key under <NAME>_PUB, both base64-encoded (Enc="b64") so the
// PEM survives the no-newline store and is decoded when written as a secret_file.
func (s *Server) ensureGeneratedSecrets(ctx context.Context, project string, def *definition.Definition, onLine func(string)) error {
	type want struct{ name, spec string }
	var wants []want
	for _, sec := range def.Spec.Secrets {
		if sec.Generate != "" {
			wants = append(wants, want{sec.Name, sec.Generate})
		}
	}
	if len(wants) == 0 {
		return nil
	}
	if s.envStore == nil {
		return fmt.Errorf("secret store unavailable")
	}
	cur, _, err := s.envStore.Current(project)
	if err != nil {
		return err
	}
	existing := make(map[string]bool, len(cur))
	for _, e := range cur {
		existing[e.Key] = true
	}
	var added []envstore.Entry
	for _, w := range wants {
		if existing[w.name] {
			continue // never overwrite a live value
		}
		outs, err := secretgen.Mint(w.spec)
		if err != nil {
			return fmt.Errorf("secret %q: %w", w.name, err)
		}
		for _, o := range outs {
			key := w.name + o.NameSuffix
			if existing[key] {
				continue
			}
			added = append(added, envstore.Entry{Key: key, Value: secret.New(o.Value), Secret: true, Enc: o.Enc})
			existing[key] = true
		}
		onLine("minted secret " + w.name)
	}
	if len(added) == 0 {
		return nil
	}
	if _, err := s.envStore.Save(ctx, project, append(cur, added...), "generate"); err != nil {
		return fmt.Errorf("persist generated secrets: %w", err)
	}
	return nil
}

// materializeManaged renders each service's config_files (from the repo @ pinned
// commit, or an inline template) and writes each secret_files value (from the
// encrypted store) into the run dir at the Mooring-managed paths — the read-only
// bind mounts for these were already emitted into the generated compose by reconcile.
// All writes are confined + symlink-safe (atomicWrite). secret values are 0600.
// (cert_bindings sync is a follow-on — it integrates with the edge cert issuance.)
func (s *Server) materializeManaged(ctx context.Context, repo *git.Repo, sha, rd, project string, def *definition.Definition) error {
	names := make([]string, 0, len(def.Spec.Compose.Services))
	for n := range def.Spec.Compose.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		svc := def.Spec.Compose.Services[name]
		for i, cf := range svc.ConfigFiles {
			var content []byte
			if cf.Repo != "" {
				b, err := repo.CatFile(ctx, sha, cf.Repo) // pinned commit; rejects symlinks/gitlinks
				if err != nil {
					return fmt.Errorf("service %q config file %q: %w", name, cf.Repo, err)
				}
				content = b
			} else {
				content = []byte(cf.Template)
			}
			// Render {{hm.KEY}} tokens against the file's explicit bindings (literal /
			// secret / env / app / cert); the app's own ${…} survive untouched.
			rendered, _, rerr := cfgfile.Render(content, s.configBindingResolver(project, name, svc, cf.Bindings))
			if rerr != nil {
				return fmt.Errorf("service %q config file: %w", name, rerr)
			}
			dest := filepath.Join(rd, filepath.FromSlash(definition.ManagedConfigPath(name, i)))
			if !confinedUnder(dest, rd) {
				return fmt.Errorf("service %q config file path escapes the run dir", name)
			}
			// 0644 (world-readable): the bind-mounted file must be readable by the
			// CONTAINER's process, which runs as a non-root user different from the
			// mooring user that wrote it — a 0600/0640 mooring-owned file EACCESes
			// inside the container. Host exposure is confined by the 0700 run dir (only
			// mooring + root can traverse it), so this does not widen on-host access.
			if err := atomicWrite(dest, rendered, 0o644, rd); err != nil {
				return fmt.Errorf("service %q config file: %w", name, err)
			}
		}
		for _, sec := range svc.SecretFiles {
			if s.envStore == nil {
				return fmt.Errorf("service %q secret_files %q: secret store unavailable", name, sec)
			}
			ent, ok, err := s.envStore.Get(project, sec)
			if err != nil {
				return fmt.Errorf("service %q secret_files %q: %w", name, sec, err)
			}
			if !ok {
				return fmt.Errorf("service %q secret_files %q: secret has no value — set it before deploying", name, sec)
			}
			// Decode any storage encoding (a generated PEM keypair is stored
			// base64'd) so the file holds the real PEM/value bytes.
			val, err := ent.DecodedValue()
			if err != nil {
				return fmt.Errorf("service %q secret_files %q: decode: %w", name, sec, err)
			}
			dest := filepath.Join(rd, filepath.FromSlash(definition.ManagedSecretPath(name, sec)))
			if !confinedUnder(dest, rd) {
				return fmt.Errorf("service %q secret file path escapes the run dir", name)
			}
			// 0644 like config files above: the container (non-root, different UID)
			// must be able to read this bind-mounted secret file; on-host access stays
			// confined by the 0700 run dir. (A 0600 file is unreadable in the container.)
			if err := atomicWrite(dest, val, 0o644, rd); err != nil {
				return fmt.Errorf("service %q secret file: %w", name, err)
			}
		}
	}
	return nil
}

// ensureDockerignore guarantees the build context excludes Mooring's managed dir
// (.mooring/ holds rendered config + secret VALUES + the generated Dockerfile), so a
// `COPY . .` in a generated Dockerfile can never bake secrets into image layers. It
// merges with the repo's own .dockerignore if present.
func ensureDockerignore(rd string) error {
	p := filepath.Join(rd, ".dockerignore")
	var existing []byte
	if b, err := os.ReadFile(p); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.TrimSuffix(strings.TrimSpace(line), "/") == ".mooring" {
				return nil // already excluded
			}
		}
		existing = b
	}
	var buf bytes.Buffer
	buf.Write(existing)
	if len(existing) > 0 && !bytes.HasSuffix(existing, []byte("\n")) {
		buf.WriteByte('\n')
	}
	buf.WriteString("# added by Mooring — never send rendered config/secrets into the build context\n.mooring\n")
	return atomicWrite(p, buf.Bytes(), 0o644, rd)
}

// managedDigests hashes each service's materialized managed files (config_files,
// secret_files, cert tls.crt/key) so a content change can be detected across deploys
// (compose only diffs a service's config, not its bind-mounted file CONTENT). A
// service with no managed files has no entry.
func (s *Server) managedDigests(rd string, def *definition.Definition) map[string]string {
	out := map[string]string{}
	for _, name := range sortedServiceNames(def) {
		svc := def.Spec.Compose.Services[name]
		h := sha256.New()
		any := false
		add := func(rel string) {
			b, err := os.ReadFile(filepath.Join(rd, filepath.FromSlash(rel)))
			if err != nil {
				return
			}
			fmt.Fprintf(h, "%s\x00%d\x00", rel, len(b))
			h.Write(b)
			any = true
		}
		for i := range svc.ConfigFiles {
			add(definition.ManagedConfigPath(name, i))
		}
		for _, sec := range svc.SecretFiles {
			add(definition.ManagedSecretPath(name, sec))
		}
		for _, cb := range svc.CertBindings {
			add(definition.ManagedCertDir(name, cb.Hostname) + "/tls.crt")
			add(definition.ManagedCertDir(name, cb.Hostname) + "/tls.key")
		}
		if any {
			out[name] = hex.EncodeToString(h.Sum(nil))
		}
	}
	return out
}

// readDigestState reads the last deploy's per-service managed-file digests.
func readDigestState(rd string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(filepath.Join(rd, ".mooring", "state", "digests"))
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, " "); ok && k != "" {
			out[k] = v
		}
	}
	return out
}

// writeDigestState records the current per-service managed-file digests (0600, under
// the gitignored .mooring tree so it never enters the build context).
func (s *Server) writeDigestState(rd string, m map[string]string) error {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	for _, k := range names {
		fmt.Fprintf(&buf, "%s %s\n", k, m[k])
	}
	return atomicWrite(filepath.Join(rd, ".mooring", "state", "digests"), buf.Bytes(), 0o600, rd)
}

// changedServices are the services whose managed-file digest changed since last
// deploy. New services (no prior digest) are excluded — the `up` creates them.
func changedServices(old, current map[string]string) []string {
	var out []string
	for svc, h := range current {
		if prev, ok := old[svc]; ok && prev != h {
			out = append(out, svc)
		}
	}
	sort.Strings(out)
	return out
}

// defaultCaddyCertRoot is where the managed edge (Caddy, XDG_DATA_HOME=/var/lib/caddy)
// stores its issued certs: <root>/<issuer-dir>/<hostname>/<hostname>.{crt,key}.
const defaultCaddyCertRoot = "/var/lib/caddy/caddy/certificates"

// registerCertBindings persists this app's cert_bindings into the cert store so the
// managed edge issues a cert for each hostname (a cert-only ACME subject), then
// reconciles the edge. Best-effort: a reconcile failure (edge not owned / Caddy down)
// is logged, not fatal — issuance applies when the edge is up.
func (s *Server) registerCertBindings(ctx context.Context, project string, def *definition.Definition, onLine func(string)) error {
	if s.cfgStore == nil {
		return nil
	}
	// Fail closed on an undefined CA BEFORE writing anything — a cert binding can only
	// reference a CA the operator defined in config.yaml (no trust-injection).
	for _, name := range sortedServiceNames(def) {
		for _, cb := range def.Spec.Compose.Services[name].CertBindings {
			if cb.CA != "" && !s.cfg.HasEdgeCA(cb.CA) {
				return fmt.Errorf("cert_binding %q references unknown CA %q — define it in config.yaml edge.cas", cb.Hostname, cb.CA)
			}
		}
	}
	any := false
	for _, name := range sortedServiceNames(def) {
		for _, cb := range def.Spec.Compose.Services[name].CertBindings {
			// cb.Hostname is already the final FQDN (any `subdomain:` was expanded upstream).
			err := s.cfgStore.SaveCertBinding(ctx, project, cfgstore.CertBinding{
				BindingName: certBindingKey(name, cb.Hostname),
				Hostname:    cb.Hostname,
				SyncDirRel:  definition.ManagedCertDir(name, cb.Hostname),
				Required:    true,
				CA:          cb.CA,
			})
			if err != nil {
				onLine("warning: could not register cert binding for " + cb.Hostname + ": " + err.Error())
				continue
			}
			any = true
		}
	}
	if any && s.edgeRecon != nil {
		if err := s.edgeRecon.Reconcile(ctx); err != nil {
			onLine("note: edge not reconciled yet (it issues the cert when up): " + err.Error())
		}
	}
	return nil
}

// certIssueWaitTimeout bounds how long a deploy waits for the managed edge to issue a
// cert_binding's ACME cert before giving up. HTTP-01 normally completes in seconds; the
// generous ceiling absorbs DNS propagation without holding a doomed deploy forever.
// A var (not const) so tests can shrink it.
var certIssueWaitTimeout = 150 * time.Second

// waitForCertBindings blocks until the managed edge has issued every cert_binding's
// leaf cert (ACME completes) or the timeout elapses, polling the edge's cert store and
// streaming progress. registerCertBindings has already told the edge to issue these
// subjects; this gives ACME the few seconds it needs so a SINGLE deploy finishes on its
// own — instead of the old fail-closed "re-deploy once it is issued" that forced the
// operator to deploy twice. On timeout it returns an actionable error (DNS / :80).
func (s *Server) waitForCertBindings(ctx context.Context, def *definition.Definition, onLine func(string)) error {
	root := s.caddyCertRoot
	if root == "" {
		root = defaultCaddyCertRoot
	}
	pending := map[string]bool{}
	for _, name := range sortedServiceNames(def) {
		for _, cb := range def.Spec.Compose.Services[name].CertBindings {
			pending[cb.Hostname] = true
		}
	}
	if len(pending) == 0 {
		return nil
	}
	sweep := func() {
		for h := range pending {
			if _, _, ok := findCaddyLeaf(root, h); ok {
				delete(pending, h)
				onLine("edge issued the TLS cert for " + h)
			}
		}
	}
	sweep()
	if len(pending) == 0 {
		return nil
	}
	for h := range pending {
		onLine("waiting for the edge to issue the TLS cert for " + h + " via ACME (automatic; up to " + certIssueWaitTimeout.String() + ")…")
	}
	wctx, cancel := context.WithTimeout(ctx, certIssueWaitTimeout)
	defer cancel()
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	ticks := 0
	for {
		select {
		case <-wctx.Done():
			var still []string
			for h := range pending {
				still = append(still, h)
			}
			sort.Strings(still)
			return fmt.Errorf("the edge did not issue the TLS cert for %s within %s — check that the hostname's DNS points at this server and that :80/:443 are reachable from the internet (Let's Encrypt HTTP-01), then re-deploy", strings.Join(still, ", "), certIssueWaitTimeout)
		case <-tick.C:
			sweep()
			if len(pending) == 0 {
				return nil
			}
			// Heartbeat ~every 15s so the deploy's streaming connection never goes
			// idle long enough for the browser/edge proxy to drop it ("network error").
			if ticks++; ticks%5 == 0 {
				var still []string
				for h := range pending {
					still = append(still, h)
				}
				sort.Strings(still)
				onLine(fmt.Sprintf("still waiting for the edge to issue %s … (%ds elapsed)", strings.Join(still, ", "), ticks*3))
			}
		}
	}
}

// syncCertBindings copies each cert_binding's issued leaf cert+key from the edge's
// store into the app's managed cert dir (tls.crt 0644, tls.key 0600), confined +
// symlink-safe. waitForCertBindings runs first, so by here the leaf should exist; the
// not-issued error remains as a fail-closed backstop.
func (s *Server) syncCertBindings(rd string, def *definition.Definition) error {
	root := s.caddyCertRoot
	if root == "" {
		root = defaultCaddyCertRoot
	}
	for _, name := range sortedServiceNames(def) {
		for _, cb := range def.Spec.Compose.Services[name].CertBindings {
			crt, key, ok := findCaddyLeaf(root, cb.Hostname)
			if !ok {
				return fmt.Errorf("service %q: the edge has not issued the TLS cert for %s yet — re-deploy once it is issued", name, cb.Hostname)
			}
			cdata, err := os.ReadFile(crt)
			if err != nil {
				return fmt.Errorf("service %q cert %s: %w", name, cb.Hostname, err)
			}
			kdata, err := os.ReadFile(key)
			if err != nil {
				return fmt.Errorf("service %q cert %s: %w", name, cb.Hostname, err)
			}
			dir := filepath.Join(rd, filepath.FromSlash(definition.ManagedCertDir(name, cb.Hostname)))
			if !confinedUnder(dir, rd) {
				return fmt.Errorf("service %q cert dir escapes the run dir", name)
			}
			// The cert dir is bind-mounted into the container, so its non-root user must
			// be able to TRAVERSE it. MkdirAll is a no-op on a dir that already exists, so
			// an explicit Chmod is needed to fix a stale 0700 left by an older deploy (the
			// run dir is not wiped between deploys). The 0700 run dir keeps the host out.
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("service %q cert dir: %w", name, err)
			}
			if err := os.Chmod(dir, 0o755); err != nil {
				return fmt.Errorf("service %q cert dir chmod: %w", name, err)
			}
			if err := atomicWrite(filepath.Join(dir, "tls.crt"), cdata, 0o644, rd); err != nil {
				return fmt.Errorf("service %q cert: %w", name, err)
			}
			// 0644: the cert-binding app (e.g. emqx) reads this key as its own non-root
			// user from the bind mount; confined on-host by the 0700 run dir.
			if err := atomicWrite(filepath.Join(dir, "tls.key"), kdata, 0o644, rd); err != nil {
				return fmt.Errorf("service %q cert key: %w", name, err)
			}
		}
	}
	return nil
}

// findCaddyLeaf locates <root>/<issuer>/<host>/<host>.{crt,key} across issuer dirs
// (the issuer subdir name depends on the ACME CA, so we scan rather than hardcode it).
func findCaddyLeaf(root, host string) (crt, key string, ok bool) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", "", false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		c := filepath.Join(root, e.Name(), host, host+".crt")
		k := filepath.Join(root, e.Name(), host, host+".key")
		if isRegularFile(c) && isRegularFile(k) {
			return c, k, true
		}
	}
	return "", "", false
}

func isRegularFile(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode().IsRegular()
}

// certBindingKey is a cert-store binding name derived from the service + hostname
// (the store's key grammar excludes dots).
func certBindingKey(service, hostname string) string {
	return service + "-" + strings.ReplaceAll(hostname, ".", "-")
}

// sortedServiceNames returns the stack's service names in deterministic order.
func sortedServiceNames(def *definition.Definition) []string {
	names := make([]string, 0, len(def.Spec.Compose.Services))
	for n := range def.Spec.Compose.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// defBindSources is every run_dir-relative bind source declared across the stack's
// services (named volumes excluded — Docker manages those).
func defBindSources(def *definition.Definition) []string {
	var out []string
	for _, svc := range def.Spec.Compose.Services {
		for _, v := range svc.Volumes {
			if v.Source != "" && v.Name == "" {
				out = append(out, v.Source)
			}
		}
	}
	return out
}

// materializeBindDirs pre-creates each bind source as a Mooring-owned directory under
// the run dir BEFORE `docker compose up`, so a missing bind isn't created by the Docker
// daemon as root. Each is confined under the run dir (symlink-safe); an existing path
// (file or dir) is left untouched.
func materializeBindDirs(rd string, binds []string) error {
	for _, src := range binds {
		if src == "" {
			continue
		}
		dest := filepath.Join(rd, filepath.FromSlash(src))
		// confinedUnder resolves symlinks, so a dest (or ancestor) pointing outside rd
		// is rejected here.
		if !confinedUnder(dest, rd) {
			return fmt.Errorf("bind source %q escapes the app directory", src)
		}
		if fi, err := os.Lstat(dest); err == nil {
			// A symlinked bind source could be swapped to escape rd — refuse it.
			if fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("bind source %q is a symlink", src)
			}
			// Pre-existing dir: re-apply 0755 so a non-root container can traverse the
			// bind mount. MkdirAll is a no-op here, so a stale 0700 from an older deploy
			// (the run dir isn't wiped) would otherwise persist → "permission denied".
			if fi.IsDir() {
				if err := os.Chmod(dest, 0o755); err != nil {
					return fmt.Errorf("bind dir %q chmod: %w", src, err)
				}
			}
			continue
		}
		// No ancestor may be a symlink BEFORE we create through it (no-follow), and we
		// re-check AFTER MkdirAll to fail closed on a symlink planted during the race.
		if err := noSymlinkComponents(dest, rd); err != nil {
			return fmt.Errorf("bind source %q: %w", src, err)
		}
		// 0755 (traversable): a bind-mounted dir must be enterable by the container's
		// non-root user. It's a subdir of the 0700 run dir, so the host stays confined.
		// Chmod after MkdirAll so the mode is exact regardless of umask.
		if err := os.MkdirAll(dest, 0o755); err != nil {
			return fmt.Errorf("create bind dir %q: %w", src, err)
		}
		if err := os.Chmod(dest, 0o755); err != nil {
			return fmt.Errorf("bind dir %q chmod: %w", src, err)
		}
		if err := noSymlinkComponents(dest, rd); err != nil {
			return fmt.Errorf("bind source %q: %w", src, err)
		}
	}
	return nil
}

// defHasBuild reports whether any service builds from source (→ compose --build).
func defHasBuild(def *definition.Definition) bool {
	for _, svc := range def.Spec.Compose.Services {
		if svc.Build != nil {
			return true
		}
	}
	return false
}

// topLevelSet is the set of a repo's top-level file names (for stack detection).
func topLevelSet(files []string) map[string]bool {
	top := map[string]bool{}
	for _, f := range files {
		f = strings.TrimPrefix(f, "./")
		if f == "" || strings.Contains(f, "/") {
			continue // only top-level entries signal the stack
		}
		top[f] = true
	}
	return top
}

// filesInDir is the set of file names directly under dir (for stack detection of a
// build.dir subdir). dir=="" means the repo top level. Nested files are ignored —
// detection keys off the manifests that sit at the build root (go.mod, package.json…).
func filesInDir(files []string, dir string) map[string]bool {
	dir = strings.Trim(strings.TrimPrefix(dir, "./"), "/")
	if dir == "" {
		return topLevelSet(files)
	}
	prefix := dir + "/"
	set := map[string]bool{}
	for _, f := range files {
		f = strings.TrimPrefix(f, "./")
		rest, ok := strings.CutPrefix(f, prefix)
		if !ok || rest == "" || strings.Contains(rest, "/") {
			continue // only entries directly under dir signal the stack
		}
		set[rest] = true
	}
	return set
}
