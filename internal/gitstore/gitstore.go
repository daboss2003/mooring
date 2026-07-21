// Package gitstore persists per-app repo-path GitOps config (plan §7.6): the
// repo URL/ref/paths, the FSM state (deployed/staged commit, update_state), and
// the secret material (PAT/deploy-key, webhook HMAC secret) AES-256-GCM at rest.
// The webhook token is stored only as a SHA-256 hash; the token itself is never
// persisted or logged.
package gitstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/crypto"
	"github.com/daboss2003/mooring/internal/git"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/store"
)

var slugRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)

func validSlug(s string) bool { return slugRe.MatchString(s) }

// mooringFileRe matches a root-level mooring file: the plain mooring.yaml or a
// named variant like mooring.staging.yaml / mooring.prod.yaml (.yml accepted).
// Root-level only — no path separators, so a stored value can never escape the repo
// root or smuggle traversal into a CatFile path.
var mooringFileRe = regexp.MustCompile(`^mooring(\.[a-z0-9][a-z0-9-]*)?\.ya?ml$`)

// ValidMooringFile reports whether name is an acceptable per-app mooring file.
func ValidMooringFile(name string) bool { return mooringFileRe.MatchString(name) }

// Config is one repo app's GitOps configuration + state.
type Config struct {
	Project        string
	RepoURL        string
	Ref            string
	ComposePath    string
	DockerfilePath string
	MooringFile    string // repo-relative mooring file driving this app (default mooring.yaml)
	AutoDeploy     bool
	BuildPolicy    string
	CredKind       string // "" | token | ssh
	DeployedCommit string
	StagedCommit   string
	UpdateState    string
	CommitsBehind  int
	LastFetchAt    int64
	LastFetchError string
	HasWebhook     bool
	PreviewEnabled bool   // base app opts into per-PR preview environments
	PreviewOf      string // non-empty ⇒ this app is an ephemeral preview OF this base slug
}

// Store persists GitOps config.
type Store struct {
	db     *store.DB
	cipher *secret.Cipher
}

// New builds a Store.
func New(db *store.DB, cipher *secret.Cipher) *Store { return &Store{db: db, cipher: cipher} }

// SaveInput is an operator's repo-app config edit.
type SaveInput struct {
	Project        string
	RepoURL        string
	Ref            string
	ComposePath    string
	DockerfilePath string
	MooringFile    string // "" keeps the stored value (or defaults to mooring.yaml on insert)
	AutoDeploy     bool
	BuildPolicy    string
	// NewCred tri-state: nil keeps, "" clears, value replaces.
	NewCred    *string
	CredKind   string // token | ssh (when NewCred set)
	KnownHosts string // ssh only
}

var validState = map[string]bool{
	"up_to_date": true, "update_available": true, "deploying": true,
	"update_blocked": true, "history_rewritten": true,
}

// Save validates + upserts a repo app's config (URL through the SSRF allowlist).
func (s *Store) Save(ctx context.Context, in SaveInput) error {
	if !validSlug(in.Project) {
		return errors.New("app slug must match [a-z][a-z0-9-]{1,30}")
	}
	if err := git.ValidateRepoURL(in.RepoURL); err != nil {
		return err
	}
	if in.Ref == "" {
		in.Ref = "refs/heads/main"
	}
	if !strings.HasPrefix(in.Ref, "refs/") {
		return errors.New("git_ref must be fully-qualified (e.g. refs/heads/main)")
	}
	if in.ComposePath == "" {
		in.ComposePath = "docker-compose.yml"
	}
	if in.BuildPolicy != "never" && in.BuildPolicy != "on_missing" {
		in.BuildPolicy = "never"
	}
	// Resolve the mooring file driving this app: an empty value KEEPS the stored
	// one (so the basic edit form never has to round-trip it), defaulting to the
	// plain mooring.yaml on a fresh insert. A provided value is validated to a
	// root-level mooring*.yaml — the connect/discovery flow is its only writer.
	mooringFile := strings.TrimSpace(in.MooringFile)
	if mooringFile == "" {
		_ = s.db.QueryRowContext(ctx, `SELECT mooring_file_path FROM app_git WHERE project=?`, in.Project).Scan(&mooringFile)
		if strings.TrimSpace(mooringFile) == "" {
			mooringFile = "mooring.yaml"
		}
	} else if !ValidMooringFile(mooringFile) {
		return errors.New("mooring file must be a root-level mooring*.yaml")
	}
	ad := b2i(in.AutoDeploy)

	// Resolve credential ciphertext: keep / clear / replace.
	var credEnc, khEnc []byte
	credKind := ""
	switch {
	case in.NewCred == nil: // keep existing
		_ = s.db.QueryRowContext(ctx, `SELECT cred_enc, known_hosts_enc, cred_kind FROM app_git WHERE project=?`, in.Project).Scan(&credEnc, &khEnc, &credKind)
	case *in.NewCred == "": // clear
		credKind = ""
	default: // replace
		ct, err := s.cipher.Seal([]byte(*in.NewCred))
		if err != nil {
			return err
		}
		credEnc = ct
		credKind = in.CredKind
		if credKind == "ssh" {
			kh, err := s.cipher.Seal([]byte(in.KnownHosts))
			if err != nil {
				return err
			}
			khEnc = kh
		}
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO app_git(project, repo_url, git_ref, compose_path, dockerfile_path, mooring_file_path, auto_deploy, build_policy, cred_kind, cred_enc, known_hosts_enc, updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(project) DO UPDATE SET
		   repo_url=excluded.repo_url, git_ref=excluded.git_ref, compose_path=excluded.compose_path,
		   dockerfile_path=excluded.dockerfile_path, mooring_file_path=excluded.mooring_file_path,
		   auto_deploy=excluded.auto_deploy, build_policy=excluded.build_policy,
		   cred_kind=excluded.cred_kind, cred_enc=excluded.cred_enc, known_hosts_enc=excluded.known_hosts_enc, updated_at=excluded.updated_at`,
		in.Project, strings.TrimSpace(in.RepoURL), in.Ref, strings.TrimSpace(in.ComposePath),
		strings.TrimSpace(in.DockerfilePath), mooringFile, ad, in.BuildPolicy, credKind, credEnc, khEnc, time.Now().Unix())
	return err
}

// Delete removes an app's entire GitOps row — repo config, deploy FSM, the encrypted
// fetch credential, and the webhook material all live on this one row, so the row
// delete fully purges them. Used by the app-delete teardown.
func (s *Store) Delete(ctx context.Context, project string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM app_git WHERE project=?`, project)
	return err
}

// Get returns a repo app's config (no secret material).
func (s *Store) Get(project string) (Config, bool, error) {
	var c Config
	var ad, pe int
	err := s.db.QueryRow(
		`SELECT project, repo_url, git_ref, compose_path, dockerfile_path, mooring_file_path, auto_deploy, build_policy, cred_kind,
		        deployed_commit, staged_commit, update_state, commits_behind, last_fetch_at, last_fetch_error,
		        webhook_token_hash IS NOT NULL, preview_enabled, preview_of
		 FROM app_git WHERE project=?`, project).Scan(
		&c.Project, &c.RepoURL, &c.Ref, &c.ComposePath, &c.DockerfilePath, &c.MooringFile, &ad, &c.BuildPolicy, &c.CredKind,
		&c.DeployedCommit, &c.StagedCommit, &c.UpdateState, &c.CommitsBehind, &c.LastFetchAt, &c.LastFetchError, &c.HasWebhook,
		&pe, &c.PreviewOf)
	if errors.Is(err, sql.ErrNoRows) {
		return Config{}, false, nil
	}
	if err != nil {
		return Config{}, false, err
	}
	c.AutoDeploy = ad == 1
	c.PreviewEnabled = pe == 1
	return c, true, nil
}

// SetPreviewEnabled toggles a base app's opt-in for per-PR preview environments.
func (s *Store) SetPreviewEnabled(ctx context.Context, project string, enabled bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE app_git SET preview_enabled=? WHERE project=?`, b2i(enabled), project)
	return err
}

// RegisterPreview creates (or refreshes the ref of) an ephemeral per-PR app that INHERITS the
// base app's repo, credentials, build policy, and mooring file, checking out the PR head `ref`.
// preview_of is set to `base`, which scopes teardown. It fail-closes: the base must exist AND
// have previews enabled, and it refuses to touch a slug already owned by a NON-preview app or a
// preview of a DIFFERENT base — so a preview can never clobber a real app.
func (s *Store) RegisterPreview(ctx context.Context, base, slug, ref string) error {
	if !slugRe.MatchString(slug) || slug == base || strings.TrimSpace(ref) == "" {
		return errors.New("gitstore: invalid preview slug/ref")
	}
	var repoURL, composePath, dockerfilePath, mooringFile, buildPolicy, credKind string
	var credEnc, khEnc []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT repo_url, compose_path, dockerfile_path, mooring_file_path, build_policy, cred_kind, cred_enc, known_hosts_enc
		 FROM app_git WHERE project=? AND preview_enabled=1`, base).
		Scan(&repoURL, &composePath, &dockerfilePath, &mooringFile, &buildPolicy, &credKind, &credEnc, &khEnc)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("gitstore: base app not found or previews not enabled")
	}
	if err != nil {
		return err
	}
	// Never clobber an existing app that isn't already a preview of THIS base.
	var existingOf string
	switch e := s.db.QueryRowContext(ctx, `SELECT preview_of FROM app_git WHERE project=?`, slug).Scan(&existingOf); {
	case errors.Is(e, sql.ErrNoRows): // new slug — fine
	case e != nil:
		return e
	default:
		if existingOf != base {
			return errors.New("gitstore: slug already in use by a non-preview app")
		}
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO app_git(project, repo_url, git_ref, compose_path, dockerfile_path, mooring_file_path, auto_deploy, build_policy, cred_kind, cred_enc, known_hosts_enc, preview_of, updated_at)
		 VALUES(?,?,?,?,?,?,0,?,?,?,?,?,?)
		 ON CONFLICT(project) DO UPDATE SET git_ref=excluded.git_ref, updated_at=excluded.updated_at`,
		slug, repoURL, ref, composePath, dockerfilePath, mooringFile, buildPolicy, credKind, credEnc, khEnc, base, time.Now().Unix())
	return err
}

// CountPreviews returns how many live previews exist for a base app (the per-base cap input).
func (s *Store) CountPreviews(base string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM app_git WHERE preview_of=?`, base).Scan(&n)
	return n, err
}

// StalePreviews returns the slugs of preview apps whose last activity (updated_at) is older than
// `before` (unix seconds) — the TTL reaper's input, so an abandoned preview (a "closed" event
// that never arrived) is still cleaned up.
func (s *Store) StalePreviews(before int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT project FROM app_git WHERE preview_of<>'' AND updated_at<?`, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// List returns all repo apps. It selects every column in ONE query and scans each
// row directly — it must NOT call Get() inside the row loop. The DB pool is capped at
// a single connection (store.SetMaxOpenConns(1)), so a nested query issued while these
// rows are still open self-deadlocks: the open rows pin the only connection and the
// nested query waits forever for a connection that never frees, stranding the pool and
// hanging every subsequent request (session validation included).
func (s *Store) List() ([]Config, error) {
	rows, err := s.db.Query(
		`SELECT project, repo_url, git_ref, compose_path, dockerfile_path, mooring_file_path, auto_deploy, build_policy, cred_kind,
		        deployed_commit, staged_commit, update_state, commits_behind, last_fetch_at, last_fetch_error,
		        webhook_token_hash IS NOT NULL, preview_enabled, preview_of
		 FROM app_git ORDER BY project`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Config
	for rows.Next() {
		var c Config
		var ad, pe int
		if err := rows.Scan(
			&c.Project, &c.RepoURL, &c.Ref, &c.ComposePath, &c.DockerfilePath, &c.MooringFile, &ad, &c.BuildPolicy, &c.CredKind,
			&c.DeployedCommit, &c.StagedCommit, &c.UpdateState, &c.CommitsBehind, &c.LastFetchAt, &c.LastFetchError, &c.HasWebhook,
			&pe, &c.PreviewOf); err != nil {
			return nil, err
		}
		c.AutoDeploy = ad == 1
		c.PreviewEnabled = pe == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// Creds returns decrypted fetch credentials for a project.
func (s *Store) Creds(project string) (git.Creds, error) {
	var credEnc, khEnc []byte
	var kind string
	err := s.db.QueryRow(`SELECT cred_kind, cred_enc, known_hosts_enc FROM app_git WHERE project=?`, project).Scan(&kind, &credEnc, &khEnc)
	if err != nil {
		return git.Creds{}, err
	}
	var c git.Creds
	if len(credEnc) > 0 {
		pt, err := s.cipher.Open(credEnc)
		if err != nil {
			return git.Creds{}, err
		}
		switch kind {
		case "token":
			c.Token = string(pt)
		case "ssh":
			c.SSHKey = string(pt)
			if len(khEnc) > 0 {
				kh, err := s.cipher.Open(khEnc)
				if err != nil {
					return git.Creds{}, err
				}
				c.KnownHosts = string(kh)
			}
		}
	}
	return c, nil
}

// SetFetchResult records a successful fetch outcome + FSM transition.
func (s *Store) SetFetchResult(ctx context.Context, project, stagedSha string, behind int, state string) {
	if !validState[state] {
		state = "update_available"
	}
	_, _ = s.db.ExecContext(ctx,
		`UPDATE app_git SET staged_commit=?, commits_behind=?, update_state=?, last_fetch_at=?, last_fetch_error='' WHERE project=?`,
		stagedSha, behind, state, time.Now().Unix(), project)
}

// SetFetchError records a classified fetch error (never raw git stderr).
func (s *Store) SetFetchError(ctx context.Context, project, classified string) {
	_, _ = s.db.ExecContext(ctx, `UPDATE app_git SET last_fetch_at=?, last_fetch_error=? WHERE project=?`, time.Now().Unix(), classified, project)
}

// SetDeployed records a successful deploy (pins deployed_commit, FSM up_to_date).
func (s *Store) SetDeployed(ctx context.Context, project, sha string) {
	_, _ = s.db.ExecContext(ctx, `UPDATE app_git SET deployed_commit=?, update_state='up_to_date', commits_behind=0 WHERE project=?`, sha, project)
}

// SetDeployedBehind records a deploy of `sha` that is `behind` commits behind the staged tip —
// used by ROLLBACK, where the app is intentionally moved to an OLDER commit while the branch tip
// is still ahead. Setting the true state (not a false 'up_to_date') keeps the UI honest.
func (s *Store) SetDeployedBehind(ctx context.Context, project, sha string, behind int) {
	state := "up_to_date"
	if behind > 0 {
		state = "update_available"
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE app_git SET deployed_commit=?, update_state=?, commits_behind=? WHERE project=?`, sha, state, behind, project)
}

// SetAutoDeploy toggles a repo app's auto-deploy flag (used to PAUSE auto-deploy after a
// rollback, so the next webhook can't silently re-promote the commit the operator rolled away).
func (s *Store) SetAutoDeploy(ctx context.Context, project string, enabled bool) {
	_, _ = s.db.ExecContext(ctx, `UPDATE app_git SET auto_deploy=? WHERE project=?`, b2i(enabled), project)
}

// SetState transitions the FSM (e.g. deploying, update_blocked).
func (s *Store) SetState(ctx context.Context, project, state string) {
	if validState[state] {
		_, _ = s.db.ExecContext(ctx, `UPDATE app_git SET update_state=? WHERE project=?`, state, project)
	}
}

// RotateWebhook generates a new webhook token (returned once) + HMAC secret,
// storing only the token hash + the encrypted secret.
func (s *Store) RotateWebhook(ctx context.Context, project string) (token string, err error) {
	token = randToken()
	secretKey := randToken()
	enc, err := s.cipher.Seal([]byte(secretKey))
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(token))
	_, err = s.db.ExecContext(ctx, `UPDATE app_git SET webhook_token_hash=?, webhook_secret_enc=? WHERE project=?`, h[:], enc, project)
	return token, err
}

// WebhookLookup resolves a token to its project + decrypted HMAC secret.
func (s *Store) WebhookLookup(token string) (project string, hmacSecret []byte, ok bool) {
	h := sha256.Sum256([]byte(token))
	var enc []byte
	err := s.db.QueryRow(`SELECT project, webhook_secret_enc FROM app_git WHERE webhook_token_hash=?`, h[:]).Scan(&project, &enc)
	if err != nil {
		return "", nil, false
	}
	pt, err := s.cipher.Open(enc)
	if err != nil {
		return "", nil, false
	}
	return project, pt, true
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func randToken() string { return crypto.RandomToken(32) }
