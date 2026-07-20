package definition

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"errors"

	"github.com/daboss2003/mooring/internal/store"
)

// ErrTampered means a stored definition's HMAC did not verify (changed outside
// Mooring). It is never loaded — fail-closed.
var ErrTampered = errors.New("definition HMAC mismatch (tampered)")

// Store persists applied canonical definitions (the history; the latest per slug is
// the live canonical). Every read RE-PARSES + RE-VALIDATES the stored YAML through
// the full pipeline (re-derive, never a verbatim replay), and the per-row HMAC is
// defence-in-depth so a DB tamper that still parses is caught.
type Store struct {
	db  *store.DB
	key []byte
}

// NewStore derives a domain-separated HMAC key from the encryption key.
func NewStore(db *store.DB, encKey []byte) *Store {
	h := sha256.New()
	h.Write([]byte("mooring/definition-hmac/v1\x00"))
	h.Write(encKey)
	return &Store{db: db, key: h.Sum(nil)}
}

func (s *Store) mac(b []byte) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write(b)
	return m.Sum(nil)
}

// rowMAC is the per-row integrity tag. It binds the canonical YAML AND the deploy-control
// commit_sha, so a DB tamper cannot repoint a version's rollback target to an unreviewed
// commit (the rollback path skips the git-ref staged cross-check, so this MAC is what keeps
// it fail-closed). Backward-compatible: a row with no commit (legacy + every dashboard edit)
// tags over the YAML alone — byte-identical to the pre-commit_sha scheme — so existing rows
// still verify. commit is always "" or 40 hex chars, and canonical YAML never contains NUL,
// so the 0x00 separator is unambiguous.
func (s *Store) rowMAC(canon []byte, commit string) []byte {
	if commit == "" {
		return s.mac(canon)
	}
	buf := make([]byte, 0, len(canon)+1+len(commit))
	buf = append(buf, canon...)
	buf = append(buf, 0)
	buf = append(buf, commit...)
	return s.mac(buf)
}

// VersionMeta is one history row (no content). Commit is the git sha this version was
// deployed from ("" for dashboard-originated versions, which are not rollback targets).
type VersionMeta struct {
	ID        int64
	Note      string
	CreatedAt int64
	Commit    string
}

// SaveCanonical re-marshals an already-validated definition to canonical YAML and
// records it as a new version (which becomes the live canonical). Returns its id.
// commit is the git sha this version was deployed from ("" for dashboard edits).
func (s *Store) SaveCanonical(ctx context.Context, d *Definition, note, commit string) (int64, error) {
	canon, err := Canonical(d)
	if err != nil {
		return 0, err
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO definition_versions(slug, yaml, hmac, note, commit_sha, created_at) VALUES(?,?,?,?,?, unixepoch())`,
		d.Metadata.Slug, string(canon), s.rowMAC(canon, commit), note, commit)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// DeleteApp removes ALL canonical-definition versions for a slug (the whole history).
// Used by the app-delete teardown.
func (s *Store) DeleteApp(ctx context.Context, slug string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM definition_versions WHERE slug=?`, slug)
	return err
}

// DeleteVersion removes ONE past version from the history (trimming the rollback list). It
// REFUSES to delete the latest version — that row is the live canonical, and losing it would
// orphan the app's current shape. Returns an error if the id is the latest or unknown. Note:
// this only frees the (tiny) history row; disk from superseded build images is reclaimed by
// the image-prune path, not here.
func (s *Store) DeleteVersion(ctx context.Context, slug string, id int64) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM definition_versions WHERE slug=? AND id=? AND id <> (SELECT MAX(id) FROM definition_versions WHERE slug=?)`,
		slug, id, slug)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("version not found, or it is the current live version (which cannot be deleted)")
	}
	return nil
}

// Current returns the live canonical definition for a slug (the latest version),
// HMAC-verified and RE-PARSED. No version yet → (nil, nil).
func (s *Store) Current(slug string) (*Definition, error) {
	var yamlText, commit string
	var mac []byte
	err := s.db.QueryRow(`SELECT yaml, hmac, commit_sha FROM definition_versions WHERE slug=? ORDER BY id DESC LIMIT 1`, slug).Scan(&yamlText, &mac, &commit)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.verifyAndParse([]byte(yamlText), mac, commit)
}

// Version returns a specific past version for ROLLBACK — HMAC-verified and re-derived
// (re-parsed + re-validated through the full pipeline, never a verbatim replay).
func (s *Store) Version(slug string, id int64) (*Definition, error) {
	var yamlText, commit string
	var mac []byte
	err := s.db.QueryRow(`SELECT yaml, hmac, commit_sha FROM definition_versions WHERE slug=? AND id=?`, slug, id).Scan(&yamlText, &mac, &commit)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return s.verifyAndParse([]byte(yamlText), mac, commit)
}

func (s *Store) verifyAndParse(yamlText, mac []byte, commit string) (*Definition, error) {
	if !hmac.Equal(mac, s.rowMAC(yamlText, commit)) {
		return nil, ErrTampered
	}
	return Parse(yamlText) // re-derive: a stored def is re-validated, never trusted blindly
}

// List returns a slug's version history, newest first.
func (s *Store) List(slug string) ([]VersionMeta, error) {
	rows, err := s.db.Query(`SELECT id, note, created_at, commit_sha FROM definition_versions WHERE slug=? ORDER BY id DESC`, slug)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VersionMeta
	for rows.Next() {
		var m VersionMeta
		if err := rows.Scan(&m.ID, &m.Note, &m.CreatedAt, &m.Commit); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// CommitForVersion returns the git sha a specific version was deployed from, scoped to the
// slug (so a cross-app id can never resolve). The commit is HMAC-VERIFIED against the row (a
// DB tamper that repoints it surfaces ErrTampered — the rollback path must not deploy an
// unverified sha, since it skips the git-ref staged cross-check). Empty string means the
// version has no recorded commit (a dashboard edit) and is not a rollback target. sql.ErrNoRows
// if the (slug, id) pair does not exist.
func (s *Store) CommitForVersion(slug string, id int64) (string, error) {
	var yamlText, commit string
	var mac []byte
	err := s.db.QueryRow(`SELECT yaml, hmac, commit_sha FROM definition_versions WHERE slug=? AND id=?`, slug, id).Scan(&yamlText, &mac, &commit)
	if errors.Is(err, sql.ErrNoRows) {
		return "", sql.ErrNoRows
	}
	if err != nil {
		return "", err
	}
	if !hmac.Equal(mac, s.rowMAC([]byte(yamlText), commit)) {
		return "", ErrTampered
	}
	return commit, nil
}
