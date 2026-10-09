package apitoken

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/store"
)

// ErrNotFound means no token row matched the id (an unknown/expired/garbage id
// looks identical to a wrong secret to the caller — no enumeration oracle).
var ErrNotFound = errors.New("apitoken: not found")

// Store persists api_tokens. The id selects exactly one row, so a request runs at
// most one argon2id verify; minting is CLI-only (no web path constructs a Store
// write for token creation).
type Store struct{ db *store.DB }

// NewStore builds a Store.
func NewStore(db *store.DB) *Store { return &Store{db: db} }

// Insert persists a freshly-minted Record (the plaintext is never stored). label is
// an informational operator note.
func (s *Store) Insert(ctx context.Context, r Record, label string, now time.Time) error {
	if !ValidID(r.ID) || r.Hash == "" || len(r.Scopes) == 0 || len(r.CIDRs) == 0 || r.ExpiresAt <= 0 {
		return errors.New("apitoken: refusing to store a malformed record")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO api_tokens(id, hash, scopes, cidrs, label, created_at, expires_at, revoked)
		 VALUES(?, ?, ?, ?, ?, ?, ?, 0)`,
		r.ID, r.Hash, joinScopes(r.Scopes), joinCIDRs(r.CIDRs), strings.TrimSpace(label),
		now.Unix(), r.ExpiresAt)
	return err
}

// Get loads one token by id. It returns ErrNotFound for any id that is malformed or
// absent — the caller cannot distinguish "no such token" from "wrong secret".
func (s *Store) Get(ctx context.Context, id string) (Record, error) {
	if !ValidID(id) {
		return Record{}, ErrNotFound
	}
	var (
		r            Record
		scopes, cidr string
		revoked      int
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, hash, scopes, cidrs, expires_at, revoked FROM api_tokens WHERE id=?`, id).
		Scan(&r.ID, &r.Hash, &scopes, &cidr, &r.ExpiresAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, err
	}
	r.Scopes = splitScopes(scopes)
	r.CIDRs = parseStoredCIDRs(cidr)
	r.Revoked = revoked != 0
	return r, nil
}

// List returns all tokens (for the CLI listing + the CIDR-union recompute on
// startup/SIGHUP).
func (s *Store) List(ctx context.Context) ([]Record, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, hash, scopes, cidrs, expires_at, revoked FROM api_tokens ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var (
			r            Record
			scopes, cidr string
			revoked      int
		)
		if err := rows.Scan(&r.ID, &r.Hash, &scopes, &cidr, &r.ExpiresAt, &revoked); err != nil {
			return nil, err
		}
		r.Scopes = splitScopes(scopes)
		r.CIDRs = parseStoredCIDRs(cidr)
		r.Revoked = revoked != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// Revoke marks a token revoked (idempotent). A revoked token fails active() and is
// excluded from the CIDR union on the next recompute.
func (s *Store) Revoke(ctx context.Context, id string) error {
	if !ValidID(id) {
		return ErrNotFound
	}
	res, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET revoked=1 WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeAppScoped takes deploy:write:<slug> off every token, revoked ones included, and
// revokes each token that had no other scope. The app-delete teardown calls it: a scope
// left behind would let the token deploy a later app connected under the same slug. Other
// scopes are kept, so a token that also serves other apps keeps working for them. Returns
// the number of tokens it revoked.
func (s *Store) RevokeAppScoped(ctx context.Context, slug string) (int64, error) {
	scope := "deploy:write:" + slug
	if !deployRe.MatchString(scope) {
		return 0, nil // no token can hold a scope outside the grammar
	}
	type tokenScopes struct {
		id, scopes string
		revoked    bool
	}
	// Read every token first and close the rows before any update (one connection: an UPDATE
	// while the rows are open would deadlock).
	rows, err := s.db.QueryContext(ctx, `SELECT id, scopes, revoked FROM api_tokens`)
	if err != nil {
		return 0, err
	}
	var holders []tokenScopes
	for rows.Next() {
		var (
			t       tokenScopes
			revoked int
		)
		if err := rows.Scan(&t.id, &t.scopes, &revoked); err != nil {
			rows.Close()
			return 0, err
		}
		t.revoked = revoked != 0
		if _, held := withoutScope(t.scopes, scope); held {
			holders = append(holders, t)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	var revokedN int64
	for _, t := range holders {
		for attempt := 0; ; attempt++ {
			kept, held := withoutScope(t.scopes, scope)
			if !held {
				break
			}
			revoke := len(kept) == 0 && !t.revoked
			q := `UPDATE api_tokens SET scopes=? WHERE id=? AND scopes=?`
			if revoke {
				q = `UPDATE api_tokens SET scopes=?, revoked=1 WHERE id=? AND scopes=?`
			}
			// The update matches the scopes it was computed from, so a row another process changed in
			// between is re-read rather than overwritten with a stale scope list.
			res, err := s.db.ExecContext(ctx, q, joinScopes(kept), t.id, t.scopes)
			if err != nil {
				return revokedN, err
			}
			if n, _ := res.RowsAffected(); n > 0 {
				if revoke {
					revokedN++
				}
				break
			}
			if attempt >= 2 {
				return revokedN, errors.New("apitoken: a token kept changing while its app's scope was removed")
			}
			var revoked int
			err = s.db.QueryRowContext(ctx, `SELECT scopes, revoked FROM api_tokens WHERE id=?`, t.id).Scan(&t.scopes, &revoked)
			if errors.Is(err, sql.ErrNoRows) {
				break
			}
			if err != nil {
				return revokedN, err
			}
			t.revoked = revoked != 0
		}
	}
	return revokedN, nil
}

// withoutScope returns the stored scope list minus every occurrence of scope, and whether it held it.
func withoutScope(stored, scope string) (kept []string, held bool) {
	for _, sc := range splitScopes(stored) {
		if sc == scope {
			held = true
			continue
		}
		kept = append(kept, sc)
	}
	return kept, held
}

// TouchLastUsed records a best-effort last-use timestamp (never gates auth — a
// failure here must not deny a valid request, so callers ignore the error).
func (s *Store) TouchLastUsed(ctx context.Context, id string, now time.Time) {
	if !ValidID(id) {
		return
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at=? WHERE id=?`, now.Unix(), id)
}

// ActiveCIDRUnion returns the union of every currently-active token's CIDR set — the
// precomputed allowlist addition the IP gate checks the peer against BEFORE any
// bearer is parsed.
func (s *Store) ActiveCIDRUnion(ctx context.Context, now time.Time) ([]netip.Prefix, error) {
	recs, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	return CIDRUnion(recs, now.Unix()), nil
}

func joinScopes(s []string) string { return strings.Join(s, " ") }

func splitScopes(s string) []string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return nil
	}
	return f
}

func joinCIDRs(ps []netip.Prefix) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return strings.Join(out, " ")
}

// parseStoredCIDRs reparses the persisted set. Values were validated by ParseCIDRs
// before storage, so a parse failure means tampering — drop the bad entry rather
// than admit a malformed prefix (fail-closed: a token with an unparseable CIDR
// simply contributes nothing to the union and matches no peer).
func parseStoredCIDRs(s string) []netip.Prefix {
	var out []netip.Prefix
	for _, f := range strings.Fields(s) {
		p, err := netip.ParsePrefix(f)
		if err != nil || p.Bits() == 0 {
			continue
		}
		out = append(out, p.Masked())
	}
	return out
}
