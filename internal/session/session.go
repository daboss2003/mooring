// Package session implements server-side opaque sessions (plan §5.3): a 256-bit
// random id handed to the browser, only its SHA-256 hash stored; rotated on
// login; idle + absolute timeouts that cannot be reopened by a backward wall
// clock step — even across a process restart (plan §5.9; review #1).
//
// Clock model: within a process, m.now() is monotonic-anchored to boot. Across
// restarts that anchor resets to the (possibly stepped-back) wall clock, so we
// additionally clamp to a persisted "high-water mark" of the greatest wall
// second ever observed. effectiveNow() = max(monotonic-anchored now, high-water)
// — it never regresses, so an expired session stays expired and GC still purges
// it after a backward step. Create and Load/GC all use the SAME effective clock.
package session

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/daboss2003/mooring/internal/crypto"
	"github.com/daboss2003/mooring/internal/store"
)

// ErrNotFound means no live session matched (missing, expired, or revoked).
var ErrNotFound = errors.New("session: not found")

const (
	idBytes              = 32 // 256-bit opaque id
	highWaterKey         = "clock_high_water"
	highWaterPersistStep = 60 // persist the high-water mark at most ~once/min
)

// Session is a loaded, still-valid session.
type Session struct {
	Username   string
	CreatedAt  time.Time
	LastSeenAt time.Time
}

// Manager owns session lifecycle against the DB.
type Manager struct {
	db       *store.DB
	idle     time.Duration
	absolute time.Duration
	bootWall time.Time     // wall clock at process start
	bootMono time.Duration // monotonic reading at process start

	hwMu        sync.Mutex
	hw          int64 // greatest wall-second ever observed (in-memory, authoritative)
	hwPersisted int64 // last value written to the DB
}

// New returns a session Manager, seeding the clock high-water mark from the DB.
func New(db *store.DB, idle, absolute time.Duration) *Manager {
	m := &Manager{
		db:       db,
		idle:     idle,
		absolute: absolute,
		bootWall: time.Now(),
		bootMono: monoNow(),
	}
	persisted := m.readHighWater()
	now := m.bootWall.Unix()
	m.hw = persisted
	if now > m.hw {
		m.hw = now
	}
	m.hwPersisted = persisted
	return m
}

func hashID(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

// Create mints a new session for username, returns the raw id for the cookie.
func (m *Manager) Create(ctx context.Context, username, peerIP, userAgent string) (rawID string, err error) {
	rawID = crypto.RandomToken(idBytes)
	now := m.effectiveNow()
	_, err = m.db.ExecContext(ctx,
		`INSERT INTO sessions(id_hash, username, created_at, last_seen_at, absolute_exp, created_mono, peer_ip, user_agent)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		hashID(rawID), username, now.Unix(), now.Unix(),
		now.Add(m.absolute).Unix(), int64(monoNow()), peerIP, userAgent,
	)
	if err != nil {
		return "", err
	}
	return rawID, nil
}

// Load returns the session for a raw cookie id, enforcing idle + absolute timeouts
// against the non-regressing effective clock, and ADVANCES last_seen — active use keeps
// the session alive (this runs on every authed request via the session middleware).
func (m *Manager) Load(ctx context.Context, rawID string) (*Session, error) {
	return m.lookup(ctx, rawID, true)
}

// Peek is Load WITHOUT advancing last_seen — a read-only liveness check enforcing the
// SAME idle + absolute expiry. It must not keep an idle session alive, so it's used by
// the dashboard's focus-loss watchdog status probe (an unfocused tab polling "am I still
// logged in?" must observe the idle-out, not postpone it).
func (m *Manager) Peek(ctx context.Context, rawID string) (*Session, error) {
	return m.lookup(ctx, rawID, false)
}

// lookup is the shared Load/Peek core. refresh advances last_seen on a hit.
func (m *Manager) lookup(ctx context.Context, rawID string, refresh bool) (*Session, error) {
	if rawID == "" {
		return nil, ErrNotFound
	}
	var (
		username            string
		createdAt, lastSeen int64
		absoluteExp         int64
	)
	err := m.db.QueryRowContext(ctx,
		`SELECT username, created_at, last_seen_at, absolute_exp FROM sessions WHERE id_hash = ?`,
		hashID(rawID),
	).Scan(&username, &createdAt, &lastSeen, &absoluteExp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	now := m.effectiveNow()
	if now.Unix() >= absoluteExp {
		_ = m.deleteByHash(ctx, hashID(rawID))
		return nil, ErrNotFound
	}
	if now.Sub(time.Unix(lastSeen, 0)) >= m.idle {
		_ = m.deleteByHash(ctx, hashID(rawID))
		return nil, ErrNotFound
	}
	seen := time.Unix(lastSeen, 0)
	if refresh {
		_, _ = m.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?`, now.Unix(), hashID(rawID))
		seen = now
	}

	return &Session{
		Username:   username,
		CreatedAt:  time.Unix(createdAt, 0),
		LastSeenAt: seen,
	}, nil
}

// Delete revokes a session by its raw id (logout).
func (m *Manager) Delete(ctx context.Context, rawID string) error {
	return m.deleteByHash(ctx, hashID(rawID))
}

func (m *Manager) deleteByHash(ctx context.Context, h []byte) error {
	_, err := m.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, h)
	return err
}

// DeleteAllForUser revokes every session for a user (privilege change / forced
// logout). Returns rows affected.
func (m *Manager) DeleteAllForUser(ctx context.Context, username string) (int64, error) {
	res, err := m.db.ExecContext(ctx, `DELETE FROM sessions WHERE username = ?`, username)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ActivePeers returns the address each still-valid session signed in from, each once (the edge
// block list never blocks these). A stored value that isn't an address is skipped.
func (m *Manager) ActivePeers(ctx context.Context) ([]netip.Addr, error) {
	now := m.effectiveNow()
	// The same expiry as lookup: valid while now < absolute_exp and now - last_seen < idle.
	rows, err := m.db.QueryContext(ctx,
		`SELECT DISTINCT peer_ip FROM sessions WHERE absolute_exp > ? AND last_seen_at > ?`,
		now.Unix(), now.Add(-m.idle).Unix())
	if err != nil {
		return nil, err
	}
	var raw []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return nil, err
		}
		raw = append(raw, s)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	seen := make(map[netip.Addr]bool, len(raw))
	out := make([]netip.Addr, 0, len(raw))
	for _, s := range raw {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			continue
		}
		if a = a.Unmap(); !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out, nil
}

// DeleteAll revokes EVERY session (used when the auth config changes — password or
// TOTP — so no session predating the change survives, regardless of which username it
// was issued under). Returns rows affected.
func (m *Manager) DeleteAll(ctx context.Context) (int64, error) {
	res, err := m.db.ExecContext(ctx, `DELETE FROM sessions`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GC removes expired sessions; called opportunistically. Uses the same effective
// clock as Load so a backward step does not strand expired rows.
func (m *Manager) GC(ctx context.Context) error {
	_, err := m.db.ExecContext(ctx, `DELETE FROM sessions WHERE absolute_exp <= ?`, m.effectiveNow().Unix())
	return err
}

// now returns a wall-clock time that is monotonic-anchored within this process.
func (m *Manager) now() time.Time {
	elapsed := monoNow() - m.bootMono
	if elapsed < 0 {
		elapsed = 0
	}
	return m.bootWall.Add(elapsed)
}

// effectiveNow returns a clock that never regresses, even across a restart that
// follows a backward wall-clock step: it is max(monotonic-anchored now,
// persisted high-water). It advances and (throttled) persists the high-water.
func (m *Manager) effectiveNow() time.Time {
	cur := m.now().Unix()
	m.hwMu.Lock()
	if cur > m.hw {
		m.hw = cur
	}
	eff := m.hw
	needPersist := m.hw-m.hwPersisted >= highWaterPersistStep
	if needPersist {
		m.hwPersisted = m.hw
	}
	toPersist := m.hwPersisted
	m.hwMu.Unlock()

	if needPersist {
		m.writeHighWater(toPersist)
	}
	return time.Unix(eff, 0)
}

func (m *Manager) readHighWater() int64 {
	var s string
	err := m.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, highWaterKey).Scan(&s)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func (m *Manager) writeHighWater(v int64) {
	_, _ = m.db.Exec(
		`INSERT INTO settings(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value WHERE CAST(value AS INTEGER) < CAST(excluded.value AS INTEGER)`,
		highWaterKey, strconv.FormatInt(v, 10))
}
