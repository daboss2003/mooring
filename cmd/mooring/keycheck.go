package main

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/store"
)

// The key-check sentinel: a known plaintext sealed under the master key so a
// key/DB mismatch is caught before it silently corrupts the next encrypted write
// (plan §5.1). Shared by `serve` (boot guard, review #21) and `verify-key`.
const (
	keyCheckPlaintext = "mooring-key-check-v1"
	keyCheckSetting   = "key_check_enc"
)

func openCipher(cfg *config.Config) (*secret.Cipher, error) {
	key, err := config.DecodeKey(cfg.EncryptionKey)
	if err != nil {
		return nil, err
	}
	var prev []byte
	if cfg.EncryptionKeyPrevious != "" {
		if prev, err = config.DecodeKey(cfg.EncryptionKeyPrevious); err != nil {
			return nil, err
		}
	}
	return secret.NewCipher(key, prev)
}

// errKeyMismatch: the configured key doesn't open the database's key-check sentinel. serve stops
// without being restarted on it (a restart can't change the key).
var errKeyMismatch = errors.New("KEY MISMATCH: the configured encryption_key does not match this DB — do NOT start the server; restore the correct key or DB")

type sentinelResult int

const (
	sentinelOK sentinelResult = iota
	sentinelInitialized
)

// verifyOrInitSentinel opens the sentinel under the configured key (initializing
// it on a fresh DB), re-sealing under the current key so a rotation settles. It
// distinguishes a genuinely-absent row (sql.ErrNoRows → initialize) from any
// other read error (→ refuse, never treat as first-run) (review #22).
func verifyOrInitSentinel(c *secret.Cipher, db *store.DB) (sentinelResult, error) {
	var stored string
	err := db.QueryRow(`SELECT value FROM settings WHERE key = ?`, keyCheckSetting).Scan(&stored)
	switch {
	case err == nil:
		blob, derr := base64.StdEncoding.DecodeString(stored)
		if derr != nil {
			return 0, fmt.Errorf("key-check sentinel is corrupt: %w", derr)
		}
		pt, oerr := c.Open(blob)
		if oerr != nil || string(pt) != keyCheckPlaintext {
			return 0, errKeyMismatch
		}
		// Re-seal under the current key so a previous→current rotation settles.
		if nb, serr := c.Seal([]byte(keyCheckPlaintext)); serr == nil {
			_, _ = db.Exec(`UPDATE settings SET value = ? WHERE key = ?`,
				base64.StdEncoding.EncodeToString(nb), keyCheckSetting)
		}
		return sentinelOK, nil
	case errors.Is(err, sql.ErrNoRows):
		blob, serr := c.Seal([]byte(keyCheckPlaintext))
		if serr != nil {
			return 0, serr
		}
		if _, ierr := db.Exec(`INSERT INTO settings(key, value) VALUES(?, ?)`,
			keyCheckSetting, base64.StdEncoding.EncodeToString(blob)); ierr != nil {
			return 0, ierr
		}
		return sentinelInitialized, nil
	default:
		return 0, fmt.Errorf("reading key-check sentinel: %w", err)
	}
}

// checkKeySentinel is the boot-time guard used by `serve`.
func checkKeySentinel(cfg *config.Config, db *store.DB) error {
	c, err := openCipher(cfg)
	if err != nil {
		return err
	}
	_, err = verifyOrInitSentinel(c, db)
	return err
}
