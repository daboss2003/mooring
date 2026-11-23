package imagescan

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/daboss2003/mooring/internal/store"
)

// HostStore persists the host's latest scan (one row, host_scans id = 1).
type HostStore struct{ db *store.DB }

// NewHostStore builds a HostStore over the shared single-conn DB.
func NewHostStore(db *store.DB) *HostStore { return &HostStore{db: db} }

// Save overwrites the host's scan result.
func (s *HostStore) Save(ctx context.Context, h HostScan) error {
	blob, err := json.Marshal(h.Reports)
	if err != nil {
		return err
	}
	eosl := 0
	if h.EOSL {
		eosl = 1
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO host_scans(id, scanned_at, os, eosl, critical, high, medium, low,
		   fixable_critical, fixable_high, fixable_medium, fixable_low, report_json, error)
		 VALUES(1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   scanned_at=excluded.scanned_at, os=excluded.os, eosl=excluded.eosl, critical=excluded.critical,
		   high=excluded.high, medium=excluded.medium, low=excluded.low, fixable_critical=excluded.fixable_critical,
		   fixable_high=excluded.fixable_high, fixable_medium=excluded.fixable_medium,
		   fixable_low=excluded.fixable_low, report_json=excluded.report_json, error=excluded.error`,
		h.ScannedAt, h.OS, eosl, h.Critical, h.High, h.Medium, h.Low,
		h.FixableCritical, h.FixableHigh, h.FixableMedium, h.FixableLow, blob, h.Error)
	return err
}

// Get returns the host's scan (ok=false if never scanned).
func (s *HostStore) Get(ctx context.Context) (HostScan, bool, error) {
	var h HostScan
	var blob []byte
	var eosl int
	err := s.db.QueryRowContext(ctx,
		`SELECT scanned_at, os, eosl, critical, high, medium, low,
		        fixable_critical, fixable_high, fixable_medium, fixable_low, report_json, error
		   FROM host_scans WHERE id = 1`).
		Scan(&h.ScannedAt, &h.OS, &eosl, &h.Critical, &h.High, &h.Medium, &h.Low,
			&h.FixableCritical, &h.FixableHigh, &h.FixableMedium, &h.FixableLow, &blob, &h.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return HostScan{}, false, nil
	}
	if err != nil {
		return HostScan{}, false, err
	}
	h.EOSL = eosl == 1
	_ = json.Unmarshal(blob, &h.Reports)
	return h, true, nil
}
