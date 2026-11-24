package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/config"
)

// auditUserChanges records how a config reload changed the operators (the `auth:` owner and
// the `users:` list, by username): one security event per change — user_added, user_removed,
// user_role_changed, user_password_changed, user_totp_changed. It compares the fields
// authFingerprint covers and never writes a password hash or a TOTP secret. prev is the state
// being replaced (nil writes nothing).
func auditUserChanges(ctx context.Context, l *audit.Logger, prev, next *secState, actor string) {
	if prev == nil || next == nil {
		return
	}
	names := make([]string, 0, len(prev.users)+len(next.users))
	for n := range prev.users {
		names = append(names, n)
	}
	for n := range next.users {
		if _, ok := prev.users[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	log := func(action, user, detail string) {
		_ = l.Log(ctx, audit.Event{
			Actor: actor, Action: action, Target: user, Outcome: audit.OK, Level: audit.Security, Detail: detail,
		})
	}
	for _, n := range names {
		was, hadWas := prev.users[n]
		now, hasNow := next.users[n]
		switch {
		case !hasNow:
			log("user_removed", n, "role "+string(was.role))
		case !hadWas:
			twoFA := "off"
			if now.totpSecret != "" {
				twoFA = "on"
			}
			log("user_added", n, "role "+string(now.role)+", 2FA "+twoFA)
		default:
			if was.role != now.role {
				log("user_role_changed", n, "role "+string(was.role)+" → "+string(now.role))
			}
			if was.passwordHash != now.passwordHash {
				log("user_password_changed", n, "")
			}
			switch {
			case was.totpSecret == now.totpSecret:
			case was.totpSecret == "":
				log("user_totp_changed", n, "2FA enabled")
			case now.totpSecret == "":
				log("user_totp_changed", n, "2FA disabled")
			default:
				log("user_totp_changed", n, "TOTP secret replaced")
			}
		}
	}
}

// usersSnapshotKey is the setting holding the operators as the last run saw them, so a change made
// in config.yaml while Mooring was stopped is audited at the next start (a restart, not a reload).
const usersSnapshotKey = "audit_users_v1"

// userSnap is one operator in the snapshot: the role, and fingerprints (16 hex of SHA-256) of the
// password hash and the TOTP secret, never either value ("" = no TOTP).
type userSnap struct {
	Role string `json:"role"`
	PW   string `json:"pw"`
	TOTP string `json:"totp,omitempty"`
}

func fingerprint(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// usersSnapshot is sec's operators as stored in the snapshot.
func usersSnapshot(sec *secState) string {
	m := make(map[string]userSnap, len(sec.users))
	for n, u := range sec.users {
		m[n] = userSnap{Role: string(u.role), PW: fingerprint(u.passwordHash), TOTP: fingerprint(u.totpSecret)}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// secStateFromSnapshot rebuilds a secState auditUserChanges can compare: the fingerprints stand in
// for the hash and the secret (it compares them for equality and emptiness only).
func secStateFromSnapshot(s string) (*secState, bool) {
	var m map[string]userSnap
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, false
	}
	sec := &secState{users: make(map[string]userSec, len(m))}
	for n, u := range m {
		sec.users[n] = userSec{role: config.Role(u.Role), passwordHash: u.PW, totpSecret: u.TOTP}
	}
	return sec, true
}

// auditUsersSinceLastRun audits how the operators changed since the snapshot the last run saved
// (a change applied by a restart), then saves cur's. The first start on this version only saves it.
func auditUsersSinceLastRun(ctx context.Context, l *audit.Logger, get func(string) string, set func(string, string) error, cur *secState) {
	if prev, ok := secStateFromSnapshot(get(usersSnapshotKey)); ok {
		auditUserChanges(ctx, l, prev, snapshotView(cur), "system (restart)")
	}
	_ = set(usersSnapshotKey, usersSnapshot(cur))
}

// snapshotView is cur with its hash and secret replaced by their fingerprints, to compare with a
// snapshot.
func snapshotView(cur *secState) *secState {
	v, _ := secStateFromSnapshot(usersSnapshot(cur))
	return v
}
