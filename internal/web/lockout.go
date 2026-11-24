package web

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
)

// Login lockout (plan §5.2): failures are keyed on BOTH (client address, username)
// and a global per-username counter, so an attacker rotating source addresses cannot
// out-run the per-username throttle. The address is ClientIP: the TCP peer, or — only
// when that peer is a trusted proxy (trusted_proxies, or the managed-edge listener,
// where Caddy overwrites X-Forwarded-For with its own TCP peer) — the single XFF value
// the proxy set. An XFF from any other peer is ignored, so it can't pick the key.
// Keying on the bare peer instead would put every edge-fronted client behind the
// edge's loopback address, letting one attacker lock the operator out.
const (
	peerMaxFailures = 5
	peerLockWindow  = 15 * time.Minute
	peerLockFor     = 15 * time.Minute

	userMaxFailures = 50
	userLockWindow  = 1 * time.Hour
	userLockFor     = 30 * time.Minute
)

// locked reports whether either the (peer,user) or the per-user counter is
// currently in a lockout window.
func (s *Server) locked(ctx context.Context, peer, user string) bool {
	now := time.Now().Unix()
	check := func(scope, key string) bool {
		var lockedUntil int64
		err := s.db.QueryRowContext(ctx,
			`SELECT locked_until FROM login_attempts WHERE scope = ? AND key = ?`,
			scope, key).Scan(&lockedUntil)
		if err != nil {
			return false
		}
		return lockedUntil > now
	}
	return check("peer_user", peer+"|"+user) || check("user", user)
}

// recordFailure bumps both counters and arms a lockout when a threshold is hit. Each
// arming writes one login_lockout audit event (its UA comes from ctx, see
// audit.WithUserAgent).
func (s *Server) recordFailure(ctx context.Context, peer, user string) {
	if s.bump(ctx, "peer_user", peer+"|"+user, peerMaxFailures, peerLockWindow, peerLockFor) {
		s.auditLockout(ctx, peer, user, "peer_user",
			fmt.Sprintf("%d failures for this user from this address within %s; locked for %s",
				peerMaxFailures, peerLockWindow, peerLockFor))
	}
	if s.bump(ctx, "user", user, userMaxFailures, userLockWindow, userLockFor) {
		s.auditLockout(ctx, peer, user, "user",
			fmt.Sprintf("%d failures for this user from any address within %s; locked for %s",
				userMaxFailures, userLockWindow, userLockFor))
	}
}

// bump counts one failure and reports whether this call armed the lock.
func (s *Server) bump(ctx context.Context, scope, key string, maxFail int, window, lockFor time.Duration) bool {
	// Single atomic UPSERT so concurrent failed logins cannot lose an increment
	// (review #16). The CASE expressions reset the window when it has elapsed and
	// increment otherwise — computed in SQL from the existing row, never
	// read-modify-write in Go.
	now := time.Now().Unix()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO login_attempts(scope, key, failures, first_failure, locked_until)
		 VALUES(@scope, @key, 1, @now, 0)
		 ON CONFLICT(scope, key) DO UPDATE SET
		   failures = CASE WHEN @now - first_failure > @window THEN 1 ELSE failures + 1 END,
		   first_failure = CASE WHEN @now - first_failure > @window THEN @now ELSE first_failure END`,
		sql.Named("scope", scope), sql.Named("key", key), sql.Named("now", now),
		sql.Named("window", int64(window/time.Second))); err != nil {
		return false
	}
	// Arming is its own conditional UPDATE so exactly one caller sees it happen, even with
	// concurrent failures crossing the threshold together (only one flips locked_until).
	// Intentional: a failure landing while the lock is already armed doesn't extend it — the
	// lock runs lockFor from when it was armed. Only an attempt that passed locked() just
	// before the arming can land then.
	res, err := s.db.ExecContext(ctx,
		`UPDATE login_attempts SET locked_until = @now + @lockfor
		 WHERE scope = @scope AND key = @key AND failures >= @maxfail AND locked_until <= @now`,
		sql.Named("scope", scope), sql.Named("key", key), sql.Named("now", now),
		sql.Named("maxfail", maxFail), sql.Named("lockfor", int64(lockFor/time.Second)))
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

// auditLockout records that a lock was armed for user (scope "peer_user" or "user").
func (s *Server) auditLockout(ctx context.Context, peer, user, scope, detail string) {
	_ = s.audit.Log(ctx, audit.Event{
		Actor: user, IP: peer, Action: "login_lockout", Target: scope,
		Outcome: audit.Deny, Level: audit.Security, Detail: detail,
	})
}

// clearFailures resets the counters on a successful login.
func (s *Server) clearFailures(ctx context.Context, peer, user string) {
	_, _ = s.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE scope = ? AND key = ?`, "peer_user", peer+"|"+user)
	_, _ = s.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE scope = ? AND key = ?`, "user", user)
}
