package web

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/store"
)

func usersAuditEnv(t *testing.T) (*store.DB, *audit.Logger) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, audit.New(db, nil)
}

func secWith(users map[string]userSec) *secState { return &secState{users: users} }

func allGapEvents(t *testing.T, db *store.DB) []gapEvent {
	t.Helper()
	rows, err := db.Query(`SELECT actor, ip, action, target, outcome, level, detail, user_agent FROM events ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []gapEvent
	for rows.Next() {
		var r gapEvent
		if err := rows.Scan(&r.Actor, &r.IP, &r.Action, &r.Target, &r.Outcome, &r.Level, &r.Detail, &r.UA); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

const (
	hashA   = "$argon2id$v=19$m=8192,t=2,p=1$c2FsdEFBQUE$aGFzaEFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE"
	hashB   = "$argon2id$v=19$m=8192,t=2,p=1$c2FsdEJCQkI$aGFzaEJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"
	totpOne = "JBSWY3DPEHPK3PXP"
	totpTwo = "KRSXG5CTMVRXEZLU"
)

func TestAuditUserChangesEachKind(t *testing.T) {
	db, l := usersAuditEnv(t)
	old := secWith(map[string]userSec{
		"owner":   {passwordHash: hashA, role: config.RoleOwner},
		"dep":     {passwordHash: hashA, role: config.RoleDeployer},
		"gone":    {passwordHash: hashA, role: config.RoleViewer},
		"pw":      {passwordHash: hashA, role: config.RoleViewer},
		"totp_on": {passwordHash: hashA, role: config.RoleViewer},
		"totp_rm": {passwordHash: hashA, totpSecret: totpOne, role: config.RoleViewer},
		"totp_rt": {passwordHash: hashA, totpSecret: totpOne, role: config.RoleViewer},
	})
	next := secWith(map[string]userSec{
		"owner":   {passwordHash: hashA, role: config.RoleOwner},  // unchanged
		"dep":     {passwordHash: hashA, role: config.RoleOwner},  // promoted
		"pw":      {passwordHash: hashB, role: config.RoleViewer}, // new password hash
		"totp_on": {passwordHash: hashA, totpSecret: totpOne, role: config.RoleViewer},
		"totp_rm": {passwordHash: hashA, role: config.RoleViewer},
		"totp_rt": {passwordHash: hashA, totpSecret: totpTwo, role: config.RoleViewer},
		"new":     {passwordHash: hashB, totpSecret: totpTwo, role: config.RoleDeployer},
	})
	auditUserChanges(context.Background(), l, old, next, "system")

	type ev struct{ Action, Target, Detail string }
	var got []ev
	for _, r := range allGapEvents(t, db) {
		got = append(got, ev{r.Action, r.Target, r.Detail})
		if r.Actor != "system" || r.Level != "security" || r.Outcome != "ok" {
			t.Errorf("row %+v: want actor system, level security, outcome ok", r)
		}
		for _, s := range []string{hashA, hashB, totpOne, totpTwo, "argon2"} {
			if strings.Contains(r.Detail+r.Target, s) {
				t.Errorf("row %+v leaks a credential (%q)", r, s)
			}
		}
	}
	want := []ev{ // sorted by username
		{"user_role_changed", "dep", "role deployer → owner"},
		{"user_removed", "gone", "role viewer"},
		{"user_added", "new", "role deployer, 2FA on"},
		{"user_password_changed", "pw", ""},
		{"user_totp_changed", "totp_on", "2FA enabled"},
		{"user_totp_changed", "totp_rm", "2FA disabled"},
		{"user_totp_changed", "totp_rt", "TOTP secret replaced"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("events:\n got  %v\n want %v", got, want)
	}
}

// One user changed in several ways at once gets one event per change.
func TestAuditUserChangesSeveralAtOnce(t *testing.T) {
	db, l := usersAuditEnv(t)
	old := secWith(map[string]userSec{"u": {passwordHash: hashA, role: config.RoleViewer}})
	next := secWith(map[string]userSec{"u": {passwordHash: hashB, totpSecret: totpOne, role: config.RoleOwner}})
	auditUserChanges(context.Background(), l, old, next, "system")
	var actions []string
	for _, r := range allGapEvents(t, db) {
		actions = append(actions, r.Action)
	}
	if want := []string{"user_role_changed", "user_password_changed", "user_totp_changed"}; !reflect.DeepEqual(actions, want) {
		t.Errorf("actions = %v, want %v", actions, want)
	}
}

func TestAuditUserChangesNoOp(t *testing.T) {
	db, l := usersAuditEnv(t)
	users := map[string]userSec{
		"owner": {passwordHash: hashA, totpSecret: totpOne, role: config.RoleOwner},
		"v":     {passwordHash: hashB, role: config.RoleViewer},
	}
	same := map[string]userSec{}
	for k, v := range users {
		same[k] = v
	}
	auditUserChanges(context.Background(), l, secWith(users), secWith(same), "system")
	auditUserChanges(context.Background(), l, nil, secWith(same), "system") // no previous state
	if rows := allGapEvents(t, db); len(rows) != 0 {
		t.Errorf("an unchanged reload wrote %d events: %+v", len(rows), rows)
	}
}

// The function reads the same secState that buildSecState produces from a config, so a real
// config pair diffs as expected.
func TestAuditUserChangesFromConfig(t *testing.T) {
	db, l := usersAuditEnv(t)
	old := &config.Config{Auth: config.AuthConfig{Username: "operator", PasswordHash: hashA}}
	next := &config.Config{
		Auth:       config.AuthConfig{Username: "operator", PasswordHash: hashA, TOTPSecret: totpOne},
		ExtraUsers: []config.UserConfig{{Username: "dep", PasswordHash: hashA, Role: config.RoleDeployer}},
	}
	oldSec, err := buildSecState(old)
	if err != nil {
		t.Fatal(err)
	}
	nextSec, err := buildSecState(next)
	if err != nil {
		t.Fatal(err)
	}
	auditUserChanges(context.Background(), l, oldSec, nextSec, "system")
	var actions []string
	for _, r := range allGapEvents(t, db) {
		actions = append(actions, r.Action+":"+r.Target)
	}
	if want := []string{"user_added:dep", "user_totp_changed:operator"}; !reflect.DeepEqual(actions, want) {
		t.Errorf("actions = %v, want %v", actions, want)
	}
}

// A change applied by a restart (config.yaml edited, then systemctl restart) is audited at the next
// start, against the snapshot the previous run left; the first start on this version records the
// snapshot without events. The snapshot never holds a password hash or TOTP secret.
func TestAuditUsersSinceLastRun(t *testing.T) {
	db, l := usersAuditEnv(t)
	ctx := context.Background()
	kv := map[string]string{}
	get := func(k string) string { return kv[k] }
	set := func(k, v string) error { kv[k] = v; return nil }

	before := secWith(map[string]userSec{
		"owner": {passwordHash: "$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aGFzaDE", role: config.RoleOwner},
		"dave":  {passwordHash: "$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aGFzaDI", role: config.RoleViewer},
	})
	auditUsersSinceLastRun(ctx, l, get, set, before) // first start: snapshot only
	if evs := allGapEvents(t, db); len(evs) != 0 {
		t.Fatalf("first start wrote events: %+v", evs)
	}
	snap := kv[usersSnapshotKey]
	if snap == "" || strings.Contains(snap, "argon2id") || strings.Contains(snap, "aGFzaDE") {
		t.Fatalf("snapshot missing or holding a hash: %q", snap)
	}

	// Edited while Mooring was stopped: dave promoted, eve added with 2FA, owner's password changed.
	after := secWith(map[string]userSec{
		"owner": {passwordHash: "$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aGFzaDM", role: config.RoleOwner},
		"dave":  {passwordHash: "$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aGFzaDI", role: config.RoleOwner},
		"eve":   {passwordHash: "$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aGFzaDQ", totpSecret: "JBSWY3DPEHPK3PXP", role: config.RoleDeployer},
	})
	auditUsersSinceLastRun(ctx, l, get, set, after)
	got := map[string]string{}
	for _, e := range allGapEvents(t, db) {
		got[e.Action+" "+e.Target] = e.Detail
		if strings.Contains(e.Detail, "JBSWY3DPEHPK3PXP") || strings.Contains(e.Detail, "argon2id") {
			t.Errorf("secret in the audit row: %+v", e)
		}
	}
	for _, want := range []string{"user_role_changed dave", "user_added eve", "user_password_changed owner"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("events = %v, want exactly the 3 changes", got)
	}
	// Nothing changed since: the next start writes nothing.
	n := len(allGapEvents(t, db))
	auditUsersSinceLastRun(ctx, l, get, set, after)
	if m := len(allGapEvents(t, db)); m != n {
		t.Errorf("an unchanged restart wrote %d events", m-n)
	}
}
