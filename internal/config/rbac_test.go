package config

import (
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/crypto"
)

func TestRoleCan(t *testing.T) {
	cases := []struct {
		role Role
		perm string
		want bool
	}{
		{RoleOwner, "view", true}, {RoleOwner, "deploy", true}, {RoleOwner, "admin", true},
		{RoleDeployer, "view", true}, {RoleDeployer, "deploy", true}, {RoleDeployer, "admin", false},
		{RoleViewer, "view", true}, {RoleViewer, "deploy", false}, {RoleViewer, "admin", false},
		{RoleViewer, "bogus", false}, {RoleOwner, "bogus", false}, // unknown perm fail-closed
	}
	for _, c := range cases {
		if got := c.role.Can(c.perm); got != c.want {
			t.Errorf("%s.Can(%q) = %v; want %v", c.role, c.perm, got, c.want)
		}
	}
}

func realHash(t *testing.T) string {
	t.Helper()
	h, err := crypto.HashPassword([]byte("correct horse battery staple"), crypto.DefaultArgon2Params)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func rbacConfig(hash, usersBlock string) string {
	return `
bind_addr: "127.0.0.1:9000"
encryption_key: "` + strings.Repeat("A", 43) + `="
ip_allowlist:
  - "127.0.0.1/32"
auth:
  username: "owner1"
  password_hash: "` + hash + `"
` + usersBlock + `
edge:
  mode: "managed"
  acme_email: "ops@example.com"
  acme_ca: "https://acme.example/directory"
data_dir: "/tmp/mooring-test-rbac"
`
}

func TestUsersParseAndResolve(t *testing.T) {
	hash := realHash(t)
	users := `users:
  - username: "dep1"
    password_hash: "` + hash + `"
    role: deployer
  - username: "vie1"
    password_hash: "` + hash + `"
    role: viewer`
	c, err := Parse([]byte(rbacConfig(hash, users)))
	if err != nil {
		t.Fatalf("valid multi-user config rejected: %v", err)
	}
	us := c.Users()
	if len(us) != 3 || us[0].Username != "owner1" || us[0].Role != RoleOwner {
		t.Fatalf("Users() should be owner-first, got %+v", us)
	}
	roles := map[string]Role{}
	for _, u := range us {
		roles[u.Username] = u.Role
	}
	if roles["dep1"] != RoleDeployer || roles["vie1"] != RoleViewer {
		t.Fatalf("roles wrong: %v", roles)
	}
}

func TestUsersValidationRejects(t *testing.T) {
	hash := realHash(t)
	cases := map[string]string{
		"bad role":     `users:` + "\n" + `  - {username: x, password_hash: "` + hash + `", role: superuser}`,
		"dup of owner": `users:` + "\n" + `  - {username: owner1, password_hash: "` + hash + `", role: viewer}`,
		"missing hash": `users:` + "\n" + `  - {username: x, role: viewer}`,
		"no username":  `users:` + "\n" + `  - {password_hash: "` + hash + `", role: viewer}`,
	}
	// Sanity: the base (no extra users) must be VALID, so a rejection is due to the user entry.
	if _, err := Parse([]byte(rbacConfig(hash, ""))); err != nil {
		t.Fatalf("base config should be valid: %v", err)
	}
	for name, users := range cases {
		if _, err := Parse([]byte(rbacConfig(hash, users))); err == nil {
			t.Errorf("%s should be rejected", name)
		}
	}
}

// A user hashed at a DIFFERENT argon2 cost than the owner is rejected — else its login-verify
// latency would differ from the timing-parity dummy and make the username enumerable.
func TestUsersRejectMismatchedArgonParams(t *testing.T) {
	owner := realHash(t) // DefaultArgon2Params
	// Same password, deliberately different memory cost.
	p := crypto.DefaultArgon2Params
	p.Memory *= 2
	other, err := crypto.HashPassword([]byte("whatever"), p)
	if err != nil {
		t.Fatal(err)
	}
	users := "users:\n  - {username: bob, password_hash: \"" + other + "\", role: viewer}"
	if _, err := Parse([]byte(rbacConfig(owner, users))); err == nil {
		t.Error("a user hashed at a different argon2 cost must be rejected")
	}
	// Sanity: a user hashed at the SAME cost is accepted.
	same := realHash(t)
	okUsers := "users:\n  - {username: carol, password_hash: \"" + same + "\", role: viewer}"
	if _, err := Parse([]byte(rbacConfig(owner, okUsers))); err != nil {
		t.Errorf("matching argon2 params should be accepted: %v", err)
	}
}
