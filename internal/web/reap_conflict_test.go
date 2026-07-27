package web

import (
	"testing"

	"github.com/daboss2003/mooring/internal/docker"
)

func ctr(id, project, service, name, state string) docker.Container {
	return docker.Container{
		ID:     id,
		Names:  []string{"/" + name},
		State:  state,
		Labels: map[string]string{"com.docker.compose.project": project, "com.docker.compose.service": service},
	}
}

func TestConflictRegexExtractsID(t *testing.T) {
	line := `Error response from daemon: Error when allocating new name: Conflict. The container name "/credlock-worker-1" is already in use by container "cb17726f76aa1234567890abcdef1234567890abcdef1234567890abcdef1234".`
	m := conflictRe.FindStringSubmatch(line)
	if m == nil {
		t.Fatal("conflict line did not match")
	}
	if !hexIDRe.MatchString(m[1]) {
		t.Errorf("captured id %q is not a valid container id", m[1])
	}
	// A non-conflict line must not match (no accidental reap trigger).
	if conflictRe.MatchString(`worker-1  | starting up on port 8080`) {
		t.Error("an app log line must not look like a conflict")
	}
}

func TestSelectConflictReap(t *testing.T) {
	declared := map[string]bool{"worker": true, "web": true}
	holderID := "cb17726f76aa1234567890abcdef1234567890abcdef1234567890abcdef1234"

	all := []docker.Container{
		// the conflict-holder: this app's worker, stuck (even 'running' → still reaped as the blocker)
		ctr(holderID, "credlock", "worker", "credlock-worker-1", "running"),
		// a dead sibling strand of the same app → swept (preventive)
		ctr("dead000000000000000000000000000000000000000000000000000000000000", "credlock", "web", "credlock-web-1", "dead"),
		// a HEALTHY sibling of the same app → left alone (never SIGKILL a live instance)
		ctr("live000000000000000000000000000000000000000000000000000000000000", "credlock", "web", "credlock-web-2", "running"),
		// a recreate ARTIFACT (non-running) of the same app → swept
		ctr("art0000000000000000000000000000000000000000000000000000000000000", "credlock", "worker", "abc123def456_credlock-worker-1", "exited"),
		// ANOTHER app's container that textually collides on name → NEVER touched (label scopes)
		ctr("foreign00000000000000000000000000000000000000000000000000000000", "credlock-worker", "x", "credlock-worker-1", "dead"),
	}
	ids, names, holderFound := selectConflictReap(all, "credlock", declared, holderID)
	if !holderFound {
		t.Fatal("the conflict-holder (this app's worker) should be found")
	}
	got := map[string]bool{}
	for _, id := range ids {
		got[id] = true
	}
	if !got[holderID] {
		t.Error("holder must be reaped")
	}
	if !got["dead000000000000000000000000000000000000000000000000000000000000"] {
		t.Error("a dead sibling strand must be swept")
	}
	if !got["art0000000000000000000000000000000000000000000000000000000000000"] {
		t.Error("a non-running recreate artifact must be swept")
	}
	if got["live000000000000000000000000000000000000000000000000000000000000"] {
		t.Error("a RUNNING healthy sibling must NOT be reaped")
	}
	if got["foreign00000000000000000000000000000000000000000000000000000000"] {
		t.Error("another app's container must NEVER be reaped (label scopes, not the name)")
	}
	_ = names
}

// A 'removing' sibling is self-clearing — force-removing it only errors, so it must NOT be swept
// (its rm error would otherwise have suppressed the retry before the best-effort fix).
func TestReapableStrandSkipsRemoving(t *testing.T) {
	removingArtifact := ctr("r00", "app", "web", "abc123_app-web-1", "removing")
	if reapableStrand(removingArtifact) {
		t.Error("a 'removing' container is self-clearing and must not be selected for the sweep")
	}
	deadC := ctr("d00", "app", "web", "app-web-1", "dead")
	if !reapableStrand(deadC) {
		t.Error("a 'dead' container must be selected (docker can't reconcile it)")
	}
}

// The cross-app name-collision seam: app A(slug=foo-bar, svc=baz) and app B(slug=foo, svc=bar-baz)
// both render the container name foo-bar-baz-1. A's reap must NEVER touch B's container — the
// authoritative scope is the compose PROJECT LABEL, not the (ambiguous) name.
func TestSelectConflictReapCrossAppCollision(t *testing.T) {
	bID := "b00000000000000000000000000000000000000000000000000000000000000b"
	// B's stranded container, labeled project=foo. Name collides with what A would produce.
	bContainer := ctr(bID, "foo", "bar-baz", "foo-bar-baz-1", "dead")
	// A deploys (slug=foo-bar, declares service baz). A's conflict names some id.
	ids, _, holderFound := selectConflictReap([]docker.Container{bContainer}, "foo-bar", map[string]bool{"baz": true}, "deadbeefdeadbeef")
	if holderFound || len(ids) != 0 {
		t.Fatalf("app A must not reap app B's container despite the colliding name; got ids=%v holder=%v", ids, holderFound)
	}
}

// If the name-holder is foreign/unlabeled, nothing is reaped (fail-closed → surface the error).
func TestSelectConflictReapForeignHolderFailsClosed(t *testing.T) {
	// An unlabeled squatter holding the name (e.g. a manual `docker run --name`).
	squatter := docker.Container{ID: "5555555555555555555555555555555555555555555555555555555555555555", Names: []string{"/credlock-worker-1"}, State: "running"}
	ids, _, holderFound := selectConflictReap([]docker.Container{squatter}, "credlock", map[string]bool{"worker": true}, "5555555555555555555555555555555555555555555555555555555555555555")
	if holderFound || len(ids) != 0 {
		t.Fatalf("an unlabeled squatter must not be reaped (fail-closed); got ids=%v holder=%v", ids, holderFound)
	}
}
