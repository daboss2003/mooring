package web

import (
	"reflect"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/definition"
)

// rolloutDur is a *config.Duration for test configs (server.start_gate.deploy_wait is optional).
func rolloutDur(d time.Duration) *config.Duration {
	c := config.Duration(d)
	return &c
}

func TestSettleDeadline(t *testing.T) {
	maxSettle, limit := 3*time.Minute, 15*time.Minute
	if got := settleDeadline(nil, maxSettle, limit); got != 3*time.Minute+30*time.Second {
		t.Fatalf("no healthcheck: %s", got)
	}
	// Docker defaults: 0 + (30s + 30s) × (3 + 1) + 60s = 5m.
	if got := settleDeadline(&definition.Healthcheck{Test: []string{"true"}}, maxSettle, limit); got != 5*time.Minute {
		t.Fatalf("default healthcheck: %s", got)
	}
	hc := &definition.Healthcheck{Test: []string{"true"}, Interval: "10s", Timeout: "5s", Retries: 2, StartPeriod: "1m"}
	if got := settleDeadline(hc, maxSettle, limit); got != 1*time.Minute+45*time.Second+time.Minute {
		t.Fatalf("tuned healthcheck: %s", got)
	}
	long := &definition.Healthcheck{Test: []string{"true"}, StartPeriod: "30m"}
	if got := settleDeadline(long, maxSettle, limit); got != limit {
		t.Fatalf("capped at the limit: %s", got)
	}
}

func TestRolloutOrder(t *testing.T) {
	got := rolloutOrder([]string{"web", "worker", "db", "cache"}, map[string][]string{
		"web": {"db", "cache"}, "worker": {"db", "queue"}, // queue isn't in the rollout: ignored
	})
	if want := []string{"cache", "db", "web", "worker"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
	cyclic := rolloutOrder([]string{"a", "b"}, map[string][]string{"a": {"b"}, "b": {"a"}})
	if len(cyclic) != 2 {
		t.Fatalf("a cycle must still list every service once: %v", cyclic)
	}
}

func TestRestartPolicy(t *testing.T) {
	for p, want := range map[string]bool{"": false, "no": false, "always": true, "unless-stopped": true, "on-failure": true, "on-failure:3": true} {
		if restartPolicy(p) != want {
			t.Errorf("restartPolicy(%q) = %v", p, !want)
		}
	}
}

func TestRolloutCallTimeout(t *testing.T) {
	if got := rolloutCallTimeout(rolloutStep{}, true); got != 3*time.Minute {
		t.Fatalf("copy default: %s", got)
	}
	if got := rolloutCallTimeout(rolloutStep{}, false); got != 10*time.Minute {
		t.Fatalf("compose default: %s", got)
	}
	if got := rolloutCallTimeout(rolloutStep{StopGrace: 5 * time.Minute}, true); got != 8*time.Minute {
		t.Fatalf("a copy's stop grace is added: %s", got)
	}
	if got := rolloutCallTimeout(rolloutStep{Timeout: 30 * time.Minute, StopGrace: time.Minute}, false); got != 31*time.Minute {
		t.Fatalf("explicit timeout plus grace: %s", got)
	}
}

func TestStopGrace(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 0, "90s": 90 * time.Second, "1m30s": 90 * time.Second, "bogus": 0, "-5s": 0} {
		if got := stopGrace(in); got != want {
			t.Errorf("stopGrace(%q) = %s, want %s", in, got, want)
		}
	}
}
