package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/docker"
	"github.com/daboss2003/mooring/internal/edge"
)

// containersJSON is a /containers/json fixture exercising every discovery filter:
// running shop/web replicas (kept), a stopped one + wrong service + wrong project +
// a loopback IP + an empty IP + a one-off `compose run` container (all dropped), and a
// multi-homed replica (dialed on its project's default network).
const containersJSON = `[
 {"Id":"1","State":"running","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web"},
  "NetworkSettings":{"Networks":{"shop_default":{"IPAddress":"172.18.0.6"}}}},
 {"Id":"2","State":"running","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web"},
  "NetworkSettings":{"Networks":{"shop_default":{"IPAddress":"172.18.0.5"}}}},
 {"Id":"3","State":"exited","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web"},
  "NetworkSettings":{"Networks":{"shop_default":{"IPAddress":"172.18.0.9"}}}},
 {"Id":"4","State":"running","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"db"},
  "NetworkSettings":{"Networks":{"shop_default":{"IPAddress":"172.18.0.10"}}}},
 {"Id":"5","State":"running","Labels":{"com.docker.compose.project":"other","com.docker.compose.service":"web"},
  "NetworkSettings":{"Networks":{"other_default":{"IPAddress":"172.20.0.2"}}}},
 {"Id":"6","State":"running","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web"},
  "NetworkSettings":{"Networks":{"shop_default":{"IPAddress":"127.0.0.1"}}}},
 {"Id":"7","State":"running","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web"},
  "NetworkSettings":{"Networks":{"shop_default":{"IPAddress":""}}}},
 {"Id":"8","State":"running","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web","com.docker.compose.oneoff":"True"},
  "NetworkSettings":{"Networks":{"shop_default":{"IPAddress":"172.18.0.30"}}}},
 {"Id":"9","State":"running","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"api"},
  "NetworkSettings":{"Networks":{"aaa_extra":{"IPAddress":"10.9.0.4"},"shop_default":{"IPAddress":"172.18.0.40"}}}}
]`

func dockerServingContainers(t *testing.T, body string) *docker.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return docker.New(strings.TrimPrefix(srv.URL, "http://"))
}

func quietWebLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// DiscoverEdgePools keeps only RUNNING, non-one-off replicas of each route's exact (project, service),
// takes one routable bridge IP per replica, attaches the route's port, drops loopback/empty IPs, and
// returns the set sorted (deterministic → stable render), keyed by PoolKey — marking the route evaluated.
func TestDiscoverEdgePools(t *testing.T) {
	s := &Server{docker: dockerServingContainers(t, containersJSON), log: quietWebLog()}
	rt := edge.Route{AppID: "shop", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true}
	got := s.DiscoverEdgePools(context.Background(), []edge.Route{rt}, nil)
	if !got.OK || !got.Evaluated[edge.PoolKey(rt)] {
		t.Fatalf("discovery must succeed and evaluate the route: %+v", got)
	}
	want := []string{"172.18.0.5:8080", "172.18.0.6:8080"}
	if !reflect.DeepEqual(got.Pools[edge.PoolKey(rt)], want) {
		t.Errorf("pool = %v, want %v (one-off and loopback/empty addresses dropped)", got.Pools[edge.PoolKey(rt)], want)
	}
}

// https upstreams are discovered too: the edge dials the IP and verifies the certificate against the
// service name (tls server_name), so they never need a name dial.
func TestDiscoverEdgePoolsIncludesHTTPS(t *testing.T) {
	s := &Server{docker: dockerServingContainers(t, containersJSON), log: quietWebLog()}
	rt := edge.Route{AppID: "shop", Upstream: "web:8443", UpstreamScheme: "https", Enabled: true}
	got := s.DiscoverEdgePools(context.Background(), []edge.Route{rt}, nil)
	if want := []string{"172.18.0.5:8443", "172.18.0.6:8443"}; !reflect.DeepEqual(got.Pools[edge.PoolKey(rt)], want) {
		t.Errorf("https pool = %v, want %v", got.Pools[edge.PoolKey(rt)], want)
	}
}

// A multi-homed replica is dialed on its project's default network, not merely the first network by name.
func TestDiscoverEdgePoolsPrefersDefaultNetwork(t *testing.T) {
	s := &Server{docker: dockerServingContainers(t, containersJSON), log: quietWebLog()}
	rt := edge.Route{AppID: "shop", Upstream: "api:3000", UpstreamScheme: "http", Enabled: true}
	got := s.DiscoverEdgePools(context.Background(), []edge.Route{rt}, nil)
	if want := []string{"172.18.0.40:3000"}; !reflect.DeepEqual(got.Pools[edge.PoolKey(rt)], want) {
		t.Errorf("pool = %v, want %v", got.Pools[edge.PoolKey(rt)], want)
	}
}

// "Listed fine, nothing running" (OK, evaluated, no pool → the route answers 503) is distinct from
// "discovery unavailable" (not OK → the edge keeps its last-known addresses for a while).
func TestDiscoverEdgePoolsNoContainerVsUnavailable(t *testing.T) {
	s := &Server{docker: dockerServingContainers(t, containersJSON), log: quietWebLog()}
	ghost := edge.Route{AppID: "shop", Upstream: "ghost:8080", UpstreamScheme: "http", Enabled: true}
	got := s.DiscoverEdgePools(context.Background(), []edge.Route{ghost}, nil)
	if !got.OK || !got.Evaluated[edge.PoolKey(ghost)] || len(got.Pools[edge.PoolKey(ghost)]) != 0 {
		t.Errorf("no container: want OK + evaluated + no pool, got %+v", got)
	}

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "proxy down", http.StatusBadGateway)
	}))
	defer failing.Close()
	for name, srv := range map[string]*Server{
		"nil docker":  {docker: nil, log: quietWebLog()},
		"list errors": {docker: docker.New(strings.TrimPrefix(failing.URL, "http://")), log: quietWebLog()},
	} {
		if d := srv.DiscoverEdgePools(context.Background(), []edge.Route{ghost}, nil); d.OK {
			t.Errorf("%s: discovery must report not OK, got %+v", name, d)
		}
	}
}

// Routes that can't be discovered (no app id, a bad upstream, disabled) are simply not evaluated.
func TestDiscoverEdgePoolsSkipsUnusableRoutes(t *testing.T) {
	s := &Server{docker: dockerServingContainers(t, containersJSON), log: quietWebLog()}
	for name, rt := range map[string]edge.Route{
		"bad upstream": {AppID: "shop", Upstream: "web", Enabled: true},
		"no app id":    {AppID: "", Upstream: "web:8080", Enabled: true},
		"disabled":     {AppID: "shop", Upstream: "web:8080", Enabled: false},
	} {
		got := s.DiscoverEdgePools(context.Background(), []edge.Route{rt}, nil)
		if !got.OK || len(got.Evaluated) != 0 || len(got.Pools) != 0 {
			t.Errorf("%s: want OK with nothing evaluated, got %+v", name, got)
		}
	}
}

// Draining containers are excluded from the pool.
func TestDiscoverEdgePoolsExcludesDraining(t *testing.T) {
	s := &Server{docker: dockerServingContainers(t, containersJSON), log: quietWebLog()}
	rt := edge.Route{AppID: "shop", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true}
	got := s.DiscoverEdgePools(context.Background(), []edge.Route{rt}, map[string]bool{"1": true})
	if want := []string{"172.18.0.5:8080"}; !reflect.DeepEqual(got.Pools[edge.PoolKey(rt)], want) {
		t.Errorf("pool = %v, want %v (container 1 draining)", got.Pools[edge.PoolKey(rt)], want)
	}
}

// A copy takes traffic only once it is ready — when at least one other copy is — and a service whose
// copies are all still starting is dialed rather than answered with a 503.
func TestServingReplicasReadiness(t *testing.T) {
	a := replica{ID: "aaaaaaaaaaaa1111", IP: "172.18.0.2"}
	b := replica{ID: "bbbbbbbbbbbb2222", IP: "172.18.0.3"}
	c := replica{ID: "cccccccccccc3333", IP: "172.18.0.4"}
	all := []replica{a, b, c}
	cases := []struct {
		name    string
		health  map[string]string
		exclude map[string]bool
		want    []replica
	}{
		{"only the ready copies", map[string]string{a.ID: "healthy", b.ID: "starting", c.ID: "unhealthy"}, nil, []replica{a}},
		{"no healthcheck counts as ready", map[string]string{a.ID: "none", b.ID: "starting"}, nil, []replica{a}},
		{"unobserved copy waits", map[string]string{a.ID: "healthy"}, nil, []replica{a}},
		{"none ready → all serve", map[string]string{a.ID: "starting", b.ID: "starting"}, nil, all},
		{"abbreviated ids match", map[string]string{"aaaaaaaaaaaa": "healthy"}, nil, []replica{a}},
		{"drained ready copy leaves the rest", map[string]string{a.ID: "healthy", b.ID: "healthy"}, map[string]bool{"aaaaaaaaaaaa": true}, []replica{b}},
	}
	for _, tc := range cases {
		if got := servingReplicas(all, tc.exclude, tc.health); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
