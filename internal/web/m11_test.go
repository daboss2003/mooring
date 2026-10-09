package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/edge"
)

// Edge routes are READ-ONLY in the dashboard: they come from the deployed mooring.yaml
// (projected into the edge route store on deploy) and the page lists them with no
// add/delete form. The route validation (control-plane ports, wildcards) is enforced by
// edge.ValidateRoute on the store/deploy path (tested in internal/edge), not via a form.
func TestEdgeRoutesReadOnly(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, _ := e.authed(t)
	cookies := []*http.Cookie{sess}
	if err := e.srv.edgeRoutes.Save(context.Background(), edge.Route{AppID: "shop", Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	page := readBody(e.req(t, "GET", "/edge", "127.0.0.1:1", nil, cookies, nil))
	if !strings.Contains(page, "app.example.com") || !strings.Contains(page, "web:8080") {
		t.Error("deployed route not listed on the edge page")
	}
	if strings.Contains(page, `action="/edge/routes"`) || strings.Contains(page, "Save route") {
		t.Error("edge page must be read-only (no write form)")
	}
}

// The edge page shows each route's lb; a route without one shows the default, least_conn.
func TestEdgeRoutesShowLB(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, _ := e.authed(t)
	ctx := context.Background()
	for _, r := range []edge.Route{
		{AppID: "shop", Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true, LB: "cookie"},
		{AppID: "shop", Hostname: "plain.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true},
	} {
		if err := e.srv.edgeRoutes.Save(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	page := readBody(e.req(t, "GET", "/edge", "127.0.0.1:1", nil, []*http.Cookie{sess}, nil))
	for _, want := range []string{"<th>LB</th>", `<td class="mono">cookie</td>`, `<td class="mono">least_conn</td>`} {
		if !strings.Contains(page, want) {
			t.Errorf("edge page missing %q", want)
		}
	}
}

// The dashboard write path is gone: POST /edge/routes is no longer registered.
func TestEdgeRouteWriteRemoved(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}
	resp := e.req(t, "POST", "/edge/routes", "127.0.0.1:1", hdr, cookies, url.Values{"csrf_token": {csrf.Value}})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST /edge/routes = %d, want 404 (route retired — edit mooring.yaml)", resp.StatusCode)
	}
}
