package web

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/servicelog"
)

func logsDef(t *testing.T, webLogs string) *definition.Definition {
	t.Helper()
	d, err := definition.Parse([]byte(`apiVersion: mooring/v1
kind: App
metadata: {slug: shop}
spec:
  compose:
    source: generated
    services:
      web:
        image: nginx:1.27
` + webLogs + `
      db:
        image: postgres:16
`))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// The policy source reads each service's `logs:` from the deployed (verified) definition.
func TestServiceLogPolicySourceReadsTheDeployedDefinition(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.defStore = definition.NewStore(e.srv.db, make([]byte, 32))
	if _, err := e.srv.defStore.SaveCanonical(context.Background(), logsDef(t, "        logs: {retain: 30d, max_lines: 50000}"), "deploy", ""); err != nil {
		t.Fatal(err)
	}
	src := e.srv.ServiceLogPolicySource()
	if p, ok := src("shop", "web"); !ok || p != (servicelog.Policy{Retain: 30 * 24 * time.Hour, MaxLines: 50000}) {
		t.Errorf("web: %+v %v", p, ok)
	}
	if p, ok := src("shop", "db"); !ok || p != (servicelog.Policy{}) {
		t.Errorf("a service without logs: gets the default: %+v %v", p, ok)
	}
	if p, ok := src("ghost", "web"); !ok || p != (servicelog.Policy{}) {
		t.Errorf("an app without a definition gets the default: %+v %v", p, ok)
	}

	// Wired into a store, the request is clamped to the server ceilings.
	st := servicelog.New(servicelog.Options{Dir: t.TempDir(), Ceiling: servicelog.Policy{Retain: 7 * 24 * time.Hour, MaxLines: 10000}})
	st.SetPolicySource(src)
	if got := st.Policy("shop", "web"); got != (servicelog.Policy{Retain: 7 * 24 * time.Hour, MaxLines: 10000}) {
		t.Errorf("clamped: %+v", got)
	}
}

func TestLogPolicyCacheTTLAndErrors(t *testing.T) {
	now := time.Unix(1000, 0)
	def := logsDef(t, "        logs: {retain: 72h}")
	var err error
	reads := 0
	c := newLogPolicyCache(func(string) (*definition.Definition, error) { reads++; return def, err }, func() time.Time { return now })

	if p, ok := c.lookup("shop", "web"); !ok || p.Retain != 72*time.Hour || reads != 1 {
		t.Fatalf("first read: %+v %v reads=%d", p, ok, reads)
	}
	def = logsDef(t, "        logs: {retain: 96h}")
	if p, _ := c.lookup("shop", "web"); p.Retain != 72*time.Hour || reads != 1 {
		t.Errorf("cached within the TTL: %+v reads=%d", p, reads)
	}
	now = now.Add(logPolicyTTL)
	if p, _ := c.lookup("shop", "web"); p.Retain != 96*time.Hour || reads != 2 {
		t.Errorf("re-read after the TTL: %+v reads=%d", p, reads)
	}
	now = now.Add(logPolicyTTL)
	err = errors.New("db down")
	if p, ok := c.lookup("shop", "web"); !ok || p.Retain != 96*time.Hour {
		t.Errorf("a failed read keeps the last good value: %+v %v", p, ok)
	}
	if _, ok := c.lookup("other", "web"); ok {
		t.Error("a failed read with nothing cached is unknown, never the default")
	}
	err = nil
	for i := 0; i < maxLogPolicyApps+10; i++ {
		c.lookup("app"+strconv.Itoa(i), "svc")
	}
	if len(c.entries) > maxLogPolicyApps {
		t.Errorf("cache grew to %d entries", len(c.entries))
	}
}

// The page's range presets and retention text follow the service's effective policy.
func TestServiceLogViewFollowsTheServicePolicy(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	st := servicelog.New(servicelog.Options{Dir: t.TempDir()})
	st.SetPolicySource(func(app, svc string) (servicelog.Policy, bool) {
		if svc == "web" {
			return servicelog.Policy{Retain: 30 * 24 * time.Hour, MaxLines: 200000}, true
		}
		return servicelog.Policy{}, true
	})
	st.Record("shop", "web", "aaaaaaaaaaaa", "hello from web")
	e.srv.serviceLogs = st

	view := func(svc, query string) *serviceLogView {
		r := httptest.NewRequest("GET", "/apps/shop/services/"+svc+"/logs/history"+query, nil)
		r.SetPathValue("project", "shop")
		r.SetPathValue("service", svc)
		return e.srv.serviceLogView(r)
	}
	presets := func(v *serviceLogView) string {
		var out []string
		for _, p := range v.Presets {
			out = append(out, p.Value)
		}
		return strings.Join(out, ",")
	}

	web := view("web", "?range=30d")
	if presets(web) != "15m,1h,6h,24h,7d,30d,all" || web.Range != "30d" || web.Window != "30 days" || web.MaxLines != "200,000" {
		t.Errorf("30d service: presets=%s range=%s window=%q lines=%q", presets(web), web.Range, web.Window, web.MaxLines)
	}
	if len(web.Lines) != 1 || web.Lines[0].Text != "hello from web" {
		t.Errorf("lines: %+v", web.Lines)
	}
	api := view("api", "?range=30d")
	if presets(api) != "15m,1h,6h,24h,all" || api.Range != "all" || api.Window != "48 hours" || api.MaxLines != "2,000" {
		t.Errorf("default service: presets=%s range=%s window=%q lines=%q", presets(api), api.Range, api.Window, api.MaxLines)
	}
	if def := view("api", ""); def.Range != "1h" {
		t.Errorf("default range: %s", def.Range)
	}

	// The rows fragment shows the service's own window, not a fixed 48 hours.
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/apps/shop/services/web/logs/history/rows?q=nomatch", nil)
	r.SetPathValue("project", "shop")
	r.SetPathValue("service", "web")
	e.srv.handleServiceLogRows(rec, r)
	if body := rec.Body.String(); !strings.Contains(body, "kept for 30 days (up to 200,000 lines)") {
		t.Errorf("rows fragment: %s", body)
	}

	// The full page lists the service's presets and window.
	rec = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/apps/shop/services/web/logs/history?range=7d", nil)
	r.SetPathValue("project", "shop")
	r.SetPathValue("service", "web")
	e.srv.handleServiceLogHistory(rec, r)
	body := rec.Body.String()
	for _, want := range []string{`<option value="30d">Last 30 days</option>`, `<option value="7d" selected>Last 7 days</option>`, "Keeps the last 30 days, up to 200,000 lines."} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing %q", want)
		}
	}
	if strings.Contains(body, "Log capture is paused") {
		t.Error("no pause notice below the disk threshold")
	}
}

// When a service's definition can't be read, the page shows the retention the store applies (the default,
// once a flush has tried to read it) and lists only lines within it.
func TestServiceLogPageMatchesTheStoreWhenThePolicyIsUnreadable(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	dir := t.TempDir()
	svcDir := filepath.Join(dir, "shop", "web")
	if err := os.MkdirAll(svcDir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	for i, l := range []struct {
		at   int64
		text string
	}{{now - 3*24*3600, "three days ago"}, {now - 60, "a minute ago"}} {
		name := fmt.Sprintf("%010d_%d_%d_1.jsonl", i+1, l.at, l.at)
		body := fmt.Sprintf("{\"at\":%d,\"text\":%q}\n", l.at, l.text)
		if err := os.WriteFile(filepath.Join(svcDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	st := servicelog.New(servicelog.Options{Dir: dir})
	st.SetPolicySource(func(string, string) (servicelog.Policy, bool) { return servicelog.Policy{}, false })
	st.Flush()
	e.srv.serviceLogs = st

	r := httptest.NewRequest("GET", "/apps/shop/services/web/logs/history?range=all", nil)
	r.SetPathValue("project", "shop")
	r.SetPathValue("service", "web")
	v := e.srv.serviceLogView(r)
	if v.Window != "48 hours" || v.MaxLines != "2,000" {
		t.Errorf("window = %q / %q, want the default 48 hours / 2,000", v.Window, v.MaxLines)
	}
	if len(v.Lines) != 1 || v.Lines[0].Text != "a minute ago" {
		t.Errorf("lines = %+v, want only the line within the shown window", v.Lines)
	}
}

// The search runs on the request's context: once the viewer has gone, nothing is searched and the page
// says the search stopped.
func TestServiceLogSearchStopsWithTheRequest(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	st := servicelog.New(servicelog.Options{Dir: t.TempDir()})
	st.Record("shop", "web", "aaaaaaaaaaaa", "hello")
	st.Flush()
	e.srv.serviceLogs = st
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("GET", "/apps/shop/services/web/logs/history/rows?range=all", nil).WithContext(ctx)
	r.SetPathValue("project", "shop")
	r.SetPathValue("service", "web")
	rec := httptest.NewRecorder()
	e.srv.handleServiceLogRows(rec, r)
	body := rec.Body.String()
	if strings.Contains(body, "hello") || !strings.Contains(body, "The search stopped before it found a matching line") {
		t.Errorf("rows for a cancelled request: %s", body)
	}
	if strings.Contains(body, "No retained log lines match") {
		t.Error("a stopped search must not claim that nothing matches")
	}
}

// Under disk pressure the page says capture is paused and history is cut to the default.
func TestServiceLogPageShowsDiskPressure(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	st := servicelog.New(servicelog.Options{Dir: t.TempDir(), DiskThresholdPct: 75,
		DiskUsage: func() (uint64, uint64, bool) { return 90, 100, true }})
	st.Flush()
	e.srv.serviceLogs = st
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/apps/shop/services/web/logs/history", nil)
	r.SetPathValue("project", "shop")
	r.SetPathValue("service", "web")
	e.srv.handleServiceLogHistory(rec, r)
	if body := rec.Body.String(); !strings.Contains(body, "Log capture is paused: disk usage is at or above 75%") ||
		!strings.Contains(body, "cut to 48 hours / 2,000 lines") {
		t.Errorf("pause notice missing: %s", body)
	}
}

func TestRetainLabelAndGroupDigits(t *testing.T) {
	for d, want := range map[time.Duration]string{
		48 * time.Hour: "48 hours", 72 * time.Hour: "3 days", 30 * 24 * time.Hour: "30 days", time.Hour: "1 hour",
		36 * time.Hour: "36 hours", 90 * time.Minute: "90 minutes", 24 * time.Hour: "24 hours", 30 * time.Second: "30 seconds",
	} {
		if got := retainLabel(d); got != want {
			t.Errorf("retainLabel(%s) = %q, want %q", d, got, want)
		}
	}
	for n, want := range map[int]string{0: "0", 999: "999", 2000: "2,000", 200000: "200,000", 10000000: "10,000,000"} {
		if got := groupDigits(n); got != want {
			t.Errorf("groupDigits(%d) = %q, want %q", n, got, want)
		}
	}
}
