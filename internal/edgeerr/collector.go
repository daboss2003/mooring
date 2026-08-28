package edgeerr

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/edgemetrics"
)

// Alerter is the subset of the alert store the collector needs (enqueue an infra alert). Kept as an
// interface so edgeerr doesn't depend on the concrete store (and stays trivially testable).
type Alerter interface {
	EnqueueInfra(ctx context.Context, o alert.Outbox) error
}

// Tunables for the "this route is erroring constantly" alert. It watches SERVER errors (5xx) only —
// 4xx (a bot spraying 404s, normal 401s) are logged but never page. A route that returns ≥ err5xx
// server errors within errWindow raises one alert, then stays quiet for alertCooldown.
const (
	errWindow    = 5 * time.Minute
	err5xxAlert  = 10
	alertCooldow = 15 * time.Minute
)

// Collector turns raw Caddy access-log lines into per-route error-log entries + the erroring-route
// alert. It shares the access-log stream with the autoscaling metrics collector (chained on the same
// hook). A line that doesn't parse, isn't an error (status < 400), or can't be attributed to a route
// is skipped — so hostile/garbage traffic and unmatched 404s are never recorded against a service.
type Collector struct {
	idx    *edgemetrics.HostIndex
	store  *Store
	alerts Alerter // nil → no alerting (log-only still works)
	now    func() int64

	mu  sync.Mutex
	win map[string]*routeWindow // route key → sliding 5xx window
}

// routeWindow tracks a route's recent 5xx for the alert. It keeps AT MOST err5xxAlert timestamps (a
// bounded ring) — that's all the "≥ err5xxAlert within errWindow" test needs — so the per-5xx work
// stays O(err5xxAlert) even under a multi-thousand-per-second 5xx flood (the exact condition this
// feature observes). An unbounded slice here would be a quadratic self-DoS on the edge's log-drain
// goroutine.
type routeWindow struct {
	stamps    []int64 // at most err5xxAlert recent 5xx unix-second timestamps
	lastAlert int64
}

// NewCollector wires the store + host index (+ optional alerter).
func NewCollector(store *Store, idx *edgemetrics.HostIndex, alerts Alerter) *Collector {
	return &Collector{idx: idx, store: store, alerts: alerts, now: func() int64 { return time.Now().Unix() }, win: map[string]*routeWindow{}}
}

// Ingest processes ONE raw access-log line (parse, then IngestRecord).
func (c *Collector) Ingest(line []byte) {
	if rec, ok := edgemetrics.ParseAccessFull(line); ok {
		c.IngestRecord(rec)
	}
}

// IngestRecord records an ALREADY-PARSED access record — so a caller that also feeds the metrics
// collector can json-parse each access-log line only once. Non-error responses (< 400) and requests
// whose Host resolves to no route are dropped (never recorded against a service).
func (c *Collector) IngestRecord(rec edgemetrics.AccessRecord) {
	if rec.Status < 400 {
		return
	}
	host := strings.ToLower(strings.TrimSpace(rec.Host)) // normalize: a case-variant Host is one route
	key, prefix, ok := c.idx.LookupRoute(host, rec.Path)
	if !ok {
		return // no route serves this host — unattributed (e.g. a bogus-Host 404)
	}
	now := c.now()
	c.store.Record(Entry{
		At: now, App: key.App, Service: key.Service, Host: host, Prefix: prefix,
		Method: rec.Method, Path: rec.Path, Status: rec.Status, RemoteIP: rec.RemoteIP, DurMs: rec.DurMs,
	})
	if rec.Status >= 500 {
		c.noteServerError(RouteKey(key.App, host, prefix), key.App, key.Service, host, prefix, now)
	}
}

// noteServerError updates a route's bounded 5xx window and raises the "erroring constantly" alert
// when ≥ err5xxAlert land within errWindow (rate-limited by alertCooldown). O(err5xxAlert) per call.
func (c *Collector) noteServerError(rk, app, service, host, prefix string, now int64) {
	cut := now - int64(errWindow.Seconds())
	c.mu.Lock()
	w := c.win[rk]
	if w == nil {
		w = &routeWindow{}
		c.win[rk] = w
	}
	// Bounded ring: keep at most err5xxAlert most-recent stamps — enough to answer "≥ err5xxAlert in
	// the window" without an unbounded, rate-scaled slice (a 5xx flood would otherwise go quadratic).
	w.stamps = append(w.stamps, now)
	if len(w.stamps) > err5xxAlert {
		w.stamps = w.stamps[len(w.stamps)-err5xxAlert:]
	}
	inWindow := 0
	for _, t := range w.stamps { // ≤ err5xxAlert iterations
		if t >= cut {
			inWindow++
		}
	}
	fire := inWindow >= err5xxAlert && now-w.lastAlert >= int64(alertCooldow.Seconds())
	if fire {
		w.lastAlert = now
	}
	c.mu.Unlock()

	if fire && c.alerts != nil {
		route := host + prefix
		if prefix == "" {
			route = host + "/"
		}
		target := app + "/" + service
		o := alert.Outbox{
			RuleID: 0, Target: target, Kind: "route_error_rate", Level: alert.LevelWarning, Transition: "firing",
			Summary:   fmt.Sprintf("Route %s (%s) returned %d+ server errors in %s — the service may be broken; check its logs.", route, target, err5xxAlert, errWindow),
			DedupeKey: "edgeerr:" + rk,
		}
		// Enqueue OFF the log-drain goroutine and with a deadline: EnqueueInfra writes the single-conn
		// SQLite DB, and this runs on the goroutine draining Caddy's access-log pipe — a blocking DB
		// write there could back-pressure the edge. It's rate-limited to ≤ once per cooldown per route.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = c.alerts.EnqueueInfra(ctx, o)
		}()
	}
}
