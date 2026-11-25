package main

import (
	"context"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/siem"
)

// The reason automatic blocks are refused is the real one: before the edge block ran, that the edge
// hasn't started; with automated response off (and no trusted proxies), that it is off; an old or
// unreadable Caddy keeps its own reason; no edge on this host says so.
func TestCaddyOKReasons(t *testing.T) {
	l := &lateBound{}
	if ok, why := l.caddyOK(); ok || why != "the edge hasn't started" {
		t.Errorf("before the edge block: %v %q", ok, why)
	}
	l.set0RTT(false, siem.ResponseModeOff)
	if ok, why := l.caddyOK(); ok || !strings.Contains(why, "automated response is off") || strings.Contains(why, "hasn't started") {
		t.Errorf("response off on a running edge: %v %q", ok, why)
	}

	l = &lateBound{}
	old := "the running Caddy is 2.10.0, older than 2.11.0; run sudo mooring setup to upgrade it"
	l.why0RTT.Store(&old)
	l.set0RTT(false, siem.ResponseModeEnforce)
	if ok, why := l.caddyOK(); ok || why != old {
		t.Errorf("old Caddy: %v %q", ok, why)
	}

	l = &lateBound{}
	l.set0RTT(false, siem.ResponseModeRecommend)
	if _, why := l.caddyOK(); strings.Contains(why, "is off") {
		t.Errorf("response on: %q", why)
	}

	l = &lateBound{}
	l.set0RTT(true, siem.ResponseModeOff) // trusted proxies refuse 0-RTT with response off
	if ok, why := l.caddyOK(); !ok || why != "" {
		t.Errorf("0-RTT refused: %v %q", ok, why)
	}
	l = &lateBound{}
	l.set0RTT(true, siem.ResponseModeEnforce)
	if ok, _ := l.caddyOK(); !ok {
		t.Error("0-RTT refused, response on: not ok")
	}

	l = &lateBound{}
	l.noEdge("caddy not found on PATH")
	if ok, why := l.caddyOK(); ok || !strings.Contains(why, "caddy not found on PATH") {
		t.Errorf("no edge: %v %q", ok, why)
	}
}

// The block list is told an L4 load balancer takes it only when one runs, and otherwise why not.
func TestL4BlockState(t *testing.T) {
	managed := func(l4 bool) *config.Config {
		c := &config.Config{}
		c.Edge.Mode = config.EdgeManaged
		c.Edge.L4Enabled = l4
		return c
	}
	external := &config.Config{}
	external.Edge.L4Enabled = true
	cases := []struct {
		name string
		cfg  *config.Config
		runs bool
		on   bool
		why  string
	}{
		{"runs", managed(true), true, true, ""},
		{"l4 off", managed(false), false, false, "edge.l4_enabled is off"},
		{"nginx missing", managed(true), false, false, "nginx has no stream module"},
		{"external edge", external, false, false, "edge.mode external"},
	}
	for _, c := range cases {
		on, why := l4BlockState(c.cfg, c.runs, "nginx has no stream module")
		if on != c.on || !strings.Contains(why, c.why) || (c.on && why != "") {
			t.Errorf("%s: %v %q, want %v %q", c.name, on, why, c.on, c.why)
		}
	}
}

// A start-up alert left open by a failed start is resolved by the start that works; with nothing
// open (or another alert of the kind open) no "resolved" is sent.
func TestResolveOpenAlert(t *testing.T) {
	db, alerts := serveAlerts(t)
	ctx := context.Background()
	sent := func() (n int) {
		t.Helper()
		if err := db.QueryRow(`SELECT COUNT(*) FROM alert_outbox WHERE transition = 'resolved'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	fire := func(key string) {
		t.Helper()
		if err := alerts.EnqueueInfra(ctx, alert.Outbox{Target: "blocklist", Kind: "security_blocking", Level: alert.LevelWarning,
			Transition: "firing", Summary: "x", DedupeKey: key}); err != nil {
			t.Fatal(err)
		}
	}
	resolveOpenAlert(alerts, "security_blocking", "blocklist:open", "blocklist", "read again")
	if n := sent(); n != 0 {
		t.Fatalf("nothing open: %d resolved rows", n)
	}
	fire("blocklist:apply")
	resolveOpenAlert(alerts, "security_blocking", "blocklist:open", "blocklist", "read again")
	if n := sent(); n != 0 {
		t.Fatalf("another alert of the kind open: %d resolved rows, want 0", n)
	}
	fire("blocklist:open")
	resolveOpenAlert(alerts, "security_blocking", "blocklist:open", "blocklist", "read again")
	open, err := alerts.OpenInfraAlerts(ctx, "security_blocking")
	if _, still := open["blocklist:open"]; err != nil || still || len(open) != 1 || sent() != 1 {
		t.Fatalf("after the resolve: open = %v (%v), resolved rows %d; want only blocklist:apply open, 1 resolved", open, err, sent())
	}
	resolveOpenAlert(nil, "security_blocking", "blocklist:open", "blocklist", "x") // no alert store: nothing
}
