package selfheal

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/alertstore"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/store"
)

// watcherWithAlerts is a test watcher with a real alert store on the same database.
func watcherWithAlerts(t *testing.T, snap **monitor.Snapshot, clock *int64) (*Watcher, *alertstore.Store) {
	t.Helper()
	w := newTestWatcher(t, snap, clock, &fakeActioner{})
	c, err := secret.NewCipher(make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	alerts := alertstore.New(w.cfg.Store.db, c)
	w.cfg.Alerts = alerts
	return w, alerts
}

// deliverAll marks every pending outbox row delivered (the notifier ran) and returns them.
func deliverAll(t *testing.T, a *alertstore.Store) []alertstore.OutboxRow {
	t.Helper()
	rows, err := a.PendingOutbox(1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if p, ok, err := a.PendingAlert(r, false); err == nil && ok {
			if err := a.FinishAlert(context.Background(), p, true, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
	}
	return rows
}

// The re-audit's E3 (item 2): clearing a circuit reset the service to HEALTHY without closing its critical
// alert, so the next, warning-level episode resolved at CRITICAL and paged at night. The clear now closes
// the alert without a message.
func TestClearCircuitClosesTheOpenAlert(t *testing.T) {
	var clock int64 = 1000
	snap := snapOf(upSvc(), 2<<30, 1<<30)
	w, alerts := watcherWithAlerts(t, &snap, &clock)
	ctx := context.Background()
	key := Key{App: "shop", Service: "web"}
	w.fsms[key] = FSM{Phase: CircuitOpen, Open: true}
	w.emitInfra(ctx, monitor.App{Project: "shop"}, "web", "crashloop_capped", "firing")
	deliverAll(t, alerts)

	w.ClearCircuit(key)
	w.Tick(ctx)
	if f := w.fsms[key]; f.Phase != Healthy || f.Open {
		t.Fatalf("cleared: %+v", f)
	}
	if rows := deliverAll(t, alerts); len(rows) != 0 {
		t.Fatalf("clearing a circuit sends nothing: %+v", rows)
	}
	if _, ok := alerts.InfraResolveLevel(ctx, "selfheal:shop/web"); ok {
		t.Fatal("the cleared alert must be closed")
	}
	w.emitInfra(ctx, monitor.App{Project: "shop"}, "web", "dependency_wait", "firing")
	w.emitInfra(ctx, monitor.App{Project: "shop"}, "web", "recovered", "resolved")
	rows := deliverAll(t, alerts)
	if len(rows) != 2 || rows[1].Transition != "resolved" || rows[1].Level != alert.LevelWarning {
		t.Fatalf("the next episode resolves at its own level: %+v", rows)
	}
}

// Item 2, the prune path: a service of an app gone from the list (deleted, or taken down) is dropped
// without a message, and its open alert is closed so a later episode under the same name starts clean.
func TestPruneOfAnUnlistedAppClosesItsAlert(t *testing.T) {
	var clock int64 = 1000
	snap := snapOf(upSvc(), 2<<30, 1<<30)
	w, alerts := watcherWithAlerts(t, &snap, &clock)
	ctx := context.Background()
	gone := Key{App: "other", Service: "api"}
	w.fsms[gone] = FSM{Phase: CircuitOpen, Open: true}
	w.emitInfra(ctx, monitor.App{Project: "other"}, "api", "crashloop_capped", "firing")
	deliverAll(t, alerts)
	w.emitInfra(ctx, monitor.App{Project: "other"}, "api", "dependency_wait", "firing") // undelivered
	w.Tick(ctx)
	if _, ok := w.fsms[gone]; ok {
		t.Fatal("the service must be pruned")
	}
	if rows := deliverAll(t, alerts); len(rows) != 0 {
		t.Fatalf("a removed app's alert is closed without a message: %+v", rows)
	}
	if _, ok := alerts.InfraResolveLevel(ctx, "selfheal:other/api"); ok {
		t.Fatal("the removed app's alert must be closed")
	}
}

// Pre-existing spam: below the headroom floor the watcher paged low_headroom on every tick, so each tick
// after a delivery sent another message. It pages once per failing episode, and the episode's recovery
// resolves it.
func TestLowHeadroomPagesOncePerEpisode(t *testing.T) {
	var clock int64
	snap := snapOf(downSvc(), 2<<30, 2<<30-(100<<20)) // ~100 MiB free, below the 256 MiB floor
	w, alerts := watcherWithAlerts(t, &snap, &clock)
	ctx := context.Background()
	var sent []alertstore.OutboxRow
	tick := func(n int) {
		for i := 0; i < n; i++ {
			clock += 100
			w.Tick(ctx)
			sent = append(sent, deliverAll(t, alerts)...)
		}
	}
	tick(12)
	if len(sent) != 1 || sent[0].Kind != "low_headroom" || sent[0].Transition != "firing" {
		t.Fatalf("12 ticks below the floor: %d messages %+v, want one low_headroom page", len(sent), sent)
	}
	snap = snapOf(upSvc(), 2<<30, 2<<30-(100<<20))
	tick(5)
	if len(sent) != 2 || sent[1].Transition != "resolved" || sent[1].Level != alert.LevelWarning {
		t.Fatalf("the recovery resolves the page: %+v", sent)
	}
	snap = snapOf(downSvc(), 2<<30, 2<<30-(100<<20))
	tick(6)
	if len(sent) != 3 || sent[2].Kind != "low_headroom" {
		t.Fatalf("a new failing episode pages again: %+v", sent)
	}
}

// failableAlerts gives w an alert store on a database of its own, so its writes can be made to fail (a full
// disk) while the supervisor's state is still saved. Reads keep working.
func failableAlerts(t *testing.T, w *Watcher) (alerts *alertstore.Store, db *store.DB, readOnly func(on bool)) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "alerts.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	c, err := secret.NewCipher(make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	alerts = alertstore.New(db, c)
	w.cfg.Alerts = alerts
	readOnly = func(on bool) {
		t.Helper()
		q := `PRAGMA query_only=OFF`
		if on {
			q = `PRAGMA query_only=ON`
		}
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return alerts, db, readOnly
}

// queued returns the outbox rows not yet delivered, without writing (it works while writes fail).
func queued(t *testing.T, a *alertstore.Store) []alertstore.OutboxRow {
	t.Helper()
	rows, err := a.PendingOutbox(1000)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// Round 4, item 3: the low_headroom episode was marked paged before the page was enqueued, and a failed
// enqueue (a full disk) wasn't reported, so it silenced the whole episode. Only an enqueued page counts:
// the next tick below the floor pages again, and an alert that was never raised isn't left open.
func TestLowHeadroomPageIsRetriedAfterAFailedEnqueue(t *testing.T) {
	var clock int64
	snap := snapOf(downSvc(), 2<<30, 2<<30-(100<<20)) // ~100 MiB free, below the 256 MiB floor
	w := newTestWatcher(t, &snap, &clock, &fakeActioner{})
	alerts, _, readOnly := failableAlerts(t, w)
	ctx := context.Background()
	key := Key{App: "shop", Service: "web"}
	tick := func(n int) {
		for i := 0; i < n; i++ {
			clock += 100
			w.Tick(ctx)
		}
	}
	readOnly(true)
	tick(12)
	if w.fsms[key].Phase != Degraded || w.fsms[key].Open {
		t.Fatalf("below the floor with the page not enqueued: %+v, want DEGRADED with no open alert", w.fsms[key])
	}
	readOnly(false)
	tick(1)
	if rows := deliverAll(t, alerts); len(rows) != 1 || rows[0].Kind != "low_headroom" || rows[0].Transition != "firing" {
		t.Fatalf("once the alert store works again the next tick pages: %+v", rows)
	}
	if !w.fsms[key].Open {
		t.Fatal("the enqueued page opens the alert")
	}
	tick(5)
	if rows := deliverAll(t, alerts); len(rows) != 0 {
		t.Fatalf("still once per episode: %+v", rows)
	}
}

// A resolve ("recovered", "service_gone") carries the level of the alert it closes. It used to be
// critical always, so a warning held through quiet hours had its resolve page at night — for an alert the
// operator never saw fire — and the warning was then dropped.
func TestResolveCarriesTheOpenAlertsLevel(t *testing.T) {
	var snap *monitor.Snapshot
	var clock int64
	w := newTestWatcher(t, &snap, &clock, &fakeActioner{})
	c, err := secret.NewCipher(make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	alerts := alertstore.New(w.cfg.Store.db, c)
	w.cfg.Alerts = alerts
	ctx := context.Background()
	app := monitor.App{Project: "shop"}
	newest := func() alertstore.OutboxRow {
		t.Helper()
		rows, err := alerts.PendingOutbox(1000)
		if err != nil || len(rows) == 0 {
			t.Fatalf("no rows: %v", err)
		}
		return rows[len(rows)-1]
	}

	w.emitInfra(ctx, app, "web", "dependency_wait", "firing")
	w.emitInfra(ctx, app, "web", "recovered", "resolved")
	if r := newest(); r.Transition != "resolved" || r.Level != alert.LevelWarning {
		t.Fatalf("resolving a warning: %+v", r)
	}

	w.emitInfra(ctx, app, "web", "dependency_wait", "firing")
	w.emitInfra(ctx, app, "web", "crashloop_capped", "firing")
	w.emitInfra(ctx, app, "web", "recovered", "resolved")
	if r := newest(); r.Transition != "resolved" || r.Level != alert.LevelCritical {
		t.Fatalf("resolving an alert that reached critical: %+v", r)
	}

	w.emitInfra(ctx, app, "web", "unhealthy_reported", "firing")
	w.emitInfra(ctx, app, "web", "service_gone", "resolved")
	if r := newest(); r.Kind != "service_gone" || r.Level != alert.LevelWarning {
		t.Fatalf("service_gone after a warning: %+v", r)
	}

	// Nothing recorded for the key (rows pruned): a resolve never wakes anyone.
	w.emitInfra(ctx, app, "api", "service_gone", "resolved")
	if r := newest(); r.Target != "shop/api" || r.Level != alert.LevelWarning {
		t.Fatalf("resolve without a recorded firing: %+v", r)
	}

	// Firing levels are unchanged.
	w.emitInfra(ctx, app, "web", "oom_killed_repeated", "firing")
	if r := newest(); r.Level != alert.LevelCritical {
		t.Fatalf("a give-up kind fires critical: %+v", r)
	}
}

// crashLoop ticks a crash-looping shop/web until the supervisor gives up (CIRCUIT_OPEN, crashloop_capped).
func crashLoop(t *testing.T, w *Watcher, snap **monitor.Snapshot, clock *int64) {
	t.Helper()
	*snap = snapOf(downSvc(), 2<<30, 1<<30)
	for i := 0; i < 12; i++ {
		*clock += 100
		w.Tick(context.Background())
	}
	if f := w.fsms[Key{App: "shop", Service: "web"}]; f.Phase != CircuitOpen || !f.Open {
		t.Fatalf("after the crash loop: %+v, want CIRCUIT_OPEN with the alert open", f)
	}
}

// ticks advances the clock and ticks n times.
func ticks(w *Watcher, clock *int64, n int) {
	for i := 0; i < n; i++ {
		*clock += 100
		w.Tick(context.Background())
	}
}

// Round 4, pre-existing: a give-up page whose enqueue failed (a full disk) was lost — the FSM had already
// moved to CIRCUIT_OPEN, so it never paged again. The page is kept and retried every tick until enqueued,
// while the FSM moves on as it would have. One warning is logged, not one per tick.
func TestFailedGiveUpPageIsRetriedUntilEnqueued(t *testing.T) {
	var clock int64 = 1000
	var snap *monitor.Snapshot
	w := newTestWatcher(t, &snap, &clock, &fakeActioner{})
	var logs strings.Builder
	w.cfg.Log = slog.New(slog.NewTextHandler(&logs, nil))
	alerts, _, readOnly := failableAlerts(t, w)
	key := Key{App: "shop", Service: "web"}

	readOnly(true)
	crashLoop(t, w, &snap, &clock)
	ticks(w, &clock, 5)
	if rows := queued(t, alerts); len(rows) != 0 {
		t.Fatalf("nothing can be enqueued yet: %+v", rows)
	}
	if f := w.fsms[key]; f.Phase != CircuitOpen || !f.Open {
		t.Fatalf("the transition is committed while the page waits: %+v", f)
	}
	if n := strings.Count(logs.String(), `level=WARN`); n != 1 || !strings.Contains(logs.String(), `level=WARN msg="selfheal: enqueue infra alert failed"`) {
		t.Fatalf("%d warnings over 6 failing ticks, want the one enqueue failure:\n%s", n, logs.String())
	}

	readOnly(false)
	ticks(w, &clock, 1)
	rows := deliverAll(t, alerts)
	if len(rows) != 1 || rows[0].Kind != "crashloop_capped" || rows[0].Transition != "firing" || rows[0].Level != alert.LevelCritical {
		t.Fatalf("once the outbox takes writes again the page is enqueued: %+v", rows)
	}
	if n := strings.Count(logs.String(), `level=INFO msg="selfheal: infra alert enqueued on retry"`); n != 1 {
		t.Fatalf("%d retry-success logs, want 1:\n%s", n, logs.String())
	}
	ticks(w, &clock, 5)
	if rows := deliverAll(t, alerts); len(rows) != 0 {
		t.Fatalf("the page is enqueued once: %+v", rows)
	}
}

// A recovery that supersedes a page never enqueued sends nothing: no "recovered" for an alert nobody saw.
func TestResolveOfANeverEnqueuedPageSendsNothing(t *testing.T) {
	var clock int64 = 1000
	var snap *monitor.Snapshot
	w := newTestWatcher(t, &snap, &clock, &fakeActioner{})
	alerts, _, readOnly := failableAlerts(t, w)

	readOnly(true)
	crashLoop(t, w, &snap, &clock)
	snap = snapOf(upSvc(), 2<<30, 1<<30)
	ticks(w, &clock, 3)
	if f := w.fsms[Key{App: "shop", Service: "web"}]; f.Phase != Healthy || f.Open {
		t.Fatalf("recovered: %+v", f)
	}
	readOnly(false)
	ticks(w, &clock, 3)
	if rows := deliverAll(t, alerts); len(rows) != 0 {
		t.Fatalf("neither the page nor its recovery is sent: %+v", rows)
	}
}

// The recovery of a page that was enqueued is retried like the page.
func TestFailedResolveOfAnEnqueuedPageIsRetried(t *testing.T) {
	var clock int64 = 1000
	var snap *monitor.Snapshot
	w := newTestWatcher(t, &snap, &clock, &fakeActioner{})
	alerts, _, readOnly := failableAlerts(t, w)

	crashLoop(t, w, &snap, &clock)
	if rows := deliverAll(t, alerts); len(rows) != 1 || rows[0].Kind != "crashloop_capped" {
		t.Fatalf("the page: %+v", rows)
	}
	readOnly(true)
	snap = snapOf(upSvc(), 2<<30, 1<<30)
	ticks(w, &clock, 5)
	if f := w.fsms[Key{App: "shop", Service: "web"}]; f.Phase != Healthy || f.Open {
		t.Fatalf("recovered: %+v", f)
	}
	readOnly(false)
	ticks(w, &clock, 1)
	rows := deliverAll(t, alerts)
	if len(rows) != 1 || rows[0].Kind != "recovered" || rows[0].Transition != "resolved" || rows[0].Level != alert.LevelCritical {
		t.Fatalf("the recovery is enqueued once the outbox takes writes, at the page's level: %+v", rows)
	}
	ticks(w, &clock, 3)
	if rows := deliverAll(t, alerts); len(rows) != 0 {
		t.Fatalf("the recovery is enqueued once: %+v", rows)
	}
}

// A newer firing that can't be enqueued doesn't cancel the recovery of an earlier one that was: the
// receiver has that alert open. Known in this process even after the outbox lost the row, and from the
// outbox after a restart.
func TestResolveIsSentWhenAnEarlierPageOfTheEpisodeWasEnqueued(t *testing.T) {
	app := monitor.App{Project: "shop"}
	check := func(t *testing.T, w *Watcher, alerts *alertstore.Store, readOnly func(bool), clock *int64) {
		t.Helper()
		ctx := context.Background()
		readOnly(true)
		w.emitInfra(ctx, app, "web", "crashloop_capped", "firing")
		w.emitInfra(ctx, app, "web", "recovered", "resolved")
		readOnly(false)
		ticks(w, clock, 1)
		rows := deliverAll(t, alerts)
		if len(rows) != 1 || rows[0].Kind != "recovered" || rows[0].Level != alert.LevelWarning {
			t.Fatalf("the earlier warning's recovery, at its level, and not the newer page: %+v", rows)
		}
	}
	t.Run("same process, rows gone from the outbox", func(t *testing.T) {
		var clock int64 = 1000
		snap := snapOf(upSvc(), 2<<30, 1<<30)
		w := newTestWatcher(t, &snap, &clock, &fakeActioner{})
		alerts, db, readOnly := failableAlerts(t, w)
		w.emitInfra(context.Background(), app, "web", "dependency_wait", "firing")
		deliverAll(t, alerts)
		if _, err := db.Exec(`DELETE FROM alert_outbox`); err != nil { // past the outbox retention
			t.Fatal(err)
		}
		check(t, w, alerts, readOnly, &clock)
	})
	t.Run("after a restart", func(t *testing.T) {
		var clock int64 = 1000
		snap := snapOf(upSvc(), 2<<30, 1<<30)
		before := newTestWatcher(t, &snap, &clock, &fakeActioner{})
		alerts, _, readOnly := failableAlerts(t, before)
		before.emitInfra(context.Background(), app, "web", "dependency_wait", "firing")
		deliverAll(t, alerts)
		w := newTestWatcher(t, &snap, &clock, &fakeActioner{})
		w.cfg.Alerts = alerts
		check(t, w, alerts, readOnly, &clock)
	})
}

// service_gone is retried after prune dropped the service's FSM.
func TestFailedServiceGoneIsRetriedAfterPrune(t *testing.T) {
	var clock int64 = 1000
	snap := snapOf(upSvc(), 2<<30, 1<<30)
	w := newTestWatcher(t, &snap, &clock, &fakeActioner{})
	alerts, _, readOnly := failableAlerts(t, w)
	gone := Key{App: "shop", Service: "api"}
	w.fsms[gone] = FSM{Phase: CircuitOpen, Open: true}
	w.emitInfra(context.Background(), monitor.App{Project: "shop"}, "api", "crashloop_capped", "firing")
	deliverAll(t, alerts)

	readOnly(true)
	ticks(w, &clock, 3)
	if _, ok := w.fsms[gone]; ok {
		t.Fatal("the service must be pruned")
	}
	readOnly(false)
	ticks(w, &clock, 1)
	rows := deliverAll(t, alerts)
	if len(rows) != 1 || rows[0].Target != "shop/api" || rows[0].Kind != "service_gone" || rows[0].Level != alert.LevelCritical {
		t.Fatalf("the service_gone resolve outlives the FSM: %+v", rows)
	}
}

// An alert closed without a message (its app gone from the list, or the operator's clear) takes its
// pending alert with it.
func TestClosingAnAlertDropsItsPendingAlert(t *testing.T) {
	ctx := context.Background()
	t.Run("app gone from the list", func(t *testing.T) {
		var clock int64 = 1000
		snap := snapOf(upSvc(), 2<<30, 1<<30)
		w := newTestWatcher(t, &snap, &clock, &fakeActioner{})
		alerts, _, readOnly := failableAlerts(t, w)
		w.fsms[Key{App: "other", Service: "api"}] = FSM{Phase: CircuitOpen, Open: true}
		readOnly(true)
		w.emitInfra(ctx, monitor.App{Project: "other"}, "api", "crashloop_capped", "firing")
		ticks(w, &clock, 1)
		readOnly(false)
		ticks(w, &clock, 3)
		if rows := deliverAll(t, alerts); len(rows) != 0 {
			t.Fatalf("a removed app's pending page is dropped: %+v", rows)
		}
	})
	t.Run("app gone after its service was pruned", func(t *testing.T) {
		var clock int64 = 1000
		both := &monitor.Snapshot{DockerOK: true, Apps: []monitor.App{
			{Project: "shop", Services: []monitor.ServiceStatus{upSvc()}},
			{Project: "other", Services: []monitor.ServiceStatus{{Service: "worker", State: "running"}}},
		}}
		snap := both
		w := newTestWatcher(t, &snap, &clock, &fakeActioner{})
		alerts, _, readOnly := failableAlerts(t, w)
		w.fsms[Key{App: "other", Service: "api"}] = FSM{Phase: CircuitOpen, Open: true}
		w.emitInfra(ctx, monitor.App{Project: "other"}, "api", "crashloop_capped", "firing")
		deliverAll(t, alerts)
		readOnly(true)
		ticks(w, &clock, 1) // other/api pruned; its service_gone waits
		snap = snapOf(upSvc(), 2<<30, 1<<30)
		ticks(w, &clock, 1) // then the whole app goes
		readOnly(false)
		ticks(w, &clock, 3)
		if rows := deliverAll(t, alerts); len(rows) != 0 {
			t.Fatalf("a removed app's pending service_gone is dropped: %+v", rows)
		}
	})
	t.Run("clear circuit", func(t *testing.T) {
		var clock int64 = 1000
		snap := snapOf(upSvc(), 2<<30, 1<<30)
		w := newTestWatcher(t, &snap, &clock, &fakeActioner{})
		_, db, readOnly := failableAlerts(t, w)
		key := Key{App: "shop", Service: "web"}
		w.fsms[key] = FSM{Phase: CircuitOpen, Open: true}
		readOnly(true)
		w.emitInfra(ctx, monitor.App{Project: "shop"}, "web", "crashloop_capped", "firing")
		readOnly(false)
		w.ClearCircuit(key) // applied by the tick that would also retry the page
		ticks(w, &clock, 3)
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM alert_outbox`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("a cleared circuit's pending page is never enqueued: %d rows (%v)", n, err)
		}
	})
}

// At most one pending alert per service, the newest; an alert enqueued later replaces it too.
func TestNewerAlertReplacesThePendingOne(t *testing.T) {
	var clock int64 = 1000
	snap := snapOf(upSvc(), 2<<30, 1<<30)
	w := newTestWatcher(t, &snap, &clock, &fakeActioner{})
	alerts, _, readOnly := failableAlerts(t, w)
	ctx := context.Background()
	app := monitor.App{Project: "shop"}

	readOnly(true)
	w.emitInfra(ctx, app, "web", "dependency_wait", "firing")
	w.emitInfra(ctx, app, "web", "crashloop_capped", "firing")
	readOnly(false)
	ticks(w, &clock, 2)
	rows := deliverAll(t, alerts)
	if len(rows) != 1 || rows[0].Kind != "crashloop_capped" {
		t.Fatalf("only the newest pending alert is enqueued: %+v", rows)
	}

	readOnly(true)
	w.emitInfra(ctx, app, "api", "unhealthy_reported", "firing")
	readOnly(false)
	w.emitInfra(ctx, app, "api", "crashloop_capped", "firing")
	ticks(w, &clock, 2)
	rows = deliverAll(t, alerts)
	if len(rows) != 1 || rows[0].Target != "shop/api" || rows[0].Kind != "crashloop_capped" {
		t.Fatalf("an older pending alert is never sent after a newer one: %+v", rows)
	}
}

// low_headroom keeps its own retry: a page not enqueued opened no alert, so it must not be enqueued later
// (after the headroom came back) — no resolve would ever close it.
func TestUnsentLowHeadroomPageIsNotEnqueuedAfterRecovery(t *testing.T) {
	var clock int64
	snap := snapOf(downSvc(), 2<<30, 2<<30-(100<<20)) // ~100 MiB free, below the 256 MiB floor
	w := newTestWatcher(t, &snap, &clock, &fakeActioner{})
	alerts, _, readOnly := failableAlerts(t, w)

	readOnly(true)
	ticks(w, &clock, 6)
	snap = snapOf(upSvc(), 2<<30, 1<<30)
	ticks(w, &clock, 4)
	if f := w.fsms[Key{App: "shop", Service: "web"}]; f.Phase != Healthy || f.Open {
		t.Fatalf("recovered: %+v", f)
	}
	readOnly(false)
	ticks(w, &clock, 3)
	if rows := deliverAll(t, alerts); len(rows) != 0 {
		t.Fatalf("nothing is sent for a page that was never enqueued: %+v", rows)
	}
}

// outboxOff makes every read and write of the outbox fail (on) or work again (off).
func outboxOff(t *testing.T, db *store.DB, on bool) {
	t.Helper()
	q := `ALTER TABLE alert_outbox_off RENAME TO alert_outbox`
	if on {
		q = `ALTER TABLE alert_outbox RENAME TO alert_outbox_off`
	}
	if _, err := db.Exec(q); err != nil {
		t.Fatal(err)
	}
}

// Round 5, finding 1: after a restart, a recovery whose newer page couldn't be enqueued was dropped whenever
// the outbox showed no firing of the episode — also when the outbox couldn't be read, or the episode's
// earlier rows had been pruned — so the alert the operator had open never got its recovery. It is dropped
// only when the outbox positively records no firing of the episode.
func TestRecoveryIsSentWhenTheOutboxCantTellThePageWasRaised(t *testing.T) {
	ctx := context.Background()
	app := monitor.App{Project: "shop"}
	key := Key{App: "shop", Service: "web"}
	// restarted returns a watcher whose shop/web alert was raised and delivered by the process before it,
	// with the service's FSM as that process saved it (circuit open, alert open).
	restarted := func(t *testing.T) (*Watcher, *alertstore.Store, *store.DB, func(bool), *int64, **monitor.Snapshot) {
		t.Helper()
		clock := new(int64)
		*clock = 1000
		snap := new(*monitor.Snapshot)
		*snap = snapOf(upSvc(), 2<<30, 1<<30)
		before := newTestWatcher(t, snap, clock, &fakeActioner{})
		alerts, db, readOnly := failableAlerts(t, before)
		before.emitInfra(ctx, app, "web", "dependency_wait", "firing")
		if rows := deliverAll(t, alerts); len(rows) != 1 {
			t.Fatalf("the earlier page: %+v", rows)
		}
		w := newTestWatcher(t, snap, clock, &fakeActioner{})
		w.cfg.Alerts = alerts
		w.fsms[key] = FSM{Phase: CircuitOpen, Open: true}
		return w, alerts, db, readOnly, clock, snap
	}
	recovered := func(t *testing.T, w *Watcher) {
		t.Helper()
		if f := w.fsms[key]; f.Phase != Healthy || f.Open {
			t.Fatalf("recovered: %+v", f)
		}
	}
	wantRecovery := func(t *testing.T, alerts *alertstore.Store) {
		t.Helper()
		rows := deliverAll(t, alerts)
		if len(rows) != 1 || rows[0].Kind != "recovered" || rows[0].Transition != "resolved" {
			t.Fatalf("the open alert's recovery is sent, and only it: %+v", rows)
		}
	}

	t.Run("the outbox can't be read", func(t *testing.T) {
		w, alerts, db, _, clock, _ := restarted(t)
		outboxOff(t, db, true)
		w.emitInfra(ctx, app, "web", "crashloop_capped", "firing")
		ticks(w, clock, 3)
		recovered(t, w)
		outboxOff(t, db, false)
		ticks(w, clock, 1)
		wantRecovery(t, alerts)
	})
	t.Run("the earlier rows were pruned", func(t *testing.T) {
		w, alerts, db, readOnly, clock, _ := restarted(t)
		if _, err := db.Exec(`DELETE FROM alert_outbox`); err != nil { // past the outbox retention
			t.Fatal(err)
		}
		readOnly(true)
		w.emitInfra(ctx, app, "web", "crashloop_capped", "firing")
		ticks(w, clock, 3)
		recovered(t, w)
		readOnly(false)
		ticks(w, clock, 1)
		wantRecovery(t, alerts)
	})
	t.Run("a recovery not enqueued doesn't end the episode", func(t *testing.T) {
		w, alerts, db, readOnly, clock, snap := restarted(t)
		if _, err := db.Exec(`DELETE FROM alert_outbox`); err != nil {
			t.Fatal(err)
		}
		readOnly(true)
		ticks(w, clock, 3) // the recovery waits
		recovered(t, w)
		crashLoop(t, w, snap, clock) // a new page replaces it, and waits too
		*snap = snapOf(upSvc(), 2<<30, 1<<30)
		ticks(w, clock, 3)
		recovered(t, w)
		readOnly(false)
		ticks(w, clock, 1)
		wantRecovery(t, alerts)
	})
	t.Run("the episode began before the outbox retention", func(t *testing.T) {
		var clock int64 = 1000
		snap := snapOf(upSvc(), 2<<30, 1<<30)
		w := newTestWatcher(t, &snap, &clock, &fakeActioner{})
		alerts, _, readOnly := failableAlerts(t, w)
		readOnly(true)
		crashLoop(t, w, &snap, &clock)
		w.episodeAt[key] = time.Now().Add(-8 * 24 * time.Hour).Unix() // the page has failed for 8 days
		snap = snapOf(upSvc(), 2<<30, 1<<30)
		ticks(w, &clock, 3)
		recovered(t, w)
		readOnly(false)
		ticks(w, &clock, 1)
		wantRecovery(t, alerts)
	})
}

// The counterpart: when the outbox positively records no firing of the episode, neither the page nor its
// recovery is sent — also after a restart, when the last episode was resolved.
func TestResolveOfANeverEnqueuedPageAfterARestartSendsNothing(t *testing.T) {
	ctx := context.Background()
	app := monitor.App{Project: "shop"}
	for _, open := range []bool{false, true} { // the FSM saved before the restart: no alert open, or one open
		var clock int64 = 1000
		snap := snapOf(upSvc(), 2<<30, 1<<30)
		before := newTestWatcher(t, &snap, &clock, &fakeActioner{})
		alerts, _, readOnly := failableAlerts(t, before)
		before.emitInfra(ctx, app, "web", "dependency_wait", "firing")
		before.emitInfra(ctx, app, "web", "recovered", "resolved")
		deliverAll(t, alerts)
		w := newTestWatcher(t, &snap, &clock, &fakeActioner{})
		w.cfg.Alerts = alerts
		w.fsms[Key{App: "shop", Service: "web"}] = FSM{Phase: CircuitOpen, Open: open}
		readOnly(true)
		w.emitInfra(ctx, app, "web", "crashloop_capped", "firing")
		w.emitInfra(ctx, app, "web", "recovered", "resolved")
		readOnly(false)
		ticks(w, &clock, 2)
		if rows := deliverAll(t, alerts); len(rows) != 0 {
			t.Fatalf("FSM open %v: neither the page nor its recovery is sent: %+v", open, rows)
		}
	}
}

// Round 5, finding 2: a close that couldn't be recorded ("Clear & retry" while the outbox writes fail) was
// never retried, so the cleared critical stayed the key's open alert and the next, warning-level episode
// resolved at critical — paging at night. The close is retried every check until it is recorded.
func TestFailedCloseIsRetriedUntilRecorded(t *testing.T) {
	var clock int64 = 1000
	var snap *monitor.Snapshot
	w := newTestWatcher(t, &snap, &clock, &fakeActioner{})
	alerts, _, readOnly := failableAlerts(t, w)
	ctx := context.Background()
	app := monitor.App{Project: "shop"}
	key := Key{App: "shop", Service: "web"}
	crashLoop(t, w, &snap, &clock)
	if rows := deliverAll(t, alerts); len(rows) != 1 || rows[0].Level != alert.LevelCritical {
		t.Fatalf("the critical page: %+v", rows)
	}
	snap = snapOf(upSvc(), 2<<30, 1<<30)
	readOnly(true)
	w.ClearCircuit(key)
	ticks(w, &clock, 3)
	w.ClearCircuit(key)
	ticks(w, &clock, 1)
	if len(w.pendingClose) != 1 {
		t.Errorf("one pending close per service: %+v", w.pendingClose)
	}
	readOnly(false)
	ticks(w, &clock, 1)
	if rows := deliverAll(t, alerts); len(rows) != 0 {
		t.Fatalf("the close sends nothing: %+v", rows)
	}
	if _, ok := alerts.InfraResolveLevel(ctx, "selfheal:shop/web"); ok {
		t.Fatal("the cleared alert must be closed once the outbox takes writes")
	}
	w.emitInfra(ctx, app, "web", "dependency_wait", "firing")
	w.emitInfra(ctx, app, "web", "recovered", "resolved")
	rows := deliverAll(t, alerts)
	if len(rows) != 2 || rows[1].Transition != "resolved" || rows[1].Level != alert.LevelWarning {
		t.Fatalf("the next episode resolves at its own level: %+v", rows)
	}
}

// A close is recorded before any later alert of the service: recorded after it, it would end the new alert's
// episode. A later alert waits behind a close that still fails.
func TestAlertWaitsBehindAPendingClose(t *testing.T) {
	ctx := context.Background()
	app := monitor.App{Project: "shop"}
	key := Key{App: "shop", Service: "web"}
	cleared := func(t *testing.T) (*Watcher, *alertstore.Store, *store.DB, func(bool), *int64) {
		t.Helper()
		clock := new(int64)
		*clock = 1000
		snap := new(*monitor.Snapshot)
		w := newTestWatcher(t, snap, clock, &fakeActioner{})
		alerts, db, readOnly := failableAlerts(t, w)
		crashLoop(t, w, snap, clock)
		deliverAll(t, alerts)
		*snap = snapOf(upSvc(), 2<<30, 1<<30)
		readOnly(true)
		w.ClearCircuit(key)
		ticks(w, clock, 1)
		if len(w.pendingClose) != 1 {
			t.Errorf("the close waits: %+v", w.pendingClose)
		}
		return w, alerts, db, readOnly, clock
	}
	newEpisode := func(t *testing.T, w *Watcher, alerts *alertstore.Store) {
		t.Helper()
		rows := deliverAll(t, alerts)
		if len(rows) != 1 || rows[0].Kind != "dependency_wait" || rows[0].Transition != "firing" {
			t.Fatalf("the new page is sent: %+v", rows)
		}
		w.emitInfra(ctx, app, "web", "recovered", "resolved")
		if rows := deliverAll(t, alerts); len(rows) != 1 || rows[0].Level != alert.LevelWarning {
			t.Fatalf("its recovery takes its own level: %+v", rows)
		}
	}

	t.Run("raised while the close fails", func(t *testing.T) {
		w, alerts, _, readOnly, clock := cleared(t)
		w.emitInfra(ctx, app, "web", "dependency_wait", "firing")
		w.emitInfra(ctx, app, "web", "unhealthy_reported", "firing")
		if len(w.pendingClose) != 1 || len(w.pendingInfra) != 1 {
			t.Errorf("one pending close and one pending alert: %+v %+v", w.pendingClose, w.pendingInfra)
		}
		w.emitInfra(ctx, app, "web", "dependency_wait", "firing")
		readOnly(false)
		ticks(w, clock, 1)
		newEpisode(t, w, alerts)
	})
	t.Run("raised once the outbox takes writes", func(t *testing.T) {
		w, alerts, _, readOnly, clock := cleared(t)
		readOnly(false)
		w.emitInfra(ctx, app, "web", "dependency_wait", "firing")
		if rows := queued(t, alerts); len(rows) != 1 || rows[0].Kind != "dependency_wait" {
			t.Fatalf("the close is recorded and the alert enqueued at once: %+v", rows)
		}
		ticks(w, clock, 1)
		newEpisode(t, w, alerts)
	})
	t.Run("only the close fails", func(t *testing.T) {
		w, alerts, db, readOnly, clock := cleared(t)
		readOnly(false)
		if _, err := db.Exec(`CREATE TRIGGER no_close BEFORE INSERT ON alert_outbox WHEN NEW.kind='circuit_cleared'
			BEGIN SELECT RAISE(ABORT, 'disk full'); END`); err != nil {
			t.Fatal(err)
		}
		w.emitInfra(ctx, app, "web", "dependency_wait", "firing")
		ticks(w, clock, 2)
		if rows := queued(t, alerts); len(rows) != 0 {
			t.Fatalf("the alert waits behind the close: %+v", rows)
		}
		if _, err := db.Exec(`DROP TRIGGER no_close`); err != nil {
			t.Fatal(err)
		}
		ticks(w, clock, 1)
		newEpisode(t, w, alerts)
	})
	t.Run("resolved while the close fails", func(t *testing.T) {
		w, alerts, db, readOnly, clock := cleared(t)
		w.emitInfra(ctx, app, "web", "crashloop_capped", "firing")
		w.emitInfra(ctx, app, "web", "recovered", "resolved")
		readOnly(false)
		ticks(w, clock, 2)
		if rows := deliverAll(t, alerts); len(rows) != 0 {
			t.Fatalf("an alert raised and resolved behind the close is never sent: %+v", rows)
		}
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM alert_outbox`).Scan(&n); err != nil || n != 2 {
			t.Fatalf("nothing but the first page and the close is recorded: %d rows (%v)", n, err)
		}
	})
}

// The close of a service whose app is gone is retried the same way, and sends nothing.
func TestFailedCloseOfAGoneAppIsRetried(t *testing.T) {
	var clock int64 = 1000
	snap := snapOf(upSvc(), 2<<30, 1<<30)
	w := newTestWatcher(t, &snap, &clock, &fakeActioner{})
	alerts, _, readOnly := failableAlerts(t, w)
	ctx := context.Background()
	gone := Key{App: "other", Service: "api"}
	w.fsms[gone] = FSM{Phase: CircuitOpen, Open: true}
	w.emitInfra(ctx, monitor.App{Project: "other"}, "api", "crashloop_capped", "firing")
	deliverAll(t, alerts)
	readOnly(true)
	ticks(w, &clock, 3)
	if _, ok := w.fsms[gone]; ok {
		t.Fatal("the service must be pruned")
	}
	if len(w.pendingClose) != 1 {
		t.Errorf("its close waits: %+v", w.pendingClose)
	}
	readOnly(false)
	ticks(w, &clock, 2)
	if rows := deliverAll(t, alerts); len(rows) != 0 {
		t.Fatalf("a removed app's alert is closed without a message: %+v", rows)
	}
	if _, ok := alerts.InfraResolveLevel(ctx, "selfheal:other/api"); ok {
		t.Fatal("the close is recorded once the outbox takes writes")
	}
	if len(w.pendingClose) != 0 {
		t.Errorf("no close left waiting: %+v", w.pendingClose)
	}
}

// A pending page is retried on every tick, also one that acts on nothing because Docker can't be listed:
// a page waiting for the outbox doesn't wait for Docker too.
func TestPendingPageIsRetriedWhileDockerIsDown(t *testing.T) {
	var clock int64 = 1000
	var snap *monitor.Snapshot
	w := newTestWatcher(t, &snap, &clock, &fakeActioner{})
	alerts, _, readOnly := failableAlerts(t, w)

	readOnly(true)
	crashLoop(t, w, &snap, &clock)
	readOnly(false)
	snap = &monitor.Snapshot{DockerOK: false}
	ticks(w, &clock, 1)
	rows := deliverAll(t, alerts)
	if len(rows) != 1 || rows[0].Kind != "crashloop_capped" || rows[0].Transition != "firing" {
		t.Fatalf("the pending page must be enqueued while Docker is down: %+v", rows)
	}
	if f := w.fsms[Key{App: "shop", Service: "web"}]; f.Phase != CircuitOpen {
		t.Fatalf("a tick without Docker must not change the service's state: %+v", f)
	}
}

// low_headroom re-pages every tick while it is below the floor; while the outbox can't take it, that is
// one warning in the log, and one info line when it finally goes in, not a warning per tick.
func TestUnsentLowHeadroomPageLogsOnce(t *testing.T) {
	var clock int64
	snap := snapOf(downSvc(), 2<<30, 2<<30-(100<<20)) // ~100 MiB free, below the 256 MiB floor
	w := newTestWatcher(t, &snap, &clock, &fakeActioner{})
	var logs strings.Builder
	w.cfg.Log = slog.New(slog.NewTextHandler(&logs, nil))
	alerts, _, readOnly := failableAlerts(t, w)

	readOnly(true)
	ticks(w, &clock, 12)
	if n := strings.Count(logs.String(), "level=WARN"); n != 1 {
		t.Fatalf("%d warnings while the low_headroom page couldn't be enqueued, want 1:\n%s", n, logs.String())
	}
	readOnly(false)
	ticks(w, &clock, 1)
	if rows := deliverAll(t, alerts); len(rows) != 1 || rows[0].Kind != "low_headroom" {
		t.Fatalf("the page goes in once the outbox takes writes: %+v", rows)
	}
	if n := strings.Count(logs.String(), `level=INFO msg="selfheal: infra alert enqueued on retry"`); n != 1 {
		t.Fatalf("%d retry-success logs, want 1:\n%s", n, logs.String())
	}
	// A later failing episode warns again.
	snap = snapOf(upSvc(), 2<<30, 1<<30)
	ticks(w, &clock, 6)
	readOnly(true)
	snap = snapOf(downSvc(), 2<<30, 2<<30-(100<<20))
	ticks(w, &clock, 12)
	if n := strings.Count(logs.String(), "level=WARN"); n != 2 {
		t.Fatalf("%d warnings over two failing episodes, want 2:\n%s", n, logs.String())
	}
}
