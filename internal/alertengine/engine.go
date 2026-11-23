// Package alertengine runs the alert engine's goroutines (plan §8): ONE evaluator
// (reads the poller's snapshot, drives the state machine, enqueues the outbox —
// never sends), a SEPARATE globally-rate-limited notifier (drains the outbox, so a
// hung SMTP/bot can't stall evaluation or spam the box), and an externalized
// dead-man's-switch heartbeat. Read-and-notify only: zero docker writes.
package alertengine

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/alertstore"
	"github.com/daboss2003/mooring/internal/monitor"
)

// Config tunes the engine (from config.AlertingConfig).
type Config struct {
	EvalInterval      time.Duration
	NotifyMinInterval time.Duration
	QuietStartHour    int // -1 disables
	QuietEndHour      int
	DeadMansURL       string
	DeadMansInterval  time.Duration
	AdminURL          string // for the "open in dashboard" link in notifications
}

const (
	drainMessages = 100 // messages one drain sends at most
	// partialKeep bounds how long the notifier remembers the channels that took a message whose delivery
	// failed elsewhere: longer than a critical is retried (24h).
	partialKeep = 25 * time.Hour
)

// Engine owns the evaluator + notifier + heartbeat.
type Engine struct {
	store  *alertstore.Store
	snapFn func() *monitor.Snapshot
	cfg    Config
	log    *slog.Logger
	wake   chan struct{}    // evaluator signals the notifier
	now    func() time.Time // the notifier's clock (quiet hours, retry backoff); a test seam
	// pendingAlert is store.PendingAlert; a test seam (a read can't be made to fail on its own).
	pendingAlert func(row alertstore.OutboxRow, criticalOnly bool) (alertstore.PendingAlert, bool, error)

	partial map[string]partialSend // AlertKey → the channels that took its current message (notifier goroutine only)
}

// partialSend records a message that some channels took and others didn't, so its retries go only to
// the others.
type partialSend struct {
	msg string         // which message: its newest row, rows combined and level
	ok  map[int64]bool // ids of the channels that took it
	at  time.Time
}

// New builds an Engine. snapFn returns the latest poller snapshot (may be nil).
func New(store *alertstore.Store, snapFn func() *monitor.Snapshot, cfg Config, log *slog.Logger) *Engine {
	return &Engine{store: store, snapFn: snapFn, cfg: cfg, log: log, wake: make(chan struct{}, 1), now: time.Now,
		pendingAlert: store.PendingAlert, partial: map[string]partialSend{}}
}

// RunEvaluator ticks the evaluator until ctx is cancelled.
func (e *Engine) RunEvaluator(ctx context.Context) {
	t := time.NewTicker(e.cfg.EvalInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.evalOnce(ctx)
		}
	}
}

func (e *Engine) evalOnce(ctx context.Context) {
	rules, err := e.store.ListRules()
	if err != nil {
		e.log.Warn("alert: load rules failed", "err", err)
		return
	}
	if len(rules) == 0 {
		return
	}
	prior, err := e.store.LoadStates()
	if err != nil {
		e.log.Warn("alert: load states failed", "err", err)
		return
	}
	now := time.Now().Unix()
	states, outbox := alert.Evaluate(now, rules, e.snapFn(), prior)
	if err := e.store.SaveStates(ctx, states); err != nil {
		e.log.Warn("alert: save states failed", "err", err)
	}
	if len(outbox) > 0 {
		if err := e.store.EnqueueOutbox(ctx, outbox); err != nil {
			e.log.Warn("alert: enqueue failed", "err", err)
			return
		}
		e.signal()
	}
}

func (e *Engine) signal() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// RunNotifier drains the outbox, globally rate-limited, until ctx is cancelled.
func (e *Engine) RunNotifier(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-e.wake:
		}
		e.notifyOnce(ctx)
	}
}

// notifyOnce is one notifier cycle. The outbox is pruned BEFORE the drain: when alerting is enabled
// after a long time off, rows past the unsent limit are dropped instead of replayed.
func (e *Engine) notifyOnce(ctx context.Context) {
	e.store.PruneOutbox(ctx, time.Now())
	e.drain(ctx)
}

// drain sends up to drainMessages messages, one per alert: all undelivered rows of an alert go out as one
// message reporting its latest state (alertstore.PendingAlert has the full rule). Pending critical alerts
// go first, and are looked for again before every non-critical message, so a critical never waits behind
// a backlog. Quiet hours HOLD every non-critical alert: its rows stay unsent (no attempt counted) and go
// out with the first drain after quiet hours end. CRITICAL always pages (plan §8). A failed send backs off
// as the store decides (FinishAlert), and an alert whose send failed, or whose outcome couldn't be
// recorded, isn't tried again in the same drain; an alert delivered earlier in the drain is sent again
// when it has a new critical row.
func (e *Engine) drain(ctx context.Context) {
	e.forgetPartial()
	handled := map[string]bool{} // AlertKey of every alert tried in this drain
	failed := map[string]bool{}  // of them, those whose send failed or whose outcome wasn't recorded
	sent := 0
	try := func(row alertstore.OutboxRow, criticalOnly bool) bool {
		if ctx.Err() != nil || sent >= drainMessages {
			return false
		}
		k := row.AlertKey()
		handled[k] = true
		sent++
		if !e.deliver(ctx, row, criticalOnly) {
			failed[k] = true
		}
		return true
	}
	criticals := func(quiet bool) bool {
		crit, err := e.store.PendingAlerts(drainMessages, true, e.now())
		if err != nil {
			return false
		}
		for _, row := range crit {
			// An alert delivered earlier in this drain is listed only for a critical row raised since:
			// it goes now. One whose send failed, or whose delivery wasn't recorded, waits for the next
			// drain.
			if failed[row.AlertKey()] {
				continue
			}
			if !try(row, quiet) {
				return false
			}
		}
		return true
	}
	quiet := e.inQuietHours(e.now())
	if !criticals(quiet) || quiet {
		return
	}
	rest, err := e.store.PendingAlerts(drainMessages, false, e.now())
	if err != nil {
		return
	}
	for _, row := range rest {
		if handled[row.AlertKey()] {
			continue
		}
		// A critical raised while this batch is being sent goes out before the next non-critical alert.
		if !criticals(false) {
			return
		}
		// Intentional: the rest of the batch stays unsent — quiet hours began while it was being sent
		// (owner decision: non-critical alerts are held until quiet hours end).
		if e.inQuietHours(e.now()) {
			return
		}
		if handled[row.AlertKey()] { // sent by criticals() just now
			continue
		}
		if !try(row, false) {
			return
		}
	}
}

// deliver sends one message for row's alert, combining every undelivered row of the alert, and records
// the outcome. criticalOnly: the quiet-hours pass. It reports false when the send failed or its outcome
// couldn't be recorded (finish).
func (e *Engine) deliver(ctx context.Context, row alertstore.OutboxRow, criticalOnly bool) bool {
	p, ok, err := e.pendingAlert(row, criticalOnly)
	if err != nil {
		e.log.Warn("alert: reading a pending alert failed; it is tried again on the next send cycle", "kind", row.Kind, "err", err)
		return false
	}
	if !ok {
		return true // nothing of it is pending any more
	}
	latest := p.Latest
	var channels []alertstore.BuiltChannel
	if latest.RuleID == 0 {
		// Mooring-originated infra alert (plan §8.4): rule_id=0, NEVER deferred to an
		// app and not tied to a rule/silence — route straight to ALL channels.
		channels, err = e.store.AllChannels()
	} else {
		// Silenced (operator) → drop. (Silence closes the rows it covers; this catches a row raised in
		// between.)
		if e.store.IsSilenced(latest.RuleID, latest.Target, e.now().Unix()) {
			return e.finish(ctx, p, true)
		}
		rule, ok := e.store.RuleByID(latest.RuleID)
		if !ok {
			return e.finish(ctx, p, true)
		}
		channels, err = e.store.ChannelsForRule(rule.ChannelID)
	}
	if err != nil || len(channels) == 0 {
		e.finish(ctx, p, false)
		return false
	}
	ok = e.sendAll(ctx, p, channels)
	recorded := e.finish(ctx, p, ok)
	if recorded && ok {
		// Only now: until the delivery is recorded its rows stay unsent, and the record of the channels that
		// took the message keeps the next drains from sending it again (they retry the record).
		delete(e.partial, p.Latest.AlertKey())
	}
	return recorded && ok
}

// finish records the outcome of one delivery of p (FinishAlert) and reports whether it was recorded.
//
// Intentional: a delivery that couldn't be recorded counts as a failed attempt for the rest of the drain.
// Its rows stay unsent and due (a full disk fails writes while reads still work), and the drain looks for
// pending criticals again before every message, so it would send the same critical before each one.
func (e *Engine) finish(ctx context.Context, p alertstore.PendingAlert, delivered bool) bool {
	if err := e.store.FinishAlert(ctx, p, delivered, e.now()); err != nil {
		e.log.Warn("alert: recording a delivery's outcome failed; the alert is tried again on the next send cycle",
			"kind", p.Latest.Kind, "delivered", delivered, "err", err)
		return false
	}
	return true
}

// sendAll delivers p's message to every channel that hasn't taken it yet, rate-limited between sends so
// a slow channel can't spam-cannon the box. Returns whether every channel has it now. A retry of the
// same message (no new row since) skips the channels that took it, so one broken channel doesn't make
// the working ones get it again on every retry, and a message every channel took whose delivery wasn't
// recorded isn't sent again. deliver forgets the message once its delivery is recorded.
func (e *Engine) sendAll(ctx context.Context, p alertstore.PendingAlert, channels []alertstore.BuiltChannel) bool {
	k := p.Latest.AlertKey()
	msg := fmt.Sprintf("%d/%d/%s", p.Latest.ID, p.Count, p.Level)
	done := e.partial[k]
	if done.msg != msg {
		done = partialSend{msg: msg, ok: map[int64]bool{}}
	}
	n := e.render(p)
	allOK := true
	for _, ch := range channels {
		if done.ok[ch.ID] {
			continue
		}
		sctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		if err := ch.Send(sctx, n); err != nil {
			allOK = false
			e.log.Warn("alert: channel send failed", "kind", p.Latest.Kind, "err", err)
		} else {
			done.ok[ch.ID] = true
		}
		cancel()
		select {
		case <-ctx.Done():
			allOK = false
		case <-time.After(e.cfg.NotifyMinInterval):
		}
		if ctx.Err() != nil {
			break
		}
	}
	done.at = e.now()
	e.partial[k] = done
	return allOK
}

// forgetPartial drops what the notifier remembers about partly delivered messages older than any retry.
func (e *Engine) forgetPartial() {
	cutoff := e.now().Add(-partialKeep)
	for k, d := range e.partial {
		if d.at.Before(cutoff) {
			delete(e.partial, k)
		}
	}
}

// render builds the message for an alert: the latest state, at the alert's level, with a note when
// several notifications were combined.
func (e *Engine) render(p alertstore.PendingAlert) alert.Notification {
	row := p.Latest
	verb := "FIRING"
	if row.Transition == "resolved" {
		verb = "RESOLVED"
	}
	title := fmt.Sprintf("[%s] %s — %s (%s)", up(p.Level), verb, row.Kind, row.Target)
	body := row.Summary
	if note := e.combinedNote(p); note != "" {
		body += "\n\n" + note
	}
	if e.cfg.AdminURL != "" {
		body += "\n\n" + e.cfg.AdminURL
	}
	return alert.Notification{Title: title, Body: body, Level: p.Level}
}

// combinedNote says how many notifications a message combines and since when, e.g. "Fired and recovered
// 14 times since 23:04.", or "Recovered at 23:00, then fired once." when the first was a recovery ("" for
// a single notification).
func (e *Engine) combinedNote(p alertstore.PendingAlert) string {
	if p.Count < 2 {
		return ""
	}
	since := e.clock(p.Since)
	var s string
	switch {
	case p.First == "resolved" && p.Fired > 0:
		then := "fired " + times(p.Fired)
		if p.Resolved > 1 {
			then += " and recovered " + times(p.Resolved-1)
		}
		s = fmt.Sprintf("Recovered at %s, then %s.", since, then)
	case p.Fired > 0 && p.Fired == p.Resolved:
		s = fmt.Sprintf("Fired and recovered %s since %s.", times(p.Fired), since)
	case p.Fired > 0 && p.Resolved > 0:
		s = fmt.Sprintf("Fired %s and recovered %s since %s.", times(p.Fired), times(p.Resolved), since)
	case p.Resolved > 0:
		s = fmt.Sprintf("Recovered %s since %s.", times(p.Resolved), since)
	default:
		s = fmt.Sprintf("Fired %s since %s.", times(p.Fired), since)
	}
	if p.Level == alert.LevelCritical && p.Latest.Level != alert.LevelCritical {
		s += " It was critical at least once in that time."
	}
	return s
}

// clock formats a unix time on the notifier's clock: "15:04" within the last day, else with the date.
func (e *Engine) clock(unix int64) string {
	now := e.now()
	t := time.Unix(unix, 0).In(now.Location())
	if d := now.Sub(t); d >= 0 && d < 24*time.Hour {
		return t.Format("15:04")
	}
	return t.Format("Jan 2 15:04")
}

func times(n int) string {
	switch n {
	case 1:
		return "once"
	case 2:
		return "twice"
	}
	return fmt.Sprintf("%d times", n)
}

// inQuietHours reports whether now falls in the configured quiet window.
func (e *Engine) inQuietHours(now time.Time) bool {
	s, end := e.cfg.QuietStartHour, e.cfg.QuietEndHour
	// Config loading turns out-of-range hours off (with a load warning); here they disable the window too,
	// so a bad value can never hold warnings forever. start == end is an empty window.
	if s < 0 || end < 0 || s > 23 || end > 23 {
		return false
	}
	h := now.Hour()
	if s <= end {
		return h >= s && h < end
	}
	return h >= s || h < end // window wraps midnight
}

// RunHeartbeat pings an external cron-monitor so a dead dashboard is detected by
// something OTHER than itself (plan §8 dead-man's-switch). SSRF-guarded outbound.
func (e *Engine) RunHeartbeat(ctx context.Context) {
	if e.cfg.DeadMansURL == "" {
		return
	}
	t := time.NewTicker(e.cfg.DeadMansInterval)
	defer t.Stop()
	e.ping(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.ping(ctx)
		}
	}
}

func (e *Engine) ping(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, e.cfg.DeadMansURL, nil)
	if err != nil {
		return
	}
	resp, err := heartbeatClient().Do(req)
	if err != nil {
		e.log.Warn("alert: dead-man heartbeat failed")
		return
	}
	resp.Body.Close()
}

// heartbeatClient blocks loopback/link-local dial targets (SSRF posture).
func heartbeatClient() *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second}
	d.Control = func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip, perr := netip.ParseAddr(host)
		if perr != nil {
			return fmt.Errorf("alert: heartbeat: unresolved")
		}
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("alert: heartbeat refusing loopback/link-local")
		}
		return nil
	}
	return &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{DialContext: d.DialContext, DisableKeepAlives: true},
	}
}

func up(s string) string { return string(bytes.ToUpper([]byte(s))) }
