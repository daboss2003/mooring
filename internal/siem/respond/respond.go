// Package respond is automated response: it takes the rule engine's response requests
// (siem.Responder), records each in mooring.db (migration 0044_security_responses.sql), and in
// enforce mode applies the automatic ones — a block through the edge block list
// (internal/blocklist), a session revoke through the dashboard (siem.AccountRevoker) — within the
// hourly caps. It serves the owner-only Responses page (siem.ResponseService).
//
// One worker (Run) applies the requests in order; the page's changes (Apply, Dismiss, SetPause,
// LiftForIncident) take the same lock, so a response's state only changes one way at a time.
package respond

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/blocklist"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/store"
)

// Alert kinds.
const (
	// AlertKind is the alert of an applied session revoke (critical, every time) and of a cap
	// reached (warning, at most once an hour per action).
	AlertKind = "security_response"
)

// Limits.
const (
	RecommendTTL = 7 * 24 * time.Hour // a recommendation nobody acted on expires
	// dismissQuiet: a recommendation the owner dismissed isn't made again (same action, target and
	// incident) for this long.
	dismissQuiet   = 24 * time.Hour
	ExemptFalsePos = 30 * 24 * time.Hour // LiftForIncident's exemption from automatic blocks
	RevokeCooldown = time.Hour           // at most one automatic revoke per account in this time
	QueueSize      = 256                 // requests waiting for the worker
	Retention      = 400 * 24 * time.Hour
	MaxSummary     = 300
)

// Alerter queues an alert (the alert store's EnqueueInfra).
type Alerter interface {
	EnqueueInfra(ctx context.Context, o alert.Outbox) error
}

// Options configures the responder.
type Options struct {
	DB *store.DB
	// Mode is security_logs.response.mode as in force (siem.ResponseModeOff / Recommend / Enforce).
	// Off at Open lifts every automatic block still in force.
	Mode              string
	MaxBlocksPerHour  int
	MaxRevokesPerHour int
	Blocks            blocklist.Service // nil: blocks are refused (no edge)
	// Timeline adds an entry to an incident's timeline (detect.Engine.NoteResponse); nil: none.
	Timeline func(ctx context.Context, incidentID int64, ev siem.IncidentEvent) error
	Alerter  Alerter // nil: no alerts
	// Audit records automatic actions (actor "siem"); nil: none.
	Audit func(ctx context.Context, e audit.Event) error
	Emit  func(siem.Event) bool // siem.response events (nil: none)
	// ManualMaxDuration is the block list's longest manual block (security_logs.blocking.
	// manual_max_duration): an applied recommendation's block is at most this long. 0: not known,
	// the recommended duration is asked for as it is (the block list refuses one too long).
	ManualMaxDuration time.Duration
	Log               *slog.Logger
	Now               func() time.Time
}

// Tunables.
const (
	defaultMaxBlocks  = 60
	defaultMaxRevokes = 3
	capWindow         = time.Hour // the caps count the automatic actions applied within it
	actionTimeout     = 15 * time.Second
	sideTimeout       = 5 * time.Second // one timeline entry, alert or audit write
	maintainEvery     = 10 * time.Minute
	pruneEvery        = 24 * time.Hour
	drainTimeout      = 2 * time.Second
	leftoverTimeout   = 2 * time.Second // recording the requests still queued after drainTimeout
	logEvery          = time.Minute
	maxRevoked        = 1000 // accounts remembered for the revoke cooldown (see recentlyRevoked)
	// blockAhead: a request to block an address whose block still has this long to go is skipped.
	blockAhead    = 2 * time.Minute
	refusalWindow = time.Hour // a refusal for the same reason is recorded once in it per action and target

	alertTarget  = "security-logs"
	auditActor   = "siem"
	auditAction  = "security_response"
	kindResponse = "siem.response"
)

// Reasons (Response.Reason) besides the block list's refusal codes.
const (
	reasonCap       = "hourly_cap"
	reasonCooldown  = "cooldown"
	reasonNoRevoker = "no_revoker"
	reasonUnknown   = "unknown_account"
	reasonError     = "error"
	// reasonInterrupted is recorded before an action and replaced by its outcome, and for a request
	// still queued when the responder stopped.
	reasonInterrupted   = "interrupted"
	reasonInvalidTarget = "invalid_target" // a revoke whose target is no account name as events store one
	reasonRefused       = "refused"        // a refusal whose code isn't a fixed word
)

type pauseState struct {
	level, by string
	at        time.Time
}

type revokerRef struct{ a siem.AccountRevoker }

type revokedAcct struct {
	user string
	at   time.Time
}

// Responder implements siem.Responder and siem.ResponseService.
type Responder struct {
	o                     Options
	log                   *slog.Logger
	now                   func() time.Time
	mode                  string
	maxBlocks, maxRevokes int

	queue     chan siem.ResponseRequest
	drainFor  time.Duration // drainTimeout (tests shorten it)
	quit      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	running   atomic.Bool
	closed    atomic.Bool
	dropped   atomic.Int64 // requests not taken: the queue was full
	skipped   atomic.Int64 // requests that needed no record (Skipped)

	revoker atomic.Pointer[revokerRef]
	pause   atomic.Pointer[pauseState] // nil: none

	// mu is held while a response's state is decided and recorded (the worker, and the page's
	// changes); never while an incident's timeline, an alert or the audit log is written.
	mu          sync.Mutex
	capWarned   map[string]time.Time   // action → the last cap warning
	revoked     map[string]revokedAcct // request target → the account its automatic revoke signed out
	liftPending bool                   // the automatic blocks are to be lifted (the effective mode is off)
	lastPrune   time.Time
	// unsettled are the recommendations an owner applied whose record couldn't be written (apply):
	// each as it is to be recorded. Intentional: no cap. An entry takes an owner's Apply of an open
	// recommendation while the database refuses writes, and each recommendation gets at most one.
	unsettled map[int64]siem.Response

	lastLog sync.Map // category → *atomic.Int64 (unix ns)
}

var (
	_ siem.Responder       = (*Responder)(nil)
	_ siem.ResponseService = (*Responder)(nil)
)

// Open reads the pause and expires old recommendations; with Mode off it lifts every automatic
// block still in force (tried again by Run until it works).
func Open(ctx context.Context, o Options) (*Responder, error) {
	if o.DB == nil {
		return nil, errors.New("respond: no database")
	}
	r := &Responder{o: o, log: o.Log, now: o.Now, mode: siem.ResponseModeOff,
		maxBlocks: o.MaxBlocksPerHour, maxRevokes: o.MaxRevokesPerHour,
		drainFor: drainTimeout,
		queue:    make(chan siem.ResponseRequest, QueueSize), quit: make(chan struct{}), done: make(chan struct{}),
		capWarned: map[string]time.Time{}, revoked: map[string]revokedAcct{}, unsettled: map[int64]siem.Response{}}
	if r.log == nil {
		r.log = slog.New(slog.DiscardHandler)
	}
	if r.now == nil {
		r.now = time.Now
	}
	// Intentional: an unknown mode is off (config validation refuses one at load).
	switch o.Mode {
	case siem.ResponseModeRecommend, siem.ResponseModeEnforce:
		r.mode = o.Mode
	}
	if r.maxBlocks <= 0 {
		r.maxBlocks = defaultMaxBlocks
	}
	if r.maxRevokes <= 0 {
		r.maxRevokes = defaultMaxRevokes
	}
	if err := r.loadPause(ctx); err != nil {
		return nil, fmt.Errorf("respond: %w", err)
	}
	if err := r.loadCapWarned(ctx); err != nil {
		r.log.Error("security response: cap warnings not read back", "err", err)
	}
	r.liftPending = r.effective() == siem.ResponseModeOff
	r.maintain(ctx)
	return r, nil
}

// Run applies queued requests until ctx is done (or Close), and expires and prunes old responses.
// Requests still queued then are applied for at most drainTimeout; the ones left after that are
// recorded as failed (interrupted), never applied.
func (r *Responder) Run(ctx context.Context) {
	if !r.running.CompareAndSwap(false, true) {
		return
	}
	defer close(r.done)
	tick := time.NewTicker(maintainEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			r.drain()
			return
		case <-r.quit:
			r.drain()
			return
		case req := <-r.queue:
			r.safe(func() { r.handle(req) })
		case <-tick.C:
			r.safe(func() { r.maintain(context.Background()) })
		}
	}
}

func (r *Responder) drain() {
	deadline := time.Now().Add(r.drainFor)
	for time.Now().Before(deadline) {
		select {
		case req := <-r.queue:
			r.safe(func() { r.handle(req) })
		default:
			return
		}
	}
	r.safe(r.recordLeftover)
}

// recordLeftover records each request still queued at shutdown as failed with reason interrupted
// (within leftoverTimeout), so the Responses page shows what was asked for and not done. Nothing
// else follows from it: the engine that would take a timeline entry is stopping too.
func (r *Responder) recordLeftover() {
	ctx, cancel := context.WithTimeout(context.Background(), leftoverTimeout)
	defer cancel()
	recorded, lost := 0, 0
	for {
		var req siem.ResponseRequest
		select {
		case req = <-r.queue:
		default:
			if recorded+lost > 0 {
				r.log.Warn("security response: requests still queued at shutdown were not applied",
					"recorded_as_failed", recorded, "not_recorded", lost)
			}
			return
		}
		if r.recordInterrupted(ctx, req) {
			recorded++
		} else {
			lost++
		}
	}
}

// recordInterrupted records one request that was never handled; false when it wasn't recorded
// (malformed, automated response off, or the database didn't take it).
func (r *Responder) recordInterrupted(ctx context.Context, req siem.ResponseRequest) bool {
	req, ok := checkRequest(req)
	if !ok || ctx.Err() != nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.effective() == siem.ResponseModeOff {
		return false
	}
	target := plain(req.Target, siem.MaxShort)
	if req.Action == siem.ResponseBlock {
		if t, ok := blockTarget(req.Target); ok {
			target = t
		} else {
			target = clean(req.Target, 64)
		}
	}
	return r.record(ctx, outcome{}, r.base(req, target), siem.ResponseFailed, reasonInterrupted).x.ID != 0
}

// Close stops what Run started.
func (r *Responder) Close() {
	r.closed.Store(true)
	r.closeOnce.Do(func() { close(r.quit) })
	if r.running.Load() {
		<-r.done
	}
}

// SetRevoker sets the session revoker (the dashboard, created after the responder); until it is
// set, revokes are refused.
func (r *Responder) SetRevoker(a siem.AccountRevoker) {
	if a == nil {
		r.revoker.Store(nil)
		return
	}
	r.revoker.Store(&revokerRef{a})
}

// Respond queues a request for the worker; it never blocks (false: the queue is full, or closed).
func (r *Responder) Respond(req siem.ResponseRequest) bool {
	if r.closed.Load() {
		return false
	}
	select {
	case r.queue <- req:
		return true
	default:
		n := r.dropped.Add(1)
		r.logLimited("dropped", "security response: queue full, response request dropped", "dropped_total", n)
		return false
	}
}

// Skipped is how many requests were handled without a record since Open: a block of an address
// still blocked, or a refusal already recorded for the same reason within the hour.
func (r *Responder) Skipped() int64 { return r.skipped.Load() }

func (r *Responder) safe(f func()) {
	defer func() {
		if p := recover(); p != nil {
			r.logLimited("panic", "security response: request handling panicked", "panic", fmt.Sprint(p))
		}
	}()
	f()
}

// logLimited logs at most once per logEvery per category.
func (r *Responder) logLimited(cat, msg string, args ...any) {
	v, _ := r.lastLog.LoadOrStore(cat, new(atomic.Int64))
	last := v.(*atomic.Int64)
	now := time.Now().UnixNano()
	prev := last.Load()
	if now-prev < int64(logEvery) || !last.CompareAndSwap(prev, now) {
		return
	}
	r.log.Warn(msg, args...)
}

// modeRank orders the modes: off < recommend < enforce.
func modeRank(m string) int {
	switch m {
	case siem.ResponseModeRecommend:
		return 1
	case siem.ResponseModeEnforce:
		return 2
	}
	return 0
}

// effective is the lower of the configured mode and the pause.
func (r *Responder) effective() string {
	if p := r.pause.Load(); p != nil && modeRank(p.level) < modeRank(r.mode) {
		return p.level
	}
	return r.mode
}

// maintain expires old recommendations, prunes responses past Retention (daily), and lifts the
// automatic blocks while that is still owed.
func (r *Responder) maintain(ctx context.Context) {
	expired, lifted, why := r.maintainLocked(ctx)
	for _, x := range expired {
		r.emit(x, "", 0)
	}
	if lifted > 0 {
		r.audit(ctx, audit.Event{Actor: auditActor, Action: auditAction, Outcome: audit.OK, Level: audit.Security,
			Detail: fmt.Sprintf("action=lift_automatic state=applied count=%d why=%s", lifted, why)})
	}
}

// maintainLocked is maintain's part under mu: the recommendations it expired, and how many
// automatic blocks it lifted (-1: none owed, or it failed) and why.
func (r *Responder) maintainLocked(ctx context.Context) (expired []siem.Response, lifted int, why string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Before expire: an applied recommendation whose record is owed must not be expired as open.
	for id := range r.unsettled {
		if err := r.settleOwed(ctx, id); err != nil {
			r.logLimited("record", "security response: an applied response is still not recorded", "err", err)
			break
		}
	}
	expired, err := r.expire(ctx)
	if err != nil {
		r.logLimited("expire", "security response: recommendations not expired", "err", err)
	}
	if now := r.now(); now.Sub(r.lastPrune) >= pruneEvery || now.Before(r.lastPrune) {
		r.lastPrune = now
		r.prune(ctx)
	}
	lifted, why = -1, "mode_off"
	if r.liftPending && r.effective() == siem.ResponseModeOff {
		text := "automated response is off"
		if r.mode != siem.ResponseModeOff {
			text, why = "automated response paused", "paused"
		}
		lifted = r.liftAll(ctx, auditActor, text)
	}
	return expired, lifted, why
}

// liftAll lifts every automatic block in force (mu held); it returns how many, -1 when it failed
// (tried again at the next maintenance while liftPending).
func (r *Responder) liftAll(ctx context.Context, by, why string) int {
	if r.o.Blocks == nil {
		r.liftPending = false
		return 0
	}
	n, err := r.o.Blocks.LiftAutomatic(ctx, by, why)
	if err != nil {
		r.liftPending = true
		r.log.Error("security response: automatic blocks not lifted", "err", err)
		return -1
	}
	r.liftPending = false
	if n > 0 {
		r.log.Info("security response: automatic blocks lifted", "count", n, "why", why)
	}
	return n
}
