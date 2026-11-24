// Package pipeline is the security-log hub: sources hand it raw lines without ever blocking, one
// goroutine parses, normalizes, redacts and stores them in batches, and subscribers (detection,
// later phases) see every stored event.
package pipeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os/user"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/hostlog"
	"github.com/daboss2003/mooring/internal/siem/parse"
	"github.com/daboss2003/mooring/internal/siem/redact"
	"github.com/daboss2003/mooring/internal/siem/store"
)

// Options configures a Pipeline.
type Options struct {
	Store     *store.Store // nil: events reach the subscribers only
	Redactor  *redact.Redactor
	QueueSize int            // default 8192
	HostLoc   *time.Location // the host's time zone for syslog timestamps (default time.Local)
	// Subscribers are called on the pipeline's goroutine, once per event, right after the event's
	// batch was handed to the store (whether or not the store took it). They must be fast, since the
	// queue waits for them, and must not keep or modify an event's F map without copying it: the map
	// is shared with the other subscribers.
	Subscribers []func(siem.Event)
	Log         *slog.Logger
	Now         func() time.Time
	// Enricher, when set, is called on the pipeline's goroutine for every event converted from a
	// source line, after redaction and before the event is normalized and stored (enrich.Enricher's
	// Enrich: Geo). It must be fast. A panic in it is recovered and counted; the event is stored
	// without Geo. Events of source siem (the pipeline's own, and those given to Emit) are not
	// enriched.
	Enricher func(*siem.Event)
}

const (
	defaultQueueSize = 8192
	// auditLaneSize is the separate lane for Mooring's own audit events.
	auditLaneSize = 1024
	auditBurst    = 64       // audit events taken in a row before the other lanes get a turn
	maxEdgeLine   = 1 << 20  // bytes of one edge line; longer ones are dropped
	maxQueueBytes = 64 << 20 // bytes of line text held in the queue at once

	batchMax    = 512             // events per store append
	batchWait   = time.Second     // a partial batch is stored after this long
	flushEvery  = 2 * time.Second // the store is flushed at most this often, when something new was appended
	reportEvery = time.Minute     // drop counts are reported (and logged) at most this often
	drainBudget = 5 * time.Second // how long shutdown spends on what is still queued
	tickEvery   = 200 * time.Millisecond
	logEvery    = time.Minute // rate limit of the error logs
)

const (
	// emitLaneSize is the lane of the events Mooring's detection emits (Emit): taken after the audit
	// lane's burst and before the main lane, at most emitBurst in a row.
	emitLaneSize = 256
	emitBurst    = 16

	maxGeoLists    = 8  // names in an event's Geo.Lists (the enricher's own bound, checked again)
	maxGeoListName = 64 // bytes of one of them
)

// Source indexes (counters, item.src).
const (
	srcApp = iota
	srcEdge
	srcMooring
	srcHost
	numSrc
)

var srcNames = [numSrc]string{siem.SrcApp, siem.SrcEdge, siem.SrcMooring, siem.SrcHost}

// storeSource is the drop-report source for events the store didn't take; the report's reason is
// reasonDisk (refused at the disk-pressure threshold, not retried) or reasonError (failed twice).
const (
	storeSource = "store"
	reasonDisk  = "disk"
	reasonError = "error"
)

// cutSlack is how far past each bound (siem.MaxMsg, MaxFieldValue, MaxShort) a value is kept for
// redaction, so a secret or personal value straddling the bound is redacted whole before the final
// cut.
const cutSlack = 512

// cutSeparators end a token for slackCut.
const cutSeparators = " \t\r\n\"'`,;&|<>()[]{}"

// sink is what the pipeline needs of the store (*store.Store; faked in tests).
type sink interface {
	Append([]siem.Event) error
	Flush() error
}

// parsers are the per-source conversions (package parse; replaced in tests).
type parsers struct {
	app     func(at time.Time, app, svc, copy, text string) siem.Event
	edge    func(raw []byte, now time.Time) (siem.Event, bool)
	audit   func(ts time.Time, ev audit.Event) siem.Event
	auth    func(line string, now time.Time, loc *time.Location) (siem.Event, bool)
	f2b     func(line string, now time.Time, loc *time.Location) (siem.Event, bool)
	journal func(raw []byte) (siem.Event, bool)
}

// item is one raw input waiting in a lane.
type item struct {
	src            uint8
	size           int64     // bytes reserved against maxQueueBytes
	at             time.Time // the source time (app, audit), when read (host), or when taken (edge)
	app, svc, copy string
	text           string // app or host line
	hostSrc        string
	raw            []byte       // edge line (a copy)
	aud            *audit.Event // audit event
}

type counters struct {
	events  atomic.Int64
	dropped atomic.Int64
	last    atomic.Int64 // unix nanoseconds of the newest event
}

// Pipeline is the hub. Its input methods never block: when the queue is full the line is dropped
// and counted, and a siem.dropped event reports the count.
type Pipeline struct {
	st     sink              // nil: no store
	redact func(*siem.Event) // nil: Run stores nothing (fail closed)
	enrich func(*siem.Event) // nil: no enrichment
	parse  parsers
	subs   []func(siem.Event)
	now    func() time.Time
	log    *slog.Logger
	loc    *time.Location

	q        chan item       // app, edge and host lines
	aq       chan item       // Mooring audit events
	eq       chan siem.Event // events Mooring's detection emits (Emit)
	qBytes   atomic.Int64
	maxBytes int64
	tick     <-chan time.Time // nil: Run's own ticker (tests drive their own)
	drain    time.Duration    // drainBudget (tests lower it)

	lookupUID func(uid string) (name string, err error) // os/user.LookupId (replaced in tests)

	src      [numSrc]counters
	emitted  counters     // Emit's events (drop-report source "siem"; not in Sources)
	panics   atomic.Int64 // parser, redactor, enricher or subscriber panics
	lostDisk atomic.Int64 // events the store refused at the disk-pressure threshold
	lostErr  atomic.Int64 // events dropped after their store retry failed
	closing  atomic.Bool  // shutdown began: input (Emit too) is counted as dropped, not queued
	// inputsOff is set by DrainInputs and by shutdown: source input (AppLine, EdgeLine, HostLine,
	// Audit) is counted as dropped, not queued. Emit checks closing only.
	inputsOff    atomic.Bool
	inflight     atomic.Int64 // source inputs between their inputsOff check and the queue (the drains wait for them)
	emitInflight atomic.Int64 // Emit calls between their closing check and the lane (shutdown waits for them)

	drainReq chan drainRequest // DrainInputs → Run
	stopped  chan struct{}     // closed when Run returns
	stopOnce sync.Once

	enqueueHook func() // called by an input past its closing check (tests)
}

// drainRequest asks Run to handle the source lanes (DrainInputs); Run closes done when it has.
type drainRequest struct {
	deadline time.Time
	done     chan struct{}
}

// New builds a Pipeline.
func New(opt Options) *Pipeline {
	if opt.QueueSize <= 0 {
		opt.QueueSize = defaultQueueSize
	}
	if opt.HostLoc == nil {
		opt.HostLoc = time.Local
	}
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	p := &Pipeline{
		subs: opt.Subscribers, enrich: opt.Enricher, now: opt.Now, log: opt.Log, loc: opt.HostLoc,
		parse: parsers{
			app: parse.AppLine, edge: parse.EdgeAccess, audit: parse.Audit,
			auth: parse.AuthLog, f2b: parse.Fail2Ban, journal: parse.Journal,
		},
		q:  make(chan item, opt.QueueSize),
		aq: make(chan item, auditLaneSize),
		eq: make(chan siem.Event, emitLaneSize),
		// Intentional: a byte budget on top of the slot count. An edge line can be 1 MiB, so slots alone
		// would let a flood of large requests hold gigabytes in the queue.
		maxBytes:  maxQueueBytes,
		drain:     drainBudget,
		lookupUID: lookupUser,
		drainReq:  make(chan drainRequest),
		stopped:   make(chan struct{}),
	}
	if opt.Store != nil { // a nil *store.Store must not become a non-nil interface
		p.st = opt.Store
	}
	if opt.Redactor != nil {
		p.redact = opt.Redactor.Apply
	}
	return p
}

// AppLine takes one app container line (servicelog's capture: at = unix seconds).
func (p *Pipeline) AppLine(at int64, app, svc, copy, text string) {
	if p == nil {
		return
	}
	var ts time.Time
	if at > 0 {
		ts = time.Unix(at, 0)
	}
	p.enqueue(item{src: srcApp, at: ts, app: app, svc: svc, copy: copy, text: text,
		size: int64(len(app) + len(svc) + len(copy) + len(text))})
}

// EdgeLine takes one raw Caddy stdout line; it copies raw (the caller reuses its buffer).
func (p *Pipeline) EdgeLine(raw []byte) {
	if p == nil || len(raw) == 0 {
		return
	}
	if len(raw) > maxEdgeLine || len(p.q) == cap(p.q) || p.inputsOff.Load() { // the last two only save a useless copy
		p.src[srcEdge].dropped.Add(1)
		return
	}
	p.enqueue(item{src: srcEdge, at: p.now(), raw: bytes.Clone(raw), size: int64(len(raw))})
}

// Audit takes one Mooring audit event recorded at ts.
func (p *Pipeline) Audit(ts time.Time, ev audit.Event) {
	if p == nil {
		return
	}
	p.inflight.Add(1)
	defer p.inflight.Add(-1)
	if p.inputsOff.Load() {
		p.src[srcMooring].dropped.Add(1)
		return
	}
	if p.enqueueHook != nil {
		p.enqueueHook()
	}
	// Intentional: audit events have their own lane (drained first), so an app log flood that fills
	// the main queue can't drop Mooring's security events. They are rare and small: no byte budget.
	select {
	case p.aq <- item{src: srcMooring, at: ts, aud: &ev}:
	default:
		p.src[srcMooring].dropped.Add(1)
	}
}

// Emit queues an event Mooring's own detection produced (a siem.detection, say) without blocking:
// false when e.Src isn't siem.SrcSIEM or e.Kind is siem.KindDropped (the pipeline's own report),
// when shutdown began, or when the emitted lane is full (then counted as dropped, source "siem").
// It still works after DrainInputs, until Run's context ends.
// The event is not parsed, redacted or enriched: it is normalized, stored and handed to the
// subscribers like any other. The pipeline takes e over: the caller must not use its F map or Geo
// afterwards.
func (p *Pipeline) Emit(e siem.Event) bool {
	if p == nil || e.Src != siem.SrcSIEM || e.Kind == siem.KindDropped {
		return false
	}
	p.emitInflight.Add(1)
	defer p.emitInflight.Add(-1)
	if p.closing.Load() {
		p.emitted.dropped.Add(1)
		return false
	}
	if p.enqueueHook != nil {
		p.enqueueHook()
	}
	select {
	case p.eq <- e:
		return true
	default:
		p.emitted.dropped.Add(1)
		return false
	}
}

// HostLine takes one host log line.
func (p *Pipeline) HostLine(l hostlog.Line) {
	if p == nil {
		return
	}
	p.enqueue(item{src: srcHost, at: l.At, hostSrc: l.Source, text: l.Text, size: int64(len(l.Source) + len(l.Text))})
}

// enqueue puts it in the main lane without blocking; a full lane or byte budget drops it.
func (p *Pipeline) enqueue(it item) {
	p.inflight.Add(1)
	defer p.inflight.Add(-1)
	if p.inputsOff.Load() {
		p.src[it.src].dropped.Add(1)
		return
	}
	if p.enqueueHook != nil {
		p.enqueueHook()
	}
	if p.qBytes.Add(it.size) > p.maxBytes {
		p.qBytes.Add(-it.size)
		p.src[it.src].dropped.Add(1)
		return
	}
	select {
	case p.q <- it:
	default:
		p.qBytes.Add(-it.size)
		p.src[it.src].dropped.Add(1)
	}
}

// DrainInputs is the first step of a two-phase stop, for when a subscriber (detection) stops before
// the pipeline: from now on source input (AppLine, EdgeLine, HostLine, Audit) is refused and counted
// as dropped, and everything already queued in the main and audit lanes, with the batch Run holds,
// is handed to the store and the subscribers before it returns. Emit keeps working until Run's
// context ends, so what the subscriber emits as it stops is still stored. The drain is bounded like
// shutdown's: what was queued when it began, for at most drainBudget (or until ctx's deadline, when
// earlier); what is still queued then is counted as dropped. It returns ctx's error when ctx ends
// before Run has done it (Run not started, say), and nil when Run has already returned (its shutdown
// handled everything).
func (p *Pipeline) DrainInputs(ctx context.Context) error {
	if p == nil {
		return nil
	}
	// Intentional: wall-clock time, as in shutdown (Options.Now may be a test clock).
	deadline := time.Now().Add(p.drain)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	// From here on source input is dropped. An input already past its check is waited for, so
	// nothing can reach the source lanes once Run takes the request.
	p.inputsOff.Store(true)
	for p.inflight.Load() > 0 && time.Now().Before(deadline) && ctx.Err() == nil {
		time.Sleep(50 * time.Microsecond)
	}
	req := drainRequest{deadline: deadline, done: make(chan struct{})}
	select {
	case p.drainReq <- req:
	case <-p.stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-req.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Run drains the queue until ctx ends, then flushes the store.
func (p *Pipeline) Run(ctx context.Context) {
	defer p.stopOnce.Do(func() { close(p.stopped) })
	if p.redact == nil {
		// Fail closed: never store events that weren't redacted.
		p.log.Error("security logs: no redactor configured; nothing is collected")
		for {
			select {
			case req := <-p.drainReq:
				close(req.done) // nothing is ever processed
			case <-ctx.Done():
				return
			}
		}
	}
	tick := p.tick
	if tick == nil {
		t := time.NewTicker(tickEvery)
		defer t.Stop()
		tick = t.C
	}
	now := p.now()
	r := &runner{p: p, lastFlush: now, lastReport: now, reported: map[string]int64{}, logged: map[string]int64{}}
	burst, ebursts := 0, 0
	for {
		// The audit lane is taken first, but at most auditBurst in a row, so a flood of audit events
		// (a login brute force) can't starve the other lanes or the timers. The emitted lane comes
		// next, at most emitBurst in a row, then every lane and the timers get a turn.
		if burst < auditBurst {
			select {
			case it := <-p.aq:
				r.take(it)
				burst++
				continue
			default:
			}
		}
		if ebursts < emitBurst {
			select {
			case ev := <-p.eq:
				r.takeEmitted(ev)
				ebursts++
				continue
			default:
			}
		}
		burst, ebursts = 0, 0
		select {
		case it := <-p.aq:
			r.take(it)
		case ev := <-p.eq:
			r.takeEmitted(ev)
		case it := <-p.q:
			r.take(it)
		case <-tick:
			r.tick(p.now())
		case req := <-p.drainReq:
			r.drainInputs(req.deadline)
			close(req.done)
		case <-ctx.Done():
			r.shutdown()
			return
		}
	}
}

// drainInputs handles DrainInputs on Run's goroutine: the audit and main lanes as they are now (no
// source input can join them any more), for at most until deadline, then everything taken is
// committed, so the subscribers have seen it. The emitted lane is left to Run.
func (r *runner) drainInputs(deadline time.Time) {
	p := r.p
	n := len(p.aq) + len(p.q)
drain:
	for i := 0; i < n && time.Now().Before(deadline); i++ {
		select {
		case it := <-p.aq:
			r.take(it)
		default:
			select {
			case it := <-p.q:
				r.take(it)
			default:
				break drain
			}
		}
	}
	// Intentional: what the budget left is counted as dropped now rather than left for shutdown, so
	// the source lanes cost one drain budget in all, and shutdown has only the emitted lane left.
	for left := true; left; {
		select {
		case it := <-p.aq:
			p.src[it.src].dropped.Add(1)
		case it := <-p.q:
			p.qBytes.Add(-it.size)
			p.src[it.src].dropped.Add(1)
		default:
			left = false
		}
	}
	r.commit(p.now())
}

// runner is Run's state, used only on its goroutine.
type runner struct {
	p           *Pipeline
	batch       []siem.Event
	batchStart  time.Time
	retry       []siem.Event // what a failed append didn't store, tried once more
	retryAt     time.Time
	dirty       bool // appended since the last flush
	lastFlush   time.Time
	lastReport  time.Time
	reported    map[string]int64      // drop counts already in a siem.dropped event, by dropKey
	logged      map[string]int64      // drop counts already logged, by dropKey
	diskBlocked bool                  // the last append was refused at the disk-pressure threshold
	senders     map[string]senderName // journal sender uid → user name, for checkSender

	storeLog, panicLog rateLog
}

func (r *runner) take(it item) {
	r.p.qBytes.Add(-it.size)
	now := r.p.now()
	if ev, ok := r.convert(&it, now); ok {
		c := &r.p.src[it.src]
		c.events.Add(1)
		c.last.Store(now.UnixNano())
		r.add(ev, now)
	}
}

// takeEmitted stores one event given to Emit: normalized, never parsed, redacted or enriched.
func (r *runner) takeEmitted(ev siem.Event) {
	now := r.p.now()
	boundGeo(&ev)
	ev.Normalize(now)
	r.p.emitted.events.Add(1)
	r.p.emitted.last.Store(now.UnixNano())
	r.add(ev, now)
}

// convert parses, normalizes, redacts and enriches one item. ok is false for a line its parser
// doesn't take, an unknown host source, or a parser or redactor panic.
func (r *runner) convert(it *item, now time.Time) (ev siem.Event, ok bool) {
	p := r.p
	// Intentional: a panic in a parser or the redactor (all input is hostile; it shouldn't happen)
	// loses only this item. It is counted as dropped and logged, and the event is never stored
	// half-redacted.
	defer func() {
		if v := recover(); v != nil {
			ev, ok = siem.Event{}, false
			p.panics.Add(1)
			p.src[it.src].dropped.Add(1)
			if r.panicLog.allow(now) {
				p.log.Error("security logs: an event could not be processed and was dropped",
					"source", srcNames[it.src], "err", panicText(v), "suppressed", r.panicLog.take())
			}
		}
	}()
	ref := it.at
	if ref.IsZero() {
		ref = now
	}
	switch it.src {
	case srcApp:
		ev, ok = p.parse.app(ref, it.app, it.svc, it.copy, it.text), true
	case srcEdge:
		ev, ok = p.parse.edge(it.raw, ref)
	case srcMooring:
		ev, ok = p.parse.audit(ref, *it.aud), true
	case srcHost:
		switch it.hostSrc {
		case hostlog.SourceAuth:
			ev, ok = p.parse.auth(it.text, ref, p.loc)
		case hostlog.SourceFail2Ban:
			ev, ok = p.parse.f2b(it.text, ref, p.loc)
		case hostlog.SourceJournal:
			ev, ok = p.parse.journal([]byte(it.text))
		default:
			p.src[srcHost].dropped.Add(1)
		}
	}
	if !ok {
		return siem.Event{}, false
	}
	if it.src == srcHost && it.hostSrc == hostlog.SourceJournal {
		r.checkSender(&ev, now) // before redaction: it compares the user names as written
	}
	// Intentional: cut with slack before redaction and to the bounds only after it. Cutting at the
	// bounds first would leave a readable prefix of an email or token straddling a bound, which the
	// redactor can no longer recognize.
	preCut(&ev)
	p.redact(&ev)
	if p.enrich != nil && ev.Src != siem.SrcSIEM {
		r.enrichEvent(&ev, now)
	}
	boundGeo(&ev)
	ev.Normalize(ref)
	return ev, true
}

// enrichEvent runs the enricher on ev. Intentional: a panic in it is recovered here, not by
// convert, so the event (already redacted) is still stored, only without Geo.
func (r *runner) enrichEvent(ev *siem.Event, now time.Time) {
	defer func() {
		if v := recover(); v != nil {
			ev.Geo = nil
			r.p.panics.Add(1)
			if r.panicLog.allow(now) {
				r.p.log.Error("security logs: enrichment failed; the event is stored without it",
					"err", panicText(v), "suppressed", r.panicLog.take())
			}
		}
	}()
	r.p.enrich(ev)
}

// boundGeo bounds e.Geo, which Normalize doesn't: strings cut, at most maxGeoLists lists, and a
// coordinate that isn't a finite number zeroed (JSON can't encode it, so the event's batch would
// fail to store). It works on a copy: the Geo may be shared with its producer.
func boundGeo(e *siem.Event) {
	g := e.Geo
	if g == nil {
		return
	}
	c := *g
	if math.IsNaN(c.Lat) || math.IsInf(c.Lat, 0) || math.IsNaN(c.Lon) || math.IsInf(c.Lon, 0) {
		c.Lat, c.Lon = 0, 0
	}
	c.Country, c.City, c.Org = siem.Cut(c.Country, siem.MaxShort), siem.Cut(c.City, siem.MaxShort), siem.Cut(c.Org, siem.MaxShort)
	if len(c.Lists) > 0 {
		c.Lists = make([]string, 0, min(len(g.Lists), maxGeoLists))
		for _, l := range g.Lists[:min(len(g.Lists), maxGeoLists)] {
			c.Lists = append(c.Lists, siem.Cut(l, maxGeoListName))
		}
	}
	e.Geo = &c
}

// preCut bounds an event for the redactor: each string at its bound plus cutSlack (see slackCut),
// F values of other types than string, float64 and bool removed, and at most twice MaxFields fields.
func preCut(e *siem.Event) {
	e.Msg = slackCut(e.Msg, siem.MaxMsg)
	e.App, e.Svc, e.Copy = slackCut(e.App, siem.MaxShort), slackCut(e.Svc, siem.MaxShort), slackCut(e.Copy, siem.MaxShort)
	e.Kind, e.Actor, e.IP = slackCut(e.Kind, siem.MaxShort), slackCut(e.Actor, siem.MaxShort), slackCut(e.IP, siem.MaxShort)
	n := 0
	for k, v := range e.F {
		switch tv := v.(type) {
		case string:
			e.F[k] = slackCut(tv, siem.MaxFieldValue)
		case float64, bool:
		default:
			delete(e.F, k)
			continue
		}
		if len(k) > siem.MaxFieldKey || n >= 2*siem.MaxFields {
			delete(e.F, k)
			continue
		}
		n++
	}
}

// slackCut cuts s to bound+cutSlack bytes. When it has to cut, it also drops the token the cut went
// through, back to the separator before it: the redactor can't recognize a token it sees only part
// of, and a redaction that shortens s earlier could pull that fragment under the bound, where the
// final cut would keep it. A token running across the whole slack began before the bound and is
// longer than the slack (a long JWT), so it is dropped back to its start, or the value is dropped
// whole when it is that one token.
func slackCut(s string, bound int) string {
	if len(s) <= bound+cutSlack {
		return s
	}
	s = siem.Cut(s, bound+cutSlack)
	if i := strings.LastIndexAny(s[bound:], cutSeparators); i >= 0 {
		return s[:bound+i]
	}
	if i := strings.LastIndexAny(s[:bound], cutSeparators); i >= 0 {
		return s[:i]
	}
	return ""
}

// The sender name cache of checkSender.
const (
	sendersMax = 256
	sendersTTL = 10 * time.Minute
)

type senderName struct {
	name string
	at   time.Time
}

// checkSender flags (F sender_mismatch) a journal sudo.command, su.session or passwd
// host.user_change event that its sender (journald's uid, F sender_uid) can't have written, unless
// the sender is root. parse.Journal takes these from any uid, because journald records them under
// the user who ran them, so a line another user wrote with `logger -t sudo …` is recognisable only
// this way. The event is kept either way.
//
//   - A line that names its user must name the sender's user.
//   - A line that names no user must still state the invoking uid (PAM's "uid=N", su's
//     "by (uid=N)"), and every uid it states must be the sender's. A sudo or su line that states
//     none claims a root action nobody can be held to, so it is flagged; every real one (a PAM
//     failure, an su session) carries the uid. A passwd line naming no user (a failed change) claims
//     no root action and isn't flagged.
func (r *runner) checkSender(e *siem.Event, now time.Time) {
	uid, _ := e.F["sender_uid"].(string)
	if uid == "" || uid == "0" {
		return
	}
	switch {
	case e.Kind == siem.KindSudo, e.Kind == siem.KindSu:
	case e.Kind == siem.KindUserChange && e.F["program"] == "passwd":
	default:
		return
	}
	claimed, _ := e.F["user"].(string)
	if claimed == "" {
		claimed = e.Actor
	}
	if claimed != "" {
		// Intentional: a uid with no user name in /etc/passwd isn't flagged (owner decision): users
		// known only to LDAP/SSSD would otherwise be flagged on every sudo of their own. sender_uid is
		// kept.
		if name := r.senderName(uid, now); name != "" && name != claimed {
			e.F["sender_mismatch"] = true
		}
		return
	}
	stated := lineUIDs.FindAllStringSubmatch(e.Msg, maxLineUIDs+1)
	for _, m := range stated {
		if m[1]+m[2] != uid {
			e.F["sender_mismatch"] = true
			return
		}
	}
	if len(stated) > maxLineUIDs || len(stated) == 0 && e.Kind != siem.KindUserChange {
		e.F["sender_mismatch"] = true
	}
}

// lineUIDs finds the invoking uid a sudo/su line states: su's "by name(uid=N)" (the name may be
// empty) and PAM's "uid=N" field (not euid=, not the target's "root(uid=0)").
var lineUIDs = regexp.MustCompile(`\bby [^\s()]*\(uid=(\d{1,10})\)|(?:^|[\s;])uid=(\d{1,10})\b`)

// maxLineUIDs bounds the uids read from one line; a line stating more is flagged.
const maxLineUIDs = 8

// senderName is uid's user name, "" when it has none, cached for sendersTTL.
func (r *runner) senderName(uid string, now time.Time) string {
	if c, ok := r.senders[uid]; ok && now.Sub(c.at) < sendersTTL {
		return c.name
	}
	name, err := r.p.lookupUID(uid)
	if err != nil {
		name = ""
	}
	if r.senders == nil || len(r.senders) >= sendersMax {
		// Intentional: a full cache is emptied, not evicted entry by entry. Only a few uids send
		// these lines (journald sets the uid, so a forger has only their own), so it never fills
		// in practice, and emptying keeps it bounded without bookkeeping.
		r.senders = make(map[string]senderName, sendersMax)
	}
	r.senders[uid] = senderName{name: name, at: now}
	return name
}

// lookupUser is uid's user name from the host's user database (/etc/passwd: Mooring is built
// without cgo).
func lookupUser(uid string) (string, error) {
	u, err := user.LookupId(uid)
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

func (r *runner) add(ev siem.Event, now time.Time) {
	if len(r.batch) == 0 {
		r.batchStart = now
	}
	r.batch = append(r.batch, ev)
	if len(r.batch) >= batchMax {
		r.commit(now)
	}
}

func (r *runner) tick(now time.Time) {
	if now.Sub(r.lastReport) >= reportEvery {
		r.reportDrops(now)
		r.lastReport = now
	}
	if (len(r.batch) > 0 && now.Sub(r.batchStart) >= batchWait) || (len(r.retry) > 0 && now.Sub(r.retryAt) >= batchWait) {
		r.commit(now)
	}
	if r.dirty && now.Sub(r.lastFlush) >= flushEvery {
		r.flush(now)
	}
}

// commit stores the batch waiting for its retry, then the current batch, and hands the current
// batch to the subscribers.
func (r *runner) commit(now time.Time) {
	p := r.p
	if len(r.retry) > 0 {
		retry := r.retry
		r.retry = nil
		if rest, disk, err := r.append(retry); len(rest) > 0 {
			reason, msg := reasonError, "security logs: the store failed twice; events dropped"
			if disk {
				reason, msg = reasonDisk, "security logs: the disk is at the pressure threshold; events not stored"
			}
			r.lose(rest, reason)
			r.storeErr(now, msg, err, len(rest))
		}
	}
	if len(r.batch) == 0 {
		return
	}
	// Intentional: a fresh slice per batch, so neither the store nor a retry ever sees it reused.
	b := r.batch
	r.batch = nil
	if p.st != nil {
		if rest, disk, err := r.append(b); len(rest) > 0 {
			if disk {
				// Intentional: no retry at the disk-pressure threshold; the store would refuse it again.
				r.lose(rest, reasonDisk)
				r.storeErr(now, "security logs: the disk is at the pressure threshold; events not stored", err, len(rest))
			} else {
				r.retry, r.retryAt = rest, now
				r.storeErr(now, "security logs: the store failed; retrying once", err, len(rest))
			}
		}
	}
	// Intentional: subscribers see a batch even when its append failed, so detection isn't blinded
	// by a full or broken disk. Each event reaches them once (never again on the retry).
	for _, sub := range p.subs {
		for i := range b {
			r.deliver(sub, b[i], now)
		}
	}
}

// append stores evs and returns the events the store didn't take (after a partial write, only those
// past AppendError.Written), and whether it refused them at the disk-pressure threshold.
func (r *runner) append(evs []siem.Event) (rest []siem.Event, disk bool, err error) {
	if err = r.p.st.Append(evs); err == nil {
		r.dirty, r.diskBlocked = true, false
		return nil, false, nil
	}
	written := 0
	var ae *store.AppendError
	if errors.As(err, &ae) {
		written = min(max(ae.Written, 0), len(evs))
	}
	if written > 0 {
		r.dirty = true
	}
	disk = errors.Is(err, store.ErrDiskPressure)
	if disk {
		r.diskBlocked = true
	}
	return evs[written:], disk, err
}

// lose counts events the store didn't take. A drop report among them is taken back instead, so its
// counts are reported again once the store takes events.
func (r *runner) lose(evs []siem.Event, reason string) {
	n := int64(0)
	for _, e := range evs {
		if e.Src == siem.SrcSIEM && e.Kind == siem.KindDropped {
			if c, ok := e.F["count"].(float64); ok {
				r.reported[dropKey(e.F["source"], e.F["reason"])] -= int64(c)
			}
			continue
		}
		n++
	}
	if reason == reasonDisk {
		r.p.lostDisk.Add(n)
	} else {
		r.p.lostErr.Add(n)
	}
}

func dropKey(source, reason any) string {
	s, _ := source.(string)
	if r, _ := reason.(string); r != "" {
		return s + "/" + r
	}
	return s
}

func (r *runner) deliver(sub func(siem.Event), ev siem.Event, now time.Time) {
	defer func() {
		if v := recover(); v != nil { // Intentional: a subscriber bug must not stop collection
			r.p.panics.Add(1)
			if r.panicLog.allow(now) {
				r.p.log.Error("security logs: a subscriber failed", "err", panicText(v), "suppressed", r.panicLog.take())
			}
		}
	}()
	sub(ev)
}

func (r *runner) flush(now time.Time) {
	r.lastFlush = now
	if r.p.st == nil {
		r.dirty = false
		return
	}
	if err := r.p.st.Flush(); err != nil {
		r.storeErr(now, "security logs: the store failed to flush", err, 0)
		return // still dirty: tried again after flushEvery
	}
	r.dirty = false
}

func (r *runner) storeErr(now time.Time, msg string, err error, events int) {
	if r.storeLog.allow(now) {
		r.p.log.Error(msg, "err", err, "events", events, "suppressed", r.storeLog.take())
	}
}

// dropCount is one drop counter (cumulative since start).
type dropCount struct {
	source, reason string
	n              int64
}

// dropTotals is every drop counter: one per source, the emitted lane's ("siem"), then the store's
// by reason.
func (p *Pipeline) dropTotals() []dropCount {
	out := make([]dropCount, 0, numSrc+3)
	for i := range p.src {
		out = append(out, dropCount{source: srcNames[i], n: p.src[i].dropped.Load()})
	}
	return append(out,
		dropCount{source: siem.SrcSIEM, n: p.emitted.dropped.Load()},
		dropCount{source: storeSource, reason: reasonDisk, n: p.lostDisk.Load()},
		dropCount{source: storeSource, reason: reasonError, n: p.lostErr.Load()})
}

// reportDrops logs one warning listing the drops since the last one and adds one siem.dropped event
// per source (and store reason) with drops not reported yet. While the store refuses events at the
// disk-pressure threshold the events wait: they would only be refused too.
func (r *runner) reportDrops(now time.Time) {
	var attrs []any
	for _, t := range r.p.dropTotals() {
		k := dropKey(t.source, t.reason)
		if n := t.n - r.logged[k]; n > 0 {
			r.logged[k] = t.n
			attrs = append(attrs, strings.ReplaceAll(k, "/", "_"), n)
		}
		if r.diskBlocked {
			continue
		}
		if n := t.n - r.reported[k]; n > 0 {
			r.reported[k] = t.n
			r.add(dropEvent(t.source, t.reason, n, now), now)
		}
	}
	if len(attrs) > 0 {
		r.p.log.Warn("security logs: events dropped since the last report", attrs...)
	}
}

func dropEvent(source, reason string, n int64, now time.Time) siem.Event {
	ev := siem.Event{
		TS: now, Src: siem.SrcSIEM, Lvl: siem.LvlWarn, Kind: siem.KindDropped,
		F:   map[string]any{"source": source, "count": float64(n)},
		Msg: fmt.Sprintf("%d %s event(s) dropped", n, source),
	}
	if reason != "" {
		ev.F["reason"] = reason
		ev.Msg += " (" + reason + ")"
	}
	ev.Normalize(now)
	return ev
}

// shutdown handles what is queued (bounded: what was there when it began, for at most
// drainBudget), reports pending drops, stores everything and flushes.
func (r *runner) shutdown() {
	p := r.p
	// Intentional: the drain deadline is wall-clock time, not Options.Now (which may be a test clock
	// that never moves); and it handles only what was queued when it began, so producers that keep
	// going can't hold shutdown.
	deadline := time.Now().Add(p.drain)
	// From here on input is counted as dropped instead of queued. An input already past that check
	// is waited for, so nothing can be queued after the leftover count below.
	p.inputsOff.Store(true)
	p.closing.Store(true)
	for p.inflight.Load()+p.emitInflight.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Microsecond)
	}
	n := len(p.aq) + len(p.eq) + len(p.q)
drain:
	for i := 0; i < n && time.Now().Before(deadline); i++ {
		select {
		case it := <-p.aq:
			r.take(it)
		default:
			select {
			case ev := <-p.eq:
				r.takeEmitted(ev)
			default:
				select {
				case it := <-p.q:
					r.take(it)
				default:
					break drain
				}
			}
		}
	}
	// What is still queued (past the snapshot or the time budget) is counted, not processed.
	for left := true; left; {
		select {
		case it := <-p.aq:
			p.src[it.src].dropped.Add(1)
		case <-p.eq:
			p.emitted.dropped.Add(1)
		case it := <-p.q:
			p.qBytes.Add(-it.size)
			p.src[it.src].dropped.Add(1)
		default:
			left = false
		}
	}
	now := p.now()
	r.reportDrops(now)
	r.commit(now)
	if len(r.retry) > 0 {
		r.commit(now) // its one retry
	}
	if p.st != nil {
		if err := p.st.Flush(); err != nil {
			p.log.Error("security logs: the store failed to flush at shutdown", "err", err)
		}
	}
	// One line with every count, final store losses included. Input after this is still counted
	// (Sources) but can't be logged.
	var events int64
	for i := range p.src {
		events += p.src[i].events.Load()
	}
	attrs := []any{"events", events}
	lost := false
	for _, t := range p.dropTotals() {
		k := strings.ReplaceAll(dropKey(t.source, t.reason), "/", "_")
		if t.source == storeSource {
			k = "lost_" + k
		} else {
			k = "dropped_" + k
		}
		attrs = append(attrs, k, t.n)
		lost = lost || t.n > 0
	}
	if lost {
		p.log.Warn("security logs: stopped", attrs...)
	} else {
		p.log.Info("security logs: stopped", attrs...)
	}
}

// rateLog lets one log line through per logEvery and counts the ones it holds back.
type rateLog struct {
	last       time.Time
	suppressed int
}

func (l *rateLog) allow(now time.Time) bool {
	if !l.last.IsZero() && now.Sub(l.last) < logEvery && now.After(l.last) {
		l.suppressed++
		return false
	}
	l.last = now
	return true
}

// take returns and resets the count of lines held back.
func (l *rateLog) take() int {
	n := l.suppressed
	l.suppressed = 0
	return n
}

// panicText describes a recovered panic without its value unless it is a runtime error: a parser's
// own panic message could quote the hostile line.
func panicText(v any) string {
	if err, ok := v.(runtime.Error); ok {
		return err.Error()
	}
	return fmt.Sprintf("panic (%T)", v)
}

// Sources reports the per-source counters ("app", "edge", "mooring", "host"; the host log files' own
// status comes from the hostlog follower) and Queue the current and maximum queue length (both
// lanes).
func (p *Pipeline) Sources() []siem.SourceStatus {
	if p == nil {
		return nil
	}
	out := make([]siem.SourceStatus, numSrc)
	for i := range p.src {
		c := &p.src[i]
		out[i] = siem.SourceStatus{Name: srcNames[i], OK: true, Events: c.events.Load(), Dropped: c.dropped.Load()}
		if l := c.last.Load(); l > 0 {
			out[i].LastSeen = time.Unix(0, l).UTC()
		}
	}
	return out
}

func (p *Pipeline) Queue() (n, capacity int) {
	if p == nil {
		return 0, 0
	}
	return len(p.q) + len(p.aq), cap(p.q) + cap(p.aq)
}
