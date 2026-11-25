package blocklist

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
)

const (
	sweepEvery   = time.Minute // expiry sweep and the protected-set re-check
	applyEvery   = time.Minute // the edge takes the list at most this often (every /load drops WebSockets)
	applyTimeout = 15 * time.Second
	selfEvery    = 5 * time.Minute // this server's own addresses re-read
	pruneEvery   = time.Hour
	// applyAlertAfter failed applies in a row raise the security_blocking alert.
	applyAlertAfter = 3
)

// pubSet is one version of the list the edge serves; never modified once built.
type pubSet struct {
	ver   uint64
	list  []netip.Prefix // sorted
	v4    []netip.Prefix // list's IPv4 entries, Options.L4 only
	host  map[netip.Addr]struct{}
	net64 map[netip.Prefix]struct{}
	wide  []netip.Prefix // the other manual ranges
}

func newPubSet(ver uint64, list []netip.Prefix, l4 bool) *pubSet {
	s := &pubSet{ver: ver, list: list, host: map[netip.Addr]struct{}{}, net64: map[netip.Prefix]struct{}{}}
	for _, p := range list {
		switch {
		case p.IsSingleIP():
			s.host[p.Addr()] = struct{}{}
		case p.Addr().Is6() && p.Bits() == 64:
			s.net64[p] = struct{}{}
		default:
			s.wide = append(s.wide, p)
		}
		if l4 && p.Addr().Is4() {
			s.v4 = append(s.v4, p)
		}
	}
	if l4 && s.v4 == nil {
		s.v4 = []netip.Prefix{}
	}
	return s
}

func (s *pubSet) has(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	if _, ok := s.host[a]; ok {
		return true
	}
	if a.Is6() {
		if _, ok := s.net64[netip.PrefixFrom(a, 64).Masked()]; ok {
			return true
		}
	}
	for _, p := range s.wide {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func comparePrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

// Snapshot is the list the edge renders: every active, unsuspended block, sorted. Lock-free. The
// slice is shared: callers must not modify it. It changes at most once a minute (Run releases the
// current list with each apply), so the edge's periodic reconcile doesn't /load every change.
func (b *Blocker) Snapshot() []netip.Prefix {
	if s := b.pub.Load(); s != nil {
		return s.list
	}
	return nil
}

// L4Snapshot is Snapshot's IPv4 entries when Options.L4 is set; nil otherwise. Lock-free; shared
// like Snapshot.
func (b *Blocker) L4Snapshot() []netip.Prefix {
	if s := b.pub.Load(); s != nil && b.o.L4 {
		return s.v4
	}
	return nil
}

// Blocked reports whether a is covered by a block the edge serves (Snapshot), in memory, lock-free.
func (b *Blocker) Blocked(a netip.Addr) bool {
	if s := b.pub.Load(); s != nil && a.IsValid() {
		return s.has(a)
	}
	return false
}

// Covering is the active block, other than p's own, whose prefix overlaps p: one that contains p or
// one inside it, the widest of them (so a block containing p before any inside it; of equally wide
// ones the lowest). A suspended block and one whose time ran out cover nothing. In memory, no I/O:
// it reads every block in force, where List returns the newest 1000. Unlike Blocked it reads the
// current list, which the edge serves within about a minute.
func (b *Blocker) Covering(p netip.Prefix) (Block, bool) {
	p = canon(p)
	if !p.IsValid() {
		return Block{}, false
	}
	now := b.now()
	var best Block
	found := false
	b.mu.Lock()
	defer b.mu.Unlock()
	for q, blk := range b.inForce {
		if q == p || blk.State != StateActive || !blk.Until.After(now) || !q.Overlaps(p) {
			continue
		}
		if !found || q.Bits() < best.Prefix.Bits() || (q.Bits() == best.Prefix.Bits() && comparePrefix(q, best.Prefix) < 0) {
			best, found = blk, true
		}
	}
	return best, found
}

// rebuildLocked re-checks every block in force against prot — one now covered by a protected
// address is suspended, one no longer covered resumes — and builds the next live list when it
// changed. It returns the suspended/resumed events. Called under mu.
func (b *Blocker) rebuildLocked(prot protSet, now time.Time) []siem.Event {
	var evs []siem.Event
	list := make([]netip.Prefix, 0, len(b.inForce))
	for p, blk := range b.inForce {
		code, _ := prot.covered(p, netip.Addr{})
		if code == "" && !b.ready && blk.State == StateSuspended {
			// Intentional: before Run's first step the guard isn't complete (no API token CIDRs, no
			// sessions: the dashboard doesn't exist yet), so a suspended block is not resumed on its
			// word.
			code = blk.SuspendedWhy
		}
		state := StateActive
		if code != "" {
			state = StateSuspended
		}
		if blk.State != state || blk.SuspendedWhy != code {
			action := "resumed"
			if state == StateSuspended {
				action = "suspended"
			}
			if blk.State != state {
				evs = append(evs, b.blockEvent(now, action, blk, map[string]any{"why": code}))
			}
			blk.State, blk.SuspendedWhy = state, code
			b.inForce[p] = blk
			if b.unsaved == nil {
				b.unsaved = map[netip.Prefix]struct{}{}
			}
			b.unsaved[p] = struct{}{}
		}
		if state == StateActive {
			list = append(list, p)
		}
	}
	slices.SortFunc(list, comparePrefix)
	if b.live == nil || !slices.Equal(list, b.live.list) {
		b.ver++
		b.live = newPubSet(b.ver, list, b.o.L4)
	}
	return evs
}

// saveSuspended writes the suspended states that changed in memory to the database, so a restart
// doesn't serve a suspended block; one that can't be written is tried again with the next change or
// sweep. Called under wmu (or from Open), never under mu.
func (b *Blocker) saveSuspended(ctx context.Context) {
	b.mu.Lock()
	todo := make(map[netip.Prefix]string, len(b.unsaved))
	for p := range b.unsaved {
		if blk, ok := b.inForce[p]; ok {
			todo[p] = blk.SuspendedWhy
		}
	}
	b.unsaved = nil
	b.mu.Unlock()
	for p, why := range todo {
		if err := b.putSuspended(ctx, p, why); err != nil {
			b.log.Warn("blocklist: could not save a block's suspended state; retrying", "prefix", p.String(), "err", err)
			b.mu.Lock()
			if b.unsaved == nil {
				b.unsaved = map[netip.Prefix]struct{}{}
			}
			b.unsaved[p] = struct{}{}
			b.mu.Unlock()
		}
	}
}

// resync reads the blocks in force from the database again when the clock is before the last sweep:
// it stepped back, and a block that sweep dropped from memory as expired may be in force again (its
// row says so), which the page, the edge and Unblock must agree on. Called under wmu.
func (b *Blocker) resync(ctx context.Context, now time.Time) {
	wall := now.Round(0) // Intentional: the wall clock; a monotonic reading never goes back
	b.mu.Lock()
	back := wall.Before(b.sweptTo)
	b.mu.Unlock()
	if !back {
		return
	}
	in, err := b.loadInForce(ctx, now)
	if err != nil {
		b.log.Warn("blocklist: the clock stepped back and the blocks in force couldn't be read again; retrying", "err", err)
		return
	}
	prot := b.protected(ctx)
	b.mu.Lock()
	b.inForce, b.sweptTo = in, wall
	evs := b.rebuildLocked(prot, now)
	b.mu.Unlock()
	b.saveSuspended(ctx)
	b.log.Warn("blocklist: the clock stepped back; the blocks in force were read from the database again", "count", len(in))
	b.emit(evs...)
	b.signal()
}

// SetApply sets the function that makes the edge (and L4) take the current snapshot.
func (b *Blocker) SetApply(fn func(ctx context.Context) error) {
	b.mu.Lock()
	b.apply = fn
	b.mu.Unlock()
}

// applyState is the edge's view of the list.
type applyState struct {
	ver      uint64    // live version the last successful apply released
	ok       bool      // the last apply worked
	err      string    // the last apply's error
	at       time.Time // the last successful apply
	attempt  time.Time // the last release
	failures int       // failed applies in a row
	alerted  bool      // the security_blocking apply alert is firing (raised in this run, or open before the restart)
	// owed: what was open before the restart isn't known, so the first apply that works sends a
	// "resolved" once.
	owed bool
}

// schedule holds when Run's periodic work is next due.
type schedule struct {
	sweep, self, prune time.Time
}

// due reports whether t has come, or the clock stepped back past one period before it.
func due(now, t time.Time, every time.Duration) bool {
	return !now.Before(t) || t.Sub(now) > every
}

// applyDueLocked reports whether the list should be released to the edge now: it changed since the
// last successful apply (or that apply failed), and the last release is a minute old. Called under mu.
func (b *Blocker) applyDueLocked(now time.Time) bool {
	if b.live == nil || (b.ap.ok && b.ap.ver == b.live.ver) {
		return false
	}
	return b.ap.attempt.IsZero() || !now.Before(b.ap.attempt.Add(applyEvery)) || now.Before(b.ap.attempt)
}

// step does whatever periodic work is due at now: re-read the server's own addresses, sweep expired
// blocks and re-check the protected set, release the list to the edge, prune.
func (b *Blocker) step(ctx context.Context) {
	now := b.now()
	b.settleAlerts(ctx, now)
	b.mu.Lock()
	b.ready = true // the first step sweeps (nothing is scheduled yet), so every block is re-checked
	selfDue := due(now, b.next.self, selfEvery)
	sweepDue := due(now, b.next.sweep, sweepEvery)
	pruneDue := due(now, b.next.prune, pruneEvery)
	applyDue := b.applyDueLocked(now)
	if selfDue {
		b.next.self = now.Add(selfEvery)
	}
	if sweepDue || applyDue {
		b.next.sweep = now.Add(sweepEvery)
	}
	if pruneDue {
		b.next.prune = now.Add(pruneEvery)
	}
	b.mu.Unlock()
	if selfDue {
		b.refreshSelf()
	}
	if sweepDue || applyDue {
		// Intentional: the protected set is re-checked right before each release too, so what the
		// edge takes was checked against the allowlist, sessions … of this minute.
		b.sweep(ctx, now)
	}
	if applyDue || b.dueAfterSweep(now) {
		b.release(ctx, now)
	}
	if pruneDue {
		b.wmu.Lock()
		b.prune(ctx, now)
		b.wmu.Unlock()
	}
}

func (b *Blocker) dueAfterSweep(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.applyDueLocked(now)
}

// sweep drops the blocks whose time ran out and re-checks the rest against the protected set.
func (b *Blocker) sweep(ctx context.Context, now time.Time) {
	b.wmu.Lock()
	defer b.wmu.Unlock()
	b.resync(ctx, now)
	prot := b.protected(ctx)
	b.mu.Lock()
	var expired []Block
	for p, blk := range b.inForce {
		if !blk.Until.After(now) {
			blk.State = StateExpired
			expired = append(expired, blk)
			delete(b.inForce, p)
		}
	}
	if wall := now.Round(0); wall.After(b.sweptTo) {
		b.sweptTo = wall
	}
	evs := b.rebuildLocked(prot, now)
	b.mu.Unlock()
	b.saveSuspended(ctx)
	slices.SortFunc(expired, func(x, y Block) int { return comparePrefix(x.Prefix, y.Prefix) })
	b.emitBlocks(now, "expired", expired, nil)
	b.emit(evs...)
}

// release publishes the live list (Snapshot) and has the edge take it, on a detached bounded context.
func (b *Blocker) release(ctx context.Context, now time.Time) {
	b.mu.Lock()
	live, fn := b.live, b.apply
	b.pub.Store(live)
	b.ap.attempt = now
	b.mu.Unlock()
	if fn == nil {
		if b.o.EdgeOwned {
			b.recordApply(ctx, now, live.ver, fmt.Errorf("the edge apply is not wired"))
		}
		return
	}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), applyTimeout)
	err := fn(actx)
	cancel()
	b.recordApply(ctx, now, live.ver, err)
}

// adoptAlerts reads which of the list's alerts were open before the restart, so they are resolved
// and not raised a second time. When the alerter can't say, a "resolved" is owed once for each.
func (b *Blocker) adoptAlerts(ctx context.Context) {
	if b.o.Alerter == nil {
		return
	}
	if oa, ok := b.o.Alerter.(openAlerts); ok {
		actx, cancel := context.WithTimeout(ctx, alertTimeout)
		open, err := oa.OpenInfraAlerts(actx, alertKind)
		cancel()
		if err == nil {
			_, b.ap.alerted = open[alertKeyApply]
			_, b.alerts.fullOpen = open[alertKeyFull]
			return
		}
		b.log.Warn("blocklist: could not read the open alerts; resolving them when the list is served", "err", err)
	}
	b.ap.owed, b.alerts.fullOwed = true, true
}

// settleAlerts sends the "resolved" alerts that are due: the apply alert's when the edge serves the
// list (one that couldn't be queued after the apply is tried again here, each step), the full-list
// alert's when the automatic blocks are below their cap again.
func (b *Blocker) settleAlerts(ctx context.Context, now time.Time) {
	b.mu.Lock()
	apply := b.ap.ok && (b.ap.alerted || b.ap.owed)
	full := (b.alerts.fullOpen || b.alerts.fullOwed) && b.activeLocked(SourceAuto, now) < b.maxAuto
	b.mu.Unlock()
	if apply {
		b.resolveApply(ctx)
	}
	// Intentional: alerts.full (the once-an-hour limit on the firing alert) is kept, so a list
	// that stays around its cap doesn't alert and resolve every minute.
	if full && b.alert(ctx, alert.Outbox{Target: alertTarget, Kind: alertKind, Level: alert.LevelWarning, Transition: "resolved", DedupeKey: alertKeyFull,
		Summary: "The automatic block list is below its limit again: new automatic blocks are placed."}) {
		b.mu.Lock()
		b.alerts.fullOpen, b.alerts.fullOwed = false, false
		b.mu.Unlock()
	}
}

// resolveApply queues the apply alert's "resolved".
func (b *Blocker) resolveApply(ctx context.Context) {
	if b.alert(ctx, alert.Outbox{Target: alertTarget, Kind: alertKind, Level: alert.LevelWarning, Transition: "resolved", DedupeKey: alertKeyApply,
		Summary: "The edge serves the block list again."}) {
		b.mu.Lock()
		b.ap.alerted, b.ap.owed = false, false
		b.mu.Unlock()
	}
}

// recordApply records an apply's outcome; the third failure in a row raises the security_blocking
// alert, the next success resolves it (also one raised before a restart).
func (b *Blocker) recordApply(ctx context.Context, now time.Time, ver uint64, err error) {
	b.mu.Lock()
	var fire, resolve bool
	var failures int
	if err == nil {
		resolve = b.ap.alerted || b.ap.owed
		b.ap.ver, b.ap.ok, b.ap.err, b.ap.at, b.ap.failures = ver, true, "", now, 0
	} else {
		b.ap.ok = false
		b.ap.err = clean(err.Error(), maxDetail)
		b.ap.failures++
		failures = b.ap.failures
		fire = failures >= applyAlertAfter && !b.ap.alerted
	}
	msg := b.ap.err
	b.mu.Unlock()
	if err != nil {
		b.log.Warn("blocklist: the edge did not take the block list; retrying in a minute", "failures", failures, "err", msg)
	}
	switch {
	case fire:
		if b.alert(ctx, alert.Outbox{Target: alertTarget, Kind: alertKind, Level: alert.LevelWarning, Transition: "firing", DedupeKey: alertKeyApply,
			Summary: fmt.Sprintf("The edge has not taken the block list for %d attempts: %s", failures, msg)}) {
			b.mu.Lock()
			b.ap.alerted, b.ap.owed = true, false
			b.mu.Unlock()
		}
	case resolve:
		b.resolveApply(ctx)
	}
}

// signal wakes Run (a change may make an apply due).
func (b *Blocker) signal() {
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

// Run sweeps expired blocks and applies list changes to the edge in batches (at most once a
// minute), until ctx is done.
func (b *Blocker) Run(ctx context.Context) {
	b.runMu.Lock()
	if b.closed || b.done != nil {
		b.runMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	b.cancel, b.done = cancel, make(chan struct{})
	done := b.done
	b.runMu.Unlock()
	defer close(done)
	defer cancel()
	for {
		b.step(ctx)
		t := time.NewTimer(b.untilNext())
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-b.wake:
			t.Stop()
		case <-t.C:
		}
	}
}

// untilNext is how long Run sleeps before the next due work (1 s to a minute).
func (b *Blocker) untilNext() time.Duration {
	now := b.now()
	b.mu.Lock()
	next := []time.Time{b.next.sweep, b.next.self, b.next.prune}
	if b.live != nil && !(b.ap.ok && b.ap.ver == b.live.ver) {
		next = append(next, b.ap.attempt.Add(applyEvery))
	}
	b.mu.Unlock()
	wait := sweepEvery
	for _, t := range next {
		if d := t.Sub(now); d < wait {
			wait = d
		}
	}
	return max(wait, time.Second)
}

// Close stops what Run started.
func (b *Blocker) Close() {
	b.runMu.Lock()
	b.closed = true
	cancel, done := b.cancel, b.done
	b.runMu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
