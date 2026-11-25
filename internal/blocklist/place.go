package blocklist

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
)

const (
	kindBlock        = "siem.block"         // F: action (applied|extended|expired|removed|suspended|resumed), prefix, source, rule, until
	kindBlockRefused = "siem.block_refused" // F: prefix, code, source, rule

	alertKind      = "security_blocking"
	alertTarget    = "blocklist"
	alertKeyApply  = "blocklist:apply"
	alertKeyFull   = "blocklist:full"
	alertKeyCDN    = "blocklist:cdn"
	alertTimeout   = 5 * time.Second
	fullAlertEvery = time.Hour
	cdnAlertEvery  = 24 * time.Hour
	// maxBlockEvents bounds the per-block events of one sweep or lift; the rest are counted in one
	// event (a mass lift must not crowd the pipeline queue the other security events share).
	maxBlockEvents = 100
)

// noEdgeWhy explains RefuseNoEdge.
const noEdgeWhy = "Mooring doesn't run the edge (edge.mode external)"

// alertState is the alerts raised from Block.
type alertState struct {
	full, cdn time.Time // when the last one was raised
	fullOpen  bool      // the full-list alert is firing (raised in this run, or open before the restart)
	// fullOwed: what was open before the restart isn't known, so a "resolved" is sent once the list
	// is below its cap.
	fullOwed bool
}

// clean removes control and format characters from s and cuts it to n bytes.
func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	return siem.Cut(s, n)
}

// refusalKey is what a refusal row names: the canonical prefix, or the request's text (cleaned).
func refusalKey(raw string, p netip.Prefix) string {
	if p.IsValid() {
		return p.String()
	}
	if k := clean(strings.TrimSpace(raw), 64); k != "" {
		return k
	}
	return "(empty)"
}

func (b *Blocker) caddyOK() (bool, string) {
	if b.o.CaddyOK == nil {
		return true, ""
	}
	return b.o.CaddyOK()
}

// Block places (or extends) a block; a refusal is a *RefusedError, recorded as a Refusal.
func (b *Blocker) Block(ctx context.Context, r Request) (Block, error) {
	src := r.Source
	r.RuleID, r.By, r.Reason = clean(r.RuleID, maxShortField), clean(r.By, maxShortField), clean(r.Reason, maxDetail)
	p, perr := parsePrefix(r.Prefix)
	switch {
	case src != SourceAuto && src != SourceManual:
		return b.refuse(ctx, r, p, RefuseInvalid, "unknown source")
	case perr != nil:
		return b.refuse(ctx, r, p, RefuseInvalid, perr.Error())
	case !widthOK(p, src) && src == SourceAuto:
		return b.refuse(ctx, r, p, RefuseWidth, "an automatic block is a single IPv4 address or an IPv6 /64")
	case !widthOK(p, src):
		return b.refuse(ctx, r, p, RefuseWidth, fmt.Sprintf("wider than /%d (IPv4) or /%d (IPv6)", ManualIPv4Bits, ManualIPv6Bits))
	case !b.o.EdgeOwned:
		return b.refuse(ctx, r, p, RefuseNoEdge, noEdgeWhy)
	}
	if src == SourceAuto {
		if ok, why := b.caddyOK(); !ok {
			return b.refuse(ctx, r, p, RefuseOldCaddy, "automatic blocks need Caddy 2.11 or later: "+clean(why, maxDetail))
		}
		if r.Duration <= 0 {
			return b.refuse(ctx, r, p, RefuseDuration, "no duration")
		}
	} else if r.Duration < MinDuration || r.Duration > b.manualMaxDur {
		return b.refuse(ctx, r, p, RefuseDuration, fmt.Sprintf("between %s and %s", MinDuration, b.manualMaxDur))
	}
	var self netip.Addr
	if src == SourceManual {
		if a, err := netip.ParseAddr(strings.TrimSpace(r.Self)); err == nil {
			self = a.Unmap().WithZone("")
		}
	}

	b.wmu.Lock()
	defer b.wmu.Unlock()
	now := b.now()
	b.resync(ctx, now)
	prot := b.protected(ctx)
	if code, detail := prot.covered(p, self); code != "" {
		return b.refuse(ctx, r, p, code, detail)
	}
	row, found, err := b.getRow(ctx, p)
	if err != nil {
		return Block{}, err
	}
	if src == SourceAuto {
		// The prefix's own exemption, or that of a range around it an owner unblocked.
		exempt, err := b.exemptUntil(ctx, p, now)
		if err != nil {
			return Block{}, err
		}
		if exempt.After(now) {
			return b.refuse(ctx, r, p, RefuseExempt, "exempt from automatic blocks until "+exempt.Format(time.RFC3339))
		}
	}

	b.mu.Lock()
	cur, inForce := b.inForce[p]
	b.mu.Unlock()
	// Intentional: an automatic request in the last RenewAhead of an automatic block is the address
	// coming back as its block ends. It is placed as a repeat (the ladder's next step) from now, not
	// as an extension at the first step's length, which would never escalate.
	renew := inForce && src == SourceAuto && cur.Source == SourceAuto && cur.Until.Sub(now) <= RenewAhead
	if inForce && cur.Until.After(now) && !renew {
		return b.extend(ctx, r, cur, now, prot)
	}

	// The cap counts the blocks in force by time: one that ran out and isn't swept yet is no entry
	// (the requested prefix's own included: it is here only when it ran out).
	b.mu.Lock()
	active := b.activeLocked(src, now)
	b.mu.Unlock()
	if renew && cur.Until.After(now) {
		active-- // its own entry, replaced by the repeat
	}
	if limit := b.capOf(src); active >= limit {
		res, rerr := b.refuse(ctx, r, p, RefuseFull, fmt.Sprintf("%d %s blocks are in force (the limit)", active, src))
		if src == SourceAuto {
			b.fullAlert(ctx, now, active)
		}
		return res, rerr
	}

	blk := Block{Prefix: p, Source: src, RuleID: r.RuleID, Reason: r.Reason, By: r.By, DetectionID: r.DetectionID,
		IncidentID: r.IncidentID, ResponseID: r.ResponseID, Created: now.Truncate(time.Second)}
	// The prefix's automatic blocks within RepeatWindow. Intentional: a manual block is not a
	// repeat and keeps this history as it is; the ladder multiplies the length the last automatic
	// block was placed with, never its extended length.
	if found && !row.autoAt.IsZero() && now.Sub(row.autoAt) < RepeatWindow {
		blk.Hits, blk.autoStep, blk.autoAt = row.Hits, row.autoStep, row.autoAt
	}
	dur := r.Duration
	if src == SourceAuto {
		dur = min(max(dur, b.escalate(blk.autoStep), MinDuration), b.maxAutoDur)
		blk.Hits, blk.autoStep, blk.autoAt = blk.Hits+1, dur, blk.Created
	}
	blk.Until = blk.Created.Add(dur)
	blk.ExemptUntil = row.ExemptUntil
	if err := b.putBlock(ctx, blk); err != nil {
		return Block{}, err
	}
	return b.commit(ctx, now, blk, "applied", prot), nil
}

// activeLocked counts the blocks of src in force at now. Called under mu.
func (b *Blocker) activeLocked(src string, now time.Time) int {
	n := 0
	for _, blk := range b.inForce {
		if blk.Source == src && blk.Until.After(now) {
			n++
		}
	}
	return n
}

// escalate is a repeat's automatic block length: the previous automatic block's times RepeatFactor, at most
// the longest automatic block.
func (b *Blocker) escalate(prev time.Duration) time.Duration {
	if prev <= 0 {
		return 0
	}
	if prev >= b.maxAutoDur/RepeatFactor {
		return b.maxAutoDur
	}
	return prev * RepeatFactor
}

func (b *Blocker) capOf(src string) int {
	if src == SourceAuto {
		return b.maxAuto
	}
	return MaxManual
}

// extend lengthens a block in force to the later of its end and the request's. Intentional: a manual
// request takes over an automatic block (it becomes the owner's: switching automated response off,
// or a false positive, no longer lifts it); an automatic request never changes a manual block's owner.
func (b *Blocker) extend(ctx context.Context, r Request, cur Block, now time.Time, prot protSet) (Block, error) {
	dur := r.Duration
	if r.Source == SourceAuto {
		dur = min(max(dur, MinDuration), b.maxAutoDur)
	}
	blk := cur
	if until := now.Truncate(time.Second).Add(dur); until.After(blk.Until) {
		blk.Until = until
	}
	if r.Source == SourceManual && blk.Source == SourceAuto {
		blk.Source, blk.By = SourceManual, r.By
		if r.Reason != "" {
			blk.Reason = r.Reason
		}
	}
	if err := b.extendBlock(ctx, blk); err != nil {
		return Block{}, err
	}
	return b.commit(ctx, now, blk, "extended", prot), nil
}

// commit puts a written block in memory, rebuilds the live list and emits the change. Called under wmu.
func (b *Blocker) commit(ctx context.Context, now time.Time, blk Block, action string, prot protSet) Block {
	b.mu.Lock()
	if action == "applied" {
		blk.State, blk.SuspendedWhy = StateActive, "" // putBlock saved it so
	}
	b.inForce[blk.Prefix] = blk
	evs := b.rebuildLocked(prot, now)
	blk = b.inForce[blk.Prefix]
	b.mu.Unlock()
	b.saveSuspended(ctx)
	b.emit(append([]siem.Event{b.blockEvent(now, action, blk, nil)}, evs...)...)
	b.signal()
	return blk
}

// refuse records a refusal (coalesced per prefix and code), emits it, and returns it as a
// *RefusedError. A CDN refusal also raises a warning at most once a day: the edge looks proxied.
func (b *Blocker) refuse(ctx context.Context, r Request, p netip.Prefix, code, detail string) (Block, error) {
	now := b.now()
	src := clean(r.Source, maxShortField)
	rf := Refusal{Prefix: refusalKey(r.Prefix, p), Code: code, Detail: clean(detail, maxDetail), Source: src, RuleID: r.RuleID,
		Count: 1, First: now, Last: now}
	if err := b.putRefusal(ctx, rf); err != nil {
		b.log.Warn("blocklist: could not record a refused block", "code", code, "err", err)
	}
	f := map[string]any{"prefix": rf.Prefix, "code": code, "source": src}
	if r.RuleID != "" {
		f["rule"] = r.RuleID
	}
	ev := siem.Event{TS: now, Src: siem.SrcSIEM, Kind: kindBlockRefused, Lvl: siem.LvlWarn, Actor: r.By, F: f,
		Msg: "edge block refused (" + code + "): " + rf.Prefix + ": " + rf.Detail}
	if p.IsValid() && p.IsSingleIP() {
		ev.IP = p.Addr().String()
	}
	b.emit(ev)
	if code == RefuseCDN && r.Source == SourceAuto {
		b.mu.Lock()
		send := b.alerts.cdn.IsZero() || now.Sub(b.alerts.cdn) >= cdnAlertEvery || now.Before(b.alerts.cdn)
		b.mu.Unlock()
		if send && b.alert(ctx, alert.Outbox{Target: alertTarget, Kind: alertKind, Level: alert.LevelWarning, Transition: "firing", DedupeKey: alertKeyCDN,
			Summary: "An automatic block of " + rf.Prefix + " was refused: it is a CDN address, so the edge looks proxied. Set edge.trusted_proxies in config.yaml so the edge sees client addresses."}) {
			b.mu.Lock()
			b.alerts.cdn = now
			b.mu.Unlock()
		}
	}
	return Block{}, &RefusedError{Code: code, Detail: rf.Detail}
}

// fullAlert raises the full-list warning at most once an hour.
func (b *Blocker) fullAlert(ctx context.Context, now time.Time, active int) {
	b.mu.Lock()
	send := b.alerts.full.IsZero() || now.Sub(b.alerts.full) >= fullAlertEvery || now.Before(b.alerts.full)
	b.mu.Unlock()
	if send && b.alert(ctx, alert.Outbox{Target: alertTarget, Kind: alertKind, Level: alert.LevelWarning, Transition: "firing", DedupeKey: alertKeyFull,
		Summary: fmt.Sprintf("The automatic block list is full (%d blocks in force): new automatic blocks are refused. Raise security_logs.blocking.max_entries or lift blocks on the Security page.", active)}) {
		b.mu.Lock()
		b.alerts.full, b.alerts.fullOpen = now, true
		b.mu.Unlock()
	}
}

// alert queues o on a detached bounded context; it reports whether the alert was queued.
func (b *Blocker) alert(ctx context.Context, o alert.Outbox) bool {
	if b.o.Alerter == nil {
		return false
	}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), alertTimeout)
	defer cancel()
	if err := b.o.Alerter.EnqueueInfra(actx, o); err != nil {
		b.log.Warn("blocklist: could not queue an alert", "key", o.DedupeKey, "err", err)
		return false
	}
	return true
}

func (b *Blocker) emit(evs ...siem.Event) {
	if b.o.Emit == nil {
		return
	}
	for _, ev := range evs {
		b.o.Emit(ev)
	}
}

// blockEvent is the siem.block event of action on blk.
func (b *Blocker) blockEvent(now time.Time, action string, blk Block, extra map[string]any) siem.Event {
	f := map[string]any{"action": action, "prefix": blk.Prefix.String(), "source": blk.Source,
		"until": blk.Until.UTC().Format(time.RFC3339)}
	if blk.RuleID != "" {
		f["rule"] = blk.RuleID
	}
	if blk.IncidentID != 0 {
		f["incident_id"] = float64(blk.IncidentID)
	}
	for k, v := range extra {
		if v != "" {
			f[k] = v
		}
	}
	actor := blk.By
	if action == "removed" {
		actor = blk.RemovedBy
	}
	ev := siem.Event{TS: now, Src: siem.SrcSIEM, Kind: kindBlock, Lvl: siem.LvlInfo, Actor: actor, F: f,
		Msg: "edge block " + action + ": " + blk.Prefix.String()}
	if blk.Prefix.IsSingleIP() {
		ev.IP = blk.Prefix.Addr().String()
	}
	return ev
}

// emitBlocks emits action for each of blks, at most maxBlockEvents of them, and one event counting
// the rest.
func (b *Blocker) emitBlocks(now time.Time, action string, blks []Block, extra map[string]any) {
	if b.o.Emit == nil || len(blks) == 0 {
		return
	}
	for i, blk := range blks {
		if i == maxBlockEvents {
			f := map[string]any{"action": action, "count": float64(len(blks) - i)}
			for k, v := range extra {
				f[k] = v
			}
			b.emit(siem.Event{TS: now, Src: siem.SrcSIEM, Kind: kindBlock, Lvl: siem.LvlInfo, F: f,
				Msg: fmt.Sprintf("edge blocks %s: %d more", action, len(blks)-i)})
			return
		}
		b.emit(b.blockEvent(now, action, blk, extra))
	}
}

// remove lifts the blocks in force that keep selects, exempting them until exempt (zero: none);
// reset also clears their prefixes' repeat history. Called under wmu.
func (b *Blocker) remove(ctx context.Context, by, why string, exempt time.Duration, reset bool, keep func(Block) bool) (int, error) {
	now := b.now()
	b.resync(ctx, now)
	by = clean(by, maxShortField)
	var exemptUntil time.Time
	if exempt > 0 {
		exemptUntil = now.Add(exempt)
	}
	b.mu.Lock()
	var gone []Block
	for _, blk := range b.inForce {
		if blk.Until.After(now) && keep(blk) {
			gone = append(gone, blk)
		}
	}
	b.mu.Unlock()
	if len(gone) == 0 {
		return 0, nil
	}
	slices.SortFunc(gone, func(x, y Block) int { return comparePrefix(x.Prefix, y.Prefix) })
	ps := make([]netip.Prefix, len(gone))
	for i, blk := range gone {
		ps[i] = blk.Prefix
	}
	if err := b.removeRows(ctx, ps, by, now, exemptUntil, reset); err != nil {
		return 0, err
	}
	prot := b.protected(ctx)
	b.mu.Lock()
	for i := range gone {
		delete(b.inForce, gone[i].Prefix)
		gone[i].State, gone[i].RemovedBy, gone[i].RemovedAt = StateRemoved, by, now.Truncate(time.Second)
		if !exemptUntil.IsZero() && exemptUntil.After(gone[i].ExemptUntil) {
			gone[i].ExemptUntil = exemptUntil
		}
	}
	evs := b.rebuildLocked(prot, now)
	b.mu.Unlock()
	b.saveSuspended(ctx)
	var extra map[string]any
	if why = clean(why, maxDetail); why != "" {
		extra = map[string]any{"why": why}
	}
	b.emitBlocks(now, "removed", gone, extra)
	b.emit(evs...)
	b.signal()
	return len(gone), nil
}

// Unblock lifts the block in force for prefix (ErrNotFound when none), exempts the prefix and the
// addresses inside it from automatic blocks for ExemptAfterUnblock, and clears its repeat history
// (its next automatic block is the first step again).
func (b *Blocker) Unblock(ctx context.Context, prefix netip.Prefix, by string) error {
	p := canon(prefix)
	if !p.IsValid() {
		return ErrNotFound
	}
	b.wmu.Lock()
	defer b.wmu.Unlock()
	n, err := b.remove(ctx, by, "", ExemptAfterUnblock, true, func(blk Block) bool { return blk.Prefix == p })
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UnblockIncident lifts the automatic blocks placed for incident id, exempts their prefixes from
// automatic blocks for exempt and clears their repeat history (a false positive is no repeat); it
// returns how many were lifted. Every automatic block ever placed for the incident is treated so,
// also one whose time already ran out.
func (b *Blocker) UnblockIncident(ctx context.Context, id int64, by string, exempt time.Duration) (int, error) {
	if id <= 0 {
		return 0, nil
	}
	b.wmu.Lock()
	defer b.wmu.Unlock()
	var until time.Time
	if exempt > 0 {
		until = b.now().Add(exempt)
	}
	if err := b.exemptIncident(ctx, id, until); err != nil {
		return 0, err
	}
	return b.remove(ctx, by, "", exempt, true, func(blk Block) bool { return blk.Source == SourceAuto && blk.IncidentID == id })
}

// LiftAutomatic lifts every automatic block in force (automated response switched off).
func (b *Blocker) LiftAutomatic(ctx context.Context, by, why string) (int, error) {
	b.wmu.Lock()
	defer b.wmu.Unlock()
	return b.remove(ctx, by, why, 0, false, func(blk Block) bool { return blk.Source == SourceAuto })
}

// Status is the list's state for the page.
func (b *Blocker) Status() Status {
	ok, why := b.caddyOK()
	st := Status{EdgeOwned: b.o.EdgeOwned, MaxAuto: b.maxAuto, MaxManual: MaxManual}
	now := b.now()
	switch {
	case !b.o.EdgeOwned:
		st.AutomaticWhy = noEdgeWhy
	case !ok:
		st.AutomaticWhy = "automatic blocks need Caddy 2.11 or later: " + clean(why, maxDetail)
	default:
		st.Automatic = true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	st.L4 = b.o.L4 && !b.l4Off
	if b.o.L4 && b.l4Off {
		st.L4Why = b.l4Why
	}
	st.ActiveAuto = b.activeLocked(SourceAuto, now)
	st.ActiveManual = b.activeLocked(SourceManual, now)
	st.Applied = b.live != nil && b.ap.ok && b.ap.ver == b.live.ver
	st.ApplyErr, st.LastApplied = b.ap.err, b.ap.at
	return st
}
