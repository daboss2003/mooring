package detect

import (
	"context"
	"errors"
	"strings"

	"github.com/daboss2003/mooring/internal/siem"
)

var (
	_ siem.DetectionService = (*Engine)(nil)
	_ siem.Reporter         = (*Engine)(nil)

	errClosed = errors.New("detect: closed")
)

// Rules returns the rules: the pack with the stored settings applied, then the custom rules by ID
// (a stored custom rule that no longer validates is listed switched off, its description saying
// why).
func (e *Engine) Rules(context.Context) ([]siem.Rule, error) {
	return e.rules.Load().rules(), nil
}

// SaveRule validates and stores a rule, then puts the new rule set in force. For a built-in rule
// only the tunable fields are taken from r (Enabled, Severity, Count, Window, Factor, Learn,
// SpeedKMH, SnoozedUntil); a custom rule is stored whole. Validation errors wrap ErrInvalid.
func (e *Engine) SaveRule(ctx context.Context, r siem.Rule) error {
	if e.rs == nil {
		return ErrNoStore
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	r.ID = strings.TrimSpace(r.ID)
	if p := packByID[r.ID]; p != nil {
		merged := tunables(r).apply(cloneRule(p.Rule))
		if err := validate(&merged, now); err != nil {
			return err
		}
		if _, err := compile(merged, p.info, e.opt.MapValue); err != nil {
			return invalid("%v", err)
		}
		o := tunables(merged)
		if err := e.rs.put(ctx, r.ID, o, now); err != nil {
			return err
		}
		e.ov[r.ID] = o
		return e.rebuild()
	}
	slug, ok := strings.CutPrefix(r.ID, CustomPrefix)
	if !ok || !reSlug.MatchString(slug) {
		return invalid("a custom rule's ID is %q followed by lowercase letters, digits and '-' (at most 48, starting with a letter or digit)", CustomPrefix)
	}
	r.Builtin = false
	r.MITRE = append([]string(nil), r.MITRE...)
	if err := validate(&r, now); err != nil {
		return err
	}
	if _, err := compile(r, packInfo{}, e.opt.MapValue); err != nil {
		return invalid("%v", err)
	}
	// The listed custom rules count (an invalid stored one too); e.custom changes only under mu.
	n := len(e.custom)
	if _, ok := e.custom[r.ID]; ok {
		n--
	}
	if n >= MaxCustomRules {
		return invalid("at most %d custom rules", MaxCustomRules)
	}
	if err := e.rs.put(ctx, r.ID, r, now); err != nil {
		return err
	}
	e.custom[r.ID] = storedCustom{r: cloneRule(r)}
	return e.rebuild()
}

// DeleteRule removes a custom rule (an invalid stored one too).
func (e *Engine) DeleteRule(ctx context.Context, id string) error {
	if packByID[id] != nil {
		return invalid("a built-in rule can't be deleted; switch it off or reset it")
	}
	if !strings.HasPrefix(id, CustomPrefix) {
		return ErrNotFound
	}
	if e.rs == nil {
		return ErrNoStore
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	n, err := e.rs.del(ctx, id)
	if err != nil {
		return err
	}
	if _, ok := e.custom[id]; !ok && n == 0 {
		return ErrNotFound
	}
	delete(e.custom, id)
	return e.rebuild()
}

// ResetRule puts a built-in rule back to the pack's settings.
func (e *Engine) ResetRule(ctx context.Context, id string) error {
	if packByID[id] == nil {
		return ErrNotFound
	}
	if e.rs == nil {
		return ErrNoStore
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.rs.del(ctx, id); err != nil {
		return err
	}
	delete(e.ov, id)
	return e.rebuild()
}

// Detections lists stored detections, most recently seen first (Last, then ID, descending), paged
// by f.BeforeLast and f.Before; From and To bound Last. Updates of the last writeEvery may not
// show yet.
func (e *Engine) Detections(ctx context.Context, f siem.DetectionFilter) ([]siem.Detection, error) {
	if e.closed.Load() {
		return nil, errClosed
	}
	return e.db.list(ctx, f)
}

// Detection returns one stored detection.
func (e *Engine) Detection(ctx context.Context, id int64) (siem.Detection, bool, error) {
	if e.closed.Load() {
		return siem.Detection{}, false, errClosed
	}
	return e.db.get(ctx, id)
}
