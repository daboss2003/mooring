package detect

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
)

// Bounds of a rule; SaveRule refuses values outside them.
const (
	MaxCustomRules = 100

	maxRuleName        = 80
	maxRuleDescription = 500
	maxMITRE           = 8
	maxCount           = 100000
	maxDistinctCount   = maxDistinctValues // a distinct rule can't count past the per-key cap
	maxSequenceCount   = 1000
	minWindow          = time.Minute
	maxWindow          = 7 * 24 * time.Hour
	maxAnomalyWindow   = 24 * time.Hour
	minFactor          = 1.5
	maxFactor          = 1000
	maxLearn           = 30 * 24 * time.Hour
	minSpeedKMH        = 100
	maxSpeedKMH        = 20000
	maxSnooze          = 30 * 24 * time.Hour
)

// CustomPrefix starts the ID of every custom rule.
const CustomPrefix = "custom."

var (
	// ErrNotFound: no rule with that ID (or not one the call applies to).
	ErrNotFound = errors.New("detect: no such rule")
	// ErrInvalid wraps every validation error of SaveRule; it is siem.ErrInvalidRule, so the
	// dashboard can tell a validation error from an internal one without importing this package.
	ErrInvalid = siem.ErrInvalidRule
	// ErrNoStore: the engine was built without Mooring's database, so rules can't be changed.
	ErrNoStore = errors.New("detect: the rule store is not available")

	reSlug  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,47}$`)
	reMITRE = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, a...)...)
}

// override is what is stored for a built-in rule: its tunable fields.
type override struct {
	Enabled      bool          `json:"enabled"`
	Severity     siem.Severity `json:"severity"`
	Count        int           `json:"count"`
	Window       time.Duration `json:"window"`
	Factor       float64       `json:"factor"`
	Learn        time.Duration `json:"learn"`
	SpeedKMH     float64       `json:"speed_kmh"`
	SnoozedUntil time.Time     `json:"snoozed_until"`
}

func tunables(r siem.Rule) override {
	return override{Enabled: r.Enabled, Severity: r.Severity, Count: r.Count, Window: r.Window, Factor: r.Factor,
		Learn: r.Learn, SpeedKMH: r.SpeedKMH, SnoozedUntil: r.SnoozedUntil}
}

func (o override) apply(r siem.Rule) siem.Rule {
	r.Enabled, r.Severity, r.Count, r.Window, r.Factor = o.Enabled, o.Severity, o.Count, o.Window, o.Factor
	r.Learn, r.SpeedKMH, r.SnoozedUntil = o.Learn, o.SpeedKMH, o.SnoozedUntil
	return r
}

// tunableFields set one stored tunable each, for applying a stored override field by field.
var tunableFields = []struct {
	name string
	set  func(r *siem.Rule, o override)
}{
	{"enabled", func(r *siem.Rule, o override) { r.Enabled = o.Enabled }},
	{"severity", func(r *siem.Rule, o override) { r.Severity = o.Severity }},
	{"count", func(r *siem.Rule, o override) { r.Count = o.Count }},
	{"window", func(r *siem.Rule, o override) { r.Window = o.Window }},
	{"factor", func(r *siem.Rule, o override) { r.Factor = o.Factor }},
	{"learn", func(r *siem.Rule, o override) { r.Learn = o.Learn }},
	{"speed_kmh", func(r *siem.Rule, o override) { r.SpeedKMH = o.SpeedKMH }},
	{"snoozed_until", func(r *siem.Rule, o override) { r.SnoozedUntil = o.SnoozedUntil }},
}

// applyStored applies a stored override to a built-in rule. When the whole override doesn't
// validate, each field is applied on its own and a field that doesn't validate keeps the pack's
// value (a switched-off rule stays off when its stored snooze is too long); errs names them.
func applyStored(p siem.Rule, o override, now time.Time) (r siem.Rule, errs []error) {
	all := o.apply(p)
	if validate(&all, now) == nil {
		return all, nil
	}
	cur := p
	for _, f := range tunableFields {
		t := cur
		f.set(&t, o)
		if err := validate(&t, now); err != nil {
			errs = append(errs, fmt.Errorf("stored %s ignored: %w", f.name, err))
			continue
		}
		cur = t
	}
	return cur, errs
}

// storedCustom is a custom rule as stored; err is set when its row didn't decode.
type storedCustom struct {
	r   siem.Rule
	err error
}

// maxStoredID bounds the ID of a stored custom rule that is listed.
const maxStoredID = 128

func cloneRule(r siem.Rule) siem.Rule {
	r.MITRE = slices.Clone(r.MITRE)
	return r
}

// validField reports whether name is a GroupBy/Field name: "", ip, actor, app, kind, geo.cc,
// geo.asn or f.<key>.
func validField(name string) bool {
	switch name {
	case "", "ip", "actor", "app", "kind", "geo.cc", "geo.asn":
		return true
	}
	key, ok := strings.CutPrefix(name, "f.")
	if !ok || key == "" || len(key) > siem.MaxFieldKey || !utf8.ValidString(key) {
		return false
	}
	for _, r := range key {
		if unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func plainText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func parseRuleQuery(what, s string) error {
	if strings.TrimSpace(s) == "" {
		return invalid("%s is empty", what)
	}
	q, err := query.Parse(s)
	if err != nil {
		return invalid("%s: %v", what, err)
	}
	if len(q.Terms) == 0 && len(q.Text) == 0 {
		return invalid("%s is empty", what)
	}
	return nil
}

func checkRange[T int | float64 | time.Duration](name string, v, lo, hi T, show func(T) string) error {
	if v < lo || v > hi {
		return invalid("%s must be between %s and %s", name, show(lo), show(hi))
	}
	return nil
}

func showInt(v int) string           { return strconv.Itoa(v) }
func showFloat(v float64) string     { return strconv.FormatFloat(v, 'f', -1, 64) }
func showDur(v time.Duration) string { return fmtDur(v) }

// validate checks a whole rule (custom, or a built-in one with its tunables applied) and clears
// the parameters its type doesn't use. now decides whether a snooze has already ended.
func validate(r *siem.Rule, now time.Time) error {
	if r.Name = strings.TrimSpace(r.Name); r.Name == "" {
		return invalid("the name is empty")
	}
	if len(r.Name) > maxRuleName || !plainText(r.Name) {
		return invalid("the name must be plain text of at most %d bytes", maxRuleName)
	}
	r.Description = strings.TrimSpace(r.Description)
	if len(r.Description) > maxRuleDescription || !utf8.ValidString(r.Description) {
		return invalid("the description must be at most %d bytes", maxRuleDescription)
	}
	if siem.SeverityRank(r.Severity) == 0 {
		return invalid("unknown severity %q (low, medium, high, critical)", siem.Cut(string(r.Severity), 32))
	}
	if len(r.MITRE) > maxMITRE {
		return invalid("at most %d MITRE ATT&CK techniques", maxMITRE)
	}
	for _, t := range r.MITRE {
		if !reMITRE.MatchString(t) {
			return invalid("%q is not a MITRE ATT&CK technique ID (T1110 or T1110.001)", siem.Cut(t, 32))
		}
	}
	if err := parseRuleQuery("the query", r.Query); err != nil {
		return err
	}
	if !validField(r.GroupBy) {
		return invalid("unknown group-by field %q", siem.Cut(r.GroupBy, 80))
	}
	if r.Field != "" && !validField(r.Field) {
		return invalid("unknown field %q", siem.Cut(r.Field, 80))
	}
	for _, f := range []float64{r.Factor, r.SpeedKMH} {
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return invalid("a parameter is not a number")
		}
	}
	window := func(hi time.Duration) error { return checkRange("the window", r.Window, minWindow, hi, showDur) }
	count := func(hi int) error { return checkRange("the count", r.Count, 1, hi, showInt) }
	learn := func() error { return checkRange("the learning period", r.Learn, 0, maxLearn, showDur) }
	var err error
	switch r.Type {
	case siem.RuleThreshold:
		err = errors.Join(count(maxCount), window(maxWindow))
		r.Field, r.Then, r.Factor, r.Learn, r.SpeedKMH = "", "", 0, 0, 0
	case siem.RuleDistinct:
		if r.Field == "" {
			return invalid("a distinct rule needs a field")
		}
		err = errors.Join(count(maxDistinctCount), window(maxWindow))
		r.Then, r.Factor, r.Learn, r.SpeedKMH = "", 0, 0, 0
	case siem.RuleNewValue:
		if r.Field == "" {
			return invalid("a new-value rule needs a field")
		}
		err = learn()
		r.Then, r.Count, r.Window, r.Factor, r.SpeedKMH = "", 0, 0, 0, 0
	case siem.RuleAnomaly:
		err = errors.Join(count(maxCount), window(maxAnomalyWindow), learn(),
			checkRange("the factor", r.Factor, minFactor, maxFactor, showFloat))
		r.Field, r.Then, r.SpeedKMH = "", "", 0
	case siem.RuleTravel:
		err = checkRange("the speed", r.SpeedKMH, minSpeedKMH, maxSpeedKMH, showFloat)
		r.Field, r.Then, r.Count, r.Window, r.Factor, r.Learn = "", "", 0, 0, 0, 0
	case siem.RuleSequence:
		if err := parseRuleQuery("the closing query", r.Then); err != nil {
			return err
		}
		err = errors.Join(count(maxSequenceCount), window(maxWindow))
		r.Field, r.Factor, r.Learn, r.SpeedKMH = "", 0, 0, 0
	default:
		return invalid("unknown rule type %q", siem.Cut(r.Type, 32))
	}
	if err != nil {
		return err
	}
	switch {
	case !r.SnoozedUntil.After(now):
		r.SnoozedUntil = time.Time{}
	case r.SnoozedUntil.Sub(now) > maxSnooze:
		return invalid("a snooze can last at most %s", fmtDur(maxSnooze))
	default:
		r.SnoozedUntil = r.SnoozedUntil.UTC()
	}
	return nil
}

// extractor returns an event's value of a GroupBy/Field name; ok is false when the event has none.
type extractor func(e *siem.Event) (string, bool)

func extract(name string) extractor {
	switch name {
	case "":
		return func(*siem.Event) (string, bool) { return "", true }
	case "ip":
		return func(e *siem.Event) (string, bool) { return ipKey(e.IP), e.IP != "" }
	case "actor":
		return func(e *siem.Event) (string, bool) { return e.Actor, e.Actor != "" }
	case "app":
		return func(e *siem.Event) (string, bool) { return e.App, e.App != "" }
	case "kind":
		return func(e *siem.Event) (string, bool) { return e.Kind, e.Kind != "" }
	case "geo.cc":
		return func(e *siem.Event) (string, bool) {
			if e.Geo == nil || e.Geo.Country == "" {
				return "", false
			}
			return siem.Cut(e.Geo.Country, siem.MaxShort), true
		}
	case "geo.asn":
		return func(e *siem.Event) (string, bool) {
			if e.Geo == nil || e.Geo.ASN == 0 {
				return "", false
			}
			return strconv.FormatUint(uint64(e.Geo.ASN), 10), true
		}
	}
	key := strings.TrimPrefix(name, "f.")
	norm := func(s string) string { return s }
	if key == "host" {
		norm = hostKey
	}
	return func(e *siem.Event) (string, bool) {
		switch v := e.F[key].(type) {
		case string:
			s := norm(siem.Cut(v, siem.MaxShort))
			return s, s != ""
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64), true
		case bool:
			return strconv.FormatBool(v), true
		}
		return "", false
	}
}

// firstOf returns the first value of a and b an event has, else "" (one group for the events that
// have neither).
func firstOf(a, b extractor) extractor {
	return func(e *siem.Event) (string, bool) {
		if v, ok := a(e); ok && v != "" {
			return v, true
		}
		if v, ok := b(e); ok && v != "" {
			return v, true
		}
		return "", true
	}
}

// ipKey is an address as a key (group-by or field ip): an IPv4 address as it is, an IPv6 address
// as its /64 ("2001:db8:1:2::/64"), an IPv4-mapped IPv6 address as the IPv4 address.
// Intentional: a single IPv6 host usually holds a whole /64, so keyed by address it could rotate
// below every count and make a new detection per request.
func ipKey(s string) string {
	if strings.IndexByte(s, ':') < 0 {
		return s
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return s
	}
	if a.Is4In6() {
		return a.Unmap().String()
	}
	p, err := a.WithZone("").Prefix(64)
	if err != nil {
		return s
	}
	return p.String()
}

// hostKey is a Host header value as a key (f.host): lowercase, without a port or a trailing dot.
func hostKey(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i > 0 {
			h = h[:i+1]
		}
	} else if i := strings.IndexByte(h, ':'); i >= 0 && strings.LastIndexByte(h, ':') == i {
		h = h[:i]
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// compiled is a rule ready to evaluate.
type compiled struct {
	r       siem.Rule
	info    packInfo
	q, then query.Query
	group   extractor
	field   extractor
	sig     string // the matching definition: state is kept while it stays the same
}

// signature identifies what a rule's state means; a change restarts the state.
func signature(r siem.Rule) string {
	h := sha256.Sum256([]byte(strings.Join([]string{r.Type, r.Query, r.Then, r.GroupBy, r.Field}, "\x00")))
	return hex.EncodeToString(h[:8])
}

func compile(r siem.Rule, info packInfo, mapValue func(field, value string) string) (*compiled, error) {
	c := &compiled{r: r, info: info, group: extract(r.GroupBy), sig: signature(r)}
	var err error
	if c.q, err = parseMapped(r.Query, mapValue); err != nil {
		return nil, err
	}
	if r.Type == siem.RuleSequence {
		if c.then, err = parseMapped(r.Then, mapValue); err != nil {
			return nil, err
		}
	}
	if r.Field != "" {
		c.field = extract(r.Field)
	}
	if info.groupAlt != "" {
		c.group = firstOf(c.group, extract(info.groupAlt))
	}
	return c, nil
}

// parseMapped parses a rule query and rewrites each actor/f.* value to the form redaction stores
// it in (a keyed hash for personal data), as the search page does.
func parseMapped(s string, mapValue func(field, value string) string) (query.Query, error) {
	q, err := query.Parse(s)
	if err != nil {
		return query.Query{}, err
	}
	if mapValue != nil {
		q.MapValues(func(field, value string) (string, bool) {
			if (field != "actor" && !strings.HasPrefix(field, "f.")) || strings.HasSuffix(value, "*") {
				return value, false
			}
			v := mapValue(field, value)
			return v, v != value
		})
	}
	return q, nil
}

// ruleSet is the compiled rules in force: the pack (with overrides) in pack order, then the
// custom rules by ID. It is never modified once built.
type ruleSet struct {
	list   []*compiled // the rules evaluated
	byID   map[string]*compiled
	listed []siem.Rule // what Rules returns: list's rules, and the invalid stored custom rules
}

func (rs *ruleSet) rules() []siem.Rule {
	out := make([]siem.Rule, len(rs.listed))
	for i, r := range rs.listed {
		out[i] = cloneRule(r)
	}
	return out
}

// buildSet compiles the pack with ov applied and the custom rules. A stored built-in setting that
// no longer validates is reported in errs and the pack's value used for it. A stored custom rule
// that doesn't validate is reported, not evaluated, and listed switched off with the reason as its
// description, so the owner can fix or delete it.
func buildSet(ov map[string]override, custom map[string]storedCustom, mapValue func(field, value string) string,
	now time.Time) (rs *ruleSet, errs []error) {
	rs = &ruleSet{byID: map[string]*compiled{}}
	for _, p := range pack {
		r := cloneRule(p.Rule)
		if o, ok := ov[r.ID]; ok {
			var bad []error
			r, bad = applyStored(r, o, now)
			for _, err := range bad {
				errs = append(errs, fmt.Errorf("rule %s: %w", r.ID, err))
			}
		}
		c, err := compile(r, p.info, mapValue)
		if err != nil {
			errs = append(errs, fmt.Errorf("rule %s: %w", r.ID, err))
			continue
		}
		rs.list = append(rs.list, c)
		rs.byID[r.ID] = c
		rs.listed = append(rs.listed, cloneRule(c.r))
	}
	ids := slices.Sorted(maps.Keys(custom))
	for _, id := range ids {
		sc := custom[id]
		r := cloneRule(sc.r)
		err := sc.err
		if slug, ok := strings.CutPrefix(id, CustomPrefix); err == nil && (!ok || !reSlug.MatchString(slug)) {
			err = invalid("the ID is not %q followed by a slug", CustomPrefix)
		}
		if err == nil {
			err = validate(&r, now)
		}
		var c *compiled
		if err == nil {
			if c, err = compile(r, packInfo{}, mapValue); err != nil {
				err = invalid("%v", err)
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("rule %s: %w", id, err))
			rs.listed = append(rs.listed, invalidListing(id, sc.r, err))
			continue
		}
		rs.list = append(rs.list, c)
		rs.byID[id] = c
		rs.listed = append(rs.listed, cloneRule(c.r))
	}
	return rs, errs
}

// invalidListing is how Rules lists a stored custom rule that doesn't validate: switched off, its
// description the reason, its other fields as stored (cut to their bounds).
func invalidListing(id string, r siem.Rule, err error) siem.Rule {
	r.ID, r.Builtin, r.Enabled, r.SnoozedUntil = id, false, false, time.Time{}
	if r.Name = clean(r.Name, maxRuleName); r.Name == "" {
		r.Name = clean(id, maxRuleName)
	}
	msg := strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": ")
	r.Description = siem.Cut(clean("stored rule is invalid: "+msg, maxRuleDescription), maxRuleDescription)
	if siem.SeverityRank(r.Severity) == 0 {
		r.Severity = siem.SevLow
	}
	r.MITRE = slices.DeleteFunc(slices.Clone(r.MITRE), func(t string) bool { return !reMITRE.MatchString(t) })
	r.MITRE = r.MITRE[:min(len(r.MITRE), maxMITRE)]
	r.Type, r.GroupBy, r.Field = siem.Cut(r.Type, 32), siem.Cut(r.GroupBy, 80), siem.Cut(r.Field, 80)
	r.Query, r.Then = siem.Cut(r.Query, maxQueryLen), siem.Cut(r.Then, maxQueryLen)
	return r
}

// maxQueryLen is the search syntax's bound on a query (bytes).
const maxQueryLen = 2 << 10

// ruleStore keeps overrides and custom rules in Mooring's database (table security_rules).
type ruleStore struct {
	db *sql.DB
}

// load reads every stored rule. A built-in rule's row that doesn't decode is returned as an
// error and skipped; a custom rule's is kept with its error (listed as invalid). A custom rule
// whose ID isn't plain text of at most maxStoredID bytes is skipped.
func (s *ruleStore) load(ctx context.Context) (map[string]override, map[string]storedCustom, []error, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT id, json FROM security_rules`)
	if err != nil {
		return nil, nil, nil, err
	}
	type row struct{ id, js string }
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.js); err != nil {
			rows.Close()
			return nil, nil, nil, err
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, nil, err
	}
	rows.Close()
	ov, custom := map[string]override{}, map[string]storedCustom{}
	var errs []error
	for _, r := range all {
		switch {
		case packByID[r.id] != nil:
			var o override
			if err := json.Unmarshal([]byte(r.js), &o); err != nil {
				errs = append(errs, fmt.Errorf("rule %s: stored settings unreadable: %w", r.id, err))
				continue
			}
			ov[r.id] = o
		case strings.HasPrefix(r.id, CustomPrefix):
			if len(r.id) > maxStoredID || !plainText(r.id) {
				errs = append(errs, fmt.Errorf("rule %q: stored custom rule with a bad ID skipped", siem.Cut(r.id, 64)))
				continue
			}
			var c siem.Rule
			var bad error
			if err := json.Unmarshal([]byte(r.js), &c); err != nil {
				c, bad = siem.Rule{}, invalid("unreadable: %v", err)
			}
			c.ID, c.Builtin = r.id, false
			custom[r.id] = storedCustom{r: c, err: bad}
		}
		// Intentional: an override of a built-in rule a later release removed is kept in the table
		// (harmless) rather than deleted at start.
	}
	return ov, custom, errs, nil
}

func (s *ruleStore) put(ctx context.Context, id string, v any, now time.Time) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err = s.db.ExecContext(ctx, `INSERT INTO security_rules(id, json, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET json = excluded.json, updated_at = excluded.updated_at`, id, string(b), now.Unix())
	return err
}

// del removes a stored rule and reports how many rows it removed.
func (s *ruleStore) del(ctx context.Context, id string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := s.db.ExecContext(ctx, `DELETE FROM security_rules WHERE id = ?`, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
