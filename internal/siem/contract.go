package siem

import (
	"context"
	"errors"
	"time"
)

// Detection (phase 2): the types the enrichment feeds, the rule engine, the app /ops alerts and the
// dashboard share. Each of those lives in its own package and depends only on these.

// Severity of a rule and of its detections. High and critical detections are also sent to the alert
// channels (high as a warning, critical as a critical); low and medium are shown on the Detections
// page only.
type Severity string

const (
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// SeverityRank orders severities (low 1 … critical 4); 0 for an unknown one.
func SeverityRank(s Severity) int {
	switch s {
	case SevLow:
		return 1
	case SevMedium:
		return 2
	case SevHigh:
		return 3
	case SevCritical:
		return 4
	}
	return 0
}

// Rule types.
const (
	RuleThreshold = "threshold" // at least Count matching events per GroupBy key within Window
	RuleDistinct  = "distinct"  // at least Count distinct values of Field per GroupBy key within Window
	RuleNewValue  = "new_value" // a value of Field never seen before for the GroupBy key (after Learn)
	RuleAnomaly   = "anomaly"   // matching events per GroupBy key within Window above Factor × the usual rate, and at least Count
	RuleTravel    = "travel"    // two matching events of one GroupBy key whose IP locations are farther apart than SpeedKMH allows
	RuleSequence  = "sequence"  // at least Count events matching Query, then one matching Then, same GroupBy key, within Window
)

// Rule is one detection rule: a built-in one from the pack (Builtin true; only the fields marked
// "tunable" can change) or an operator's own ("custom." + slug).
type Rule struct {
	ID          string   `json:"id"` // built-in: "<area>.<name>" (e.g. "ssh.bruteforce"); custom: "custom.<slug>"
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Type        string   `json:"type"`            // one of the Rule* types
	Severity    Severity `json:"severity"`        // tunable
	MITRE       []string `json:"mitre,omitempty"` // MITRE ATT&CK technique IDs, e.g. "T1110.001"
	Query       string   `json:"query"`           // events to match, in the search syntax (internal/siem/query)
	Then        string   `json:"then,omitempty"`  // sequence: the closing event's query
	// GroupBy is the event field state is kept per: "ip", "actor", "app", "kind", "f.<name>", or ""
	// (one group for the whole rule).
	GroupBy      string        `json:"group_by,omitempty"`
	Field        string        `json:"field,omitempty"`     // distinct / new_value: the field whose values count (same names as GroupBy, plus "geo.cc", "geo.asn")
	Count        int           `json:"count,omitempty"`     // tunable
	Window       time.Duration `json:"window,omitempty"`    // tunable
	Factor       float64       `json:"factor,omitempty"`    // anomaly; tunable
	Learn        time.Duration `json:"learn,omitempty"`     // new_value / anomaly: watched this long before it can fire; tunable
	SpeedKMH     float64       `json:"speed_kmh,omitempty"` // travel; tunable
	Enabled      bool          `json:"enabled"`             // tunable
	Builtin      bool          `json:"builtin"`
	SnoozedUntil time.Time     `json:"snoozed_until,omitempty"` // tunable: detections are still recorded, but not sent to the alert channels before this
}

// Evidence is one event behind a detection (enough to find it with the search).
type Evidence struct {
	TS    time.Time `json:"ts"`
	Kind  string    `json:"kind"`
	IP    string    `json:"ip,omitempty"`
	Actor string    `json:"actor,omitempty"`
	App   string    `json:"app,omitempty"`
}

// Detection sources.
const (
	DetectionSIEM = "siem" // a rule over security events
	DetectionOps  = "ops"  // an app's own /ops alert (mooring.yaml ops_interface.alerts)
)

// MaxEvidence bounds Detection.Evidence.
const MaxEvidence = 10

// Detection is one firing of a rule for one key.
type Detection struct {
	ID       int64     `json:"id"` // assigned when stored
	Source   string    `json:"source"`
	RuleID   string    `json:"rule_id"` // ops: "ops:<app>/<service>/<alert name>"
	RuleName string    `json:"rule_name"`
	Severity Severity  `json:"severity"`
	MITRE    []string  `json:"mitre,omitempty"`
	Key      string    `json:"key,omitempty"` // the GroupBy value: an IP, an actor (a keyed hash when personal data) …
	App      string    `json:"app,omitempty"` // the app it concerns, when it concerns one (ops: always)
	Service  string    `json:"service,omitempty"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	Count    int       `json:"count"`
	// Summary is one line for the page and the alert message: no secrets, no message text; IPs and
	// (hashed) actors only. At most 300 bytes.
	Summary  string     `json:"summary"`
	Geo      *Geo       `json:"geo,omitempty"`
	Evidence []Evidence `json:"evidence,omitempty"` // at most MaxEvidence
	Snoozed  bool       `json:"snoozed,omitempty"`  // the rule was snoozed: recorded, not sent
}

// Reporter takes detections from a source that evaluates its own condition (the app /ops alerts).
// The rule engine stores each one, emits it as a security event, and alerts on high/critical. It
// must not block.
type Reporter interface {
	Report(d Detection)
}

// DetectionFilter selects detections for the page, most recently seen first (Last, then ID, both
// descending). From/To bound Last.
type DetectionFilter struct {
	From, To    time.Time // zero: unbounded
	RuleID      string    // "": any
	MinSeverity Severity  // "": any
	App         string    // "": any
	// Keyset paging: with BeforeLast set, only detections last seen before BeforeLast, or at it with
	// an ID below Before (the last row of the previous page). Zero BeforeLast: from the newest.
	BeforeLast time.Time
	Before     int64
	Limit      int // 1–200 (default 50)
}

// ErrInvalidRule is wrapped by every validation error DetectionService.SaveRule returns; such an
// error's message describes the problem and is safe to show the owner. Any other error is internal.
var ErrInvalidRule = errors.New("invalid rule")

// DetectionService is what the owner-only dashboard pages use.
type DetectionService interface {
	Rules(ctx context.Context) ([]Rule, error) // the pack merged with overrides, then custom rules
	// SaveRule validates and stores a rule. For a built-in rule only the tunable fields are taken
	// from r; a custom rule is stored whole (ID "custom.<slug>", slug ^[a-z0-9][a-z0-9-]{0,47}$, at
	// most 100 custom rules).
	SaveRule(ctx context.Context, r Rule) error
	DeleteRule(ctx context.Context, id string) error // custom rules only
	ResetRule(ctx context.Context, id string) error  // built-in rules only: back to the pack's values
	Detections(ctx context.Context, f DetectionFilter) ([]Detection, error)
	Detection(ctx context.Context, id int64) (Detection, bool, error)
}

// FeedStatus is one enrichment feed's state (GeoIP databases, threat-intel lists), for the page.
type FeedStatus struct {
	Name      string    `json:"name"` // "dbip-city", "dbip-asn", "spamhaus-drop", "tor-exits", "dshield"
	Enabled   bool      `json:"enabled"`
	Version   string    `json:"version,omitempty"` // e.g. "2026-11" for DB-IP, the list's own date otherwise
	Updated   time.Time `json:"updated,omitempty"` // when the file in use was fetched
	Entries   int       `json:"entries,omitempty"`
	LastError string    `json:"last_error,omitempty"`
	NextTry   time.Time `json:"next_try,omitempty"`
}

// FeedStatusSource reports the feeds' state.
type FeedStatusSource interface {
	FeedStatus() []FeedStatus
}
