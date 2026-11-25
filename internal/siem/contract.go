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
	// RuleBaseline learns each GroupBy key's normal behaviour and fires on a departure from it;
	// Baseline names what it learns (Baseline* below). Built-in rules only.
	RuleBaseline = "baseline"
)

// Baseline kinds (Rule.Baseline).
const (
	BaselineSignIn  = "signin"  // per account: usual sign-in hours of the week, countries, networks (ASN), clients
	BaselineTraffic = "traffic" // per edge host with a route: requests and errors per hour of the week vs previous weeks
	BaselineAdmin   = "admin"   // per server user: usual sudo/su hours, programs and target users
	BaselineIP      = "ip"      // per address: its usual request mix
	// BaselinePattern (phase 4): per app service (and the host), the templates its log lines fall
	// into and each template's hourly count; fires on a new template or a spike of a known one.
	BaselinePattern = "pattern"
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
	Baseline     string        `json:"baseline,omitempty"`      // RuleBaseline: one of the Baseline* kinds
	// Response (phase 4, tunable) is what automated response does about the rule's detections when
	// it is on (security_logs.response.mode recommend or enforce). Zero value: nothing.
	Response RuleResponse `json:"response"`
}

// Evidence is one event behind a detection (enough to find it with the search).
type Evidence struct {
	TS    time.Time `json:"ts"`
	Kind  string    `json:"kind"`
	IP    string    `json:"ip,omitempty"`
	Actor string    `json:"actor,omitempty"`
	App   string    `json:"app,omitempty"`
	// Browser: the request carried browser fetch metadata (an edge event with f.fetch_site), so a
	// browser sent it. A web page can make its visitors' browsers send requests anywhere; such
	// requests never count toward an automatic block.
	Browser bool `json:"browser,omitempty"`
	// BrowserAgent: an edge request whose User-Agent is a browser's or a mail client's (they fetch
	// what a page or an email tells them to) without fetch metadata.
	BrowserAgent bool `json:"browser_agent,omitempty"`
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
	Muted    bool       `json:"muted,omitempty"`    // a false-positive mute for this rule and entity: recorded, no alert, no incident
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
	Key         string    // "": any; otherwise exactly this key (a pattern's ID, an address …)
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

// Incidents (phase 3): related detections of one entity grouped, with a timeline and a workflow.

// Incident states.
const (
	IncidentOpen          = "open"
	IncidentAcknowledged  = "acknowledged"
	IncidentResolved      = "resolved"
	IncidentFalsePositive = "false_positive"
)

// Entity kinds.
const (
	EntityAccount = "account" // an actor: a Mooring user, an app account (often a keyed hash), a server user
	EntityAddress = "address" // an IP address (IPv6 as its /64)
)

// Entity is what incidents and risk are kept per. Scope separates accounts of different systems
// ("mooring", "host", "app:<slug>"; "" for an address), so a server user alice isn't app account alice.
type Entity struct {
	Kind  string `json:"kind"`
	Key   string `json:"key"`
	Scope string `json:"scope,omitempty"`
}

// Incident timeline entry kinds.
const (
	TimelineOpened    = "opened"
	TimelineDetection = "detection"
	TimelineEscalated = "escalated"
	TimelineState     = "state"
	TimelineAssigned  = "assigned"
	TimelineNote      = "note"
	TimelineMuted     = "muted"
	TimelineResponse  = "response" // an automated response about it (Text: what was done, or why not)
)

// IncidentEvent is one entry of an incident's timeline.
type IncidentEvent struct {
	TS          time.Time `json:"ts"`
	Kind        string    `json:"kind"`                   // a Timeline* kind
	DetectionID int64     `json:"detection_id,omitempty"` // detection entries
	RuleID      string    `json:"rule_id,omitempty"`
	RuleName    string    `json:"rule_name,omitempty"`
	Severity    Severity  `json:"severity,omitempty"`
	Actor       string    `json:"actor,omitempty"` // who did it (state, assigned, note, muted); "" for Mooring
	Text        string    `json:"text,omitempty"`  // the summary, the new state, the assignee, the note (≤ MaxNote)
}

// MaxNote bounds a note's text (bytes).
const MaxNote = 4 << 10

// Incident is related detections of one or more entities, most often one account or address.
type Incident struct {
	ID         int64     `json:"id"`
	State      string    `json:"state"`           // an Incident* state
	Severity   Severity  `json:"severity"`        // the highest detection's, raised for a known chain
	Title      string    `json:"title"`           // one line, like a detection summary (≤ 300 bytes)
	Chain      string    `json:"chain,omitempty"` // the name of the known chain it matched ("" for none)
	Entities   []Entity  `json:"entities"`
	First      time.Time `json:"first"`
	Last       time.Time `json:"last"`
	Detections int       `json:"detections"`      // detections in it
	Rules      []string  `json:"rules,omitempty"` // rule IDs in it (≤ 20)
	Assignee   string    `json:"assignee,omitempty"`
	Updated    time.Time `json:"updated"`
	// Timeline is filled by IncidentService.Incident only, oldest first (≤ 500 entries).
	Timeline []IncidentEvent `json:"timeline,omitempty"`
	// Mutes is filled by IncidentService.Incident only: the false-positive mutes this incident made
	// that are still in force.
	Mutes []Mute `json:"mutes,omitempty"`
}

// IncidentFilter selects incidents for the page, most recently active first (Last, then ID, both
// descending), keyset-paged like DetectionFilter.
type IncidentFilter struct {
	States      []string  // empty: any
	MinSeverity Severity  // "": any
	Entity      *Entity   // nil: any
	Assignee    string    // "": any
	BeforeLast  time.Time // keyset paging with Before (zero: from the newest)
	Before      int64
	Limit       int // 1–200 (default 50)
}

// RiskScore is an entity's current risk: it rises with each detection (by severity) and fades over
// days.
type RiskScore struct {
	Entity        Entity    `json:"entity"`
	Score         float64   `json:"score"` // 0–100
	Updated       time.Time `json:"updated"`
	OpenIncidents int       `json:"open_incidents"`
}

// Mute is a false-positive mute: the rule's detections for the entity are still recorded (marked
// muted) but alert nothing and open no incident until Until.
type Mute struct {
	RuleID     string    `json:"rule_id"`
	Entity     Entity    `json:"entity"`
	Until      time.Time `json:"until"`
	By         string    `json:"by"`
	IncidentID int64     `json:"incident_id,omitempty"`
	Created    time.Time `json:"created"`
}

// ErrInvalidInput is wrapped by every validation error IncidentService returns; such an error's
// message describes the problem and is safe to show the owner. Any other error is internal.
var ErrInvalidInput = errors.New("invalid input")

// IncidentService is what the owner-only Incidents and entity pages use. Every method that changes
// something takes the acting user (actor) and records the change in the incident's timeline.
type IncidentService interface {
	Incidents(ctx context.Context, f IncidentFilter) ([]Incident, error)
	Incident(ctx context.Context, id int64) (Incident, bool, error) // with its Timeline
	// SetState moves an incident to open, acknowledged or resolved (not false_positive: see
	// MarkFalsePositive); note ("" for none) is added to the timeline.
	SetState(ctx context.Context, id int64, state, actor, note string) error
	Assign(ctx context.Context, id int64, assignee, actor string) error // "" unassigns; assignee must be a Mooring user (the caller checks)
	AddNote(ctx context.Context, id int64, actor, text string) error    // text 1–MaxNote bytes
	// MarkFalsePositive sets the false_positive state; with mute, every (rule, entity) pair of the
	// incident is muted for 30 days.
	MarkFalsePositive(ctx context.Context, id int64, actor string, mute bool, note string) error
	Entity(ctx context.Context, e Entity) (RiskScore, []Incident, []Mute, error) // the entity page
	RemoveMute(ctx context.Context, ruleID string, e Entity, actor string) error
	Risky(ctx context.Context, limit int) ([]RiskScore, error) // the highest-risk entities, 1–100
}

// Log patterns (phase 4): the templates an app service's log lines (and the host's unclassified
// lines) fall into, learned per scope; the pattern.* rules (RuleBaseline, BaselinePattern) fire on
// a template first seen after its scope's learning period and on a spike of a known one.

// Pattern states.
const (
	PatternLearned  = "learned"  // seen while its scope was learning, or put back to watching by the owner
	PatternNew      = "new"      // first seen after its scope's learning period (reported by pattern.new)
	PatternExpected = "expected" // the owner marked it normal: pattern.new and pattern.spike stay silent for it
	PatternIgnored  = "ignored"  // the owner switched its spikes off: pattern.spike stays silent for it
)

// MaxPatternText bounds Pattern.Template and Pattern.Sample (bytes).
const MaxPatternText = 512

// Pattern is one log template of one scope.
type Pattern struct {
	ID      string `json:"id"`    // "p" + 16 lowercase hex, stable for (scope, template)
	Scope   string `json:"scope"` // "app:<slug>/<service>" or "host"
	App     string `json:"app,omitempty"`
	Service string `json:"service,omitempty"`
	// Template is the masked token sequence: variable parts are <NUM>, <HEX>, <UUID>, <IP>, <TS>,
	// <HASH>, <B64>, <STR>, <LONG> or <*>. Built from redacted text only. At most MaxPatternText.
	Template string `json:"template"`
	// Sample is one redacted line of it, kept until the security logs' hot_retention after it was
	// seen; Pattern only (not Patterns). At most MaxPatternText.
	Sample string    `json:"sample,omitempty"`
	Level  string    `json:"lvl,omitempty"` // the highest level seen (an event Lvl)
	State  string    `json:"state"`         // a Pattern* state
	First  time.Time `json:"first"`
	Last   time.Time `json:"last"`
	Count  int64     `json:"count"` // lines since First
	// Hourly is lines per hour for the last 168 hours, oldest first; Pattern only.
	Hourly []uint32 `json:"hourly,omitempty"`
}

// PatternFilter selects patterns for the page. Sort "last" (default: most recently seen first),
// "count" (most lines in the last 24 hours first) or "first" (newest first).
type PatternFilter struct {
	App      string   // "": any
	Service  string   // "": any (with App)
	Host     bool     // only the host's patterns (App must be "")
	States   []string // empty: any
	MinLevel string   // "": any; otherwise an event Lvl ("warn", "error" …)
	Sort     string
	Offset   int
	Limit    int // 1–200 (default 50)
}

// PatternStats is the miner's state for the page header.
type PatternStats struct {
	Enabled    bool     `json:"enabled"`
	Scopes     int      `json:"scopes"`
	Patterns   int      `json:"patterns"`
	Lines      int64    `json:"lines"`              // lines mined since start
	Unmined    int64    `json:"unmined"`            // lines counted only (over the CPU budget, or a scope's new-template cap)
	Dropped    int64    `json:"dropped"`            // lines not taken (the miner's queue was full)
	Overflowed int64    `json:"overflowed"`         // lines past a scope's template cap
	BudgetPct  float64  `json:"budget_pct"`         // share of the CPU budget used in the last minute (0–100)
	Learning   []string `json:"learning,omitempty"` // scopes still in their learning period (at most 50)
}

// PatternService is what the owner-only Patterns pages use.
type PatternService interface {
	Patterns(ctx context.Context, f PatternFilter) ([]Pattern, error)
	Pattern(ctx context.Context, id string) (Pattern, bool, error) // with Sample and Hourly
	// SetPatternState sets expected, ignored or learned (watch again); ErrInvalidInput for another
	// state or an unknown pattern. actor is recorded by the caller's audit event.
	SetPatternState(ctx context.Context, id, state, actor string) error
	PatternStats() PatternStats
}

// Automated response (phase 4): blocking a detection's address at the edge, or signing a Mooring
// account out of every session, decided per rule (Rule.Response) and applied by the responder
// (internal/siem/respond) according to security_logs.response.mode.

// Response actions.
const (
	ResponseBlock  = "block"  // block the detection's address at the edge for a time
	ResponseRevoke = "revoke" // sign the Mooring account out of every session
)

// RuleResponse is a rule's response. The zero value is none.
type RuleResponse struct {
	Action string `json:"action,omitempty"` // "", ResponseBlock or ResponseRevoke
	// Duration: block only, the first block's length (5m–7d); a repeat within 30 days blocks four
	// times as long, up to security_logs.response.max_block_duration. Revoke: 0.
	Duration time.Duration `json:"duration,omitempty"`
}

// Response modes (security_logs.response.mode).
const (
	ResponseModeOff       = "off"       // no responses (default)
	ResponseModeRecommend = "recommend" // responses are recorded as recommendations for the owner to apply
	ResponseModeEnforce   = "enforce"   // automatic responses are applied; recommend-only ones are recorded
)

// Response states.
const (
	ResponseRecommended = "recommended" // waiting for the owner (recommend mode, or recommend-only)
	ResponseApplied     = "applied"     // done: the block was placed / the sessions were revoked
	ResponseRefused     = "refused"     // not done; Reason says why (a protected address, a cap …)
	ResponseFailed      = "failed"      // tried and failed; Reason says why
	ResponseDismissed   = "dismissed"   // the owner dismissed the recommendation
	ResponseExpired     = "expired"     // a recommendation nobody acted on within 7 days
)

// ResponseRequest is one response the rule engine asks for, after the detection was stored.
type ResponseRequest struct {
	Action string
	// Target: block, the detection's address key (an IPv4 address, or an IPv6 /64 such as
	// "2001:db8:1:2::/64"); revoke, the Mooring account as the event stored it (the actor: the
	// username, or its keyed hash when the username is personal data).
	Target    string
	Duration  time.Duration // block: the rule's first-block length
	Automatic bool          // may be applied without the owner (enforce); false: recommend only
	RuleID    string
	RuleName  string
	Severity  Severity
	// DetectionID is 0 when the detection couldn't be stored; IncidentID 0 when it joined none.
	DetectionID int64
	IncidentID  int64
	Summary     string // the detection's summary (no secrets, no message text)
	At          time.Time
}

// Responder takes the rule engine's response requests. It must not block (false: not taken).
type Responder interface {
	Respond(r ResponseRequest) bool
}

// Response is one recorded response.
type Response struct {
	ID     int64  `json:"id"`
	Action string `json:"action"`
	// Target: block, the canonical prefix ("203.0.113.7/32", "2001:db8:1:2::/64"); revoke, the
	// Mooring username.
	Target      string        `json:"target"`
	State       string        `json:"state"`            // a Response* state
	Reason      string        `json:"reason,omitempty"` // refused / failed: a fixed code
	Automatic   bool          `json:"automatic"`
	RuleID      string        `json:"rule_id,omitempty"`
	DetectionID int64         `json:"detection_id,omitempty"`
	IncidentID  int64         `json:"incident_id,omitempty"`
	Summary     string        `json:"summary,omitempty"`
	Duration    time.Duration `json:"duration,omitempty"` // block: as applied (after a repeat's escalation)
	Created     time.Time     `json:"created"`
	Updated     time.Time     `json:"updated"`
	By          string        `json:"by,omitempty"` // the owner who applied or dismissed it ("" for Mooring)
}

// ResponseFilter selects responses for the page, newest first (ID descending), keyset-paged.
type ResponseFilter struct {
	States      []string // empty: any
	Action      string   // "": any
	IncidentID  int64    // 0: any
	DetectionID int64    // 0: any
	Before      int64    // 0: from the newest; otherwise IDs below it
	Limit       int      // 1–200 (default 50)
}

// ResponseStatus is the responder's state for the page header.
type ResponseStatus struct {
	Mode      string    `json:"mode"`                // security_logs.response.mode
	Paused    string    `json:"paused,omitempty"`    // "" or the dashboard pause: ResponseModeRecommend / ResponseModeOff
	PausedBy  string    `json:"paused_by,omitempty"` // who paused
	PausedAt  time.Time `json:"paused_at,omitempty"`
	Effective string    `json:"effective"` // the lower of Mode and Paused
	// This hour's automatic actions against their caps (security_logs.response.max_*_per_hour).
	BlocksThisHour    int  `json:"blocks_this_hour"`
	MaxBlocksPerHour  int  `json:"max_blocks_per_hour"`
	RevokesThisHour   int  `json:"revokes_this_hour"`
	MaxRevokesPerHour int  `json:"max_revokes_per_hour"`
	Revoker           bool `json:"revoker"` // false: session revokes are refused (not wired yet)
}

// ResponseService is what the owner-only Responses page uses. Every method that changes something
// takes the acting user (actor).
type ResponseService interface {
	Status(ctx context.Context) (ResponseStatus, error)
	Responses(ctx context.Context, f ResponseFilter) ([]Response, error)
	Response(ctx context.Context, id int64) (Response, bool, error)
	// Apply applies a recommended response now (ErrInvalidInput when it isn't one); a refusal is
	// returned as an error whose message is safe to show and recorded on the response.
	Apply(ctx context.Context, id int64, actor string) error
	Dismiss(ctx context.Context, id int64, actor string) error // a recommended one
	// SetPause lowers what responses do until lifted: "" lifts it, ResponseModeRecommend records
	// recommendations only, ResponseModeOff also removes every automatic block now. It can never
	// raise the configured mode.
	SetPause(ctx context.Context, level, actor string) error
	// LiftForIncident: the incident was marked a false positive. Its automatic blocks are removed
	// and their addresses exempt from automatic blocks for 30 days; returns how many were removed.
	LiftForIncident(ctx context.Context, incidentID int64, actor string) (int, error)
}

// ErrBlocksNotLifted is wrapped by the error ResponseService.SetPause returns when the pause WAS
// stored and is in force, but removing the automatic blocks (level off) failed; the responder
// retries the removal by itself.
var ErrBlocksNotLifted = errors.New("the automatic blocks were not removed yet")

// ErrUnknownAccount is returned by an AccountRevoker for an actor that is no Mooring user.
var ErrUnknownAccount = errors.New("unknown account")

// AccountRevoker signs Mooring accounts out (the dashboard implements it).
type AccountRevoker interface {
	// Revoke signs the account stored as actor (the username, or its keyed hash) out of every
	// session; it returns the username and how many sessions ended. When several users are stored
	// as that actor (email usernames differing only in case), all are signed out and username lists
	// them, comma-separated.
	Revoke(ctx context.Context, actor string) (username string, sessions int64, err error)
}

// RuleResponder is implemented by the DetectionService: which response actions a rule may take
// (for the rule page), or why it may take none.
type RuleResponder interface {
	RuleResponses(r Rule) (actions []string, why string)
}
