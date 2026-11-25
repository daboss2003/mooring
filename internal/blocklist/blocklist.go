// Package blocklist is the managed edge's block list: addresses and ranges the edge answers 403
// (and, with security_logs.blocking.l4, L4 `forward: proxy` listeners refuse), each for a time.
// Automated response (internal/siem/respond) places automatic blocks; owners place manual ones on
// the dashboard. It works with security logs off. The list is kept in mooring.db (migration
// 0043_edge_blocks.sql) and published to the edge as an immutable snapshot.
package blocklist

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/store"
)

// Block sources.
const (
	SourceAuto   = "auto"   // automated response
	SourceManual = "manual" // an owner on the dashboard
)

// Block states.
const (
	StateActive    = "active"    // in force: published to the edge
	StateSuspended = "suspended" // in force by time, but now covered by a protected address (SuspendedWhy): not published
	StateExpired   = "expired"   // its time ran out
	StateRemoved   = "removed"   // lifted early (RemovedBy)
)

// Refusal codes: fixed words, safe to show the owner (RefusedError.Code, Refusal.Code).
const (
	RefuseInvalid    = "invalid"       // not an address or CIDR
	RefuseWidth      = "width"         // manual: wider than /24 (IPv4) or /48 (IPv6); automatic: not a single IPv4 address or an IPv6 /64
	RefuseNoEdge     = "no_edge"       // Mooring doesn't run the edge (edge.mode external)
	RefuseOldCaddy   = "old_caddy"     // automatic: the running Caddy can't refuse 0-RTT (needs 2.11 or later)
	RefuseAllowlist  = "allowlist"     // overlaps ip_allowlist
	RefuseTokenCIDR  = "token_cidr"    // overlaps an API token's allowed CIDRs
	RefuseProxy      = "trusted_proxy" // overlaps edge.trusted_proxies or trusted_proxies
	RefuseCDN        = "cdn"           // overlaps a CDN's published ranges
	RefuseLocal      = "local"         // loopback, private, link-local, shared (CGNAT), multicast, unspecified, or this server's own address
	RefuseNeverBlock = "never_block"   // overlaps security_logs.blocking.never_block
	RefuseSession    = "session"       // covers the address of a signed-in dashboard session
	RefuseSelf       = "self"          // manual: covers the requesting owner's own address
	RefuseExempt     = "exempt"        // automatic: an owner unblocked it, or its incident was a false positive, recently
	RefuseFull       = "full"          // the active blocks of its source are at their cap
	RefuseDuration   = "duration"      // a duration outside the allowed range
)

// Limits.
const (
	MaxManual          = 1000                // active manual blocks
	ManualIPv4Bits     = 24                  // the widest manual IPv4 range
	ManualIPv6Bits     = 48                  // the widest manual IPv6 range
	MinDuration        = 5 * time.Minute     // the shortest block
	RenewAhead         = 2 * time.Minute     // an automatic request this close to an automatic block's end is a repeat
	RepeatWindow       = 30 * 24 * time.Hour // automatic blocks of a prefix within this escalate
	RepeatFactor       = 4                   // each repeat's automatic block is this many times longer
	ExemptAfterUnblock = 24 * time.Hour      // an owner's unblock exempts the prefix (and the addresses inside it) from automatic blocks this long
)

// Request is one block to place.
type Request struct {
	// Prefix: automatic, a single IPv4 address or an IPv6 /64 ("2001:db8:1:2::/64", the SIEM's
	// address key); manual, an address or a CIDR up to /24 (IPv4) or /48 (IPv6). A bare address is
	// a /32 or /128; IPv4-mapped IPv6 is IPv4.
	Prefix string
	Source string // SourceAuto or SourceManual
	// Duration: automatic, the first block's length (a repeat within RepeatWindow is RepeatFactor
	// times longer than the previous automatic block was placed for, up to Options.MaxAutoDuration;
	// extensions and manual blocks don't count, and an owner's unblock or a false positive starts
	// the prefix over); manual, MinDuration to Options.ManualMaxDuration.
	Duration    time.Duration
	RuleID      string // automatic: the rule
	Reason      string // shown on the page (≤ 300 bytes, no secrets)
	By          string // manual: the owner
	Self        string // manual: the requesting owner's own address (refused when covered)
	DetectionID int64
	IncidentID  int64
	ResponseID  int64
}

// Block is one entry of the list.
type Block struct {
	Prefix       netip.Prefix
	Source       string
	RuleID       string
	Reason       string
	By           string
	DetectionID  int64
	IncidentID   int64
	ResponseID   int64
	Created      time.Time
	Until        time.Time
	Hits         int // automatic blocks of this prefix within RepeatWindow (this one included when it is automatic)
	State        string
	SuspendedWhy string // StateSuspended: a Refuse* code
	RemovedBy    string
	RemovedAt    time.Time
	ExemptUntil  time.Time // no automatic block of it before this

	// The prefix's last automatic block: the length it was placed with (the ladder step a repeat
	// multiplies; an extension doesn't change it) and when. Zero: none within RepeatWindow.
	autoStep time.Duration
	autoAt   time.Time
}

// Refusal is a refused block, coalesced per (prefix, code).
type Refusal struct {
	Prefix string
	Code   string
	Detail string
	Source string
	RuleID string
	Count  int
	First  time.Time
	Last   time.Time
}

// RefusedError is returned by Block for a refused request (also recorded as a Refusal).
type RefusedError struct {
	Code   string
	Detail string // safe to show
}

func (e *RefusedError) Error() string { return "block refused: " + e.Code + ": " + e.Detail }

// ErrNotFound is returned by Unblock for a prefix with no block in force.
var ErrNotFound = errors.New("no such block")

// Status is the list's state for the page.
type Status struct {
	EdgeOwned    bool
	Automatic    bool   // automatic blocks can be placed (edge owned, Caddy ≥ 2.11)
	AutomaticWhy string // why not, when they can't (a Refuse* code's explanation)
	L4           bool   // also published to L4 proxy listeners (security_logs.blocking.l4 is on and Mooring runs the L4 load balancer)
	L4Why        string // why not, when security_logs.blocking.l4 is on and no L4 load balancer takes the list (SetL4)
	ActiveAuto   int
	ActiveManual int
	MaxAuto      int
	MaxManual    int
	Applied      bool      // the current list is what the edge serves
	ApplyErr     string    // the last apply's error ("" when it worked)
	LastApplied  time.Time // when the edge last took the list
}

// Filter selects blocks for the page, newest first.
type Filter struct {
	States     []string // empty: any
	Source     string   // "": any
	IncidentID int64    // 0: any
	Limit      int      // 1–1000 (default 100)
}

// Service is what the dashboard and the responder use.
type Service interface {
	// Block places (or extends) a block; a refusal is a *RefusedError, recorded as a Refusal.
	Block(ctx context.Context, r Request) (Block, error)
	// Unblock lifts the block in force for prefix (ErrNotFound when none), exempts the prefix and
	// the addresses inside it from automatic blocks for ExemptAfterUnblock, and clears its repeat
	// history.
	Unblock(ctx context.Context, prefix netip.Prefix, by string) error
	// UnblockIncident lifts the automatic blocks placed for incident id, exempts their prefixes
	// from automatic blocks for exempt and clears their repeat history; it returns how many were
	// lifted.
	UnblockIncident(ctx context.Context, id int64, by string, exempt time.Duration) (int, error)
	// LiftAutomatic lifts every automatic block in force (automated response switched off).
	LiftAutomatic(ctx context.Context, by, why string) (int, error)
	List(ctx context.Context, f Filter) ([]Block, error)
	Get(ctx context.Context, prefix netip.Prefix) (Block, bool, error)
	Refusals(ctx context.Context, limit int) ([]Refusal, error)
	// Blocked reports whether a is covered by a block in force (in memory, no I/O).
	Blocked(a netip.Addr) bool
	Status() Status
}

// Guard are the addresses never blocked, besides the built-in ones (loopback, private, link-local,
// shared, multicast, unspecified, and this server's own interface addresses, read from /proc).
// Each func is called at request and publish time; nil means none.
type Guard struct {
	Allowlist  func() []netip.Prefix                  // the live ip_allowlist
	TokenCIDRs func() []netip.Prefix                  // the union of active API tokens' CIDRs
	Proxies    []netip.Prefix                         // edge.trusted_proxies and trusted_proxies
	CDN        []netip.Prefix                         // CDN ranges Mooring knows (edge.CDNRanges)
	Configured []netip.Prefix                         // security_logs.blocking.never_block
	Sessions   func(ctx context.Context) []netip.Addr // signed-in dashboard sessions' addresses
}

// Alerter queues an alert (the alert store's EnqueueInfra). When it also has the alert store's
// OpenInfraAlerts, Open reads which of the list's alerts were open before the restart, so they are
// resolved (and not raised a second time).
type Alerter interface {
	EnqueueInfra(ctx context.Context, o alert.Outbox) error
}

// openAlerts is the alert store's OpenInfraAlerts: the dedupe keys of kind whose alert is open.
type openAlerts interface {
	OpenInfraAlerts(ctx context.Context, kind string) (map[string]string, error)
}

// Options configures the list.
type Options struct {
	DB        *store.DB
	Guard     Guard
	EdgeOwned bool // false: every block is refused (RefuseNoEdge)
	// CaddyOK reports whether the running Caddy can refuse QUIC 0-RTT (2.11 or later); while it
	// can't, automatic blocks are refused (RefuseOldCaddy). nil: it can.
	CaddyOK           func() (ok bool, why string)
	MaxAuto           int           // security_logs.blocking.max_entries
	MaxAutoDuration   time.Duration // security_logs.response.max_block_duration
	ManualMaxDuration time.Duration // security_logs.blocking.manual_max_duration
	L4                bool          // security_logs.blocking.l4 (SetL4 says whether an L4 load balancer runs)
	Alerter           Alerter       // nil: no alerts
	Emit              func(siem.Event) bool
	Log               *slog.Logger
	Now               func() time.Time
}

// Blocker implements Service. Its methods write mooring.db: never call one while holding a
// *sql.Tx or open *sql.Rows of the same database.
type Blocker struct {
	o            Options
	db           *store.DB
	log          *slog.Logger
	now          func() time.Time
	maxAuto      int
	maxAutoDur   time.Duration
	manualMaxDur time.Duration
	static       staticGuard

	// wmu serializes changes: each one's guard check and database write, then its memory update.
	// Guard funcs and database I/O run under wmu, never under mu.
	wmu sync.Mutex

	mu      sync.Mutex // the fields below; never held across I/O or a callback
	inForce map[netip.Prefix]Block
	// ready: Run's first step has begun, so the guard is complete (the dashboard gives it the API
	// tokens' CIDRs and the sessions). Until then a block saved as suspended stays suspended.
	ready bool
	// unsaved are the blocks whose suspended state changed in memory and isn't in the database yet.
	unsaved map[netip.Prefix]struct{}
	// sweptTo is the latest time a sweep dropped the expired blocks at (wall clock): a clock before
	// it stepped back, and blocks dropped from memory may be in force again.
	sweptTo time.Time
	l4Off   bool    // SetL4: no L4 load balancer takes the list
	l4Why   string  // why
	live    *pubSet // what the edge should serve now; released (pub) at most once a minute
	ver     uint64
	apply   func(ctx context.Context) error
	ap      applyState
	alerts  alertState
	next    schedule

	pub  atomic.Pointer[pubSet]         // released: Snapshot, L4Snapshot, Blocked
	self atomic.Pointer[[]netip.Prefix] // this server's own addresses

	oddMu sync.Mutex
	odd   map[string]struct{} // guard entries already logged as not canonical (canonGuard)

	wake   chan struct{}
	runMu  sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
	closed bool
}

var _ Service = (*Blocker)(nil)

// Defaults for unset Options (the config layer's defaults).
const (
	defaultMaxAuto           = 1000
	defaultMaxAutoDuration   = 24 * time.Hour
	defaultManualMaxDuration = 30 * 24 * time.Hour
)

// Open reads the blocks in force from the database and publishes those that weren't suspended when
// last saved and that the guard as it is now doesn't cover (an expired one is never published).
// Intentional: a block saved as suspended is not re-checked here but on Run's first step. The guard
// isn't complete before the dashboard exists (no API token CIDRs, no sessions), so re-checking now
// would serve a block of a protected address until Run starts.
func Open(ctx context.Context, o Options) (*Blocker, error) {
	if o.DB == nil {
		return nil, errors.New("blocklist: no database")
	}
	b := &Blocker{o: o, db: o.DB, log: o.Log, now: o.Now, maxAuto: o.MaxAuto, maxAutoDur: o.MaxAutoDuration,
		manualMaxDur: o.ManualMaxDuration, wake: make(chan struct{}, 1)}
	if b.log == nil {
		b.log = slog.New(slog.DiscardHandler)
	}
	b.static = staticGuard{proxies: b.canonGuard("trusted proxy", o.Guard.Proxies), cdn: b.canonGuard("CDN range", o.Guard.CDN),
		configured: b.canonGuard("never_block", o.Guard.Configured)}
	if b.now == nil {
		b.now = time.Now
	}
	if b.maxAuto <= 0 {
		b.maxAuto = defaultMaxAuto
	}
	if b.maxAutoDur <= 0 {
		b.maxAutoDur = defaultMaxAutoDuration
	}
	if b.manualMaxDur <= 0 {
		b.manualMaxDur = defaultManualMaxDuration
	}
	b.maxAutoDur, b.manualMaxDur = max(b.maxAutoDur, MinDuration), max(b.manualMaxDur, MinDuration)
	b.refreshSelf()
	now := b.now()
	in, err := b.loadInForce(ctx, now)
	if err != nil {
		return nil, err
	}
	prot := b.protected(ctx)
	b.adoptAlerts(ctx)
	b.mu.Lock()
	b.inForce = in
	_ = b.rebuildLocked(prot, now) // Intentional: no suspended events at start (the pipeline they go to doesn't exist yet)
	b.pub.Store(b.live)
	b.mu.Unlock()
	b.saveSuspended(ctx)
	return b, nil
}

// SetL4 says whether an L4 load balancer takes the list: with security_logs.blocking.l4 on and no
// L4 load balancer running (edge.l4_enabled off, or nginx with the stream module missing), Status
// reports L4 false and why. Not calling it means one runs.
func (b *Blocker) SetL4(on bool, why string) {
	b.mu.Lock()
	b.l4Off, b.l4Why = !on, clean(why, maxDetail)
	b.mu.Unlock()
}
