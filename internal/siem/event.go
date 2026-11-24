// Package siem holds the types shared by the security-log pipeline (docs/security-logs.md): the
// normalized event every source is converted to, its bounds, and the status the dashboard shows.
// The packages under it do the work: parse (source lines → Event), redact (secrets and personal
// data), hostlog (host auth logs), store (on-box segments and the security database), query (the
// search syntax), archive (encrypted S3 copies) and pipeline (the bounded queue that ties them).
//
// The JSON form of Event is schema version 1. It is written to the on-box segments and the S3
// archive and read back by search and `mooring security-logs`, so a field is never renamed or
// re-typed under the same version: add fields, or bump SchemaVersion.
package siem

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"math"
	"strings"
	"time"
)

// SchemaVersion is the version of Event's JSON form (the "v" field).
const SchemaVersion = 1

// Sources (Event.Src).
const (
	SrcApp     = "app"     // an app container's stdout/stderr
	SrcEdge    = "edge"    // the Caddy edge's access log
	SrcMooring = "mooring" // Mooring's own audit events
	SrcHost    = "host"    // the host's auth/sudo/sshd/Fail2Ban logs
	SrcSIEM    = "siem"    // the pipeline itself (dropped events, archive failures)
)

// Levels (Event.Lvl), lowest to highest.
const (
	LvlDebug    = "debug"
	LvlInfo     = "info"
	LvlWarn     = "warn"
	LvlError    = "error"
	LvlCritical = "critical"
)

// LevelRank orders levels for comparisons (lvl>=warn); an unknown level ranks as info.
func LevelRank(l string) int {
	switch l {
	case LvlDebug:
		return 0
	case LvlWarn:
		return 2
	case LvlError:
		return 3
	case LvlCritical:
		return 4
	}
	return 1
}

// Outcomes (Event.Out).
const (
	OutSuccess = "success"
	OutFailure = "failure"
)

// Kinds (Event.Kind) are dot.case names. An app line names its own kind in an `event` field (see
// parse.AppLine); a line without one is KindLog. The host and Mooring kinds are fixed here.
const (
	KindLog         = "log"          // unclassified output
	KindHTTPRequest = "http.request" // one edge access log line

	KindSSHLogin       = "ssh.login"        // Out success/failure; F: method (password|publickey|keyboard-interactive), user, key_fp, port
	KindSSHInvalidUser = "ssh.invalid_user" // F: user
	KindSSHDisconnect  = "ssh.disconnect"   // F: user, reason (pre-auth disconnects, "Too many authentication failures")
	KindSudo           = "sudo.command"     // Out success/failure; F: user, target_user, command, tty, reason
	KindSu             = "su.session"       // Out success/failure; F: user, target_user
	KindUserChange     = "host.user_change" // useradd/usermod/passwd/groupadd lines; F: program, user, detail
	KindFail2BanBan    = "fail2ban.ban"     // F: jail
	KindFail2BanUnban  = "fail2ban.unban"   // F: jail

	KindMooringPrefix = "mooring." // + the audit action, e.g. mooring.login, mooring.env_set_secret

	KindDropped       = "siem.dropped"        // F: source, count, reason (store drops: disk|error) — events dropped or lost
	KindArchiveFailed = "siem.archive_failed" // F: segment, error
)

// Bounds applied by Event.Normalize (and so to every stored event).
const (
	MaxMsg        = 8 << 10 // bytes of Msg
	MaxFields     = 64      // keys in F
	MaxFieldKey   = 64      // bytes of a key in F
	MaxFieldValue = 1 << 10 // bytes of a string value in F
	MaxShort      = 256     // bytes of App, Svc, Copy, Kind, Actor, IP
)

// Event is one normalized security-log event (schema version 1).
type Event struct {
	V     int       `json:"v"`
	TS    time.Time `json:"ts"` // UTC; the source's own timestamp when it has a trustworthy one, else capture time
	Src   string    `json:"src"`
	App   string    `json:"app,omitempty"`
	Svc   string    `json:"svc,omitempty"`
	Copy  string    `json:"copy,omitempty"` // short container id of the replica
	Lvl   string    `json:"lvl"`
	Kind  string    `json:"kind"`
	Out   string    `json:"out,omitempty"`
	Actor string    `json:"actor,omitempty"` // the account or user acting (keyed hash when it is personal data)
	IP    string    `json:"ip,omitempty"`    // the client IP (the real client, never a proxy in front of the edge)
	Geo   *Geo      `json:"geo,omitempty"`   // enrichment (phase 2)
	// F holds the structured fields after redaction, flattened with dots ("req.method"). Values are
	// string, float64 or bool only.
	F   map[string]any `json:"f,omitempty"`
	Msg string         `json:"msg,omitempty"`
}

// Geo is what enrichment knows about Event.IP (phase 2). Lat/Lon are the IP's approximate city,
// not a device's position.
type Geo struct {
	Country string   `json:"cc,omitempty"` // ISO 3166-1 alpha-2
	City    string   `json:"city,omitempty"`
	Lat     float64  `json:"lat,omitempty"`
	Lon     float64  `json:"lon,omitempty"`
	ASN     uint32   `json:"asn,omitempty"`
	Org     string   `json:"org,omitempty"`
	Lists   []string `json:"lists,omitempty"` // threat-intel lists the IP is on
}

// Normalize sets the version, makes TS UTC (zero → now), fills the default level and kind, and
// applies the bounds: long strings are cut (on a UTF-8 boundary), extra fields are dropped, and a
// field value that isn't string, float64 or bool is removed.
func (e *Event) Normalize(now time.Time) {
	e.V = SchemaVersion
	if e.TS.IsZero() {
		e.TS = now
	}
	e.TS = e.TS.UTC()
	if e.Lvl == "" {
		e.Lvl = LvlInfo
	}
	if e.Kind == "" {
		e.Kind = KindLog
	}
	e.App, e.Svc, e.Copy = Cut(e.App, MaxShort), Cut(e.Svc, MaxShort), Cut(e.Copy, MaxShort)
	e.Kind, e.Actor, e.IP = Cut(e.Kind, MaxShort), Cut(e.Actor, MaxShort), Cut(e.IP, MaxShort)
	e.Msg = Cut(e.Msg, MaxMsg)
	if len(e.F) == 0 {
		e.F = nil
		return
	}
	n := 0
	for k, v := range e.F {
		switch tv := v.(type) {
		case string:
			e.F[k] = Cut(tv, MaxFieldValue)
		case float64:
			if math.IsNaN(tv) || math.IsInf(tv, 0) {
				delete(e.F, k) // JSON can't encode it: the event would fail to store
				continue
			}
		case bool:
		default:
			delete(e.F, k)
			continue
		}
		if len(k) > MaxFieldKey || n >= MaxFields {
			delete(e.F, k)
			continue
		}
		n++
	}
}

// Cut returns s cut to at most n bytes without splitting a UTF-8 sequence.
func Cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

// Key purposes for DeriveKey.
const (
	KeyPII     = "mooring siem pii v1"     // the keyed hash of personal data (redact)
	KeySeal    = "mooring siem seal v1"    // the mac of each archive seal (archive)
	KeyArchive = "mooring siem archive v1" // reserved; the archive uses the backup format with the master key
)

// DeriveKey derives a 32-byte key for purpose from Mooring's master key (HKDF-SHA256), so the
// personal-data hash can't be reversed with a key used elsewhere.
func DeriveKey(master []byte, purpose string) ([]byte, error) {
	if len(master) < 32 {
		return nil, errors.New("siem: master key too short")
	}
	return hkdf.Key(sha256.New, master, nil, purpose, 32)
}

// SourceStatus is one source's counters for the dashboard.
type SourceStatus struct {
	Name     string    // "app", "edge", "mooring", "host:auth", "host:fail2ban", "host:journal"
	OK       bool      // reading (a host source whose file can't be read is not OK)
	Err      string    // why not, when not OK
	Events   int64     // events taken since start
	Dropped  int64     // events the queue dropped since start
	LastSeen time.Time // the newest event's capture time
}

// Status is the pipeline's state for the dashboard and `mooring doctor`.
type Status struct {
	Enabled       bool
	Sources       []SourceStatus
	Queue         int // events waiting
	QueueCap      int
	DiskBytes     int64 // on-box segments + security database
	Segments      int
	Oldest        time.Time // the oldest event still on the box
	ArchiveOn     bool      // an S3 archive is configured
	LastArchived  time.Time // when the newest segment was uploaded
	ArchiveBehind int       // sealed segments not yet uploaded
	ArchiveErr    string    // the last upload error, "" when the last upload worked
}

// SafeName reports whether s is usable as a path element of an archive key or segment name
// (letters, digits, '.', '_', '-'; not starting with '.').
func SafeName(s string) bool {
	if s == "" || len(s) > 128 || s[0] == '.' {
		return false
	}
	return strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") == ""
}
