// Package audit appends to the append-only events table (plan §5.8). It never
// records secret values — callers pass already-redacted detail strings.
package audit

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/daboss2003/mooring/internal/store"
)

// Level distinguishes routine actions from security-relevant ones.
type Level string

const (
	Info     Level = "info"
	Security Level = "security"
)

// Outcome of an audited action.
type Outcome string

const (
	OK    Outcome = "ok"
	Deny  Outcome = "deny"
	Error Outcome = "error"
)

// Event is one audit record.
type Event struct {
	Actor   string
	IP      string
	Action  string
	Target  string
	Outcome Outcome
	Level   Level
	Detail  string
	UA      string // the client's User-Agent, when the event comes from a request
}

// maxUserAgent and maxActor are the most of a User-Agent and of an actor an event stores, in bytes.
// The actor can come from a request (the username a login attempt sends).
const (
	maxUserAgent = 256
	maxActor     = 256
)

// Logger writes audit events.
type Logger struct {
	db   *store.DB
	log  *slog.Logger // may be nil
	sink atomic.Pointer[func(time.Time, Event)]
	now  func() time.Time // test seam; nil = time.Now
}

// New returns a Logger backed by db. log (may be nil) receives a line whenever an
// audit write FAILS, so a dropped security event is never invisible (review #12).
func New(db *store.DB, log *slog.Logger) *Logger { return &Logger{db: db, log: log} }

// SetSink registers fn to receive every event Log records, as stored (defaults applied, UA
// cleaned), with the time the row was stamped (ts.Unix() is the row's ts). fn runs on the
// caller's goroutine after the INSERT, holding no lock, so it must not block; it may call Log.
// nil removes the sink. Safe to call at any time, also on a nil Logger.
func (l *Logger) SetSink(fn func(ts time.Time, e Event)) {
	if l == nil {
		return
	}
	if fn == nil {
		l.sink.Store(nil)
		return
	}
	l.sink.Store(&fn)
}

type uaKey struct{}

// WithUserAgent returns ctx carrying a request's User-Agent. Log uses it for an event whose UA is
// empty, so events built deeper in a request (where the *http.Request isn't at hand) carry it too.
func WithUserAgent(ctx context.Context, ua string) context.Context {
	if ua == "" {
		return ctx
	}
	return context.WithValue(ctx, uaKey{}, ua)
}

// Log appends an event. A DB failure is returned AND logged (if a logger is set):
// it is non-fatal to the request path (the request still fails closed on its own
// merits), but the dropped event must not vanish silently.
func (l *Logger) Log(ctx context.Context, e Event) error {
	if e.Level == "" {
		e.Level = Info
	}
	if e.Outcome == "" {
		e.Outcome = OK
	}
	if e.UA == "" {
		e.UA, _ = ctx.Value(uaKey{}).(string)
	}
	e.UA = cleanField(e.UA, maxUserAgent)
	e.Actor = cleanField(e.Actor, maxActor)
	now := time.Now()
	if l.now != nil {
		now = l.now()
	}
	_, err := l.db.ExecContext(ctx,
		`INSERT INTO events(ts, actor, ip, action, target, outcome, level, detail, user_agent)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		now.Unix(), e.Actor, e.IP, e.Action, e.Target,
		string(e.Outcome), string(e.Level), e.Detail, e.UA,
	)
	if err != nil && l.log != nil {
		l.log.Error("audit write failed",
			"action", e.Action, "outcome", string(e.Outcome),
			"actor", e.Actor, "ip", e.IP, "err", err)
	}
	// Intentional: the sink runs even when the INSERT failed — a security event must still reach
	// the SIEM when the main database can't take it.
	if fn := l.sink.Load(); fn != nil {
		(*fn)(now, e)
	}
	return err
}

// cleanField drops control and format characters (CR/LF, ESC, bidi overrides, zero-width) and cuts
// the result to max bytes on a character boundary. Invalid UTF-8 becomes U+FFFD.
func cleanField(s string, max int) string {
	if s == "" {
		return ""
	}
	if len(s) > 16*max {
		s = s[:16*max] // bounds the work on a huge value; the result is far shorter
	}
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > max {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
