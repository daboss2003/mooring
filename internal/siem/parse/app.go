package parse

import (
	"bytes"
	"encoding/json"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// Bounds of JSON app lines: anything nested deeper or with more keys is kept as plain text.
const (
	maxJSONLine  = 16 << 10
	maxJSONDepth = 6
	maxJSONKeys  = 256
	maxArrayJSON = 4 << 10 // an array value longer than this, re-encoded, is skipped
)

// AppLine parses one app container output line captured at at. A JSON object line (Pino,
// Bunyan, zap, logrus or any flat/nested JSON) gives TS, Lvl, Msg, IP, Actor, Out and F from its
// fields, and Kind from an `event` field when it is a dot.case name; anything else is KindLog
// with the text as Msg.
func AppLine(at time.Time, app, svc, copy, text string) siem.Event {
	e := siem.Event{TS: at, Src: siem.SrcApp, App: app, Svc: svc, Copy: copy, Lvl: siem.LvlInfo, Kind: siem.KindLog}
	text = strings.TrimRight(text, "\r\n")
	if f, ok := decodeObject(text); ok {
		appFields(&e, at, f)
		return e
	}
	e.Msg = text
	if l := textLevel(text); l != "" {
		e.Lvl = l
	}
	return e
}

// decodeObject flattens a JSON object line into dot keys, or reports false (plain text).
func decodeObject(text string) (map[string]any, bool) {
	t := strings.TrimLeft(text, " \t")
	if t == "" || t[0] != '{' || len(t) > maxJSONLine || !shapeOK(t) {
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(t), &m); err != nil {
		return nil, false // invalid, trailing data, or a number beyond float64
	}
	f := make(map[string]any, len(m))
	flatten(f, "", m)
	return f, true
}

// shapeOK checks nesting depth and key count before decoding, so a hostile line is never
// decoded into thousands of maps.
func shapeOK(t string) bool {
	depth, keys := 0, 0
	inStr := false
	for i := 0; i < len(t); i++ {
		c := t[i]
		if inStr {
			switch c {
			case '\\':
				i++
			case '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{', '[':
			if depth++; depth > maxJSONDepth {
				return false
			}
		case '}', ']':
			depth--
		case ':':
			if keys++; keys > maxJSONKeys {
				return false
			}
		}
	}
	return true
}

func flatten(out map[string]any, prefix string, m map[string]any) {
	keys := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			keys = append(keys, k)
		}
	}
	// Intentional: sorted so that a dotted key colliding with a nested one ("a.b" vs {"a":{"b"}})
	// resolves the same way every time (first written wins).
	sort.Strings(keys)
	for _, k := range keys {
		name := k
		if strings.IndexByte(k, '@') >= 0 && strings.IndexByte(k, '.') >= 0 {
			// Intentional: a key holding an address ({"attempts":{"john.doe@x.com":3}}) keeps it one
			// element of the flattened name — '.' as %2E, '%' as %25 — so redaction can hash the
			// whole address instead of guessing where it starts.
			name = strings.ReplaceAll(strings.ReplaceAll(k, "%", "%25"), ".", "%2E")
		}
		if prefix != "" {
			name = prefix + "." + name
		}
		switch v := m[k].(type) {
		case map[string]any:
			flatten(out, name, v)
		case []any:
			var b bytes.Buffer
			enc := json.NewEncoder(&b)
			enc.SetEscapeHTML(false)
			if enc.Encode(v) == nil && b.Len() <= maxArrayJSON {
				setFirst(out, name, strings.TrimSuffix(b.String(), "\n"))
			}
		case string, bool:
			setFirst(out, name, v)
		case float64:
			if !math.IsInf(v, 0) && !math.IsNaN(v) {
				setFirst(out, name, v)
			}
		}
	}
}

func setFirst(m map[string]any, k string, v any) {
	if _, ok := m[k]; !ok {
		m[k] = v
	}
}

var (
	timeKeys  = []string{"time", "ts", "timestamp", "@timestamp"}
	msgKeys   = []string{"msg", "message", "@message", "error.message"}
	kindKeys  = []string{"event", "evt", "event_type"}
	ipKeys    = []string{"ip", "client_ip", "clientIp", "remote_ip", "remoteAddress", "req.remoteAddress", "req.ip", "request.ip"}
	xffKeys   = []string{"x-forwarded-for", "req.headers.x-forwarded-for"}
	actorKeys = []string{"actor_id", "actorId", "user_id", "userId", "uid", "account", "username", "user", "sub"}
	lvlKeys   = []string{"lvl", "severity", "log.level"}

	// Intentional: an app line can't claim one of Mooring's own, the host's or the edge's kinds, so
	// a rule on mooring.login, ssh.login or http.request never fires on what an app chose to print.
	reservedKinds = []string{"mooring.", "siem.", "ssh.", "sudo.", "su.", "fail2ban.", "host.", "http."}
)

func appFields(e *siem.Event, at time.Time, f map[string]any) {
	lvlSet := false
	if v, ok := f["level"]; ok {
		if l := anyLevel(v); l != "" {
			e.Lvl, lvlSet = l, true
			delete(f, "level")
		}
	}
	for _, k := range lvlKeys {
		if lvlSet {
			break
		}
		if s, ok := f[k].(string); ok {
			if l := stringLevel(s); l != "" {
				e.Lvl, lvlSet = l, true
				delete(f, k)
			}
		}
	}
	if !lvlSet {
		if sc, ok := f["res.statusCode"].(float64); ok {
			switch {
			case sc >= 500:
				e.Lvl = siem.LvlError
			case sc >= 400:
				e.Lvl = siem.LvlWarn
			}
		}
	}

	for _, k := range timeKeys {
		v, ok := f[k]
		if !ok {
			continue
		}
		t := anyTime(v)
		if t.IsZero() {
			continue
		}
		if w := within(t, at); w.Equal(t) {
			e.TS = t.UTC()
			delete(f, k)
		}
		break
	}

	for _, k := range msgKeys {
		if s, ok := f[k].(string); ok {
			e.Msg = s
			delete(f, k)
			break
		}
	}

	for _, k := range kindKeys {
		if s, ok := f[k].(string); ok && validKind(s) && !reserved(s) {
			e.Kind = s
			delete(f, k)
			break
		}
	}
	// structlog names its message "event": a value that isn't a kind name is the message.
	if s, ok := f["event"].(string); ok && e.Msg == "" && !validKind(s) {
		e.Msg = s
	}

	if s, ok := f["outcome"].(string); ok {
		if o := outcome(s); o != "" {
			e.Out = o
			delete(f, "outcome")
		}
	}
	if e.Out == "" && (strings.HasSuffix(e.Kind, "_failed") || strings.HasSuffix(e.Kind, ".failed") ||
		strings.HasSuffix(e.Kind, "_denied") || strings.HasSuffix(e.Kind, ".denied")) {
		e.Out = siem.OutFailure
	}

	direct, directKey := "", ""
	for _, k := range ipKeys {
		if s, ok := f[k].(string); ok {
			if ip := parseIP(s); ip != "" {
				direct, directKey = ip, k
				break
			}
		}
	}
	fwd := ""
	for _, k := range xffKeys {
		if s, ok := f[k].(string); ok {
			first, _, _ := strings.Cut(s, ",")
			if ip := parseIP(first); ip != "" {
				fwd = ip
				break
			}
		}
	}
	// Intentional: every app sits behind the edge, so a private socket peer (req.remoteAddress =
	// the edge container) is the proxy hop; the X-Forwarded-For the edge set names the client.
	// The forwarded-for field stays in F as the full chain.
	switch {
	case direct != "" && (fwd == "" || !privateIP(direct)):
		e.IP = direct
		delete(f, directKey)
	case fwd != "":
		e.IP = fwd
	}

	for _, k := range actorKeys {
		if s, ok := f[k].(string); ok {
			if s = strings.TrimSpace(s); s != "" {
				e.Actor = s
				delete(f, k)
				break
			}
		}
	}

	if len(f) > 0 {
		e.F = f
	}
}

// validKind reports whether s is a dot.case kind name: ^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,3}$.
func validKind(s string) bool {
	if s == "" || len(s) > siem.MaxShort || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	dots, seg := 0, 1
	for i := 1; i < len(s); i++ {
		switch c := s[i]; {
		case c == '.':
			if seg == 0 {
				return false
			}
			dots++
			seg = 0
		case c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_':
			seg++
		default:
			return false
		}
	}
	return dots >= 1 && dots <= 3 && seg > 0
}

func reserved(kind string) bool {
	for _, p := range reservedKinds {
		if strings.HasPrefix(kind, p) {
			return true
		}
	}
	return false
}

func outcome(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "success", "ok", "succeeded":
		return siem.OutSuccess
	case "failure", "fail", "failed", "denied", "error":
		return siem.OutFailure
	}
	return ""
}

// anyLevel maps a `level` value: a Pino/Bunyan number or a level name.
func anyLevel(v any) string {
	switch tv := v.(type) {
	case float64:
		switch {
		case tv >= 60:
			return siem.LvlCritical
		case tv >= 50:
			return siem.LvlError
		case tv >= 40:
			return siem.LvlWarn
		case tv >= 30:
			return siem.LvlInfo
		case tv >= 0:
			return siem.LvlDebug
		}
	case string:
		return stringLevel(tv)
	}
	return ""
}

func stringLevel(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trace", "debug":
		return siem.LvlDebug
	case "info", "notice":
		return siem.LvlInfo
	case "warn", "warning":
		return siem.LvlWarn
	case "error", "err":
		return siem.LvlError
	case "fatal", "panic", "critical", "crit", "alert", "emerg", "emergency":
		return siem.LvlCritical
	}
	return ""
}

// anyTime reads a timestamp field: RFC 3339 text, or an epoch number (or numeric string) whose
// unit is told by magnitude.
func anyTime(v any) time.Time {
	switch tv := v.(type) {
	case float64:
		return epoch(tv)
	case string:
		if n, ok := number(tv); ok {
			return epoch(n)
		}
		if t, err := time.Parse(time.RFC3339Nano, tv); err == nil {
			return t
		}
	}
	return time.Time{}
}

// textLevel finds the level of a plain-text line: a leading ERROR/WARN/[INFO]/panic: token, or a
// logfmt level=/lvl= pair. "" means none.
func textLevel(text string) string {
	t := strings.TrimLeft(text, " \t")
	if strings.HasPrefix(t, "[") {
		t = t[1:]
	}
	n := 0
	for n < len(t) && n <= 8 && (t[n]|0x20 >= 'a' && t[n]|0x20 <= 'z') {
		n++
	}
	if n > 0 && n <= 8 && (n == len(t) || strings.IndexByte(" \t:]|,", t[n]) >= 0) {
		switch w := strings.ToUpper(t[:n]); w {
		case "ERROR", "WARN", "WARNING", "FATAL", "PANIC", "DEBUG", "INFO", "TRACE", "CRITICAL":
			return stringLevel(w)
		}
	}
	for _, key := range []string{"level=", "lvl="} {
		i := strings.Index(text, key)
		if i < 0 || i > 0 && text[i-1] != ' ' {
			continue
		}
		v := text[i+len(key):]
		if j := strings.IndexAny(v, " \t"); j >= 0 {
			v = v[:j]
		}
		if l := stringLevel(strings.Trim(v, `"`)); l != "" {
			return l
		}
	}
	return ""
}
