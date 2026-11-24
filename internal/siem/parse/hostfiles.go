package parse

import (
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

var (
	reF2B       = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:,(\d{1,6}))? +(fail2ban(?:\.[\w.-]+)?)(?: +\[(\d+)\])?: +(\w+) +(.*)$`)
	reF2BAction = regexp.MustCompile(`^\[([^\]]+)\] +(Restore Ban|Ban|Unban|Found) +(\S+)`)
	reF2BJail   = regexp.MustCompile(`^\[([^\]]+)\] +(.*)$`)
)

// Fail2Ban parses one /var/log/fail2ban.log line (Ban/Unban → KindFail2BanBan/Unban, else a host
// KindLog event); ok is false for an empty or malformed line.
func Fail2Ban(line string, now time.Time, loc *time.Location) (siem.Event, bool) {
	if loc == nil {
		loc = time.Local
	}
	m := reF2B.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
	if m == nil {
		return siem.Event{}, false
	}
	ts, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], loc)
	if err != nil {
		return siem.Event{}, false
	}
	if m[2] != "" {
		frac, _ := strconv.Atoi((m[2] + "00000")[:6])
		ts = ts.Add(time.Duration(frac) * time.Microsecond)
	}
	msg := m[6]
	e := siem.Event{TS: notFuture(ts, now), Src: siem.SrcHost, Kind: siem.KindLog, Lvl: siem.LvlInfo, Msg: msg}
	f := map[string]any{"logger": m[3]}
	if n, ok := number(m[4]); ok {
		f["pid"] = n
	}
	switch strings.ToUpper(m[5]) {
	case "WARNING", "WARN":
		e.Lvl = siem.LvlWarn
	case "ERROR", "CRITICAL":
		e.Lvl = siem.LvlError
	}
	if a := reF2BAction.FindStringSubmatch(msg); a != nil {
		f["jail"] = a[1]
		e.IP = parseIP(a[3])
		switch a[2] {
		case "Ban":
			e.Kind, e.Lvl = siem.KindFail2BanBan, siem.LvlWarn
		case "Restore Ban":
			// Intentional: a ban re-applied at fail2ban start is the ban state, not a new
			// detection, so it is a ban event at info.
			e.Kind, e.Lvl = siem.KindFail2BanBan, siem.LvlInfo
			f["restore"] = true
		case "Unban":
			e.Kind, e.Lvl = siem.KindFail2BanUnban, siem.LvlInfo
		case "Found":
			e.Lvl = siem.LvlInfo
		}
	} else if j := reF2BJail.FindStringSubmatch(msg); j != nil {
		f["jail"] = j[1]
		e.IP = firstIP(j[2])
	}
	e.F = f
	return e, true
}

// journalEntry is the part of a `journalctl -o json` entry used. journald writes a field that is
// not valid UTF-8 as an array of bytes, and a field present twice as an array of values, so
// MESSAGE and the identifiers are decoded by hand.
type journalEntry struct {
	Ident     json.RawMessage `json:"SYSLOG_IDENTIFIER"`
	Comm      json.RawMessage `json:"_COMM"`
	Message   json.RawMessage `json:"MESSAGE"`
	Realtime  json.RawMessage `json:"__REALTIME_TIMESTAMP"` // µs since the epoch, as a string
	PID       json.RawMessage `json:"_PID"`
	SyslogPID json.RawMessage `json:"SYSLOG_PID"`
	UID       json.RawMessage `json:"_UID"` // set by journald from the sender's credentials
}

// journalAnyUID are the programs taken from any sender uid: they are set-uid root, but journald
// records the invoking user's real uid for them (systemd 257: sudo run by a user, su to root by a
// user, passwd on one's own account). sshd is taken from any uid too, but from one other than 0
// only as a log event (see Journal). Every other program is taken only from uid 0, the only user
// that runs it, so `logger -t useradd …` by another user is not a user change.
var journalAnyUID = map[string]bool{"sudo": true, "su": true, "passwd": true}

// Journal parses one `journalctl -o json` entry for sshd, sudo, su or a user/group program
// (useradd, usermod, passwd, …: KindUserChange) sent by a trusted uid (see journalAnyUID; a
// non-root sshd line is a plain log event) — MESSAGE parsed as AuthLog does, TS from
// __REALTIME_TIMESTAMP, F sender_uid journald's uid; ok is false for anything else.
func Journal(raw []byte) (siem.Event, bool) {
	var j journalEntry
	if err := json.Unmarshal(raw, &j); err != nil {
		var te *json.UnmarshalTypeError
		if !errors.As(err, &te) {
			return siem.Event{}, false
		}
	}
	prog, _ := journalField(j.Ident)
	if prog == "" {
		prog, _ = journalField(j.Comm)
	}
	if !isSSHD(prog) && prog != "sudo" && prog != "su" && !userChangeProgs[prog] {
		return siem.Event{}, false
	}
	// SYSLOG_IDENTIFIER is the sender's own claim; _UID is journald's. A plain string only (a
	// trusted field is never repeated or sent as bytes); absent or null drops the entry.
	var uid string
	if json.Unmarshal(j.UID, &uid) != nil || uid == "" {
		return siem.Event{}, false
	}
	// Intentional: sshd sends its after-login lines ("Disconnected from user alice …") from the
	// user's own session process, so a non-root sshd line is kept, but never classified: anyone
	// can send one (`logger -t sshd "Accepted password for root from …"`), so it is a plain log
	// event without actor, outcome or IP and can't raise an ssh.* detection.
	untrusted := uid != "0" && isSSHD(prog)
	if uid != "0" && !journalAnyUID[prog] && !untrusted {
		return siem.Event{}, false
	}
	msg, ok := journalField(j.Message)
	if !ok {
		return siem.Event{}, false
	}
	pid, _ := journalField(j.PID)
	if pid == "" {
		pid, _ = journalField(j.SyslogPID)
	}
	e := siem.Event{Src: siem.SrcHost}
	if s, _ := journalField(j.Realtime); s != "" {
		if us, err := strconv.ParseInt(s, 10, 64); err == nil && us > 0 && us < 1<<62 {
			e.TS = time.UnixMicro(us)
		}
	}
	if untrusted {
		e.Kind, e.Lvl, e.Msg, e.F = siem.KindLog, siem.LvlInfo, msg, map[string]any{"program": prog}
		if n, ok := number(pid); ok {
			e.F["pid"] = n
		}
	} else {
		classifyHost(&e, prog, pid, msg)
	}
	if e.F == nil {
		e.F = map[string]any{}
	}
	e.F["sender_uid"] = uid // journald's, so the pipeline can tell who wrote a sudo/su/passwd line
	return e, true
}

// journalField decodes a journal field: a string, an array of byte values, or an array of
// values (the first is used). ok is false for anything else.
func journalField(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	switch raw[0] {
	case '"':
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return "", false
		}
		return s, true
	case '[':
		var bs []int
		if json.Unmarshal(raw, &bs) == nil {
			b := make([]byte, len(bs))
			for i, v := range bs {
				if v < 0 || v > 255 {
					return "", false
				}
				b[i] = byte(v)
			}
			return string(b), true
		}
		var many []json.RawMessage
		if json.Unmarshal(raw, &many) != nil || len(many) == 0 || many[0][0] == '[' {
			return "", false
		}
		return journalField(many[0])
	}
	return "", false
}
