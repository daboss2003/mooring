package parse

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// AuthLog parses one line of /var/log/auth.log or /var/log/secure (a syslog line with an
// RFC 3164 or RFC 3339 timestamp, read in loc) into an sshd/sudo/su/user-change event, or a host
// KindLog event for a line it doesn't classify. ok is false only for an empty or malformed line.
func AuthLog(line string, now time.Time, loc *time.Location) (siem.Event, bool) {
	ts, rest, ok := syslogTime(strings.TrimRight(line, "\r\n"), now, loc)
	if !ok {
		return siem.Event{}, false
	}
	// "<host> <tag>: <message>"; the tag is optional.
	rest = strings.TrimLeft(rest, " ")
	sp := strings.IndexByte(rest, ' ')
	if sp <= 0 {
		return siem.Event{}, false
	}
	rest = strings.TrimLeft(rest[sp+1:], " ")
	prog, pid, msg := "", "", rest
	if c := strings.IndexByte(rest, ':'); c > 0 && !strings.ContainsAny(rest[:c], " \t") {
		prog, msg = rest[:c], strings.TrimPrefix(rest[c+1:], " ")
		if b := strings.IndexByte(prog, '['); b >= 0 && strings.HasSuffix(prog, "]") {
			prog, pid = prog[:b], prog[b+1:len(prog)-1]
		}
	}
	e := siem.Event{TS: notFuture(ts, now), Src: siem.SrcHost}
	classifyHost(&e, prog, pid, msg)
	return e, true
}

// syslogTime reads the leading RFC 3339 or RFC 3164 timestamp and returns the rest of the line.
// An RFC 3164 time has no year: it is now's year, or the year before when that would put the
// line more than a day ahead of now (a December line read in January).
func syslogTime(line string, now time.Time, loc *time.Location) (time.Time, string, bool) {
	if loc == nil {
		loc = time.Local
	}
	if len(line) >= 20 && line[0] >= '0' && line[0] <= '9' && line[4] == '-' {
		tok, rest, _ := strings.Cut(line, " ")
		t, err := time.Parse(time.RFC3339Nano, tok)
		if err != nil {
			return time.Time{}, "", false
		}
		return t, rest, true
	}
	// "Mmm dd hh:mm:ss", the day space-padded ("Nov  3") or not.
	f := strings.Fields(line[:min(len(line), 24)])
	if len(f) < 3 || len(f[0]) != 3 || len(f[1]) > 2 || len(f[2]) != 8 {
		return time.Time{}, "", false
	}
	t, err := time.ParseInLocation("Jan 2 15:04:05", f[0]+" "+f[1]+" "+f[2], loc)
	if err != nil {
		return time.Time{}, "", false
	}
	n := now.In(loc)
	t = time.Date(n.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, loc)
	if t.After(now.Add(window)) {
		t = t.AddDate(-1, 0, 0)
	}
	i := strings.Index(line, f[2]) + len(f[2])
	return t, line[i:], true
}

func isSSHD(prog string) bool { return prog == "sshd" || prog == "sshd-session" || prog == "sshd-auth" }

var userChangeProgs = map[string]bool{"useradd": true, "usermod": true, "userdel": true, "groupadd": true,
	"groupmod": true, "groupdel": true, "gpasswd": true, "passwd": true, "chpasswd": true, "chage": true}

var reRepeated = regexp.MustCompile(`^message repeated (\d{1,9}) times: \[ ?(.*?)\]?$`)

// classifyHost fills e from one host log message of prog (shared by AuthLog and Journal).
func classifyHost(e *siem.Event, prog, pid, msg string) {
	e.Kind, e.Lvl, e.Msg = siem.KindLog, siem.LvlInfo, msg
	f := map[string]any{}
	if prog != "" {
		f["program"] = prog
	}
	if n, ok := number(pid); ok {
		f["pid"] = n
	}
	if m := reRepeated.FindStringSubmatch(msg); m != nil {
		n, _ := strconv.Atoi(m[1])
		f["repeated"] = float64(n)
		msg = m[2]
	}
	switch {
	case isSSHD(prog):
		sshd(e, f, msg)
	case prog == "sudo":
		sudo(e, f, msg)
	case prog == "su":
		su(e, f, msg)
	case userChangeProgs[prog]:
		userChange(e, f, prog, msg)
	}
	if e.Kind == siem.KindLog && e.IP == "" {
		e.IP = firstIP(msg)
	}
	if len(f) > 0 {
		e.F = f
	}
}

// sshd patterns (OpenSSH 8.x–10.x wording). User names are matched greedily so the address is
// the LAST "from <ip> port <n>": sshd appends the real one after whatever an attacker typed as
// the user name.
var (
	reSSHAccepted  = regexp.MustCompile(`^Accepted (\S+) for (.*) from (\S+) port (\d+)(?: ssh2)?(?:: (\S+) (\S+).*)?$`)
	reSSHFailed    = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(.*) from (\S+) port (\d+)(?: ssh2)?(?:: (\S+) (\S+).*)?$`)
	reSSHInvalid   = regexp.MustCompile(`^Invalid user (.*) from (\S+)(?: port (\d+))?$`)
	reSSHClosed    = regexp.MustCompile(`^Connection (closed|reset) by (?:(invalid|authenticating) user (.*) )?(\S+) port (\d+)( \[preauth\])?$`)
	reSSHDiscFrom  = regexp.MustCompile(`^Disconnected from (?:(invalid user|authenticating user|user) (.*) )?(\S+) port (\d+)( \[preauth\])?$`)
	reSSHReceived  = regexp.MustCompile(`^Received disconnect from (\S+) port (\d+):\d+: (.*?)( \[preauth\])?$`)
	reSSHMaxAuth   = regexp.MustCompile(`^error: (maximum authentication attempts exceeded) for (invalid user )?(.*) from (\S+) port (\d+)(?: ssh2)?( \[preauth\])?$`)
	reSSHTooMany   = regexp.MustCompile(`^Disconnecting (invalid|authenticating) user (.*) (\S+) port (\d+): (.*?)( \[preauth\])?$`)
	reSSHTooManyNo = regexp.MustCompile(`^Disconnecting: (.*?)( \[preauth\])?$`)
)

// sshAddr sets IP and port from an sshd "<addr> port <n>" pair; a host name (UseDNS yes) goes
// to F remote instead.
func sshAddr(e *siem.Event, f map[string]any, addr, port string) {
	if ip := parseIP(addr); ip != "" {
		e.IP = ip
	} else if addr != "" {
		f["remote"] = addr
	}
	if n, ok := number(port); ok {
		f["port"] = n
	}
}

func sshUser(e *siem.Event, f map[string]any, user string, invalid bool) {
	e.Actor = user
	if user != "" {
		f["user"] = user
	}
	if invalid {
		f["invalid"] = true
	}
}

func sshd(e *siem.Event, f map[string]any, msg string) {
	if m := reSSHAccepted.FindStringSubmatch(msg); m != nil {
		e.Kind, e.Out = siem.KindSSHLogin, siem.OutSuccess
		f["method"], _, _ = strings.Cut(m[1], "/") // keyboard-interactive/pam
		sshUser(e, f, m[2], false)
		sshAddr(e, f, m[3], m[4])
		sshKey(f, m[5], m[6])
		return
	}
	if m := reSSHFailed.FindStringSubmatch(msg); m != nil {
		e.Kind, e.Out, e.Lvl = siem.KindSSHLogin, siem.OutFailure, siem.LvlWarn
		f["method"], _, _ = strings.Cut(m[1], "/")
		sshUser(e, f, m[3], m[2] != "")
		sshAddr(e, f, m[4], m[5])
		sshKey(f, m[6], m[7])
		return
	}
	if m := reSSHInvalid.FindStringSubmatch(msg); m != nil {
		e.Kind, e.Lvl = siem.KindSSHInvalidUser, siem.LvlWarn
		sshUser(e, f, m[1], false)
		sshAddr(e, f, m[2], m[3])
		return
	}
	if m := reSSHClosed.FindStringSubmatch(msg); m != nil {
		disconnect(e, f, "connection "+m[1], m[3], m[2] == "invalid", m[4], m[5], m[2] != "" || m[6] != "")
		return
	}
	if m := reSSHDiscFrom.FindStringSubmatch(msg); m != nil {
		preauth := m[1] == "invalid user" || m[1] == "authenticating user" || m[5] != ""
		disconnect(e, f, "disconnected", m[2], m[1] == "invalid user", m[3], m[4], preauth)
		return
	}
	if m := reSSHReceived.FindStringSubmatch(msg); m != nil {
		disconnect(e, f, m[3], "", false, m[1], m[2], m[4] != "")
		return
	}
	if m := reSSHMaxAuth.FindStringSubmatch(msg); m != nil {
		disconnect(e, f, m[1], m[3], m[2] != "", m[4], m[5], true)
		return
	}
	if m := reSSHTooMany.FindStringSubmatch(msg); m != nil {
		disconnect(e, f, m[5], m[2], m[1] == "invalid", m[3], m[4], true)
		return
	}
	if m := reSSHTooManyNo.FindStringSubmatch(msg); m != nil {
		disconnect(e, f, m[1], "", false, "", "", true)
	}
}

// disconnect records an sshd disconnect: a pre-auth one is KindSSHDisconnect (warn); the end of
// an authenticated session stays an ordinary log line, still attributed.
func disconnect(e *siem.Event, f map[string]any, reason, user string, invalid bool, addr, port string, preauth bool) {
	sshUser(e, f, user, invalid)
	sshAddr(e, f, addr, port)
	if preauth {
		e.Kind, e.Lvl = siem.KindSSHDisconnect, siem.LvlWarn
		f["reason"] = reason
	}
}

func sshKey(f map[string]any, typ, fp string) {
	if typ != "" {
		f["key_type"] = typ
	}
	if fp != "" {
		f["key_fp"] = fp
	}
}

// pamFailure reads "pam_unix(<svc>:auth): authentication failure; logname=… uid=… tty=… ruser=…
// rhost=… user=…": the acting user is ruser (else logname), the target is user.
func pamFailure(e *siem.Event, f map[string]any, kind, msg string) {
	_, kv, _ := strings.Cut(msg, ";")
	vals := map[string]string{}
	for _, w := range strings.Fields(kv) {
		// Intentional: the first occurrence wins. pam_unix writes user= (the name typed, e.g.
		// `su 'x ruser=root rhost=6.6.6.6'`) last and unescaped; the real values come first.
		if k, v, ok := strings.Cut(w, "="); ok {
			if _, seen := vals[k]; !seen {
				vals[k] = v
			}
		}
	}
	actor := vals["ruser"]
	if actor == "" {
		actor = vals["logname"]
	}
	e.Kind, e.Out, e.Lvl, e.Actor = kind, siem.OutFailure, siem.LvlWarn, actor
	if actor != "" {
		f["user"] = actor
	}
	if vals["user"] != "" {
		f["target_user"] = vals["user"]
	}
	if vals["tty"] != "" {
		f["tty"] = vals["tty"]
	}
	if ip := parseIP(vals["rhost"]); ip != "" {
		e.IP = ip
	}
	f["reason"] = "authentication failure"
}

// sudo reads "<user> : [<reason> ; ]TTY=… ; PWD=… ; USER=… [; GROUP=…] ; COMMAND=…" and the PAM
// authentication failure line.
func sudo(e *siem.Event, f map[string]any, msg string) {
	m := strings.TrimSpace(msg)
	if strings.HasPrefix(m, "pam_unix(sudo") && strings.Contains(m, ":auth): authentication failure;") {
		pamFailure(e, f, siem.KindSudo, m)
		return
	}
	user, rest, ok := strings.Cut(m, " : ")
	if !ok || user == "" || strings.ContainsAny(user, " \t") {
		return
	}
	if sudoAmbiguous(rest) {
		sudoAmbiguousEvent(e, f, user, rest)
		return
	}
	// COMMAND is last and may itself contain " ; ".
	cmd, hasCmd := "", false
	if i := strings.Index(rest, "COMMAND="); i >= 0 {
		cmd, rest, hasCmd = rest[i+len("COMMAND="):], rest[:i], true
	}
	// Fields come in sudo's fixed order: [reason ; ] [TTY ; ] PWD ; USER [; GROUP] [; ENV] ; COMMAND.
	// A field out of that order, repeated, unknown or stray text before COMMAND is the user's own
	// text (a working directory "/tmp/x ; GROUP=wheel") writing a field of its own.
	var tty, cwd, target, group, reason string
	fields, last, ordered := 0, 0, true
	for i, p := range strings.Split(rest, " ; ") {
		p = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(p), ";"))
		if p == "" {
			continue
		}
		k, v, kv := strings.Cut(p, "=")
		n := sudoFieldOrder[k]
		switch {
		case kv && n > last:
			last, fields = n, fields+1
			switch k {
			case "TTY":
				tty = v
			case "PWD":
				cwd = v
			case "USER":
				target = v
			case "GROUP":
				group = v
			}
		case i == 0 && !kv:
			reason = p
		default:
			ordered = false
		}
	}
	if fields == 0 && !hasCmd {
		return
	}
	if !ordered {
		sudoAmbiguousEvent(e, f, user, rest+"COMMAND="+cmd)
		return
	}
	for k, v := range map[string]string{"tty": tty, "cwd": cwd, "target_user": target, "target_group": group} {
		if v != "" {
			// Intentional: "cwd", not "pwd" — pwd is a password field name to the redactor.
			f[k] = v
		}
	}
	e.Kind, e.Actor, e.Out = siem.KindSudo, user, siem.OutSuccess
	f["user"] = user
	if hasCmd {
		f["command"] = cmd
	}
	if reason != "" {
		e.Out, e.Lvl = siem.OutFailure, siem.LvlWarn
		f["reason"] = reason
	}
}

var sudoFieldOrder = map[string]int{"TTY": 1, "PWD": 2, "USER": 3, "GROUP": 4, "ENV": 5}

// sudoAmbiguous reports whether a sudo line's fields can't be told apart: PWD (and the command)
// are the user's own text, so a directory named "/tmp/COMMAND=/usr/bin/true" or "x ; USER=nobody"
// writes a second COMMAND=/USER=/… into the line.
func sudoAmbiguous(rest string) bool {
	if strings.Count(rest, "COMMAND=") > 1 {
		return true
	}
	for _, k := range []string{"TTY=", "PWD=", "USER=", "GROUP="} {
		n := strings.Count(rest, " ; "+k)
		if strings.HasPrefix(rest, k) {
			n++
		}
		if n > 1 {
			return true
		}
	}
	return false
}

// sudoAmbiguousEvent records an ambiguous sudo line without picking a command, target user or
// directory: F ambiguous=true at warn, the raw message in Msg (already set), and only what comes
// before the first PWD= (the failure reason and TTY, which sudo writes itself).
func sudoAmbiguousEvent(e *siem.Event, f map[string]any, user, rest string) {
	e.Kind, e.Actor, e.Out, e.Lvl = siem.KindSudo, user, siem.OutSuccess, siem.LvlWarn
	f["user"], f["ambiguous"] = user, true
	head := rest
	if i := strings.Index(head, "PWD="); i >= 0 {
		head = head[:i]
	} else if i := strings.Index(head, "COMMAND="); i >= 0 {
		head = head[:i]
	}
	for i, p := range strings.Split(head, " ; ") {
		p = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(p), ";"))
		k, v, kv := strings.Cut(p, "=")
		switch {
		case p == "":
		case kv && k == "TTY":
			f["tty"] = v
		case i == 0 && !kv:
			e.Out = siem.OutFailure
			f["reason"] = p
		}
	}
}

var (
	reSuOpened  = regexp.MustCompile(`^pam_unix\(su(?:-l)?:session\): session opened for user ([^\s(]+)(?:\(uid=\d+\))? by ([^\s(]*)(?:\(uid=\d+\))?$`)
	reSuFailed  = regexp.MustCompile(`^FAILED SU \(to ([^)]*)\) (\S+) on (\S+)$`)
	reSuFailed2 = regexp.MustCompile(`^FAILED su for (\S+) by (\S+)$`)
)

func su(e *siem.Event, f map[string]any, msg string) {
	m := strings.TrimSpace(msg)
	set := func(out, user, target string) {
		e.Kind, e.Out, e.Actor = siem.KindSu, out, user
		if out == siem.OutFailure {
			e.Lvl = siem.LvlWarn
		}
		if user != "" {
			f["user"] = user
		}
		if target != "" {
			f["target_user"] = target
		}
	}
	switch {
	case strings.HasPrefix(m, "pam_unix(su") && strings.Contains(m, ":auth): authentication failure;"):
		pamFailure(e, f, siem.KindSu, m)
	case reSuOpened.MatchString(m):
		s := reSuOpened.FindStringSubmatch(m)
		set(siem.OutSuccess, s[2], s[1])
	case reSuFailed.MatchString(m):
		s := reSuFailed.FindStringSubmatch(m)
		set(siem.OutFailure, s[2], s[1])
		f["tty"] = s[3]
	case reSuFailed2.MatchString(m):
		s := reSuFailed2.FindStringSubmatch(m)
		set(siem.OutFailure, s[2], s[1])
	}
}

var (
	reUCName   = regexp.MustCompile(`\bname=([^\s,]+)`)
	reUCQuoted = regexp.MustCompile(`'([^']+)'`)
	reUCFor    = regexp.MustCompile(`\bfor (\S+)$`)
	reUCUser   = regexp.MustCompile(`\buser (\S+)`)
)

// userChange records useradd/usermod/userdel/group*/passwd/chpasswd/chage lines; F user (or
// group, for the group programs) is the account changed when the line names it.
func userChange(e *siem.Event, f map[string]any, prog, msg string) {
	e.Kind = siem.KindUserChange
	f["detail"] = msg
	key := "user"
	if strings.HasPrefix(prog, "group") {
		key = "group"
	}
	for _, re := range []*regexp.Regexp{reUCName, reUCQuoted, reUCFor, reUCUser} {
		if m := re.FindStringSubmatch(msg); m != nil {
			f[key] = m[1]
			return
		}
	}
}
