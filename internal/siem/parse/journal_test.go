package parse

import (
	"encoding/json"
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

func journalLine(ident, msg string) []byte {
	b, _ := json.Marshal(map[string]any{
		"__CURSOR": "s=abc;i=1", "__REALTIME_TIMESTAMP": "1795440881123456", "__MONOTONIC_TIMESTAMP": "1",
		"_HOSTNAME": "web1", "SYSLOG_IDENTIFIER": ident, "_PID": "1234", "_UID": "0", "_COMM": ident, "PRIORITY": "6",
		"SYSLOG_FACILITY": "4", "MESSAGE": msg,
	})
	return b
}

func TestJournal(t *testing.T) {
	cases := []struct {
		raw           []byte
		kind, out, ip string
		actor, prog   string
	}{
		{journalLine("sshd", "Failed password for invalid user admin from 198.51.100.7 port 40022 ssh2"),
			siem.KindSSHLogin, siem.OutFailure, "198.51.100.7", "admin", "sshd"},
		{journalLine("sshd-session", "Accepted publickey for deploy from 203.0.113.5 port 52134 ssh2: ED25519 SHA256:abc"),
			siem.KindSSHLogin, siem.OutSuccess, "203.0.113.5", "deploy", "sshd-session"},
		{journalLine("sudo", "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id"),
			siem.KindSudo, siem.OutSuccess, "", "alice", "sudo"},
		{journalLine("su", "FAILED SU (to root) alice on pts/0"), siem.KindSu, siem.OutFailure, "", "alice", "su"},
		{journalLine("sshd", "Server listening on :: port 22."), siem.KindLog, "", "", "", "sshd"},
		// MESSAGE as a byte array (journald does this for non-UTF-8 text).
		{[]byte(`{"SYSLOG_IDENTIFIER":"sshd","_PID":"9","_UID":"0","__REALTIME_TIMESTAMP":"1795440881123456","MESSAGE":[73,110,118,97,108,105,100,32,117,115,101,114,32,255,32,102,114,111,109,32,49,57,56,46,53,49,46,49,48,48,46,55,32,112,111,114,116,32,49]}`),
			siem.KindSSHInvalidUser, "", "198.51.100.7", "\xff", "sshd"},
		// No SYSLOG_IDENTIFIER: _COMM.
		{[]byte(`{"_COMM":"sudo","_UID":"1000","MESSAGE":"bob : command not allowed ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/sh","__REALTIME_TIMESTAMP":"1795440881123456"}`),
			siem.KindSudo, siem.OutFailure, "", "bob", "sudo"},
		// A field journald repeats comes as an array of strings: the first is used.
		{[]byte(`{"SYSLOG_IDENTIFIER":["sshd","x"],"_UID":"0","MESSAGE":["Invalid user z from 198.51.100.7 port 1","second"],"__REALTIME_TIMESTAMP":"1795440881123456"}`),
			siem.KindSSHInvalidUser, "", "198.51.100.7", "z", "sshd"},
	}
	for i, c := range cases {
		e, ok := Journal(c.raw)
		if !ok {
			t.Errorf("%d: not ok", i)
			continue
		}
		checkEvent(t, e)
		if e.Src != siem.SrcHost || e.Kind != c.kind || e.Out != c.out || e.IP != c.ip || e.Actor != c.actor || e.F["program"] != c.prog {
			t.Errorf("%d: %+v", i, e)
		}
		if want := time.UnixMicro(1795440881123456); !e.TS.Equal(want) {
			t.Errorf("%d: TS %v want %v", i, e.TS, want)
		}
	}
	e, _ := Journal(journalLine("sshd", "x"))
	if e.F["pid"] != 1234.0 || e.Msg != "x" {
		t.Errorf("pid/msg: %v %q", e.F, e.Msg)
	}
	if e, ok := Journal([]byte(`{"SYSLOG_IDENTIFIER":"sshd","_UID":"0","MESSAGE":"x"}`)); !ok || !e.TS.IsZero() {
		t.Errorf("missing timestamp: ok=%v TS %v (zero means capture time in Normalize)", ok, e.TS)
	}
	for name, raw := range map[string]string{
		"other identifier": string(journalLine("cron", "x")),
		"systemd":          string(journalLine("systemd", "Started x")),
		"no identifier":    `{"MESSAGE":"Failed password for root from 1.2.3.4 port 1 ssh2"}`,
		"no message":       `{"SYSLOG_IDENTIFIER":"sshd"}`,
		"null message":     `{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":null}`,
		"bad byte":         `{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":[300]}`,
		"neg byte":         `{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":[-1]}`,
		"float byte":       `{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":[1.5]}`,
		"object message":   `{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":{"a":1}}`,
		"number message":   `{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":5}`,
		"malformed":        `{"SYSLOG_IDENTIFIER":"sshd",`,
		"empty":            ``,
		"array":            `[]`,
	} {
		if _, ok := Journal([]byte(raw)); ok {
			t.Errorf("%s: must not parse", name)
		}
	}
	if e, ok := Journal(journalLine("sshd-auth", "Invalid user z from 198.51.100.7 port 1")); !ok || e.Kind != siem.KindSSHInvalidUser {
		t.Errorf("sshd-auth (OpenSSH 10): ok=%v %+v", ok, e)
	}
	for _, ts := range []string{"abc", "-1", "99999999999999999999999", ""} {
		e, ok := Journal([]byte(fmt.Sprintf(`{"SYSLOG_IDENTIFIER":"sshd","_UID":"0","MESSAGE":"x","__REALTIME_TIMESTAMP":%q}`, ts)))
		if !ok || !e.TS.IsZero() {
			t.Errorf("ts %q: ok=%v TS %v", ts, ok, e.TS)
		}
	}
}

// User and group changes on a host with no auth log file (Amazon Linux 2023). Messages are as
// shadow-utils 4.9 and passwd 0.80 write them there; the identifier is the program name.
func TestJournalUserChange(t *testing.T) {
	for _, c := range []struct{ prog, msg, key, name string }{
		{"useradd", "new user: name=carol, UID=1000, GID=1000, home=/home/carol, shell=/bin/bash, from=none", "user", "carol"},
		{"usermod", "add 'bob' to group 'dev'", "user", "bob"},
		{"userdel", "delete user 'carol'", "user", "carol"},
		{"groupadd", "group added to /etc/group: name=ops, GID=1001", "group", "ops"},
		{"groupmod", "group changed in /etc/group (group ops/1001, new name: ops2)", "group", ""},
		{"groupdel", "group 'ops2' removed", "group", "ops2"},
		{"gpasswd", "user alice added by root to group ops2", "user", "alice"},
		{"passwd", "pam_unix(passwd:chauthtok): password changed for carol", "user", "carol"},
		{"chpasswd", "pam_unix(chpasswd:chauthtok): password changed for bobby", "user", "bobby"},
		{"chage", "changed password expiry for carol", "user", "carol"},
	} {
		e, ok := Journal(journalLine(c.prog, c.msg))
		if !ok {
			t.Errorf("%s: not ok", c.prog)
			continue
		}
		checkEvent(t, e)
		got, _ := e.F[c.key].(string)
		if e.Src != siem.SrcHost || e.Kind != siem.KindUserChange || e.F["program"] != c.prog || e.F["detail"] != c.msg || got != c.name {
			t.Errorf("%s: %+v", c.prog, e)
		}
		if want := time.UnixMicro(1795440881123456); !e.TS.Equal(want) {
			t.Errorf("%s: TS %v want %v", c.prog, e.TS, want)
		}
	}
}

// SYSLOG_IDENTIFIER is whatever the sender says (`logger -t sshd …`); _UID is set by journald from
// the sender's credentials. The programs that only root runs are trusted from uid 0 alone. sudo,
// su and passwd are set-uid root but reach journald with the invoking user's (real) uid, as seen on
// systemd 257, so they are taken from any uid. Every entry must carry _UID.
func TestJournalSenderTrust(t *testing.T) {
	entry := func(ident, uid any, msg string) []byte {
		m := map[string]any{"SYSLOG_IDENTIFIER": ident, "MESSAGE": msg, "__REALTIME_TIMESTAMP": "1795440881123456"}
		if uid != nil {
			m["_UID"] = uid
		}
		b, _ := json.Marshal(m)
		return b
	}
	rootOnly := map[string]string{
		"useradd": "new user: name=evil, UID=0",
		"usermod": "add 'evil' to group 'sudo'", "userdel": "delete user 'admin'", "groupadd": "new group: name=evil, GID=0",
		"groupmod": "group changed in /etc/group (group sudo/27, new name: x)", "groupdel": "group 'sudo' removed",
		"gpasswd": "user evil added by root to group sudo", "chpasswd": "pam_unix(chpasswd:chauthtok): password changed for root",
		"chage": "changed password expiry for root",
	}
	for ident, msg := range rootOnly {
		if e, ok := Journal(entry(ident, "0", msg)); !ok || e.F["sender_uid"] != "0" {
			t.Errorf("%s from uid 0: ok=%v F=%v, want it kept with sender_uid \"0\"", ident, ok, e.F)
		}
		for _, uid := range []any{"1001", "", nil, 0, []string{"0"}, "00", " 0"} {
			if e, ok := Journal(entry(ident, uid, msg)); ok {
				t.Errorf("%s from _UID %#v accepted: %+v", ident, uid, e)
			}
		}
	}
	// sshd's lines after a login come from the user's own session process ("Disconnected from user
	// alice …"). From a uid other than 0 an sshd line is kept, but only as a plain log event: a
	// forger gets a log line, never an ssh.login, ssh.disconnect or ssh.invalid_user event.
	for ident, msg := range map[string]string{
		"sshd": "Accepted password for root from 6.6.6.6 port 22 ssh2", "sshd-session": "Accepted password for root from 6.6.6.6 port 22 ssh2",
		"sshd-auth": "Invalid user admin from 6.6.6.6 port 22",
	} {
		e, ok := Journal(entry(ident, "0", msg))
		if !ok || e.Kind == siem.KindLog || e.IP != "6.6.6.6" || e.F["sender_uid"] != "0" {
			t.Errorf("%s from uid 0: ok=%v %+v, want it classified", ident, ok, e)
		}
		for _, uid := range []string{"1001", "1000"} {
			e, ok := Journal(entry(ident, uid, msg))
			if !ok {
				t.Errorf("%s from uid %s dropped", ident, uid)
				continue
			}
			checkEvent(t, e)
			want := map[string]any{"program": ident, "sender_uid": uid}
			if e.Kind != siem.KindLog || e.Out != "" || e.Actor != "" || e.IP != "" || e.Msg != msg || !maps.Equal(e.F, want) {
				t.Errorf("%s from uid %s: %+v, want a plain log event with F %v", ident, uid, e, want)
			}
		}
		for _, uid := range []any{"", nil, 0, []string{"0"}} {
			if e, ok := Journal(entry(ident, uid, msg)); ok {
				t.Errorf("%s with _UID %#v accepted: %+v", ident, uid, e)
			}
		}
	}
	if e, ok := Journal(entry("sshd-session", "1000", "Disconnected from user alice 127.0.0.1 port 52778")); !ok || e.Kind != siem.KindLog {
		t.Errorf("after-login sshd line from the user's uid: ok=%v %+v", ok, e)
	}
	for ident, msg := range map[string]string{
		"sudo": "   alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/true", "su": "FAILED SU (to root) alice on pts/0",
		"passwd": "pam_unix(passwd:chauthtok): password changed for alice",
	} {
		for _, uid := range []any{"0", "1000"} {
			if e, ok := Journal(entry(ident, uid, msg)); !ok || e.F["sender_uid"] != uid {
				t.Errorf("%s from _UID %v: ok=%v F=%v, want it kept with sender_uid", ident, uid, ok, e.F)
			}
		}
		for _, uid := range []any{nil, "", 1000, []string{"1000"}} {
			if _, ok := Journal(entry(ident, uid, msg)); ok {
				t.Errorf("%s with _UID %#v accepted", ident, uid)
			}
		}
	}
}
