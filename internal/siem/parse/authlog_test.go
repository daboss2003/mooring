package parse

import (
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

var (
	wat     = time.FixedZone("WAT", 3600)
	hostNow = time.Date(2026, 11, 23, 15, 0, 0, 0, wat)
)

type hostCase struct {
	line           string
	kind, out, lvl string
	actor, ip      string
	f              map[string]any // must be present with these values
	msg            string         // "" = the syslog message
}

func runHost(t *testing.T, cases []hostCase) {
	t.Helper()
	for _, c := range cases {
		e, ok := AuthLog(c.line, hostNow, wat)
		if !ok {
			t.Errorf("%s: not ok", c.line)
			continue
		}
		checkEvent(t, e)
		if e.Src != siem.SrcHost || e.Kind != c.kind || e.Out != c.out || e.Lvl != c.lvl {
			t.Errorf("%s:\n kind %q out %q lvl %q, want %q %q %q", c.line, e.Kind, e.Out, e.Lvl, c.kind, c.out, c.lvl)
		}
		if e.Actor != c.actor || e.IP != c.ip {
			t.Errorf("%s:\n actor %q ip %q, want %q %q", c.line, e.Actor, e.IP, c.actor, c.ip)
		}
		for k, v := range c.f {
			if e.F[k] != v {
				t.Errorf("%s:\n F[%s] = %#v want %#v (F %v)", c.line, k, e.F[k], v, e.F)
			}
		}
		if c.msg != "" && e.Msg != c.msg {
			t.Errorf("%s:\n msg %q want %q", c.line, e.Msg, c.msg)
		}
	}
}

func TestAuthLogSSHD(t *testing.T) {
	const h = "Nov 23 13:14:41 web1 "
	runHost(t, []hostCase{
		{line: h + "sshd[1234]: Accepted publickey for deploy from 203.0.113.5 port 52134 ssh2: ED25519 SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg",
			kind: siem.KindSSHLogin, out: siem.OutSuccess, lvl: siem.LvlInfo, actor: "deploy", ip: "203.0.113.5",
			f: map[string]any{"method": "publickey", "user": "deploy", "port": 52134.0, "key_type": "ED25519",
				"key_fp": "SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg", "program": "sshd", "pid": 1234.0},
			msg: "Accepted publickey for deploy from 203.0.113.5 port 52134 ssh2: ED25519 SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg"},
		{line: h + "sshd[1234]: Accepted password for root from 2001:db8::7 port 52134 ssh2",
			kind: siem.KindSSHLogin, out: siem.OutSuccess, lvl: siem.LvlInfo, actor: "root", ip: "2001:db8::7",
			f: map[string]any{"method": "password", "user": "root", "port": 52134.0}},
		{line: h + "sshd[1234]: Accepted keyboard-interactive/pam for ops from 203.0.113.5 port 1 ssh2",
			kind: siem.KindSSHLogin, out: siem.OutSuccess, lvl: siem.LvlInfo, actor: "ops", ip: "203.0.113.5",
			f: map[string]any{"method": "keyboard-interactive"}},
		{line: h + "sshd[1234]: Accepted publickey for ci from 203.0.113.5 port 2 ssh2: ED25519-CERT SHA256:certfp ID ci@build (serial 7) CA ED25519 SHA256:cafp",
			kind: siem.KindSSHLogin, out: siem.OutSuccess, lvl: siem.LvlInfo, actor: "ci", ip: "203.0.113.5",
			f: map[string]any{"key_type": "ED25519-CERT", "key_fp": "SHA256:certfp"}},
		{line: h + "sshd[1235]: Failed password for invalid user admin from 198.51.100.7 port 40022 ssh2",
			kind: siem.KindSSHLogin, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "admin", ip: "198.51.100.7",
			f: map[string]any{"method": "password", "user": "admin", "invalid": true, "port": 40022.0}},
		{line: h + "sshd[1235]: Failed password for root from 198.51.100.7 port 40022 ssh2",
			kind: siem.KindSSHLogin, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "root", ip: "198.51.100.7",
			f: map[string]any{"user": "root"}},
		{line: h + "sshd[1235]: Failed publickey for git from 198.51.100.7 port 4 ssh2: RSA SHA256:rsafp",
			kind: siem.KindSSHLogin, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "git", ip: "198.51.100.7",
			f: map[string]any{"method": "publickey", "key_type": "RSA", "key_fp": "SHA256:rsafp"}},
		{line: h + "sshd[1235]: Failed none for invalid user  from 198.51.100.7 port 4 ssh2",
			kind: siem.KindSSHLogin, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "", ip: "198.51.100.7",
			f: map[string]any{"invalid": true, "method": "none"}},
		{line: "Nov  3 01:02:03 web1 sshd[99]: Invalid user oracle from 198.51.100.7 port 40100",
			kind: siem.KindSSHInvalidUser, lvl: siem.LvlWarn, actor: "oracle", ip: "198.51.100.7",
			f: map[string]any{"user": "oracle", "port": 40100.0}},
		{line: h + "sshd[99]: Invalid user  from 198.51.100.7 port 40100",
			kind: siem.KindSSHInvalidUser, lvl: siem.LvlWarn, actor: "", ip: "198.51.100.7"},
		{line: h + "sshd[1236]: Connection closed by invalid user admin 198.51.100.7 port 40022 [preauth]",
			kind: siem.KindSSHDisconnect, lvl: siem.LvlWarn, actor: "admin", ip: "198.51.100.7",
			f: map[string]any{"user": "admin", "invalid": true, "reason": "connection closed"}},
		{line: h + "sshd[1236]: Connection closed by authenticating user root 198.51.100.7 port 40024 [preauth]",
			kind: siem.KindSSHDisconnect, lvl: siem.LvlWarn, actor: "root", ip: "198.51.100.7",
			f: map[string]any{"user": "root", "reason": "connection closed"}},
		{line: h + "sshd[1236]: Connection closed by 198.51.100.7 port 40026 [preauth]",
			kind: siem.KindSSHDisconnect, lvl: siem.LvlWarn, ip: "198.51.100.7", f: map[string]any{"port": 40026.0}},
		{line: h + "sshd[1236]: Connection reset by 198.51.100.7 port 40040 [preauth]",
			kind: siem.KindSSHDisconnect, lvl: siem.LvlWarn, ip: "198.51.100.7", f: map[string]any{"reason": "connection reset"}},
		{line: h + "sshd[1236]: Disconnected from invalid user admin 198.51.100.7 port 40022 [preauth]",
			kind: siem.KindSSHDisconnect, lvl: siem.LvlWarn, actor: "admin", ip: "198.51.100.7",
			f: map[string]any{"invalid": true, "reason": "disconnected"}},
		{line: h + "sshd[1236]: Disconnected from authenticating user root 198.51.100.7 port 40024 [preauth]",
			kind: siem.KindSSHDisconnect, lvl: siem.LvlWarn, actor: "root", ip: "198.51.100.7"},
		{line: h + "sshd[1236]: Received disconnect from 198.51.100.7 port 40022:11: Bye Bye [preauth]",
			kind: siem.KindSSHDisconnect, lvl: siem.LvlWarn, ip: "198.51.100.7", f: map[string]any{"reason": "Bye Bye"}},
		{line: h + "sshd[1236]: error: maximum authentication attempts exceeded for root from 198.51.100.7 port 40030 ssh2 [preauth]",
			kind: siem.KindSSHDisconnect, lvl: siem.LvlWarn, actor: "root", ip: "198.51.100.7",
			f: map[string]any{"reason": "maximum authentication attempts exceeded"}},
		{line: h + "sshd[1236]: error: maximum authentication attempts exceeded for invalid user test from 198.51.100.7 port 40030 ssh2 [preauth]",
			kind: siem.KindSSHDisconnect, lvl: siem.LvlWarn, actor: "test", ip: "198.51.100.7", f: map[string]any{"invalid": true}},
		{line: h + "sshd[1236]: Disconnecting authenticating user root 198.51.100.7 port 40030: Too many authentication failures [preauth]",
			kind: siem.KindSSHDisconnect, lvl: siem.LvlWarn, actor: "root", ip: "198.51.100.7",
			f: map[string]any{"reason": "Too many authentication failures"}},
		{line: h + "sshd[1236]: Disconnecting invalid user test 198.51.100.7 port 40030: Too many authentication failures [preauth]",
			kind: siem.KindSSHDisconnect, lvl: siem.LvlWarn, actor: "test", ip: "198.51.100.7", f: map[string]any{"invalid": true}},
		{line: h + "sshd[1236]: Disconnecting: Too many authentication failures [preauth]",
			kind: siem.KindSSHDisconnect, lvl: siem.LvlWarn, f: map[string]any{"reason": "Too many authentication failures"}},
		// Post-auth session ends are ordinary logs, still attributed.
		{line: h + "sshd[1234]: Received disconnect from 203.0.113.5 port 52134:11: disconnected by user",
			kind: siem.KindLog, lvl: siem.LvlInfo, ip: "203.0.113.5"},
		{line: h + "sshd[1234]: Disconnected from user deploy 203.0.113.5 port 52134",
			kind: siem.KindLog, lvl: siem.LvlInfo, actor: "deploy", ip: "203.0.113.5"},
		{line: h + "sshd[1235]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.7  user=root",
			kind: siem.KindLog, lvl: siem.LvlInfo, ip: "198.51.100.7"},
		{line: h + "sshd[900]: Server listening on 0.0.0.0 port 22.", kind: siem.KindLog, lvl: siem.LvlInfo},
		{line: h + "sshd[901]: Unable to negotiate with 198.51.100.7 port 40050: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1",
			kind: siem.KindLog, lvl: siem.LvlInfo, ip: "198.51.100.7"},
		// rsyslog's repeat folding keeps the count.
		{line: h + "sshd[1235]: message repeated 2 times: [ Failed password for root from 198.51.100.7 port 40022 ssh2]",
			kind: siem.KindSSHLogin, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "root", ip: "198.51.100.7",
			f: map[string]any{"repeated": 2.0}},
		// A username can't move the address: sshd appends the real one last.
		{line: h + "sshd[1235]: Failed password for invalid user x from 6.6.6.6 port 1 from 203.0.113.5 port 22 ssh2",
			kind: siem.KindSSHLogin, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "x from 6.6.6.6 port 1", ip: "203.0.113.5"},
		{line: h + "sshd[99]: Invalid user a from 6.6.6.6 port 1 from 203.0.113.5 port 22",
			kind: siem.KindSSHInvalidUser, lvl: siem.LvlWarn, actor: "a from 6.6.6.6 port 1", ip: "203.0.113.5"},
		// A user name that also fakes the trailing key part only works against a lazy match.
		{line: h + "sshd[1235]: Failed password for invalid user x from 6.6.6.6 port 1 ssh2: RSA SHA256:x from 203.0.113.5 port 22 ssh2",
			kind: siem.KindSSHLogin, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "x from 6.6.6.6 port 1 ssh2: RSA SHA256:x", ip: "203.0.113.5"},
		// sshd logging a host name (UseDNS yes) instead of an address.
		{line: h + "sshd[1235]: Failed password for root from scanner.example.net port 40022 ssh2",
			kind: siem.KindSSHLogin, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "root", f: map[string]any{"remote": "scanner.example.net"}},
	})
}

func TestAuthLogRFC3339AndSSHDSession(t *testing.T) {
	runHost(t, []hostCase{
		{line: "2026-11-23T13:14:41.123456+01:00 web1 sshd[1234]: Accepted publickey for deploy from 203.0.113.5 port 52134 ssh2: ED25519 SHA256:abc",
			kind: siem.KindSSHLogin, out: siem.OutSuccess, lvl: siem.LvlInfo, actor: "deploy", ip: "203.0.113.5"},
		{line: "2026-11-23T13:14:42.000001+00:00 web1 sshd-session[2001]: Failed password for root from 198.51.100.7 port 40022 ssh2",
			kind: siem.KindSSHLogin, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "root", ip: "198.51.100.7",
			f: map[string]any{"program": "sshd-session", "pid": 2001.0}},
		{line: "2026-11-23T13:14:42Z web1 sshd-auth[2002]: Invalid user bob from 198.51.100.7 port 1",
			kind: siem.KindSSHInvalidUser, lvl: siem.LvlWarn, actor: "bob", ip: "198.51.100.7"},
	})
	e, _ := AuthLog("2026-11-23T13:14:41.123456+01:00 web1 sshd[1]: x", hostNow, wat)
	if want := time.Date(2026, 11, 23, 12, 14, 41, 123456000, time.UTC); !e.TS.Equal(want) {
		t.Errorf("RFC 3339 TS %v want %v", e.TS, want)
	}
	// A timestamp more than a day ahead of now is not trusted.
	e, _ = AuthLog("2026-11-25T13:14:41+01:00 web1 sshd[1]: x", hostNow, wat)
	if !e.TS.Equal(hostNow) {
		t.Errorf("future TS %v want now", e.TS)
	}
	// A backlog from days ago keeps its own time.
	e, _ = AuthLog("2026-11-20T13:14:41+01:00 web1 sshd[1]: x", hostNow, wat)
	if want := time.Date(2026, 11, 20, 12, 14, 41, 0, time.UTC); !e.TS.Equal(want) {
		t.Errorf("past TS %v", e.TS)
	}
}

func TestAuthLogSudo(t *testing.T) {
	const h = "Nov 23 13:20:01 web1 sudo: "
	runHost(t, []hostCase{
		{line: h + "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart mooring",
			kind: siem.KindSudo, out: siem.OutSuccess, lvl: siem.LvlInfo, actor: "alice",
			f: map[string]any{"user": "alice", "target_user": "root", "tty": "pts/0", "cwd": "/home/alice",
				"command": "/usr/bin/systemctl restart mooring", "program": "sudo"}},
		{line: "2026-11-23T13:20:01.555555+01:00 web1 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update",
			kind: siem.KindSudo, out: siem.OutSuccess, lvl: siem.LvlInfo, actor: "alice", f: map[string]any{"command": "/usr/bin/apt update"}},
		{line: h + "   alice : TTY=pts/0 ; PWD=/root ; USER=root ; GROUP=docker ; COMMAND=/bin/sh -c echo a ; echo b",
			kind: siem.KindSudo, out: siem.OutSuccess, lvl: siem.LvlInfo, actor: "alice",
			f: map[string]any{"command": "/bin/sh -c echo a ; echo b", "target_group": "docker"}},
		{line: h + "   deploy : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id",
			kind: siem.KindSudo, out: siem.OutSuccess, lvl: siem.LvlInfo, actor: "deploy", f: map[string]any{"tty": "unknown"}},
		{line: h + "   alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash",
			kind: siem.KindSudo, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "alice",
			f: map[string]any{"reason": "3 incorrect password attempts", "command": "/bin/bash", "target_user": "root"}},
		{line: h + "   alice : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls",
			kind: siem.KindSudo, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "alice"},
		{line: h + "     bob : command not allowed ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/cat /etc/shadow",
			kind: siem.KindSudo, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "bob",
			f: map[string]any{"reason": "command not allowed", "command": "/bin/cat /etc/shadow"}},
		{line: h + "     eve : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/eve ; USER=root ; COMMAND=/bin/sh",
			kind: siem.KindSudo, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "eve", f: map[string]any{"reason": "user NOT in sudoers"}},
		{line: h + "pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=alice",
			kind: siem.KindSudo, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "alice",
			f: map[string]any{"user": "alice", "target_user": "alice", "reason": "authentication failure", "tty": "/dev/pts/0"}},
		{line: h + "pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)",
			kind: siem.KindLog, lvl: siem.LvlInfo},
		{line: h + "   alice : unable to resolve host web1: Name or service not known",
			kind: siem.KindLog, lvl: siem.LvlInfo},
	})
}

func TestAuthLogSudoAmbiguous(t *testing.T) {
	const h = "Nov 23 13:20:01 web1 sudo: "
	for _, line := range []string{
		// cd '/tmp/COMMAND=/usr/bin/true' && sudo -u root /bin/bash
		h + "  mallory : TTY=pts/0 ; PWD=/tmp/COMMAND=/usr/bin/true ; USER=root ; COMMAND=/bin/bash",
		// cd '/tmp/x ; USER=nobody' && sudo /bin/bash
		h + "  mallory : TTY=pts/0 ; PWD=/tmp/x ; USER=nobody ; USER=root ; COMMAND=/bin/bash",
		h + "  mallory : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/tmp/COMMAND=x ; USER=root ; COMMAND=/bin/sh",
	} {
		e, ok := AuthLog(line, hostNow, wat)
		if !ok {
			t.Fatalf("%s: not ok", line)
		}
		checkEvent(t, e)
		if e.Kind != siem.KindSudo || e.Actor != "mallory" || e.Lvl != siem.LvlWarn || e.F["ambiguous"] != true {
			t.Errorf("%s:\n %+v", line, e)
		}
		for _, k := range []string{"command", "target_user", "cwd"} {
			if v, ok := e.F[k]; ok {
				t.Errorf("%s: ambiguous line must not pick %s=%v", line, k, v)
			}
		}
		if want := line[len(h):]; e.Msg != want {
			t.Errorf("Msg %q want the raw message", e.Msg)
		}
	}
	e, _ := AuthLog(h+"  mallory : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/tmp/COMMAND=x ; USER=root ; COMMAND=/bin/sh", hostNow, wat)
	if e.Out != siem.OutFailure || e.F["reason"] != "3 incorrect password attempts" || e.F["tty"] != "pts/0" {
		t.Errorf("reason/tty before PWD are kept: %+v", e)
	}
	// A single COMMAND= and USER= is not ambiguous.
	e, _ = AuthLog(h+"  alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id", hostNow, wat)
	if e.F["ambiguous"] != nil || e.F["command"] != "/usr/bin/id" {
		t.Errorf("plain line: %v", e.F)
	}
}

func TestAuthLogSu(t *testing.T) {
	const h = "Nov 23 13:25:00 web1 "
	runHost(t, []hostCase{
		{line: h + "su: pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)",
			kind: siem.KindSu, out: siem.OutSuccess, lvl: siem.LvlInfo, actor: "alice",
			f: map[string]any{"user": "alice", "target_user": "root"}},
		{line: h + "su[4242]: pam_unix(su-l:session): session opened for user postgres(uid=113) by root(uid=0)",
			kind: siem.KindSu, out: siem.OutSuccess, lvl: siem.LvlInfo, actor: "root", f: map[string]any{"target_user": "postgres"}},
		{line: h + "su[4242]: pam_unix(su:session): session opened for user root(uid=0) by (uid=0)",
			kind: siem.KindSu, out: siem.OutSuccess, lvl: siem.LvlInfo, actor: "", f: map[string]any{"target_user": "root"}},
		{line: h + "su[4242]: FAILED SU (to root) alice on pts/0",
			kind: siem.KindSu, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "alice",
			f: map[string]any{"user": "alice", "target_user": "root", "tty": "pts/0"}},
		{line: h + "su[4242]: FAILED su for root by alice",
			kind: siem.KindSu, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "alice", f: map[string]any{"target_user": "root"}},
		{line: h + "su[4242]: pam_unix(su:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=root",
			kind: siem.KindSu, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "alice",
			f: map[string]any{"user": "alice", "target_user": "root", "reason": "authentication failure"}},
		{line: h + "su[4242]: pam_unix(su:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser= rhost=  user=root",
			kind: siem.KindSu, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "alice"},
		// ruser (who asked) wins over logname (who logged in on the terminal).
		{line: h + "su[4242]: pam_unix(su:auth): authentication failure; logname=bob uid=1001 euid=0 tty=/dev/pts/3 ruser=carol rhost=  user=root",
			kind: siem.KindSu, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "carol", f: map[string]any{"user": "carol", "target_user": "root"}},
		// pam_unix logs the target name last and raw: a name carrying "ruser=… rhost=…" can't
		// override the real values, which come first.
		{line: h + "su: pam_unix(su:auth): authentication failure; logname=mallory uid=1001 euid=0 tty=pts/0 ruser=mallory rhost=  user=x ruser=root rhost=6.6.6.6",
			kind: siem.KindSu, out: siem.OutFailure, lvl: siem.LvlWarn, actor: "mallory", ip: "",
			f: map[string]any{"user": "mallory", "target_user": "x", "tty": "pts/0"}},
		{line: h + "su[4242]: (to root) alice on pts/0", kind: siem.KindLog, lvl: siem.LvlInfo},
		{line: h + "su[4242]: pam_unix(su:session): session closed for user root", kind: siem.KindLog, lvl: siem.LvlInfo},
	})
}

func TestAuthLogUserChange(t *testing.T) {
	const h = "Nov 23 14:00:00 web1 "
	uc := func(line, prog, key, name string) hostCase {
		f := map[string]any{"program": prog, "detail": line[strings.Index(line, ": ")+2:]}
		if key != "" {
			f[key] = name
		}
		return hostCase{line: line, kind: siem.KindUserChange, lvl: siem.LvlInfo, f: f}
	}
	runHost(t, []hostCase{
		uc(h+"useradd[5000]: new user: name=mallory, UID=1002, GID=1002, home=/home/mallory, shell=/bin/bash, from=/dev/pts/0", "useradd", "user", "mallory"),
		uc(h+"useradd[5000]: new group: name=mallory, GID=1002", "useradd", "user", "mallory"),
		uc(h+"usermod[5001]: add 'mallory' to group 'sudo'", "usermod", "user", "mallory"),
		uc(h+"usermod[5001]: add 'mallory' to shadow group 'sudo'", "usermod", "user", "mallory"),
		uc(h+"userdel[5002]: delete user 'mallory'", "userdel", "user", "mallory"),
		uc(h+"passwd[5003]: pam_unix(passwd:chauthtok): password changed for mallory", "passwd", "user", "mallory"),
		uc(h+"chpasswd[5004]: pam_unix(chpasswd:chauthtok): password changed for bob", "chpasswd", "user", "bob"),
		uc(h+"groupadd[5005]: group added to /etc/group: name=devs, GID=1003", "groupadd", "group", "devs"),
		uc(h+"groupdel[5005]: group 'devs' removed", "groupdel", "group", "devs"),
		uc(h+"gpasswd[5006]: user mallory added by root to group docker", "gpasswd", "user", "mallory"),
		uc(h+"chage[5007]: changed password expiry for mallory", "chage", "user", "mallory"),
		uc(h+"groupmod[5008]: something odd", "groupmod", "", ""),
	})
}

func TestAuthLogOther(t *testing.T) {
	const h = "Nov 23 13:30:01 web1 "
	runHost(t, []hostCase{
		{line: h + "CRON[6000]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
			kind: siem.KindLog, lvl: siem.LvlInfo, f: map[string]any{"program": "CRON", "pid": 6000.0},
			msg: "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"},
		{line: h + "systemd-logind[700]: New session 12 of user alice.", kind: siem.KindLog, lvl: siem.LvlInfo,
			f: map[string]any{"program": "systemd-logind"}},
		{line: h + "kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.9 DST=203.0.113.1", kind: siem.KindLog, lvl: siem.LvlInfo,
			ip: "198.51.100.9", f: map[string]any{"program": "kernel"}},
		{line: h + "no tag here at all", kind: siem.KindLog, lvl: siem.LvlInfo, msg: "no tag here at all"},
		// A program that only looks like sshd is not classified.
		{line: h + "notsshd[1]: Accepted password for root from 203.0.113.5 port 1 ssh2", kind: siem.KindLog, lvl: siem.LvlInfo, ip: "203.0.113.5"},
	})
}

func TestAuthLogTimestamps(t *testing.T) {
	// RFC 3164 is read in loc.
	e, _ := AuthLog("Nov 23 13:14:41 web1 sshd[1]: x", hostNow, wat)
	if want := time.Date(2026, 11, 23, 12, 14, 41, 0, time.UTC); !e.TS.Equal(want) {
		t.Errorf("loc: %v want %v", e.TS, want)
	}
	cases := []struct {
		now  time.Time
		line string
		want time.Time
	}{
		// New Year: December lines read in January belong to last year.
		{time.Date(2027, 1, 1, 0, 30, 0, 0, wat), "Dec 31 23:59:59 h p: m", time.Date(2026, 12, 31, 23, 59, 59, 0, wat)},
		{time.Date(2027, 1, 1, 0, 30, 0, 0, wat), "Jan  1 00:29:00 h p: m", time.Date(2027, 1, 1, 0, 29, 0, 0, wat)},
		// Up to a day ahead (clock skew) stays this year; more is last year.
		{hostNow, "Nov 24 13:00:00 h p: m", time.Date(2026, 11, 24, 13, 0, 0, 0, wat)},
		{hostNow, "Nov 24 16:00:00 h p: m", time.Date(2025, 11, 24, 16, 0, 0, 0, wat)},
		{hostNow, "Dec 25 10:00:00 h p: m", time.Date(2025, 12, 25, 10, 0, 0, 0, wat)},
		{hostNow, "Nov  3 10:00:00 h p: m", time.Date(2026, 11, 3, 10, 0, 0, 0, wat)},
		{hostNow, "Nov 3 10:00:00 h p: m", time.Date(2026, 11, 3, 10, 0, 0, 0, wat)},
	}
	for _, c := range cases {
		e, ok := AuthLog(c.line, c.now, wat)
		if !ok || !e.TS.Equal(c.want) {
			t.Errorf("now %v %q: ok=%v TS %v want %v", c.now, c.line, ok, e.TS, c.want)
		}
	}
	// nil loc means the local zone, never a panic.
	if _, ok := AuthLog("Nov 23 13:14:41 web1 sshd[1]: x", hostNow, nil); !ok {
		t.Error("nil loc")
	}
}

func TestAuthLogHostile(t *testing.T) {
	for _, line := range []string{"", "   ", "\n", "garbage", "Nov 99 99:99:99 h p: m", "Foo 23 13:14:41 h p: m",
		"2026-13-45T99:00:00Z h sshd[1]: x", "Nov 23 13:14:41", "Nov 23 13:14:41 ", "\x00\x00\x00"} {
		if _, ok := AuthLog(line, hostNow, wat); ok {
			t.Errorf("%q must not parse", line)
		}
	}
	long := "Nov 23 13:14:41 web1 sshd[1]: Invalid user " + strings.Repeat("A", 8<<10) + " from 198.51.100.7 port 1"
	for _, line := range []string{
		long,
		"Nov 23 13:14:41 web1 sshd[1]: Failed password for \x00\xff\xfe from 198.51.100.7 port 1 ssh2",
		"Nov 23 13:14:41 web1 sshd[\xff]: Accepted password for root from 198.51.100.7 port 99999999999999999999 ssh2",
		"Nov 23 13:14:41 web1 sudo: x : TTY=" + strings.Repeat(" ; ", 3000),
		"Nov 23 13:14:41 web1 sshd[1]: message repeated 99999999999999999999 times: [ x",
		"Nov 23 13:14:41 web1 [1]: x",
		"Nov 23 13:14:41 web1 :",
	} {
		e, ok := AuthLog(line, hostNow, wat)
		if !ok {
			t.Errorf("%.60q must parse as a host line", line)
			continue
		}
		checkEvent(t, e)
	}
	e, _ := AuthLog(long, hostNow, wat)
	if e.Kind != siem.KindSSHInvalidUser || e.IP != "198.51.100.7" {
		t.Errorf("long user: %q %q", e.Kind, e.IP)
	}
}

func TestAuthLogSudoFieldOrder(t *testing.T) {
	const h = "Nov 23 13:20:01 web1 sudo: "
	for _, rest := range []string{
		"TTY=pts/0 ; PWD=/tmp/x ; GROUP=wheel ; USER=root ; COMMAND=/bin/id", // a directory "x ; GROUP=wheel"
		"PWD=/tmp/x ; TTY=pts/9 ; USER=root ; COMMAND=/bin/id",               // TTY written by a directory, no terminal
		"TTY=pts/0 ; PWD=/tmp/a ; stray ; USER=root ; COMMAND=/bin/id",
		"TTY=pts/0 ; PWD=/tmp/a ; X=1 ; USER=root ; COMMAND=/bin/id",
		"TTY=pts/0 ; USER=root ; PWD=/tmp ; COMMAND=/bin/id",
	} {
		e, _ := AuthLog(h+"  mallory : "+rest, hostNow, wat)
		if e.F["ambiguous"] != true || e.Lvl != siem.LvlWarn || e.F["target_group"] != nil || e.F["command"] != nil {
			t.Errorf("%s: %+v", rest, e.F)
		}
	}
	for rest, want := range map[string]map[string]any{
		"TTY=pts/0 ; PWD=/ ; USER=root ; GROUP=docker ; COMMAND=/usr/bin/id":      {"target_group": "docker", "command": "/usr/bin/id"},
		"TTY=pts/0 ; PWD=/ ; USER=root ; ENV=LANG=C ; COMMAND=/usr/bin/id":        {"target_user": "root", "command": "/usr/bin/id"},
		"PWD=/ ; USER=root ; COMMAND=/usr/bin/id":                                 {"cwd": "/", "target_user": "root"},
		"TTY=pts/0 ; PWD=/tmp/COMMAND-dir ; USER=root ; COMMAND=/bin/sh -c a ; b": {"cwd": "/tmp/COMMAND-dir", "command": "/bin/sh -c a ; b"},
	} {
		e, _ := AuthLog(h+"  alice : "+rest, hostNow, wat)
		if e.F["ambiguous"] != nil {
			t.Errorf("%s: flagged ambiguous", rest)
		}
		for k, v := range want {
			if e.F[k] != v {
				t.Errorf("%s: F[%s] = %v want %v", rest, k, e.F[k], v)
			}
		}
	}
}
