package pipeline

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/hostlog"
	"github.com/daboss2003/mooring/internal/siem/parse"
)

// users is a fake uid → name lookup that counts its calls.
type users struct {
	mu    sync.Mutex
	names map[string]string
	calls map[string]int
}

func newUsers() *users {
	return &users{names: map[string]string{"1000": "alice", "1001": "bob"}, calls: map[string]int{}}
}

func (u *users) lookup(uid string) (string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.calls[uid]++
	if n, ok := u.names[uid]; ok {
		return n, nil
	}
	return "", errors.New("user: unknown userid " + uid)
}

func (u *users) n(uid string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls[uid]
}

func journalEntry(ident, uid, msg string) string {
	b, _ := json.Marshal(map[string]string{"SYSLOG_IDENTIFIER": ident, "_UID": uid, "MESSAGE": msg,
		"__REALTIME_TIMESTAMP": "1795440881123456"})
	return string(b)
}

// sudo, su and passwd are taken from the journal whatever user sent them (journald records the
// invoking user for them). One whose sender isn't the user the line names was written by someone
// else (logger -t sudo …): it is kept, flagged sender_mismatch.
func TestSenderCheck(t *testing.T) {
	u := newUsers()
	p := New(Options{Log: discard})
	p.lookupUID = u.lookup
	r := &runner{p: p}
	now := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	const (
		sudoAlice = "   alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/true"
		suAlice   = "FAILED SU (to root) alice on pts/0"
		pwAlice   = "pam_unix(passwd:chauthtok): password changed for alice"
		sudoFail  = "pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=alice"
	)
	for _, c := range []struct {
		ident, uid, msg string
		flag            bool
	}{
		{"sudo", "1000", sudoAlice, false}, // alice's own sudo
		{"sudo", "1000", sudoFail, false},  // her failed password
		{"sudo", "1001", sudoAlice, true},  // bob writing a sudo line about alice
		{"sudo", "0", sudoAlice, false},    // root is trusted
		{"sudo", "4242", sudoAlice, false}, // a uid with no user name (an LDAP/SSSD user): not flagged (owner decision)
		{"su", "1000", suAlice, false},     //
		{"su", "1001", suAlice, true},      //
		{"passwd", "1000", pwAlice, false}, //
		{"passwd", "1001", pwAlice, true},  //
		{"passwd", "0", pwAlice, false},    // root changing alice's password
		{"sudo", "1001", "pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1001)", false}, // not a sudo.command
		{"passwd", "1001", "pam_unix(passwd:chauthtok): password - (old) token not obtained", false},         // names no user
		{"sshd", "0", "Accepted password for alice from 203.0.113.9 port 22 ssh2", false},                    // root-only source
		{"useradd", "0", "new user: name=alice, UID=1000", false},                                            //
		// Lines that name no user: the invoking uid they state must be the sender's.
		{"su", "1001", "pam_unix(su:session): session opened for user root(uid=0) by (uid=0)", true},                                            // forged: bob claims root opened it
		{"su", "1001", "pam_unix(su:session): session opened for user root(uid=0) by (uid=1001)", false},                                        // bob's own, his name unknown to PAM
		{"su", "1001", "pam_unix(su:auth): authentication failure; logname= uid=1001 euid=0 tty=/dev/pts/0 ruser= rhost=  user=root", false},    // bob's own failure, no login name
		{"sudo", "1001", "pam_unix(sudo:auth): authentication failure; logname= uid=0 euid=0 tty= ruser= rhost=6.6.6.6  user=root", true},       // forged: uid 0 from bob
		{"sudo", "1001", "pam_unix(sudo:auth): authentication failure; logname= uid=1001 euid=0 tty=/dev/pts/0 ruser= rhost=  user=bob", false}, // bob's own
		{"sudo", "1001", "pam_unix(sudo:auth): authentication failure; logname= uid=1001 euid=0 tty= ruser= rhost=  user=root uid=0", true},     // any stated uid that isn't the sender's
		{"sudo", "1001", "pam_unix(sudo:auth): authentication failure; logname= uid=1001 uid=0 euid=0 tty= ruser= rhost=  user=root", true},     // adjacent claims
		{"sudo", "1001", "pam_unix(sudo:auth): authentication failure; user=root", true},                                                        // a root claim with no uid at all
		{"sudo", "0", "pam_unix(sudo:auth): authentication failure; user=root", false},                                                          // root is trusted
		{"sudo", "4242", "pam_unix(sudo:auth): authentication failure; logname= uid=4242 euid=0 tty= ruser= rhost=  user=root", false},          // a nameless (LDAP) uid's own
		{"sudo", "4242", "pam_unix(sudo:auth): authentication failure; logname= uid=0 euid=0 tty= ruser= rhost=  user=root", true},              // a nameless uid forging uid 0: no lookup needed
	} {
		ev, ok := parse.Journal([]byte(journalEntry(c.ident, c.uid, c.msg)))
		if !ok {
			t.Fatalf("%s/%s: parse.Journal dropped %q", c.ident, c.uid, c.msg)
		}
		r.checkSender(&ev, now)
		if got := ev.F["sender_mismatch"] == true; got != c.flag {
			t.Errorf("%s from uid %s (%q): sender_mismatch = %v, want %v (F=%v)", c.ident, c.uid, c.msg, got, c.flag, ev.F)
		}
		if _, set := ev.F["sender_mismatch"]; set && !c.flag {
			t.Errorf("%s from uid %s: sender_mismatch set to %v", c.ident, c.uid, ev.F["sender_mismatch"])
		}
	}
	// A line stating more uids than any real one is flagged, even when they are all the sender's.
	many := "pam_unix(sudo:auth): authentication failure; logname=" + strings.Repeat(" uid=1001", maxLineUIDs+1) + " user=root"
	ev, _ := parse.Journal([]byte(journalEntry("sudo", "1001", many)))
	if r.checkSender(&ev, now); ev.F["sender_mismatch"] != true {
		t.Errorf("a line stating %d uids: not flagged (F=%v)", maxLineUIDs+1, ev.F)
	}
	// Only sudo, su and passwd are checked (parse.Journal keeps no other program from a non-root uid).
	for _, kind := range []string{siem.KindSSHLogin, siem.KindUserChange, siem.KindLog} {
		ev := siem.Event{Src: siem.SrcHost, Kind: kind, F: map[string]any{"sender_uid": "1001", "user": "alice", "program": "useradd"}}
		r.checkSender(&ev, now)
		if _, set := ev.F["sender_mismatch"]; set {
			t.Errorf("%s checked: %v", kind, ev.F)
		}
	}
	if n := u.n("0"); n != 0 {
		t.Errorf("uid 0 looked up %d times; root is never looked up", n)
	}
	if n := u.n("1001"); n != 1 {
		t.Errorf("uid 1001 looked up %d times, want 1 (cached)", n)
	}
}

func TestSenderCacheTTLAndBound(t *testing.T) {
	u := newUsers()
	p := New(Options{Log: discard})
	p.lookupUID = u.lookup
	r := &runner{p: p}
	now := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	for range 3 {
		r.senderName("1000", now)
	}
	if n := u.n("1000"); n != 1 {
		t.Fatalf("looked up %d times within the TTL, want 1", n)
	}
	r.senderName("1000", now.Add(sendersTTL-time.Second))
	if n := u.n("1000"); n != 1 {
		t.Fatalf("looked up again before the TTL: %d", n)
	}
	r.senderName("1000", now.Add(sendersTTL))
	if n := u.n("1000"); n != 2 {
		t.Fatalf("not looked up again after the TTL: %d", n)
	}
	if got := r.senderName("4242", now); got != "" {
		t.Fatalf("unknown uid resolved to %q", got)
	}
	for i := range 3 * sendersMax {
		r.senderName(strconv.Itoa(20000+i), now)
		if len(r.senders) > sendersMax {
			t.Fatalf("cache grew to %d entries (max %d)", len(r.senders), sendersMax)
		}
	}
}

// End to end through Run: the flag is set on the stored event, and the event is never dropped.
func TestSenderMismatchStored(t *testing.T) {
	u := newUsers()
	h := newHarness(t, 64, nil)
	h.p.parse.journal = parse.Journal
	h.p.lookupUID = u.lookup
	h.run()
	h.p.HostLine(hostlog.Line{Source: hostlog.SourceJournal, Text: journalEntry("sudo", "1001", "   alice : PWD=/ ; USER=root ; COMMAND=/bin/forged"), At: h.clk.Now()})
	h.p.HostLine(hostlog.Line{Source: hostlog.SourceJournal, Text: journalEntry("sudo", "1000", "   alice : PWD=/ ; USER=root ; COMMAND=/usr/bin/true"), At: h.clk.Now()})
	h.advance(time.Second)
	evs := h.st.events()
	if len(evs) != 2 {
		t.Fatalf("stored %d events, want both: %+v", len(evs), evs)
	}
	if evs[0].Kind != siem.KindSudo || evs[0].F["sender_mismatch"] != true || evs[0].F["sender_uid"] != "1001" {
		t.Errorf("forged sudo line: %+v", evs[0])
	}
	if _, set := evs[1].F["sender_mismatch"]; set || evs[1].F["sender_uid"] != "1000" {
		t.Errorf("alice's own sudo line: %+v", evs[1])
	}
}
