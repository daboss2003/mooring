package detect

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
)

// Re-audit 4: the last three items.

// Item 1: one (rule, address) pair seen from two sources (the scope column holds the events'
// source for an address) is one pair: muted once, counted once.
func TestMutePairCountsAnAddressOnce(t *testing.T) {
	h := incHarness(t, true)
	h.only(t, incRule("custom.ip", siem.SevHigh, "ip", "kind:t.x"))
	h.feed(incEv(0, siem.SrcHost, "t.x", addrX, "", nil))
	h.flushAlerts()
	id := h.detIncident(t, "custom.ip", addrX)
	h.feed(incEv(3*time.Hour, siem.SrcEdge, "t.x", addrX, "", nil)) // a second detection, another source
	h.flushAlerts()
	if n := countRows(t, h, `SELECT COUNT(*) FROM detections WHERE incident_id = ?`, id); n != 2 {
		t.Fatalf("setup: %d detections", n)
	}
	rep := make(chan incReply, 1)
	h.e.serve(&incReq{op: opFPPairs, id: id, reply: rep})
	if r := <-rep; r.err != nil || len(r.pairs) != 1 || r.pairs[0].Entity != addr(addrX) {
		t.Fatalf("pairs %+v %v", r.pairs, r.err)
	}
	stop := h.run(t)
	if err := h.e.MarkFalsePositive(context.Background(), id, "owner", true, ""); err != nil {
		t.Fatal(err)
	}
	stop()
	inc := h.incGet(t, id)
	if tl := inc.Timeline[len(inc.Timeline)-1]; tl.Kind != siem.TimelineMuted || !strings.HasPrefix(tl.Text, "1 rule and entity pair muted") {
		t.Fatalf("timeline %+v", inc.Timeline)
	}
}

// Item 2 (owner decision): a sign-in listing two addresses, the first of whose incidents makes the
// chain for the account already, joins the other's, which it completes (raised to critical).
func TestChainJoinPrefersTheIncidentItCompletes(t *testing.T) {
	h := incHarness(t, false)
	tr := incRule("ssh.login_travel", siem.SevHigh, "actor", "kind:t.tr")
	tr.Count = 2
	h.only(t, incRule("ssh.bruteforce", siem.SevHigh, "ip", "kind:t.bf"),
		incRule("ssh.success_after_failures", siem.SevHigh, "ip", "kind:t.saf"), tr)
	h.feed(hostEv(0, "t.bf", addrX, "root"))
	h.feed(hostEv(time.Minute, "t.bf", addrY, "root"))
	h.feed(hostEv(20*time.Minute, "t.saf", addrX, "root"))
	h.flushAlerts()
	iX, iY := h.detIncident(t, "ssh.bruteforce", addrX), h.detIncident(t, "ssh.bruteforce", addrY)
	h.feed(hostEv(30*time.Minute, "t.tr", addrX, "root"))
	h.feed(hostEv(31*time.Minute, "t.tr", addrY, "root"))
	al := h.flushAlerts()
	y := h.incGet(t, iY)
	if got := h.detIncident(t, "ssh.login_travel", "root"); got != iY || y.Chain != "Brute force then sign-in" ||
		y.Severity != siem.SevCritical {
		t.Fatalf("travel joined %d (X %d, Y %d): Y %+v", got, iX, iY, y)
	}
	if len(al) != 1 || al[0].Level != alert.LevelCritical || al[0].DedupeKey != "siem-incident:"+itoa(iY) {
		t.Fatalf("alerts %+v", al)
	}
}

// Item 3: at start, the mutes of the accounts of apps that no longer exist go (Mooring's database
// and in force); existing apps' and other scopes' stay; an empty list of apps removes every app's.
func TestKeepAppMutes(t *testing.T) {
	h := incHarness(t, true)
	ctx := context.Background()
	scopes := []string{"app:shop", "app:gone", "app:gone-2", "app", "mooring", "host"}
	var pairs []siem.Mute
	for _, sc := range scopes {
		pairs = append(pairs, siem.Mute{RuleID: "custom.r", Entity: acct(sc, "alice")})
	}
	pairs = append(pairs, siem.Mute{RuleID: "custom.r", Entity: addr(addrX)})
	if err := h.e.addMutes(ctx, pairs, h.clk.now().Add(muteFor), "owner", 1); err != nil {
		t.Fatal(err)
	}
	stored := func() string {
		t.Helper()
		rows, err := h.main.Query(`SELECT kind, scope FROM security_mutes ORDER BY kind, scope`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var k, s string
			if err := rows.Scan(&k, &s); err != nil {
				t.Fatal(err)
			}
			out = append(out, k+":"+s)
		}
		return strings.Join(out, ",")
	}
	muted := func(sc string) bool { return h.e.isMuted("custom.r", entOf(acct(sc, "alice")), h.clk.now()) }
	if err := h.e.KeepAppMutes(ctx, []string{"shop", "other"}); err != nil {
		t.Fatal(err)
	}
	if got := stored(); got != "account:app,account:app:shop,account:host,account:mooring,address:" {
		t.Fatalf("stored %s", got)
	}
	if muted("app:gone") || muted("app:gone-2") || !muted("app:shop") || !muted("app") || !muted("mooring") ||
		!h.e.isMuted("custom.r", entOf(addr(addrX)), h.clk.now()) {
		t.Fatal("in force")
	}
	if err := h.e.KeepAppMutes(ctx, nil); err != nil { // no app left
		t.Fatal(err)
	}
	if got := stored(); got != "account:app,account:host,account:mooring,address:" || muted("app:shop") {
		t.Fatalf("no apps: stored %s", got)
	}
	// Without Mooring's database there are no mutes: nothing to do.
	h2 := incHarness(t, false)
	if err := h2.e.KeepAppMutes(ctx, nil); err != nil {
		t.Fatal(fmt.Sprint("no store: ", err))
	}
}
