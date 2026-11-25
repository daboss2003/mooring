package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/blocklist"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/l4"
	"github.com/daboss2003/mooring/internal/siem"
)

func TestBlocksPage(t *testing.T) {
	now := time.Now().UTC()
	b := newBlockFake(now)
	e := respEnv(t, nil, b)
	e.srv.l4Routes = l4.NewRouteStore(e.srv.db)
	if err := e.srv.l4Routes.ReplaceProject(context.Background(), "shop", []l4.Route{
		{AppID: "shop", Listen: 5432, Protocol: "tcp", Service: "db", Port: 5432, Forward: "kernel"},
		{AppID: "shop", Listen: 6379, Protocol: "tcp", Service: "cache", Port: 6379, Forward: "proxy"},
	}); err != nil {
		t.Fatal(err)
	}
	sess := e.loginAs(t, "operator")
	resp, body := e.get(t, "/security/blocks", sess)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET = %d", resp.StatusCode)
	}
	for _, want := range []string{
		"1<small> / 1,000", ">Applied<", "Last applied", ">Not filtered<",
		">198.51.100.7/32<", `href="/security/detections?rule=edge.scan"`, "Scanning &lt;i&gt;paths&lt;/i&gt;", `href="/security/incidents/9"`,
		">203.0.113.0/24<", "by operator", ">Suspended<", "Not applied: it covers the address of a signed-in dashboard session",
		`name="prefix" value="198.51.100.7/32"`, "Remove the block of 198.51.100.7/32?",
		// refusals
		">192.0.2.1/32<", ">It overlaps ip_allowlist<", "in 192.0.2.0/24", ">4<",
		// the count's header, and the incident link in the Source cell
		`title="Automatic blocks of it placed within 30 days of each other">Times blocked<`, `<a href="/security/incidents/9">Incident #9</a>`,
		// the manual form: lengths up to the default longest (30 days), 24 hours chosen
		`<option value="1h">1 hour`, `<option value="24h" selected>24 hours`, `<option value="7d">7 days`, `<option value="30d">30 days`,
		// not filtered: SSH, the kernel route, and (L4 blocking off) the proxy route
		"SSH and any other port", ">5432/tcp<", "forward: kernel (Docker forwards it)", ">6379/tcp<", "L4 blocking is off",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if strings.Contains(body, "<i>paths</i>") {
		t.Error("a reason reached the page unescaped")
	}
	if strings.Contains(body, "Blocks in 30 days") || strings.Contains(body, "<th>Incident</th>") {
		t.Error("the blocks table still has its old count header or its Incident column")
	}
	b.mu.Lock()
	fl := b.lists[len(b.lists)-1]
	b.mu.Unlock()
	if !slices.Equal(fl.States, []string{blocklist.StateActive, blocklist.StateSuspended}) || fl.Source != "" || fl.Limit != blockListMax {
		t.Errorf("list filter = %+v", fl)
	}
	_, body = e.get(t, "/security/blocks?source=manual", sess)
	b.mu.Lock()
	fl = b.lists[len(b.lists)-1]
	b.mu.Unlock()
	if fl.Source != blocklist.SourceManual || strings.Contains(body, ">198.51.100.7/32<") {
		t.Errorf("manual filter = %+v", fl)
	}
	// With L4 blocking on, a proxy listener is filtered; a kernel one never is.
	b.mu.Lock()
	b.status.L4 = true
	b.mu.Unlock()
	_, body = e.get(t, "/security/blocks", sess)
	if !strings.Contains(body, ">5432/tcp<") || strings.Contains(body, ">6379/tcp<") || !strings.Contains(body, "IPv6 clients of L4 listeners") {
		t.Error("L4 on: want only the kernel listener as not filtered")
	}
	// Automatic blocks that can't be placed say why; a failing apply is shown.
	b.mu.Lock()
	b.status.Automatic, b.status.AutomaticWhy, b.status.ApplyErr = false, blocklist.RefuseOldCaddy, "caddy: load failed"
	b.list, b.refusals = nil, nil
	b.mu.Unlock()
	_, body = e.get(t, "/security/blocks", sess)
	for _, want := range []string{"Not placed: the running Caddy is older than 2.11", ">Failing<", "caddy: load failed", "No blocks in force", "No block was refused recently."} {
		if !strings.Contains(body, want) {
			t.Errorf("states: missing %q", want)
		}
	}
	// Read errors: generic, 500.
	b.mu.Lock()
	b.listErr, b.refErr = errors.New("db /var/lib/x"), errors.New("db /var/lib/x")
	b.mu.Unlock()
	resp, body = e.get(t, "/security/blocks", sess)
	if resp.StatusCode != http.StatusInternalServerError || strings.Contains(body, "/var/lib/x") || strings.Count(body, "log has the details") != 2 {
		t.Errorf("read errors = %d", resp.StatusCode)
	}
}

func TestBlockAdd(t *testing.T) {
	b := newBlockFake(time.Now().UTC())
	e := respEnv(t, nil, b)
	sess, csrf := e.detLogin(t, "operator")
	for _, c := range []struct{ prefix, want string }{
		{"203.0.113.7", "203.0.113.7/32"}, {" 203.0.113.9/24 ", "203.0.113.0/24"}, {"::ffff:203.0.113.8", "203.0.113.8/32"},
		{"2001:db8:1:2::9/64", "2001:db8:1:2::/64"},
	} {
		resp, _ := e.detPost(t, "/security/blocks/add", sess, csrf, url.Values{"prefix": {c.prefix}, "duration": {"24h"}, "reason": {"Brute force"}})
		if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/security/blocks?done=added" {
			t.Errorf("block %q = %d → %q", c.prefix, resp.StatusCode, loc)
		}
		reqs := b.reqList()
		want := blocklist.Request{Prefix: c.want, Source: blocklist.SourceManual, Duration: 24 * time.Hour, Reason: "Brute force", By: "operator", Self: "127.0.0.1"}
		if got := reqs[len(reqs)-1]; got != want {
			t.Errorf("request = %+v\nwant %+v", got, want)
		}
	}
	if _, body := e.get(t, "/security/blocks?done=added", sess); !strings.Contains(body, "Block placed.") {
		t.Error("done notice missing")
	}
	// Refused before the list: not an address, no length, a bad reason.
	n := len(b.reqList())
	for _, c := range []struct {
		form url.Values
		msg  string
	}{
		{url.Values{"prefix": {"not-an-ip"}, "duration": {"24h"}}, "That is not an IP address or CIDR range"},
		{url.Values{"prefix": {"fe80::1%eth0"}, "duration": {"24h"}}, "That is not an IP address or CIDR range"},
		{url.Values{"prefix": {"::ffff:10.0.0.0/8"}, "duration": {"24h"}}, "That is not an IP address or CIDR range"},
		{url.Values{"duration": {"24h"}}, "That is not an IP address or CIDR range"},
		{url.Values{"prefix": {"203.0.113.7"}, "duration": {"2h"}}, "Pick a block length."},
		{url.Values{"prefix": {"203.0.113.7"}}, "Pick a block length."},
		{url.Values{"prefix": {"203.0.113.7"}, "duration": {"24h"}, "reason": {strings.Repeat("r", blockReasonMax+1)}}, "The reason is too long"},
		{url.Values{"prefix": {"203.0.113.7"}, "duration": {"24h"}, "reason": {"a\x1bb"}}, "The reason has characters"},
	} {
		resp, body := e.detPost(t, "/security/blocks/add", sess, csrf, c.form)
		if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, c.msg) {
			t.Errorf("%v = %d, want 422 with %q", c.form, resp.StatusCode, c.msg)
		}
	}
	if len(b.reqList()) != n {
		t.Error("a refused form reached the block list")
	}
	// The list's refusal, in words, with what was typed kept.
	b.mu.Lock()
	b.blockErr = &blocklist.RefusedError{Code: blocklist.RefuseSelf, Detail: "your address 127.0.0.1"}
	b.mu.Unlock()
	resp, body := e.detPost(t, "/security/blocks/add", sess, csrf, url.Values{"prefix": {"127.0.0.0/24"}, "duration": {"7d"}, "reason": {"Mine <b>x</b>"}})
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "The block was refused: it covers your own address (your address 127.0.0.1).") {
		t.Errorf("refused = %d", resp.StatusCode)
	}
	if !strings.Contains(body, `name="prefix" value="127.0.0.0/24"`) || !strings.Contains(body, `value="Mine &lt;b&gt;x&lt;/b&gt;"`) || !strings.Contains(body, `<option value="7d" selected>`) {
		t.Error("a refused block didn't keep what was typed")
	}
	b.mu.Lock()
	b.blockErr = errors.New("edge reload failed at /var/lib/caddy")
	b.mu.Unlock()
	if resp, body := e.detPost(t, "/security/blocks/add", sess, csrf, url.Values{"prefix": {"203.0.113.7"}, "duration": {"1h"}}); resp.StatusCode != http.StatusInternalServerError || strings.Contains(body, "/var/lib/caddy") {
		t.Errorf("internal error = %d (or leaked)", resp.StatusCode)
	}
	var details []string
	for _, r := range secAuditRows(t, e, "security_block_add") {
		details = append(details, r.Outcome+" "+r.Detail)
		if strings.Contains(r.Detail, "Brute") || strings.Contains(r.Detail, "Mine") {
			t.Errorf("audit row %+v", r)
		}
	}
	want := []string{
		"ok source=manual prefix=203.0.113.7/32 duration=24h", "ok source=manual prefix=203.0.113.0/24 duration=24h",
		"ok source=manual prefix=203.0.113.8/32 duration=24h", "ok source=manual prefix=2001:db8:1:2::/64 duration=24h",
		"error source=manual result=refused code=invalid", "error source=manual result=refused code=invalid",
		"error source=manual result=refused code=invalid", "error source=manual result=refused code=invalid",
		"error source=manual prefix=203.0.113.7/32 result=rejected", "error source=manual prefix=203.0.113.7/32 result=rejected",
		"error source=manual prefix=203.0.113.7/32 duration=24h result=rejected", "error source=manual prefix=203.0.113.7/32 duration=24h result=rejected",
		"error source=manual prefix=127.0.0.0/24 duration=7d result=refused code=self",
		"error source=manual prefix=203.0.113.7/32 duration=1h result=error",
	}
	if !slices.Equal(details, want) {
		t.Errorf("audit =\n%q\nwant\n%q", details, want)
	}
}

// The lengths offered stop at security_logs.blocking.manual_max_duration, which is offered itself.
func TestBlockAddManualLongest(t *testing.T) {
	b := newBlockFake(time.Now().UTC())
	e := respEnv(t, nil, b)
	e.srv.cfg.SecurityLogs.Blocking.ManualMaxDuration = config.Duration(72 * time.Hour)
	sess, csrf := e.detLogin(t, "operator")
	_, body := e.get(t, "/security/blocks", sess)
	if !strings.Contains(body, `<option value="3d">3 days (the longest)`) || strings.Contains(body, `value="7d"`) || !strings.Contains(body, "at most 3 days") {
		t.Error("lengths past the longest are offered")
	}
	if resp, _ := e.detPost(t, "/security/blocks/add", sess, csrf, url.Values{"prefix": {"203.0.113.7"}, "duration": {"7d"}}); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("7d over a 3d longest = %d, want 422", resp.StatusCode)
	}
	if resp, _ := e.detPost(t, "/security/blocks/add", sess, csrf, url.Values{"prefix": {"203.0.113.7"}, "duration": {"3d"}}); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("3d = %d, want 303", resp.StatusCode)
	}
	if r := b.reqList(); len(r) != 1 || r[0].Duration != 72*time.Hour {
		t.Errorf("requests = %+v", r)
	}
	// Shorter than a day: the address page's button uses the longest.
	e.srv.cfg.SecurityLogs.Blocking.ManualMaxDuration = config.Duration(2 * time.Hour)
	if d := e.srv.entityBlockDuration(); d.Value != "2h" || d.d != 2*time.Hour {
		t.Errorf("entity length = %+v, want 2h", d)
	}
}

func TestBlockRemove(t *testing.T) {
	b := newBlockFake(time.Now().UTC())
	e := respEnv(t, nil, b)
	sess, csrf := e.detLogin(t, "operator")
	resp, _ := e.detPost(t, "/security/blocks/remove", sess, csrf, url.Values{"prefix": {"198.51.100.7/32"}})
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/security/blocks?done=removed" {
		t.Errorf("remove = %d → %q", resp.StatusCode, loc)
	}
	if got := b.unblockList(); !slices.Equal(got, []string{"198.51.100.7/32 operator"}) {
		t.Errorf("Unblock calls = %v", got)
	}
	if resp, body := e.detPost(t, "/security/blocks/remove", sess, csrf, url.Values{"prefix": {"nope"}}); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "That is not a valid block.") {
		t.Errorf("bad prefix = %d", resp.StatusCode)
	}
	b.mu.Lock()
	b.unblockErr = fmt.Errorf("unblock: %w", blocklist.ErrNotFound)
	b.mu.Unlock()
	if resp, body := e.detPost(t, "/security/blocks/remove", sess, csrf, url.Values{"prefix": {"203.0.113.7"}}); resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "That address has no block in force.") {
		t.Errorf("not found = %d", resp.StatusCode)
	}
	b.mu.Lock()
	b.unblockErr = errors.New("db /var/lib/x")
	b.mu.Unlock()
	if resp, body := e.detPost(t, "/security/blocks/remove", sess, csrf, url.Values{"prefix": {"203.0.113.7"}}); resp.StatusCode != http.StatusInternalServerError || strings.Contains(body, "/var/lib/x") {
		t.Errorf("internal = %d", resp.StatusCode)
	}
	var details []string
	for _, r := range secAuditRows(t, e, "security_block_remove") {
		details = append(details, r.Outcome+" "+r.Detail)
	}
	want := []string{"ok prefix=198.51.100.7/32", "error result=rejected", "error prefix=203.0.113.7/32 result=not found", "error prefix=203.0.113.7/32 result=error"}
	if !slices.Equal(details, want) {
		t.Errorf("audit = %q, want %q", details, want)
	}
}

func TestEntityPageBlock(t *testing.T) {
	now := time.Now().UTC()
	b := newBlockFake(now)
	e := incEnv(t, newIncFake(now))
	e.srv.blocks = b
	sess, csrf := e.detLogin(t, "operator")
	// A blocked IPv4 address: its state and Unblock.
	_, body := e.get(t, "/security/entities?kind=address&key=198.51.100.7", sess)
	for _, want := range []string{"Edge block", ">Blocked<", `action="/security/blocks/remove"`, `name="prefix" value="198.51.100.7/32"`,
		`name="back" value="entity"`, `name="key" value="198.51.100.7"`, "placed by automated response",
		// the plain address in the page's words, small buttons, and a text link to the list
		`<span class="mono">198.51.100.7</span>`, `data-confirm="Remove the block of 198.51.100.7? `, `class="btn btn-sm">Unblock<`, `<a href="/security/blocks">Blocked addresses</a>`} {
		if !strings.Contains(body, want) {
			t.Errorf("blocked address page missing %q", want)
		}
	}
	if strings.Contains(body, "/64 network") {
		t.Error("an IPv4 address page talks about a /64")
	}
	// An IPv6 address is looked up as its /64, and offered a 24-hour block.
	_, body = e.get(t, "/security/entities?kind=address&key=2001:db8:1:2::5", sess)
	for _, want := range []string{">Not blocked<", `action="/security/blocks/add"`, `name="prefix" value="2001:db8:1:2::/64"`, `name="duration" value="24h"`, `class="btn btn-sm">Block for 24 hours<`,
		"<br>IPv6 addresses are blocked as their whole /64 network.</p>",
		`data-confirm="Block 2001:db8:1:2::/64 at the edge for 24 hours? IPv6 addresses are blocked as their whole /64 network."`} {
		if !strings.Contains(body, want) {
			t.Errorf("IPv6 address page missing %q", want)
		}
	}
	b.mu.Lock()
	gets := slices.Clone(b.gets)
	b.mu.Unlock()
	if !slices.Equal(gets, []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32"), netip.MustParsePrefix("2001:db8:1:2::/64")}) {
		t.Errorf("Get calls = %v", gets)
	}
	// An account has no block.
	if _, body := e.get(t, "/security/entities?kind=account&key=alice&scope=mooring", sess); strings.Contains(body, "Edge block") {
		t.Error("an account page shows a block")
	}
	// From the address page and back.
	key := "2001:db8:1:2::/64"
	resp, _ := e.detPost(t, "/security/blocks/add", sess, csrf, url.Values{"prefix": {key}, "duration": {"24h"}, "back": {"entity"}, "key": {key}})
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != entityURL(siem.Entity{Kind: siem.EntityAddress, Key: key}, url.Values{"done": {"blocked"}}) {
		t.Errorf("block from the entity page = %d → %q", resp.StatusCode, loc)
	}
	resp, _ = e.detPost(t, "/security/blocks/remove", sess, csrf, url.Values{"prefix": {"198.51.100.7/32"}, "back": {"entity"}, "key": {"198.51.100.7"}})
	if loc := resp.Header.Get("Location"); loc != "/security/entities?done=unblocked&key=198.51.100.7&kind=address" {
		t.Errorf("unblock from the entity page → %q", loc)
	}
	if _, body := e.get(t, "/security/entities?kind=address&key=198.51.100.7&done=unblocked", sess); !strings.Contains(body, "Block removed.") {
		t.Error("entity unblock notice missing")
	}
	// A refusal comes back on the address page.
	b.mu.Lock()
	b.blockErr = &blocklist.RefusedError{Code: blocklist.RefuseSession}
	b.mu.Unlock()
	resp, body = e.detPost(t, "/security/blocks/add", sess, csrf, url.Values{"prefix": {"203.0.113.9"}, "duration": {"24h"}, "back": {"entity"}, "key": {"203.0.113.9"}})
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "The block was refused: it covers the address of a signed-in dashboard session.") || !strings.Contains(body, "Risk score") {
		t.Errorf("refusal from the entity page = %d, want it on the entity page", resp.StatusCode)
	}
	// A bad key on a back link falls back to the Blocks page.
	resp, _ = e.detPost(t, "/security/blocks/remove", sess, csrf, url.Values{"prefix": {"198.51.100.7"}, "back": {"entity"}, "key": {"javascript:alert(1)"}})
	if loc := resp.Header.Get("Location"); loc != "/security/blocks?done=removed" {
		t.Errorf("bad back key → %q", loc)
	}
	// The block state can't be read: said, and no buttons.
	b.mu.Lock()
	b.getErr = errors.New("db")
	b.mu.Unlock()
	if _, body := e.get(t, "/security/entities?kind=address&key=198.51.100.7", sess); !strings.Contains(body, "The block state could not be read.") || strings.Contains(body, `action="/security/blocks/`) {
		t.Error("a failed block read: want the message and no buttons")
	}
}

func TestBlockListGuard(t *testing.T) {
	e := securityEnv(t, nil)
	if got := e.srv.GuardAllowlist(); !slices.Equal(got, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}) {
		t.Errorf("GuardAllowlist = %v", got)
	}
	// A reload's values are what the guard sees, and the guard gets a copy.
	sec := *e.srv.security()
	sec.allowlist = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	sec.tokenCIDRUnion = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	e.srv.sec.Store(&sec)
	got := e.srv.GuardAllowlist()
	if !slices.Equal(got, sec.allowlist) {
		t.Errorf("GuardAllowlist after a reload = %v", got)
	}
	got[0] = netip.MustParsePrefix("0.0.0.0/0")
	if e.srv.security().allowlist[0] != netip.MustParsePrefix("192.0.2.0/24") {
		t.Error("the guard's slice aliases the live allowlist")
	}
	if got := e.srv.GuardTokenCIDRs(); !slices.Equal(got, sec.tokenCIDRUnion) {
		t.Errorf("GuardTokenCIDRs = %v", got)
	}
	sec.allowlist = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	e.srv.sec.Store(&sec)
	if p := e.srv.SessionPeers(context.Background()); len(p) != 0 {
		t.Errorf("SessionPeers with no session = %v", p)
	}
	e.loginAs(t, "operator")
	e.loginAs(t, "dep")
	if p := e.srv.SessionPeers(context.Background()); !slices.Equal(p, []netip.Addr{netip.MustParseAddr("127.0.0.1")}) {
		t.Errorf("SessionPeers = %v", p)
	}
}

func TestSecurityTabsPhase4(t *testing.T) {
	now := time.Now().UTC()
	e := respEnv(t, newRespFake(now), newBlockFake(now))
	e.srv.patterns = newPatFake(now)
	e.srv.securityLogs = &fakeSecurityLogs{}
	sess := e.loginAs(t, "operator")
	order := []string{`href="/security"`, `href="/security/detections"`, `href="/security/incidents"`, `href="/security/patterns"`, `href="/security/responses"`, `href="/security/rules"`}
	for p, active := range map[string]string{
		"/security/patterns": "Patterns", "/security/patterns/" + patWebID: "Patterns", "/security/responses": "Responses",
		"/security/blocks": "Responses", "/security/rules": "Rules", "/security": "Search",
	} {
		_, body := e.get(t, p, sess)
		start := strings.Index(body, `<nav class="subnav"`)
		if start < 0 {
			t.Fatalf("%s: no tabs", p)
		}
		nav := body[start : start+strings.Index(body[start:], "</nav>")]
		last := -1
		for _, h := range order {
			i := strings.Index(nav, h+">") + strings.Index(nav, h+" ") + 1 // the tab, with or without the active class
			if i <= last {
				t.Errorf("%s: tab %s out of order", p, h)
			}
			last = i
		}
		if want := `aria-current="page">` + active + `</a>`; !strings.Contains(nav, want) || strings.Count(body, `aria-current="page"`) != 1 {
			t.Errorf("%s: want exactly one active tab, %s", p, active)
		}
	}
}
