package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/blocklist"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/siem"
)

// caseFoldLogs stores an email actor the way redaction does: lower-cased before it is hashed.
type caseFoldLogs struct{ *fakeSecurityLogs }

func (c caseFoldLogs) SearchValue(field, value string) string {
	if field == "actor" && strings.Contains(value, "@") {
		value = strings.ToLower(value)
	}
	return c.fakeSecurityLogs.SearchValue(field, value)
}

// Two users whose email usernames differ only in case are stored as one actor: both are signed
// out, and the names come back sorted, comma-separated.
func TestAccountRevokerSharedActor(t *testing.T) {
	sl := &fakeSecurityLogs{}
	e := securityEnv(t, sl)
	e.srv.securityLogs = caseFoldLogs{sl}
	hash := e.srv.cfg.ExtraUsers[0].PasswordHash
	e.srv.cfg.ExtraUsers = append(e.srv.cfg.ExtraUsers,
		config.UserConfig{Username: "ann@example.com", PasswordHash: hash, Role: config.RoleOwner},
		config.UserConfig{Username: "Ann@example.com", PasswordHash: hash, Role: config.RoleOwner})
	sec, err := buildSecState(e.srv.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.srv.sec.Store(sec)
	for _, u := range []string{"Ann@example.com", "ann@example.com", "ann@example.com", "dep"} {
		e.loginAs(t, u)
	}
	count := func(user string) int {
		var n int
		if err := e.srv.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE username = ?`, user).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	user, n, err := e.srv.AccountRevoker().Revoke(context.Background(), hashOf("ann@example.com"))
	if err != nil || user != "Ann@example.com, ann@example.com" || n != 3 {
		t.Errorf("Revoke = %q %d %v, want both users and 3 sessions", user, n, err)
	}
	if count("Ann@example.com") != 0 || count("ann@example.com") != 0 {
		t.Errorf("sessions left: Ann %d, ann %d", count("Ann@example.com"), count("ann@example.com"))
	}
	if count("dep") != 1 {
		t.Error("another user's session ended")
	}
	// The exact name is not stored as an actor (it is hashed), so it names nobody else.
	if user, _, err := e.srv.AccountRevoker().Revoke(context.Background(), "dep"); err != nil || user != "dep" || count("dep") != 0 {
		t.Errorf("Revoke(dep) = %q %v", user, err)
	}
}

// A pause that was stored although the automatic blocks couldn't be removed yet is told as a
// pause, not as a failure.
func TestResponsePauseBlocksNotLifted(t *testing.T) {
	f := newRespFake(time.Now().UTC())
	e := respEnv(t, f, nil)
	sess, csrf := e.detLogin(t, "operator")
	f.mu.Lock()
	f.changeErr = fmt.Errorf("respond: pause: %w: edge down at /var/lib/x", siem.ErrBlocksNotLifted)
	f.mu.Unlock()
	resp, body := e.detPost(t, "/security/responses/pause", sess, csrf, url.Values{"level": {"off"}})
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || loc != "/security/responses?done=paused_off_pending" {
		t.Fatalf("pause with the blocks not lifted = %d → %q (%s)", resp.StatusCode, loc, firstLine(body))
	}
	_, body = e.get(t, loc, sess)
	if !strings.Contains(body, "Responses are paused. The automatic blocks couldn&#39;t be removed yet; Mooring keeps trying.") || strings.Contains(body, "/var/lib/x") {
		t.Error("the pending-lift notice is missing")
	}
	// Any other error is the generic failure.
	f.mu.Lock()
	f.changeErr = errors.New("sqlite busy at /var/lib/x")
	f.mu.Unlock()
	resp, body = e.detPost(t, "/security/responses/pause", sess, csrf, url.Values{"level": {"off"}})
	if resp.StatusCode != http.StatusInternalServerError || !strings.Contains(body, "The pause was not changed. Mooring") || strings.Contains(body, "/var/lib/x") {
		t.Errorf("another error = %d", resp.StatusCode)
	}
	var got []string
	for _, r := range secAuditRows(t, e, "security_response_pause") {
		got = append(got, r.Outcome+" "+r.Detail)
	}
	if want := []string{"ok level=off result=ok lift=error", "error level=off result=error"}; !slices.Equal(got, want) {
		t.Errorf("audit = %q, want %q", got, want)
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func coverFake(now time.Time) *blockFake {
	b := newBlockFake(now)
	b.list = append(b.list,
		// A narrower range around the same addresses, listed first: the widest block is the one shown.
		blocklist.Block{Prefix: netip.MustParsePrefix("192.0.2.0/26"), Source: blocklist.SourceAuto, State: blocklist.StateActive, Until: now.Add(time.Hour)},
		blocklist.Block{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Source: blocklist.SourceManual, By: "operator", State: blocklist.StateActive, Until: now.Add(time.Hour)},
		blocklist.Block{Prefix: netip.MustParsePrefix("192.0.2.0/25"), Source: blocklist.SourceAuto, State: blocklist.StateActive, Until: now.Add(time.Hour)},
		blocklist.Block{Prefix: netip.MustParsePrefix("2001:db8:1::/48"), Source: blocklist.SourceManual, State: blocklist.StateActive, Until: now.Add(time.Hour)},
		blocklist.Block{Prefix: netip.MustParsePrefix("2001:db8:9:9::1/128"), Source: blocklist.SourceManual, State: blocklist.StateActive, Until: now.Add(time.Hour)},
	)
	return b
}

// coveringFake is a block list with the optional in-memory Covering (as *blocklist.Blocker has).
// Its List returns the newest Limit blocks only, as the real list does.
type coveringFake struct {
	*blockFake
	covers []netip.Prefix
}

func (f *coveringFake) List(ctx context.Context, fl blocklist.Filter) ([]blocklist.Block, error) {
	out, err := f.blockFake.List(ctx, fl)
	if fl.Limit > 0 && len(out) > fl.Limit {
		out = out[:fl.Limit]
	}
	return out, err
}

func (f *coveringFake) Covering(p netip.Prefix) (blocklist.Block, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.covers = append(f.covers, p)
	var best blocklist.Block
	found := false
	for _, b := range f.list {
		if b.State != blocklist.StateActive || b.Prefix == p || !b.Prefix.Overlaps(p) {
			continue
		}
		if !found || b.Prefix.Bits() < best.Prefix.Bits() {
			best, found = b, true
		}
	}
	return best, found
}

// checkEntityCovered asserts the address pages of a coverFake list: an address inside a wider
// block, or an IPv6 /64 a /48 covers, is blocked by that block with neither button; an IPv6 /64
// holding one blocked /128 is partly blocked and keeps Block.
func checkEntityCovered(t *testing.T, e *testEnv, sess *http.Cookie) {
	t.Helper()
	for key, by := range map[string]string{
		"192.0.2.50":      "192.0.2.0/24",
		"2001:db8:1:2::5": "2001:db8:1::/48",
	} {
		_, body := e.get(t, "/security/entities?"+url.Values{"kind": {"address"}, "key": {key}}.Encode(), sess)
		if !strings.Contains(body, `<p>Blocked by <a class="mono" href="/security/blocks">`+by+`</a>`) || !strings.Contains(body, ">Blocked<") {
			t.Errorf("%s: want it shown as blocked by %s", key, by)
		}
		if strings.Contains(body, ">Not blocked<") || strings.Contains(body, "Partly blocked") || strings.Contains(body, `action="/security/blocks/add"`) || strings.Contains(body, `action="/security/blocks/remove"`) {
			t.Errorf("%s: a covered address is offered Block or Unblock", key)
		}
	}
	// One /128 inside the /64 is blocked: the rest of the /64 is not, so Block stays.
	_, body := e.get(t, "/security/entities?kind=address&key=2001:db8:9:9::77", sess)
	for _, want := range []string{`<p>Partly blocked by <a class="mono" href="/security/blocks">2001:db8:9:9::1/128</a>`, ">Partly blocked<",
		`action="/security/blocks/add"`, `name="prefix" value="2001:db8:9:9::/64"`} {
		if !strings.Contains(body, want) {
			t.Errorf("a /64 holding a blocked /128: page missing %q", want)
		}
	}
	for _, not := range []string{"<p>Blocked by", ">Blocked<", ">Not blocked<", `action="/security/blocks/remove"`, "placed by automated response", "until "} {
		if strings.Contains(body, not) {
			t.Errorf("a /64 holding a blocked /128: page has %q", not)
		}
	}
}

// An address inside a wider block, or an IPv6 /64 that a /48 covers, is shown as blocked by that
// block, without a Block or Unblock button; an IPv6 /64 that holds a blocked /128 is partly blocked.
func TestEntityBlockCoveredByAnotherBlock(t *testing.T) {
	now := time.Now().UTC()
	b := coverFake(now)
	e := incEnv(t, newIncFake(now))
	e.srv.blocks = b
	sess := e.loginAs(t, "operator")
	checkEntityCovered(t, e, sess)
	// A suspended range is not applied, and an address outside every block is not blocked.
	for _, key := range []string{"203.0.113.9", "198.51.100.8", "2001:db8:9:8::1"} {
		_, body := e.get(t, "/security/entities?"+url.Values{"kind": {"address"}, "key": {key}}.Encode(), sess)
		if !strings.Contains(body, ">Not blocked<") || !strings.Contains(body, `action="/security/blocks/add"`) || strings.Contains(body, "Blocked by") {
			t.Errorf("%s: want it not blocked, with the Block button", key)
		}
	}
	// The exact block still wins.
	if _, body := e.get(t, "/security/entities?kind=address&key=198.51.100.7", sess); !strings.Contains(body, `action="/security/blocks/remove"`) || strings.Contains(body, "Blocked by") {
		t.Error("an exactly blocked address lost its Unblock")
	}
	// The covering blocks can't be read: said, and no buttons.
	b.mu.Lock()
	b.listErr = errors.New("db /var/lib/x")
	b.mu.Unlock()
	if _, body := e.get(t, "/security/entities?kind=address&key=192.0.2.50", sess); !strings.Contains(body, "The block state could not be read.") || strings.Contains(body, `action="/security/blocks/`) {
		t.Error("a failed read of the covering blocks: want the message and no buttons")
	}
}

func TestResponseRowsCoveredByAnotherBlock(t *testing.T) {
	now := time.Now().UTC()
	f, b := newRespFake(now), coverFake(now)
	f.resps = []siem.Response{
		{ID: 3, Action: siem.ResponseBlock, Target: "192.0.2.50/32", State: siem.ResponseRecommended, Created: now},
		{ID: 2, Action: siem.ResponseBlock, Target: "2001:db8:1:2::/64", State: siem.ResponseRefused, Reason: blocklist.RefuseFull, Created: now},
		{ID: 1, Action: siem.ResponseBlock, Target: "203.0.113.9/32", State: siem.ResponseDismissed, Created: now},
	}
	e := respEnv(t, f, b)
	sess := e.loginAs(t, "operator")
	_, body := e.get(t, "/security/responses", sess)
	for _, want := range []string{`by <a class="mono" href="/security/blocks">192.0.2.0/24</a>`, `by <a class="mono" href="/security/blocks">2001:db8:1::/48</a>`, ">Not blocked<"} {
		if !strings.Contains(body, want) {
			t.Errorf("responses page missing %q", want)
		}
	}
	// 203.0.113.9 (inside a suspended range only) is in the history once; 192.0.2.50 shows in both tables.
	if n := strings.Count(body, ">Not blocked<"); n != 1 {
		t.Errorf("Not blocked shown %d times, want once (203.0.113.9)", n)
	}
	b.mu.Lock()
	lists := len(b.lists)
	b.mu.Unlock()
	if lists != 1 {
		t.Errorf("List calls = %d, want the blocks in force read once for the page", lists)
	}
}

// A detection's responses are asked for by detection, however many newer responses there are.
func TestDetectionResponsesByDetection(t *testing.T) {
	now := time.Now().UTC()
	det := &detFakeService{rules: detRules(), dets: []siem.Detection{
		{ID: 499, RuleID: "edge.scan", RuleName: "Scan", Severity: siem.SevMedium, Key: "198.51.100.7", First: now.Add(-time.Hour), Last: now},
	}}
	f := newRespFake(now)
	f.resps = []siem.Response{{ID: 5, Action: siem.ResponseBlock, Target: "198.51.100.7/32", State: siem.ResponseApplied, DetectionID: 499, Duration: 4 * time.Hour, Created: now}}
	for i := 0; i < 300; i++ {
		f.resps = append(f.resps, siem.Response{ID: int64(1000 + i), Action: siem.ResponseRevoke, Target: "alice", State: siem.ResponseApplied, DetectionID: 7, Created: now})
	}
	e := detEnv(t, det, nil)
	e.srv.responses = f
	sess := e.loginAs(t, "operator")
	_, body := e.get(t, "/security/detections/499", sess)
	if !strings.Contains(body, ">Responses</h2>") || !strings.Contains(body, "Block 198.51.100.7/32 for 4 hours") || strings.Contains(body, "Sign out alice") {
		t.Error("detection page: want its own response, behind 300 newer ones")
	}
	if fl := f.lastFilter(t); fl.DetectionID != 499 || fl.Limit < 1 || fl.Limit > 200 {
		t.Errorf("responses filter = %+v, want DetectionID 499", fl)
	}
	// A service that ignores the field never puts another detection's responses on the page.
	f.mu.Lock()
	f.ignoreDetection = true
	f.mu.Unlock()
	if _, body := e.get(t, "/security/detections/499", sess); strings.Contains(body, "Sign out alice") {
		t.Error("another detection's responses on the page")
	}
}

func TestRuleNewResponseNote(t *testing.T) {
	det := &detResponder{
		detFakeService: &detFakeService{rules: respRules()},
		byRule:         map[string][]string{"custom.x": {siem.ResponseBlock}},
		why:            "only rules over Mooring sign-ins can sign an account out",
	}
	e := detEnv(t, det.detFakeService, nil)
	e.srv.detections = det
	sess, csrf := e.detLogin(t, "operator")
	const note = "A response can be set after the rule is saved."
	check := func(what, body string) {
		t.Helper()
		if !strings.Contains(body, note) || strings.Contains(body, det.why) || strings.Contains(body, `name="response"`) {
			t.Errorf("%s: want only the after-saving note (note %v, why %v, select %v)", what,
				strings.Contains(body, note), strings.Contains(body, det.why), strings.Contains(body, `name="response"`))
		}
	}
	_, body := e.get(t, "/security/rules/new", sess)
	check("new-rule form", body)
	// The form shown again after a refused save says the same.
	form := url.Values{"slug": {"x"}, "name": {"X"}, "type": {"threshold"}, "severity": {"medium"},
		"query": {"kind:edge.request"}, "group_by": {"ip"}, "count": {"5"}, "window": {"10m"}, "enabled": {"on"}}
	det.mu.Lock()
	det.saveErr = fmt.Errorf("%w: query: unknown field", siem.ErrInvalidRule)
	det.mu.Unlock()
	resp, body := e.detPost(t, "/security/rules/save", sess, csrf, form)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("refused create = %d", resp.StatusCode)
	}
	check("refused create", body)
	// A crafted create can't carry a response the form never offered.
	det.mu.Lock()
	det.saveErr = nil
	det.mu.Unlock()
	form.Set("response", "block")
	form.Set("response_duration", "1h")
	saves := det.savedCount()
	resp, body = e.detPost(t, "/security/rules/save", sess, csrf, form)
	if resp.StatusCode != http.StatusUnprocessableEntity || det.savedCount() != saves || !strings.Contains(body, "Pick a response this rule can take.") {
		t.Errorf("create with a crafted response = %d (saves %d → %d), want 422 and no save", resp.StatusCode, saves, det.savedCount())
	}
	// An existing rule's form doesn't carry the note.
	if _, body := e.get(t, "/security/rules/edit?id=edge.scan", sess); strings.Contains(body, note) {
		t.Error("the note on an existing rule's form")
	}
}

func TestOffPanelsLinkTheirDocs(t *testing.T) {
	e := respEnv(t, nil, nil) // detection on; no responder, no patterns
	sess := e.loginAs(t, "operator")
	for path, doc := range map[string]string{"/security/patterns": "security-patterns.md", "/security/responses": "security-responses.md"} {
		_, body := e.get(t, path, sess)
		if !strings.Contains(body, `href="https://github.com/daboss2003/mooring/blob/main/docs/`+doc+`">docs/`+doc+`</a>`) || strings.Contains(body, "docs/security-logs.md") {
			t.Errorf("%s (off): want a link to docs/%s only", path, doc)
		}
	}
}

// Deps.Patterns is nil when log patterns are switched off: the page says how to turn them on, and
// a pattern detection's page links neither a pattern page nor a search for the pattern ID.
func TestPatternsSwitchedOff(t *testing.T) {
	now := time.Now().UTC()
	det := &detFakeService{
		rules: append(detRules(), siem.Rule{ID: "pattern.new", Name: "New log pattern", Type: siem.RuleBaseline, Baseline: siem.BaselinePattern, GroupBy: "app", Query: "src:app", Builtin: true}),
		dets:  []siem.Detection{{ID: 7, RuleID: "pattern.new", RuleName: "New log pattern", Severity: siem.SevLow, Key: patWebID, App: "shop", First: now.Add(-time.Hour), Last: now}},
	}
	e := detEnv(t, det, nil)
	sess := e.loginAs(t, "operator")
	_, body := e.get(t, "/security/patterns", sess)
	for _, want := range []string{"Log patterns are off", "To turn them on, set <code>security_logs.detection.patterns.enabled</code> to <code>true</code>", "restart Mooring"} {
		if !strings.Contains(body, want) {
			t.Errorf("patterns off panel missing %q", want)
		}
	}
	resp, body := e.get(t, "/security/detections/7", sess)
	if resp.StatusCode != http.StatusOK || strings.Contains(body, "View the log pattern") || strings.Contains(body, "/security/patterns/"+patWebID) || strings.Contains(body, "Find related events") {
		t.Errorf("pattern detection with patterns off = %d: want no pattern link and no related search", resp.StatusCode)
	}
	e.srv.patterns = newPatFake(now)
	if _, body := e.get(t, "/security/detections/7", sess); !strings.Contains(body, "View the log pattern") {
		t.Error("pattern detection with patterns on: want the pattern link")
	}
}

func TestBlocksApplyErrShown(t *testing.T) {
	now := time.Now().UTC()
	b := newBlockFake(now)
	b.status.ApplyErr = "caddy: <b>load</b> failed"
	e := respEnv(t, nil, b)
	sess := e.loginAs(t, "operator")
	_, body := e.get(t, "/security/blocks", sess)
	if !strings.Contains(body, `<code class="sec-src-err">caddy: &lt;b&gt;load&lt;/b&gt; failed</code>`) || !strings.Contains(body, "Mooring retries every minute.") || strings.Contains(body, "<b>load</b>") {
		t.Error("a failing apply: want its text escaped in a code element and the retry sentence")
	}
	b.mu.Lock()
	b.status.ApplyErr = ""
	b.mu.Unlock()
	if _, body := e.get(t, "/security/blocks", sess); strings.Contains(body, "Mooring retries every minute.") {
		t.Error("the retry sentence without a failing apply")
	}
}

// A template part with a Unicode format character (a bidi override, a zero-width space) is left
// out of the Find events search like one with a control character.
func TestPatternFindEventsDropsFormatCharacters(t *testing.T) {
	realQueryParser(t)
	p := siem.Pattern{Scope: "app:shop/web", App: "shop", Service: "web", Template: "hello ev\u202eil zero\u200bwidth bom\ufeff ctl\x1bx world"}
	if got, want := patternSearch(&p), `app:shop svc:web "hello" "world"`; got != want {
		t.Errorf("search = %q, want %q", got, want)
	}
}

func TestDetectionEvidenceBrowserLabels(t *testing.T) {
	now := time.Now().UTC()
	det := &detFakeService{rules: detRules(), dets: []siem.Detection{{
		ID: 60, RuleID: "edge.scan", RuleName: "Scan", Severity: siem.SevMedium, Key: "198.51.100.7", First: now.Add(-time.Hour), Last: now,
		Evidence: []siem.Evidence{
			{TS: now, Kind: "edge.request", IP: "198.51.100.7", Browser: true},
			{TS: now, Kind: "edge.request", IP: "198.51.100.7", BrowserAgent: true},
			{TS: now, Kind: "edge.request", IP: "198.51.100.7", Browser: true, BrowserAgent: true},
			{TS: now, Kind: "edge.request", IP: "198.51.100.7"},
		},
	}, {
		ID: 61, RuleID: "edge.scan", RuleName: "Scan", Severity: siem.SevMedium, Key: "198.51.100.8", First: now.Add(-time.Hour), Last: now,
		Evidence: []siem.Evidence{{TS: now, Kind: "edge.request", IP: "198.51.100.8"}},
	}}}
	e := detEnv(t, det, nil)
	sess := e.loginAs(t, "operator")
	_, body := e.get(t, "/security/detections/60", sess)
	if n := strings.Count(body, `<span class="badge badge-muted">browser</span>`); n != 2 {
		t.Errorf("browser labels = %d, want 2", n)
	}
	if n := strings.Count(body, `<span class="badge badge-muted">browser-like agent</span>`); n != 1 {
		t.Errorf("browser-like agent labels = %d, want 1", n)
	}
	if !strings.Contains(body, "don't count toward an automatic block") {
		t.Error("no line saying what the labels mean")
	}
	if _, body := e.get(t, "/security/detections/61", sess); strings.Contains(body, "badge-muted\">browser") || strings.Contains(body, "count toward an automatic block") {
		t.Error("labels on evidence that isn't from a browser")
	}
}

// Every reason code the responder and the block list record has words, capitalised because a row
// shows them on their own; a value that is no code is shown as it is.
func TestResponseReasonWords(t *testing.T) {
	now := time.Now().UTC()
	for code, want := range map[string]string{
		"interrupted":     "Mooring stopped before it was handled",
		"invalid_target":  "The account name is not valid",
		"hourly_cap":      "The hourly cap of automatic actions was reached",
		"cooldown":        "Automated response signed this account out less than an hour ago",
		"no_revoker":      "Dashboard sign-outs are not available",
		"unknown_account": "No Mooring user is stored as that account",
		"some_new_code":   "Some new code",
		"<b>Not a code":   "<b>Not a code",
	} {
		for _, st := range []string{siem.ResponseFailed, siem.ResponseRefused} {
			if got := respRowOf(&siem.Response{ID: 1, Action: siem.ResponseRevoke, Target: "a", State: st, Reason: code}, now).Reason; got != want {
				t.Errorf("%s %q = %q, want %q", st, code, got, want)
			}
		}
	}
	if got := respRowOf(&siem.Response{ID: 1, State: siem.ResponseApplied, Reason: "interrupted"}, now).Reason; got != "" {
		t.Errorf("an applied response shows a reason: %q", got)
	}
	// On the page: in words, and an unknown one escaped.
	f := newRespFake(now)
	f.resps = []siem.Response{
		{ID: 3, Action: siem.ResponseRevoke, Target: "bob", State: siem.ResponseFailed, Reason: "interrupted", Created: now},
		{ID: 2, Action: siem.ResponseRevoke, Target: "bob", State: siem.ResponseFailed, Reason: "invalid_target", Created: now},
		{ID: 1, Action: siem.ResponseRevoke, Target: "bob", State: siem.ResponseFailed, Reason: "<b>odd</b>", Created: now},
	}
	e := respEnv(t, f, nil)
	sess := e.loginAs(t, "operator")
	_, body := e.get(t, "/security/responses", sess)
	for _, want := range []string{"Mooring stopped before it was handled", "The account name is not valid", "&lt;b&gt;odd&lt;/b&gt;"} {
		if !strings.Contains(body, want) {
			t.Errorf("responses page missing %q", want)
		}
	}
	if strings.Contains(body, "<b>odd</b>") {
		t.Error("an unknown reason reached the page unescaped")
	}

	// The codes as the responder and the block list declare them.
	decl := regexp.MustCompile(`(?m)^\s*(?:reason|Refuse)[A-Za-z0-9]*\s*=\s*"([a-z0-9_]+)"`)
	found := 0
	for _, dir := range []string{"../siem/respond", "../blocklist"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no sources in %s: %v", dir, err)
		}
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			src, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range decl.FindAllStringSubmatch(string(src), -1) {
				found++
				if refusalWords[m[1]] == "" {
					t.Errorf("%s declares reason code %q, which the pages have no words for", file, m[1])
				}
			}
		}
	}
	if found < 20 {
		t.Errorf("found %d reason codes in the sources, want the responder's and the block list's", found)
	}
}

// With security_logs.blocking.l4 on and no L4 load balancer, the Blocks page gives the block
// list's reason instead of saying the setting is off.
func TestBlocksL4WhyShown(t *testing.T) {
	b := newBlockFake(time.Now().UTC())
	b.status.L4, b.status.L4Why = false, "edge.l4_enabled is off, so no L4 listener takes the list"
	e := respEnv(t, nil, b)
	sess := e.loginAs(t, "operator")
	_, body := e.get(t, "/security/blocks", sess)
	if strings.Count(body, "edge.l4_enabled is off, so no L4 listener takes the list") < 2 || strings.Contains(body, "</code> is off.") {
		t.Error("L4 on without a load balancer: want the reason on the card and in the not-filtered list, not \"is off\"")
	}
	b.mu.Lock()
	b.status.L4Why = ""
	b.mu.Unlock()
	if _, body := e.get(t, "/security/blocks", sess); !strings.Contains(body, "<code>security_logs.blocking.l4</code> is off.") {
		t.Error("blocking.l4 off: want the setting named as off")
	}
}

// The covering block is asked of the block list when it can answer (Covering), so a range older
// than the newest 1000 active blocks is still found: List returns only those.
func TestEntityBlockCoveredBeyondTheListLimit(t *testing.T) {
	now := time.Now().UTC()
	b := &coveringFake{blockFake: newBlockFake(now)}
	b.list = nil
	for i := range blockListMax {
		b.list = append(b.list, blocklist.Block{Prefix: netip.MustParsePrefix(fmt.Sprintf("45.0.%d.%d/32", i/250, 1+i%250)), Source: blocklist.SourceAuto,
			State: blocklist.StateActive, Until: now.Add(time.Hour)})
	}
	b.list = append(b.list,
		blocklist.Block{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Source: blocklist.SourceManual, By: "operator", State: blocklist.StateActive, Until: now.Add(time.Hour)},
		blocklist.Block{Prefix: netip.MustParsePrefix("2001:db8:9:9::1/128"), Source: blocklist.SourceManual, State: blocklist.StateActive, Until: now.Add(time.Hour)})
	f := newRespFake(now)
	f.resps = []siem.Response{{ID: 3, Action: siem.ResponseBlock, Target: "192.0.2.50/32", State: siem.ResponseRecommended, Created: now}}
	e := incEnv(t, newIncFake(now))
	e.srv.responses, e.srv.blocks = f, b
	sess := e.loginAs(t, "operator")
	_, body := e.get(t, "/security/entities?kind=address&key=192.0.2.50", sess)
	if !strings.Contains(body, `<p>Blocked by <a class="mono" href="/security/blocks">192.0.2.0/24</a>`) || strings.Contains(body, ">Not blocked<") || strings.Contains(body, `action="/security/blocks/add"`) {
		t.Error("an address inside a range older than the newest 1000 blocks: want it blocked by the range, with no Block button")
	}
	_, body = e.get(t, "/security/entities?kind=address&key=2001:db8:9:9::77", sess)
	if !strings.Contains(body, `<p>Partly blocked by <a class="mono" href="/security/blocks">2001:db8:9:9::1/128</a>`) || !strings.Contains(body, `action="/security/blocks/add"`) {
		t.Error("a /64 holding a blocked /128 older than the newest 1000 blocks: want it partly blocked, with the Block button")
	}
	_, body = e.get(t, "/security/responses", sess)
	if !strings.Contains(body, `by <a class="mono" href="/security/blocks">192.0.2.0/24</a>`) || strings.Contains(body, ">Not blocked<") {
		t.Error("responses page: want the row's address blocked by the range")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, fl := range b.lists {
		if slices.Equal(fl.States, []string{blocklist.StateActive}) {
			t.Errorf("the active blocks were listed (%+v) though the block list answers Covering", fl)
		}
	}
	if len(b.covers) == 0 {
		t.Error("Covering was never asked")
	}
}

// The same pages through a block list that answers Covering.
func TestEntityBlockCoveredThroughCovering(t *testing.T) {
	now := time.Now().UTC()
	b := &coveringFake{blockFake: coverFake(now)}
	e := incEnv(t, newIncFake(now))
	e.srv.blocks = b
	sess := e.loginAs(t, "operator")
	checkEntityCovered(t, e, sess)
	for _, key := range []string{"203.0.113.9", "198.51.100.8", "2001:db8:9:8::1"} {
		_, body := e.get(t, "/security/entities?"+url.Values{"kind": {"address"}, "key": {key}}.Encode(), sess)
		if !strings.Contains(body, ">Not blocked<") || !strings.Contains(body, `action="/security/blocks/add"`) || strings.Contains(body, "locked by") {
			t.Errorf("%s: want it not blocked, with the Block button", key)
		}
	}
	if _, body := e.get(t, "/security/entities?kind=address&key=198.51.100.7", sess); !strings.Contains(body, `action="/security/blocks/remove"`) || strings.Contains(body, "locked by") {
		t.Error("an exactly blocked address lost its Unblock")
	}
	// A failing List doesn't matter: it isn't read.
	b.mu.Lock()
	b.listErr = errors.New("db /var/lib/x")
	b.mu.Unlock()
	if _, body := e.get(t, "/security/entities?kind=address&key=192.0.2.50", sess); !strings.Contains(body, `<p>Blocked by <a class="mono" href="/security/blocks">192.0.2.0/24</a>`) {
		t.Error("the covering block was read through List though the block list answers Covering")
	}
}

// A response row whose /64 holds one blocked /128 is partly blocked, on both lookup paths.
func TestResponseRowsPartlyBlocked(t *testing.T) {
	now := time.Now().UTC()
	for name, wrap := range map[string]func(*blockFake) blocklist.Service{
		"list":     func(b *blockFake) blocklist.Service { return b },
		"covering": func(b *blockFake) blocklist.Service { return &coveringFake{blockFake: b} },
	} {
		f := newRespFake(now)
		f.resps = []siem.Response{
			{ID: 2, Action: siem.ResponseBlock, Target: "2001:db8:9:9::/64", State: siem.ResponseRecommended, Created: now},
			{ID: 1, Action: siem.ResponseBlock, Target: "2001:db8:1:2::/64", State: siem.ResponseRecommended, Created: now},
		}
		e := respEnv(t, f, nil)
		e.srv.blocks = wrap(coverFake(now))
		_, body := e.get(t, "/security/responses", e.loginAs(t, "operator"))
		for _, want := range []string{`>Partly blocked</span><div class="muted small">by <a class="mono" href="/security/blocks">2001:db8:9:9::1/128</a>`,
			`>Blocked</span><div class="muted small">by <a class="mono" href="/security/blocks">2001:db8:1::/48</a>`} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: responses page missing %q", name, want)
			}
		}
	}
}
