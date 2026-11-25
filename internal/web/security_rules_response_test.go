package web

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// detResponder is a detection service that also says which responses a rule may take (as the
// engine does, siem.RuleResponder): byRule per rule ID, else none with why.
type detResponder struct {
	*detFakeService
	rmu    sync.Mutex
	byRule map[string][]string
	why    string
	asked  []siem.Rule
}

func (d *detResponder) RuleResponses(r siem.Rule) ([]string, string) {
	d.rmu.Lock()
	defer d.rmu.Unlock()
	d.asked = append(d.asked, r)
	if a := d.byRule[r.ID]; len(a) > 0 {
		return a, ""
	}
	return nil, d.why
}

func (d *detResponder) lastAsked(t *testing.T) siem.Rule {
	t.Helper()
	d.rmu.Lock()
	defer d.rmu.Unlock()
	if len(d.asked) == 0 {
		t.Fatal("RuleResponses was not called")
	}
	return d.asked[len(d.asked)-1]
}

func respRules() []siem.Rule {
	rules := detRules()
	rules = append(rules, siem.Rule{ID: "edge.scan", Name: "Path scan", Type: siem.RuleThreshold, Severity: siem.SevMedium,
		Query: "src:edge out:failure", GroupBy: "ip", Count: 30, Window: 10 * time.Minute, Enabled: true, Builtin: true,
		Response: siem.RuleResponse{Action: siem.ResponseBlock, Duration: 90 * time.Minute}})
	return rules
}

func TestRuleEditResponse(t *testing.T) {
	det := &detResponder{
		detFakeService: &detFakeService{rules: respRules()},
		byRule:         map[string][]string{"edge.scan": {siem.ResponseBlock}, "ssh.bruteforce": {siem.ResponseBlock}, "custom.admin-probe": {siem.ResponseBlock}},
		why:            "only rules over Mooring sign-ins can sign an account out",
	}
	e := detEnv(t, det.detFakeService, nil)
	e.srv.detections = det
	sess, csrf := e.detLogin(t, "operator")

	// A rule with a response: the section shows it, its length kept although it isn't one offered.
	_, body := e.get(t, "/security/rules/edit?id=edge.scan", sess)
	for _, want := range []string{"Automated response", `name="response"`, `<option value="block" selected>Block the address at the edge`,
		`<option value="90m" selected>90m`, `<option value="4h">4 hours`, `<option value="1d">24 hours`} {
		if !strings.Contains(body, want) {
			t.Errorf("edit form missing %q", want)
		}
	}
	if strings.Contains(body, `value="revoke"`) {
		t.Error("an action the rule can't take is offered")
	}
	if got := det.lastAsked(t); got.ID != "edge.scan" {
		t.Errorf("RuleResponses asked about %q", got.ID)
	}
	// A rule that can take none: the why text, no select.
	_, body = e.get(t, "/security/rules/edit?id=auth.new_country", sess)
	if strings.Contains(body, `name="response"`) || !strings.Contains(body, "only rules over Mooring sign-ins can sign an account out") {
		t.Error("a rule with no response: want the why text only")
	}
	// A response the rule has but may no longer take stays shown and chosen, so a save keeps it.
	det.mu.Lock()
	det.rules[1].Response = siem.RuleResponse{Action: siem.ResponseRevoke}
	det.mu.Unlock()
	_, body = e.get(t, "/security/rules/edit?id=auth.new_country", sess)
	if !strings.Contains(body, `<option value="revoke" selected>Sign the Mooring account out of every session (not available for this rule)`) {
		t.Error("a stored response the rule can't take is not shown")
	}
	det.mu.Lock()
	det.rules[1].Response = siem.RuleResponse{}
	det.mu.Unlock()
	// The rules list shows it briefly.
	_, body = e.get(t, "/security/rules", sess)
	if !strings.Contains(body, "Response: block the address for 90 minutes") {
		t.Error("rules list: response missing")
	}

	// Save a built-in rule's response with its other tunables.
	resp, _ := e.detPost(t, "/security/rules/save", sess, csrf, url.Values{"id": {"ssh.bruteforce"}, "severity": {"high"}, "count": {"10"}, "window": {"10m"},
		"enabled": {"on"}, "response": {"block"}, "response_duration": {"4h"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save = %d", resp.StatusCode)
	}
	if got := det.lastSaved(t).Response; got != (siem.RuleResponse{Action: siem.ResponseBlock, Duration: 4 * time.Hour}) {
		t.Errorf("saved response = %+v", got)
	}
	// None clears it; a sign-out isn't offered for it, so it's refused before SaveRule.
	e.detPost(t, "/security/rules/save", sess, csrf, url.Values{"id": {"ssh.bruteforce"}, "severity": {"high"}, "count": {"10"}, "window": {"10m"}, "response": {""}, "response_duration": {"4h"}})
	if got := det.lastSaved(t).Response; got != (siem.RuleResponse{}) {
		t.Errorf("none saved %+v", got)
	}
	n := det.savedCount()
	for _, c := range []struct {
		form url.Values
		msg  string
	}{
		{url.Values{"response": {"revoke"}}, "Pick a response this rule can take."},
		{url.Values{"response": {"lock"}}, "Pick a response this rule can take."},
		{url.Values{"response": {"block"}, "response_duration": {"soon"}}, "Block length must be a duration"},
		{url.Values{"response": {"block"}, "response_duration": {""}}, "Block length must be a duration"},
	} {
		form := url.Values{"id": {"ssh.bruteforce"}, "severity": {"high"}, "count": {"10"}, "window": {"10m"}}
		for k, v := range c.form {
			form[k] = v
		}
		resp, body := e.detPost(t, "/security/rules/save", sess, csrf, form)
		if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, c.msg) {
			t.Errorf("%v = %d, want 422 with %q", c.form, resp.StatusCode, c.msg)
		}
	}
	if det.savedCount() != n {
		t.Error("a refused response reached SaveRule")
	}
	// The service's validation (siem.ErrInvalidRule) is shown, with the choice kept.
	det.mu.Lock()
	det.saveErr = fmt.Errorf("%w: response: a block lasts 5m to 7d", siem.ErrInvalidRule)
	det.mu.Unlock()
	resp, body = e.detPost(t, "/security/rules/save", sess, csrf, url.Values{"id": {"ssh.bruteforce"}, "severity": {"high"}, "count": {"10"}, "window": {"10m"}, "response": {"block"}, "response_duration": {"14d"}})
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "a block lasts 5m to 7d") || !strings.Contains(body, `<option value="14d" selected>`) {
		t.Errorf("rejected save = %d, want the message and the length kept", resp.StatusCode)
	}
	det.mu.Lock()
	det.saveErr = nil
	det.mu.Unlock()

	// A custom rule: the response is offered for the rule as it will be saved, and a save without
	// the section keeps the response it had.
	det.mu.Lock()
	det.rules[2].Response = siem.RuleResponse{Action: siem.ResponseBlock, Duration: time.Hour}
	det.mu.Unlock()
	custom := url.Values{"id": {"custom.admin-probe"}, "name": {"Admin path probing"}, "type": {"threshold"}, "severity": {"low"}, "query": {"src:edge f.path:/admin*"},
		"group_by": {"ip"}, "count": {"20"}, "window": {"1h"}}
	e.detPost(t, "/security/rules/save", sess, csrf, custom)
	if got := det.lastSaved(t); got.Response != (siem.RuleResponse{Action: siem.ResponseBlock, Duration: time.Hour}) {
		t.Errorf("custom save without the section dropped its response: %+v", got.Response)
	}
	if got := det.lastAsked(t); got.ID != "custom.admin-probe" || got.GroupBy != "ip" || got.Query != "src:edge f.path:/admin*" {
		t.Errorf("RuleResponses asked about %+v, want the rule as saved", got)
	}
	custom.Set("response", "block")
	custom.Set("response_duration", "7d")
	e.detPost(t, "/security/rules/save", sess, csrf, custom)
	if got := det.lastSaved(t); got.Response != (siem.RuleResponse{Action: siem.ResponseBlock, Duration: 7 * 24 * time.Hour}) {
		t.Errorf("custom response = %+v", got.Response)
	}
	// A new custom rule's form offers no response: it can be set once the rule is saved
	// (TestRuleNewResponseNote).
	_, body = e.get(t, "/security/rules/new", sess)
	if !strings.Contains(body, "A response can be set after the rule is saved.") || strings.Contains(body, "only rules over Mooring sign-ins") {
		t.Error("new rule: want the after-saving note instead of a reason")
	}
	// Audit Details carry no response text either way.
	for _, r := range secAuditRows(t, e, "security_rule_save") {
		if strings.Contains(r.Detail, "block") {
			t.Errorf("audit detail %q", r.Detail)
		}
	}
}

// Without a RuleResponder the forms have no response section and a save keeps the rule's response.
func TestRuleEditWithoutResponder(t *testing.T) {
	f := &detFakeService{rules: respRules()}
	e := detEnv(t, f, nil)
	sess, csrf := e.detLogin(t, "operator")
	_, body := e.get(t, "/security/rules/edit?id=edge.scan", sess)
	if strings.Contains(body, "Automated response") || strings.Contains(body, `name="response"`) {
		t.Error("a response section without a RuleResponder")
	}
	// A crafted post can't set a response the page never offered.
	resp, _ := e.detPost(t, "/security/rules/save", sess, csrf, url.Values{"id": {"edge.scan"}, "severity": {"medium"}, "count": {"30"}, "window": {"10m"}, "enabled": {"on"},
		"response": {"revoke"}})
	if resp.StatusCode != http.StatusUnprocessableEntity || f.savedCount() != 0 {
		t.Errorf("crafted response = %d (saves %d), want 422 and no save", resp.StatusCode, f.savedCount())
	}
	e.detPost(t, "/security/rules/save", sess, csrf, url.Values{"id": {"edge.scan"}, "severity": {"medium"}, "count": {"30"}, "window": {"10m"}, "enabled": {"on"}})
	if got := f.lastSaved(t).Response; got != (siem.RuleResponse{Action: siem.ResponseBlock, Duration: 90 * time.Minute}) {
		t.Errorf("save without the section = %+v, want the response kept", got)
	}
	if !slices.ContainsFunc(f.rules, func(r siem.Rule) bool { return r.ID == "edge.scan" }) {
		t.Fatal("rule lost")
	}
}
