package detect

import "github.com/daboss2003/mooring/internal/siem"

// The built-in baseline rules (docs/security-detections.md "Baselines").
//
// signinQuery matches the successful sign-ins of every source: SSH logins (host), Mooring's own
// (mooring.login) and an app's auth.login / admin.login (any kind containing .login but not
// .login_, as the app.* rules take them); kinds like mooring.login_lockout are not sign-ins.
const signinQuery = "out:success kind~.login -kind~.login_" + notForged

var baselinePack = []packRule{
	{siem.Rule{ID: "baseline.signin_unusual", Name: "Unusual sign-in",
		Description: "A successful sign-in that departs from the account's usual pattern in at least two ways: a new place (a country or network (ASN) not seen for it), a new client, an hour of the day it rarely signs in at.",
		Type:        siem.RuleBaseline, Baseline: siem.BaselineSignIn, Severity: siem.SevMedium, MITRE: []string{"T1078"},
		Query: signinQuery, GroupBy: "actor", Count: 2, Learn: 14 * day},
		packInfo{noun: "sign-ins"}},
	{siem.Rule{ID: "baseline.traffic_surge", Name: "Traffic surge",
		Description: "Far more requests or server errors for a host name in an hour than in the same hour of the week in earlier weeks.",
		Type:        siem.RuleBaseline, Baseline: siem.BaselineTraffic, Severity: siem.SevMedium, MITRE: []string{"T1498", "T1499"},
		Query: "src:edge kind:http.request", GroupBy: "f.host", Count: 200, Factor: 5, Learn: 14 * day},
		packInfo{noun: "requests"}},
	{siem.Rule{ID: "baseline.traffic_drop", Name: "Traffic drop",
		Description: "Far fewer requests for a host name in an hour than in the same hour of the week in earlier weeks: an outage, or traffic blocked before it reaches the server.",
		Type:        siem.RuleBaseline, Baseline: siem.BaselineTraffic, Severity: siem.SevMedium, MITRE: []string{"T1489"},
		Query: "src:edge kind:http.request", GroupBy: "f.host", Count: 200, Factor: 5, Learn: 14 * day},
		packInfo{noun: "requests"}},
	{siem.Rule{ID: "baseline.admin_unusual", Name: "Unusual sudo or su",
		Description: "A server user's sudo or su departs from their usual pattern: a program or target user not seen for them before (root at an hour they rarely use sudo or su at is noted with it, never alone).",
		Type:        siem.RuleBaseline, Baseline: siem.BaselineAdmin, Severity: siem.SevHigh, MITRE: []string{"T1548.003"},
		Query: "src:host kind:su* out:success" + notForged, GroupBy: "actor", Learn: 14 * day},
		packInfo{noun: "sudo and su commands", subject: "server user"}},
	{siem.Rule{ID: "baseline.ip_behaviour", Name: "Address behaviour change",
		Description: "Most of an address's recent requests go to sign-in endpoints or admin paths, or are answered with an error, far more than its usual share.",
		Type:        siem.RuleBaseline, Baseline: siem.BaselineIP, Severity: siem.SevLow, MITRE: []string{"T1110", "T1595"},
		Query: "src:edge kind:http.request", GroupBy: "ip", Count: 50, Window: 10 * minute, Factor: 5, Learn: day},
		packInfo{noun: "requests"}},
}

// Intentional: appended in init, after packByID was built from pack.go's rules (package variables
// are initialized before any init function), so the baseline rules are marked and indexed here the
// same way, and packByID is rebuilt over the grown slice (append may have moved it).
func init() {
	pack = append(pack, baselinePack...)
	for i := range pack {
		pack[i].Enabled, pack[i].Builtin = true, true
		packByID[pack[i].ID] = &pack[i]
	}
}
