package detect

import "github.com/daboss2003/mooring/internal/siem"

// The built-in log-pattern rules (docs/security-detections.md "Log patterns"). The miner
// (pattern_miner.go) evaluates them on the lines it takes (app lines, and the host's unclassified
// lines from a trusted sender), not on their query: the query is what the Detections page searches
// for related events.
const patternQuery = "-src:edge -src:mooring"

var patternPack = []packRule{
	{siem.Rule{ID: rulePatternNew, Name: "New log pattern",
		Description: "An app service's (or the host's) log lines below warn fall into a template not seen before, after its learning period. Reported once, when it has settled.",
		Type:        siem.RuleBaseline, Baseline: siem.BaselinePattern, Severity: siem.SevLow,
		Query: patternQuery, GroupBy: "app", Count: 1, Window: 5 * minute, Learn: 7 * day},
		packInfo{noun: "log lines", subject: "log pattern"}},
	{siem.Rule{ID: rulePatternNewError, Name: "New error log pattern",
		Description: "An app service's (or the host's) log lines at warn or above fall into a template not seen before, after its learning period. Reported once, when it has settled.",
		Type:        siem.RuleBaseline, Baseline: siem.BaselinePattern, Severity: siem.SevMedium,
		Query: patternQuery + " lvl>=warn", GroupBy: "app", Count: 1, Window: 5 * minute, Learn: 7 * day},
		packInfo{noun: "log lines", subject: "log pattern"}},
	{siem.Rule{ID: rulePatternSpike, Name: "Log pattern spike",
		Description: "Far more lines of a known log template in a short time than usual at that time of day on the previous days.",
		Type:        siem.RuleBaseline, Baseline: siem.BaselinePattern, Severity: siem.SevMedium,
		Query: patternQuery, GroupBy: "app", Count: 100, Window: 10 * minute, Factor: 5, Learn: 3 * day},
		packInfo{noun: "log lines", subject: "log pattern"}},
	{siem.Rule{ID: rulePatternChurn, Name: "Log pattern churn",
		Description: "An app service's (or the host's) logs make new templates faster than the cap allows: text an attacker controls in the logs, or a large change.",
		Type:        siem.RuleBaseline, Baseline: siem.BaselinePattern, Severity: siem.SevMedium,
		Query: patternQuery, GroupBy: "app", Count: 1},
		packInfo{noun: "log lines", subject: "log scope"}},
}

// Intentional: appended in init like the baseline rules (pack_baseline.go, whose init runs first:
// init functions run in file name order), so they are marked and indexed the same way, and
// packByID is rebuilt over the grown slice (append may have moved it).
func init() {
	pack = append(pack, patternPack...)
	for i := range pack {
		pack[i].Enabled, pack[i].Builtin = true, true
		packByID[pack[i].ID] = &pack[i]
	}
}
