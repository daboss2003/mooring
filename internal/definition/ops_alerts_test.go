package definition

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// resolverOpsDoc is a resolver service with a per-service ops_interface whose alerts are the given
// flow-style list items (each line indented under `alerts:`).
func resolverOpsDoc(enabled bool, alerts ...string) string {
	var b strings.Builder
	b.WriteString("  secrets:\n    - {name: OPS_SECRET, generate: 'password:32'}\n")
	b.WriteString("  compose:\n    services:\n      resolver:\n        image: coredns/coredns:1.11.1\n")
	b.WriteString("        ops_interface:\n          enabled: " + strconv.FormatBool(enabled) + "\n")
	b.WriteString("          base_url: http://resolver:8081\n          base_path: /ops\n")
	b.WriteString("          secret_header: X-Ops-Secret\n          secret: OPS_SECRET\n")
	if len(alerts) > 0 {
		b.WriteString("          alerts:\n")
		for _, a := range alerts {
			b.WriteString("            - " + a + "\n")
		}
	}
	return docWith(b.String())
}

// appOpsDoc is the same with an app-level spec.ops_interface.
func appOpsDoc(alerts ...string) string {
	var b strings.Builder
	b.WriteString("  compose:\n    services:\n      web: {image: nginx:1}\n")
	b.WriteString("  ops_interface:\n    enabled: true\n    base_url: http://web:8080\n")
	b.WriteString("    alerts:\n")
	for _, a := range alerts {
		b.WriteString("      - " + a + "\n")
	}
	return docWith(b.String())
}

// The DNS-resolver example from docs/app-ops-interface.md, verbatim.
var resolverDocAlerts = []string{
	"{ name: ratelimit-drops, metric: { group: Limiter, label: Ratelimit drops }, when: increases, window: 5m }",
	"{ name: qps-spike, metric: { queue: dns, count: qps }, when: above_usual, factor: 5, min: 200, window: 2m }",
	"{ name: allowlist-refusals, metric: { group: Limiter, label: Refused (allowlist) }, when: increases, value: 100, window: 5m, severity: medium }",
	"{ name: empty-questions, metric: { group: Limiter, label: Empty questions }, when: increases, value: 100, window: 5m, severity: medium }",
}

func TestOpsAlertsDocExampleParses(t *testing.T) {
	d, err := Parse([]byte(resolverOpsDoc(true, resolverDocAlerts...)))
	if err != nil {
		t.Fatalf("the documented example must parse: %v", err)
	}
	got := d.Spec.Compose.Services["resolver"].OpsInterface.Alerts
	want := []OpsAlert{
		{Name: "ratelimit-drops", Metric: OpsMetricRef{Group: "Limiter", Label: "Ratelimit drops"}, When: "increases", Window: "5m"},
		{Name: "qps-spike", Metric: OpsMetricRef{Queue: "dns", Count: "qps"}, When: "above_usual", Factor: 5, Min: 200, Window: "2m"},
		{Name: "allowlist-refusals", Metric: OpsMetricRef{Group: "Limiter", Label: "Refused (allowlist)"}, When: "increases", Value: 100, Window: "5m", Severity: "medium"},
		{Name: "empty-questions", Metric: OpsMetricRef{Group: "Limiter", Label: "Empty questions"}, When: "increases", Value: 100, Window: "5m", Severity: "medium"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("alerts = %+v\nwant %+v", got, want)
	}
}

func TestOpsAlertsAccepted(t *testing.T) {
	sixteen := make([]string, 16)
	for i := range sixteen {
		sixteen[i] = "{ name: a" + strconv.Itoa(i) + ", metric: { group: G, label: L }, when: increases }"
	}
	label128 := strings.Repeat("x", 128)
	accepted := map[string]string{
		"sixteen alerts":        resolverOpsDoc(true, sixteen...),
		"above with a negative": resolverOpsDoc(true, "{ name: a, metric: { group: Temp, label: Celsius }, when: above, value: -5, severity: critical }"),
		"increases 24h window":  resolverOpsDoc(true, "{ name: a, metric: { group: G, label: L }, when: increases, window: 24h, severity: low }"),
		"increases 30s window":  resolverOpsDoc(true, "{ name: a, metric: { group: G, label: L }, when: increases, window: 30s }"),
		"factor bounds low":     resolverOpsDoc(true, "{ name: a, metric: { queue: q, count: c }, when: above_usual, factor: 1.5 }"),
		"factor bounds high":    resolverOpsDoc(true, "{ name: a, metric: { queue: q, count: c }, when: above_usual, factor: 1000, window: 23h }"),
		"above_usual defaults":  resolverOpsDoc(true, "{ name: a, metric: { queue: q, count: c }, when: above_usual }"),
		"128-byte label":        resolverOpsDoc(true, "{ name: a, metric: { group: G, label: "+label128+" }, when: increases }"),
		"48-char name":          resolverOpsDoc(true, "{ name: "+strings.Repeat("a", 48)+", metric: { group: G, label: L }, when: increases }"),
		"same name, other iface": strings.Replace(resolverOpsDoc(true, "{ name: a, metric: { group: G, label: L }, when: increases }"),
			"  compose:", "  ops_interface:\n    enabled: true\n    base_url: http://resolver:8081\n    alerts:\n      - { name: a, metric: { group: G, label: L }, when: increases }\n  compose:", 1),
		"app-level example": appOpsDoc(resolverDocAlerts...),
	}
	for name, doc := range accepted {
		if _, err := Parse([]byte(doc)); err != nil {
			t.Errorf("%s: must be accepted: %v", name, err)
		}
	}
}

func TestOpsAlertsRefused(t *testing.T) {
	seventeen := make([]string, 17)
	for i := range seventeen {
		seventeen[i] = "{ name: a" + strconv.Itoa(i) + ", metric: { group: G, label: L }, when: increases }"
	}
	ok := "metric: { group: G, label: L }"
	refused := map[string]struct{ doc, want string }{
		"bad name":               {resolverOpsDoc(true, "{ name: Rate_Drops, "+ok+", when: increases }"), "name \"Rate_Drops\" must match"},
		"empty name":             {resolverOpsDoc(true, "{ "+ok+", when: increases }"), "must match [a-z0-9][a-z0-9-]{0,47}"},
		"49-char name":           {resolverOpsDoc(true, "{ name: "+strings.Repeat("a", 49)+", "+ok+", when: increases }"), "must match"},
		"duplicate name":         {resolverOpsDoc(true, "{ name: a, "+ok+", when: increases }", "{ name: a, "+ok+", when: above, value: 1 }"), "declared twice"},
		"seventeen alerts":       {resolverOpsDoc(true, seventeen...), "at most 16"},
		"not enabled":            {resolverOpsDoc(false, "{ name: a, "+ok+", when: increases }"), "need services.resolver.ops_interface.enabled: true"},
		"both metric forms":      {resolverOpsDoc(true, "{ name: a, metric: { group: G, label: L, queue: q, count: c }, when: increases }"), "not both"},
		"no metric":              {resolverOpsDoc(true, "{ name: a, when: increases }"), "metric needs group + label"},
		"group without label":    {resolverOpsDoc(true, "{ name: a, metric: { group: G }, when: increases }"), "needs both group and label"},
		"label without group":    {resolverOpsDoc(true, "{ name: a, metric: { label: L }, when: increases }"), "needs both group and label"},
		"queue without count":    {resolverOpsDoc(true, "{ name: a, metric: { queue: q }, when: increases }"), "needs both queue and count"},
		"129-byte label":         {resolverOpsDoc(true, "{ name: a, metric: { group: G, label: "+strings.Repeat("x", 129)+" }, when: increases }"), "is 129 bytes (at most 128)"},
		"control char":           {resolverOpsDoc(true, `{ name: a, metric: { group: G, label: "Rate\tdrops" }, when: increases }`), "control character"},
		"padded label":           {resolverOpsDoc(true, `{ name: a, metric: { group: G, label: " Drops" }, when: increases }`), "start or end with a space"},
		"bad when":               {resolverOpsDoc(true, "{ name: a, "+ok+", when: below }"), "must be increases, above or above_usual"},
		"no when":                {resolverOpsDoc(true, "{ name: a, "+ok+" }"), "must be increases, above or above_usual"},
		"above without value":    {resolverOpsDoc(true, "{ name: a, "+ok+", when: above }"), "needs value"},
		"increases negative":     {resolverOpsDoc(true, "{ name: a, "+ok+", when: increases, value: -1 }"), "value must be >= 0"},
		"increases with factor":  {resolverOpsDoc(true, "{ name: a, "+ok+", when: increases, factor: 5 }"), "apply only to when: above_usual"},
		"above with min":         {resolverOpsDoc(true, "{ name: a, "+ok+", when: above, value: 1, min: 5 }"), "apply only to when: above_usual"},
		"above_usual with value": {resolverOpsDoc(true, "{ name: a, "+ok+", when: above_usual, value: 5 }"), "value applies only to"},
		"factor too low":         {resolverOpsDoc(true, "{ name: a, "+ok+", when: above_usual, factor: 1.4 }"), "factor 1.4 must be between 1.5 and 1000"},
		"factor too high":        {resolverOpsDoc(true, "{ name: a, "+ok+", when: above_usual, factor: 1001 }"), "must be between 1.5 and 1000"},
		"negative min":           {resolverOpsDoc(true, "{ name: a, "+ok+", when: above_usual, min: -1 }"), "min must be >= 0"},
		"NaN value":              {resolverOpsDoc(true, "{ name: a, "+ok+", when: above, value: .nan }"), "finite number"},
		"Inf factor":             {resolverOpsDoc(true, "{ name: a, "+ok+", when: above_usual, factor: .inf }"), "finite number"},
		"-Inf min":               {resolverOpsDoc(true, "{ name: a, "+ok+", when: above_usual, min: -.inf }"), "finite number"},
		"window too short":       {resolverOpsDoc(true, "{ name: a, "+ok+", when: increases, window: 29s }"), "must be between 30s and 24h"},
		"window too long":        {resolverOpsDoc(true, "{ name: a, "+ok+", when: increases, window: 25h }"), "must be between 30s and 24h"},
		"window not a duration":  {resolverOpsDoc(true, "{ name: a, "+ok+", when: increases, window: 5 minutes }"), "not a valid duration"},
		"above_usual window 24h": {resolverOpsDoc(true, "{ name: a, "+ok+", when: above_usual, window: 23h30m }"), "at most 23h"},
		"bad severity":           {resolverOpsDoc(true, "{ name: a, "+ok+", when: increases, severity: urgent }"), "must be low, medium, high or critical"},
		"unknown key":            {resolverOpsDoc(true, "{ name: a, "+ok+", when: increases, threshold: 5 }"), "unknown or mistyped"},
		"unknown metric key":     {resolverOpsDoc(true, "{ name: a, metric: { group: G, label: L, item: x }, when: increases }"), "unknown or mistyped"},
		"app-level not enabled":  {docWith("  compose:\n    services:\n      web: {image: nginx:1}\n  ops_interface:\n    enabled: false\n    alerts:\n      - { name: a, " + ok + ", when: increases }\n"), "need ops_interface.enabled: true"},
		"app-level bad when":     {appOpsDoc("{ name: a, " + ok + ", when: rises }"), "ops_interface.alerts \"a\": when \"rises\""},
	}
	for name, tc := range refused {
		_, err := Parse([]byte(tc.doc))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: must be refused with %q, got %v", name, tc.want, err)
		}
	}
}

// manyOpsDoc is an app with an app-level ops_interface (with one alert when appAlert) and services
// s0…s<n-1>, each with an ops_interface; the first withAlerts of them declare one alert.
func manyOpsDoc(appAlert bool, n, withAlerts int) string {
	var b strings.Builder
	alert := "{ name: a, metric: { group: G, label: L }, when: increases }"
	b.WriteString("  ops_interface:\n    enabled: true\n    base_url: http://s0:8081\n")
	if appAlert {
		b.WriteString("    alerts:\n      - " + alert + "\n")
	}
	b.WriteString("  compose:\n    services:\n")
	for i := 0; i < n; i++ {
		name := "s" + strconv.Itoa(i)
		b.WriteString("      " + name + ":\n        image: coredns/coredns:1.11.1\n        ops_interface:\n")
		b.WriteString("          enabled: true\n          base_url: http://" + name + ":8081\n")
		if i < withAlerts {
			b.WriteString("          alerts:\n            - " + alert + "\n")
		}
	}
	return docWith(b.String())
}

// An app declares alerts on at most MaxOpsAlertInterfaces ops_interface blocks, the app-level one and
// the services' together; blocks without alerts don't count.
func TestOpsAlertsInterfaceCap(t *testing.T) {
	if MaxOpsAlertInterfaces != 8 {
		t.Fatalf("MaxOpsAlertInterfaces = %d; the docs say 8", MaxOpsAlertInterfaces)
	}
	accepted := map[string]string{
		"8 services":                 manyOpsDoc(false, 8, 8),
		"app-level + 7 services":     manyOpsDoc(true, 7, 7),
		"12 interfaces, 8 alerting":  manyOpsDoc(false, 12, 8),
		"app-level + 11, 7 alerting": manyOpsDoc(true, 11, 7),
	}
	for name, doc := range accepted {
		if _, err := Parse([]byte(doc)); err != nil {
			t.Errorf("%s: must be accepted: %v", name, err)
		}
	}
	refused := map[string]string{
		"9 services":             manyOpsDoc(false, 9, 9),
		"app-level + 8 services": manyOpsDoc(true, 8, 8),
	}
	for name, doc := range refused {
		_, err := Parse([]byte(doc))
		if err == nil || !strings.Contains(err.Error(), "alerts are declared on 9 ops_interface blocks (at most 8 per app") {
			t.Errorf("%s: must be refused naming the cap, got %v", name, err)
		}
	}
}

// The alerts survive the write-back path (Canonical → Parse) at both levels, every field intact.
func TestOpsAlertsCanonicalRoundTrip(t *testing.T) {
	for name, doc := range map[string]string{
		"per service": resolverOpsDoc(true, append(resolverDocAlerts,
			"{ name: hot, metric: { group: Temp, label: Celsius }, when: above, value: -5.5, window: 90s, severity: critical }")...),
		"app level": appOpsDoc(resolverDocAlerts...),
	} {
		d, err := Parse([]byte(doc))
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		canon, err := Canonical(d)
		if err != nil {
			t.Fatalf("%s: canonical: %v", name, err)
		}
		d2, err := Parse(canon)
		if err != nil {
			t.Fatalf("%s: re-parse canonical: %v\n%s", name, err, canon)
		}
		before, after := d.Spec.OpsInterface, d2.Spec.OpsInterface
		if name == "per service" {
			before, after = d.Spec.Compose.Services["resolver"].OpsInterface, d2.Spec.Compose.Services["resolver"].OpsInterface
		}
		if len(before.Alerts) == 0 || !reflect.DeepEqual(before.Alerts, after.Alerts) {
			t.Errorf("%s: alerts did not round-trip:\n%+v\n%+v", name, before.Alerts, after.Alerts)
		}
	}
}
