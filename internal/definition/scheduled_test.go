package definition

import (
	"strings"
	"testing"
)

const cronDef = `apiVersion: mooring/v1
kind: App
metadata:
  slug: shop
spec:
  compose:
    source: generated
    services:
      web:
        image: ghcr.io/acme/web:1.2
        ports:
          - internal: 8080
      cleanup:
        image: ghcr.io/acme/web:1.2
        command: ["python", "manage.py", "cleanup"]
  scheduled_tasks:
    - name: nightly-cleanup
      service: cleanup
      every: 24h
  edge:
    routes:
      - hostname: shop.example.com
        service: web
        port: 8080
`

func TestScheduledTasksParseAndProfile(t *testing.T) {
	d, err := Parse([]byte(cronDef))
	if err != nil {
		t.Fatalf("valid scheduled_tasks rejected: %v", err)
	}
	if len(d.Spec.ScheduledTasks) != 1 || d.Spec.ScheduledTasks[0].Service != "cleanup" || d.Spec.ScheduledTasks[0].Every != "24h" {
		t.Fatalf("scheduled task not parsed: %+v", d.Spec.ScheduledTasks)
	}
	set := d.Spec.ScheduledServiceSet()
	if !set["cleanup"] || set["web"] {
		t.Fatalf("ScheduledServiceSet wrong: %v", set)
	}
	// The generated compose profiles the scheduled service so `up` never starts it.
	compose, err := ComposeBytes(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(compose), "mooring-scheduled") {
		t.Errorf("scheduled service must get a compose profile:\n%s", compose)
	}
}

func TestScheduledTasksRejects(t *testing.T) {
	cases := map[string]string{
		"unknown service": strings.Replace(cronDef, "service: cleanup", "service: nope", 1),
		"bad interval":    strings.Replace(cronDef, "every: 24h", "every: nonsense", 1),
		"duplicate name": strings.Replace(cronDef, "  edge:",
			"    - name: nightly-cleanup\n      service: cleanup\n      every: 1h\n  edge:", 1),
		"scaled + scheduled": strings.Replace(cronDef, "  edge:",
			"  scaling:\n    - service: cleanup\n      max: 3\n  edge:", 1),
		"scheduled a server (ports)": strings.Replace(cronDef, "service: cleanup", "service: web", 1),
	}
	for name, bad := range cases {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%s should be rejected", name)
		}
	}
}
