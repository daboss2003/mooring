package web

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/definition"
)

func schedDef() *definition.Definition {
	d := &definition.Definition{}
	d.Spec.Compose.Services = map[string]definition.Service{
		"web":    {Build: &definition.Build{}},
		"scan":   {Build: &definition.Build{}},
		"digest": {Image: "busybox:1.36"},
		"db":     {Image: "postgres:16"},
	}
	d.Spec.ScheduledTasks = []definition.ScheduledTask{
		{Name: "nightly-scan", Service: "scan", Every: "1h"},
		{Name: "daily-digest", Service: "digest", Every: "24h"},
	}
	return d
}

// Every build service is built — the scheduled one too (up --build never builds profiled services).
func TestBuildServiceNamesIncludesScheduled(t *testing.T) {
	got := buildServiceNames(schedDef())
	if want := []string{"scan", "web"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("buildServiceNames = %v, want %v (sorted, scheduled included)", got, want)
	}
	if got := buildServiceNames(&definition.Definition{}); len(got) != 0 {
		t.Fatalf("no build services must yield nothing, got %v", got)
	}
}

// The build argv names services after a `--` terminator and never uses --profile (a root flag that
// would render after the subcommand).
func TestBuildActionArgv(t *testing.T) {
	got := buildAction([]string{"scan", "web"})
	if want := []string{"build", "--", "scan", "web"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("buildAction = %v, want %v", got, want)
	}
	for _, a := range got {
		if strings.HasPrefix(a, "--profile") {
			t.Fatal("build must not use --profile")
		}
	}
}

// A scheduled service must never be named in an up/recreate: naming it would start it.
func TestWithoutScheduled(t *testing.T) {
	d := schedDef()
	got := withoutScheduled(d, []string{"db", "scan", "web", "digest"})
	if want := []string{"db", "web"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("withoutScheduled = %v, want %v", got, want)
	}
	if got := withoutScheduled(nil, []string{"a"}); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("nil def must pass through, got %v", got)
	}
	if !isScheduledService(d, "scan") || isScheduledService(d, "web") || isScheduledService(d, "") || isScheduledService(nil, "scan") {
		t.Fatal("isScheduledService misclassified")
	}
}

func TestImageInspectArgv(t *testing.T) {
	got := imageInspectArgv("shop", []string{"scan", "web"})
	want := []string{"image", "inspect", "--format", `{{.Id}} {{.Created}} {{join .RepoTags ","}}`, "--", "shop-scan", "shop-web"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
}

const idA = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const idB = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// Lines are matched to services by tag (not position), a missing image just has no line, and malformed
// lines are ignored.
func TestParseImageReport(t *testing.T) {
	out := strings.Join([]string{
		idB + " 2026-09-29T14:02:11.123456789Z shop-web:latest",
		"garbage line",
		"sha256:nothex 2026-09-29T14:02:11Z shop-scan:latest",
		idA + " not-a-time shop-scan:latest",
		idA + " 2026-09-27T09:00:00Z other-app:latest,shop-scan:latest",
		"",
	}, "\n")
	got := parseImageReport(out, "shop", []string{"scan", "web", "worker"})
	if len(got) != 2 {
		t.Fatalf("want 2 parsed images, got %d: %+v", len(got), got)
	}
	if got["web"].ID != idB || got["web"].Created.Format(time.RFC3339) != "2026-09-29T14:02:11Z" {
		t.Errorf("web parsed wrong: %+v", got["web"])
	}
	if got["scan"].ID != idA {
		t.Errorf("scan must match by tag in a multi-tag list: %+v", got["scan"])
	}
	if _, ok := got["worker"]; ok {
		t.Error("a service with no line must be absent")
	}
}

// Rebuilt vs cache-hit vs missing are all reported, one line per service.
func TestImageReportLines(t *testing.T) {
	start := time.Date(2026, 9, 29, 14, 0, 0, 0, time.UTC)
	got := map[string]imageInfo{
		"web":  {ID: idB, Created: start.Add(2 * time.Minute)},
		"scan": {ID: idA, Created: start.Add(-48 * time.Hour)},
	}
	lines := imageReportLines("shop", []string{"scan", "web", "worker"}, got, start)
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %v", lines)
	}
	if !strings.Contains(lines[0], "image scan: aaaaaaaaaaaa") || !strings.Contains(lines[0], "unchanged, build cache") {
		t.Errorf("scan line: %q", lines[0])
	}
	if !strings.Contains(lines[1], "image web: bbbbbbbbbbbb") || !strings.Contains(lines[1], "built by this deploy") {
		t.Errorf("web line: %q", lines[1])
	}
	if !strings.Contains(lines[2], "image worker: not found (expected shop-worker)") {
		t.Errorf("worker line: %q", lines[2])
	}
}
