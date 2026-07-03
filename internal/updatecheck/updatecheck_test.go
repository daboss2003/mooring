package updatecheck

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/github"
)

type fakeGH struct {
	rel     github.Release
	relErr  error
	advs    []github.Advisory
	advsErr error
}

func (f *fakeGH) LatestRelease(ctx context.Context, o, r string) (github.Release, error) {
	return f.rel, f.relErr
}
func (f *fakeGH) SecurityAdvisories(ctx context.Context, o, r string) ([]github.Advisory, error) {
	return f.advs, f.advsErr
}

type fakeSink struct{ sent []alert.Outbox }

func (f *fakeSink) EnqueueInfra(ctx context.Context, o alert.Outbox) error {
	f.sent = append(f.sent, o)
	return nil
}

func newChecker(gh ghAPI, version string, sink alertSink) *Checker {
	return New(gh, "daboss2003", "mooring", version, 0, sink, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestCheckOnceUpdateAvailable(t *testing.T) {
	gh := &fakeGH{rel: github.Release{TagName: "v0.4.5", HTMLURL: "https://x/rel"}}
	sink := &fakeSink{}
	c := newChecker(gh, "0.4.3", sink)
	c.checkOnce(context.Background())

	st := c.State()
	if st == nil || !st.UpdateAvailable || st.LatestVersion != "v0.4.5" {
		t.Fatalf("expected update available: %+v", st)
	}
	if st.Advisory != nil {
		t.Error("no advisory expected")
	}
	if len(sink.sent) != 0 {
		t.Error("a plain update-available must NOT page")
	}
}

func TestCheckOnceSecurityAdvisoryPagesCritical(t *testing.T) {
	gh := &fakeGH{
		rel: github.Release{TagName: "v0.4.5", HTMLURL: "https://x/rel"},
		advs: []github.Advisory{{
			GHSAID: "GHSA-xxxx", Severity: "critical", Summary: "RCE in the edge", HTMLURL: "https://x/adv",
			Vulnerabilities: []github.AdvisoryVulnRange{{VulnerableVersionRange: "< 0.4.4", PatchedVersions: "0.4.4"}},
		}},
	}
	sink := &fakeSink{}
	c := newChecker(gh, "0.4.3", sink)
	c.checkOnce(context.Background())

	st := c.State()
	if st.Advisory == nil || st.Advisory.GHSAID != "GHSA-xxxx" || st.Advisory.Patched != "0.4.4" {
		t.Fatalf("expected advisory: %+v", st.Advisory)
	}
	if len(sink.sent) != 1 {
		t.Fatalf("expected exactly one critical page, got %d", len(sink.sent))
	}
	o := sink.sent[0]
	if o.Level != alert.LevelCritical || o.DedupeKey != "mooring:advisory:GHSA-xxxx" {
		t.Errorf("bad alert: %+v", o)
	}
	// A second check must NOT re-page the same GHSA within the process.
	c.checkOnce(context.Background())
	if len(sink.sent) != 1 {
		t.Errorf("re-paged the same advisory: %d sends", len(sink.sent))
	}
}

func TestCheckOnceNotAffectedNewerVersion(t *testing.T) {
	// running 0.4.5 is NOT in "< 0.4.4" → no advisory, no page.
	gh := &fakeGH{advs: []github.Advisory{{GHSAID: "GHSA-y", Severity: "high",
		Vulnerabilities: []github.AdvisoryVulnRange{{VulnerableVersionRange: "< 0.4.4"}}}}}
	sink := &fakeSink{}
	c := newChecker(gh, "0.4.5", sink)
	c.checkOnce(context.Background())
	if c.State().Advisory != nil || len(sink.sent) != 0 {
		t.Error("a patched version must not be flagged/paged")
	}
}

func TestCheckOnceDevVersionSkips(t *testing.T) {
	gh := &fakeGH{relErr: errors.New("should not be called")}
	c := newChecker(gh, "dev", &fakeSink{})
	c.checkOnce(context.Background())
	st := c.State()
	if !st.Checked || st.UpdateAvailable || st.Advisory != nil {
		t.Errorf("dev version must produce a benign state: %+v", st)
	}
}

func TestUnparseableRangeFailsSafe(t *testing.T) {
	gh := &fakeGH{advs: []github.Advisory{{GHSAID: "GHSA-z", Severity: "high",
		Vulnerabilities: []github.AdvisoryVulnRange{{VulnerableVersionRange: "~> 0.4.0"}}}}}
	sink := &fakeSink{}
	c := newChecker(gh, "0.4.3", sink)
	c.checkOnce(context.Background())
	if c.State().Advisory == nil {
		t.Error("an unparseable advisory range must FAIL SAFE (treated as affected)")
	}
}
