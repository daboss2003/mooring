package detect

import (
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// An edge event with browser fetch metadata is marked Browser in its evidence; any other event,
// even one claiming f.fetch_site from an app's own log line, is not.
func TestEvidenceBrowser(t *testing.T) {
	at := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		ev   siem.Event
		want bool
	}{
		{siem.Event{Src: siem.SrcEdge, TS: at, F: map[string]any{"fetch_site": "cross-site"}}, true},
		{siem.Event{Src: siem.SrcEdge, TS: at, F: map[string]any{"status": 404.0}}, false},
		{siem.Event{Src: siem.SrcEdge, TS: at, F: map[string]any{"fetch_site": ""}}, false},
		{siem.Event{Src: siem.SrcEdge, TS: at, F: map[string]any{"fetch_site": true}}, false},
		{siem.Event{Src: siem.SrcApp, TS: at, F: map[string]any{"fetch_site": "none"}}, false},
	} {
		if got := evidenceOf(&tc.ev).Browser; got != tc.want {
			t.Errorf("%s %v: Browser = %v, want %v", tc.ev.Src, tc.ev.F, got, tc.want)
		}
	}
}
