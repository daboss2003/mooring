package web

import (
	"strings"
	"testing"
)

func TestUnixTS(t *testing.T) {
	// A real instant → its UTC display string (the "ts" template wraps this in a
	// <time data-ts> element app.js localises).
	if got, want := unixTS(1751630405), "2025-07-04 12:00:05 UTC"; got != want {
		t.Fatalf("unixTS(1751630405) = %q, want %q", got, want)
	}
	// Zero/negative = absent → an em-dash, never "1970-…".
	for _, ts := range []int64{0, -5} {
		if got := unixTS(ts); got != "—" {
			t.Fatalf("unixTS(%d) = %q, want em-dash", ts, got)
		}
	}
}

// TestTsTemplate proves the "ts" define (templates/_layout.html) compiles and executes
// with an int64 pipeline: a real value becomes a <time data-ts> element carrying the
// exact unix seconds (for app.js to localise); an absent one is a bare em-dash.
func TestTsTemplate(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	render := func(ts int64) string {
		var b strings.Builder
		if err := tmpl.ExecuteTemplate(&b, "ts", ts); err != nil {
			t.Fatalf("execute ts(%d): %v", ts, err)
		}
		return b.String()
	}
	if got := render(1751630405); got != `<time data-ts="1751630405">2025-07-04 12:00:05 UTC</time>` {
		t.Fatalf("ts(real) = %q", got)
	}
	if got := render(0); got != "—" {
		t.Fatalf("ts(0) = %q, want em-dash (no <time>)", got)
	}
}
