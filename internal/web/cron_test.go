package web

import (
	"context"
	"strings"
	"testing"
)

func TestCronFailReason(t *testing.T) {
	// The task's last output line (the real error) is what the audit Detail leads with.
	if got := cronFailReason("psql: FATAL: permission denied for table jobs", nil); got != "psql: FATAL: permission denied for table jobs" {
		t.Errorf("should surface the last output line verbatim, got %q", got)
	}
	// No output → a classified reason for each empty case.
	if got := cronFailReason("", context.DeadlineExceeded); !strings.Contains(got, "timed out") {
		t.Errorf("empty + deadline should classify as timed out, got %q", got)
	}
	if got := cronFailReason("   \r\n  ", context.Canceled); !strings.Contains(got, "cancelled") {
		t.Errorf("whitespace-only + cancel should classify as cancelled, got %q", got)
	}
	if got := cronFailReason("", nil); got != "run failed" {
		t.Errorf("empty + no ctx err should be 'run failed', got %q", got)
	}
	// CR/LF/NUL are flattened so a hostile line can't break the audit row.
	if got := cronFailReason("line1\r\nline2\x00end", nil); strings.ContainsAny(got, "\r\n\x00") {
		t.Errorf("control chars must be flattened, got %q", got)
	}
	// Length-bounded.
	if got := cronFailReason(strings.Repeat("x", 500), nil); len([]rune(got)) > 320 {
		t.Errorf("reason must be bounded, got len %d", len([]rune(got)))
	}
}
