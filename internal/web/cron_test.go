package web

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCronFailReason(t *testing.T) {
	to := 45 * time.Minute
	// The task's last output line (the real error) is what the audit Detail leads with.
	if got := cronFailReason("psql: FATAL: permission denied for table jobs", nil, to); got != "psql: FATAL: permission denied for table jobs" {
		t.Errorf("should surface the last output line verbatim, got %q", got)
	}
	// No output → a classified reason for each empty case; the timeout message uses the per-task cap.
	if got := cronFailReason("", context.DeadlineExceeded, to); !strings.Contains(got, "timed out after 45m") {
		t.Errorf("empty + deadline should classify as timed out with the per-task cap, got %q", got)
	}
	if got := cronFailReason("   \r\n  ", context.Canceled, to); !strings.Contains(got, "cancelled") {
		t.Errorf("whitespace-only + cancel should classify as cancelled, got %q", got)
	}
	if got := cronFailReason("", nil, to); got != "run failed" {
		t.Errorf("empty + no ctx err should be 'run failed', got %q", got)
	}
	// CR/LF/NUL are flattened so a hostile line can't break the audit row.
	if got := cronFailReason("line1\r\nline2\x00end", nil, to); strings.ContainsAny(got, "\r\n\x00") {
		t.Errorf("control chars must be flattened, got %q", got)
	}
	// Length-bounded.
	if got := cronFailReason(strings.Repeat("x", 500), nil, to); len([]rune(got)) > 320 {
		t.Errorf("reason must be bounded, got len %d", len([]rune(got)))
	}
}
