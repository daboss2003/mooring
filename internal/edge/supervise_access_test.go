package edge

import (
	"log/slog"
	"strings"
	"testing"
)

// TestDrainAccess verifies the stdout scanner splits lines and hands each to AccessLine, tolerating
// blank lines and a very long line, and never blocking.
func TestDrainAccess(t *testing.T) {
	var got []string
	s := &Supervisor{
		Log:        slog.Default(),
		AccessLine: func(line []byte) { got = append(got, string(line)) },
	}
	long := strings.Repeat("x", 200_000) // a big-but-under-cap line
	input := "line-a\nline-b\n\n" + long + "\n"
	s.drainAccess(strings.NewReader(input))

	if len(got) != 4 {
		t.Fatalf("got %d lines, want 4: %v", len(got), truncate(got))
	}
	if got[0] != "line-a" || got[1] != "line-b" || got[2] != "" {
		t.Errorf("unexpected lines: %v", truncate(got))
	}
	if got[3] != long {
		t.Errorf("long line not passed through intact (len %d, want %d)", len(got[3]), len(long))
	}
}

// TestDrainAccessOverlongLineDoesNotStop is the regression for the crash-loop DoS: a line LONGER
// than the buffer must be dropped, but draining MUST continue with the following lines (a
// bufio.Scanner would have stopped forever on ErrTooLong, orphaning the read end and SIGPIPE-killing
// Caddy). We also confirm the over-long line itself is not delivered.
func TestDrainAccessOverlongLineDoesNotStop(t *testing.T) {
	var got []string
	s := &Supervisor{
		Log:        slog.Default(),
		AccessLine: func(line []byte) { got = append(got, string(line)) },
	}
	huge := strings.Repeat("Z", drainAccessBuf+50_000) // exceeds the per-line buffer
	input := "before\n" + huge + "\n" + "after\n"       // an over-long line BETWEEN two good ones
	s.drainAccess(strings.NewReader(input))

	if len(got) != 2 || got[0] != "before" || got[1] != "after" {
		t.Fatalf("over-long line must be dropped and draining must continue; got %v", truncate(got))
	}
	for _, g := range got {
		if len(g) > 1000 {
			t.Errorf("the over-long line must not be delivered (got a %d-byte line)", len(g))
		}
	}
}

func truncate(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		if len(s) > 20 {
			out[i] = s[:20] + "…"
		} else {
			out[i] = s
		}
	}
	return out
}
