package definition

import (
	"testing"
	"time"
)

func TestScheduledTaskTimeoutD(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 30 * time.Minute},        // unset → default
		{"garbage", 30 * time.Minute}, // invalid → default
		{"0s", 30 * time.Minute},      // non-positive → default
		{"10s", time.Minute},          // below floor → 1m
		{"1h", time.Hour},             // valid
		{"90m", 90 * time.Minute},     // valid
		{"48h", 24 * time.Hour},       // above ceiling → 24h (defensive; validation rejects >24h first)
	}
	for _, c := range cases {
		if got := (ScheduledTask{Timeout: c.in}).TimeoutD(); got != c.want {
			t.Errorf("TimeoutD(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
