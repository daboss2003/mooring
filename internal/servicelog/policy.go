package servicelog

import "time"

// Policy is how much of one service's captured output is kept.
type Policy struct {
	Retain   time.Duration // lines older than this are removed
	MaxLines int           // at most this many of the service's most recent lines are kept
}

// DefaultPolicy applies to a service whose mooring.yaml sets no `logs:`.
var DefaultPolicy = Policy{Retain: 48 * time.Hour, MaxLines: 2000}

// defaultCeiling fills a zero field of Options.Ceiling (the config defaults).
var defaultCeiling = Policy{Retain: 30 * 24 * time.Hour, MaxLines: 200_000}

// PolicySource reports the retention a service's deployed definition asks for (zero fields = unset).
// ok=false means it couldn't be read; the store then keeps the last policy it knew for the service, or
// applies the default when it knew none.
type PolicySource func(app, svc string) (req Policy, ok bool)

// Effective is the policy a service gets: each requested field (zero = the default) clamped to ceil.
// A ceiling below the default lowers the default too.
func Effective(req, ceil Policy) Policy {
	out := DefaultPolicy
	if req.Retain > 0 {
		out.Retain = req.Retain
	}
	if req.MaxLines > 0 {
		out.MaxLines = req.MaxLines
	}
	if ceil.Retain > 0 && out.Retain > ceil.Retain {
		out.Retain = ceil.Retain
	}
	if ceil.MaxLines > 0 && out.MaxLines > ceil.MaxLines {
		out.MaxLines = ceil.MaxLines
	}
	return out
}

// minPolicy is the field-wise minimum of a and b.
func minPolicy(a, b Policy) Policy {
	if b.Retain < a.Retain {
		a.Retain = b.Retain
	}
	if b.MaxLines < a.MaxLines {
		a.MaxLines = b.MaxLines
	}
	return a
}

// segmentLines is how many lines one segment file holds before a new one is started. Pruning removes
// whole segments, so a service keeps between MaxLines and MaxLines+segmentLines lines on disk.
func (p Policy) segmentLines() int {
	n := p.MaxLines / 4
	if n < 100 {
		n = 100
	}
	if n > 1_000_000 {
		n = 1_000_000
	}
	return n
}

// segmentAge is how long one segment file is written to before a new one is started, so age pruning
// can drop old lines a segment at a time.
func (p Policy) segmentAge() time.Duration {
	d := p.Retain / 8
	if d < 10*time.Minute {
		d = 10 * time.Minute
	}
	if d > 24*time.Hour {
		d = 24 * time.Hour
	}
	return d
}

func (p Policy) retainSecs() int64 { return int64(p.Retain / time.Second) }
