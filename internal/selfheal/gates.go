package selfheal

// The ordered tiny-box safety gates (plan §8.5) applied before EVERY action.
// All must pass or the action defers (re-checked next tick) — EXCEPT the headroom
// gate, which converts a restart into a page ("don't restart, page instead"), and
// the edge gate, which removes a target entirely. These are what guarantee the
// supervisor can only reduce pressure or hold steady, never manufacture an OOM.
// The last gate is the host-wide start gate: a restart waits while another container
// is still starting or the host has no CPU headroom.

// GateOutcome is the result of evaluating the gates for a proposed action.
type GateOutcome string

const (
	GateProceed GateOutcome = "proceed" // all gates pass: execute the rung
	GateDefer   GateOutcome = "defer"   // a transient gate failed: retry next tick, no attempt consumed
	GatePage    GateOutcome = "page"    // headroom too low to safely restart: page instead
	GateSkip    GateOutcome = "skip"    // edge / control-plane target: never a remediation target
)

// GateInput is the environment for the gate checks at action time.
type GateInput struct {
	Rung Rung

	// Gate 1 — §0 resource gate for the action's plane. WritePlaneOK is the global
	// ≥1 GB write-plane gate; RedeployEnabled gates the redeploy rung specifically.
	WritePlaneOK    bool
	RedeployEnabled bool

	// Gate 2 — the global one-docker-child semaphore. AcquireSemaphore is a
	// NON-BLOCKING TryAcquire supplied by the watcher; nil means "treat as busy".
	// When it returns true the caller now HOLDS the semaphore and must Release it.
	AcquireSemaphore func() bool
	// ReleaseSemaphore gives the slot back when a later gate defers after acquiring it.
	ReleaseSemaphore func()

	// Gate 3 — memory-headroom floor. A restart momentarily runs old+new, so below
	// the floor we must not restart. HeadroomBytes is current free memory (host),
	// FloorBytes the configured minimum that must remain available.
	HeadroomBytes uint64
	FloorBytes    uint64

	// Gate 4 — edge protection. The edge slice and control plane are never targets.
	IsEdgeOrControlPlane bool

	// Gate 5 — the host-wide start gate, asked while holding the slot so no other starter can
	// start a container in between. nil = the action starts nothing (or pacing is off).
	Admit func() (bool, string)
}

// Gates evaluates the four gates IN ORDER for a proposed remediation. On
// GateProceed the caller holds the docker-child semaphore and MUST release it after
// running the action; on every other outcome no semaphore is held.
func Gates(in GateInput) (GateOutcome, string) {
	// Gate 4 first as a hard filter: never touch the edge / control plane.
	if in.IsEdgeOrControlPlane {
		return GateSkip, "edge/control-plane is never a remediation target"
	}

	// Gate 1 — §0 resource gate for the plane. A redeploy needs the write plane AND
	// the explicit opt-in; without them the rung is structurally unavailable (the
	// ladder should have stopped before here, but defend in depth).
	if !in.WritePlaneOK {
		return GateDefer, "write plane disabled (§0 resource gate)"
	}
	if in.Rung == RungRedeploy && !in.RedeployEnabled {
		return GateDefer, "redeploy not available on this host"
	}

	// Gate 3 — memory-headroom floor (before acquiring the semaphore, so we don't
	// hold it while deciding to page). Below the floor: do NOT restart, page.
	if in.FloorBytes > 0 && in.HeadroomBytes < in.FloorBytes {
		return GatePage, "memory headroom below floor; restarting could OOM"
	}

	// Gate 2 — non-blocking acquire of the one-docker-child semaphore. NEVER queue
	// docker children (queuing IS the OOM vector) — if busy, defer to next tick.
	if in.AcquireSemaphore == nil || !in.AcquireSemaphore() {
		return GateDefer, "docker-child semaphore busy"
	}

	// Gate 5 — start pacing. Deferring here consumes no attempt.
	if in.Admit != nil {
		if ok, why := in.Admit(); !ok {
			if in.ReleaseSemaphore != nil {
				in.ReleaseSemaphore()
			}
			return GateDefer, "start gate: " + why
		}
	}
	return GateProceed, "all gates passed"
}
