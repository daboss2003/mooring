package web

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/selfheal"
	"github.com/daboss2003/mooring/internal/startgate"
)

// One entry per key, in arrival order; a closed PR's entry can be removed.
func TestDeployQueueDedupeAndOrder(t *testing.T) {
	q := newDeployQueue()
	a := pendingDeploy{key: appQueueKey("shop"), project: "shop"}
	b := pendingDeploy{key: prQueueKey("shop", 7), project: "shop", pr: 7}
	if !q.add(a) || !q.add(b) || q.add(a) {
		t.Fatal("add must accept new keys and refuse a waiting duplicate")
	}
	if got := q.keys(); !reflect.DeepEqual(got, []string{"app:shop", "pr:shop#7"}) {
		t.Fatalf("keys = %v", got)
	}
	if !q.remove(prQueueKey("shop", 7)) || q.remove("nope") {
		t.Fatal("remove must drop exactly the named entry")
	}
	if got := q.keys(); !reflect.DeepEqual(got, []string{"app:shop"}) {
		t.Fatalf("keys after remove = %v", got)
	}
	d, ok := q.pop()
	if !ok || d.key != "app:shop" {
		t.Fatalf("pop = %+v, %v", d, ok)
	}
	if _, ok := q.pop(); ok {
		t.Fatal("the queue must be empty")
	}
}

// While the gate is busy the entry never leaves the queue, so a PR-close remove() always finds it.
func TestQueuedPreviewRemovableWhileGateBusy(t *testing.T) {
	s := &Server{log: quietWebLog(), gitDeploy: dockerexec.NewSemaphore(), deployQueue: newDeployQueue()}
	s.queuedRun = func(context.Context, pendingDeploy) { t.Error("a removed entry must never run") }
	s.deployQueue.add(pendingDeploy{key: prQueueKey("shop", 7), project: "shop", pr: 7})
	if !s.gitDeploy.TryAcquire() {
		t.Fatal("pre-acquire")
	}
	if s.startPendingDeploy() {
		t.Fatal("must not start while the gate is held")
	}
	if !s.deployQueue.remove(prQueueKey("shop", 7)) {
		t.Fatal("the waiting entry must still be removable")
	}
	s.gitDeploy.Release()
	if s.startPendingDeploy() {
		t.Fatal("nothing left to start")
	}
	if !s.gitDeploy.TryAcquire() {
		t.Fatal("an empty queue must give the gate back")
	}
	s.gitDeploy.Release()
}

// A queued webhook waits while the git gate is held and runs (holding the gate) once it frees.
func TestStartPendingDeployWaitsForTheGate(t *testing.T) {
	ran := make(chan pendingDeploy, 1)
	s := &Server{log: quietWebLog(), gitDeploy: dockerexec.NewSemaphore(), deployQueue: newDeployQueue()}
	s.queuedRun = func(_ context.Context, d pendingDeploy) {
		if s.gitDeploy.TryAcquire() {
			t.Error("the queued run must hold the gate")
		}
		ran <- d
	}
	s.deployQueue.add(pendingDeploy{key: appQueueKey("shop"), project: "shop", queued: time.Now()})

	if !s.gitDeploy.TryAcquire() {
		t.Fatal("pre-acquire")
	}
	if s.startPendingDeploy() {
		t.Fatal("must not start while the gate is held")
	}
	if got := s.deployQueue.keys(); len(got) != 1 {
		t.Fatalf("the entry must keep its place, got %v", got)
	}
	s.gitDeploy.Release()
	if !s.startPendingDeploy() {
		t.Fatal("must start once the gate is free")
	}
	select {
	case d := <-ran:
		if d.project != "shop" {
			t.Fatalf("ran %+v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("queued run never happened")
	}
	// The run released the gate when it finished.
	deadline := time.Now().Add(5 * time.Second)
	for !s.gitDeploy.TryAcquire() {
		if time.Now().After(deadline) {
			t.Fatal("the gate was never released")
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.gitDeploy.Release()
	if len(s.deployQueue.keys()) != 0 {
		t.Fatal("the queue must be empty")
	}
}

// Overlapping expected_down holders (a per-copy restart while a deploy runs) are reference-counted: the
// first holder to finish must not lift the suspension the other still needs.
func TestExpectedDownLeaseIsRefcounted(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.selfHeal = selfheal.NewStore(e.srv.db)
	ctx := context.Background()
	leased := func() bool {
		m, err := e.srv.selfHeal.ActiveExpectedDown(time.Now().Unix())
		if err != nil {
			t.Fatal(err)
		}
		return m["shop"]
	}
	releaseDeploy := e.srv.leaseExpectedDown(ctx, "shop")
	releaseCopy := e.srv.leaseExpectedDown(ctx, "shop")
	if !leased() {
		t.Fatal("the app must be leased")
	}
	releaseCopy()
	releaseCopy() // a double release is harmless
	if !leased() {
		t.Fatal("the deploy still holds the lease after the per-copy action finished")
	}
	releaseDeploy()
	if leased() {
		t.Fatal("the last holder's release must lift the lease")
	}
}

// A due task the start gate holds back runs once it has been held for max_wait, and the hold clock
// isn't reset until the task actually ran.
func TestCronHoldIsBoundedAndClearedOnlyByARun(t *testing.T) {
	g := startgate.New(startgate.DefaultConfig(2))
	g.Record("other", "", time.Now(), time.Now(), false) // another start is still settling: the gate says no
	s := &Server{startGate: g}
	if s.cronMayStart("shop/job") {
		t.Fatal("a due task waits while the gate says no")
	}
	s.cronHeld["shop/job"] = time.Now().Add(-11 * time.Minute) // held past max_wait (10m)
	if !s.cronMayStart("shop/job") {
		t.Fatal("after max_wait it runs anyway")
	}
	if !s.cronMayStart("shop/job") {
		t.Fatal("it stays allowed until it actually ran (the clock isn't reset by asking)")
	}
}
