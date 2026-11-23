package edge

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// PID is the running child's pid, a new one after a restart, and 0 when no child runs.
func TestSupervisorPID(t *testing.T) {
	skipNoShell(t)
	if (&Supervisor{}).PID() != 0 {
		t.Fatal("no child: PID must be 0")
	}
	bin := filepath.Join(t.TempDir(), "caddy")
	writeExec(t, bin, []byte("#!/bin/sh\nexec /bin/sleep 60\n"))
	launched := make(chan struct{}, 4)
	s := &Supervisor{BinFn: func() string { return bin }, Log: quietLog(), OnLaunch: func() { launched <- struct{}{} }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.supervise(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	wait := func() {
		t.Helper()
		select {
		case <-launched:
		case <-time.After(10 * time.Second):
			t.Fatal("the child was not launched")
		}
	}
	wait()
	first := s.PID()
	if first == 0 {
		t.Fatal("PID must be the running child's")
	}
	if p, err := os.FindProcess(first); err != nil || p.Signal(syscall.Signal(0)) != nil {
		t.Fatalf("pid %d is not a live process: %v", first, err)
	}
	s.Restart()
	wait()
	if second := s.PID(); second == 0 || second == first {
		t.Errorf("after a restart PID = %d (was %d); want the new child's", second, first)
	}
	cancel()
	<-done
	if s.PID() != 0 {
		t.Error("once supervision stops, PID must be 0")
	}
}
