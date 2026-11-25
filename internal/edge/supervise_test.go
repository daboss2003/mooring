package edge

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
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

// SetInitialCfg changes what the NEXT launched child boots on (the running one is untouched), and is
// safe while the launch loop reads it (run with -race).
func TestSupervisorSetInitialCfg(t *testing.T) {
	skipNoShell(t)
	dir := t.TempDir()
	bin := filepath.Join(dir, "caddy")
	// Stands in for `caddy run --config -`: keeps what it was given on stdin, then stays up.
	writeExec(t, bin, []byte("#!/bin/sh\n/bin/cat > \"$0.boot.$$.tmp\"\n/bin/mv \"$0.boot.$$.tmp\" \"$0.boot.$$\"\nexec /bin/sleep 60\n"))
	launched := make(chan struct{}, 4)
	s := &Supervisor{BinFn: func() string { return bin }, Log: quietLog(), OnLaunch: func() { launched <- struct{}{} },
		InitialCfg: []byte(`{"list":"start"}`)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.supervise(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	booted := func() string {
		t.Helper()
		select {
		case <-launched:
		case <-time.After(10 * time.Second):
			t.Fatal("the child was not launched")
		}
		path := bin + ".boot." + strconv.Itoa(s.PID())
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if b, err := os.ReadFile(path); err == nil {
				return string(b)
			}
		}
		t.Fatalf("the child never wrote %s", path)
		return ""
	}
	if got := booted(); got != `{"list":"start"}` {
		t.Fatalf("first launch booted on %q", got)
	}
	next := []byte(`{"list":"reloaded"}`)
	s.SetInitialCfg(next)
	next[2] = 'X' // the caller's slice is not kept
	if got := string(s.BootConfig()); got != `{"list":"reloaded"}` {
		t.Fatalf("BootConfig = %q", got)
	}
	// Writers racing the relaunch's read.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				s.SetInitialCfg([]byte(`{"list":"reloaded"}`))
				_ = s.BootConfig()
			}
		}
	}()
	s.Restart()
	got := booted()
	close(stop)
	wg.Wait()
	if got != `{"list":"reloaded"}` {
		t.Errorf("the relaunched child booted on %q, want the config set by SetInitialCfg", got)
	}
}
