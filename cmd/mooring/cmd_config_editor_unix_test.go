//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// waitForFile waits until path exists.
func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never appeared", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// isZombie reports that pid has ended and waits to be reaped (Linux /proc only; false elsewhere).
func isZombie(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	i := strings.LastIndexByte(string(b), ')')
	return i >= 0 && i+2 < len(b) && b[i+2] == 'Z'
}

func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// pidGone waits for the process to end (a zombie that its new parent has not reaped yet counts as
// alive for a moment).
// Intentional: on Linux a zombie counts as ended. In a container whose PID 1 is the test binary's
// parent (no init), nothing ever reaps the orphaned editor, so it stays a zombie for good.
func pidGone(pid int) bool {
	for i := 0; i < 200; i++ {
		if syscall.Kill(pid, 0) != nil || isZombie(pid) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// A wrapper editor (Debian's sensible-editor: a script that runs the real editor as a child, not
// by exec). Stopping the run must stop the real editor too: left alive it writes the copy back
// after config edit removed it and said the file was not changed.
func TestRunConfigEditorStopsAWrappersEditor(t *testing.T) {
	for _, c := range []struct {
		name string
		// The real editor, run by the wrapper as a child: what it does before it says it is
		// there (its pid file), and after.
		first, real string
	}{
		{"ends on SIGTERM", "", "exec sleep 30"},
		{"ignores SIGTERM: killed after the delay", "trap \"\" TERM; ", "while :; do sleep 0.05; done"},
		// The real editor is ASKED to stop (so it can leave the terminal as it found it), not
		// just killed once its wrapper is gone.
		{"asked to stop", "trap \"echo asked > " + "$0.asked" + "; exit 0\" TERM; ", "while :; do sleep 0.05; done"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			pidFile := filepath.Join(dir, "pid")
			asked := filepath.Join(dir, "asked")
			wrapper := writeScript(t, dir, "wrapper-editor", "#!/bin/sh\nsh -c '"+strings.ReplaceAll(c.first, "$0.asked", asked)+"echo $$ > "+pidFile+".tmp; mv "+pidFile+".tmp "+pidFile+"; "+c.real+"'\nexit $?\n")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			j := editorJob{tty: -1, stopDelay: 400 * time.Millisecond, suspendSelf: func() {}}
			go func() { done <- j.run(ctx, []string{wrapper, filepath.Join(dir, "f")}) }()
			waitForFile(t, pidFile)
			raw, err := os.ReadFile(pidFile)
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
			if err != nil || pid <= 1 {
				t.Fatalf("pid file: %q", raw)
			}
			defer syscall.Kill(pid, syscall.SIGKILL)
			if pgid, _ := syscall.Getpgid(pid); pgid == syscall.Getpgrp() {
				t.Errorf("the editor must run in a process group of its own, not in this one (%d)", pgid)
			}
			start := time.Now()
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Error("a stopped editor is an error")
				}
			case <-time.After(15 * time.Second):
				t.Fatal("the run never returned")
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("stopping took %v", d)
			}
			if !pidGone(pid) {
				t.Errorf("the real editor (pid %d) outlived the run", pid)
			}
			if c.name == "asked to stop" {
				if _, err := os.Stat(asked); err != nil {
					t.Error("the real editor was killed without being asked to stop (no SIGTERM reached it)")
				}
			}
		})
	}
}

// runConfigEditor itself (the production wiring) puts the editor in its own group and stops the
// group.
func TestRunConfigEditorOwnProcessGroup(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "pid")
	wrapper := writeScript(t, dir, "wrapper-editor", "#!/bin/sh\nsh -c 'echo $$ > "+pidFile+".tmp; mv "+pidFile+".tmp "+pidFile+"; exec sleep 30'\nexit $?\n")
	t.Setenv("SUDO_EDITOR", wrapper)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runConfigEditor(ctx, filepath.Join(dir, "f")) }()
	waitForFile(t, pidFile)
	raw, _ := os.ReadFile(pidFile)
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 1 {
		t.Fatalf("pid file: %q", raw)
	}
	defer syscall.Kill(pid, syscall.SIGKILL)
	cancel()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the run never returned")
	}
	if !pidGone(pid) {
		t.Errorf("the real editor (pid %d) outlived runConfigEditor", pid)
	}
}

// An editor that suspends itself (Ctrl-Z) suspends this process with it; once this process is
// continued the editor is continued too.
func TestEditorJobSuspendsWithTheEditor(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	editor := writeScript(t, dir, "editor", "#!/bin/sh\necho 1 > \"$1.before\"\nkill -STOP $$\necho 2 > \"$1.after\"\n")
	var suspended atomic.Int32
	j := editorJob{tty: -1, stopDelay: time.Second, suspendSelf: func() {
		suspended.Add(1)
		if _, err := os.Stat(f + ".after"); err == nil {
			t.Error("the editor ran on while it was stopped")
		}
	}}
	done := make(chan error, 1)
	go func() { done <- j.run(context.Background(), []string{editor, f}) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("the editor ended normally after it was continued: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("a stopped editor was never continued")
	}
	if suspended.Load() != 1 {
		t.Errorf("this process was suspended %d times, want 1", suspended.Load())
	}
	if _, err := os.Stat(f + ".after"); err != nil {
		t.Error("the editor did not run on after it was continued")
	}
}

// A stopped editor still ends when the run is stopped (it is continued so that it can).
func TestEditorJobStopsAStoppedEditor(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	editor := writeScript(t, dir, "editor", "#!/bin/sh\necho $$ > \"$1.pid\"\nkill -STOP $$\nsleep 30\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The run is stopped while this process is "suspended".
	j := editorJob{tty: -1, stopDelay: 500 * time.Millisecond, suspendSelf: cancel}
	done := make(chan error, 1)
	go func() { done <- j.run(ctx, []string{editor, f}) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the run never returned")
	}
	raw, _ := os.ReadFile(f + ".pid")
	if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err != nil || !pidGone(pid) {
		t.Errorf("the editor (pid %q) is still there", raw)
	}
}

func TestEditorJobExitStatus(t *testing.T) {
	dir := t.TempDir()
	j := editorJob{tty: -1, stopDelay: time.Second, suspendSelf: func() {}}
	if err := j.run(context.Background(), []string{writeScript(t, dir, "ok", "#!/bin/sh\nexit 0\n"), "f"}); err != nil {
		t.Errorf("exit 0: %v", err)
	}
	if err := j.run(context.Background(), []string{writeScript(t, dir, "fail", "#!/bin/sh\nexit 3\n"), "f"}); err == nil || !strings.Contains(err.Error(), "exit status 3") {
		t.Errorf("exit 3: %v", err)
	}
	if err := j.run(context.Background(), []string{writeScript(t, dir, "killed", "#!/bin/sh\nkill -KILL $$\n"), "f"}); err == nil || !strings.Contains(err.Error(), "signal") {
		t.Errorf("killed: %v", err)
	}
	if err := j.run(context.Background(), []string{filepath.Join(dir, "not-there"), "f"}); err == nil {
		t.Error("an editor that can't be started is an error")
	}
}

// setForeground leaves SIGTTOU ignored in this process. An editor started afterwards (the "edit
// again" run) must have it at its default all the same: here it sends itself SIGTTOU and must
// stop. This process goes on ignoring it.
func TestEditorStartedAfterSetForegroundHasDefaultTTOU(t *testing.T) {
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	// Not a terminal: the call fails, what it does with the signal is the same.
	setForeground(int(null.Fd()), syscall.Getpgrp())
	// The other tests' child processes are not started by editorJob: they get the default again.
	t.Cleanup(func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGTTOU)
		signal.Stop(c)
	})
	if !signal.Ignored(syscall.SIGTTOU) {
		t.Fatal("setForeground ignores SIGTTOU")
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	editor := writeScript(t, dir, "editor", "#!/bin/sh\nkill -TTOU $$\necho done > \"$1.done\"\n")
	var stopped atomic.Int32
	j := editorJob{tty: -1, stopDelay: time.Second, suspendSelf: func() { stopped.Add(1) }}
	done := make(chan error, 1)
	go func() { done <- j.run(context.Background(), []string{editor, f}) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("the editor: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the run never returned")
	}
	if stopped.Load() != 1 {
		t.Errorf("the editor stopped %d times on SIGTTOU, want 1: it inherited the signal ignored", stopped.Load())
	}
	if !signal.Ignored(syscall.SIGTTOU) {
		t.Error("after the start this process must ignore SIGTTOU again, not handle it: a terminal call from the background would never end")
	}
}

const suspendSelfEnv = "MOORING_TEST_SUSPEND_SELF"

// TestSuspendSelfHelper is not a test: TestSuspendSelfStopsBeforeItReturns runs it in a child
// process, which suspends itself as many times as the environment says and writes one byte on
// descriptor 3 each time suspendSelf returns.
func TestSuspendSelfHelper(t *testing.T) {
	n, err := strconv.Atoi(os.Getenv(suspendSelfEnv))
	if err != nil {
		return
	}
	w := os.NewFile(3, "w")
	for i := 0; i < n; i++ {
		suspendSelf()
		if _, err := w.Write([]byte{1}); err != nil {
			os.Exit(1)
		}
	}
	os.Exit(0)
}

// Under a parent that does job control, suspendSelf stops the process and returns only after it
// was continued. kill returning is not that: on Linux the stop can take effect a moment later, and
// going on meanwhile would hand the terminal to the editor just before the shell takes it. (The
// macOS kernel stops the process before kill returns, so this discriminates on Linux.)
func TestSuspendSelfStopsBeforeItReturns(t *testing.T) {
	const rounds = 300
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSuspendSelfHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), suspendSelfEnv+"="+strconv.Itoa(rounds))
	cmd.ExtraFiles = []*os.File{w}
	// A group of its own, whose parent is in another group of the same session: not orphaned.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	w.Close()
	pid := cmd.Process.Pid
	defer cmd.Process.Release()
	// One wait at a time: true for a stop, false once the helper ended.
	waits := make(chan bool)
	go func() {
		for {
			var ws syscall.WaitStatus
			_, err := syscall.Wait4(pid, &ws, syscall.WUNTRACED, nil)
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			stopped := err == nil && !ws.Exited() && !ws.Signaled()
			waits <- stopped
			if !stopped {
				return
			}
		}
	}()
	ended := false
	t.Cleanup(func() {
		if !ended {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	next := func() bool {
		t.Helper()
		select {
		case stopped := <-waits:
			ended = !stopped
			return stopped
		case <-time.After(20 * time.Second):
			t.Fatal("the helper neither stopped nor ended")
			return false
		}
	}
	b := make([]byte, 1)
	for i := 0; i < rounds; i++ {
		if !next() {
			t.Fatalf("round %d: the helper ended instead of stopping", i)
		}
		// Stopped: suspendSelf must not have returned yet.
		_ = r.SetReadDeadline(time.Now().Add(time.Millisecond))
		if n, _ := r.Read(b); n > 0 {
			t.Fatalf("round %d: suspendSelf returned before the stop took effect", i)
		}
		_ = syscall.Kill(pid, syscall.SIGCONT)
		_ = r.SetReadDeadline(time.Now().Add(20 * time.Second))
		if n, err := r.Read(b); n != 1 {
			t.Fatalf("round %d: suspendSelf did not return once the process was continued: %v", i, err)
		}
	}
	if next() {
		t.Error("the helper stopped once more than it was asked to")
	}
}
