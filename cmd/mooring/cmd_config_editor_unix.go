//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// cmd_config_editor_unix.go runs the operator's editor for `config edit` as a job of its own, the
// way a shell runs one:
//
//   - the editor gets its own process group. Debian's sensible-editor (and any wrapper script)
//     runs the real editor as a child; stopping the run signals the GROUP, so the real editor
//     can't outlive it and write the copy back after it was removed;
//   - while the editor runs its group is the terminal's foreground group, so the terminal's
//     Ctrl-C and Ctrl-Z reach the editor and nothing else, and the editor may read the terminal;
//   - an editor that suspends itself (Ctrl-Z) suspends this process with it, so the shell (or
//     sudo) gets the terminal back; `fg` continues both. Where nothing above this process does
//     job control there is nobody to continue it: it is not stopped, and the editor runs on.

// runConfigEditor runs the operator's editor on file, on this terminal. When ctx ends the editor's
// process group is asked to stop (SIGTERM, so a full-screen editor leaves the terminal as it found
// it) and whatever is left of it after editorStopDelay is killed.
func runConfigEditor(ctx context.Context, file string) error {
	argv, err := resolveEditor(os.Getenv, exec.LookPath)
	if err != nil {
		return err
	}
	j := editorJob{tty: -1, stopDelay: editorStopDelay, suspendSelf: suspendSelf}
	if fd := int(os.Stdin.Fd()); foregroundOf(fd) > 0 {
		j.tty = fd
	}
	return j.run(ctx, append(argv, file))
}

// editorJob is one editor run.
type editorJob struct {
	// tty is the controlling terminal's descriptor; -1 when there is none. Whether this process
	// is in its foreground group is asked each time: fg and bg change it while the editor runs.
	tty int
	// stopDelay is how long the group has after SIGTERM before it is killed.
	stopDelay time.Duration
	// suspendSelf stops this process until it is continued (tests replace it).
	suspendSelf func()
}

// foregroundOf returns the foreground process group of the terminal fd; -1 when fd is not this
// process's controlling terminal.
func foregroundOf(fd int) int {
	pgrp, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil {
		return -1
	}
	return pgrp
}

// isForegroundOn reports that fd is a terminal whose foreground process group is this process's.
func isForegroundOn(fd int) bool { return foregroundOf(fd) == syscall.Getpgrp() }

// suspendSettle is how long suspendSelf waits to be continued before it takes it that nothing
// stopped this process.
const suspendSettle = 100 * time.Millisecond

// suspendSelf stops this process, as the terminal's Ctrl-Z did when the editor shared its process
// group. It returns once the process is continued, or after suspendSettle when it was not stopped.
// Intentional: SIGTSTP, not SIGSTOP. Where nothing above this process does job control (ssh -t
// host 'sudo mooring config edit', docker exec -it, a wrapper script) its process group is
// orphaned and nobody could continue it. The kernel discards SIGTSTP for an orphaned group, and
// sudo passes SIGTSTP on the same way; SIGSTOP is never discarded and froze the session for good.
// Go leaves SIGTSTP at the system default (stop) unless signal.Notify asks for it, and nothing in
// `config edit` does.
// Intentional: SIGCONT is waited for instead of trusting that kill returns after the stop. The
// kernel may hand the signal to another thread of this process, so kill can return before the stop
// takes effect; going on then would hand the terminal to the editor a moment before the shell
// takes it. A process that is continued always gets SIGCONT. None within suspendSettle: the
// signal was discarded. (A stop that lasts longer is not mistaken for that: nothing here runs
// while the process is stopped, and by the time the timer is seen it has been continued.)
func suspendSelf() {
	continued := make(chan os.Signal, 1)
	signal.Notify(continued, syscall.SIGCONT)
	defer signal.Stop(continued)
	_ = syscall.Kill(syscall.Getpid(), syscall.SIGTSTP)
	select {
	case <-continued:
	case <-time.After(suspendSettle):
	}
}

// setForeground makes pgid the terminal's foreground process group.
// Intentional: SIGTTOU is ignored, and stays ignored. A process that is not in the foreground
// group (this one, while the editor's group is) is stopped by SIGTTOU when it changes the
// terminal's foreground group, unless it ignores the signal: a shell ignores it for itself for
// that reason. The Go runtime can't put the default back afterwards. signal.Reset leaves the
// signal ignored; Notify then Stop leaves the runtime's own handler, which does nothing, and a
// terminal call made from the background then never ends on Linux (the kernel restarts it for as
// long as the signal is caught) and fails with EINTR on macOS. The editor is given the default
// when it is started: see startWithDefaultTTOU.
func setForeground(tty, pgid int) {
	signal.Ignore(syscall.SIGTTOU)
	_ = unix.IoctlSetPointerInt(tty, unix.TIOCSPGRP, pgid)
}

// startWithDefaultTTOU starts cmd with SIGTTOU at its default where setForeground has ignored it
// in this process (the "edit again" run): an editor in the background must be stopped when it
// changes the terminal, and exec keeps an ignored signal ignored.
// Intentional: Notify around the start. A signal with a handler is at its default after exec, and
// Notify installs the runtime's handler; the channel is never read. Ignore puts back what
// setForeground left.
func startWithDefaultTTOU(cmd *exec.Cmd) error {
	if !signal.Ignored(syscall.SIGTTOU) {
		return cmd.Start()
	}
	signal.Notify(make(chan os.Signal, 1), syscall.SIGTTOU)
	defer signal.Ignore(syscall.SIGTTOU)
	return cmd.Start()
}

// editorWait is one thing the editor did: it stopped, or it ended.
type editorWait struct {
	stopped bool
	status  syscall.WaitStatus
	err     error
}

func (j editorJob) run(ctx context.Context, argv []string) error {
	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 -- the operator's own editor, run as argv, no shell
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// holds: this process gave the terminal to the editor's group and has not taken it back.
	// Started in the background (`mooring config edit &`) the editor doesn't get it: the terminal
	// is the shell's.
	holds := j.tty >= 0 && isForegroundOn(j.tty)
	if holds {
		// The child puts its own group in the foreground before it execs the editor (the Go
		// runtime does that with every signal blocked, so SIGTTOU can't stop it).
		cmd.SysProcAttr.Foreground = true
		cmd.SysProcAttr.Ctty = j.tty
	}
	if err := startWithDefaultTTOU(cmd); err != nil {
		return err
	}
	// Setpgid: the editor leads a group whose id is its pid. The id can't be given to another
	// process while any member of the group is alive.
	pid := cmd.Process.Pid
	self := syscall.Getpgrp()

	// Intentional: wait4 here instead of cmd.Wait. Only WUNTRACED reports an editor that stopped
	// (Ctrl-Z); cmd.Wait would sit there while the terminal belonged to a stopped group.
	events := make(chan editorWait)
	go func() {
		for {
			var ws syscall.WaitStatus
			_, err := syscall.Wait4(pid, &ws, syscall.WUNTRACED, nil)
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			// Intentional: not ws.Stopped(). On the BSDs and macOS that is false for a stop by
			// SIGSTOP. With WUNTRACED alone, a status that is neither an exit nor a death by a
			// signal is a stop.
			if err == nil && !ws.Exited() && !ws.Signaled() {
				events <- editorWait{stopped: true}
				continue
			}
			events <- editorWait{status: ws, err: err}
			return
		}
	}()

	var (
		done   = ctx.Done()
		kill   <-chan time.Time
		stopBy time.Time
		ended  editorWait
	)
loop:
	for {
		select {
		case ev := <-events:
			if !ev.stopped {
				ended = ev
				break loop
			}
			if ctx.Err() != nil {
				_ = syscall.Kill(-pid, syscall.SIGCONT) // it was told to end: it must run to do so
				continue
			}
			if j.tty >= 0 {
				// Asked of the terminal, not of holds: the editor's group exists (its leader is
				// stopped, not reaped), so its id means that group and nothing else.
				switch foregroundOf(j.tty) {
				case pid:
					// The editor suspended itself (Ctrl-Z): take the terminal back before
					// stopping with it.
					setForeground(j.tty, self)
				case self:
					// This process was brought to the foreground (fg) after the editor lost or
					// never had the terminal, and the editor stopped for want of it (SIGTTIN,
					// SIGTTOU): it gets the terminal and runs on; nothing is suspended.
					setForeground(j.tty, pid)
					holds = true
					_ = syscall.Kill(-pid, syscall.SIGCONT)
					continue
				}
				// Otherwise the terminal is the shell's (this job is in the background) and
				// stays so: taking it would leave the shell reading end-of-file at its prompt.
				holds = false
			}
			j.suspendSelf()
			// Continued. In the foreground again (fg): the editor gets the terminal back. In the
			// background (bg): it doesn't, and stops again when it touches the terminal.
			if j.tty >= 0 && isForegroundOn(j.tty) {
				setForeground(j.tty, pid)
				holds = true
			}
			_ = syscall.Kill(-pid, syscall.SIGCONT)
		case <-done:
			done = nil
			_ = syscall.Kill(-pid, syscall.SIGTERM)
			_ = syscall.Kill(-pid, syscall.SIGCONT) // a stopped editor only handles SIGTERM once it runs
			stopBy = time.Now().Add(j.stopDelay)
			kill = time.After(j.stopDelay)
		case <-kill:
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	}
	_ = cmd.Process.Release() // already reaped above; this only frees the handle
	if holds {
		// Before anything else touches the terminal: restoring its settings from a background
		// group would stop this process (SIGTTOU).
		// Intentional: decided by holds, not by asking the terminal. The editor's group is gone,
		// so its id says nothing any more; and a job the shell put in the background (bg) never
		// had the terminal to take back.
		setForeground(j.tty, self)
	}

	if ctx.Err() != nil {
		// The group's leader ended; a wrapper's real editor may not have. Nothing of the group
		// survives this run: what is left when the delay is over is killed.
		if stopBy.IsZero() { // the leader ended in the instant ctx did
			_ = syscall.Kill(-pid, syscall.SIGTERM)
			stopBy = time.Now().Add(j.stopDelay)
		}
		for groupAlive(pid) {
			if !time.Now().Before(stopBy) {
				_ = syscall.Kill(-pid, syscall.SIGKILL)
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		return ctx.Err()
	}
	switch {
	case ended.err != nil:
		return fmt.Errorf("wait for the editor: %w", ended.err)
	case ended.status.Signaled():
		return fmt.Errorf("the editor was ended by signal %v", ended.status.Signal())
	case ended.status.ExitStatus() != 0:
		return fmt.Errorf("exit status %d", ended.status.ExitStatus())
	}
	return nil
}

// groupAlive reports that the process group pgid still has a member.
func groupAlive(pgid int) bool {
	err := syscall.Kill(-pgid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
