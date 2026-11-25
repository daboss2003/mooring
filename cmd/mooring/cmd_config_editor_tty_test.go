//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const editorTTYEnv = "MOORING_TEST_EDITOR_TTY"

// TestEditorJobTTYHelper is not a test: the tests below run it in a child process that leads a
// session on a pseudo-terminal, as `config edit` runs in a terminal. What it does there is named
// by the environment; it records what it saw in files beside f.
//
//   - "": one editorJob whose suspendSelf waits for f.continue instead of stopping;
//   - "real": runConfigEditor, as `config edit` calls it;
//   - "shell", "shell-bg": a job-control shell that runs a "real" helper as its one job, in the
//     foreground or in the background (see ttyShell).
func TestEditorJobTTYHelper(t *testing.T) {
	f := os.Getenv(editorTTYEnv)
	if f == "" {
		return
	}
	note := func(name, format string, a ...any) { ttyNote(f, name, format, a...) }
	switch mode := os.Getenv(editorTTYEnv + "_MODE"); mode {
	case "real":
		err := runConfigEditor(context.Background(), f)
		note("result", "err=%v foreground=%v", err, isForegroundOn(0))
		os.Exit(0)
	case "shell", "shell-bg":
		ttyShell(f, mode == "shell-bg")
		os.Exit(0)
	}
	if !isForegroundOn(0) {
		note("result", "the helper is not in the foreground of its terminal")
		os.Exit(1)
	}
	j := editorJob{tty: 0, stopDelay: time.Second, suspendSelf: func() {
		// Stands in for the stop: the shell would now have the terminal. What matters is that
		// this process took the terminal back from the stopped editor first.
		note("suspended", "foreground=%v", isForegroundOn(0))
		for {
			if _, err := os.Stat(f + ".continue"); err == nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}}
	err := j.run(context.Background(), []string{os.Getenv("SUDO_EDITOR"), f})
	note("result", "err=%v foreground=%v pgrp=%d", err, isForegroundOn(0), syscall.Getpgrp())
	os.Exit(0)
}

// ttyNote writes f.name in one step, so a reader never sees it half written.
func ttyNote(f, name, format string, a ...any) {
	tmp := f + "." + name + ".tmp"
	_ = os.WriteFile(tmp, []byte(fmt.Sprintf(format, a...)), 0o600)
	_ = os.Rename(tmp, f+"."+name)
}

// ttyShell does what an interactive shell does for one job, on the terminal on descriptor 0: the
// job has its own process group; when it stops the shell takes the terminal back; f.fg continues
// it with the terminal and f.bg without. It records in f.jobs, one line per event: where the
// terminal was when the job stopped ("stopped fg=job|shell|other") and "exited"; and in f.stolen,
// a foreground group other than the shell's while the job was in the background.
func ttyShell(f string, background bool) {
	self := syscall.Getpgrp()
	cmd := exec.Command(os.Args[0], "-test.run=^TestEditorJobTTYHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), editorTTYEnv+"_MODE=real")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if !background {
		cmd.SysProcAttr.Foreground = true
		cmd.SysProcAttr.Ctty = 0
	}
	if err := cmd.Start(); err != nil {
		ttyNote(f, "jobs", "start: %v", err)
		return
	}
	job := cmd.Process.Pid
	ttyNote(f, "jobpid", "%d", job)
	stops := make(chan bool)
	go func() {
		for {
			var ws syscall.WaitStatus
			_, err := syscall.Wait4(job, &ws, syscall.WUNTRACED, nil)
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			stopped := err == nil && !ws.Exited() && !ws.Signaled()
			stops <- stopped
			if !stopped {
				return
			}
		}
	}()
	var jobs []string
	event := func(line string) {
		jobs = append(jobs, line)
		ttyNote(f, "jobs", "%s", strings.Join(jobs, "\n"))
	}
	watch := func() {
		if fg, _ := unix.IoctlGetInt(0, unix.TIOCGPGRP); background && fg != self {
			ttyNote(f, "stolen", "foreground group %d, the shell's is %d", fg, self)
		}
	}
	command := func(name string) bool {
		if _, err := os.Stat(f + "." + name); err != nil {
			return false
		}
		_ = os.Remove(f + "." + name)
		return true
	}
	for {
		select {
		case stopped := <-stops:
			watch()
			if !stopped {
				event("exited")
				return
			}
			switch fg, _ := unix.IoctlGetInt(0, unix.TIOCGPGRP); fg {
			case job:
				event("stopped fg=job")
			case self:
				event("stopped fg=shell")
			default:
				event("stopped fg=other")
			}
			setForeground(0, self)
			background = true
		case <-time.After(5 * time.Millisecond):
			watch()
			switch {
			case command("fg"):
				background = false
				setForeground(0, job)
				_ = syscall.Kill(-job, syscall.SIGCONT)
			case command("bg"):
				_ = syscall.Kill(-job, syscall.SIGCONT)
			}
		}
	}
}

// ttySession is a helper process that leads a session on a pseudo-terminal.
type ttySession struct {
	t      *testing.T
	f      string // the helper's files are f.<name>
	master *os.File
	pid    int
	exited chan error
	out    string
}

// startTTYSession runs the helper in mode on a new pseudo-terminal, with editor (a /bin/sh script
// body, run with f as $1) as the editor.
func startTTYSession(t *testing.T, mode, editor string) *ttySession {
	t.Helper()
	master, slaveName, err := openPTY()
	if err != nil {
		t.Skipf("no pseudo-terminal here: %v", err)
	}
	t.Cleanup(func() { master.Close() })
	slave, err := os.OpenFile(slaveName, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal here: %v", err)
	}
	defer slave.Close()
	// Drain what the terminal echoes, so nothing blocks on a full buffer.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := master.Read(buf); err != nil {
				return
			}
		}
	}()

	dir := t.TempDir()
	s := &ttySession{t: t, f: filepath.Join(dir, "f"), master: master, exited: make(chan error, 1), out: filepath.Join(dir, "helper.out")}
	out, err := os.Create(s.out)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestEditorJobTTYHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), editorTTYEnv+"="+s.f, editorTTYEnv+"_MODE="+mode,
		"SUDO_EDITOR="+writeScript(t, dir, "editor", "#!/bin/sh\necho $$ > \"$1.pid.tmp\"; mv \"$1.pid.tmp\" \"$1.pid\"\n"+editor))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Skipf("can't start a session on the pseudo-terminal: %v", err)
	}
	s.pid = cmd.Process.Pid
	go func() { s.exited <- cmd.Wait() }()
	// Every process of the session: the helper, the shell's job and the editor each lead a group.
	t.Cleanup(func() {
		pids := []int{s.pid}
		for _, name := range []string{"jobpid", "pid"} {
			if b, err := os.ReadFile(s.f + "." + name); err == nil {
				if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 1 {
					pids = append(pids, pid)
				}
			}
		}
		for _, pid := range pids {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	return s
}

func (s *ttySession) fail(format string, a ...any) {
	s.t.Helper()
	helperOut, _ := os.ReadFile(s.out)
	jobs, _ := os.ReadFile(s.f + ".jobs")
	s.t.Fatalf("%s\njobs: %q\nhelper output:\n%s", fmt.Sprintf(format, a...), jobs, helperOut)
}

// wait returns f.name's content once it is there.
func (s *ttySession) wait(name string) string {
	s.t.Helper()
	return s.waitFor(name, func(string) bool { return true })
}

// waitFor returns f.name's content once ok accepts it.
func (s *ttySession) waitFor(name string, ok func(string) bool) string {
	s.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		b, err := os.ReadFile(s.f + "." + name)
		if got := strings.TrimSpace(string(b)); err == nil && ok(got) {
			return got
		}
		if time.Now().After(deadline) {
			s.fail("%s.%s never appeared, or never as expected: %q", filepath.Base(s.f), name, b)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitJobs waits until the shell has recorded exactly these events, in this order.
func (s *ttySession) waitJobs(want ...string) {
	s.t.Helper()
	all := strings.Join(want, "\n")
	deadline := time.Now().Add(20 * time.Second)
	for {
		b, _ := os.ReadFile(s.f + ".jobs")
		got := strings.TrimSpace(string(b))
		if got == all {
			return
		}
		if !strings.HasPrefix(all, got) || time.Now().After(deadline) {
			s.fail("the shell's job events: want %q", want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (s *ttySession) exists(name string) bool {
	_, err := os.Stat(s.f + "." + name)
	return err == nil
}

func (s *ttySession) touch(name string) {
	s.t.Helper()
	if err := os.WriteFile(s.f+"."+name, nil, 0o600); err != nil {
		s.t.Fatal(err)
	}
}

// taken waits until the shell has carried out the command f.name (it removes the file).
func (s *ttySession) taken(name string) {
	s.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for s.exists(name) {
		if time.Now().After(deadline) {
			s.fail("the shell never took %q", name)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// typed sends what the operator types on the terminal.
func (s *ttySession) typed(b string) {
	s.t.Helper()
	if _, err := s.master.Write([]byte(b)); err != nil {
		s.t.Fatal(err)
	}
}

func (s *ttySession) waitExit() {
	s.t.Helper()
	select {
	case err := <-s.exited:
		if err != nil {
			s.fail("the helper: %v", err)
		}
	case <-time.After(20 * time.Second):
		s.fail("the helper never ended (stopped?)")
	}
}

const ctrlZ = "\x1a"

// On a real terminal: while the editor runs its process group is the terminal's foreground group
// (it can read the terminal, and the terminal's Ctrl-Z reaches it alone); when it stops, this
// process takes the terminal back and suspends; continued, the editor has the terminal again;
// afterwards the terminal is this process's again.
func TestEditorJobOnATerminal(t *testing.T) {
	// The editor records its group and the terminal's foreground group, then reads the terminal
	// twice. A process outside the foreground group is stopped (SIGTTIN) when it reads.
	s := startTTYSession(t, "", "ps -o pgid= -o tpgid= -p $$ > \"$1.ps.tmp\"; mv \"$1.ps.tmp\" \"$1.ps\"\n"+
		"read one\necho \"$one\" > \"$1.one\"\nread two\necho \"$two\" > \"$1.two.tmp\"; mv \"$1.two.tmp\" \"$1.two\"\n")
	ps := strings.Fields(s.wait("ps"))
	if len(ps) != 2 || ps[0] != ps[1] {
		t.Fatalf("the editor's group must be the terminal's foreground group: pgid/tpgid = %v", ps)
	}
	if ps[0] == fmt.Sprint(s.pid) {
		t.Errorf("the editor must have a process group of its own, not the helper's (%s)", ps[0])
	}
	// Ctrl-Z: the terminal stops its foreground group, which is the editor alone.
	s.typed(ctrlZ)
	if got := s.wait("suspended"); got != "foreground=true" {
		t.Errorf("when the editor stops, this process takes the terminal back before it suspends: %s", got)
	}
	if s.exists("one") {
		t.Error("the editor read the terminal while it was stopped")
	}
	// fg: the editor is continued with the terminal, and reads it.
	s.touch("continue")
	s.typed("first\nsecond\n")
	if got := s.wait("two"); got != "second" {
		t.Errorf("the continued editor reads the terminal: %q", got)
	}
	if got := s.wait("one"); got != "first" {
		t.Errorf("the continued editor reads the terminal: %q", got)
	}
	want := fmt.Sprintf("err=<nil> foreground=true pgrp=%d", s.pid)
	if got := s.wait("result"); got != want {
		t.Errorf("after the editor the terminal is this process's again: %q, want %q", got, want)
	}
	s.waitExit()
}

// Nothing above `config edit` does job control (ssh -t host 'sudo mooring config edit', docker
// exec -it, a wrapper script): it leads the session, so nobody could continue it. Ctrl-Z in the
// editor must leave neither of them stopped.
func TestConfigEditorCtrlZWithoutJobControl(t *testing.T) {
	s := startTTYSession(t, "real", "echo started > \"$1.started\"\nread line\necho \"$line\" > \"$1.got.tmp\"; mv \"$1.got.tmp\" \"$1.got\"\n")
	s.wait("started")
	s.typed(ctrlZ)
	s.typed("hello\n")
	if got := s.wait("got"); got != "hello" {
		t.Errorf("after Ctrl-Z the editor reads the terminal: %q", got)
	}
	if got := s.wait("result"); got != "err=<nil> foreground=true" {
		t.Errorf("after the editor the terminal is this process's again: %q", got)
	}
	s.waitExit()
}

// Under a shell that does job control, with the stop that `config edit` really uses.
func TestConfigEditorUnderAJobControlShell(t *testing.T) {
	const read = "read line\necho \"$line\" > \"$1.got.tmp\"; mv \"$1.got.tmp\" \"$1.got\"\n"
	const started = "echo started > \"$1.started\"\n"
	reads := func(t *testing.T, s *ttySession) {
		t.Helper()
		s.typed("hello\n")
		if got := s.wait("got"); got != "hello" {
			t.Errorf("the editor reads the terminal: %q", got)
		}
	}
	ends := func(t *testing.T, s *ttySession, jobs ...string) {
		t.Helper()
		s.waitJobs(append(jobs, "exited")...)
		s.waitExit()
		if got := s.wait("result"); !strings.HasPrefix(got, "err=<nil> ") {
			t.Errorf("config edit: %s", got)
		}
		if s.exists("stolen") {
			t.Errorf("config edit took the terminal from the shell while it was in the background: %s", s.wait("stolen"))
		}
	}

	// Ctrl-Z stops the editor and `config edit` with it, the terminal back with its own group;
	// fg continues both and the editor has the terminal.
	t.Run("Ctrl-Z then fg", func(t *testing.T) {
		s := startTTYSession(t, "shell", started+read)
		s.wait("started")
		s.typed(ctrlZ)
		s.waitJobs("stopped fg=job")
		if s.exists("got") {
			t.Error("the editor read the terminal while it was stopped")
		}
		s.touch("fg")
		reads(t, s)
		ends(t, s, "stopped fg=job")
	})

	// bg: the editor runs on without the terminal, which stays the shell's — also when the
	// editor ends there.
	t.Run("Ctrl-Z then bg, the editor ends", func(t *testing.T) {
		s := startTTYSession(t, "shell", started+"kill -TSTP $$\necho after > \"$1.after\"\n")
		s.waitJobs("stopped fg=job")
		s.touch("bg")
		s.wait("after")
		ends(t, s, "stopped fg=job")
	})

	// bg, and the editor wants the terminal: the job stops again, the terminal untouched; fg
	// gives it to the editor.
	t.Run("Ctrl-Z then bg, the editor reads", func(t *testing.T) {
		s := startTTYSession(t, "shell", started+"kill -TSTP $$\n"+read)
		s.waitJobs("stopped fg=job")
		s.touch("bg")
		s.waitJobs("stopped fg=job", "stopped fg=shell")
		s.touch("fg")
		reads(t, s)
		ends(t, s, "stopped fg=job", "stopped fg=shell")
	})

	// Started in the background (`sudo mooring config edit &`): the editor stops when it wants
	// the terminal and the job with it; fg gives the editor the terminal.
	t.Run("started in the background, fg once it stopped", func(t *testing.T) {
		s := startTTYSession(t, "shell-bg", started+read)
		s.waitJobs("stopped fg=shell")
		s.touch("fg")
		reads(t, s)
		ends(t, s, "stopped fg=shell")
	})

	// Started in the background and brought to the foreground before the editor wants the
	// terminal: when it does, it gets it, and nothing stops.
	t.Run("started in the background, fg before the editor reads", func(t *testing.T) {
		s := startTTYSession(t, "shell-bg", started+"while [ ! -e \"$1.go\" ]; do sleep 0.05; done\n"+read)
		s.wait("started")
		s.touch("fg")
		s.taken("fg")
		s.touch("go")
		reads(t, s)
		ends(t, s)
	})
}
