package hostlog

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A default log path replaced by a symlink to a file outside /var/log (a syslog-group user can
// write /var/log on Debian) must not make Mooring read that file into the security log.
func TestAbuseDefaultPathSymlinkOutsideVarLogRefused(t *testing.T) {
	root := t.TempDir()
	vl := filepath.Join(root, "var", "log")
	setVarLog(t, vl)
	secret := filepath.Join(root, "etc", "shadow")
	writeFile(t, secret, "root:$6$salt$hash:19000:0:99999:7:::\n")
	if err := os.MkdirAll(vl, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(vl, "auth.log")
	if err := os.Symlink(secret, p); err != nil {
		t.Fatal(err)
	}

	ff, f, ck, s := authFile(t, Config{AuthLog: p})
	ff.step()
	appendFile(t, secret, "mooring:$6$another$hash:::\n")
	ck.Add(ff.f.retry)
	ff.step()
	wantLines(t, s.texts())
	if st := statusOf(t, f, "host:auth"); st.OK || !strings.HasPrefix(st.Err, "refused: ") {
		t.Fatalf("status = %+v, want a refusal", st)
	}

	// Rotation into a symlink is refused the same way.
	real := filepath.Join(vl, "auth.log.real")
	writeFile(t, real, "")
	os.Remove(p)
	if err := os.Symlink(real, p); err != nil {
		t.Fatal(err)
	}
	ck.Add(ff.f.retry)
	ff.step()
	appendFile(t, real, "inside\n")
	ff.step()
	wantLines(t, s.texts(), "inside") // a symlink that stays under /var/log is followed
	os.Remove(p)
	if err := os.Symlink(secret, p); err != nil {
		t.Fatal(err)
	}
	ff.step()
	appendFile(t, secret, "leak\n")
	ck.Add(ff.f.retry)
	ff.step()
	ff.step()
	wantLines(t, s.texts(), "inside")
	if st := statusOf(t, f, "host:auth"); st.OK || !strings.HasPrefix(st.Err, "refused: ") {
		t.Fatalf("status after rotation into a symlink = %+v, want a refusal", st)
	}
}

// A path the operator named (not one of the defaults) may live, or point, anywhere but /proc,
// /sys and /dev.
func TestAbuseExplicitPathMayLeaveVarLog(t *testing.T) {
	root := t.TempDir()
	setVarLog(t, filepath.Join(root, "var", "log"))
	target := filepath.Join(root, "srv", "logs", "auth.log")
	writeFile(t, target, "")
	p := filepath.Join(root, "custom", "auth.log")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	ff, _, _, s := authFile(t, Config{AuthLog: p})
	ff.step()
	appendFile(t, target, "ok\n")
	ff.step()
	wantLines(t, s.texts(), "ok")
}

func TestAbuseProcSysDevRefusedEvenWhenExplicit(t *testing.T) {
	dir := t.TempDir()
	viaLink := filepath.Join(dir, "environ")
	if err := os.Symlink("/proc/self/environ", viaLink); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/proc/self/environ", "/sys/kernel/notes", "/dev/null", "/dev/zero", viaLink} {
		ff, f, _, s := authFile(t, Config{AuthLog: p})
		ff.step()
		st := statusOf(t, f, "host:auth")
		if p == viaLink && st.Err == "not found" {
			continue // no /proc on this OS: nothing to read either way
		}
		if st.OK || !strings.HasPrefix(st.Err, "refused: ") || len(s.texts()) != 0 {
			t.Errorf("%s: status = %+v lines = %q, want a refusal", p, st, s.texts())
		}
	}
}

func TestAbuseFIFODoesNotHang(t *testing.T) {
	p := filepath.Join(t.TempDir(), "auth.log")
	if err := syscall.Mkfifo(p, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	ff, f, _, _ := authFile(t, Config{AuthLog: p})
	done := make(chan struct{})
	go func() {
		ff.step()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		// Unblock the stuck open so the test binary can exit.
		if w, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			w.Close()
		}
		t.Fatal("opening a FIFO at the log path blocked")
	}
	if st := statusOf(t, f, "host:auth"); st.OK || st.Err != "refused: not a regular file" {
		t.Fatalf("status = %+v, want refused: not a regular file", st)
	}
}

func TestAbuseDirectoryRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "auth.log")
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	ff, f, _, _ := authFile(t, Config{AuthLog: p})
	ff.step()
	if st := statusOf(t, f, "host:auth"); st.OK || st.Err != "refused: not a regular file" {
		t.Fatalf("status = %+v, want refused: not a regular file", st)
	}
}

// An enormous line is cut at maxLine, and the rest of it is never handed on as a line of its own:
// it is attacker-controlled text (an sshd user name, a sudo command) that would read like a fresh
// log line.
func TestAbuseEnormousLineIsCut(t *testing.T) {
	p := filepath.Join(t.TempDir(), "auth.log")
	writeFile(t, p, "")
	ff, _, _, s := authFile(t, Config{AuthLog: p})
	ff.step()

	appendFile(t, p, strings.Repeat("x", 20000)+"\nok\n")
	ff.step()
	got := s.texts()
	if len(got) != 2 || got[0] != strings.Repeat("x", maxLine) || got[1] != "ok" {
		t.Fatalf("got %d lines (first %d bytes), want the cut line and \"ok\"", len(got), len(got[0]))
	}

	// No newline at all: emitted cut once, the buffer stays bounded, and the remainder is skipped.
	appendFile(t, p, strings.Repeat("y", 100<<10))
	ff.step()
	appendFile(t, p, strings.Repeat("y", 100<<10)+" Accepted password for root from 203.0.113.9 port 22 ssh2\nz\n")
	ff.step()
	got = s.texts()
	if len(got) != 4 || got[2] != strings.Repeat("y", maxLine) || got[3] != "z" {
		t.Fatalf("got %d lines %q..., want the cut y line then \"z\"", len(got), trunc(got))
	}
	if c := cap(ff.cur.part); c > maxLine {
		t.Fatalf("partial-line buffer grew to %d bytes", c)
	}
}

func trunc(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s[:min(len(s), 40)]
	}
	return out
}
