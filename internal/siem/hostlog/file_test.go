package hostlog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileFirstRunStartsAtEnd(t *testing.T) {
	p := filepath.Join(t.TempDir(), "auth.log")
	writeFile(t, p, "old 1\nold 2\n")
	ff, f, _, s := authFile(t, Config{AuthLog: p})
	ff.step()
	appendFile(t, p, "new 1\n")
	ff.step()
	wantLines(t, s.texts(), "new 1")
	st := statusOf(t, f, "host:auth")
	if !st.OK || st.Err != "" || st.N != 1 {
		t.Fatalf("status = %+v, want OK with 1 event", st)
	}
	if s.lines[0].Source != SourceAuth || s.lines[0].At.IsZero() {
		t.Fatalf("line = %+v, want Source auth and a read time", s.lines[0])
	}
}

func TestFileResumesFromState(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.log")
	stateDir := filepath.Join(dir, "state")
	writeFile(t, p, "old\n")
	ff, _, _, s := authFile(t, Config{AuthLog: p, StateDir: stateDir})
	ff.step()
	appendFile(t, p, "a\n")
	ff.step()
	ff.close()
	wantLines(t, s.texts(), "a")

	fi, err := os.Stat(filepath.Join(stateDir, "auth.offset"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode = %v, want 0600", fi.Mode().Perm())
	}
	di, _ := os.Stat(stateDir)
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("state dir mode = %v, want 0700", di.Mode().Perm())
	}

	// Lines written while Mooring was down are read on the next start.
	appendFile(t, p, "b\nc\n")
	ff2, _, _, s2 := authFile(t, Config{AuthLog: p, StateDir: stateDir})
	ff2.step()
	wantLines(t, s2.texts(), "b", "c")
}

func TestFileRotatedWhileDownStartsAtZero(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.log")
	stateDir := filepath.Join(dir, "state")
	writeFile(t, p, "old\n")
	ff, _, _, _ := authFile(t, Config{AuthLog: p, StateDir: stateDir})
	ff.step()
	ff.close()

	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, "x\ny\n")
	ff2, _, _, s := authFile(t, Config{AuthLog: p, StateDir: stateDir})
	ff2.step()
	wantLines(t, s.texts(), "x", "y")
}

func TestFileStateForAnotherPathIsIgnored(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	a := filepath.Join(dir, "auth.log")
	writeFile(t, a, "a\n")
	ff, _, _, _ := authFile(t, Config{AuthLog: a, StateDir: stateDir})
	ff.step()
	ff.close()

	// The operator points auth_log at another file: its history is not replayed.
	b := filepath.Join(dir, "secure")
	writeFile(t, b, "history 1\nhistory 2\n")
	ff2, _, _, s := authFile(t, Config{AuthLog: b, StateDir: stateDir})
	ff2.step()
	appendFile(t, b, "fresh\n")
	ff2.step()
	wantLines(t, s.texts(), "fresh")
}

func TestFileRotationRenameAndCreate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "auth.log")
	writeFile(t, p, "")
	ff, _, ck, s := authFile(t, Config{AuthLog: p})
	ff.step()

	// w is the syslog daemon's fd: it keeps writing to the renamed file until it reopens.
	w, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.WriteString("l1\n")
	ff.step()

	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	w.WriteString("l2\n")
	writeFile(t, p, "n1\n")
	ff.step() // sees the new file: drains the old one first
	wantLines(t, s.texts(), "l1", "l2", "n1")
	ck.Add(ff.f.grace / 2)
	ff.step() // nothing new in the old file, but it is kept open within the grace period

	w.WriteString("l3\n")
	w.WriteString("cut-by-rotation")
	ff.step()
	wantLines(t, s.texts(), "l1", "l2", "n1", "l3")

	ck.Add(ff.f.grace)
	ff.step() // grace over: the old file is closed and its partial last line handed on
	if ff.prev != nil {
		t.Fatal("rotated-away file still open after the grace period")
	}
	appendFile(t, p, "n2\n")
	ff.step()
	wantLines(t, s.texts(), "l1", "l2", "n1", "l3", "cut-by-rotation", "n2")
}

func TestFileCopyTruncate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fail2ban.log")
	writeFile(t, p, "a\n")
	ff, _, _, s := authFile(t, Config{AuthLog: p})
	ff.step()
	appendFile(t, p, "b\n")
	ff.step()
	if err := os.Truncate(p, 0); err != nil {
		t.Fatal(err)
	}
	appendFile(t, p, "c\n")
	ff.step()
	wantLines(t, s.texts(), "b", "c")
}

func TestFileMissingThenCreated(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fail2ban.log")
	ff, f, ck, s := authFile(t, Config{AuthLog: p})
	ff.step()
	if st := statusOf(t, f, "host:auth"); st.OK || st.Err != "not found" {
		t.Fatalf("status = %+v, want Err \"not found\"", st)
	}
	writeFile(t, p, "first\nsecond\n")
	ff.step()
	wantLines(t, s.texts()) // not retried before the retry interval
	ck.Add(ff.f.retry)
	ff.step()
	// A file that appeared after Mooring started is read from its start.
	wantLines(t, s.texts(), "first", "second")
	if st := statusOf(t, f, "host:auth"); !st.OK || st.Err != "" {
		t.Fatalf("status = %+v, want OK", st)
	}
}

func TestFilePermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-000 file")
	}
	p := filepath.Join(t.TempDir(), "auth.log")
	writeFile(t, p, "old\n")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	ff, f, ck, s := authFile(t, Config{AuthLog: p})
	ff.step()
	if st := statusOf(t, f, "host:auth"); st.OK || st.Err != permHint {
		t.Fatalf("status = %+v, want Err %q", st, permHint)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	ck.Add(ff.f.retry)
	ff.step()
	if st := statusOf(t, f, "host:auth"); !st.OK {
		t.Fatalf("status = %+v, want OK after the permission is fixed", st)
	}
	appendFile(t, p, "new\n")
	ff.step()
	wantLines(t, s.texts(), "new") // the existing history is not replayed
}

func TestFilePartialLineHeldUntilNewline(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.log")
	writeFile(t, p, "")
	ff, _, _, s := authFile(t, Config{AuthLog: p})
	ff.step()
	appendFile(t, p, "par")
	ff.step()
	wantLines(t, s.texts())
	appendFile(t, p, "tial\nnext")
	ff.step()
	wantLines(t, s.texts(), "partial")
	ff.close()
	// The saved offset covers emitted lines only: "next" is read again on restart.
	if got := readOffset(t, ff); got != int64(len("partial\n")) {
		t.Fatalf("saved offset = %d, want %d", got, len("partial\n"))
	}
}

func TestFileCRLFAndEmptyLines(t *testing.T) {
	p := filepath.Join(t.TempDir(), "auth.log")
	writeFile(t, p, "")
	ff, _, _, s := authFile(t, Config{AuthLog: p})
	ff.step()
	appendFile(t, p, "a\r\nb\r\n\r\n\n\x00\x00\x00c\n")
	ff.step()
	wantLines(t, s.texts(), "a", "b", "c")
}

func TestFileStartMidLineSkipsToNextLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "auth.log")
	writeFile(t, p, "complete\nhalf-writ") // the writer is mid-line when Mooring starts
	ff, _, _, s := authFile(t, Config{AuthLog: p})
	ff.step()
	appendFile(t, p, "ten\nwhole\n")
	ff.step()
	wantLines(t, s.texts(), "whole")
}

func TestFileOffsetPersistence(t *testing.T) {
	p := filepath.Join(t.TempDir(), "auth.log")
	writeFile(t, p, "")
	ff, _, ck, _ := authFile(t, Config{AuthLog: p})
	ff.step()
	if got := readOffset(t, ff); got != 0 {
		t.Fatalf("offset = %d, want 0 (the start is saved at once)", got)
	}
	appendFile(t, p, "a\n")
	ff.step()
	if got := readOffset(t, ff); got != 0 {
		t.Fatalf("offset = %d, want 0 (saved at most every %v)", got, ff.f.persistEvery)
	}
	ck.Add(ff.f.persistEvery)
	ff.step()
	if got := readOffset(t, ff); got != 2 {
		t.Fatalf("offset = %d, want 2", got)
	}
	appendFile(t, p, "b\n")
	ff.step()
	if got := readOffset(t, ff); got != 2 {
		t.Fatalf("offset = %d, want 2 (saved at most every %v)", got, ff.f.persistEvery)
	}
	ck.Add(ff.f.persistEvery)
	ff.step()
	if got := readOffset(t, ff); got != 4 {
		t.Fatalf("offset = %d, want 4", got)
	}
	appendFile(t, p, "c\n")
	ff.step()
	ff.close() // exit saves whatever is pending
	if got := readOffset(t, ff); got != 6 {
		t.Fatalf("offset after close = %d, want 6", got)
	}
	var st fileState
	b, _ := os.ReadFile(ff.state)
	if err := json.Unmarshal(b, &st); err != nil || st.Dev == 0 && st.Ino == 0 || st.Path != p {
		t.Fatalf("state = %s (%v), want path, dev, ino and offset", b, err)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(ff.state), ".*")); len(left) != 0 {
		t.Fatalf("temp files left in the state dir: %v", left)
	}
}

func TestFileBurstIsReadInSteps(t *testing.T) {
	p := filepath.Join(t.TempDir(), "auth.log")
	writeFile(t, p, "")
	ff, _, _, s := authFile(t, Config{AuthLog: p})
	ff.step()
	var b strings.Builder
	for i := range linesPerPoll + 500 {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	appendFile(t, p, b.String())
	ff.step()
	if n := len(s.texts()); n != linesPerPoll {
		t.Fatalf("one poll emitted %d lines, want %d", n, linesPerPoll)
	}
	ff.step()
	got := s.texts()
	if len(got) != linesPerPoll+500 || got[len(got)-1] != fmt.Sprintf("line %d", linesPerPoll+499) {
		t.Fatalf("after two polls: %d lines, last %q", len(got), got[len(got)-1])
	}
}

func readOffset(t *testing.T, ff *fileFollower) int64 {
	t.Helper()
	b, err := os.ReadFile(ff.state)
	if err != nil {
		t.Fatal(err)
	}
	var st fileState
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	return st.Offset
}
