package hostlog

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/parse"
)

// fakeJournal writes an executable stand-in for journalctl that records its argv and environment
// next to itself and then runs body.
func fakeJournal(t *testing.T, body string) (bin, dir string) {
	t.Helper()
	dir = t.TempDir()
	bin = filepath.Join(dir, "journalctl")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" >> '" + dir + "/args'\n" +
		"echo --- >> '" + dir + "/args'\n" +
		"env > '" + dir + "/env.tmp' && mv '" + dir + "/env.tmp' '" + dir + "/env'\n" +
		body + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, dir
}

// runs returns each recorded invocation's argv.
func runs(t *testing.T, dir string) [][]string {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(dir, "args"))
	var out [][]string
	var cur []string
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if l == "---" {
			out = append(out, cur)
			cur = nil
			continue
		}
		if l != "" {
			cur = append(cur, l)
		}
	}
	return out
}

func journalFollower(t *testing.T, bin, stateDir string) *Follower {
	t.Helper()
	if stateDir == "" {
		stateDir = filepath.Join(t.TempDir(), "state")
	}
	f := New(Config{Journal: true, StateDir: stateDir, Poll: 10 * time.Millisecond, Log: quietLog})
	f.journalctl = bin
	return f
}

// sleeps records the durations the journal follower waits and cancels after n of them.
type sleeps struct {
	mu     sync.Mutex
	got    []time.Duration
	n      int
	cancel context.CancelFunc
}

func (s *sleeps) sleep(ctx context.Context, d time.Duration) bool {
	s.mu.Lock()
	s.got = append(s.got, d)
	done := len(s.got) >= s.n
	s.mu.Unlock()
	if done {
		s.cancel()
	}
	return ctx.Err() == nil
}

func (s *sleeps) durations() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.got)
}

const (
	entry1 = `{"__CURSOR":"s=0a1b;i=1;b=77;m=1;t=5e1;x=9f","__REALTIME_TIMESTAMP":"1700000000000000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for root from 203.0.113.9 port 22 ssh2"}`
	// journalctl before systemd 246 spaced its JSON.
	entry2 = `{ "__CURSOR" : "s=0a1b;i=2;b=77;m=2;t=5e2;x=a0", "SYSLOG_IDENTIFIER" : "sudo", "MESSAGE" : "alice : COMMAND=/bin/ls" }`
)

func TestJournalEmitsLinesAndSavesCursor(t *testing.T) {
	bin, dir := fakeJournal(t, "printf '%s\\n' '"+entry1+"' '"+entry2+"'\nexec sleep 30")
	stateDir := filepath.Join(t.TempDir(), "state")
	f := journalFollower(t, bin, stateDir)
	s := &sink{}
	stop := runFollower(t, f, s.emit)
	got := s.waitFor(2, 5*time.Second)
	if st := statusOf(t, f, "host:journal"); !st.OK || st.N != 2 {
		t.Fatalf("status = %+v, want OK with 2 events", st)
	}
	stop() // the fake is still "following": ctx cancel must kill it
	wantLines(t, got, entry1, entry2)
	if s.lines[0].Source != SourceJournal {
		t.Fatalf("source = %q", s.lines[0].Source)
	}

	argv := runs(t, dir)
	want := append([]string{"--follow", "--output=json", "--no-pager", "--lines=0"}, wantIdents...)
	if len(argv) != 1 || !slices.Equal(argv[0], want) {
		t.Fatalf("argv = %q, want %q", argv, want)
	}
	if c := savedCursor(t, stateDir); c != "s=0a1b;i=2;b=77;m=2;t=5e2;x=a0" {
		t.Fatalf("saved cursor = %q", c)
	}

	// The next start resumes after the saved cursor.
	bin2, dir2 := fakeJournal(t, "exec sleep 30")
	f2 := journalFollower(t, bin2, stateDir)
	stop2 := runFollower(t, f2, (&sink{}).emit)
	waitRuns(t, dir2, 1)
	stop2()
	argv = runs(t, dir2)
	if !slices.Contains(argv[0], "--after-cursor=s=0a1b;i=2;b=77;m=2;t=5e2;x=a0") || !slices.Contains(argv[0], "--lines=0") {
		t.Fatalf("argv = %q, want --after-cursor with the saved cursor", argv[0])
	}
}

// wantIdents are the journalctl matches. Matches on one field are ORed, different fields ANDed,
// and "+" starts another OR group: the user/group programs only from uid 0; sshd (OpenSSH 9.8+
// logs as sshd-session, 10 also as sshd-auth), sudo, su and passwd from any uid (parse.Journal
// keeps a non-root sshd line only as a log event).
var wantIdents = []string{
	"SYSLOG_IDENTIFIER=useradd", "SYSLOG_IDENTIFIER=usermod", "SYSLOG_IDENTIFIER=userdel",
	"SYSLOG_IDENTIFIER=groupadd", "SYSLOG_IDENTIFIER=groupmod", "SYSLOG_IDENTIFIER=groupdel",
	"SYSLOG_IDENTIFIER=gpasswd", "SYSLOG_IDENTIFIER=chpasswd", "SYSLOG_IDENTIFIER=chage",
	"_UID=0", "+",
	"SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "SYSLOG_IDENTIFIER=sshd-auth",
	"SYSLOG_IDENTIFIER=sudo", "SYSLOG_IDENTIFIER=su", "SYSLOG_IDENTIFIER=passwd",
}

// The journalctl match and parse.Journal agree: every identifier asked for is one parse.Journal
// turns into an event; the ones asked for only from uid 0 are dropped from any other uid, the rest
// are kept from a user's uid; the user-change programs come out as host.user_change.
func TestJournalArgsMatchTheParser(t *testing.T) {
	args := journalArgs("")
	if len(args) < len(wantIdents) || !slices.Equal(args[len(args)-len(wantIdents):], wantIdents) {
		t.Fatalf("argv = %q, want it to end with %q", args, wantIdents)
	}
	entry := func(ident, uid string) []byte {
		raw, _ := json.Marshal(map[string]string{"SYSLOG_IDENTIFIER": ident, "_UID": uid, "MESSAGE": "delete user 'mallory'"})
		return raw
	}
	rootOnly := true
	for _, a := range args {
		if a == "+" {
			rootOnly = false
			continue
		}
		ident, ok := strings.CutPrefix(a, "SYSLOG_IDENTIFIER=")
		if !ok {
			continue
		}
		e, ok := parse.Journal(entry(ident, "0"))
		if !ok {
			t.Errorf("parse.Journal drops entries of %q, which journalctl is asked for", ident)
			continue
		}
		if _, fromUser := parse.Journal(entry(ident, "1001")); fromUser == rootOnly {
			t.Errorf("%s from uid 1001: parsed = %v, but journalctl asks for it only from uid 0 = %v", ident, fromUser, rootOnly)
		}
		user := !strings.HasPrefix(ident, "sshd") && ident != "sudo" && ident != "su"
		if user != (e.Kind == siem.KindUserChange) {
			t.Errorf("%s: kind %q", ident, e.Kind)
		}
		if strings.HasPrefix(ident, "sshd") {
			forged, _ := json.Marshal(map[string]string{"SYSLOG_IDENTIFIER": ident, "_UID": "1001", "MESSAGE": "Accepted password for root from 6.6.6.6 port 22 ssh2"})
			if e, ok := parse.Journal(forged); !ok || e.Kind != siem.KindLog {
				t.Errorf("%s from uid 1001: ok=%v kind %q, want a log event", ident, ok, e.Kind)
			}
		}
	}
}

func TestJournalMinimalEnvironment(t *testing.T) {
	t.Setenv("MOORING_TEST_SECRET", "hunter2")
	bin, dir := fakeJournal(t, "exec sleep 30")
	f := journalFollower(t, bin, "")
	stop := runFollower(t, f, (&sink{}).emit)
	waitRuns(t, dir, 1)
	stop()
	b, err := os.ReadFile(filepath.Join(dir, "env"))
	if err != nil {
		t.Fatal(err)
	}
	env := string(b)
	if strings.Contains(env, "MOORING_TEST_SECRET") || strings.Contains(env, "hunter2") {
		t.Fatalf("journalctl inherited Mooring's environment:\n%s", env)
	}
	for _, kv := range []string{"LANG=C.UTF-8", "SYSTEMD_COLORS=0", "PATH="} {
		if !strings.Contains(env, kv) {
			t.Fatalf("environment lacks %s:\n%s", kv, env)
		}
	}
}

// A cursor that isn't journald's [a-z0-9;=] shape is never passed on.
func TestAbuseJournalCursorWithMetacharactersDropped(t *testing.T) {
	for _, bad := range []string{
		"s=1;$(touch /tmp/pwned)", "s=1;`id`", "s=1 i=2", "--output=export", "s=1\nSYSLOG_IDENTIFIER=x", "S=ABC", strings.Repeat("a", 600),
	} {
		t.Run("", func(t *testing.T) {
			t.Parallel()
			stateDir := filepath.Join(t.TempDir(), "state")
			writeFile(t, filepath.Join(stateDir, "journal.cursor"), mustJSON(t, journalState{Cursor: bad}))
			bin, dir := fakeJournal(t, "exec sleep 30")
			f := journalFollower(t, bin, stateDir)
			stop := runFollower(t, f, (&sink{}).emit)
			waitRuns(t, dir, 1)
			stop()
			for _, a := range runs(t, dir)[0] {
				if strings.HasPrefix(a, "--after-cursor") || strings.Contains(a, "pwned") || a == "--output=export" {
					t.Fatalf("cursor %q reached argv: %q", bad, runs(t, dir)[0])
				}
			}
		})
	}
}

func TestJournalRestartBackoff(t *testing.T) {
	bin, _ := fakeJournal(t, "echo 'Failed to open journal: boom' >&2\nexit 1")
	f := journalFollower(t, bin, "")
	ctx, cancel := context.WithCancel(context.Background())
	sl := &sleeps{n: 8, cancel: cancel}
	f.sleep = sl.sleep
	f.Run(ctx, (&sink{}).emit)
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, time.Minute, time.Minute}
	if got := sl.durations(); !slices.Equal(got, want) {
		t.Fatalf("backoff = %v, want %v", got, want)
	}
	if st := statusOf(t, f, "host:journal"); st.OK || !strings.Contains(st.Err, "boom") {
		t.Fatalf("status = %+v, want the stderr of the failed run", st)
	}
}

func TestJournalBackoffResetsAfterAHealthyRun(t *testing.T) {
	bin, _ := fakeJournal(t, "exit 0")
	f := journalFollower(t, bin, "")
	f.healthy = 0 // every run counts as one that ran long enough
	ctx, cancel := context.WithCancel(context.Background())
	sl := &sleeps{n: 4, cancel: cancel}
	f.sleep = sl.sleep
	f.Run(ctx, (&sink{}).emit)
	if got := sl.durations(); !slices.Equal(got, []time.Duration{time.Second, time.Second, time.Second, time.Second}) {
		t.Fatalf("backoff = %v, want 1s each time", got)
	}
}

func TestJournalNotFound(t *testing.T) {
	for _, bin := range []string{"mooring-test-no-such-journalctl", filepath.Join(t.TempDir(), "journalctl")} {
		f := journalFollower(t, bin, "")
		ctx, cancel := context.WithCancel(context.Background())
		sl := &sleeps{n: 1, cancel: cancel}
		f.sleep = sl.sleep
		f.Run(ctx, (&sink{}).emit)
		if got := sl.durations(); !slices.Equal(got, []time.Duration{5 * time.Minute}) {
			t.Fatalf("%s: retry = %v, want 5m", bin, got)
		}
		if st := statusOf(t, f, "host:journal"); st.OK || st.Err != "journalctl not found" {
			t.Fatalf("%s: status = %+v", bin, st)
		}
	}
}

func TestJournalBadCursorDroppedAfterRefusal(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	writeFile(t, filepath.Join(stateDir, "journal.cursor"), mustJSON(t, journalState{Cursor: "s=dead;i=1"}))
	bin, dir := fakeJournal(t, "echo 'Failed to seek to cursor: Invalid argument' >&2\nexit 1")
	f := journalFollower(t, bin, stateDir)
	ctx, cancel := context.WithCancel(context.Background())
	sl := &sleeps{n: 2, cancel: cancel}
	f.sleep = sl.sleep
	f.Run(ctx, (&sink{}).emit)
	r := runs(t, dir)
	if len(r) != 2 || !slices.Contains(r[0], "--after-cursor=s=dead;i=1") || slices.ContainsFunc(r[1], func(a string) bool { return strings.HasPrefix(a, "--after-cursor") }) {
		t.Fatalf("runs = %q, want the refused cursor dropped on the retry", r)
	}
}

func TestJournalPermissionHint(t *testing.T) {
	bin, _ := fakeJournal(t, "echo 'Hint: You are currently not seeing messages from other users and the system.' >&2\nexec sleep 30")
	f := journalFollower(t, bin, "")
	stop := runFollower(t, f, (&sink{}).emit)
	deadline := time.Now().Add(5 * time.Second)
	for statusOf(t, f, "host:journal").Err != permHint {
		if time.Now().After(deadline) {
			t.Fatalf("status = %+v, want %q", f.Status(), permHint)
		}
		time.Sleep(5 * time.Millisecond)
	}
	stop()
}

func TestAbuseJournalHugeEntryDropped(t *testing.T) {
	before := `{"__CURSOR":"s=0a1b;i=3","MESSAGE":"before"}`
	huge := `{"__CURSOR":"s=0a1b;i=4","MESSAGE":"` + strings.Repeat("A", 100<<10) + `"}`
	after := `{"__CURSOR":"s=0a1b;i=5","MESSAGE":"after"}`
	bin, dir := fakeJournal(t, "printf '%s\\n' '"+before+"' '"+huge+"' '"+after+"'\nexec sleep 30")
	stateDir := filepath.Join(t.TempDir(), "state")
	f := journalFollower(t, bin, stateDir)
	s := &sink{}
	stop := runFollower(t, f, s.emit)
	got := s.waitFor(2, 5*time.Second)
	stop()
	wantLines(t, got, before, after)

	// A huge last entry still moves the saved position past itself.
	bin, dir = fakeJournal(t, "printf '%s\\n' '"+before+"' '"+huge+"'\nexec sleep 30")
	f = journalFollower(t, bin, stateDir)
	s = &sink{}
	stop = runFollower(t, f, s.emit)
	s.waitFor(1, 5*time.Second)
	waitRuns(t, dir, 1)
	time.Sleep(300 * time.Millisecond) // the huge entry follows "before" on the same pipe
	stop()
	wantLines(t, s.texts(), before)
	if c := savedCursor(t, stateDir); c != "s=0a1b;i=4" {
		t.Fatalf("cursor = %q, want the dropped entry's", c)
	}
}

func TestJournalBacklogIsPaced(t *testing.T) {
	n := linesPerPoll + 5
	bin, _ := fakeJournal(t, fmt.Sprintf("i=0\nwhile [ $i -lt %d ]; do printf '{\"MESSAGE\":\"%%d\"}\\n' $i; i=$((i+1)); done\nexec sleep 30", n))
	f := journalFollower(t, bin, "")
	ck := &clock{t: time.Unix(1_700_000_000, 0)} // frozen: every line lands in one Poll window
	f.now = ck.Now
	sl := &sleeps{n: 1 << 30}
	f.sleep = sl.sleep
	s := &sink{}
	stop := runFollower(t, f, s.emit)
	got := s.waitFor(n, 10*time.Second)
	stop()
	if len(got) != n {
		t.Fatalf("got %d lines, want %d", len(got), n)
	}
	if d := sl.durations(); len(d) != 1 || d[0] != f.cfg.Poll {
		t.Fatalf("pacing waits = %v, want one wait of %v after %d lines", d, f.cfg.Poll, linesPerPoll)
	}
}

func TestCursorOf(t *testing.T) {
	for in, want := range map[string]string{
		`{"__CURSOR":"s=1;i=2","MESSAGE":"x"}`:     "s=1;i=2",
		`{ "__CURSOR" : "s=1;i=2", "MESSAGE":"x"}`: "s=1;i=2",
		`{"MESSAGE":"x","__CURSOR":"s=1;i=2"}`:     "", // __CURSOR comes first in journalctl's output; anywhere else is a forgery
		`{"MESSAGE":"\"__CURSOR\":\"s=9\""}`:       "",
		`{"__CURSOR":"s=1;$(id)"}`:                 "",
		`{"__CURSOR":"s=1\"}`:                      "",
		`{"__CURSOR":"`:                            "",
		`{"__CURSOR":""}`:                          "",
		`not json`:                                 "",
	} {
		got, ok := cursorOf([]byte(in))
		if got != want || ok != (want != "") {
			t.Errorf("cursorOf(%s) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

func waitRuns(t *testing.T, dir string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(runs(t, dir)) < n {
		if time.Now().After(deadline) {
			t.Fatalf("fake journalctl started %d times, want %d", len(runs(t, dir)), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The env file is written right after the argv.
	for _, err := os.Stat(filepath.Join(dir, "env")); err != nil; _, err = os.Stat(filepath.Join(dir, "env")) {
		if time.Now().After(deadline) {
			t.Fatal("fake journalctl wrote no env file")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func savedCursor(t *testing.T, stateDir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(stateDir, "journal.cursor"))
	if err != nil {
		t.Fatal(err)
	}
	var st journalState
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	return st.Cursor
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
