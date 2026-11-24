package hostlog

import (
	"bytes"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/config"
)

func ptr[T any](v T) *T { return &v }

func TestFromConfigDefaults(t *testing.T) {
	vl := t.TempDir()
	setVarLog(t, vl)
	auth, secure, f2b := filepath.Join(vl, "auth.log"), filepath.Join(vl, "secure"), filepath.Join(vl, "fail2ban.log")

	// No auth log file: the journal is read instead; fail2ban.log is followed even though absent.
	c := FromConfig(config.SecurityLogsHost{}, "/state", nil)
	if c.AuthLog != "" || c.Fail2BanLog != f2b || !c.Journal || c.Poll != time.Second || c.StateDir != "/state" || c.Log == nil {
		t.Fatalf("no auth log: %+v", c)
	}

	writeFile(t, secure, "")
	c = FromConfig(config.SecurityLogsHost{}, "/state", nil)
	if c.AuthLog != secure || c.Journal {
		t.Fatalf("RHEL layout: %+v, want %s and no journal", c, secure)
	}

	writeFile(t, auth, "")
	c = FromConfig(config.SecurityLogsHost{}, "/state", nil)
	if c.AuthLog != auth || c.Journal {
		t.Fatalf("Debian layout: %+v, want %s and no journal", c, auth)
	}

	// Journal set explicitly wins either way.
	if c := FromConfig(config.SecurityLogsHost{Journal: ptr(true)}, "", nil); !c.Journal {
		t.Fatal("journal: true ignored")
	}
	os.Remove(auth)
	os.Remove(secure)
	if c := FromConfig(config.SecurityLogsHost{Journal: ptr(false)}, "", nil); c.Journal || c.AuthLog != "" {
		t.Fatalf("journal: false with no auth log: %+v", c)
	}
}

func TestFromConfigExplicitPaths(t *testing.T) {
	setVarLog(t, t.TempDir())
	c := FromConfig(config.SecurityLogsHost{AuthLog: "/srv/log/auth.log", Fail2BanLog: "/srv/log/f2b.log"}, "", nil)
	if c.AuthLog != "/srv/log/auth.log" || c.Fail2BanLog != "/srv/log/f2b.log" || c.Journal {
		t.Fatalf("%+v", c)
	}
}

func TestFromConfigBadPathsIgnoredWithWarning(t *testing.T) {
	vl := t.TempDir()
	setVarLog(t, vl)
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	c := FromConfig(config.SecurityLogsHost{AuthLog: "var/log/auth.log", Fail2BanLog: "/var/log/../../etc/shadow"}, "", log)
	if c.AuthLog != "" || c.Fail2BanLog != filepath.Join(vl, "fail2ban.log") {
		t.Fatalf("bad paths not ignored: %+v", c)
	}
	if n := strings.Count(buf.String(), "level=WARN"); n != 2 {
		t.Fatalf("want 2 warnings, got:\n%s", buf.String())
	}
}

func TestFromConfigDisabledFollowsNothing(t *testing.T) {
	vl := t.TempDir()
	setVarLog(t, vl)
	writeFile(t, filepath.Join(vl, "auth.log"), "")
	c := FromConfig(config.SecurityLogsHost{Enabled: ptr(false), AuthLog: "/x", Journal: ptr(true)}, "/state", nil)
	if c.AuthLog != "" || c.Fail2BanLog != "" || c.Journal {
		t.Fatalf("disabled host logs still follow something: %+v", c)
	}
	if st := New(c).Status(); len(st) != 0 {
		t.Fatalf("status of a follower of nothing = %+v", st)
	}
}

// An auth log that exists but can't be read (RHEL and Fedora: /var/log/secure is root:root 0600)
// is replaced by the journal when host_logs.journal is unset; the file is then not followed, so
// no event is collected twice. The choice is made once, at start.
func TestFromConfigUnreadableAuthLogUsesTheJournal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-000 file")
	}
	vl := t.TempDir()
	setVarLog(t, vl)
	secure := filepath.Join(vl, "secure")
	writeFile(t, secure, "history\n")
	if err := os.Chmod(secure, 0); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	c := FromConfig(config.SecurityLogsHost{}, t.TempDir(), slog.New(slog.NewTextHandler(&buf, nil)))
	if c.AuthLog != secure || !c.Journal {
		t.Fatalf("unreadable auth log: %+v, want the journal on", c)
	}
	if !strings.Contains(buf.String(), "level=WARN") {
		t.Fatalf("no warning logged:\n%s", buf.String())
	}
	c.Log = quietLog
	f := New(c)
	for _, spec := range f.files {
		if spec.source == SourceAuth {
			t.Fatal("the unreadable auth log is still followed alongside the journal")
		}
	}
	if st := statusOf(t, f, "host:auth"); st.OK || st.Err != authViaJournal {
		t.Fatalf("host:auth = %+v, want Err %q", st, authViaJournal)
	}
	statusOf(t, f, "host:journal")

	// Run never opens the file, even once it is readable: the choice was made at start.
	if err := os.Chmod(secure, 0o644); err != nil {
		t.Fatal(err)
	}
	bin, _ := fakeJournal(t, "exec sleep 30")
	f.journalctl = bin
	f.cfg.Poll = 10 * time.Millisecond
	s := &sink{}
	stop := runFollower(t, f, s.emit)
	appendFile(t, secure, "sshd[1]: Accepted password for root from 203.0.113.9 port 22 ssh2\n")
	time.Sleep(100 * time.Millisecond)
	stop()
	for _, l := range s.lines {
		if l.Source == SourceAuth {
			t.Fatalf("auth log read while the journal replaces it: %+v", l)
		}
	}
	if st := statusOf(t, f, "host:auth"); st.Err != authViaJournal {
		t.Fatalf("host:auth after Run = %+v", st)
	}

	// journal: false means never; journal: true reads both (the file reports why it can't).
	if err := os.Chmod(secure, 0); err != nil {
		t.Fatal(err)
	}
	if c := FromConfig(config.SecurityLogsHost{Journal: ptr(false)}, "", quietLog); c.Journal || c.AuthLog != secure {
		t.Fatalf("journal: false: %+v", c)
	}
	c = FromConfig(config.SecurityLogsHost{Journal: ptr(true)}, "", quietLog)
	f = New(c)
	if len(f.files) == 0 || f.files[0].source != SourceAuth {
		t.Fatalf("journal: true dropped the auth file follower: %+v", f.files)
	}
	if st := statusOf(t, f, "host:auth"); st.Err == authViaJournal {
		t.Fatalf("journal: true: host:auth = %+v", st)
	}
}

// A readable auth log, or one that can't be opened for another reason, keeps the file.
func TestFromConfigReadableOrRefusedAuthLogKeepsTheFile(t *testing.T) {
	vl := t.TempDir()
	setVarLog(t, vl)
	auth := filepath.Join(vl, "auth.log")
	writeFile(t, auth, "")
	if c := FromConfig(config.SecurityLogsHost{}, "", quietLog); c.Journal {
		t.Fatalf("readable auth log: %+v", c)
	}
	os.Remove(auth)
	if err := os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), auth); err != nil {
		t.Fatal(err)
	}
	if c := FromConfig(config.SecurityLogsHost{}, "", quietLog); c.Journal || c.AuthLog != auth {
		t.Fatalf("dangling auth log symlink: %+v, want the file followed (reported as not found)", c)
	}
}

func TestStatusNames(t *testing.T) {
	f := New(Config{AuthLog: "/a", Fail2BanLog: "/b", Journal: true})
	var names []string
	for _, s := range f.Status() {
		names = append(names, s.Name)
		if s.OK || s.Dropped != 0 {
			t.Fatalf("before Run: %+v", s)
		}
	}
	if !slices.Equal(names, []string{"host:auth", "host:fail2ban", "host:journal"}) {
		t.Fatalf("names = %v", names)
	}
}

// Run end to end on real timers: two files followed concurrently, Status read while they run,
// offsets saved on exit.
func TestRunFollowsBothFiles(t *testing.T) {
	dir := t.TempDir()
	auth, f2b := filepath.Join(dir, "auth.log"), filepath.Join(dir, "fail2ban.log")
	writeFile(t, auth, "old\n")
	writeFile(t, f2b, "old\n")
	stateDir := filepath.Join(dir, "state")
	f := New(Config{AuthLog: auth, Fail2BanLog: f2b, StateDir: stateDir, Poll: 10 * time.Millisecond, Log: quietLog})
	s := &sink{}
	stop := runFollower(t, f, s.emit)

	waitOK := func(name string) {
		deadline := time.Now().Add(3 * time.Second)
		for !statusOf(t, f, name).OK {
			if time.Now().After(deadline) {
				t.Fatalf("%s never became OK: %+v", name, f.Status())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitOK("host:auth")
	waitOK("host:fail2ban")
	appendFile(t, auth, "sshd line\n")
	appendFile(t, f2b, "ban line\n")
	got := s.waitFor(2, 3*time.Second)
	stop()
	slices.Sort(got)
	wantLines(t, got, "ban line", "sshd line")
	for _, l := range s.lines {
		if (l.Text == "sshd line") != (l.Source == SourceAuth) {
			t.Fatalf("line %+v has the wrong source", l)
		}
	}
	for _, name := range []string{"auth.offset", "fail2ban.offset"} {
		if _, err := os.Stat(filepath.Join(stateDir, name)); err != nil {
			t.Fatalf("state %s not saved: %v", name, err)
		}
	}
	if st := statusOf(t, f, "host:auth"); st.N != 1 {
		t.Fatalf("auth events = %d, want 1", st.N)
	}
}

// When the journal replaces the auth log, or the auth log the journal, across restarts, the source
// taken up again starts at now: its saved position predates the period the other source collected,
// so resuming from it would collect those events twice. A restart in the same mode resumes.
func TestSwitchBetweenFileAndJournalStartsAtNow(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secure")
	stateDir := filepath.Join(dir, "state")
	writeFile(t, p, "")
	cursorFile := filepath.Join(stateDir, journalStateFile)
	fileMode := Config{AuthLog: p, StateDir: stateDir, Poll: 10 * time.Millisecond, Log: quietLog}
	journalMode := Config{AuthLog: p, Journal: true, authViaJournal: true, StateDir: stateDir, Poll: 10 * time.Millisecond, Log: quietLog}
	entry := func(i int) string {
		return `{"__CURSOR":"s=0a1b;i=` + strconv.Itoa(i) + `","SYSLOG_IDENTIFIER":"sshd","_UID":"0","MESSAGE":"m"}`
	}
	runJournal := func(body string) (argv []string, lines []string) {
		t.Helper()
		bin, jdir := fakeJournal(t, body)
		f := New(journalMode)
		f.journalctl = bin
		s := &sink{}
		stop := runFollower(t, f, s.emit)
		waitRuns(t, jdir, 1)
		got := s.waitFor(strings.Count(body, "__CURSOR"), 5*time.Second)
		stop()
		return runs(t, jdir)[0], got
	}
	runFile := func(appendText string, want ...string) {
		t.Helper()
		f := New(fileMode)
		s := &sink{}
		stop := runFollower(t, f, s.emit)
		deadline := time.Now().Add(3 * time.Second)
		for !statusOf(t, f, "host:auth").OK {
			if time.Now().After(deadline) {
				t.Fatalf("auth log never opened: %+v", f.Status())
			}
			time.Sleep(5 * time.Millisecond)
		}
		if appendText != "" {
			appendFile(t, p, appendText)
		}
		got := s.waitFor(len(want), 3*time.Second)
		time.Sleep(50 * time.Millisecond) // nothing more than want arrives
		got = s.texts()
		stop()
		wantLines(t, got, want...)
	}

	// Journal period: the cursor is saved; a restart in journal mode resumes after it.
	runJournal("printf '%s\\n' '" + entry(1) + "'\nexec sleep 30")
	if argv, _ := runJournal("exec sleep 30"); !slices.Contains(argv, "--after-cursor=s=0a1b;i=1") {
		t.Fatalf("journal → journal: argv %q, want it to resume after the saved cursor", argv)
	}

	// File period: the stale cursor is forgotten, the file is read from now, a restart resumes.
	appendFile(t, p, "written during the journal period\n")
	runFile("f1\n", "f1")
	if _, err := os.Stat(cursorFile); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("journal cursor still saved while the file is followed: %v", err)
	}
	appendFile(t, p, "f2\n") // written while Mooring is down: a same-mode restart reads it
	runFile("", "f2")

	// Journal again: from now, not from the old cursor; the auth offset is forgotten.
	argv, _ := runJournal("exec sleep 30")
	if slices.ContainsFunc(argv, func(a string) bool { return strings.HasPrefix(a, "--after-cursor") }) {
		t.Fatalf("file → journal: argv %q resumes an old cursor", argv)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "auth.offset")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("auth offset still saved while the journal replaces the file: %v", err)
	}

	// File again, after the journal collected what was written meanwhile and auth.log rotated.
	appendFile(t, p, "collected by the journal\n")
	os.Rename(p, p+".1")
	writeFile(t, p, "also collected by the journal\n")
	runFile("f3\n", "f3")
}
