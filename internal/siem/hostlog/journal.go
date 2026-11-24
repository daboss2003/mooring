package hostlog

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

const (
	maxJournalLine   = 64 << 10 // a longer journal entry is dropped (cut JSON can't be parsed)
	maxCursor        = 512
	maxStderr        = 4 << 10
	journalStateFile = "journal.cursor"
)

// journalPath is the PATH journalctl runs with; Mooring finds the binary with its own PATH.
const journalPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

var errJournalNotFound = errors.New("journalctl not found")

// journalState is the saved journal position.
type journalState struct {
	Cursor string `json:"cursor"`
}

// journalArgs is journalctl's argv: constants plus a cursor that passed validCursor. Matches on
// one field are ORed, on different fields ANDed, and "+" starts another OR group. SYSLOG_IDENTIFIER
// is the sender's own claim (`logger -t sshd …` sets it), _UID is journald's: the user/group
// programs are root's, so they are taken from uid 0 only. sudo, su and passwd reach journald with
// the invoking user's uid, and sshd (sshd-session from OpenSSH 9.8, also sshd-auth from 10) sends
// its after-login lines with the user's uid, so these are taken from any uid; parse.Journal keeps a
// non-root sshd line only as a log event and applies the same rule.
func journalArgs(cursor string) []string {
	args := []string{"--follow", "--output=json", "--no-pager", "--lines=0"}
	if validCursor(cursor) {
		args = append(args, "--after-cursor="+cursor)
	}
	return append(args,
		"SYSLOG_IDENTIFIER=useradd", "SYSLOG_IDENTIFIER=usermod", "SYSLOG_IDENTIFIER=userdel",
		"SYSLOG_IDENTIFIER=groupadd", "SYSLOG_IDENTIFIER=groupmod", "SYSLOG_IDENTIFIER=groupdel",
		"SYSLOG_IDENTIFIER=gpasswd", "SYSLOG_IDENTIFIER=chpasswd", "SYSLOG_IDENTIFIER=chage",
		"_UID=0", "+",
		"SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "SYSLOG_IDENTIFIER=sshd-auth",
		"SYSLOG_IDENTIFIER=sudo", "SYSLOG_IDENTIFIER=su", "SYSLOG_IDENTIFIER=passwd")
}

// journalEnv is journalctl's whole environment: nothing of Mooring's own is inherited.
func journalEnv() []string {
	return []string{"PATH=" + journalPath, "LANG=C.UTF-8", "SYSTEMD_COLORS=0"}
}

// validCursor reports whether c has the shape of a journald cursor ("s=<hex>;i=<hex>;b=…"):
// lowercase letters, digits, '=' and ';' only.
func validCursor(c string) bool {
	if c == "" || len(c) > maxCursor {
		return false
	}
	for i := 0; i < len(c); i++ {
		if b := c[i]; !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '=' || b == ';') {
			return false
		}
	}
	return true
}

// cursorOf reads an entry's __CURSOR without decoding the whole (possibly large) entry. It must be
// the first key, as journalctl writes it: a "__CURSOR" anywhere else is ignored, so a crafted
// message can't move the saved position.
func cursorOf(b []byte) (string, bool) {
	b = bytes.TrimLeft(b, " \t")
	if len(b) == 0 || b[0] != '{' {
		return "", false
	}
	b = bytes.TrimLeft(b[1:], " \t")
	key := []byte(`"__CURSOR"`)
	if !bytes.HasPrefix(b, key) {
		return "", false
	}
	b = bytes.TrimLeft(b[len(key):], " \t")
	if len(b) == 0 || b[0] != ':' {
		return "", false
	}
	b = bytes.TrimLeft(b[1:], " \t")
	if len(b) == 0 || b[0] != '"' {
		return "", false
	}
	b = b[1:]
	end := bytes.IndexByte(b[:min(len(b), maxCursor+1)], '"')
	if end < 0 {
		return "", false
	}
	if c := string(b[:end]); validCursor(c) {
		return c, true
	}
	return "", false
}

// journal follows journalctl; its methods run on one goroutine.
type journal struct {
	f       *Follower
	line    func(string)
	cursor  string // the last entry handed on
	saved   string
	savedAt time.Time
	winAt   time.Time // pacing window start
	winN    int
}

func (f *Follower) runJournal(ctx context.Context, emit func(Line)) {
	var st journalState
	if f.readState(journalStateFile, &st) && !validCursor(st.Cursor) {
		f.cfg.Log.Warn("security_logs: dropping an invalid saved journal cursor")
		st.Cursor = ""
	}
	j := &journal{f: f, line: f.lineFunc(f.journalSI, SourceJournal, emit), cursor: st.Cursor, saved: st.Cursor}
	defer j.save(true)
	backoff := f.backoffMin
	for ctx.Err() == nil {
		start := f.now()
		err := j.once(ctx)
		if ctx.Err() != nil {
			return
		}
		f.setErr(f.journalSI, err.Error())
		wait := f.missingRetry
		if !errors.Is(err, errJournalNotFound) {
			if f.now().Sub(start) >= f.healthy {
				backoff = f.backoffMin
			}
			wait, backoff = backoff, min(backoff*2, f.backoffMax)
		}
		if !f.sleep(ctx, wait) {
			return
		}
	}
}

// once runs journalctl until it exits or ctx ends; ctx cancel kills it.
func (j *journal) once(ctx context.Context) error {
	f := j.f
	cmd := exec.CommandContext(ctx, f.journalctl, journalArgs(j.cursor)...)
	cmd.Env = journalEnv()
	cmd.WaitDelay = 2 * time.Second
	stderr := &stderrBuf{hint: func() { f.setErr(f.journalSI, permHint) }}
	cmd.Stderr = stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	// Before Start, as a permission hint on stderr may arrive at once. Not logged: a crash loop
	// logs each failure (at most once a minute, the backoff cap), not each restart.
	f.markOK(f.journalSI)
	if err := cmd.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
			return errJournalNotFound
		}
		return err
	}
	// Closing the pipe also ends the read when something else holds journalctl's stdout open.
	stop := context.AfterFunc(ctx, func() { _ = out.Close() })
	n := j.read(ctx, out)
	stop()
	werr := cmd.Wait()
	j.save(true)
	msg := siem.Cut(stderr.String(), 512)
	if n == 0 && j.cursor != "" && strings.Contains(msg, "cursor") {
		// journalctl refused the saved cursor (from another machine, or vacuumed away): follow
		// from now on rather than fail the same way forever.
		f.cfg.Log.Warn("security_logs: journalctl refused the saved cursor; following from now", "stderr", msg)
		j.cursor = ""
		j.save(true)
	}
	if werr == nil {
		werr = errors.New("exited")
	}
	if msg != "" {
		return fmt.Errorf("journalctl: %v: %s", werr, msg)
	}
	return fmt.Errorf("journalctl: %v", werr)
}

// read hands on journalctl's output line by line and returns how many lines it handed on.
func (j *journal) read(ctx context.Context, r io.Reader) int {
	br := bufio.NewReaderSize(r, maxJournalLine)
	n := 0
	for {
		b, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// Intentional: an entry over maxJournalLine is dropped, not cut (cut JSON can't be
			// parsed). Its cursor, at the start, still moves the saved position past it.
			if c, ok := cursorOf(b); ok {
				j.cursor = c
			}
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = br.ReadSlice('\n')
			}
			if err != nil {
				return n
			}
			continue
		}
		if err != nil {
			return n // EOF or the pipe closed; an unterminated last line is a cut entry
		}
		b = bytes.TrimSuffix(bytes.TrimSuffix(b, []byte{'\n'}), []byte{'\r'})
		if c, ok := cursorOf(b); ok {
			j.cursor = c
		}
		if len(b) > 0 {
			j.line(string(b))
			n++
		}
		j.save(false)
		if !j.pace(ctx) {
			return n
		}
	}
}

// pace holds the reader once linesPerPoll lines arrived within one Poll; journalctl then waits on
// the full pipe, so a backlog drains at a rate the pipeline can take.
func (j *journal) pace(ctx context.Context) bool {
	f := j.f
	now := f.now()
	if now.Sub(j.winAt) >= f.cfg.Poll {
		j.winAt, j.winN = now, 0
	}
	if j.winN++; j.winN < linesPerPoll {
		return true
	}
	ok := f.sleep(ctx, f.cfg.Poll-now.Sub(j.winAt))
	j.winAt, j.winN = f.now(), 0
	return ok
}

// save writes the cursor when it changed, at most every persistEvery unless forced.
func (j *journal) save(force bool) {
	if j.cursor == j.saved {
		return
	}
	now := j.f.now()
	if !force && now.Sub(j.savedAt) < j.f.persistEvery {
		return
	}
	j.savedAt = now
	if err := j.f.writeState(journalStateFile, journalState{Cursor: j.cursor}); err != nil {
		j.f.cfg.Log.Warn("security_logs: saving the journal cursor failed", "err", err)
		return
	}
	j.saved = j.cursor
}

// stderrBuf keeps the first maxStderr bytes journalctl writes to stderr and calls hint when
// journalctl says it can only see the service user's own messages (no adm group).
type stderrBuf struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	hint   func()
	hinted bool
}

func (s *stderrBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	if room := maxStderr - s.buf.Len(); room > 0 {
		s.buf.Write(p[:min(len(p), room)])
	}
	fire := !s.hinted && (bytes.Contains(s.buf.Bytes(), []byte("not seeing messages from other users")) ||
		bytes.Contains(s.buf.Bytes(), []byte("insufficient permissions")))
	s.hinted = s.hinted || fire
	s.mu.Unlock()
	if fire {
		s.hint()
	}
	return len(p), nil // never block journalctl on a full buffer
}

// String is the captured stderr on one line.
func (s *stderrBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(strings.Fields(s.buf.String()), " ")
}
