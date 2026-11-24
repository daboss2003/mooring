package hostlog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

const (
	maxLine      = 16 << 10 // a longer line is cut here and the rest of it discarded
	readChunk    = 64 << 10
	bytesPerPoll = 8 << 20 // with linesPerPoll, bounds one poll's work (a run of NULs has no lines)
)

// fileState is a followed file's saved position: the file (path + dev/ino) and the offset just
// past the last line handed on.
type fileState struct {
	Path   string `json:"path"`
	Dev    uint64 `json:"dev"`
	Ino    uint64 `json:"ino"`
	Offset int64  `json:"offset"`
}

// fileFollower follows one log file. Its methods run on one goroutine.
type fileFollower struct {
	f       *Follower
	si      int
	path    string
	confine bool   // a default path: the file it resolves to must stay under /var/log
	state   string // the state file ("" = positions not kept)
	line    func(string)
	buf     []byte

	cur        *tail     // the file at path
	prev       *tail     // the file rotated away, still read until prevUntil
	prevUntil  time.Time //
	sawMissing bool      // path was absent before anything was opened: read it from 0 when it appears
	nextOpen   time.Time
	last       fileState // the position in the current file (Path "" until one was opened)
	saved      fileState // what the state file holds
	savedAt    time.Time
}

func (f *Follower) newFile(spec fileSpec, emit func(Line)) *fileFollower {
	ff := &fileFollower{
		f: f, si: spec.si, path: spec.path, line: f.lineFunc(spec.si, spec.source, emit),
		// Intentional: only the built-in default paths are confined to /var/log. They are named by
		// Mooring, not the operator, and /var/log is writable by the syslog group on Debian, so a
		// symlink planted there must not make Mooring read (and archive) a file it can read for
		// other reasons, such as its own keys. A path the operator wrote may point anywhere except
		// /proc, /sys and /dev: the operator owns that choice.
		confine: isDefault(spec.path),
		buf:     make([]byte, readChunk),
	}
	if f.cfg.StateDir != "" {
		ff.state = filepath.Join(f.cfg.StateDir, spec.source+".offset")
	}
	return ff
}

func (ff *fileFollower) run(ctx context.Context) {
	defer ff.close()
	t := time.NewTicker(ff.f.cfg.Poll)
	defer t.Stop()
	for {
		ff.step()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// quota is what one poll may still read.
type quota struct {
	lines int
	bytes int
}

// step is one poll: read the rotated-away file, follow a rotation, (re)open the file, read it.
func (ff *fileFollower) step() {
	now := ff.f.now()
	q := quota{lines: linesPerPoll, bytes: bytesPerPoll}
	if ff.prev != nil {
		err := ff.prev.read(ff.buf, &q, ff.line)
		if err != nil || (ff.prev.eof && !now.Before(ff.prevUntil)) {
			ff.closePrev(&q)
		}
	}
	if ff.cur != nil && ff.rotated() {
		if ff.prev != nil {
			ff.closePrev(&q) // rotated twice within the grace period
		}
		_ = ff.cur.read(ff.buf, &q, ff.line) // the old file is read to its end before the new one
		ff.prev, ff.prevUntil, ff.cur = ff.cur, now.Add(ff.f.grace), nil
		ff.nextOpen = time.Time{}
	}
	if ff.cur == nil && !now.Before(ff.nextOpen) {
		ff.open(now)
	}
	if c := ff.cur; c != nil {
		fi, err := c.f.Stat()
		if err == nil && fi.Size() < c.pos {
			// copytruncate: the file was emptied under the open fd; start it again
			c.flush(ff.line)
			c.pos, c.done = 0, 0
		}
		if err == nil {
			err = c.read(ff.buf, &q, ff.line)
		}
		ff.last.Offset = c.done
		if err != nil {
			// Not flushed: a reopen of the same file resumes at last.Offset and reads it again.
			c.f.Close()
			ff.cur, ff.nextOpen = nil, now.Add(ff.f.retry)
			ff.f.setErr(ff.si, errText(err), "path", ff.path)
		}
	}
	ff.persist(now, false)
}

// rotated reports whether path now names another file than the open one. A missing path is not a
// rotation yet: the old file is read on until a new one appears.
func (ff *fileFollower) rotated() bool {
	fi, err := os.Stat(ff.path)
	if err != nil {
		return false
	}
	dev, ino := devIno(fi)
	return dev != ff.cur.dev || ino != ff.cur.ino
}

// open opens path and picks where to start reading it.
func (ff *fileFollower) open(now time.Time) {
	t, size, err := openLog(ff.path, ff.confine)
	if err != nil {
		if ff.last.Path == "" && errors.Is(err, fs.ErrNotExist) {
			ff.sawMissing = true
		}
		ff.nextOpen = now.Add(ff.f.retry)
		ff.f.setErr(ff.si, errText(err), "path", ff.path)
		return
	}
	ref := ff.last
	if ref.Path == "" {
		var saved fileState
		if ff.state != "" && ff.f.readState(filepath.Base(ff.state), &saved) && saved.Offset >= 0 {
			ref, ff.saved = saved, saved
		}
	}
	var start int64
	switch {
	case ref.Path != ff.path:
		// No position for this path: the first run. Lines already there are history, except in a
		// file that appeared after Mooring started.
		if !ff.sawMissing {
			start = size
		}
	case ref.Dev == t.dev && ref.Ino == t.ino:
		if ref.Offset <= size {
			start = ref.Offset
		}
	default:
		// Another file is at the path: the one we were reading was rotated away (while Mooring was
		// down, or just now). The new one is read from its start.
	}
	t.seek(start)
	ff.cur = t
	ff.last = fileState{Path: ff.path, Dev: t.dev, Ino: t.ino, Offset: t.done}
	ff.f.setOK(ff.si, "path", ff.path)
}

func (ff *fileFollower) closePrev(q *quota) {
	_ = ff.prev.read(ff.buf, q, ff.line)
	ff.prev.flush(ff.line) // nothing else will finish its last line
	ff.prev.f.Close()
	ff.prev = nil
}

// close releases the files and saves the position. The current file's partial last line is not
// handed on: it is read again from the saved offset.
func (ff *fileFollower) close() {
	if ff.prev != nil {
		q := quota{lines: linesPerPoll, bytes: bytesPerPoll}
		ff.closePrev(&q)
	}
	if ff.cur != nil {
		ff.cur.f.Close()
		ff.cur = nil
	}
	ff.persist(ff.f.now(), true)
}

// persist saves the position when it changed, at most every persistEvery unless forced.
func (ff *fileFollower) persist(now time.Time, force bool) {
	if ff.state == "" || ff.last.Path == "" || ff.last == ff.saved {
		return
	}
	if !force && now.Sub(ff.savedAt) < ff.f.persistEvery {
		return
	}
	ff.savedAt = now
	if err := ff.f.writeState(filepath.Base(ff.state), ff.last); err != nil {
		ff.f.cfg.Log.Warn("security_logs: saving the host log offset failed", "path", ff.state, "err", err)
		return
	}
	ff.saved = ff.last
}

// tail is one open log file and the line split state of what was read from it.
type tail struct {
	f        *os.File
	dev, ino uint64
	pos      int64  // bytes consumed
	done     int64  // end of the last complete line (what is saved)
	part     []byte // the partial last line, at most maxLine
	skip     bool   // discarding the rest of a line cut at maxLine
	eof      bool   // the last read reached the end of the file
}

// seek starts reading at off. Starting mid-line (the writer was mid-line when Mooring first read
// the file) skips to the next line rather than hand on the tail of one.
func (t *tail) seek(off int64) {
	t.pos, t.done = off, off
	if off > 0 {
		var b [1]byte
		if n, _ := t.f.ReadAt(b[:], off-1); n == 1 && b[0] != '\n' {
			t.skip = true
		}
	}
}

// read hands on the complete lines from pos up to the end of the file or the quota.
func (t *tail) read(buf []byte, q *quota, line func(string)) error {
	t.eof = false
	for q.lines > 0 && q.bytes > 0 {
		n, err := t.f.ReadAt(buf, t.pos)
		used := t.feed(buf[:n], q, line)
		t.pos += int64(used)
		q.bytes -= used
		if used < n {
			return nil // quota spent mid-chunk; the rest is read again next poll
		}
		if err == io.EOF {
			t.eof = true
			return nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// feed splits b into lines and returns how many bytes it consumed.
func (t *tail) feed(b []byte, q *quota, line func(string)) int {
	used := 0
	for used < len(b) && q.lines > 0 {
		rest := b[used:]
		seg, n := rest, len(rest)
		i := bytes.IndexByte(rest, '\n')
		if i >= 0 {
			seg, n = rest[:i], i+1
		}
		end := t.pos + int64(used+n) // offset just past this segment
		switch {
		case t.skip:
			// Intentional: the rest of a cut line is discarded, never handed on as a line of its
			// own. It is text an attacker can shape (an sshd user name, a sudo command) and would
			// otherwise read like a fresh log line.
			if i >= 0 {
				t.skip, t.done = false, end
			}
		default:
			if len(t.part) == 0 {
				seg = bytes.TrimLeft(seg, "\x00") // the hole a copytruncate leaves when the writer doesn't append
			}
			if room := maxLine - len(t.part); len(seg) > room {
				t.part = append(t.part, seg[:room]...)
				t.emit(line)
				q.lines--
				if i >= 0 {
					t.done = end
				} else {
					// done stays at the cut line's start: a restart cuts it again rather than
					// starting mid-line.
					t.skip = true
				}
			} else if t.part = append(t.part, seg...); i >= 0 {
				t.emit(line)
				q.lines--
				t.done = end
			}
		}
		used += n
	}
	return used
}

// emit hands on the held line (without a trailing '\r'; empty lines are dropped).
func (t *tail) emit(line func(string)) {
	if p := bytes.TrimSuffix(t.part, []byte{'\r'}); len(p) > 0 {
		line(siem.Cut(string(p), maxLine))
	}
	t.part = t.part[:0]
}

// flush hands on a partial last line the file will never finish (it was rotated away or emptied).
func (t *tail) flush(line func(string)) {
	if !t.skip {
		t.emit(line)
	}
	t.part, t.skip = t.part[:0], false
}

// refusedError is a log path Mooring will not read.
type refusedError string

func (e refusedError) Error() string { return "refused: " + string(e) }

// errText is the status text for a failed open.
func errText(err error) string {
	var r refusedError
	switch {
	case errors.As(err, &r):
		return r.Error()
	case errors.Is(err, fs.ErrNotExist):
		return "not found"
	case errors.Is(err, fs.ErrPermission):
		return permHint
	}
	return err.Error()
}

// openLog opens the regular file path names. A symlink at path is followed, but the file it
// resolves to must be a regular file outside /proc, /sys and /dev and, when confine is set, under
// /var/log. The resolved path is opened with O_NOFOLLOW (a symlink swapped in after the check is
// not followed) and O_NONBLOCK (a FIFO can't block the open).
func openLog(path string, confine bool) (*tail, int64, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, 0, refusedError("not an absolute, clean path")
	}
	if pseudoFS(path) {
		return nil, 0, refusedError(path + " is under /proc, /sys or /dev")
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, 0, err
	}
	if pseudoFS(real) {
		return nil, 0, refusedError(fmt.Sprintf("%s resolves to %s, under /proc, /sys or /dev", path, real))
	}
	if confine && !underVarLog(real) {
		return nil, 0, refusedError(fmt.Sprintf("%s resolves to %s, outside %s (set that path in security_logs.host_logs to read it)", path, real, varLog))
	}
	f, err := os.OpenFile(real, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, 0, refusedError("not a regular file")
	}
	dev, ino := devIno(fi)
	return &tail{f: f, dev: dev, ino: ino, part: make([]byte, 0, maxLine)}, fi.Size(), nil
}

func pseudoFS(p string) bool {
	for _, d := range []string{"/proc", "/sys", "/dev"} {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// underVarLog reports whether the resolved path real is inside varLog (itself possibly a symlink).
func underVarLog(real string) bool {
	roots := []string{filepath.Clean(varLog)}
	if r, err := filepath.EvalSymlinks(varLog); err == nil {
		roots = append(roots, r)
	}
	for _, r := range roots {
		if strings.HasPrefix(real, r+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func devIno(fi os.FileInfo) (dev, ino uint64) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev), st.Ino // Dev is int32 on darwin
	}
	return 0, 0
}
