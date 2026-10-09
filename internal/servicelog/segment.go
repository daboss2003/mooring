package servicelog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// A segment is one append-only JSONL file of a service's lines, in capture order. The open (newest)
// segment is named <seq>_<first>.jsonl; when it is closed it is renamed to
// <seq>_<first>_<last>_<lines>.jsonl, so a restart knows every closed segment's time range and line
// count without reading it. seq orders a service's segments; first/last are unix seconds.
type segment struct {
	name        string
	seq         uint64
	first, last int64
	lines       int
	bytes       int64
	open        bool
}

var segNameRe = regexp.MustCompile(`^([0-9]{1,19})_([0-9]{1,19})(?:_([0-9]{1,19})_([0-9]{1,19}))?\.jsonl$`)

// parseSegmentName parses a segment file name; ok=false for anything else.
func parseSegmentName(name string) (segment, bool) {
	m := segNameRe.FindStringSubmatch(name)
	if m == nil {
		return segment{}, false
	}
	seq, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		return segment{}, false
	}
	first, err := strconv.ParseInt(m[2], 10, 64)
	if err != nil {
		return segment{}, false
	}
	g := segment{name: name, seq: seq, first: first, last: first, open: m[3] == ""}
	if !g.open {
		last, err1 := strconv.ParseInt(m[3], 10, 64)
		lines, err2 := strconv.ParseInt(m[4], 10, 64)
		if err1 != nil || err2 != nil || last < first || lines > 1<<40 {
			return segment{}, false
		}
		g.last, g.lines = last, int(lines)
	}
	return g, true
}

func (g segment) fileName() string {
	if g.open {
		return fmt.Sprintf("%010d_%d.jsonl", g.seq, g.first)
	}
	return fmt.Sprintf("%010d_%d_%d_%d.jsonl", g.seq, g.first, g.last, g.lines)
}

// diskLine is a Line as stored in a segment (the app and service are the directory names).
type diskLine struct {
	At   int64  `json:"at"`
	Copy string `json:"copy,omitempty"`
	Text string `json:"text"`
}

const (
	backChunk      = 64 << 10
	maxPartialLine = 1 << 20 // a "line" longer than this (a corrupt file) is dropped while reading
)

// eachLineBackward calls fn with each non-empty '\n'-separated line in the first size bytes of r,
// last line first, reading chunk bytes at a time from the end. It stops when fn returns false. The
// slice passed to fn is only valid during the call.
func eachLineBackward(r io.ReaderAt, size int64, chunk int, fn func([]byte) bool) error {
	if chunk <= 0 {
		chunk = backChunk
	}
	buf := make([]byte, chunk)
	var carry []byte // the end part of a line whose start is further back in the file
	for pos := size; pos > 0; {
		n := int64(chunk)
		if n > pos {
			n = pos
		}
		pos -= n
		b := buf[:n]
		if got, err := r.ReadAt(b, pos); int64(got) < n {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return err
		}
		end := len(b)
		for i := len(b) - 1; i >= 0; i-- {
			if b[i] != '\n' {
				continue
			}
			line := b[i+1 : end]
			if len(carry) > 0 {
				line = append(append(make([]byte, 0, len(line)+len(carry)), line...), carry...)
				carry = nil
			}
			if len(line) > 0 && !fn(line) {
				return nil
			}
			end = i
		}
		if end > 0 {
			if len(carry)+end > maxPartialLine {
				carry = nil
			} else {
				carry = append(append(make([]byte, 0, end+len(carry)), b[:end]...), carry...)
			}
		}
	}
	if len(carry) > 0 {
		fn(carry)
	}
	return nil
}

// openSegment opens a segment file for reading, refusing a symlink.
func openSegment(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
}

// scanSegment reads an open segment left by a previous run (whose name doesn't record its line count
// or last time): it counts the lines that decode and returns the newest line's time.
func scanSegment(path string) (lines int, last int64, size int64, err error) {
	f, err := openSegment(path)
	if err != nil {
		return 0, 0, 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return 0, 0, 0, fmt.Errorf("not a regular file")
	}
	size = fi.Size()
	err = eachLineBackward(f, size, 0, func(b []byte) bool {
		var d diskLine
		if json.Unmarshal(b, &d) == nil {
			if lines == 0 {
				last = d.At
			}
			lines++
		}
		return true
	})
	return lines, last, size, err
}

// loadSegments indexes a service directory: regular files with a segment name only (symlinks and
// anything else are ignored). Segments a previous run left open are scanned and closed, so new lines
// always start a fresh segment and never append after a torn last line. Caller owns sl.
func (s *Store) loadSegments(sl *svcLog) {
	ents, err := os.ReadDir(sl.dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		g, ok := parseSegmentName(e.Name())
		if !ok {
			continue
		}
		path := filepath.Join(sl.dir, g.name)
		if g.open {
			lines, last, size, err := scanSegment(path)
			if err != nil {
				continue
			}
			if lines == 0 {
				_ = os.Remove(path)
				continue
			}
			if last < g.first {
				last = g.first
			}
			g.lines, g.last, g.bytes = lines, last, size
			g.open = false
			if os.Rename(path, filepath.Join(sl.dir, g.fileName())) == nil {
				g.name = g.fileName()
			}
		} else {
			fi, err := e.Info()
			if err != nil {
				continue
			}
			if fi.Size() == 0 {
				_ = os.Remove(path)
				continue
			}
			g.bytes = fi.Size()
		}
		sl.segs = append(sl.segs, g)
	}
	sort.Slice(sl.segs, func(i, j int) bool { return sl.segs[i].seq < sl.segs[j].seq })
	for _, g := range sl.segs {
		if g.seq >= sl.nextSeq {
			sl.nextSeq = g.seq + 1
		}
		if g.last > sl.lastAt {
			sl.lastAt = g.last
		}
	}
	sl.seedCopies(s.copySeedLines)
}

// seedCopies fills the replica list from the newest segment's last n lines. Caller owns sl.
func (sl *svcLog) seedCopies(n int) {
	if len(sl.segs) == 0 {
		return
	}
	f, err := openSegment(filepath.Join(sl.dir, sl.segs[len(sl.segs)-1].name))
	if err != nil {
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return
	}
	seen := 0
	_ = eachLineBackward(f, fi.Size(), 0, func(b []byte) bool {
		var d diskLine
		if json.Unmarshal(b, &d) == nil && d.Copy != "" {
			if _, ok := sl.copies[d.Copy]; !ok {
				sl.noteCopy(d.Copy, d.At)
			}
		}
		seen++
		return seen < n
	})
}

// active returns the open segment, if any. Caller holds sl.mu.
func (sl *svcLog) active() *segment {
	if n := len(sl.segs); n > 0 && sl.segs[n-1].open {
		return &sl.segs[n-1]
	}
	return nil
}

// closeActiveLocked closes the open segment: renamed to record its time range and line count, or
// removed when nothing reached it. Caller holds sl.mu.
func (sl *svcLog) closeActiveLocked() {
	a := sl.active()
	if a == nil {
		return
	}
	oldPath := filepath.Join(sl.dir, a.name)
	if a.lines == 0 {
		_ = os.Remove(oldPath)
		sl.segs = sl.segs[:len(sl.segs)-1]
		return
	}
	a.open = false
	if os.Rename(oldPath, filepath.Join(sl.dir, a.fileName())) == nil {
		a.name = a.fileName()
	}
}

// writePendingLocked appends the buffered lines to the service's open segment, starting a new
// segment whenever the current one is full by size, line count or age. Caller holds sl.mu.
func (s *Store) writePendingLocked(sl *svcLog) {
	if len(sl.pending) == 0 {
		return
	}
	pending := sl.pending
	// Intentional: the buffer is released before the write, so a disk that refuses writes drops
	// lines instead of growing memory without bound.
	sl.pending, sl.pendingBytes = nil, 0
	pol := s.segPolicy(sl)
	now := s.now().Unix()
	for len(pending) > 0 {
		if a := sl.active(); a != nil && (a.bytes >= s.segMaxBytes || a.lines >= pol.segmentLines() || now-a.first >= int64(pol.segmentAge()/time.Second)) {
			sl.closeActiveLocked()
		}
		a := sl.active()
		if a == nil {
			if err := os.MkdirAll(sl.dir, 0o700); err != nil {
				s.writeFailed(sl, err)
				return
			}
			sl.segs = append(sl.segs, segment{seq: sl.nextSeq, first: pending[0].At, last: pending[0].At, open: true})
			sl.nextSeq++
			a = &sl.segs[len(sl.segs)-1]
			a.name = a.fileName()
		}
		n := pol.segmentLines() - a.lines
		if n < 1 {
			n = 1
		}
		if n > len(pending) {
			n = len(pending)
		}
		batch := pending[:n]
		pending = pending[n:]

		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		for _, l := range batch {
			_ = enc.Encode(diskLine{At: l.At, Copy: l.Copy, Text: l.Text})
		}
		f, err := os.OpenFile(filepath.Join(sl.dir, a.name), os.O_WRONLY|os.O_APPEND|os.O_CREATE|oNoFollow, 0o600)
		if err != nil {
			if a.lines == 0 {
				sl.segs = sl.segs[:len(sl.segs)-1] // nothing was created
			}
			s.writeFailed(sl, err)
			return
		}
		w, werr := f.Write(buf.Bytes())
		cerr := f.Close()
		a.bytes += int64(w)
		if werr != nil || cerr != nil {
			// The file may now end in a torn line: count what fully reached it and close the segment
			// so later lines start a clean one.
			a.lines += bytes.Count(buf.Bytes()[:w], []byte{'\n'})
			if a.lines > 0 {
				a.last = batch[len(batch)-1].At
			}
			sl.closeActiveLocked()
			if werr == nil {
				werr = cerr
			}
			s.writeFailed(sl, werr)
			return
		}
		a.lines += len(batch)
		a.last = batch[len(batch)-1].At
	}
	sl.writeErrLogged = false
}

// writeFailed logs a failed write once until a later write succeeds. Caller holds sl.mu.
func (s *Store) writeFailed(sl *svcLog, err error) {
	if !sl.writeErrLogged {
		sl.writeErrLogged = true
		s.log.Warn("servicelog: cannot write captured lines; dropping them", "app", sl.app, "service", sl.svc, "err", err)
	}
}

// pruneLocked removes whole segments older than pol.Retain, then the oldest segments while the rest
// still hold at least pol.MaxLines lines. Caller holds sl.mu.
func (s *Store) pruneLocked(sl *svcLog, pol Policy, now int64) {
	cut := now - pol.retainSecs()
	keep := sl.segs[:0]
	for _, g := range sl.segs {
		if g.last < cut && sl.removeSegment(g) {
			continue
		}
		keep = append(keep, g)
	}
	sl.segs = keep
	total := 0
	for _, g := range sl.segs {
		total += g.lines
	}
	for len(sl.segs) > 0 && total-sl.segs[0].lines >= pol.MaxLines {
		if !sl.removeSegment(sl.segs[0]) {
			break
		}
		total -= sl.segs[0].lines
		sl.segs = sl.segs[1:]
	}
}

// removeSegment deletes a segment's file; false if it is still there. Caller holds sl.mu.
func (sl *svcLog) removeSegment(g segment) bool {
	err := os.Remove(filepath.Join(sl.dir, g.name))
	return err == nil || os.IsNotExist(err)
}
