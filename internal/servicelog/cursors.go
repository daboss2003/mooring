package servicelog

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"time"
)

// The cursor file keeps each container's position across Mooring restarts, so output a container
// writes while Mooring is stopped is read on the next start (from its last line, at most
// backfillTail lines).

// cursorState is the cursor file's JSON form (unix nanoseconds).
type cursorState struct {
	V       int                     `json:"v"`
	Cursors map[string]cursorRecord `json:"cursors"`
}

type cursorRecord struct {
	TS   int64 `json:"ts"`   // the Docker timestamp of the container's last line read
	Seen int64 `json:"seen"` // when the container was last in the running set
}

const (
	cursorFileVersion  = 1
	saveEvery          = 10 * time.Second // the cursor file is written at most this often
	cursorRefresh      = time.Hour        // an unchanged file is rewritten this often, keeping its seen times current
	maxCursorFileBytes = 1 << 20
	tailerStopWait     = 2 * time.Second // how long shutdown waits for tailers before the final save
)

// containerIDRe is the shape of a Docker container id; anything else in the file is dropped.
var containerIDRe = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

// SetCursorFile makes the manager keep each container's position in path (written 0600 through a
// temporary file and a rename), loaded when Run starts. Call it before Run; "" (the default) keeps
// positions in memory only.
func (m *Manager) SetCursorFile(path string) {
	m.mu.Lock()
	m.cursorFile = path
	m.mu.Unlock()
}

func (m *Manager) cursorPath() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cursorFile
}

// loadCursors reads the cursor file into the cursor map. An unreadable or malformed file is ignored
// with a warning.
//
// Intentional: every entry that isn't plausible is dropped (not a container id, a line time not
// after 1970 or in the future, a seen time in the future or more than cursorTTL ago), so a hostile or
// stale file can only cost a container the output written while Mooring was down (it gets the
// first-attach rule), never skip new lines or bring back old ones.
func (m *Manager) loadCursors(now time.Time) {
	path := m.cursorPath()
	if path == "" {
		return
	}
	b, err := readCursorFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			m.log.Warn("servicelog: ignoring the log cursor file", "path", path, "err", err)
		}
		return
	}
	var st cursorState
	if err := json.Unmarshal(b, &st); err != nil {
		m.log.Warn("servicelog: ignoring the log cursor file", "path", path, "err", err)
		return
	}
	if st.V != cursorFileVersion {
		m.log.Warn("servicelog: ignoring the log cursor file", "path", path, "err", fmt.Sprintf("unknown version %d", st.V))
		return
	}
	type entry struct {
		id string
		r  cursorRecord
	}
	nowN, minSeen := now.UnixNano(), now.Add(-cursorTTL).UnixNano()
	keep := make([]entry, 0, len(st.Cursors))
	for id, r := range st.Cursors {
		if !containerIDRe.MatchString(id) || r.TS <= 0 || r.TS > nowN || r.Seen > nowN || r.Seen < minSeen {
			continue
		}
		keep = append(keep, entry{id, r})
	}
	if len(keep) > maxCursors {
		sort.Slice(keep, func(i, j int) bool { return keep[i].r.Seen > keep[j].r.Seen })
		keep = keep[:maxCursors]
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.savedTS = make(map[string]int64, len(keep))
	for _, e := range keep {
		c := &cursor{gone: time.Unix(0, e.r.Seen)} // gone until a reconcile finds it running
		c.last.Store(e.r.TS)
		m.cursors[e.id] = c
		m.savedTS[e.id] = e.r.TS
	}
}

func readCursorFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxCursorFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxCursorFileBytes {
		return nil, fmt.Errorf("larger than %d bytes", maxCursorFileBytes)
	}
	return b, nil
}

// saveCursors writes the cursor file: at most every saveEvery and only when a cursor moved or
// appeared (or cursorRefresh passed), unless force (shutdown). Called from Run's goroutine only.
func (m *Manager) saveCursors(now time.Time, force bool) {
	path := m.cursorPath()
	if path == "" {
		return
	}
	if !force && !m.lastSave.IsZero() && now.Sub(m.lastSave) < m.saveInterval {
		return
	}
	st := cursorState{V: cursorFileVersion, Cursors: map[string]cursorRecord{}}
	changed := false
	m.mu.Lock()
	for id, c := range m.cursors {
		ts := c.last.Load()
		if ts == 0 {
			continue
		}
		seen := now
		if !c.gone.IsZero() {
			seen = c.gone
		}
		st.Cursors[id] = cursorRecord{TS: ts, Seen: seen.UnixNano()}
		if m.savedTS[id] != ts {
			changed = true
		}
	}
	m.mu.Unlock()
	if len(st.Cursors) != len(m.savedTS) {
		changed = true
	}
	if !force && !changed && now.Sub(m.lastSave) < cursorRefresh {
		return
	}
	m.lastSave = now
	b, err := json.Marshal(st)
	if err == nil {
		err = m.writeState(path, b)
	}
	if err != nil {
		if !m.saveErrLogged {
			m.saveErrLogged = true
			m.log.Warn("servicelog: cannot write the log cursor file", "path", path, "err", err)
		}
		return
	}
	m.saveErrLogged = false
	m.savedTS = make(map[string]int64, len(st.Cursors))
	for id, r := range st.Cursors {
		m.savedTS[id] = r.TS
	}
}

// writeFileAtomic replaces path with b through a fresh 0600 temporary file and a rename. The
// temporary file is created exclusively, so a symlink planted at its name is never followed.
func writeFileAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}
