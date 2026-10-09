package servicelog

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
)

// importLegacy moves the pre-segment single-file store (every service's lines in one JSONL file,
// 48h TTL) into the segment layout once, then removes it. Lines past the old TTL, with an invalid
// name, or not newer than what a service already holds (a re-run after a crash) are skipped.
func (s *Store) importLegacy(path string) {
	defer func() {
		// Intentional: removed even after a partial import. It holds at most 48h of output that may
		// contain secrets; keeping it for a retry could leave it on disk indefinitely.
		_ = os.Remove(path)
		_ = os.Remove(path + ".tmp")
	}()
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return
	}
	cut := s.now().Unix() - DefaultPolicy.retainSecs()
	groups := map[string][]Line{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var l Line
		if json.Unmarshal(sc.Bytes(), &l) != nil || l.At < cut || !validName(l.App) || !validName(l.Svc) {
			continue
		}
		if len(l.Text) > maxLineBytes {
			l.Text = l.Text[:maxLineBytes] + "…"
		}
		k := key(l.App, l.Svc)
		groups[k] = append(groups[k], l)
	}
	_ = f.Close()

	imported := 0
	for _, lines := range groups {
		sort.SliceStable(lines, func(i, j int) bool { return lines[i].At < lines[j].At })
		sl := s.service(lines[0].App, lines[0].Svc, true)
		if sl == nil {
			continue
		}
		sl.mu.Lock()
		held := sl.lastAt
		for _, l := range lines {
			if l.At <= held {
				continue
			}
			sl.append(Line{At: l.At, Copy: l.Copy, Text: l.Text})
			imported++
			if sl.pendingBytes >= pendingFlushBytes {
				s.writePendingLocked(sl)
			}
		}
		s.writePendingLocked(sl)
		sl.mu.Unlock()
	}
	if imported > 0 {
		s.log.Info("servicelog: imported captured lines from the previous single-file store", "lines", imported)
	}
}
