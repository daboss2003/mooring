package archive

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/store"
)

// The archiver against the real store: an hour of events is sealed, uploaded with its seal,
// recorded as archived, staged in the store's temp directory, and verifies.
func TestWithRealStore(t *testing.T) {
	clk := &clock{t: t0.Add(5 * time.Minute)}
	st, err := store.Open(store.Options{Dir: filepath.Join(t.TempDir(), "security-logs"), Box: "web-1",
		HotRetention: 14 * 24 * time.Hour, MaxDiskBytes: 1 << 30, Now: clk.Now})
	if err != nil && strings.Contains(err.Error(), "not implemented") {
		t.Skip("store not implemented yet")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var evs []siem.Event
	for i := 0; i < 5; i++ {
		ev := siem.Event{TS: t0.Add(time.Duration(i) * time.Minute), Src: siem.SrcHost, Kind: siem.KindSSHLogin, Out: siem.OutFailure, IP: "203.0.113.9"}
		ev.Normalize(clk.Now())
		evs = append(evs, ev)
	}
	if err := st.Append(evs); err != nil {
		t.Fatal(err)
	}
	if err := st.Flush(); err != nil {
		t.Fatal(err)
	}
	clk.set(t0.Add(time.Hour + 2*time.Minute)) // the hour is over: SealDue seals it

	l := &callLog{}
	up := newFakeUp(l)
	key := testKey(t)
	a := New(Options{Store: st, Up: up, Key: key, Prefix: "pfx/", Box: "web-1", Retention: 365 * 24 * time.Hour, Now: clk.Now})
	if a.Err() != "" {
		t.Fatal(a.Err())
	}
	a.nextPrune = clk.Now().Add(firstPruneAfter)
	a.step(context.Background())
	if a.Err() != "" || a.Behind() != 0 {
		t.Fatalf("after a step: err=%q behind=%d", a.Err(), a.Behind())
	}
	left, err := st.Unarchived()
	if err != nil || len(left) != 0 {
		t.Fatalf("unarchived after upload = %v, %v", left, err)
	}
	var encs int
	for k := range up.objects {
		if ki, ok := ParseKey("pfx/", k); !ok || ki.Box != "web-1" || !ki.Hour.Equal(t0) {
			t.Errorf("unexpected key %s", k)
		} else if !ki.Seal {
			encs++
		}
	}
	if encs != 1 {
		t.Fatalf("uploaded %d segments, want 1: %v", encs, up.puts)
	}
	if td, ok := any(st).(interface{ TempDir() string }); ok {
		for _, s := range up.tmps {
			if filepath.Dir(s.path) != td.TempDir() {
				t.Errorf("staged in %s, not the store's TempDir %s", s.path, td.TempDir())
			}
		}
	}
	dir := t.TempDir()
	for k, b := range up.objects {
		p := filepath.Join(dir, filepath.FromSlash(k))
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, b, 0o600)
	}
	rep, err := Verify(context.Background(), dir, [][]byte{key})
	if err != nil || rep.ProblemCount != 0 || rep.Verified != 1 {
		t.Fatalf("verify = %+v, %v", rep, err)
	}
}

// With the real store's Boxes, prune removes a renamed server's old objects past the retention.
func TestRealStorePruneRenamedBox(t *testing.T) {
	clk := &clock{t: t0.Add(5 * time.Minute)}
	dir := filepath.Join(t.TempDir(), "security-logs")
	open := func(box string) *store.Store {
		st, err := store.Open(store.Options{Dir: dir, Box: box, HotRetention: 14 * 24 * time.Hour, MaxDiskBytes: 1 << 30, Now: clk.Now, ArchiveConfigured: true})
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	ev := func() []siem.Event {
		e := siem.Event{TS: clk.Now(), Src: siem.SrcHost, Kind: siem.KindSSHLogin}
		e.Normalize(clk.Now())
		return []siem.Event{e}
	}
	st := open("oldname")
	st.Append(ev())
	st.Close()
	clk.add(10 * time.Minute)
	st = open("newname")
	defer st.Close()
	st.Append(ev())
	st.Flush()
	clk.set(t0.Add(time.Hour + 2*time.Minute))
	up := newFakeUp(&callLog{})
	up.now = clk.Now
	a := New(Options{Store: st, Up: up, Key: testKey(t), Prefix: "pfx/", Box: "newname", Retention: 30 * 24 * time.Hour, Now: clk.Now})
	a.nextPrune = clk.Now().Add(time.Hour)
	a.step(context.Background())
	up.mu.Lock()
	n := len(up.objects)
	up.mu.Unlock()
	if n != 4 {
		t.Fatalf("uploaded %d objects, want 4 (two boxes)", n)
	}
	up.objects["pfx/v1/2026/11/22/14/other-host-0001"+SealSuffix] = []byte("{}") // another server's
	up.mod["pfx/v1/2026/11/22/14/other-host-0001"+SealSuffix] = clk.Now()
	clk.add(31 * 24 * time.Hour)
	a.nextPrune = clk.Now()
	a.step(context.Background())
	var left []string
	for k := range up.objects {
		left = append(left, k)
	}
	if len(left) != 1 || !strings.Contains(left[0], "other-host") {
		t.Errorf("left after prune: %v (deleted %v)", left, up.deleted)
	}
}
