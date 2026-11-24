package backupsched

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/s3"
)

// memBucket is an in-memory S3 bucket (Put/List/Delete) that can be made to fail Put.
type memBucket struct {
	mu      sync.Mutex
	objs    map[string][]byte
	mod     map[string]time.Time
	failPut error
	puts    int
	onPut   func(ctx context.Context) error // when set, Put returns its error (a shutdown, a stall)
}

func newBucket() *memBucket {
	return &memBucket{objs: map[string][]byte{}, mod: map[string]time.Time{}}
}

func (b *memBucket) Put(ctx context.Context, key string, r io.Reader, size int64, ct string) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.puts++
	if b.onPut != nil {
		if err := b.onPut(ctx); err != nil {
			return err
		}
	}
	if b.failPut != nil {
		return b.failPut
	}
	if int64(len(data)) != size {
		return fmt.Errorf("size %d, read %d", size, len(data))
	}
	b.objs[key] = data
	b.mod[key] = time.Now()
	return nil
}

func (b *memBucket) List(ctx context.Context, prefix string) ([]s3.Object, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []s3.Object
	for k, v := range b.objs {
		if strings.HasPrefix(k, prefix) {
			out = append(out, s3.Object{Key: k, Size: int64(len(v)), LastModified: b.mod[k]})
		}
	}
	return out, nil
}

func (b *memBucket) Delete(ctx context.Context, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.objs, key)
	return nil
}

func (b *memBucket) keys() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for k := range b.objs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type alertRec struct {
	mu   sync.Mutex
	msgs []string
}

func (a *alertRec) fn(level, title, detail string) {
	a.mu.Lock()
	a.msgs = append(a.msgs, level+" "+title)
	a.mu.Unlock()
}

func (a *alertRec) n() int { a.mu.Lock(); defer a.mu.Unlock(); return len(a.msgs) }

func stateRunner(t *testing.T, b *memBucket, al *alertRec, clock *time.Time) *StateRunner {
	t.Helper()
	cat, _ := testCatalog(t)
	r := NewState(cat, b, "pfx/", al.fn, nil)
	r.now = func() time.Time { return *clock }
	r.loc = time.UTC // the "server time" of these tests
	return r
}

// A due run makes the restore backup (the encrypted .mbk `mooring restore` takes), uploads exactly
// that file under the layout, and records the S3 copy; nothing else (no key, no config) is uploaded.
func TestStateBackupUploadsTheRestoreArchive(t *testing.T) {
	clock := time.Date(2026, 11, 24, 9, 30, 0, 0, time.UTC)
	b, al := newBucket(), &alertRec{}
	r := stateRunner(t, b, al, &clock)
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	keys := b.keys()
	if len(keys) != 1 || !stateKeyRe.MatchString(strings.TrimPrefix(keys[0], "pfx/")) || !strings.HasPrefix(keys[0], "pfx/mooring-state/20261124T093000Z-") {
		t.Fatalf("uploaded %q", keys)
	}
	recs, _ := r.cat.List(context.Background())
	if len(recs) != 1 || recs[0].Kind != "mooring-state" || recs[0].Location != "local+s3" {
		t.Fatalf("catalog %+v", recs)
	}
	local, err := os.ReadFile(r.cat.FilePath(recs[0]))
	if err != nil {
		t.Fatal(err)
	}
	if string(b.objs[keys[0]]) != string(local) {
		t.Error("the uploaded object is not the local .mbk")
	}
	if StateKey("pfx/", recs[0]) != keys[0] {
		t.Errorf("StateKey = %q, uploaded as %q", StateKey("pfx/", recs[0]), keys[0])
	}
	if al.n() != 0 {
		t.Errorf("alerts on success: %v", al.msgs)
	}
}

// Once a day, at the quiet hour: the first check after 03:00 server time takes the day's backup;
// the first check after Mooring starts takes it when that day's was missed. A restart doesn't add
// one (the catalog says when it last ran).
func TestStateBackupRunsDailyAtTheQuietHour(t *testing.T) {
	clock := time.Date(2026, 11, 24, 14, 0, 0, 0, time.UTC) // first start, in the afternoon
	b, al := newBucket(), &alertRec{}
	r := stateRunner(t, b, al, &clock)
	ctx := context.Background()
	_ = r.Check(ctx)
	if n := len(b.keys()); n != 1 {
		t.Fatalf("the first start (today's backup missed) made %d, want 1", n)
	}
	for _, h := range []int{15, 23} { // later today, then late evening
		clock = time.Date(2026, 11, 24, h, 0, 0, 0, time.UTC)
		_ = r.Check(ctx)
	}
	clock = time.Date(2026, 11, 25, 2, 0, 0, 0, time.UTC) // the next night, before the quiet hour
	_ = r.Check(ctx)
	if n := len(b.keys()); n != 1 {
		t.Fatalf("%d backups before the quiet hour, want 1", n)
	}
	// A restart before 03:00 waits too.
	r2 := NewState(r.cat, b, "pfx/", al.fn, nil)
	r2.now, r2.loc = func() time.Time { return clock }, time.UTC
	_ = r2.Check(ctx)
	if n := len(b.keys()); n != 1 {
		t.Fatalf("a restart made another backup: %d", n)
	}
	clock = time.Date(2026, 11, 25, 3, 0, 0, 0, time.UTC)
	_ = r2.Check(ctx)
	clock = time.Date(2026, 11, 25, 4, 0, 0, 0, time.UTC)
	_ = r2.Check(ctx)
	keys := b.keys()
	if len(keys) != 2 || !strings.Contains(keys[1], "20261125T030000Z") {
		t.Fatalf("want the second backup at 03:00 on the 25th, got %q", keys)
	}
}

// A failed upload alerts once and is retried on the next check with the SAME snapshot (no new
// backup per retry); the retry that works records the S3 copy.
func TestStateBackupRetriesTheSameSnapshot(t *testing.T) {
	clock := time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC)
	b, al := newBucket(), &alertRec{}
	b.failPut = errors.New("503 slow down")
	r := stateRunner(t, b, al, &clock)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := r.Check(ctx); err == nil {
			t.Fatal("a failed upload must return its error")
		}
		clock = clock.Add(time.Hour)
	}
	recs, _ := r.cat.List(ctx)
	if len(recs) != 1 || recs[0].Location != "local" {
		t.Fatalf("retries made new snapshots or recorded a failed upload: %+v", recs)
	}
	if al.n() != 1 {
		t.Fatalf("%d alerts for one outage, want 1: %v", al.n(), al.msgs)
	}
	b.failPut = nil
	if err := r.Check(ctx); err != nil {
		t.Fatal(err)
	}
	recs, _ = r.cat.List(ctx)
	if len(recs) != 1 || recs[0].Location != "local+s3" || len(b.keys()) != 1 {
		t.Fatalf("after recovery: %+v, bucket %q", recs, b.keys())
	}
}

// At most 10 state backups are kept: on the server the newest 10 (manual ones count), and in S3
// the newest 10 objects of the layout; other objects in the bucket are never touched.
func TestStateBackupKeepsTen(t *testing.T) {
	clock := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	b, al := newBucket(), &alertRec{}
	r := stateRunner(t, b, al, &clock)
	ctx := context.Background()
	b.objs["pfx/abc123.mbk"] = []byte("a volume snapshot")             // another backup kind
	b.objs["pfx/mooring-state/notes.txt"] = []byte("operator's file")  // not the layout
	b.objs["other/mooring-state/20200101T000000Z-x.mbk"] = []byte("x") // outside the prefix
	for i := 0; i < 13; i++ {
		if err := r.Check(ctx); err != nil {
			t.Fatal(err)
		}
		clock = clock.Add(25 * time.Hour)
	}
	var state []string
	for _, k := range b.keys() {
		if strings.HasPrefix(k, "pfx/mooring-state/") && strings.HasSuffix(k, ".mbk") {
			state = append(state, k)
		}
	}
	if len(state) != StateKeep {
		t.Fatalf("%d state backups in S3, want %d: %q", len(state), StateKeep, state)
	}
	if state[0] < "pfx/mooring-state/20261104" { // the 3 oldest (Nov 1–3) are gone
		t.Errorf("an old one survived: %q", state[0])
	}
	for _, k := range []string{"pfx/abc123.mbk", "pfx/mooring-state/notes.txt", "other/mooring-state/20200101T000000Z-x.mbk"} {
		if _, ok := b.objs[k]; !ok {
			t.Errorf("deleted %q, which isn't a state backup of this layout", k)
		}
	}
	recs, _ := r.cat.List(ctx)
	if len(recs) != StateKeep {
		t.Fatalf("%d state backups on the server, want %d", len(recs), StateKeep)
	}
	for _, rec := range recs {
		if _, err := os.Stat(r.cat.FilePath(rec)); err != nil {
			t.Errorf("kept record without its file: %v", err)
		}
	}
	// A manual backup counts toward the server's 10: the oldest scheduled one goes.
	oldest := recs[len(recs)-1].ID
	if _, err := r.cat.Create(ctx, clock); err != nil {
		t.Fatal(err)
	}
	r.pruneLocal(ctx)
	recs, _ = r.cat.List(ctx)
	if len(recs) != StateKeep {
		t.Fatalf("%d after a manual backup, want %d", len(recs), StateKeep)
	}
	for _, rec := range recs {
		if rec.ID == oldest {
			t.Error("the oldest wasn't removed to make room for the manual backup")
		}
	}
}

// StateBackups (what `mooring restore --from-s3` lists) returns only keys of the layout under the
// prefix, newest first, with StateName the part after <prefix>mooring-state/.
func TestStateBackupsListsTheLayoutNewestFirst(t *testing.T) {
	b := newBucket()
	for _, k := range []string{
		"pfx/mooring-state/20261122T030000Z-aaaaaaaaaaaaaaaaaaaaaaaa.mbk",
		"pfx/mooring-state/20261124T030000Z-cccccccccccccccccccccccc.mbk",
		"pfx/mooring-state/20261123T030000Z-bbbbbbbbbbbbbbbbbbbbbbbb.mbk",
		"pfx/mooring-state/zz-notes.mbk",                                       // not the layout
		"pfx/mooring-state/20261125T030000Z-dddddddddddddddddddddddd.mbk.part", // not the layout
		"pfx/abc123.mbk",
	} {
		b.objs[k] = []byte("x")
	}
	objs, err := StateBackups(context.Background(), b, "pfx/")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, o := range objs {
		names = append(names, StateName("pfx/", o))
	}
	want := "20261124T030000Z-cccccccccccccccccccccccc.mbk 20261123T030000Z-bbbbbbbbbbbbbbbbbbbbbbbb.mbk 20261122T030000Z-aaaaaaaaaaaaaaaaaaaaaaaa.mbk"
	if strings.Join(names, " ") != want {
		t.Fatalf("got %q\nwant %q", names, want)
	}
}

// After a restore onto a new server the catalog can hold a recent, not-yet-uploaded record whose
// file stayed on the old server. That record is not "pending": a new snapshot is taken and
// uploaded, with no failure alert.
func TestStateBackupSkipsAPendingRecordWithoutItsFile(t *testing.T) {
	clock := time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC)
	b, al := newBucket(), &alertRec{}
	r := stateRunner(t, b, al, &clock)
	ctx := context.Background()
	gone, err := r.cat.Create(ctx, clock.Add(-time.Hour)) // 08:00, after today's 03:00
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(r.cat.FilePath(gone)); err != nil {
		t.Fatal(err)
	}
	if err := r.Check(ctx); err != nil {
		t.Fatalf("Check: %v", err)
	}
	keys := b.keys()
	if len(keys) != 1 || strings.Contains(keys[0], gone.ID) {
		t.Fatalf("uploaded %q; want one new snapshot, not %s", keys, gone.ID)
	}
	if al.n() != 0 {
		t.Errorf("alerted: %v", al.msgs)
	}
}

// Mooring stopping mid-upload (its context cancelled) is not an upload failure: no alert, and the
// backup is uploaded at the next check after the restart.
func TestStateBackupShutdownIsNotAFailure(t *testing.T) {
	clock := time.Date(2026, 11, 24, 3, 0, 0, 0, time.UTC)
	b, al := newBucket(), &alertRec{}
	r := stateRunner(t, b, al, &clock)
	ctx, cancel := context.WithCancel(context.Background())
	b.onPut = func(context.Context) error { cancel(); return context.Canceled }
	if err := r.Check(ctx); err == nil {
		t.Fatal("a cancelled upload must return its error")
	}
	if al.n() != 0 {
		t.Fatalf("alerted on shutdown: %v", al.msgs)
	}
	b.onPut = nil
	r2 := NewState(r.cat, b, "pfx/", al.fn, nil)
	r2.now, r2.loc = func() time.Time { return clock.Add(10 * time.Minute) }, time.UTC
	if err := r2.Check(context.Background()); err != nil || len(b.keys()) != 1 {
		t.Fatalf("after the restart: %v, bucket %q", err, b.keys())
	}
}

// An upload that stops moving is cut off by a deadline (an hour, plus a minute per 64 MiB) so it
// can't hold the hourly check; it counts as a failed upload.
func TestStateBackupUploadHasADeadline(t *testing.T) {
	clock := time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC)
	b, al := newBucket(), &alertRec{}
	r := stateRunner(t, b, al, &clock)
	r.uploadTimeout = func(int64) time.Duration { return 50 * time.Millisecond }
	b.onPut = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	done := make(chan error, 1)
	go func() { done <- r.Check(context.Background()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a stalled upload succeeded")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a stalled upload held the check: no deadline")
	}
	if al.n() != 1 {
		t.Errorf("a timed-out upload must alert like any failure: %d alerts", al.n())
	}
	if got := stateUploadTimeout(0); got != time.Hour {
		t.Errorf("deadline for a small archive = %v, want 1h", got)
	}
	if got := stateUploadTimeout(5 << 30); got != time.Hour+80*time.Minute {
		t.Errorf("deadline for 5 GiB = %v, want 2h20m", got)
	}
}
