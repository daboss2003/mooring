package backupsched

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/backupstore"
	"github.com/daboss2003/mooring/internal/store"
)

// fakeRunner answers `volume ls` with a fixed volume and any `run … tar` with fake bytes.
type fakeRunner struct {
	volumes string
	tar     []byte
	runs    int
}

func (f *fakeRunner) RunStreamHeld(ctx context.Context, argv []string, stdout io.Writer, onErr func(string)) error {
	if len(argv) > 0 && argv[0] == "volume" {
		_, _ = io.WriteString(stdout, f.volumes)
		return nil
	}
	f.runs++
	_, _ = stdout.Write(f.tar)
	return nil
}

type fakeSem struct{}

func (fakeSem) TryAcquire() bool { return true }
func (fakeSem) Release()         {}

type fakeUploader struct {
	mu   sync.Mutex
	keys []string
}

func (u *fakeUploader) Put(ctx context.Context, key string, r io.Reader, size int64, ct string) error {
	_, _ = io.Copy(io.Discard, r)
	u.mu.Lock()
	u.keys = append(u.keys, key)
	u.mu.Unlock()
	return nil
}
func (u *fakeUploader) Delete(ctx context.Context, key string) error { return nil }

func testCatalog(t *testing.T) (*backupstore.Store, string) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	dir := t.TempDir()
	key := make([]byte, 32)
	return backupstore.New(db, dir, key), dir
}

func TestBackupAllProducesCatalogsAndInventories(t *testing.T) {
	cat, dir := testCatalog(t)
	run := &fakeRunner{volumes: "shop_data\n", tar: []byte("fake-volume-tar-contents")}
	cfg := Config{Interval: time.Hour, Retention: 2, HelperImage: "busybox", Key: make([]byte, 32), EnvFileDir: dir}
	r := New(run, fakeSem{}, cat, func() []string { return []string{"shop"} }, nil, cfg, nil, nil)

	r.BackupAll(context.Background())

	recs, err := cat.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("want 1 backup, got %d", len(recs))
	}
	got := recs[0]
	if got.Kind != "volume" || got.Project != "shop" || got.Target != "shop_data" || got.Location != "local" {
		t.Fatalf("unexpected record %+v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, got.ID+".mbk")); err != nil {
		t.Errorf(".mbk file missing: %v", err)
	}
	// The volume is now in backup_inventory (feeds PruneVolumeSafe).
	vols, _ := cat.BackedUpVolumes(context.Background())
	if !vols["shop_data"] {
		t.Errorf("backup_inventory should record shop_data, got %v", vols)
	}
}

func TestRetentionKeepsN(t *testing.T) {
	cat, dir := testCatalog(t)
	run := &fakeRunner{volumes: "v1\n", tar: []byte("x")}
	cfg := Config{Interval: time.Hour, Retention: 2, HelperImage: "b", Key: make([]byte, 32), EnvFileDir: dir}
	r := New(run, fakeSem{}, cat, func() []string { return []string{"shop"} }, nil, cfg, nil, nil)
	for i := 0; i < 5; i++ {
		r.BackupAll(context.Background())
	}
	recs, _ := cat.List(context.Background())
	if len(recs) != 2 {
		t.Fatalf("retention=2 should keep 2, got %d", len(recs))
	}
}

func TestS3UploadMarksLocationAndUploads(t *testing.T) {
	cat, dir := testCatalog(t)
	run := &fakeRunner{volumes: "v1\n", tar: []byte("x")}
	up := &fakeUploader{}
	cfg := Config{Interval: time.Hour, Retention: 3, HelperImage: "b", Key: make([]byte, 32), EnvFileDir: dir, S3Prefix: "mooring/"}
	r := New(run, fakeSem{}, cat, func() []string { return []string{"shop"} }, up, cfg, nil, nil)
	r.BackupAll(context.Background())

	recs, _ := cat.List(context.Background())
	if len(recs) != 1 || recs[0].Location != "local+s3" {
		t.Fatalf("want one local+s3 record, got %+v", recs)
	}
	if len(up.keys) != 1 || !strings.HasPrefix(up.keys[0], "mooring/") || !strings.HasSuffix(up.keys[0], ".mbk") {
		t.Fatalf("expected one prefixed .mbk upload, got %v", up.keys)
	}
}

// A busy semaphore (a deploy holds the docker slot) → the cycle is skipped, not queued.
func TestBusySemaphoreSkips(t *testing.T) {
	cat, dir := testCatalog(t)
	run := &fakeRunner{volumes: "v1\n", tar: []byte("x")}
	cfg := Config{Interval: time.Hour, Retention: 2, HelperImage: "b", Key: make([]byte, 32), EnvFileDir: dir}
	busy := busySem{}
	r := New(run, busy, cat, func() []string { return []string{"shop"} }, nil, cfg, nil, nil)
	r.BackupAll(context.Background())
	if recs, _ := cat.List(context.Background()); len(recs) != 0 {
		t.Fatalf("a busy docker slot must skip the backup, got %d records", len(recs))
	}
}

type busySem struct{}

func (busySem) TryAcquire() bool { return false }
func (busySem) Release()         {}
