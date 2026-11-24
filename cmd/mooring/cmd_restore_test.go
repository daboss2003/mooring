package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/backupsched"
	"github.com/daboss2003/mooring/internal/backupstore"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/s3"
	"github.com/daboss2003/mooring/internal/store"
)

// fakeStateBucket serves List/Get from memory for `restore --from-s3`.
type fakeStateBucket struct {
	objs map[string][]byte
	gets []string
}

func (b *fakeStateBucket) List(ctx context.Context, prefix string) ([]s3.Object, error) {
	var out []s3.Object
	for k, v := range b.objs {
		if strings.HasPrefix(k, prefix) {
			out = append(out, s3.Object{Key: k, Size: int64(len(v))})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key }) // S3 lists in key order
	return out, nil
}

func (b *fakeStateBucket) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	d, ok := b.objs[key]
	if !ok {
		return nil, 0, fmt.Errorf("get %q: %w", key, s3.ErrNotFound)
	}
	b.gets = append(b.gets, key)
	return io.NopCloser(bytes.NewReader(d)), int64(len(d)), nil
}

// restoreS3Host is a host with backups.s3 set, a live mooring.db, and three daily state backups in
// the bucket (names oldest first). Backup i was taken with i earlier ones in the catalog, so the
// number of backups rows in the restored database says which one was restored; the live database
// has 3.
func restoreS3Host(t *testing.T) (cfgPath, dataDir string, b *fakeStateBucket, names []string) {
	t.Helper()
	cfgPath, dataDir = cliHost(t)
	f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(f, "backups:\n  s3:\n    bucket: \"state\"\n    endpoint: \"s3.example.com\"\n    region: \"us-east-1\"\n"+
		"    access_key_id: \"AKIDTEST\"\n    secret_access_key: \"secret-test-key\"\n    prefix: \"pfx/\"\n")
	f.Close()

	db, err := store.Open(filepath.Join(dataDir, "mooring.db"))
	if err != nil {
		t.Fatal(err)
	}
	cat := backupstore.New(db, t.TempDir(), make([]byte, 32)) // cliHost's key
	b = &fakeStateBucket{objs: map[string][]byte{}}
	day := time.Date(2026, 11, 22, 3, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		rec, err := cat.Create(context.Background(), day.AddDate(0, 0, i))
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(cat.FilePath(rec))
		if err != nil {
			t.Fatal(err)
		}
		key := backupsched.StateKey("pfx/", rec)
		b.objs[key] = data
		names = append(names, strings.TrimPrefix(key, "pfx/mooring-state/"))
	}
	// Not a state backup: sorts after them, so picking it would mean the layout filter is gone.
	b.objs["pfx/mooring-state/zz-notes.mbk"] = []byte("operator's file")
	db.Close()

	old := restoreBucketFor
	restoreBucketFor = func(sc *config.BackupS3) (restoreBucket, error) {
		if sc.Bucket != "state" || sc.Prefix != "pfx/" {
			t.Errorf("client for %+v, want backups.s3", sc)
		}
		return b, nil
	}
	t.Cleanup(func() { restoreBucketFor = old })
	return cfgPath, dataDir, b, names
}

func backupRows(t *testing.T, dataDir string) int {
	t.Helper()
	db, err := store.Open(filepath.Join(dataDir, "mooring.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM backups`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// noLeftovers fails when the downloaded archive or the decrypted temp DB was left in the data dir.
func noLeftovers(t *testing.T, dataDir string) {
	t.Helper()
	for _, pat := range []string{"*restore-s3*", "*.restore-tmp*"} {
		if m, _ := filepath.Glob(filepath.Join(dataDir, pat)); len(m) > 0 {
			t.Errorf("left behind: %q", m)
		}
	}
}

// --from-s3 latest downloads the newest state backup of the layout and restores it like --from.
func TestRestoreFromS3Latest(t *testing.T) {
	cfgPath, dataDir, b, names := restoreS3Host(t)
	var out bytes.Buffer
	if err := restoreRun(context.Background(), []string{"--config", cfgPath, "--from-s3", "latest", "--force"}, &out); err != nil {
		t.Fatalf("restore: %v\n%s", err, out.String())
	}
	if n := backupRows(t, dataDir); n != 2 {
		t.Fatalf("restored database has %d backups rows, want 2 (the newest backup)", n)
	}
	if len(b.gets) != 1 || !strings.HasSuffix(b.gets[0], names[2]) {
		t.Errorf("downloaded %q, want only %s", b.gets, names[2])
	}
	if !strings.Contains(out.String(), "s3://state/pfx/mooring-state/"+names[2]) {
		t.Errorf("output doesn't name the object:\n%s", out.String())
	}
	if m, _ := filepath.Glob(filepath.Join(dataDir, "mooring.db.pre-restore-*")); len(m) != 1 {
		t.Errorf("previous database not kept aside: %q", m)
	}
	noLeftovers(t, dataDir)
}

// A name from the list, or a unique start of one, picks that backup; an ambiguous or unknown one
// is refused with the database untouched.
func TestRestoreFromS3ByName(t *testing.T) {
	cfgPath, dataDir, _, names := restoreS3Host(t)
	ctx := context.Background()
	for _, bad := range []string{"2026112", "20261130", "zz-notes.mbk"} {
		err := restoreRun(ctx, []string{"--config", cfgPath, "--from-s3", bad, "--force"}, io.Discard)
		if err == nil {
			t.Fatalf("--from-s3 %s accepted", bad)
		}
		if !strings.Contains(err.Error(), "--from-s3 list") {
			t.Errorf("--from-s3 %s: error doesn't point at the list: %v", bad, err)
		}
		if n := backupRows(t, dataDir); n != 3 {
			t.Fatalf("--from-s3 %s changed the database (%d rows)", bad, n)
		}
	}
	if err := restoreRun(ctx, []string{"--config", cfgPath, "--from-s3", "20261122", "--force"}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if n := backupRows(t, dataDir); n != 0 {
		t.Fatalf("restored %d rows, want 0 (the oldest backup)", n)
	}
	if err := restoreRun(ctx, []string{"--config", cfgPath, "--from-s3", names[1], "--force"}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if n := backupRows(t, dataDir); n != 1 {
		t.Fatalf("restored %d rows, want 1 (the middle backup by its full name)", n)
	}
	noLeftovers(t, dataDir)
}

// --from-s3 list prints the state backups newest first and changes nothing.
func TestRestoreFromS3List(t *testing.T) {
	cfgPath, dataDir, b, names := restoreS3Host(t)
	var out bytes.Buffer
	if err := restoreRun(context.Background(), []string{"--config", cfgPath, "--from-s3", "list"}, &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	i2, i1, i0 := strings.Index(s, names[2]), strings.Index(s, names[1]), strings.Index(s, names[0])
	if i2 < 0 || i1 < 0 || i0 < 0 || !(i2 < i1 && i1 < i0) {
		t.Fatalf("list isn't the three backups newest first:\n%s", s)
	}
	if !strings.Contains(s, names[2]+"  2026-11-24 03:00:00 UTC  ") || !strings.Contains(s, " KiB\n") {
		t.Errorf("list lines aren't name, UTC time, size:\n%s", s)
	}
	if strings.Contains(s, "zz-notes") {
		t.Errorf("listed an object that isn't a state backup:\n%s", s)
	}
	if len(b.gets) != 0 || backupRows(t, dataDir) != 3 {
		t.Errorf("list downloaded %q or changed the database", b.gets)
	}
}

// Without --force the backup is downloaded and checked, then refused; nothing is replaced and the
// download is removed.
func TestRestoreFromS3NeedsForce(t *testing.T) {
	cfgPath, dataDir, _, _ := restoreS3Host(t)
	err := restoreRun(context.Background(), []string{"--config", cfgPath, "--from-s3", "latest"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("restore without --force: %v", err)
	}
	if n := backupRows(t, dataDir); n != 3 {
		t.Fatalf("database replaced without --force (%d rows)", n)
	}
	noLeftovers(t, dataDir)
}

func TestRestoreUsage(t *testing.T) {
	cfgPath, _ := cliHost(t) // no backups.s3
	old := restoreBucketFor
	restoreBucketFor = func(*config.BackupS3) (restoreBucket, error) {
		t.Error("an S3 client was built without backups.s3")
		return nil, fmt.Errorf("no")
	}
	t.Cleanup(func() { restoreBucketFor = old })
	ctx := context.Background()
	for _, args := range [][]string{
		{"--config", cfgPath, "--force"},
		{"--config", cfgPath, "--from", "x.mbk", "--from-s3", "latest", "--force"},
	} {
		if err := restoreRun(ctx, args, io.Discard); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("%q: %v, want a usage error", args, err)
		}
	}
	err := restoreRun(ctx, []string{"--config", cfgPath, "--from-s3", "latest", "--force"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "backups.s3") {
		t.Errorf("--from-s3 without backups.s3: %v", err)
	}
}

// The download and the decrypted copy both land in the data dir: with less than twice the backup's
// size free there, the restore is refused before anything is downloaded.
func TestRestoreFromS3NeedsFreeSpace(t *testing.T) {
	cfgPath, dataDir, b, names := restoreS3Host(t)
	size := int64(len(b.objs["pfx/mooring-state/"+names[2]]))
	old := restoreDiskFree
	restoreDiskFree = func(dir string) (uint64, error) {
		if dir != dataDir {
			t.Errorf("free space checked in %s, want the data dir", dir)
		}
		return uint64(2*size - 1), nil
	}
	t.Cleanup(func() { restoreDiskFree = old })
	err := restoreRun(context.Background(), []string{"--config", cfgPath, "--from-s3", "latest", "--force"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "free") {
		t.Fatalf("restore with too little disk: %v", err)
	}
	if len(b.gets) != 0 || backupRows(t, dataDir) != 3 {
		t.Fatalf("downloaded %q or changed the database", b.gets)
	}
	restoreDiskFree = func(string) (uint64, error) { return uint64(2 * size), nil }
	if err := restoreRun(context.Background(), []string{"--config", cfgPath, "--from-s3", "latest", "--force"}, io.Discard); err != nil {
		t.Fatalf("restore with exactly enough disk: %v", err)
	}
}

func TestHumanSize(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 48230912: "46.0 MiB", 5 << 30: "5.0 GiB"} {
		if got := humanSize(n); got != want {
			t.Errorf("humanSize(%d) = %q, want %q", n, got, want)
		}
	}
}
