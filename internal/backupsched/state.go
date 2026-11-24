package backupsched

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/backupstore"
	"github.com/daboss2003/mooring/internal/s3"
)

// The daily Mooring-state backup (docs/backup-and-recovery.md "Daily copies in S3"): when an S3
// destination is set, the backup `mooring restore` takes (the encrypted .mbk of Mooring's database,
// the same file the Backups page's "Back up now" makes) is uploaded once a day, and at most
// StateKeep of them are kept, on the server and in the bucket each. Only that encrypted file is
// uploaded: the encryption key never leaves the server, and restoring needs it.
const (
	StateKeep  = 10        // state backups kept on the server and in S3 (each)
	StateHour  = 3         // the daily backup is taken at the first check after 03:00 server time
	stateCheck = time.Hour // how often the runner checks whether one is due (and retries)
	StateDir   = "mooring-state/"
)

// stateKeyRe is a state backup's object key below the prefix. Only keys of exactly this layout are
// ever deleted.
var stateKeyRe = regexp.MustCompile(`^mooring-state/[0-9]{8}T[0-9]{6}Z-[a-f0-9]{24}\.mbk$`)

// StateLister lists a bucket (*s3.Client).
type StateLister interface {
	List(ctx context.Context, prefix string) ([]s3.Object, error)
}

// StateUploader is the S3 subset the state backup needs (*s3.Client).
type StateUploader interface {
	StateLister
	Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error
	Delete(ctx context.Context, key string) error
}

// StateBackups lists the state backups in the bucket under prefix, newest first. Only keys of the
// state layout count; anything else under <prefix>mooring-state/ is left out.
func StateBackups(ctx context.Context, l StateLister, prefix string) ([]s3.Object, error) {
	objs, err := l.List(ctx, prefix+StateDir)
	if err != nil {
		return nil, err
	}
	var out []s3.Object
	for _, o := range objs {
		if rest, ok := strings.CutPrefix(o.Key, prefix); ok && stateKeyRe.MatchString(rest) {
			out = append(out, o)
		}
	}
	// Intentional: newest first by key — the key starts with the backup's UTC time.
	sort.Slice(out, func(i, j int) bool { return out[i].Key > out[j].Key })
	return out, nil
}

// StateName is a state backup's name: its key without <prefix>mooring-state/.
func StateName(prefix string, o s3.Object) string {
	return strings.TrimPrefix(o.Key, prefix+StateDir)
}

// StateRunner uploads the daily Mooring-state backup and keeps StateKeep of them.
type StateRunner struct {
	cat     *backupstore.Store
	up      StateUploader
	prefix  string
	alert   func(level, title, detail string) // nil = log only
	log     *slog.Logger
	now     func() time.Time
	loc     *time.Location // the server's time zone (StateHour is in it)
	failing bool           // the last upload failed (alerted once per outage)

	uploadTimeout func(size int64) time.Duration
}

// stateUploadTimeout bounds one upload so a connection that stops moving can't hold the hourly
// check: an hour, plus a minute per 64 MiB (about 1 MiB/s at the slowest it lets finish).
func stateUploadTimeout(size int64) time.Duration {
	return time.Hour + time.Duration(size/(64<<20))*time.Minute
}

// NewState builds a StateRunner uploading to up under prefix ("" or ending in '/').
func NewState(cat *backupstore.Store, up StateUploader, prefix string, alert func(level, title, detail string), log *slog.Logger) *StateRunner {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &StateRunner{cat: cat, up: up, prefix: prefix, alert: alert, log: log, now: time.Now, loc: time.Local, uploadTimeout: stateUploadTimeout}
}

// StateKey is the object key of a state backup: <prefix>mooring-state/<UTC time>-<id>.mbk.
func StateKey(prefix string, rec backupstore.Record) string {
	return prefix + StateDir + time.Unix(rec.CreatedAt, 0).UTC().Format("20060102T150405Z") + "-" + rec.ID + ".mbk"
}

// Run checks a few minutes after boot, then every hour, until ctx ends.
func (r *StateRunner) Run(ctx context.Context) {
	select {
	case <-time.After(5 * time.Minute):
	case <-ctx.Done():
		return
	}
	for {
		_ = r.Check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(stateCheck):
		}
	}
}

// Check uploads a state backup when none was uploaded since the last StateHour o'clock server time
// (judged from the backup catalog, so a restart doesn't add one), then keeps StateKeep on the server
// and in S3. The day's backup is therefore taken at the first check after StateHour, a quiet hour,
// or at the first check after Mooring starts when that day's was missed. A failed upload is retried
// at the next check with the same snapshot rather than a new one, and alerts once per outage.
func (r *StateRunner) Check(ctx context.Context) error {
	if !r.cat.Available() {
		return nil
	}
	recs, err := r.cat.List(ctx)
	if err != nil {
		return err
	}
	now := r.now()
	since := r.lastQuietHour(now).Unix()
	var pending *backupstore.Record // the newest state backup taken since then, not uploaded yet
	for i := range recs {           // newest first
		rec := recs[i]
		if rec.Kind != "mooring-state" {
			continue
		}
		if strings.Contains(rec.Location, "s3") {
			if rec.CreatedAt >= since {
				return nil // today's is uploaded: not due
			}
			break
		}
		// A record whose file is missing (restored from another server's catalog, or removed by
		// hand) can't be uploaded: take a new snapshot instead.
		if pending == nil && rec.CreatedAt >= since && fileExists(r.cat.FilePath(rec)) {
			pending = &rec
		}
	}
	rec := backupstore.Record{}
	if pending != nil {
		rec = *pending // a retry, or a recent "Back up now" snapshot: upload it rather than make another
	} else if rec, err = r.cat.Create(ctx, now); err != nil {
		r.failed(ctx, fmt.Errorf("making the backup: %w", err))
		return err
	}
	uctx, cancel := context.WithTimeout(ctx, r.uploadTimeout(rec.SizeBytes))
	err = r.upload(uctx, rec)
	cancel()
	if err != nil {
		r.failed(ctx, err)
		return err
	}
	if err := r.cat.SetLocation(ctx, rec.ID, "local+s3"); err != nil {
		return err
	}
	if r.failing {
		r.log.Info("mooring-state backup: S3 uploads work again")
		r.failing = false
	}
	r.log.Info("mooring-state backup uploaded", "key", StateKey(r.prefix, rec), "bytes", rec.SizeBytes)
	r.pruneLocal(ctx)
	r.pruneS3(ctx)
	return nil
}

// lastQuietHour is the most recent StateHour o'clock at or before now, in the server's time zone.
func (r *StateRunner) lastQuietHour(now time.Time) time.Time {
	t := now.In(r.loc)
	q := time.Date(t.Year(), t.Month(), t.Day(), StateHour, 0, 0, 0, r.loc)
	if q.After(t) {
		q = q.AddDate(0, 0, -1)
	}
	return q
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func (r *StateRunner) upload(ctx context.Context, rec backupstore.Record) error {
	f, err := os.Open(r.cat.FilePath(rec))
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	return r.up.Put(ctx, StateKey(r.prefix, rec), f, st.Size(), "application/octet-stream")
}

func (r *StateRunner) failed(ctx context.Context, err error) {
	if ctx.Err() != nil {
		return // Mooring is stopping; the next start uploads it
	}
	r.log.Warn("mooring-state backup: upload to S3 failed; retrying hourly", "err", err)
	if r.failing {
		return
	}
	r.failing = true
	if r.alert != nil {
		r.alert("warning", "Mooring state backup upload failed", err.Error()+" (kept on the server; retried every hour)")
	}
}

// pruneLocal keeps the newest StateKeep state backups on the server (manual ones included) and
// removes the rest (file + catalog row). Their S3 copies are pruned separately (pruneS3).
func (r *StateRunner) pruneLocal(ctx context.Context) {
	recs, err := r.cat.List(ctx)
	if err != nil {
		return
	}
	n := 0
	for _, rec := range recs { // newest first
		if rec.Kind != "mooring-state" {
			continue
		}
		if n++; n > StateKeep {
			if err := r.cat.Delete(ctx, rec.ID); err != nil {
				r.log.Warn("mooring-state backup: removing an old one failed", "id", rec.ID, "err", err)
			}
		}
	}
}

// pruneS3 keeps the newest StateKeep state backups in the bucket, from a listing (so it holds after
// the server's catalog is lost or restored). Only keys of the state layout under the prefix are
// deleted; anything else in the bucket is left alone.
func (r *StateRunner) pruneS3(ctx context.Context) {
	objs, err := StateBackups(ctx, r.up, r.prefix)
	if err != nil {
		r.log.Warn("mooring-state backup: listing the bucket failed; old copies are removed next time", "err", err)
		return
	}
	for _, o := range objs[min(len(objs), StateKeep):] {
		if err := r.up.Delete(ctx, o.Key); err != nil {
			r.log.Warn("mooring-state backup: deleting an old copy failed", "key", o.Key, "err", err)
		}
	}
}
