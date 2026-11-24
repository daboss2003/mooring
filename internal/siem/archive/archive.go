// Package archive uploads sealed security-log segments to S3, encrypted in the backup format with
// Mooring's encryption key, with a seal object recording each segment's hash chain, and deletes
// archived objects past the retention.
//
// Object layout (schema v1, fixed): <prefix>v1/YYYY/MM/DD/HH/<box>-<seq>.ndjson.gz.enc and, next to
// it, <box>-<seq>.seal.json.
package archive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/daboss2003/mooring/internal/backup"
	"github.com/daboss2003/mooring/internal/s3"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/store"
)

// Uploader is the S3 subset the archive needs (*s3.Client). Get must return an error matching
// s3.ErrNotFound for a missing object.
type Uploader interface {
	Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error
	Get(ctx context.Context, key string) (io.ReadCloser, int64, error)
	List(ctx context.Context, prefix string) ([]s3.Object, error)
	Delete(ctx context.Context, key string) error
}

// Alerter raises the archive's alerts (alertstore EnqueueInfra-shaped); nil = log only.
// ArchiveFailing(true, detail) is sent once when uploads have failed for an hour (or six sealed
// segments are waiting) and ArchiveFailing(false, "") once when an upload works again.
// SegmentChanged(segment, detail) is sent once for a segment whose file changed after it was
// sealed (a separate alert: it has no "resolved", and an upload recovering must not close it).
type Alerter interface {
	ArchiveFailing(ctx context.Context, failing bool, detail string)
	SegmentChanged(ctx context.Context, segment, detail string)
}

// Options configures an Archiver.
type Options struct {
	Store     *store.Store
	Up        Uploader
	Key       []byte // the master encryption key (backup.Encrypt)
	Prefix    string // the s3 prefix, "" or ending in '/'
	Box       string
	Retention time.Duration
	Alerts    Alerter
	Log       *slog.Logger
	Now       func() time.Time
	// PreviousKey (optional) is the master key before a rotation: a seal already in the bucket
	// that authenticates with it still counts as this archiver's own. New seals use Key.
	PreviousKey []byte
}

// segmentStore is the part of *store.Store the archiver uses; an interface so tests can stand in
// for the store.
type segmentStore interface {
	SealDue() error
	Unarchived() ([]store.Segment, error)
	MarkArchived(name, key string, at time.Time) error
	Append(evs []siem.Event) error
	Flush() error
	Boxes() ([]string, error)
}

const (
	tickInterval    = time.Minute
	maxBackoff      = 30 * time.Minute
	alertAfter      = time.Hour // failing this long raises the alert
	alertBehind     = 6         // or this many sealed segments waiting while failing
	firstPruneAfter = 10 * time.Minute
	pruneInterval   = 24 * time.Hour
	pruneRetry      = time.Hour
	minRetention    = 24 * time.Hour
	segmentTimeout  = 30 * time.Minute // both uploads of one segment
	takenRecheck    = time.Hour        // a segment skipped for a taken key is checked again after this
	deleteTimeout   = time.Minute
	maxSegmentBytes = 4 << 30 // plaintext cap: the object stays under S3's 5 GiB single PUT
	maxErrLen       = 512
	tmpPattern      = "archive-*.enc.tmp"
)

var (
	// errSegmentGone: the segment's file no longer exists on the host.
	errSegmentGone = errors.New("segment file is gone")
	// errKeyTaken: the segment's archive key already holds a seal that isn't this segment's.
	errKeyTaken = errors.New("the archive key already holds a different seal")
)

// Archiver uploads and prunes. Run must be called at most once; the status methods are safe to
// call from any goroutine.
type Archiver struct {
	opt     Options
	st      segmentStore
	invalid string // why the options are unusable ("" = usable)
	sealKey []byte // siem.DeriveKey(Key, siem.KeySeal)
	prevKey []byte // the same from PreviousKey; nil without one

	mu           sync.Mutex
	lastArchived time.Time
	behind       int
	lastErr      string

	// Owned by the Run goroutine.
	fails        int       // consecutive failed attempts
	failingSince time.Time // the first failure of the current run of failures
	nextTry      time.Time // no upload attempt before this (backoff)
	alerted      bool      // ArchiveFailing(true) sent for the current run of failures
	nextPrune    time.Time
	tmpDir       string
	reported     map[string]bool      // "<kind>:<segment>" already reported (gone, taken)
	recheck      map[string]time.Time // segment skipped for a taken key -> its next check
}

// New builds an Archiver. Unusable options (no store or uploader, a key that isn't 32 bytes, an
// unsafe prefix or box, a retention under a day) are reported by Err, and Run then does nothing.
func New(opt Options) *Archiver {
	var st segmentStore
	if opt.Store != nil {
		st = opt.Store
	}
	return newArchiver(opt, st)
}

func newArchiver(opt Options, st segmentStore) *Archiver {
	if opt.Log == nil {
		opt.Log = slog.New(slog.DiscardHandler)
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	a := &Archiver{opt: opt, st: st, reported: map[string]bool{}, recheck: map[string]time.Time{}}
	if err := a.check(); err != nil {
		a.invalid = err.Error()
		a.lastErr = a.invalid
		return a
	}
	a.sealKey, _ = siem.DeriveKey(opt.Key, siem.KeySeal) // can't fail: the keys are 32 bytes
	if opt.PreviousKey != nil {
		a.prevKey, _ = siem.DeriveKey(opt.PreviousKey, siem.KeySeal)
	}
	return a
}

func (a *Archiver) check() error {
	switch {
	case a.st == nil:
		return errors.New("archive: no store")
	case a.opt.Up == nil:
		return errors.New("archive: no S3 client")
	case len(a.opt.Key) != 32:
		return errors.New("archive: the encryption key must be 32 bytes")
	case a.opt.PreviousKey != nil && len(a.opt.PreviousKey) != 32:
		return errors.New("archive: the previous encryption key must be 32 bytes")
	case a.opt.Retention < minRetention:
		return fmt.Errorf("archive: retention %s is under %s", a.opt.Retention, minRetention)
	}
	if err := checkPrefix(a.opt.Prefix); err != nil {
		return err
	}
	return checkBox(a.opt.Box)
}

// Run seals due segments and uploads every unarchived one every minute, and prunes the bucket
// once a day, until ctx ends.
func (a *Archiver) Run(ctx context.Context) {
	if a.invalid != "" {
		a.opt.Log.Error("security-log archive disabled", "err", a.invalid)
		<-ctx.Done()
		return
	}
	a.nextPrune = a.opt.Now().Add(firstPruneAfter)
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	for {
		a.step(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// step is one tick: seal, upload, and prune when due.
func (a *Archiver) step(ctx context.Context) {
	now := a.opt.Now()
	a.tick(ctx, now)
	if ctx.Err() != nil || now.Before(a.nextPrune) {
		return
	}
	if a.prune(ctx, now) {
		a.nextPrune = now.Add(pruneInterval)
	} else {
		a.nextPrune = now.Add(pruneRetry)
	}
}

// tick seals what is due and uploads the unarchived segments oldest first, stopping at the first
// failure so the chain reaches the bucket in order.
func (a *Archiver) tick(ctx context.Context, now time.Time) {
	if err := a.st.SealDue(); err != nil {
		a.opt.Log.Warn("security-log archive: sealing segments", "err", err)
	}
	segs, err := a.st.Unarchived()
	if err != nil {
		a.failed(now, fmt.Errorf("list unarchived segments: %w", err))
		a.checkAlert(ctx, now, "")
		return
	}
	a.setBehind(len(segs))
	a.forgetReported(segs)
	if len(segs) == 0 {
		return
	}
	if now.Before(a.nextTry) {
		a.checkAlert(ctx, now, segs[0].Name)
		return
	}
	left := len(segs)
	for _, seg := range segs {
		if ctx.Err() != nil {
			return
		}
		if next, ok := a.recheck[seg.Name]; ok && now.Before(next) {
			continue // its key is taken; checked again hourly, not every minute
		}
		at, mismatch, err := a.archiveOne(ctx, seg)
		if errors.Is(err, errSegmentGone) {
			// Intentional: a segment whose file is gone can never be uploaded. Skipping it keeps the
			// rest of the chain moving (verify reports the gap) instead of blocking every later
			// segment until the store forgets this one. It stays in Behind.
			a.reportGone(now, seg)
			continue
		}
		if errors.Is(err, errKeyTaken) {
			// Intentional: never overwrite another seal. Like a gone file it is skipped (it stays in
			// Behind and is alerted once), so one collision doesn't stop the rest of the archive.
			a.reportTaken(ctx, now, seg)
			a.recheck[seg.Name] = now.Add(takenRecheck)
			continue
		}
		delete(a.recheck, seg.Name)
		if err != nil {
			a.failed(now, fmt.Errorf("segment %s: %w", seg.Name, err))
			a.checkAlert(ctx, now, seg.Name)
			return
		}
		left--
		a.succeeded(ctx, at, left)
		if mismatch != "" {
			a.reportMismatch(ctx, at, seg, mismatch)
		}
	}
}

// archiveOne encrypts one sealed segment to a temp file, uploads it and its seal, and records it
// as archived. mismatch is the file's actual SHA-256 when it no longer matches the sealed one.
func (a *Archiver) archiveOne(ctx context.Context, seg store.Segment) (at time.Time, mismatch string, err error) {
	if seg.Seq < 0 || seg.Hour.IsZero() || seg.Path == "" || !isSHA256Hex(seg.SHA256) || seg.Chain < 1 || checkBox(seg.Box) != nil {
		return at, "", errors.New("invalid segment record")
	}
	// The key names the box that wrote the segment: after a rename, the hour's segments of the old
	// and the new name keep separate objects.
	encKey, sealKey := objectKeys(a.opt.Prefix, seg.Box, seg.Hour, seg.Seq)
	if !siem.SafeName(path.Base(encKey)) {
		return at, "", fmt.Errorf("object name %q is not allowed", path.Base(encKey))
	}
	uctx, cancel := context.WithTimeout(ctx, segmentTimeout)
	defer cancel()
	existing, found, err := a.existingSeal(uctx, sealKey)
	if err != nil {
		return at, "", err
	}
	if found {
		if !a.ours(existing, seg) {
			return at, "", errKeyTaken
		}
		if existing.N != seg.Chain {
			a.opt.Log.Info("security-log archive: the bucket already holds this segment under another chain position (the store's manifest was rebuilt); recording it",
				"segment", seg.Name, "bucket_n", existing.N, "store_n", seg.Chain)
		}
		// Intentional: a complete upload of this very segment is already there (MarkArchived failed
		// after both puts); record it instead of uploading again.
		at = a.opt.Now().UTC()
		if err := a.st.MarkArchived(seg.Name, encKey, at); err != nil {
			return at, "", fmt.Errorf("record the upload: %w", err)
		}
		if existing.SHA256Mismatch {
			mismatch = existing.ActualSHA256
		}
		return at, mismatch, nil
	}
	src, err := os.Open(seg.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return at, "", errSegmentGone
	}
	if err != nil {
		return at, "", err
	}
	defer src.Close()
	if fi, err := src.Stat(); err != nil {
		return at, "", err
	} else if !fi.Mode().IsRegular() {
		return at, "", errors.New("segment is not a regular file")
	}

	dir, err := a.tempDir(seg)
	if err != nil {
		return at, "", err
	}
	tmp, err := os.CreateTemp(dir, tmpPattern) // 0600; ciphertext only, never the plaintext
	if err != nil {
		return at, "", err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()

	// The plaintext hash is taken from the very bytes that are encrypted, so the check below is
	// about what is uploaded, not about an earlier read of the file.
	plainH, encH := sha256.New(), sha256.New()
	cw := &countWriter{w: io.MultiWriter(tmp, encH)}
	if err := backup.Encrypt(cw, io.TeeReader(src, plainH), a.opt.Key, maxSegmentBytes); err != nil {
		return at, "", fmt.Errorf("encrypt: %w", err)
	}
	if actual := hex.EncodeToString(plainH.Sum(nil)); actual != seg.SHA256 {
		mismatch = actual
		a.opt.Log.Error("security-log archive: segment changed after it was sealed; uploading it flagged",
			"segment", seg.Name, "sealed_sha256", seg.SHA256, "actual_sha256", actual)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return at, "", err
	}
	if err := a.opt.Up.Put(uctx, encKey, tmp, cw.n, "application/octet-stream"); err != nil {
		return at, "", err
	}
	at = a.opt.Now().UTC()
	seal := Seal{
		V: sealVersion, Name: seg.Name, Box: seg.Box, Hour: seg.Hour.UTC(), Seq: seg.Seq, N: seg.Chain,
		Events: seg.Events, First: seg.First.UTC(), Last: seg.Last.UTC(),
		SHA256: seg.SHA256, PrevSHA256: seg.PrevSHA256,
		EncSHA256: hex.EncodeToString(encH.Sum(nil)), EncBytes: cw.n, ArchivedAt: at,
	}
	if mismatch != "" {
		// Intentional: a segment that no longer matches its seal is still uploaded, under its own
		// key, but flagged, so the bucket holds the evidence and verify fails on it; SHA256 stays
		// the sealed hash so the chain is not rewritten.
		seal.SHA256Mismatch, seal.ActualSHA256 = true, mismatch
	}
	seal.MAC = seal.mac(a.sealKey)
	body, err := json.Marshal(seal)
	if err != nil {
		return at, "", err
	}
	if err := a.opt.Up.Put(uctx, sealKey, bytes.NewReader(body), int64(len(body)), "application/json"); err != nil {
		return at, "", err
	}
	if err := a.st.MarkArchived(seg.Name, encKey, at); err != nil {
		return at, "", fmt.Errorf("record the upload: %w", err)
	}
	return at, mismatch, nil
}

// existingSeal reads the seal already at key, if any. found with a zero Seal means something
// unreadable is there.
func (a *Archiver) existingSeal(ctx context.Context, key string) (s Seal, found bool, err error) {
	body, _, err := a.opt.Up.Get(ctx, key)
	if errors.Is(err, s3.ErrNotFound) {
		return s, false, nil
	}
	if err != nil {
		return s, false, fmt.Errorf("check for an existing seal: %w", err)
	}
	defer body.Close()
	b, err := io.ReadAll(io.LimitReader(body, maxSealBytes+1))
	if err != nil {
		return s, false, fmt.Errorf("read the existing seal: %w", err)
	}
	if len(b) > maxSealBytes || json.Unmarshal(b, &s) != nil {
		return Seal{}, true, nil
	}
	return s, true, nil
}

// ours reports whether s is this archiver's own seal of seg, signed with Key or PreviousKey.
// Intentional: n is not compared. A rebuilt manifest (security.db lost) gives a segment another
// chain position, and the authentic seal of the same file is still this server's upload.
func (a *Archiver) ours(s Seal, seg store.Segment) bool {
	signed := s.authenticWith(a.sealKey) || (a.prevKey != nil && s.authenticWith(a.prevKey))
	return signed && s.Name == seg.Name && s.Box == seg.Box && s.Seq == seg.Seq &&
		s.SHA256 == seg.SHA256 && s.Hour.Equal(seg.Hour)
}

// tempDir is where ciphertext is staged: the store's TempDir when it has one, else
// <store dir>/tmp, else a tmp directory next to the segments. Never the system temp directory.
// The first call removes temp files a crash left behind.
func (a *Archiver) tempDir(seg store.Segment) (string, error) {
	if a.tmpDir != "" {
		return a.tmpDir, nil
	}
	var dir string
	switch s := a.st.(type) {
	case interface{ TempDir() string }:
		dir = s.TempDir()
	case interface{ Dir() string }:
		dir = filepath.Join(s.Dir(), "tmp")
	default:
		dir = filepath.Join(filepath.Dir(seg.Path), "tmp")
	}
	if dir == "" || dir == "tmp" {
		return "", errors.New("no directory for temp files")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if stale, err := filepath.Glob(filepath.Join(dir, tmpPattern)); err == nil {
		for _, p := range stale {
			os.Remove(p)
		}
	}
	a.tmpDir = dir
	return dir, nil
}

// prune deletes this server's objects (its Box and every box name the store wrote under, so a
// renamed server's old objects go too) whose hour ended more than Retention ago and that the
// bucket last modified before then too (so a host clock running ahead, or an old hour uploaded
// late, deletes nothing early). It reports whether the listing worked.
func (a *Archiver) prune(ctx context.Context, now time.Time) bool {
	ours := map[string]bool{a.opt.Box: true}
	if boxes, err := a.st.Boxes(); err != nil {
		a.opt.Log.Warn("security-log archive: listing this server's box names; pruning only "+a.opt.Box, "err", err)
	} else {
		for _, b := range boxes {
			ours[b] = true
		}
	}
	root := a.opt.Prefix + layoutDir
	objs, err := a.opt.Up.List(ctx, root)
	if err != nil {
		a.opt.Log.Warn("security-log archive: listing for prune", "err", cleanErr(err))
		return false
	}
	cutoff := now.Add(-a.opt.Retention)
	var deleted, failed, skipped int
	for _, o := range objs {
		if ctx.Err() != nil {
			break
		}
		// ParseKey accepts only keys under <prefix>v1/ in the exact layout, so nothing else in the
		// bucket (or anything a hostile listing returns) is ever deleted.
		ki, ok := ParseKey(a.opt.Prefix, o.Key)
		if !ok || !ours[ki.Box] { // never another server's box
			skipped++
			continue
		}
		if !ki.Hour.Add(time.Hour).Before(cutoff) || o.LastModified.IsZero() || !o.LastModified.Before(cutoff) {
			continue
		}
		dctx, cancel := context.WithTimeout(ctx, deleteTimeout)
		err := a.opt.Up.Delete(dctx, o.Key)
		cancel()
		if err != nil {
			failed++
			a.opt.Log.Warn("security-log archive: delete", "key", o.Key, "err", cleanErr(err))
			continue
		}
		deleted++
	}
	a.opt.Log.Info("security-log archive pruned", "deleted", deleted, "failed", failed, "not_ours", skipped, "listed", len(objs))
	return true
}

func (a *Archiver) failed(now time.Time, err error) {
	a.fails++
	if a.fails == 1 {
		a.failingSince = now
	}
	back := tickInterval << min(a.fails-1, 5)
	if back > maxBackoff {
		back = maxBackoff
	}
	// Measured from the tick's start, so a 1-minute backoff never skips the next tick.
	a.nextTry = now.Add(back)
	msg := cleanErr(err)
	a.mu.Lock()
	a.lastErr = msg
	a.mu.Unlock()
	a.opt.Log.Warn("security-log archive: upload failed", "err", msg, "attempt", a.fails, "retry_in", back)
}

// checkAlert raises the failing alert once per run of failures.
func (a *Archiver) checkAlert(ctx context.Context, now time.Time, oldest string) {
	if a.alerted || a.fails == 0 {
		return
	}
	behind := a.Behind()
	if now.Sub(a.failingSince) < alertAfter && behind < alertBehind {
		return
	}
	a.alerted = true
	lastErr := a.Err()
	detail := fmt.Sprintf("%d sealed segment(s) not uploaded; uploads failing since %s: %s",
		behind, a.failingSince.UTC().Format(time.RFC3339), lastErr)
	a.opt.Log.Error("security-log archive failing", "behind", behind, "since", a.failingSince.UTC(), "err", lastErr)
	a.event(now, siem.LvlError, oldest, detail)
	if a.opt.Alerts != nil {
		a.opt.Alerts.ArchiveFailing(ctx, true, detail)
	}
}

func (a *Archiver) succeeded(ctx context.Context, at time.Time, left int) {
	a.mu.Lock()
	a.lastArchived, a.lastErr, a.behind = at, "", left
	a.mu.Unlock()
	if a.fails > 0 {
		a.opt.Log.Info("security-log archive: uploads work again", "after_attempts", a.fails)
	}
	a.fails, a.failingSince, a.nextTry = 0, time.Time{}, time.Time{}
	if a.alerted {
		a.alerted = false
		if a.opt.Alerts != nil {
			a.opt.Alerts.ArchiveFailing(ctx, false, "")
		}
	}
}

func (a *Archiver) reportMismatch(ctx context.Context, at time.Time, seg store.Segment, actual string) {
	detail := fmt.Sprintf("segment %s changed on this host after it was sealed (sealed sha256 %s, uploaded %s); it is archived flagged sha256_mismatch",
		seg.Name, seg.SHA256, actual)
	a.event(at, siem.LvlCritical, seg.Name, detail)
	if a.opt.Alerts != nil {
		a.opt.Alerts.SegmentChanged(ctx, seg.Name, detail)
	}
}

func (a *Archiver) reportGone(now time.Time, seg store.Segment) {
	if a.once("gone", seg.Name) {
		return
	}
	a.opt.Log.Error("security-log archive: segment file is gone; it can't be uploaded", "segment", seg.Name, "path", seg.Path)
	a.event(now, siem.LvlError, seg.Name, "the sealed segment's file is gone from this host before it was uploaded")
}

func (a *Archiver) reportTaken(ctx context.Context, now time.Time, seg store.Segment) {
	_, sk := objectKeys(a.opt.Prefix, seg.Box, seg.Hour, seg.Seq)
	detail := fmt.Sprintf("the archive key %s already holds a different seal; not overwriting it (another host uses the box name %q in this bucket and prefix, or the object was changed in the bucket)", sk, seg.Box)
	a.mu.Lock()
	a.lastErr = cleanErr(fmt.Errorf("segment %s: %s", seg.Name, detail))
	a.mu.Unlock()
	if a.once("taken", seg.Name) {
		return
	}
	a.opt.Log.Error("security-log archive: "+detail, "segment", seg.Name)
	a.event(now, siem.LvlCritical, seg.Name, detail)
	if a.opt.Alerts != nil {
		a.opt.Alerts.SegmentChanged(ctx, seg.Name, detail)
	}
}

// once reports whether kind was already reported for segment, and marks it reported.
func (a *Archiver) once(kind, segment string) bool {
	k := kind + ":" + segment
	if a.reported[k] {
		return true
	}
	a.reported[k] = true
	return false
}

// forgetReported drops reported and re-check names the store no longer lists (keeps the maps
// bounded).
func (a *Archiver) forgetReported(segs []store.Segment) {
	if len(a.reported) == 0 && len(a.recheck) == 0 {
		return
	}
	live := make(map[string]bool, len(segs))
	for _, s := range segs {
		live[s.Name] = true
	}
	for k := range a.reported {
		if _, name, _ := strings.Cut(k, ":"); !live[name] {
			delete(a.reported, k)
		}
	}
	for name := range a.recheck {
		if !live[name] {
			delete(a.recheck, name)
		}
	}
}

// event records an archive problem in the security log itself (it is indexed: lvl >= error).
func (a *Archiver) event(now time.Time, lvl, segment, msg string) {
	ev := siem.Event{TS: now, Src: siem.SrcSIEM, Lvl: lvl, Kind: siem.KindArchiveFailed,
		F: map[string]any{"segment": segment, "error": msg}, Msg: "security-log archive: " + msg}
	ev.Normalize(now)
	if err := a.st.Append([]siem.Event{ev}); err != nil {
		a.opt.Log.Warn("security-log archive: recording an archive event", "err", err)
		return
	}
	if err := a.st.Flush(); err != nil {
		a.opt.Log.Warn("security-log archive: flushing an archive event", "err", err)
	}
}

func (a *Archiver) setBehind(n int) {
	a.mu.Lock()
	a.behind = n
	a.mu.Unlock()
}

// LastArchived, Behind and Err are for the dashboard status.
func (a *Archiver) LastArchived() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastArchived
}

func (a *Archiver) Behind() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.behind
}

func (a *Archiver) Err() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastErr
}

// cleanErr is an error's text on one line, bounded. The s3 client's errors never carry the
// secret key (they are scrubbed of both credentials).
func cleanErr(err error) string {
	return siem.Cut(strings.Join(strings.Fields(err.Error()), " "), maxErrLen)
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
