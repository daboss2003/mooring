// Package backupsched is the scheduled app-data backup loop. On a fixed interval it discovers
// every app's docker DATA VOLUMES and snapshots each one — a read-only tar of the volume,
// streamed through gzip + AES-256-GCM (internal/appbackup) into a local .mbk and, when an S3
// destination is configured, uploaded off-box. Old snapshots beyond the retention count are
// pruned (local file + catalog row + remote object).
//
// It rides the existing write-plane one-docker-child semaphore via TryAcquire (skip-don't-
// queue — never queue a docker child; a backup that can't get the slot this cycle retries the
// next), so a backup never competes with or delays a deploy/self-heal. Volume snapshots are
// engine-agnostic and safe for every stateful service (Postgres, MySQL, Redis, Mongo, …);
// logical DB dumps (appbackup's pg_dump/mysqldump path) are a future per-service refinement.
package backupsched

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/appbackup"
	"github.com/daboss2003/mooring/internal/backupstore"
)

// StreamRunner runs a static-argv docker command (satisfied by dockerexec.Runner). The caller
// of RunStreamHeld must hold the one-docker-child semaphore. Its method set matches
// appbackup.StreamRunner, so a StreamRunner value passes straight to appbackup.Produce.
type StreamRunner interface {
	RunStreamHeld(ctx context.Context, argv []string, stdout io.Writer, onErrLine func(string)) error
}

// Semaphore is the one-docker-child gate (satisfied by dockerexec.Semaphore).
type Semaphore interface {
	TryAcquire() bool
	Release()
}

// Uploader is the optional off-box destination (satisfied by s3.Client).
type Uploader interface {
	Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error
	Delete(ctx context.Context, key string) error
}

// Config is the resolved backup policy.
type Config struct {
	Interval    time.Duration
	Retention   int
	HelperImage string
	Key         []byte // 32-byte master key
	EnvFileDir  string // 0700 dir for transient credential env-files (unused for volume tars)
	S3Prefix    string // optional key prefix for uploads
}

// Runner is the scheduled backup loop.
type Runner struct {
	run   StreamRunner
	sem   Semaphore
	cat   *backupstore.Store
	apps  func() []string // live app slugs
	s3    Uploader        // nil = local only
	cfg   Config
	alert func(level, title, detail string) // optional; nil = no alert
	log   *slog.Logger
}

// New builds a Runner. s3 may be nil (local-only). alert may be nil.
func New(run StreamRunner, sem Semaphore, cat *backupstore.Store, apps func() []string, s3 Uploader, cfg Config, alert func(level, title, detail string), log *slog.Logger) *Runner {
	return &Runner{run: run, sem: sem, cat: cat, apps: apps, s3: s3, cfg: cfg, alert: alert, log: log}
}

const minInterval = time.Hour

// Run backs up a few minutes after boot (let the box settle), then every interval, until ctx
// is done.
func (r *Runner) Run(ctx context.Context) {
	iv := r.cfg.Interval
	if iv < minInterval {
		iv = minInterval
	}
	select {
	case <-time.After(3 * time.Minute):
	case <-ctx.Done():
		return
	}
	r.BackupAll(ctx)
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.BackupAll(ctx)
		}
	}
}

// BackupAll snapshots every data volume of every app, one at a time.
func (r *Runner) BackupAll(ctx context.Context) {
	if !r.cat.Available() {
		return
	}
	for _, project := range r.apps() {
		if ctx.Err() != nil {
			return
		}
		for _, vol := range r.discoverVolumes(ctx, project) {
			if ctx.Err() != nil {
				return
			}
			r.backupVolume(ctx, project, vol)
		}
	}
}

// discoverVolumes lists an app's docker named volumes (those compose labelled with the
// project). Runs under a briefly-held semaphore; returns nil if the slot is busy this cycle.
func (r *Runner) discoverVolumes(ctx context.Context, project string) []string {
	if !r.sem.TryAcquire() {
		return nil
	}
	defer r.sem.Release()
	var buf bytes.Buffer
	argv := []string{"volume", "ls", "--filter", "label=com.docker.compose.project=" + project, "-q"}
	if err := r.run.RunStreamHeld(ctx, argv, &buf, nil); err != nil {
		r.logWarn("backup: could not list volumes", project, err)
		return nil
	}
	var vols []string
	for _, line := range strings.Split(buf.String(), "\n") {
		if v := strings.TrimSpace(line); v != "" {
			vols = append(vols, v)
		}
	}
	return vols
}

// backupVolume snapshots one volume: tar → gzip → encrypt → local .mbk (+ optional S3), then
// catalogues it and prunes old snapshots beyond the retention count. The whole produce runs
// under the held semaphore (TryAcquire; skip if a deploy holds it).
func (r *Runner) backupVolume(ctx context.Context, project, volume string) {
	if !r.sem.TryAcquire() {
		return // busy (a deploy is running) — retry next cycle
	}
	defer r.sem.Release()

	id, err := r.cat.NewID()
	if err != nil {
		return
	}
	f, path, err := appbackup.LocalFile(r.cat.Dir(), id)
	if err != nil {
		r.logWarn("backup: open sink", project, err)
		return
	}
	spec := appbackup.Spec{Kind: appbackup.KindVolume, Volume: volume, Image: r.cfg.HelperImage}
	res, perr := appbackup.Produce(ctx, r.run, spec, r.cfg.Key, f, appbackup.Options{EnvFileDir: r.cfg.EnvFileDir, OnErr: nil})
	cerr := f.Close()
	if perr != nil || cerr != nil {
		_ = os.Remove(path)
		e := perr
		if e == nil {
			e = cerr
		}
		r.logWarn("backup: produce "+project+"/"+volume, project, e)
		r.notify("critical", "Backup failed", fmt.Sprintf("%s volume %s: %v", project, volume, e))
		return
	}

	rec := backupstore.Record{
		ID: id, CreatedAt: time.Now().Unix(), SizeBytes: res.Ciphertext, File: id + ".mbk",
		SHA256: res.SHA256, Kind: "volume", Project: project, Target: volume, Location: "local",
		Note: "scheduled volume snapshot",
	}
	if r.s3 != nil {
		if err := r.upload(ctx, path, id, res.Ciphertext); err != nil {
			r.logWarn("backup: s3 upload "+project+"/"+volume, project, err)
			r.notify("warning", "Backup off-box upload failed", fmt.Sprintf("%s volume %s kept locally: %v", project, volume, err))
		} else {
			rec.Location = "local+s3"
		}
	}
	if err := r.cat.Catalog(ctx, rec); err != nil {
		r.logWarn("backup: catalog", project, err)
		return
	}
	r.pruneRetention(ctx, project, volume)
}

// upload streams the local .mbk to the object store under <prefix><id>.mbk.
func (r *Runner) upload(ctx context.Context, path, id string, size int64) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return r.s3.Put(ctx, r.cfg.S3Prefix+id+".mbk", f, size, "application/octet-stream")
}

// pruneRetention keeps the newest Retention snapshots for (project, target) and deletes the
// rest — local file + catalog row (backupstore.Delete) + remote object.
func (r *Runner) pruneRetention(ctx context.Context, project, target string) {
	all, err := r.cat.List(ctx)
	if err != nil {
		return
	}
	keep := r.cfg.Retention
	if keep < 1 {
		keep = 1
	}
	var seen int
	for _, rec := range all { // newest first
		if rec.Project != project || rec.Target != target {
			continue
		}
		seen++
		if seen <= keep {
			continue
		}
		if r.s3 != nil && strings.Contains(rec.Location, "s3") {
			_ = r.s3.Delete(ctx, r.cfg.S3Prefix+rec.File)
		}
		_ = r.cat.Delete(ctx, rec.ID) // removes local file + catalog row
	}
}

func (r *Runner) notify(level, title, detail string) {
	if r.alert != nil {
		r.alert(level, title, detail)
	}
}

func (r *Runner) logWarn(msg, project string, err error) {
	if r.log != nil {
		r.log.Warn(msg, "project", project, "err", err)
	}
}
