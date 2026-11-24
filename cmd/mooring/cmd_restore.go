package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/daboss2003/mooring/internal/backup"
	"github.com/daboss2003/mooring/internal/backupsched"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/hostmon"
	"github.com/daboss2003/mooring/internal/s3"
	"github.com/daboss2003/mooring/internal/store"
)

// restoreBucket is the S3 subset `restore --from-s3` needs (*s3.Client).
type restoreBucket interface {
	backupsched.StateLister
	Get(ctx context.Context, key string) (io.ReadCloser, int64, error)
}

// restoreBucketFor builds the backups.s3 client (swapped in tests).
var restoreBucketFor = func(sc *config.BackupS3) (restoreBucket, error) {
	c, err := s3ClientFor(sc)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// restoreDiskFree reports the free bytes on a path's filesystem (swapped in tests).
var restoreDiskFree = hostmon.DiskFree

// maxStateDownload bounds a --from-s3 download: state backups are uploaded with one PUT, which S3
// caps at 5 GiB.
const maxStateDownload = 5 << 30

// humanSize formats n bytes as "46.0 MiB".
func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// cmdRestore restores Mooring's database from an encrypted .mbk backup archive, a local file
// (--from) or a daily Mooring-state backup in backups.s3 (--from-s3). It is deliberately a CLI step
// (not a dashboard button): it REPLACES the live database, so it must run with the service
// stopped, and it needs the same master key the backup was made with. The archive is decrypted,
// validated by opening it (which also runs migrations + refuses a downgrade from a newer binary),
// and only then swapped in — the previous DB is kept aside as mooring.db.pre-restore-<ts>.
func cmdRestore(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return restoreRun(ctx, args, os.Stdout)
}

func restoreRun(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultPath, "path to config.yaml")
	from := fs.String("from", "", "path to the .mbk backup archive")
	fromS3 := fs.String("from-s3", "", "a daily Mooring-state backup in backups.s3: latest, list, or a name from the list (its start is enough)")
	force := fs.Bool("force", false, "confirm the restore (it replaces the current database)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*from == "") == (*fromS3 == "") {
		return errors.New("usage: mooring restore --from <archive.mbk> --force, or mooring restore --from-s3 latest|list|<name> --force")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	key, err := config.DecodeKey(cfg.EncryptionKey)
	if err != nil {
		return fmt.Errorf("decode master key: %w", err)
	}

	archive, source := *from, *from
	if *fromS3 != "" {
		path, src, err := fetchStateBackup(ctx, cfg, *fromS3, stdout)
		if err != nil || path == "" { // path "" = list printed
			return err
		}
		defer os.Remove(path)
		archive, source = path, src
	}
	return restoreDB(cfg, key, archive, source, *force, stdout)
}

// fetchStateBackup downloads the state backup which names ("latest", or a name from the list or
// the start of one) from backups.s3 into a 0600 temp file in the data dir, and returns its path and
// s3:// address. For "list" it prints the backups, newest first, and returns "".
func fetchStateBackup(ctx context.Context, cfg *config.Config, which string, stdout io.Writer) (string, string, error) {
	sc := cfg.Backups.S3
	if sc == nil {
		return "", "", errors.New("--from-s3 needs backups.s3 in config.yaml (the bucket the daily Mooring-state backups are uploaded to)")
	}
	if p := sc.Problems("backups.s3"); len(p) > 0 {
		return "", "", fmt.Errorf("backups.s3 is incomplete: %s", strings.Join(p, "; "))
	}
	b, err := restoreBucketFor(sc)
	if err != nil {
		return "", "", fmt.Errorf("backups.s3: %w", err)
	}
	where := "s3://" + sc.Bucket + "/" + sc.Prefix + backupsched.StateDir
	objs, err := backupsched.StateBackups(ctx, b, sc.Prefix)
	if err != nil {
		return "", "", fmt.Errorf("listing %s: %w", where, err)
	}
	if len(objs) == 0 {
		return "", "", fmt.Errorf("no Mooring-state backups in %s", where)
	}
	if which == "list" {
		for _, o := range objs {
			name := backupsched.StateName(sc.Prefix, o)
			when := name
			if t, terr := time.Parse("20060102T150405Z", name[:16]); terr == nil { // the layout's UTC time
				when = t.Format("2006-01-02 15:04:05 UTC")
			}
			fmt.Fprintf(stdout, "%s  %s  %s\n", name, when, humanSize(o.Size))
		}
		return "", "", nil
	}
	pick, err := pickStateBackup(objs, sc.Prefix, which)
	if err != nil {
		return "", "", err
	}
	src := "s3://" + sc.Bucket + "/" + pick.Key

	// The download and the decrypted copy both land in the data dir.
	// Intentional: when free space can't be read, the restore goes ahead; a full disk then fails the
	// download or the decrypt, which removes its temp files and replaces nothing.
	if free, ferr := restoreDiskFree(cfg.DataDir); ferr == nil && uint64(2*pick.Size) > free {
		return "", "", fmt.Errorf("not enough free space in %s: restoring %s (%s) needs about %s for the download and the decrypted database, %s free",
			cfg.DataDir, src, humanSize(pick.Size), humanSize(2*pick.Size), humanSize(int64(free)))
	}

	rc, _, err := b.Get(ctx, pick.Key)
	if err != nil {
		return "", "", fmt.Errorf("downloading %s: %w", src, err)
	}
	defer rc.Close()
	// The data dir rather than /tmp: it holds the database already, so it has the room, and it's
	// owner-only. The archive is still encrypted here; the temp file is 0600.
	f, err := os.CreateTemp(cfg.DataDir, ".restore-s3-*.mbk")
	if err != nil {
		return "", "", err
	}
	n, err := io.Copy(f, io.LimitReader(rc, maxStateDownload+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxStateDownload {
		err = fmt.Errorf("larger than %d bytes", int64(maxStateDownload))
	}
	if err != nil {
		os.Remove(f.Name())
		return "", "", fmt.Errorf("downloading %s: %w", src, err)
	}
	fmt.Fprintf(stdout, "downloaded %s (%d bytes)\n", src, n)
	return f.Name(), src, nil
}

// pickStateBackup is the backup which names: "latest", or the one whose name starts with which.
func pickStateBackup(objs []s3.Object, prefix, which string) (s3.Object, error) {
	if which == "latest" {
		return objs[0], nil // newest first
	}
	var m []s3.Object
	for _, o := range objs {
		if strings.HasPrefix(backupsched.StateName(prefix, o), which) {
			m = append(m, o)
		}
	}
	switch len(m) {
	case 1:
		return m[0], nil
	case 0:
		return s3.Object{}, fmt.Errorf("no Mooring-state backup named %q (see: mooring restore --from-s3 list)", which)
	default:
		return s3.Object{}, fmt.Errorf("%q matches %d backups; give more of the name (see: mooring restore --from-s3 list)", which, len(m))
	}
}

// restoreDB decrypts archive, checks it is a compatible Mooring database, and (with force) swaps
// it in for the live one. source is how the archive is named in the output.
func restoreDB(cfg *config.Config, key []byte, archive, source string, force bool, stdout io.Writer) error {
	dbPath := filepath.Join(cfg.DataDir, "mooring.db")
	tmp := dbPath + ".restore-tmp"

	// 1. Decrypt the archive to a temp file.
	enc, err := os.Open(archive)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer enc.Close()
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := backup.Decrypt(out, enc, key); err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("decrypt archive (wrong master key, or corrupt/tampered backup): %w", err)
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}

	// 2a. Reject anything that isn't actually a Mooring database (a blank or foreign
	// SQLite file must NEVER be installed over the live DB — store.Open alone would
	// happily migrate a fresh/empty file, so check the real schema first, read-only).
	if _, err := store.Inspect(tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("the archive is not a valid mooring backup: %w", err)
	}
	// 2b. Open it too (also runs migrations + refuses a downgrade from a newer binary).
	vdb, err := store.Open(tmp)
	if err != nil {
		os.Remove(tmp)
		os.Remove(tmp + "-wal")
		os.Remove(tmp + "-shm")
		return fmt.Errorf("the archive is not a valid/compatible mooring database: %w", err)
	}
	vdb.Close()
	os.Remove(tmp + "-wal")
	os.Remove(tmp + "-shm")

	if !force {
		os.Remove(tmp)
		return fmt.Errorf("this REPLACES the current database at %s. Stop the service first, then re-run with --force", dbPath)
	}

	// 3. Swap: keep the current DB aside, clear its stale side files, move in the new one.
	if _, statErr := os.Stat(dbPath); statErr == nil {
		aside := fmt.Sprintf("%s.pre-restore-%d", dbPath, time.Now().Unix())
		if err := os.Rename(dbPath, aside); err != nil {
			os.Remove(tmp)
			return fmt.Errorf("set current db aside: %w", err)
		}
		fmt.Fprintf(stdout, "previous database kept at %s\n", aside)
	}
	os.Remove(dbPath + "-wal")
	os.Remove(dbPath + "-shm")
	if err := os.Rename(tmp, dbPath); err != nil {
		return fmt.Errorf("install restored db: %w", err)
	}

	fmt.Fprintf(stdout, "restored %s from %s\nstart Mooring again: systemctl start mooring\n", dbPath, source)
	return nil
}
