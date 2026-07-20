package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/daboss2003/mooring/internal/appbackup"
	"github.com/daboss2003/mooring/internal/backupstore"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/store"
)

// cmdRestoreVolume restores a single app DATA VOLUME from a catalogued, encrypted volume
// snapshot. Like the DB restore it is deliberately a CLI step (not a one-click dashboard
// button): it OVERWRITES the volume's contents, so it must run with the app's containers
// stopped, and it needs the same master key the backup was made with. The archive is
// decrypted (AES-256-GCM — a wrong key or a tampered/corrupt file fails before anything is
// written), gunzipped, and extracted into the volume via a throwaway `docker run -i --rm`
// sidecar.
func cmdRestoreVolume(args []string) error {
	fs := flag.NewFlagSet("restore-volume", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultPath, "path to config.yaml")
	backupID := fs.String("backup", "", "catalogued backup id (from the Backups page) to restore")
	volume := fs.String("volume", "", "override the target docker volume (defaults to the backup's recorded volume)")
	force := fs.Bool("force", false, "confirm the restore (it OVERWRITES the volume's contents)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *backupID == "" {
		return fmt.Errorf("usage: mooring restore-volume --backup <id> --force  (stop the app's containers first)")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	key, err := config.DecodeKey(cfg.EncryptionKey)
	if err != nil {
		return fmt.Errorf("decode master key: %w", err)
	}

	db, err := store.Open(filepath.Join(cfg.DataDir, "mooring.db"))
	if err != nil {
		return err
	}
	defer db.Close()

	cat := backupstore.New(db, filepath.Join(cfg.DataDir, "backups"), key)
	rec, ok, err := cat.Get(context.Background(), *backupID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no backup with id %q in the catalog", *backupID)
	}
	if rec.Kind != "volume" {
		return fmt.Errorf("backup %q is a %q backup, not a volume snapshot; only volume restore is supported here", *backupID, rec.Kind)
	}
	target := rec.Target
	if *volume != "" {
		target = *volume
	}
	if target == "" {
		return fmt.Errorf("backup %q has no recorded volume; pass --volume", *backupID)
	}

	if !*force {
		return fmt.Errorf("this OVERWRITES the contents of docker volume %q (app %q) with snapshot %s.\n"+
			"Stop the app's containers first, then re-run with --force", target, rec.Project, *backupID)
	}

	archive := cat.FilePath(rec)
	f, err := os.Open(archive)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	// A standalone CLI restore: its own one-docker-child semaphore, write plane armed (the
	// operator ran this deliberately on the box). The sidecar mounts only the target volume.
	// A standalone CLI restore holds its OWN fresh one-docker-child semaphore (no serve is
	// sharing it), so RunStreamStdinHeld is correct. *dockerexec.Runner satisfies StdinRunner.
	runner := dockerexec.NewRunner(dockerexec.NewSemaphore(), true, "")
	fmt.Printf("restoring volume %q (app %q) from backup %s …\n", target, rec.Project, *backupID)
	tmpDir := filepath.Join(cfg.DataDir, "backups") // 0700; holds the verified plaintext transiently
	if err := appbackup.RestoreVolume(context.Background(), runner, target, cfg.BackupHelperImage(), key, f, tmpDir, func(line string) {
		fmt.Println("  " + line)
	}); err != nil {
		return err
	}
	fmt.Printf("restored volume %q. Start the app again from the dashboard.\n", target)
	return nil
}
