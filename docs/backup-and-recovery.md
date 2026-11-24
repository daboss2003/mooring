# Backups & recovery

Mooring makes your setup reproducible, but two things deserve real backups: **Mooring's own configuration** (every app's settings, secrets, routes, and definitions) and your **apps' data** (their databases and uploaded files). This page covers both, and how to recover onto a fresh server.

See also: [Alerts](./alerting.md) · [Deploy from a Git repo](./gitops.md)

---

## Backing up Mooring

This is the "get everything back on a new server" backup. It captures Mooring's entire state — all your apps' config, definitions, edge routes, and secrets (which stay encrypted) — in one encrypted file.

Open **System → Backups** in the dashboard:

- **Back up now** takes a snapshot. It appears in the list with its date, size, and a checksum.
- **Download** saves the encrypted archive so you can keep it off-site. It's locked with your master key, so it's safe to store anywhere — only someone with that key can read it.
- **Delete** removes a snapshot you no longer need.

> **Keep your master key.** A backup is encrypted with the same master key you generated at install. Store that key somewhere safe and separate from the backups — restoring needs it.

### Restoring Mooring onto a fresh server

Restoring replaces Mooring's database, so it's a deliberate command-line step rather than a dashboard button:

1. Install Mooring on the new server with the **same `encryption_key`** as the original.
2. Stop the service: `systemctl stop mooring`.
3. Restore from your archive:

   ```bash
   mooring restore --from mooring-backup-<id>.mbk --force
   ```

   Mooring decrypts and verifies the archive before swapping it in, and keeps the existing database aside (as a `.pre-restore-*` copy) just in case.
4. Start it again: `systemctl start mooring`.

Your apps' definitions and settings are back; redeploy them and Mooring rebuilds their files and re-issues certificates.

### Daily copies in S3

When `backups.s3` is set in `config.yaml` (with or without `backups.enabled`), Mooring takes a
Mooring-state backup once a day and uploads it to that bucket as
`<prefix>mooring-state/<YYYYMMDD>T<HHMMSS>Z-<id>.mbk` (UTC). It is the same encrypted archive
**Back up now** makes, so `mooring restore --from <file>.mbk --force` restores it. Only the archive
is uploaded: `config.yaml` and the encryption key stay on the server. Keep `encryption_key`
somewhere else too, or a copy in S3 can't be restored.

- One is taken each day at 03:00 server time (the first hourly check after it). When that day's
  backup was missed (Mooring was stopped, or this is the first start), it is taken a few minutes
  after Mooring starts. A restart doesn't add one.
- At most 10 are kept in the bucket and 10 on the server. In the bucket, the oldest objects under
  `<prefix>mooring-state/` are deleted; other objects there are never touched. On the server, the
  newest 10 Mooring-state backups are kept, **Back up now** ones included.
- A failed upload is kept on the server and retried every hour with the same archive; Mooring
  raises a `backup` alert once per outage. An upload that stalls is stopped after an hour (plus a
  minute per 64 MiB of archive) and counts as failed.
- With versioning on, a deleted object stays in the bucket as a noncurrent version, so the bucket
  holds more than 10 copies. Add a lifecycle rule that expires noncurrent versions under
  `<prefix>mooring-state/` to keep it at 10.
- An incomplete `backups.s3` block (missing bucket, region, endpoint or keys) turns the daily
  backup off and is reported at startup and by `sudo mooring doctor`; with `backups.enabled` it
  refuses to start, as before.

The `backups.s3` credentials need `s3:PutObject`, `s3:ListBucket` and `s3:DeleteObject` on the
bucket, and `s3:GetObject` to restore from it.

To restore from S3, follow the steps above with step 3 replaced by:

```bash
mooring restore --from-s3 latest --force
```

`config.yaml` on the new server needs the same `encryption_key` and the same `backups.s3` block.
`mooring restore --from-s3 list` prints the backups in the bucket, newest first; pass one of those
names (or the start of one, such as `20261124`) instead of `latest` to restore an older one. The
data dir needs about twice the backup's size free (the download plus the decrypted database);
the restore checks this before downloading.

---

## Backing up your apps' data

Mooring's own backup brings back *configuration*, but not the data **inside** your apps — a database's contents, a volume of uploaded files. Those live in Docker volumes. Turn on scheduled, encrypted snapshots of them in `config.yaml`:

```yaml
backups:
  enabled: true
  schedule: 24h        # how often (default 24h; 1h floor)
  retention: 7         # keep the newest N snapshots per volume
  helper_image: busybox:1.36   # optional: the small image (with `tar`) used to read a volume
  # optional: also ship each snapshot off-box to any S3-compatible store
  s3:
    bucket: my-mooring-backups
    endpoint: s3.us-east-1.amazonaws.com   # or a MinIO / R2 / B2 endpoint
    region: us-east-1
    access_key_id: "…"
    secret_access_key: "…"
    prefix: "mooring/"                       # optional key prefix
    path_style: true                         # default true; needed by most S3-compatible endpoints (MinIO/R2/B2)
    insecure: false                          # allow plain http:// (e.g. a private MinIO on the LAN); default https
```

Once enabled, Mooring discovers every app's Docker **data volumes** and, on the schedule, snapshots each one: a read-only `tar` of the volume streamed through **gzip + AES-256-GCM** into a `.mbk` file under `<data_dir>/backups/`, kept to your retention count, and — when `s3` is set — uploaded off-box too. It rides the same one-docker-child slot as deploys and *skips* (never queues) when a deploy is running, so backups never slow a deploy. A failed backup raises an alert. The snapshots appear on the **Backups** page alongside your Mooring-state backups.

Credentials for S3 live only in `config.yaml` (root-owned, `0600`) — never in an app repo — so a repository can never name an exfiltration bucket or hold your keys.

### Restoring an app's data volume

Restoring **overwrites** the live volume, so — like the Mooring-state restore — it's a deliberate CLI step. Stop the app's containers first, then restore a snapshot by its id (from the Backups page):

```
mooring restore-volume --backup <id> --force
```

Mooring decrypts the snapshot (a wrong key or a tampered/corrupt file fails *before* anything is written — the archive is authenticated), gunzips it, and extracts it into the volume via a throwaway container. Start the app again from the dashboard afterward.

Worth remembering:

- **A definition file recreates the app, not its data.** Redeploying gives you a fresh, empty volume — so a database still needs these snapshots.
- **Keep backups off the server** (use the `s3` destination) so losing the box doesn't lose the backups too.
- **Test a restore occasionally.** A backup you've never restored is a hope, not a plan.
- **A volume snapshot is crash-consistent.** For a busy database it's usually fine, but the cleanest possible dump is a logical one (`pg_dump`) — per-service logical DB dumps are the next refinement on top of this.
