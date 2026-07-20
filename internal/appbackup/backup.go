// Package appbackup is the app-data backup ENGINE: it produces encrypted snapshots of an
// app's stateful data — a logical database dump (pg_dump / mysqldump / mongodump) or a raw
// data-volume tar — by running a THROWAWAY sidecar container (`docker run --rm …`) on the
// write plane, piping its stdout through gzip and the tamper-evident AES-256-GCM stream from
// internal/backup, to a sink (a local .mbk file and/or an off-box object store).
//
// Security posture:
//   - A sidecar is a fresh one-shot container that removes itself — NEVER an exec into a
//     running container (Mooring does not give shells into live containers).
//   - Database credentials are passed via a 0600 --env-file, NEVER on the argv (argv is
//     world-visible in `ps`). The file lives in a 0700 dir and is removed after the run.
//   - All container mutation rides the existing write-plane Runner (the §0 RAM gate + the
//     one-docker-child semaphore); this package only builds STATIC argv (no shell).
//   - The plaintext dump never touches disk unencrypted — it streams sidecar→gzip→Encrypt→sink.
package appbackup

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/daboss2003/mooring/internal/backup"
)

// StreamRunner runs a static-argv `docker` command, streaming its raw stdout to w and its
// stderr line-by-line to onErrLine. It is satisfied by dockerexec.Runner (RunStreamHeld — the
// caller holds the one-docker-child semaphore); a fake implements it in tests.
type StreamRunner interface {
	RunStreamHeld(ctx context.Context, argv []string, stdout io.Writer, onErrLine func(string)) error
}

// Kind is the backup producer type.
type Kind string

const (
	KindPostgres Kind = "postgres" // pg_dump (custom format); password via PGPASSWORD env-file
	KindMySQL    Kind = "mysql"    // mysqldump (also mariadb); password via MYSQL_PWD env-file
	KindVolume   Kind = "volume"   // tar of a named data volume — the universal fallback for
	// every other stateful engine (mongo, redis, …), whose CLI tools can't take a password
	// off the argv cleanly. A volume tar is engine-agnostic and equally restorable.
)

// Spec describes one backup target. Exactly the fields for its Kind are used.
type Spec struct {
	Kind Kind

	// Image is the sidecar image, digest- or tag-pinned by the caller. For a DB dump it is
	// normally the DB service's OWN image (so the client tool version matches the server);
	// for a volume tar it is a minimal helper (e.g. a pinned busybox/alpine) that has `tar`.
	Image string

	// Network is the app's compose network the sidecar joins to reach the DB service
	// (e.g. "<project>_default"). Empty for a volume tar (no network needed).
	Network string

	// DB-dump fields.
	Host     string // the DB service name on the compose network (e.g. "db")
	Port     int    // 0 → engine default
	User     string
	DBName   string
	Password string // resolved from the secret store by the caller; passed via 0600 env-file

	// Volume-tar field.
	Volume string // the named data volume to snapshot (read-only mount)
}

// EnvFileDir is where the transient 0600 credential env-file is written. It MUST be a
// Mooring-owned 0700 directory. The file is removed as soon as the sidecar exits.
type Options struct {
	EnvFileDir string
	// Gzip compresses the plaintext before encryption (dumps compress well). Default true;
	// a volume that is already compressed data still tars fine, just with less gain.
	NoGzip bool
	OnErr  func(string) // sidecar stderr sink (best-effort logging); may be nil
}

// Result is the outcome of a successful Produce.
type Result struct {
	Ciphertext int64  // bytes written to the sink (the .mbk size)
	SHA256     string // sha256 of the ciphertext (integrity of the stored blob)
}

// Produce runs the target's sidecar and streams sidecar-stdout → gzip → backup.Encrypt → dst.
// The caller MUST already hold the one-docker-child semaphore (Produce uses RunStreamHeld).
// key is the 32-byte master key. dst is the ciphertext sink (a local file and/or an S3
// multi-writer). Returns the ciphertext size + sha256. The plaintext is never written to disk.
func Produce(ctx context.Context, r StreamRunner, spec Spec, key []byte, dst io.Writer, opts Options) (Result, error) {
	argv, cleanup, err := buildArgv(spec, opts.EnvFileDir)
	if err != nil {
		return Result{}, err
	}
	defer cleanup()

	// Count + hash the ciphertext as it lands in the sink.
	cw := &countingSHA{w: dst, h: sha256.New()}

	// producer stdout → (gzip) → pipe; the reader side is Encrypt's plaintext src.
	pr, pw := io.Pipe()
	go func() {
		var sink io.Writer = pw
		var gz *gzip.Writer
		if !opts.NoGzip {
			gz = gzip.NewWriter(pw)
			sink = gz
		}
		runErr := r.RunStreamHeld(ctx, argv, sink, opts.OnErr)
		if gz != nil {
			if cerr := gz.Close(); runErr == nil {
				runErr = cerr
			}
		}
		// Propagate a producer failure to Encrypt so a partial dump can NEVER be finalized
		// as a valid backup (Encrypt returns the error; nothing is catalogued).
		pw.CloseWithError(runErr)
	}()

	if err := backup.Encrypt(cw, pr, key, 0); err != nil {
		_, _ = io.Copy(io.Discard, pr) // drain so the producer goroutine can't block
		return Result{}, fmt.Errorf("appbackup: encrypt stream: %w", err)
	}
	return Result{Ciphertext: cw.n, SHA256: hex.EncodeToString(cw.h.Sum(nil))}, nil
}

// buildArgv constructs the STATIC `docker run --rm …` argv for a spec, plus a cleanup func
// that removes any transient 0600 credential env-file. No secret is ever placed on the argv.
func buildArgv(spec Spec, envFileDir string) (argv []string, cleanup func(), err error) {
	cleanup = func() {}

	switch spec.Kind {
	case KindVolume:
		if spec.Volume == "" || spec.Image == "" {
			return nil, cleanup, fmt.Errorf("appbackup: volume backup needs Volume and Image")
		}
		// Read-only mount of the named volume; tar its contents to stdout. No network.
		argv = []string{
			"run", "--rm", "--network", "none",
			"-v", spec.Volume + ":/data:ro",
			spec.Image,
			"tar", "-c", "-C", "/data", ".",
		}
		return argv, cleanup, nil

	case KindPostgres, KindMySQL:
		if spec.Image == "" || spec.Host == "" || spec.DBName == "" {
			return nil, cleanup, fmt.Errorf("appbackup: db backup needs Image, Host and DBName")
		}
		// Credentials go in a 0600 env-file, referenced by PATH on the argv (never the value).
		efPath, cl, ferr := writeCredEnvFile(spec, envFileDir)
		if ferr != nil {
			return nil, cleanup, ferr
		}
		cleanup = cl
		argv = []string{"run", "--rm"}
		if spec.Network != "" {
			argv = append(argv, "--network", spec.Network)
		}
		argv = append(argv, "--env-file", efPath, spec.Image)
		argv = append(argv, dumpCmd(spec)...)
		return argv, cleanup, nil

	default:
		return nil, cleanup, fmt.Errorf("appbackup: unknown backup kind %q", spec.Kind)
	}
}

// dumpCmd returns the in-container dump command for a DB engine. The password is NOT here —
// it is supplied to the tool via the env-file (PGPASSWORD / MYSQL_PWD / MONGO*). Host/user/db
// are discrete argv elements (no shell); they come from the validated definition, not user
// free-text, and carry no shell metacharacters.
func dumpCmd(spec Spec) []string {
	switch spec.Kind {
	case KindPostgres:
		args := []string{"pg_dump", "--format=custom", "--no-owner", "--no-privileges", "-h", spec.Host, "-U", defUser(spec.User, "postgres"), "-d", spec.DBName}
		if spec.Port > 0 {
			args = append(args, "-p", strconv.Itoa(spec.Port))
		}
		return args
	case KindMySQL:
		args := []string{"mysqldump", "--single-transaction", "--quick", "-h", spec.Host, "-u", defUser(spec.User, "root")}
		if spec.Port > 0 {
			args = append(args, "-P", strconv.Itoa(spec.Port))
		}
		return append(args, spec.DBName)
	}
	return nil
}

func defUser(u, fallback string) string {
	if strings.TrimSpace(u) == "" {
		return fallback
	}
	return u
}

// writeCredEnvFile writes a 0600 env-file with the engine's password variable into a 0700
// dir and returns its path + a cleanup that removes it. The value never appears on any argv.
func writeCredEnvFile(spec Spec, dir string) (string, func(), error) {
	if dir == "" {
		return "", func() {}, fmt.Errorf("appbackup: no env-file dir configured")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", func() {}, err
	}
	f, err := os.CreateTemp(dir, ".dbcreds-*")
	if err != nil {
		return "", func() {}, err
	}
	path := f.Name()
	cleanup := func() { _ = os.Remove(path) }
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		cleanup()
		return "", func() {}, err
	}
	var line string
	switch spec.Kind {
	case KindPostgres:
		line = "PGPASSWORD=" + spec.Password + "\n"
	case KindMySQL:
		line = "MYSQL_PWD=" + spec.Password + "\n"
	}
	if _, err := io.WriteString(f, line); err != nil {
		f.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

// countingSHA tees writes to an underlying writer while counting bytes and hashing.
type countingSHA struct {
	w io.Writer
	h interface {
		io.Writer
		Sum([]byte) []byte
	}
	n int64
}

func (c *countingSHA) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		c.h.Write(p[:n])
		c.n += int64(n)
	}
	return n, err
}

// StdinRunner runs a static-argv docker command feeding stdin to the child (satisfied by
// dockerexec.Runner.RunStreamStdinHeld); the caller holds the one-docker-child semaphore.
type StdinRunner interface {
	RunStreamStdinHeld(ctx context.Context, argv []string, stdin io.Reader, onLine func(string)) error
}

// RestoreVolume restores a volume snapshot IN PLACE: it overwrites the volume's contents with
// the snapshot. DESTRUCTIVE — the caller MUST stop every container using the volume first and
// gate the action.
//
// The archive is decrypted+AUTHENTICATED IN FULL to a transient 0600 file (under tmpDir)
// BEFORE the tar sidecar touches the volume. This matters because backup.Decrypt is a chunked
// stream: were we to pipe it straight into `tar`, a corrupt/truncated archive past the first
// 64 KiB chunk would already have extracted the leading chunks into the live volume before the
// defect surfaced. Verifying the whole archive first makes "a bad archive never clobbers the
// volume" actually true. Only then is the verified plaintext gunzipped into a throwaway
// `docker run -i --rm -v <volume>:/data <image> tar -x -C /data` sidecar.
func RestoreVolume(ctx context.Context, r StdinRunner, volume, image string, key []byte, src io.Reader, tmpDir string, onLine func(string)) error {
	if volume == "" || image == "" {
		return fmt.Errorf("appbackup: restore needs volume and image")
	}
	if tmpDir == "" {
		return fmt.Errorf("appbackup: restore needs a tmpDir for the verified plaintext")
	}
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return err
	}
	// 1. Decrypt + authenticate the ENTIRE archive to a 0600 temp file first (fail-closed:
	//    a wrong key or a tampered/corrupt/truncated .mbk errors here, before any write to
	//    the volume). The plaintext is still gzip-compressed, so this is not the raw volume.
	tf, err := os.CreateTemp(tmpDir, ".restore-*")
	if err != nil {
		return err
	}
	tfPath := tf.Name()
	defer os.Remove(tfPath)
	if err := tf.Chmod(0o600); err != nil {
		tf.Close()
		return err
	}
	if err := backup.Decrypt(tf, src, key); err != nil {
		tf.Close()
		return fmt.Errorf("appbackup: decrypt archive (wrong master key, or corrupt/tampered backup — the volume was NOT touched): %w", err)
	}
	if _, err := tf.Seek(0, io.SeekStart); err != nil {
		tf.Close()
		return err
	}
	// 2. Gunzip the VERIFIED plaintext into the tar sidecar's stdin.
	gz, err := gzip.NewReader(tf)
	if err != nil {
		tf.Close()
		return fmt.Errorf("appbackup: restore gunzip: %w", err)
	}
	argv := []string{"run", "--rm", "-i", "--network", "none", "-v", volume + ":/data", image, "tar", "-x", "-C", "/data"}
	err = r.RunStreamStdinHeld(ctx, argv, gz, onLine)
	tf.Close()
	if err != nil {
		return fmt.Errorf("appbackup: restore extract: %w", err)
	}
	return nil
}

// LocalFile opens a 0600 ciphertext sink under dir/<id>.mbk, returning the file and its path.
// The caller writes the Produce result into it and catalogues it.
func LocalFile(dir, id string) (*os.File, string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", err
	}
	path := filepath.Join(dir, id+".mbk")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	return f, path, err
}
