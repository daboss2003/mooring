package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/s3"
	"github.com/daboss2003/mooring/internal/siem/archive"
)

const securityLogsUsage = `Usage:
  mooring security-logs decrypt <file.ndjson.gz.enc> [-o out.ndjson.gz] [--config PATH]
  mooring security-logs verify <dir> [--config PATH]
  mooring security-logs fetch --from <time> --to <time> -o <dir> [--config PATH]

  decrypt  Decrypt one archive object to its gzip NDJSON (-o - writes to stdout; the
           default output is the input path without .enc). Tries encryption_key, then
           encryption_key_previous. An existing file is never overwritten.
  verify   Check a directory of downloaded objects: each one decrypts, matches its seal,
           and every host's hash chain is unbroken. Exits 1 on any problem.
  fetch    Download the objects of a time range from security_logs.archive.s3, still
           encrypted, under <dir> by object key. <time> is RFC 3339 or YYYY-MM-DD (UTC);
           a date alone as --to includes that whole day. Refuses to overwrite files.

Run as root or as the mooring user (the config file holds the key).
`

// secLogsMaxSeal and secLogsMaxObject cap one downloaded seal and object (the archive never
// uploads an object over S3's 5 GiB single PUT).
const (
	secLogsMaxSeal   = 64 << 10
	secLogsMaxObject = 5 << 30
)

// cmdSecurityLogs works with the encrypted security-log archive (docs/cli.md).
func cmdSecurityLogs(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return secLogsRun(ctx, args, os.Stdout, os.Stderr)
}

func secLogsRun(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: mooring security-logs <decrypt|verify|fetch> [flags] (see: mooring security-logs help)")
	}
	switch args[0] {
	case "decrypt":
		return secLogsDecryptCmd(args[1:], stdout, stderr)
	case "verify":
		return secLogsVerifyCmd(ctx, args[1:], stdout)
	case "fetch":
		return secLogsFetchCmd(ctx, args[1:], stdout)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, securityLogsUsage)
		return nil
	default:
		return fmt.Errorf("unknown security-logs command %q (try: decrypt, verify, fetch)", args[0])
	}
}

func secLogsDecryptCmd(args []string, stdout, stderr io.Writer) error {
	fl := flag.NewFlagSet("security-logs decrypt", flag.ContinueOnError)
	configPath := fl.String("config", config.DefaultPath, "path to config.yaml")
	out := fl.String("o", "", "output file (default: the input path without .enc; - for stdout)")
	pos, err := secLogsParse(fl, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: mooring security-logs decrypt <file.ndjson.gz.enc> [-o out.ndjson.gz]")
	}
	cfg, err := secLogsConfig(*configPath)
	if err != nil {
		return err
	}
	keys, err := secLogsKeys(cfg)
	if err != nil {
		return err
	}
	return secLogsDecrypt(pos[0], *out, keys, stdout, stderr)
}

// secLogsDecrypt decrypts the object at in to out ("" = in without .enc, "-" = stdout). The
// whole object is authenticated before anything is written.
func secLogsDecrypt(in, out string, keys [][]byte, stdout, stderr io.Writer) error {
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return err
	} else if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", in)
	}
	if out == "" {
		trimmed, ok := strings.CutSuffix(in, ".enc")
		if !ok || trimmed == "" {
			return fmt.Errorf("%s does not end in .enc; name the output with -o", in)
		}
		out = trimmed
	}
	if out == "-" {
		idx, err := archive.Decrypt(stdout, f, keys)
		if err != nil {
			return secLogsDecryptErr(err)
		}
		if idx == 1 {
			fmt.Fprintln(stderr, "decrypted with encryption_key_previous")
		}
		return nil
	}
	w, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s already exists; not overwriting it", out)
	}
	if err != nil {
		return err
	}
	cw := &secLogsCounter{w: w}
	idx, derr := archive.Decrypt(cw, f, keys)
	cerr := w.Close()
	if derr != nil || cerr != nil {
		os.Remove(out)
		if derr != nil {
			return secLogsDecryptErr(derr)
		}
		return cerr
	}
	fmt.Fprintf(stdout, "wrote %s (%d bytes, gzip NDJSON)\n", out, cw.n)
	if idx == 1 {
		fmt.Fprintln(stdout, "decrypted with encryption_key_previous")
	}
	return nil
}

func secLogsDecryptErr(err error) error {
	if errors.Is(err, archive.ErrNoKey) {
		return errors.New("the object does not decrypt with encryption_key or encryption_key_previous (wrong key, or a corrupt or tampered object)")
	}
	return err
}

func secLogsVerifyCmd(ctx context.Context, args []string, stdout io.Writer) error {
	fl := flag.NewFlagSet("security-logs verify", flag.ContinueOnError)
	configPath := fl.String("config", config.DefaultPath, "path to config.yaml")
	pos, err := secLogsParse(fl, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: mooring security-logs verify <dir>")
	}
	cfg, err := secLogsConfig(*configPath)
	if err != nil {
		return err
	}
	keys, err := secLogsKeys(cfg)
	if err != nil {
		return err
	}
	return secLogsVerify(ctx, pos[0], keys, stdout)
}

// secLogsVerify prints what archive.Verify found and fails on any problem.
func secLogsVerify(ctx context.Context, dir string, keys [][]byte, w io.Writer) error {
	if fi, err := os.Stat(dir); err != nil {
		return err
	} else if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	rep, err := archive.Verify(ctx, dir, keys)
	if err != nil {
		return err
	}
	for _, n := range rep.Notes {
		fmt.Fprintf(w, "note: %s\n", n)
	}
	for _, p := range rep.Problems {
		fmt.Fprintf(w, "problem: %s\n", p)
	}
	if more := rep.ProblemCount - len(rep.Problems); more > 0 {
		fmt.Fprintf(w, "problem: %d more not shown\n", more)
	}
	if rep.Segments == 0 {
		if rep.ProblemCount > 0 {
			return fmt.Errorf("%d problem(s) found", rep.ProblemCount)
		}
		return fmt.Errorf("no archive objects (%s) under %s", archive.SealSuffix, dir)
	}
	if len(rep.Boxes) == 0 {
		fmt.Fprintf(w, "checked %d segment(s): %d verified\n", rep.Segments, rep.Verified)
	} else {
		fmt.Fprintf(w, "checked %d segment(s) from %d host(s) (%s), %s to %s: %d verified\n",
			rep.Segments, len(rep.Boxes), strings.Join(rep.Boxes, ", "),
			rep.First.Format("2006-01-02T15:04Z"), rep.Last.Format("2006-01-02T15:04Z"), rep.Verified)
	}
	if rep.Ignored > 0 {
		fmt.Fprintf(w, "ignored %d other file(s)\n", rep.Ignored)
	}
	if rep.ProblemCount > 0 {
		return fmt.Errorf("%d problem(s) found", rep.ProblemCount)
	}
	fmt.Fprintln(w, "OK")
	return nil
}

func secLogsFetchCmd(ctx context.Context, args []string, stdout io.Writer) error {
	fl := flag.NewFlagSet("security-logs fetch", flag.ContinueOnError)
	configPath := fl.String("config", config.DefaultPath, "path to config.yaml")
	fromS := fl.String("from", "", "start: RFC 3339 or YYYY-MM-DD (UTC)")
	toS := fl.String("to", "", "end: RFC 3339 or YYYY-MM-DD (UTC; a date alone includes that day)")
	outDir := fl.String("o", "", "directory to download into")
	pos, err := secLogsParse(fl, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 || *fromS == "" || *toS == "" || *outDir == "" {
		return errors.New("usage: mooring security-logs fetch --from <time> --to <time> -o <dir>")
	}
	from, err := secLogsTime(*fromS, false)
	if err != nil {
		return fmt.Errorf("--from: %w", err)
	}
	to, err := secLogsTime(*toS, true)
	if err != nil {
		return fmt.Errorf("--to: %w", err)
	}
	if !to.After(from) {
		return errors.New("--to must be after --from")
	}
	cfg, err := secLogsConfig(*configPath)
	if err != nil {
		return err
	}
	sc := cfg.SecurityLogs.Archive.S3
	if sc == nil {
		return fmt.Errorf("security_logs.archive.s3 is not set in %s", *configPath)
	}
	cl, err := secLogsS3Client(sc)
	if err != nil {
		return err
	}
	return secLogsFetch(ctx, cl, sc.Prefix, from, to, *outDir, stdout)
}

// secLogsBucket is the part of *s3.Client fetch uses.
type secLogsBucket interface {
	List(ctx context.Context, prefix string) ([]s3.Object, error)
	Get(ctx context.Context, key string) (io.ReadCloser, int64, error)
}

// secLogsFetch downloads every object (both .enc and .seal.json) whose hour overlaps [from, to)
// to dir/<key without the prefix>.
func secLogsFetch(ctx context.Context, b secLogsBucket, prefix string, from, to time.Time, dir string, w io.Writer) error {
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		return fmt.Errorf("security_logs.archive.s3.prefix %q must end with '/'", prefix)
	}
	objs, err := b.List(ctx, prefix+"v1/"+secLogsHourPrefix(from, to))
	if err != nil {
		return err
	}
	type want struct {
		key, path string
		max       int64
	}
	var wants []want
	segments := 0
	for _, o := range objs {
		// ParseKey accepts only the exact layout with safe names, so a key can't point the local
		// path outside dir.
		ki, ok := archive.ParseKey(prefix, o.Key)
		if !ok || !ki.Hour.Before(to) || !ki.Hour.Add(time.Hour).After(from) {
			continue
		}
		max := int64(secLogsMaxObject)
		if ki.Seal {
			max = secLogsMaxSeal
			segments++
		}
		wants = append(wants, want{o.Key, filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(o.Key, prefix))), max})
	}
	if len(wants) == 0 {
		fmt.Fprintf(w, "no archive objects between %s and %s\n", from.Format(time.RFC3339), to.Format(time.RFC3339))
		return nil
	}
	sort.Slice(wants, func(i, j int) bool { return wants[i].key < wants[j].key })
	exist := 0
	for _, x := range wants {
		if _, err := os.Lstat(x.path); err == nil {
			exist++
		}
	}
	if exist > 0 {
		return fmt.Errorf("%d of the %d files already exist under %s; not overwriting (use an empty directory)", exist, len(wants), dir)
	}
	var total int64
	for _, x := range wants {
		n, err := secLogsDownload(ctx, b, x.key, x.path, x.max)
		if err != nil {
			return fmt.Errorf("%s: %w", x.key, err)
		}
		total += n
	}
	fmt.Fprintf(w, "fetched %d object(s) (%d segment(s), %d bytes) to %s\n", len(wants), segments, total, dir)
	return nil
}

// secLogsDownload writes one object to path (which must not exist), at most max bytes.
func secLogsDownload(ctx context.Context, b secLogsBucket, key, path string, max int64) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return 0, err
	}
	body, size, err := b.Get(ctx, key)
	if err != nil {
		return 0, err
	}
	defer body.Close()
	if size > max {
		return 0, fmt.Errorf("the object is %d bytes, over the %d-byte limit", size, max)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, io.LimitReader(body, max+1))
	switch {
	case err != nil:
	case n > max:
		err = fmt.Errorf("the object is over the %d-byte limit", max)
	case size >= 0 && n != size:
		err = fmt.Errorf("read %d of %d bytes", n, size)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return 0, err
	}
	return n, nil
}

// secLogsHourPrefix is the longest YYYY/MM/DD/HH/ directory prefix shared by every hour in
// [from, to), so one listing covers the range.
func secLogsHourPrefix(from, to time.Time) string {
	a := strings.Split(from.UTC().Format("2006/01/02/15"), "/")
	b := strings.Split(to.Add(-time.Nanosecond).UTC().Format("2006/01/02/15"), "/")
	var p string
	for i := range a {
		if a[i] != b[i] {
			break
		}
		p += a[i] + "/"
	}
	return p
}

// secLogsTime parses RFC 3339 or a UTC date; a date as the end of a range means the end of that
// day.
func secLogsTime(s string, end bool) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is not RFC 3339 (2026-11-22T14:00:00Z) or a date (2026-11-22)", s)
	}
	if end {
		t = t.Add(24 * time.Hour)
	}
	return t, nil
}

// secLogsParse parses flags given before or after the positional arguments.
func secLogsParse(fl *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fl.Parse(args); err != nil {
			return nil, err
		}
		rest := fl.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func secLogsConfig(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if errors.Is(err, fs.ErrPermission) {
		return nil, fmt.Errorf("%w (run as root or as the mooring user)", err)
	}
	return cfg, err
}

// secLogsKeys is encryption_key, then encryption_key_previous when set.
func secLogsKeys(cfg *config.Config) ([][]byte, error) {
	key, err := config.DecodeKey(cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("decode encryption_key: %w", err)
	}
	keys := [][]byte{key}
	if cfg.EncryptionKeyPrevious != "" {
		prev, err := config.DecodeKey(cfg.EncryptionKeyPrevious)
		if err != nil {
			return nil, fmt.Errorf("decode encryption_key_previous: %w", err)
		}
		keys = append(keys, prev)
	}
	return keys, nil
}

// secLogsS3Client builds the client for an S3 block of config.yaml (path_style unset = true).
func secLogsS3Client(sc *config.BackupS3) (*s3.Client, error) {
	pathStyle := true
	if sc.PathStyle != nil {
		pathStyle = *sc.PathStyle
	}
	return s3.New(s3.Config{
		Endpoint: sc.Endpoint, Region: sc.Region, Bucket: sc.Bucket,
		AccessKeyID: sc.AccessKeyID, SecretAccessKey: sc.SecretAccessKey,
		UsePathStyle: pathStyle, Insecure: sc.Insecure,
	}, nil)
}

type secLogsCounter struct {
	w io.Writer
	n int64
}

func (c *secLogsCounter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
