package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/backup"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/crypto"
	"github.com/daboss2003/mooring/internal/siem/archive"
)

var secLogsT0 = time.Date(2026, 11, 22, 14, 0, 0, 0, time.UTC)

func secLogsTestKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// secLogsTestObjects returns n chained segments' objects in the archive layout (key → bytes),
// encrypted with key, the way internal/siem/archive writes them (its own tests pin the writer).
func secLogsTestObjects(t *testing.T, key []byte, prefix, box string, start time.Time, n int) (map[string][]byte, [][]byte) {
	t.Helper()
	objs := map[string][]byte{}
	var plains [][]byte
	prev := ""
	for i := 0; i < n; i++ {
		hour := start.Add(time.Duration(i) * time.Hour)
		plain := []byte(fmt.Sprintf("segment %d of %s\n", i, box)) // stands in for gzip NDJSON
		var enc bytes.Buffer
		if err := backup.Encrypt(&enc, bytes.NewReader(plain), key, 0); err != nil {
			t.Fatal(err)
		}
		ps, es := sha256.Sum256(plain), sha256.Sum256(enc.Bytes())
		s := archive.Seal{V: 1, Name: fmt.Sprintf("%s-%s-%d.ndjson.gz", hour.Format("2006010215"), box, i+1), Box: box, Hour: hour,
			Seq: i + 1, N: int64(i + 1), Events: 1, First: hour, Last: hour, SHA256: hex.EncodeToString(ps[:]), PrevSHA256: prev,
			EncSHA256: hex.EncodeToString(es[:]), EncBytes: int64(enc.Len()), ArchivedAt: hour.Add(time.Hour)}
		if err := s.Sign(key); err != nil {
			t.Fatal(err)
		}
		sb, _ := json.Marshal(s)
		base := fmt.Sprintf("%sv1/%s/%s-%04d", prefix, hour.Format("2006/01/02/15"), box, i+1)
		objs[base+archive.EncSuffix] = enc.Bytes()
		objs[base+archive.SealSuffix] = sb
		plains = append(plains, plain)
		prev = s.SHA256
	}
	return objs, plains
}

func secLogsWriteObjects(t *testing.T, dir string, objs map[string][]byte) {
	t.Helper()
	for k, b := range objs {
		p := filepath.Join(dir, filepath.FromSlash(k))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// secLogsTestConfig writes a valid config.yaml (dev permissions) and returns its path.
func secLogsTestConfig(t *testing.T, key, prev []byte, s3Endpoint string) string {
	t.Helper()
	t.Setenv(config.DevInsecurePermsEnv, "1")
	hash, err := crypto.HashPassword([]byte("a-strong-password"), crypto.DefaultArgon2Params)
	if err != nil {
		t.Fatal(err)
	}
	y := `bind_addr: "127.0.0.1:9000"
encryption_key: "` + base64.StdEncoding.EncodeToString(key) + `"
ip_allowlist:
  - "203.0.113.10/32"
auth:
  username: "operator"
  password_hash: "` + hash + `"
edge:
  mode: "managed"
  acme_email: "ops@example.com"
  acme_ca: "https://acme.example/directory"
data_dir: "` + t.TempDir() + `"
`
	if prev != nil {
		y += `encryption_key_previous: "` + base64.StdEncoding.EncodeToString(prev) + "\"\n"
	}
	if s3Endpoint != "" {
		y += `security_logs:
  archive:
    s3:
      bucket: "logs"
      endpoint: "` + s3Endpoint + `"
      region: "us-east-1"
      access_key_id: "AKIDTEST"
      secret_access_key: "secret-test-key"
      prefix: "siem/"
      insecure: true
`
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSecurityLogsUsage(t *testing.T) {
	ctx := context.Background()
	var out bytes.Buffer
	if err := secLogsRun(ctx, nil, &out, io.Discard); err == nil {
		t.Error("no subcommand accepted")
	}
	if err := secLogsRun(ctx, []string{"nope"}, &out, io.Discard); err == nil {
		t.Error("unknown subcommand accepted")
	}
	if err := secLogsRun(ctx, []string{"help"}, &out, io.Discard); err != nil || !strings.Contains(out.String(), "security-logs fetch") {
		t.Errorf("help = %v, %q", err, out.String())
	}
	for _, args := range [][]string{{"decrypt"}, {"verify"}, {"fetch", "--from", "2026-11-01"}, {"decrypt", "a", "b"}} {
		if err := secLogsRun(ctx, args, &out, io.Discard); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("%v = %v, want a usage error", args, err)
		}
	}
}

func TestSecurityLogsDecrypt(t *testing.T) {
	key, prev := secLogsTestKey(t), secLogsTestKey(t)
	dir := t.TempDir()
	objs, plains := secLogsTestObjects(t, prev, "", "web-1", secLogsT0, 1)
	secLogsWriteObjects(t, dir, objs)
	in := filepath.Join(dir, "v1/2026/11/22/14/web-1-0001"+archive.EncSuffix)
	cfg := secLogsTestConfig(t, key, prev, "")
	ctx := context.Background()

	// Default output name, flags after the positional argument, previous key fallback.
	var out bytes.Buffer
	if err := secLogsRun(ctx, []string{"decrypt", in, "--config", cfg}, &out, io.Discard); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	want := strings.TrimSuffix(in, ".enc")
	got, err := os.ReadFile(want)
	if err != nil || !bytes.Equal(got, plains[0]) {
		t.Fatalf("decrypted file %s = %q, %v", want, got, err)
	}
	if fi, _ := os.Stat(want); fi.Mode().Perm() != 0o600 {
		t.Errorf("output mode %#o", fi.Mode().Perm())
	}
	if !strings.Contains(out.String(), "encryption_key_previous") {
		t.Errorf("no note that the previous key was used: %q", out.String())
	}
	// Never overwrites.
	os.WriteFile(want, []byte("keep me"), 0o600)
	if err := secLogsRun(ctx, []string{"decrypt", "--config", cfg, in}, &out, io.Discard); err == nil || !strings.Contains(err.Error(), "not overwriting") {
		t.Errorf("overwrite = %v", err)
	}
	if b, _ := os.ReadFile(want); string(b) != "keep me" {
		t.Error("existing output was changed")
	}
	// Stdout.
	out.Reset()
	if err := secLogsRun(ctx, []string{"decrypt", in, "-o", "-", "--config", cfg}, &out, io.Discard); err != nil || !bytes.Equal(out.Bytes(), plains[0]) {
		t.Errorf("stdout decrypt = %v, %q", err, out.String())
	}
	// Wrong key: an error and no output file.
	wrongCfg := secLogsTestConfig(t, secLogsTestKey(t), nil, "")
	o2 := filepath.Join(dir, "wrong.ndjson.gz")
	if err := secLogsRun(ctx, []string{"decrypt", in, "-o", o2, "--config", wrongCfg}, &out, io.Discard); err == nil || !strings.Contains(err.Error(), "does not decrypt") {
		t.Errorf("wrong key = %v", err)
	}
	if _, err := os.Stat(o2); err == nil {
		t.Error("an output file was left for a wrong key")
	}
	// Tampered object: an error, nothing written to stdout.
	b, _ := os.ReadFile(in)
	b[len(b)-3] ^= 1
	bad := filepath.Join(dir, "bad"+archive.EncSuffix)
	os.WriteFile(bad, b, 0o600)
	out.Reset()
	if err := secLogsRun(ctx, []string{"decrypt", bad, "-o", "-", "--config", cfg}, &out, io.Discard); err == nil || out.Len() != 0 {
		t.Errorf("tampered = %v, wrote %d bytes", err, out.Len())
	}
	// A name without .enc needs -o.
	plainIn := filepath.Join(dir, "object.bin")
	os.WriteFile(plainIn, b, 0o600)
	if err := secLogsRun(ctx, []string{"decrypt", plainIn, "--config", cfg}, &out, io.Discard); err == nil || !strings.Contains(err.Error(), "-o") {
		t.Errorf("no .enc suffix = %v", err)
	}
}

func TestSecurityLogsVerify(t *testing.T) {
	key := secLogsTestKey(t)
	cfg := secLogsTestConfig(t, key, nil, "")
	ctx := context.Background()
	objs, _ := secLogsTestObjects(t, key, "", "web-1", secLogsT0, 3)

	good := t.TempDir()
	secLogsWriteObjects(t, good, objs)
	var out bytes.Buffer
	if err := secLogsRun(ctx, []string{"verify", good, "--config", cfg}, &out, io.Discard); err != nil {
		t.Fatalf("verify clean = %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "checked 3 segment(s) from 1 host(s) (web-1)") || !strings.HasSuffix(out.String(), "OK\n") {
		t.Errorf("verify output:\n%s", out.String())
	}

	broken := t.TempDir()
	secLogsWriteObjects(t, broken, objs)
	os.Remove(filepath.Join(broken, "v1/2026/11/22/15/web-1-0002"+archive.EncSuffix))
	os.Remove(filepath.Join(broken, "v1/2026/11/22/15/web-1-0002"+archive.SealSuffix))
	out.Reset()
	err := secLogsRun(ctx, []string{"verify", broken, "--config", cfg}, &out, io.Discard)
	if err == nil || !strings.Contains(out.String(), "problem: box web-1: segment(s) missing before") {
		t.Errorf("broken chain = %v\n%s", err, out.String())
	}

	tampered := t.TempDir()
	secLogsWriteObjects(t, tampered, objs)
	p := filepath.Join(tampered, "v1/2026/11/22/16/web-1-0003"+archive.EncSuffix)
	b, _ := os.ReadFile(p)
	b[30] ^= 1
	os.WriteFile(p, b, 0o600)
	out.Reset()
	if err := secLogsRun(ctx, []string{"verify", tampered, "--config", cfg}, &out, io.Discard); err == nil || !strings.Contains(out.String(), "does not decrypt") {
		t.Errorf("tampered = %v\n%s", err, out.String())
	}

	wrongCfg := secLogsTestConfig(t, secLogsTestKey(t), nil, "")
	out.Reset()
	if err := secLogsRun(ctx, []string{"verify", good, "--config", wrongCfg}, &out, io.Discard); err == nil || !strings.Contains(err.Error(), "6 problem") ||
		!strings.Contains(out.String(), "mac does not verify") || !strings.Contains(out.String(), "checked 3 segment(s): 0 verified") {
		t.Errorf("wrong key = %v\n%s", err, out.String())
	}

	// A forged link (segment 2 deleted, seal 3 pointed at segment 1) is caught without the key.
	forged := t.TempDir()
	secLogsWriteObjects(t, forged, objs)
	os.Remove(filepath.Join(forged, "v1/2026/11/22/15/web-1-0002"+archive.EncSuffix))
	os.Remove(filepath.Join(forged, "v1/2026/11/22/15/web-1-0002"+archive.SealSuffix))
	var s1, s3 archive.Seal
	json.Unmarshal(objs["v1/2026/11/22/14/web-1-0001"+archive.SealSuffix], &s1)
	p3 := filepath.Join(forged, "v1/2026/11/22/16/web-1-0003"+archive.SealSuffix)
	b3, _ := os.ReadFile(p3)
	json.Unmarshal(b3, &s3)
	s3.PrevSHA256, s3.N = s1.SHA256, 2
	b3, _ = json.Marshal(s3)
	os.WriteFile(p3, b3, 0o600)
	out.Reset()
	if err := secLogsRun(ctx, []string{"verify", forged, "--config", cfg}, &out, io.Discard); err == nil || !strings.Contains(out.String(), "mac does not verify") {
		t.Errorf("forged chain = %v\n%s", err, out.String())
	}

	if err := secLogsRun(ctx, []string{"verify", t.TempDir(), "--config", cfg}, &out, io.Discard); err == nil || !strings.Contains(err.Error(), "no archive objects") {
		t.Errorf("empty dir = %v", err)
	}
}

// fakeS3 serves ListObjectsV2 and GET for a fixed object set, path-style.
type fakeS3 struct {
	mu     sync.Mutex
	objs   map[string][]byte
	listed []string
	gets   []string
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/logs") {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if r.URL.Path == "/logs" {
		prefix := r.URL.Query().Get("prefix")
		f.listed = append(f.listed, prefix)
		keys := make([]string, 0, len(f.objs))
		for k := range f.objs {
			if strings.HasPrefix(k, prefix) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteString("<ListBucketResult><IsTruncated>false</IsTruncated>")
		for _, k := range keys {
			fmt.Fprintf(&b, "<Contents><Key>%s</Key><Size>%d</Size></Contents>", k, len(f.objs[k]))
		}
		b.WriteString("</ListBucketResult>")
		io.WriteString(w, b.String())
		return
	}
	key, _ := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), "/logs/"))
	f.gets = append(f.gets, key)
	body, ok := f.objs[key]
	if !ok {
		http.Error(w, "<Error><Code>NoSuchKey</Code></Error>", http.StatusNotFound)
		return
	}
	w.Write(body)
}

func TestSecurityLogsFetch(t *testing.T) {
	key := secLogsTestKey(t)
	objs, _ := secLogsTestObjects(t, key, "siem/", "web-1", secLogsT0.Add(-2*time.Hour), 6) // 12:00 – 17:00
	other, _ := secLogsTestObjects(t, key, "siem/", "db-2", secLogsT0.Add(-26*time.Hour), 1)
	for k, v := range other {
		objs[k] = v // 21 November: outside the range
	}
	// Keys outside the layout or the prefix are never downloaded.
	objs["siem/v1/2026/11/22/14/../../../../../escape.seal.json"] = []byte("{}")
	objs["siem/v1/2026/11/22/14/notes.txt"] = []byte("x")
	objs["elsewhere/v1/2026/11/22/14/web-1-0001.seal.json"] = []byte("{}")
	srv := &fakeS3{objs: objs}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	cfg := secLogsTestConfig(t, key, nil, u.Host)
	ctx := context.Background()

	dir := filepath.Join(t.TempDir(), "out")
	var out bytes.Buffer
	err := secLogsRun(ctx, []string{"fetch", "--from", "2026-11-22T13:30:00Z", "--to", "2026-11-22T16:00:00Z", "-o", dir, "--config", cfg}, &out, io.Discard)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	// Hours 13, 14 and 15 overlap [13:30, 16:00).
	var got []string
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			got = append(got, filepath.ToSlash(rel))
			if fi, _ := d.Info(); fi.Mode().Perm() != 0o600 {
				t.Errorf("%s mode %#o", rel, fi.Mode().Perm())
			}
		}
		return nil
	})
	sort.Strings(got)
	want := []string{
		"v1/2026/11/22/13/web-1-0002" + archive.EncSuffix, "v1/2026/11/22/13/web-1-0002" + archive.SealSuffix,
		"v1/2026/11/22/14/web-1-0003" + archive.EncSuffix, "v1/2026/11/22/14/web-1-0003" + archive.SealSuffix,
		"v1/2026/11/22/15/web-1-0004" + archive.EncSuffix, "v1/2026/11/22/15/web-1-0004" + archive.SealSuffix,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("downloaded:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(out.String(), "fetched 6 object(s) (3 segment(s)") {
		t.Errorf("fetch output %q", out.String())
	}
	if len(srv.listed) != 1 || srv.listed[0] != "siem/v1/2026/11/22/" {
		t.Errorf("listed %v, want the one day prefix", srv.listed)
	}
	for _, g := range srv.gets {
		if strings.Contains(g, "..") || strings.Contains(g, "notes") || strings.HasPrefix(g, "elsewhere") {
			t.Errorf("downloaded a key outside the layout: %s", g)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "escape.seal.json")); err == nil {
		t.Error("a key escaped the output directory")
	}

	// The download verifies (the chain starts mid-way: a note, not a problem).
	out.Reset()
	if err := secLogsRun(ctx, []string{"verify", dir, "--config", cfg}, &out, io.Discard); err != nil {
		t.Errorf("verify fetched = %v\n%s", err, out.String())
	}

	// A second fetch into the same directory refuses to overwrite.
	before := len(srv.gets)
	err = secLogsRun(ctx, []string{"fetch", "--from", "2026-11-22", "--to", "2026-11-22", "-o", dir, "--config", cfg}, &out, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "not overwriting") || len(srv.gets) != before {
		t.Errorf("refetch = %v (gets %d → %d)", err, before, len(srv.gets))
	}

	// A whole-day range (a date alone as --to includes that day) into a fresh directory.
	dir2 := t.TempDir()
	out.Reset()
	if err := secLogsRun(ctx, []string{"fetch", "--from", "2026-11-22", "--to", "2026-11-22", "-o", dir2, "--config", cfg}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "(6 segment(s)") {
		t.Errorf("whole-day fetch: %q", out.String())
	}

	// An empty range prints so and succeeds.
	out.Reset()
	if err := secLogsRun(ctx, []string{"fetch", "--from", "2025-01-01", "--to", "2025-01-02", "-o", t.TempDir(), "--config", cfg}, &out, io.Discard); err != nil || !strings.Contains(out.String(), "no archive objects") {
		t.Errorf("empty range = %v %q", err, out.String())
	}
	if err := secLogsRun(ctx, []string{"fetch", "--from", "2026-11-22", "--to", "2026-11-21", "-o", t.TempDir(), "--config", cfg}, &out, io.Discard); err == nil {
		t.Error("--to before --from accepted")
	}
	// No archive configured.
	noS3 := secLogsTestConfig(t, key, nil, "")
	if err := secLogsRun(ctx, []string{"fetch", "--from", "2026-11-22", "--to", "2026-11-22", "-o", t.TempDir(), "--config", noS3}, &out, io.Discard); err == nil || !strings.Contains(err.Error(), "security_logs.archive.s3") {
		t.Errorf("no s3 = %v", err)
	}
}

func TestSecurityLogsDownloadBounds(t *testing.T) {
	dir := t.TempDir()
	srv := &fakeS3{objs: map[string][]byte{"k": bytes.Repeat([]byte("x"), 100)}}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	cl, err := s3ClientFor(&config.BackupS3{Bucket: "logs", Endpoint: u.Host, Region: "r", AccessKeyID: "a", SecretAccessKey: "s", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "a", "k")
	if _, err := secLogsDownload(context.Background(), cl, "k", p, 50); err == nil {
		t.Error("an object over the cap was downloaded")
	}
	if _, err := os.Stat(p); err == nil {
		t.Error("a partial file was left behind")
	}
	if n, err := secLogsDownload(context.Background(), cl, "k", p, 100); err != nil || n != 100 {
		t.Errorf("download = %d, %v", n, err)
	}

	// Without a Content-Length (chunked) the cap still holds.
	chunked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 10; i++ {
			w.Write(bytes.Repeat([]byte("y"), 10))
			w.(http.Flusher).Flush()
		}
	}))
	defer chunked.Close()
	cu, _ := url.Parse(chunked.URL)
	cl2, _ := s3ClientFor(&config.BackupS3{Bucket: "logs", Endpoint: cu.Host, Region: "r", AccessKeyID: "a", SecretAccessKey: "s", Insecure: true})
	p2 := filepath.Join(dir, "chunked")
	if _, err := secLogsDownload(context.Background(), cl2, "k", p2, 50); err == nil {
		t.Error("a chunked object over the cap was downloaded")
	}
	if _, err := os.Stat(p2); err == nil {
		t.Error("a partial chunked file was left behind")
	}
}

func TestSecurityLogsTimeAndPrefix(t *testing.T) {
	from, _ := secLogsTime("2026-11-22", false)
	to, _ := secLogsTime("2026-11-22", true)
	if !from.Equal(time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)) || !to.Equal(time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("date range = %v – %v", from, to)
	}
	if ts, err := secLogsTime("2026-11-22T15:04:05+01:00", false); err != nil || !ts.Equal(time.Date(2026, 11, 22, 14, 4, 5, 0, time.UTC)) {
		t.Errorf("RFC 3339 = %v, %v", ts, err)
	}
	if _, err := secLogsTime("22/11/2026", false); err == nil {
		t.Error("a bad time accepted")
	}
	cases := []struct {
		from, to time.Time
		want     string
	}{
		{secLogsT0, secLogsT0.Add(time.Hour), "2026/11/22/14/"},
		{secLogsT0, secLogsT0.Add(90 * time.Minute), "2026/11/22/"},
		{time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC), "2026/11/"},
		{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), "2026/"},
		{time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC), time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), ""},
	}
	for _, c := range cases {
		if got := secLogsHourPrefix(c.from, c.to); got != c.want {
			t.Errorf("secLogsHourPrefix(%v, %v) = %q, want %q", c.from, c.to, got, c.want)
		}
	}
}

func TestSecurityLogsConfigPermissionHint(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	key := secLogsTestKey(t)
	p := secLogsTestConfig(t, key, nil, "")
	os.Chmod(p, 0o200)
	defer os.Chmod(p, 0o600)
	if _, err := secLogsConfig(p); err == nil || !strings.Contains(err.Error(), "mooring user") {
		t.Errorf("unreadable config = %v", err)
	}
}
