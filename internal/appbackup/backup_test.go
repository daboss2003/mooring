package appbackup

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/backup"
)

type fakeRunner struct {
	gotArgv []string
	stdout  []byte
	err     error
}

func (f *fakeRunner) RunStreamHeld(ctx context.Context, argv []string, w io.Writer, onErr func(string)) error {
	f.gotArgv = argv
	if len(f.stdout) > 0 {
		_, _ = w.Write(f.stdout)
	}
	return f.err
}

func TestBuildArgvVolumeReadOnlyNoNetwork(t *testing.T) {
	argv, cleanup, err := buildArgv(Spec{Kind: KindVolume, Volume: "shop_data", Image: "busybox@sha256:abc"}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	got := strings.Join(argv, " ")
	for _, want := range []string{"run --rm", "--network none", "-v shop_data:/data:ro", "busybox@sha256:abc", "tar -c -C /data ."} {
		if !strings.Contains(got, want) {
			t.Errorf("volume argv missing %q in: %s", want, got)
		}
	}
}

// The DB password must NEVER appear on the argv (argv is world-visible in `ps`); it goes only
// into a 0600 --env-file, referenced by path.
func TestBuildArgvPostgresPasswordNotOnArgv(t *testing.T) {
	dir := t.TempDir()
	secret := "sup3r-s3cret-pw"
	argv, cleanup, err := buildArgv(Spec{
		Kind: KindPostgres, Image: "postgres:16", Network: "shop_default",
		Host: "db", User: "app", DBName: "shopdb", Password: secret,
	}, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	joined := strings.Join(argv, " ")
	if strings.Contains(joined, secret) {
		t.Fatalf("password leaked onto argv: %s", joined)
	}
	for _, want := range []string{"run --rm", "--network shop_default", "--env-file", "postgres:16", "pg_dump", "-h db", "-d shopdb", "-U app"} {
		if !strings.Contains(joined, want) {
			t.Errorf("postgres argv missing %q in: %s", want, joined)
		}
	}
	// The env-file must exist, be 0600, and carry PGPASSWORD=<secret>.
	var efPath string
	for i, a := range argv {
		if a == "--env-file" && i+1 < len(argv) {
			efPath = argv[i+1]
		}
	}
	if efPath == "" {
		t.Fatal("no --env-file path on argv")
	}
	fi, err := os.Stat(efPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("env-file perms = %v; want 0600", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(efPath)
	if !strings.Contains(string(b), "PGPASSWORD="+secret) {
		t.Errorf("env-file missing PGPASSWORD; got %q", b)
	}
	// cleanup removes the env-file.
	cleanup()
	if _, err := os.Stat(efPath); !os.IsNotExist(err) {
		t.Errorf("cleanup did not remove the env-file")
	}
}

func TestBuildArgvMySQL(t *testing.T) {
	dir := t.TempDir()
	argv, cleanup, err := buildArgv(Spec{Kind: KindMySQL, Image: "mysql:8", Host: "db", DBName: "app", Password: "x"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	joined := strings.Join(argv, " ")
	for _, want := range []string{"mysqldump", "--single-transaction", "-h db", "app"} {
		if !strings.Contains(joined, want) {
			t.Errorf("mysql argv missing %q in: %s", want, joined)
		}
	}
}

func TestBuildArgvRejectsIncomplete(t *testing.T) {
	if _, _, err := buildArgv(Spec{Kind: KindVolume}, ""); err == nil {
		t.Error("volume without Volume/Image should error")
	}
	if _, _, err := buildArgv(Spec{Kind: KindPostgres, Image: "x"}, t.TempDir()); err == nil {
		t.Error("postgres without Host/DBName should error")
	}
	if _, _, err := buildArgv(Spec{Kind: "bogus"}, ""); err == nil {
		t.Error("unknown kind should error")
	}
}

// Produce streams sidecar-stdout → gzip → Encrypt → sink; the result decrypts + gunzips back
// to the exact producer bytes, and the reported sha256 matches the ciphertext.
func TestProduceRoundTrip(t *testing.T) {
	plaintext := bytes.Repeat([]byte("PGDMP-fake-dump-block;\n"), 500)
	r := &fakeRunner{stdout: plaintext}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	var sink bytes.Buffer
	res, err := Produce(context.Background(), r, Spec{Kind: KindVolume, Volume: "v", Image: "busybox"}, key, &sink, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Ciphertext != int64(sink.Len()) {
		t.Errorf("reported ciphertext %d != sink %d", res.Ciphertext, sink.Len())
	}
	sum := sha256.Sum256(sink.Bytes())
	if res.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("sha mismatch")
	}
	// Decrypt → gunzip → must equal the original producer bytes.
	var dec bytes.Buffer
	if err := backup.Decrypt(&dec, bytes.NewReader(sink.Bytes()), key); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	gz, err := gzip.NewReader(&dec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch: got %d bytes, want %d", len(got), len(plaintext))
	}
}

// A producer (sidecar) failure must fail Produce — a partial dump can never become a valid
// backup.
func TestProduceProducerErrorFails(t *testing.T) {
	r := &fakeRunner{stdout: []byte("partial"), err: io.ErrClosedPipe}
	key := make([]byte, 32)
	var sink bytes.Buffer
	if _, err := Produce(context.Background(), r, Spec{Kind: KindVolume, Volume: "v", Image: "b"}, key, &sink, Options{}); err == nil {
		t.Fatal("a producer error must fail Produce")
	}
}
