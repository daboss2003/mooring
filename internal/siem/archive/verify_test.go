package archive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/backup"
)

// archived runs the archiver over n segments and writes the bucket's objects into a directory,
// as `mooring security-logs fetch` would.
func archived(t *testing.T, n int) (*rig, string) {
	t.Helper()
	r := newRig(t, n)
	r.step()
	if r.a.Behind() != 0 || r.a.Err() != "" {
		t.Fatalf("archive run: behind=%d err=%q", r.a.Behind(), r.a.Err())
	}
	out := t.TempDir()
	for key, b := range r.up.objects {
		p := filepath.Join(out, filepath.FromSlash(key))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return r, out
}

func verify(t *testing.T, dir string, keys ...[]byte) Report {
	t.Helper()
	rep, err := Verify(context.Background(), dir, keys)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return rep
}

func hasProblem(rep Report, sub string) bool {
	for _, p := range rep.Problems {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

func objPath(dir string, r *rig, i int, suffix string) string {
	enc, seal := objectKeys("pfx/", "web-1", r.st.segs[i].Hour, r.st.segs[i].Seq)
	if suffix == SealSuffix {
		return filepath.Join(dir, filepath.FromSlash(seal))
	}
	return filepath.Join(dir, filepath.FromSlash(enc))
}

func TestVerifyRoundTrip(t *testing.T) {
	r, dir := archived(t, 4)
	rep := verify(t, dir, r.key)
	if rep.ProblemCount != 0 {
		t.Fatalf("problems on a clean archive: %v", rep.Problems)
	}
	if rep.Segments != 4 || rep.Verified != 4 || len(rep.Boxes) != 1 || rep.Boxes[0] != "web-1" {
		t.Errorf("report = %+v", rep)
	}
	if !rep.First.Equal(t0) || !rep.Last.Equal(t0.Add(3*60*60*1e9)) {
		t.Errorf("range %v – %v", rep.First, rep.Last)
	}
	if len(rep.Notes) != 1 || !strings.Contains(rep.Notes[0], "starts at its first segment") {
		t.Errorf("notes = %v", rep.Notes)
	}
	// Decrypt gives back the segment file exactly.
	f, err := os.Open(objPath(dir, r, 2, EncSuffix))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out bytes.Buffer
	if idx, err := Decrypt(&out, f, [][]byte{r.key}); err != nil || idx != 0 {
		t.Fatalf("Decrypt = %d, %v", idx, err)
	}
	want, _ := os.ReadFile(r.st.segs[2].Path)
	if !bytes.Equal(out.Bytes(), want) {
		t.Error("decrypted object differs from the segment file")
	}
}

func TestVerifyPartialRangeIsNotAProblem(t *testing.T) {
	r, dir := archived(t, 3)
	os.Remove(objPath(dir, r, 0, EncSuffix))
	os.Remove(objPath(dir, r, 0, SealSuffix))
	rep := verify(t, dir, r.key)
	if rep.ProblemCount != 0 {
		t.Fatalf("a range that starts mid-chain reported: %v", rep.Problems)
	}
	if len(rep.Notes) != 1 || !strings.Contains(rep.Notes[0], "not in this directory") {
		t.Errorf("notes = %v", rep.Notes)
	}
}

func TestVerifyTamperedObject(t *testing.T) {
	r, dir := archived(t, 3)
	p := objPath(dir, r, 1, EncSuffix)
	b, _ := os.ReadFile(p)
	b[len(b)-5] ^= 0x01
	os.WriteFile(p, b, 0o600)
	rep := verify(t, dir, r.key)
	if rep.ProblemCount != 1 || !hasProblem(rep, "does not decrypt") || rep.Verified != 2 {
		t.Errorf("tampered object: %d problems %v, verified %d", rep.ProblemCount, rep.Problems, rep.Verified)
	}
}

func TestVerifyTamperedSeal(t *testing.T) {
	r, dir := archived(t, 3)
	p := objPath(dir, r, 1, SealSuffix)
	var s Seal
	b, _ := os.ReadFile(p)
	json.Unmarshal(b, &s)
	s.SHA256 = strings.Repeat("a", 64)
	b, _ = json.Marshal(s)
	os.WriteFile(p, b, 0o600)
	rep := verify(t, dir, r.key)
	// The edited seal fails its mac and leaves the chain, so the next segment's link is broken.
	if !hasProblem(rep, "mac does not verify") || !hasProblem(rep, "missing before") || rep.Verified != 2 {
		t.Errorf("tampered seal: %v (verified %d)", rep.Problems, rep.Verified)
	}
}

// Without the key a gap can't be hidden: deleting a segment and pointing the next seal at the one
// before it breaks that seal's mac.
func TestVerifyForgedChain(t *testing.T) {
	r, dir := archived(t, 4)
	var s0, s2 Seal
	b, _ := os.ReadFile(objPath(dir, r, 0, SealSuffix))
	json.Unmarshal(b, &s0)
	os.Remove(objPath(dir, r, 1, EncSuffix))
	os.Remove(objPath(dir, r, 1, SealSuffix))
	p := objPath(dir, r, 2, SealSuffix)
	b, _ = os.ReadFile(p)
	json.Unmarshal(b, &s2)
	s2.PrevSHA256 = s0.SHA256
	s2.N = s0.N + 1
	b, _ = json.Marshal(s2)
	os.WriteFile(p, b, 0o600)
	rep := verify(t, dir, r.key)
	if !hasProblem(rep, "web-1-0003: the seal's mac does not verify") || !hasProblem(rep, "missing before") {
		t.Errorf("forged chain: %v", rep.Problems)
	}
}

func TestVerifyUnauthenticatedSeal(t *testing.T) {
	r, dir := archived(t, 2)
	p := objPath(dir, r, 1, SealSuffix)
	var raw map[string]any
	b, _ := os.ReadFile(p)
	json.Unmarshal(b, &raw)
	delete(raw, "mac")
	b, _ = json.Marshal(raw)
	os.WriteFile(p, b, 0o600)
	rep := verify(t, dir, r.key)
	if rep.ProblemCount != 1 || !hasProblem(rep, "unauthenticated seal (no mac)") || rep.Verified != 1 {
		t.Errorf("seal without a mac: %v (verified %d)", rep.Problems, rep.Verified)
	}
}

// The chain is ordered by n, not by hour: a clock stepped back across an hour seals an earlier
// hour after a later one, and that is not a problem.
func TestVerifyChainOrderedByN(t *testing.T) {
	r := newRig(t, 2)
	r.st.segs[0].Hour, r.st.segs[1].Hour = t0.Add(time.Hour), t0
	r.step()
	dir := t.TempDir()
	for key, b := range r.up.objects {
		p := filepath.Join(dir, filepath.FromSlash(key))
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, b, 0o600)
	}
	if rep := verify(t, dir, r.key); rep.ProblemCount != 0 || rep.Verified != 2 {
		t.Errorf("clock stepped back: %v", rep.Problems)
	}
}

// n must increase along the chain (checked on seals that do carry a valid mac).
func TestVerifyNMustIncrease(t *testing.T) {
	r, dir := archived(t, 3)
	p := objPath(dir, r, 2, SealSuffix)
	var s Seal
	b, _ := os.ReadFile(p)
	json.Unmarshal(b, &s)
	s.N = 1
	if err := s.Sign(r.key); err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(s)
	os.WriteFile(p, b, 0o600)
	rep := verify(t, dir, r.key)
	if !hasProblem(rep, "n does not increase") || !hasProblem(rep, "both at chain position 1") {
		t.Errorf("n going down: %v", rep.Problems)
	}
	s.N = 0
	s.Sign(r.key)
	b, _ = json.Marshal(s)
	os.WriteFile(p, b, 0o600)
	if rep := verify(t, dir, r.key); !hasProblem(rep, "no chain position") {
		t.Errorf("n = 0: %v", rep.Problems)
	}
}

func TestVerifyBrokenChain(t *testing.T) {
	r, dir := archived(t, 4)
	os.Remove(objPath(dir, r, 1, EncSuffix))
	os.Remove(objPath(dir, r, 1, SealSuffix))
	rep := verify(t, dir, r.key)
	if rep.ProblemCount != 1 || !hasProblem(rep, "missing before") || !hasProblem(rep, "web-1-0003") {
		t.Errorf("missing middle segment: %v", rep.Problems)
	}
}

func TestVerifyMissingHalf(t *testing.T) {
	r, dir := archived(t, 2)
	os.Remove(objPath(dir, r, 0, EncSuffix))
	os.Remove(objPath(dir, r, 1, SealSuffix))
	rep := verify(t, dir, r.key)
	if !hasProblem(rep, "has no "+EncSuffix) || !hasProblem(rep, "has no seal") {
		t.Errorf("half-missing pairs: %v", rep.Problems)
	}
}

func TestVerifyWrongKeyAndPrevious(t *testing.T) {
	r, dir := archived(t, 2)
	wrong := testKey(t)
	rep := verify(t, dir, wrong)
	if rep.ProblemCount != 4 || rep.Verified != 0 || !hasProblem(rep, "does not decrypt") || !hasProblem(rep, "mac does not verify") {
		t.Errorf("wrong key: %v", rep.Problems)
	}
	// The previous key is tried after the current one.
	if rep := verify(t, dir, wrong, r.key); rep.ProblemCount != 0 || rep.Verified != 2 {
		t.Errorf("[wrong, right]: %v", rep.Problems)
	}
	f, _ := os.Open(objPath(dir, r, 0, EncSuffix))
	defer f.Close()
	var out bytes.Buffer
	if _, err := Decrypt(&out, f, [][]byte{wrong}); !errors.Is(err, ErrNoKey) || out.Len() != 0 {
		t.Errorf("Decrypt with a wrong key = %v, wrote %d bytes", err, out.Len())
	}
	if idx, err := Decrypt(&out, f, [][]byte{wrong, r.key}); err != nil || idx != 1 {
		t.Errorf("Decrypt with [wrong, right] = %d, %v", idx, err)
	}
	want, _ := os.ReadFile(r.st.segs[0].Path)
	if !bytes.Equal(out.Bytes(), want) {
		t.Errorf("Decrypt with [wrong, right] wrote %d bytes, want the %d-byte segment once", out.Len(), len(want))
	}
}

// Decrypt writes nothing unless the whole object authenticates: a corrupt later chunk is found
// before the first chunk reaches dst.
func TestDecryptWritesNothingForCorruptObject(t *testing.T) {
	key := testKey(t)
	plain := bytes.Repeat([]byte("0123456789abcdef"), 20<<10) // 320 KiB: several 64 KiB chunks
	var enc bytes.Buffer
	if err := backup.Encrypt(&enc, bytes.NewReader(plain), key, 0); err != nil {
		t.Fatal(err)
	}
	b := enc.Bytes()
	b[len(b)-1] ^= 0xff // in the final chunk
	var out bytes.Buffer
	if _, err := Decrypt(&out, bytes.NewReader(b), [][]byte{key}); err == nil || out.Len() != 0 {
		t.Errorf("Decrypt(corrupt last chunk) = %v, wrote %d bytes", err, out.Len())
	}
	b[len(b)-1] ^= 0xff
	out.Reset()
	if _, err := Decrypt(&out, bytes.NewReader(b), [][]byte{key}); err != nil || !bytes.Equal(out.Bytes(), plain) {
		t.Errorf("Decrypt(intact) = %v, %d bytes", err, out.Len())
	}
}

func TestVerifyFlaggedMismatch(t *testing.T) {
	r := newRig(t, 2)
	os.WriteFile(r.st.segs[0].Path, []byte("forged"), 0o600)
	r.step()
	dir := t.TempDir()
	for key, b := range r.up.objects {
		p := filepath.Join(dir, filepath.FromSlash(key))
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, b, 0o600)
	}
	rep := verify(t, dir, r.key)
	if !hasProblem(rep, "changed on the host after it was sealed") {
		t.Errorf("flagged seal not reported: %v", rep.Problems)
	}
}

func TestVerifyNamesForksRestartsAndHostileFiles(t *testing.T) {
	r, dir := archived(t, 3)
	// A seal whose name disagrees with its content, a restart, an oversized seal, a symlink.
	p2 := objPath(dir, r, 2, SealSuffix)
	var s Seal
	b, _ := os.ReadFile(p2)
	json.Unmarshal(b, &s)
	s.PrevSHA256 = ""
	s.Sign(r.key) // a writer holding the key: the chain checks still catch it
	b, _ = json.Marshal(s)
	os.WriteFile(p2, b, 0o600)

	renamed := filepath.Join(filepath.Dir(p2), "web-1-0042"+SealSuffix)
	os.WriteFile(renamed, b, 0o600)
	os.WriteFile(strings.TrimSuffix(renamed, SealSuffix)+EncSuffix, []byte("x"), 0o600)

	big := filepath.Join(dir, "huge"+SealSuffix)
	os.WriteFile(big, bytes.Repeat([]byte(" "), maxSealBytes+10), 0o600)

	os.Symlink("/etc/passwd", filepath.Join(dir, "link"+SealSuffix))

	rep := verify(t, dir, r.key)
	for _, want := range []string{"restarts at", "file name does not match", "larger than", "duplicate segment"} {
		if !hasProblem(rep, want) {
			t.Errorf("missing problem %q in %v", want, rep.Problems)
		}
	}
	if rep.Ignored < 1 {
		t.Error("the symlink was not ignored")
	}

	// A fork: two segments claim the same predecessor.
	r2, dir2 := archived(t, 3)
	p1 := objPath(dir2, r2, 1, SealSuffix)
	b1, _ := os.ReadFile(p1)
	var s1 Seal
	json.Unmarshal(b1, &s1)
	p3 := objPath(dir2, r2, 2, SealSuffix)
	b3, _ := os.ReadFile(p3)
	var s3 Seal
	json.Unmarshal(b3, &s3)
	s3.PrevSHA256 = s1.PrevSHA256
	s3.Sign(r2.key)
	b3, _ = json.Marshal(s3)
	os.WriteFile(p3, b3, 0o600)
	rep = verify(t, dir2, r2.key)
	if !hasProblem(rep, "fork") {
		t.Errorf("fork not reported: %v", rep.Problems)
	}
}

// An object replaced by another encryption of the same segment still decrypts to the right bytes,
// but it is not the object the seal was written for.
func TestVerifyObjectNotTheSealedOne(t *testing.T) {
	r, dir := archived(t, 2)
	plain, _ := os.ReadFile(r.st.segs[1].Path)
	var enc bytes.Buffer
	if err := backup.Encrypt(&enc, bytes.NewReader(plain), r.key, 0); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(objPath(dir, r, 1, EncSuffix), enc.Bytes(), 0o600)
	rep := verify(t, dir, r.key)
	if rep.ProblemCount != 1 || !hasProblem(rep, "enc_sha256") {
		t.Errorf("swapped object: %v", rep.Problems)
	}
}

func TestVerifyMissingDir(t *testing.T) {
	if _, err := Verify(context.Background(), filepath.Join(t.TempDir(), "nope"), nil); err == nil {
		t.Error("a missing directory must be an error")
	}
}
