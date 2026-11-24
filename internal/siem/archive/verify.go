package archive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/backup"
	"github.com/daboss2003/mooring/internal/siem"
)

// ErrNoKey is returned when an archive object opens with none of the keys: a wrong key, or a
// corrupt or tampered object (the two can't be told apart).
var ErrNoKey = errors.New("archive: the object does not decrypt with the given keys (wrong key, or a corrupt or tampered object)")

const (
	maxSealBytes   = 64 << 10
	maxVerifyFiles = 1 << 20
	maxProblems    = 1000
)

// Decrypt writes the plaintext of one archive object (the gzip NDJSON segment) to dst. It first
// authenticates the whole object with each key in turn and decrypts with the first that opens it,
// so nothing reaches dst unless the object is intact; src is read twice. It returns the index of
// the key used.
func Decrypt(dst io.Writer, src io.ReadSeeker, keys [][]byte) (int, error) {
	used := -1
	for i, k := range keys {
		if _, err := src.Seek(0, io.SeekStart); err != nil {
			return -1, err
		}
		if backup.Decrypt(io.Discard, src, k) == nil {
			used = i
			break
		}
	}
	if used < 0 {
		return -1, ErrNoKey
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return -1, err
	}
	if err := backup.Decrypt(dst, src, keys[used]); err != nil {
		return -1, err
	}
	return used, nil
}

// Report is what Verify found.
type Report struct {
	Segments     int       // seals read
	Verified     int       // segments whose object decrypted and matched its seal
	Boxes        []string  // the hosts seen, sorted
	First, Last  time.Time // the oldest and newest segment hour
	Ignored      int       // files that are neither seals nor objects
	Problems     []string  // the first problems found (at most 1000)
	ProblemCount int       // every problem found
	Notes        []string  // not problems: where each host's chain starts
}

func (r *Report) problem(format string, args ...any) {
	r.ProblemCount++
	if len(r.Problems) < maxProblems {
		r.Problems = append(r.Problems, fmt.Sprintf(format, args...))
	}
}

type verifyEntry struct {
	label string // the seal's path relative to dir, without SealSuffix
	seal  Seal
}

// Verify checks a directory tree of downloaded archive objects (.ndjson.gz.enc + .seal.json):
// every object has a seal and every seal an object; each seal's mac verifies with one of keys;
// each object decrypts with one of keys; the plaintext's SHA-256 is the seal's sha256, and the
// object's size and SHA-256 are the seal's enc_bytes and enc_sha256; no seal is flagged
// sha256_mismatch; file names and hour directories agree with the seals; and each box's
// prev_sha256 links form one chain, n increasing along it, with no gaps, forks or restarts. Only
// seals whose mac verifies take part in the chain. The directory is untrusted: symlinks are not
// followed and seals are size-capped. The error is only for a directory that can't be walked.
func Verify(ctx context.Context, dir string, keys [][]byte) (Report, error) {
	var rep Report
	var sealKeys [][]byte
	for _, k := range keys {
		if sk, err := siem.DeriveKey(k, siem.KeySeal); err == nil {
			sealKeys = append(sealKeys, sk)
		}
	}
	seals := map[string]string{} // rel path without suffix -> abs path of the seal
	encs := map[string]string{}  // same, for objects
	files := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if files++; files > maxVerifyFiles {
			return fmt.Errorf("more than %d files under %s", maxVerifyFiles, dir)
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !d.Type().IsRegular() {
			rep.Ignored++
			return nil
		}
		switch {
		case strings.HasSuffix(rel, SealSuffix):
			seals[strings.TrimSuffix(rel, SealSuffix)] = p
		case strings.HasSuffix(rel, EncSuffix):
			encs[strings.TrimSuffix(rel, EncSuffix)] = p
		default:
			rep.Ignored++
		}
		return nil
	})
	if err != nil {
		return rep, err
	}

	labels := make([]string, 0, len(seals))
	for l := range seals {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	byBox := map[string][]verifyEntry{}
	for _, label := range labels {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		rep.Segments++
		s, ok, authentic := readSeal(&rep, label, seals[label], sealKeys)
		encPath, hasEnc := encs[label]
		delete(encs, label)
		if !ok {
			continue
		}
		if !hasEnc {
			rep.problem("%s: the seal has no %s object", label, EncSuffix)
		} else if checkObject(&rep, label, encPath, s, keys, authentic) && authentic {
			rep.Verified++
		}
		if !authentic {
			continue // an edited or foreign seal says nothing about the chain
		}
		byBox[s.Box] = append(byBox[s.Box], verifyEntry{label: label, seal: s})
		h := s.Hour.UTC()
		if rep.First.IsZero() || h.Before(rep.First) {
			rep.First = h
		}
		if h.After(rep.Last) {
			rep.Last = h
		}
	}
	orphans := make([]string, 0, len(encs))
	for l := range encs {
		orphans = append(orphans, l)
	}
	sort.Strings(orphans)
	for _, l := range orphans {
		rep.problem("%s%s: the object has no seal", l, EncSuffix)
	}

	for box := range byBox {
		rep.Boxes = append(rep.Boxes, box)
	}
	sort.Strings(rep.Boxes)
	for _, box := range rep.Boxes {
		checkChain(&rep, box, byBox[box])
	}
	return rep, nil
}

// readSeal reads and checks one seal file; ok is false when the seal can't be used at all, and
// authentic reports that its mac verifies (and it has a chain position).
func readSeal(rep *Report, label, p string, sealKeys [][]byte) (s Seal, ok, authentic bool) {
	f, err := os.Open(p)
	if err != nil {
		rep.problem("%s: %v", label, err)
		return s, false, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSealBytes+1))
	if err != nil {
		rep.problem("%s: %v", label, err)
		return s, false, false
	}
	if len(b) > maxSealBytes {
		rep.problem("%s: the seal is larger than %d bytes", label, maxSealBytes)
		return s, false, false
	}
	if err := json.Unmarshal(b, &s); err != nil {
		rep.problem("%s: the seal is not valid JSON: %v", label, err)
		return s, false, false
	}
	switch {
	case s.V != sealVersion:
		rep.problem("%s: unknown seal version %d", label, s.V)
		return s, false, false
	case !siem.SafeName(s.Box) || s.Seq < 0:
		rep.problem("%s: the seal's box %q or seq %d is not valid", label, siem.Cut(s.Box, 64), s.Seq)
		return s, false, false
	case !isSHA256Hex(s.SHA256) || (s.PrevSHA256 != "" && !isSHA256Hex(s.PrevSHA256)):
		rep.problem("%s: the seal's sha256 or prev_sha256 is not a SHA-256", label)
		return s, false, false
	case s.Hour.IsZero():
		rep.problem("%s: the seal has no hour", label)
		return s, false, false
	}
	switch {
	case s.MAC == "":
		rep.problem("%s: unauthenticated seal (no mac)", label)
	case !macVerifies(s, sealKeys):
		rep.problem("%s: the seal's mac does not verify with the key(s) given (an edited seal, or another key)", label)
	case s.N < 1:
		rep.problem("%s: the seal has no chain position (n)", label)
	default:
		authentic = true
	}
	if base := path0(label); base != baseName(s.Box, s.Seq) {
		rep.problem("%s: the file name does not match the seal (box %s, seq %d)", label, s.Box, s.Seq)
	}
	if dirHour, ok := labelHour(label); ok && !dirHour.Equal(s.Hour.UTC().Truncate(time.Hour)) {
		rep.problem("%s: the seal's hour %s does not match its directory", label, s.Hour.UTC().Format(time.RFC3339))
	}
	if s.SHA256Mismatch {
		rep.problem("%s: the archiver found this segment changed on the host after it was sealed (sealed sha256 %s, uploaded %s)",
			label, s.SHA256, siem.Cut(s.ActualSHA256, 64))
	}
	return s, true, authentic
}

func macVerifies(s Seal, sealKeys [][]byte) bool {
	for _, k := range sealKeys {
		if s.authenticWith(k) {
			return true
		}
	}
	return false
}

// checkObject decrypts one object and, when its seal is authentic (compare), compares the two.
func checkObject(rep *Report, label, p string, s Seal, keys [][]byte, compare bool) bool {
	f, err := os.Open(p)
	if err != nil {
		rep.problem("%s%s: %v", label, EncSuffix, err)
		return false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		rep.problem("%s%s: %v", label, EncSuffix, err)
		return false
	}
	var plainH, encH hash.Hash
	opened := false
	for _, k := range keys {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			rep.problem("%s%s: %v", label, EncSuffix, err)
			return false
		}
		plainH, encH = sha256.New(), sha256.New()
		if backup.Decrypt(plainH, io.TeeReader(f, encH), k) == nil {
			opened = true
			break
		}
	}
	if !opened {
		rep.problem("%s%s: does not decrypt with the key(s) given (wrong key, or a corrupt or tampered object)", label, EncSuffix)
		return false
	}
	if !compare {
		return false // the seal's hashes can't be trusted, so there is nothing to compare with
	}
	ok := true
	if fi.Size() != s.EncBytes || hex.EncodeToString(encH.Sum(nil)) != s.EncSHA256 {
		rep.problem("%s%s: the object's size or SHA-256 differs from the seal's enc_bytes/enc_sha256", label, EncSuffix)
		ok = false
	}
	if hex.EncodeToString(plainH.Sum(nil)) != s.SHA256 {
		rep.problem("%s%s: the decrypted segment's SHA-256 differs from the seal's sha256", label, EncSuffix)
		ok = false
	}
	return ok && !s.SHA256Mismatch
}

// checkChain follows one box's prev_sha256 links, in n order (n, not the hour: a clock stepped
// back can seal an earlier hour after a later one). The earliest segment may point outside the
// directory (an earlier range); every other break is a problem.
func checkChain(rep *Report, box string, es []verifyEntry) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].seal.N != es[j].seal.N {
			return es[i].seal.N < es[j].seal.N
		}
		return es[i].label < es[j].label
	})
	bySHA := map[string]int{}
	dup := make([]bool, len(es))
	for i, e := range es {
		if j, seen := bySHA[e.seal.SHA256]; seen {
			rep.problem("%s: same sha256 as %s (a duplicate segment)", e.label, es[j].label)
			dup[i] = true
			continue
		}
		bySHA[e.seal.SHA256] = i
	}
	for i := 1; i < len(es); i++ {
		if !dup[i] && es[i].seal.N == es[i-1].seal.N {
			rep.problem("box %s: %s and %s are both at chain position %d", box, es[i-1].label, es[i].label, es[i].seal.N)
		}
	}
	children := map[string][]int{}
	var heads []int
	for i, e := range es {
		if dup[i] {
			continue
		}
		prev := e.seal.PrevSHA256
		if _, inSet := bySHA[prev]; prev == "" || !inSet {
			heads = append(heads, i)
			continue
		}
		children[prev] = append(children[prev], i)
	}
	for i := range es { // in chain order, so the report is stable
		kids := children[es[i].seal.SHA256]
		if dup[i] || len(kids) < 2 {
			continue
		}
		names := make([]string, len(kids))
		for n, k := range kids {
			names[n] = es[k].label
		}
		rep.problem("box %s: %s all follow %s (a fork in the chain)", box, strings.Join(names, ", "), es[i].label)
	}
	for n, h := range heads {
		e := es[h]
		switch {
		case n == 0 && e.seal.PrevSHA256 == "":
			rep.Notes = append(rep.Notes, fmt.Sprintf("box %s: the chain starts at its first segment, %s", box, e.label))
		case n == 0:
			rep.Notes = append(rep.Notes, fmt.Sprintf("box %s: the chain starts at %s; the segments before it are not in this directory", box, e.label))
		case e.seal.PrevSHA256 == "":
			rep.problem("box %s: the chain restarts at %s (prev_sha256 is empty)", box, e.label)
		default:
			rep.problem("box %s: segment(s) missing before %s (its prev_sha256 %s is not in this directory)", box, e.label, e.seal.PrevSHA256[:12])
		}
	}
	// Walk from the heads; whatever is unreachable sits in a loop of links.
	seen := make([]bool, len(es))
	for _, h := range heads {
		for i := h; i >= 0 && !seen[i]; {
			seen[i] = true
			next := -1
			for _, k := range children[es[i].seal.SHA256] {
				if !seen[k] {
					if es[k].seal.N <= es[i].seal.N {
						rep.problem("box %s: %s follows %s but its n does not increase (%d after %d)", box, es[k].label, es[i].label, es[k].seal.N, es[i].seal.N)
					}
					if next < 0 {
						next = k
					}
				}
			}
			i = next
		}
	}
	for i, e := range es {
		if !seen[i] && !dup[i] {
			rep.problem("box %s: %s is not reachable from the start of the chain (a loop of links)", box, e.label)
		}
	}
}

// path0 is the last element of a slash path.
func path0(label string) string {
	if i := strings.LastIndexByte(label, '/'); i >= 0 {
		return label[i+1:]
	}
	return label
}

// labelHour parses the YYYY/MM/DD/HH directories right above a seal, when they are there.
func labelHour(label string) (time.Time, bool) {
	parts := strings.Split(label, "/")
	if len(parts) < 5 {
		return time.Time{}, false
	}
	return parseHourDirs(parts[len(parts)-5 : len(parts)-1])
}
