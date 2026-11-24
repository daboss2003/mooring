package archive

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// The two objects of an archived segment are <box>-<seq> followed by one of these.
const (
	EncSuffix  = ".ndjson.gz.enc"
	SealSuffix = ".seal.json"
)

const (
	layoutDir   = "v1/"           // the layout version, right after the prefix
	hourLayout  = "2006/01/02/15" // the hour directories under it
	sealVersion = 1
	maxPrefix   = 512
)

// Seal is the JSON object stored next to each archived segment (<box>-<seq>.seal.json).
type Seal struct {
	V          int       `json:"v"`
	Name       string    `json:"name"` // the segment's file name on the host
	Box        string    `json:"box"`  // the host that wrote it
	Hour       time.Time `json:"hour"`
	Seq        int       `json:"seq"`
	N          int64     `json:"n"` // the segment's position in its host's seal order (1, 2, ...)
	Events     int       `json:"events"`
	First      time.Time `json:"first"`
	Last       time.Time `json:"last"`
	SHA256     string    `json:"sha256"`      // of the plaintext segment file, recorded when it was sealed
	PrevSHA256 string    `json:"prev_sha256"` // SHA256 of the segment sealed before it ("" for the first)
	EncSHA256  string    `json:"enc_sha256"`  // of the uploaded .ndjson.gz.enc object
	EncBytes   int64     `json:"enc_bytes"`
	ArchivedAt time.Time `json:"archived_at"`
	// SHA256Mismatch is set when the file no longer hashed to SHA256 at upload time: it changed on
	// the host after it was sealed. ActualSHA256 is then the hash of what was uploaded.
	SHA256Mismatch bool   `json:"sha256_mismatch,omitempty"`
	ActualSHA256   string `json:"actual_sha256,omitempty"`
	// MAC is HMAC-SHA256 (hex) of every other field, keyed with siem.DeriveKey(master,
	// siem.KeySeal): without the key a seal can't be edited, so neither can the chain.
	MAC string `json:"mac"`
}

// Sign sets MAC from the master encryption key.
func (s *Seal) Sign(master []byte) error {
	k, err := siem.DeriveKey(master, siem.KeySeal)
	if err != nil {
		return err
	}
	s.MAC = s.mac(k)
	return nil
}

// Authentic reports whether MAC is the seal's mac under one of the master keys. A seal without a
// mac is never authentic.
func (s Seal) Authentic(masters [][]byte) bool {
	for _, m := range masters {
		if k, err := siem.DeriveKey(m, siem.KeySeal); err == nil && s.authenticWith(k) {
			return true
		}
	}
	return false
}

func (s Seal) authenticWith(sealKey []byte) bool {
	return s.MAC != "" && hmac.Equal([]byte(s.MAC), []byte(s.mac(sealKey)))
}

func (s Seal) mac(sealKey []byte) string {
	h := hmac.New(sha256.New, sealKey)
	h.Write(s.canonical())
	return hex.EncodeToString(h.Sum(nil))
}

// canonical is the byte form the mac covers: every field but MAC, in a fixed order, each value
// quoted, times as RFC 3339 UTC, so it doesn't depend on how the JSON was written.
func (s Seal) canonical() []byte {
	var b strings.Builder
	b.WriteString("mooring siem seal v1\n")
	f := func(k, v string) {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(strconv.Quote(v))
		b.WriteByte('\n')
	}
	ts := func(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
	f("v", strconv.Itoa(s.V))
	f("name", s.Name)
	f("box", s.Box)
	f("hour", ts(s.Hour))
	f("seq", strconv.Itoa(s.Seq))
	f("n", strconv.FormatInt(s.N, 10))
	f("events", strconv.Itoa(s.Events))
	f("first", ts(s.First))
	f("last", ts(s.Last))
	f("sha256", s.SHA256)
	f("prev_sha256", s.PrevSHA256)
	f("enc_sha256", s.EncSHA256)
	f("enc_bytes", strconv.FormatInt(s.EncBytes, 10))
	f("archived_at", ts(s.ArchivedAt))
	f("sha256_mismatch", strconv.FormatBool(s.SHA256Mismatch))
	f("actual_sha256", s.ActualSHA256)
	return []byte(b.String())
}

// KeyInfo is what an archive object key says about its object.
type KeyInfo struct {
	Hour time.Time // UTC
	Box  string
	Seq  int
	Seal bool // the .seal.json object; false for the .ndjson.gz.enc one
}

// Base is the object's file name without its suffix: <box>-<seq>.
func (k KeyInfo) Base() string { return baseName(k.Box, k.Seq) }

func baseName(box string, seq int) string { return fmt.Sprintf("%s-%04d", box, seq) }

// objectKeys returns the keys of a segment's object and seal.
func objectKeys(prefix, box string, hour time.Time, seq int) (enc, seal string) {
	dir := prefix + layoutDir + hour.UTC().Format(hourLayout) + "/" + baseName(box, seq)
	return dir + EncSuffix, dir + SealSuffix
}

// ParseKey parses key as an object of the v1 layout under prefix
// (<prefix>v1/YYYY/MM/DD/HH/<box>-<seq>.ndjson.gz.enc or .seal.json). ok is false for any key that
// doesn't match it exactly: another prefix, a non-canonical date, an unsafe name, another suffix.
func ParseKey(prefix, key string) (KeyInfo, bool) {
	rest, found := strings.CutPrefix(key, prefix+layoutDir)
	if !found {
		return KeyInfo{}, false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 5 {
		return KeyInfo{}, false
	}
	hour, ok := parseHourDirs(parts[:4])
	if !ok {
		return KeyInfo{}, false
	}
	file := parts[4]
	var ki KeyInfo
	base, isEnc := strings.CutSuffix(file, EncSuffix)
	if !isEnc {
		var isSeal bool
		if base, isSeal = strings.CutSuffix(file, SealSuffix); !isSeal {
			return KeyInfo{}, false
		}
		ki.Seal = true
	}
	box, seq, ok := parseBase(base)
	if !ok || !siem.SafeName(file) {
		return KeyInfo{}, false
	}
	ki.Hour, ki.Box, ki.Seq = hour, box, seq
	return ki, true
}

// parseHourDirs parses the four YYYY, MM, DD, HH elements, accepting only the canonical form.
func parseHourDirs(el []string) (time.Time, bool) {
	if len(el) != 4 {
		return time.Time{}, false
	}
	s := strings.Join(el, "/")
	t, err := time.Parse(hourLayout, s)
	if err != nil || t.Format(hourLayout) != s {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// parseBase splits <box>-<seq> (the box may itself contain '-').
func parseBase(base string) (string, int, bool) {
	i := strings.LastIndexByte(base, '-')
	if i <= 0 {
		return "", 0, false
	}
	box, digits := base[:i], base[i+1:]
	if !siem.SafeName(box) || len(digits) < 4 || len(digits) > 9 {
		return "", 0, false
	}
	seq, err := strconv.Atoi(digits)
	if err != nil || seq < 0 || fmt.Sprintf("%04d", seq) != digits {
		return "", 0, false
	}
	return box, seq, true
}

// checkPrefix accepts "" or a '/'-terminated path whose every element passes siem.SafeName.
func checkPrefix(p string) error {
	if p == "" {
		return nil
	}
	if len(p) > maxPrefix {
		return fmt.Errorf("archive: prefix is longer than %d bytes", maxPrefix)
	}
	if !strings.HasSuffix(p, "/") {
		return errors.New("archive: prefix must be empty or end in '/'")
	}
	for _, el := range strings.Split(strings.TrimSuffix(p, "/"), "/") {
		if !siem.SafeName(el) {
			return fmt.Errorf("archive: prefix element %q is not allowed (letters, digits, '.', '_', '-'; not starting with '.')", el)
		}
	}
	return nil
}

// checkBox accepts a box name that passes siem.SafeName and still does in an object name.
func checkBox(box string) error {
	if !siem.SafeName(box) || !siem.SafeName(baseName(box, 0)+EncSuffix) {
		return fmt.Errorf("archive: box name %q is not allowed (letters, digits, '.', '_', '-'; not starting with '.'; at most %d bytes)", box, 128-len("-0000"+EncSuffix))
	}
	return nil
}
