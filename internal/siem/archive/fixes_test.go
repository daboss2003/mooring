package archive

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/s3"
	"github.com/daboss2003/mooring/internal/siem"
)

func sealAt(t *testing.T, r *rig, key string) Seal {
	t.Helper()
	var s Seal
	if err := json.Unmarshal(r.up.objects[key], &s); err != nil {
		t.Fatalf("seal %s: %v", key, err)
	}
	return s
}

// The key and the seal name the box that wrote the segment, not the archiver's own: after a
// rename within an hour, both segments of that hour keep their own objects.
func TestKeyUsesSegmentBox(t *testing.T) {
	r := newRig(t, 2)
	r.st.segs[0].Box, r.st.segs[1].Box = "oldname", "newname"
	r.st.segs[1].Hour, r.st.segs[1].Seq = r.st.segs[0].Hour, r.st.segs[0].Seq
	r.step()
	for i, box := range []string{"oldname", "newname"} {
		enc, seal := objectKeys("pfx/", box, r.st.segs[i].Hour, r.st.segs[i].Seq)
		if _, ok := r.up.objects[enc]; !ok {
			t.Fatalf("no object %s: %v", enc, r.up.puts)
		}
		if s := sealAt(t, r, seal); s.Box != box {
			t.Errorf("seal box %q, want %q", s.Box, box)
		}
	}
	if r.a.Behind() != 0 {
		t.Errorf("behind = %d", r.a.Behind())
	}
}

func TestSegmentWithoutBoxOrChainIsRefused(t *testing.T) {
	for name, mut := range map[string]func(*rig){
		"no box":       func(r *rig) { r.st.segs[0].Box = "" },
		"unsafe box":   func(r *rig) { r.st.segs[0].Box = "../x" },
		"no chain pos": func(r *rig) { r.st.segs[0].Chain = 0 },
	} {
		r := newRig(t, 1)
		mut(r)
		r.step()
		if len(r.up.puts) != 0 {
			t.Errorf("%s: uploaded %v", name, r.up.puts)
		}
		if !strings.Contains(r.a.Err(), "invalid segment record") {
			t.Errorf("%s: err = %q", name, r.a.Err())
		}
	}
}

func TestSealCarriesChainPositionAndMAC(t *testing.T) {
	r := newRig(t, 2)
	r.st.segs[0].Chain, r.st.segs[1].Chain = 41, 42
	r.step()
	for _, seg := range r.st.segs {
		_, sk := objectKeys("pfx/", seg.Box, seg.Hour, seg.Seq)
		s := sealAt(t, r, sk)
		if s.N != seg.Chain {
			t.Errorf("seal n = %d, want %d", s.N, seg.Chain)
		}
		if s.MAC == "" || !s.Authentic([][]byte{r.key}) {
			t.Errorf("seal %s is not authentic under the key: %+v", sk, s)
		}
		if s.Authentic([][]byte{testKey(t)}) {
			t.Error("seal authentic under another key")
		}
		if !s.Authentic([][]byte{testKey(t), r.key}) {
			t.Error("seal not authentic when the key is the second one given")
		}
	}
}

// Every field is covered by the mac: changing any one of them breaks it.
func TestSealMACCoversEveryField(t *testing.T) {
	r := newRig(t, 2)
	r.step()
	_, sk := objectKeys("pfx/", "web-1", r.st.segs[1].Hour, r.st.segs[1].Seq)
	var raw map[string]any
	if err := json.Unmarshal(r.up.objects[sk], &raw); err != nil {
		t.Fatal(err)
	}
	// Flagged seals carry two more fields; cover them too.
	raw["sha256_mismatch"], raw["actual_sha256"] = false, ""
	changed := map[string]any{
		"v": 2.0, "name": "x.ndjson.gz", "box": "other", "hour": "2026-11-22T16:00:00Z", "seq": 9.0, "n": 99.0,
		"events": 7.0, "first": "2026-11-22T15:00:01Z", "last": "2026-11-22T15:00:02Z",
		"sha256": strings.Repeat("a", 64), "prev_sha256": strings.Repeat("b", 64), "enc_sha256": strings.Repeat("c", 64),
		"enc_bytes": 1.0, "archived_at": "2027-01-01T00:00:00Z", "sha256_mismatch": true, "actual_sha256": strings.Repeat("d", 64),
	}
	for k := range raw {
		if k == "mac" {
			continue
		}
		if _, ok := changed[k]; !ok {
			t.Errorf("seal field %q has no mutation in this test", k)
		}
	}
	for k, v := range changed {
		m := map[string]any{}
		for kk, vv := range raw {
			m[kk] = vv
		}
		m[k] = v
		b, _ := json.Marshal(m)
		var s Seal
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatal(err)
		}
		if s.Authentic([][]byte{r.key}) {
			t.Errorf("changing %q keeps the seal authentic", k)
		}
	}
	// Unchanged it verifies; without a mac it never does.
	b, _ := json.Marshal(raw)
	var s Seal
	json.Unmarshal(b, &s)
	if !s.Authentic([][]byte{r.key}) {
		t.Fatal("unchanged seal not authentic")
	}
	s.MAC = ""
	if s.Authentic([][]byte{r.key}) {
		t.Error("a seal without a mac is authentic")
	}
}

// A seal at the segment's key that is not this segment's (another host with the same box name,
// or an object changed in the bucket) is never overwritten.
func TestRefuseOverwriteOfDifferentSeal(t *testing.T) {
	for name, other := range map[string]func(r *rig) []byte{
		"another host's seal": func(r *rig) []byte {
			s := Seal{V: 1, Name: "x", Box: "web-1", Hour: t0, Seq: 1, N: 7, SHA256: strings.Repeat("e", 64)}
			if err := s.Sign(r.key); err != nil {
				t.Fatal(err)
			}
			b, _ := json.Marshal(s)
			return b
		},
		"unauthenticated copy of ours": func(r *rig) []byte {
			seg := r.st.segs[0]
			s := Seal{V: 1, Name: seg.Name, Box: seg.Box, Hour: seg.Hour, Seq: seg.Seq, N: seg.Chain, SHA256: seg.SHA256}
			b, _ := json.Marshal(s)
			return b
		},
		"garbage": func(r *rig) []byte { return []byte("not json") },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, 2)
			seg := r.st.segs[0]
			enc, sk := objectKeys("pfx/", seg.Box, seg.Hour, seg.Seq)
			theirs := other(r)
			r.up.objects[sk] = theirs
			r.step()
			for _, p := range r.up.puts {
				if p == enc || p == sk {
					t.Fatalf("overwrote %s", p)
				}
			}
			if string(r.up.objects[sk]) != string(theirs) {
				t.Fatal("the existing seal changed")
			}
			if _, ok := r.st.archived(seg.Name); ok {
				t.Fatal("marked archived")
			}
			if _, ok := r.st.archived(r.st.segs[1].Name); !ok {
				t.Error("the next segment was blocked")
			}
			calls := r.alerts.all()
			if len(calls) != 1 || calls[0].segment != seg.Name || !strings.Contains(calls[0].detail, "not overwriting") {
				t.Fatalf("alerts = %+v, want one SegmentChanged", calls)
			}
			var crit int
			for _, ev := range r.st.events {
				if ev.Kind == siem.KindArchiveFailed && ev.Lvl == siem.LvlCritical {
					crit++
				}
			}
			if crit != 1 || !strings.Contains(r.logs.String(), "level=ERROR") {
				t.Errorf("events=%d, logs:\n%s", crit, r.logs.String())
			}
			if r.a.Behind() != 1 {
				t.Errorf("behind = %d, want 1", r.a.Behind())
			}
			// Once per segment, not every tick.
			r.clk.add(time.Minute)
			r.step()
			if len(r.alerts.all()) != 1 {
				t.Errorf("alerted again: %+v", r.alerts.all())
			}
		})
	}
}

// After a MarkArchived failure the next attempt finds its own complete upload and records it
// without uploading again.
func TestRetryAfterMarkFailureReusesUpload(t *testing.T) {
	r := newRig(t, 1)
	seg := r.st.segs[0]
	r.st.markErr = errors.New("database is locked")
	r.step()
	puts := len(r.up.puts)
	if puts != 2 {
		t.Fatalf("first attempt puts = %v", r.up.puts)
	}
	enc, _ := objectKeys("pfx/", seg.Box, seg.Hour, seg.Seq)
	before := string(r.up.objects[enc])
	r.st.markErr = nil
	r.clk.add(time.Minute)
	r.step()
	if len(r.up.puts) != puts {
		t.Errorf("uploaded again: %v", r.up.puts[puts:])
	}
	got, ok := r.st.archived(seg.Name)
	if !ok || got.Key != enc || string(r.up.objects[enc]) != before {
		t.Errorf("retry: %+v ok=%v", got, ok)
	}
	if r.a.Err() != "" || len(r.alerts.all()) != 0 {
		t.Errorf("err=%q alerts=%+v", r.a.Err(), r.alerts.all())
	}
}

// A failing existence check is a transient upload failure, not a reason to overwrite.
func TestExistenceCheckErrorBlocksUpload(t *testing.T) {
	r := newRig(t, 1)
	r.up.getErr = errors.New("s3: get: unexpected status 503")
	r.step()
	if len(r.up.puts) != 0 || !strings.Contains(r.a.Err(), "503") {
		t.Errorf("puts=%v err=%q", r.up.puts, r.a.Err())
	}
	if filepath.Base(r.up.gets[0]) != baseName("web-1", 1)+SealSuffix {
		t.Errorf("checked %v, want the seal key", r.up.gets)
	}
}

// A seal signed with the previous key (a rotation between the upload and its MarkArchived) is
// still this archiver's own: recorded, not re-uploaded, not alerted. New seals use Key.
func TestPreviousKeySealIsOurs(t *testing.T) {
	r := newRig(t, 2)
	oldKey := r.key
	r.st.markErr = errors.New("database is locked")
	r.st.segs = r.st.segs[:1]
	r.step() // uploads segment 1 signed with the old key; MarkArchived fails
	more := writeSegments(t, filepath.Join(r.dir, "later"), t0.Add(5*time.Hour), 1)
	more[0].Chain, more[0].PrevSHA256 = 2, r.st.segs[0].SHA256
	r.st.segs = append(r.st.segs, more...)
	r.st.markErr = nil
	puts := len(r.up.puts)

	newKey := testKey(t)
	rotated := func(prev []byte) *Archiver {
		o := r.a.opt
		o.Key, o.PreviousKey = newKey, prev
		a := newArchiver(o, r.st)
		if a.Err() != "" {
			t.Fatal(a.Err())
		}
		a.nextPrune = r.clk.Now().Add(time.Hour)
		return a
	}

	// Without the previous key the leftover seal looks foreign (segment 2's upload fails here, so
	// only the archiver below uploads it).
	r.up.putErr = func(string) error { return errors.New("down") }
	a := rotated(nil)
	a.step(t.Context())
	if calls := r.alerts.all(); len(calls) != 1 || calls[0].segment != r.st.segs[0].Name {
		t.Fatalf("without PreviousKey: alerts = %+v, want the collision alert", calls)
	}

	// With it, the seal is recognised and recorded, and only the new segment is uploaded.
	r.up.putErr = nil
	r.alerts.calls = nil
	r.up.puts = r.up.puts[:puts]
	a = rotated(oldKey)
	a.step(t.Context())
	if _, ok := r.st.archived(r.st.segs[0].Name); !ok {
		t.Fatal("the leftover upload was not recorded")
	}
	if len(r.alerts.all()) != 0 {
		t.Errorf("alerts = %+v", r.alerts.all())
	}
	for _, p := range r.up.puts[puts:] {
		if strings.Contains(p, baseName("web-1", r.st.segs[0].Seq)) && strings.Contains(p, "/14/") {
			t.Errorf("re-uploaded %s", p)
		}
	}
	_, sk := objectKeys("pfx/", "web-1", more[0].Hour, more[0].Seq)
	s := sealAt(t, r, sk)
	if !s.Authentic([][]byte{newKey}) || s.Authentic([][]byte{oldKey}) {
		t.Error("a new seal must be signed with Key, not PreviousKey")
	}
}

func TestPreviousKeyMustBe32Bytes(t *testing.T) {
	r := newRig(t, 0)
	o := r.a.opt
	o.PreviousKey = make([]byte, 16)
	if newArchiver(o, r.st).Err() == "" {
		t.Error("a 16-byte previous key accepted")
	}
	o.PreviousKey = nil
	if e := newArchiver(o, r.st).Err(); e != "" {
		t.Errorf("no previous key rejected: %s", e)
	}
}

// Prune also removes past-retention objects of the box names this server wrote under before a
// rename, and never another server's.
func TestPruneRenamedBoxes(t *testing.T) {
	for name, tc := range map[string]struct {
		boxes   []string
		boxErr  error
		deleted []string
	}{
		"store lists the old name": {boxes: []string{"oldname", "web-1"}, deleted: []string{"oldname", "web-1"}},
		"current box not listed":   {boxes: []string{"oldname"}, deleted: []string{"oldname", "web-1"}},
		"listing fails":            {boxErr: errors.New("database is locked"), deleted: []string{"web-1"}},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, 0)
			r.st.boxes, r.st.boxErr = tc.boxes, tc.boxErr
			now := t0.Add(400 * 24 * time.Hour)
			r.clk.set(now)
			old := t0
			for _, box := range []string{"web-1", "oldname", "other-host"} {
				for _, suf := range []string{EncSuffix, SealSuffix} {
					enc, seal := objectKeys("pfx/", box, old, 1)
					key := enc
					if suf == SealSuffix {
						key = seal
					}
					r.up.list = append(r.up.list, s3.Object{Key: key, LastModified: old.Add(time.Hour)})
				}
			}
			r.a.nextPrune = now
			r.step()
			got := map[string]int{}
			for _, d := range r.up.deleted {
				ki, _ := ParseKey("pfx/", d)
				got[ki.Box]++
			}
			want := map[string]int{}
			for _, b := range tc.deleted {
				want[b] = 2
			}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("deleted per box = %v, want %v (%v)", got, want, r.up.deleted)
			}
		})
	}
}

// After the store's manifest is rebuilt (security.db lost), a segment's chain position changes;
// this server's own authentic seal of the same segment is still recorded, not treated as another
// host's.
func TestOwnSealWithOtherChainPositionIsRecorded(t *testing.T) {
	r := newRig(t, 2)
	seg := r.st.segs[0]
	enc, sk := objectKeys("pfx/", seg.Box, seg.Hour, seg.Seq)
	own := Seal{V: 1, Name: seg.Name, Box: seg.Box, Hour: seg.Hour, Seq: seg.Seq, N: 99, SHA256: seg.SHA256, PrevSHA256: seg.PrevSHA256}
	if err := own.Sign(r.key); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(own)
	r.up.objects[sk], r.up.objects[enc] = b, []byte("the earlier upload")
	r.step()
	got, ok := r.st.archived(seg.Name)
	if !ok || got.Key != enc {
		t.Fatalf("own seal with another n not recorded: %+v ok=%v", got, ok)
	}
	for _, p := range r.up.puts {
		if p == enc || p == sk {
			t.Errorf("re-uploaded %s", p)
		}
	}
	if len(r.alerts.all()) != 0 || r.a.Err() != "" {
		t.Errorf("alerts=%+v err=%q", r.alerts.all(), r.a.Err())
	}
	if n := strings.Count(r.logs.String(), "chain position"); n != 1 {
		t.Errorf("logged the renumbering %d times, want once:\n%s", n, r.logs.String())
	}

	// The same seal for different content is still another segment's.
	r2 := newRig(t, 1)
	seg2 := r2.st.segs[0]
	_, sk2 := objectKeys("pfx/", seg2.Box, seg2.Hour, seg2.Seq)
	other := Seal{V: 1, Name: seg2.Name, Box: seg2.Box, Hour: seg2.Hour, Seq: seg2.Seq, N: seg2.Chain, SHA256: strings.Repeat("f", 64)}
	other.Sign(r2.key)
	b2, _ := json.Marshal(other)
	r2.up.objects[sk2] = b2
	r2.step()
	if _, ok := r2.st.archived(seg2.Name); ok || len(r2.alerts.all()) != 1 {
		t.Errorf("a different sha256 was taken as ours (alerts %+v)", r2.alerts.all())
	}
}

// A segment skipped for a different seal is checked again about once an hour, not every minute,
// and alerted once.
func TestTakenKeyRecheckBacksOff(t *testing.T) {
	r := newRig(t, 1)
	seg := r.st.segs[0]
	_, sk := objectKeys("pfx/", seg.Box, seg.Hour, seg.Seq)
	r.up.objects[sk] = []byte("not ours")
	gets := func() int {
		n := 0
		for _, g := range r.up.gets {
			if g == sk {
				n++
			}
		}
		return n
	}
	start := r.clk.Now()
	for m := 0; m < 60; m++ {
		r.clk.set(start.Add(time.Duration(m) * time.Minute))
		r.step()
	}
	if gets() != 1 {
		t.Fatalf("checked the taken key %d times in an hour, want 1", gets())
	}
	if r.a.Behind() != 1 {
		t.Errorf("behind = %d", r.a.Behind())
	}
	r.clk.set(start.Add(time.Hour))
	r.step()
	if gets() != 2 {
		t.Fatalf("no re-check after an hour (%d checks)", gets())
	}
	if len(r.alerts.all()) != 1 {
		t.Errorf("alerts = %+v, want one", r.alerts.all())
	}
	// Once the key is free the segment uploads on the next re-check.
	delete(r.up.objects, sk)
	r.clk.set(start.Add(2 * time.Hour))
	r.step()
	if _, ok := r.st.archived(seg.Name); !ok {
		t.Error("not uploaded after the key was freed")
	}
}
