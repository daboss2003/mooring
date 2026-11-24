package archive

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/backup"
	"github.com/daboss2003/mooring/internal/s3"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/store"
)

// ---- fakes ------------------------------------------------------------------------------------

// callLog records the order of store and uploader calls across both fakes.
type callLog struct {
	mu    sync.Mutex
	calls []string
}

func (l *callLog) add(s string) {
	l.mu.Lock()
	l.calls = append(l.calls, s)
	l.mu.Unlock()
}

func (l *callLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.calls...)
}

type fakeStore struct {
	log     *callLog
	mu      sync.Mutex
	segs    []store.Segment
	events  []siem.Event
	sealErr error
	listErr error
	markErr error
	sealed  int
	boxes   []string
	boxErr  error
}

func (f *fakeStore) Boxes() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.boxes...), f.boxErr
}

func (f *fakeStore) SealDue() error {
	f.log.add("seal")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sealed++
	return f.sealErr
}

func (f *fakeStore) Unarchived() ([]store.Segment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []store.Segment
	for _, s := range f.segs {
		if s.ArchivedAt.IsZero() {
			out = append(out, s)
		}
	}
	return out, nil
}

func (f *fakeStore) MarkArchived(name, key string, at time.Time) error {
	f.log.add("mark:" + name)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.markErr != nil {
		return f.markErr
	}
	for i := range f.segs {
		if f.segs[i].Name == name {
			f.segs[i].ArchivedAt, f.segs[i].Key = at, key
			return nil
		}
	}
	return errors.New("no such segment")
}

func (f *fakeStore) Append(evs []siem.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, evs...)
	return nil
}

func (f *fakeStore) Flush() error { return nil }

func (f *fakeStore) archived(name string) (store.Segment, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.segs {
		if s.Name == name {
			return s, !s.ArchivedAt.IsZero()
		}
	}
	return store.Segment{}, false
}

// tempDirStore is a fakeStore that names its temp directory.
type tempDirStore struct {
	*fakeStore
	tmp string
}

func (s tempDirStore) TempDir() string { return s.tmp }

type tmpSeen struct {
	path string
	mode fs.FileMode
	head []byte
}

type fakeUp struct {
	log      *callLog
	mu       sync.Mutex
	objects  map[string][]byte
	ctypes   map[string]string
	puts     []string
	putErr   func(key string) error // nil = succeed
	tmps     []tmpSeen
	list     []s3.Object // returned by List when non-nil (else the stored objects)
	listErr  error
	listed   []string
	deleted  []string
	inFlight func() // called during each Put (e.g. to inspect the temp dir)
	now      func() time.Time
	mod      map[string]time.Time // LastModified per key
	gets     []string
	getErr   error
}

func newFakeUp(l *callLog) *fakeUp {
	return &fakeUp{log: l, objects: map[string][]byte{}, ctypes: map[string]string{}, mod: map[string]time.Time{}, now: time.Now}
}

func (u *fakeUp) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	u.log.add("get:" + key)
	u.mu.Lock()
	defer u.mu.Unlock()
	u.gets = append(u.gets, key)
	if u.getErr != nil {
		return nil, 0, u.getErr
	}
	b, ok := u.objects[key]
	if !ok {
		return nil, 0, fmt.Errorf("fake: get %q: %w", key, s3.ErrNotFound)
	}
	return io.NopCloser(bytes.NewReader(b)), int64(len(b)), nil
}

func (u *fakeUp) Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error {
	u.log.add("put:" + key)
	if u.inFlight != nil {
		u.inFlight()
	}
	if f, ok := r.(*os.File); ok {
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		head := make([]byte, 6)
		_, _ = f.ReadAt(head, 0)
		u.mu.Lock()
		u.tmps = append(u.tmps, tmpSeen{path: f.Name(), mode: fi.Mode().Perm(), head: head})
		u.mu.Unlock()
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if int64(len(b)) != size {
		return fmt.Errorf("fake: size %d but body %d bytes", size, len(b))
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.puts = append(u.puts, key)
	if u.putErr != nil {
		if err := u.putErr(key); err != nil {
			return err
		}
	}
	u.objects[key] = b
	u.ctypes[key] = contentType
	u.mod[key] = u.now()
	return nil
}

func (u *fakeUp) List(ctx context.Context, prefix string) ([]s3.Object, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.listed = append(u.listed, prefix)
	if u.listErr != nil {
		return nil, u.listErr
	}
	if u.list != nil {
		return u.list, nil
	}
	var out []s3.Object
	for k, b := range u.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, s3.Object{Key: k, Size: int64(len(b)), LastModified: u.mod[k]})
		}
	}
	return out, nil
}

func (u *fakeUp) Delete(ctx context.Context, key string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.deleted = append(u.deleted, key)
	delete(u.objects, key)
	return nil
}

type alertCall struct {
	failing bool
	detail  string
	segment string // set for SegmentChanged
}

type fakeAlerts struct {
	mu    sync.Mutex
	calls []alertCall
}

func (a *fakeAlerts) ArchiveFailing(ctx context.Context, failing bool, detail string) {
	a.mu.Lock()
	a.calls = append(a.calls, alertCall{failing: failing, detail: detail})
	a.mu.Unlock()
}

func (a *fakeAlerts) SegmentChanged(ctx context.Context, segment, detail string) {
	a.mu.Lock()
	a.calls = append(a.calls, alertCall{failing: true, detail: detail, segment: segment})
	a.mu.Unlock()
}

func (a *fakeAlerts) all() []alertCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]alertCall(nil), a.calls...)
}

// syncBuf is a goroutine-safe log sink.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// ---- fixtures ---------------------------------------------------------------------------------

var t0 = time.Date(2026, 11, 22, 14, 0, 0, 0, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func (c *clock) add(d time.Duration) { c.set(c.Now().Add(d)) }

func testKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// writeSegments writes n sealed segment files (gzip NDJSON, hours from start) chained by
// PrevSHA256, as the store would.
func writeSegments(t *testing.T, dir string, start time.Time, n int) []store.Segment {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var segs []store.Segment
	prev := ""
	for i := 0; i < n; i++ {
		hour := start.Add(time.Duration(i) * time.Hour)
		name := fmt.Sprintf("%s-web-1-%d.ndjson.gz", hour.Format("2006010215"), i+1)
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		for j := 0; j < 3; j++ {
			ev := siem.Event{TS: hour.Add(time.Duration(j) * time.Minute), Src: siem.SrcHost, Kind: siem.KindSSHLogin, Out: siem.OutFailure, IP: "203.0.113.9"}
			ev.Normalize(hour)
			line, _ := json.Marshal(ev)
			zw.Write(append(line, '\n'))
		}
		zw.Close()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(buf.Bytes())
		h := hex.EncodeToString(sum[:])
		segs = append(segs, store.Segment{
			Name: name, Box: "web-1", Path: p, Hour: hour, Seq: i + 1, Events: 3, Bytes: int64(buf.Len()),
			SHA256: h, PrevSHA256: prev, First: hour, Last: hour.Add(2 * time.Minute), Chain: int64(i + 1),
		})
		prev = h
	}
	return segs
}

type rig struct {
	t      *testing.T
	log    *callLog
	st     *fakeStore
	up     *fakeUp
	alerts *fakeAlerts
	clk    *clock
	key    []byte
	a      *Archiver
	dir    string
	logs   *syncBuf
}

func newRig(t *testing.T, nsegs int) *rig {
	t.Helper()
	l := &callLog{}
	dir := t.TempDir()
	r := &rig{t: t, log: l, st: &fakeStore{log: l}, up: newFakeUp(l), alerts: &fakeAlerts{},
		clk: &clock{t: t0.Add(time.Duration(nsegs)*time.Hour + time.Minute)}, key: testKey(t), dir: dir, logs: &syncBuf{}}
	r.up.now = r.clk.Now
	r.st.segs = writeSegments(t, filepath.Join(dir, "segments"), t0, nsegs)
	r.a = newArchiver(Options{
		Up: r.up, Key: r.key, Prefix: "pfx/", Box: "web-1", Retention: 365 * 24 * time.Hour,
		Alerts: r.alerts, Log: slog.New(slog.NewTextHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug})), Now: r.clk.Now,
	}, r.st)
	if e := r.a.Err(); e != "" {
		t.Fatalf("valid options rejected: %s", e)
	}
	r.a.nextPrune = r.clk.Now().Add(firstPruneAfter)
	return r
}

func (r *rig) step() { r.a.step(context.Background()) }

func decryptBytes(t *testing.T, key, enc []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := backup.Decrypt(&out, bytes.NewReader(enc), key); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return out.Bytes()
}

// ---- tests ------------------------------------------------------------------------------------

func TestNewValidatesOptions(t *testing.T) {
	l := &callLog{}
	good := func() Options {
		return Options{Up: newFakeUp(l), Key: make([]byte, 32), Prefix: "mooring/siem/", Box: "web-1", Retention: 24 * time.Hour}
	}
	st := &fakeStore{log: l}
	if e := newArchiver(good(), st).Err(); e != "" {
		t.Fatalf("good options rejected: %s", e)
	}
	o := good()
	o.Prefix = ""
	if e := newArchiver(o, st).Err(); e != "" {
		t.Fatalf("empty prefix rejected: %s", e)
	}
	bad := map[string]func(*Options){
		"prefix without slash": func(o *Options) { o.Prefix = "mooring" },
		"leading slash":        func(o *Options) { o.Prefix = "/mooring/" },
		"empty element":        func(o *Options) { o.Prefix = "a//b/" },
		"dot dot":              func(o *Options) { o.Prefix = "../" },
		"hidden element":       func(o *Options) { o.Prefix = "a/.git/" },
		"space":                func(o *Options) { o.Prefix = "my logs/" },
		"long prefix":          func(o *Options) { o.Prefix = strings.Repeat("a/", 300) },
		"empty box":            func(o *Options) { o.Box = "" },
		"box with slash":       func(o *Options) { o.Box = "a/b" },
		"dot box":              func(o *Options) { o.Box = ".web" },
		"box too long":         func(o *Options) { o.Box = strings.Repeat("b", 110) },
		"short key":            func(o *Options) { o.Key = make([]byte, 16) },
		"no uploader":          func(o *Options) { o.Up = nil },
		"retention under 1d":   func(o *Options) { o.Retention = time.Hour },
	}
	for name, mut := range bad {
		o := good()
		mut(&o)
		if e := newArchiver(o, st).Err(); e == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	if e := New(good()).Err(); e == "" {
		t.Error("New without a store accepted")
	}

	// Invalid options: Run touches neither the store nor the bucket and returns on cancel.
	o = good()
	o.Prefix = "bad"
	a := newArchiver(o, st)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if len(l.all()) != 0 {
		t.Errorf("invalid archiver made calls: %v", l.all())
	}
}

func TestRunStepsAtOnceAndStops(t *testing.T) {
	r := newRig(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.a.Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := r.st.archived(r.st.segs[0].Name); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Run did not archive on its first step")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestKeyLayoutAndSeal(t *testing.T) {
	r := newRig(t, 1)
	seg := r.st.segs[0]
	r.step()

	encKey := "pfx/v1/2026/11/22/14/web-1-0001.ndjson.gz.enc"
	sealKey := "pfx/v1/2026/11/22/14/web-1-0001.seal.json"
	if got := r.up.puts; len(got) != 2 || got[0] != encKey || got[1] != sealKey {
		t.Fatalf("puts = %v, want [%s %s]", got, encKey, sealKey)
	}
	if r.up.ctypes[encKey] != "application/octet-stream" || r.up.ctypes[sealKey] != "application/json" {
		t.Errorf("content types = %v", r.up.ctypes)
	}
	plain, _ := os.ReadFile(seg.Path)
	if got := decryptBytes(t, r.key, r.up.objects[encKey]); !bytes.Equal(got, plain) {
		t.Error("the object does not decrypt to the segment file")
	}

	var raw map[string]any
	if err := json.Unmarshal(r.up.objects[sealKey], &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"v", "name", "box", "hour", "seq", "events", "first", "last", "sha256", "prev_sha256", "enc_sha256", "enc_bytes", "archived_at"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("seal is missing %q: %s", k, r.up.objects[sealKey])
		}
	}
	if _, ok := raw["sha256_mismatch"]; ok {
		t.Error("a clean seal must not carry sha256_mismatch")
	}
	var s Seal
	_ = json.Unmarshal(r.up.objects[sealKey], &s)
	encSum := sha256.Sum256(r.up.objects[encKey])
	want := Seal{
		V: 1, Name: seg.Name, Box: "web-1", Hour: seg.Hour, Seq: 1, Events: 3, First: seg.First, Last: seg.Last,
		SHA256: seg.SHA256, PrevSHA256: "", EncSHA256: hex.EncodeToString(encSum[:]),
		EncBytes: int64(len(r.up.objects[encKey])), ArchivedAt: r.clk.Now(),
	}
	if !sealEqual(s, want) {
		t.Errorf("seal =\n %+v\nwant\n %+v", s, want)
	}

	got, ok := r.st.archived(seg.Name)
	if !ok || got.Key != encKey || !got.ArchivedAt.Equal(r.clk.Now()) {
		t.Errorf("MarkArchived = %+v ok=%v", got, ok)
	}
	if !r.a.LastArchived().Equal(r.clk.Now()) || r.a.Behind() != 0 || r.a.Err() != "" {
		t.Errorf("status: last=%v behind=%d err=%q", r.a.LastArchived(), r.a.Behind(), r.a.Err())
	}
}

func sealEqual(a, b Seal) bool {
	return a.V == b.V && a.Name == b.Name && a.Box == b.Box && a.Hour.Equal(b.Hour) && a.Seq == b.Seq &&
		a.Events == b.Events && a.First.Equal(b.First) && a.Last.Equal(b.Last) && a.SHA256 == b.SHA256 &&
		a.PrevSHA256 == b.PrevSHA256 && a.EncSHA256 == b.EncSHA256 && a.EncBytes == b.EncBytes &&
		a.ArchivedAt.Equal(b.ArchivedAt) && a.SHA256Mismatch == b.SHA256Mismatch && a.ActualSHA256 == b.ActualSHA256
}

func TestMarkArchivedOnlyAfterBothPuts(t *testing.T) {
	r := newRig(t, 1)
	name := r.st.segs[0].Name
	r.up.putErr = func(key string) error {
		if strings.HasSuffix(key, SealSuffix) {
			return errors.New("seal put failed")
		}
		return nil
	}
	r.step()
	if _, ok := r.st.archived(name); ok {
		t.Fatal("marked archived although the seal upload failed")
	}
	for _, c := range r.log.all() {
		if strings.HasPrefix(c, "mark:") {
			t.Fatalf("MarkArchived called after a failed seal put: %v", r.log.all())
		}
	}
	r.up.putErr = nil
	r.clk.add(time.Minute)
	r.step()
	if _, ok := r.st.archived(name); !ok {
		t.Fatal("not archived on retry")
	}
	calls := r.log.all()
	last := calls[len(calls)-3:]
	if !strings.HasSuffix(last[0], EncSuffix) || !strings.HasSuffix(last[1], SealSuffix) || last[2] != "mark:"+name {
		t.Errorf("retry order = %v, want put enc, put seal, mark", last)
	}
}

func TestOrderAndRetry(t *testing.T) {
	r := newRig(t, 3)
	failFor := baseName("web-1", 2) + EncSuffix
	failing := true
	r.up.putErr = func(key string) error {
		if failing && strings.HasSuffix(key, failFor) {
			return errors.New("s3: put: unexpected status 503 Service Unavailable: SlowDown")
		}
		return nil
	}
	r.step()
	if _, ok := r.st.archived(r.st.segs[0].Name); !ok {
		t.Fatal("segment 1 not archived")
	}
	for _, k := range r.up.puts {
		if strings.Contains(k, baseName("web-1", 3)) {
			t.Fatalf("segment 3 uploaded before segment 2 succeeded: %v", r.up.puts)
		}
	}
	if r.a.Behind() != 2 || !strings.Contains(r.a.Err(), "SlowDown") {
		t.Errorf("after failure: behind=%d err=%q", r.a.Behind(), r.a.Err())
	}
	failing = false
	r.clk.add(time.Minute)
	r.step()
	for _, s := range r.st.segs {
		if _, ok := r.st.archived(s.Name); !ok {
			t.Errorf("%s not archived on retry", s.Name)
		}
	}
	var encOrder []string
	for _, k := range r.up.puts {
		if strings.HasSuffix(k, EncSuffix) {
			encOrder = append(encOrder, filepath.Base(k))
		}
	}
	want := []string{"web-1-0001" + EncSuffix, "web-1-0002" + EncSuffix, "web-1-0002" + EncSuffix, "web-1-0003" + EncSuffix}
	if strings.Join(encOrder, ",") != strings.Join(want, ",") {
		t.Errorf("upload order = %v, want %v", encOrder, want)
	}
	if r.a.Behind() != 0 || r.a.Err() != "" {
		t.Errorf("after retry: behind=%d err=%q", r.a.Behind(), r.a.Err())
	}
}

func TestBackoff(t *testing.T) {
	r := newRig(t, 1)
	var attempts []int
	start := r.clk.Now()
	r.up.putErr = func(key string) error {
		attempts = append(attempts, int(r.clk.Now().Sub(start)/time.Minute))
		return errors.New("down")
	}
	for m := 0; m <= 95; m++ {
		r.clk.set(start.Add(time.Duration(m) * time.Minute))
		r.step()
	}
	want := []int{0, 1, 3, 7, 15, 31, 61, 91}
	if fmt.Sprint(attempts) != fmt.Sprint(want) {
		t.Errorf("attempt minutes = %v, want %v", attempts, want)
	}
	// SealDue still runs every tick while uploads back off.
	if r.st.sealed != 96 {
		t.Errorf("SealDue ran %d times in 96 ticks", r.st.sealed)
	}
}

func TestAlertOnceResolveOnce(t *testing.T) {
	r := newRig(t, 1)
	start := r.clk.Now()
	r.up.putErr = func(string) error { return errors.New("down") }
	for m := 0; m < 60; m++ {
		r.clk.set(start.Add(time.Duration(m) * time.Minute))
		r.step()
	}
	if n := len(r.alerts.all()); n != 0 {
		t.Fatalf("alerted after %d failing minutes (<1h): %v", 59, r.alerts.all())
	}
	for m := 60; m < 180; m++ {
		r.clk.set(start.Add(time.Duration(m) * time.Minute))
		r.step()
	}
	calls := r.alerts.all()
	if len(calls) != 1 || !calls[0].failing || !strings.Contains(calls[0].detail, "down") {
		t.Fatalf("alerts after 3h failing = %+v, want one failing alert", calls)
	}
	var failed int
	for _, ev := range r.st.events {
		if ev.Kind == siem.KindArchiveFailed && ev.Src == siem.SrcSIEM {
			failed++
		}
	}
	if failed != 1 {
		t.Errorf("siem.archive_failed events = %d, want 1", failed)
	}
	r.up.putErr = nil
	r.st.segs = append(r.st.segs, writeSegments(t, filepath.Join(r.dir, "more"), t0.Add(5*time.Hour), 1)...)
	for m := 180; m < 200; m++ {
		r.clk.set(start.Add(time.Duration(m) * time.Minute))
		r.step()
	}
	calls = r.alerts.all()
	if len(calls) != 2 || calls[1].failing || calls[1].detail != "" {
		t.Fatalf("alerts after recovery = %+v, want exactly one resolve", calls)
	}
}

func TestAlertWhenSixBehind(t *testing.T) {
	r := newRig(t, 6)
	r.up.putErr = func(string) error { return errors.New("down") }
	r.step()
	calls := r.alerts.all()
	if len(calls) != 1 || !calls[0].failing || !strings.Contains(calls[0].detail, "6 ") {
		t.Fatalf("6 behind and failing: alerts = %+v", calls)
	}
	r.clk.add(time.Minute)
	r.step()
	if len(r.alerts.all()) != 1 {
		t.Errorf("alerted twice: %+v", r.alerts.all())
	}
	// Five behind and just failed: no alert yet.
	r2 := newRig(t, 5)
	r2.up.putErr = func(string) error { return errors.New("down") }
	r2.step()
	if len(r2.alerts.all()) != 0 {
		t.Errorf("5 behind alerted: %+v", r2.alerts.all())
	}
	// A big backlog that uploads fine is not an alert.
	r3 := newRig(t, 8)
	r3.step()
	if len(r3.alerts.all()) != 0 || r3.a.Behind() != 0 {
		t.Errorf("healthy backlog: alerts=%+v behind=%d", r3.alerts.all(), r3.a.Behind())
	}
}

func TestNilAlertsLogsOnly(t *testing.T) {
	r := newRig(t, 6)
	r.a.opt.Alerts = nil
	r.up.putErr = func(string) error { return errors.New("down") }
	r.step()
	if !strings.Contains(r.logs.String(), "level=ERROR") {
		t.Errorf("no error log for a failing archive:\n%s", r.logs.String())
	}
}

func TestTamperDetection(t *testing.T) {
	r := newRig(t, 2)
	seg := r.st.segs[0]
	// The file changes on the host after it was sealed.
	if err := os.WriteFile(seg.Path, []byte("forged"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.step()
	encKey, sealKey := objectKeys("pfx/", "web-1", seg.Hour, seg.Seq)
	if _, ok := r.up.objects[encKey]; !ok {
		t.Fatal("a mismatching segment must still be uploaded, under its own key")
	}
	var s Seal
	if err := json.Unmarshal(r.up.objects[sealKey], &s); err != nil {
		t.Fatal(err)
	}
	forged := sha256.Sum256([]byte("forged"))
	if !s.SHA256Mismatch || s.SHA256 != seg.SHA256 || s.ActualSHA256 != hex.EncodeToString(forged[:]) {
		t.Errorf("seal = %+v, want sha256_mismatch with the sealed and the actual hash", s)
	}
	if got := decryptBytes(t, r.key, r.up.objects[encKey]); string(got) != "forged" {
		t.Errorf("uploaded %q", got)
	}
	if !strings.Contains(r.logs.String(), "level=ERROR") || !strings.Contains(r.logs.String(), seg.Name) {
		t.Errorf("no error log naming the segment:\n%s", r.logs.String())
	}
	var crit int
	for _, ev := range r.st.events {
		if ev.Kind == siem.KindArchiveFailed && ev.Lvl == siem.LvlCritical && ev.F["segment"] == seg.Name {
			crit++
		}
	}
	if crit != 1 {
		t.Errorf("critical archive_failed events for the segment = %d (%+v)", crit, r.st.events)
	}
	calls := r.alerts.all()
	if len(calls) != 1 || calls[0].segment != seg.Name || !strings.Contains(calls[0].detail, seg.Name) {
		t.Fatalf("alerts = %+v, want one SegmentChanged naming the segment", calls)
	}
	// The second, clean segment was archived in the same tick and is not flagged.
	_, seal2 := objectKeys("pfx/", "web-1", r.st.segs[1].Hour, r.st.segs[1].Seq)
	var s2 Seal
	_ = json.Unmarshal(r.up.objects[seal2], &s2)
	if s2.SHA256Mismatch || s2.SHA256 == "" {
		t.Errorf("clean segment flagged: %+v", s2)
	}
	if _, ok := r.st.archived(seg.Name); !ok {
		t.Error("the flagged segment must be recorded as archived (it is in the bucket, flagged)")
	}
}

func TestTempFiles(t *testing.T) {
	r := newRig(t, 2)
	tmp := filepath.Join(filepath.Dir(r.st.segs[0].Path), "tmp")
	// A temp file left by a crash is removed; anything else in the directory is not.
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(tmp, "archive-123.enc.tmp")
	other := filepath.Join(tmp, "store-owned")
	os.WriteFile(stale, []byte("x"), 0o600)
	os.WriteFile(other, []byte("x"), 0o600)
	inTmp := 0
	r.up.inFlight = func() {
		ents, _ := os.ReadDir(tmp)
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), "archive-") {
				inTmp++
			}
		}
	}
	r.up.putErr = func(key string) error {
		if strings.Contains(key, "0002") {
			return errors.New("fail the second segment")
		}
		return nil
	}
	r.step()
	if len(r.up.tmps) == 0 {
		t.Fatal("uploads did not stream from a temp file")
	}
	for _, s := range r.up.tmps {
		if filepath.Dir(s.path) != tmp {
			t.Errorf("temp file %s is not in %s", s.path, tmp)
		}
		if s.mode != 0o600 {
			t.Errorf("temp file mode %#o, want 0600", s.mode)
		}
		if string(s.head) != "HMBK1\n" {
			t.Errorf("temp file starts %q: not ciphertext", s.head)
		}
	}
	if inTmp == 0 {
		t.Error("never saw the temp file during the upload")
	}
	ents, _ := os.ReadDir(tmp)
	for _, e := range ents {
		if e.Name() != "store-owned" {
			t.Errorf("left in the temp dir: %s", e.Name())
		}
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("removed a file the archiver does not own")
	}
	// Nothing was written outside the temp dir and the segment dir.
	filepath.WalkDir(r.dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Dir(p) != tmp && filepath.Dir(p) != filepath.Dir(r.st.segs[0].Path) {
			t.Errorf("unexpected file %s", p)
		}
		return nil
	})
}

func TestTempDirFromStore(t *testing.T) {
	r := newRig(t, 1)
	tmp := filepath.Join(r.dir, "store-tmp")
	r.a.st = tempDirStore{fakeStore: r.st, tmp: tmp}
	r.step()
	if len(r.up.tmps) == 0 || filepath.Dir(r.up.tmps[0].path) != tmp {
		t.Fatalf("temp files = %+v, want them in the store's TempDir %s", r.up.tmps, tmp)
	}
	if fi, err := os.Stat(tmp); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("temp dir: %v %v", fi, err)
	}
}

func TestMissingSegmentFileIsSkipped(t *testing.T) {
	r := newRig(t, 2)
	os.Remove(r.st.segs[0].Path)
	r.step()
	if _, ok := r.st.archived(r.st.segs[1].Name); !ok {
		t.Fatal("a missing segment file blocked the next segment")
	}
	if _, ok := r.st.archived(r.st.segs[0].Name); ok {
		t.Fatal("a missing segment was marked archived")
	}
	if r.a.Behind() != 1 {
		t.Errorf("behind = %d, want 1 (the missing one)", r.a.Behind())
	}
	r.clk.add(time.Minute)
	r.step()
	if n := strings.Count(r.logs.String(), "segment file is gone"); n != 1 {
		t.Errorf("logged the missing segment %d times over two ticks, want once", n)
	}
}

func TestUnarchivedErrorCountsAsFailure(t *testing.T) {
	r := newRig(t, 1)
	r.st.listErr = errors.New("database is locked")
	r.step()
	if !strings.Contains(r.a.Err(), "database is locked") {
		t.Errorf("err = %q", r.a.Err())
	}
}

func TestErrTextIsBoundedAndOneLine(t *testing.T) {
	r := newRig(t, 1)
	r.up.putErr = func(string) error { return errors.New("line1\nline2 " + strings.Repeat("x", 5000)) }
	r.step()
	e := r.a.Err()
	if len(e) > maxErrLen || strings.Contains(e, "\n") {
		t.Errorf("Err() = %d bytes, newline=%v", len(e), strings.Contains(e, "\n"))
	}
}

func TestPrune(t *testing.T) {
	r := newRig(t, 0)
	ret := r.a.opt.Retention
	// now is such that an object whose hour+1h equals now-ret is exactly at the boundary.
	edge := time.Date(2025, 11, 22, 10, 0, 0, 0, time.UTC)
	now := edge.Add(time.Hour).Add(ret)
	r.clk.set(now)
	k := func(prefix string, h time.Time, box string, seq int, suf string) string {
		return prefix + "v1/" + h.Format(hourLayout) + "/" + baseName(box, seq) + suf
	}
	old := edge.Add(-time.Hour)
	keep := []string{
		k("pfx/", edge, "web-1", 1, EncSuffix), // exactly at the boundary
		k("pfx/", edge, "web-1", 1, SealSuffix),
		k("pfx/", edge.Add(time.Hour), "web-1", 2, EncSuffix),
		k("pfx/", old, "db-2", 1, EncSuffix),          // another host's object
		"pfx/v1/2025/13/01/00/web-1-0001" + EncSuffix, // month 13
		"pfx/v1/2024/01/01/00/notes.txt",              // another file
		"pfx/v1/2024/01/01/00/web-1-0001" + EncSuffix + ".bak",
		"pfx/v1/2024/01/01/web-1-0001" + SealSuffix,      // no hour directory
		"pfx/v1/2024/01/01/0/web-1-0001" + SealSuffix,    // non-canonical hour
		"pfx/v1/2024/01/01/00/x/web-1-0001" + SealSuffix, // too deep
		"pfx/v1/2024/01/01/00/web-1-1" + EncSuffix,       // seq not padded
		"other/v1/2020/01/01/00/web-1-0001" + SealSuffix, // outside the prefix (hostile listing)
		"pfx/v2/2020/01/01/00/web-1-0001" + SealSuffix,   // another layout version
		"pfx/2020/01/01/00/web-1-0001" + SealSuffix,      // outside v1/
	}
	del := []string{
		k("pfx/", old, "web-1", 9, EncSuffix),
		k("pfx/", old, "web-1", 9, SealSuffix),
		k("pfx/", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), "web-1", 1, EncSuffix),
	}
	// Uploaded an hour after the hour they hold.
	mod := func(key string) time.Time {
		if ki, ok := ParseKey("pfx/", key); ok {
			return ki.Hour.Add(time.Hour)
		}
		return time.Time{}
	}
	for _, key := range append(append([]string{}, keep...), del...) {
		r.up.list = append(r.up.list, s3.Object{Key: key, LastModified: mod(key)})
	}
	// An old hour uploaded recently (captured while the host clock was behind), and an object the
	// listing gave no LastModified for: both kept.
	recent := k("pfx/", old, "web-1", 7, EncSuffix)
	noDate := k("pfx/", old, "web-1", 8, EncSuffix)
	r.up.list = append(r.up.list, s3.Object{Key: recent, LastModified: now.Add(-time.Hour)}, s3.Object{Key: noDate})
	keep = append(keep, recent, noDate)
	r.a.nextPrune = now
	r.step()
	if len(r.up.listed) != 1 || r.up.listed[0] != "pfx/v1/" {
		t.Fatalf("listed %v, want [pfx/v1/]", r.up.listed)
	}
	got := map[string]bool{}
	for _, d := range r.up.deleted {
		got[d] = true
	}
	for _, d := range del {
		if !got[d] {
			t.Errorf("not deleted: %s", d)
		}
	}
	for _, kp := range keep {
		if got[kp] {
			t.Errorf("deleted: %s", kp)
		}
	}
	if len(r.up.deleted) != len(del) {
		t.Errorf("deleted %d objects, want %d: %v", len(r.up.deleted), len(del), r.up.deleted)
	}

	// One second later the boundary objects are past the retention.
	r.up.deleted = nil
	r.clk.set(now.Add(time.Second))
	r.a.nextPrune = r.clk.Now()
	r.step()
	if len(r.up.deleted) != len(del)+2 {
		t.Errorf("1s past the boundary deleted %v", r.up.deleted)
	}
}

func TestPruneSchedule(t *testing.T) {
	r := newRig(t, 0)
	start := r.clk.Now()
	r.a.nextPrune = start.Add(firstPruneAfter)
	at := func(d time.Duration) int {
		r.clk.set(start.Add(d))
		r.step()
		return len(r.up.listed)
	}
	if at(9*time.Minute) != 0 {
		t.Fatal("pruned before 10 minutes")
	}
	if at(10*time.Minute) != 1 {
		t.Fatal("no prune at 10 minutes")
	}
	if at(10*time.Minute+23*time.Hour) != 1 {
		t.Fatal("pruned twice within a day")
	}
	if at(10*time.Minute+24*time.Hour) != 2 {
		t.Fatal("no prune a day later")
	}
	// A failed listing is retried an hour later, not a day later.
	r.up.listErr = errors.New("down")
	if at(10*time.Minute+48*time.Hour) != 3 {
		t.Fatal("no prune two days later")
	}
	r.up.listErr = nil
	if at(10*time.Minute+48*time.Hour+59*time.Minute) != 3 {
		t.Fatal("retried a failed prune within the hour")
	}
	if at(10*time.Minute+49*time.Hour) != 4 {
		t.Fatal("failed prune not retried after an hour")
	}
}

func TestParseKey(t *testing.T) {
	ok := map[string]KeyInfo{
		"pfx/v1/2026/11/22/14/web-1-0007.ndjson.gz.enc": {Hour: t0, Box: "web-1", Seq: 7},
		"pfx/v1/2026/11/22/14/web-1-0007.seal.json":     {Hour: t0, Box: "web-1", Seq: 7, Seal: true},
		"pfx/v1/2026/02/28/00/a-12345.seal.json":        {Hour: time.Date(2026, 2, 28, 0, 0, 0, 0, time.UTC), Box: "a", Seq: 12345, Seal: true},
	}
	for key, want := range ok {
		got, good := ParseKey("pfx/", key)
		if !good || !got.Hour.Equal(want.Hour) || got.Box != want.Box || got.Seq != want.Seq || got.Seal != want.Seal {
			t.Errorf("ParseKey(%q) = %+v %v, want %+v", key, got, good, want)
		}
	}
	for _, key := range []string{
		"pfx/v1/2026/02/30/00/a-0001.seal.json", // no 30 February
		"pfx/v1/2026/11/22/24/a-0001.seal.json",
		"pfx/v1/26/11/22/14/a-0001.seal.json",
		"pfx/v1/2026/11/22/14/-0001.seal.json",
		"pfx/v1/2026/11/22/14/.a-0001.seal.json",
		"pfx/v1/2026/11/22/14/a-00001.seal.json", // padded past 4
		"pfx/v1/2026/11/22/14/a-0001.json",
		"pfx/v1/2026/11/22/14/a b-0001.seal.json",
		"pfx/v1/2026/11/22/14/a-0001.seal.json/",
		"v1/2026/11/22/14/a-0001.seal.json",
	} {
		if ki, good := ParseKey("pfx/", key); good {
			t.Errorf("ParseKey(%q) accepted: %+v", key, ki)
		}
	}
	if _, good := ParseKey("", "v1/2026/11/22/14/a-0001.seal.json"); !good {
		t.Error("empty prefix not parsed")
	}
}
