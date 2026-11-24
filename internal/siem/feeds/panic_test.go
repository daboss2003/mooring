package feeds

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// panicBody gives data, then panics on the next Read: a bug that panics while a download is read
// and unpacked into the temporary file.
type panicBody struct {
	data []byte
	off  int
}

func (b *panicBody) Read(p []byte) (int, error) {
	if b.off < len(b.data) {
		n := copy(p, b.data[b.off:])
		b.off += n
		return n, nil
	}
	panic("unpacking bug")
}

func (b *panicBody) Close() error { return nil }

// panicTransport answers every DB-IP City request with 200 and a body that panics halfway through
// the gzip stream; anything else is a 404.
type panicTransport struct{ gz []byte }

func (t panicTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !strings.Contains(r.URL.Path, "dbip-city-lite-") {
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}, Request: r}, nil
	}
	return &http.Response{StatusCode: http.StatusOK, Body: &panicBody{data: t.gz[:len(t.gz)/2]}, ContentLength: -1,
		Header: http.Header{}, Request: r}, nil
}

// openFiles is the number of file descriptors this process has open (-1 where /dev/fd can't be read).
func openFiles() int {
	ents, err := os.ReadDir("/dev/fd")
	if err != nil {
		return -1
	}
	return len(ents)
}

// A panic while a DB-IP download is unpacked (recovered by safeFetch) leaves no temporary file in
// the feeds directory and no file open: the install cleans up unless it completed.
func TestDBIPPanicLeavesNoTempFile(t *testing.T) {
	e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
	m, _ := e.manager(func(o *Options) {
		o.Spamhaus, o.Tor = false, false
		o.client = &http.Client{Transport: panicTransport{gz: cityFile(t, "Lagos")}}
	})
	defer m.Close()
	city := m.feed(NameCity)
	fds := openFiles()
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("the panic escaped the attempt: %v", r)
			}
		}()
		m.attempt(context.Background(), city)
	}()
	if st := status(m, NameCity); !strings.Contains(st.LastError, "internal error") {
		t.Fatalf("the panic must fail the attempt: %+v", st)
	}
	ents, err := os.ReadDir(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range ents {
		if strings.Contains(x.Name(), tmpMark) {
			t.Errorf("temporary file %s left in the feeds directory", x.Name())
		}
	}
	if now := openFiles(); fds >= 0 && now != fds {
		t.Errorf("open files %d → %d: the temporary file's handle was left open", fds, now)
	}
}

// A panic in writeFile between creating its temporary file and the rename (a list snapshot, the
// state file) still closes the file and removes it; the panic goes on to the caller (safeFetch).
func TestWriteFilePanicLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	afterTempWrite = func() { panic("write bug") }
	defer func() { afterTempWrite = nil }()
	fds := openFiles()
	func() {
		defer func() {
			if r := recover(); r != "write bug" {
				t.Fatalf("recovered %v, want the panic passed on", r)
			}
		}()
		_ = writeFile(root, "spamhaus.json", []byte(`{"v":1}`))
	}()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Errorf("files left in the directory: %v", ents)
	}
	if now := openFiles(); fds >= 0 && now != fds {
		t.Errorf("open files %d → %d: the temporary file's handle was left open", fds, now)
	}
	// Without the panic the file is written whole.
	afterTempWrite = nil
	if err := writeFile(root, "spamhaus.json", []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	if b, err := readFile(root, "spamhaus.json", 1<<10); err != nil || string(b) != `{"v":1}` {
		t.Fatalf("written %q (%v)", b, err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("after a write: %v", ents)
	}
}

// A bug that panics while a download is being processed (a parser meeting hostile content) must not
// take serve down: the attempt fails like any other, and for Spamhaus it still counts as a download,
// so the next attempt waits the day the source asks for.
func TestFetchPanicIsAFailedAttempt(t *testing.T) {
	e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
	e.fs.serveAll(t, "2026-11")
	m, _ := e.manager(nil)
	var sp *feed
	for _, f := range m.feeds {
		if f.name == NameSpamhaus {
			sp = f
		}
	}
	if sp == nil {
		t.Fatal("no Spamhaus feed")
	}
	sp.fetch = func(context.Context, *feed, time.Time) (result, error) { panic("parser bug") }
	start := e.clk.Now()
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("the panic escaped the attempt: %v", r)
			}
		}()
		m.attempt(context.Background(), sp)
	}()
	m.mu.Lock()
	st := sp.st
	m.mu.Unlock()
	if !strings.Contains(st.LastError, "internal error") || st.Fails != 1 {
		t.Errorf("state after the panic: %+v", st)
	}
	if st.NextTry.Before(start.Add(sp.afterDownload)) {
		t.Errorf("next Spamhaus try %v, want at least a day after %v", st.NextTry, start)
	}
}
