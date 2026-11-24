package docker

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// frame wraps p in one stdcopy frame for stream (1 stdout, 2 stderr).
func frame(stream byte, p string) []byte {
	h := make([]byte, 8)
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:], uint32(len(p)))
	return append(h, p...)
}

type tsLine struct {
	ts   time.Time
	text string
}

func collect(t *testing.T, r *bytes.Reader, timestamps bool) []tsLine {
	t.Helper()
	var got []tsLine
	if err := demuxLogs(r, timestamps, func(ts time.Time, s string) { got = append(got, tsLine{ts, s}) }); err != nil {
		t.Fatal(err)
	}
	return got
}

func mustTS(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// Without timestamps, lines are emitted as before: framed and TTY streams, CR trimmed, empty lines
// skipped, long lines cut at 8 KiB.
func TestDemuxWithoutTimestamps(t *testing.T) {
	var b bytes.Buffer
	b.Write(frame(1, "first\nsec"))
	b.Write(frame(2, "ond\r\n\n"))
	b.Write(frame(1, strings.Repeat("x", maxLogLineBytes+100)+"\n"))
	got := collect(t, bytes.NewReader(b.Bytes()), false)
	if len(got) != 3 || got[0].text != "first" || got[1].text != "second" || !got[0].ts.IsZero() {
		t.Fatalf("framed: %+v", got)
	}
	if got[2].text != strings.Repeat("x", maxLogLineBytes)+"…" {
		t.Errorf("long line: %d bytes", len(got[2].text))
	}
	tty := collect(t, bytes.NewReader([]byte("hello tty\r\nbye\r\n")), false)
	if len(tty) != 2 || tty[0].text != "hello tty" || tty[1].text != "bye" {
		t.Errorf("tty: %+v", tty)
	}
}

// With timestamps, each line's Docker timestamp is parsed and stripped, in framed and TTY streams.
func TestDemuxStripsTimestamps(t *testing.T) {
	ts1, ts2 := "2026-11-23T10:00:00.123456789Z", "2026-11-23T10:00:01.000000001Z"
	var b bytes.Buffer
	b.Write(frame(1, ts1+" GET /health 200\n"))
	b.Write(frame(2, ts2+" panic: boom\r\n"))
	b.Write(frame(1, ts2+" \n")) // an empty line is skipped, as without timestamps
	got := collect(t, bytes.NewReader(b.Bytes()), true)
	if len(got) != 2 {
		t.Fatalf("framed: %+v", got)
	}
	if got[0].text != "GET /health 200" || !got[0].ts.Equal(mustTS(t, ts1)) {
		t.Errorf("line 1: %+v", got[0])
	}
	if got[1].text != "panic: boom" || !got[1].ts.Equal(mustTS(t, ts2)) {
		t.Errorf("line 2: %+v", got[1])
	}

	// A TTY container's stream has no stdcopy framing; Docker still prefixes every line.
	tty := collect(t, bytes.NewReader([]byte(ts1+" $ prompt\r\n"+ts2+" done\r\n")), true)
	if len(tty) != 2 || tty[0].text != "$ prompt" || !tty[0].ts.Equal(mustTS(t, ts1)) || tty[1].text != "done" || !tty[1].ts.Equal(mustTS(t, ts2)) {
		t.Errorf("tty: %+v", tty)
	}

	// A line without a parseable timestamp is kept whole, with a zero timestamp.
	odd := collect(t, bytes.NewReader(frame(1, "not-a-time something\nnospace\n")), true)
	if len(odd) != 2 || odd[0].text != "not-a-time something" || !odd[0].ts.IsZero() || odd[1].text != "nospace" {
		t.Errorf("no timestamp: %+v", odd)
	}
}

// The 8 KiB cut applies to the text after the timestamp is stripped.
func TestDemuxCutsAfterStripping(t *testing.T) {
	ts := "2026-11-23T10:00:00.000000000Z"
	exact := strings.Repeat("a", maxLogLineBytes)
	got := collect(t, bytes.NewReader(frame(1, ts+" "+exact+"\n")), true)
	if len(got) != 1 || got[0].text != exact {
		t.Fatalf("a line of exactly 8 KiB after the prefix must be whole: %d bytes, truncated=%v", len(got[0].text), strings.HasSuffix(got[0].text, "…"))
	}
	long := strings.Repeat("b", 3*maxLogLineBytes)
	got = collect(t, bytes.NewReader(frame(1, ts+" "+long+"\n")), true)
	if len(got) != 1 || got[0].text != strings.Repeat("b", maxLogLineBytes)+"…" || !got[0].ts.Equal(mustTS(t, ts)) {
		t.Fatalf("long line: %d bytes", len(got[0].text))
	}
}

// StreamLogsSince asks for timestamps, the since bound and the tail cap.
func TestStreamLogsSinceQuery(t *testing.T) {
	since := time.Unix(1700000000, 5).UTC()
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/abc/logs" {
			http.NotFound(w, r)
			return
		}
		gotQuery = r.URL.RawQuery
		w.Write(frame(1, "2026-11-23T10:00:00.5Z hello\n"))
	}))
	defer srv.Close()
	c := New(strings.TrimPrefix(srv.URL, "http://"))
	var lines []tsLine
	if err := c.StreamLogsSince(context.Background(), "abc", 1000, since, true, func(ts time.Time, s string) {
		lines = append(lines, tsLine{ts, s})
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"timestamps=1", "since=1700000000.000000005", "tail=1000", "follow=1", "stdout=1", "stderr=1"} {
		if !strings.Contains(gotQuery, want) {
			t.Errorf("query %q lacks %s", gotQuery, want)
		}
	}
	if len(lines) != 1 || lines[0].text != "hello" || !lines[0].ts.Equal(mustTS(t, "2026-11-23T10:00:00.5Z")) {
		t.Errorf("lines: %+v", lines)
	}

	// No since: no since parameter; the plain StreamLogs keeps timestamps off.
	if err := c.StreamLogsSince(context.Background(), "abc", 1, time.Time{}, false, func(time.Time, string) {}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(gotQuery, "since=") || strings.Contains(gotQuery, "follow=") {
		t.Errorf("zero since / no follow: %q", gotQuery)
	}
	var plain []string
	if err := c.StreamLogs(context.Background(), "abc", 300, true, func(s string) { plain = append(plain, s) }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, "timestamps=0") || !strings.Contains(gotQuery, "tail=300") {
		t.Errorf("StreamLogs query: %q", gotQuery)
	}
	// The test server sends a timestamp anyway: StreamLogs passes the line through unchanged.
	if len(plain) != 1 || plain[0] != "2026-11-23T10:00:00.5Z hello" {
		t.Errorf("StreamLogs lines: %q", plain)
	}
}
