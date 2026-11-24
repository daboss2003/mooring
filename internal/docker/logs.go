package docker

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// streamClient is a no-overall-timeout client for following log streams (the
// short per-request Timeout on the read client would cut a `follow` stream off).
// Lifetime is bound by the caller's context.
func (c *Client) streamClient() *http.Client {
	return &http.Client{Transport: c.hc.Transport}
}

const (
	maxLogLineBytes  = 8 << 10 // truncate pathological lines
	maxLogFrameBytes = 1 << 20 // sanity cap on a single stdcopy frame
	// maxTimestampPrefix is room for Docker's "2006-01-02T15:04:05.000000000Z " prefix (plus slack
	// for a numeric zone), buffered on top of maxLogLineBytes so the cut applies to the text after it.
	maxTimestampPrefix = 40
)

// StreamLogs follows a container's logs through the read-only socket-proxy (read
// plane — no docker child, no semaphore), demultiplexing the stdcopy framing and
// invoking onLine per (truncated) line until ctx is done or the stream ends.
func (c *Client) StreamLogs(ctx context.Context, id string, tail int, follow bool, onLine func(string)) error {
	return c.streamLogs(ctx, id, tail, time.Time{}, follow, false, func(_ time.Time, s string) { onLine(s) })
}

// StreamLogsSince is StreamLogs with Docker's per-line timestamps: onLine gets each line's
// timestamp (zero when a line has none) and the line without it, cut to the same 8 KiB. A non-zero
// since starts the stream at that time (Docker includes lines stamped exactly since); tail still caps
// the backlog to the last tail lines.
func (c *Client) StreamLogsSince(ctx context.Context, id string, tail int, since time.Time, follow bool, onLine func(ts time.Time, line string)) error {
	return c.streamLogs(ctx, id, tail, since, follow, true, onLine)
}

func (c *Client) streamLogs(ctx context.Context, id string, tail int, since time.Time, follow, timestamps bool, onLine func(time.Time, string)) error {
	q := url.Values{}
	q.Set("stdout", "1")
	q.Set("stderr", "1")
	if timestamps {
		q.Set("timestamps", "1")
	} else {
		q.Set("timestamps", "0")
	}
	if tail <= 0 || tail > 5000 {
		tail = 500
	}
	q.Set("tail", strconv.Itoa(tail))
	if !since.IsZero() {
		// The Engine API takes seconds with an optional 9-digit fraction.
		q.Set("since", strconv.FormatInt(since.Unix(), 10)+"."+fmt.Sprintf("%09d", since.Nanosecond()))
	}
	if follow {
		q.Set("follow", "1")
	}
	reqURL := c.base + "/containers/" + url.PathEscape(id) + "/logs?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	resp, err := c.streamClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker: logs status %d", resp.StatusCode)
	}
	return demuxLogs(resp.Body, timestamps, onLine)
}

// demuxLogs reads the Docker multiplexed log stream (8-byte stdcopy headers) and
// emits whole lines. Falls back to raw line reading if the stream isn't framed
// (a TTY container). Bounded line + frame sizes guard against a hostile stream.
// With timestamps, each line's leading Docker timestamp is parsed and stripped.
func demuxLogs(r io.Reader, timestamps bool, onLine func(time.Time, string)) error {
	br := bufio.NewReaderSize(r, 64<<10)
	emit := newLineEmitter(onLine, timestamps)

	header := make([]byte, 8)
	for {
		_, err := io.ReadFull(br, header)
		if err != nil {
			emit.flush()
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return err
		}
		// Framed iff stream byte ∈ {0,1,2} and the 3 reserved bytes are zero.
		if header[0] > 2 || header[1]|header[2]|header[3] != 0 {
			// Not framed (TTY): treat the 8 bytes + the rest as raw text.
			emit.write(header)
			_ = emitRaw(br, emit)
			return nil
		}
		size := int64(binary.BigEndian.Uint32(header[4:8]))
		// Emit at most maxLogFrameBytes of the frame, but ALWAYS consume the full
		// declared size so the next 8 bytes are a real header — clamping the read
		// would desync the framing (review #20).
		emitN := size
		if emitN > maxLogFrameBytes {
			emitN = maxLogFrameBytes
		}
		if _, err := io.CopyN(emit, br, emitN); err != nil {
			emit.flush()
			if err == io.EOF {
				return nil
			}
			return err
		}
		if rest := size - emitN; rest > 0 {
			if _, err := io.CopyN(io.Discard, br, rest); err != nil {
				emit.flush()
				if err == io.EOF {
					return nil
				}
				return err
			}
		}
	}
}

func emitRaw(br *bufio.Reader, emit *lineEmitter) error {
	buf := make([]byte, 32<<10)
	for {
		n, err := br.Read(buf)
		if n > 0 {
			emit.write(buf[:n])
		}
		if err != nil {
			emit.flush()
			return err
		}
	}
}

// lineEmitter accumulates bytes and emits whole lines, truncating any line longer
// than maxLogLineBytes (counted after the timestamp prefix when timestamps is set).
type lineEmitter struct {
	onLine     func(time.Time, string)
	timestamps bool
	limit      int // bytes buffered per line
	buf        strings.Builder
	trunc      bool
}

func newLineEmitter(onLine func(time.Time, string), timestamps bool) *lineEmitter {
	e := &lineEmitter{onLine: onLine, timestamps: timestamps, limit: maxLogLineBytes}
	if timestamps {
		e.limit += maxTimestampPrefix
	}
	return e
}

// Write satisfies io.Writer so io.CopyN can target the emitter.
func (e *lineEmitter) Write(p []byte) (int, error) { e.write(p); return len(p), nil }

func (e *lineEmitter) write(p []byte) {
	for _, b := range p {
		if b == '\n' {
			e.flush()
			continue
		}
		if e.buf.Len() >= e.limit {
			e.trunc = true
			continue
		}
		e.buf.WriteByte(b)
	}
}

func (e *lineEmitter) flush() {
	if e.buf.Len() == 0 && !e.trunc {
		return
	}
	line, trunc := e.buf.String(), e.trunc
	e.buf.Reset()
	e.trunc = false
	var ts time.Time
	if e.timestamps {
		ts, line = splitTimestamp(line)
		if line == "" && !trunc {
			return // an empty line, skipped as it is without timestamps
		}
	}
	if len(line) > maxLogLineBytes {
		line, trunc = line[:maxLogLineBytes], true
	}
	if trunc {
		line += "…"
	}
	if e.onLine != nil {
		e.onLine(ts, strings.TrimRight(line, "\r"))
	}
}

// splitTimestamp splits Docker's "<RFC 3339 nano> " line prefix off. A line without one is
// returned whole with a zero time.
func splitTimestamp(line string) (time.Time, string) {
	head := line
	if len(head) > maxTimestampPrefix {
		head = head[:maxTimestampPrefix]
	}
	i := strings.IndexByte(head, ' ')
	if i <= 0 {
		return time.Time{}, line
	}
	ts, err := time.Parse(time.RFC3339Nano, line[:i])
	if err != nil {
		return time.Time{}, line
	}
	return ts, line[i+1:]
}
