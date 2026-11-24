package store

import (
	"fmt"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
)

// benchEvent is a typical edge request line after parsing: a few fields, a short message.
func benchEvent(c *clock, i int) siem.Event {
	kind, lvl := siem.KindHTTPRequest, siem.LvlInfo
	if i%20 == 0 {
		kind, lvl = "auth.login", siem.LvlWarn // 5% classified
	}
	e := siem.Event{
		TS: c.now(), Src: siem.SrcEdge, App: "web", Svc: "api", Kind: kind, Lvl: lvl, IP: fmt.Sprintf("10.0.%d.%d", i%250, i%200),
		F: map[string]any{
			"req.method": "GET", "req.uri": fmt.Sprintf("/api/v1/items/%d?page=2", i), "status": 200.0,
			"duration_ms": float64(i%900) / 3, "req.headers.user_agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0",
		},
		Msg: fmt.Sprintf("GET /api/v1/items/%d 200", i),
	}
	e.Normalize(c.now())
	return e
}

func BenchmarkAppend(b *testing.B) {
	c := newClock(h10)
	s, err := Open(testOptions(b.TempDir()+"/sl", c))
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	batch := make([]siem.Event, 256)
	for i := range batch {
		batch[i] = benchEvent(c, i)
	}
	line, _ := marshalLine(&batch[1])
	b.SetBytes(int64(len(line)) * int64(len(batch)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.Append(batch); err != nil {
			b.Fatal(err)
		}
		if i%8 == 0 {
			if err := s.Flush(); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.ReportMetric(float64(b.N*len(batch))/b.Elapsed().Seconds(), "events/s")
}

func benchScanStore(b *testing.B, n int) *Store {
	b.Helper()
	c := newClock(h10)
	s, err := Open(testOptions(b.TempDir()+"/sl", c))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { s.Close() })
	batch := make([]siem.Event, 0, 1000)
	for i := 0; i < n; i++ {
		batch = append(batch, benchEvent(c, i))
		if len(batch) == cap(batch) {
			if err := s.Append(batch); err != nil {
				b.Fatal(err)
			}
			batch = batch[:0]
			c.add(time.Second)
		}
	}
	if err := s.Append(batch); err != nil {
		b.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		b.Fatal(err)
	}
	return s
}

func benchScan(b *testing.B, q string) {
	const n = 50_000
	s := benchScanStore(b, n)
	pq, err := query.Parse(q)
	if err != nil {
		b.Fatal(err)
	}
	var raw int64
	for _, e := range []int{1, 2} {
		ev := benchEvent(newClock(h10), e)
		l, _ := marshalLine(&ev)
		raw += int64(len(l))
	}
	b.SetBytes(raw / 2 * n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := s.searchScan(bg, pq, 100)
		if err != nil || r.Scanned != n || len(r.Events) != 0 {
			b.Fatalf("scanned %d of %d, %d matches, %v", r.Scanned, n, len(r.Events), err)
		}
	}
	b.ReportMetric(float64(b.N*n)/b.Elapsed().Seconds(), "events/s")
}

// BenchmarkScanText is a text search the prefilter can reject lines for without decoding them.
func BenchmarkScanText(b *testing.B) { benchScan(b, `"no such text"`) }

// BenchmarkScanDecode is a search every line has to be decoded and matched for.
func BenchmarkScanDecode(b *testing.B) { benchScan(b, `f.status>=500`) }
