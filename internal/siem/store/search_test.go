package store

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
)

// corpus appends a varied set of events over three hours (with same-TS groups, lying timestamps,
// mixed case and non-ASCII values) and returns them in append order, as stored.
func corpus(t *testing.T, s *Store, c *clock, n int) []siem.Event {
	t.Helper()
	r := rand.New(rand.NewSource(7))
	pick := func(xs ...string) string { return xs[r.Intn(len(xs))] }
	var out, batch []siem.Event
	var ts time.Time
	for i := 0; i < n; i++ {
		c.add(time.Duration(r.Intn(40)+1) * time.Second)
		if i%4 != 0 { // groups of up to 4 share a timestamp
			ts = c.now()
		}
		e := siem.Event{
			TS:    ts,
			Src:   pick(siem.SrcApp, siem.SrcEdge, siem.SrcHost, "APP"),
			App:   pick("web", "api", "Wéb", "WEB", ""),
			Svc:   pick("api", "worker", ""),
			Copy:  pick("c1", "c2", ""),
			Kind:  pick(siem.KindLog, siem.KindHTTPRequest, "auth.login", "auth.logout", "Auth.Login", siem.KindSSHLogin, siem.KindDropped, "LOG"),
			Lvl:   pick(siem.LvlDebug, siem.LvlInfo, siem.LvlWarn, siem.LvlError, siem.LvlCritical),
			Out:   pick("", siem.OutSuccess, siem.OutFailure),
			Actor: pick("", "h:aaaa", "bob", "BOB", "\u212Aelvin"),
			IP:    pick("", "10.0.0.1", "10.2.3.4", "192.168.1.5", "::ffff:10.0.0.9", "2001:db8::5", "unknown"),
			Msg:   fmt.Sprintf("event %d %s", i, pick("login ok", "Login FAILED", "ärger <b>&", "plain", `quote " here`)),
			F:     map[string]any{"i": float64(i), "path": pick("/a", "/b c")},
		}
		if i%37 == 0 {
			e.TS = h10.Add(-time.Duration(r.Intn(5))*time.Hour - time.Duration(i)) // a source claiming an earlier time
		}
		if i%151 == 0 {
			e.TS = c.now().Add(3 * time.Hour) // or a later one
		}
		e.Normalize(c.now())
		batch = append(batch, e)
		if len(batch) == 5 || i == n-1 {
			mustAppend(t, s, batch...)
			batch = batch[:0]
		}
		// Round-trip, as search returns it.
		b, _ := json.Marshal(e)
		var back siem.Event
		_ = json.Unmarshal(b, &back)
		out = append(out, back)
		if i%50 == 0 {
			mustFlush(t, s)
		}
	}
	mustFlush(t, s)
	return out
}

// brute is the reference answer: every match, newest TS first, later appends first on a tie.
func brute(evs []siem.Event, q query.Query) []string {
	idx := make([]int, 0)
	for i := range evs {
		if q.Match(&evs[i]) {
			idx = append(idx, i)
		}
	}
	sort.SliceStable(idx, func(a, b int) bool {
		ea, eb := evs[idx[a]], evs[idx[b]]
		if !ea.TS.Equal(eb.TS) {
			return ea.TS.After(eb.TS)
		}
		return idx[a] > idx[b]
	})
	out := make([]string, len(idx))
	for i, j := range idx {
		out[i] = evs[j].Msg
	}
	return out
}

type searchFn func(ctx context.Context, q query.Query, limit int) (Result, error)

// pages pages through every result of q with the given limit.
func pages(t *testing.T, fn searchFn, q query.Query, limit int) []string {
	t.Helper()
	var out []string
	for n := 0; ; n++ {
		r, err := fn(bg, q, limit)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Events) > limit {
			t.Fatalf("page of %d events, limit %d", len(r.Events), limit)
		}
		for i := 1; i < len(r.Events); i++ {
			if r.Events[i].TS.After(r.Events[i-1].TS) {
				t.Fatalf("page not newest first at %d", i)
			}
		}
		out = append(out, msgs(r.Events)...)
		if !r.More {
			return out
		}
		if len(r.Events) == 0 || n > 1000 {
			t.Fatalf("More with an empty page")
		}
		if !r.Before.Equal(r.Events[len(r.Events)-1].TS) {
			t.Fatalf("Before %v is not the oldest returned TS", r.Before)
		}
		q.To = r.Before
	}
}

var indexQueries = []string{
	`kind:auth.login`, `kind:auth.*`, `kind:AUTH.LOGIN`, `lvl>=warn`, `lvl>=warn app:web`, `lvl:error -app:web`,
	`kind:ssh.login out:failure ip:10.0.0.0/8`, `kind:auth.* actor!=bob`, `kind:auth.* -actor:bob`,
	`lvl>info src:edge`, `kind:auth.* ip:10.0.0.1`, `kind:auth.* ip:10.0.0.9`, `kind:auth.* ip!=10.0.0.1`,
	`lvl>=warn kind~log`, `lvl>=warn -kind~login`, `kind:auth.* app:*`, `kind:auth.* -app:*`,
	`kind:auth.* lvl<warn`, `kind:auth.* -lvl>=error`, `kind:auth.* app:wé*`, `kind:auth.* actor:kelvin`,
	`lvl:critical svc!=api`, `kind:siem.dropped -svc:worker`, `kind:auth.* -app!=web`, `lvl>=error lvl~rit`,
	`kind:auth.* -ip:10.0.0.0/8`, `kind:auth.* ip~10.`, `lvl>=warn src:app`, `kind:a*`, `kind:auth.* out:*`,
	`-lvl>=warn kind:auth.*`, `kind:auth.* -out:*`, `kind:auth.* -app!=w*`, `kind:auth.* app!=w*`,
}

var scanQueries = []string{
	`kind:log`, `lvl<warn`, `login`, `"login failed"`, `app:web`, `kind:auth.* "event 1"`, `-kind:log`,
	`kind:http.*`, `kind:l*`, `f.i>100`, `copy:c1 lvl>=warn`, `ärger`, `ÄRGER "<b>"`, `"quote \" here"`,
	`f.path:"/b c"`, `kind~login`, `actor:kelvin`, `ip:10.0.0.0/8 login`, `-lvl>=warn kind:log`,
	`lvl>=warn f.path:/a`, ``,
}

func TestIndexable(t *testing.T) {
	for _, q := range indexQueries {
		pq, err := query.Parse(q)
		if err != nil {
			t.Fatal(err)
		}
		if !indexable(pq) {
			t.Errorf("%q not answered from the index", q)
		}
	}
	for _, q := range scanQueries {
		pq, err := query.Parse(q)
		if err != nil {
			t.Fatal(err)
		}
		if indexable(pq) {
			t.Errorf("%q answered from the index (it may match unindexed events)", q)
		}
	}
}

func TestSearchIndexAndScanAgree(t *testing.T) {
	c := newClock(h10.Add(-time.Minute))
	s := openStore(t, storeDir(t), c, nil)
	s.maxEvents = 40 // several segments per hour
	evs := corpus(t, s, c, 320)
	if err := s.SealDue(); err != nil {
		t.Fatal(err)
	}
	ranges := []query.Query{
		{},
		{From: h10.Add(-3 * time.Hour), To: h10.Add(50 * time.Minute)}, // takes in the lying timestamps
	}
	for _, q := range append(append([]string(nil), indexQueries...), scanQueries...) {
		for _, rg := range ranges {
			pq, err := query.Parse(q)
			if err != nil {
				t.Fatal(err)
			}
			pq.From, pq.To = rg.From, rg.To
			want := brute(evs, pq)
			for _, limit := range []int{11, 1000} {
				if got := pages(t, s.searchScan, pq, limit); strings.Join(got, "|") != strings.Join(want, "|") {
					t.Errorf("scan %q %v..%v limit %d:\n got %d %q\nwant %d %q", q, rg.From, rg.To, limit, len(got), head(got), len(want), head(want))
				}
				if !indexable(pq) {
					continue
				}
				if got := pages(t, s.searchIndex, pq, limit); strings.Join(got, "|") != strings.Join(want, "|") {
					t.Errorf("index %q %v..%v limit %d:\n got %d %q\nwant %d %q", q, rg.From, rg.To, limit, len(got), head(got), len(want), head(want))
				}
			}
			// The public entry point, one page.
			r, err := s.Search(bg, pq, 10)
			if err != nil {
				t.Fatal(err)
			}
			if n := min(10, len(want)); len(r.Events) > 10 || strings.Join(msgs(r.Events), "|") != strings.Join(want[:min(len(r.Events), n)], "|") {
				t.Errorf("Search %q: %q", q, msgs(r.Events))
			}
		}
	}
}

func head(xs []string) []string {
	if len(xs) > 6 {
		return xs[:6]
	}
	return xs
}

func TestSearchTiesDoNotSplitAcrossPages(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	var evs []siem.Event
	for i := 0; i < 12; i++ {
		e := mkev(c, "auth.login", siem.LvlInfo, i)
		e.TS = h10.Add(time.Duration(i/4) * time.Second) // three groups of four
		evs = append(evs, e)
	}
	mustAppend(t, s, evs...)
	mustFlush(t, s)
	pq, _ := query.Parse("kind:auth.login")
	for name, fn := range map[string]searchFn{"scan": s.searchScan, "index": s.searchIndex} {
		r, err := fn(bg, pq, 6)
		if err != nil {
			t.Fatal(err)
		}
		// Six would split the middle group: the page stops after the first group.
		if got := strings.Join(msgs(r.Events), ","); got != "event 11,event 10,event 9,event 8" || !r.More {
			t.Errorf("%s: page = %q More=%v", name, got, r.More)
		}
		all := pages(t, fn, pq, 6)
		if len(all) != 12 {
			t.Errorf("%s: paged %d of 12 events", name, len(all))
		}
		// A group larger than a page still makes progress.
		r, err = fn(bg, pq, 2)
		if err != nil || len(r.Events) != 2 || !r.More {
			t.Errorf("%s: limit 2 = %q %v", name, msgs(r.Events), err)
		}
	}
}

func TestSearchBudgetCaps(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	s.maxEvents = 50
	for i := 0; i < 500; i++ {
		mustAppend(t, s, mkev(c, siem.KindLog, siem.LvlInfo, i))
		c.add(time.Second)
	}
	mustFlush(t, s)
	s.searchBytes = 20 << 10
	r, err := s.Search(bg, query.Query{Text: []string{"event 1"}}, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Capped || !r.More || r.Scanned == 0 || r.Scanned >= 500 {
		t.Errorf("byte budget: Capped %v More %v Scanned %d", r.Capped, r.More, r.Scanned)
	}
	// The budget also stops a read inside one large segment.
	// (The newest segment is always read whole, so the large one is the older.)
	one := openStore(t, storeDir(t), c, nil)
	var big []siem.Event
	for i := 0; i < 500; i++ {
		big = append(big, mkev(c, siem.KindLog, siem.LvlInfo, i))
	}
	mustAppend(t, one, big...)
	c.add(time.Hour)
	mustAppend(t, one, mkev(c, siem.KindLog, siem.LvlInfo, 999))
	mustFlush(t, one)
	one.searchBytes = 20 << 10
	r, err = one.Search(bg, query.Query{Text: []string{"event 1"}}, 1000)
	if err != nil || !r.Capped || r.Scanned <= 1 || r.Scanned >= 501 {
		t.Errorf("budget inside a segment: Capped %v Scanned %d %v", r.Capped, r.Scanned, err)
	}
	// The time budget.
	s.searchBytes, s.searchTime = searchBudget, time.Nanosecond
	r, err = s.Search(bg, query.Query{Text: []string{"nothing"}}, 10)
	if err != nil || !r.Capped {
		t.Errorf("time budget: %+v %v", r, err)
	}
	// The caller's context ending is an error, not a capped result.
	s.searchTime = searchTimeout
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if _, err := s.Search(ctx, query.Query{}, 10); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled search: %v", err)
	}
	// The index path keeps to the byte budget too.
	for i := 0; i < 300; i++ {
		mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, i))
		c.add(time.Second)
	}
	mustFlush(t, s)
	s.searchBytes = 4 << 10
	pq, _ := query.Parse("kind:auth.login")
	r, err = s.searchIndex(bg, pq, 1000)
	if err != nil || !r.Capped || len(r.Events) == 0 || len(r.Events) >= 300 {
		t.Errorf("index budget: %d events Capped %v %v", len(r.Events), r.Capped, err)
	}
}

func TestSearchConcurrencyLimit(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	s.busyWait = 50 * time.Millisecond
	s.sem <- struct{}{}
	s.sem <- struct{}{}
	start := time.Now()
	if _, err := s.Search(bg, query.Query{}, 10); !errors.Is(err, ErrBusy) {
		t.Fatalf("third search: %v", err)
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Error("did not wait for a slot")
	}
	if _, err := s.Export(bg, query.Query{}, &bytes.Buffer{}, 10); !errors.Is(err, ErrBusy) {
		t.Fatalf("export while busy: %v", err)
	}
	ctx, cancel := context.WithCancel(bg)
	cancel()
	s.busyWait = time.Minute
	if _, err := s.Search(ctx, query.Query{}, 10); !errors.Is(err, context.Canceled) {
		t.Errorf("waiting search with a cancelled context: %v", err)
	}
	<-s.sem
	if _, err := s.Search(bg, query.Query{}, 10); err != nil {
		t.Errorf("with a free slot: %v", err)
	}
	if len(s.sem) != 1 {
		t.Errorf("search did not release its slot: %d held", len(s.sem))
	}
}

func TestSearchDoesNotBlockAppend(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	var setup []siem.Event
	for i := 0; i < 300; i++ {
		setup = append(setup, mkev(c, "auth.login", siem.LvlWarn, i))
	}
	mustAppend(t, s, setup...)
	mustFlush(t, s)
	// Searches hold every read connection with open rows, as long index searches would.
	for i := 0; i < maxSearches; i++ {
		rows, err := s.rdb.Query(`SELECT id FROM events`)
		if err != nil {
			t.Fatal(err)
		}
		if !rows.Next() {
			t.Fatal("no rows")
		}
		defer rows.Close()
	}
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 20; i++ {
			if err := s.Append([]siem.Event{mkev(c, "auth.login", siem.LvlWarn, i)}); err != nil {
				done <- err
				return
			}
		}
		if err := s.Flush(); err != nil {
			done <- err
			return
		}
		c.add(time.Hour)
		done <- s.SealDue()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Append waited for the search connections")
	}
	// Searches and appends side by side (for the race detector).
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pq, _ := query.Parse("kind:auth.login")
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = s.Search(bg, pq, 50)
				_, _ = s.Search(bg, query.Query{Text: []string{"zzz"}}, 10)
				_, _ = s.Export(bg, query.Query{}, io.Discard, 100)
			}
		}()
	}
	for i := 0; i < 50; i++ {
		mustAppend(t, s, mkev(c, "auth.login", siem.LvlWarn, i))
		if i%10 == 0 {
			mustFlush(t, s)
			_ = s.SealDue()
			_ = s.Prune()
			_, _ = s.Unarchived()
			_ = s.DiskBytes()
		}
	}
	close(stop)
	wg.Wait()
}

func TestExportOrderCapAndBudget(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	s.maxEvents = 10
	for i := 0; i < 45; i++ {
		mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, i))
		c.add(3 * time.Minute)
	}
	mustFlush(t, s)
	var buf bytes.Buffer
	n, err := s.Export(bg, query.Query{}, &buf, 1000)
	if err != nil || n != 45 {
		t.Fatalf("Export = %d, %v", n, err)
	}
	sc := bufio.NewScanner(&buf)
	i := 0
	for sc.Scan() {
		var e siem.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if e.Msg != fmt.Sprintf("event %d", i) {
			t.Fatalf("line %d = %q: not oldest first", i, e.Msg)
		}
		i++
	}
	if i != 45 {
		t.Fatalf("%d lines", i)
	}
	// Filter, time range and the event cap.
	buf.Reset()
	q, _ := query.Parse("f.i>=10")
	q.To = h10.Add(30 * 3 * time.Minute)
	n, err = s.Export(bg, q, &buf, 7)
	if err != nil || n != 7 || strings.Count(buf.String(), "\n") != 7 || !strings.Contains(strings.SplitN(buf.String(), "\n", 2)[0], `"event 10"`) {
		t.Fatalf("filtered export = %d %v %q", n, err, buf.String())
	}
	// The byte budget stops an export with ErrBudget.
	s.exportBytes = 2 << 10
	buf.Reset()
	n, err = s.Export(bg, query.Query{}, &buf, 1000)
	if !errors.Is(err, ErrBudget) || n == 0 || n >= 45 || strings.Count(buf.String(), "\n") != n {
		t.Errorf("budget export = %d, %v", n, err)
	}
	// A failing writer stops the export with its error.
	s.exportBytes = exportBudget
	werr := errors.New("client gone")
	if _, err := s.Export(bg, query.Query{}, failWriter{werr}, 1000); !errors.Is(err, werr) {
		t.Errorf("write error = %v", err)
	}
}

type failWriter struct{ err error }

func (f failWriter) Write([]byte) (int, error) { return 0, f.err }

func TestPrefilterNeverHidesAMatch(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	words := []string{"a", "A", "é", "É", "\u212A", "k", "<", "&", `"`, "\\", "\u2028", "\ufffd", "\xff", "x", " ", "1", "-", ":", "/"}
	gen := func() string {
		var b strings.Builder
		for i := r.Intn(6); i >= 0; i-- {
			b.WriteString(words[r.Intn(len(words))])
		}
		return b.String()
	}
	fields := []string{"src", "app", "svc", "copy", "kind", "out", "actor", "geo.cc", "geo.org", "geo.city", "list"}
	for n := 0; n < 20000; n++ {
		e := siem.Event{V: 1, TS: h10, Src: gen(), App: gen(), Svc: gen(), Copy: gen(), Kind: gen(), Out: gen(), Actor: gen(), Msg: gen(),
			Geo: &siem.Geo{Country: gen(), Org: gen(), City: gen(), Lists: []string{gen(), gen()}}}
		line, err := json.Marshal(&e)
		if err != nil {
			t.Fatal(err)
		}
		var back siem.Event
		if err := json.Unmarshal(line, &back); err != nil {
			t.Fatal(err)
		}
		op := []query.Op{query.OpEq, query.OpContains}[r.Intn(2)]
		v := gen()
		if strings.TrimSpace(v) == "" {
			continue
		}
		if r.Intn(3) == 0 {
			v += "*"
		}
		q := query.Query{Terms: []query.Term{{Field: fields[r.Intn(len(fields))], Op: op, Value: v}}}
		if r.Intn(2) == 0 {
			q = query.Query{Text: []string{v}}
		}
		if q.Match(&back) && !newPrefilter(q).pass(line) {
			t.Fatalf("prefilter rejected a match: query %+v line %s", q, line)
		}
	}
}

// Paging a capped scan with To = Before returns every match: a page stops just above the newest TS
// it couldn't finish examining, so the next page repeats that part rather than skipping it.
func TestCappedScanPagingReturnsEverything(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	s.maxEvents = 100
	for i := 0; i < 500; i++ {
		mustAppend(t, s, mkev(c, siem.KindLog, siem.LvlInfo, i))
		c.add(time.Second)
	}
	mustFlush(t, s)
	s.searchBytes = 12 << 10 // less than one segment
	q := query.Query{Text: []string{"event"}}
	var got []string
	capped := 0
	for n := 0; ; n++ {
		if n > 200 {
			t.Fatal("paging does not end")
		}
		r, err := s.Search(bg, q, 1000)
		if err != nil {
			t.Fatal(err)
		}
		if r.Capped {
			capped++
		}
		got = append(got, msgs(r.Events)...)
		if !r.More {
			break
		}
		if !q.To.IsZero() && !r.Before.Before(q.To) {
			t.Fatalf("page %d made no progress (Before %v, To %v)", n, r.Before, q.To)
		}
		q.To = r.Before
	}
	if capped == 0 {
		t.Fatal("no page was capped")
	}
	if len(got) != 500 {
		t.Fatalf("paging returned %d of 500 events", len(got))
	}
	for i, m := range got {
		if m != fmt.Sprintf("event %d", 499-i) {
			t.Fatalf("result %d = %q: not every event once, newest first", i, m)
		}
	}
}

// A capped page with no matches still says where the next page starts.
func TestCappedEmptyPageOffersOlder(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	var old []siem.Event
	for i := 0; i < 300; i++ {
		e := mkev(c, siem.KindLog, siem.LvlInfo, i)
		e.Msg = fmt.Sprintf("needle %d", i)
		old = append(old, e)
		c.add(time.Second)
	}
	mustAppend(t, s, old...)
	c.add(time.Hour)
	mustAppend(t, s, mkev(c, siem.KindLog, siem.LvlInfo, 1000)) // newest segment, no match
	mustFlush(t, s)
	oldSeg := segByName(s, "2026112310-box1-1.ndjson.gz")
	s.searchBytes = 4 << 10
	r, err := s.Search(bg, query.Query{Text: []string{"needle"}}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Capped || !r.More || len(r.Events) != 0 || !r.Before.Equal(nsTime(oldSeg.last).Add(time.Nanosecond)) {
		t.Fatalf("capped empty page: %d events Capped %v More %v Before %v (segment last %v)",
			len(r.Events), r.Capped, r.More, r.Before, nsTime(oldSeg.last))
	}
	// The next page reads that segment whole: its newest matches come back.
	r, err = s.Search(bg, query.Query{Text: []string{"needle"}, To: r.Before}, 100)
	if err != nil || len(r.Events) != 100 || r.Events[0].Msg != "needle 299" {
		t.Fatalf("next page: %d events, first %q, %v", len(r.Events), msgs(r.Events[:min(1, len(r.Events))]), err)
	}
}

// The index path stops on its budget the same way: no event is skipped.
func TestCappedIndexPagingReturnsEverything(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	var evs []siem.Event
	for i := 0; i < 300; i++ {
		e := mkev(c, "auth.login", siem.LvlInfo, i)
		e.TS = h10.Add(time.Duration(i/3) * time.Second) // groups of three share a TS
		evs = append(evs, e)
	}
	mustAppend(t, s, evs...)
	mustFlush(t, s)
	s.searchBytes = 3 << 10
	pq, _ := query.Parse("kind:auth.login")
	var got []string
	for n := 0; ; n++ {
		if n > 1000 {
			t.Fatal("paging does not end")
		}
		r, err := s.searchIndex(bg, pq, 1000)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, msgs(r.Events)...)
		if !r.More {
			break
		}
		if !pq.To.IsZero() && !r.Before.Before(pq.To) {
			t.Fatalf("page %d made no progress", n)
		}
		pq.To = r.Before
	}
	seen := map[string]bool{}
	for _, m := range got {
		if seen[m] {
			t.Fatalf("%s returned twice", m)
		}
		seen[m] = true
	}
	if len(seen) != 300 {
		t.Fatalf("index paging returned %d of 300", len(seen))
	}
	// A group of one TS larger than the budget is still returned whole (the first TS is examined
	// whatever the budget), so paging gets past it.
	c.add(time.Hour)
	var group []siem.Event
	for i := 0; i < 50; i++ {
		e := mkev(c, "auth.logout", siem.LvlInfo, 1000+i)
		group = append(group, e)
	}
	mustAppend(t, s, group...)
	mustFlush(t, s)
	s.searchBytes = 1 << 10
	pq, _ = query.Parse("kind:auth.logout")
	r, err := s.searchIndex(bg, pq, 1000)
	if err != nil || len(r.Events) != 50 {
		t.Fatalf("one-TS group over the budget: %d events (%v)", len(r.Events), err)
	}
}
