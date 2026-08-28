package edgeerr

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/edgemetrics"
)

// fakeAlerter is thread-safe: the collector enqueues alerts from a goroutine (off the log-drain path).
type fakeAlerter struct {
	mu    sync.Mutex
	fired int
	last  alert.Outbox
}

func (f *fakeAlerter) EnqueueInfra(_ context.Context, o alert.Outbox) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fired++
	f.last = o
	return nil
}

func (f *fakeAlerter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fired
}

// waitFired polls until the async alert has landed (or times out).
func (f *fakeAlerter) waitFired(t *testing.T, want int) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if f.count() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("expected %d alert(s), got %d", want, f.count())
}

func TestCollectorRecordsAttributesAndAlerts(t *testing.T) {
	var clk int64 = 1000
	store := newWithClock(filepath.Join(t.TempDir(), "e.jsonl"), func() time.Time { return time.Unix(clk, 0) })
	idx := edgemetrics.NewHostIndex()
	idx.Set([]edgemetrics.Route{{Host: "api.example.com", PathPrefix: "/v1", Key: edgemetrics.Key{App: "shop", Service: "api"}}})
	al := &fakeAlerter{}
	c := NewCollector(store, idx, al)
	c.now = func() int64 { return clk }

	line := func(status int, host string) []byte {
		return []byte(fmt.Sprintf(`{"status":%d,"request":{"host":%q,"uri":"/v1/x?a=1","method":"GET","remote_ip":"1.2.3.4"}}`, status, host))
	}
	c.Ingest(line(200, "api.example.com")) // success — ignored
	c.Ingest(line(404, "api.example.com")) // client error — recorded, no alert
	if got := store.Errors("shop", "api.example.com", "/v1", "", 10); len(got) != 1 || got[0].Status != 404 || got[0].Path != "/v1/x" {
		t.Fatalf("only the 404 recorded (query stripped): %+v", got)
	}
	if al.count() != 0 {
		t.Errorf("a single 4xx must not alert, got %d", al.count())
	}

	// A 5xx spike raises exactly one alert (cooldown suppresses the rest).
	for i := 0; i < err5xxAlert+3; i++ {
		c.Ingest(line(500, "api.example.com"))
	}
	al.waitFired(t, 1)
	if al.last.Kind != "route_error_rate" || al.last.DedupeKey == "" {
		t.Errorf("wrong alert: %+v", al.last)
	}

	// Host header case is normalized: a case-variant Host is the SAME route (not a new one, no split).
	c.Ingest(line(500, "API.Example.com"))
	if routes := store.Routes(); len(routes) != 1 {
		t.Errorf("case-variant Host must be one route, got %d", len(routes))
	}

	// A request to an UNATTRIBUTED host is dropped (never recorded against a service).
	before := len(store.Errors("shop", "api.example.com", "/v1", "", 1000))
	c.Ingest(line(500, "bogus.example.com"))
	if after := len(store.Errors("shop", "api.example.com", "/v1", "", 1000)); after != before {
		t.Errorf("unattributed host must be dropped: before=%d after=%d", before, after)
	}
}
