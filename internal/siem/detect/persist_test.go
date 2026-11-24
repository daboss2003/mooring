package detect

import (
	"context"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

func TestNewValueSurvivesRestart(t *testing.T) {
	h := newHarness(t, false)
	r := newValueRule(time.Hour)
	h.only(t, r)
	h.feed(sshOK(0, "198.51.100.1", "alice", geo("NG", "Lagos", 6.45, 3.39)))
	h.clk.set(t0.Add(2 * time.Hour))
	h.reopen(t)
	h.only(t, r)
	h.feed(sshOK(2*time.Hour, "198.51.100.1", "alice", geo("NG", "Lagos", 6.45, 3.39)))
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("a value learned before the restart fired: %+v", ds)
	}
	h.feed(sshOK(2*time.Hour+time.Minute, "198.51.100.2", "alice", geo("DE", "Berlin", 52.52, 13.40)))
	if ds := h.all(t); len(ds) != 1 {
		t.Fatalf("new value after the restart (key and learning period kept): %+v", ds)
	}
}

func TestAnomalyCountsSurviveRestart(t *testing.T) {
	h := newHarness(t, false)
	r := anomalyRule()
	h.only(t, r)
	history(h, "shop.example.com", 30, 2)
	h.reopen(t)
	h.only(t, r)
	spike(h, "shop.example.com", 30*time.Hour+30*time.Minute, 20)
	if ds := h.all(t); len(ds) != 1 {
		t.Fatalf("spike after a restart with 30h of history: %+v", ds)
	}
}

// A rule whose matching definition changed starts again; a damaged blob is discarded.
func TestPersistedStateDiscarded(t *testing.T) {
	h := newHarness(t, false)
	r := newValueRule(time.Hour)
	h.only(t, r)
	h.feed(sshOK(0, "198.51.100.1", "alice", geo("NG", "Lagos", 6.45, 3.39)))
	h.clk.set(t0.Add(2 * time.Hour))
	h.reopen(t)
	r2 := r
	r2.Query = "kind:ssh.login out:success src:host"
	h.only(t, r2)
	h.feed(sshOK(2*time.Hour, "198.51.100.2", "alice", geo("DE", "Berlin", 52.52, 13.40)))
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("state of a changed rule was reused: %+v", ds)
	}

	if _, err := h.e.db.w.Exec(`UPDATE rule_state SET data = x'01ffffffff'`); err != nil {
		t.Fatal(err)
	}
	h.e.flush(true)
	if err := h.e.Close(); err != nil {
		t.Fatal(err)
	}
	h.open(t)
	h.only(t, r2)
	h.feed(sshOK(3*time.Hour, "198.51.100.3", "alice", geo("FR", "Paris", 48.86, 2.35)))
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("damaged state: %+v", ds)
	}
}

// The saved state of a rule that is gone is removed.
func TestPersistRemovesStateOfRemovedRules(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, newValueRule(0))
	h.feed(sshOK(0, "198.51.100.1", "alice", geo("NG", "Lagos", 6.45, 3.39)))
	h.e.persist()
	h.only(t, thresholdRule(1, time.Hour))
	h.e.persist()
	rows, err := h.e.db.loadState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("state rows of removed rules: %v", rows)
	}
}

func TestStateEncodingRoundTrip(t *testing.T) {
	s := newSeen()
	s.observe("alice", "NG", int64(time.Hour), 0)
	s.observe("bob", "US", int64(2*time.Hour), 0)
	got, err := decodeSeen(s.encode())
	if err != nil || got.start != s.start || len(got.keys) != 2 || len(got.pairs) != 2 {
		t.Fatalf("seen round trip: %+v %v", got, err)
	}
	for _, bad := range [][]byte{nil, {2}, {1}, append(s.encode(), 0)} {
		if _, err := decodeSeen(bad); err == nil {
			t.Errorf("decodeSeen(%x) accepted", bad)
		}
	}
	st := newRuleState("sig")
	k := st.key("shop")
	k.an = &anomaly{first: 5, last: 100}
	k.an.hours[3] = 42
	st.charge(k)
	st2 := newRuleState("sig")
	if err := decodeAnomaly(encodeAnomaly(st), st2); err != nil {
		t.Fatal(err)
	}
	k2 := st2.keys["shop"].Value.(*keyState)
	if k2.an.first != 5 || k2.an.last != 100 || k2.an.hours[3] != 42 || st2.entries != k2.cost {
		t.Fatalf("anomaly round trip: %+v", k2.an)
	}
	if err := decodeAnomaly([]byte{1, 0xff, 0xff, 0xff, 0xff, 0x0f}, newRuleState("x")); err == nil {
		t.Error("decodeAnomaly accepted a key count above the cap")
	}
}

func TestRestoredKeysStayBounded(t *testing.T) {
	st := newRuleState("sig")
	for i := range maxKeys + 10 {
		k := st.key(string(rune('a'+i%26)) + time.Duration(i).String())
		k.an = &anomaly{}
		st.charge(k)
	}
	if len(st.keys) > maxKeys || st.entries > maxEntries {
		t.Fatalf("%d keys, %d entries", len(st.keys), st.entries)
	}
	_ = siem.Event{}
}
