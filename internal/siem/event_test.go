package siem

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

// Normalize keeps only values JSON can encode: NaN and ±Inf would make the whole event fail to store.
func TestNormalizeDropsNonFiniteNumbers(t *testing.T) {
	e := Event{F: map[string]any{"ok": 1.5, "nan": math.NaN(), "inf": math.Inf(1), "ninf": math.Inf(-1), "s": "x", "b": true}}
	e.Normalize(time.Unix(1, 0))
	for _, k := range []string{"nan", "inf", "ninf"} {
		if _, ok := e.F[k]; ok {
			t.Errorf("%s kept", k)
		}
	}
	if e.F["ok"] != 1.5 || e.F["s"] != "x" || e.F["b"] != true {
		t.Errorf("finite values changed: %v", e.F)
	}
	if _, err := json.Marshal(e); err != nil {
		t.Fatalf("the normalized event doesn't encode: %v", err)
	}
}

func TestNormalizeBounds(t *testing.T) {
	e := Event{Msg: strings.Repeat("é", MaxMsg), Kind: strings.Repeat("k", 1000)}
	e.Normalize(time.Unix(1, 0))
	if len(e.Msg) > MaxMsg || !utf8Valid(e.Msg) || len(e.Kind) != MaxShort || e.V != SchemaVersion || e.Lvl != LvlInfo || !e.TS.Equal(time.Unix(1, 0)) {
		t.Errorf("bounds/defaults not applied: msg %d bytes, kind %d, v %d, lvl %q, ts %v", len(e.Msg), len(e.Kind), e.V, e.Lvl, e.TS)
	}
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "�") == s }
