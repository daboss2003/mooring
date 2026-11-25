package web

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/blocklist"
	"github.com/daboss2003/mooring/internal/siem"
)

// A reason shown on its own starts with a capital; the same words stay lower case where they finish
// a sentence.
func TestStandAloneReasonsAreCapitalised(t *testing.T) {
	for in, want := range map[string]string{"it overlaps ip_allowlist": "It overlaps ip_allowlist", "Mooring": "Mooring", "": "", "<b>x": "<b>x", "état": "État"} {
		if got := capFirst(in); got != want {
			t.Errorf("capFirst(%q) = %q, want %q", in, got, want)
		}
	}
	if got := refusedMessage(&blocklist.RefusedError{Code: blocklist.RefuseAllowlist}); got != "The block was refused: it overlaps ip_allowlist." {
		t.Errorf("refusedMessage = %q", got)
	}
	now := time.Now().UTC()
	sus := blocklist.Block{Prefix: netip.MustParsePrefix("203.0.113.0/24"), State: blocklist.StateSuspended, SuspendedWhy: blocklist.RefuseSession}
	if got := blockRowOf(&sus, now).SuspendedWhy; got != "it covers the address of a signed-in dashboard session" {
		t.Errorf("a suspended block's why (after \"Not applied: \") = %q", got)
	}
}

// The "Still learning" labels are the rows' Scope words, not the stored scope keys.
func TestPatternScopeLabels(t *testing.T) {
	for in, want := range map[string]string{"host": "Host", "app:shop/api": "shop/api", "app:shop": "shop", "app:": "app:", "other": "other"} {
		if got := patScopeLabel(in); got != want {
			t.Errorf("patScopeLabel(%q) = %q, want %q", in, got, want)
		}
	}
	v := patStatsOf(siem.PatternStats{Learning: []string{"app:shop/api", "host"}})
	if strings.Join(v.Learning, ",") != "shop/api,Host" {
		t.Errorf("learning labels = %q", v.Learning)
	}
}

// An address page says a single address plainly and an IPv6 address's /64 as a network.
func TestEntityBlockShownPrefix(t *testing.T) {
	now := time.Now().UTC()
	e := incEnv(t, newIncFake(now))
	e.srv.blocks = newBlockFake(now)
	for key, want := range map[string]struct {
		prefix, shown string
		whole         bool
	}{
		"203.0.113.9":        {"203.0.113.9/32", "203.0.113.9", false},
		"2001:db8:1:2::5":    {"2001:db8:1:2::/64", "2001:db8:1:2::/64", true},
		"2001:db8:1:2::/64":  {"2001:db8:1:2::/64", "2001:db8:1:2::/64", false},
		"::ffff:203.0.113.9": {"203.0.113.9/32", "203.0.113.9", false},
	} {
		v := e.srv.entityBlock(t.Context(), siem.Entity{Kind: siem.EntityAddress, Key: key})
		if v == nil || v.Prefix != want.prefix || v.Shown != want.shown || v.WholeNet != want.whole {
			t.Errorf("entityBlock(%q) = %+v, want %+v", key, v, want)
		}
	}
}

// The pattern page's words for a pattern with no sample line.
func TestPatternNoSampleWords(t *testing.T) {
	now := time.Now().UTC()
	f := newPatFake(now)
	e := patEnv(t, f)
	sess := e.loginAs(t, "operator")
	var id string
	for _, p := range f.pats {
		if p.Sample == "" {
			id = p.ID
		}
	}
	if id == "" {
		t.Fatal("no fixture without a sample")
	}
	_, body := e.get(t, "/security/patterns/"+id, sess)
	if !strings.Contains(body, "No sample line. Samples are deleted along with older security logs.") || strings.Contains(body, "hot retention") {
		t.Error("the no-sample words are not the plain ones")
	}
	if !strings.Contains(body, `class="muted small sec-find"`) && strings.Contains(body, "Find events") {
		t.Error("the Find events hint lost the class that lets its term wrap")
	}
}
