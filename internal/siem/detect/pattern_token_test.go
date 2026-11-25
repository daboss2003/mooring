package detect

import (
	"strings"
	"testing"
)

func masked(msg string) string {
	var toks [maxPatTokens]tok
	n := tokenize(msg, &toks)
	out := make([]string, n)
	for i := range out {
		out[i] = tokText(msg, toks[i])
	}
	return strings.Join(out, " ")
}

// Each variable part of a line is masked; constants (words, "[redacted]", versions) are kept.
func TestPatternTokenizeMasks(t *testing.T) {
	long := strings.Repeat("z", 33)
	cases := []struct{ in, want string }{
		{"GET /api/users 200 15ms", "GET /api/users <NUM> <NUM>"},
		{"took 1h2m3.5s, 250µs and 12.5ms", "took <NUM>, <NUM> and <NUM>"},
		{"used 45% of 1.5GiB (10KB free) 2x x2", "used <NUM> of <NUM> (<NUM> free) <NUM> x2"},
		{"latency=-3.5e-3s count=+7", "latency=<NUM> count=<NUM>"},
		{"from 203.0.113.7:51234 to [2001:db8::1]:443 via 10.0.0.0/8 and fe80::1 2001:db8::/32", "from <IP> to <IP> via <IP> and <IP> <IP>"},
		{"999.1.1.1 1.2.3.4:99999 a::b::c", "999.1.1.1 1.2.3.4:99999 a::b::c"},
		{"id=550e8400-e29b-41d4-a716-446655440000 req 550E8400-E29B-41D4-A716-446655440000", "id=<UUID> req <UUID>"},
		{"at 2026-11-25T10:00:00.123Z then 2026-11-25t10:00:00+01:00 and 10:00:01 or 09:30", "at <TS> then <TS> and <TS> or <TS>"},
		{"on 2026/11/25 at 23:59:60,5 zone 2026-11-25T10:00:00-0700", "on <TS> at <TS> zone <TS>"},
		{"2026-13-01 25:00 10:61", "2026-13-01 25:00 10:61"},
		{"user h:0123456789abcdef logged in h:0123456789ABCDEF", "user <HASH> logged in h:0123456789ABCDEF"},
		{"token eyJhbGciOiJIUzI1NiIsInR5cCI6 and authentication_failed_for_user", "token <B64> and authentication_failed_for_user"},
		{"sha deadbeefcafebabe0123 addr 0x7ffe1234 short abc123", "sha <HEX> addr <HEX> short abc123"},
		{`msg="hello world, again" status=500 user=alice empty=`, `msg=<STR> status=<NUM> user=alice empty=`},
		{`said "a b c" and 'x y', then "unclosed`, `said <STR> and <STR>, then "unclosed`},
		{"password=[redacted] cookie [redacted]", "password=[redacted] cookie [redacted]"},
		{"path " + long + " ok k=" + long, "path <LONG> ok k=<LONG>"},
		{"(42), [2026-11-25] <0x1f>; {10.0.0.1}.", "(<NUM>), [<TS>] <<HEX>>; {<IP>}."},
		{"\x1b[32mINFO\x1b[0m started\tworker\x00 7", "INFO started worker <NUM>"},
		{"v1.2.3 build 3rd 5xx error: connection refused", "v1.2.3 build 3rd 5xx error: connection refused"},
		{"", ""},
		{"   \t ", ""},
	}
	for _, c := range cases {
		if got := masked(c.in); got != c.want {
			t.Errorf("%q:\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

// A line of more than maxPatTokens tokens ends in one <*> for the rest; a token is never longer than
// maxTokText as text.
func TestPatternTokenizeBounds(t *testing.T) {
	msg := strings.TrimSpace(strings.Repeat("a ", 70))
	var toks [maxPatTokens]tok
	n := tokenize(msg, &toks)
	if n != maxPatTokens || tokText(msg, toks[n-1]) != wildcard || tokText(msg, toks[n-2]) != "a" {
		t.Fatalf("%d tokens, last %q", n, tokText(msg, toks[n-1]))
	}
	if n := tokenize(strings.TrimSpace(strings.Repeat("a ", maxPatTokens)), &toks); n != maxPatTokens || toks[n-1].code != mLit {
		t.Fatalf("exactly %d tokens: %d, last code %d", maxPatTokens, n, toks[n-1].code)
	}
	for _, s := range []string{strings.Repeat("(", 60) + "5" + strings.Repeat(")", 60), `"x"` + strings.Repeat("y", 90),
		"k=" + strings.Repeat("(", 70) + "1"} {
		n := tokenize(s, &toks)
		for i := range n {
			if txt := tokText(s, toks[i]); len(txt) > maxTokText {
				t.Fatalf("%q: token %q longer than %d", s, txt, maxTokText)
			}
		}
	}
	if n := tokenize(strings.Repeat("x", 3*maxPatLine), &toks); n != 1 || toks[0].code != mLong {
		t.Fatalf("a huge token: %d tokens", n)
	}
}

// Tokenizing and fingerprinting a line allocates nothing (it runs for every line mined).
func TestPatternTokenizeNoAlloc(t *testing.T) {
	msg := `GET /api/users/42 200 15ms from 203.0.113.7:51234 [2001:db8::1]:443 id=550e8400-e29b-41d4-a716-446655440000 msg="a b" at 2026-11-25T10:00:00Z user=alice h:0123456789abcdef dead:beef`
	var toks [maxPatTokens]tok
	var sink uint64
	allocs := testing.AllocsPerRun(200, func() {
		n := tokenize(msg, &toks)
		sink += fingerprint(msg, toks[:n])
	})
	if allocs != 0 {
		t.Fatalf("%v allocations per line", allocs)
	}
	_ = sink
}

// tokMatches: a key=<*> template token takes any value of its key.
func TestPatternTokMatches(t *testing.T) {
	var toks [maxPatTokens]tok
	msg := "user=alice status=500 user"
	n := tokenize(msg, &toks)
	if n != 3 {
		t.Fatalf("%d tokens", n)
	}
	for _, c := range []struct {
		i    int
		s    string
		want bool
	}{{0, "user=<*>", true}, {0, "user=alice", true}, {0, "user=bob", false}, {0, "usr=<*>", false},
		{1, "status=<NUM>", true}, {1, "status=<*>", true}, {1, "status=500", false}, {2, "user=<*>", false}, {2, "user", true}} {
		if got := tokMatches(msg, toks[c.i], c.s); got != c.want {
			t.Errorf("token %d vs %q: %v", c.i, c.s, got)
		}
	}
	fp := func(s string) uint64 { n := tokenize(s, &toks); return fingerprint(s, toks[:n]) }
	if fp("user=alice status=500") != fp("user=alice status=404") || fp("user=alice status=500") == fp("user=bob status=500") ||
		fp("a b") == fp("ab") || fp("a b") == fp("b a") {
		t.Fatal("fingerprints: masked values must not count, literals and token boundaries must")
	}
}
