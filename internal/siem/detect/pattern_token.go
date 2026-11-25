package detect

import (
	"net/netip"
	"strings"
)

// The log-pattern tokenizer (docs/security-detections.md "Log patterns"): a line's text (Msg,
// already redacted) is split at whitespace into at most maxPatTokens tokens, and the variable part
// of each is masked. Byte scanners only, no regular expressions: it runs for every line mined, a
// repeated line included, and allocates nothing.

const (
	maxPatTokens = 64
	maxPatLine   = 1 << 10 // bytes of a line's text mined (offerPattern takes this prefix)
	maxPlainTok  = 32      // a longer token is <LONG>
	maxTokText   = 2 * maxPlainTok
	maxPatKey    = 32 // bytes of the key of a key=value token
)

// Mask codes (tok.code); mLit is a literal token.
const (
	mLit uint8 = iota
	mNum
	mHex
	mUUID
	mIP
	mTS
	mHash
	mB64
	mStr
	mLong
	mRest // the rest of a line past maxPatTokens
)

const wildcard = "<*>"

var maskText = [...]string{mLit: "", mNum: "<NUM>", mHex: "<HEX>", mUUID: "<UUID>", mIP: "<IP>", mTS: "<TS>",
	mHash: "<HASH>", mB64: "<B64>", mStr: "<STR>", mLong: "<LONG>", mRest: wildcard}

// tok is one token of a line: the text msg[ps:pe] (all of it for a literal token), the mask, then
// msg[ss:se]. kv > 0: the token is key=value and msg[ps:ps+kv] is its "key=".
type tok struct {
	ps, pe, ss, se uint16
	kv             uint16
	code           uint8
}

func isSep(c byte) bool { return c <= ' ' || c == 0x7f }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHexDigit(c byte) bool { return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// skipEscape skips an ANSI escape sequence (ESC '[' … final byte, colours) at msg[i], or the ESC.
func skipEscape(msg string, i int) int {
	i++
	if i >= len(msg) || msg[i] != '[' {
		return i
	}
	i++
	for i < len(msg) && msg[i] >= 0x30 && msg[i] <= 0x3f {
		i++
	}
	for i < len(msg) && msg[i] >= 0x20 && msg[i] <= 0x2f {
		i++
	}
	if i < len(msg) && msg[i] >= 0x40 && msg[i] <= 0x7e {
		i++
	}
	return i
}

// closeQuote returns the index of the quote closing the run opened at msg[i], -1 for none. In a
// double-quoted run a backslash escapes the next byte.
func closeQuote(msg string, i int) int {
	q := msg[i]
	for j := i + 1; j < len(msg); j++ {
		switch msg[j] {
		case '\\':
			if q == '"' {
				j++
			}
		case q:
			return j
		}
	}
	return -1
}

func validKey(k string) bool {
	if k == "" || len(k) > maxPatKey || !(isLetter(k[0]) || k[0] == '_') {
		return false
	}
	for i := 1; i < len(k); i++ {
		c := k[i]
		if !isLetter(c) && !isDigit(c) && c != '_' && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

// tokenize splits msg (at most maxPatLine bytes) into toks and returns how many. A quoted run is
// <STR>; key=value keeps "key=" and masks the value; a run of more than maxPatTokens tokens ends
// in one <*> for the rest. Control characters separate tokens; ANSI colour sequences are skipped.
func tokenize(msg string, toks *[maxPatTokens]tok) int {
	if len(msg) > maxPatLine {
		msg = msg[:maxPatLine]
	}
	n := 0
	for i := 0; i < len(msg); {
		c := msg[i]
		if isSep(c) {
			if c == 0x1b {
				i = skipEscape(msg, i)
			} else {
				i++
			}
			continue
		}
		if n == maxPatTokens {
			toks[n-1] = tok{code: mRest}
			return n
		}
		start, end := i, i
		quoted, kv := -1, 0 // the closing quote of a quoted run (the token's or its value's)
		if c == '"' || c == '\'' {
			if j := closeQuote(msg, i); j > 0 {
				quoted, end = j, j+1
			}
		}
		for end < len(msg) && !isSep(msg[end]) {
			if msg[end] == '=' && kv == 0 && quoted < 0 && validKey(msg[start:end]) {
				kv = end - start + 1
				if v := end + 1; v < len(msg) && (msg[v] == '"' || msg[v] == '\'') {
					if j := closeQuote(msg, v); j > 0 {
						quoted, end = j, j+1
						continue
					}
				}
			}
			end++
		}
		toks[n] = classifyTok(msg, start, end, kv, quoted)
		n++
		i = end
	}
	return n
}

// classifyTok is the token msg[start:end]; kv its "key=" length (0: none), quoted the index of the
// quote closing its quoted run (the token's or its value's; -1: none).
func classifyTok(msg string, start, end, kv, quoted int) tok {
	u := func(v int) uint16 { return uint16(v) }
	t := tok{ps: u(start), pe: u(end), ss: u(end), se: u(end), kv: u(kv)}
	switch {
	case quoted >= 0:
		t.pe, t.ss, t.code = u(start+kv), u(quoted+1), mStr
	case kv > 0 && start+kv < end:
		lead, trail, code := classifyTrim(msg[start+kv : end])
		if code != mLit {
			t.pe, t.ss, t.code = u(start+kv+lead), u(end-trail), code
		}
	case kv == 0:
		lead, trail, code := classifyTrim(msg[start:end])
		if code != mLit {
			t.pe, t.ss, t.code = u(start+lead), u(end-trail), code
		}
	}
	if int(t.pe-t.ps)+len(maskText[t.code])+int(t.se-t.ss) > maxTokText {
		t = tok{ps: u(start), pe: u(start), ss: u(start), se: u(start), code: mLong}
	}
	return t
}

func isLead(c byte) bool { return c == '(' || c == '[' || c == '{' || c == '<' }

func isTrail(c byte) bool {
	switch c {
	case ')', ']', '}', '>', ',', ';', '.', ':', '!', '?':
		return true
	}
	return false
}

// classifyTrim masks s: as it is, else without leading brackets and trailing brackets and
// punctuation (returned as lead and trail bytes kept around the mask), else <LONG> past
// maxPlainTok; mLit when s is a constant.
func classifyTrim(s string) (lead, trail int, code uint8) {
	if c := classify(s); c != mLit {
		return 0, 0, c
	}
	l, r := 0, len(s)
	for l < r && isLead(s[l]) {
		l++
	}
	for r > l && isTrail(s[r-1]) {
		r--
	}
	if (l > 0 || r < len(s)) && r > l {
		if c := classify(s[l:r]); c != mLit {
			return l, len(s) - r, c
		}
	}
	if len(s) > maxPlainTok {
		return 0, 0, mLong
	}
	return 0, 0, mLit
}

// classify is the mask of s, mLit when it is none (<LONG> aside).
func classify(s string) uint8 {
	n := len(s)
	if n == 0 {
		return mLit
	}
	switch {
	case n == 18 && s[0] == 'h' && s[1] == ':' && isLowerHex(s[2:]):
		return mHash // redaction's keyed hash
	case n == 36 && isUUID(s):
		return mUUID
	}
	c := s[0]
	if isDigit(c) {
		switch {
		case isTS(s):
			return mTS
		case isIPv4(s):
			return mIP
		case isNum(s):
			return mNum
		}
	}
	if (c == '+' || c == '-') && n > 1 && isDigit(s[1]) && isNum(s) {
		return mNum
	}
	switch {
	case strings.IndexByte(s, ':') >= 0 && isIPv6(s):
		return mIP
	case isHex(s):
		return mHex
	case isB64(s):
		return mB64
	}
	return mLit
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !isDigit(c) && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func allHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHexDigit(s[i]) {
			return false
		}
	}
	return len(s) > 0
}

func isUUID(s string) bool {
	for i := 0; i < 36; i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHexDigit(s[i]) {
				return false
			}
		}
	}
	return true
}

// isHex: 0x followed by hex digits, or at least 8 hex digits.
func isHex(s string) bool {
	if len(s) >= 3 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return allHex(s[2:])
	}
	return len(s) >= 8 && allHex(s)
}

// isB64: at least 20 base64 (or base64url) characters with an upper and a lower case letter and a
// digit, '=' only as padding at the end; not a path (a leading '/').
func isB64(s string) bool {
	if len(s) < 20 || s[0] == '/' {
		return false
	}
	var up, lo, dig bool
	pad := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '=':
			pad++
			continue
		case pad > 0:
			return false
		case c >= 'A' && c <= 'Z':
			up = true
		case c >= 'a' && c <= 'z':
			lo = true
		case isDigit(c):
			dig = true
		case c == '+' || c == '/' || c == '_' || c == '-':
		default:
			return false
		}
	}
	return up && lo && dig && pad <= 3
}

// digitsAt reports whether s[i:i+n] are n digits, and their value.
func digitsAt(s string, i, n int) (int, bool) {
	if i+n > len(s) {
		return 0, false
	}
	v := 0
	for j := i; j < i+n; j++ {
		if !isDigit(s[j]) {
			return 0, false
		}
		v = v*10 + int(s[j]-'0')
	}
	return v, true
}

// isTS: an RFC 3339 time, a date (YYYY-MM-DD or YYYY/MM/DD) with an optional time, or a clock time
// (HH:MM, HH:MM:SS with an optional fraction), with an optional zone.
func isTS(s string) bool {
	i := 0
	if len(s) >= 10 && (s[4] == '-' || s[4] == '/') && s[7] == s[4] {
		_, y := digitsAt(s, 0, 4)
		mo, m := digitsAt(s, 5, 2)
		d, dd := digitsAt(s, 8, 2)
		if !y || !m || !dd || mo < 1 || mo > 12 || d < 1 || d > 31 {
			return false
		}
		if i = 10; i == len(s) {
			return true
		}
		if c := s[i]; c != 'T' && c != 't' && c != '_' {
			return false
		}
		i++
	}
	j, ok := clockLen(s[i:])
	if !ok {
		return false
	}
	return isZone(s[i+j:])
}

// clockLen is the length of the clock time HH:MM[:SS[.frac]] that starts s.
func clockLen(s string) (int, bool) {
	h, ok1 := digitsAt(s, 0, 2)
	m, ok2 := digitsAt(s, 3, 2)
	if !ok1 || !ok2 || s[2] != ':' || h > 24 || m > 59 {
		return 0, false
	}
	i := 5
	if i < len(s) && s[i] == ':' {
		sec, ok := digitsAt(s, i+1, 2)
		if !ok || sec > 60 {
			return 0, false
		}
		i += 3
		if i+1 < len(s) && (s[i] == '.' || s[i] == ',') && isDigit(s[i+1]) {
			i++
			for i < len(s) && isDigit(s[i]) {
				i++
			}
		}
	}
	return i, true
}

func isZone(s string) bool {
	switch {
	case s == "", s == "Z", s == "z":
		return true
	case s[0] != '+' && s[0] != '-':
		return false
	}
	s = s[1:]
	if _, ok := digitsAt(s, 0, 2); !ok {
		return false
	}
	switch s = s[2:]; {
	case s == "":
		return true
	case s[0] == ':':
		s = s[1:]
	}
	_, ok := digitsAt(s, 0, 2)
	return ok && len(s) == 2
}

// isIPv4: a.b.c.d with an optional :port or /bits.
func isIPv4(s string) bool {
	i := 0
	for part := 0; part < 4; part++ {
		if part > 0 {
			if i >= len(s) || s[i] != '.' {
				return false
			}
			i++
		}
		j, v := i, 0
		for j < len(s) && isDigit(s[j]) && j-i < 3 {
			v = v*10 + int(s[j]-'0')
			j++
		}
		if j == i || v > 255 {
			return false
		}
		i = j
	}
	if i == len(s) {
		return true
	}
	lim := 65535
	switch s[i] {
	case ':':
	case '/':
		lim = 32
	default:
		return false
	}
	v, d := 0, 0
	for i++; i < len(s); i++ {
		if !isDigit(s[i]) || d == 5 {
			return false
		}
		v, d = v*10+int(s[i]-'0'), d+1
	}
	return d > 0 && v <= lim
}

// isIPv6: an IPv6 address, bare, in brackets with an optional :port, or with /bits.
func isIPv6(s string) bool {
	if len(s) > 2 && s[0] == '[' {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return false
		}
		rest := s[end+1:]
		if rest != "" {
			if rest[0] != ':' || len(rest) < 2 || len(rest) > 6 {
				return false
			}
			for i := 1; i < len(rest); i++ {
				if !isDigit(rest[i]) {
					return false
				}
			}
		}
		s = s[1:end]
	} else if k := strings.IndexByte(s, '/'); k > 0 {
		bits, ok := 0, k+1 < len(s) && len(s)-k-1 <= 3
		for i := k + 1; ok && i < len(s); i++ {
			ok = isDigit(s[i])
			bits = bits*10 + int(s[i]-'0')
		}
		if !ok || bits > 128 {
			return false
		}
		s = s[:k]
	}
	// Only a run that can be one is parsed (a failed parse allocates its error).
	colons := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == ':':
			colons++
		case c == '.' || isHexDigit(c):
		default:
			return false
		}
	}
	if colons < 2 || len(s) > 45 {
		return false
	}
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is6()
}

// isNum: a decimal number (sign, fraction, exponent) with an optional unit (ms, s, %, KB, MiB …),
// or a Go duration of several parts (1h2m3.5s).
func isNum(s string) bool {
	i := 0
	if s[0] == '+' || s[0] == '-' {
		i++
	}
	for {
		if i >= len(s) || !isDigit(s[i]) {
			return false
		}
		for i < len(s) && isDigit(s[i]) {
			i++
		}
		if i+1 < len(s) && s[i] == '.' && isDigit(s[i+1]) {
			for i++; i < len(s) && isDigit(s[i]); i++ {
			}
		}
		if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
			j := i + 1
			if j < len(s) && (s[j] == '+' || s[j] == '-') {
				j++
			}
			if j < len(s) && isDigit(s[j]) {
				for i = j; i < len(s) && isDigit(s[i]); i++ {
				}
			}
		}
		u := i
		for i < len(s) && isUnitByte(s[i]) {
			i++
		}
		unit := s[u:i]
		if i == len(s) {
			return unit == "" || isUnit(unit)
		}
		if !isDurUnit(unit) {
			return false
		}
	}
}

// isUnitByte: a letter, '%', or a byte of µ (U+00B5) or μ (U+03BC).
func isUnitByte(c byte) bool {
	return isLetter(c) || c == '%' || c == 0xc2 || c == 0xb5 || c == 0xce || c == 0xbc
}

var numUnits = []string{"ns", "us", "µs", "μs", "ms", "s", "m", "h", "d", "w", "%", "b", "k", "kb", "kib", "mb",
	"mib", "g", "gb", "gib", "t", "tb", "tib", "bytes", "x"}

func isUnit(u string) bool {
	for _, x := range numUnits {
		if strings.EqualFold(u, x) {
			return true
		}
	}
	return false
}

func isDurUnit(u string) bool {
	switch u {
	case "h", "m", "s", "ms", "us", "µs", "μs", "ns":
		return true
	}
	return false
}

// tokText is a line's token as text, a copy (it never keeps the line's memory).
func tokText(msg string, t tok) string {
	return string(appendTok(make([]byte, 0, int(t.pe-t.ps)+len(maskText[t.code])+int(t.se-t.ss)), msg, t))
}

// appendTok appends a line's token as text.
func appendTok(b []byte, msg string, t tok) []byte {
	b = append(b, msg[t.ps:t.pe]...)
	b = append(b, maskText[t.code]...)
	return append(b, msg[t.ss:t.se]...)
}

// tokIs reports whether a line's token is the template token s (as text).
func tokIs(msg string, t tok, s string) bool {
	p, m, q := msg[t.ps:t.pe], maskText[t.code], msg[t.ss:t.se]
	return len(s) == len(p)+len(m)+len(q) && s[:len(p)] == p && s[len(p):len(p)+len(m)] == m && s[len(p)+len(m):] == q
}

// tokMatches reports whether a line's token fits the template token s (not <*>): it is s, or s is
// "key=<*>" and the token has that key.
func tokMatches(msg string, t tok, s string) bool {
	if k := kvWild(s); k != "" {
		return t.kv > 0 && msg[t.ps:t.ps+t.kv] == k
	}
	return tokIs(msg, t, s)
}

// kvWild is the "key=" of a template token "key=<*>", "" for any other.
func kvWild(s string) string {
	if len(s) > len(wildcard)+1 && strings.HasSuffix(s, "="+wildcard) {
		return s[:len(s)-len(wildcard)]
	}
	return ""
}

// kvKeyOf is the "key=" of a template token that is key=value, "" for any other.
func kvKeyOf(s string) string {
	if i := strings.IndexByte(s, '='); i > 0 && validKey(s[:i]) {
		return s[:i+1]
	}
	return ""
}

// fingerprint is a line's masked tokens' hash (FNV-1a 64), the fingerprint cache's key.
func fingerprint(msg string, toks []tok) uint64 {
	const prime = 1099511628211
	h := uint64(14695981039346656037)
	for _, t := range toks {
		for i := t.ps; i < t.pe; i++ {
			h = (h ^ uint64(msg[i])) * prime
		}
		h = (h ^ (0x100 + uint64(t.code))) * prime
		for i := t.ss; i < t.se; i++ {
			h = (h ^ uint64(msg[i])) * prime
		}
		h = (h ^ 0x200) * prime
	}
	return (h ^ uint64(len(toks))) * prime
}

func hasDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			return true
		}
	}
	return false
}
