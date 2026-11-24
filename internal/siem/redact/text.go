package redact

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
)

// rePEM is the one pattern left to the regexp engine: it starts with a literal, which the engine
// jumps between (the other patterns are the scanners in scan.go).
var rePEM = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----(?s:.*?)(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|$)`)

// text redacts one string: credential patterns, URL passwords, key=value pairs by key name (also
// inside percent-encoded values), and (when pii is set) email addresses and phone numbers → Hash.
func (r *Redactor) text(s string, pii bool) string {
	if len(s) < 3 {
		return s
	}
	s = tokens(s)
	if strings.Contains(s, "://") && strings.IndexByte(s, '@') >= 0 {
		s = userinfo(s)
	}
	if hasEncodedPair(s) {
		s = r.decodedValues(s)
	}
	if strings.ContainsAny(s, "=:") {
		s = r.kv(s)
	}
	if pii {
		t := s
		if strings.IndexByte(s, '@') >= 0 || strings.Contains(s, "%40") {
			s = r.emails(s)
		}
		s = r.phones(s)
		// Intentional: a hash written over an address or phone number holds a ':' ("h:…"); after
		// "://" it can read as user:password@, so the URL pass runs once more over the result.
		if s != t && strings.Contains(s, "://") && strings.IndexByte(s, '@') >= 0 {
			s = userinfo(s)
		}
	}
	return s
}

// tokens replaces credential-shaped substrings, whatever key they appear under.
func tokens(s string) string {
	if strings.Contains(s, "PRIVATE KEY") && rePEM.MatchString(s) {
		s = rePEM.ReplaceAllLiteralString(s, redacted)
	}
	if strings.Contains(s, "eyJ") {
		s = jwts(s)
	}
	if authCandidate(s) {
		s = authSchemes(s)
	}
	if vendorCandidate(s) {
		s = vendorTokens(s)
	}
	return s
}

// hasToken reports whether a field name contains a JWT or vendor key (names never hold PEM
// blocks or "Bearer x", so those checks are skipped).
func hasToken(s string) bool {
	return strings.Contains(s, "eyJ") && jwts(s) != s || vendorCandidate(s) && vendorTokens(s) != s
}

func basicWithColon(scheme, cred string) bool {
	if !strings.EqualFold(scheme, "basic") {
		return false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		if b, err := enc.DecodeString(cred); err == nil && strings.IndexByte(string(b), ':') >= 0 {
			return true
		}
	}
	return false
}

func allLetters(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i] | 0x20; c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

// authCandidate is the cheap check for "Bearer"/"Basic" in the casings HTTP clients and
// loggers write (Bearer, bearer, BEARER).
func authCandidate(s string) bool {
	return strings.Contains(s, "earer") || strings.Contains(s, "EARER") ||
		strings.Contains(s, "asic") || strings.Contains(s, "ASIC")
}

func vendorCandidate(s string) bool {
	if strings.Contains(s, "AKIA") || strings.Contains(s, "ASIA") || strings.Contains(s, "xox") ||
		strings.Contains(s, "k_live_") || strings.Contains(s, "github_pat_") {
		return true
	}
	for i := strings.Index(s, "gh"); i >= 0 && i+3 < len(s); {
		if strings.IndexByte("pousr", s[i+2]) >= 0 && s[i+3] == '_' {
			return true
		}
		j := strings.Index(s[i+2:], "gh")
		if j < 0 {
			break
		}
		i += 2 + j
	}
	return false
}

// maxKeyScan bounds how far back from a '=' or ':' a key is read.
const maxKeyScan = 96

func isKeyByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '_' || c == '-' || c == '.' || c == '[' || c == ']' || c == '%'
}

// kv replaces the value of every key=value, key: value, "key":"value", 'key' => 'value' pair
// whose key is a secret, personal-data or dropped name (in log text, query strings and form
// bodies). It allocates only when it replaces something, and is linear in len(s): a value it
// leaves alone is never scanned again from a separator inside it.
func (r *Redactor) kv(s string) string {
	var out []byte
	last := 0
	runStart, runEnd := -1, -1 // the last base64 run measured for a signature value
	for i := 0; i < len(s); {
		j := strings.IndexAny(s[i:], "=:")
		if j < 0 {
			break
		}
		sep := i + j
		i = sep + 1
		if writtenHash(s, sep) {
			i = sep + 17 // the ':' of a hash already written ("email[h:…" is not key h)
			continue
		}
		c, quotedKey := r.keyBefore(s, sep)
		if c == clsNone || c == clsKeep {
			continue
		}
		cs, q := valueStart(s, sep)
		// Intentional: a value already redacted is stepped over, never rescanned from inside;
		// rescanning made "pwd=[redacted]" repeated over a line quadratic.
		if strings.HasPrefix(s[cs:], redacted) {
			i = max(i, cs+len(redacted))
			continue
		}
		var ce, ve int
		if c == clsSignature {
			// A signature is redacted only when the whole value is one long base64/hex run. The run
			// is measured once: a later signature= inside it shares its end.
			if cs < runStart || cs >= runEnd {
				runStart, runEnd = cs, b64End(s, cs)
			}
			ce, ve = runEnd, runEnd
			if ce-cs < 32 || !valueEndsAt(s, ce, q, quotedKey) {
				continue // a pair inside the run (signature=password=x) is still read
			}
		} else {
			if c == clsHash {
				// A hash already written here is stepped over, and scanning resumes right after it
				// (phone=h:<hex>!0, or h:<hex>,password=x where a pair follows).
				a := cs
				for a < len(s) && strings.IndexByte("<([{", s[a]) >= 0 {
					a++
				}
				if a+18 <= len(s) && isHash(s[a:a+18]) && (a+18 == len(s) || !isHex(s[a+18])) {
					i = max(i, a+18)
					continue
				}
			}
			ce, ve = valueEnd(s, cs, q, c == clsHeader, quotedKey)
			// A phone number written with spaces is one value: phone: +234 803 123 4567.
			if pe := phoneEnd(s, cs); c == clsHash && pe > ce && (pe == len(s) || !isWordByte(s[pe])) {
				ce, ve = pe, pe
			}
		}
		repl, ce, ok := r.replacement(c, s, cs, ce, s[sep] == '=')
		i = max(i, ve)
		if !ok {
			continue
		}
		if out == nil {
			out = make([]byte, 0, len(s)+32)
		}
		out = append(out, s[last:cs]...)
		out = append(out, repl...)
		last = ce
	}
	if out == nil {
		return s
	}
	return string(append(out, s[last:]...))
}

// writtenHash reports whether s[sep] is the ':' of a Hash result standing alone: "h:" + 16 hex,
// the h not continuing a word (so key "auth:0123456789abcdef" is still a key) and no more hex
// after it.
func writtenHash(s string, sep int) bool {
	if s[sep] != ':' || sep < 1 || s[sep-1] != 'h' || sep >= 2 && isAlnum(s[sep-2]) ||
		sep+17 > len(s) || !isHash(s[sep-1:sep+17]) {
		return false
	}
	return sep+17 == len(s) || !isHex(s[sep+17])
}

// keyBefore classifies the key that ends just before s[sep] ("key=", "key :", `"key":`, `\"key\":`).
func (r *Redactor) keyBefore(s string, sep int) (class, bool) {
	ke := sep
	for ke > 0 && sep-ke < 4 && (s[ke-1] == ' ' || s[ke-1] == '\t') {
		ke--
	}
	quoted := false
	if ke > 0 && (s[ke-1] == '"' || s[ke-1] == '\'') {
		ke--
		quoted = true
		if ke > 0 && s[ke-1] == '\\' {
			ke--
		}
	}
	ks := ke
	for ks > 0 && ke-ks < maxKeyScan && isKeyByte(s[ks-1]) {
		ks--
	}
	if ks == ke {
		return clsNone, false
	}
	return r.classifyText(s[ks:ke]), quoted
}

// valueStart returns where the value after s[sep] begins (after "=>", blanks and an opening
// quote) and that quote: a double or single quote, a backslash for an escaped \", or 0.
func valueStart(s string, sep int) (int, byte) {
	vs := sep + 1
	if s[sep] == '=' && vs < len(s) && s[vs] == '>' {
		vs++
	}
	for vs < len(s) && vs-sep < 6 && (s[vs] == ' ' || s[vs] == '\t') {
		vs++
	}
	if vs < len(s) {
		switch s[vs] {
		case '"', '\'':
			return vs + 1, s[vs]
		case '\\':
			if vs+1 < len(s) && s[vs+1] == '"' {
				return vs + 2, '\\'
			}
		}
	}
	return vs, 0
}

// valueEnd finds the end of a value starting at cs: ce ends its content, ve is where scanning
// resumes. A quoted value runs to its closing quote (or the end); an unquoted one to whitespace,
// '&' or a quote — after a quoted key (JSON) also to ',', '}' or ']' — and a header value
// (Authorization, Cookie) to the end of the line.
func valueEnd(s string, cs int, q byte, header, quotedKey bool) (ce, ve int) {
	switch q {
	case '"', '\'':
		for k := cs; k < len(s); k++ {
			if s[k] == '\\' {
				k++
				continue
			}
			if s[k] == q {
				return k, k + 1
			}
		}
		return len(s), len(s)
	case '\\':
		if k := strings.Index(s[cs:], `\"`); k >= 0 {
			return cs + k, cs + k + 2
		}
		return len(s), len(s)
	}
	k := cs
	for ; k < len(s); k++ {
		c := s[k]
		if c == '\n' || c == '\r' || c == '"' || c == '\'' {
			break
		}
		if header {
			continue
		}
		if c == ' ' || c == '\t' || c == '&' {
			break
		}
		if quotedKey && (c == ',' || c == '}' || c == ']') {
			break
		}
	}
	return k, k
}

func isB64(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '+' || c == '/' || c == '=' || c == '_' || c == '-'
}

func b64End(s string, k int) int {
	for k < len(s) && isB64(s[k]) {
		k++
	}
	return k
}

// valueEndsAt reports whether a value of quote q ends at s[k] (so s[cs:k] is the whole value).
func valueEndsAt(s string, k int, q byte, quotedKey bool) bool {
	if k >= len(s) {
		return true
	}
	c := s[k]
	switch q {
	case '"', '\'':
		return c == q
	case '\\':
		return c == '\\' && k+1 < len(s) && s[k+1] == '"'
	}
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '&' || c == '"' || c == '\'' ||
		quotedKey && (c == ',' || c == '}' || c == ']')
}

// replacement is what replaces s[cs:ce] for class c; ce may move back (trailing punctuation
// kept out of a hashed value). ok is false when nothing is replaced.
func (r *Redactor) replacement(c class, s string, cs, ce int, eqSep bool) (string, int, bool) {
	if cs >= ce {
		return "", ce, false
	}
	switch c {
	case clsSecret, clsHeader, clsDrop, clsSignature:
		return redacted, ce, true
	case clsHash:
		if phoneEnd(s, cs) == ce {
			return r.Hash(s[cs:ce]), ce, true // the value is one phone number, as written
		}
		// Punctuation around the value stays outside the hash (email: <a@b.co>.), so it is the
		// hash of the address SearchText and SearchValue give.
		for ce > cs && strings.IndexByte(",;:.!?)]}>", s[ce-1]) >= 0 {
			ce--
		}
		a := cs
		for a < ce && strings.IndexByte("<([{", s[a]) >= 0 {
			a++
		}
		v := s[a:ce]
		if v == "" || isHash(v) || v == "null" || v == "true" || v == "false" {
			return "", ce, false
		}
		if eqSep && strings.IndexByte(v, '%') >= 0 {
			if d, err := url.PathUnescape(v); err == nil {
				v = d
			}
		}
		return s[cs:a] + r.Hash(v), ce, true
	}
	return "", ce, false
}

// hasEncodedPair reports whether s holds a percent-encoded '"', ':' or '=' — the signs of a
// key/value pair hidden by URL encoding (?variables=%7B%22password%22%3A%22…%22%7D).
func hasEncodedPair(s string) bool {
	for i := strings.IndexByte(s, '%'); i >= 0 && i+2 < len(s); {
		switch a, b := s[i+1], s[i+2]|0x20; {
		case a == '2' && b == '2', a == '3' && (b == 'a' || b == 'd'):
			return true
		}
		j := strings.IndexByte(s[i+1:], '%')
		if j < 0 {
			break
		}
		i += 1 + j
	}
	return false
}

// isValueStop ends a value in decodedValues (and is always re-encoded there, so the value stays
// one piece).
func isValueStop(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '&', '?', '#', '"', '\'':
		return true
	}
	return false
}

// decodedValues finds each value (the part of a token after its first '=') that hides a
// key/value pair behind percent-encoding, decodes it once, redacts the pairs in it, and when that
// changed something writes it back re-encoded ('%', '=' and the value stops) so the line keeps its
// shape and a second pass finds nothing new. One level only: what is still encoded after one
// decode stays as it is.
func (r *Redactor) decodedValues(s string) string {
	var b strings.Builder
	last := 0
	for i := 0; i < len(s); {
		j := i
		for j < len(s) && !isValueStop(s[j]) {
			j++
		}
		// The value is what follows the token's first '=', unless the part before it is encoded
		// too: then the whole token, so a pass that redacts that '=' away decodes the same span.
		vs := i
		if eq := strings.IndexByte(s[i:j], '='); eq >= 0 && !hasEncodedPair(s[i:i+eq]) {
			vs = i + eq + 1
		}
		if v := s[vs:j]; hasEncodedPair(v) {
			d := pctDecode(v)
			if in := r.kv(tokens(d)); in != d {
				b.WriteString(s[last:vs])
				pctEncodeStops(&b, in)
				last = j
			}
		}
		i = j + 1
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func pctEncodeStops(b *strings.Builder, s string) {
	const hexd = "0123456789ABCDEF"
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '%' || c == '=' || isValueStop(c) {
			b.WriteByte('%')
			b.WriteByte(hexd[c>>4])
			b.WriteByte(hexd[c&15])
		} else {
			b.WriteByte(c)
		}
	}
}

func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c >= 0x80
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// phoneEnd returns the end of the phone number written at s[p:], or -1: "+" and 10–15 digits, or
// a national number of "0" (not "00") and 10 more digits. The digits may be grouped by single
// spaces, dashes or dots ("+234 803 123 4567", "0803-123-4567"), and a national area code may be
// in parentheses ("(0803) 123 4567"). When more groups follow than a number holds, the longest
// valid number is taken. Intentional trade-offs: "+" needs 10 digits, so "+1234567" (a delta) is
// not a number; "00" starts a padded id, not a number; a padded id like "01234567890" still
// hashes, since a UK geographic number has exactly that shape.
func phoneEnd(s string, p int) int {
	k, plus, paren := p, false, false
	switch {
	case k < len(s) && s[k] == '+':
		plus, k = true, k+1
	case k < len(s) && s[k] == '(':
		paren, k = true, k+1
	}
	g := k
	for k < len(s) && isDigit(s[k]) && k-g <= 15 {
		k++
	}
	first := k - g
	if first == 0 || first > 15 {
		return -1
	}
	if !plus && (s[g] != '0' || first < 2 || s[g+1] == '0') {
		return -1
	}
	valid := func(n int) bool {
		if plus {
			return n >= 10 && n <= 15
		}
		return n == 11
	}
	digits, best, needSep := first, -1, true
	if paren {
		if first < 3 || first > 5 || k >= len(s) || s[k] != ')' {
			return -1
		}
		if k++; k < len(s) && s[k] == ' ' {
			k++
		}
		needSep = false
	} else {
		// One unbroken run ("+2348031234567", "08031234567"), not the start of a decimal.
		if valid(digits) && !(k+1 < len(s) && s[k] == '.' && isDigit(s[k+1])) {
			best = k
		}
		if plus && first > 4 || !plus && (first < 3 || first > 5) {
			return best // only a short country or area code starts a grouped number
		}
	}
	for groups := 1; groups < 8 && digits <= 15; groups++ {
		j := k
		if needSep {
			if j >= len(s) || s[j] != ' ' && s[j] != '-' && s[j] != '.' {
				break
			}
			j++
		}
		needSep = true
		g := j
		for j < len(s) && isDigit(s[j]) && j-g <= 10 {
			j++
		}
		if n := j - g; n < 2 || n > 10 {
			break
		}
		digits += j - g
		k = j
		if digits <= 15 && valid(digits) {
			best = k
		}
	}
	return best
}

// phoneToken reports whether s is one phone number as written in free text (phoneEnd).
func phoneToken(s string) bool { return s != "" && phoneEnd(s, 0) == len(s) }

// phones replaces each phone number standing on its own in free text (phoneEnd; not inside a
// longer word or number, not after a decimal point) with its Hash. Intentional: stricter than an
// actor (isPhone), so epoch timestamps, ports and ids in a line stay readable.
func (r *Redactor) phones(s string) string {
	w := rewriter{s: s}
	for i := 0; i < len(s); {
		j := strings.IndexAny(s[i:], "+0(")
		if j < 0 {
			break
		}
		p := i + j
		i = p + 1
		if p > 0 && (isWordByte(s[p-1]) || s[p-1] == '.' || s[p-1] == '+') {
			continue
		}
		e := phoneEnd(s, p)
		if e < 0 || e < len(s) && isWordByte(s[e]) {
			continue
		}
		w.replace(p, e, r.Hash(s[p:e]))
		i = e
	}
	return w.result()
}
