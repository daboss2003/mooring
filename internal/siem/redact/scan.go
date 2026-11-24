package redact

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// The scanners below find credential and personal-data shapes by hand. Each is anchored on a
// literal or a byte ("eyJ", "bearer", "://", "AKIA", '@', '+') and reads every byte of the line a
// bounded number of times. Intentional: not regexps — a pattern without a literal prefix runs the
// whole regexp machine at every position of a hostile line, up to ~1 µs per byte for the Unicode
// email pattern, which a few requests per second of crafted paths would turn into a backlog.

// rewriter builds s with spans replaced, copying only once the first span is replaced.
type rewriter struct {
	s       string
	b       strings.Builder
	last    int
	changed bool
}

func (w *rewriter) replace(a, b int, with string) {
	w.b.WriteString(w.s[w.last:a])
	w.b.WriteString(with)
	w.last, w.changed = b, true
}

func (w *rewriter) result() string {
	if !w.changed {
		return w.s
	}
	w.b.WriteString(w.s[w.last:])
	return w.b.String()
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// isASCIIWord is a word byte in the regexp sense (\w, \b): letters, digits, '_'.
func isASCIIWord(c byte) bool { return isAlnum(c) || c == '_' }

func runOf(s string, i int, in func(byte) bool) int {
	for i < len(s) && in(s[i]) {
		i++
	}
	return i
}

func isJWTByte(c byte) bool { return isASCIIWord(c) || c == '-' }

// jwts replaces JSON Web Tokens: eyJ<header>.<payload>.<signature>, and the two further parts of
// an encrypted one.
func jwts(s string) string {
	w := rewriter{s: s}
	for i := 0; ; {
		j := strings.Index(s[i:], "eyJ")
		if j < 0 {
			break
		}
		p := i + j
		h := runOf(s, p+3, isJWTByte)
		if h == p+3 || h == len(s) || s[h] != '.' {
			i = max(h, p+1) // an eyJ inside the same run fails at the same place
			continue
		}
		q := runOf(s, h+1, isJWTByte)
		if q == h+1 || q == len(s) || s[q] != '.' {
			i = max(q, p+1)
			continue
		}
		e := runOf(s, q+1, isJWTByte)
		if e < len(s) && s[e] == '.' {
			if e2 := runOf(s, e+1, isJWTByte); e2 > e+1 && e2 < len(s) && s[e2] == '.' {
				if e3 := runOf(s, e2+1, isJWTByte); e3 > e2+1 {
					e = e3
				}
			}
		}
		w.replace(p, e, redacted)
		i = e
	}
	return w.result()
}

func isCredByte(c byte) bool { return isAlnum(c) || strings.IndexByte("._~+/-", c) >= 0 }

// authSchemes replaces the credential of "Bearer <token>" and "Basic <b64>" (any case), unless
// it is an ordinary word ("basic configuration", "bearer authentication").
func authSchemes(s string) string {
	w := rewriter{s: s}
	for i := 0; i < len(s); {
		j := strings.IndexAny(s[i:], "bB")
		if j < 0 {
			break
		}
		p := i + j
		i = p + 1
		n := 0
		switch {
		case p+6 <= len(s) && strings.EqualFold(s[p:p+6], "bearer"):
			n = 6
		case p+5 <= len(s) && strings.EqualFold(s[p:p+5], "basic"):
			n = 5
		default:
			continue
		}
		if p > 0 && isASCIIWord(s[p-1]) {
			continue
		}
		k := runOf(s, p+n, func(c byte) bool { return c == ' ' || c == '\t' })
		if k == p+n {
			continue
		}
		cs := k
		if k = runOf(s, cs, isCredByte); k == cs {
			continue
		}
		k = runOf(s, k, func(c byte) bool { return c == '=' })
		if ordinaryWord(s[p:p+n], s[cs:k]) {
			i = cs // the word may itself be the scheme: "Bearer Bearer <token>"
			continue
		}
		w.replace(cs, k, redacted)
		i = k
	}
	return w.result()
}

func ordinaryWord(scheme, cred string) bool {
	return len(cred) < 16 && allLetters(cred) && !basicWithColon(scheme, cred)
}

// vendorTokens replaces AWS access key ids, GitHub tokens, Slack tokens and Stripe live secret
// and restricted keys.
func vendorTokens(s string) string {
	s = prefixed(s, "gh", func(s string, p int) (int, int) {
		if p+4 > len(s) || strings.IndexByte("pousr", s[p+2]) < 0 || s[p+3] != '_' {
			return -1, -1
		}
		return p, minRun(s, p+4, 20, isAlnum)
	})
	s = prefixed(s, "github_pat_", func(s string, p int) (int, int) {
		return p, minRun(s, p+11, 20, isASCIIWord)
	})
	s = prefixed(s, "xox", func(s string, p int) (int, int) {
		if p+5 > len(s) || strings.IndexByte("baprs", s[p+3]) < 0 || s[p+4] != '-' {
			return -1, -1
		}
		return p, minRun(s, p+5, 10, func(c byte) bool { return isAlnum(c) || c == '-' })
	})
	s = prefixed(s, "k_live_", func(s string, p int) (int, int) {
		if p == 0 || s[p-1] != 's' && s[p-1] != 'r' {
			return -1, -1
		}
		return p - 1, minRun(s, p+7, 10, isAlnum)
	})
	// Last: an AWS key id needs a word boundary after it, which a token glued to it only gets
	// once replaced (AKIA…sk_live_… → AKIA…[redacted]).
	if strings.Contains(s, "AKIA") || strings.Contains(s, "ASIA") {
		s = prefixed(s, "A", func(s string, p int) (int, int) {
			if p+20 > len(s) || s[p+2] != 'I' || s[p+3] != 'A' || (s[p+1] != 'K' && s[p+1] != 'S') ||
				p > 0 && isASCIIWord(s[p-1]) || p+20 < len(s) && isASCIIWord(s[p+20]) {
				return -1, -1
			}
			for k := p + 4; k < p+20; k++ {
				if c := s[k]; !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
					return -1, -1
				}
			}
			return p, p + 20
		})
	}
	return s
}

// minRun returns the end of the run of in-bytes at i, or -1 when it is shorter than n.
func minRun(s string, i, n int, in func(byte) bool) int {
	if e := runOf(s, i, in); e-i >= n {
		return e
	}
	return -1
}

// prefixed replaces each token that match finds at an occurrence of lit; match returns its span
// or a negative end. A failed match costs only its own bytes: lit can't occur inside a run that
// match rejected without ending it.
func prefixed(s, lit string, match func(s string, p int) (int, int)) string {
	if !strings.Contains(s, lit) {
		return s
	}
	w := rewriter{s: s}
	for i := 0; ; {
		j := strings.Index(s[i:], lit)
		if j < 0 {
			break
		}
		p := i + j
		a, e := match(s, p)
		if e < 0 || a < w.last {
			i = p + 1
			continue
		}
		w.replace(a, e, redacted)
		i = e
	}
	return w.result()
}

func isSchemeByte(c byte) bool { return isAlnum(c) || c == '+' || c == '.' || c == '-' }

// isRESpace is \s in the regexp sense.
func isRESpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r' }

// userinfo replaces the password of scheme://user:password@host.
func userinfo(s string) string {
	w := rewriter{s: s}
	for i := 0; ; {
		j := strings.Index(s[i:], "://")
		if j < 0 {
			break
		}
		p := i + j
		i = p + 3
		a := p
		for a > w.last && isSchemeByte(s[a-1]) {
			a--
		}
		for a < p && !(s[a]|0x20 >= 'a' && s[a]|0x20 <= 'z') {
			a++ // the scheme starts with a letter
		}
		if a == p {
			continue
		}
		u := runOf(s, p+3, func(c byte) bool { return c != '/' && c != ':' && c != '@' && !isRESpace(c) })
		if u >= len(s) || s[u] != ':' {
			continue
		}
		k := runOf(s, u+1, func(c byte) bool { return c != '/' && c != '@' && !isRESpace(c) })
		if k == u+1 || k >= len(s) || s[k] != '@' {
			continue
		}
		w.replace(u+1, k, redacted)
		i = k + 1
	}
	return w.result()
}

// Email addresses: a local part of letters, marks, digits and ._%+-, an '@' (or %40), and a
// domain of labels of letters, marks, digits and '-' joined by dots ending in a top-level domain
// of two letters or more (or xn--…). Unicode letters count (jöhn@exämple.com).

func isLMN(r rune) bool { return unicode.IsLetter(r) || unicode.IsMark(r) || unicode.IsNumber(r) }

// localBack returns where the run of local-part characters ending at k begins, not before floor.
func localBack(s string, k, floor int) int {
	for k > floor {
		if c := s[k-1]; c < utf8.RuneSelf {
			if !isAlnum(c) && strings.IndexByte("._%+-", c) < 0 || encodedStopEnds(s, k, floor) {
				break
			}
			k--
			continue
		}
		r, n := utf8.DecodeLastRuneInString(s[floor:k])
		if r == utf8.RuneError && n <= 1 || !isLMN(r) {
			break
		}
		k -= n
	}
	return k
}

// encodedStopEnds reports whether s[:k] ends in a percent escape of a character a local part
// can't hold (a space, quote, ':', '<'…): "<hash>%20@x.co" or "<hash>%22@x.co" (a re-encoded value)
// is not one address.
func encodedStopEnds(s string, k, floor int) bool {
	if k-3 < floor || s[k-3] != '%' || !isHex(s[k-2]) || !isHex(s[k-1]) {
		return false
	}
	c := unhex(s[k-2])<<4 | unhex(s[k-1])
	// %40 (an encoded '@') is part of the text as a regexp would read it, and the %40 trigger
	// handles it.
	return c != '@' && !isAlnum(c) && strings.IndexByte("._%+-", c) < 0 && c < utf8.RuneSelf
}

// label returns the end of the domain label at k.
func label(s string, k int) int {
	for k < len(s) {
		if c := s[k]; c < utf8.RuneSelf {
			if !isAlnum(c) && c != '-' {
				break
			}
			k++
			continue
		}
		r, n := utf8.DecodeRuneInString(s[k:])
		if r == utf8.RuneError && n <= 1 || !isLMN(r) {
			break
		}
		k += n
	}
	return k
}

// tldPrefix returns the end of the longest top-level domain at the start of the label s[a:b],
// or -1.
func tldPrefix(s string, a, b int) int {
	if b-a > 4 && strings.HasPrefix(s[a:b], "xn--") {
		if e := runOf(s[:b], a+4, func(c byte) bool { return isAlnum(c) || c == '-' }); e > a+4 {
			return e
		}
	}
	k, runes := a, 0
	for k < b {
		r, n := utf8.DecodeRuneInString(s[k:b])
		if runes == 0 && !unicode.IsLetter(r) || runes > 0 && !unicode.IsLetter(r) && !unicode.IsMark(r) {
			break
		}
		k += n
		runes++
	}
	if runes < 2 {
		return -1
	}
	return k
}

// domainEnd returns the end of the longest domain starting at d (two labels or more, the last
// ending in a top-level domain), or d when there is none.
func domainEnd(s string, d int) int {
	end, labels := d, 0
	for k := d; ; k++ {
		ls := k
		if k = label(s, k); k == ls {
			break
		}
		if labels++; labels >= 2 {
			if t := tldPrefix(s, ls, k); t > ls {
				end = t
			}
		}
		if k >= len(s) || s[k] != '.' {
			break
		}
	}
	return end
}

// isEmail reports whether s is one email address (an actor, a key element).
func isEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	return at > 0 && at+1 < len(s) && localBack(s, at, 0) == 0 && domainEnd(s, at+1) == len(s)
}

// emails replaces each email address (also with %40 for the '@') with its Hash, except a URL's
// user part (ssh://git@host).
func (r *Redactor) emails(s string) string {
	w := rewriter{s: s}
	floor := 0                   // where the last address ended: the next can't start before
	prevEnd, prevStart := -1, -1 // the last trigger and its local part, to scan each run once
	for i := 0; i < len(s); {
		j := strings.IndexAny(s[i:], "@%")
		if j < 0 {
			break
		}
		at, n := i+j, 1
		if s[at] == '%' {
			if at+2 >= len(s) || s[at+1] != '4' || s[at+2] != '0' {
				i = at + 1
				continue
			}
			n = 3
		}
		i = at + n
		stop := max(floor, prevEnd)
		a := localBack(s, at, stop)
		// "%40" is made of local-part characters: a run reaching it continues before it.
		if a == stop && prevEnd == stop && stop >= 3 && s[stop-3:stop] == "%40" {
			a = max(prevStart, floor)
		}
		prevEnd, prevStart = at+n, a
		e := domainEnd(s, at+n)
		if a == at || e == at+n {
			continue
		}
		floor, i = e, e
		// A URL's plain user part (ssh://git@github.com) is not an address; an encoded or doubled
		// '@' is (smtp://victim%40x.com:pw@…, imap://victim@x.com@mail…).
		if n == 1 && a >= 3 && s[a-3:a] == "://" && (e == len(s) || s[e] != '@') {
			continue
		}
		// A hash already written here ("h:<hex>@rest" from "a@b.co@rest") is not part of an
		// address: the local part starts after it.
		if a >= 2 && a+16 <= at && isHash(s[a-2:a+16]) && (a+16 == at || !isHex(s[a+16])) {
			if a += 16; a == at {
				continue
			}
		}
		addr := s[a:e]
		if n == 3 {
			addr = s[a:at] + "@" + s[at+3:e]
		}
		w.replace(a, e, r.Hash(addr))
	}
	return w.result()
}
