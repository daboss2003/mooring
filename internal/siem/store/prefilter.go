package store

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"github.com/daboss2003/mooring/internal/siem/query"
)

// prefilter rejects a stored line before it is decoded when it can't match: every needle must be
// in the line, lowercased. A needle is the lowercased value of a positive ':' or '~' term on a
// plain string field, or a text term, and only when every character of it is written literally by
// encoding/json; then an event field (or Msg) that matches has the needle's characters verbatim in
// its line. ip, lvl, geo.asn and f.* compare parsed values, so they give no needle.
type prefilter struct{ needles [][]byte }

var prefilterFields = map[string]bool{
	"src": true, "app": true, "svc": true, "copy": true, "kind": true, "out": true, "actor": true,
	"geo.cc": true, "geo.org": true, "geo.city": true, "list": true,
}

func newPrefilter(q query.Query) prefilter {
	var p prefilter
	add := func(v string) {
		v = strings.ToLower(v)
		if v != "" && jsonLiteral(v) {
			p.needles = append(p.needles, []byte(v))
		}
	}
	for _, t := range q.Terms {
		if t.Neg || !prefilterFields[t.Field] {
			continue
		}
		switch t.Op {
		case query.OpEq:
			add(strings.TrimSuffix(t.Value, "*"))
		case query.OpContains:
			add(t.Value)
		}
	}
	for _, x := range q.Text {
		add(x)
	}
	return p
}

// jsonLiteral reports whether encoding/json writes every character of s as itself (it escapes
// '"', '\\', control characters, '<', '>', '&', U+2028, U+2029, and writes invalid UTF-8 as
// �).
func jsonLiteral(s string) bool {
	for _, r := range s {
		switch {
		case r < 0x20, r == '"', r == '\\', r == '<', r == '>', r == '&', r == ' ', r == ' ', r == utf8.RuneError:
			return false
		}
	}
	return true
}

func (p prefilter) pass(line []byte) bool {
	if len(p.needles) == 0 {
		return true
	}
	ascii := true
	for _, c := range line {
		if c >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	var low []byte
	for _, n := range p.needles {
		if ascii {
			if !containsLowerASCII(line, n) {
				return false
			}
			continue
		}
		if low == nil {
			low = bytes.ToLower(line)
		}
		if !bytes.Contains(low, n) {
			return false
		}
	}
	return true
}

// containsLowerASCII reports whether the ASCII text s, lowercased, contains the lowercase needle.
func containsLowerASCII(s, needle []byte) bool {
	n := len(needle)
	if n > len(s) {
		return false
	}
	c0 := needle[0]
outer:
	for i := 0; i+n <= len(s); i++ {
		if lower(s[i]) != c0 {
			continue
		}
		for j := 1; j < n; j++ {
			if lower(s[i+j]) != needle[j] {
				continue outer
			}
		}
		return true
	}
	return false
}

func lower(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
