// Package query parses and evaluates the security-log search syntax (docs/security-logs.md
// "Search"): space-separated terms field:value, field!=value, field>N, field>=N, field<N, field<=N,
// field~substring, a leading '-' negates a term, "quoted text" or a bare word matches Msg.
//
// Syntax. Terms are separated by whitespace and all of them must match. A term is
// field<op>value, or text: a bare word without an operator, or a double-quoted string (\" and \\
// are escapes). A value may be quoted too (f.path:"/a b"). Field names are matched without regard
// to case; the key after "f." is the exact flattened key of Event.F. A search is at most 2 KiB and
// 32 terms. A bare word that contains an operator character (http://x) must be quoted to search
// the text.
//
// Matching. Strings compare without regard to case. ':' is equality, and a value ending in '*'
// matches as a prefix (kind:auth.*, app:* matches any app). '!=' is the opposite of ':' for an
// event that has the field. '~' is a substring match. ip:<prefix> (ip:10.0.0.0/8) matches the
// addresses in the prefix and ip:<address> compares addresses. lvl compares by level
// (lvl>=warn). geo.asn and f.* compare as numbers when both sides are numbers (f.status>=500);
// other f.* values compare as strings. list matches any of the IP's threat-intel lists. An event
// without the field never matches a term, unless the term is negated: -app:web matches events of
// other apps and events without an app, app!=web only events of other apps. Text matches a
// substring of Msg.
package query

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/daboss2003/mooring/internal/siem"
)

// Op is a term's comparison.
type Op string

// Ops.
const (
	OpEq       Op = ":"
	OpNe       Op = "!="
	OpGt       Op = ">"
	OpGe       Op = ">="
	OpLt       Op = "<"
	OpLe       Op = "<="
	OpContains Op = "~"
)

// Term is one field comparison. Field is src, app, svc, copy, lvl, kind, out, actor, ip,
// geo.cc, geo.asn, geo.org, geo.city, list, or f.<name>.
type Term struct {
	Field string
	Op    Op
	Value string
	Neg   bool
}

// Query is a parsed search. From/To bound TS (zero = unbounded; From inclusive, To exclusive, so
// the next page of a search is To = Result.Before); every Term and every Text (case-insensitive
// substring of Msg) must match.
type Query struct {
	From, To time.Time
	Terms    []Term
	Text     []string
}

// Bounds of a search string.
const (
	maxLen   = 2 << 10 // bytes
	maxTerms = 32      // field and text terms together
)

// stringFields are the fields compared as plain strings (':', '!=' and '~' only).
var stringFields = map[string]bool{
	"src": true, "app": true, "svc": true, "copy": true, "kind": true, "out": true, "actor": true,
	"geo.cc": true, "geo.org": true, "geo.city": true, "list": true,
}

func knownField(f string) bool {
	switch {
	case stringFields[f], f == "ip", f == "lvl", f == "geo.asn":
		return true
	case strings.HasPrefix(f, "f."):
		return len(f) > 2 && len(f)-2 <= siem.MaxFieldKey
	}
	return false
}

// Parse parses a search string. Errors name the offending term.
func Parse(s string) (Query, error) {
	var q Query
	if len(s) > maxLen {
		return Query{}, fmt.Errorf("query: longer than %d bytes", maxLen)
	}
	if !utf8.ValidString(s) {
		return Query{}, errors.New("query: not valid UTF-8")
	}
	i := 0
	for {
		i = skipSpace(s, i)
		if i >= len(s) {
			return q, nil
		}
		if len(q.Terms)+len(q.Text) >= maxTerms {
			return Query{}, fmt.Errorf("query: more than %d terms", maxTerms)
		}
		start := i
		neg := false
		if s[i] == '-' {
			neg = true
			i++
			if i >= len(s) || spaceAt(s, i) {
				return Query{}, errors.New(`query: "-": nothing to negate`)
			}
		}
		if s[i] == '"' {
			txt, n, err := unquote(s[i:])
			if err != nil {
				return Query{}, termErr(s[start:], err.Error())
			}
			i += n
			if i < len(s) && !spaceAt(s, i) {
				return Query{}, termErr(s[start:tokenEnd(s, i)], "text after the closing quote")
			}
			if neg {
				return Query{}, termErr(s[start:i], "only a field term can be negated")
			}
			if txt != "" {
				q.Text = append(q.Text, txt)
			}
			continue
		}
		// A bare token: a field term when it holds an operator before its end, else text.
		j, opPos := i, -1
		var op Op
		for j < len(s) && !spaceAt(s, j) {
			if o, _ := opAt(s, j); o != "" {
				opPos, op = j, o
				break
			}
			_, w := utf8.DecodeRuneInString(s[j:])
			j += w
		}
		if opPos < 0 {
			if neg {
				return Query{}, termErr(s[start:j], `only a field term can be negated (quote it to search the text)`)
			}
			q.Text = append(q.Text, s[i:j])
			i = j
			continue
		}
		vi := opPos + len(op)
		var val string
		if vi < len(s) && s[vi] == '"' {
			v, n, err := unquote(s[vi:])
			if err != nil {
				return Query{}, termErr(s[start:], err.Error())
			}
			val, vi = v, vi+n
			if vi < len(s) && !spaceAt(s, vi) {
				return Query{}, termErr(s[start:tokenEnd(s, vi)], "text after the closing quote")
			}
		} else {
			end := tokenEnd(s, vi)
			val, vi = s[vi:end], end
		}
		tok := s[start:vi]
		i = vi
		name := s[start+btoi(neg) : opPos]
		if name == "" {
			return Query{}, termErr(tok, "missing field name")
		}
		field, err := fieldName(name)
		if err != nil {
			return Query{}, termErr(tok, err.Error())
		}
		if val == "" {
			return Query{}, termErr(tok, "empty value")
		}
		t := Term{Field: field, Op: op, Value: val, Neg: neg}
		if err := check(t); err != nil {
			return Query{}, termErr(tok, err.Error())
		}
		q.Terms = append(q.Terms, t)
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func termErr(tok, msg string) error {
	return fmt.Errorf("query: %q: %s", siem.Cut(tok, 64), msg)
}

func spaceAt(s string, i int) bool {
	r, _ := utf8.DecodeRuneInString(s[i:])
	return unicode.IsSpace(r)
}

func skipSpace(s string, i int) int {
	for i < len(s) {
		r, w := utf8.DecodeRuneInString(s[i:])
		if !unicode.IsSpace(r) {
			break
		}
		i += w
	}
	return i
}

func tokenEnd(s string, i int) int {
	for i < len(s) && !spaceAt(s, i) {
		_, w := utf8.DecodeRuneInString(s[i:])
		i += w
	}
	return i
}

// opAt returns the operator starting at s[i], if any.
func opAt(s string, i int) (Op, int) {
	next := byte(0)
	if i+1 < len(s) {
		next = s[i+1]
	}
	switch s[i] {
	case ':':
		return OpEq, 1
	case '~':
		return OpContains, 1
	case '!':
		if next == '=' {
			return OpNe, 2
		}
	case '>':
		if next == '=' {
			return OpGe, 2
		}
		return OpGt, 1
	case '<':
		if next == '=' {
			return OpLe, 2
		}
		return OpLt, 1
	}
	return "", 0
}

// unquote reads the quoted string at the start of s and returns it and the bytes consumed.
func unquote(s string) (string, int, error) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			return b.String(), i + 1, nil
		case '\\':
			if i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
				b.WriteByte(s[i+1])
				i++
				continue
			}
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return "", 0, errors.New("unterminated quote")
}

func fieldName(name string) (string, error) {
	if len(name) >= 2 && (name[0] == 'f' || name[0] == 'F') && name[1] == '.' {
		key := name[2:]
		switch {
		case key == "":
			return "", errors.New("empty field name after f.")
		case len(key) > siem.MaxFieldKey:
			return "", fmt.Errorf("field name longer than %d bytes", siem.MaxFieldKey)
		}
		return "f." + key, nil
	}
	f := strings.ToLower(name)
	if !knownField(f) {
		return "", fmt.Errorf("unknown field %q (quote the term to search the text)", siem.Cut(name, 64))
	}
	return f, nil
}

func isLevel(v string) bool {
	switch strings.ToLower(v) {
	case siem.LvlDebug, siem.LvlInfo, siem.LvlWarn, siem.LvlError, siem.LvlCritical:
		return true
	}
	return false
}

// check validates a term's operator and value for its field.
func check(t Term) error {
	rangeOp := t.Op == OpGt || t.Op == OpGe || t.Op == OpLt || t.Op == OpLe
	switch {
	case t.Field == "lvl":
		if t.Op != OpContains && !isLevel(t.Value) {
			return fmt.Errorf("unknown level %q (debug, info, warn, error, critical)", siem.Cut(t.Value, 32))
		}
	case t.Field == "geo.asn":
		if t.Op != OpContains {
			if _, ok := parseASN(t.Value); !ok {
				return fmt.Errorf("%q is not an AS number", siem.Cut(t.Value, 32))
			}
		}
	case t.Field == "ip":
		if rangeOp {
			return fmt.Errorf("%q is not supported for ip", t.Op)
		}
		if t.Op != OpContains && strings.Contains(t.Value, "/") {
			if _, err := netip.ParsePrefix(t.Value); err != nil {
				return fmt.Errorf("%q is not an IP prefix", siem.Cut(t.Value, 64))
			}
		}
	case stringFields[t.Field]:
		if rangeOp {
			return fmt.Errorf("%q is not supported for %s", t.Op, t.Field)
		}
	}
	return nil
}

func parseASN(v string) (uint64, bool) {
	if len(v) > 2 && (v[0] == 'A' || v[0] == 'a') && (v[1] == 'S' || v[1] == 's') {
		v = v[2:]
	}
	n, err := strconv.ParseUint(v, 10, 32)
	return n, err == nil
}

// parseNum parses a finite number.
func parseNum(v string) (float64, bool) {
	n, err := strconv.ParseFloat(v, 64)
	if err != nil || math.IsInf(n, 0) || math.IsNaN(n) {
		return 0, false
	}
	return n, true
}

// Match reports whether e matches q.
func (q Query) Match(e *siem.Event) bool {
	if e == nil {
		return false
	}
	if !q.From.IsZero() && e.TS.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && !e.TS.Before(q.To) {
		return false
	}
	for _, t := range q.Terms {
		ok, present := t.compare(e)
		if t.Neg {
			ok = !(present && ok)
		} else {
			ok = present && ok
		}
		if !ok {
			return false
		}
	}
	for _, x := range q.Text {
		if !containsFold(e.Msg, x) {
			return false
		}
	}
	return true
}

// compare tests the term against its field of e; present is false when e has no such field.
func (t Term) compare(e *siem.Event) (ok, present bool) {
	switch t.Field {
	case "src":
		return strOp(e.Src, t)
	case "app":
		return strOp(e.App, t)
	case "svc":
		return strOp(e.Svc, t)
	case "copy":
		return strOp(e.Copy, t)
	case "kind":
		return strOp(e.Kind, t)
	case "out":
		return strOp(e.Out, t)
	case "actor":
		return strOp(e.Actor, t)
	case "ip":
		return ipOp(e.IP, t)
	case "lvl":
		return lvlOp(e.Lvl, t)
	case "geo.cc", "geo.org", "geo.city", "geo.asn", "list":
		if e.Geo == nil {
			return false, false
		}
		switch t.Field {
		case "geo.cc":
			return strOp(e.Geo.Country, t)
		case "geo.org":
			return strOp(e.Geo.Org, t)
		case "geo.city":
			return strOp(e.Geo.City, t)
		case "geo.asn":
			return asnOp(e.Geo.ASN, t)
		}
		return listOp(e.Geo.Lists, t)
	}
	if key, ok := strings.CutPrefix(t.Field, "f."); ok {
		v, ok := e.F[key]
		if !ok {
			return false, false
		}
		return fOp(v, t)
	}
	return false, false
}

// eqOrPrefix is ':' on strings: equality, or a prefix match for a pattern ending in '*'.
func eqOrPrefix(v, pat string) bool {
	if p, ok := strings.CutSuffix(pat, "*"); ok {
		return hasPrefixFold(v, p)
	}
	return eqFold(v, pat)
}

func strOp(v string, t Term) (bool, bool) {
	if v == "" {
		return false, false
	}
	switch t.Op {
	case OpEq:
		return eqOrPrefix(v, t.Value), true
	case OpNe:
		return !eqOrPrefix(v, t.Value), true
	case OpContains:
		return containsFold(v, t.Value), true
	}
	return cmpOp(strings.Compare(strings.ToLower(v), strings.ToLower(t.Value)), t.Op), true
}

// cmpOp applies a range operator to a comparison result (-1, 0, 1).
func cmpOp(c int, op Op) bool {
	switch op {
	case OpGt:
		return c > 0
	case OpGe:
		return c >= 0
	case OpLt:
		return c < 0
	case OpLe:
		return c <= 0
	case OpEq:
		return c == 0
	case OpNe:
		return c != 0
	}
	return false
}

func cmpNum(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func ipEq(v, pat string) bool {
	if strings.Contains(pat, "/") {
		p, err := netip.ParsePrefix(pat)
		if err != nil {
			return false
		}
		a, err := netip.ParseAddr(v)
		if err != nil {
			return false
		}
		p = p.Masked()
		return p.Contains(a.Unmap()) || p.Contains(a)
	}
	if b, err := netip.ParseAddr(pat); err == nil {
		if a, err := netip.ParseAddr(v); err == nil {
			return a.Unmap() == b.Unmap()
		}
	}
	return eqOrPrefix(v, pat)
}

func ipOp(v string, t Term) (bool, bool) {
	if v == "" {
		return false, false
	}
	switch t.Op {
	case OpEq:
		return ipEq(v, t.Value), true
	case OpNe:
		return !ipEq(v, t.Value), true
	case OpContains:
		return containsFold(v, t.Value), true
	}
	return false, true
}

func lvlOp(v string, t Term) (bool, bool) {
	if v == "" {
		return false, false
	}
	if t.Op == OpContains {
		return containsFold(v, t.Value), true
	}
	return cmpOp(cmpNum(float64(siem.LevelRank(v)), float64(siem.LevelRank(strings.ToLower(t.Value)))), t.Op), true
}

func asnOp(asn uint32, t Term) (bool, bool) {
	if asn == 0 {
		return false, false
	}
	if t.Op == OpContains {
		return containsFold(strconv.FormatUint(uint64(asn), 10), t.Value), true
	}
	n, ok := parseASN(t.Value)
	if !ok {
		return false, true
	}
	return cmpOp(cmpNum(float64(asn), float64(n)), t.Op), true
}

func listOp(lists []string, t Term) (bool, bool) {
	if len(lists) == 0 {
		return false, false
	}
	any := false
	for _, l := range lists {
		if (t.Op == OpContains && containsFold(l, t.Value)) || ((t.Op == OpEq || t.Op == OpNe) && eqOrPrefix(l, t.Value)) {
			any = true
			break
		}
	}
	switch t.Op {
	case OpEq, OpContains:
		return any, true
	case OpNe:
		return !any, true
	}
	return false, true
}

func fOp(v any, t Term) (bool, bool) {
	var (
		str   string
		num   float64
		isNum bool
	)
	switch x := v.(type) {
	case string:
		str = x
		num, isNum = parseNum(x)
	case float64:
		str, num, isNum = strconv.FormatFloat(x, 'f', -1, 64), x, true
	case bool:
		str = strconv.FormatBool(x)
	default:
		return false, true
	}
	qn, qIsNum := parseNum(t.Value)
	switch t.Op {
	case OpEq, OpNe:
		var eq bool
		if qIsNum && isNum {
			eq = num == qn
		} else {
			eq = eqOrPrefix(str, t.Value)
		}
		return eq == (t.Op == OpEq), true
	case OpContains:
		return containsFold(str, t.Value), true
	}
	if qIsNum {
		if !isNum {
			return false, true
		}
		return cmpOp(cmpNum(num, qn), t.Op), true
	}
	return cmpOp(strings.Compare(strings.ToLower(str), strings.ToLower(t.Value)), t.Op), true
}

// MapValues rewrites the value of every term fn accepts (the search page hashes the value of a
// personal-data field before matching). Text is not passed to fn.
func (q *Query) MapValues(fn func(field, value string) (string, bool)) {
	if q == nil || fn == nil {
		return
	}
	// Copy first so a Query copied before the call keeps its values.
	q.Terms = append([]Term(nil), q.Terms...)
	for i := range q.Terms {
		if v, ok := fn(q.Terms[i].Field, q.Terms[i].Value); ok {
			q.Terms[i].Value = v
		}
	}
}

// Case-insensitive comparisons. All of them mean "equal after strings.ToLower on both sides" (the
// store's index lowercases the same way); ASCII inputs take a path that doesn't allocate.

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func eqFold(a, b string) bool {
	if isASCII(a) && isASCII(b) {
		return equalFoldASCII(a, b)
	}
	return strings.ToLower(a) == strings.ToLower(b)
}

func hasPrefixFold(s, p string) bool {
	if isASCII(s) && isASCII(p) {
		return len(s) >= len(p) && equalFoldASCII(s[:len(p)], p)
	}
	return strings.HasPrefix(strings.ToLower(s), strings.ToLower(p))
}

func containsFold(s, sub string) bool {
	if isASCII(s) && isASCII(sub) {
		n := len(sub)
		if n == 0 {
			return true
		}
		c0 := lowerASCII(sub[0])
		for i := 0; i+n <= len(s); i++ {
			if lowerASCII(s[i]) == c0 && equalFoldASCII(s[i:i+n], sub) {
				return true
			}
		}
		return false
	}
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
