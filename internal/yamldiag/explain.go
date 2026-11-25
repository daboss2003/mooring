package yamldiag

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

func explain(raw []byte, target reflect.Type, cause error, o Options) (d *Diagnostics) {
	d = &Diagnostics{File: o.File, Cause: cause, redact: o.RedactValues}
	defer func() {
		// Intentional: a panic here must never replace the refusal it was explaining; the caller
		// still gets the decoder's own message.
		if recover() != nil {
			d = &Diagnostics{File: o.File, Cause: cause, redact: o.RedactValues}
		}
	}()
	// The decoder found no document: nothing but blank lines and comments, whatever the size.
	if errors.Is(cause, io.EOF) {
		d.Problems = []Problem{{Kind: KindSyntax, Msg: "the file is empty", Hint: "it has no settings, only blank lines or comments"}}
		return d
	}
	if len(raw) == 0 || len(raw) > MaxInput {
		return d
	}
	src := newSource(raw)
	root, perr := parseRoot(raw)
	w := &walker{root: target, o: o, infos: map[reflect.Type]*structInfo{}}
	var red *redactor
	if o.RedactValues {
		red = &redactor{named: w.named}
	}
	if perr != nil {
		p := Problem{Kind: KindSyntax}
		var f *finding
		// A byte the YAML reader refuses is what stopped the parser: the scanner would report
		// whatever that byte makes of its line instead.
		if !readerRefusal(perr) {
			f = src.scan()
		}
		if f != nil {
			p.Pos, p.Msg, p.Hint = Pos{f.line, f.col}, f.msg, f.hint
			if f.gluedKey != "" && o.RedactValues && !w.named(f.gluedKey) {
				p.Hint = "put a space after the ':'"
			}
		} else {
			p.Pos, p.Msg, p.Hint = translate(perr, src, o.RedactValues)
		}
		p.Msg, p.Hint = cleanText(p.Msg, maxMsg), cleanText(p.Hint, maxMsg)
		src.fill(&p, red, f != nil && f.gluedKey != "")
		d.Problems = []Problem{p}
		return d
	}
	if root == nil {
		return d
	}
	if red != nil {
		red.keys = lineKeys(root)
	}
	if target != nil {
		w.walk(nil, root, target, "", 0)
	}
	w.fromCause(root, cause, len(src.lines))
	for i := range w.probs {
		p := &w.probs[i]
		if p.Hint == "" && p.Kind == KindType {
			p.Hint = src.commentHint(p.Line)
		}
		// The first document is not a mapping at all: the settings may be in a later one.
		if p.Hint == "" && p.Kind == KindType && p.Path == "" && !p.merge {
			p.Hint = src.laterDocument()
		}
		src.clamp(&p.Pos)
		src.fill(p, red, false)
	}
	d.Problems, d.More = w.probs, w.more
	d.settle()
	return d
}

func (d *Diagnostics) semantic(raw []byte, problems []Problem, cause error, o Options) {
	if d == nil {
		return
	}
	if d.Cause == nil {
		d.Cause = cause
	}
	d.redact = d.redact || o.RedactValues
	if d.File == "" {
		d.File = o.File
	}
	var src *source
	var ix *Index
	var red *redactor
	if len(raw) <= MaxInput {
		src = newSource(raw)
		ix, _ = newIndex(raw)
	}
	schema := &walker{root: o.Schema, o: o, infos: map[reflect.Type]*structInfo{}}
	if o.RedactValues {
		red = &redactor{}
		if ix != nil && ix.root != nil {
			red.keys = lineKeys(ix.root)
		}
	}
	for n, p := range problems {
		if n >= maxCollected {
			d.More += len(problems) - n
			break
		}
		if p.Kind == "" {
			p.Kind = KindSemantic
		}
		p.Msg, p.Hint, p.Path = cleanText(p.Msg, maxMsg), cleanText(p.Hint, maxMsg), cleanText(p.Path, maxMsg)
		inFile := false // the position is this path's own, found here
		if p.Line == 0 && ix != nil && p.Path != "" {
			var key, val *yaml.Node
			key, val, inFile = ix.lookup(p.Path)
			p.Pos = posOf(key, val)
			// The key is not in the document that was read: it may be in a later one.
			if p.Hint == "" && !inFile {
				p.Hint = src.laterDocument()
			}
		}
		src.clamp(&p.Pos)
		if p.Excerpt == "" {
			if p.Hint == "" && inFile {
				p.Hint = src.commentHint(p.Line)
			}
			if red != nil {
				// A key of the problem's own path is printed with the problem anyway; any other key
				// is named by the rule of Explain (walker.named).
				own := strings.Split(stripIndexes(p.Path), ".")
				red.named = func(k string) bool { return k != "" && (slices.Contains(own, k) || schema.named(k)) }
			}
			src.fill(&p, red, false)
		}
		d.Problems = append(d.Problems, p)
	}
	d.settle()
}

// clamp keeps a position inside the file: the parser places an empty document one line past the
// last line when the file ends in comments. The column belonged to the line that does not exist.
func (s *source) clamp(p *Pos) {
	if s != nil && len(s.lines) > 0 && p.Line > len(s.lines) {
		p.Line, p.Col = len(s.lines), 0
	}
}

// laterDocument is the hint for a file with more than one YAML document: only the first is read, so
// what is written after the "---" or "..." line that ends it is not seen. "" for a file with one
// document. Intentional: it is read from the lines, not from the parser. It is only asked about a
// file that parses, and there a line that starts with --- or ... in column 1 is a document marker.
func (s *source) laterDocument() string {
	if s == nil {
		return ""
	}
	if !s.laterKnown {
		s.laterKnown, s.later = true, s.findLaterDocument()
	}
	return s.later
}

func (s *source) findLaterDocument() string {
	nothing := func(text string) bool { // blank, or a comment
		text = strings.TrimLeft(text, " \t")
		return text == "" || text[0] == '#'
	}
	open := false // the first document has started
	end := 0      // the line of the marker that ended it
	for i, line := range s.lines {
		rest, marker := line, isDocMarker(line)
		if marker {
			rest = line[3:]
		}
		if end == 0 {
			switch {
			case marker && open:
				end = i + 1 // what follows a "---" on its own line is the second document's
			case marker:
				// The "---" that opens the first document. A "..." with nothing before it ends nothing.
				open = line[0] == '-'
				continue
			default:
				// A directive (%YAML) before the first document is not part of it.
				open = open || !nothing(line) && line[0] != '%'
				continue
			}
		}
		if !nothing(rest) && (marker || line[0] != '%') {
			return fmt.Sprintf("only the first document of the file is read; it ends at the %q on line %d", s.lines[end-1][:3], end)
		}
	}
	return ""
}

// commentHint explains a value cut short by " #": `color: #fff` is an empty value and a comment.
// Only for a '#' glued to the text after it — a comment is normally written "# like this".
func (s *source) commentHint(line int) string {
	if s == nil || line < 1 || line > len(s.lines) {
		return ""
	}
	text := strings.TrimLeft(s.lines[line-1], " \t")
	for isDash(text) {
		text = strings.TrimLeft(text[1:], " \t")
	}
	c := keyColon(text)
	if c < 0 {
		return ""
	}
	v := text[c+1:]
	if t := strings.TrimLeft(v, " \t"); t != "" && strings.ContainsRune("\"'[{|>", rune(t[0])) {
		return ""
	}
	for j := 1; j+1 < len(v); j++ {
		if v[j] == '#' && isSpace(v[j-1]) && !isSpace(v[j+1]) && v[j+1] != '#' {
			return `everything after " #" is a comment; put the value in quotes if the # is part of it`
		}
	}
	return ""
}

// Where the parser's line number points.
const (
	lineExact = iota // the line itself
	// Intentional: for these yaml.v3 prints a 0-based line (it adds one only for its scanner's
	// errors), so the line meant is the next one.
	lineBefore
	lineNone // no position is given
)

var translations = []struct {
	yaml      string
	at        int
	msg, hint string
}{
	{"mapping values are not allowed in this context", lineExact,
		"this line has a ':' the parser did not expect",
		"check the indentation of this line and the one above, or quote the value"},
	{"did not find expected key", lineBefore,
		`this line, or a line below it in the same block, is indented differently from its neighbours or is not in "key: value" form`,
		"check the indentation from this line down; the keys of one block start in the same column"},
	{"did not find expected '-' indicator", lineBefore,
		`this line, or a line below it in the same list, is in the list's column but does not start with "- "`,
		"indent that line under its list item, or move it left to the column of the key that owns the list"},
	{"found a tab character", lineExact,
		"a tab is used for indentation on or near this line",
		"indent with spaces; YAML does not accept tabs for indentation"},
	{"found character that cannot start any token", lineExact,
		"a value on or near this line starts with a character YAML does not allow there (a tab used for indentation, or an unquoted @ or `)",
		"indent with spaces, and put a value that starts with @ or ` in quotes"},
	{"could not find expected ':'", lineExact,
		`a line here is not in "key: value" form: a key has no ':' after it, or no space follows the ':'`,
		`write each entry as "key: value"`},
	{"found unexpected end of stream", lineExact,
		`a quote (" or ') opened earlier in the file is never closed`,
		"add the closing quote"},
	{"did not find expected ',' or ']'", lineBefore,
		"a list written with [ ] is not closed before this line, or its items are not separated by commas",
		"add the missing ] or comma"},
	{"did not find expected ',' or '}'", lineBefore,
		"a mapping written with { } is not closed before this line, or its entries are not separated by commas",
		"add the missing } or comma"},
	{"found unknown escape character", lineExact,
		`a double-quoted value contains a backslash sequence YAML does not know`,
		`use single quotes around the value, or write each backslash as \\`},
	{"did not find expected alphabetic or numeric character", lineExact,
		"a value starts with * or & but is not a valid reference",
		"put the value in quotes"},
	{"unknown anchor", lineNone,
		"a value that starts with * refers to an anchor that is not defined",
		"put the value in quotes if the * is part of it"},
	{"block sequence entries are not allowed in this context", lineExact,
		`a list item ("- ") starts on the same line as its key, or is indented where no list can start`,
		`put each "- item" on its own line below the key`},
	{"did not find expected node content", lineBefore,
		"a value is missing, or starts with a character that cannot begin one (such as ] } or ,)",
		"put the value in quotes"},
	{"control characters are not allowed", lineNone,
		"the file contains a control character",
		"remove it; the file must be plain UTF-8 text"},
	{"UTF-8", lineNone, "the file is not valid UTF-8 text", "save the file as UTF-8"},
	{"invalid Unicode character", lineNone, "the file is not valid UTF-8 text", "save the file as UTF-8"},
	{"did not find expected <document start>", lineBefore,
		`content follows the end of the document (a "..." line, or a line indented to the left of the first key)`,
		`remove the "..." line, or fix this line's indentation`},
	{"found unexpected document indicator", lineExact,
		`a line that starts with --- or ... is inside a quoted value`,
		"close the quote above it"},
	{"did not find expected comment or line break", lineExact,
		"unexpected text follows a | or > on this line",
		"start the text on the next line, indented"},
	{"found undefined tag handle", lineBefore,
		"a value starts with ! which YAML reads as a tag",
		"put the value in quotes"},
}

// translate is the parser's own complaint in plain words, at the line the parser means (which for
// an indentation mistake may be where the surrounding block starts). The column is unknown.
func translate(err error, src *source, redact bool) (Pos, string, string) {
	text := strings.TrimPrefix(err.Error(), "yaml: ")
	line := 0
	if rest, ok := strings.CutPrefix(text, "line "); ok {
		if n, after, ok := strings.Cut(rest, ": "); ok {
			if v, err := strconv.Atoi(n); err == nil && v > 0 && v <= MaxInput {
				line, text = v, after
			}
		}
	}
	clamp := func(n int) Pos {
		if n > len(src.lines) {
			n = len(src.lines)
		}
		return Pos{Line: n}
	}
	for _, t := range translations {
		if !strings.Contains(text, t.yaml) {
			continue
		}
		switch {
		case t.at == lineBefore:
			return clamp(line + 1), t.msg, t.hint
		case t.at == lineExact:
			// Intentional: yaml.v3 leaves the line out when it is the first one.
			return clamp(max(line, 1)), t.msg, t.hint
		case t.yaml == "unknown anchor":
			return src.alias(text), t.msg, t.hint
		}
		return src.badByte(), t.msg, t.hint
	}
	if redact { // a message with no translation may quote the file
		if text = scrub(text); text == "" {
			text = "the file is not valid YAML"
		}
	}
	// Intentional: yaml.v3 leaves the line out when it is the first one (as above); the parser has
	// no complaint without a position.
	return clamp(max(line, 1)), text, ""
}

// readerRefusal: the YAML reader stopped at a byte it does not take (the parser never saw the rest).
func readerRefusal(err error) bool {
	text := err.Error()
	return strings.Contains(text, "control characters are not allowed") || strings.Contains(text, "UTF-8") ||
		strings.Contains(text, "invalid Unicode character")
}

// alias is the position of the reference yaml's "unknown anchor 'x' referenced" is about.
func (s *source) alias(msg string) Pos {
	_, name, _ := strings.Cut(msg, "'")
	name, _, ok := strings.Cut(name, "'")
	if !ok || name == "" {
		return Pos{}
	}
	for i, line := range s.lines {
		if at := strings.Index(line, "*"+name); at >= 0 {
			return Pos{i + 1, utf8.RuneCountInString(line[:at]) + 1}
		}
	}
	return Pos{}
}

// badByte is the position of the first byte the YAML reader refuses: invalid UTF-8 or a control
// character other than tab, CR and LF.
func (s *source) badByte() Pos {
	for i, line := range s.lines {
		col := 0
		for _, r := range line {
			col++
			if (r == utf8.RuneError) || (r < 0x20 && r != '\t') || r == 0x7f || (r >= 0x80 && r < 0xa0 && r != 0x85) {
				return Pos{i + 1, col}
			}
		}
	}
	return Pos{}
}

func suggest(key string, candidates []string) string {
	const maxLen = 64
	if key == "" || len(key) > maxLen {
		return ""
	}
	k := []rune(strings.ToLower(key))
	limit := 2
	if len(k)/3 > limit {
		limit = len(k) / 3
	}
	// Intentional: a match must leave at least one letter of the key in place, or every two-letter
	// key would "suggest" any other two-letter key.
	if limit >= len(k) {
		limit = len(k) - 1
	}
	best, bestDist := "", limit+1
	for n, c := range candidates {
		if n >= 1000 {
			break
		}
		if len(c) > maxLen || c == "" {
			continue
		}
		if d := distance(k, []rune(strings.ToLower(c)), bestDist); d < bestDist {
			best, bestDist = c, d
		}
	}
	return best
}

// distance is the Levenshtein distance between a and b, or stop when it is at least stop.
func distance(a, b []rune, stop int) int {
	if len(a)-len(b) >= stop || len(b)-len(a) >= stop {
		return stop
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return min(prev[len(b)], stop)
}
