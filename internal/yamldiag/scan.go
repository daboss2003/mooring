package yamldiag

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// source is the file as lines: no line break, no leading BOM.
type source struct {
	raw    []byte
	lines  []string
	starts []int // byte offset of each line in raw
	// odd: the file has a line break other than LF and CRLF. The line scanner does not model those
	// and says nothing about such a file.
	odd bool

	later      string // laterDocument's answer
	laterKnown bool
}

// breakLen is the length of the line break at s[i:], 0 when there is none there. Intentional: the
// set is yaml.v3's (LF, CR, CRLF, U+0085, U+2028, U+2029), not "\n" alone — every position a node
// or a parser message carries counts lines this way, and an excerpt cut on "\n" only would show
// another line than the one reported (the next one, which may hold a secret).
func breakLen(s string, i int) int {
	switch s[i] {
	case '\n':
		return 1
	case '\r':
		if i+1 < len(s) && s[i+1] == '\n' {
			return 2
		}
		return 1
	case 0xC2:
		if i+1 < len(s) && s[i+1] == 0x85 {
			return 2
		}
	case 0xE2:
		if i+2 < len(s) && s[i+1] == 0x80 && (s[i+2] == 0xA8 || s[i+2] == 0xA9) {
			return 3
		}
	}
	return 0
}

func newSource(raw []byte) *source {
	s := &source{raw: raw}
	text := string(raw)
	add := func(from, to int) {
		line := text[from:to]
		if from == 0 {
			line = strings.TrimPrefix(line, "\xef\xbb\xbf")
		}
		s.lines = append(s.lines, line)
		s.starts = append(s.starts, from)
	}
	start := 0
	for i := 0; i < len(text); {
		n := breakLen(text, i)
		if n == 0 {
			i++
			continue
		}
		s.odd = s.odd || !(text[i] == '\n' || n == 2 && text[i] == '\r')
		add(start, i)
		i += n
		start = i
	}
	if start < len(text) {
		add(start, len(text))
	}
	return s
}

// through is the file's first n lines.
func (s *source) through(n int) []byte {
	if n >= len(s.lines) {
		return s.raw
	}
	if n <= 0 {
		return nil
	}
	return s.raw[:s.starts[n]]
}

// parses reports whether b is accepted by the YAML parser (the first document, as the decoders read
// it).
func parses(b []byte) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	var n yaml.Node
	return yaml.Unmarshal(b, &n) == nil
}

// finding is what the line scanner reports: one place, 1-based.
type finding struct {
	line, col int
	msg, hint string
	// through is the line the file must stop parsing at for the finding to be the cause (0: line).
	through int
	tab     bool
	// gluedKey: the finding is a "key:value" with no space, and this is the word before the ':'.
	gluedKey string
}

// Intentional: a sentinel, not an error — the scanner met something it does not model and must say
// nothing rather than guess.
var bail = &finding{}

type level struct {
	indent int
	seq    bool
	line   int // index of the line the block starts on
}

type scanner struct {
	src    *source
	noTabs bool // the tab check is off (a tab was found but was not what broke the file)

	stack      []level
	open       bool // the last key or '-' has no value yet
	openIndent int
	entryLine  int // the last key or '-': line index and column offset
	entryCol   int
	hasContent bool
	rootScalar bool
	suspect    *finding
	inBlock    bool // inside a | or > scalar
	blockInd   int
	// A plain value written where a key could be: the text on its own line under a key with no
	// value, or after a "- ". ownLine is its line number (0: none), ownCol its column offset.
	ownLine, ownCol int
	ownPlain        bool // it is not quoted, a flow collection, a block scalar, tagged or anchored
	ownMore         bool // the value goes on over more lines
	more            bool // the line just read was more of the value above
}

// scan looks for the mistake that broke the file. It is only called for a file the parser refused,
// and a finding is kept only when the parser agrees about the line: everything before it parses,
// and the file up to it does not.
func (s *source) scan() *finding {
	if s.odd {
		return nil
	}
	f := (&scanner{src: s}).run()
	if f != nil && f.tab && !s.confirmed(f) {
		f = (&scanner{src: s, noTabs: true}).run()
	}
	if f == nil || !s.confirmed(f) {
		return nil
	}
	return f
}

func (s *source) confirmed(f *finding) bool {
	through := f.through
	if through == 0 {
		through = f.line
	}
	return parses(s.through(f.line-1)) && !parses(s.through(through))
}

func (sc *scanner) at(i, off int, msg, hint string) *finding {
	line := sc.src.lines[i]
	if off > len(line) {
		off = len(line)
	}
	return &finding{line: i + 1, col: utf8.RuneCountInString(line[:off]) + 1, msg: msg, hint: hint}
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' }

func isDash(s string) bool {
	return len(s) > 0 && s[0] == '-' && (len(s) == 1 || isSpace(s[1]))
}

func isDocMarker(s string) bool {
	return (strings.HasPrefix(s, "---") || strings.HasPrefix(s, "...")) && (len(s) == 3 || isSpace(s[3]))
}

func (sc *scanner) run() *finding {
	lines := sc.src.lines
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		ind := 0
		for ind < len(line) && line[ind] == ' ' {
			ind++
		}
		ws := ind
		for ws < len(line) && isSpace(line[ws]) {
			ws++
		}
		if sc.inBlock {
			if ws == len(line) || ind > sc.blockInd {
				continue
			}
			sc.inBlock = false
		}
		if tab := strings.IndexByte(line[:ws], '\t'); tab >= 0 {
			if sc.noTabs {
				continue
			}
			f := sc.at(i, tab, "a tab is used for indentation", "indent with spaces; YAML does not accept tabs for indentation")
			f.tab = true
			return f
		}
		rest := line[ws:]
		if rest == "" || rest[0] == '#' {
			continue
		}
		if ind == 0 && isDocMarker(rest) {
			if after := strings.TrimLeft(rest[3:], " \t"); after != "" && after[0] != '#' {
				return nil
			}
			*sc = scanner{src: sc.src, noTabs: sc.noTabs}
			continue
		}
		if ind == 0 && rest[0] == '%' && !sc.hasContent {
			continue
		}
		suspect := sc.suspect
		sc.suspect = nil
		if sc.rootScalar {
			if suspect != nil {
				suspect.through = i + 1
			}
			return suspect
		}
		sc.more = false
		f, last := sc.line(i, ind)
		if f == bail {
			return nil
		}
		if f == nil && sc.more {
			sc.suspect = suspect // still the value the suspect line started
		}
		if f != nil {
			if suspect != nil {
				// The line above was taken as a value but reads like key:value with the space missing,
				// and that is what made this line wrong.
				suspect.through = max(f.line, f.through)
				return suspect
			}
			return f
		}
		if last > i {
			i = last
		}
	}
	return nil
}

// line handles one line of block structure; it returns the last line it consumed.
func (sc *scanner) line(i, ind int) (*finding, int) {
	line := sc.src.lines[i]
	off, first, parent := ind, true, -1
	for isDash(line[off:]) {
		f, skip := sc.enter(i, off, true, first)
		if f != nil || skip {
			return f, i
		}
		sc.entryLine, sc.entryCol = i, off
		sc.ownLine = 0
		parent = off
		off++
		for off < len(line) && isSpace(line[off]) {
			off++
		}
		if off >= len(line) || line[off] == '#' {
			sc.open, sc.openIndent = true, parent
			return nil, i
		}
		first = false
	}
	rest := line[off:]
	if (rest[0] == '?' || rest[0] == ':') && (len(rest) == 1 || isSpace(rest[1])) {
		return bail, i
	}
	if colon := keyColon(rest); colon >= 0 {
		f, skip := sc.enter(i, off, false, first)
		if f != nil || skip {
			return f, i
		}
		sc.entryLine, sc.entryCol = i, off
		sc.ownLine = 0
		return sc.value(i, off+colon+1, off, true)
	}
	if !first {
		sc.suspect = sc.glued(i, off)
		sc.own(i, off)
		return sc.value(i, off, parent, false)
	}
	switch {
	case sc.open && off > sc.openIndent:
		sc.suspect = sc.glued(i, off)
		sc.own(i, off)
		return sc.value(i, off, sc.openIndent, false)
	case len(sc.stack) == 0:
		sc.rootScalar, sc.hasContent = true, true
		sc.suspect = sc.glued(i, off)
		return sc.value(i, off, -1, false)
	case off > sc.stack[len(sc.stack)-1].indent:
		sc.ownMore, sc.more = true, true
		return nil, i // more of the value above
	}
	before := sc.indents()
	var left *level
	for len(sc.stack) > 0 && sc.stack[len(sc.stack)-1].indent > off {
		l := sc.stack[len(sc.stack)-1]
		left = &l
		sc.stack = sc.stack[:len(sc.stack)-1]
	}
	if len(sc.stack) == 0 {
		return bail, i
	}
	if sc.stack[len(sc.stack)-1].indent < off {
		return sc.mismatch(i, off, before, left), i
	}
	if n := len(sc.stack); sc.stack[n-1].seq && !(n >= 2 && sc.stack[n-2].indent == off && !sc.stack[n-2].seq) {
		return bail, i
	}
	if f := sc.glued(i, off); f != nil {
		return f, i
	}
	return sc.at(i, off, notKeyValueMsg, notKeyValueHint), i
}

const (
	notKeyValueMsg  = `this line is not in "key: value" form`
	notKeyValueHint = `the lines around it are "key: value" entries; add the missing ':' or fix this line's indentation`
)

// own notes a plain value that starts at column offset off of line i, where a key could be written.
func (sc *scanner) own(i, off int) {
	line := sc.src.lines[i]
	sc.ownLine, sc.ownCol, sc.ownMore = i+1, off, false
	sc.ownPlain = off < len(line) && strings.IndexByte("\"'[{|>&!*@`#", line[off]) < 0
}

func (sc *scanner) indents() []int {
	var out []int
	for _, l := range sc.stack {
		if len(out) == 0 || out[len(out)-1] != l.indent {
			out = append(out, l.indent)
		}
	}
	return out
}

func spaces(n int) string {
	if n == 1 {
		return "1 space"
	}
	return strconv.Itoa(n) + " spaces"
}

// mismatch: the line's indentation is that of no open block. left is the innermost block it is left
// of, the one it most likely belongs to: the message names where that block starts, because the
// mistake may be there (a block whose first line is indented wrongly makes every later line of it
// the one that "matches nothing").
func (sc *scanner) mismatch(i, off int, levels []int, left *level) *finding {
	hint := ""
	switch {
	case len(levels) == 1 && levels[0] == 0:
		hint = "start it at the beginning of the line"
	case len(levels) == 1:
		hint = "indent it by " + spaces(levels[0])
	case len(levels) > 1:
		if len(levels) > 6 {
			levels = levels[len(levels)-6:]
		}
		parts := make([]string, len(levels))
		for k, l := range levels {
			parts[k] = strconv.Itoa(l)
		}
		hint = "indent it by " + strings.Join(parts[:len(parts)-1], ", ") + " or " + parts[len(parts)-1] + " spaces"
	}
	msg := fmt.Sprintf("this line is indented by %s, which matches no block above it", spaces(off))
	if left != nil && left.line < i {
		msg += fmt.Sprintf("; it does not match line %d above (indented by %s)", left.line+1, spaces(left.indent))
	}
	return sc.at(i, off, msg, hint)
}

// enter places a key or a '-' that starts at column offset c among the open blocks. skip: the line
// is more of a value above and says nothing about structure.
func (sc *scanner) enter(i, c int, seq, first bool) (f *finding, skip bool) {
	if !first { // after a '-' on the same line: always a new block
		sc.stack = append(sc.stack, level{c, seq, i})
		sc.open = false
		return nil, false
	}
	before := sc.indents()
	popped := false
	var left *level
	for len(sc.stack) > 0 && sc.stack[len(sc.stack)-1].indent > c {
		l := sc.stack[len(sc.stack)-1]
		left = &l
		sc.stack = sc.stack[:len(sc.stack)-1]
		popped = true
	}
	if len(sc.stack) == 0 {
		// Also for a line left of the first key: the parser takes that in some places.
		sc.stack = append(sc.stack, level{c, seq, i})
		sc.open, sc.hasContent = false, true
		return nil, false
	}
	n := len(sc.stack)
	top := sc.stack[n-1]
	if top.indent == c {
		switch {
		case top.seq == seq:
		case top.seq: // a key in the column of a list: fine when the list sits under a key of that column
			if n < 2 || sc.stack[n-2].indent != c || sc.stack[n-2].seq {
				return sc.at(i, c, `this key starts in the same column as the list items above it, so it is neither a list item nor a key of the block the list belongs to`,
					`indent it under its list item, or move it left to the column of the key that owns the list`), false
			}
			sc.stack = sc.stack[:n-1]
		default: // a '-' in the column of a key: the list of that key, when the key has no value
			if !sc.open || sc.openIndent != c || popped {
				return sc.at(i, c, `a list item ("- ") cannot start here: the block at this indentation is made of "key: value" lines`,
					`indent the "- " lines under the key they belong to, and give that key no value of its own`), false
			}
			sc.stack = append(sc.stack, level{c, true, i})
		}
		sc.open = false
		return nil, false
	}
	if popped {
		return sc.mismatch(i, c, before, left), false
	}
	if sc.open {
		sc.stack = append(sc.stack, level{c, seq, i})
		sc.open = false
		return nil, false
	}
	if seq {
		return nil, true
	}
	if sc.ownLine > 0 && sc.ownPlain && !sc.ownMore && sc.ownCol == c {
		// The line above is in this key's column but has no ':' — it was read as the value of the
		// key before it, and that is why this line cannot be a key. The line above is the mistake.
		f := sc.at(sc.ownLine-1, c, notKeyValueMsg, notKeyValueHint)
		f.through = i + 1
		return f, false
	}
	if sc.ownLine > 0 && sc.ownLine-1 != sc.entryLine { // the value is not on the key's own line
		return sc.at(i, c, fmt.Sprintf("this line is indented under line %d, which already has a value (the text that starts on line %d)", sc.entryLine+1, sc.ownLine),
			fmt.Sprintf("start it in column %d like line %d, or remove that text to nest this line under line %d", sc.entryCol+1, sc.entryLine+1, sc.entryLine+1)), false
	}
	return sc.at(i, c, fmt.Sprintf("this line is indented under line %d, which already has a value", sc.entryLine+1),
		fmt.Sprintf("start it in column %d like line %d, or remove the value on line %d to nest this line under it", sc.entryCol+1, sc.entryLine+1, sc.entryLine+1)), false
}

// keyColon is the offset of the ':' that ends a key at the start of s, or -1.
func keyColon(s string) int {
	if s == "" {
		return -1
	}
	switch s[0] {
	case '"', '\'':
		j := quoteEnd(s, 0)
		if j < 0 {
			return -1
		}
		for j < len(s) && isSpace(s[j]) {
			j++
		}
		if j < len(s) && s[j] == ':' && (j+1 == len(s) || isSpace(s[j+1])) {
			return j
		}
		return -1
	case '[', '{', '|', '>', '@', '`', '#', '%':
		return -1
	}
	for j := 0; j < len(s); j++ {
		switch {
		case s[j] == '#' && j > 0 && isSpace(s[j-1]):
			return -1
		case s[j] == ':' && (j+1 == len(s) || isSpace(s[j+1])):
			return j
		}
	}
	return -1
}

// quoteEnd is the offset just after the quote that closes the one at s[start], or -1 when it does
// not close in s.
func quoteEnd(s string, start int) int {
	q := s[start]
	for j := start + 1; j < len(s); j++ {
		switch {
		case q == '"' && s[j] == '\\':
			j++
		case s[j] == q:
			if q == '\'' && j+1 < len(s) && s[j+1] == '\'' {
				j++
				continue
			}
			return j + 1
		}
	}
	return -1
}

// gluedColon is the offset of the ':' in a line that reads key:value with no space, or -1.
func gluedColon(s string) int {
	j := strings.IndexByte(s, ':')
	if j <= 0 || j+1 >= len(s) || isSpace(s[j+1]) || s[j+1] == '/' || s[j+1] == ':' {
		return -1
	}
	for k := 0; k < j; k++ {
		c := s[k]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return -1
		}
	}
	return j
}

func (sc *scanner) glued(i, off int) *finding {
	rest := sc.src.lines[i][off:]
	j := gluedColon(rest)
	if j < 0 {
		return nil
	}
	f := sc.at(i, off+j+1, gluedMsg, fmt.Sprintf(`put a space between "%s:" and its value`, cleanText(rest[:j], 60)))
	f.gluedKey = rest[:j]
	return f
}

const gluedMsg = "there is no space after the ':'"

func blockHeader(s string) bool {
	j := 1
	for j < len(s) && (s[j] == '+' || s[j] == '-' || s[j] >= '1' && s[j] <= '9') {
		j++
	}
	if j > 3 {
		return false
	}
	rest := strings.TrimLeft(s[j:], " \t")
	return rest == "" || (rest[0] == '#' && len(rest) < len(s[j:]))
}

// value examines what follows a key's ':' or a '-' (or a value on its own line), starting at off.
// parent is the column offset a block scalar's text must be indented beyond.
func (sc *scanner) value(i, off, parent int, isKey bool) (*finding, int) {
	line := sc.src.lines[i]
	for {
		for off < len(line) && isSpace(line[off]) {
			off++
		}
		if off >= len(line) || (line[off] != '&' && line[off] != '!') {
			break
		}
		for off < len(line) && !isSpace(line[off]) { // an anchor or a tag
			off++
		}
	}
	if off >= len(line) || line[off] == '#' {
		sc.open, sc.openIndent = true, parent
		return nil, i
	}
	sc.open = false
	v := line[off:]
	switch v[0] {
	case '|', '>':
		if blockHeader(v) {
			sc.inBlock, sc.blockInd = true, parent
			return nil, i
		}
	case '"', '\'':
		return sc.quoted(i, off)
	case '[', '{':
		return sc.flow(i, off)
	case '@', '`':
		return sc.at(i, off, fmt.Sprintf("a value cannot start with %c unless it is in quotes", v[0]), "put the value in quotes"), i
	case '*':
		return nil, i
	}
	if isKey && isDash(v) {
		return sc.at(i, off, `a list item ("- ") starts on the same line as its key`,
			`put each "- item" on its own line below the key, or write the list as [a, b]`), i
	}
	for j := 0; j < len(v); j++ {
		if v[j] == '#' && j > 0 && isSpace(v[j-1]) {
			break
		}
		if v[j] == ':' && (j+1 == len(v) || isSpace(v[j+1])) {
			return sc.at(i, off+j, "the value contains ':' followed by a space, which YAML reads as the start of another key",
				"put the whole value in quotes"), i
		}
	}
	return nil, i
}

func (sc *scanner) quoted(i, off int) (*finding, int) {
	lines := sc.src.lines
	unclosed := func(through int) *finding {
		f := sc.at(i, off, fmt.Sprintf("this quote (%c) is never closed", lines[i][off]), "add the closing quote at the end of the value")
		f.through = through
		return f
	}
	if quoteEnd(lines[i], off) >= 0 {
		return nil, i // closed on its own line; what follows is not judged here
	}
	q := lines[i][off]
	for li := i + 1; li < len(lines); li++ {
		// Intentional: the opening quote is put back in front of each later line so quoteEnd applies
		// the same escape rules to it.
		end := quoteEnd(string(q)+lines[li], 0)
		if end < 0 {
			continue
		}
		after := lines[li][end-1:]
		trimmed := strings.TrimLeft(after, " \t")
		if trimmed == "" || (trimmed[0] == '#' && len(trimmed) < len(after)) {
			return nil, li // a quoted value written over several lines
		}
		return unclosed(li + 1), li
	}
	return unclosed(len(lines)), i
}

// flow skips a [..] or {..} collection that starts at off; it may span lines.
func (sc *scanner) flow(i, off int) (*finding, int) {
	lines := sc.src.lines
	depth := 0
	var quote byte
	for li := i; li < len(lines); li++ {
		line := lines[li]
		start := 0
		if li == i {
			start = off
		}
		prev := byte(',')
	scanLine:
		for j := start; j < len(line); j++ {
			c := line[j]
			if quote != 0 {
				switch {
				case quote == '"' && c == '\\':
					j++
				case c == quote:
					if quote == '\'' && j+1 < len(line) && line[j+1] == '\'' {
						j++
						continue
					}
					quote, prev = 0, 'x'
				}
				continue
			}
			switch {
			case isSpace(c):
				continue
			case c == '#' && (j == 0 || isSpace(line[j-1])):
				break scanLine
			case (c == '"' || c == '\'') && strings.IndexByte("[{,:", prev) >= 0:
				quote = c
				continue
			case c == '[' || c == '{':
				depth++
			case c == ']' || c == '}':
				depth--
				if depth == 0 {
					return nil, li
				}
			}
			prev = c
		}
	}
	if quote != 0 {
		return bail, i
	}
	f := sc.at(i, off, fmt.Sprintf("this %c is never closed", lines[i][off]),
		fmt.Sprintf("add the closing %c", map[byte]byte{'[': ']', '{': '}'}[lines[i][off]]))
	f.through = len(lines)
	return f, i
}
