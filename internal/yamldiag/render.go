package yamldiag

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	maxMsg  = 300  // bytes of a message, a hint or a path
	maxLine = 1000 // bytes of Error()
)

func hidden(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' || r == utf8.RuneError
}

func cut(s string, max int) string {
	if len(s) <= max {
		return s
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max]
}

// cleanText makes hostile text safe to print on one line: control and formatting characters become
// spaces, runs of spaces collapse, and the result is cut to max bytes.
func cleanText(s string, max int) string {
	if len(s) > 4*max {
		s = s[:4*max]
	}
	var b strings.Builder
	space := false
	for _, r := range s {
		if hidden(r) || r == ' ' {
			space = b.Len() > 0
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	return cut(b.String(), max)
}

// showLine is a source line as an excerpt: a tab becomes one space (the caret keeps its column),
// other control and formatting characters are removed, and the line is cut to MaxExcerpt.
func showLine(line string) string {
	if len(line) > 4*MaxExcerpt {
		line = line[:4*MaxExcerpt]
	}
	return cut(showLineUncut(line), MaxExcerpt)
}

func showLineUncut(line string) string {
	var b strings.Builder
	for _, r := range line {
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case hidden(r):
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// redactor is how lines are shown under RedactValues (nil: as written).
type redactor struct {
	// named: the key name may be printed (a key of the schema: walker.named).
	named func(key string) bool
	// keys are the mapping keys the parser found on each line, nil for a file that does not parse.
	// With them a "word:" is kept in an excerpt only where the parser read a key: a line of a block
	// scalar or of a multi-line value that merely looks like "key: value" is masked whole.
	keys map[int]map[string]bool
}

func (r *redactor) shows(line int, key string) bool {
	// A merge key is YAML's own word, not a name from the file: it stays where the parser read it.
	if key == "<<" {
		return r != nil && r.keys != nil && r.keys[line][key]
	}
	if r == nil || r.named == nil || !r.named(key) {
		return false
	}
	return r.keys == nil || r.keys[line][key]
}

// lineKeys records the mapping keys written on each line of a parsed file.
func lineKeys(root *yaml.Node) map[int]map[string]bool {
	out := map[int]map[string]bool{}
	budget := maxNodes
	var visit func(n *yaml.Node, depth int)
	visit = func(n *yaml.Node, depth int) {
		budget--
		if n == nil || depth > maxDepth || budget < 0 {
			return
		}
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				if k := n.Content[i]; k.Kind == yaml.ScalarNode {
					if out[k.Line] == nil {
						out[k.Line] = map[string]bool{}
					}
					out[k.Line][k.Value] = true
				}
			}
		}
		for _, c := range n.Content {
			visit(c, depth+1)
		}
	}
	visit(root, 0)
	return out
}

// redactLine is a line as shown under RedactValues: the indentation, the "- " markers and the key
// stay, the rest becomes "…". Default deny: a line with no key (more of a value above, a list item)
// and a key that may not be printed (shows) keep nothing but the indentation. Intentional: there is
// no way to show a value — an error about a file that holds secrets never prints one (owner
// decision 2026-11-25; the earlier "safe keys" exception is gone). glued: the problem reported on
// this line is its "key:value" with no space, so the word before the ':' is a key; on any other
// line that shape is part of a value and is masked.
func redactLine(line string, glued bool, shows func(key string) bool) string {
	off := 0
	for {
		for off < len(line) && isSpace(line[off]) {
			off++
		}
		if !isDash(line[off:]) {
			break
		}
		off++
	}
	rest := line[off:]
	if rest == "" {
		return line
	}
	if c := keyColon(rest); c >= 0 && shows(rest[:c]) {
		if strings.TrimLeft(rest[c+1:], " \t") == "" {
			return line
		}
		return line[:off+c+1] + " …"
	}
	if glued {
		if c := gluedColon(rest); c >= 0 && shows(rest[:c]) {
			return line[:off+c+1] + "…"
		}
	}
	return line[:off] + "…"
}

// fill sets a problem's excerpt, the caret under it and the line before it (for Terminal) from the
// source. With a redactor both lines are masked.
func (s *source) fill(p *Problem, red *redactor, glued bool) {
	if s == nil || p.Line < 1 || p.Line > len(s.lines) {
		return
	}
	line := s.lines[p.Line-1]
	if len(line) > 4*MaxExcerpt {
		line = cut(line, 4*MaxExcerpt)
	}
	text := line
	if red != nil {
		text = redactLine(line, glued, func(k string) bool { return red.shows(p.Line, k) })
	}
	p.Excerpt = showLine(text)
	p.shown = true
	p.caret = caretOf(line, text, p.Excerpt, p.Col, red != nil)
	if p.Line > 1 {
		prev := s.lines[p.Line-2]
		if len(prev) > 4*MaxExcerpt {
			prev = cut(prev, 4*MaxExcerpt)
		}
		if red != nil {
			prev = redactLine(prev, false, func(k string) bool { return red.shows(p.Line-1, k) })
		}
		p.prev = showLine(prev)
	}
}

// caretOf is the 1-based column of the caret under an excerpt, 0 for none. The column of a problem
// counts the source line's characters; the excerpt has lost the control characters, may be cut and
// may be masked, so the caret is placed by what is displayed: never past the end of a cut excerpt,
// and on the "…" when the column lies in the part that was masked (which also keeps the length of a
// masked value out of the output).
func caretOf(line, text, excerpt string, col int, masked bool) int {
	if col < 1 {
		return 0
	}
	disp, n := 0, 0
	for _, r := range line {
		if n == col-1 {
			break
		}
		n++
		if r == '\t' || !hidden(r) {
			disp++
		}
	}
	shown := utf8.RuneCountInString(excerpt)
	wasCut := len(excerpt) < len(showLineUncut(text))
	switch {
	case wasCut && disp >= shown, disp > shown && !masked:
		return 0
	case masked && text != line && disp > shown-1: // redactLine put a "…" at the end
		disp = shown - 1
	case disp > shown:
		return 0
	}
	return disp + 1
}

func sortProblems(ps []Problem) {
	sort.SliceStable(ps, func(i, j int) bool {
		a, b := ps[i], ps[j]
		if (a.Line == 0) != (b.Line == 0) {
			return b.Line == 0
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Col < b.Col
	})
}

// settle sorts the problems and keeps the first MaxProblems.
func (d *Diagnostics) settle() {
	sortProblems(d.Problems)
	if len(d.Problems) > MaxProblems {
		d.More += len(d.Problems) - MaxProblems
		d.Problems = d.Problems[:MaxProblems:MaxProblems]
	}
}

func where(file string, p Pos) string {
	var b strings.Builder
	b.WriteString(file)
	if p.Line > 0 {
		if b.Len() > 0 {
			b.WriteByte(':')
		}
		b.WriteString(strconv.Itoa(p.Line))
		if p.Col > 0 {
			b.WriteByte(':')
			b.WriteString(strconv.Itoa(p.Col))
		}
	}
	if b.Len() > 0 {
		b.WriteString(": ")
	}
	return b.String()
}

var (
	scrubFieldRE  = regexp.MustCompile(`(?:^|: )field `)
	scrubTypedRE  = regexp.MustCompile(`cannot (?:unmarshal|decode) `)
	scrubStringRE = regexp.MustCompile(`"(?:[^"\\\n]|\\.)*"`)
	scrubMapKeyRE = regexp.MustCompile(`invalid map key: [^\n]*`)
	scrubCharRE   = regexp.MustCompile(`'([,:\-\[\]{}?])'`)
	scrubTagRE    = regexp.MustCompile(`![^\s` + "`" + `]*`)
	yamlTags      = map[string]bool{"!!str": true, "!!int": true, "!!float": true, "!!bool": true, "!!null": true,
		"!!seq": true, "!!map": true, "!!binary": true, "!!timestamp": true, "!!merge": true}
)

// maxScrub is the longest decoder message shown under RedactValues.
const maxScrub = 64 << 10

// scrub is the decoder's own text without anything it copied from the file (RedactValues). yaml.v3
// quotes keys with Go quoting ("mapping key \"KEY\" already defined"), anchor names in single
// quotes, and copies three things bare: a value in backticks ("cannot unmarshal TAG `VALUE` into
// T"), a tag ("cannot unmarshal TAG …": written "!<tag:x>" it has no "!", and with %-escapes it may
// hold spaces and line breaks) and an unknown key ("field KEY not found in type T").
func scrub(text string) string {
	if len(text) > maxScrub {
		return ""
	}
	text = scrubCut(text)
	// Intentional: NUL stands in for a masked string while a quote left open is looked for; the
	// text has none of its own after this line.
	text = strings.ReplaceAll(text, "\x00", " ")
	text = scrubStringRE.ReplaceAllString(text, "\x00")
	if i := strings.IndexByte(text, '"'); i >= 0 {
		text = text[:i] + "\x00"
	}
	text = strings.ReplaceAll(text, "\x00", `"…"`)
	text = scrubMapKeyRE.ReplaceAllString(text, "invalid map key: …")
	// Single quotes are not paired up (an apostrophe would shift the pairs): per line, everything
	// from the first to the last goes, except the parser naming a character it expected ("did not
	// find expected ',' or ']'").
	lines := strings.Split(text, "\n")
	for n, line := range lines {
		line = scrubCharRE.ReplaceAllString(line, "\x00$1\x00")
		if i, j := strings.IndexByte(line, '\''), strings.LastIndexByte(line, '\''); i >= 0 {
			line = line[:i] + "'…'" + line[j+1:]
		}
		lines[n] = strings.ReplaceAll(line, "\x00", "'")
	}
	text = strings.Join(lines, "\n")
	return scrubTagRE.ReplaceAllStringFunc(text, func(tag string) string {
		if yamlTags[tag] {
			return tag
		}
		return "!…"
	})
}

// scrubCut ends the text at the first thing yaml.v3 copies bare from the file: a value's tag, an
// unknown key, a backtick. Intentional: everything after that point is dropped, not only the copied
// part. A bare key, tag or value can hold the very words that would mark its end (" not found in
// type ", " into ", a backtick, a line break followed by "line 3: "), so no pattern can tell where
// it stops; masking "up to the end marker" left the rest of a crafted key or tag in the message.
// The text before the first one is the decoder's own.
func scrubCut(text string) string {
	cut, tail := len(text), ""
	if i := strings.IndexByte(text, '`'); i >= 0 {
		cut, tail = i, "`…`"
	}
	if m := scrubFieldRE.FindStringIndex(text[:cut]); m != nil {
		cut, tail = m[1]-len("field "), "field … not found in type …"
	}
	if m := scrubTypedRE.FindStringIndex(text[:cut]); m != nil {
		cut, tail = m[1], scrubbedTag(text[m[1]:])+" …"
	}
	return text[:cut] + tail
}

// scrubbedTag is the tag at the start of s when it is one of yaml's own, "!…" for any other.
func scrubbedTag(s string) string {
	if i := strings.IndexAny(s, " \t\r\n`"); i >= 0 {
		s = s[:i]
	}
	if yamlTags[s] {
		return s
	}
	return "!…"
}

func (d *Diagnostics) causeText() string {
	if d.Cause == nil {
		return "the file was refused"
	}
	msg := d.Cause.Error()
	if d.redact {
		msg = scrub(msg)
	}
	if len(msg) > 4*maxLine {
		msg = msg[:4*maxLine]
	}
	if msg = cleanText(msg, maxLine); msg == "" {
		return "the file was refused"
	}
	return msg
}

func (d *Diagnostics) errorLine() string {
	if d == nil {
		return ""
	}
	file := cleanText(d.File, maxMsg)
	if len(d.Problems) == 0 {
		return where(file, Pos{}) + d.causeText()
	}
	p := d.Problems[0]
	var b strings.Builder
	b.WriteString(where(file, p.Pos))
	b.WriteString(cleanText(p.Msg, maxMsg))
	if hint := cleanText(p.Hint, maxMsg); hint != "" {
		b.WriteString(" (hint: " + hint + ")")
	}
	switch n := len(d.Problems) - 1 + d.More; {
	case n == 1:
		b.WriteString("; 1 more problem")
	case n > 1:
		fmt.Fprintf(&b, "; %d more problems", n)
	}
	return b.String()
}

func (d *Diagnostics) terminal() string {
	if d == nil {
		return ""
	}
	file := cleanText(d.File, maxMsg)
	if len(d.Problems) == 0 {
		return where(file, Pos{}) + d.causeText() + "\n"
	}
	var b strings.Builder
	for i, p := range d.Problems {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(where(file, p.Pos) + cleanText(p.Msg, maxMsg) + "\n")
		if p.Line > 0 && (p.shown || p.Excerpt != "") {
			width := len(strconv.Itoa(p.Line))
			if p.Line > 1 && p.shown {
				fmt.Fprintf(&b, "  %*d | %s\n", width, p.Line-1, showLine(p.prev))
			}
			excerpt := showLine(p.Excerpt)
			fmt.Fprintf(&b, "  %*d | %s\n", width, p.Line, excerpt)
			caret := p.caret
			if !p.shown && p.Col > 0 && p.Col-1 <= utf8.RuneCountInString(excerpt) { // the caller's own excerpt
				caret = p.Col
			}
			if caret > 0 {
				fmt.Fprintf(&b, "  %*s | %s^\n", width, "", strings.Repeat(" ", caret-1))
			}
		}
		if hint := cleanText(p.Hint, maxMsg); hint != "" {
			b.WriteString("   hint: " + hint + "\n")
		}
	}
	if d.More > 0 {
		fmt.Fprintf(&b, "\n… and %d more\n", d.More)
	}
	return b.String()
}

func (d *Diagnostics) json() []byte {
	if d == nil {
		return []byte("null")
	}
	out := struct {
		File     string    `json:"file"`
		Problems []Problem `json:"problems"`
		More     int       `json:"more,omitempty"`
	}{d.File, d.Problems, d.More}
	if out.Problems == nil {
		out.Problems = []Problem{}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return []byte(`{"file":"","problems":[]}`)
	}
	return b
}
