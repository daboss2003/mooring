package yamldiag

import (
	"strings"
	"testing"
)

// The scanner names the line that is wrong, not a neighbour of it (the v0.34.0 fix round).
func TestScannerBlamesTheRightLine(t *testing.T) {
	const (
		ownHint  = `the lines around it are "key: value" entries; add the missing ':' or fix this line's indentation`
		noSpace  = "there is no space after the ':'"
		ctrlMsg  = "the file contains a control character"
		ctrlHint = "remove it; the file must be plain UTF-8 text"
	)
	cases := []struct {
		name, raw string
		line, col int
		msg, hint string
	}{
		// A first entry with no ':' is read as the value of the key above; the next key cannot follow it.
		{"missing colon, first entry", "edge:\n  mode managed\n  acme_email: y\n", 2, 3, notKeyValueMsg, ownHint},
		{"missing colon, first entry, deeper", "port: 1\nedge:\n  base_domains:\n    - domain: a\n      mode x\n      dns01: true\n", 5, 7,
			notKeyValueMsg, ownHint},
		{"missing colon after a dash", "edge:\n  base_domains:\n    - domain a\n      dns01: true\n", 3, 7, notKeyValueMsg, ownHint},
		{"missing colon between entries", "edge:\n  mode: x\n  enabled true\n  acme_email: y\n", 3, 3, notKeyValueMsg, ownHint},
		// Text over several lines under a key is a value: the key below it is what does not fit, and
		// the hint does not ask to remove a value the key's own line does not have.
		{"text over two lines, then a key", "edge:\n  mode:\n    some text\n    more text\n    acme_email: y\n", 5, 5,
			"this line is indented under line 2, which already has a value (the text that starts on line 3)",
			"start it in column 3 like line 2, or remove that text to nest this line under line 2"},
		{"quoted text, then a key", "edge:\n  mode:\n    \"quoted\"\n    acme_email: y\n", 4, 5,
			"this line is indented under line 2, which already has a value (the text that starts on line 3)",
			"start it in column 3 like line 2, or remove that text to nest this line under line 2"},
		// No space after the ':' following a dash, and before a block scalar's | or >.
		{"glued after a dash", "edge:\n  base_domains:\n    - domain:example.com\n      dns01: true\n", 3, 14, noSpace,
			`put a space between "domain:" and its value`},
		{"glued before a block scalar", "port: 1\nbind_addr:|\n  text\nworkers: 2\n", 2, 11, noSpace, `put a space between "bind_addr:" and its value`},
		{"glued before a block scalar, nested", "edge:\n  mode:|\n    text\n  acme_email: y\n", 2, 8, noSpace, `put a space between "mode:" and its value`},
		{"glued before a folded scalar, nested", "edge:\n  mode:>-\n    text\n    more\n  acme_email: y\n", 2, 8, noSpace,
			`put a space between "mode:" and its value`},
		// A byte the reader refuses is the mistake, whatever its line looks like.
		{"control character alone on a line", "port: 1\n\x01\nworkers: 2\n", 2, 1, ctrlMsg, ctrlHint},
		{"control character alone, indented", "edge:\n  mode: x\n  \x7f\n", 3, 3, ctrlMsg, ctrlHint},
		{"control character in a line with no colon", "port: 1\njunk\x02\nworkers: 2\n", 2, 5, ctrlMsg, ctrlHint},
		// A block whose first line is indented wrongly makes a later line "match nothing": both are named.
		{"first entry of a block mis-indented", "port: 1\nedge:\n     mode: x\n  acme_email: y\n", 4, 3,
			"this line is indented by 2 spaces, which matches no block above it; it does not match line 3 above (indented by 5 spaces)",
			"indent it by 0 or 5 spaces"},
		{"first entry of a list mis-indented", "edge:\n  base_domains:\n      - domain: a\n    - domain: b\n", 4, 5,
			"this line is indented by 4 spaces, which matches no block above it; it does not match line 3 above (indented by 6 spaces)",
			"indent it by 0, 2, 6 or 8 spaces"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := explainT(t, c.raw, Options{})
			if len(d.Problems) != 1 {
				t.Fatalf("problems = %+v", d.Problems)
			}
			p := d.Problems[0]
			if p.Line != c.line || p.Col != c.col || p.Msg != c.msg || p.Hint != c.hint || p.Kind != KindSyntax {
				t.Errorf("got  %d:%d %q hint %q\nwant %d:%d %q hint %q", p.Line, p.Col, p.Msg, p.Hint, c.line, c.col, c.msg, c.hint)
			}
			// Every scanner report is one the parser confirms: the file parses up to the line before.
			if c.msg != ctrlMsg && !parses(newSource([]byte(c.raw)).through(p.Line-1)) {
				t.Errorf("the file does not parse up to line %d", p.Line-1)
			}
		})
	}
	// The same shapes in files that ARE valid YAML: nothing is reported.
	for _, raw := range []string{
		"edge:\n  mode managed\n", "l:\n  - name:VALUE\n  - name: y\n", "a:\n  key:>-\n    text\n", "a:\n  b:\n    some text\n    more text\nc: 1\n",
		"l:\n  - name x\n  - k: v\n",
	} {
		if !parses([]byte(raw)) {
			t.Fatalf("not valid YAML: %q", raw)
		}
		if f := (&scanner{src: newSource([]byte(raw))}).run(); f != nil && f != bail {
			t.Errorf("%q: the scanner reports %d:%d %q", raw, f.line, f.col, f.msg)
		}
	}
}

// The caret is drawn under what the excerpt displays: never past a cut excerpt, and counted in
// characters like the column.
func TestCaretStaysUnderTheExcerpt(t *testing.T) {
	carets := func(d *Diagnostics) (lines []string) {
		for _, l := range strings.Split(d.Terminal(), "\n") {
			if strings.HasSuffix(l, "^") {
				lines = append(lines, l)
			}
		}
		return lines
	}
	// 150 two-byte characters: the excerpt is cut at 200 bytes (100 characters).
	wide := strings.Repeat("é", 150)
	d := explainT(t, "labels:\n  "+wide+": [x]\n", Options{})
	if p := d.Problems[0]; p.Col != 3 || len(carets(d)) != 1 || !strings.HasSuffix(carets(d)[0], "|   ^") {
		t.Errorf("a column inside the cut excerpt: col %d, %q", p.Col, carets(d))
	}
	d = explainT(t, "labels:\n  k: \""+wide+"\n", Options{})
	if p := d.Problems[0]; p.Col != 6 || len(carets(d)) != 1 {
		t.Errorf("an unclosed quote at the start of a long line: col %d, %q", p.Col, carets(d))
	}
	// The column is past the cut: no caret at all, instead of one hanging in the air.
	d = explainT(t, "bind_addr: "+wide+": x\n", Options{})
	p := d.Problems[0]
	if p.Col != 162 || len([]rune(p.Excerpt)) > 110 || len(carets(d)) != 0 {
		t.Errorf("a column past the cut: col %d, excerpt of %d characters, carets %q", p.Col, len([]rune(p.Excerpt)), carets(d))
	}
	// One character before the cut still gets its caret (counted in characters, not bytes).
	d = explainT(t, "bind_addr: "+strings.Repeat("é", 80)+": "+strings.Repeat("x", 300)+"\n", Options{})
	p = d.Problems[0]
	if p.Col != 92 || len(carets(d)) != 1 || !strings.HasSuffix(carets(d)[0], "| "+strings.Repeat(" ", 91)+"^") {
		t.Errorf("a column in a multi-byte line: col %d, carets %q", p.Col, carets(d))
	}
	// A masked excerpt: the caret sits on the "…", wherever in the value the column was.
	d = explainT(t, "bind_addr: "+wide+": x\n", Options{RedactValues: true})
	if got := carets(d); d.Problems[0].Excerpt != "bind_addr: …" || len(got) != 1 || !strings.HasSuffix(got[0], "|            ^") {
		t.Errorf("a masked value: %q, carets %q", d.Problems[0].Excerpt, got)
	}
	// An excerpt the caller supplied keeps the plain rule.
	own := &Diagnostics{File: "m", Problems: []Problem{{Pos: Pos{1, 3}, Msg: "a", Excerpt: "abc"}, {Pos: Pos{2, 9}, Msg: "b", Excerpt: "abc"}}}
	if got := carets(own); len(got) != 1 || !strings.HasSuffix(got[0], "|   ^") {
		t.Errorf("a caller's excerpt: %q", got)
	}
}
