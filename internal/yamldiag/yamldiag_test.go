package yamldiag

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

type tDomain struct {
	Domain string `yaml:"domain"`
	DNS01  bool   `yaml:"dns01,omitempty"`
	Mode   string `yaml:"mode,omitempty"`
}

type tEdge struct {
	Mode    string        `yaml:"mode"`
	Email   string        `yaml:"acme_email"`
	Timeout time.Duration `yaml:"timeout"`
	Domains []tDomain     `yaml:"base_domains"`
}

type tCommon struct {
	Region string `yaml:"region"`
}

// tCheck decodes itself, like the app definition's healthcheck.
type tCheck struct{ Test []string }

func (c *tCheck) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: healthcheck must be a mapping with test", n.Line)
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value != "test" {
			return fmt.Errorf("line %d: unknown healthcheck key %q", n.Content[i].Line, n.Content[i].Value)
		}
		if err := n.Content[i+1].Decode(&c.Test); err != nil {
			return err
		}
	}
	return nil
}

type tConfig struct {
	Bind    string            `yaml:"bind_addr"`
	Scan    bool              `yaml:"image_scan_enabled"`
	Port    int               `yaml:"port"`
	Workers uint8             `yaml:"workers"`
	Ratio   float64           `yaml:"ratio"`
	Edge    tEdge             `yaml:"edge"`
	Allow   []string          `yaml:"ip_allowlist"`
	Labels  map[string]string `yaml:"labels"`
	Key     string            `yaml:"encryption_key"`
	Check   *tCheck           `yaml:"healthcheck"`
	Common  tCommon           `yaml:",inline"`
	Skipped string            `yaml:"-"`
	Any     interface{}       `yaml:"extra"`
	private string
}

var tType = reflect.TypeOf(tConfig{})

// strict is the decode the diagnostics explain: what config.Parse and definition.Parse do.
func strict(raw string, out interface{}) error {
	dec := yaml.NewDecoder(strings.NewReader(raw))
	dec.KnownFields(true)
	return dec.Decode(out)
}

func explainT(t *testing.T, raw string, o Options) *Diagnostics {
	t.Helper()
	var c tConfig
	err := strict(raw, &c)
	if err == nil {
		t.Fatalf("the strict decode accepts %q; the case tests nothing", raw)
	}
	if o.File == "" {
		o.File = "f.yaml"
	}
	return Explain([]byte(raw), tType, err, o)
}

func TestScannerFindsTheRealLine(t *testing.T) {
	const (
		tabMsg    = "a tab is used for indentation"
		tabHint   = "indent with spaces; YAML does not accept tabs for indentation"
		colonMsg  = "the value contains ':' followed by a space, which YAML reads as the start of another key"
		quoteHint = "add the closing quote at the end of the value"
	)
	cases := []struct {
		name, raw string
		line, col int
		msg, hint string
	}{
		{"tab in indentation", "edge:\n\tmode: x\n", 2, 1, tabMsg, tabHint},
		{"tab after spaces", "edge:\n  mode: x\n  \tacme_email: y\n", 3, 3, tabMsg, tabHint},
		{"indentation matches no block", "edge:\n    mode: x\n  acme_email: y\n", 3, 3,
			"this line is indented by 2 spaces, which matches no block above it; it does not match line 2 above (indented by 4 spaces)", "indent it by 0 or 4 spaces"},
		{"three levels", "edge:\n  base_domains:\n    - domain: a\n      dns01: true\n   mode: x\n", 5, 4,
			"this line is indented by 3 spaces, which matches no block above it; it does not match line 3 above (indented by 4 spaces)", "indent it by 0, 2, 4 or 6 spaces"},
		{"one space under a key with a value", "port: 1\n bind_addr: x\n", 2, 2,
			"this line is indented under line 1, which already has a value",
			"start it in column 1 like line 1, or remove the value on line 1 to nest this line under it"},
		{"sibling indented deeper", "edge:\n  mode: x\n    acme_email: y\n", 3, 5,
			"this line is indented under line 2, which already has a value",
			"start it in column 3 like line 2, or remove the value on line 2 to nest this line under it"},
		{"list entry key indented deeper", "edge:\n  base_domains:\n    - domain: a\n       dns01: true\n", 4, 8,
			"this line is indented under line 3, which already has a value",
			"start it in column 7 like line 3, or remove the value on line 3 to nest this line under it"},
		{"no space after colon", "port: 1\nbind_addr:x\nlabels: {}\n", 2, 11,
			"there is no space after the ':'", `put a space between "bind_addr:" and its value`},
		{"no space after colon, nested", "edge:\n  mode:x\n  acme_email: y\n", 2, 8,
			"there is no space after the ':'", `put a space between "mode:" and its value`},
		{"no space after colon, first line", "port:1\nbind_addr: x\n", 1, 6,
			"there is no space after the ':'", `put a space between "port:" and its value`},
		{"colon space in a value", "bind_addr: host: 8080\n", 1, 16, colonMsg, "put the whole value in quotes"},
		{"colon at the end of a value", "port: 1\nbind_addr: host:\n", 2, 16, colonMsg, "put the whole value in quotes"},
		{"unclosed double quote", "bind_addr: \"x\nport: 1\n", 1, 12, `this quote (") is never closed`, quoteHint},
		{"unclosed quote closed by a later one", "bind_addr: \"x\nencryption_key: \"y\"\n", 1, 12, `this quote (") is never closed`, quoteHint},
		{"unclosed single quote", "port: 1\nbind_addr: 'x\n", 2, 12, `this quote (') is never closed`, quoteHint},
		{"unclosed bracket", "ip_allowlist: [a, b\nport: 1\n", 1, 15, "this [ is never closed", "add the closing ]"},
		{"value starts with @", "bind_addr: @home\n", 1, 12,
			"a value cannot start with @ unless it is in quotes", "put the value in quotes"},
		{"a line with no colon", "port: 1\njunk\nbind_addr: x\n", 2, 1,
			`this line is not in "key: value" form`,
			`the lines around it are "key: value" entries; add the missing ':' or fix this line's indentation`},
		{"a comment is not a key", "port: 1\nbind_addr x # note: here\nlabels: {}\n", 2, 1,
			`this line is not in "key: value" form`,
			`the lines around it are "key: value" entries; add the missing ':' or fix this line's indentation`},
		{"key in the column of a list", "edge:\n  - a\n  mode: x\n", 3, 3,
			"this key starts in the same column as the list items above it, so it is neither a list item nor a key of the block the list belongs to",
			"indent it under its list item, or move it left to the column of the key that owns the list"},
		{"list item under a key with a value", "port: 1\n- a\n", 2, 1,
			`a list item ("- ") cannot start here: the block at this indentation is made of "key: value" lines`,
			`indent the "- " lines under the key they belong to, and give that key no value of its own`},
		{"list on the key line", "ip_allowlist: - a\n", 1, 15,
			`a list item ("- ") starts on the same line as its key`,
			`put each "- item" on its own line below the key, or write the list as [a, b]`},
		{"CRLF is not the mistake", "port: 1\r\n bind_addr: x\r\n", 2, 2,
			"this line is indented under line 1, which already has a value",
			"start it in column 1 like line 1, or remove the value on line 1 to nest this line under it"},
		{"BOM is not the mistake and takes no column", "\xef\xbb\xbfport: 1\n bind_addr: x\n", 2, 2,
			"this line is indented under line 1, which already has a value",
			"start it in column 1 like line 1, or remove the value on line 1 to nest this line under it"},
		{"columns count characters, not bytes", "labels:\n  é: \"x\n", 2, 6, `this quote (") is never closed`, quoteHint},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := explainT(t, c.raw, Options{})
			if len(d.Problems) != 1 {
				t.Fatalf("problems = %+v, want exactly one", d.Problems)
			}
			p := d.Problems[0]
			if p.Line != c.line || p.Col != c.col || p.Msg != c.msg || p.Hint != c.hint || p.Kind != KindSyntax || p.Path != "" {
				t.Errorf("got  %d:%d %q hint %q (%s)\nwant %d:%d %q hint %q", p.Line, p.Col, p.Msg, p.Hint, p.Kind, c.line, c.col, c.msg, c.hint)
			}
		})
	}
}

// The case the package exists for: yaml.v3 names another line than the one that is wrong.
func TestTopLevelKeyIndentedByOneSpaceOnALaterLine(t *testing.T) {
	var b strings.Builder
	b.WriteString("bind_addr: x\nport: 1\nworkers: 2\nratio: 1.5\nip_allowlist:\n  - 10.0.0.1\nedge:\n  mode: managed\n  base_domains:\n")
	for i := 0; i < 11; i++ {
		fmt.Fprintf(&b, "    - domain: d%d.example\n      dns01: true\n", i)
	}
	b.WriteString("  acme_email: a@b.c\n ip_allowlist: []\nlabels: {}\n")
	raw := b.String()
	if got := strings.Split(raw, "\n")[32]; got != " ip_allowlist: []" {
		t.Fatalf("line 33 is %q", got)
	}
	var c tConfig
	cause := strict(raw, &c)
	if cause == nil || strings.Contains(cause.Error(), "line 33") {
		t.Fatalf("yaml.v3 says %v; the case needs it to name another line", cause)
	}
	d := Explain([]byte(raw), tType, cause, Options{File: "/etc/mooring/config.yaml"})
	want := "/etc/mooring/config.yaml:33:2: this line is indented by 1 space, which matches no block above it; it does not match line 8 above (indented by 2 spaces) (hint: indent it by 0 or 2 spaces)"
	if d.Error() != want {
		t.Errorf("Error() = %q\n      want %q (yaml.v3: %v)", d.Error(), want, cause)
	}
	if !errors.Is(d, cause) {
		t.Error("the cause is not unwrapped")
	}
}

// Text that only looks like a mistake. run() is the scanner without the parser's confirmation, so
// this pins the scanner's own silence.
func TestScannerSilentOnValidYAML(t *testing.T) {
	cases := map[string]string{
		"block scalar":         "a: |\n  key: value: more\n   deeper: x\n  \"unclosed\n  \ttab # not a comment\n\n  - [\nb: 1\n",
		"folded with chomping": "a: >-\n  x: y: z\n\n  @at\nb: 2\n",
		"block scalar in list": "l:\n  - |\n    k: v: w\n    'x\n  - b\n",
		"block under list key": "- run: |\n    if x: then\n     y:z\n  name: a\n",
		"flow collections":     "a: [x, \"y: z\", 'it''s', {k: v, u: \"#no\"}]\nb: {c: [1,\n   2], d: 'e: f'}\nc: 1\n",
		"quoted strings":       "a: \"x: y # z\"\nb: 'p: q # r'\nc: \"multi\n  line: value # x\"\nd: 'it''s: fine'\n\"k: 1\": v\n",
		"comments":             "# a: b: c\na: 1 # x: y: z\n  # \"unclosed\n\n#\ttab\nb: 2\n",
		"urls and times":       "u: http://x.example:8080/a#frag\nt: 12:30:00\nw: C:\\dir\n",
		"plain continuation":   "a: some text\n  that goes on\n  - and on\nb: 2\n",
		"value on next line":   "a:\n  plain text\n  more text\nb:\n  \"quoted\"\n",
		"list under key":       "a:\n- x\n- y\nb:\n  - z\nc: 1\n",
		"nested lists":         "- - a\n  - b\n- c: 1\n  d:\n    - e\n  f: 2\n",
		"anchors and tags":     "a: &x\n  k: v\nb: *x\nc: !!str 1\nd: !!map\n  e: 1\nf: &y |\n  t: u: v\n",
		"documents":            "a: 1\n---\n  b: 1\n---\nc: 2\n...\n",
		"directive":            "%YAML 1.1\n---\na: 1\n",
		"crlf":                 "a:\r\n  b: 1\r\nc: |\r\n  x: y: z\r\nd: 2\r\n",
		"bom":                  "\xef\xbb\xbfa: 1\nb: 2\n",
		"empty values":         "a:\nb:\n  c:\n  d: ~\ne: ''\n",
		"hash in values":       "a: x#y\nb: '#z'\nc: #comment\n  d: 1\n",
		"tab after colon":      "a:\tx\nb: 1\t# c\n",
		"merge":                "base: &b\n  x: 1\nuse:\n  <<: *b\n  y: 2\n",
		"complex key":          "? a\n: b\n",
		"deep dedent":          "a:\n  b:\n    c:\n      d: 1\ne: 2\n",
		"flow in list":         "- [a, b]\n- {c: d}\n- \"e: f\"\n",
		"scalar document":      "plain words\n  and more\n",
		"indented first key":   "  a: 1\n  b: 2\n",
		"empty":                "",
		"only comments":        "# nothing\n\n",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if !parses([]byte(raw)) {
				t.Fatalf("not valid YAML: %q", raw)
			}
			if f := (&scanner{src: newSource([]byte(raw))}).run(); f != nil && f != bail {
				t.Errorf("the scanner reports %d:%d %q on valid YAML", f.line, f.col, f.msg)
			}
			if d := Explain([]byte(raw), nil, errors.New("refused"), Options{File: "f"}); len(d.Problems) != 0 || d.Error() != "f: refused" {
				t.Errorf("Explain reports %+v / %q", d.Problems, d.Error())
			}
		})
	}
}

// The scanner stays quiet inside the constructs above and still finds the mistake after them.
func TestScannerSkipsLookalikesBeforeTheMistake(t *testing.T) {
	raw := "labels:\n  a: |\n    k: v: w\n    \ttabbed\n    \"open\n  b: \"x: y # z\"\n  c: [1, '2: 3',\n     4] # d: e: f\n  # g: h: i\n  d: 'multi\n    line: x'\n  e: 1\n   f: 2\n"
	d := explainT(t, raw, Options{})
	if len(d.Problems) != 1 || d.Problems[0].Line != 13 || d.Problems[0].Col != 4 ||
		d.Problems[0].Msg != "this line is indented under line 12, which already has a value" {
		t.Errorf("problems = %+v", d.Problems)
	}
}

// A scanner finding the parser does not confirm is dropped: here a tab that YAML takes (it comes
// after the indentation of a value's second line), in a file broken further down.
func TestScannerFindingNeedsTheParsersConfirmation(t *testing.T) {
	raw := "bind_addr: x\n \ty\nencryption_key: \"a\\qb\"\n"
	if !parses([]byte("bind_addr: x\n \ty\n")) {
		t.Fatal("the tab line is not valid YAML; the case tests nothing")
	}
	if f := (&scanner{src: newSource([]byte(raw))}).run(); f == nil || !f.tab || f.line != 2 {
		t.Fatalf("the unconfirmed scanner finds %+v; the case needs its tab finding", f)
	}
	d := explainT(t, raw, Options{})
	if len(d.Problems) != 1 || d.Problems[0].Line != 3 || d.Problems[0].Msg != "a double-quoted value contains a backslash sequence YAML does not know" {
		t.Errorf("problems = %+v", d.Problems)
	}
	// With the tab set aside the scanner still finds a mistake after it.
	d = explainT(t, "bind_addr: x\n \ty\nport: 1\n workers: 2\n", Options{})
	if len(d.Problems) != 1 || d.Problems[0].Line != 4 || d.Problems[0].Col != 2 {
		t.Errorf("problems = %+v", d.Problems)
	}
}

// With nothing found by the scanner the parser's own message is reported, in plain words, at the
// parser's line and with no column.
func TestParserMessageInPlainWords(t *testing.T) {
	cases := []struct {
		raw       string
		line, col int
		msg, hint string
	}{
		{"port: 1\nbind_addr: \"a\\qb\"\n", 2, 0,
			"a double-quoted value contains a backslash sequence YAML does not know",
			`use single quotes around the value, or write each backslash as \\`},
		{"port: 1\nbind_addr: *nope\n", 2, 12,
			"a value that starts with * refers to an anchor that is not defined", "put the value in quotes if the * is part of it"},
		{"port: 1\nbind_addr: ]\n", 2, 0,
			"a value is missing, or starts with a character that cannot begin one (such as ] } or ,)", "put the value in quotes"},
		{"port: 1\nbind_addr: a\x01b\n", 2, 13,
			"the file contains a control character", "remove it; the file must be plain UTF-8 text"},
		{"port: 1\nbind_addr: \xff\n", 2, 12,
			"the file is not valid UTF-8 text", "save the file as UTF-8"},
	}
	for _, c := range cases {
		d := explainT(t, c.raw, Options{})
		if len(d.Problems) != 1 {
			t.Errorf("%q: problems = %+v", c.raw, d.Problems)
			continue
		}
		p := d.Problems[0]
		if p.Line != c.line || p.Col != c.col || p.Msg != c.msg || p.Hint != c.hint || p.Kind != KindSyntax {
			t.Errorf("%q:\n got  %d:%d %q hint %q\n want %d:%d %q hint %q", c.raw, p.Line, p.Col, p.Msg, p.Hint, c.line, c.col, c.msg, c.hint)
		}
	}
	for _, tr := range translations {
		if strings.Contains(tr.msg, "yaml") || strings.HasSuffix(tr.msg, ".") || tr.hint == "" {
			t.Errorf("translation of %q: %q / %q", tr.yaml, tr.msg, tr.hint)
		}
	}
	three := newSource([]byte("a\nb\nc\n"))
	pos, msg, hint := translate(errors.New("yaml: line 3: mapping values are not allowed in this context"), three, false)
	if pos != (Pos{Line: 3}) || msg != "this line has a ':' the parser did not expect" ||
		hint != "check the indentation of this line and the one above, or quote the value" {
		t.Errorf("translate = %v %q %q", pos, msg, hint)
	}
	if pos, _, _ := translate(errors.New("yaml: mapping values are not allowed in this context"), three, false); pos != (Pos{Line: 1}) {
		t.Errorf("no line means the first: %v", pos)
	}
	// yaml.v3 prints its parser's errors with a 0-based line.
	pos, msg, _ = translate(errors.New("yaml: line 2: did not find expected key"), three, false)
	if pos != (Pos{Line: 3}) || msg != `this line, or a line below it in the same block, is indented differently from its neighbours or is not in "key: value" form` {
		t.Errorf("a parser error: %v %q", pos, msg)
	}
	if pos, msg, _ := translate(errors.New("yaml: line 9: something new"), three, false); pos != (Pos{Line: 3}) || msg != "something new" {
		t.Errorf("an unknown message: %v %q", pos, msg)
	}
}

func TestTypedWalk(t *testing.T) {
	type want struct {
		line, col             int
		kind, path, msg, hint string
	}
	const (
		wantMap  = ` must be a mapping (indented "key: value" lines), found `
		wantList = ` must be a list (lines starting with "- "), found `
		noDash   = `remove the "- " and write the keys directly under it`
	)
	cases := []struct {
		name, raw string
		want      []want
	}{
		{"unknown key with a close sibling", "edgee:\n  mode: x\n", []want{
			{1, 1, KindUnknownKey, "edgee", `unknown key "edgee"`, "did you mean edge?"}}},
		{"unknown nested key", "edge:\n  base_domains:\n    - domain: a\n    - domian: b\n", []want{
			{4, 7, KindUnknownKey, "edge.base_domains[1].domian", `unknown key "domian" in edge.base_domains[1]`, "did you mean domain?"}}},
		{"key of another block", "acme_email: a@b.c\n", []want{
			{1, 1, KindUnknownKey, "acme_email", `unknown key "acme_email"`, "acme_email belongs under edge:"}}},
		{"key of several other blocks", "mode: x\n", []want{
			{1, 1, KindUnknownKey, "mode", `unknown key "mode"`, ""}}},
		{"top-level key inside a block", "edge:\n  encryption_key: x\n", []want{
			{2, 3, KindUnknownKey, "edge.encryption_key", `unknown key "encryption_key" in edge`, "encryption_key belongs at the top level of the file"}}},
		{"unknown key with nothing close", "edge:\n  zzzzzzzz: 1\n", []want{
			{2, 3, KindUnknownKey, "edge.zzzzzzzz", `unknown key "zzzzzzzz" in edge`, "keys allowed here: mode, acme_email, timeout, base_domains"}}},
		{"duplicate key", "port: 1\nbind_addr: x\nport: 2\n", []want{
			{3, 1, KindDuplicate, "port", `key "port" is written twice in this block (first on line 1)`, "keep one of the two"}}},
		{"quoted boolean", "image_scan_enabled: \"false\"\n", []want{
			{1, 21, KindType, "image_scan_enabled", `image_scan_enabled must be true or false without quotes (found "false")`, "remove the quotes"}}},
		{"single-quoted boolean in a list entry", "edge:\n  base_domains:\n    - dns01: 'True'\n", []want{
			{3, 14, KindType, "edge.base_domains[0].dns01", `edge.base_domains[0].dns01 must be true or false without quotes (found "True")`, "remove the quotes"}}},
		{"text for a boolean", "image_scan_enabled: maybe\n", []want{
			{1, 21, KindType, "image_scan_enabled", `image_scan_enabled must be true or false (found "maybe")`, ""}}},
		{"number for a boolean", "image_scan_enabled: 1\n", []want{
			{1, 21, KindType, "image_scan_enabled", `image_scan_enabled must be true or false (found 1)`, ""}}},
		{"text for a number", "port: eighty\n", []want{
			{1, 7, KindType, "port", `port must be a number (found "eighty")`, ""}}},
		{"quoted number", "port: \"8080\"\n", []want{
			{1, 7, KindType, "port", `port must be a number without quotes (found "8080")`, "remove the quotes"}}},
		{"negative for an unsigned number", "workers: -1\n", []want{
			{1, 10, KindType, "workers", `workers must not be negative (found -1)`, ""}}},
		{"number out of range", "workers: 300\n", []want{
			{1, 10, KindType, "workers", `workers is out of range (found 300)`, ""}}},
		{"text for a float", "ratio: half\n", []want{
			{1, 8, KindType, "ratio", `ratio must be a number (found "half")`, ""}}},
		{"bad duration", "edge:\n  timeout: soon\n", []want{
			{2, 12, KindType, "edge.timeout", `edge.timeout must be a duration like 30s or 5m (found "soon")`, ""}}},
		{"scalar where a list is expected", "ip_allowlist: 10.0.0.1\n", []want{
			{1, 15, KindType, "ip_allowlist", "ip_allowlist" + wantList + "text",
				`write the value as "- value" on its own line below the key, or as [value]`}}},
		{"mapping where a list is expected", "ip_allowlist:\n  a: b\n", []want{
			{1, 1, KindType, "ip_allowlist", "ip_allowlist" + wantList + "a mapping", `start each entry with "- "`}}},
		{"scalar where a mapping is expected", "edge: managed\n", []want{
			{1, 7, KindType, "edge", "edge" + wantMap + "text", ""}}},
		{"key:value where a mapping is expected", "edge:\n  mode:x\n", []want{
			{2, 3, KindType, "edge", "edge" + wantMap + "text", "add a space after the ':'"}}},
		{"list where a mapping is expected", "edge:\n  - mode: x\n", []want{
			{1, 1, KindType, "edge", "edge" + wantMap + "a list", noDash}}},
		{"number where a string map is expected", "labels: 5\n", []want{
			{1, 9, KindType, "labels", "labels" + wantMap + "a number", ""}}},
		{"list where a value is expected", "bind_addr:\n  - x\n", []want{
			{1, 1, KindType, "bind_addr", "bind_addr must be a single value, found a list", ""}}},
		{"mapping where a number is expected", "port:\n  a: 1\n", []want{
			{1, 1, KindType, "port", "port must be a number, found a mapping", ""}}},
		{"list where a boolean is expected", "image_scan_enabled: [true]\n", []want{
			{1, 1, KindType, "image_scan_enabled", "image_scan_enabled must be true or false, found a list", ""}}},
		{"mapping in a string map", "labels:\n  a: {b: c}\n", []want{
			{2, 3, KindType, "labels.a", "labels.a must be a single value, found a mapping", ""}}},
		{"a list file", "- a\n", []want{
			{1, 1, KindType, "", "the file" + wantMap + "a list", noDash}}},
		{"value cut by a comment", "port: #8080\nworkers: x #1\n", []want{
			{2, 10, KindType, "workers", `workers must be a number (found "x")`, `everything after " #" is a comment; put the value in quotes if the # is part of it`}}},
		{"several, in file order", "zzz: 1\nport: x\nedge:\n  mod: y\n", []want{
			{1, 1, KindUnknownKey, "zzz", `unknown key "zzz"`, ""},
			{2, 7, KindType, "port", `port must be a number (found "x")`, ""},
			{4, 3, KindUnknownKey, "edge.mod", `unknown key "mod" in edge`, "did you mean mode?"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := explainT(t, c.raw, Options{})
			if len(d.Problems) != len(c.want) {
				t.Fatalf("problems = %+v, want %d", d.Problems, len(c.want))
			}
			for i, w := range c.want {
				p := d.Problems[i]
				if p.Line != w.line || p.Col != w.col || p.Kind != w.kind || p.Path != w.path || p.Msg != w.msg || p.Hint != w.hint {
					t.Errorf("problem %d:\n got  %d:%d %s %q %q hint %q\n want %d:%d %s %q %q hint %q", i,
						p.Line, p.Col, p.Kind, p.Path, p.Msg, p.Hint, w.line, w.col, w.kind, w.path, w.msg, w.hint)
				}
				for _, goName := range []string{"yamldiag.", "tConfig", "tEdge", "!!", "struct", "bool", "string", "float", "uint", "[]", "time."} {
					if strings.Contains(p.Msg+p.Hint, goName) {
						t.Errorf("the message names a Go or YAML type (%s): %q", goName, p.Msg)
					}
				}
			}
		})
	}
}

// What the decoder accepts the walk must not report, even when something else refuses the file.
func TestWalkAgreesWithTheDecoder(t *testing.T) {
	raw := "bind_addr: 80\nimage_scan_enabled: yes\nport: 3.0\nworkers: 0x10\nratio: 2\nedge:\n  timeout: 90s\n  base_domains:\n    - {domain: a, dns01: 'on'}\n" +
		"ip_allowlist: [1, true]\nlabels: {a: 1, b: ~}\nencryption_key: ~\nregion: eu\nextra: &more {ratio: 3}\nhealthcheck:\n  test: [a]\n<<: *more\n? ~\n: x\n"
	var c tConfig
	if err := strict(raw, &c); err != nil {
		t.Fatalf("the decoder refuses the file: %v", err)
	}
	if c.Common.Region != "eu" || !c.Scan || c.Port != 3 || !c.Edge.Domains[0].DNS01 {
		t.Fatalf("decoded %+v", c)
	}
	if d := Explain([]byte(raw), tType, errors.New("validation said no"), Options{File: "f"}); len(d.Problems) != 0 {
		t.Errorf("problems on a file the decoder accepts: %+v", d.Problems)
	}
	if d := Explain([]byte("edgee: 1\n"), reflect.TypeOf(&tConfig{}), errors.New("x"), Options{}); len(d.Problems) != 1 {
		t.Errorf("a pointer target: %+v", d.Problems)
	}
	if d := Explain([]byte("edgee: 1\n"), nil, errors.New("x"), Options{}); len(d.Problems) != 0 {
		t.Errorf("no target: %+v", d.Problems)
	}
}

func TestInlineAndSkippedFields(t *testing.T) {
	d := explainT(t, "region: eu\nregoin: us\nSkipped: x\nprivate: y\ncommon:\n  region: z\n", Options{})
	var got []string
	for _, p := range d.Problems {
		got = append(got, fmt.Sprintf("%d %s %s|%s", p.Line, p.Kind, p.Msg, p.Hint))
	}
	want := []string{
		`2 unknown_key unknown key "regoin"|did you mean region?`,
		`3 unknown_key unknown key "Skipped"|`,
		`4 unknown_key unknown key "private"|`,
		`5 unknown_key unknown key "common"|`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}

	type withMap struct {
		Name  string            `yaml:"name"`
		Other map[string]string `yaml:",inline"`
	}
	raw := "name: a\nanything: b\nnested: {c: d}\n"
	var v withMap
	cause := strict(raw, &v)
	d = Explain([]byte(raw), reflect.TypeOf(v), cause, Options{})
	if cause == nil || len(d.Problems) != 1 || d.Problems[0].Msg != "nested must be a single value, found a mapping" {
		t.Errorf("an inline map: cause %v, problems %+v", cause, d.Problems)
	}
}

type tNoLine struct{}

func (*tNoLine) UnmarshalYAML(*yaml.Node) error { return errors.New("no good\n\there") }

// A type that decodes itself is not walked; the message it gives with its own line is kept there.
func TestOpaqueUnmarshaler(t *testing.T) {
	d := explainT(t, "port: 1\nhealthcheck:\n  test: [a]\n  interval: 5s\n", Options{})
	if len(d.Problems) != 1 {
		t.Fatalf("problems = %+v", d.Problems)
	}
	p := d.Problems[0]
	if p.Line != 4 || p.Col != 3 || p.Msg != `unknown healthcheck key "interval"` || p.Path != "healthcheck.interval" ||
		p.Excerpt != "  interval: 5s" || p.Kind != KindSemantic {
		t.Errorf("got %+v", p)
	}

	// The decoder's own complaint from inside it, without Go type names.
	d = explainT(t, "healthcheck:\n  test: {a: b}\n", Options{})
	if len(d.Problems) != 1 || d.Problems[0].Line != 2 || d.Problems[0].Msg != "healthcheck.test has the wrong type (found a mapping)" || d.Problems[0].Kind != KindType {
		t.Errorf("got %+v", d.Problems)
	}

	// Nothing with a line: the cause's own message, on one line.
	type bare struct {
		H tNoLine `yaml:"h"`
	}
	var b bare
	cause := strict("h: 1\n", &b)
	d = Explain([]byte("h: 1\n"), reflect.TypeOf(b), cause, Options{File: "m.yaml"})
	if len(d.Problems) != 0 || d.Error() != "m.yaml: no good here" {
		t.Errorf("problems %+v, Error() %q", d.Problems, d.Error())
	}
}

func TestRedaction(t *testing.T) {
	const secret = "hunter2-SECRET"
	o := Options{File: "config.yaml", RedactValues: true}
	cases := []struct {
		name, raw, excerpt string
		line, col          int
		caret              int // where the caret is drawn: on the "…" when the column is in the masked part
	}{
		{"indentation", "port: 1\n encryption_key: " + secret + "\n", " encryption_key: …", 2, 2, 2},
		{"tab", "edge:\n\tacme_email: " + secret + "\n", " acme_email: …", 2, 1, 1},
		{"no space after colon", "port: 1\nencryption_key:" + secret + "\nbind_addr: x\n", "encryption_key:…", 2, 16, 16},
		{"colon in the value", "encryption_key: " + secret + ": x\n", "encryption_key: …", 1, 16 + len(secret) + 1, 17},
		{"unclosed quote", "encryption_key: \"" + secret + "\nport: 1\n", "encryption_key: …", 1, 17, 17},
		{"line without a key", "port: 1\n" + secret + "\nbind_addr: x\n", "…", 2, 1, 1},
		{"type mismatch", "port: " + secret + "\n", "port: …", 1, 7, 7},
		{"quoted number", "workers: \"12345\"\n", "workers: …", 1, 10, 10},
		{"unknown key", "encryption_kee: " + secret + "\n", "…", 1, 1, 1},
		{"unknown key, a schema key", "edge:\n  encryption_key: " + secret + "\n", "  encryption_key: …", 2, 3, 3},
		{"duplicate", "encryption_key: a\nencryption_key: " + secret + "\n", "encryption_key: …", 2, 1, 1},
		{"list item", "ip_allowlist:\n  - " + secret + "\n  -  x: y: z\n", "  -  …", 3, 10, 6},
		{"parser message", "encryption_key: \"" + secret + "\\q\"\n", "encryption_key: …", 1, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := explainT(t, c.raw, o)
			if len(d.Problems) != 1 {
				t.Fatalf("problems = %+v", d.Problems)
			}
			p := d.Problems[0]
			if p.Excerpt != c.excerpt || p.Line != c.line || p.Col != c.col {
				t.Errorf("got %d:%d %q, want %d:%d %q", p.Line, p.Col, p.Excerpt, c.line, c.col, c.excerpt)
			}
			for form, out := range map[string]string{"Error": d.Error(), "Terminal": d.Terminal(), "JSON": string(d.JSON())} {
				if strings.Contains(out, secret[:7]) || strings.Contains(out, "12345") {
					t.Errorf("%s shows the value: %s", form, out)
				}
			}
			if c.caret > 0 && !strings.Contains(d.Terminal(), "\n    | "+strings.Repeat(" ", c.caret-1)+"^\n") {
				t.Errorf("the caret is not under column %d:\n%s", c.caret, d.Terminal())
			}
			if c.caret == 0 && strings.Contains(d.Terminal(), "^") {
				t.Errorf("a caret with no column:\n%s", d.Terminal())
			}
		})
	}

	// The line before is context for the terminal and is masked too.
	d := explainT(t, "encryption_key: "+secret+"\n port: 1\n", o)
	if out := d.Terminal(); strings.Contains(out, secret) || !strings.Contains(out, "  1 | encryption_key: …\n  2 |  port: …\n") {
		t.Errorf("the previous line: %s", out)
	}

	// Nothing Explain finds shows a value.
	d = explainT(t, "bind_addr: [0.0.0.0]\nedge:\n  base_domains:\n    - domain: [apps.example]\n  mode: ["+secret+"]\n", o)
	if len(d.Problems) != 3 || d.Problems[0].Excerpt != "bind_addr: …" || d.Problems[1].Excerpt != "    - domain: …" || d.Problems[2].Excerpt != "  mode: …" {
		t.Errorf("lists where a value belongs: %+v", d.Problems)
	}
	d = explainT(t, "bind_addr: [x]\nport: nope\n", Options{RedactValues: true})
	if len(d.Problems) != 2 || d.Problems[1].Msg != `port must be a number` || d.Problems[1].Excerpt != "port: …" || d.Problems[0].Excerpt != "bind_addr: …" {
		t.Errorf("a value that failed its type: %+v", d.Problems)
	}

	// With no problem found, the decoder's message is shown without the value yaml quotes in it.
	cause := errors.New("yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `hunter2` into int")
	d = Explain(nil, tType, cause, o)
	if d.Error() != "config.yaml: yaml: unmarshal errors: line 1: cannot unmarshal !!str …" {
		t.Errorf("Error() = %q", d.Error())
	}
	if d := Explain(nil, nil, cause, Options{File: "m"}); !strings.Contains(d.Error(), "hunter2") {
		t.Errorf("without RedactValues the message is yaml's own: %q", d.Error())
	}
}

func TestWithoutRedactionTheLineIsShown(t *testing.T) {
	d := explainT(t, "port: 1\n encryption_key: abc # c\n", Options{})
	if d.Problems[0].Excerpt != " encryption_key: abc # c" {
		t.Errorf("excerpt = %q", d.Problems[0].Excerpt)
	}
}

func TestHostileTextIsCleaned(t *testing.T) {
	// A bidi override and a zero-width space in a key, an escape sequence in a value, a huge line.
	raw := "po\u202ert\u200b: 1\nlabels:\n  a: {b: \"\\e[31m\"}\n  " + strings.Repeat("é", 400) + ": [x]\n"
	d := explainT(t, raw, Options{File: "m\x1b[2J.yaml"})
	if len(d.Problems) != 3 {
		t.Fatalf("problems = %+v", d.Problems)
	}
	if p := d.Problems[0]; p.Msg != `unknown key "po rt"` || p.Excerpt != "port: 1" {
		t.Errorf("got %q / %q", p.Msg, p.Excerpt)
	}
	if p := d.Problems[2]; len(p.Excerpt) > MaxExcerpt || !strings.HasSuffix(p.Excerpt, "é") || len(p.Msg) > maxMsg || len(p.Path) > maxMsg {
		t.Errorf("a long line: excerpt %d bytes, msg %d bytes", len(p.Excerpt), len(p.Msg))
	}
	for form, out := range map[string]string{"Error": d.Error(), "Terminal": d.Terminal(), "JSON": string(d.JSON())} {
		for _, r := range out {
			if (unicode.IsControl(r) && r != '\n') || unicode.Is(unicode.Cf, r) {
				t.Fatalf("%s contains %U: %q", form, r, out)
			}
		}
	}
	if strings.Contains(d.Error(), "\n") || !strings.HasPrefix(d.Error(), "m [2J.yaml:1:1: ") {
		t.Errorf("Error() = %q", d.Error())
	}

	d = explainT(t, "port: 1\n\tbind\x07_addr: \x1b[31mx\n", Options{})
	// The caret counts what is displayed: the tab is one space, the BEL before column 6 is gone.
	if p := d.Problems[0]; p.Excerpt != " bind_addr: [31mx" || p.Col != 6 || p.Msg != "the file contains a control character" ||
		!strings.Contains(d.Terminal(), "\n  2 |  bind_addr: [31mx\n    |      ^\n") {
		t.Errorf("control characters in the excerpt: %q at column %d: %q\n%s", p.Excerpt, p.Col, p.Msg, d.Terminal())
	}
}

func TestLimits(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxProblems+7; i++ {
		fmt.Fprintf(&b, "unknown%02d: 1\n", i)
	}
	d := explainT(t, b.String(), Options{})
	if len(d.Problems) != MaxProblems || d.More != 7 {
		t.Fatalf("%d problems, %d more", len(d.Problems), d.More)
	}
	if d.Problems[0].Line != 1 || d.Problems[MaxProblems-1].Line != MaxProblems {
		t.Errorf("not the first %d in file order", MaxProblems)
	}
	if want := `f.yaml:1:1: unknown key "unknown00"; 26 more problems`; d.Error() != want {
		t.Errorf("Error() = %q, want %q", d.Error(), want)
	}
	if !strings.HasSuffix(d.Terminal(), "\n… and 7 more\n") {
		t.Errorf("Terminal() ends %q", d.Terminal()[len(d.Terminal())-40:])
	}
	var out struct {
		More int `json:"more"`
	}
	if json.Unmarshal(d.JSON(), &out) != nil || out.More != 7 {
		t.Errorf("JSON more = %d", out.More)
	}

	// Far more than is collected: still counted.
	b.Reset()
	for i := 0; i < maxCollected+50; i++ {
		fmt.Fprintf(&b, "u%d: 1\n", i)
	}
	if d := explainT(t, b.String(), Options{}); len(d.Problems) != MaxProblems || d.More != maxCollected+50-MaxProblems {
		t.Errorf("%d problems, %d more", len(d.Problems), d.More)
	}

	// Above MaxInput nothing is examined.
	big := "edgee: 1\n" + strings.Repeat("# padding\n", MaxInput/10+1)
	cause := errors.New("yaml: line 1: field edgee not found in type config.Config")
	d = Explain([]byte(big), tType, cause, Options{File: "big.yaml"})
	if len(d.Problems) != 0 || d.Error() != "big.yaml: "+cause.Error() || !errors.Is(d, cause) {
		t.Errorf("a file above MaxInput: %+v, %q", d.Problems, d.Error())
	}
	if ix, err := NewIndex([]byte(big)); err == nil || ix != nil {
		t.Error("NewIndex examines a file above MaxInput")
	}
	d.Semantic([]byte(big), []Problem{{Path: "edgee", Msg: "bad"}}, nil, Options{})
	if len(d.Problems) != 1 || d.Problems[0].Line != 0 {
		t.Errorf("Semantic examines a file above MaxInput: %+v", d.Problems)
	}
	if d := Explain([]byte(big[:MaxInput]), tType, cause, Options{}); len(d.Problems) != 1 {
		t.Errorf("a file of exactly MaxInput: %+v", d.Problems)
	}

	// Deep nesting and repeated aliases end the walk; they do not hang or panic.
	deep := strings.Repeat("{extra: ", 400) + "1" + strings.Repeat("}", 400) + "\n"
	_ = Explain([]byte(deep), tType, errors.New("x"), Options{})
	type rec struct {
		Next *rec `yaml:"next"`
		Bad  int  `yaml:"bad"`
	}
	chain := strings.Repeat("{next: ", maxDepth+50) + "{bad: x}" + strings.Repeat("}", maxDepth+50) + "\n"
	if d := Explain([]byte(chain), reflect.TypeOf(rec{}), errors.New("x"), Options{}); len(d.Problems) != 0 {
		t.Errorf("the walk went below maxDepth: %+v", d.Problems)
	}
	shallow := strings.Repeat("{next: ", 5) + "{bad: x}" + strings.Repeat("}", 5) + "\n"
	if d := Explain([]byte(shallow), reflect.TypeOf(rec{}), errors.New("x"), Options{}); len(d.Problems) != 1 {
		t.Errorf("a recursive type: %+v", d.Problems)
	}
	bomb := "a: &a [x, x, x, x, x, x, x, x, x]\n"
	for c := 'b'; c <= 'i'; c++ {
		bomb += fmt.Sprintf("%c: &%c [%s*%c]\n", c, c, strings.Repeat(fmt.Sprintf("*%c, ", c-1), 8), c-1)
	}
	type nested struct {
		I [][][][][][][][][]int `yaml:"i"`
		A interface{}           `yaml:"a"`
		B interface{}           `yaml:"b"`
		C interface{}           `yaml:"c"`
		D interface{}           `yaml:"d"`
		E interface{}           `yaml:"e"`
		F interface{}           `yaml:"f"`
		G interface{}           `yaml:"g"`
		H interface{}           `yaml:"h"`
	}
	start := time.Now()
	d = Explain([]byte(bomb), reflect.TypeOf(nested{}), errors.New("x"), Options{})
	if time.Since(start) > 5*time.Second || len(d.Problems) != MaxProblems || d.More == 0 {
		t.Errorf("an alias bomb took %v, %d problems, %d more", time.Since(start), len(d.Problems), d.More)
	}
}

func TestEmptyAndMultiDocument(t *testing.T) {
	cause := errors.New("config is empty")
	for _, raw := range []string{"", "\n\n", "# only a comment\n", "---\n", "\xef\xbb\xbf"} {
		d := Explain([]byte(raw), tType, cause, Options{File: "c.yaml"})
		if d == nil || len(d.Problems) != 0 || d.Error() != "c.yaml: config is empty" || d.Terminal() != "c.yaml: config is empty\n" ||
			string(d.JSON()) != `{"file":"c.yaml","problems":[]}` {
			t.Errorf("%q: %+v %q %q %s", raw, d.Problems, d.Error(), d.Terminal(), d.JSON())
		}
	}
	if d := Explain(nil, nil, nil, Options{}); d == nil || d.Error() != "the file was refused" || d.Unwrap() != nil {
		t.Errorf("nothing at all: %q", d.Error())
	}

	// Only the first document is decoded, so only it is explained.
	d := explainT(t, "port: x\n---\nedgee: 1\n  bad: indent\n", Options{})
	if len(d.Problems) != 1 || d.Problems[0].Line != 1 || d.Problems[0].Msg != `port must be a number (found "x")` {
		t.Errorf("multi-document: %+v", d.Problems)
	}
	// A mistake in the first document is found after a document marker.
	d = explainT(t, "---\nport: 1\n  bind_addr: x\n", Options{})
	if len(d.Problems) != 1 || d.Problems[0].Line != 3 || d.Problems[0].Col != 3 {
		t.Errorf("after ---: %+v", d.Problems)
	}
}

func TestRendering(t *testing.T) {
	raw := "port: 1\n" + strings.Repeat("# filler\n", 8) + "edge:\n  mod: 1\nimage_scan_enabled: 'true'\n\nzzz: 1\n"
	d := explainT(t, raw, Options{File: "/etc/mooring/config.yaml"})
	wantTerm := `/etc/mooring/config.yaml:11:3: unknown key "mod" in edge
  10 | edge:
  11 |   mod: 1
     |   ^
   hint: did you mean mode?

/etc/mooring/config.yaml:12:21: image_scan_enabled must be true or false without quotes (found "true")
  11 |   mod: 1
  12 | image_scan_enabled: 'true'
     |                     ^
   hint: remove the quotes

/etc/mooring/config.yaml:14:1: unknown key "zzz"
  13 | 
  14 | zzz: 1
     | ^
`
	if got := d.Terminal(); got != wantTerm {
		t.Errorf("Terminal():\n%s\nwant:\n%s", got, wantTerm)
	}
	if want := `/etc/mooring/config.yaml:11:3: unknown key "mod" in edge (hint: did you mean mode?); 2 more problems`; d.Error() != want {
		t.Errorf("Error() = %q\n     want %q", d.Error(), want)
	}
	wantJSON := `{"file":"/etc/mooring/config.yaml","problems":[` +
		`{"line":11,"col":3,"kind":"unknown_key","path":"edge.mod","msg":"unknown key \"mod\" in edge","hint":"did you mean mode?","excerpt":"  mod: 1"},` +
		`{"line":12,"col":21,"kind":"type","path":"image_scan_enabled","msg":"image_scan_enabled must be true or false without quotes (found \"true\")","hint":"remove the quotes","excerpt":"image_scan_enabled: 'true'"},` +
		`{"line":14,"col":1,"kind":"unknown_key","path":"zzz","msg":"unknown key \"zzz\"","excerpt":"zzz: 1"}]}`
	if got := string(d.JSON()); got != wantJSON {
		t.Errorf("JSON() = %s\n    want %s", got, wantJSON)
	}

	// The first line has no line before it; a one-digit gutter.
	d = explainT(t, "port: 1\n bind_addr: x\n", Options{File: "m.yaml"})
	want := "m.yaml:2:2: this line is indented under line 1, which already has a value\n  1 | port: 1\n  2 |  bind_addr: x\n    |  ^\n" +
		"   hint: start it in column 1 like line 1, or remove the value on line 1 to nest this line under it\n"
	if d.Terminal() != want {
		t.Errorf("Terminal():\n%s\nwant:\n%s", d.Terminal(), want)
	}
	if d := explainT(t, "edgee: 1\n", Options{File: "m.yaml"}); d.Terminal() != "m.yaml:1:1: unknown key \"edgee\"\n  1 | edgee: 1\n    | ^\n   hint: did you mean edge?\n" {
		t.Errorf("Terminal() on line 1:\n%s", d.Terminal())
	}

	one := &Diagnostics{File: "m.yaml", Problems: []Problem{{Pos: Pos{Line: 2}, Kind: KindSyntax, Msg: "bad"}, {Kind: KindSemantic, Msg: "worse", Hint: "fix"}}}
	if one.Error() != "m.yaml:2: bad; 1 more problem" || one.Terminal() != "m.yaml:2: bad\n\nm.yaml: worse\n   hint: fix\n" {
		t.Errorf("unknown positions: %q / %q", one.Error(), one.Terminal())
	}
	var none *Diagnostics
	if none.Error() != "" || none.Terminal() != "" || string(none.JSON()) != "null" || none.Unwrap() != nil {
		t.Error("a nil *Diagnostics")
	}
	none.Semantic(nil, []Problem{{Msg: "x"}}, nil, Options{})
}

func TestIndex(t *testing.T) {
	raw := "bind_addr: \"\"\nport: 0\nedge:\n  acme_email:\n  base_domains:\n    - domain: a\n    - domain: b\n      dns01: false\n" +
		"users:\n  - {name: x, role: admin}\nlabels:\n  example.com/team: ops\n  a.b: c\nempty: {}\nnone: []\nbase: &b\n  shared: 1\nuse:\n  <<: *b\n  own: 2\nref: *b\ndots:\n  a: z\n  a.b: c\nstod:\n  a.b: c\n  a: z\n"
	ix, err := NewIndex([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path      string
		line, col int
		has       bool
	}{
		{"bind_addr", 1, 12, true}, // written, with an empty value
		{"port", 2, 7, true},       // written, with a zero value
		{"edge", 3, 1, true},
		{"edge.acme_email", 4, 14, true}, // written, with no value at all
		{"edge.base_domains", 5, 3, true},
		{"edge.base_domains[0]", 6, 7, true},
		{"edge.base_domains[1].domain", 7, 15, true},
		{"edge.base_domains[1].dns01", 8, 14, true},
		{"users[0].role", 10, 21, true},
		{"labels.example.com/team", 12, 21, true},
		{"labels.a.b", 13, 8, true},
		{"empty", 14, 1, true},
		{"none", 15, 1, true},
		{"use.own", 20, 8, true},
		{"use.shared", 17, 11, true},
		{"ref.shared", 17, 11, true},
		{"dots.a", 23, 6, true},
		{"dots.a.b", 24, 8, true}, // the longer key, not a's child b
		{"stod.a.b", 26, 8, true}, // in either order
		{"stod.a", 27, 6, true},
		{"", 1, 1, true},
		// Not in the file: the nearest parent's position.
		{"edge.mode", 3, 1, false},
		{"edge.base_domains[2]", 5, 3, false},
		{"edge.base_domains[1].zzz", 7, 7, false},
		{"edge.base_domains[x]", 5, 3, false},
		{"edge.base_domains[", 5, 3, false},
		{"port.sub", 2, 7, false},
		{"port[0]", 2, 7, false},
		{"nothing.at.all", 1, 1, false},
		{"bind_addrx", 1, 1, false},
		{"bind", 1, 1, false},
	}
	for _, c := range cases {
		pos, ok := ix.Pos(c.path)
		if pos.Line != c.line || pos.Col != c.col || ok != c.has || ix.Has(c.path) != c.has {
			t.Errorf("%q: got %d:%d %v (Has %v), want %d:%d %v", c.path, pos.Line, pos.Col, ok, ix.Has(c.path), c.line, c.col, c.has)
		}
	}

	if _, err := NewIndex([]byte("a: 1\n b: 2\n")); err == nil {
		t.Error("NewIndex accepts a file that is not YAML")
	}
	for _, raw := range []string{"", "# c\n"} {
		ix, err := NewIndex([]byte(raw))
		if err != nil || ix.Has("a") || ix.Has("") {
			t.Errorf("an empty file: %v", err)
		}
		if pos, ok := ix.Pos("a"); ok || pos != (Pos{}) {
			t.Errorf("an empty file: %v", pos)
		}
	}
	var nilIx *Index
	if nilIx.Has("a") {
		t.Error("a nil index has a key")
	}
	if pos, ok := nilIx.Pos("a"); ok || pos != (Pos{}) {
		t.Error("a nil index has a position")
	}
	// The BOM takes no column.
	ix, _ = NewIndex([]byte("\xef\xbb\xbfport: 1\n"))
	if pos, _ := ix.Pos("port"); pos != (Pos{1, 7}) {
		t.Errorf("after a BOM: %v", pos)
	}
}

func TestSemantic(t *testing.T) {
	const secret = "hunter2-SECRET"
	raw := "bind_addr: 0.0.0.0\nport: 70000\nencryption_key: " + secret + "\nedge:\n  base_domains:\n    - domain: bad_domain\nlabels:\n  color: #fff\n"
	cause := errors.New("config invalid")
	o := Options{File: "config.yaml", RedactValues: true, Schema: tType}
	d := Explain([]byte(raw), tType, nil, o)
	if len(d.Problems) != 0 {
		t.Fatalf("problems before validation: %+v", d.Problems)
	}
	d.Semantic([]byte(raw), []Problem{
		{Path: "edge.acme_email", Msg: "edge.acme_email is required"},
		{Path: "encryption_key", Msg: "encryption_key must be 32 bytes", Hint: "run mooring gen-key"},
		{Path: "port", Msg: "port must be below 65536"},
		{Path: "edge.base_domains[0].domain", Msg: "not a hostname"},
		{Path: "labels.color", Msg: "labels.color is empty"},
		{Path: "encryption_key.sub", Msg: "odd"},
		{Msg: "something\nwith no path\x07"},
		{Pos: Pos{Line: 1, Col: 2}, Path: "port", Msg: "placed by the caller"},
	}, cause, o)
	type row struct {
		line, col              int
		path, msg, hint, excpt string
	}
	want := []row{
		{1, 2, "port", "placed by the caller", "", "bind_addr: …"},
		{2, 7, "port", "port must be below 65536", "", "port: …"},
		{3, 17, "encryption_key", "encryption_key must be 32 bytes", "run mooring gen-key", "encryption_key: …"},
		// Not in the file: its parent's line.
		{3, 17, "encryption_key.sub", "odd", "", "encryption_key: …"},
		{4, 1, "edge.acme_email", "edge.acme_email is required", "", "edge:"},
		{6, 15, "edge.base_domains[0].domain", "not a hostname", "", "    - domain: …"},
		{8, 9, "labels.color", "labels.color is empty", `everything after " #" is a comment; put the value in quotes if the # is part of it`, "  color: …"},
		{0, 0, "", "something with no path", "", ""},
	}
	if len(d.Problems) != len(want) {
		t.Fatalf("%d problems: %+v", len(d.Problems), d.Problems)
	}
	for i, w := range want {
		p := d.Problems[i]
		if p.Line != w.line || p.Col != w.col || p.Path != w.path || p.Msg != w.msg || p.Hint != w.hint || p.Excerpt != w.excpt || p.Kind != KindSemantic {
			t.Errorf("problem %d: got %+v\nwant %+v", i, p, w)
		}
	}
	if d.Cause != cause || !errors.Is(d, cause) {
		t.Error("the cause is not set")
	}
	if out := d.Terminal() + d.Error() + string(d.JSON()); strings.Contains(out, secret) || strings.Contains(out, "70000") || strings.Contains(out, "bad_domain") || strings.Contains(out, "0.0.0.0") {
		t.Errorf("a value is shown: %s", out)
	}
	d.Semantic([]byte(raw), nil, errors.New("other"), o)
	if d.Cause != cause {
		t.Error("an existing cause is replaced")
	}

	// A file that does not parse: the problems are kept, without positions.
	d = &Diagnostics{File: "m.yaml"}
	d.Semantic([]byte("a: 1\n b: 2\n"), []Problem{{Path: "a", Msg: "bad a"}}, cause, Options{})
	if len(d.Problems) != 1 || d.Problems[0].Line != 0 || d.Error() != "m.yaml: bad a" {
		t.Errorf("unparsable: %+v %q", d.Problems, d.Error())
	}

	// The limit holds across calls and sorts with what Explain found.
	d = explainT(t, "zzz: 1\nport: 1\n", Options{})
	var many []Problem
	for i := 0; i < MaxProblems+4; i++ {
		many = append(many, Problem{Path: "port", Msg: fmt.Sprintf("p%d", i)})
	}
	d.Semantic([]byte("zzz: 1\nport: 1\n"), many, nil, Options{})
	if len(d.Problems) != MaxProblems || d.More != 5 || d.Problems[0].Kind != KindUnknownKey || d.Problems[1].Msg != "p0" {
		t.Errorf("%d problems, %d more, first %+v", len(d.Problems), d.More, d.Problems[0])
	}
}

func TestSuggest(t *testing.T) {
	keys := []string{"edge", "bind_addr", "ip_allowlist", "image_scan_enabled", "port", "post", "users", "l4"}
	cases := []struct{ key, want string }{
		{"edgee", "edge"},
		{"egde", "edge"},
		{"Edge", "edge"},
		{"EDGE", "edge"},
		{"bind_adr", "bind_addr"},
		{"bindaddr", "bind_addr"},
		{"ip_allowlists", "ip_allowlist"},
		{"image_scan_enable", "image_scan_enabled"},
		{"imagescanenabled", "image_scan_enabled"}, // 2 edits
		{"img_scan_enabld", "image_scan_enabled"},  // 3 edits; a third of 15 letters is 5
		{"image_scanning_on", ""},                  // 7 edits; a third of 17 letters is 5
		{"pot", "port"},                            // port and post tie: the first candidate wins
		{"pord", "port"},
		{"user", "users"},
		{"l5", "l4"},
		{"x9", ""}, // 2 edits would change every letter
		{"zzzzzz", ""},
		{"", ""},
		{strings.Repeat("a", 65), ""},
	}
	for _, c := range cases {
		if got := Suggest(c.key, keys); got != c.want {
			t.Errorf("Suggest(%q) = %q, want %q", c.key, got, c.want)
		}
	}
	if Suggest("edge", nil) != "" || Suggest("edge", []string{""}) != "" {
		t.Error("a suggestion from nothing")
	}
	if got := Suggest("pot", []string{"post", "port"}); got != "post" {
		t.Errorf("ties go to the first candidate: %q", got)
	}
	if got := Suggest("pot", []string{"post", "pot2", "Pot"}); got != "Pot" {
		t.Errorf("a closer candidate wins over an earlier one: %q", got)
	}
}

// FuzzExplain: arbitrary bytes never panic, the result is never nil, Error() is one line with no
// control characters, a file the strict decode accepts gets no problem, and the work is bounded.
func FuzzExplain(f *testing.F) {
	for _, seed := range []string{
		"", "a: 1\n b: 2\n", "edge:\n\tmode: x\n", "edgee: 1\nport: \"1\"\nimage_scan_enabled: 'no'\n", "a: \"x\nb: \"y\"\n",
		"a: [1, {b: 'c\n", "a: |\n  x: y: z\nb:c\n", "a: &a [*a]\n", "? [a]\n: b\n", "\xef\xbb\xbf- a\n  -b:\r\n", "a: \x00\xff\n",
		"healthcheck:\n  nope: 1\n", "<<: {port: x}\nedge: {<<: [1]}\n", "labels:\n  a.b: {c: d}\nextra: !!binary x\n", "port: 1\n---\n\tx\n",
		"region: [a]\nworkers: -1\nratio: .inf\nedge: {timeout: 5, base_domains: {a: b}}\n",
		"# c\u2028port: x\rbind_addr: [a]\u0085edge:\u2029  mode:x\r\n", "edge:\n  mode managed\n  acme_email:|\n    t\n  - name:v\n",
		"port: !!int abc\nedge: !foo x\n0123456789abcdef0123456789abcdef: 1\n", "bind_addr: \"a\" # c\nip_allowlist:\n  - 'it''s' #c\n  - {a: b}\n",
		"labels:\n  " + strings.Repeat("é", 150) + ": [x]\n",
		"a: &a {<<: [*a, *a], zz: 1}\nedge:\n  <<: *a\nlabels: *a\n", "extra: &x\n  mode: [1]\n  zz: 1\nedge:\n  mode: m\n  <<: [*x, {yy: 1}]\n",
		"extra: &p [a, {b: c}]\nedge:\n  base_domains: *p\n  <<: *p\n", "---\n---\nport: x\n", "%\nport: 1\n", "# c\n---\n# d\n",
	} {
		f.Add([]byte(seed), false)
	}
	f.Fuzz(func(t *testing.T, raw []byte, redact bool) {
		start := time.Now()
		var c tConfig
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		cause := dec.Decode(&c)
		o := Options{File: "f.yaml", RedactValues: redact}
		d := Explain(raw, tType, cause, o)
		if d == nil {
			t.Fatal("Explain returned nil")
		}
		if cause == nil && len(d.Problems) != 0 {
			t.Fatalf("the decoder accepts the file, Explain reports %+v", d.Problems)
		}
		check := func(when string) {
			line := d.Error()
			if line == "" {
				t.Fatalf("%s: Error() is empty", when)
			}
			for _, r := range line {
				if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
					t.Fatalf("%s: Error() contains %U: %q", when, r, line)
				}
			}
			for _, r := range d.Terminal() {
				if (unicode.IsControl(r) && r != '\n') || unicode.Is(unicode.Cf, r) {
					t.Fatalf("%s: Terminal() contains %U", when, r)
				}
			}
			if !json.Valid(d.JSON()) {
				t.Fatalf("%s: JSON() is not JSON", when)
			}
			if len(d.Problems) > MaxProblems {
				t.Fatalf("%s: %d problems", when, len(d.Problems))
			}
			for _, p := range d.Problems {
				if len(p.Excerpt) > MaxExcerpt || p.Line < 0 || p.Col < 0 {
					t.Fatalf("%s: problem %+v", when, p)
				}
			}
		}
		check("Explain")
		for _, p := range d.Problems {
			if p.Msg == "" {
				t.Fatalf("a problem with no message: %+v", p)
			}
		}
		d.Semantic(raw, []Problem{{Path: "edge.base_domains[0].domain", Msg: "bad"}, {Path: string(raw), Msg: string(raw)}}, cause, o)
		check("Semantic")
		if ix, err := NewIndex(raw); err == nil {
			ix.Pos(string(raw))
			ix.Has("edge.base_domains[0].domain")
		}
		Suggest(string(raw), []string{"edge", string(raw)})
		if took := time.Since(start); took > 10*time.Second {
			t.Fatalf("took %v for %d bytes", took, len(raw))
		}
	})
}
