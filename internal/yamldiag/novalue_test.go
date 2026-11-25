package yamldiag

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// Tests of the v0.34.0 re-audit fixes: the decoder's text over every yaml.v3 error format, a
// complaint placed by line AND column, complaints reached through an alias, an empty file.

// tDur decodes itself and reports its position the way config.Duration does.
type tDur time.Duration

const tDurMsg = "not a valid duration"

func (d *tDur) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d, column %d: %s", n.Line, n.Column, tDurMsg)
	}
	*d = tDur(v)
	return nil
}

type tTimes struct {
	Key     string `yaml:"encryption_key"`
	Proxy   bool   `yaml:"trust_proxy"`
	Rows    int    `yaml:"rows"`
	Session struct {
		Idle     tDur `yaml:"idle_timeout"`
		Absolute tDur `yaml:"absolute_timeout"`
	} `yaml:"session"`
	Retention struct {
		Interval tDur `yaml:"interval"`
		Rows     int  `yaml:"events_max_rows"`
	} `yaml:"retention"`
	Edge struct {
		CatchAll bool `yaml:"catch_all"`
	} `yaml:"edge"`
}

func explainTimes(t *testing.T, raw string) *Diagnostics {
	t.Helper()
	var v tTimes
	cause := strict(raw, &v)
	if cause == nil {
		t.Fatalf("the strict decode accepts %q; the case tests nothing", raw)
	}
	return Explain([]byte(raw), reflect.TypeOf(v), cause, Options{File: "config.yaml", RedactValues: true})
}

// Two values on one line: the complaint of a type that decodes itself is placed by its column, so
// it names the key it is about and not the first key on the line.
func TestCauseLineUsesTheColumn(t *testing.T) {
	for _, c := range []struct {
		raw, path string
		line, col int
	}{
		{"session: {idle_timeout: 10m, absolute_timeout: bogus}\n", "session.absolute_timeout", 1, 48},
		{"retention: {events_max_rows: 5000, interval: bogus}\n", "retention.interval", 1, 46},
		{"session: {idle_timeout: bogus, absolute_timeout: 1h}\n", "session.idle_timeout", 1, 25},
		{"session:\n  idle_timeout: 10m\n  absolute_timeout: bogus\n", "session.absolute_timeout", 3, 21},
		{"retention:\n  interval:\n    bogus\n", "retention.interval", 3, 5},
	} {
		d := explainTimes(t, c.raw)
		if len(d.Problems) != 1 {
			t.Fatalf("%q: problems = %+v", c.raw, d.Problems)
		}
		if p := d.Problems[0]; p.Path != c.path || p.Pos != (Pos{c.line, c.col}) || p.Msg != tDurMsg {
			t.Errorf("%q: got %s at %d:%d %q, want %s at %d:%d", c.raw, p.Path, p.Line, p.Col, p.Msg, c.path, c.line, c.col)
		}
	}
	// A column no node is at falls back to the line; a line-only complaint works as before.
	raw := "rows: 1\nsession:\n  idle_timeout: 10m\n"
	for cause, want := range map[string]Pos{
		"line 3, column 99: odd": {3, 3},
		"line 3: odd":            {3, 3},
		"line 3, column 17: odd": {3, 17},
	} {
		d := Explain([]byte(raw), reflect.TypeOf(tTimes{}), errors.New(cause), Options{File: "f"})
		if len(d.Problems) != 1 || d.Problems[0].Pos != want || d.Problems[0].Msg != "odd" || d.Problems[0].Path != "session.idle_timeout" {
			t.Errorf("%q: %+v, want %v", cause, d.Problems, want)
		}
	}
}

// The decoder reports a value read through an alias at the ANCHOR's line. The complaint is never
// pinned on the key the anchor is written under: it goes to the alias's key, or is dropped when the
// walk already reported it there.
func TestCauseLineThroughAnAlias(t *testing.T) {
	// A duration key aliases the encryption key.
	d := explainTimes(t, "encryption_key: &k "+marker+"\nrows: 1\nretention:\n  interval: *k\n")
	if len(d.Problems) != 1 {
		t.Fatalf("an alias under a duration: %+v", d.Problems)
	}
	if p := d.Problems[0]; p.Path != "retention.interval" || p.Pos != (Pos{4, 13}) || p.Msg != tDurMsg || p.Excerpt != "  interval: …" {
		t.Errorf("an alias under a duration: %+v", p)
	}
	if out := allForms(d); strings.Contains(out, "ZQX") || strings.Contains(out, "encryption_key ") || strings.Contains(out, `"path":"encryption_key"`) {
		t.Errorf("the anchor's key is blamed, or its value shown:\n%s", out)
	}
	// A boolean aliases it: the walk reports the boolean; the decoder's line-1 complaint adds nothing.
	d = explainTimes(t, "encryption_key: &k "+marker+"\ntrust_proxy: *k\n")
	if len(d.Problems) != 1 || d.Problems[0].Path != "trust_proxy" || d.Problems[0].Msg != "trust_proxy must be true or false" || d.Problems[0].Line != 2 {
		t.Errorf("an alias under a boolean: %+v", d.Problems)
	}
	// Two aliases, a number and a nested boolean: one problem each, none for the anchor.
	d = explainTimes(t, "encryption_key: &k "+marker+"\nrows: *k\nedge:\n  catch_all: *k\n")
	if len(d.Problems) != 2 || d.Problems[0].Path != "rows" || d.Problems[1].Path != "edge.catch_all" {
		t.Errorf("two aliases: %+v", d.Problems)
	}
	// An anchored list under a boolean.
	d = explainTimes(t, "encryption_key: &k ["+marker+"]\ntrust_proxy: *k\n")
	for _, p := range d.Problems {
		if p.Path != "encryption_key" && p.Path != "trust_proxy" {
			t.Errorf("an anchored list: %+v", d.Problems)
		}
	}
	if out := allForms(d); strings.Contains(out, "ZQX") || strings.Contains(out, "encryption_key has the wrong type") && len(d.Problems) > 2 {
		t.Errorf("an anchored list:\n%s", out)
	}
	// The anchor is itself the bad duration: it is the anchor's own problem, at the anchor.
	d = explainTimes(t, "session:\n  idle_timeout: &d bogus\n  absolute_timeout: *d\n")
	if len(d.Problems) != 1 || d.Problems[0].Path != "session.idle_timeout" || d.Problems[0].Line != 2 {
		t.Errorf("a bad duration with an anchor: %+v", d.Problems)
	}
	// The same without RedactValues (definition files): same attribution.
	raw := "encryption_key: &k x\nretention:\n  interval: *k\n"
	var v tTimes
	d = Explain([]byte(raw), reflect.TypeOf(v), strict(raw, &v), Options{File: "m.yaml"})
	if len(d.Problems) != 1 || d.Problems[0].Path != "retention.interval" || d.Problems[0].Line != 3 {
		t.Errorf("without RedactValues: %+v", d.Problems)
	}
}

// scrubT is every type the decoder writes an error about.
type scrubT struct {
	A  bool              `yaml:"a"`
	N  int               `yaml:"n"`
	M  map[string]int    `yaml:"m"`
	MI map[int]string    `yaml:"mi"`
	L  []string          `yaml:"l"`
	B  []byte            `yaml:"b"`
	D  time.Duration     `yaml:"d"`
	Tm time.Time         `yaml:"tm"`
	MM map[string]string `yaml:"mm"`
	Ar [2]int            `yaml:"ar"`
	F  float32           `yaml:"f"`
	MK map[[2]int]string `yaml:"mk"`
}

// Every error format of yaml.v3, with the secret where the decoder copies from the file: a value, a
// key, a tag (also written verbatim, and with %-escaped spaces, words and line breaks), an anchor.
// No form of the diagnostics shows it — examined, too large to examine, or printed as the bare
// decoder text.
func TestNoYAMLErrorFormatShowsTheFile(t *testing.T) {
	const S = "ZQXSECRET"
	inputs := map[string]string{
		"unknown field":                 S + ": 1\n",
		"unknown field with spaces":     "\"" + S + " x\": 1\n",
		"unknown field with a newline":  "\"a\\nline 2: " + S + "\": 1\n",
		"field holding the end words":   "\"x not found in type y " + S + "\": 1\n",
		"field holding the whole form":  "\"field q not found in type y " + S + "\": 1\n",
		"field with a backtick":         "\"" + S + "`x\": 1\n",
		"field, end words, backtick":    "\"a not found in type " + S + "`\": 1\n",
		"field then a value":            "zz: 1\na: \"x not found in type " + S + " y\"\n",
		"value then a field":            "a: v\n\"K1`" + S + "\": 1\n",
		"str into bool":                 "a: " + S + "\n",
		"str with a backtick":           "a: \"x`y " + S + " `z\"\n",
		"str with a newline":            "a: \"x\\nline 9: " + S + "\"\n",
		"two type errors":               "a: " + S + "\nn: " + S + "2\n",
		"seq into bool":                 "a: [" + S + "]\n",
		"map into int":                  "n: {" + S + ": 1}\n",
		"dup key":                       "m:\n  " + S + ": 1\n  " + S + ": 2\n",
		"dup key with a quote":          "m:\n  \"" + S + "\\\"q\": 1\n  \"" + S + "\\\"q\": 2\n",
		"dup key with a backslash":      "m:\n  '" + S + "\\': 1\n  '" + S + "\\': 2\n",
		"dup key in single quotes":      "m:\n  'it''s " + S + "': 1\n  'it''s " + S + "': 2\n",
		"dup key holding a field":       "m:\n  \"a: field " + S + "\": 1\n  \"a: field " + S + "\": 2\n",
		"unknown anchor":                "a: *" + S + "\n",
		"anchor of itself":              "l: &" + S + " [*" + S + "]\n",
		"int map key":                   "mi:\n  " + S + ": x\n",
		"invalid map key":               "mk:\n  [" + S + ", 2]: x\n",
		"tag int":                       "n: !!int " + S + "\n",
		"tag float":                     "f: !!float " + S + "\n",
		"tag bool":                      "a: !!bool " + S + "\n",
		"tag binary":                    "b: !!binary " + S + "!\n",
		"tag timestamp":                 "tm: !!timestamp " + S + "\n",
		"custom tag":                    "a: !" + S + " x\n",
		"custom tag, verbatim":          "a: !<tag:" + S + "> x\n",
		"verbatim tag on a list":        "a: !<tag:" + S + "> [x]\n",
		"verbatim tag with a space":     "a: !<tag:x%20" + S + "> x\n",
		"str tag with a space":          "a: !<tag:yaml.org,2002:str%20" + S + "> [x]\n",
		"str tag with the word into":    "a: !<tag:yaml.org,2002:str%20into%20" + S + "> [x]\n",
		"tag with a line break":         "a: !<tag:x%0Aline%202:%20" + S + "> x\n",
		"str tag, into and line break":  "a: !<tag:yaml.org,2002:str%20into%20" + S + "%0A%20%20line%209:%20x> [x]\n",
		"tag with a backtick":           "a: !<tag:x%60" + S + "%60y> x\n",
		"tag handle":                    "a: !" + S + "!x y\n",
		"duration":                      "d: " + S + "\n",
		"time":                          "tm: " + S + "\n",
		"array":                         "ar: [" + S + "]\n",
		"merge":                         "<<: " + S + "\n",
		"merge of a list":               "m:\n  <<: [" + S + "]\n",
		"directive":                     "%" + S + " x\n---\na: true\n",
		"tag directive":                 "%TAG !" + S + "! tag:x\n---\na: true\n",
		"float":                         "f: " + S + "\n",
		"complex key":                   "? [" + S + "]\n: 1\n",
		"str with apostrophes":          "a: it's " + S + " isn't\n",
		"anchor with an apostrophe":     "a: *it's" + S + "\n",
		"tab":                           "a:\n\t" + S + ": 1\n",
		"unclosed quote":                "a: \"" + S + "\n",
		"bad escape":                    "a: \"\\q" + S + "\"\n",
		"alias to a mapping":            "m: &" + S + " {x: 1}\nmm: *" + S + "\n",
		"alias, verbatim tag, boolean":  "l: &k !<tag:" + S + "> [x]\na: *k\n",
		"alias, verbatim tag, a number": "mm: {q: &k !<tag:" + S + "> v}\nn: *k\n",
	}
	pad := strings.Repeat("# pad pad pad pad pad pad pad pad pad pad pad pad\n", MaxInput/40)
	refused, quoting := 0, 0
	for name, in := range inputs {
		for _, big := range []bool{false, true} {
			raw := in
			if big {
				raw += pad
			}
			var v scrubT
			cause := strict(raw, &v)
			if cause == nil {
				if !big {
					t.Logf("%s: accepted by the decoder", name)
				}
				continue
			}
			if !big {
				refused++
				if strings.Contains(cause.Error(), S) {
					quoting++
				}
				if out := scrub(cause.Error()); strings.Contains(out, S) {
					t.Errorf("%s: scrub keeps the secret:\n in %q\nout %q", name, cause.Error(), out)
				}
			}
			bare := &Diagnostics{File: "f"}
			bare.Semantic(nil, nil, cause, Options{RedactValues: true})
			for form, d := range map[string]*Diagnostics{
				"no type":      Explain([]byte(raw), nil, cause, Options{File: "f", RedactValues: true}),
				"with a type":  Explain([]byte(raw), reflect.TypeOf(v), cause, Options{File: "f", RedactValues: true}),
				"decoder text": bare,
			} {
				if out := allForms(d); strings.Contains(out, S) {
					t.Errorf("%s (%s, above MaxInput: %v) shows the secret:\n%.700s\ncause: %.300q", name, form, big, out, cause.Error())
				}
			}
		}
	}
	if refused < 45 || quoting < 30 {
		t.Errorf("%d inputs refused, %d of the decoder's texts quote the secret: the test no longer covers the formats", refused, quoting)
	}
}

// yaml's own list of type errors is read entry by entry under RedactValues: one crafted entry (a
// key or a tag holding a line break and "line N: …") neither becomes a problem of its own nor
// hides the entries after it.
func TestTypeErrorsAreReadEntryByEntry(t *testing.T) {
	type self struct {
		H *tCheck `yaml:"healthcheck"`
		I *tCheck `yaml:"other"`
		A bool    `yaml:"a"`
	}
	// tCheck decodes "test" itself, so the walk says nothing about its type errors, and "test" is not
	// a key the schema's struct tags have: it is not named.
	raw := "a: !<tag:x%0Aline%205:%20" + marker + "> x\nhealthcheck:\n  test: {x: 1}\nother:\n  test: {y: 2}\n"
	var v self
	cause := strict(raw, &v)
	var te *yaml.TypeError
	if !errors.As(cause, &te) || len(te.Errors) != 3 || !strings.Contains(cause.Error(), marker) {
		t.Fatalf("cause = %v; the case needs three type errors, the first one crafted", cause)
	}
	d := Explain([]byte(raw), reflect.TypeOf(v), cause, Options{File: "f", RedactValues: true})
	if out := allForms(d); len(d.Problems) != 3 || strings.Contains(out, "ZQX") {
		t.Fatalf("problems = %+v\n%s", d.Problems, out)
	}
	for i, want := range []struct {
		line int
		path string
	}{{1, "a"}, {3, "healthcheck.…"}, {5, "other.…"}} {
		if p := d.Problems[i]; p.Line != want.line || p.Path != want.path || p.Kind != KindType {
			t.Errorf("problem %d: %+v, want line %d path %s", i, p, want.line, want.path)
		}
	}
	if d.Problems[2].Msg != "other.… has the wrong type (found a mapping)" || d.Problems[2].Excerpt != "  …" {
		t.Errorf("the last entry: %q", d.Problems[2].Msg)
	}
}

// A file with no document (empty, or only blank lines and comments) says so instead of "EOF".
func TestEmptyFile(t *testing.T) {
	big := strings.Repeat("# a comment line that fills the file\n", MaxInput/30)
	if len(big) <= MaxInput {
		t.Fatal("the padding is not above MaxInput")
	}
	for name, raw := range map[string]string{"empty": "", "a comment": "# nothing here\n", "blank lines": "\n\n  \n", "a large comment": big} {
		for _, redact := range []bool{false, true} {
			var v tConfig
			cause := strict(raw, &v)
			if !errors.Is(cause, io.EOF) {
				t.Fatalf("%s: cause = %v; the case tests nothing", name, cause)
			}
			d := Explain([]byte(raw), tType, fmt.Errorf("config: parse: %w", cause), Options{File: "config.yaml", RedactValues: redact})
			if d.Error() != "config.yaml: the file is empty (hint: it has no settings, only blank lines or comments)" {
				t.Errorf("%s: Error() = %q", name, d.Error())
			}
			if len(d.Problems) != 1 || d.Problems[0].Kind != KindSyntax || d.Problems[0].Line != 0 || !errors.Is(d, io.EOF) {
				t.Errorf("%s: %+v", name, d.Problems)
			}
			if strings.Contains(allForms(d), "EOF") {
				t.Errorf("%s: EOF is shown: %s", name, allForms(d))
			}
		}
	}
	// Another cause on an empty input keeps its own text.
	if d := Explain(nil, tType, errors.New("other"), Options{File: "f"}); d.Error() != "f: other" {
		t.Errorf("another cause: %q", d.Error())
	}
}
