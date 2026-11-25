package yamldiag

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Where a problem is placed when it is reached through a merge (<<) or an alias, and around
// document markers and directives.

const tMergeHint = "the merge copies every key of the block it refers to; write the keys this block needs instead"

type placed struct {
	line, col               int
	kind, path, msg, excerp string
}

func placedOf(d *Diagnostics) []placed {
	var out []placed
	for _, p := range d.Problems {
		out = append(out, placed{p.Line, p.Col, p.Kind, p.Path, p.Msg, p.Excerpt})
	}
	return out
}

func checkPlaced(t *testing.T, name string, d *Diagnostics, want []placed) {
	t.Helper()
	if got := placedOf(d); !reflect.DeepEqual(got, want) {
		t.Errorf("%s:\n got %+v\nwant %+v\n%s", name, got, want, d.Terminal())
	}
}

// What a merge brings into a block is reported at the "<<" with the block's path; the anchor's
// lines are another key's and may be right where they are written.
func TestMergedKeysAreReportedAtTheMerge(t *testing.T) {
	red := Options{File: "config.yaml", RedactValues: true}
	// "mode" is a key of the schema, "bogus" is not; "extra" takes anything.
	raw := "extra: &x\n  mode: m\n  bogus: 1\nlabels:\n  <<: *x\nedge:\n  <<: *x\n  acme_email: a\nregion: [r]\n"
	checkPlaced(t, "an unknown merged key", explainT(t, raw, Options{}), []placed{
		{7, 3, KindUnknownKey, "edge", `unknown key "bogus" merged into edge`, "  <<: *x"},
		{9, 1, KindType, "region", "region must be a single value, found a list", "region: [r]"},
	})
	d := explainT(t, raw, red)
	checkPlaced(t, "an unknown merged key, redacted", d, []placed{
		{7, 3, KindUnknownKey, "edge", "unknown key merged into edge", "  <<: …"},
		{9, 1, KindType, "region", "region must be a single value, found a list", "region: …"},
	})
	if d.Problems[0].Hint != tMergeHint {
		t.Errorf("hint: %q", d.Problems[0].Hint)
	}

	// A schema key merged into a block that does not have it is named under redaction too.
	d = explainT(t, "edge: &e\n  mode: m\n<<: *e\n", red)
	checkPlaced(t, "a schema key merged where it is unknown", d, []placed{
		{3, 1, KindUnknownKey, "", `unknown key "mode" merged into the top level of the file`, "<<: …"},
	})
	if want := `config.yaml:3:1: unknown key "mode" merged into the top level of the file (hint: ` + tMergeHint + `)`; d.Error() != want {
		t.Errorf("Error() = %s", d.Error())
	}

	// A mistyped merged value: the usual message with the key's path, at the merge.
	checkPlaced(t, "a mistyped merged value", explainT(t, "extra: &x\n  mode: [1]\n  timeout: soon\nedge:\n  acme_email: a\n  <<: *x\n", red), []placed{
		{6, 3, KindType, "edge.mode", "edge.mode must be a single value, found a list", "  <<: …"},
		{6, 3, KindType, "edge.timeout", "edge.timeout must be a duration like 30s or 5m", "  <<: …"},
	})

	// A list of anchors, a merge inside a merged block, a merge in a list entry and at the top level.
	checkPlaced(t, "a list of anchors", explainT(t, "extra:\n  a: &a {zzz: 1}\n  b: &b {acme_email: [2], yyy: 1}\nedge:\n  <<: [*a, *b]\n", Options{}), []placed{
		{5, 3, KindUnknownKey, "edge", `unknown key "zzz" merged into edge`, "  <<: [*a, *b]"},
		{5, 3, KindType, "edge.acme_email", "edge.acme_email must be a single value, found a list", "  <<: [*a, *b]"},
		{5, 3, KindUnknownKey, "edge", `unknown key "yyy" merged into edge`, "  <<: [*a, *b]"},
	})
	checkPlaced(t, "a merge inside the merged block", explainT(t, "extra: &a\n  nope: 1\n  <<: &b\n    deep: 1\n    mode: [x]\nedge:\n  <<: *a\n", Options{}), []placed{
		{7, 3, KindUnknownKey, "edge", `unknown key "nope" merged into edge`, "  <<: *a"},
		{7, 3, KindUnknownKey, "edge", `unknown key "deep" merged into edge`, "  <<: *a"},
		{7, 3, KindType, "edge.mode", "edge.mode must be a single value, found a list", "  <<: *a"},
	})
	checkPlaced(t, "a merge in a list entry", explainT(t, "extra: &d {zz: 1}\nedge:\n  base_domains:\n    - domain: ok\n      <<: *d\n", Options{}), []placed{
		{5, 7, KindUnknownKey, "edge.base_domains[0]", `unknown key "zz" merged into edge.base_domains[0]`, "      <<: *d"},
	})
	checkPlaced(t, "a block merged at the top level", explainT(t, "extra: &s {port: x, edge: {nope: 1}}\n<<: *s\n", red), []placed{
		{2, 1, KindType, "port", "port must be a number", "<<: …"},
		{2, 1, KindUnknownKey, "edge.…", "unknown key in edge, in the block this line refers to", "<<: …"},
	})

	// A mapping written in place is reported where it is written: its lines are the block's own.
	checkPlaced(t, "a mapping merged in place", explainT(t, "edge:\n  <<: {mode: m, nope: 1}\n", Options{}), []placed{
		{2, 17, KindUnknownKey, "edge.nope", `unknown key "nope" in edge`, "  <<: {mode: m, nope: 1}"},
	})

	// A merge of something that is not a mapping: the decoder's complaint has no line.
	for _, raw := range []string{"edge:\n  <<: 5\n", "extra: &s [1]\nedge:\n  <<: *s\n", "extra: &s {mode: m}\nedge:\n  <<: [*s, x]\n"} {
		d := explainT(t, raw, red)
		p := d.Problems[len(d.Problems)-1]
		if len(d.Problems) != 1 || p.Line != strings.Count(raw, "\n") || p.Col != 3 || p.Kind != KindType || p.Path != "edge" ||
			p.Msg != "a merge (<<) takes a mapping or a list of mappings" || p.Excerpt != "  <<: …" {
			t.Errorf("%q: %+v", raw, d.Problems)
		}
	}
}

// The walk merges as the decoder does: a key the block writes itself wins over a merged one, an
// earlier anchor of a list over a later one, and two "<<" merge nothing. None of these may add a
// problem the decoder does not have.
func TestMergeFollowsTheDecoder(t *testing.T) {
	for name, raw := range map[string]string{
		"the block's own key wins":        "extra: &a {mode: [1]}\nedge:\n  mode: mine\n  <<: *a\nport: x\n",
		"own key written after":           "extra: &a {mode: [1]}\nedge:\n  <<: *a\n  mode: mine\nport: x\n",
		"the first anchor of a list wins": "extra:\n  ok: &ok {mode: m}\n  bad: &bad {mode: [1]}\nedge:\n  <<: [*ok, *bad]\nport: x\n",
		"the outer block over the inner":  "extra: &a\n  mode: m\n  <<: {mode: [1]}\nedge:\n  <<: *a\nport: x\n",
		"into a map":                      "extra: &a {k: v}\nlabels:\n  <<: *a\nport: x\n",
	} {
		for _, o := range []Options{{}, {RedactValues: true}} {
			d := explainT(t, raw, o)
			if len(d.Problems) != 1 || d.Problems[0].Path != "port" {
				t.Errorf("%s: %+v", name, d.Problems)
			}
		}
	}
	// A merge's problem carries the path of the block that merges; it does not stand for the
	// block's other keys, so a self-decoding type's own complaint below it is kept.
	d := explainT(t, "extra: &e {zz: 1}\n<<: *e\nhealthcheck:\n  nope: 1\n", Options{})
	checkPlaced(t, "a merge and another complaint", d, []placed{
		{2, 1, KindUnknownKey, "", `unknown key "zz" merged into the top level of the file`, "<<: *e"},
		{4, 3, KindSemantic, "healthcheck.nope", `unknown healthcheck key "nope"`, "  nope: 1"},
	})
	// Two merges in one block are the decoder's duplicate key, on the second one's own line.
	d = explainT(t, "extra: &a {nope: 1}\nedge:\n  <<: *a\n  <<: *a\n", Options{RedactValues: true})
	checkPlaced(t, "two merges", d, []placed{{4, 3, KindDuplicate, "edge.…", "a key is written twice in this block (first on line 3)", "  <<: …"}})
}

// A problem inside an aliased mapping or list is placed at the alias, like one in an aliased value.
func TestAliasedBlocksAreReportedAtTheAlias(t *testing.T) {
	red := Options{File: "config.yaml", RedactValues: true}
	raw := "extra: &d\n  domain: [1]\n  zz: 1\nedge:\n  base_domains:\n    - *d\n"
	checkPlaced(t, "an aliased mapping", explainT(t, raw, Options{}), []placed{
		{6, 7, KindType, "edge.base_domains[0].domain", "edge.base_domains[0].domain must be a single value, found a list", "    - *d"},
		{6, 7, KindUnknownKey, "edge.base_domains[0].zz", `unknown key "zz" in edge.base_domains[0]`, "    - *d"},
	})
	checkPlaced(t, "an aliased mapping, redacted", explainT(t, raw, red), []placed{
		{6, 7, KindType, "edge.base_domains[0].domain", "edge.base_domains[0].domain must be a single value, found a list", "    - …"},
		{6, 7, KindUnknownKey, "edge.base_domains[0].…", "unknown key in edge.base_domains[0], in the block this line refers to", "    - …"},
	})
	checkPlaced(t, "an aliased list", explainT(t, "ip_allowlist: &p [a, b]\nedge:\n  base_domains: *p\n", red), []placed{
		{3, 17, KindType, "edge.base_domains[0]", `edge.base_domains[0] must be a mapping (indented "key: value" lines), found text`, "  base_domains: …"},
		{3, 17, KindType, "edge.base_domains[1]", `edge.base_domains[1] must be a mapping (indented "key: value" lines), found text`, "  base_domains: …"},
	})
	// An alias inside the aliased block: still the alias the file writes under the key.
	checkPlaced(t, "an alias behind an alias", explainT(t, "extra:\n  inner: &i [x]\n  outer: &o\n    mode: *i\nedge: *o\n", red), []placed{
		{5, 7, KindType, "edge.mode", "edge.mode must be a single value, found a list", "edge: …"},
	})
	// A merge inside the aliased block: the place is the alias, not the anchor's "<<" line.
	checkPlaced(t, "a merge behind an alias", explainT(t, "extra:\n  o: &o {zz: 1}\n  x: &x\n    <<: *o\nedge: *x\n", red), []placed{
		{5, 7, KindUnknownKey, "edge", "unknown key merged into edge", "edge: …"},
	})
	// A map of anything: the key cannot be named, the place still is the alias.
	checkPlaced(t, "an aliased map", explainT(t, "extra: &m {k: [1]}\nlabels: *m\n", red), []placed{
		{2, 9, KindType, "labels.…", "labels.… must be a single value, found a list", "labels: …"},
	})
	// A self-decoding type behind the alias keeps the alias's place too.
	checkPlaced(t, "a self-decoding type", explainT(t, "extra: &h {nope: 1}\nhealthcheck: *h\n", red), []placed{
		{2, 14, KindSemantic, "healthcheck", `unknown healthcheck key "…"`, "healthcheck: …"},
	})
	// A key written twice in the anchored block is the anchor's own mistake: it stays on its lines.
	d := explainT(t, "extra: &a\n  x: 1\n  x: 2\nlabels: *a\n", Options{})
	if len(d.Problems) != 1 || d.Problems[0].Pos != (Pos{3, 3}) || d.Problems[0].Kind != KindDuplicate || d.Problems[0].Path != "extra.x" {
		t.Errorf("a duplicate in an anchored block: %+v", d.Problems)
	}
}

// The merge and alias paths never show the file: the secret as the anchored value, as a merged or
// aliased key that is not a key of the schema, and as the anchor's name.
func TestMergeAndAliasNeverShowTheFile(t *testing.T) {
	templates := map[string]string{
		"merge":                "extra: &@A@\n  mode: @V@\n  @K@: @V@\nedge:\n  <<: *@A@\n",
		"merge, mistyped":      "extra: &@A@\n  mode: [@V@]\n  timeout: @V@\n  @K@: [@V@]\nedge:\n  <<: *@A@\n",
		"merge at the top":     "extra: &@A@ {port: @V@, @K@: @V@, edge: {@K@: @V@}}\n<<: *@A@\n",
		"merge of a list":      "extra:\n  a: &@A@ {@K@: @V@}\n  b: &@A@2 {port: @V@}\n<<: [*@A@, *@A@2]\n",
		"merge in place":       "edge:\n  <<: {mode: m, @K@: @V@}\n",
		"merge in a merge":     "extra: &@A@\n  <<: &@A@2 {@K@: @V@, mode: [@V@]}\nedge:\n  <<: *@A@\n",
		"merge of a scalar":    "extra: &@A@ @V@\nedge:\n  <<: *@A@\n",
		"merge into a map":     "extra: &@A@ {@K@: [@V@]}\nlabels:\n  <<: *@A@\n",
		"merge, twice":         "extra: &@A@ {@K@: @V@}\nedge:\n  <<: *@A@\n  <<: *@A@\n",
		"alias of a mapping":   "extra: &@A@\n  mode: [@V@]\n  @K@: @V@\nedge: *@A@\n",
		"alias of a list":      "extra: &@A@ [@V@, {@K@: @V@}]\nedge:\n  base_domains: *@A@\n",
		"alias in a list":      "extra: &@A@ {@K@: @V@, domain: [@V@]}\nedge:\n  base_domains:\n    - *@A@\n",
		"alias of a scalar":    "encryption_key: &@A@ @V@\nport: *@A@\nimage_scan_enabled: *@A@\n",
		"alias of a map":       "extra: &@A@ {@K@: [@V@]}\nlabels: *@A@\n",
		"alias, self-decoding": "extra: &@A@ {@K@: @V@}\nhealthcheck: *@A@\n",
		"alias, key twice":     "extra: &@A@ {@K@: @V@, @K@: @V@}\nlabels: *@A@\n",
		"alias behind alias":   "extra:\n  i: &@A@2 [@V@]\n  o: &@A@\n    mode: *@A@2\n    @K@: *@A@2\nedge: *@A@\n",
	}
	const sV, sK, sA = "ZQXvalueZQX", "ZQXkeyZQX", "ZQXanchorZQX"
	fill := func(tmpl, v, k, a string) string {
		return strings.NewReplacer("@V@", v, "@K@", k, "@A@", a).Replace(tmpl)
	}
	explained := 0
	for name, tmpl := range templates {
		raw := fill(tmpl, sV, sK, sA)
		var c tConfig
		cause := strict(raw, &c)
		if cause == nil {
			t.Fatalf("%s: accepted; the case tests nothing", name)
		}
		for form, d := range map[string]*Diagnostics{
			"Explain":          Explain([]byte(raw), tType, cause, Options{File: "config.yaml", RedactValues: true}),
			"Explain, no type": Explain([]byte(raw), nil, cause, Options{File: "config.yaml", RedactValues: true}),
		} {
			explained += len(d.Problems)
			if out := keyForms(d); strings.Contains(out, "ZQX") {
				t.Errorf("%s, %s: the file is shown:\n%s", name, form, out)
			}
		}
		// Without RedactValues the line is shown as written, and nothing else is: a message, a hint
		// and a path never hold the anchor's name or a value met through an alias or a merge.
		d := Explain([]byte(raw), tType, cause, Options{File: "mooring.yaml"})
		for _, p := range d.Problems {
			if said := p.Msg + "\n" + p.Hint + "\n" + p.Path; strings.Contains(said, sA) {
				t.Errorf("%s: the anchor's name is in a message: %+v", name, p)
			}
		}
		// The typed secrets of TestSecretTypedAsAKeyIsNeverShown as the merged or aliased key.
		for _, k := range typedSecrets {
			raw := fill(tmpl, "v", k, "anchor")
			var c tConfig
			if cause := strict(raw, &c); cause != nil {
				d := Explain([]byte(raw), tType, cause, Options{File: "config.yaml", RedactValues: true})
				if out := keyForms(d); showsKey(out, k) {
					t.Errorf("%s: %q is shown:\n%s", name, k, out)
				}
			}
		}
	}
	if explained < 2*len(templates) {
		t.Errorf("%d problems for %d files: the cases are not explained", explained, 2*len(templates))
	}
}

// Merges that refer to themselves, and fan out, end: the walk's budget covers what a merge visits.
func TestMergeBombIsBounded(t *testing.T) {
	bomb := "a: &a {<<: [*a, *a, *a], zz: 1}\nedge:\n  <<: [*a, *a]\n"
	chain := "x0: &x0 {zz: 1}\n"
	for i := 1; i < 40; i++ {
		chain += "x" + string(rune('0'+i/10)) + string(rune('0'+i%10)) + ": &x" + string(rune('0'+i/10)) + string(rune('0'+i%10)) +
			" {<<: [*x" + string(rune('0'+(i-1)/10)) + string(rune('0'+(i-1)%10)) + ", *x" + string(rune('0'+(i-1)/10)) + string(rune('0'+(i-1)%10)) + "]}\n"
	}
	chain = strings.ReplaceAll(chain, "x00", "x0") + "edge:\n  <<: *x39\n"
	for name, raw := range map[string]string{"a merge of itself": bomb, "a chain that doubles": chain} {
		for _, target := range []reflect.Type{tType, nil} {
			start := time.Now()
			d := Explain([]byte(raw), target, errors.New("refused"), Options{File: "f.yaml", RedactValues: true})
			if took := time.Since(start); took > 5*time.Second || d == nil || len(d.Problems) > MaxProblems {
				t.Errorf("%s: took %v, %d problems", name, took, len(d.Problems))
			}
		}
	}
}

// A parser complaint about the first line keeps its line; a position past the end of the file is
// brought back into it; and a file with a second document is told that only the first is read.
func TestDocumentMarkersAndDirectives(t *testing.T) {
	d := explainT(t, "%\nport: 1\n", Options{})
	checkPlaced(t, "a directive on line 1", d, []placed{{1, 0, KindSyntax, "", "could not find expected directive name", "%"}})
	if d.Error() != "f.yaml:1: could not find expected directive name" {
		t.Errorf("Error() = %s", d.Error())
	}
	// A file the parser itself could not read has no position to give.
	if p, _, _ := translate(errors.New("yaml: the file could not be parsed"), newSource([]byte("a\nb\n")), true); p.Line != 1 {
		t.Errorf("an untranslated message with no line is placed on line %d", p.Line)
	}

	o := Options{File: "config.yaml", RedactValues: true, Schema: tType}
	semantic := func(raw string) *Diagnostics {
		d := &Diagnostics{}
		d.Semantic([]byte(raw), []Problem{{Path: "encryption_key", Msg: "encryption_key: empty"}, {Path: "port", Msg: "port is refused", Hint: "the caller's"},
			{Msg: "no path"}}, errors.New("refused"), o)
		return d
	}
	// The parser places an empty document after the last line.
	d = semantic("# only\n---\n# c\n")
	if p := d.Problems[0]; p.Pos != (Pos{Line: 3}) || p.Excerpt != "…" || p.Hint != "" || d.Problems[1].Pos != (Pos{Line: 3}) || d.Problems[2].Line != 0 {
		t.Errorf("an empty document: %+v", d.Problems)
	}
	if !strings.HasPrefix(d.Terminal(), "config.yaml:3: encryption_key: empty\n  2 | …\n  3 | …\n\n") {
		t.Errorf("an empty document:\n%s", d.Terminal())
	}
	// Settings in the second document.
	const hint = `only the first document of the file is read; it ends at the "---" on line 2`
	d = semantic("---\n---\nport: 1\nencryption_key: x\n")
	if p := d.Problems[0]; p.Pos != (Pos{2, 1}) || p.Hint != hint || d.Problems[1].Hint != "the caller's" || d.Problems[2].Hint != "" {
		t.Errorf("a second document: %+v", d.Problems)
	}
	// A key the first document has keeps its own place and gets no such hint.
	d = semantic("encryption_key: x\n---\nport: 1\n")
	if p := d.Problems[1]; p.Path != "encryption_key" || p.Pos != (Pos{1, 17}) || p.Hint != "" || d.Problems[0].Pos != (Pos{1, 1}) {
		t.Errorf("a key of the first document: %+v", d.Problems)
	}
	// The first document is not a mapping.
	d = explainT(t, "hello\n...\nport: 1\n", Options{RedactValues: true})
	if p := d.Problems[0]; len(d.Problems) != 1 || p.Pos != (Pos{1, 1}) ||
		p.Hint != `only the first document of the file is read; it ends at the "..." on line 2` {
		t.Errorf("a scalar first document: %+v", d.Problems)
	}

	for raw, want := range map[string]int{
		"":                                   0,
		"port: 1\n":                          0,
		"---\nport: 1\n":                     0,
		"# c\n---\nport: 1\n":                0,
		"%YAML 1.2\n---\nport: 1\n":          0,
		"---\nport: 1\n---\n":                0, // a marker with nothing after it
		"port: 1\n...\n":                     0,
		"port: 1\n---\n# only a comment\n\n": 0,
		"port: 1\n...\n%YAML 1.2\n---\n":     0,
		"port: 1\n  ---\n  b: 1\n":           0, // indented: text, not a marker
		"port: 1\n---x\n":                    0,
		"a: |\n  ---\n  text\n":              0,
		"---\n---\nport: 1\n":                2,
		"port: 1\n---\nport: 2\n":            2,
		"port: 1\n--- port\n":                2,
		"port: 1\n---\n---\nx: 1\n":          2,
		"port: 1\n...\n---\nport: 2\n":       2,
		"# c\n\n--- \nport: 1\n...\n\nx\n":   5,
		"\xef\xbb\xbf---\na: 1\n---\nb: 1\n": 3,
		"--- a\n---\r\nb\r\n":                2,
		"port: 1\n---\n%YAML 1.2\n---\nx\n":  2,
	} {
		got := newSource([]byte(raw)).laterDocument()
		if want == 0 && got != "" || want > 0 && !strings.HasSuffix(got, " on line "+string(rune('0'+want))) {
			t.Errorf("%q: %q, want line %d", raw, got, want)
		}
	}
	var none *source
	if none.laterDocument() != "" {
		t.Error("a nil source has a later document")
	}
}
