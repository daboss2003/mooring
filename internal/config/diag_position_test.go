package config

import (
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/yamldiag"
)

// Where a refusal is placed when the mistake is reached through a merge (<<), through an alias, or
// sits next to a document marker or a directive.

// refusalAt is the first problem of the refusal of y, with the refusal's one-line and terminal forms.
func refusalAt(t *testing.T, y string) (yamldiag.Problem, string, string, *yamldiag.Diagnostics) {
	t.Helper()
	d := diagnosticsOf(t, y)
	if len(d.Problems) == 0 {
		t.Fatalf("no problem: %s", d.Error())
	}
	return d.Problems[0], d.Error(), d.Terminal(), d
}

const mergeHint = "the merge copies every key of the block it refers to; write the keys this block needs instead"

// A merge that brings a key into a block that does not have it is reported at the "<<", for the
// block that merges: the anchor's own key is valid where it is written.
func TestMergeIsReportedAtTheMerge(t *testing.T) {
	if !yamldiagReady() {
		t.Skip("internal/yamldiag is not implemented yet")
	}
	base := validYAML(t, "")
	p, line, term, d := refusalAt(t, base+"session: &s\n  idle_timeout: 10m\nretention:\n  <<: *s\n  interval: 6h\n")
	if len(d.Problems) != 1 || p.Pos != (yamldiag.Pos{Line: 16, Col: 3}) || p.Kind != yamldiag.KindUnknownKey || p.Path != "retention" ||
		p.Msg != `unknown key "idle_timeout" merged into retention` || p.Hint != mergeHint || p.Excerpt != "  <<: …" {
		t.Errorf("a merge under retention: %+v", d.Problems)
	}
	if want := `config.yaml:16:3: unknown key "idle_timeout" merged into retention (hint: ` + mergeHint + `)`; line != want {
		t.Errorf("Error():\n got %s\nwant %s", line, want)
	}
	if want := "config.yaml:16:3: unknown key \"idle_timeout\" merged into retention\n  15 | retention:\n  16 |   <<: …\n     |   ^\n   hint: " + mergeHint + "\n"; term != want {
		t.Errorf("Terminal():\n got %s\nwant %s", term, want)
	}

	// A merged key that is not a key of config.yaml is not named, and neither is the anchor.
	p, line, term, d = refusalAt(t, base+"github: &ZQXanchor\n  client_id: a\n  ZQXkey: ZQXvalue\nretention:\n  <<: *ZQXanchor\n")
	if strings.Contains(line+term+string(d.JSON()), "ZQX") {
		t.Errorf("a merge shows the file:\n%s\n%s", term, d.JSON())
	}
	var merged []yamldiag.Problem
	for _, q := range d.Problems {
		if q.Line == 17 {
			merged = append(merged, q)
		}
	}
	// github's own unknown key is reported where it is written (line 15), the two keys the merge
	// brings into retention at the merge.
	if len(d.Problems) != 3 || p.Line != 15 || len(merged) != 2 || merged[0].Msg != `unknown key "client_id" merged into retention` ||
		merged[1].Msg != "unknown key merged into retention" || merged[1].Path != "retention" || merged[1].Excerpt != "  <<: …" {
		t.Errorf("an unnamed merged key: %+v", d.Problems)
	}

	// A key the block writes itself wins over the merged one, and a merged key of the right block
	// is no problem: only the mistyped value is reported, at the merge, under the merging block.
	p, _, _, d = refusalAt(t, base+"session: &s\n  idle_timeout: 10m\n  absolute_timeout: 1h\nsnippet: &r\n  events_max_rows: many\nretention:\n  <<: *r\n  interval: 6h\n")
	var atMerge []yamldiag.Problem
	for _, q := range d.Problems {
		if q.Line == 19 {
			atMerge = append(atMerge, q)
		}
	}
	if len(atMerge) != 1 || atMerge[0].Pos != (yamldiag.Pos{Line: 19, Col: 3}) || atMerge[0].Path != "retention.events_max_rows" ||
		atMerge[0].Msg != "retention.events_max_rows must be a number" || atMerge[0].Excerpt != "  <<: …" {
		t.Errorf("a mistyped merged value: %+v", d.Problems)
	}
	for _, q := range d.Problems {
		if q.Line == 17 || strings.HasPrefix(q.Path, "snippet.") {
			t.Errorf("the anchor's line is blamed: %+v", q)
		}
	}
	_ = p
}

// A problem inside an aliased mapping or list is reported at the alias: the anchor's lines are
// valid where they are written.
func TestAliasedBlockIsReportedAtTheAlias(t *testing.T) {
	if !yamldiagReady() {
		t.Skip("internal/yamldiag is not implemented yet")
	}
	base := validYAML(t, "")
	p, line, term, d := refusalAt(t, base+"github: &g\n  client_id: a\nbackups:\n  s3: *g\n")
	if len(d.Problems) != 1 || p.Pos != (yamldiag.Pos{Line: 16, Col: 7}) || p.Kind != yamldiag.KindUnknownKey || p.Path != "backups.s3.client_id" ||
		p.Msg != `unknown key "client_id" in backups.s3` || p.Hint != "client_id belongs under github:" || p.Excerpt != "  s3: …" {
		t.Errorf("an aliased mapping: %+v", d.Problems)
	}
	if want := `config.yaml:16:7: unknown key "client_id" in backups.s3 (hint: client_id belongs under github:)`; line != want {
		t.Errorf("Error():\n got %s\nwant %s", line, want)
	}
	if want := "config.yaml:16:7: unknown key \"client_id\" in backups.s3\n  15 | backups:\n  16 |   s3: …\n     |       ^\n   hint: client_id belongs under github:\n"; term != want {
		t.Errorf("Terminal():\n got %s\nwant %s", term, want)
	}

	p, line, term, d = refusalAt(t, base+"protected_projects: &p [a, b]\nusers: *p\n")
	const msg = `users[0] must be a mapping (indented "key: value" lines), found text`
	if len(d.Problems) != 2 || p.Pos != (yamldiag.Pos{Line: 14, Col: 8}) || p.Kind != yamldiag.KindType || p.Path != "users[0]" || p.Msg != msg ||
		p.Excerpt != "users: …" || d.Problems[1].Pos != p.Pos || d.Problems[1].Path != "users[1]" {
		t.Errorf("an aliased list: %+v", d.Problems)
	}
	if want := "config.yaml:14:8: " + msg + "; 1 more problem"; line != want {
		t.Errorf("Error():\n got %s\nwant %s", line, want)
	}
	if !strings.HasPrefix(term, "config.yaml:14:8: "+msg+"\n  13 | protected_projects: …\n  14 | users: …\n     |        ^\n") {
		t.Errorf("Terminal():\n%s", term)
	}

	// A key that may not be named is not said to be "on this line": it is in the block the line
	// refers to.
	p, line, _, d = refusalAt(t, base+"github: &ZQXg\n  ZQXkey: ZQXvalue\nbackups:\n  s3: *ZQXg\n")
	var atAlias []yamldiag.Problem
	for _, q := range d.Problems {
		if q.Line == 16 {
			atAlias = append(atAlias, q)
		}
	}
	if len(d.Problems) != 2 || p.Line != 14 || len(atAlias) != 1 || atAlias[0].Col != 7 || atAlias[0].Path != "backups.s3.…" ||
		atAlias[0].Msg != "unknown key in backups.s3, in the block this line refers to" || atAlias[0].Excerpt != "  s3: …" {
		t.Errorf("an unnamed key behind an alias: %+v", d.Problems)
	}
	if strings.Contains(line+d.Terminal()+string(d.JSON()), "ZQX") {
		t.Errorf("an alias shows the file:\n%s", d.Terminal())
	}
}

// Document markers and directives: the line is kept, stays inside the file, and a file whose
// settings are in a second document is told that only the first is read.
func TestPositionsAroundDocumentMarkers(t *testing.T) {
	if !yamldiagReady() {
		t.Skip("internal/yamldiag is not implemented yet")
	}
	base := validYAML(t, "")

	p, line, term, _ := refusalAt(t, "%\n"+base)
	if p.Pos != (yamldiag.Pos{Line: 1}) || p.Kind != yamldiag.KindSyntax || p.Msg != "could not find expected directive name" || p.Excerpt != "…" {
		t.Errorf("a directive on line 1: %+v", p)
	}
	if line != "config.yaml:1: could not find expected directive name" || term != "config.yaml:1: could not find expected directive name\n  1 | …\n" {
		t.Errorf("a directive on line 1:\n%s\n%s", line, term)
	}

	p, line, term, _ = refusalAt(t, "# only\n---\n# c\n")
	if p.Pos != (yamldiag.Pos{Line: 3}) || p.Path != "encryption_key" || p.Msg != "encryption_key: empty" || p.Hint != "" || p.Excerpt != "…" {
		t.Errorf("an empty document: %+v", p)
	}
	if !strings.HasPrefix(line, "config.yaml:3: encryption_key: empty; ") || !strings.HasPrefix(term, "config.yaml:3: encryption_key: empty\n  2 | …\n  3 | …\n") {
		t.Errorf("an empty document:\n%s\n%s", line, term)
	}

	const hint = `only the first document of the file is read; it ends at the "---" on line 2`
	p, line, term, d := refusalAt(t, "---\n---\n"+base)
	if p.Pos != (yamldiag.Pos{Line: 2, Col: 1}) || p.Path != "encryption_key" || p.Msg != "encryption_key: empty" || p.Hint != hint || p.Excerpt != "…" {
		t.Errorf("settings in the second document: %+v", p)
	}
	if want := "config.yaml:2:1: encryption_key: empty (hint: " + hint + "); 5 more problems"; line != want {
		t.Errorf("Error():\n got %s\nwant %s", line, want)
	}
	if !strings.HasPrefix(term, "config.yaml:2:1: encryption_key: empty\n  1 | …\n  2 | …\n    | ^\n   hint: "+hint+"\n") {
		t.Errorf("Terminal():\n%s", term)
	}
	for _, q := range d.Problems {
		if q.Hint != hint {
			t.Errorf("every problem about a key the first document lacks carries the hint: %+v", q)
		}
	}
	// One document: no such hint, whatever the file lacks.
	if p, _, _, _ := refusalAt(t, "---\n"+strings.Replace(base, "encryption_key:", "#encryption_key:", 1)); strings.Contains(p.Hint, "document") {
		t.Errorf("one document: %+v", p)
	}
}

// The merge and alias paths with a secret as the anchored value, as a merged or aliased key and as
// the anchor's name: no form of the refusal shows it.
func TestMergeAndAliasRefusalsNeverShowSecrets(t *testing.T) {
	if !yamldiagReady() {
		t.Skip("internal/yamldiag is not implemented yet")
	}
	base := validYAML(t, "")
	for name, ov := range map[string]string{
		"merge, anchored value":        "github: &g\n  client_secret: ZQXvalue\nretention:\n  <<: *g\n",
		"merge, mistyped value":        "github: &g\n  client_secret: ZQXvalue\nbackups:\n  <<: *g\n  s3: *g\n",
		"merge, a secret as the key":   "github: &g\n  ZQXkey: x\nretention:\n  <<: *g\n",
		"merge, the anchor's name":     "session: &ZQXanchor\n  idle_timeout: 10m\nretention:\n  <<: *ZQXanchor\n",
		"merge of a list":              "github: &ZQXa\n  ZQXkey: ZQXvalue\nsession: &ZQXb\n  idle_timeout: 1h\nretention:\n  <<: [*ZQXa, *ZQXb]\n",
		"merge in place":               "retention:\n  <<: {ZQXkey: ZQXvalue, client_secret: ZQXvalue2}\n",
		"merge of a secret":            "encryption_key_previous: &ZQXa ZQXvalue\nretention:\n  <<: *ZQXa\n",
		"merge at the top level":       "github: &ZQXa\n  client_secret: ZQXvalue\n<<: *ZQXa\n",
		"alias, anchored mapping":      "github: &ZQXa\n  client_secret: ZQXvalue\n  ZQXkey: ZQXvalue\nbackups:\n  s3: *ZQXa\n",
		"alias, anchored list":         "protected_projects: &ZQXa [ZQXvalue, ZQXvalue2]\nusers: *ZQXa\n",
		"alias, anchored secret":       "encryption_key_previous: &ZQXa ZQXvalue\ntrust_proxy: *ZQXa\nretention:\n  interval: *ZQXa\n  events_max_rows: *ZQXa\n",
		"alias, a duration in a block": "github: &ZQXa\n  interval: ZQXvalue\n  ZQXkey: ZQXvalue\nretention: *ZQXa\n",
		"alias in a list":              "github: &ZQXa\n  client_secret: ZQXvalue\nusers:\n  - *ZQXa\n",
	} {
		d := mustNotShow(t, name, base+ov)
		if d == nil {
			continue
		}
		if len(d.Problems) == 0 {
			t.Errorf("%s: not explained: %s", name, d.Error())
		}
		for _, p := range d.Problems {
			if strings.Contains(p.Msg+p.Hint+p.Path+p.Excerpt, "ZQX") {
				t.Errorf("%s: %+v", name, p)
			}
		}
	}
}
