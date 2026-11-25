package yamldiag

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Tests of what RedactValues lets through (the v0.34.0 fix rounds). The rule has no exception: no
// value is printed, and a key's name only when it is a key of the schema, spelled as the schema has it.

const marker = "ZQXsecretZQX"

func allForms(d *Diagnostics) string {
	return d.Error() + "\n" + d.Terminal() + "\n" + string(d.JSON())
}

// semanticT is Semantic on a file with one problem per path, RedactValues on.
func semanticT(t *testing.T, raw string, paths ...string) *Diagnostics {
	t.Helper()
	if !parses([]byte(raw)) {
		t.Fatalf("not valid YAML: %q", raw)
	}
	o := Options{File: "config.yaml", RedactValues: true}
	var ps []Problem
	for _, p := range paths {
		ps = append(ps, Problem{Path: p, Msg: p + " is refused"})
	}
	d := &Diagnostics{}
	d.Semantic([]byte(raw), ps, errors.New("refused"), o)
	if len(d.Problems) != len(paths) {
		t.Fatalf("problems = %+v", d.Problems)
	}
	return d
}

// yaml.v3 ends a line at LF, CR, CRLF, U+0085, U+2028 and U+2029, and every position it reports
// counts lines that way. The source must be cut into the same lines, or an excerpt shows the line
// after the one reported.
func TestLinesAreCutAsTheParserCountsThem(t *testing.T) {
	breaks := map[string]string{"LF": "\n", "CR": "\r", "CRLF": "\r\n", "NEL": "\u0085", "LS": " ", "PS": " ", "LF CR": "\n\r"}
	for name, br := range breaks {
		for where, raw := range map[string]string{
			"comment":       "# note" + br + "# more\nalpha: 1\nbeta: 2\n",
			"between":       "alpha: 1" + br + "beta: 2\ngamma: 3\n",
			"double quoted": "alpha: \"x" + br + "  y\"\nbeta: 2\n",
			"block scalar":  "alpha: |\n  x" + br + "  y\nbeta: 2\n",
			"plain scalar":  "alpha: x" + br + "  y\nbeta: 2\n",
			"after comment": "alpha: 1 # c" + br + "\nbeta: 2\n",
			"blank line":    "alpha: 1\n" + br + "beta: 2\n",
			"at the end":    "alpha: 1\nbeta: 2" + br,
			"twice":         br + br + "alpha: 1" + br + br + "beta: 2\n",
		} {
			root, err := parseRoot([]byte(raw))
			if err != nil || root == nil {
				t.Fatalf("%s/%s: %v", name, where, err)
			}
			src := newSource([]byte(raw))
			if want := br != "\n" && br != "\r\n"; src.odd != want && where != "after comment" { // CR + LF there
				t.Errorf("%s/%s: odd = %v", name, where, src.odd)
			}
			for i := 0; i+1 < len(root.Content); i += 2 {
				k := root.Content[i]
				if k.Line < 1 || k.Line > len(src.lines) || !strings.HasPrefix(src.lines[k.Line-1], k.Value+":") {
					t.Errorf("%s/%s: the parser has key %q on line %d; the source's lines are %q", name, where, k.Value, k.Line, src.lines)
				}
			}
			for _, line := range src.lines {
				if strings.ContainsAny(line, "\r\n\u0085  ") {
					t.Errorf("%s/%s: a line holds a line break: %q", name, where, line)
				}
			}
		}
	}
	// through() still cuts the file after whole lines.
	src := newSource([]byte("a: 1 b: 2\r\nc: 3\rd: 4"))
	if got := []string{string(src.through(1)), string(src.through(2)), string(src.through(3)), string(src.through(4))}; !reflect.DeepEqual(got,
		[]string{"a: 1 ", "a: 1 b: 2\r\n", "a: 1 b: 2\r\nc: 3\r", "a: 1 b: 2\r\nc: 3\rd: 4"}) {
		t.Errorf("through: %q", got)
	}
}

// The reviewer's reproduction: a pasted comment that ends in U+2028 (or a lone CR, or U+0085) made
// the excerpt of a problem on the safe line above show the secret line below it.
func TestUnusualLineBreakDoesNotShiftTheExcerpt(t *testing.T) {
	for name, br := range map[string]string{"LS": " \n", "PS": " \n", "NEL": "\u0085\n", "CR": "\r# more\n", "LS inline": " "} {
		for _, at := range []string{"first line", "between"} {
			raw := "# pasted note" + br + "bind_addr: \"0.0.0.0:9000\"\nencryption_key: \"" + marker + "\"\nport: 1\n"
			if at == "between" {
				raw = "port: 1\nbind_addr: \"0.0.0.0:9000\"   # note" + br + "encryption_key: \"" + marker + "\"\n"
			}
			d := semanticT(t, raw, "bind_addr", "port")
			if out := allForms(d); strings.Contains(out, "ZQX") {
				t.Errorf("%s/%s: the secret is shown:\n%s", name, at, out)
			}
			for _, p := range d.Problems {
				if p.Path == "bind_addr" && p.Excerpt != "bind_addr: …" {
					t.Errorf("%s/%s: excerpt %q", name, at, p.Excerpt)
				}
			}
			// The same file, refused by the decoder: an unknown key next to the secret.
			bad := strings.Replace(raw, "port: 1", "prot: 1", 1)
			var c tConfig
			d = Explain([]byte(bad), tType, strict(bad, &c), Options{File: "config.yaml", RedactValues: true})
			if out := allForms(d); len(d.Problems) != 1 || d.Problems[0].Excerpt != "…" || d.Problems[0].Hint != "did you mean port?" || strings.Contains(out, "ZQX") {
				t.Errorf("%s/%s: %+v\n%s", name, at, d.Problems, out)
			}
		}
	}
	// The line scanner does not model those breaks: it says nothing, and the parser's message is used.
	raw := "port: 1  bind_addr: x\n"
	if !newSource([]byte(raw)).odd || newSource([]byte(raw)).scan() != nil {
		t.Error("the scanner judges a file with a U+2028 line break")
	}
	if d := explainT(t, raw, Options{}); len(d.Problems) != 1 || d.Problems[0].Line != 2 {
		t.Errorf("problems = %+v", d.Problems)
	}
}

// Owner decision 2026-11-25: under RedactValues a validation problem never shows the value of its
// key, whatever the key and however plainly the value is written (there was a list of "safe" keys
// before; a secret typed under one of them, an alias to one, a block scalar were printed).
func TestSemanticNeverShowsAValue(t *testing.T) {
	type tc struct {
		name, raw, path, excerpt string
	}
	cases := []tc{
		{"plain", "bind_addr: " + marker + "\n", "bind_addr", "bind_addr: …"},
		{"double quoted", "bind_addr: \"" + marker + "\"\n", "bind_addr", "bind_addr: …"},
		{"single quoted", "bind_addr: 'it''s " + marker + "'\n", "bind_addr", "bind_addr: …"},
		{"nested", "edge:\n  mode: " + marker + "\n", "edge.mode", "  mode: …"},
		{"in a list entry", "edge:\n  base_domains:\n    - domain: " + marker + "\n", "edge.base_domains[0].domain", "    - domain: …"},
		{"second key of a list entry", "edge:\n  base_domains:\n    - mode: m\n      domain: " + marker + "\n", "edge.base_domains[0].domain", "      domain: …"},
		{"list item", "ip_allowlist:\n  - 10.0.0.1\n  - " + marker + "\n", "ip_allowlist[1]", "  - …"},
		{"extra spaces", "bind_addr:    " + marker + "   \n", "bind_addr", "bind_addr: …"},
		{"empty quoted", "bind_addr: \"\"\n", "bind_addr", "bind_addr: …"},
		{"a number", "port: 70000\n", "port", "port: …"},
		{"a boolean", "image_scan_enabled: true\n", "image_scan_enabled", "image_scan_enabled: …"},
		{"a key with no value", "edge:\n  mode:\n", "edge.mode", "  mode:"},
		{"a mapping", "labels:\n  a: " + marker + "\n", "labels", "labels:"},
		{"comment", "bind_addr: 0.0.0.0 # old key " + marker + "\n", "bind_addr", "bind_addr: …"},
		{"comment, no value", "edge:\n  mode: # " + marker + "\n", "edge.mode", "  mode: …"},
		{"flow mapping", "edge: {mode: bogus, acme_email: " + marker + "}\n", "edge.mode", "edge: …"},
		{"flow mapping, key first", "edge:\n  base_domains:\n    - {domain: BAD, mode: " + marker + "}\n", "edge.base_domains[0].domain", "    - …"},
		{"root flow mapping", "{bind_addr: \"0.0.0.0:1\", encryption_key: " + marker + "}\n", "bind_addr", "…"},
		{"flow list", "ip_allowlist: [nope, " + marker + "]\n", "ip_allowlist[0]", "ip_allowlist: …"},
		{"flow on the next line", "edge:\n  {mode: bogus,\n   acme_email: " + marker + "}\n", "edge.mode", "  …"},
		{"tag", "bind_addr: !!str " + marker + "\n", "bind_addr", "bind_addr: …"},
		{"anchor", "bind_addr: &a " + marker + "\n", "bind_addr", "bind_addr: …"},
		{"alias", "encryption_key: &k " + marker + "\nbind_addr: *k\n", "bind_addr", "bind_addr: …"},
		{"value on the next line", "bind_addr:\n  " + marker + "\n", "bind_addr", "  …"},
		{"two lines", "bind_addr: 0.0\n  " + marker + "\n", "bind_addr", "bind_addr: …"},
		{"block scalar", "bind_addr: |\n  " + marker + "\n", "bind_addr", "bind_addr: …"},
		{"folded scalar", "bind_addr: >-\n  " + marker + "\n", "bind_addr", "bind_addr: …"},
		{"quoted key", "\"bind_addr\": " + marker + "\n", "bind_addr", "…"},
		{"merged from an anchor", "extra: &b\n  mode: " + marker + "\nedge:\n  <<: *b\n", "edge.mode", "  mode: …"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := semanticT(t, c.raw, c.path)
			p := d.Problems[0]
			if p.Excerpt != c.excerpt {
				t.Errorf("excerpt %q, want %q (%d:%d)", p.Excerpt, c.excerpt, p.Line, p.Col)
			}
			if out := allForms(d); strings.Contains(out, "ZQX") || strings.Contains(out, "70000") {
				t.Errorf("the value is shown:\n%s", out)
			}
		})
	}
}

// In a file that parses, a "word:" stays in an excerpt only where the parser read a key: a line of
// a block scalar or of a multi-line value that looks like "key: value" is part of a value.
func TestOnlyParsedKeysStayInAnExcerpt(t *testing.T) {
	raw := "encryption_key: |\n  password: " + marker + "\n  hunter: two\nport: 70000\nbind_addr: \"a\n  token: b\"\nworkers: 1\n"
	o := Options{File: "config.yaml", RedactValues: true, Schema: tType}
	d := &Diagnostics{}
	d.Semantic([]byte(raw), []Problem{
		{Pos: Pos{Line: 2, Col: 3}, Msg: "placed on a line of the block scalar"},
		{Path: "port", Msg: "port is refused"},
		{Path: "workers", Msg: "workers is refused"},
	}, errors.New("refused"), o)
	if len(d.Problems) != 3 || d.Problems[0].Excerpt != "  …" || d.Problems[1].Excerpt != "port: …" || d.Problems[2].Excerpt != "workers: …" {
		t.Fatalf("problems = %+v", d.Problems)
	}
	out := d.Terminal()
	// The lines before: line 1 (a key), line 3 (block scalar text) and line 6 (the quoted value's second line).
	for _, want := range []string{"  1 | encryption_key: …\n  2 |   …\n", "  3 |   …\n  4 | port: …\n", "  6 |   …\n  7 | workers: …\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q in:\n%s", want, out)
		}
	}
	if all := allForms(d); strings.Contains(all, "ZQX") || strings.Contains(all, "password") || strings.Contains(all, "hunter") || strings.Contains(all, "token") {
		t.Errorf("a word of a value is shown:\n%s", all)
	}
	// The same through Explain (an unknown key after the block scalar).
	bad := "encryption_key: |\n  password: " + marker + "\nprot: 1\n"
	e := explainT(t, bad, Options{RedactValues: true})
	if out := e.Terminal(); len(e.Problems) != 1 || !strings.Contains(out, "  2 |   …\n  3 | …\n") || strings.Contains(out, "password") || strings.Contains(out, "prot") {
		t.Errorf("Explain:\n%s", out)
	}
}

// With RedactValues a value that was found is never quoted in a message (owner decision): a secret
// pasted under trust_proxy: must not be printed. Without it the messages keep the value.
func TestMessagesNeverQuoteAFoundValue(t *testing.T) {
	for _, c := range []struct{ raw, msg, plain string }{
		{"image_scan_enabled: " + marker + "\n", "image_scan_enabled must be true or false", `image_scan_enabled must be true or false (found "` + marker + `")`},
		{"image_scan_enabled: \"true\"\n", "image_scan_enabled must be true or false without quotes", `image_scan_enabled must be true or false without quotes (found "true")`},
		{"port: " + marker + "\n", "port must be a number", `port must be a number (found "` + marker + `")`},
		{"port: \"8080\"\n", "port must be a number without quotes", `port must be a number without quotes (found "8080")`},
		{"workers: -1\n", "workers must not be negative", "workers must not be negative (found -1)"},
		{"workers: 300\n", "workers is out of range", "workers is out of range (found 300)"},
		{"ratio: " + marker + "\n", "ratio must be a number", `ratio must be a number (found "` + marker + `")`},
		{"edge:\n  timeout: " + marker + "\n", "edge.timeout must be a duration like 30s or 5m", `edge.timeout must be a duration like 30s or 5m (found "` + marker + `")`},
	} {
		d := explainT(t, c.raw, Options{RedactValues: true})
		if len(d.Problems) != 1 || d.Problems[0].Msg != c.msg || !strings.HasSuffix(d.Problems[0].Excerpt, ": …") {
			t.Errorf("%q: %+v", c.raw, d.Problems)
		}
		if out := allForms(d); strings.Contains(out, "ZQX") || strings.Contains(out, "8080") || strings.Contains(out, "300") {
			t.Errorf("%q: the value is shown:\n%s", c.raw, out)
		}
		if d := explainT(t, c.raw, Options{}); len(d.Problems) != 1 || d.Problems[0].Msg != c.plain {
			t.Errorf("%q without RedactValues: %+v", c.raw, d.Problems)
		}
	}
}

// typedSecrets are secrets typed where a key belongs, in the shapes a key name has too: a short
// lowercase word, lowercase with digits, snake_case words, lowercase hex of 16 to 40 characters.
var typedSecrets = []string{
	"hunter", "hunter2", "tr0ub4dor3", "zz", "s3cr3t", "correct_horse_battery", "my_db_pass_2024", "dns01x",
	"deadbeefcafe0123", "deadbeefcafe0123deadbeef", "deadbeefcafe0123deadbeefcafe0123deadbeef", "dead_beef_cafe_0123_dead_beef",
}

// nearMisses are keys one character (or one case, or one "-") away from a key of tConfig, with the
// key each is taken for. None is a substring of the schema's key.
var nearMisses = map[string]string{
	"bind_adr": "bind_addr", "bind_addrs": "bind_addr", "Bind_Addr": "bind_addr", "bind-addr": "bind_addr", "bnd_addr": "bind_addr",
	"edgee": "edge", "prot": "port", "workerz": "workers", "encryption_kez": "encryption_key", "ip_allowlists": "ip_allowlist",
}

// Under RedactValues a key's name is printed only when it is a key of the schema, spelled as the
// schema spells it. Whatever else is written where a key belongs is never echoed: it may be a secret
// (a password on a line of its own before a colon, a key and its value swapped), and a short
// lowercase secret looks exactly like a key. A key close to a schema key gets that key as a hint.
func TestKeyNamesUnderRedaction(t *testing.T) {
	w := &walker{root: tType, o: Options{RedactValues: true}, infos: map[reflect.Type]*structInfo{}}
	for k, want := range map[string]bool{
		"edge": true, "bind_addr": true, "mode": true, "acme_email": true, "base_domains": true, "domain": true, "dns01": true,
		"region": true, "labels": true, "encryption_key": true, "extra": true, "healthcheck": true,
		"test": false, // a key of a type that decodes itself: not read from struct tags
		"":     false, "Edge": false, "BIND_ADDR": false, "edge ": false, "edge.mode": false, "s3": false, "a": false,
		"zzzz_qqqq": false, "example.com": false, "x-forwarded-for": false, "two words": false, "77077": false, "5m": false,
		"JBSWY3DPEHPK3PXP": false, "AKI" + "AIOSFODNN7EXAMPLQ": false, "0123456789abcdef0123456789abcdef": false,
		strings.Repeat("a", 41): false, strings.Repeat("a_", 20): false,
	} {
		if got := w.named(k); got != want {
			t.Errorf("named(%q) = %v, want %v", k, got, want)
		}
	}
	for _, k := range typedSecrets {
		if w.named(k) {
			t.Errorf("named(%q): a secret typed as a key is named", k)
		}
	}
	for k := range nearMisses {
		if w.named(k) {
			t.Errorf("named(%q): a key that is only close to a schema key is named", k)
		}
	}
	if (&walker{o: Options{RedactValues: true}, infos: map[reflect.Type]*structInfo{}}).named("edge") {
		t.Error("with no schema a key is named")
	}

	secretKey := "0123456789abcdef0123456789abcdef"
	o := Options{RedactValues: true}
	type row struct{ msg, path, excerpt, hint string }
	for _, c := range []struct {
		name, raw string
		want      row
	}{
		// A key of the schema, spelled right, is named wherever it is written.
		{"a schema key in the wrong block", "mode: x\n", row{`unknown key "mode"`, "mode", "mode: …", ""}},
		{"a schema key in the wrong block, one owner", "acme_email: x\n", row{`unknown key "acme_email"`, "acme_email", "acme_email: …", "acme_email belongs under edge:"}},
		{"a schema key under a block", "edge:\n  port: 1\n", row{`unknown key "port" in edge`, "edge.port", "  port: …", "port belongs at the top level of the file"}},
		{"a schema key written twice", "port: 1\nport: 2\n", row{`key "port" is written twice in this block (first on line 1)`, "port", "port: …", "keep one of the two"}},
		{"a schema key as a map key", "labels:\n  port: [x]\n", row{"labels.port must be a single value, found a list", "labels.port", "  port: …", ""}},
		// One close to a schema key is not: the hint names the schema's key, nothing typed is shown.
		{"a word", "edgee: 1\n", row{"unknown key on this line", "…", "…", "did you mean edge?"}},
		{"a schema key in capitals", "Bind_Addr: 1\n", row{"unknown key on this line", "…", "…", "did you mean bind_addr?"}},
		{"a schema key with a dash", "edge:\n  acme-email: x\n", row{"unknown key on this line in edge", "edge.…", "  …", "did you mean acme_email?"}},
		{"a key missing a letter", "bind_adr: x\n", row{"unknown key on this line", "…", "…", "did you mean bind_addr?"}},
		{"a nested key's name in capitals at the top", "ACME_EMAIL: x\n", row{"unknown key on this line", "…", "…", "did you mean acme_email? acme_email belongs under edge:"}},
		{"a nested key's name mistyped at the top", "base_domain: x\n", row{"unknown key on this line", "…", "…", "did you mean base_domains? base_domains belongs under edge:"}},
		{"a key of two blocks mistyped at the top", "modee: x\n", row{"unknown key on this line", "…", "…", "did you mean mode?"}},
		// Anything else.
		{"a word nothing is close to", "zzzz_qqqq: 1\n", row{"unknown key on this line", "…", "…", ""}},
		{"a short lowercase secret", "hunter2: x\n", row{"unknown key on this line", "…", "…", ""}},
		{"a short lowercase secret in a block", "edge:\n  hunter2: x\n", row{"unknown key on this line in edge", "edge.…", "  …", "keys allowed here: mode, acme_email, timeout, base_domains"}},
		{"snake_case words", "correct_horse_battery: x\n", row{"unknown key on this line", "…", "…", ""}},
		{"a short lowercase secret as a map key", "labels:\n  hunter2: [x]\n", row{"labels.… must be a single value, found a list", "labels.…", "  …", ""}},
		{"a short lowercase secret under a map key", "labels:\n  hunter2:\n    tr0ub4dor3: x\n", row{"labels.… must be a single value, found a mapping", "labels.…", "  …", ""}},
		{"a TOTP secret as a key", "JBSWY3DPEHPK3PXP: 1\n", row{"unknown key on this line", "…", "…", ""}},
		{"an access key id as a key", "edge:\n  AKI" + "AIOSFODNN7EXAMPLQ: 1\n", row{"unknown key on this line in edge", "edge.…", "  …", "keys allowed here: mode, acme_email, timeout, base_domains"}},
		{"a 24-character token as a key", "ghp_abcdefghij0123456789: 1\n", row{"unknown key on this line", "…", "…", ""}},
		{"a 40-character key as a key", "wJalrXUtn" + "FEMIxK7MDENGzbPxRfiCYEXAMPLEKEY: 1\n", row{"unknown key on this line", "…", "…", ""}},
		{"a capitalised word nothing is close to", "Tr0ub4dor: 1\n", row{"unknown key on this line", "…", "…", ""}},
		{"a secret as a key", secretKey + ": 1\n", row{"unknown key on this line", "…", "…", ""}},
		{"a secret as a nested key", "edge:\n  " + secretKey + ": 1\n", row{"unknown key on this line in edge", "edge.…", "  …", "keys allowed here: mode, acme_email, timeout, base_domains"}},
		{"a sentence as a key", "my password is " + marker + ": 1\n", row{"unknown key on this line", "…", "…", ""}},
		{"a quoted key", "\"" + marker + " x\": 1\n", row{"unknown key on this line", "…", "…", ""}},
		{"a long key", strings.Repeat("k", 41) + ": 1\n", row{"unknown key on this line", "…", "…", ""}},
		{"a secret written twice", "port: 1\n" + secretKey + ": 1\n" + secretKey + ": 2\n", row{"unknown key on this line", "…", "…", ""}},
		{"a short secret written twice", "port: 1\nhunter2: 1\nhunter2: 2\n", row{"unknown key on this line", "…", "…", ""}},
		{"a secret as a map key", "labels:\n  " + secretKey + ": [x]\n", row{"labels.… must be a single value, found a list", "labels.…", "  …", ""}},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := explainT(t, c.raw, o)
			p := d.Problems[0]
			if got := (row{p.Msg, p.Path, p.Excerpt, p.Hint}); got != c.want {
				t.Errorf("got  %+v\nwant %+v", got, c.want)
			}
			out := allForms(d)
			for _, bad := range []string{"ZQX", secretKey, "kkkk", "JBSWY", "AKIA", "ghp_", "wJalr", "Tr0ub", "hunter", "tr0ub", "horse", "zzzz", "edgee",
				"Bind_", "acme-", "bind_adr", "ACME", "modee", `base_domain"`, "base_domain:"} {
				if strings.Contains(out, bad) {
					t.Errorf("the key is shown (%q):\n%s", bad, out)
				}
			}
		})
	}
	for _, c := range []struct{ raw, dup string }{
		{"port: 1\n" + secretKey + ": 1\n" + secretKey + ": 2\n", "a key is written twice in this block (first on line 2)"},
		{"port: 1\nhunter2: 1\nhunter2: 2\n", "a key is written twice in this block (first on line 2)"},
		{"port: 1\nbind_adr: 1\nbind_adr: 2\n", "a key is written twice in this block (first on line 2)"},
	} {
		d := explainT(t, c.raw, o)
		if len(d.Problems) != 2 || d.Problems[1].Msg != c.dup || d.Problems[1].Kind != KindDuplicate || d.Problems[1].Path != "…" || d.Problems[1].Excerpt != "…" {
			t.Errorf("%q: %+v", c.raw, d.Problems)
		}
	}
	// Without RedactValues the name is shown as before.
	for k, hint := range map[string]string{secretKey: "", "hunter2": "", "Bind_Addr": "did you mean bind_addr?", "ACME_EMAIL": "", "edgee": "did you mean edge?"} {
		if p := explainT(t, k+": 1\n", Options{}).Problems[0]; p.Msg != `unknown key "`+k+`"` || p.Path != k || p.Excerpt != k+": 1" || p.Hint != hint {
			t.Errorf("without RedactValues: %+v", p)
		}
	}

	// The masked line before the problem follows the same rule, and a "word:rest" there is part of a
	// value (a URL's user:password), not a key.
	raw := "encryption_key:\n    " + marker + "user:" + marker + "pass\nedgee: 1\n"
	d := explainT(t, raw, o)
	if out := allForms(d); len(d.Problems) != 1 || strings.Contains(out, "ZQX") || !strings.Contains(d.Terminal(), "  2 |     …\n  3 | …\n") {
		t.Errorf("a continuation line shaped word:rest:\n%s", out)
	}
	// The glued form stays where it IS the problem reported, for a key of the schema.
	d = explainT(t, "edge:\n  mode:"+marker+"\n  acme_email: y\n", o)
	if p := d.Problems[0]; p.Msg != gluedMsg || p.Excerpt != "  mode:…" || p.Hint != `put a space between "mode:" and its value` || strings.Contains(allForms(d), "ZQX") {
		t.Errorf("a glued colon: %+v", p)
	}
	// Any other word before a glued ':' is not named: capitals, a typo, a secret of any shape.
	for _, k := range append([]string{secretKey, "JBSWY3DPEHPK3PXP", "AKI" + "AIOSFODNN7EXAMPLQ", "Mode", "modee"}, typedSecrets...) {
		d = explainT(t, "edge:\n  "+k+":x\n  acme_email: y\n", o)
		if p := d.Problems[0]; p.Msg != gluedMsg || p.Excerpt != "  …" || p.Hint != "put a space after the ':'" || strings.Contains(allForms(d), k+":") {
			t.Errorf("a glued colon after %s: %+v", k, p)
		}
	}
}

// keyForms is every form a refusal is printed in, with each problem's own fields.
func keyForms(d *Diagnostics) string {
	out := allForms(d)
	for _, p := range d.Problems {
		out += "\n" + p.Msg + "\n" + p.Hint + "\n" + p.Excerpt + "\n" + p.Path + "\n" + p.prev
	}
	return out
}

// showsKey reports whether out holds key as a word of its own (not as part of a longer name).
func showsKey(out, key string) bool {
	for rest := out; ; {
		i := strings.Index(rest, key)
		if i < 0 {
			return false
		}
		before, after := byte(' '), byte(' ')
		if i > 0 {
			before = rest[i-1]
		}
		if i+len(key) < len(rest) {
			after = rest[i+len(key)]
		}
		word := func(c byte) bool {
			return c == '_' || c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		}
		if !word(before) && !word(after) {
			return true
		}
		rest = rest[i+1:]
	}
}

// A secret typed where a key belongs is in no form of the refusal, wherever in the file it is: the
// problem's own line, the line before it, a file that does not parse, a validation problem's lines.
func TestSecretTypedAsAKeyIsNeverShown(t *testing.T) {
	o := Options{File: "config.yaml", RedactValues: true}
	places := map[string]string{
		"at the top":                 "port: 1\n@K@: x\n",
		"alone on a line":            "port: 1\n@K@:\nbind_addr: x\n",
		"in a block":                 "edge:\n  @K@: x\n",
		"in a list entry":            "edge:\n  base_domains:\n    - @K@: x\n",
		"second key of a list entry": "edge:\n  base_domains:\n    - domain: d\n      @K@: x\n",
		"as a map key":               "labels:\n  @K@: [x]\n",
		"under a map key":            "labels:\n  a:\n    @K@: x\n",
		"written twice":              "@K@: 1\n@K@: 2\n",
		"swapped with its value":     "@K@: encryption_key\n",
		"the line before a problem":  "labels:\n  @K@: x\nport: nope\n",
		"flow mapping":               "edge: {@K@: x}\n",
		"glued":                      "edge:\n  @K@:x\n  mode: y\n",
		"glued, the line before":     "labels:\n  @K@: x\nedge:\n  mode:x\n",
		"before a tab":               "labels:\n  @K@: x\n\tport: 1\n",
		"before a bad indent":        "labels:\n  @K@: x\n   port: 1\n",
		"on the bad indent":          "edge:\n  mode: m\n   @K@: x\n",
		"unclosed quote":             "@K@: \"x\nport: 1\n",
		"colon in the value":         "@K@: a: b\n",
		"under a self-decoding type": "healthcheck:\n  @K@: x\n",
		"quoted":                     "\"@K@\": x\n",
		"with a tag":                 "!!str @K@: x\n",
		"complex key":                "? @K@\n: x\n",
	}
	keys := append([]string{}, typedSecrets...)
	for k := range nearMisses {
		keys = append(keys, k)
	}
	explained := 0
	for _, k := range keys {
		for place, tmpl := range places {
			raw := strings.ReplaceAll(tmpl, "@K@", k)
			var c tConfig
			cause := strict(raw, &c)
			if cause == nil {
				t.Fatalf("%s, %q: accepted; the case tests nothing", place, k)
			}
			for form, d := range map[string]*Diagnostics{
				"Explain":          Explain([]byte(raw), tType, cause, o),
				"Explain, no type": Explain([]byte(raw), nil, cause, o),
			} {
				explained += len(d.Problems)
				if out := keyForms(d); showsKey(out, k) {
					t.Errorf("%s, %s: %q is shown:\n%s", place, form, k, out)
				}
			}
		}
		// Validation problems: on the key's own line (by position), on the line after it, and with
		// the schema given.
		raw := "labels:\n  " + k + ": x\nport: 70000\nedge:\n  " + k + ": 1\n  mode: m\n"
		for form, so := range map[string]Options{"Semantic": o, "Semantic with the schema": {File: "config.yaml", RedactValues: true, Schema: tType}} {
			d := &Diagnostics{}
			d.Semantic([]byte(raw), []Problem{
				{Path: "port", Msg: "port is refused"}, {Path: "edge.mode", Msg: "edge.mode is refused"},
				{Pos: Pos{Line: 2, Col: 3}, Msg: "a label is refused"}, {Path: "labels", Msg: "labels is refused"},
			}, errors.New("refused"), so)
			if out := keyForms(d); len(d.Problems) != 4 || showsKey(out, k) {
				t.Errorf("%s: %q is shown:\n%s", form, k, out)
			}
		}
	}
	if explained < len(keys)*len(places) {
		t.Errorf("%d problems for %d files: the cases are not explained", explained, len(keys)*len(places)*2)
	}
	// A near miss still gets the schema's key as its hint.
	for k, want := range nearMisses {
		p := explainT(t, k+": x\n", o).Problems[0]
		if p.Kind != KindUnknownKey || p.Msg != "unknown key on this line" || p.Hint != "did you mean "+want+"?" || p.Excerpt != "…" || p.Path != "…" {
			t.Errorf("%q: %+v", k, p)
		}
	}
}

// Semantic names a key in an excerpt when it is part of the problem's own path (which is printed
// anyway) or, with Options.Schema, a key of the schema.
func TestSemanticKeyNames(t *testing.T) {
	raw := "labels:\n  team: x\nport: 70000\nedge:\n  mode: m\nbind_addr: x\nworkers: 1\n"
	ps := []Problem{{Path: "port", Msg: "port is refused"}, {Path: "edge.mode", Msg: "edge.mode is refused"}, {Path: "labels.team", Msg: "a label is refused"},
		{Pos: Pos{Line: 7, Col: 10}, Msg: "placed by position"}}
	for _, c := range []struct {
		name string
		o    Options
		want string
	}{
		{"no schema", Options{File: "c.yaml", RedactValues: true},
			"  1 | labels:\n  2 |   team: …\n|  2 |   …\n  3 | port: …\n|  4 | edge:\n  5 |   mode: …\n|  6 | …\n  7 | …\n"},
		{"schema", Options{File: "c.yaml", RedactValues: true, Schema: tType},
			"  1 | labels:\n  2 |   team: …\n|  2 |   …\n  3 | port: …\n|  4 | edge:\n  5 |   mode: …\n|  6 | bind_addr: …\n  7 | workers: …\n"},
		{"not redacted", Options{File: "c.yaml", Schema: tType},
			"  1 | labels:\n  2 |   team: x\n|  2 |   team: x\n  3 | port: 70000\n|  4 | edge:\n  5 |   mode: m\n|  6 | bind_addr: x\n  7 | workers: 1\n"},
	} {
		d := &Diagnostics{}
		d.Semantic([]byte(raw), append([]Problem{}, ps...), errors.New("refused"), c.o)
		out := d.Terminal()
		for _, want := range strings.Split(c.want, "|") {
			if !strings.Contains(out, want) {
				t.Errorf("%s: want %q in:\n%s", c.name, want, out)
			}
		}
	}
}

// Only "[digits]" is a list index: a key with other brackets is not another key's alias.
func TestStripIndexes(t *testing.T) {
	for in, want := range map[string]string{
		"users[1].role": "users.role", "a[0][12].b[3]": "a.b", "plain": "plain",
		"session.idle_time[x]out": "session.idle_time[x]out", "a[]b": "a[]b", "a[1": "a[1", "a[1x]": "a[1x]", "a[-1]": "a[-1]", "x]y[": "x]y[",
	} {
		if got := stripIndexes(in); got != want {
			t.Errorf("stripIndexes(%q) = %q, want %q", in, got, want)
		}
	}
	// The reviewer's reproduction: idle_time[x]out is not the key idle_timeout.
	raw := "edge:\n  time[x]out: " + marker + "\n"
	d := explainT(t, raw, Options{RedactValues: true})
	if out := allForms(d); len(d.Problems) != 1 || d.Problems[0].Kind != KindUnknownKey || strings.Contains(out, "ZQX") {
		t.Errorf("%+v\n%s", d.Problems, out)
	}
	d = semanticT(t, raw, "edge.time[x]out")
	if out := allForms(d); strings.Contains(out, "ZQX") {
		t.Errorf("Semantic on a bracket key:\n%s", out)
	}
}

type tS3 struct {
	Bucket string `yaml:"bucket"`
	Secret string `yaml:"secret_access_key"`
}

type tDNS struct {
	Provider string `yaml:"provider"`
	Token    string `yaml:"api_token"`
}

type tNS struct {
	Name  string `yaml:"name"`
	DNS01 *tDNS  `yaml:"dns01"`
}

type tOwners struct {
	Backups struct {
		Enabled bool `yaml:"enabled"`
		S3      tS3  `yaml:"s3"`
	} `yaml:"backups"`
	Logs struct {
		Archive struct {
			Days int  `yaml:"days"`
			S3   *tS3 `yaml:"s3"`
		} `yaml:"archive"`
	} `yaml:"security_logs"`
	Edge struct {
		DNS01       *tDNS `yaml:"dns01"`
		BaseDomains []tNS `yaml:"base_domains"`
	} `yaml:"edge"`
	Only struct {
		Unique string `yaml:"unique"`
	} `yaml:"only"`
	Next *tOwners `yaml:"next"`
}

// A block type used in two places has two owners: "belongs under" names the one inside the block
// the key was written in, and nothing when that is a guess.
func TestBelongsUnderWithSeveralOwners(t *testing.T) {
	for _, c := range []struct{ raw, hint string }{
		{"security_logs:\n  archive:\n    secret_access_key: x\n", "secret_access_key belongs under security_logs.archive.s3:"},
		{"security_logs:\n  bucket: b\n", "bucket belongs under security_logs.archive.s3:"},
		{"backups:\n  bucket: b\n", "bucket belongs under backups.s3:"},
		{"edge:\n  base_domains:\n    - name: stg\n      api_token: x\n", "api_token belongs under edge.base_domains.dns01:"},
		{"edge:\n  base_domains:\n    - name: stg\n      provider: x\n", "provider belongs under edge.base_domains.dns01:"},
		// Two owners inside the block (edge.dns01 and edge.base_domains.dns01), or none: no guess.
		{"edge:\n  api_token: x\n", "keys allowed here: dns01, base_domains"},
		{"api_token: x\n", "keys allowed here: backups, security_logs, edge, only, next"},
		{"only:\n  bucket: b\n", "keys allowed here: unique"},
		// One owner in the whole file.
		{"edge:\n  unique: x\n", "unique belongs under only:"},
		{"edge:\n  days: 3\n", "days belongs under security_logs.archive:"},
		{"backups:\n  s3:\n    only: x\n", "only belongs at the top level of the file"},
	} {
		var v tOwners
		cause := strict(c.raw, &v)
		if cause == nil {
			t.Fatalf("%q is accepted", c.raw)
		}
		d := Explain([]byte(c.raw), reflect.TypeOf(v), cause, Options{})
		if len(d.Problems) != 1 || d.Problems[0].Hint != c.hint {
			t.Errorf("%q: hint %q, want %q (%+v)", c.raw, d.Problems[0].Hint, c.hint, d.Problems)
		}
	}
	// A type that contains itself ends the search.
	w := &walker{root: reflect.TypeOf(tOwners{}), infos: map[reflect.Type]*structInfo{}}
	w.keyHint("zzz", "", w.info(w.root))
	if w.visits == 0 || w.visits >= maxTypes || len(w.owners["bucket"]) != 2 {
		t.Errorf("visits %d, owners of bucket %v", w.visits, w.owners["bucket"])
	}
}

// With no problem found, Error() is the decoder's own text; under RedactValues without anything it
// copied from the file.
func TestDecoderTextIsScrubbed(t *testing.T) {
	for in, want := range map[string]string{
		// A value, its tag or an unknown key ends the text: what follows it cannot be told from more
		// of it (scrubCut).
		"yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `hunter2` into int":                                      "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str …",
		"yaml: cannot decode !!str `" + marker + "` as a !!int":                                                             "yaml: cannot decode !!str …",
		"yaml: cannot decode !!str `a`b\nline 2: " + marker + "\n` as a !!float":                                            "yaml: cannot decode !!str …",
		"line 1: cannot unmarshal !foo `" + marker + "...` into config.GitHub":                                              "line 1: cannot unmarshal !… …",
		"line 1: cannot unmarshal !" + marker + " `x` into int\n  line 2: cannot unmarshal !!str `" + marker + "` into int": "line 1: cannot unmarshal !… …",
		"line 1: cannot unmarshal !!seq into bool\n  line 2: field " + marker + " not found in type T":                      "line 1: cannot unmarshal !!seq …",
		"line 3: mapping key \"" + marker + "\" already defined at line 2":                                                  "line 3: mapping key \"…\" already defined at line 2",
		"line 3: mapping key \"a\\\"" + marker + "\" already defined at line 2":                                             "line 3: mapping key \"…\" already defined at line 2",
		"line 3: mapping key \"a: field " + marker + "\" already defined at line 2":                                         "line 3: mapping key \"…\"",
		"line 3: field " + marker + " not found in type config.Config":                                                      "line 3: field … not found in type …",
		"line 3: field a\nline 4: " + marker + " not found in type config.Config\n  line 9: field b not found in type T":    "line 3: field … not found in type …",
		// The re-audit's holes. A verbatim tag (!<tag:x>) is printed with no "!"; with %-escapes it
		// holds spaces, the words " into " and line breaks.
		"line 2: cannot unmarshal tag:" + marker + " `x` into bool":                 "line 2: cannot unmarshal !… …",
		"line 2: cannot unmarshal tag:" + marker + " into bool":                     "line 2: cannot unmarshal !… …",
		"line 2: cannot unmarshal !!str " + marker + " `x` into bool":               "line 2: cannot unmarshal !!str …",
		"line 2: cannot unmarshal !!str into " + marker + " into bool":              "line 2: cannot unmarshal !!str …",
		"line 2: cannot unmarshal !!str into " + marker + "\n  line 9: x into bool": "line 2: cannot unmarshal !!str …",
		"line 2: cannot unmarshal tag:x\n  line 3: " + marker + " `v` into bool":    "line 2: cannot unmarshal !… …",
		// A key that holds the words that end the decoder's sentence about it.
		"line 3: field x not found in type y " + marker + " not found in type config.Config":                                     "line 3: field … not found in type …",
		"line 3: field a not found in type " + marker + "` not found in type T":                                                  "line 3: field … not found in type …",
		"line 3: field " + marker + "`x not found in type T":                                                                     "line 3: field … not found in type …",
		"line 3: field k not found in type T\n  line 5: cannot unmarshal !!str `x not found in type " + marker + " y` into bool": "line 3: field … not found in type …",
		"line 2: cannot unmarshal !!str `v` into bool\n  line 3: field K1`" + marker + " not found in type T":                    "line 2: cannot unmarshal !!str …",
		"yaml: invalid map key: []interface {}{12345678}":                                                                        "yaml: invalid map key: …",
		"yaml: unknown anchor '" + marker + "' referenced":                                                                       "yaml: unknown anchor '…' referenced",
		"yaml: line 5: did not find expected ',' or ']'":                                                                         "yaml: line 5: did not find expected ',' or ']'",
		"it isn't '" + marker + "' here":                                                                                         "it isn'…' here",
		"an open quote \"" + marker:                                                                                              "an open quote \"…\"",
		"a truncated `" + marker:                                                                                                 "a truncated `…`",
		"config: parse: EOF":                                                                                                     "config: parse: EOF",
		"line 4: not a valid duration: use a number and a unit like 30s, 5m, 12h or 30d":                                         "line 4: not a valid duration: use a number and a unit like 30s, 5m, 12h or 30d",
		"line 4, column 13: not a valid duration: use a number and a unit like 30s, 5m, 12h or 30d":                              "line 4, column 13: not a valid duration: use a number and a unit like 30s, 5m, 12h or 30d",
		strings.Repeat("x", maxScrub+1):                                                                                          "",
	} {
		got := scrub(in)
		if got != want {
			t.Errorf("scrub(%q)\n got %q\nwant %q", in, got, want)
		}
		if strings.Contains(got, "ZQX") {
			t.Errorf("scrub(%q) keeps the value: %q", in, got)
		}
	}

	o := Options{File: "config.yaml", RedactValues: true}
	pad := strings.Repeat("# padding\n", MaxInput/10+1)
	for name, raw := range map[string]string{
		"explicit tag":            "port: !!int " + marker + "\n",
		"explicit tag, float":     "ratio: !!float " + marker + "\n",
		"custom tag on a mapping": "edge: !foo " + marker + "\n",
		"custom tag is a secret":  "port: !" + marker + " x\n",
		"oversize, wrong type":    "port: " + marker + "\n" + pad,
		"oversize, tag":           "port: !!int " + marker + "\n" + pad,
		"oversize, unknown key":   marker + ": 1\n" + pad,
		"oversize, twice":         "port: 1\n" + marker + ": 1\n" + marker + ": 2\n" + pad,
		"oversize, anchor":        "bind_addr: *" + marker + "\n" + pad,
	} {
		var c tConfig
		cause := strict(raw, &c)
		if cause == nil {
			t.Fatalf("%s: accepted", name)
		}
		if !strings.Contains(cause.Error(), "ZQX") {
			t.Fatalf("%s: the decoder's text has no value in it (%v); the case tests nothing", name, cause)
		}
		d := Explain([]byte(raw), tType, cause, o)
		if out := allForms(d); strings.Contains(out, "ZQX") {
			t.Errorf("%s: the value is shown:\n%.600s", name, out)
		}
		if strings.HasPrefix(name, "oversize") && len(d.Problems) != 0 {
			t.Errorf("%s: a file above MaxInput was examined", name)
		}
		if !errors.Is(d, cause) {
			t.Errorf("%s: the cause is not kept", name)
		}
		// Without RedactValues the text is the decoder's own.
		if d := Explain([]byte(raw), tType, cause, Options{File: "m.yaml"}); !strings.Contains(allForms(d), "ZQX") && strings.HasPrefix(name, "oversize") {
			t.Errorf("%s: without RedactValues the decoder's text is changed: %q", name, d.Error())
		}
	}
	// A value under an explicit tag is reported in plain words where the decoder gives a line.
	d := explainT(t, "healthcheck:\n  test: !!int "+marker+"\n", o)
	if out := allForms(d); strings.Contains(out, "ZQX") {
		t.Errorf("inside a type that decodes itself:\n%s", out)
	}
	// A message that is too long to scrub is not shown at all.
	d = Explain(nil, nil, errors.New(strings.Repeat("`"+marker, maxScrub/8)), o)
	if d.Error() != "config.yaml: the file was refused" {
		t.Errorf("an oversize message: %.200q", d.Error())
	}
	// A parser message with no translation goes through the same scrub.
	pos, msg, _ := translate(errors.New("yaml: line 2: something new about '"+marker+"' and `"+marker+"`"), newSource([]byte("a\nb\n")), true)
	if pos.Line != 2 || msg != "something new about '…' and `…`" {
		t.Errorf("an untranslated parser message: %v %q", pos, msg)
	}
	if _, msg, _ := translate(errors.New("yaml: line 2: something new about '"+marker+"'"), newSource([]byte("a\nb\n")), false); !strings.Contains(msg, marker) {
		t.Errorf("without RedactValues: %q", msg)
	}
}

// A message from a type that decodes itself (the cause's "line N: …") is read from the scrubbed
// text, so a value that holds a line break and "line N: " cannot become a message of its own.
func TestCauseLinesComeFromScrubbedText(t *testing.T) {
	raw := "port: 1\nbind_addr: x\nworkers: 2\n"
	cause := fmt.Errorf("yaml: cannot decode !!str `a\nline 2: %s\nb` as a !!int", marker)
	d := Explain([]byte(raw), tType, cause, Options{File: "c.yaml", RedactValues: true})
	if out := allForms(d); len(d.Problems) != 0 || strings.Contains(out, "ZQX") {
		t.Errorf("problems %+v\n%s", d.Problems, out)
	}
	cause = fmt.Errorf("yaml: unmarshal errors:\n  line 2: mapping key %q already defined at line 1\n  line 3: field %s not found in type T", marker, marker)
	d = Explain([]byte(raw), tType, cause, Options{File: "c.yaml", RedactValues: true})
	if out := allForms(d); len(d.Problems) != 2 || strings.Contains(out, "ZQX") ||
		d.Problems[0].Msg != "a key is written twice in this block (first on line 1)" || d.Problems[1].Msg != "unknown key on this line" {
		t.Errorf("problems %+v\n%s", d.Problems, out)
	}
	d = Explain([]byte(raw), tType, cause, Options{File: "c.yaml"})
	if len(d.Problems) != 2 || d.Problems[0].Msg != `key "`+marker+`" is written twice in this block (first on line 1)` || d.Problems[1].Msg != `unknown key "`+marker+`"` {
		t.Errorf("without RedactValues: %+v", d.Problems)
	}
}
