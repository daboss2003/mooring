package definition

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/yamldiag"
)

// diagOf is the Diagnostics a refusal carries.
func diagOf(t *testing.T, err error) *yamldiag.Diagnostics {
	t.Helper()
	if err == nil {
		t.Fatal("expected a refusal")
	}
	var d *yamldiag.Diagnostics
	if !errors.As(err, &d) {
		t.Fatalf("a refusal must be (or wrap) a *yamldiag.Diagnostics, got %T: %v", err, err)
	}
	return d
}

func oneLine(t *testing.T, err error) string {
	t.Helper()
	s := err.Error()
	if strings.ContainsAny(s, "\n\r") {
		t.Errorf("Error() must be one line: %q", s)
	}
	return s
}

const (
	legacyDecodePrefix = "definition rejected (unknown or mistyped field): "
	legacySyntaxPrefix = "invalid YAML: "
)

type corpusRecord struct {
	Kind string `json:"kind"` // "app" (Parse) or "host" (ParseHost)
	OK   bool   `json:"ok"`
	Err  string `json:"err"`
	Raw  []byte `json:"raw"`
}

// The golden is every input the package's tests fed Parse and ParseHost (valid and invalid, the
// stored canonicals included) plus a set of hostile variants, with the verdict and the error text of
// the parser as it was BEFORE diagnostics existed (captured at 1c6271d by recording inside Parse and
// ParseHost while the test suite ran). Never regenerate it from the current code to make this test
// pass: a difference here is a change in what Mooring accepts.
func loadCorpus(t *testing.T) []corpusRecord {
	t.Helper()
	f, err := os.Open("testdata/parse_corpus.jsonl.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var out []corpusRecord
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		var r corpusRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestParseVerdictsUnchanged pins what is accepted and what is refused, and that a refusal still
// carries the text it had.
func TestParseVerdictsUnchanged(t *testing.T) {
	corpus := loadCorpus(t)
	accepted, refused := 0, 0
	for i, r := range corpus {
		var err error
		switch r.Kind {
		case "app":
			_, err = Parse(r.Raw)
			// The named and the stored entry points share the verdict.
			if _, nerr := ParseNamed(r.Raw, "mooring.prod.yaml"); (nerr == nil) != r.OK {
				t.Errorf("#%d ParseNamed: accepted=%v, before=%v\n%s", i, nerr == nil, r.OK, r.Raw)
			}
			_, serr := ParseStored(r.Raw)
			if (serr == nil) != r.OK {
				t.Errorf("#%d ParseStored: accepted=%v, before=%v\n%s", i, serr == nil, r.OK, r.Raw)
			}
			if serr != nil {
				d := diagOf(t, serr)
				if len(d.Problems) != 0 || d.Cause == nil || d.Cause.Error() != r.Err {
					t.Errorf("#%d ParseStored must carry the refusal's text and no position: %+v", i, d)
				}
				oneLine(t, serr)
			}
		case "host":
			_, err = ParseHost(r.Raw)
		default:
			t.Fatalf("#%d: kind %q", i, r.Kind)
		}
		if (err == nil) != r.OK {
			t.Errorf("#%d %s: accepted=%v, before=%v (before: %q, now: %v)\n%s", i, r.Kind, err == nil, r.OK, r.Err, err, r.Raw)
			continue
		}
		if err == nil {
			accepted++
			continue
		}
		refused++
		d := diagOf(t, err)
		line := oneLine(t, err)
		prefix := ""
		for _, p := range []string{legacyDecodePrefix, legacySyntaxPrefix} {
			if strings.HasPrefix(r.Err, p) {
				prefix = p
			}
		}
		// The refusal of before is still there, word for word.
		if d.Cause == nil || prefix+d.Cause.Error() != r.Err {
			t.Errorf("#%d: the refusal's text changed:\n before: %q\n now:    %q", i, r.Err, prefix+d.Cause.Error())
		}
		if prefix != "" {
			if !strings.HasPrefix(line, prefix) {
				t.Errorf("#%d: Error() lost its prefix %q: %q", i, prefix, line)
			}
			continue
		}
		// Everything else keeps its whole message in Error() (control characters and runs of
		// spaces are flattened so it stays one line).
		if want := strings.Join(strings.Fields(r.Err), " "); !strings.Contains(strings.Join(strings.Fields(line), " "), want) {
			t.Errorf("#%d: Error() must contain the message of before:\n before: %q\n now:    %q", i, r.Err, line)
		}
		if len(d.Problems) != 1 {
			t.Errorf("#%d: a harden or validation refusal is ONE problem (first error only), got %d: %q", i, len(d.Problems), line)
		}
	}
	if accepted < 100 || refused < 500 {
		t.Fatalf("corpus too small: %d accepted, %d refused", accepted, refused)
	}
	t.Logf("corpus: %d inputs, %d accepted, %d refused — verdicts unchanged", len(corpus), accepted, refused)
}

func TestParseOversizeStillRefused(t *testing.T) {
	big := []byte(goodDef + strings.Repeat("# pad\n", 100000))
	for name, err := range map[string]error{
		"app":  second(Parse(big)),
		"host": second(ParseHost(big)),
	} {
		if err == nil || !strings.Contains(oneLine(t, err), "definition too large (") {
			t.Errorf("%s: an oversize definition must be refused with its message: %v", name, err)
		}
		diagOf(t, err)
	}
}

func second[T any](_ T, err error) error { return err }

func TestHardenRefusalsCarryPositions(t *testing.T) {
	cases := []struct {
		name, src, msg, kind string
		line, col            int
	}{
		{"anchor", strings.Replace(goodDef, "metadata:\n", "metadata: &m\n", 1),
			"YAML anchors (&ref) are not allowed in a definition", yamldiag.KindSyntax, 3, 11},
		{"merge key", strings.Replace(goodDef, "  slug: shop", "  slug: shop\n  <<: {kind: Host}", 1),
			"YAML merge keys (<<) are not allowed in a definition", yamldiag.KindSyntax, 5, 3},
		{"duplicate key", strings.Replace(goodDef, "        hsts: true", "        hsts: true\n        hsts: false", 1),
			`duplicate key "hsts" in a definition`, yamldiag.KindDuplicate, 23, 9},
		{"tier-1 key", goodDef + "ip_allowlist: [10.0.0.1]\n",
			`"ip_allowlist" is a Tier-1 security field — it lives only in /etc/mooring/config.yaml (SSH-edit), never a host/app definition`, yamldiag.KindSemantic, 23, 1},
		{"nested tier-1 key", strings.Replace(goodDef, "        hsts: true", "        hsts: true\n        acme_email: a@example.com", 1),
			`"acme_email" is a Tier-1 security field`, yamldiag.KindSemantic, 23, 9},
	}
	for _, tc := range cases {
		_, err := Parse([]byte(tc.src))
		d := diagOf(t, err)
		if len(d.Problems) != 1 {
			t.Fatalf("%s: one problem expected: %+v", tc.name, d.Problems)
		}
		p := d.Problems[0]
		if p.Line != tc.line || p.Col != tc.col || p.Kind != tc.kind || !strings.Contains(p.Msg, tc.msg) {
			t.Errorf("%s: got %d:%d %s %q, want %d:%d %s %q", tc.name, p.Line, p.Col, p.Kind, p.Msg, tc.line, tc.col, tc.kind, tc.msg)
		}
		if want := strings.Split(tc.src, "\n")[tc.line-1]; p.Excerpt != want {
			t.Errorf("%s: excerpt %q, want the offending line %q", tc.name, p.Excerpt, want)
		}
		if line := oneLine(t, err); !strings.HasPrefix(line, "mooring.yaml:") || !strings.Contains(line, tc.msg) {
			t.Errorf("%s: Error() = %q", tc.name, line)
		}
	}
	// An anchor always comes before the alias that uses it, so the anchor is what is reported.
	var target map[string]int
	var he *hardenError
	if err := hardenAndDecode([]byte("a: &x 1\nb: *x\n"), &target); !errors.As(err, &he) || he.line != 1 || he.col != 4 || !strings.Contains(he.msg, "anchors") {
		t.Errorf("anchor position: %#v (%v)", he, err)
	}
	// An alias to nothing is the YAML parser's refusal.
	if err := second(Parse([]byte(goodDef + "extra: *nope\n"))); err == nil || !strings.HasPrefix(err.Error(), legacySyntaxPrefix) {
		t.Errorf("unknown alias: %v", err)
	}
}

func TestUnknownKeySuggestsTheRightOne(t *testing.T) {
	_, err := Parse([]byte(strings.Replace(goodDef, "  edge:", "  egde:", 1)))
	d := diagOf(t, err)
	if len(d.Problems) != 1 {
		t.Fatalf("problems: %+v", d.Problems)
	}
	p := d.Problems[0]
	if p.Kind != yamldiag.KindUnknownKey || p.Line != 17 || p.Col != 3 || p.Path != "spec.egde" || !strings.Contains(p.Hint, "did you mean edge?") {
		t.Errorf("unknown key: %+v", p)
	}
	line := oneLine(t, err)
	if !strings.HasPrefix(line, legacyDecodePrefix+"mooring.yaml:17:3: ") || !strings.Contains(line, "did you mean edge?") {
		t.Errorf("Error() = %q", line)
	}
	// Several unknown keys are all listed.
	_, err = Parse([]byte(strings.Replace(goodDef, "        hsts: true", "        htss: true\n        prot: 1", 1)))
	if d := diagOf(t, err); len(d.Problems) != 2 || d.Problems[0].Line != 22 || d.Problems[1].Line != 23 {
		t.Errorf("both unknown keys must be listed: %+v", d.Problems)
	}
}

func TestQuotedBooleanRefusedEnvValueKept(t *testing.T) {
	_, err := Parse([]byte(strings.Replace(goodDef, "hsts: true", `hsts: "true"`, 1)))
	d := diagOf(t, err)
	if len(d.Problems) != 1 {
		t.Fatalf("problems: %+v", d.Problems)
	}
	p := d.Problems[0]
	if p.Kind != yamldiag.KindType || p.Line != 22 || p.Path != "spec.edge.routes[0].hsts" ||
		!strings.Contains(p.Msg, "must be true or false without quotes") || p.Hint != "remove the quotes" {
		t.Errorf("quoted boolean: %+v", p)
	}
	if line := oneLine(t, err); !strings.HasPrefix(line, legacyDecodePrefix) || strings.Contains(line, "unmarshal") || strings.Contains(line, "!!") {
		t.Errorf("the message must be plain: %q", line)
	}
	// Text is what an env value IS: "false" in quotes stays a literal.
	def, err := Parse([]byte(strings.Replace(goodDef, "        env:\n", "        env:\n          FLAG: \"false\"\n          BARE: false\n", 1)))
	if err != nil {
		t.Fatalf(`"false" as an env value must stay accepted: %v`, err)
	}
	env := def.Spec.Compose.Services["web"].Env
	if env["FLAG"].Value != "false" || env["BARE"].Value != "false" {
		t.Errorf("env literals: %+v", env)
	}
}

func TestFirstSemanticErrorIsLocated(t *testing.T) {
	rich := goodDef + `    l4_routes:
      - listen: 853
        protocol: tcp
        service: web
        port: 853
  scaling:
    - service: web
      enabled: true
      min: 1
      max: 3
  scheduled_tasks:
    - name: nightly
      service: job
      every: 24h
`
	rich = strings.Replace(rich, "  secrets:", "      job:\n        image: ghcr.io/acme/job:1\n  secrets:", 1)
	if _, err := Parse([]byte(rich)); err != nil {
		t.Fatalf("base document: %v", err)
	}
	cases := []struct {
		name, old, new, path, msg string
		line, col                 int
	}{
		{"service", "        image: ghcr.io/acme/web:1.2\n", "", "spec.compose.services.web",
			`service "web" must set exactly one of image or build`, 9, 7},
		{"service port", "internal: 8080", "internal: 9000", "spec.compose.services.web.ports[0]",
			`service "web" port 9000 is a reserved control-plane port`, 12, 13},
		{"service restart", "        image: ghcr.io/acme/job:1", "        image: ghcr.io/acme/job:1\n        restart: sometimes", "spec.compose.services.job.restart",
			`service "job" restart "sometimes" is not allowed`, 17, 18},
		{"edge route", "        service: web\n        port: 8080", "        service: nope\n        port: 8080", "spec.edge.routes[0].service",
			`edge route "shop.example.com" targets unknown service "nope"`, 22, 18},
		{"edge route lb", "        hsts: true", "        lb: fastest", "spec.edge.routes[0].lb",
			`edge route "shop.example.com" lb "fastest" must be least_conn, round_robin, ip_hash or cookie`, 24, 13},
		{"l4 route", "listen: 853", "listen: 443", "spec.edge.l4_routes[0].listen",
			"edge l4_route listen port 443 is reserved for the HTTP edge", 26, 17},
		{"scaling", "      min: 1", "      min: 5", "spec.scaling[0].min",
			`scaling "web": min (5) cannot exceed max (3)`, 33, 12},
		{"scaling entry", "      min: 1", "      min: -1", "spec.scaling[0]",
			`scaling "web": min/max must be >= 0`, 31, 7},
		{"scheduled task", "every: 24h", "every: soon", "spec.scheduled_tasks[0].every",
			`scheduled_task "nightly": every "soon" is not a valid positive duration (e.g. 24h, 15m)`, 38, 14},
		{"envelope", "slug: shop", "slug: Shop_Bad", "metadata.slug",
			`metadata.slug must match [a-z][a-z0-9-]{1,30} (got "Shop_Bad")`, 4, 9},
	}
	for _, tc := range cases {
		if !strings.Contains(rich, tc.old) {
			t.Fatalf("%s: seed %q missing", tc.name, tc.old)
		}
		src := strings.Replace(rich, tc.old, tc.new, 1)
		_, err := ParseNamed([]byte(src), "mooring.staging.yaml")
		d := diagOf(t, err)
		if len(d.Problems) != 1 {
			t.Fatalf("%s: validation reports its FIRST error only: %+v", tc.name, d.Problems)
		}
		p := d.Problems[0]
		if p.Kind != yamldiag.KindSemantic || p.Path != tc.path || p.Msg != tc.msg || p.Line != tc.line || p.Col != tc.col {
			t.Errorf("%s: got %s %d:%d %q, want %s %d:%d %q", tc.name, p.Path, p.Line, p.Col, p.Msg, tc.path, tc.line, tc.col, tc.msg)
		}
		if want := strings.Split(src, "\n")[tc.line-1]; p.Excerpt != want {
			t.Errorf("%s: excerpt %q, want %q", tc.name, p.Excerpt, want)
		}
		if line := oneLine(t, err); !strings.HasPrefix(line, "mooring.staging.yaml:") || !strings.HasSuffix(line, ": "+tc.msg) {
			t.Errorf("%s: Error() = %q", tc.name, line)
		}
	}
	// Two semantic mistakes: only the first is reported.
	src := strings.Replace(strings.Replace(rich, "internal: 8080", "internal: 9000", 1), "every: 24h", "every: soon", 1)
	if d := diagOf(t, second(Parse([]byte(src)))); len(d.Problems) != 1 || !strings.Contains(d.Problems[0].Msg, "port 9000") {
		t.Errorf("first semantic error only: %+v", d.Problems)
	}
}

// The text of a validation error is the same with or without a key path, and the path survives
// wrapping; a nil error stays nil.
func TestFieldErrorKeepsTextAndInnerPath(t *testing.T) {
	if at("spec.x", nil) != nil {
		t.Fatal("at must keep nil")
	}
	inner := atf("spec.a.b", "value %d is wrong", 7)
	outer := at("spec.a", inner)
	var fe *fieldError
	if !errors.As(outer, &fe) || fe.path != "spec.a.b" || outer.Error() != "value 7 is wrong" {
		t.Errorf("the inner, more exact path wins: %#v %q", fe, outer.Error())
	}
	plain := errors.New("plain")
	if got := at("", plain); got != plain {
		t.Error("an empty path adds nothing")
	}
	if got := at("spec.a", plain); !errors.Is(got, plain) || got.Error() != "plain" {
		t.Errorf("wrapping keeps the error: %v", got)
	}
	d := &Definition{APIVersion: APIVersion, Kind: "App", Metadata: Metadata{Slug: "shop"},
		Spec: Spec{Compose: Compose{Services: map[string]Service{"web": {}}}}}
	if err := d.validateEnvelope(); err == nil || err.Error() != `service "web" must set exactly one of image or build` {
		t.Errorf("a definition built in code gets the same text: %v", err)
	}
}

func TestFileNameInMessages(t *testing.T) {
	bad := []byte(strings.Replace(goodDef, "kind: App", "kind: Nope", 1))
	if line := oneLine(t, second(Parse(bad))); !strings.HasPrefix(line, `mooring.yaml:2:7: kind must be "App"`) {
		t.Errorf("Parse names mooring.yaml: %q", line)
	}
	err := second(ParseNamed(bad, "mooring.staging.yaml"))
	if line := oneLine(t, err); !strings.HasPrefix(line, `mooring.staging.yaml:2:7: kind must be "App"`) {
		t.Errorf("ParseNamed names the file it was given: %q", line)
	}
	if d := diagOf(t, err); d.File != "mooring.staging.yaml" || !strings.HasPrefix(d.Terminal(), "mooring.staging.yaml:2:7: ") || !strings.Contains(d.Terminal(), "kind: Nope\n") {
		t.Errorf("Terminal():\n%s", d.Terminal())
	}
	host := []byte("apiVersion: mooring/v1\nkind: Host\nspec:\n  defualts: {}\n")
	if line := oneLine(t, second(ParseHost(host))); !strings.HasPrefix(line, legacyDecodePrefix+"host.yaml:4:3: ") || !strings.Contains(line, "did you mean defaults?") {
		t.Errorf("ParseHost: %q", line)
	}
	herr := second(ParseHostNamed([]byte("apiVersion: mooring/v1\nkind: Host\nspec:\n  apps:\n    - slug: shop\n      source: {managed: true}\n    - slug: shop\n      source: {managed: true}\n"), "fleet.yaml"))
	if line := oneLine(t, herr); line != `fleet.yaml:7:13: duplicate app "shop" in the registry` {
		t.Errorf("ParseHostNamed: %q", line)
	}
	// A syntax error: the real line, and no file name from Kind (it is not given one).
	tab := []byte(strings.Replace(goodDef, "  slug: shop", "\tslug: shop", 1))
	if line := oneLine(t, second(ParseNamed(tab, "mooring.yaml"))); !strings.HasPrefix(line, legacySyntaxPrefix+"mooring.yaml:4:1: ") {
		t.Errorf("syntax error: %q", line)
	}
	_, kerr := Kind(tab)
	if line := oneLine(t, kerr); !strings.HasPrefix(line, legacySyntaxPrefix+"4:1: ") {
		t.Errorf("Kind: %q", line)
	}
	diagOf(t, kerr)
	// Kind looks at one key: the file's other keys are never called unknown.
	if _, err := Kind([]byte(goodDef)); err != nil {
		t.Errorf("Kind: %v", err)
	}
	_, kerr = Kind([]byte("apiVersion: mooring/v1\nkind: {a: b}\nspec: {}\n"))
	if d := diagOf(t, kerr); len(d.Problems) > 1 || strings.Contains(kerr.Error(), "unknown key") {
		t.Errorf("Kind must not judge other keys: %v", kerr)
	}
}

// The file is hostile text: whatever it holds, Error() is one bounded line and the excerpt has no
// control characters.
func TestRefusalOfHostileTextStaysOneLine(t *testing.T) {
	evil := "\x1b[31m<script>alert(1)</script>‮"
	for name, src := range map[string]string{
		"unknown key":   goodDef + "\"" + evil + "\": 1 # \x07\n",
		"semantic":      strings.Replace(goodDef, "service: web", "service: \"a\\nb\\e[0m<script>\"", 1),
		"duplicate key": strings.Replace(goodDef, "kind: App", "\"k\\n"+strings.Repeat("x", 5000)+"\": 1\n\"k\\n"+strings.Repeat("x", 5000)+"\": 2", 1),
		"syntax":        strings.Replace(goodDef, "kind: App", "kind: [\x1b]0;title\x07 <script>", 1),
	} {
		_, err := ParseNamed([]byte(src), "mooring.yaml")
		d := diagOf(t, err)
		line := oneLine(t, err)
		if len(line) > 2000 {
			t.Errorf("%s: Error() is %d bytes", name, len(line))
		}
		for _, r := range line + d.Terminal() {
			if r != '\n' && (r < 0x20 || r == 0x7f || r == '‮') {
				t.Errorf("%s: control character %U in the output", name, r)
				break
			}
		}
	}
}

// Positions around a directive and document markers. Anchors, aliases and merge keys never reach
// the typed decode in a definition (TestHardenRefusalsCarryPositions): they are refused where they
// are written.
func TestPositionsAroundDocumentMarkers(t *testing.T) {
	// The parser leaves the line out of a complaint about the first line.
	_, err := Parse([]byte("%\n" + goodDef))
	d := diagOf(t, err)
	if p := d.Problems[0]; len(d.Problems) != 1 || p.Pos != (yamldiag.Pos{Line: 1}) || p.Kind != yamldiag.KindSyntax || p.Excerpt != "%" {
		t.Errorf("a directive on line 1: %+v", d.Problems)
	}
	if line := oneLine(t, err); line != legacySyntaxPrefix+"mooring.yaml:1: could not find expected directive name" {
		t.Errorf("a directive on line 1: %q", line)
	}
	// An empty document is placed by the parser after the last line: the position stays in the file.
	_, err = Parse([]byte("# only\n---\n# c\n"))
	d = diagOf(t, err)
	if p := d.Problems[0]; len(d.Problems) != 1 || p.Pos != (yamldiag.Pos{Line: 3}) || p.Path != "apiVersion" || p.Excerpt != "# c" {
		t.Errorf("an empty document: %+v", d.Problems)
	}
	if line := oneLine(t, err); !strings.HasPrefix(line, "mooring.yaml:3: apiVersion must be exactly") {
		t.Errorf("an empty document: %q", line)
	}
	// The definition is in a second document and the first is not a mapping.
	_, err = Parse([]byte("shop\n---\n" + goodDef))
	d = diagOf(t, err)
	if p := d.Problems[0]; len(d.Problems) != 1 || p.Pos != (yamldiag.Pos{Line: 1, Col: 1}) || p.Kind != yamldiag.KindType || p.Excerpt != "shop" ||
		p.Hint != `only the first document of the file is read; it ends at the "---" on line 2` {
		t.Errorf("a scalar first document: %+v", d.Problems)
	}
	// A merge key is still refused by the hardening, at the "<<" itself.
	_, err = Parse([]byte(strings.Replace(goodDef, "        hsts: true", "        <<: {hsts: true, nope: 1}", 1)))
	d = diagOf(t, err)
	if p := d.Problems[0]; len(d.Problems) != 1 || p.Pos != (yamldiag.Pos{Line: 22, Col: 9}) || p.Excerpt != "        <<: {hsts: true, nope: 1}" ||
		!strings.Contains(p.Msg, "merge keys (<<) are not allowed") {
		t.Errorf("a merge key: %+v", d.Problems)
	}
}
