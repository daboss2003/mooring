package config

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/yamldiag"
)

// Abuse tests of what a refused config.yaml prints (the v0.34.0 fix round). config.yaml holds the
// master key, password hashes, TOTP secrets, tokens and S3 keys, and a refusal reaches the journal.

// shownForms is every form a refusal is printed in.
func shownForms(t *testing.T, err error) (string, *yamldiag.Diagnostics) {
	t.Helper()
	var d *yamldiag.Diagnostics
	if !errors.As(err, &d) {
		return err.Error(), nil
	}
	if e := d.Error(); e == "" || strings.ContainsAny(e, "\r\n") {
		t.Errorf("Error() must be one non-empty line: %q", e)
	}
	return d.Error() + "\n" + d.Terminal() + "\n" + string(d.JSON()), d
}

func mustNotShow(t *testing.T, name, y string) *yamldiag.Diagnostics {
	t.Helper()
	cfg, err := Parse([]byte(y))
	if err == nil || cfg != nil {
		t.Errorf("%s: accepted; the case tests nothing", name)
		return nil
	}
	shown, d := shownForms(t, err)
	if strings.Contains(shown, "ZQX") {
		if len(shown) > 1500 {
			shown = shown[:1500]
		}
		t.Errorf("%s: the refusal shows a secret:\n%s", name, shown)
	}
	return d
}

// The reviewer's reproductions: a line break only YAML knows shifted the excerpt onto the next line.
func TestRefusalWithUnusualLineBreaks(t *testing.T) {
	base := validYAML(t, "")
	bad := strings.Replace(base, "\"127.0.0.1:9000\"\nencryption_key: \"", "\"0.0.0.0:9000\"\nencryption_key: \"ZQX", 1)
	if bad == base {
		t.Fatal("the base config changed; the case tests nothing")
	}
	for name, y := range map[string]string{
		"LS after a comment":     "# pasted note\u2028\n" + bad,
		"PS after a comment":     "# pasted note\u2029\n" + bad,
		"NEL after a comment":    "# pasted note\u0085\n" + bad,
		"CR inside a comment":    "# pasted note\r# more\n" + bad,
		"LS, three of them":      "# a\u2028# b\u2028# c\u2028\n" + bad,
		"LS after the first key": strings.Replace(bad, "\nbind_addr", "\n# x\u2028\nbind_addr", 1),
		"LS, unknown key":        "# pasted note\u2028\n" + strings.Replace(bad, "bind_addr:", "bind_adr:", 1),
		"LS, quoted boolean":     "# pasted note\u2028\n" + base + "trust_proxy: \"true\"\ngithub:\n  client_secret: ZQXgh\n",
		"LS at the end of a key": strings.Replace(bad, "\"0.0.0.0:9000\"\n", "\"0.0.0.0:9000\"\u2028", 1),
	} {
		d := mustNotShow(t, name, y)
		if d == nil || len(d.Problems) == 0 {
			t.Errorf("%s: nothing explained", name)
			continue
		}
		for _, p := range d.Problems {
			if p.Path == "bind_addr" && p.Excerpt != "bind_addr: …" {
				t.Errorf("%s: the excerpt of bind_addr is %q", name, p.Excerpt)
			}
		}
	}
}

// The reviewer's hand-written cases: flow collections, comments, tags, bracket keys, values pasted
// under the wrong key, files too large to examine.
func TestRefusalHandCases(t *testing.T) {
	base := validYAML(t, "")
	edge := "edge:\n  mode: \"managed\"\n  acme_email: \"ops@example.com\"\n  acme_ca: \"https://acme.example/directory\"\n"
	if !strings.Contains(base, edge) || !strings.Contains(base, "bind_addr: \"127.0.0.1:9000\"") {
		t.Fatal("the base config changed; the cases test nothing")
	}
	pad := strings.Repeat("# pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad\n", 20000)
	if len(pad) <= yamldiag.MaxInput {
		t.Fatal("the padding is not above MaxInput")
	}
	cases := map[string]string{
		"flow dns01": base + "  base_domain: apps.example.com\n  dns01: {provider: \"Cloud Flare\", api_token: ZQXtoken}\n",
		"flow edge": strings.Replace(base, edge,
			"edge: {mode: bogus, acme_email: ops@example.com, acme_ca: \"https://acme.example/directory\", base_domain: apps.example.com, dns01: {provider: cloudflare, api_token: ZQXflowtoken}}\n", 1),
		"flow base_domains":              base + "  base_domains:\n    - {name: stg, domain: BAD_DOMAIN, dns01: {provider: cloudflare, api_token: ZQXnstoken}}\n",
		"flow root":                      "{bind_addr: \"0.0.0.0:1\", encryption_key: ZQXrootkey, ip_allowlist: [1.2.3.4]}\n",
		"flow retention":                 base + "alerting: {telegram: {bot_token: ZQXtg}}\nretention: {interval: 1s}\n",
		"comment after a value":          strings.Replace(base, "bind_addr: \"127.0.0.1:9000\"", "bind_addr: \"0.0.0.0:9000\" # old key ZQXcomment", 1),
		"comment on a list item":         strings.Replace(base, "  - \"203.0.113.10/32\"", "  - \"nope\" # ZQXcomment", 1),
		"tag int":                        base + "encryption_key_previous: !!int ZQXprevkey\n",
		"tag float":                      base + "github:\n  client_secret: !!float ZQXfl\n",
		"tag under users":                base + "users:\n  - username: bob\n    password_hash: !!int ZQXuhash\n",
		"tag in a duration":              base + "retention:\n  interval: !!int ZQXint\n",
		"custom tag, struct":             base + "github: !foo ZQXgithub\n",
		"custom tag is a value":          base + "trust_proxy: !ZQXtag true\n",
		"scalar for a struct":            base + "github: ZQXgithub2\n",
		"bracket key":                    base + "session:\n  idle_time[x]out: ZQXbracket\n",
		"secret under a boolean":         base + "trust_proxy: ZQXbool\n",
		"secret under a quoted boolean":  base + "trust_proxy: \"ZQXbool\"\n",
		"secret under a number":          base + "retention:\n  events_max_rows: ZQXnum\n",
		"secret under a duration":        base + "retention:\n  interval: ZQXdur\n",
		"secret under a quoted duration": base + "retention:\n  interval: \"ZQX dur\"\n",
		"value on the next line, glued":  base + "alerting:\n  dead_mans_url:\n    ZQXuser:ZQXpass\n  bogus: 1\n",
		"multi-line quoted":              base + "github:\n  client_secret: \"ZQXline1\n    ZQXline2\n  client_id: x\n",
		"block scalar":                   base + "github:\n  client_secret: |\n    ZQXblock1\n   ZQXblock2\n",
		"block scalar that looks safe":   base + "github:\n  client_secret: |\n    bind_addr: ZQXblock\nbind_addr: \"0.0.0.0:1\"\n",
		"duplicate key":                  base + "encryption_key: ZQXdup\n",
		"key under a secret":             base + "github:\n  client_secret:\n  ZQX0123456789abcdef01234567: x\n",
		"secret typed as a key":          base + "ZQX0123456789abcdef0123456789abcdef: 1\n",
		"secret typed as a key, twice":   base + "ZQX0123456789abcdef0123456789abcdef: 1\nZQX0123456789abcdef0123456789abcdef: 2\n",
		"sentence typed as a key":        base + "the token is ZQXtoken: 1\n",
		"unclosed flow":                  base + "protected_projects: [a, b\ngithub:\n  client_secret: ZQXafterflow\n",
		"oversize, custom tag":           base + "github: !foo ZQXgithubbig\n" + pad,
		"oversize, tag int":              base + "encryption_key_previous: !!int ZQXprevkeybig\n" + pad,
		"oversize, scalar for a struct":  base + "github: ZQXg3\n" + pad,
		"oversize, duplicate key":        base + "ZQXdupkey: 1\nZQXdupkey: 2\n" + pad,
		"oversize, unknown key":          base + "ZQXunknownkey: 1\n" + pad,
		"oversize, syntax":               base + "github:\n  client_secret: *ZQXanchor\n" + pad,
		"oversize, validation":           strings.Replace(base, "\"operator\"", "\"operator\"\n  totp_secret: ZQX-not-base32", 1) + pad,
	}
	for name, y := range cases {
		if d := mustNotShow(t, name, y); d != nil && strings.HasPrefix(name, "oversize") && name != "oversize, validation" && len(d.Problems) != 0 {
			t.Errorf("%s: a file above MaxInput was examined: %+v", name, d.Problems)
		}
	}

	// What the owner decided the messages say.
	for ov, want := range map[string]string{
		"trust_proxy: ZQXbool\n":                   "config.yaml:13:14: trust_proxy must be true or false",
		"trust_proxy: \"true\"\n":                  "config.yaml:13:14: trust_proxy must be true or false without quotes (hint: remove the quotes)",
		"retention:\n  events_max_rows: ZQXnum\n":  "config.yaml:14:20: retention.events_max_rows must be a number",
		"retention:\n  interval: ZQXdur\n":         "config.yaml:14:13: retention.interval is not a valid duration: use a number and a unit like 30s, 5m, 12h or 30d",
		"ZQX0123456789abcdef0123456789abcdef: 1\n": "config.yaml:13:1: unknown key on this line",
		// A key close to one of the schema's is not named: the hint names the schema's key.
		"session:\n  idle_time[x]out: ZQXbracket\n":          `config.yaml:14:3: unknown key on this line in session (hint: did you mean idle_timeout?)`,
		"JBSWY3DPEHPK3PXP: 1\n":                              "config.yaml:13:1: unknown key on this line",
		"backups:\n  AKI" + "AIOSFODNN7EXAMPLQ: x\n":         "config.yaml:14:3: unknown key on this line in backups (hint: keys allowed here: enabled, schedule, retention, helper_image, s3)",
		"alerting:\n  JBSWY3DPEHPK3PXP:x\n  enabled: true\n": "config.yaml:14:20: there is no space after the ':' (hint: put a space after the ':')",
		"encryption_key_previous: !!int ZQXprevkey\n":        "config.yaml:13:26: encryption_key_previous must be text",
	} {
		_, err := Parse([]byte(base + ov))
		if err == nil || err.Error() != want {
			t.Errorf("%q:\n got %v\nwant %s", ov, err, want)
		}
	}
	// An alias to the encryption key under a text key: neither the excerpt nor the message has it.
	y := strings.Replace(base, "encryption_key: \"", "encryption_key: &k \"", 1) + "admin:\n  listen: *k\n"
	_, err := Parse([]byte(y))
	var ad *yamldiag.Diagnostics
	if !errors.As(err, &ad) || len(ad.Problems) != 1 || ad.Problems[0].Path != "admin.listen" || ad.Problems[0].Excerpt != "  listen: …" ||
		ad.Problems[0].Msg != "admin.listen: must be a unix socket (unix//...) or 127.0.0.1:2019, never routable" || strings.Contains(ad.Terminal()+string(ad.JSON()), "AAAA") {
		t.Errorf("an alias under a text key: %v", err)
	}
	// A value validation refuses is masked whatever its key, and so is the comment after it.
	d := mustNotShow(t, "comment", strings.Replace(base, "bind_addr: \"127.0.0.1:9000\"", "bind_addr: \"0.0.0.0:9000\"   # old key ZQXcomment", 1))
	if d == nil || len(d.Problems) != 1 || d.Problems[0].Excerpt != "bind_addr: …" || strings.Contains(d.Terminal(), "0.0.0.0") {
		t.Errorf("a refused value with a comment: %+v", d)
	}
}

// Owner decision 2026-11-25: a key is named only when it is a key of config.yaml, spelled right. A
// short lowercase secret typed where a key belongs (a password on a line of its own before a colon,
// a key and its value swapped) is written exactly like a key, so no shape makes a key nameable; a
// key close to one of config.yaml's is not echoed either, the hint names the key that was meant.
func TestOnlySchemaKeysAreNamed(t *testing.T) {
	base := validYAML(t, "")
	const plain = "config.yaml:13:1: unknown key on this line"
	inSession := "config.yaml:14:3: unknown key on this line in session (hint: keys allowed here: idle_timeout, absolute_timeout)"
	for ov, want := range map[string]string{
		// Secrets written like keys.
		"hunter2: x\n":                                  plain,
		"hunter2:\n":                                    plain,
		"hunter:\n  x: 1\n":                             plain,
		"tr0ub4dor3: x\n":                               plain,
		"correct_horse_battery: x\n":                    plain,
		"my_db_pass_2024: auth\n":                       plain,
		"deadbeefcafe0123: x\n":                         plain,
		"deadbeefcafe0123deadbeefcafe0123deadbeef: x\n": plain,
		"dead_beef_cafe_0123_dead_beef_cafe_0123: x\n":  plain,
		"session:\n  hunter2: idle_timeout\n":           inSession,
		"session:\n  s3cr3t:\n":                         inSession,
		"hunter2: 1\nhunter2: 2\n":                      plain + "; 1 more problem",
		// One character from a key of config.yaml: the key that was meant is the hint.
		"bind_addrs: x\n":                plain + " (hint: did you mean bind_addr?)",
		"Bind_Addr: x\n":                 plain + " (hint: did you mean bind_addr?)",
		"trust-proxy: true\n":            plain + " (hint: did you mean trust_proxy?)",
		"encryption_kez: x\n":            plain + " (hint: did you mean encryption_key?)",
		"session:\n  idle-timeout: 1h\n": "config.yaml:14:3: unknown key on this line in session (hint: did you mean idle_timeout?)",
		"session:\n  Idle_Timeout: 1h\n": "config.yaml:14:3: unknown key on this line in session (hint: did you mean idle_timeout?)",
		// A key of another block, mistyped: the same, with where it belongs.
		"IDLE_TIMEOUT: 1h\n": plain + " (hint: did you mean idle_timeout? idle_timeout belongs under session:)",
		"idle_timeot: 1h\n":  plain + " (hint: did you mean idle_timeout? idle_timeout belongs under session:)",
		// A key of config.yaml, spelled right, is named wherever it is written.
		"idle_timeout: 1h\n":                                    `config.yaml:13:1: unknown key "idle_timeout" (hint: idle_timeout belongs under session:)`,
		"session:\n  trust_proxy: true\n":                       `config.yaml:14:3: unknown key "trust_proxy" in session (hint: trust_proxy belongs at the top level of the file)`,
		"bind_addr: x\n":                                        `config.yaml:13:1: key "bind_addr" is written twice in this block (first on line 2) (hint: keep one of the two)`,
		"session:\n  idle_timeout: [1h]\n":                      "config.yaml:14:3: session.idle_timeout has the wrong type (found a list)",
		"session:\n  idle_timeout:1h\n  absolute_timeout: 2h\n": `config.yaml:14:16: there is no space after the ':' (hint: put a space between "idle_timeout:" and its value)`,
		"session:\n  Idle_Timeout:1h\n  absolute_timeout: 2h\n": "config.yaml:14:16: there is no space after the ':' (hint: put a space after the ':')",
		"session:\n  hunter2:1h\n  absolute_timeout: 2h\n":      "config.yaml:14:11: there is no space after the ':' (hint: put a space after the ':')",
	} {
		_, err := Parse([]byte(base + ov))
		if err == nil || err.Error() != want {
			t.Errorf("%q:\n got %v\nwant %s", ov, err, want)
			continue
		}
		shown, d := shownForms(t, err)
		if d == nil {
			t.Errorf("%q: not a Diagnostics", ov)
			continue
		}
		for _, p := range d.Problems {
			shown += "\n" + p.Msg + "\n" + p.Hint + "\n" + p.Excerpt + "\n" + p.Path
		}
		for _, typed := range []string{"hunter", "tr0ub", "horse", "db_pass", "deadbeef", "dead_beef", "s3cr3t", "bind_addrs", "Bind_", "trust-", "_kez", "idle-", "Idle_", "IDLE", "timeot"} {
			if strings.Contains(shown, typed) {
				t.Errorf("%q: the refusal shows what was typed (%s):\n%s", ov, typed, shown)
			}
		}
	}
	// The excerpt and the line before it name config.yaml's own keys and nothing else: the unknown
	// key's line is masked whole, the line above it (a key of config.yaml) is not.
	_, err := Parse([]byte(base + "session:\n  hunter2: idle_timeout\n"))
	var d *yamldiag.Diagnostics
	if !errors.As(err, &d) || len(d.Problems) != 1 || d.Problems[0].Path != "session.…" || d.Problems[0].Excerpt != "  …" ||
		!strings.Contains(d.Terminal(), "  13 | session:\n  14 |   …\n     |   ^\n") {
		t.Errorf("a secret as a key in a block: %v\n%s", err, d.Terminal())
	}
	// A validation problem: its own key, and on the line before it another key of config.yaml.
	_, err = Parse([]byte(strings.Replace(base, "encryption_key: \"AAA", "encryption_key: \"ZQX!", 1)))
	if !errors.As(err, &d) || len(d.Problems) == 0 || !strings.Contains(d.Terminal(), "  2 | bind_addr: …\n  3 | encryption_key: …\n") {
		t.Errorf("a validation problem's lines: %v\n%s", err, d.Terminal())
	}
}

// "belongs under" names the block inside the one the key was written in (the S3 block and the DNS
// block exist in two places each).
func TestBelongsUnderNamesTheRightBlock(t *testing.T) {
	base := validYAML(t, "")
	for ov, want := range map[string]string{
		"security_logs:\n  archive:\n    secret_access_key: ZQXs3\n":                               "secret_access_key belongs under security_logs.archive.s3:",
		"security_logs:\n  archive:\n    bucket: b\n":                                              "bucket belongs under security_logs.archive.s3:",
		"backups:\n  secret_access_key: ZQXs3\n":                                                   "secret_access_key belongs under backups.s3:",
		"  base_domains:\n    - name: stg\n      domain: stg.example.com\n      api_token: ZQXt\n": "api_token belongs under edge.base_domains.dns01:",
		"  base_domains:\n    - name: stg\n      domain: stg.example.com\n      provider: x\n":     "provider belongs under edge.base_domains.dns01:",
	} {
		d := mustNotShow(t, ov, base+ov)
		if d == nil || len(d.Problems) != 1 || d.Problems[0].Hint != want {
			t.Errorf("%q: %+v\nwant hint %q", ov, d, want)
		}
	}
	// Top level: two blocks own it, neither is inside "the file" more than the other.
	_, err := Parse([]byte(base + "secret_access_key: ZQXs3\n"))
	var d *yamldiag.Diagnostics
	if !errors.As(err, &d) || len(d.Problems) != 1 || strings.Contains(d.Problems[0].Hint, "belongs") {
		t.Errorf("a key of two blocks at the top level: %v", err)
	}
}

// A panic while explaining must not hand back the raw refusal: its text quotes values.
func TestExplainPanicStillRedacts(t *testing.T) {
	old := explainFile
	explainFile = func([]byte, reflect.Type, error, yamldiag.Options) *yamldiag.Diagnostics { panic("boom") }
	defer func() { explainFile = old }()
	y := validYAML(t, "retention:\n  events_max_rows: ZQXnum\n")
	_, err := Parse([]byte(y))
	if err == nil {
		t.Fatal("accepted")
	}
	var d *yamldiag.Diagnostics
	if !errors.As(err, &d) || d.Cause == nil || !strings.Contains(d.Cause.Error(), "ZQXnum") {
		t.Fatalf("err = %T %v; the case needs a cause that quotes the value", err, err)
	}
	if shown, _ := shownForms(t, err); strings.Contains(shown, "ZQX") || err.Error() != "config.yaml: config: parse: yaml: unmarshal errors: line 14: cannot unmarshal !!str …" {
		t.Errorf("the panic path shows the value: %s", shown)
	}
	// The last resort says nothing of the file's content and keeps the cause.
	cause := errors.New("cause with ZQXvalue")
	if r := (refused{file: "config.yaml", cause: cause}); r.Error() != "config.yaml: the file was refused" || !errors.Is(r, cause) {
		t.Errorf("refused: %q", r.Error())
	}
}

// checkPerms' group rule wraps ErrOtherGroup and keeps its message.
func TestCheckGroupWrapsErrOtherGroup(t *testing.T) {
	const path = "/etc/mooring/config.yaml"
	err := checkGroup(path, 0o640, 990, 1000, 1000)
	if !errors.Is(err, ErrOtherGroup) || err.Error() != "config: /etc/mooring/config.yaml is group-readable by gid 990, not the service group 1000" {
		t.Errorf("another group: %v", err)
	}
	for name, err := range map[string]error{
		"the service's own group": checkGroup(path, 0o640, 990, 990, 990),
		"root calls":              checkGroup(path, 0o640, 990, 0, 0),
		"group root":              checkGroup(path, 0o640, 0, 1000, 1000),
		"not group-readable":      checkGroup(path, 0o600, 990, 1000, 1000),
	} {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The other refusals of checkPerms are not "another group".
	p := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkPerms(p); err == nil || errors.Is(err, ErrOtherGroup) {
		t.Errorf("a world-readable file: %v", err)
	}
	if err := checkPerms(p + ".missing"); err == nil || errors.Is(err, ErrOtherGroup) {
		t.Errorf("a missing file: %v", err)
	}
}

// --- the property: no mutation of a config full of secrets prints one ---

// Owner decision 2026-11-25: an error about config.yaml never shows a value from the file. There is
// NO list of exempt keys in this test: every text value is a marker, every number and duration a
// recognisable one, and none may appear in any form of a refusal.

// plainValues are well-formed values for the text keys that have a fixed form (a mode, an address,
// a name). The "plain" config is written with them so validation gets past those keys to its later
// checks; each of them still gets a marker in turn (secretUnderEveryKey). Every other text key holds
// a marker in both configs.
var plainValues = map[string]string{
	"bind_addr": `"127.0.0.1:9000"`, "ip_allowlist": `"203.0.113.10/32"`, "trusted_proxies": `"192.0.2.1"`,
	"auth.username": "operator", "users.username": "dev", "users.role": "viewer",
	"edge.mode": "managed", "edge.base_domain": "apps.example.com", "edge.dns01.provider": "cloudflare",
	"edge.cas.name": "corp", "edge.base_domains.name": "stg", "edge.base_domains.domain": "stg.example.net",
	"edge.base_domains.dns01.provider": "cloudflare", "edge.trusted_proxies": "cloudflare", "edge.client_ip_header": "CF-Connecting-IP",
	"admin.subdomain": "admin", "admin.listen": `"127.0.0.1:2019"`, "admin.edge_listen": `"127.0.0.1:9100"`,
	"cookie.prefix": `"__Secure-"`, "cookie.base_path": "/mooring", "docker.proxy_addr": `"127.0.0.1:2375"`,
	"caddy_editor.mode": "strict", "compose_validation.mode": "strict", "server.build_concurrency": "auto",
	"security_logs.response.mode": "recommend",
}

// The markers. A number read from the file must not be printed either: every number is numberMarker
// and every duration numberMarker hours (which time.Duration prints as "77077h0m0s").
const numberMarker = "77077"

// showsMarker reports whether text holds a marker (a text one in any case, or the number).
func showsMarker(text string) bool {
	l := strings.ToLower(text)
	return strings.Contains(l, "zqx") || strings.Contains(l, "canary") || strings.Contains(l, numberMarker)
}

// markedYAML writes every key of t in block style: a marker ("ZQX<n>canary…", shaped like a key or a
// token) in every text key that plain has no value for, numberMarker in every number and duration.
func markedYAML(t reflect.Type, prefix, indent string, plain map[string]string, marked *[]string, used map[string]bool, b *strings.Builder) {
	durT := reflect.TypeOf(Duration(0))
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := yamlKey(f)
		if name == "" {
			continue
		}
		path := prefix + name
		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		scalar := func(ft reflect.Type) (string, bool) {
			switch {
			case ft == durT:
				return numberMarker + "h", true
			case ft.Kind() == reflect.String:
				if v, ok := plain[path]; ok {
					used[path] = true
					return v, true
				}
				*marked = append(*marked, path)
				return fmt.Sprintf("\"ZQX%03dcanarycanarycanarycanary\"", len(*marked)), true
			case ft.Kind() == reflect.Bool:
				return "true", true
			case ft.Kind() == reflect.Int || ft.Kind() == reflect.Int64 || ft.Kind() == reflect.Float64:
				return numberMarker, true
			}
			return "", false
		}
		if s, ok := scalar(ft); ok {
			fmt.Fprintf(b, "%s%s: %s\n", indent, name, s)
			continue
		}
		switch ft.Kind() {
		case reflect.Struct:
			fmt.Fprintf(b, "%s%s:\n", indent, name)
			markedYAML(ft, path+".", indent+"  ", plain, marked, used, b)
		case reflect.Slice:
			et := ft.Elem()
			for et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			if s, ok := scalar(et); ok {
				fmt.Fprintf(b, "%s%s:\n%s  - %s\n", indent, name, indent, s)
				s2, _ := scalar(et)
				fmt.Fprintf(b, "%s  - %s\n", indent, s2)
			} else if et.Kind() == reflect.Struct {
				fmt.Fprintf(b, "%s%s:\n", indent, name)
				var sub strings.Builder
				markedYAML(et, path+".", indent+"    ", plain, marked, used, &sub)
				lines := strings.SplitAfter(sub.String(), "\n")
				if len(lines) > 0 && len(lines[0]) > len(indent)+4 {
					lines[0] = indent + "  - " + lines[0][len(indent)+4:]
				}
				b.WriteString(strings.Join(lines, ""))
			} else {
				panic("markedYAML: a list of " + et.String() + " at " + path)
			}
		default:
			panic("markedYAML: " + ft.Kind().String() + " at " + path)
		}
	}
}

// credentialKeys are the keys whose values are secrets (each must hold a marker in both configs).
var credentialKeys = []string{"encryption_key", "encryption_key_previous", "auth.password_hash", "auth.totp_secret",
	"users.password_hash", "users.totp_secret", "edge.dns01.api_token", "edge.base_domains.dns01.api_token",
	"github.client_secret", "alerting.dead_mans_url", "backups.s3.access_key_id", "backups.s3.secret_access_key",
	"security_logs.archive.s3.access_key_id", "security_logs.archive.s3.secret_access_key"}

// keySecrets are secrets typed where a key belongs: 16 characters (a base32 TOTP secret), 20 (an
// access key id), 24 and 40 (tokens, a secret access key), each also in lower case, one of short
// words with capitals (base64url), and the ones that are written exactly like a key: a short
// lowercase word, lowercase with digits, snake_case words.
var keySecrets = []string{
	"ZQXJBSWY3DPEHPK3", "AKI" + "AZQX7ODNN7EXAMPLQ", "ghp_ZQXdefghij0123456789", "ZQXrXUtn" + "FEMIxK7MDENGzbPxRfiCYEXAMPLEKEY0",
	"zqxjbswy3dpehpk3", "akiazqx7odnn7examplq", "zqxdefghij0123456789abcd", "zqxrxutnfemixk7mdengzbpxrficyexamplekey0",
	"zqX_cAnArY_k9_Lm2Pq",
	"canary", "zqxpass", "zqxhunter2", "zqx_canary_horse", "zqx_k9_lm2_pq7", "zqx4",
}

// valueStart is the offset of a line's scalar value ("key: value" or "- value"), false for a line
// that has none (a block's key).
func valueStart(l string) (int, bool) {
	if c := strings.Index(l, ": "); c >= 0 {
		return c + 2, true
	}
	if t := strings.TrimLeft(l, " "); strings.HasPrefix(t, "- ") && !strings.HasSuffix(t, ":") {
		return len(l) - len(t) + 2, true
	}
	return 0, false
}

type lineMutation struct {
	name string
	f    func(line string) []string // the lines that replace it (nil: does not apply)
}

func lineMutations() []lineMutation {
	ind := func(l string) int { return len(l) - len(strings.TrimLeft(l, " ")) }
	value := func(l string) (int, bool) { c := strings.Index(l, ": "); return c, c >= 0 }
	sub := func(old, repl string) func(string) []string {
		return func(l string) []string {
			if !strings.Contains(l, old) {
				return nil
			}
			return []string{strings.Replace(l, old, repl, 1)}
		}
	}
	brk := func(b string) func(string) []string {
		return func(l string) []string { return []string{"# note" + b, l} }
	}
	return []lineMutation{
		{"indent+1", func(l string) []string { return []string{" " + l} }},
		{"indent+3", func(l string) []string { return []string{"   " + l} }},
		{"indent-1", func(l string) []string {
			if ind(l) == 0 {
				return nil
			}
			return []string{l[1:]}
		}},
		{"indent-2", func(l string) []string {
			if ind(l) < 2 {
				return nil
			}
			return []string{l[2:]}
		}},
		{"tab", func(l string) []string { return []string{"\t" + strings.TrimLeft(l, " ")} }},
		{"tab after the indentation", func(l string) []string { return []string{l[:ind(l)] + "\t" + l[ind(l):]} }},
		{"no space after the colon", sub(": ", ":")},
		{"no colon", sub(":", "")},
		{"closing quote dropped", func(l string) []string {
			if !strings.HasSuffix(l, "\"") {
				return nil
			}
			return []string{l[:len(l)-1]}
		}},
		{"opening quote dropped", sub(": \"", ": ")},
		{"both quotes dropped", func(l string) []string {
			if !strings.Contains(l, ": \"") || !strings.HasSuffix(l, "\"") {
				return nil
			}
			return []string{strings.Replace(l[:len(l)-1], ": \"", ": ", 1)}
		}},
		{"written twice", func(l string) []string { return []string{l, l} }},
		{"dash added", func(l string) []string { return []string{l[:ind(l)] + "- " + l[ind(l):]} }},
		{"dash removed", sub("- ", "  ")},
		{"key mistyped", func(l string) []string {
			c := strings.Index(l, ":")
			if c < 1 {
				return nil
			}
			return []string{l[:c] + "x" + l[c:]}
		}},
		{"key with brackets", func(l string) []string {
			c := strings.Index(l, ":")
			if c < 2 {
				return nil
			}
			return []string{l[:c-1] + "[x]" + l[c-1:]}
		}},
		{"key with an index", func(l string) []string {
			c := strings.Index(l, ":")
			if c < 1 {
				return nil
			}
			return []string{l[:c] + "[0]" + l[c:]}
		}},
		{"second colon", func(l string) []string { return []string{l + " more: stuff"} }},
		{"trailing comma", func(l string) []string { return []string{l + ","} }},
		{"open bracket", sub(": ", ": [")},
		{"open brace", sub(": ", ": {")},
		{"at sign", sub(": ", ": @")},
		{"star", sub(": ", ": *")},
		{"ampersand", sub(": ", ": &a ")},
		{"custom tag", sub(": ", ": !foo ")},
		{"tag int", sub(": ", ": !!int ")},
		{"tag float", sub(": ", ": !!float ")},
		{"tag bool", sub(": ", ": !!bool ")},
		{"tag map", sub(": ", ": !!map ")},
		{"tag seq", sub(": ", ": !!seq ")},
		{"pipe", sub(": ", ": | ")},
		{"value on the next line", func(l string) []string {
			c, ok := value(l)
			if !ok {
				return nil
			}
			return []string{l[:c+1], l[:ind(l)] + "  " + l[c+2:]}
		}},
		{"value on the next line, same indentation", func(l string) []string {
			c, ok := value(l)
			if !ok {
				return nil
			}
			return []string{l[:c+1], l[:ind(l)] + l[c+2:]}
		}},
		{"value on the next line, glued colon", func(l string) []string {
			c, ok := value(l)
			if !ok {
				return nil
			}
			return []string{l[:c+1], l[:ind(l)] + "  " + strings.Trim(l[c+2:], "\"") + ":tail"}
		}},
		{"value as a key below", func(l string) []string {
			c, ok := value(l)
			if !ok {
				return nil
			}
			return []string{l[:c+1], l[:ind(l)] + "  " + strings.Trim(l[c+2:], "\"") + ": x"}
		}},
		{"key and value swapped", func(l string) []string {
			c, ok := value(l)
			if !ok {
				return nil
			}
			return []string{l[:ind(l)] + strings.Trim(l[c+2:], "\"") + ": " + strings.TrimLeft(l[:c], " -")}
		}},
		{"key dropped", func(l string) []string {
			c, ok := value(l)
			if !ok {
				return nil
			}
			return []string{l[:ind(l)] + l[c+2:]}
		}},
		{"list on the key line", sub(": ", ": - ")},
		{"trailing comment", func(l string) []string { return []string{l + " #c"} }},
		{"secret in a trailing comment", func(l string) []string { return []string{l + " # was ZQXcommentcanarycanarycanary"} }},
		{"carriage return", func(l string) []string { return []string{l + "\r"} }},
		{"control character", func(l string) []string { return []string{l + "\x01"} }},
		{"invalid UTF-8", func(l string) []string { return []string{l + "\xff"} }},
		{"document end before", func(l string) []string { return []string{"...", l} }},
		{"garbage after", func(l string) []string { return []string{l, l[:ind(l)] + "   ]"} }},
		{"flow mapping", func(l string) []string {
			if _, ok := value(l); !ok || strings.Contains(l, "- ") {
				return nil
			}
			return []string{l[:ind(l)] + "{" + strings.TrimLeft(l, " ") + ", zz: 1}"}
		}},
		{"flow list item", func(l string) []string {
			if _, ok := value(l); !ok || strings.Contains(l, "- ") {
				return nil
			}
			return []string{l[:ind(l)] + "- {" + strings.TrimLeft(l, " ") + "}"}
		}},
		{"value in a flow mapping", func(l string) []string {
			c, ok := value(l)
			if !ok {
				return nil
			}
			return []string{l[:c+2] + "{sub: " + l[c+2:] + "}"}
		}},
		{"value in a flow list", func(l string) []string {
			c, ok := value(l)
			if !ok {
				return nil
			}
			return []string{l[:c+2] + "[" + l[c+2:] + ", x]"}
		}},
		{"nested mapping", func(l string) []string {
			c, ok := value(l)
			if !ok {
				return nil
			}
			return []string{l[:c+1], l[:ind(l)] + "  sub: " + l[c+2:]}
		}},
		{"nested list", func(l string) []string {
			c, ok := value(l)
			if !ok {
				return nil
			}
			return []string{l[:c+1], l[:ind(l)] + "  - " + l[c+2:]}
		}},
		{"quoted boolean", sub(": true", ": \"true\"")},
		{"secret under a boolean, number or duration", func(l string) []string {
			for _, v := range []string{": " + numberMarker, ": true", ": " + numberMarker + "h"} {
				if strings.HasSuffix(l, v) {
					return []string{strings.TrimSuffix(l, v) + ": ZQXpastedcanarycanarycanary"}
				}
			}
			return nil
		}},
		{"LS before", brk("\u2028")},
		{"PS before", brk("\u2029")},
		{"NEL before", brk("\u0085")},
		{"CR before", brk("\r")},
		{"LS at the end", func(l string) []string { return []string{l + "\u2028"} }},
		{"NEL inside", func(l string) []string {
			c, ok := value(l)
			if !ok {
				return nil
			}
			return []string{l[:c+1] + "\u0085" + l[c+1:]}
		}},
	}
}

// keyPathsOfLines is the key path (without list indexes) of each line of a markedYAML config.
func keyPathsOfLines(lines []string) []string {
	out := make([]string, len(lines))
	var stack []string // the key at each indentation level (two spaces each)
	for i, l := range lines {
		t := strings.TrimLeft(l, " ")
		depth := (len(l) - len(t)) / 2
		if strings.HasPrefix(t, "- ") {
			t = t[2:]
			depth++
			if !strings.Contains(t, ":") { // a scalar list item: its list's path
				out[i] = strings.Join(stack[:min(depth-1, len(stack))], ".")
				continue
			}
		}
		key, _, _ := strings.Cut(t, ":")
		stack = append(stack[:min(depth, len(stack))], key)
		out[i] = strings.Join(stack, ".")
	}
	return out
}

// For a config with a recognisable marker in EVERY text value, number and duration, no mistake makes
// any form of the refusal print one: Error(), Terminal(), JSON(), a problem's message, hint, excerpt
// or path, the validation's own text, or a validation message beyond the 20 that are shown. The
// mistakes: indentation, tabs, colons, quotes, tags, flow forms, comments, bracket keys, line breaks
// only YAML knows, a secret under every key (text, number, boolean, duration, list item), an alias
// from every credential to every other key, block and folded scalars, the values of two adjacent
// keys swapped, a secret typed as a key name (also one written exactly like a key: there is no list
// of exempt keys or shapes), every key typed one character off, and files too large to examine.
func TestNoMutationShowsASecret(t *testing.T) {
	check := func(label, y string) (refused bool) {
		t.Helper()
		_, err := Parse([]byte(y))
		if err == nil {
			return false
		}
		forms := map[string]string{}
		shown, d := shownForms(t, err)
		forms["the refusal"] = shown
		if d == nil {
			t.Errorf("%s: the refusal is not a Diagnostics (%T)", label, err)
		} else {
			for i, p := range d.Problems {
				forms[fmt.Sprintf("problem %d", i)] = p.Msg + "\n" + p.Hint + "\n" + p.Excerpt + "\n" + p.Path
			}
			// Validate()'s own text is the cause of a validation refusal; a caller may print it.
			if d.Cause != nil && strings.HasPrefix(d.Cause.Error(), "config: refusing to boot") {
				forms["Validate()"] = d.Cause.Error()
			}
		}
		// Every validation message when the refusal shows only its first 20.
		if d != nil && d.More > 0 {
			c := &Config{}
			if yamlStrict([]byte(y), c) == nil {
				applyDefaults(c)
				for _, p := range c.Problems() {
					forms["Problems() at "+p.Path] = p.Msg + "\n" + p.Hint + "\n" + p.Path
				}
			}
		}
		for where, text := range forms {
			if !showsMarker(text) {
				continue
			}
			var bad []string
			for _, l := range strings.Split(text, "\n") {
				if showsMarker(l) {
					if len(l) > 300 {
						l = l[:300] + "…"
					}
					bad = append(bad, l)
				}
			}
			t.Errorf("%s: %s shows a value from the file:\n%s", label, where, strings.Join(bad, "\n"))
			break
		}
		return true
	}

	pad := strings.Repeat("# padding padding padding padding padding padding padding padding\n", yamldiag.MaxInput/60)
	muts := lineMutations()
	total, totalRefused := 0, 0
	for _, variant := range []struct {
		name  string
		plain map[string]string
	}{{"every text key a marker", nil}, {"plain", plainValues}} {
		var b strings.Builder
		var marked []string
		used := map[string]bool{}
		markedYAML(reflect.TypeOf(Config{}), "", "", variant.plain, &marked, used, &b)
		base := b.String()
		for k := range variant.plain {
			if !used[k] {
				t.Errorf("plainValues has %q, which is not a text key of the config", k)
			}
		}
		for _, cred := range credentialKeys {
			if !slices.Contains(marked, cred) {
				t.Errorf("%s: the credential key %s has no marker (marked: %d keys)", variant.name, cred, len(marked))
			}
		}
		lines := strings.Split(strings.TrimRight(base, "\n"), "\n")
		if len(lines) < 150 || len(marked) < 20 {
			t.Fatalf("%s: %d lines, %d markers: the generated config is too small to mean anything", variant.name, len(lines), len(marked))
		}
		paths := keyPathsOfLines(lines)
		if !check(variant.name, base) {
			t.Fatalf("%s: the generated config is accepted", variant.name)
		}
		with := func(i int, repl ...string) string {
			out := append(append(append([]string{}, lines[:i]...), repl...), lines[i+1:]...)
			return strings.Join(out, "\n") + "\n"
		}
		ind := func(l string) string { return l[:len(l)-len(strings.TrimLeft(l, " "))] }
		cases, refusedN := 0, 0
		failed := map[string]int{}
		// run checks one file; a class that has failed three times is not run further.
		// Intentional: under -race only every fifth file is checked. The property has one goroutine
		// and nothing for the race detector to find, and all ~19000 files take minutes with it; the
		// plain `go test` (which the security gate runs) checks every file.
		seq := 0
		run := func(class, label, y string) {
			if seq++; failed[class] >= 3 || (raceDetector && seq%5 != 0) {
				return
			}
			cases++
			before := t.Failed()
			if check(variant.name+": "+class+" "+label, y) {
				refusedN++
			}
			if !before && t.Failed() {
				failed[class]++
			}
		}
		at := func(i int) string { return fmt.Sprintf("at line %d (%q)", i+1, lines[i]) }

		// 1. Single-line mistakes. Every mutation on every line is ~15000 files; a third of them
		// (each mutation on every third line, the phase shifted per mutation) still puts every
		// mutation on every kind of line.
		const stride = 3
		for mi, m := range muts {
			for i := mi % stride; i < len(lines); i += stride {
				if rep := m.f(lines[i]); rep != nil {
					run(m.name, at(i), with(i, rep...))
				}
			}
		}
		// 2. A secret under every key: text, number, boolean, duration and list item, plain and quoted.
		for i, l := range lines {
			if v, ok := valueStart(l); ok {
				run("secret under the key", at(i), with(i, l[:v]+"ZQXpastedcanarycanarycanary"))
				run("quoted secret under the key", at(i), with(i, l[:v]+"\"ZQXpastedcanarycanarycanary\""))
				// A number and a duration below every minimum (the configs' own are above every maximum).
				run("negative number under the key", at(i), with(i, l[:v]+"-"+numberMarker))
				run("negative duration under the key", at(i), with(i, l[:v]+"-"+numberMarker+"h"))
			}
		}
		// 3. Block and folded scalars: the line's own value, and a secret, as the text of one.
		for i, l := range lines {
			v, ok := valueStart(l)
			if !ok {
				continue
			}
			for _, style := range []string{"|", ">-", "|+", ">"} {
				for _, text := range []string{strings.Trim(l[v:], "\""), "ZQXblockcanarycanarycanary", "password: ZQXblockcanarycanary"} {
					run("block scalar "+style, at(i), with(i, l[:v]+style, ind(l)+"    "+text, ind(l)+"    second: "+text))
				}
			}
		}
		// 4. The values of two adjacent keys swapped (a hash under username, a token under provider).
		for i := 0; i+1 < len(lines); i++ {
			a, aok := valueStart(lines[i])
			c, cok := valueStart(lines[i+1])
			if aok && cok {
				out := append([]string{}, lines...)
				out[i], out[i+1] = lines[i][:a]+lines[i+1][c:], lines[i+1][:c]+lines[i][a:]
				run("values swapped", at(i), strings.Join(out, "\n")+"\n")
			}
		}
		// 5. An alias from each credential key to every other scalar line (before the anchor it is
		// an unknown anchor, after it the credential's value read under the other key).
		for i, l := range lines {
			v, ok := valueStart(l)
			if !ok || !slices.Contains(credentialKeys, paths[i]) {
				continue
			}
			for k, other := range lines {
				ov, ok := valueStart(other)
				if !ok || k == i {
					continue
				}
				out := append([]string{}, lines...)
				out[i] = l[:v] + "&s " + l[v:]
				out[k] = other[:ov] + "*s"
				run("alias to "+paths[i], fmt.Sprintf("from line %d (%q)", k+1, other), strings.Join(out, "\n")+"\n")
			}
		}
		// 6. A secret typed where a key belongs: as a new key, in place of the line's key, and glued
		// to its value.
		for si, secret := range keySecrets {
			for i := si % stride; i < len(lines); i += stride {
				l := lines[i]
				class := fmt.Sprintf("secret %d (%d characters) as a key", si, len(secret))
				run(class, "added "+at(i), with(i, ind(l)+secret+": 1", l))
				run(class, "glued "+at(i), with(i, ind(l)+secret+":x", l))
				if c := strings.Index(l, ":"); c > 0 && !strings.Contains(l, "- ") {
					run(class, "replacing the key "+at(i), with(i, ind(l)+secret+l[c:]))
					run(class, "replacing the key, glued "+at(i), with(i, ind(l)+secret+":"+strings.TrimPrefix(l[c+1:], " ")))
				}
			}
		}
		// 7. Every key written one character off (a letter added, its first letter a capital, a "_"
		// typed "-"): what was typed is never printed; the problem is an unknown key without its
		// name, and its hint is the key of config.yaml that was meant.
		isKey := map[string]bool{}
		keyOf := func(l string) (key string, c int) {
			if c = strings.Index(l, ":"); c < 1 {
				return "", c
			}
			return strings.TrimLeft(l[:c], " -"), c
		}
		for _, l := range lines {
			key, _ := keyOf(l)
			isKey[key] = true
		}
		nearN := 0
		for i, l := range lines {
			key, c := keyOf(l)
			if key == "" {
				continue
			}
			for vi, typed := range []string{key + "x", strings.ToUpper(key[:1]) + key[1:], strings.Replace(key, "_", "-", 1)} {
				if isKey[typed] || (i+vi)%stride != 0 || (raceDetector && i%5 != 0) {
					continue
				}
				label := fmt.Sprintf("%s: key typed %q %s", variant.name, typed, at(i))
				_, err := Parse([]byte(with(i, l[:c-len(key)]+typed+l[c:])))
				shown, d := shownForms(t, err)
				if err == nil || d == nil || len(d.Problems) == 0 {
					t.Errorf("%s: not explained (%v)", label, err)
					continue
				}
				for _, p := range d.Problems {
					shown += "\n" + p.Msg + "\n" + p.Hint + "\n" + p.Excerpt + "\n" + p.Path
				}
				typedRE := regexp.MustCompile(`(^|[^A-Za-z0-9_-])` + regexp.QuoteMeta(typed) + `($|[^A-Za-z0-9_-])`)
				if typedRE.MatchString(shown) || showsMarker(shown) {
					t.Errorf("%s: the refusal shows what was typed, or a value:\n%s", label, shown)
				}
				p := d.Problems[0]
				if p.Kind != yamldiag.KindUnknownKey || !strings.HasPrefix(p.Msg, "unknown key on this line") || p.Hint != "did you mean "+key+"?" || strings.Trim(p.Excerpt, " -") != "…" {
					t.Errorf("%s: %+v", label, p)
				}
				nearN++
			}
		}
		if want := 150; (!raceDetector && nearN < want) || nearN < want/5 {
			t.Errorf("%s: %d keys typed one character off: the property no longer exercises them", variant.name, nearN)
		}
		// Files above MaxInput get the decoder's own text: every mutation, and a file of each class
		// above, on a few lines. Nothing is validated on that path, so one of the two configs is
		// enough (each file is a megabyte to parse).
		big := 0
		for mi, m := range muts {
			if variant.plain != nil || (raceDetector && mi%5 != 0) {
				break
			}
			i := (mi * 7) % len(lines)
			for n := 0; n < len(lines); n++ {
				if rep := m.f(lines[(i+n)%len(lines)]); rep != nil {
					big++
					check(fmt.Sprintf("%s: oversize, %s at line %d", variant.name, m.name, (i+n)%len(lines)+1), with((i+n)%len(lines), rep...)+pad)
					break
				}
			}
		}
		for n, i := 0, 0; i < len(lines) && n < 12 && variant.plain == nil; i += 16 {
			l := lines[i]
			v, ok := valueStart(l)
			if !ok {
				continue
			}
			n++
			big += 4
			check(fmt.Sprintf("%s: oversize, secret under the key at line %d", variant.name, i+1), with(i, l[:v]+"ZQXpastedcanarycanarycanary")+pad)
			check(fmt.Sprintf("%s: oversize, block scalar at line %d", variant.name, i+1), with(i, l[:v]+"|", ind(l)+"    ZQXblockcanarycanary")+pad)
			check(fmt.Sprintf("%s: oversize, secret as a key at line %d", variant.name, i+1), with(i, ind(l)+keySecrets[n%len(keySecrets)]+": 1", l)+pad)
			check(fmt.Sprintf("%s: oversize, verbatim tag at line %d", variant.name, i+1), with(i, l[:v]+"!<tag:ZQXtagcanary%20into%20ZQXcanary> "+l[v:])+pad)
		}
		t.Logf("%s: %d lines, %d markers, %d mutations: %d files (%d refused), %d above MaxInput", variant.name, len(lines), len(marked), len(muts), cases, refusedN, big)
		if want := 9000; (!raceDetector && cases < want) || cases < want/5 || refusedN < cases/2 {
			t.Errorf("%s: %d files, %d refused: the property no longer exercises refusals", variant.name, cases, refusedN)
		}
		total, totalRefused = total+cases, totalRefused+refusedN
	}
	t.Logf("%d files, %d refused", total, totalRefused)
}

// Every validation message is value-free (see addFn): a config whose every text value is a marker
// and whose every number is a recognisable one is validated as decoded, and with each value changed
// to shapes that reach other checks. No message, path or Validate() text holds a marker, and no
// message names a list entry by anything but its index.
func TestValidationNeverQuotesAValue(t *testing.T) {
	for _, plain := range []map[string]string{nil, plainValues} {
		var b strings.Builder
		var marked []string
		markedYAML(reflect.TypeOf(Config{}), "", "", plain, &marked, map[string]bool{}, &b)
		lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
		variants := []string{b.String()}
		// Each text value in shapes the validators look at before they complain: an address, a
		// CIDR, a path, a URL, a hostname, an email, a header, a name — each still holding a marker.
		for i, l := range lines {
			v, ok := valueStart(l)
			if !ok {
				continue
			}
			for _, shape := range []string{
				"0.0.0.0:77077", "10.77.0.77/8", "0.0.0.0/0", "::/0", "/var/zqx/../canary", "rel/zqxcanary", "https://zqx.example/canary",
				"http://zqx.example/canary", "zqx.canary.example.com", "ZQX.Canary.Example.com", "zqx@canary.example", "X-ZQX-Canary", "Host",
				"zqxcanary", "zqx/", "/zqx/", "zqx/.canary/", "__ZQX-", "external", "enforce", "\"\"", "apps.example.com", "stg.example.net", "operator",
				// Numbers and durations below every minimum (the configs' own are above every maximum).
				"-" + numberMarker, "-" + numberMarker + "h", "0", "0s",
			} {
				out := append(append(append([]string{}, lines[:i]...), l[:v]+shape), lines[i+1:]...)
				variants = append(variants, strings.Join(out, "\n")+"\n")
			}
		}
		decoded, problems := 0, map[string]bool{}
		for n, y := range variants {
			if raceDetector && n%5 != 0 { // Intentional: a sample under -race, as in TestNoMutationShowsASecret
				continue
			}
			c := &Config{}
			if yamlStrict([]byte(y), c) != nil {
				continue
			}
			decoded++
			applyDefaults(c)
			ps := c.Problems()
			text := ""
			if err := c.Validate(); err != nil {
				text = err.Error()
			}
			for _, p := range ps {
				problems[p.Msg] = true
				text += "\n" + p.Msg + "\n" + p.Path
			}
			// "apps.example.com" and the like are plainValues: a message that quotes a domain, a
			// username or an address is caught through them too.
			for _, bad := range []string{"zqx", "canary", numberMarker, "apps.example.com", "stg.example.net", "(operator)", "(dev)", "0.0.0.0", "10.77.", "::/0", "127.0.0.1:9", "203.0.113.10"} {
				if i := strings.Index(strings.ToLower(text), bad); i >= 0 {
					t.Fatalf("a validation message holds %q from the file: %q", bad, text[max(0, i-120):min(len(text), i+80)])
				}
			}
		}
		if want := 2000; (!raceDetector && decoded < want) || decoded < want/5 || len(problems) < 60 {
			t.Errorf("%d configs validated, %d distinct messages: the test no longer exercises the validators", decoded, len(problems))
		}
	}
}

// The re-audit's reproductions (v0.34.0), each with what the refusal now says.
func TestReauditCases(t *testing.T) {
	base := validYAML(t, "session:\n  idle_timeout: 10m\nretention:\n  interval: 6h\n  events_max_rows: 5000\ncookie:\n  prefix: \"__Host-\"\ntrust_proxy: false\n"+
		"users:\n  - username: \"dev\"\n    password_hash: \"@HASH@\"\n    role: deployer\n")
	hash, err := validHash()
	if err != nil {
		t.Fatal(err)
	}
	base = strings.Replace(base, "@HASH@", hash, 1)
	if _, err := Parse([]byte(base)); err != nil {
		t.Fatalf("the base config is refused: %v", err)
	}
	const key = "ZQXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	base = strings.Replace(base, "encryption_key: \"AAA", "encryption_key: \"ZQX", 1)
	anchored := strings.Replace(base, "encryption_key: \"", "encryption_key: &k \"", 1)
	if !strings.Contains(anchored, "&k \""+key) {
		t.Fatal("the base config changed; the cases test nothing")
	}
	rep := func(y, old, repl string) string {
		t.Helper()
		if !strings.Contains(y, old) {
			t.Fatalf("no %q in the config", old)
		}
		return strings.Replace(y, old, repl, 1)
	}
	first := func(name, y string) yamldiag.Problem {
		t.Helper()
		d := mustNotShow(t, name, y)
		if d == nil || len(d.Problems) == 0 {
			t.Fatalf("%s: nothing explained", name)
		}
		for _, p := range d.Problems {
			if p.Path == "encryption_key" || strings.HasPrefix(p.Msg, "encryption_key ") {
				t.Errorf("%s: the anchor's key is blamed: %+v", name, p)
			}
		}
		return d.Problems[0]
	}
	type want struct{ path, msg, excerpt string }
	for name, c := range map[string]struct {
		y string
		want
	}{
		// 2. A validation message quoted the value: a secret reached through an alias, a hash
		// under username, a token under provider.
		"alias under bind_addr": {rep(anchored, `bind_addr: "127.0.0.1:9000"`, "") + "bind_addr: *k\n",
			want{"bind_addr", "bind_addr: must bind loopback only (127.0.0.1 / [::1]); the edge fronts the public ports", "bind_addr: …"}},
		"alias under cookie.prefix": {rep(anchored, `prefix: "__Host-"`, "prefix: *k"),
			want{"cookie.prefix", "cookie.prefix: must be __Host- or __Secure-", "  prefix: …"}},
		"alias as an ip_allowlist entry": {rep(anchored, `  - "203.0.113.10/32"`, "  - \"203.0.113.10/32\"\n  - *k"),
			want{"ip_allowlist[1]", "ip_allowlist[1]: must be an IP address or a CIDR (203.0.113.7, 203.0.113.0/24)", "  - …"}},
		"a hash under username": {rep(base, `  - username: "dev"`, `  - username: "operator"`) + "  - username: \"ZQX$argon2id$v=19$m=65536\"\n    role: boss\n",
			want{"users[0].username", "users[0]: duplicate username (already the auth owner or another user)", "  - username: …"}},
		"a block scalar under bind_addr": {rep(base, `bind_addr: "127.0.0.1:9000"`, "bind_addr: |\n  ZQXtoken"),
			want{"bind_addr", "bind_addr: must bind loopback only (127.0.0.1 / [::1]); the edge fronts the public ports", "bind_addr: …"}},
		"a token under provider": {rep(base, "  acme_email:", "  base_domain: apps.example.com\n  dns01:\n    provider: \"ZQXtokZQX\"\n    api_token: cloudflare\n  acme_email:"),
			want{"edge.dns01.provider", "edge.dns01.provider: must be a caddy DNS module name [a-z0-9._-] (e.g. cloudflare)", "    provider: …"}},
		// 3. A bad duration in a flow mapping or through an alias named the wrong key.
		"a duration in a flow mapping": {rep(base, "session:\n  idle_timeout: 10m", "session: {idle_timeout: 10m, absolute_timeout: bogus}"),
			want{"session.absolute_timeout", "session.absolute_timeout is not a valid duration: use a number and a unit like 30s, 5m, 12h or 30d", "session: …"}},
		"a duration in a flow mapping, second": {rep(base, "retention:\n  interval: 6h\n  events_max_rows: 5000", "retention: {events_max_rows: 5000, interval: bogus}"),
			want{"retention.interval", "retention.interval is not a valid duration: use a number and a unit like 30s, 5m, 12h or 30d", "retention: …"}},
		"alias under a duration": {rep(anchored, "interval: 6h", "interval: *k"),
			want{"retention.interval", "retention.interval is not a valid duration: use a number and a unit like 30s, 5m, 12h or 30d", "  interval: …"}},
		"alias under a boolean": {rep(anchored, "trust_proxy: false", "trust_proxy: *k"),
			want{"trust_proxy", "trust_proxy must be true or false", "trust_proxy: …"}},
		"alias under a number": {rep(anchored, "events_max_rows: 5000", "events_max_rows: *k"),
			want{"retention.events_max_rows", "retention.events_max_rows must be a number", "  events_max_rows: …"}},
		// 4. The decoder's text: a verbatim tag, a key holding the words that end its sentence.
		"a verbatim tag": {rep(base, "trust_proxy: false", "trust_proxy: !<tag:ZQXTopSecretTag> x"),
			want{"trust_proxy", "trust_proxy must be true or false", "trust_proxy: …"}},
		"a verbatim tag through an alias": {rep(rep(base, "encryption_key: \"", "encryption_key: &k !<tag:ZQXTopSecretTag> \""), "trust_proxy: false", "trust_proxy: *k"),
			want{"trust_proxy", "trust_proxy must be true or false", "trust_proxy: …"}},
		"a key holding the end words": {base + "\"x not found in type y ZQXTopSecretKey\": 1\n",
			want{"…", "unknown key on this line", "…"}},
		// 5. A secret shorter than 24 characters typed as a key.
		"a TOTP secret as a key":    {base + "ZQXWY3DPEHPK3PXP: totp_secret\n", want{"…", "unknown key on this line", "…"}},
		"an access key id as a key": {base + "backups:\n  AKI" + "AZQXFODNN7EXAMPLQ: access_key_id\n", want{"backups.…", "unknown key on this line in backups", "  …"}},
	} {
		p := first(name, c.y)
		if got := (want{p.Path, p.Msg, p.Excerpt}); got != c.want {
			t.Errorf("%s:\n got %+v\nwant %+v", name, got, c.want)
		}
	}
	// The spurious second problem of an alias under a boolean is gone.
	if d := mustNotShow(t, "alias under a boolean", rep(anchored, "trust_proxy: false", "trust_proxy: *k")); d == nil || len(d.Problems) != 1 {
		t.Errorf("an alias under a boolean: %+v", d)
	}
	// Above MaxInput nothing is examined and the decoder's text is all there is: still no value.
	pad := strings.Repeat("# pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad\n", 20000)
	for name, y := range map[string]string{
		"oversize, verbatim tag":    rep(base, "trust_proxy: false", "trust_proxy: !<tag:ZQXTopSecretTag> x") + pad,
		"oversize, end words key":   base + "\"x not found in type y ZQXTopSecretKey\": 1\n" + pad,
		"oversize, tag with spaces": rep(base, "trust_proxy: false", "trust_proxy: !<tag:yaml.org,2002:str%20into%20ZQXTopSecret> [x]") + pad,
	} {
		if d := mustNotShow(t, name, y); d == nil || len(d.Problems) != 0 {
			t.Errorf("%s: %+v", name, d)
		}
	}
}
