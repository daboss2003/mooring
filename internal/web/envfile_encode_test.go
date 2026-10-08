package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/compose"
	"github.com/daboss2003/mooring/internal/envstore"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/secret"
)

// envValueCorpus is every awkward value class an env-file encoding has to survive: compose's
// `$` expansion and `$$` escape, inline `#` comments, both quote characters, backslash escapes
// (including the `\'` the single-quote scanner unescapes and a trailing `\` that would swallow a
// closing quote), whitespace trimming, `=`, unicode, and line breaks.
var envValueCorpus = []string{
	"plain",
	"pa$$word",
	"pa$word",
	"$",
	"$$$",
	"a #b",
	"#x",
	"a # b #c",
	"it's",
	"'",
	"''",
	`a\b`,
	`ends\`,
	`ends\\`,
	`\'`,
	`x\'y`,
	`"q"`,
	`"`,
	`\"`,
	"`cmd` $(sub)",
	"${X}",
	"$X",
	"${X:-def}",
	`\$X`,
	`\\$X`,
	`\n`,
	`\0123`,
	`\a\t\v`,
	"ünï=c✓ 日本",
	"tab\there",
	"  lead",
	"trail  ",
	" ",
	"a=b=c",
	"",
	"l1\nl2",
	"cr\rx",
	"\r",
	"\n",
	"crlf\r\n",
	"\u0085nel\u00a0nbsp",
	`mix '"$\ #` + "\n",
}

// The rule itself is pinned: single quotes for a value with no `'`, `\`, LF or CR; double quotes
// with \\ \" $$ \n \r escapes otherwise.
func TestEncodeEnvFileValueRule(t *testing.T) {
	cases := map[string]string{
		"plain":    `'plain'`,
		"pa$$word": `'pa$$word'`,
		"a #b":     `'a #b'`,
		"":         `''`,
		"it's$x":   `"it's$$x"`,
		`ends\`:    `"ends\\"`,
		`x\'y`:     `"x\\'y"`,
		"a\"b\n\r": `"a\"b\n\r"`,
	}
	for in, want := range cases {
		got, err := encodeEnvFileValue(in)
		if err != nil || got != want {
			t.Errorf("encode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

// Every corpus value must decode back byte-for-byte under BOTH generations of compose-go's
// dotenv scanner (the one in Compose v2.20's compose-go v1.18 and the current one), without
// leaving anything for compose to expand.
func TestEncodeEnvFileValueRoundTripsReferenceParsers(t *testing.T) {
	for _, v := range envValueCorpus {
		enc, err := encodeEnvFileValue(v)
		if err != nil {
			t.Fatalf("encode(%q): %v", v, err)
		}
		for _, p := range []struct {
			name string
			fn   func(string) (string, string, error)
		}{{"compose-go v2", refQuotedV2}, {"compose-go v1.18", refQuotedV1}} {
			got, rest, err := p.fn(enc + "\n")
			if err != nil {
				t.Errorf("%s: %q encoded as %s: %v", p.name, v, enc, err)
				continue
			}
			if got != v || rest != "\n" {
				t.Errorf("%s: %q encoded as %s reads back as %q (rest %q)", p.name, v, enc, got, rest)
			}
		}
	}
}

func TestEnvFileBodyNULFailsNamingKeyOnly(t *testing.T) {
	_, _, err := envFileBody(compose.Env{"OK": "fine", "BAD_KEY": "s3kr1t\x00value"})
	if err == nil || !errors.Is(err, errEnvValueNUL) {
		t.Fatalf("a NUL byte must fail the render, got %v", err)
	}
	if !strings.Contains(err.Error(), "BAD_KEY") || strings.Contains(err.Error(), "s3kr1t") {
		t.Fatalf("error must name the key and never the value: %v", err)
	}
}

// renderEnvFile surfaces the encode error and leaves no file behind.
func TestRenderEnvFileNULIsAnError(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.cfg.DataDir = t.TempDir()
	if _, err := e.srv.envStore.Save(context.Background(), "shop", []envstore.Entry{{Key: "K", Value: secret.New("v")}}, "op"); err != nil {
		t.Fatal(err)
	}
	app := &monitor.App{Project: "shop", WorkingDir: "/srv/shop"}
	p, c, err := e.srv.renderEnvFile(app, compose.Env{"K": "v", "FROM_DOTENV": "a\x00b"})
	defer c()
	if err == nil || p != "" || !strings.Contains(err.Error(), "FROM_DOTENV") {
		t.Fatalf("render with a NUL value = %q, %v; want an error naming FROM_DOTENV", p, err)
	}
	if left, _ := filepath.Glob(filepath.Join(e.srv.cfg.DataDir, "envfiles", "*")); len(left) != 0 {
		t.Fatalf("a failed render left files behind: %v", left)
	}
}

// The reported bug: a stored `pa$$word` reached the container as `pa`. Store values are literal
// in composeEnv — never expanded and never re-scanned when a .env value references them — while
// .env values keep compose syntax.
func TestComposeEnvKeepsStoredValuesLiteral(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	ctx := context.Background()
	if _, err := e.srv.envStore.Save(ctx, "shop", []envstore.Entry{
		{Key: "PW", Value: secret.New("pa$$word"), Secret: true},
		{Key: "TOK", Value: secret.New("a$b"), Secret: true},
		{Key: "BRACE", Value: secret.New("${X}"), Secret: false},
		{Key: "EMPTY", Value: secret.New(""), Secret: true},
	}, "op"); err != nil {
		t.Fatal(err)
	}
	wd := t.TempDir()
	dotenv := "PW=from-file\nURL=pg://u:${PW}@db\nESC=x$$y\nREF=${TOK}\nCHAIN=${URL}/x\nX=xv\n"
	if err := os.WriteFile(filepath.Join(wd, ".env"), []byte(dotenv), 0o600); err != nil {
		t.Fatal(err)
	}
	env := e.srv.composeEnv(&monitor.App{Project: "shop", WorkingDir: wd})
	want := map[string]string{
		"PW":    "pa$$word",           // stored, literal; overrides the .env PW
		"TOK":   "a$b",                // stored, literal
		"BRACE": "${X}",               // stored, literal — not expanded from the .env X
		"EMPTY": "",                   // stored empty value
		"URL":   "pg://u:pa$$word@db", // .env value; the stored value is inserted as-is
		"ESC":   "x$y",                // .env value: `$$` is compose's escaped `$`
		"REF":   "a$b",                // not re-scanned after substitution
		"CHAIN": "pg://u:pa$$word@db/x",
		"X":     "xv",
	}
	for k, w := range want {
		if got, ok := env[k]; !ok || got != w {
			t.Errorf("%s = %q (present %v), want %q", k, got, ok, w)
		}
	}
	// The validator interpolates the generated compose with this env: it sees the stored bytes.
	if got := compose.Interpolate("- DB_PASSWORD=${PW}", env); got != "- DB_PASSWORD=pa$$word" {
		t.Errorf("validator view of the secret ref = %q", got)
	}
}

// A reference cycle in .env values resolves deterministically (to "" for the back edge) and
// never loops.
func TestMergeEnvCycleIsDeterministic(t *testing.T) {
	for i := 0; i < 20; i++ {
		out := mergeEnv(compose.Env{"A": "x${B}", "B": "y${A}", "SELF": "${SELF}z"}, nil)
		if out["A"] != "xy" || out["B"] != "y" || out["SELF"] != "z" {
			t.Fatalf("cycle resolution = A:%q B:%q SELF:%q", out["A"], out["B"], out["SELF"])
		}
	}
}

func TestEnvRefsGrammar(t *testing.T) {
	got := envRefs("a$$b ${C} $D_1x ${E:-f} ${G-h} $ $9 ${I?msg} $$J ${unterminated")
	want := []string{"C", "D_1x", "E", "G", "I"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("envRefs = %v, want %v", got, want)
	}
}

// The encoder against the real parser: every corpus value, written by envFileBody, must come
// back from `docker compose config` byte-for-byte. Skipped when docker isn't installed; needs no
// daemon. See composeEnvReadback for how the readback is made exact.
func TestEnvFileRoundTripsThroughDockerCompose(t *testing.T) {
	requireDockerCompose(t)
	env := compose.Env{}
	var keys []string
	for i, v := range envValueCorpus {
		k := fmt.Sprintf("MOORING_ENC_%02d", i)
		env[k] = v
		keys = append(keys, k)
	}
	body, _, err := envFileBody(env)
	if err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(t.TempDir(), "probe.env")
	if err := os.WriteFile(envFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := composeEnvReadback(t, envFile, keys)
	for _, k := range keys {
		if got[k] != env[k] {
			t.Errorf("%s: wrote %q, compose read %q", k, env[k], got[k])
		}
	}
}

// The full deploy path for stored values: store → composeEnv → renderEnvFile → compose.
func TestStoredEnvReachesComposeExactly(t *testing.T) {
	requireDockerCompose(t)
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.cfg.DataDir = t.TempDir()
	var entries []envstore.Entry
	var keys []string
	want := map[string]string{}
	for i, v := range envValueCorpus {
		if strings.ContainsAny(v, "\x00\n\r") {
			continue // the store refuses these on save
		}
		k := fmt.Sprintf("MOORING_ST_%02d", i)
		entries = append(entries, envstore.Entry{Key: k, Value: secret.New(v), Secret: i%2 == 0})
		keys = append(keys, k)
		want[k] = v
	}
	if _, err := e.srv.envStore.Save(context.Background(), "shop", entries, "op"); err != nil {
		t.Fatal(err)
	}
	app := &monitor.App{Project: "shop", WorkingDir: t.TempDir()}
	p, c, err := e.srv.renderEnvFile(app, e.srv.composeEnv(app))
	if err != nil || p == "" {
		t.Fatalf("render: %q %v", p, err)
	}
	defer c()
	got := composeEnvReadback(t, p, keys)
	for _, k := range keys {
		if got[k] != want[k] {
			t.Errorf("%s: stored %q, compose read %q", k, want[k], got[k])
		}
	}
}

func requireDockerCompose(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	if err := exec.Command("docker", "compose", "version").Run(); err != nil {
		t.Skip("docker compose not available")
	}
}

// composeEnvReadback runs `docker compose config --format json` (no daemon needed) over a probe
// compose file whose environment is `- K=${K}` for each key, with envFile as --env-file, and
// returns the values compose would give the container. Hermetic: a temp project dir (no .env), a
// fixed probe project name, and a process environment of only PATH and HOME, so no inherited
// variable can shadow an env-file key. config prints a literal `$` as `$$` (its output is itself
// a compose file); the MOORING_CAL entry (`a$$b` in the file, true value `a$b`) shows whether this
// compose version does that, and the readback undoes it only then.
func composeEnvReadback(t *testing.T, envFile string, keys []string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("name: mooring-envprobe\nservices:\n  probe:\n    image: alpine:3\n    environment:\n      - MOORING_CAL=a$$b\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "      - %s=${%s}\n", k, k)
	}
	cf := filepath.Join(dir, "compose.yml")
	if err := os.WriteFile(cf, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("docker", "compose", "-p", "mooring-envprobe", "--project-directory", dir, "-f", cf, "--env-file", envFile, "config", "--format", "json")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker compose config: %v\n%s", err, stderr.String())
	}
	var doc struct {
		Services map[string]struct {
			Environment map[string]*string `json:"environment"`
		} `json:"services"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("decode config json: %v", err)
	}
	raw := doc.Services["probe"].Environment
	cal := raw["MOORING_CAL"]
	if cal == nil || (*cal != "a$b" && *cal != "a$$b") {
		t.Fatalf("calibration entry read back as %v", cal)
	}
	escaped := *cal == "a$$b"
	got := map[string]string{}
	for _, k := range keys {
		if v := raw[k]; v != nil {
			s := *v
			if escaped {
				s = strings.ReplaceAll(s, "$$", "$")
			}
			got[k] = s
		}
	}
	return got
}

// refQuotedV2 mirrors compose-go v2's dotenv extractVarValue for a quoted value (a backslash
// before the quote character is dropped; any other backslash is kept, then a double-quoted value
// goes through escape expansion and variable substitution). It returns the value and the rest.
func refQuotedV2(src string) (string, string, error) {
	if src == "" || src[0] != '\'' && src[0] != '"' {
		return "", "", errors.New("not quoted")
	}
	quote := src[0]
	prev := false
	var chars []byte
	for i := 1; i < len(src); i++ {
		c := src[i]
		if c != quote {
			if !prev && c == '\\' {
				prev = true
				continue
			}
			if prev {
				prev = false
				chars = append(chars, '\\')
			}
			chars = append(chars, c)
			continue
		}
		if prev {
			prev = false
			chars = append(chars, c)
			continue
		}
		v := string(chars)
		if quote == '"' {
			var err error
			if v, err = refSubstitute(refExpandEscapes(v)); err != nil {
				return "", "", err
			}
		}
		return v, src[i+1:], nil
	}
	return "", "", errors.New("unterminated quoted value")
}

// refQuotedV1 mirrors compose-go v1.18 (Compose v2.20): the value is the raw text between the
// quotes; only a double-quoted value is processed.
func refQuotedV1(src string) (string, string, error) {
	if src == "" || src[0] != '\'' && src[0] != '"' {
		return "", "", errors.New("not quoted")
	}
	quote := src[0]
	prev := false
	for i := 1; i < len(src); i++ {
		if c := src[i]; c != quote {
			prev = !prev && c == '\\'
			continue
		}
		if prev {
			prev = false
			continue
		}
		v := src[1:i]
		if quote == '"' {
			var err error
			if v, err = refSubstitute(refExpandEscapes(v)); err != nil {
				return "", "", err
			}
		}
		return v, src[i+1:], nil
	}
	return "", "", errors.New("unterminated quoted value")
}

var refEscapeSeq = regexp.MustCompile(`(\\(?:[abcfnrtv$"\\]|0\d{0,3}))`)

// refExpandEscapes is compose-go's expandEscapes.
func refExpandEscapes(s string) string {
	return refEscapeSeq.ReplaceAllStringFunc(s, func(m string) string {
		if m == `\$` {
			return "$$"
		}
		if strings.HasPrefix(m, `\0`) {
			m = strings.Replace(m, `\0`, `\`, 1)
		}
		v, _, _, err := strconv.UnquoteChar(m, '"')
		if err != nil {
			return m
		}
		return string(v)
	})
}

// refSubstitute is compose's template substitution restricted to what an encoded value may
// contain: `$$` is a literal `$`; any other `$` would expand a variable (or be a template error),
// which the encoder must never produce.
func refSubstitute(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 < len(s) && s[i+1] == '$' {
			b.WriteByte('$')
			i++
			continue
		}
		return "", fmt.Errorf("unescaped $ at byte %d would be expanded", i)
	}
	return b.String(), nil
}
