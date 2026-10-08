package provision

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/compose"
	"gopkg.in/yaml.v3"
)

// envLiterals are literal env values that compose's interpolation would otherwise rewrite.
var envLiterals = map[string]string{
	"A_DOLLAR":   "a$b",
	"A_ESCAPED":  "x$$y",
	"A_TRAILING": "cost$",
	"A_MANY":     "$$$",
	"A_PLAIN":    "plain value # not a comment",
	"A_BRACEISH": "$ {x}",
	"A_PADDED":   "  padded $x  ",
	"A_QUOTES":   `it's "q" \ back`,
}

func envSpec() Spec {
	s := sampleSpec()
	s.Services[0].Env = nil
	for k, v := range envLiterals {
		s.Services[0].Env = append(s.Services[0].Env, EnvVar{Key: k, Value: v})
	}
	s.Services[0].Env = append(s.Services[0].Env,
		EnvVar{Key: "DB_PASSWORD", Secret: "DB_PASSWORD"},
		EnvVar{Key: "OPT", Secret: "OPT_SECRET", Optional: true})
	return s
}

// generatedEnv returns the generated compose's environment entries for service web.
func generatedEnv(t *testing.T, out []byte) []string {
	t.Helper()
	var doc struct {
		Services map[string]struct {
			Environment []string `yaml:"environment"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Services["web"].Environment
}

// Literal values are emitted with `$` escaped as `$$`; a secret ref is ${NAME}; an optional one
// is ${NAME:-}.
func TestGenerateEnvEscapesLiteralsAndRendersRefs(t *testing.T) {
	out, err := Generate(envSpec())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range generatedEnv(t, out) {
		got[e] = true
	}
	for _, want := range []string{
		"A_DOLLAR=a$$b", "A_ESCAPED=x$$$$y", "A_TRAILING=cost$$", "A_MANY=$$$$$$",
		"A_PLAIN=plain value # not a comment", "A_BRACEISH=$$ {x}", "A_PADDED=  padded $$x  ",
		"DB_PASSWORD=${DB_PASSWORD}", "OPT=${OPT_SECRET:-}",
	} {
		if !got[want] {
			t.Errorf("generated environment missing %q:\n%s", want, out)
		}
	}
	// Mooring's own validator interpolates the compose the same way compose does: it sees the
	// literal exactly as written.
	interp := compose.Interpolate(string(out), compose.Env{"DB_PASSWORD": "s"})
	for _, e := range generatedEnv(t, []byte(interp)) {
		k, v, _ := strings.Cut(e, "=")
		if w, ok := envLiterals[k]; ok && v != w {
			t.Errorf("validator view of %s = %q, want %q", k, v, w)
		}
	}
}

func TestValidateRejectsOptionalLiteral(t *testing.T) {
	s := sampleSpec()
	s.Services[0].Env = []EnvVar{{Key: "X", Value: "v", Optional: true}}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "optional") {
		t.Fatalf("optional on a literal must be rejected, got %v", err)
	}
}

// The real compose reads every literal back exactly, and an unset optional ref as "" without a
// warning. Skipped when docker isn't installed; `config` needs no daemon.
func TestGeneratedEnvLiteralsRoundTripThroughDockerCompose(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	if err := exec.Command("docker", "compose", "version").Run(); err != nil {
		t.Skip("docker compose not available")
	}
	spec := envSpec()
	// Calibration: config prints a literal `$` as `$$` on the compose versions that re-escape
	// their output; MOORING_CAL's true value is `a$b`.
	spec.Services[0].Env = append(spec.Services[0].Env, EnvVar{Key: "MOORING_CAL", Value: "a$b"})
	out, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cf := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(cf, out, 0o600); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(dir, "probe.env")
	if err := os.WriteFile(envFile, []byte("DB_PASSWORD='s'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("docker", "compose", "-p", "mooring-envprobe", "--project-directory", dir, "-f", cf, "--env-file", envFile, "config", "--format", "json")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker compose config: %v\n%s", err, stderr.String())
	}
	if strings.Contains(stderr.String(), "OPT_SECRET") {
		t.Errorf("an optional ref must not warn about the unset variable:\n%s", stderr.String())
	}
	var doc struct {
		Services map[string]struct {
			Environment map[string]*string `json:"environment"`
		} `json:"services"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	env := doc.Services["web"].Environment
	read := func(k string) string {
		if env[k] == nil {
			return "<unset>"
		}
		return *env[k]
	}
	escaped := read("MOORING_CAL") == "a$$b"
	if !escaped && read("MOORING_CAL") != "a$b" {
		t.Fatalf("calibration entry read back as %q", read("MOORING_CAL"))
	}
	for k, want := range envLiterals {
		got := read(k)
		if escaped {
			got = strings.ReplaceAll(got, "$$", "$")
		}
		if got != want {
			t.Errorf("%s: declared %q, compose read %q", k, want, got)
		}
	}
	if got := read("OPT"); got != "" {
		t.Errorf("unset optional ref = %q, want empty", got)
	}
}
