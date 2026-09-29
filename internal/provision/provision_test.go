package provision

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/compose"
)

func sampleSpec() Spec {
	return Spec{
		Slug: "shop",
		Services: []Service{{
			Name:    "web",
			Image:   "nginx:1.27",
			Ports:   []Port{{Internal: 8080, Publish: true}},
			Volumes: []Volume{{Name: "data", Target: "/var/lib/data"}, {Source: "conf", Target: "/etc/app", ReadOnly: true}},
			Env:     []EnvVar{{Key: "LOG_LEVEL", Value: "info"}, {Key: "DB_PASSWORD", Secret: "DB_PASSWORD"}},
			Restart: "unless-stopped",
		}},
	}
}

// A service's mem_limit/mem_reservation are emitted into the generated compose; unset
// fields are omitted (existing apps stay byte-identical, no cgroup cap).
func TestGenerateMemLimit(t *testing.T) {
	spec := sampleSpec()
	spec.Services[0].MemLimit = "768m"
	spec.Services[0].MemReservation = "512m"
	out, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mem_limit: 768m", "mem_reservation: 512m"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("generated compose missing %q:\n%s", want, out)
		}
	}
	bare, err := Generate(sampleSpec())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bare), "mem_limit") || strings.Contains(string(bare), "mem_reservation") {
		t.Errorf("a service with no mem fields must omit the keys:\n%s", bare)
	}
}

// ulimits.nofile is rendered as the {soft, hard} map; unset omits the key.
func TestGenerateUlimits(t *testing.T) {
	spec := sampleSpec()
	spec.Services[0].Ulimits = &Ulimits{Nofile: &NofileLimit{Soft: 1048576, Hard: 1048576}}
	out, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ulimits:", "nofile:", "soft: 1048576", "hard: 1048576"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("generated compose missing %q:\n%s", want, out)
		}
	}
	if bare, _ := Generate(sampleSpec()); strings.Contains(string(bare), "ulimits") {
		t.Errorf("a service with no ulimits must omit the key:\n%s", bare)
	}
}

// stop_grace_period is emitted into the generated compose; unset omits the key.
func TestGenerateStopGracePeriod(t *testing.T) {
	spec := sampleSpec()
	spec.Services[0].StopGracePeriod = "60s"
	out, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "stop_grace_period: 60s") {
		t.Errorf("generated compose missing stop_grace_period:\n%s", out)
	}
	if bare, _ := Generate(sampleSpec()); strings.Contains(string(bare), "stop_grace_period") {
		t.Errorf("a service with no stop_grace_period must omit the key:\n%s", bare)
	}
}

// testOnlyHealthCompose is Generate's output for a test-only healthcheck as produced BEFORE the
// timing fields existed (captured from that build). It must stay byte-identical so an existing
// app's compose is unchanged and an upgrade recreates nothing.
const testOnlyHealthCompose = `name: shop
services:
    web:
        image: nginx:1.27
        restart: unless-stopped
        ports:
            - 127.0.0.1:8080:8080
        volumes:
            - data:/var/lib/data
            - ./conf:/etc/app:ro
        environment:
            - LOG_LEVEL=info
            - DB_PASSWORD=${DB_PASSWORD}
        command:
            - nginx
            - -g
            - daemon off;
        healthcheck:
            test:
                - CMD
                - curl
                - -f
                - http://localhost:8080/health
volumes:
    data: null
`

func TestGenerateHealthcheckTestOnlyByteIdentical(t *testing.T) {
	spec := sampleSpec()
	spec.Services[0].Healthcheck = &Healthcheck{Test: []string{"curl", "-f", "http://localhost:8080/health"}}
	spec.Services[0].Command = []string{"nginx", "-g", "daemon off;"}
	out, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != testOnlyHealthCompose {
		t.Fatalf("test-only healthcheck compose changed:\n--- got\n%s\n--- want\n%s", out, testOnlyHealthCompose)
	}
}

// The timing fields render under the healthcheck only when set, in compose's key order.
func TestGenerateHealthcheckTiming(t *testing.T) {
	spec := sampleSpec()
	spec.Services[0].Healthcheck = &Healthcheck{Test: []string{"curl", "-f", "http://localhost:8080/health"},
		Interval: "10s", Timeout: "5s", Retries: 3, StartPeriod: "1m"}
	out, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	want := "        healthcheck:\n            test:\n                - CMD\n                - curl\n                - -f\n                - http://localhost:8080/health\n" +
		"            interval: 10s\n            timeout: 5s\n            retries: 3\n            start_period: 1m\n"
	if !strings.Contains(string(out), want) {
		t.Errorf("generated compose missing the timed healthcheck:\n%s", out)
	}
	if res := compose.ValidateBytes(out, compose.Env{}, "/srv/apps/shop", compose.Options{}); !res.OK() {
		t.Fatalf("timed healthcheck compose failed §5.6: %s", res.Error())
	}
	// Only the fields that are set are emitted.
	spec.Services[0].Healthcheck = &Healthcheck{Test: []string{"curl"}, Retries: 5}
	out, _ = Generate(spec)
	if !strings.Contains(string(out), "retries: 5") || strings.Contains(string(out), "interval") ||
		strings.Contains(string(out), "timeout") || strings.Contains(string(out), "start_period") {
		t.Errorf("unset timing fields must be omitted:\n%s", out)
	}
	// No healthcheck (nil or empty test) emits no key.
	for _, hc := range []*Healthcheck{nil, {}} {
		spec.Services[0].Healthcheck = hc
		if bare, _ := Generate(spec); strings.Contains(string(bare), "healthcheck") {
			t.Errorf("%+v must not emit a healthcheck:\n%s", hc, bare)
		}
	}
}

// The generated compose is safe by construction AND passes the §5.6 chokepoint.
func TestGenerateProducesSafeComposeThatPassesValidator(t *testing.T) {
	out, err := Generate(sampleSpec())
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "image: nginx:1.27") {
		t.Errorf("missing image:\n%s", s)
	}
	// Loopback-bound publish by default (not 0.0.0.0).
	if !strings.Contains(s, "127.0.0.1:8080:8080") {
		t.Errorf("port not loopback-bound:\n%s", s)
	}
	// Non-secret literals are inline; secrets are by-reference (${NAME}), never valued.
	if !strings.Contains(s, "LOG_LEVEL=info") {
		t.Errorf("literal env not inline:\n%s", s)
	}
	if !strings.Contains(s, "DB_PASSWORD=${DB_PASSWORD}") {
		t.Errorf("secret env not by-reference:\n%s", s)
	}
	// Must pass §5.6 against a run dir.
	res := compose.ValidateBytes(out, compose.Env{}, "/srv/apps/shop", compose.Options{})
	if !res.OK() {
		t.Fatalf("generated compose failed §5.6: %s", res.Error())
	}
}

// A udp protocol is emitted as a /udp suffix; tcp/"" stay bare so existing
// (no-protocol) apps render byte-identically. A DNS resolver can publish both.
func TestGeneratePortProtocol(t *testing.T) {
	spec := sampleSpec()
	spec.Services[0].Ports = []Port{
		{Internal: 53, Publish: true, Public: true, Protocol: "udp"},
		{Internal: 53, Publish: true, Public: true, Protocol: "tcp"},
		{Internal: 8080, Publish: true}, // no protocol → bare mapping (backward compat)
	}
	out, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "53:53/udp") {
		t.Errorf("missing udp mapping:\n%s", s)
	}
	if !strings.Contains(s, "53:53/tcp") {
		t.Errorf("missing tcp mapping:\n%s", s)
	}
	if !strings.Contains(s, "127.0.0.1:8080:8080") || strings.Contains(s, "8080:8080/") {
		t.Errorf("no-protocol port should stay a bare loopback mapping:\n%s", s)
	}
	// The generated compose must still pass §5.6 (the validator tolerates /proto).
	if res := compose.ValidateBytes(out, compose.Env{}, "/srv/apps/shop", compose.Options{}); !res.OK() {
		t.Fatalf("udp compose failed §5.6: %s", res.Error())
	}
}

// A distinct `published` host port maps host→container (e.g. publish 853 to a
// container listening on 8853), so a non-root container can serve a privileged
// host port without cap_add or running as root. Unset → host==container.
func TestGeneratePublishedHostPort(t *testing.T) {
	spec := sampleSpec()
	spec.Services[0].Ports = []Port{
		{Internal: 8853, Published: 853, Publish: true, Public: true, Protocol: "tcp"},
		{Internal: 8080, Publish: true}, // no published → host==container (8080:8080)
	}
	out, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "853:8853/tcp") {
		t.Errorf("published host port should map 853→8853:\n%s", s)
	}
	if !strings.Contains(s, "127.0.0.1:8080:8080") {
		t.Errorf("port without published must stay host==container:\n%s", s)
	}
	if res := compose.ValidateBytes(out, compose.Env{}, "/srv/apps/shop", compose.Options{}); !res.OK() {
		t.Fatalf("published-port compose failed §5.6: %s", res.Error())
	}
}

// Public publish binds all interfaces only when explicitly acked.
func TestGeneratePublicPortBindsAllInterfaces(t *testing.T) {
	spec := sampleSpec()
	spec.Services[0].Ports = []Port{{Internal: 8080, Publish: true, Public: true}}
	out, _ := Generate(spec)
	if strings.Contains(string(out), "127.0.0.1:8080") {
		t.Error("public port should not be loopback-bound")
	}
	if !strings.Contains(string(out), "8080:8080") {
		t.Errorf("public port mapping missing:\n%s", out)
	}
}

func TestValidateRejectsBadInput(t *testing.T) {
	cases := map[string]func(*Spec){
		"bad slug":             func(s *Spec) { s.Slug = "Bad Slug" },
		"empty tag":            func(s *Spec) { s.Services[0].Image = "nginx" },
		"control port":         func(s *Spec) { s.Services[0].Ports = []Port{{Internal: 9000, Publish: true}} },
		"published control":    func(s *Spec) { s.Services[0].Ports = []Port{{Internal: 8853, Published: 2375, Publish: true}} },
		"abs bind":             func(s *Spec) { s.Services[0].Volumes = []Volume{{Source: "/etc", Target: "/x"}} },
		"traversal bind":       func(s *Spec) { s.Services[0].Volumes = []Volume{{Source: "../escape", Target: "/x"}} },
		"both name+source":     func(s *Spec) { s.Services[0].Volumes = []Volume{{Name: "v", Source: "s", Target: "/x"}} },
		"rel container target": func(s *Spec) { s.Services[0].Volumes = []Volume{{Name: "v", Target: "rel"}} },
		"bad env key":          func(s *Spec) { s.Services[0].Env = []EnvVar{{Key: "1BAD"}} },
		"env literal interp":   func(s *Spec) { s.Services[0].Env = []EnvVar{{Key: "X", Value: "${OTHER}"}} },
		"unknown depends_on":   func(s *Spec) { s.Services[0].DependsOn = []string{"ghost"} },
		"bad restart":          func(s *Spec) { s.Services[0].Restart = "sometimes" },
		"newline in command":   func(s *Spec) { s.Services[0].Command = []string{"sh\n-c"} },
		"newline in health":    func(s *Spec) { s.Services[0].Healthcheck = &Healthcheck{Test: []string{"curl\n-f"}} },
		"empty health arg":     func(s *Spec) { s.Services[0].Healthcheck = &Healthcheck{Test: []string{"curl", ""}} },
		"health timing no test": func(s *Spec) {
			s.Services[0].Healthcheck = &Healthcheck{Interval: "10s"}
		},
		"colon in bind source": func(s *Spec) { s.Services[0].Volumes = []Volume{{Source: "a:b", Target: "/x"}} },
		"colon in target":      func(s *Spec) { s.Services[0].Volumes = []Volume{{Name: "v", Target: "/x:y"}} },
	}
	for name, mut := range cases {
		s := sampleSpec()
		mut(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

// The generator has no field for dangerous keys; even a maximal spec can't emit
// them. (Belt: scan the output for the forbidden set.)
func TestGenerateNeverEmitsDangerousKeys(t *testing.T) {
	out, err := Generate(sampleSpec())
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"privileged", "cap_add", "devices", "network_mode", "pid:", "security_opt", "/var/run/docker.sock"} {
		if strings.Contains(string(out), bad) {
			t.Errorf("generated compose contains forbidden token %q:\n%s", bad, out)
		}
	}
}

// Commit writes atomically and is replaceable; a half-written staging dir never
// becomes the app, and SweepStaging cleans leftovers.
func TestCommitAtomicAndSweep(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "shop")
	files := []File{{RelPath: "docker-compose.yml", Data: []byte("services: {}\n")}}
	if err := Commit(root, runDir, files); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(runDir, "docker-compose.yml")); err != nil || !strings.Contains(string(b), "services") {
		t.Fatalf("compose not committed: %v %q", err, b)
	}
	// Re-commit (update) replaces atomically.
	files2 := []File{{RelPath: "docker-compose.yml", Data: []byte("services:\n  v2: {}\n")}}
	if err := Commit(root, runDir, files2); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(runDir, "docker-compose.yml"))
	if !strings.Contains(string(b), "v2") {
		t.Errorf("update did not replace: %q", b)
	}
	// No staging/aside leftovers after a clean commit.
	leftovers := stagingLeftovers(t, root)
	if leftovers != 0 {
		t.Errorf("%d staging/aside dirs left after commit", leftovers)
	}
	// Sweep removes a planted stale staging dir.
	os.Mkdir(filepath.Join(root, ".staging-abc"), 0o700)
	os.Mkdir(filepath.Join(root, ".old-xyz"), 0o700)
	SweepStaging(root)
	if stagingLeftovers(t, root) != 0 {
		t.Error("sweep did not remove stale dirs")
	}
}

func TestCommitRejectsTraversalArtifact(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "shop")
	err := Commit(root, runDir, []File{{RelPath: "../../etc/evil", Data: []byte("x")}})
	if err == nil {
		t.Fatal("traversal artifact path should be rejected")
	}
	if _, statErr := os.Stat(runDir); statErr == nil {
		t.Error("run dir should not exist after a rejected commit")
	}
}

func stagingLeftovers(t *testing.T, root string) int {
	t.Helper()
	entries, _ := os.ReadDir(root)
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".staging-") || strings.HasPrefix(e.Name(), ".old-") {
			n++
		}
	}
	return n
}
