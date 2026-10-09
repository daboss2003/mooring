package dockerexec

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJobArgvIsStaticAndTerminated(t *testing.T) {
	j := Job{
		Project:     "shop",
		Dir:         "/srv/shop",
		ConfigFiles: []string{"/srv/shop/docker-compose.yml", "/srv/shop/override.yml"},
		Action:      []string{"up", "-d", "--force-recreate"},
		Service:     "web",
	}
	got := strings.Join(j.argv(), " ")
	want := "compose -p shop --project-directory /srv/shop -f /srv/shop/docker-compose.yml -f /srv/shop/override.yml up -d --force-recreate -- web"
	if got != want {
		t.Errorf("argv:\n got %q\nwant %q", got, want)
	}
}

// The docker exec env must disable BuildKit default attestations, or a fully-cached
// `compose up --build` re-exports a new image digest each deploy and needlessly
// recreates unchanged build-services.
func TestMinimalEnvDisablesAttestations(t *testing.T) {
	found := false
	for _, kv := range minimalEnv() {
		if kv == "BUILDX_NO_DEFAULT_ATTESTATIONS=1" {
			found = true
		}
	}
	if !found {
		t.Errorf("minimalEnv() must set BUILDX_NO_DEFAULT_ATTESTATIONS=1, got %v", minimalEnv())
	}
}

// Compose reads its own settings from an env file (or the repo's committed .env) unless the process
// environment defines them. minimalEnv must pin the dangerous ones — and a host value must never leak
// through in their place.
func TestMinimalEnvPinsComposeSettings(t *testing.T) {
	t.Setenv("COMPOSE_PROFILES", "mooring-scheduled")
	t.Setenv("DOCKER_DEFAULT_PLATFORM", "linux/amd64")
	env := minimalEnv()
	want := map[string]string{
		"COMPOSE_PROFILES":        "",
		"COMPOSE_COMPATIBILITY":   "false",
		"COMPOSE_IGNORE_ORPHANS":  "false",
		"DOCKER_DEFAULT_PLATFORM": "",
	}
	seen := map[string]int{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		if w, ok := want[k]; ok {
			seen[k]++
			if v != w {
				t.Errorf("%s=%q, want %q", k, v, w)
			}
		}
	}
	for k := range want {
		if seen[k] != 1 {
			t.Errorf("%s must appear exactly once in minimalEnv (got %d): %v", k, seen[k], env)
		}
	}
}

// A one-off's command arguments go AFTER `-- <service>`, so compose hands them to the container
// verbatim (`--rm -x` included) and never parses them as its own flags. Without a service they are
// dropped: they could only land where compose reads flags.
func TestJobArgsFollowTheServiceTerminator(t *testing.T) {
	j := Job{Project: "shop", ConfigFiles: []string{"/c.yml"}, Action: []string{"run", "--rm", "--no-deps", "-T"},
		Service: "api", Args: []string{"node", "--rm", "-x", "--", "--entrypoint=sh"}}
	got := strings.Join(j.argv(), " ")
	want := "compose -p shop -f /c.yml run --rm --no-deps -T -- api node --rm -x -- --entrypoint=sh"
	if got != want {
		t.Errorf("argv:\n got %q\nwant %q", got, want)
	}
	argv := j.argv()
	term := -1
	for i, a := range argv {
		if a == "--" {
			term = i
			break
		}
	}
	if term < 0 || argv[term+1] != "api" {
		t.Fatalf("the service must directly follow the first --: %q", argv)
	}
	for _, a := range argv[:term] {
		if a == "node" || a == "-x" || a == "--entrypoint=sh" {
			t.Errorf("a command argument %q appears before `-- <service>`: %q", a, argv)
		}
	}
	j.Service = ""
	if got := strings.Join(j.argv(), " "); got != "compose -p shop -f /c.yml run --rm --no-deps -T" {
		t.Errorf("args without a service must be dropped, got %q", got)
	}
}

// Tag and untag take only a full image id and a compose-style reference, so no value can smuggle an
// option or a second image into `docker tag` / `docker rmi`.
func TestImageTagValidation(t *testing.T) {
	id := "sha256:" + strings.Repeat("ab", 32)
	if argv, err := tagArgv(id, "shop-api"); err != nil || strings.Join(argv, " ") != "tag -- "+id+" shop-api" {
		t.Errorf("tag argv = %q, %v", argv, err)
	}
	if argv, err := tagArgv(id, "shop-api:mooring-previous"); err != nil || argv[len(argv)-1] != "shop-api:mooring-previous" {
		t.Errorf("a tagged reference must be accepted: %q, %v", argv, err)
	}
	for _, bad := range [][2]string{
		{"-f", "shop-api"},
		{"sha256:" + strings.Repeat("ab", 31), "shop-api"},
		{"shop-api", "shop-api"},
		{id + " x", "shop-api"},
		{id, "-x"},
		{id, "--help"},
		{id, "shop api"},
		{id, "shop-api;rm"},
		{id, "registry.example.com/shop-api"},
		{id, "Shop-api"},
		{id, ""},
		{id, "shop-api:"},
		{id, "shop-api:-x"},
		{id, id},
	} {
		if _, err := tagArgv(bad[0], bad[1]); err == nil {
			t.Errorf("tagArgv(%q, %q) must be refused", bad[0], bad[1])
		}
	}
	if argv, err := untagArgv("shop-api:mooring-previous"); err != nil || strings.Join(argv, " ") != "rmi -- shop-api:mooring-previous" {
		t.Errorf("untag argv = %q, %v", argv, err)
	}
	for _, bad := range []string{"shop-api", "shop-api:latest", "-f", id, "shop-api:mooring-previous -f", "--force"} {
		if _, err := untagArgv(bad); err == nil {
			t.Errorf("untagArgv(%q) must be refused (only an explicit non-latest tag can be removed)", bad)
		}
	}
	r := NewRunner(NewSemaphore(), false, "test")
	if err := r.TagImageHeld(context.Background(), id, "shop-api", nil); err != ErrWritePlaneDisabled {
		t.Errorf("tag on a disabled write plane: %v", err)
	}
}

func TestJobArgvIncludesEnvFile(t *testing.T) {
	j := Job{Project: "shop", ConfigFiles: []string{"/c.yml"}, EnvFile: "/run/x.env", Action: []string{"up", "-d"}}
	got := strings.Join(j.argv(), " ")
	want := "compose -p shop -f /c.yml --env-file /run/x.env up -d"
	if got != want {
		t.Errorf("argv with env-file:\n got %q\nwant %q", got, want)
	}
}

func TestValidVolumeName(t *testing.T) {
	for _, ok := range []string{"shop_data", "app-1_db", "a.b_c", "X9"} {
		if !validVolumeName(ok) {
			t.Errorf("%q should be a valid volume name", ok)
		}
	}
	for _, bad := range []string{"", "-x", "a b", "a;b", "a/b", "a$b", "a\nb", "--rm"} {
		if validVolumeName(bad) {
			t.Errorf("%q must be rejected (argv/option smuggling)", bad)
		}
	}
}

func TestWritePlaneGate(t *testing.T) {
	if ok, _ := WritePlaneGate(2<<30, 0, 0); !ok {
		t.Error("2 GiB should arm the write plane")
	}
	// A genuine "1 GB" VPS reports MemTotal a little under 1 GiB — it must NOT trip the gate.
	if ok, _ := WritePlaneGate(987<<20, 0, 0); !ok {
		t.Error("a real 1 GB box (987 MiB, no swap) must arm — the floor is decimal-GB, not 1 GiB")
	}
	// Swap counts: a small box with swap clears the floor.
	if ok, _ := WritePlaneGate(700<<20, 1<<30, 0); !ok {
		t.Error("700 MiB RAM + 1 GiB swap should arm (swap counts toward the gate)")
	}
	// Genuinely tiny (no swap) is still gated by default.
	if ok, reason := WritePlaneGate(512<<20, 0, 0); ok || reason == "" {
		t.Errorf("512 MiB, no swap should disable the write plane, got ok=%v", ok)
	}
	// The operator override lets a small box arm at their own risk.
	if ok, _ := WritePlaneGate(512<<20, 0, 400<<20); !ok {
		t.Error("a 400 MB floor override should arm a 512 MiB box")
	}
	if ok, _ := WritePlaneGate(0, 0, 0); !ok {
		t.Error("unknown RAM (0) should arm with a caveat (dev)")
	}
}

func TestSemaphoreOneAtATime(t *testing.T) {
	s := NewSemaphore()
	if !s.TryAcquire() {
		t.Fatal("first TryAcquire should succeed")
	}
	if s.TryAcquire() {
		t.Fatal("second TryAcquire should fail (cap 1)")
	}
	s.Release()
	if !s.TryAcquire() {
		t.Fatal("TryAcquire after Release should succeed")
	}
	s.Release()
}

func TestRunStreamsAndGates(t *testing.T) {
	// fake "docker" that prints two lines and exits 0
	dir := t.TempDir()
	fake := filepath.Join(dir, "fakedocker")
	script := "#!/bin/sh\necho line-one\necho line-two\nexit 0\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	// write plane disabled → ErrWritePlaneDisabled, no exec
	rDisabled := NewRunner(NewSemaphore(), false, "test")
	rDisabled.binary = fake
	if err := rDisabled.Run(context.Background(), Job{Project: "x", Action: []string{"up"}}, nil); err != ErrWritePlaneDisabled {
		t.Errorf("disabled write plane: got %v, want ErrWritePlaneDisabled", err)
	}

	// armed → streams lines, exit 0
	r := NewRunner(NewSemaphore(), true, "")
	r.binary = fake
	var lines []string
	err := r.Run(context.Background(), Job{Project: "x", Action: []string{"up"}}, func(l string) { lines = append(lines, l) })
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(lines) != 2 || lines[0] != "line-one" || lines[1] != "line-two" {
		t.Errorf("streamed lines = %v", lines)
	}
}

// RunInternal must run Mooring-owned infra (the socket-proxy) even when the
// write-plane RAM gate is CLOSED — the read plane has to work on a small box.
func TestRunInternalIsUngated(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "fakedocker")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho proxy-up\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// writeAllowed=false: Run() would refuse, but RunInternal must proceed.
	r := NewRunner(NewSemaphore(), false, "below gate")
	r.binary = fake
	if err := r.Run(context.Background(), Job{Project: "x", Action: []string{"up"}}, nil); err != ErrWritePlaneDisabled {
		t.Fatalf("Run on a gated box: got %v, want ErrWritePlaneDisabled", err)
	}
	var lines []string
	if err := r.RunInternal(context.Background(), Job{Project: "p", Action: []string{"up", "-d"}}, func(l string) { lines = append(lines, l) }); err != nil {
		t.Fatalf("RunInternal must run ungated: %v", err)
	}
	if len(lines) != 1 || lines[0] != "proxy-up" {
		t.Errorf("RunInternal stream = %v", lines)
	}
}

func TestRunContextCancelKills(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "fakedocker")
	// a long sleeper; ctx cancel must reap it promptly
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nsleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := NewRunner(NewSemaphore(), true, "")
	r.binary = fake
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_ = r.Run(ctx, Job{Project: "x", Action: []string{"up"}}, nil)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("ctx cancel did not reap the child promptly: %v", elapsed)
	}
}
