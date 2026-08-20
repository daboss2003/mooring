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

func TestJobArgvIncludesEnvFile(t *testing.T) {
	j := Job{Project: "shop", ConfigFiles: []string{"/c.yml"}, EnvFile: "/run/x.env", Action: []string{"up", "-d"}}
	got := strings.Join(j.argv(), " ")
	want := "compose -p shop -f /c.yml --env-file /run/x.env up -d"
	if got != want {
		t.Errorf("argv with env-file:\n got %q\nwant %q", got, want)
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
