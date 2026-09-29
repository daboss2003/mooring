package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/docker"
	"github.com/daboss2003/mooring/internal/dockerexec"
)

// fakeDockerCLI puts a `docker` script first on PATH whose `docker info --format {{.ID}}` prints id.
func fakeDockerCLI(t *testing.T, id string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake docker")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\nif [ \"$1\" = info ]; then echo " + id + "; exit 0; fi\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// readPlaneInfo serves GET /info with the given daemon id, like the socket-proxy.
func readPlaneInfo(t *testing.T, id string) *docker.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/info" || strings.HasSuffix(r.URL.Path, "/info") {
			_, _ = io.WriteString(w, `{"ID":"`+id+`","Name":"host1","DockerRootDir":"/var/lib/docker"}`)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return docker.New(strings.TrimPrefix(srv.URL, "http://"))
}

// A mismatch flips the verdict (and pauses writes); an unreadable side never changes it; a match clears it.
func TestRecordDaemonCheckTransitions(t *testing.T) {
	s := &Server{log: quietWebLog()}
	ctx := context.Background()
	s.recordDaemonCheck(ctx, docker.Info{ID: "A"}, "A")
	if s.DaemonMismatch() {
		t.Fatal("same daemon must not be a mismatch")
	}
	s.recordDaemonCheck(ctx, docker.Info{ID: "A"}, "B")
	if !s.DaemonMismatch() {
		t.Fatal("different daemons must be a mismatch")
	}
	s.recordDaemonCheck(ctx, docker.Info{}, "B")
	if !s.DaemonMismatch() {
		t.Fatal("an unreadable side must keep the last verdict")
	}
	s.recordDaemonCheck(ctx, docker.Info{ID: "B"}, "B")
	if s.DaemonMismatch() {
		t.Fatal("a later match must clear the mismatch")
	}
}

// A deploy refuses when the socket-proxy and the docker CLI reach different daemons.
func TestPreDeployPlaneCheckRefusesDaemonMismatch(t *testing.T) {
	fakeDockerCLI(t, "WRITE-DAEMON")
	s := &Server{log: quietWebLog(), docker: readPlaneInfo(t, "READ-DAEMON"),
		runner: dockerexec.NewRunner(dockerexec.NewSemaphore(), true, "")}
	err := s.preDeployPlaneCheck(context.Background(), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "refusing to deploy") || !strings.Contains(err.Error(), "WRITE-DAEMON") {
		t.Fatalf("want a refusal naming both daemons, got %v", err)
	}
	if !s.DaemonMismatch() {
		t.Fatal("the refusal must also record the mismatch (pausing automatic writes)")
	}
}

// Matching daemons pass and report the daemon in the deploy log.
func TestPreDeployPlaneCheckPassesSameDaemon(t *testing.T) {
	fakeDockerCLI(t, "0123456789abcdef-SAME")
	s := &Server{log: quietWebLog(), docker: readPlaneInfo(t, "0123456789abcdef-SAME"),
		runner: dockerexec.NewRunner(dockerexec.NewSemaphore(), true, "")}
	var lines []string
	if err := s.preDeployPlaneCheck(context.Background(), func(l string) { lines = append(lines, l) }); err != nil {
		t.Fatalf("same daemon must pass, got %v", err)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "0123456789ab") {
		t.Fatalf("want one 'docker daemon <id>' line, got %v", lines)
	}
}

// With no read plane configured (tests, dev builds) the check is skipped; a disarmed write plane is left
// for the build/up to report.
func TestPreDeployPlaneCheckSkips(t *testing.T) {
	if err := (&Server{log: quietWebLog()}).preDeployPlaneCheck(context.Background(), func(string) {}); err != nil {
		t.Fatalf("no read plane → skip, got %v", err)
	}
	s := &Server{log: quietWebLog(), docker: readPlaneInfo(t, "A"),
		runner: dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")}
	if err := s.preDeployPlaneCheck(context.Background(), func(string) {}); err != nil {
		t.Fatalf("a disarmed write plane → skip (the build reports it), got %v", err)
	}
}

// A socket-proxy that doesn't answer /info refuses the deploy with the managed proxy (which always allows
// /info, so a failure means it is unhealthy) but only skips the comparison with an operator-run external
// proxy, which need not allow /info.
func TestPreDeployPlaneCheckReadInfoFailure(t *testing.T) {
	fakeDockerCLI(t, "WRITE")
	noInfo := httptest.NewServer(http.NotFoundHandler())
	defer noInfo.Close()
	newSrv := func(external bool) *Server {
		cfg := &config.Config{}
		cfg.Docker.ExternalProxy = external
		return &Server{log: quietWebLog(), cfg: cfg, docker: docker.New(strings.TrimPrefix(noInfo.URL, "http://")),
			runner: dockerexec.NewRunner(dockerexec.NewSemaphore(), true, "")}
	}
	if err := newSrv(false).preDeployPlaneCheck(context.Background(), func(string) {}); err == nil || !strings.Contains(err.Error(), "could not confirm") {
		t.Fatalf("managed proxy without /info must refuse, got %v", err)
	}
	var lines []string
	if err := newSrv(true).preDeployPlaneCheck(context.Background(), func(l string) { lines = append(lines, l) }); err != nil {
		t.Fatalf("external proxy without /info must skip, got %v", err)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "not compared") {
		t.Fatalf("want a 'not compared' line, got %v", lines)
	}
}

// A mismatch alert raised before a restart is re-adopted from the outbox on the first comparison after
// boot, so a matching comparison still resolves it (the documented fix ends with restarting mooring).
func TestDaemonAlertResolvesAcrossRestart(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	ctx := context.Background()
	if err := e.srv.alertStore.EnqueueInfra(ctx, alert.Outbox{
		Kind: "docker_daemon_mismatch", Level: alert.LevelCritical, Transition: "firing", DedupeKey: daemonMismatchKey,
	}); err != nil {
		t.Fatal(err)
	}
	// Fresh process state (as after a restart): nothing in memory says an alert is open.
	e.srv.recordDaemonCheck(ctx, docker.Info{ID: "SAME"}, "SAME")
	open, err := e.srv.alertStore.OpenInfraAlerts(ctx, "docker_daemon_mismatch")
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 0 {
		t.Fatalf("the pre-restart alert must be resolved, still open: %v", open)
	}
	if e.srv.DaemonMismatch() {
		t.Fatal("matching daemons must not pause writes")
	}
}
