package imagescan

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// wantScanName is the only shape a scan container's name may have.
var wantScanName = regexp.MustCompile(`^mooring-scan-[0-9a-f]{16}$`)

// loggingDocker is a fake docker CLI that appends every invocation to a log as "<argc>|<arg>|<arg>|…"
// (one line each), then runs rmBody for `rm` and runBody for anything else.
func loggingDocker(t *testing.T, runBody, rmBody string) (bin, logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "argv.log")
	bin = filepath.Join(dir, "docker")
	script := "#!/bin/sh\n{ printf '%s|' \"$#\" \"$@\"; echo; } >> '" + logPath + "'\n" +
		"if [ \"$1\" = rm ]; then\n" + rmBody + "\nexit 0\nfi\n" + runBody + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, logPath
}

// dockerCalls splits the fake's log into the `run` argvs and the `rm` lines.
func dockerCalls(t *testing.T, logPath string) (runs [][]string, rms []string) {
	t.Helper()
	b, err := os.ReadFile(logPath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(strings.TrimSuffix(line, "|"), "|")
		if len(f) > 1 && f[1] == "rm" {
			rms = append(rms, line)
		} else {
			runs = append(runs, f[1:])
		}
	}
	return runs, rms
}

// nameOf returns the value of the one --name flag among docker's own flags (everything ahead of the
// image) in a `docker run` argv.
func nameOf(t *testing.T, args []string) string {
	t.Helper()
	for i, a := range args {
		if a == TrivyImage {
			args = args[:i]
			break
		}
	}
	name, n := "", 0
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--name" {
			name = args[i+1]
			n++
		}
	}
	for _, a := range args {
		if strings.HasPrefix(a, "--name=") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want exactly one --name in %q, got %d", args, n)
	}
	return name
}

// wantOneRemoval checks the fake saw one `docker run` and exactly one `rm -f <name>` whose name is
// the run's --name.
func wantOneRemoval(t *testing.T, logPath string) string {
	t.Helper()
	runs, rms := dockerCalls(t, logPath)
	if len(runs) != 1 {
		t.Fatalf("want one docker run, got %q", runs)
	}
	name := nameOf(t, runs[0])
	if !wantScanName.MatchString(name) {
		t.Errorf("container name %q does not match %s", name, wantScanName)
	}
	if want := "3|rm|-f|" + name + "|"; len(rms) != 1 || rms[0] != want {
		t.Errorf("removals = %q; want exactly [%q]", rms, want)
	}
	return name
}

func captureLog(sc *Scanner) *bytes.Buffer {
	var buf bytes.Buffer
	sc.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return &buf
}

// cancelWhenReady cancels once the fake docker has created the ready file (its trap is set).
func cancelWhenReady(ready string, cancel context.CancelFunc) {
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(ready); err == nil {
			break
		}
	}
	cancel()
}

// A scan Mooring stops mid-run force-removes the container it named, once, whatever stopped it: the
// caller's context (so the removal runs with that context already cancelled), a report limit, or a
// docker CLI that had to be killed because the scanner ignored SIGTERM.
func TestStoppedScanRemovesItsContainer(t *testing.T) {
	small := limits{report: 1 << 20, entry: 64 << 10, kept: 1 << 20}
	plan, files := ubuntuPlan()
	scans := map[string]func(*Scanner, context.Context) error{
		"image": func(sc *Scanner, ctx context.Context) error { _, err := sc.ScanImage(ctx, "nginx:1"); return err },
		"fs": func(sc *Scanner, ctx context.Context) error {
			_, err := sc.ScanFS(ctx, "/var/lib/mooring-apps/blog", "blog dependencies")
			return err
		},
		"host": func(sc *Scanner, ctx context.Context) error { _, err := sc.ScanHost(ctx, plan); return err },
	}
	for kind, scan := range scans {
		t.Run(kind+"/context ended", func(t *testing.T) {
			ready := filepath.Join(t.TempDir(), "ready")
			bin, logPath := loggingDocker(t, `trap 'kill $!; exit 0' TERM
sleep 60 &
: > "`+ready+`"
wait`, "")
			sc := New(bin, "", 5*time.Minute)
			sc.lstat = fakeLstat(files)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go cancelWhenReady(ready, cancel)
			if err := scan(sc, ctx); err == nil {
				t.Error("want an error from a scan whose context ended")
			}
			if ctx.Err() == nil {
				t.Fatal("the scan ended before its context did")
			}
			wantOneRemoval(t, logPath)
		})
		t.Run(kind+"/report limit", func(t *testing.T) {
			bin, logPath := loggingDocker(t, `printf '{"X":['
exec yes '1,'`, "")
			sc := New(bin, "", 5*time.Minute)
			sc.lstat = fakeLstat(files)
			sc.lim = small
			wantReason(t, kind, scan(sc, context.Background()), "the scan report is larger than 1 MiB")
			wantOneRemoval(t, logPath)
		})
	}
	t.Run("SIGTERM ignored", func(t *testing.T) {
		ready := filepath.Join(t.TempDir(), "ready")
		bin, logPath := loggingDocker(t, `trap '' TERM
: > "`+ready+`"
exec sleep 60`, "")
		sc := New(bin, "", 5*time.Minute)
		sc.grace = 300 * time.Millisecond
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go cancelWhenReady(ready, cancel)
		start := time.Now()
		if _, err := sc.ScanImage(ctx, "nginx:1"); err == nil {
			t.Error("want an error")
		}
		if d := time.Since(start); d > 30*time.Second {
			t.Errorf("took %v", d)
		}
		wantOneRemoval(t, logPath)
	})
}

// The rule: the removal runs when Mooring stopped the scan or `docker run` exited with an error. A run
// that exits 0 by itself was already removed by --rm and gets no `rm`, even when its report is
// refused; a run that fails by itself gets one (the docker CLI can fail while the container lives on).
func TestScanEndingByItself(t *testing.T) {
	t.Run("clean exit", func(t *testing.T) {
		bin, logPath := loggingDocker(t, `echo '{"Results":[]}'`, "")
		plan, files := ubuntuPlan()
		sc := New(bin, "", 5*time.Minute)
		sc.lstat = fakeLstat(files)
		if _, err := sc.ScanImage(context.Background(), "nginx:1"); err != nil {
			t.Fatal(err)
		}
		if _, err := sc.ScanFS(context.Background(), "/var/lib/mooring-apps/blog", "blog dependencies"); err != nil {
			t.Fatal(err)
		}
		if _, err := sc.ScanHost(context.Background(), plan); err != nil {
			t.Fatal(err)
		}
		runs, rms := dockerCalls(t, logPath)
		if len(runs) != 3 || len(rms) != 0 {
			t.Errorf("3 clean scans: %d runs, removals %q; want 3 runs and no removal", len(runs), rms)
		}
		seen := map[string]bool{}
		for _, r := range runs {
			if len(r) < 4 || strings.Join(r[:3], " ") != "run --rm --name" {
				t.Errorf("argv must start with run --rm --name <name>: %q", r)
			}
			n := nameOf(t, r)
			if !wantScanName.MatchString(n) || seen[n] {
				t.Errorf("name %q: wrong shape or reused", n)
			}
			seen[n] = true
		}
	})
	t.Run("refused report, exit 0", func(t *testing.T) {
		bin, logPath := loggingDocker(t, `echo 'not json'`, "")
		sc := New(bin, "", 5*time.Minute)
		_, err := sc.ScanImage(context.Background(), "nginx:1")
		wantReason(t, "invalid", err, "the scan report is not valid JSON")
		if _, rms := dockerCalls(t, logPath); len(rms) != 0 {
			t.Errorf("removals = %q; want none", rms)
		}
	})
	t.Run("exit 3", func(t *testing.T) {
		bin, logPath := loggingDocker(t, `echo "FATAL db download failed" >&2; exit 3`, "")
		sc := New(bin, "", 5*time.Minute)
		_, err := sc.ScanImage(context.Background(), "nginx:1")
		if err == nil || err.Error() != "trivy scan failed: exit status 3: FATAL db download failed" {
			t.Errorf("err = %v", err)
		}
		wantOneRemoval(t, logPath)
	})
}

// The removal is not tied to the caller's context: it runs when that context is already cancelled.
func TestRemovalRunsWithCancelledContext(t *testing.T) {
	bin, logPath := loggingDocker(t, "", "")
	sc := New(bin, "", 5*time.Minute)
	buf := captureLog(sc)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sc.removeContainer(ctx, "mooring-scan-0123456789abcdef")
	if _, rms := dockerCalls(t, logPath); len(rms) != 1 || rms[0] != "3|rm|-f|mooring-scan-0123456789abcdef|" {
		t.Errorf("removals = %q", rms)
	}
	if buf.Len() != 0 {
		t.Errorf("a removal that worked logs nothing: %s", buf)
	}
}

// A removal that fails is a WARN naming the container; the scan's own error is what the operator
// gets, and nothing of the scan's output is logged. A container that is already gone is not a failure.
// A removal that hangs is cut off.
func TestFailedRemovalKeepsScanError(t *testing.T) {
	small := limits{report: 1 << 20, entry: 64 << 10, kept: 1 << 20}
	endless := `printf '{"SCANOUTPUTMARK":['
exec yes '1,'`
	failing := `echo "Error response from daemon: boom" >&2; exit 1`

	t.Run("limit", func(t *testing.T) {
		bin, logPath := loggingDocker(t, endless, failing)
		sc := New(bin, "", 5*time.Minute)
		sc.lim = small
		buf := captureLog(sc)
		_, err := sc.ScanImage(context.Background(), "nginx:1")
		wantReason(t, "limit", err, "the scan report is larger than 1 MiB")
		if err.Error() != "the scan report is larger than 1 MiB" {
			t.Errorf("err = %q; the removal's failure must not be in it", err)
		}
		name := wantOneRemoval(t, logPath)
		got := buf.String()
		if strings.Count(got, "level=WARN") != 1 || !strings.Contains(got, "container="+name) {
			t.Errorf("want one WARN naming %s, got: %s", name, got)
		}
		if strings.Contains(got, "SCANOUTPUTMARK") || strings.Contains(got, "1,1,") {
			t.Errorf("scan output in the log: %.300s", got)
		}
	})
	t.Run("exit 3", func(t *testing.T) {
		bin, logPath := loggingDocker(t, `echo "FATAL db download failed" >&2; exit 3`, failing)
		sc := New(bin, "", 5*time.Minute)
		buf := captureLog(sc)
		_, err := sc.ScanImage(context.Background(), "nginx:1")
		if err == nil || err.Error() != "trivy scan failed: exit status 3: FATAL db download failed" {
			t.Errorf("err = %v; want the scan's own error", err)
		}
		wantOneRemoval(t, logPath)
		if strings.Count(buf.String(), "level=WARN") != 1 {
			t.Errorf("want one WARN, got: %s", buf)
		}
	})
	t.Run("already gone", func(t *testing.T) {
		for _, msg := range []string{
			"Error response from daemon: No such container: mooring-scan-0123456789abcdef",
			"Error response from daemon: removal of container mooring-scan-0123456789abcdef is already in progress",
		} {
			bin, logPath := loggingDocker(t, "", `echo "`+msg+`" >&2; exit 1`)
			sc := New(bin, "", 5*time.Minute)
			buf := captureLog(sc)
			sc.removeContainer(context.Background(), "mooring-scan-0123456789abcdef")
			if _, rms := dockerCalls(t, logPath); len(rms) != 1 {
				t.Errorf("removals = %q", rms)
			}
			if buf.Len() != 0 {
				t.Errorf("%q is not a failure, but logged: %s", msg, buf)
			}
		}
	})
	t.Run("hangs", func(t *testing.T) {
		bin, _ := loggingDocker(t, "", `sleep 60`)
		sc := New(bin, "", 5*time.Minute)
		sc.rmWait = 300 * time.Millisecond
		buf := captureLog(sc)
		start := time.Now()
		sc.removeContainer(context.Background(), "mooring-scan-0123456789abcdef")
		if d := time.Since(start); d > 20*time.Second {
			t.Errorf("a hanging removal took %v; want it cut off", d)
		}
		if strings.Count(buf.String(), "level=WARN") != 1 || !strings.Contains(buf.String(), "container=mooring-scan-0123456789abcdef") {
			t.Errorf("want one WARN naming the container, got: %s", buf)
		}
		if New("docker", "", time.Minute).rmWait != 0 || removeTimeout != 30*time.Second {
			t.Error("the default removal timeout is 30s")
		}
	})
}

// Abuse test. The container name is Mooring's own: a fixed prefix plus 16 hex digits from crypto/rand,
// new for every run. The removal's argv is exactly `rm -f <name>`: no image reference, label, host
// path or scan output reaches it, and a name of any other shape is never passed to docker.
func TestScanContainerNameShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		n, err := newScanName()
		if err != nil {
			t.Fatal(err)
		}
		if !wantScanName.MatchString(n) || seen[n] {
			t.Fatalf("name %q: wrong shape or repeated", n)
		}
		seen[n] = true
	}
	if got := strings.Join(removeArgs("mooring-scan-0123456789abcdef"), "|"); got != "rm|-f|mooring-scan-0123456789abcdef" {
		t.Errorf("removeArgs = %q", got)
	}

	// Hostile scan inputs and output: the name stays Mooring's, and the removal names only it.
	hostile := "--name=evil mooring-scan-ffffffffffffffff; rm -f victim"
	plan, files := ubuntuPlan()
	plan.Binaries = append(plan.Binaries, HostBinary{Label: hostile, Path: "/usr/bin/caddy"})
	for kind, scan := range map[string]func(*Scanner) error{
		"image": func(sc *Scanner) error { _, err := sc.ScanImage(context.Background(), hostile); return err },
		"fs": func(sc *Scanner) error {
			_, err := sc.ScanFS(context.Background(), "/srv/"+hostile, hostile)
			return err
		},
		"host": func(sc *Scanner) error { _, err := sc.ScanHost(context.Background(), plan); return err },
	} {
		bin, logPath := loggingDocker(t, `echo '{"Results":[{"Target":"mooring-scan-ffffffffffffffff","Class":"os-pkgs","Vulnerabilities":[{"VulnerabilityID":"victim","PkgName":"--name=evil"}]}]}'
echo "mooring-scan-ffffffffffffffff victim" >&2
exit 3`, "")
		sc := New(bin, "", 5*time.Minute)
		sc.lstat = fakeLstat(files)
		if err := scan(sc); err == nil {
			t.Errorf("%s: want the exit status as an error", kind)
		}
		name := wantOneRemoval(t, logPath)
		if name == "mooring-scan-ffffffffffffffff" {
			t.Errorf("%s: the name came from scan input", kind)
		}
		runs, _ := dockerCalls(t, logPath)
		if strings.Join(runs[0][:4], " ") != "run --rm --name "+name {
			t.Errorf("%s: argv head = %q", kind, runs[0][:4])
		}
	}

	// A name of any other shape is refused before docker is started.
	bin, logPath := loggingDocker(t, "", "")
	sc := New(bin, "", 5*time.Minute)
	buf := captureLog(sc)
	bad := []string{
		"", "-f", "--all", "victim", "mooring-scan-", "mooring-scan-0123456789abcde", "mooring-scan-0123456789abcdef0",
		"mooring-scan-0123456789ABCDEF", "mooring-scan-0123456789abcdeg", "mooring-scan-0123456789abcdef\n",
		"mooring-scan-0123456789abcdef victim", "xmooring-scan-0123456789abcdef", "mooring-scan-0123456789abcdef\nvictim",
	}
	for _, n := range bad {
		sc.removeContainer(context.Background(), n)
	}
	if runs, rms := dockerCalls(t, logPath); len(runs)+len(rms) != 0 {
		t.Errorf("docker was started for a refused name: %q %q", runs, rms)
	}
	if got := strings.Count(buf.String(), "level=WARN"); got != len(bad) {
		t.Errorf("want %d refusals logged, got %d: %s", len(bad), got, buf)
	}
}

// The Runner hands its logger to the Scanner, so a failed removal lands in Mooring's log.
func TestNewRunnerGivesTheScannerItsLogger(t *testing.T) {
	lg := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	sc := New("docker", "", 5*time.Minute)
	NewRunner(sc, nil, nil, nil, time.Hour, lg)
	if sc.log != lg {
		t.Error("the scanner did not get the runner's logger")
	}
	own := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	sc = New("docker", "", 5*time.Minute)
	sc.log = own
	NewRunner(sc, nil, nil, nil, time.Hour, lg)
	if sc.log != own {
		t.Error("a logger already set must be kept")
	}
}
