package web

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/envstore"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/secret"
)

// releaseOneOff is the one-off container the fake docker's `ps -aq` lists (the reap after a killed job).
var releaseOneOff = strings.Repeat("0f", 32)

// releaseDockerPrefix runs ahead of fakeDockerScript in the same script.
//   - `compose … run --rm …` prints $d/run-lines numbered lines (when that file exists) and "migrating", then
//     sleeps 30s with $d/run-sleep and exits 3 with $d/run-fail. With $d/run-then-fail-up every `up` after it
//     fails.
//   - `ps -aq …` lists releaseOneOff; `rmi` succeeds; `tag` succeeds, except one that points shop-api itself
//     at an image while $d/tag-fail exists.
//   - `container inspect … -- <id>…` prints $d/inspect, else "<id>\t[]\t{}" per id (no mounts, no ports); it
//     fails with $d/inspect-fail.
//   - `image inspect --format {{.Id}} -- <ref>` fails once with a daemon error when $d/image-inspect-error
//     exists; otherwise fakeDockerScript answers it.
//   - A volume-owner helper's `stat` prints $d/vol-uid.
//   - `build … -- <svc>` fails when $d/build-fail holds <svc>; otherwise it replaces $d/images with
//     $d/images-built when that exists (the build gave each ref a new image id) and goes on to fakeDockerScript,
//     which logs it.
func releaseDockerPrefix() string {
	return `
pl=""
for a in "$@"; do pl="$a"; done
case "$*" in
"run --rm --network none "*" stat "*)
	printf '%s\n' "$*" >> "$d/calls.log"
	if [ -f "$d/vol-uid" ]; then cat "$d/vol-uid"; fi
	exit 0 ;;
*" run --rm "*)
	printf '%s\n' "$*" >> "$d/calls.log"
	if [ -f "$d/run-lines" ]; then
		i=0; n=$(cat "$d/run-lines")
		while [ $i -lt $n ]; do i=$((i+1)); echo "line $i"; done
	fi
	echo "migrating"
	if [ -f "$d/run-then-fail-up" ]; then : > "$d/fail-all"; fi
	if [ -f "$d/run-sleep" ]; then sleep 30; fi
	if [ -f "$d/run-fail" ]; then echo "migration failed" >&2; exit 3; fi
	exit 0 ;;
"ps -aq "*)
	printf '%s\n' "$*" >> "$d/calls.log"
	echo "` + releaseOneOff + `"
	exit 0 ;;
"container inspect "*)
	printf '%s\n' "$*" >> "$d/calls.log"
	if [ -f "$d/inspect-fail" ]; then echo "error during connect: daemon unreachable" >&2; exit 1; fi
	if [ -f "$d/inspect" ]; then cat "$d/inspect"; exit 0; fi
	past=""
	for a in "$@"; do
		if [ -n "$past" ]; then printf '%s\t[]\t{}\n' "$a"; fi
		if [ "$a" = "--" ]; then past=1; fi
	done
	exit 0 ;;
"image inspect --format {{.Id}} -- "*)
	if [ -f "$d/image-inspect-error" ]; then
		rm -f "$d/image-inspect-error"
		printf '%s\n' "$*" >> "$d/calls.log"
		echo "error during connect: daemon unreachable" >&2
		exit 1
	fi ;;
"tag "*)
	printf '%s\n' "$*" >> "$d/calls.log"
	if [ -f "$d/tag-fail" ] && [ "$pl" = "shop-api" ]; then echo "Error response from daemon: tag failed" >&2; exit 1; fi
	exit 0 ;;
"rmi "*)
	printf '%s\n' "$*" >> "$d/calls.log"
	exit 0 ;;
*" build "*)
	if [ -f "$d/build-fail" ] && [ "$pl" = "$(cat "$d/build-fail")" ]; then
		printf '%s\n' "$*" >> "$d/calls.log"
		echo "build of $pl failed" >&2
		exit 1
	fi
	if [ -f "$d/images-built" ]; then cp "$d/images-built" "$d/images"; fi ;;
esac
`
}

// releaseYAML: api (built) runs the release job and depends on db, which depends on cache; worker is built
// too; legacy (in the initial view) is a service the file dropped.
const releaseYAML = `apiVersion: mooring/v1
kind: App
metadata: {slug: app}
spec:
  compose:
    source: generated
    services:
      api:
        build: {language: go}
        depends_on: [db]
      cache:
        image: redis:7
      db:
        image: postgres:16
        depends_on: [cache]
      worker:
        build: {language: go}
  release:
    service: api
    command: [/app/migrate, --rm, -x]
`

var (
	apiOldImage    = testImageID("shop-api@old")
	apiNewImage    = testImageID("shop-api@new")
	workerNewImage = testImageID("shop-worker@new")
)

// newReleaseEnv is the app "shop" (mooringYAML, plus a Go module for its build services) ready for a deploy
// with a release job, against the fake docker CLI (extended by releaseDockerPrefix) and the containers in
// initial. Before the build shop-api is apiOldImage and shop-worker doesn't exist; the build makes them
// apiNewImage and workerNewImage.
func newReleaseEnv(t *testing.T, mooringYAML string, initial []monitor.ServiceStatus) *pacedDeployEnv {
	t.Helper()
	p := newPacedServer(t, map[string]string{"api": "shop-api", "cache": "redis:7", "db": "postgres:16", "worker": "shop-worker"}, initial)
	d := p.docker.dir
	files := map[string]string{
		"docker":       "#!/bin/sh\nd='" + d + "'\n" + releaseDockerPrefix() + fakeDockerScript,
		"images":       fmt.Sprintf("shop-api %s\nredis:7 %s\npostgres:16 %s\n", apiOldImage, testImageID("redis:7"), testImageID("postgres:16")),
		"images-built": fmt.Sprintf("shop-api %s\nshop-worker %s\nredis:7 %s\npostgres:16 %s\n", apiNewImage, workerNewImage, testImageID("redis:7"), testImageID("postgres:16")),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(d, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	p.e.srv.defStore = definition.NewStore(p.e.srv.db, make([]byte, 32))
	p.sha = gitObjStoreFixtureFiles(t, p.e.srv.gitObjectDir("shop"), map[string]string{
		"mooring.yaml": mooringYAML,
		"go.mod":       "module x\n\ngo 1.23\n",
		"main.go":      "package main\nfunc main(){}\n",
	})
	p.cfg = configureRepo(t, p.e, "shop", p.sha)
	return p
}

// releaseInitial: the previous release runs api and cache; db has no container; legacy is an orphan.
func releaseInitial() []monitor.ServiceStatus {
	return []monitor.ServiceStatus{
		{Service: "api", ContainerID: apiCopy, State: "running", Health: "healthy", Inspected: true, ConfigHash: testConfigHash("api"), ImageID: apiOldImage},
		{Service: "cache", ContainerID: cacheCopy, State: "running", Health: "healthy", Inspected: true, ConfigHash: testConfigHash("cache"), ImageID: testImageID("redis:7")},
		{Service: "legacy", ContainerID: legacyCopy, State: "running", Health: "none", Inspected: true},
	}
}

func (p *pacedDeployEnv) touch(t *testing.T, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(p.docker.dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// releasePrevYAML is the release before releaseYAML: api and cache only.
const releasePrevYAML = `apiVersion: mooring/v1
kind: App
metadata: {slug: shop}
spec:
  compose:
    source: generated
    services:
      api:
        build: {language: go}
      cache:
        image: redis:7
`

// recordVersion stores mooringYAML as a version of the app's definition: a git deploy's when commit is set,
// else a dashboard edit's.
func (p *pacedDeployEnv) recordVersion(t *testing.T, mooringYAML, commit string) *definition.Definition {
	t.Helper()
	d, err := definition.Parse([]byte(mooringYAML))
	if err != nil {
		t.Fatal(err)
	}
	d.Metadata.Slug = "shop"
	note := "dashboard: edit"
	if commit != "" {
		note = "git deploy: " + commit[:7]
	}
	if _, err := p.e.srv.defStore.SaveCanonical(context.Background(), d, note, commit); err != nil {
		t.Fatal(err)
	}
	return d
}

// plantCompose writes body as the run dir's docker-compose.yml.
func (p *pacedDeployEnv) plantCompose(t *testing.T, body string) {
	t.Helper()
	rd := p.e.srv.appRunDir("shop")
	if err := os.MkdirAll(rd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rd, "docker-compose.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (p *pacedDeployEnv) runDirCompose(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(p.e.srv.appRunDir("shop"), "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// composeOf is the compose a deploy of d at commit generates.
func composeOf(t *testing.T, d *definition.Definition, commit string) string {
	t.Helper()
	b, err := definition.ComposeBytesAt(d, commit)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const plantedCompose = "# not generated by Mooring\nservices:\n  api:\n    image: evil:1\n    privileged: true\n"

// callIndex is the index of the first call containing sub (-1 if none).
func callIndex(calls []string, sub string) int {
	return slices.IndexFunc(calls, func(c string) bool { return strings.Contains(c, sub) })
}

const releaseRunCall = " run --rm --no-deps -T -- api /app/migrate --rm -x"

// The job runs once, after every build and before anything replaces or removes a running service: only the
// dependency with no container (db) starts before it — not the running one (cache) — and the rollout, the
// orphan removal and every other start come after. Its output reaches the deploy log, prefixed.
func TestReleaseJobRunsBeforeAnyServiceIsReplaced(t *testing.T) {
	p := newReleaseEnv(t, releaseYAML, releaseInitial())
	const dbPassword = "s3cret-value-never-logged"
	if _, err := p.e.srv.envStore.Save(context.Background(), "shop",
		[]envstore.Entry{{Key: "DB_PASSWORD", Value: secret.New(dbPassword), Secret: true}}, "operator"); err != nil {
		t.Fatal(err)
	}
	problems, err := p.deploy(false)
	if err != nil || len(problems) != 0 {
		t.Fatalf("deploy: problems=%v err=%v\n%s", problems, err, p.output())
	}
	calls := p.docker.calls()
	all := strings.Join(calls, "\n")
	run := callIndex(calls, releaseRunCall)
	if run < 0 || strings.Count(all, " run --rm ") != 1 {
		t.Fatalf("want exactly one release run `…%s`:\n%s", releaseRunCall, all)
	}
	if !strings.Contains(calls[run], " --env-file ") || !strings.HasPrefix(calls[run], "compose -p shop ") {
		t.Errorf("the job runs in the app's compose project with its env file: %q", calls[run])
	}
	if strings.Contains(all, dbPassword) || strings.Contains(p.output(), dbPassword) {
		t.Errorf("an env value must reach the job only through the env file, never argv or the deploy log")
	}
	lastBuild := -1
	for i, c := range calls {
		if strings.Contains(c, " build -- ") {
			lastBuild = i
		}
	}
	if lastBuild < 0 || lastBuild > run {
		t.Errorf("the job must run after every build (last build %d, run %d):\n%s", lastBuild, run, all)
	}
	for i, c := range calls[:run] {
		if strings.Contains(c, " up ") && !strings.HasSuffix(c, " up -d --no-deps --no-build -- db") {
			t.Errorf("before the job only the stopped dependency db may start, got call %d %q", i, c)
		}
		if strings.HasPrefix(c, "rm ") {
			t.Errorf("nothing may be removed before the job, got call %d %q", i, c)
		}
	}
	if callIndex(calls[:run], " up -d --no-deps --no-build -- db") < 0 {
		t.Errorf("db (a dependency with no container) must start before the job:\n%s", all)
	}
	if got := p.docker.ups(); !slices.Equal(got, []string{"db", "api", "worker"}) {
		t.Errorf("starts = %v, want db (for the job), then the rollout's api and worker — db once, cache never", got)
	}
	if rm := callIndex(calls, "rm -f "+legacyCopy); rm < run {
		t.Errorf("the orphan must be removed after the job (rm %d, run %d)", rm, run)
	}
	for _, want := range []string{"release: migrating", "$ docker compose run --rm --no-deps -T -- api /app/migrate --rm -x"} {
		if !strings.Contains(p.output(), want) {
			t.Errorf("deploy log lacks %q:\n%s", want, p.output())
		}
	}
	// The previous image is kept under a second tag for the length of the deploy, then let go.
	backup := callIndex(calls, "tag -- "+apiOldImage+" shop-api:mooring-previous")
	if backup < 0 || backup > callIndex(calls, " build -- ") {
		t.Errorf("shop-api's previous image must be tagged before the build:\n%s", all)
	}
	if slices.Contains(calls, "tag -- "+apiOldImage+" shop-api") || strings.Contains(all, " shop-worker:mooring-previous") {
		t.Errorf("a successful job restores nothing, and a ref that didn't exist gets no backup:\n%s", all)
	}
	if rmi := callIndex(calls, "rmi -- shop-api:mooring-previous"); rmi < 0 || rmi < run {
		t.Errorf("the backup tag must be dropped at the end of the deploy:\n%s", all)
	}
	if cfg, _, _ := p.e.srv.gitStore.Get("shop"); cfg.DeployedCommit != p.sha {
		t.Errorf("deployed commit %q, want %q", cfg.DeployedCommit, p.sha)
	}
}

// A failed job fails the deploy before any service is replaced: no rollout step, no orphan removal; the run
// dir's compose file is the previous release's again — generated from the definition that release deployed,
// never whatever file was in the run dir — and every built ref that existed before points at its previous
// image, so restarts, scale-ups and scheduled tasks keep running the previous code.
func TestReleaseJobFailureKeepsThePreviousRelease(t *testing.T) {
	p := newReleaseEnv(t, releaseYAML, releaseInitial())
	prev := p.recordVersion(t, releasePrevYAML, strings.Repeat("cd", 20))
	// A dashboard edit after that release was never deployed, so it isn't what goes back.
	edited := p.recordVersion(t, releasePrevYAML+"        config_files:\n          - {template: \"maxmemory 64mb\", mount: /etc/redis/extra.conf}\n", "")
	want := composeOf(t, prev, strings.Repeat("cd", 20))
	if want == composeOf(t, edited, strings.Repeat("cd", 20)) {
		t.Fatal("test setup: the dashboard edit must change the compose")
	}
	p.plantCompose(t, plantedCompose)
	p.touch(t, "run-fail", "")
	problems, err := p.deploy(false)
	if err == nil || !strings.Contains(err.Error(), "release job failed") || !strings.Contains(err.Error(), "exit status 3") || problems != nil {
		t.Fatalf("want the deploy failed by the job, got problems=%v err=%v\n%s", problems, err, p.output())
	}
	calls := p.docker.calls()
	all := strings.Join(calls, "\n")
	run := callIndex(calls, releaseRunCall)
	if run < 0 {
		t.Fatalf("the job never ran:\n%s", all)
	}
	if got := p.docker.ups(); !slices.Equal(got, []string{"db"}) {
		t.Errorf("only the job's stopped dependency may have started, got %v", got)
	}
	if strings.Contains(all, "rm -f "+legacyCopy) || strings.Contains(all, "rm -f "+apiCopy) {
		t.Errorf("a failed job must not remove any running container:\n%s", all)
	}
	if got := p.runDirCompose(t); got != want {
		t.Errorf("the run dir's compose file must be the previous release's again, got:\n%s\nwant:\n%s", got, want)
	}
	restore := slices.Index(calls, "tag -- "+apiOldImage+" shop-api")
	if restore < run {
		t.Errorf("shop-api must point at its previous image again, after the job:\n%s", all)
	}
	for _, c := range calls {
		if strings.HasPrefix(c, "tag ") && strings.Contains(c, "shop-worker") {
			t.Errorf("shop-worker didn't exist before this deploy, so it has nothing to go back to: %q", c)
		}
	}
	if rmi := callIndex(calls, "rmi -- shop-api:mooring-previous"); rmi < restore {
		t.Errorf("the backup tag must be dropped after the restore:\n%s", all)
	}
	for _, want := range []string{"release: migration failed", "the previous release keeps running"} {
		if !strings.Contains(p.output(), want) {
			t.Errorf("deploy log lacks %q:\n%s", want, p.output())
		}
	}
	if cfg, _, _ := p.e.srv.gitStore.Get("shop"); cfg.UpdateState != "update_blocked" || cfg.DeployedCommit == p.sha {
		t.Errorf("a failed job: state %q deployed %q", cfg.UpdateState, cfg.DeployedCommit)
	}
	if got := p.lastDeployOutcome(t); got != "error" {
		t.Errorf("deploy outcome = %q, want error", got)
	}
}

// Only a compose generated from a deployed definition and passed by the §5.6 validator is ever put back: on a
// first deploy, or when the previous release's compose fails the validator, the file stays as this deploy
// wrote it and the deploy log says why.
func TestReleaseJobFailurePutsBackOnlyACheckedCompose(t *testing.T) {
	cases := []struct {
		name, deployed, why string
	}{
		{"first deploy", "", "no previous release"},
		{"previous compose fails the validator", strings.Replace(releasePrevYAML, "image: redis:7", "image: redis:7\n        ports: [{internal: 80, publish: true}]", 1), "§5.6"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newReleaseEnv(t, releaseYAML, releaseInitial())
			var rejected string
			if tc.deployed != "" {
				rejected = composeOf(t, p.recordVersion(t, tc.deployed, strings.Repeat("cd", 20)), strings.Repeat("cd", 20))
			}
			p.plantCompose(t, plantedCompose)
			p.touch(t, "run-fail", "")
			if _, err := p.deploy(false); err == nil || !strings.Contains(err.Error(), "release job failed") {
				t.Fatalf("want the deploy failed by the job, got %v\n%s", err, p.output())
			}
			got := p.runDirCompose(t)
			if got == plantedCompose {
				t.Fatalf("a compose file Mooring didn't generate was put back:\n%s", got)
			}
			if rejected != "" && got == rejected {
				t.Fatalf("a compose the validator rejects was written:\n%s", got)
			}
			if !strings.Contains(got, "postgres:16") {
				t.Errorf("the compose this deploy wrote must stay:\n%s", got)
			}
			out := p.output()
			if !strings.Contains(out, "release: warning: docker-compose.yml not put back") || !strings.Contains(out, tc.why) {
				t.Errorf("deploy log must say the compose wasn't put back (%q):\n%s", tc.why, out)
			}
			if !slices.Contains(p.docker.calls(), "tag -- "+apiOldImage+" shop-api") {
				t.Errorf("the images still go back:\n%s", strings.Join(p.docker.calls(), "\n"))
			}
		})
	}
}

// releaseRenameYAML renames the database service db → postgres; postgres keeps db's volume and host port.
const releaseRenameYAML = `apiVersion: mooring/v1
kind: App
metadata: {slug: app}
spec:
  compose:
    source: generated
    services:
      api:
        build: {language: go}
        depends_on: [postgres]
      postgres:
        image: postgres:16
        volumes: [{name: pgdata, target: /var/lib/postgresql/data}]
        ports: [{internal: 5432, publish: true}]
  release:
    service: api
    command: [/app/migrate]
`

// A dependency the job would start is refused, before anything starts, while a running container of a service
// the file no longer declares uses its volume or host port (a rename would run two databases on one data dir);
// so is one that can't be checked.
func TestReleaseRefusesADependencyThatClashesWithARemovedService(t *testing.T) {
	vol := `[{"Type":"volume","Name":"shop_pgdata","Source":"/var/lib/docker/volumes/shop_pgdata/_data","Destination":"/var/lib/postgresql/data","RW":true}]`
	port := `{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"5432"}]}`
	cases := []struct {
		name, inspect string
		inspectFails  bool
		want          []string
	}{
		{"shared volume", dbCopy + "\t" + vol + "\tnull\n", false, []string{"db", "volume shop_pgdata", "postgres", "spec.release"}},
		{"shared host port", dbCopy + "\t[]\t" + port + "\n", false, []string{"db", "host port 5432/tcp", "postgres", "spec.release"}},
		{"can't be checked", "", true, []string{"could not check", "db", "postgres"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newReleaseEnv(t, releaseRenameYAML, []monitor.ServiceStatus{
				{Service: "api", ContainerID: apiCopy, State: "running", Health: "healthy", Inspected: true, ConfigHash: testConfigHash("api"), ImageID: apiOldImage},
				{Service: "db", ContainerID: dbCopy, State: "running", Health: "healthy", Inspected: true},
			})
			if tc.inspectFails {
				p.touch(t, "inspect-fail", "")
			} else {
				p.touch(t, "inspect", tc.inspect)
			}
			_, err := p.deploy(false)
			if err == nil || !strings.Contains(err.Error(), "release job didn't run") {
				t.Fatalf("want the deploy refused before the job, got %v\n%s", err, p.output())
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error lacks %q: %v", w, err)
				}
			}
			calls := p.docker.calls()
			all := strings.Join(calls, "\n")
			if strings.Contains(all, " up ") || strings.Contains(all, " run --rm ") || strings.HasPrefix(all, "rm ") || strings.Contains(all, "\nrm ") {
				t.Errorf("nothing may start, run or be removed:\n%s", all)
			}
			if i := callIndex(calls, "container inspect "); i < 0 || !strings.HasSuffix(calls[i], " -- "+dbCopy) {
				t.Errorf("only the removed service's running container is inspected:\n%s", all)
			}
			if !slices.Contains(calls, "tag -- "+apiOldImage+" shop-api") {
				t.Errorf("the refused deploy puts the images back:\n%s", all)
			}
		})
	}
}

// A removed service whose container is stopped doesn't hold its volume: the dependency starts before the job.
func TestReleaseStartsADependencyBesideAStoppedRemovedService(t *testing.T) {
	p := newReleaseEnv(t, releaseRenameYAML, []monitor.ServiceStatus{
		{Service: "api", ContainerID: apiCopy, State: "running", Health: "healthy", Inspected: true, ConfigHash: testConfigHash("api"), ImageID: apiOldImage},
		{Service: "db", ContainerID: dbCopy, State: "exited", Health: "none", Inspected: true},
	})
	p.touch(t, "inspect", dbCopy+"\t"+`[{"Type":"volume","Name":"shop_pgdata","RW":true}]`+"\tnull\n")
	if _, err := p.deploy(false); err != nil {
		t.Fatalf("deploy: %v\n%s", err, p.output())
	}
	calls := p.docker.calls()
	up, run := callIndex(calls, " up -d --no-deps --no-build -- postgres"), callIndex(calls, " run --rm --no-deps -T -- api /app/migrate")
	if up < 0 || run < up {
		t.Fatalf("postgres must start before the job (up %d, run %d):\n%s", up, run, strings.Join(calls, "\n"))
	}
	if callIndex(calls, "container inspect ") >= 0 {
		t.Errorf("no running removed service, nothing to inspect:\n%s", strings.Join(calls, "\n"))
	}
}

// The backup of the current images waits for the docker slot however long it is busy (a scheduled task, a
// backup); the per-call timeout only bounds each docker call once the slot is taken.
func TestReleaseImageBackupWaitsForTheDockerSlot(t *testing.T) {
	old := releaseImageCallTimeout
	releaseImageCallTimeout = time.Second
	t.Cleanup(func() { releaseImageCallTimeout = old })
	p := newReleaseEnv(t, releaseYAML, nil)
	def, err := definition.Parse([]byte(releaseYAML))
	if err != nil {
		t.Fatal(err)
	}
	// The first exec of a fresh script can take longer than the shrunk call timeout (the OS scans it).
	if err := exec.Command(filepath.Join(p.docker.dir, "docker"), "version").Run(); err != nil {
		t.Fatal(err)
	}
	sem := p.e.srv.runner.Semaphore()
	if err := sem.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(2500 * time.Millisecond) // well past the call timeout
		sem.Release()
	}()
	var lines []string
	ids := p.e.srv.backupBuildImages(context.Background(), "shop", def, func(l string) { lines = append(lines, l) })
	if ids["api"] != apiOldImage || len(ids) != 1 {
		t.Fatalf("backup = %v, want api → its current image\n%s", ids, strings.Join(lines, "\n"))
	}
	if !slices.Contains(p.docker.calls(), "tag -- "+apiOldImage+" shop-api:mooring-previous") {
		t.Errorf("shop-api's image must be tagged:\n%s", strings.Join(p.docker.calls(), "\n"))
	}
}

// An image that can't be read is a warning naming the service; a ref that doesn't exist yet (a new service) is
// silently nothing to keep.
func TestReleaseImageBackupWarnsWhenAnImageCantBeRead(t *testing.T) {
	p := newReleaseEnv(t, releaseYAML, nil)
	def, err := definition.Parse([]byte(releaseYAML))
	if err != nil {
		t.Fatal(err)
	}
	p.touch(t, "image-inspect-error", "")
	var lines []string
	ids := p.e.srv.backupBuildImages(context.Background(), "shop", def, func(l string) { lines = append(lines, l) })
	if len(ids) != 0 {
		t.Errorf("backup = %v, want nothing kept", ids)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "shop-api") || !strings.Contains(lines[0], "daemon unreachable") ||
		!strings.Contains(lines[0], "api's previous image can't be put back") {
		t.Errorf("want one warning naming api and the error, got:\n%s", strings.Join(lines, "\n"))
	}
}

// A ref the restore can't point back keeps its backup tag — the only reference left to its previous image.
func TestReleaseRestoreFailureKeepsTheBackupTag(t *testing.T) {
	p := newReleaseEnv(t, releaseYAML, releaseInitial())
	p.touch(t, "run-fail", "")
	p.touch(t, "tag-fail", "")
	if _, err := p.deploy(false); err == nil || !strings.Contains(err.Error(), "release job failed") {
		t.Fatalf("want the deploy failed by the job, got %v\n%s", err, p.output())
	}
	all := strings.Join(p.docker.calls(), "\n")
	if !slices.Contains(p.docker.calls(), "tag -- "+apiOldImage+" shop-api") {
		t.Fatalf("the restore must have tried shop-api:\n%s", all)
	}
	if strings.Contains(all, "rmi -- shop-api:mooring-previous") {
		t.Errorf("the backup tag of a ref that couldn't be put back must stay:\n%s", all)
	}
	if !strings.Contains(p.output(), "release: kept shop-api:mooring-previous") {
		t.Errorf("deploy log must say the backup tag was kept:\n%s", p.output())
	}
}

// With a release job, a build that fails part-way puts back the images already rebuilt (a scheduled task would
// otherwise run new code against the old schema) and the previous release's compose file.
func TestReleaseBuildFailurePutsBackImagesAndCompose(t *testing.T) {
	p := newReleaseEnv(t, releaseYAML, releaseInitial())
	p.e.srv.cfg.Server.BuildConcurrency = "serial"
	prev := p.recordVersion(t, releasePrevYAML, strings.Repeat("cd", 20))
	p.touch(t, "build-fail", "worker")
	_, err := p.deploy(false)
	if err == nil || !strings.Contains(err.Error(), "docker compose build failed") {
		t.Fatalf("want the build to fail the deploy, got %v\n%s", err, p.output())
	}
	calls := p.docker.calls()
	all := strings.Join(calls, "\n")
	failedBuild := callIndex(calls, " build -- worker")
	restore := slices.Index(calls, "tag -- "+apiOldImage+" shop-api")
	if callIndex(calls, " build -- api") < 0 || failedBuild < 0 || restore < failedBuild {
		t.Fatalf("api built, worker's build failed, then shop-api must point at its previous image again:\n%s", all)
	}
	if rmi := callIndex(calls, "rmi -- shop-api:mooring-previous"); rmi < restore {
		t.Errorf("the backup tag must be dropped after the restore:\n%s", all)
	}
	if got := p.runDirCompose(t); got != composeOf(t, prev, strings.Repeat("cd", 20)) {
		t.Errorf("the previous release's compose must be back, got:\n%s", got)
	}
	if strings.Contains(all, " run --rm ") || strings.Contains(all, " up ") {
		t.Errorf("nothing may run or start after a failed build:\n%s", all)
	}
}

// releaseVolumesYAML: the job's service api depends on queue; queue and worker are built (run as the pinned
// non-root uid) and each has its own writable volume, so a deploy re-owns both.
const releaseVolumesYAML = `apiVersion: mooring/v1
kind: App
metadata: {slug: app}
spec:
  compose:
    source: generated
    services:
      api:
        build: {language: go}
        depends_on: [queue]
      queue:
        build: {language: go}
        volumes: [{name: qdata, target: /data}]
      worker:
        build: {language: go}
        volumes: [{name: wdata, target: /data}]
  release:
    service: api
    command: [/app/migrate]
`

// A start that fails after the job gives back the previous owner of a volume only services that didn't start
// use — never one a dependency the job started (running the new image) uses.
func TestReleaseFailedStartKeepsTheVolumesOfDependenciesTheJobStarted(t *testing.T) {
	for _, atOnce := range []bool{false, true} {
		t.Run(fmt.Sprintf("all at once %v", atOnce), func(t *testing.T) {
			p := newReleaseEnv(t, releaseVolumesYAML, []monitor.ServiceStatus{
				{Service: "api", ContainerID: apiCopy, State: "running", Health: "healthy", Inspected: true, ConfigHash: testConfigHash("api"), ImageID: apiOldImage},
			})
			p.touch(t, "vol-uid", "1000\n")
			p.touch(t, "run-then-fail-up", "")
			_, err := p.deploy(atOnce)
			if err == nil || !strings.Contains(err.Error(), "docker compose up failed") {
				t.Fatalf("want the start after the job to fail, got %v\n%s", err, p.output())
			}
			out := p.output()
			if !strings.Contains(out, "reconciled volume shop_qdata") || !strings.Contains(out, "reconciled volume shop_wdata") {
				t.Fatalf("test setup: both volumes must have been re-owned:\n%s", out)
			}
			if !strings.Contains(out, "rolled volume shop_wdata ownership back") {
				t.Errorf("worker didn't start: its volume goes back to its previous owner:\n%s", out)
			}
			if strings.Contains(out, "rolled volume shop_qdata ownership back") {
				t.Errorf("queue, started for the job, runs the new image: its volume must keep the new owner:\n%s", out)
			}
		})
	}
}

// When the all-at-once start of the job's dependencies fails, a dependency it did start anyway counts as
// started: its volume keeps the new owner if the deploy then fails.
func TestReleaseDependencyStartErrorCountsTheOnesRunning(t *testing.T) {
	p := newReleaseEnv(t, releaseVolumesYAML, []monitor.ServiceStatus{
		{Service: "api", ContainerID: apiCopy, State: "running", Health: "healthy", Inspected: true, ConfigHash: testConfigHash("api"), ImageID: apiOldImage},
	})
	view := p.e.srv.snapFn
	p.e.srv.snapFn = func() *monitor.Snapshot {
		snap := view()
		if callIndex(p.docker.calls(), " --wait ") >= 0 { // compose started queue, then failed
			snap.Apps[0].Services = append(snap.Apps[0].Services, monitor.ServiceStatus{
				Service: "queue", ContainerID: strings.Repeat("9e", 32), State: "running", Health: "healthy", Inspected: true})
		}
		return snap
	}
	p.touch(t, "vol-uid", "1000\n")
	p.touch(t, "fail-queue", "")
	p.touch(t, "run-then-fail-up", "")
	if _, err := p.deploy(true); err == nil || !strings.Contains(err.Error(), "docker compose up failed") {
		t.Fatalf("want the start after the job to fail, got %v\n%s", err, p.output())
	}
	out := p.output()
	if !strings.Contains(out, "release: warning: could not start them") {
		t.Fatalf("test setup: the dependencies' start must have failed:\n%s", out)
	}
	if !strings.Contains(out, "rolled volume shop_wdata ownership back") {
		t.Errorf("worker's volume goes back:\n%s", out)
	}
	if strings.Contains(out, "rolled volume shop_qdata ownership back") {
		t.Errorf("queue runs (the failed up started it): its volume must keep the new owner:\n%s", out)
	}
}

// A job past its timeout is killed, and its container — which outlives the killed compose CLI — is removed;
// the deploy fails.
func TestReleaseJobTimeoutReapsItsContainer(t *testing.T) {
	old := releaseJobTimeout
	releaseJobTimeout = func(*definition.Release) time.Duration { return 300 * time.Millisecond }
	t.Cleanup(func() { releaseJobTimeout = old })
	p := newReleaseEnv(t, releaseYAML, releaseInitial())
	p.touch(t, "run-sleep", "")
	start := time.Now()
	_, err := p.deploy(false)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want a timed-out job to fail the deploy, got %v\n%s", err, p.output())
	}
	if took := time.Since(start); took > 20*time.Second {
		t.Errorf("the job wasn't killed at its timeout: the deploy took %s", took)
	}
	calls := p.docker.calls()
	run := callIndex(calls, releaseRunCall)
	ps := callIndex(calls, "ps -aq --no-trunc --filter label=com.docker.compose.project=shop --filter label=com.docker.compose.oneoff=True")
	rm := slices.Index(calls, "rm -f "+releaseOneOff)
	if run < 0 || ps < run || rm < ps {
		t.Fatalf("after the killed job its one-off container must be listed and removed (run %d, ps %d, rm %d):\n%s",
			run, ps, rm, strings.Join(calls, "\n"))
	}
	if got := p.docker.ups(); !slices.Equal(got, []string{"db"}) {
		t.Errorf("no service may be replaced after a timed-out job, starts = %v", got)
	}
}

// "All at once" starts the job's stopped dependencies with one call before it, then the whole-project `up`.
func TestReleaseJobAllAtOnceStartsStoppedDependenciesTogether(t *testing.T) {
	p := newReleaseEnv(t, releaseYAML, []monitor.ServiceStatus{
		{Service: "api", ContainerID: apiCopy, State: "running", Health: "healthy", Inspected: true, ConfigHash: testConfigHash("api"), ImageID: apiOldImage},
	})
	if _, err := p.deploy(true); err != nil {
		t.Fatalf("deploy: %v\n%s", err, p.output())
	}
	calls := p.docker.calls()
	deps := slices.IndexFunc(calls, func(c string) bool {
		return strings.HasSuffix(c, " up -d --no-deps --no-build --wait --wait-timeout 300 -- cache db")
	})
	run := callIndex(calls, releaseRunCall)
	whole := slices.IndexFunc(calls, func(c string) bool { return strings.HasSuffix(c, " up -d --remove-orphans --no-build") })
	if deps < 0 || run < deps || whole < run {
		t.Fatalf("want `up -d --no-deps --no-build --wait --wait-timeout 300 -- cache db`, then the job, then the whole-project up (deps %d, run %d, up %d):\n%s",
			deps, run, whole, strings.Join(calls, "\n"))
	}
}

// On a PR preview the job runs only when the BASE app's deployed definition opts in; the preview's own
// file (here always `previews: true`) can't turn it on.
func TestReleaseJobOnPreviewsFollowsTheBaseApp(t *testing.T) {
	const previewYAML = `apiVersion: mooring/v1
kind: App
metadata: {slug: app}
spec:
  compose:
    source: generated
    services:
      api:
        image: nginx:1.27
  release: {service: api, command: [migrate], previews: true}
`
	cases := []struct {
		name, base string
		runs       bool
	}{
		{"base has no release", "", false},
		{"base doesn't opt in", "  release: {service: api, command: [migrate]}\n", false},
		{"base opts in", "  release: {service: api, command: [migrate], previews: true}\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newReleaseEnv(t, previewYAML, nil)
			base, err := definition.Parse([]byte("apiVersion: mooring/v1\nkind: App\nmetadata: {slug: base}\nspec:\n  compose:\n    source: generated\n    services:\n      api:\n        image: nginx:1.27\n" + tc.base))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.e.srv.defStore.SaveCanonical(context.Background(), base, "git deploy", strings.Repeat("ab", 20)); err != nil {
				t.Fatal(err)
			}
			p.cfg.PreviewOf = "base"
			if _, err := p.deploy(false); err != nil {
				t.Fatalf("preview deploy: %v\n%s", err, p.output())
			}
			ran := strings.Contains(strings.Join(p.docker.calls(), "\n"), " run --rm --no-deps -T -- api migrate")
			if ran != tc.runs {
				t.Fatalf("job ran = %v, want %v\n%s", ran, tc.runs, p.output())
			}
			if skipped := strings.Contains(p.output(), "release job skipped on this PR preview"); skipped == tc.runs {
				t.Errorf("the skip must be logged exactly when the job doesn't run:\n%s", p.output())
			}
		})
	}
}

// A base definition that can't be read never lets a preview run its job.
func TestReleaseOnPreviewFailsClosed(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	if ok, why := e.srv.releaseOnPreview("base"); ok || why == "" {
		t.Errorf("no definition store: ok=%v why=%q", ok, why)
	}
	e.srv.defStore = definition.NewStore(e.srv.db, make([]byte, 32))
	if ok, why := e.srv.releaseOnPreview("base"); ok || why == "" {
		t.Errorf("base never deployed: ok=%v why=%q", ok, why)
	}
}

// The job is a one-off `run` of the service with the command after `-- <service>`, in the deploy's project.
func TestReleaseJobArgv(t *testing.T) {
	base := dockerexec.Job{Project: "shop", Dir: "/w", ConfigFiles: []string{"/w/docker-compose.yml"}, EnvFile: "/e/env"}
	job := releaseJob(base, &definition.Release{Service: "api", Command: []string{"node", "dist/migrate.js", "--rm"}})
	if got := strings.Join(job.Action, " ") + " -- " + job.Service + " " + strings.Join(job.Args, " "); got != "run --rm --no-deps -T -- api node dist/migrate.js --rm" {
		t.Errorf("job = %q", got)
	}
	if job.Project != "shop" || job.Dir != "/w" || job.EnvFile != "/e/env" || len(job.ConfigFiles) != 1 {
		t.Errorf("the job must target the deploy's compose project: %+v", job)
	}
}

// The job's dependencies are its service's depends_on, followed through other services, never itself or a
// scheduled-only service, each once.
func TestReleaseDeps(t *testing.T) {
	def := &definition.Definition{}
	def.Spec.Compose.Services = map[string]definition.Service{
		"api":    {DependsOn: []string{"db", "queue"}},
		"db":     {DependsOn: []string{"cache"}},
		"queue":  {DependsOn: []string{"cache", "api"}},
		"cache":  {},
		"report": {},
		"web":    {DependsOn: []string{"api"}},
	}
	def.Spec.ScheduledTasks = []definition.ScheduledTask{{Name: "nightly", Service: "report", Every: "24h"}}
	if got := releaseDeps(def, "api"); !slices.Equal(got, []string{"cache", "db", "queue"}) {
		t.Errorf("releaseDeps(api) = %v", got)
	}
	if got := releaseDeps(def, "cache"); len(got) != 0 {
		t.Errorf("releaseDeps(cache) = %v, want none", got)
	}
}

// The deploy log gets the first lines as they come and the last ones at the end, each bounded, with a count
// of what was left out between them.
func TestReleaseOutputIsBounded(t *testing.T) {
	var got []string
	out := &releaseOutput{onLine: func(l string) { got = append(got, l) }}
	long := strings.Repeat("x", 10_000)
	total := releaseLogHead + releaseLogTail + 1500
	for i := 1; i <= total; i++ {
		out.add(fmt.Sprintf("line %d %s", i, long))
	}
	if len(got) != releaseLogHead {
		t.Fatalf("%d lines streamed before the end, want the first %d", len(got), releaseLogHead)
	}
	out.flush()
	if len(got) != releaseLogHead+1+releaseLogTail {
		t.Fatalf("%d lines in all, want head + marker + tail = %d", len(got), releaseLogHead+1+releaseLogTail)
	}
	if !strings.HasPrefix(got[0], "release: line 1 ") || !strings.HasPrefix(got[len(got)-1], fmt.Sprintf("release: line %d ", total)) {
		t.Errorf("first %q… last %q…", got[0][:20], got[len(got)-1][:20])
	}
	if marker := got[releaseLogHead]; marker != "release: … 1500 lines omitted" {
		t.Errorf("marker = %q", marker)
	}
	for _, l := range got {
		if len(l) > len("release: ")+releaseLineMax+len("…") {
			t.Fatalf("a %d-byte line was forwarded", len(l))
		}
	}
	got = nil
	short := &releaseOutput{onLine: func(l string) { got = append(got, l) }}
	short.add("one\r\ntwo")
	short.flush()
	if !slices.Equal(got, []string{"release: one  two"}) {
		t.Errorf("a short job's output = %q", got)
	}
}

// The deploy deadline leaves room for the longest release job.
func TestDeployTimeoutIncludesTheReleaseJob(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	budget := e.srv.cfg.Server.StartGateSettings().RolloutBudget
	if got, want := e.srv.repoDeployTimeout(), gitDeployTimeout+definition.ReleaseTimeoutMax+budget+10*time.Minute; got != want {
		t.Fatalf("repoDeployTimeout = %s, want %s", got, want)
	}
	if got, want := e.srv.deployTimeout(), gitDeployTimeout+budget+10*time.Minute; got != want {
		t.Fatalf("deployTimeout (lifecycle, cert renewal) = %s, want %s", got, want)
	}
}

// Putting the previous images back waits for a busy docker slot instead of giving up after one call's
// timeout: otherwise a restart, scale-up or scheduled task would run the new image against the old schema.
func TestReleaseRestoreWaitsForTheDockerSlot(t *testing.T) {
	old := releaseImageCallTimeout
	releaseImageCallTimeout = time.Second
	t.Cleanup(func() { releaseImageCallTimeout = old })
	p := newReleaseEnv(t, releaseYAML, nil)
	def, err := definition.Parse([]byte(releaseYAML))
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(filepath.Join(p.docker.dir, "docker"), "version").Run(); err != nil {
		t.Fatal(err)
	}
	sem := p.e.srv.runner.Semaphore()
	if err := sem.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(2500 * time.Millisecond) // well past the call timeout
		sem.Release()
	}()
	r := releaseRun{slug: "shop", dir: p.e.srv.appRunDir("shop"), def: def, prev: &releasePrev{images: map[string]string{"api": apiOldImage}}}
	var lines []string
	p.e.srv.restoreRelease(context.Background(), r, false, func(l string) { lines = append(lines, l) })
	if !slices.Contains(p.docker.calls(), "tag -- "+apiOldImage+" shop-api") {
		t.Fatalf("shop-api must point back at its previous image:\n%s\n%s", strings.Join(p.docker.calls(), "\n"), strings.Join(lines, "\n"))
	}
	if r.prev.keep["api"] {
		t.Error("a ref that was put back must not keep its backup tag")
	}
}

// A git deploy gives every build service the commit it deployed as MOORING_COMMIT; image services don't get it.
func TestDeployGivesBuildServicesTheCommit(t *testing.T) {
	p := newReleaseEnv(t, releaseYAML, releaseInitial())
	if _, err := p.deploy(false); err != nil {
		t.Fatal(err)
	}
	d, err := definition.Parse([]byte(releaseYAML))
	if err != nil {
		t.Fatal(err)
	}
	d.Metadata.Slug = "shop" // the registration slug, which the deploy uses
	if got, want := p.runDirCompose(t), composeOf(t, d, p.sha); got != want {
		t.Fatalf("the run dir's compose must be the deploy's, with its commit:\n%s\nwant:\n%s", got, want)
	}
	if n := strings.Count(p.runDirCompose(t), "MOORING_COMMIT="+p.sha); n != 2 {
		t.Fatalf("api and worker (the build services) must each get MOORING_COMMIT, got %d:\n%s", n, p.runDirCompose(t))
	}
}

// A deploy without a release job that stops before starting anything puts the deployed release's compose back
// (with that release's MOORING_COMMIT), so a restart or scale-up doesn't label the old images with the new
// commit or apply the new config to them. A first deploy has nothing to put back and keeps its file.
func TestFailedDeployPutsBackTheDeployedCompose(t *testing.T) {
	noRelease := strings.Replace(releaseYAML, "  release:\n    service: api\n    command: [/app/migrate, --rm, -x]\n", "", 1)
	if noRelease == releaseYAML {
		t.Fatal("test setup: the release block must be removed")
	}
	p := newReleaseEnv(t, noRelease, releaseInitial())
	prev := p.recordVersion(t, releasePrevYAML, strings.Repeat("cd", 20))
	p.touch(t, "build-fail", "worker")
	if _, err := p.deploy(false); err == nil || !strings.Contains(err.Error(), "docker compose build failed") {
		t.Fatalf("want the build to fail the deploy, got %v\n%s", err, p.output())
	}
	if got, want := p.runDirCompose(t), composeOf(t, prev, strings.Repeat("cd", 20)); got != want {
		t.Fatalf("the deployed release's compose must be back:\n%s\nwant:\n%s", got, want)
	}

	// First deploy: no release to go back to, the new file stays.
	q := newReleaseEnv(t, noRelease, nil)
	q.touch(t, "build-fail", "worker")
	if _, err := q.deploy(false); err == nil {
		t.Fatal("want the build to fail the deploy")
	}
	if !strings.Contains(q.runDirCompose(t), "MOORING_COMMIT="+q.sha) {
		t.Fatalf("a first deploy keeps the compose it wrote:\n%s", q.runDirCompose(t))
	}
}
