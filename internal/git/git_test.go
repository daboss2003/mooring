package git

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitFixture builds a real git repo in a temp dir and returns a Repo pointing at
// its object store (.git), plus the HEAD sha. Uses the real git to create the
// fixture (the hardened Repo only reads it).
func gitFixture(t *testing.T, build func(dir string)) (*Repo, string) {
	t.Helper()
	dir := t.TempDir()
	runGit := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
			"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	runGit("init", "-q", "-b", "main")
	build(dir)
	runGit("add", "-A")
	runGit("commit", "-q", "-m", "initial")

	r, err := Open(filepath.Join(dir, ".git"))
	if err != nil {
		t.Fatal(err)
	}
	sha, err := r.ResolveRef(context.Background(), "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	return r, sha
}

func TestCatFileReadsRegularFile(t *testing.T) {
	r, sha := gitFixture(t, func(dir string) {
		os.WriteFile(filepath.Join(dir, "compose.yml"), []byte("services:\n  web:\n    image: nginx\n"), 0o644)
		os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
		os.WriteFile(filepath.Join(dir, "sub", "app.env"), []byte("X=1\n"), 0o644)
	})
	b, err := r.CatFile(context.Background(), sha, "compose.yml")
	if err != nil || !strings.Contains(string(b), "image: nginx") {
		t.Fatalf("cat-file compose.yml: %v %q", err, b)
	}
	if _, err := r.CatFile(context.Background(), sha, "sub/app.env"); err != nil {
		t.Errorf("cat-file sub/app.env: %v", err)
	}
	if _, err := r.CatFile(context.Background(), sha, "nope.yml"); err == nil {
		t.Error("cat-file of a missing path should error")
	}
}

// The critical confinement test: a symlink tree entry must be rejected, never
// followed (plan §7.6 symlink/gitlink escape).
func TestCatFileRejectsSymlink(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	r, sha := gitFixture(t, func(dir string) {
		os.WriteFile(filepath.Join(dir, "real.yml"), []byte("ok\n"), 0o644)
		// a symlink pointing outside the repo
		os.Symlink("/etc/passwd", filepath.Join(dir, "evil"))
		// a symlink directory component
		os.MkdirAll(filepath.Join(dir, "realdir"), 0o755)
		os.WriteFile(filepath.Join(dir, "realdir", "f"), []byte("x\n"), 0o644)
		os.Symlink("/etc", filepath.Join(dir, "etclink"))
	})
	if _, err := r.CatFile(context.Background(), sha, "evil"); err == nil {
		t.Error("cat-file followed a symlink (should reject mode 120000)")
	}
	// traversal through a symlinked dir component must not resolve
	if _, err := r.CatFile(context.Background(), sha, "etclink/passwd"); err == nil {
		t.Error("cat-file traversed a symlinked directory component")
	}
}

func TestArchiveExtractsAndConfines(t *testing.T) {
	r, sha := gitFixture(t, func(dir string) {
		os.WriteFile(filepath.Join(dir, "compose.yml"), []byte("services: {}\n"), 0o644)
		os.MkdirAll(filepath.Join(dir, "cfg"), 0o755)
		os.WriteFile(filepath.Join(dir, "cfg", "a.conf"), []byte("a\n"), 0o644)
	})
	dest := t.TempDir()
	if err := r.ArchiveTo(context.Background(), sha, dest); err != nil {
		t.Fatalf("archive: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "cfg", "a.conf")); err != nil || string(b) != "a\n" {
		t.Errorf("extracted file wrong: %v %q", err, b)
	}
}

func TestArchiveRejectsSymlinkEntry(t *testing.T) {
	r, sha := gitFixture(t, func(dir string) {
		os.WriteFile(filepath.Join(dir, "f"), []byte("x\n"), 0o644)
		os.Symlink("/etc/passwd", filepath.Join(dir, "link"))
	})
	if err := r.ArchiveTo(context.Background(), sha, t.TempDir()); err == nil {
		t.Error("archive extraction should reject a symlink entry")
	}
}

func TestDiffBetweenCommits(t *testing.T) {
	dir := t.TempDir()
	runGit := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	runGit("init", "-q", "-b", "main")
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("1\n"), 0o644)
	runGit("add", "-A")
	runGit("commit", "-q", "-m", "first")
	r, _ := Open(filepath.Join(dir, ".git"))
	from, _ := r.ResolveRef(context.Background(), "HEAD")
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("2\n"), 0o644)
	runGit("add", "-A")
	runGit("commit", "-q", "-m", "second commit subject")
	to, _ := r.ResolveRef(context.Background(), "HEAD")

	d, err := r.Diff(context.Background(), from, to)
	if err != nil {
		t.Fatal(err)
	}
	if d.CommitsBehind != 1 || len(d.Commits) != 1 || d.Commits[0].Subject != "second commit subject" {
		t.Errorf("diff commits wrong: %+v", d)
	}
	foundB := false
	for _, f := range d.Files {
		if f.Path == "b.txt" && f.Status == "A" {
			foundB = true
		}
	}
	if !foundB {
		t.Errorf("diff files missing b.txt(A): %+v", d.Files)
	}
}

func TestIsAncestor(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	runGit := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	runGit("init", "-q", "-b", "main")
	os.WriteFile(filepath.Join(dir, "a"), []byte("1\n"), 0o644)
	runGit("add", "-A")
	runGit("commit", "-q", "-m", "first")
	r, _ := Open(filepath.Join(dir, ".git"))
	ctx := context.Background()
	first, _ := r.ResolveRef(ctx, "HEAD")
	os.WriteFile(filepath.Join(dir, "b"), []byte("2\n"), 0o644)
	runGit("add", "-A")
	runGit("commit", "-q", "-m", "second")
	second, _ := r.ResolveRef(ctx, "HEAD")

	if anc, err := r.IsAncestor(ctx, first, second); err != nil || !anc {
		t.Errorf("first should be ancestor of second: anc=%v err=%v", anc, err)
	}
	if anc, err := r.IsAncestor(ctx, second, first); err != nil || anc {
		t.Errorf("second is NOT ancestor of first: anc=%v err=%v", anc, err)
	}
}

func TestValidateRepoURL(t *testing.T) {
	good := []string{"https://github.com/o/r.git", "ssh://git@github.com/o/r.git", "git@github.com:o/r.git"}
	for _, u := range good {
		if err := ValidateRepoURL(u); err != nil {
			t.Errorf("ValidateRepoURL(%q) errored: %v", u, err)
		}
	}
	bad := map[string]string{
		"http://github.com/o/r":            "scheme",
		"https://user:pass@github.com/o/r": "credentials",
		"https://127.0.0.1/o/r":            "loopback",
		"https://169.254.169.254/o/r":      "metadata",
		"file:///etc/x":                    "scheme",
		"ftp://x/y":                        "scheme",
	}
	for u := range bad {
		if err := ValidateRepoURL(u); err == nil {
			t.Errorf("ValidateRepoURL(%q) accepted an unsafe URL", u)
		}
	}
}

func TestClassifyErrCarriesRawStderr(t *testing.T) {
	raw := []byte("ERROR: Repository not found.\nfatal: Could not read from remote repository.")
	e := classifyErr(raw, errors.New("exit status 128"))
	// The operator-facing message stays CLASSIFIED (no raw stderr in it).
	if got := e.Error(); !strings.Contains(got, "repository or ref not found") {
		t.Errorf("classified message = %q", got)
	}
	if strings.Contains(e.Error(), "Could not read") {
		t.Error("the classified message must NOT echo raw git stderr")
	}
	// …but RawStderr surfaces the real git words for the operator journal.
	if rs := RawStderr(e); !strings.Contains(rs, "Repository not found") {
		t.Errorf("RawStderr = %q, want GitHub's actual message", rs)
	}
	// A non-git error yields no raw detail.
	if RawStderr(errors.New("plain")) != "" {
		t.Error("RawStderr must be empty for a non-git error")
	}
	// Defense-in-depth: any userinfo in a URL is redacted (never present, but proven stripped).
	red := RawStderr(classifyErr([]byte("fatal: unable to access https://x-access-token:ghs_SECRET@github.com/o/r.git: not found"), errors.New("x")))
	if strings.Contains(red, "ghs_SECRET") || strings.Contains(red, "x-access-token") {
		t.Errorf("userinfo must be redacted from raw stderr: %q", red)
	}
}

func TestClassifyErrStaleLock(t *testing.T) {
	lock := []byte("fatal: Unable to create '/var/lib/mooring/git/credlock.git/shallow.lock': File exists.\n\n" +
		"Another git process seems to be running in this repository, e.g.\nan editor opened by 'git commit'.")
	e := classifyErr(lock, errors.New("exit status 128"))
	// The stale-lock error must NOT be mis-classified as "repository or ref not found" (the bug that
	// sent a real operator chasing tokens/keys for hours) — and StaleLock must detect it.
	if strings.Contains(e.Error(), "repository or ref not found") {
		t.Errorf("stale lock mis-classified as not-found: %q", e.Error())
	}
	if !strings.Contains(e.Error(), "stale lock") {
		t.Errorf("stale-lock message = %q, want it to name the stale lock", e.Error())
	}
	if !StaleLock(e) {
		t.Error("StaleLock must detect the lock error (so the fetch self-heals)")
	}

	// GitHub's genuine "Repository not found." must still classify as not-found (and NOT as a lock).
	nf := classifyErr([]byte("ERROR: Repository not found.\nfatal: Could not read from remote repository."), errors.New("x"))
	if !strings.Contains(nf.Error(), "repository or ref not found") {
		t.Errorf("real not-found = %q", nf.Error())
	}
	if StaleLock(nf) {
		t.Error("a real not-found must not be treated as a stale lock")
	}
	if StaleLock(errors.New("plain")) {
		t.Error("a non-git error is not a stale lock")
	}
}

func TestClearStaleLocks(t *testing.T) {
	dir := t.TempDir()
	// Plant the locks a crashed fetch strands: top-level ones + a ref lock.
	must := func(p string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	must(filepath.Join(dir, "shallow.lock"))
	must(filepath.Join(dir, "packed-refs.lock"))
	must(filepath.Join(dir, StagedRef+".lock"))
	keep := filepath.Join(dir, "config") // a NON-lock file must survive
	must(keep)

	r := &Repo{dir: dir, binary: "git"}
	r.clearStaleLocks()

	for _, p := range []string{"shallow.lock", "packed-refs.lock", StagedRef + ".lock"} {
		if _, err := os.Stat(filepath.Join(dir, p)); !os.IsNotExist(err) {
			t.Errorf("%s must be removed", p)
		}
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("a non-lock file must be preserved: %v", err)
	}
}
