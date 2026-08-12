package git

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Creds carries fetch credentials. They are written to a 0700 PrivateTmp dir and
// passed to git via an askpass helper / GIT_SSH_COMMAND — NEVER in the URL argv.
type Creds struct {
	Token      string // https PAT (username defaults to x-access-token)
	SSHKey     string // ssh private key (PEM)
	KnownHosts string // pinned known_hosts for ssh (required for ssh)
}

// Fetch fetches the fully-qualified ref into the staged ref and returns its sha.
// It performs NO worktree change and runs nothing live (read-plane).
func (r *Repo) Fetch(ctx context.Context, repoURL, ref string, creds Creds) (string, error) {
	if err := ValidateRepoURL(repoURL); err != nil {
		return "", err
	}
	if ref == "" {
		return "", errors.New("git: a fully-qualified ref is required (e.g. refs/heads/main)")
	}
	credDir, err := os.MkdirTemp("", "hm-git-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(credDir)
	if err := os.Chmod(credDir, 0o700); err != nil {
		return "", err
	}
	env, err := credEnv(credDir, repoURL, creds)
	if err != nil {
		return "", err
	}

	refspec := "+" + ref + ":" + StagedRef
	sha, err := r.fetchOnce(ctx, env, repoURL, refspec)
	if err != nil && StaleLock(err) {
		// A crashed/killed/cancelled/rebooted fetch leaves a *.lock (e.g. shallow.lock) behind and
		// wedges the clone FOREVER — every later fetch fails "File exists". Git ops on this repo are
		// single-flighted by the caller (the gitDeploy semaphore), so a lock present now means a
		// PREVIOUS op died with no live holder — safe to clear and retry ONCE (self-heal, mirroring
		// the container-name-conflict recovery).
		r.clearStaleLocks()
		sha, err = r.fetchOnce(ctx, env, repoURL, refspec)
	}
	return sha, err
}

// fetchOnce runs a single shallow fetch of refspec into the staged ref.
func (r *Repo) fetchOnce(ctx context.Context, env []string, repoURL, refspec string) (string, error) {
	_, errb, ferr := r.run(ctx, env,
		"fetch", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head",
		"--force", "--quiet", "--depth=1", repoURL, refspec)
	if ferr != nil {
		return "", classifyErr(errb, ferr)
	}
	return r.ResolveRef(ctx, StagedRef)
}

// clearStaleLocks removes the lock files a crashed git op can strand in the bare repo: the
// top-level *.lock (shallow.lock, index.lock, config.lock, packed-refs.lock, FETCH_HEAD.lock, …)
// plus the staged/deployed ref locks. Best-effort — a missing file is fine. Only ever called after
// a "lock exists" error under the caller's single-flight gate, so nothing live holds these.
func (r *Repo) clearStaleLocks() {
	if matches, err := filepath.Glob(filepath.Join(r.dir, "*.lock")); err == nil {
		for _, m := range matches {
			_ = os.Remove(m)
		}
	}
	_ = os.Remove(filepath.Join(r.dir, StagedRef+".lock"))
	_ = os.Remove(filepath.Join(r.dir, DeployedRef+".lock"))
}

// credEnv writes credential material into credDir (0600) and returns the git env
// extras that reference it (askpass helper for https, GIT_SSH_COMMAND for ssh).
func credEnv(credDir, repoURL string, creds Creds) ([]string, error) {
	if creds.SSHKey != "" {
		keyPath := filepath.Join(credDir, "id")
		if err := os.WriteFile(keyPath, []byte(ensureTrailingNL(creds.SSHKey)), 0o600); err != nil {
			return nil, err
		}
		khPath := filepath.Join(credDir, "known_hosts")
		if err := os.WriteFile(khPath, []byte(creds.KnownHosts), 0o600); err != nil {
			return nil, err
		}
		// StrictHostKeyChecking=yes with a pinned known_hosts; empty known_hosts
		// fails closed. IdentitiesOnly so only our key is offered.
		sshCmd := fmt.Sprintf("ssh -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%s -o BatchMode=yes",
			shJoin(keyPath), shJoin(khPath))
		return []string{"GIT_SSH_COMMAND=" + sshCmd}, nil
	}
	if creds.Token != "" {
		tokPath := filepath.Join(credDir, "token")
		if err := os.WriteFile(tokPath, []byte(creds.Token), 0o600); err != nil {
			return nil, err
		}
		askPath := filepath.Join(credDir, "askpass")
		// Fixed-content helper: username -> x-access-token, password -> token file.
		script := "#!/bin/sh\ncase \"$1\" in *[Uu]sername*) printf 'x-access-token';; *) cat \"$MOORING_TOKEN_FILE\";; esac\n"
		if err := os.WriteFile(askPath, []byte(script), 0o700); err != nil {
			return nil, err
		}
		return []string{"GIT_ASKPASS=" + askPath, "MOORING_TOKEN_FILE=" + tokPath}, nil
	}
	// Public repo (no creds) — fine for https public clones.
	return nil, nil
}

// IsAncestor reports whether commit a is an ancestor of commit b (i.e. b
// fast-forwards from a). A "no" on two real commits means history diverged /
// was rewritten (e.g. a force-push) — the FSM surfaces that as history_rewritten.
func (r *Repo) IsAncestor(ctx context.Context, a, b string) (bool, error) {
	if !isFullSha(a) || !isFullSha(b) {
		return false, errors.New("git: is-ancestor requires full shas")
	}
	_, errb, err := r.run(ctx, nil, "merge-base", "--is-ancestor", a, b)
	if err == nil {
		return true, nil
	}
	// Exit code 1 = "not an ancestor" (a normal, non-error answer). Any other
	// failure (bad object, etc.) is a real error.
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
		return false, nil
	}
	return false, classifyErr(errb, err)
}

// CommitsBehind counts commits in to that are not in from (from "" → count all
// reachable from to).
func (r *Repo) CommitsBehind(ctx context.Context, from, to string) (int, error) {
	spec := to
	if from != "" {
		spec = from + ".." + to
	}
	out, errb, err := r.run(ctx, nil, "rev-list", "--count", spec)
	if err != nil {
		return 0, classifyErr(errb, err)
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}

// CommitInfo is one sanitized commit summary for the diff preview.
type CommitInfo struct {
	Sha     string
	Author  string
	Subject string
}

// FileChange is one sanitized changed-file entry.
type FileChange struct {
	Status string
	Path   string
}

// DiffResult is the hostile-data-safe, capped pending-update preview.
type DiffResult struct {
	CommitsBehind int
	Commits       []CommitInfo
	Files         []FileChange
	Truncated     bool
}

const (
	maxDiffCommits = 50
	maxDiffFiles   = 200
	maxFieldLen    = 200
)

// Diff builds the pending-update preview between from and to. ALL fields are
// sanitized (strip NUL/CR/LF/ANSI, cap length) — the operator's session is the
// most privileged; an oversized/hostile diff must truncate, never OOM.
func (r *Repo) Diff(ctx context.Context, from, to string) (DiffResult, error) {
	var res DiffResult
	n, _ := r.CommitsBehind(ctx, from, to)
	res.CommitsBehind = n

	logSpec := to
	if from != "" {
		logSpec = from + ".." + to
	}
	out, errb, err := r.run(ctx, nil, "log", "--no-color", "-z",
		"--format=%H%x1f%an%x1f%s", "-n", itoa(maxDiffCommits+1), logSpec)
	if err != nil {
		return res, classifyErr(errb, err)
	}
	for _, rec := range splitNUL(out) {
		if len(res.Commits) >= maxDiffCommits {
			res.Truncated = true
			break
		}
		f := strings.Split(rec, "\x1f")
		if len(f) < 3 {
			continue
		}
		res.Commits = append(res.Commits, CommitInfo{
			Sha: sanitize(f[0])[:min(12, len(sanitize(f[0])))], Author: sanitize(f[1]), Subject: sanitize(f[2]),
		})
	}

	// name-status; from "" → all files new.
	var nargs []string
	if from == "" {
		nargs = []string{"ls-tree", "-r", "--name-only", "-z", to}
	} else {
		nargs = []string{"diff", "--no-textconv", "--no-ext-diff", "--no-color", "--name-status", "-z", from, to}
	}
	nout, nerr, e := r.run(ctx, nil, nargs...)
	if e != nil {
		return res, classifyErr(nerr, e)
	}
	parseNameStatus(string(nout), from == "", &res)
	return res, nil
}

func parseNameStatus(z string, allNew bool, res *DiffResult) {
	parts := strings.Split(z, "\x00")
	i := 0
	for i < len(parts) {
		if parts[i] == "" {
			i++
			continue
		}
		if len(res.Files) >= maxDiffFiles {
			res.Truncated = true
			return
		}
		if allNew {
			res.Files = append(res.Files, FileChange{Status: "A", Path: sanitize(parts[i])})
			i++
			continue
		}
		// diff -z name-status: status and path are separate NUL fields
		status := sanitize(parts[i])
		i++
		if i >= len(parts) {
			break
		}
		res.Files = append(res.Files, FileChange{Status: status, Path: sanitize(parts[i])})
		i++
	}
}

// ArchiveTo extracts the commit's tree into destDir via `git archive` + an
// in-process tar reader that REJECTS symlinks/hardlinks/devices and confines
// every path under destDir (no worktree, no smudge, no hooks).
func (r *Repo) ArchiveTo(ctx context.Context, sha, destDir string) error {
	if !isFullSha(sha) {
		return errors.New("git: archive requires a full commit sha")
	}
	out, errb, err := r.run(ctx, nil, "archive", "--format=tar", sha)
	if err != nil {
		return classifyErr(errb, err)
	}
	if len(out) > maxArchiveBytes {
		return errors.New("git: archive exceeds size cap")
	}
	dest := filepath.Clean(destDir)
	tr := tar.NewReader(bytes.NewReader(out))
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if h.Typeflag == tar.TypeXGlobalHeader || h.Typeflag == tar.TypeXHeader {
			continue // pax metadata, not a filesystem entry
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir {
			return fmt.Errorf("git: archive entry %q is not a regular file/dir (symlinks rejected)", h.Name)
		}
		target := filepath.Join(dest, filepath.Clean("/"+h.Name))
		if target != dest && !strings.HasPrefix(target, dest+string(filepath.Separator)) {
			return fmt.Errorf("git: archive entry %q escapes the checkout dir", h.Name)
		}
		if h.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, 0o750); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return err
		}
		mode := os.FileMode(h.Mode).Perm() & 0o755
		f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY|oNoFollow, mode)
		if err != nil {
			return err
		}
		if _, err := io.CopyN(f, tr, maxCatFileBytes*16); err != nil && err != io.EOF {
			f.Close()
			return err
		}
		f.Close()
	}
	return nil
}

func sanitize(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c == 0x1b || c == '\r' || c == '\n' || c == 0 || c < 0x20 {
			continue // strip ANSI ESC, CR, LF, NUL, control
		}
		b.WriteRune(c)
		if b.Len() >= maxFieldLen {
			break
		}
	}
	return b.String()
}

func ensureTrailingNL(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

// shJoin single-quotes a path for safe embedding in GIT_SSH_COMMAND.
func shJoin(p string) string { return "'" + strings.ReplaceAll(p, "'", `'\''`) + "'" }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
