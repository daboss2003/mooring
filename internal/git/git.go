package git

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Ref names. The object store is per-app, so a single staged/deployed ref each.
const (
	StagedRef   = "refs/mooring/staged"
	DeployedRef = "refs/mooring/deployed"
)

const (
	maxCatFileBytes = 1 << 20  // a single config/compose file
	maxOutputBytes  = 8 << 20  // any git command's stdout
	maxArchiveBytes = 64 << 20 // a checkout tarball
)

// Repo is a per-app bare object store with hardened git access.
type Repo struct {
	dir    string
	binary string // "git"; overridable in tests
}

// Open opens (creating a bare repo if needed) the per-app object store at dir.
func Open(dir string) (*Repo, error) {
	r := &Repo{dir: dir, binary: "git"}
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if _, _, e := r.run(context.Background(), nil, "init", "--bare", "--quiet"); e != nil {
			return nil, fmt.Errorf("git: init bare: %w", e)
		}
	}
	return r, nil
}

// hardenedFlags are applied to EVERY invocation (plan §7.6 red-team): no hooks,
// no fsmonitor, no symlink materialization, no ext/file transports, no
// submodule recursion, no gc, no credential helpers, neutralized LFS filters.
func (r *Repo) hardenedFlags() []string {
	return []string{
		"--git-dir=" + r.dir,
		"-c", "core.hooksPath=/dev/null",
		"-c", "core.fsmonitor=false",
		"-c", "core.symlinks=false",
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.file.allow=never",
		"-c", "submodule.recurse=false",
		"-c", "gc.auto=0",
		"-c", "credential.helper=",
		"-c", "core.askPass=",
		"-c", "filter.lfs.smudge=cat",
		"-c", "filter.lfs.process=",
		"-c", "filter.lfs.required=false",
	}
}

func (r *Repo) baseEnv(extra ...string) []string {
	env := []string{
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"HOME=", // no ~/.gitconfig, no ~/.ssh
		"GIT_TERMINAL_PROMPT=0",
		"GIT_LFS_SKIP_SMUDGE=1",
		"GIT_ALLOW_PROTOCOL=https:ssh:git", // belt-and-suspenders transport allowlist
	}
	if p, ok := os.LookupEnv("PATH"); ok {
		env = append(env, "PATH="+p)
	}
	return append(env, extra...)
}

// run executes a hardened git command, capping stdout/stderr.
func (r *Repo) run(ctx context.Context, env []string, args ...string) (stdout, stderr []byte, err error) {
	cmd := exec.CommandContext(ctx, r.binary, append(r.hardenedFlags(), args...)...)
	cmd.Env = r.baseEnv(env...)
	var out, errb cappedBuffer
	out.cap = maxOutputBytes
	errb.cap = 64 << 10
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err = cmd.Run()
	return out.b.Bytes(), errb.b.Bytes(), err
}

// ResolveRef returns the commit sha a ref or sha points at (verified to exist).
func (r *Repo) ResolveRef(ctx context.Context, ref string) (string, error) {
	out, errb, err := r.run(ctx, nil, "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	if err != nil {
		return "", classifyErr(errb, err)
	}
	sha := strings.TrimSpace(string(out))
	if !isFullSha(sha) {
		return "", errors.New("git: could not resolve ref to a commit")
	}
	return sha, nil
}

// CatFile reads a file's bytes from the pinned commit's tree — object-store only,
// no worktree, no smudge. It first rejects any symlink/gitlink on the path: a
// single ls-tree resolves the path THROUGH real trees, so a regular-blob result
// guarantees no symlink/gitlink component (git can't descend a blob).
func (r *Repo) CatFile(ctx context.Context, sha, path string) ([]byte, error) {
	if !isFullSha(sha) {
		return nil, errors.New("git: cat-file requires a full commit sha")
	}
	clean := cleanRepoPath(path)
	if clean == "" {
		return nil, errors.New("git: invalid path")
	}
	mode, _, err := r.treeEntry(ctx, sha, clean)
	if err != nil {
		return nil, err
	}
	if mode != "100644" && mode != "100755" {
		return nil, fmt.Errorf("git: %q is not a regular file (mode %s; symlinks/gitlinks rejected)", path, mode)
	}
	out, errb, err := r.run(ctx, nil, "cat-file", "blob", sha+":"+clean)
	if err != nil {
		return nil, classifyErr(errb, err)
	}
	if len(out) > maxCatFileBytes {
		return nil, errors.New("git: file exceeds size cap")
	}
	return out, nil
}

// treeEntry returns the (mode, objectSha) of the single tree entry at path under
// the commit, or an error if the path doesn't resolve to exactly one entry.
func (r *Repo) treeEntry(ctx context.Context, sha, path string) (mode, obj string, err error) {
	out, errb, err := r.run(ctx, nil, "ls-tree", "--full-tree", "-z", sha, "--", path)
	if err != nil {
		return "", "", classifyErr(errb, err)
	}
	entries := splitNUL(out)
	if len(entries) != 1 {
		return "", "", fmt.Errorf("git: path %q not found in commit", path)
	}
	// format: "<mode> <type> <objectsha>\t<name>"
	line := entries[0]
	tab := strings.IndexByte(line, '\t')
	if tab < 0 {
		return "", "", errors.New("git: malformed ls-tree output")
	}
	fields := strings.Fields(line[:tab])
	if len(fields) < 3 {
		return "", "", errors.New("git: malformed ls-tree output")
	}
	return fields[0], fields[2], nil
}

// FileExists reports whether path is a regular file in the commit (no symlink).
func (r *Repo) FileExists(ctx context.Context, sha, path string) bool {
	mode, _, err := r.treeEntry(ctx, sha, cleanRepoPath(path))
	return err == nil && (mode == "100644" || mode == "100755")
}

// LsFiles returns up to a cap of regular-file paths in the commit (for the
// compose-path wizard; never a filesystem walk).
func (r *Repo) LsFiles(ctx context.Context, sha string) ([]string, error) {
	out, errb, err := r.run(ctx, nil, "ls-tree", "-r", "--full-tree", "--name-only", "-z", sha)
	if err != nil {
		return nil, classifyErr(errb, err)
	}
	names := splitNUL(out)
	if len(names) > 5000 {
		names = names[:5000]
	}
	return names, nil
}

// LsTreeRoot lists the names directly under the commit's ROOT tree (NOT recursive),
// so callers that only care about top-level files (e.g. the mooring*.yaml discovery)
// never depend on a capped full-tree walk that could drop a root entry behind 5000
// nested files. Bounded by the number of root entries (and the shared output cap).
func (r *Repo) LsTreeRoot(ctx context.Context, sha string) ([]string, error) {
	out, errb, err := r.run(ctx, nil, "ls-tree", "--full-tree", "--name-only", "-z", sha)
	if err != nil {
		return nil, classifyErr(errb, err)
	}
	return splitNUL(out), nil
}

// SetDeployedRef pins the deployed commit so gc can never prune it (rollback
// stays valid).
func (r *Repo) SetDeployedRef(ctx context.Context, sha string) error {
	_, errb, err := r.run(ctx, nil, "update-ref", DeployedRef, sha)
	if err != nil {
		return classifyErr(errb, err)
	}
	return nil
}

// RefSha returns the sha a local mooring ref points at, or "" if unset.
func (r *Repo) RefSha(ctx context.Context, ref string) string {
	out, _, err := r.run(ctx, nil, "rev-parse", "--verify", "--quiet", ref)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func isFullSha(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// cleanRepoPath normalizes a repo-relative path and rejects traversal/absolute.
func cleanRepoPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "./")
	if p == "" || strings.HasPrefix(p, "/") {
		return ""
	}
	clean := filepath.ToSlash(filepath.Clean(p))
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return ""
	}
	return clean
}

func splitNUL(b []byte) []string {
	var out []string
	for _, p := range strings.Split(string(b), "\x00") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// cappedBuffer is an io.Writer that stops accepting bytes past cap.
type cappedBuffer struct {
	b   bytes.Buffer
	cap int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.b.Len() >= c.cap {
		return len(p), nil // discard overflow, report success so the child isn't killed mid-write
	}
	room := c.cap - c.b.Len()
	if len(p) > room {
		c.b.Write(p[:room])
		return len(p), nil
	}
	return c.b.Write(p)
}

// errClass categorizes a git failure so a credential in a URL can never surface
// in last_fetch_error/logs (plan §7.6: classified, not echoed).
func classifyErr(stderr []byte, err error) error {
	s := strings.ToLower(string(stderr))
	switch {
	case strings.Contains(s, "authentication") || strings.Contains(s, "403") || strings.Contains(s, "permission denied") || strings.Contains(s, "could not read") && strings.Contains(s, "credential"):
		return errors.New("git: authentication failed")
	case strings.Contains(s, "host key") || strings.Contains(s, "known_hosts") || strings.Contains(s, "host key verification"):
		return errors.New("git: host key verification failed")
	case strings.Contains(s, "could not resolve host") || strings.Contains(s, "connection") || strings.Contains(s, "timed out") || strings.Contains(s, "network"):
		return errors.New("git: network error reaching the remote")
	case strings.Contains(s, "not found") || strings.Contains(s, "does not exist") || strings.Contains(s, "repository") && strings.Contains(s, "not"):
		// GitHub answers "Repository not found" for BOTH a missing/renamed repo AND a token that lost
		// access (it hides private repos), so spell out both so the operator knows where to look.
		return errors.New("git: repository or ref not found — check the repo URL (renamed/moved?) and that the access token or deploy key is still valid and authorized for it")
	default:
		return errors.New("git: command failed")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
