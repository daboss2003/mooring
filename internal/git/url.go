// Package git is the HARDENED git read/fetch layer (plan §7.6 + §15). A connected
// repo is attacker-controlled: merely fetching, diffing, or checking out can run
// code via .gitattributes filter/textconv, LFS smudge, fsmonitor/sshCommand,
// hooks, and submodule ext::. Every invocation here is run config-/attribute-
// proof with static argv (never a shell); file bytes are read via `cat-file`
// from the object store (no worktree, no smudge); symlink/gitlink tree modes are
// rejected; and the remote URL passes an SSRF allowlist.
package git

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/daboss2003/mooring/internal/opsclient"
)

// ValidateRepoURL enforces the §15 SSRF allowlist on a git remote: scheme ∈
// {https, ssh} (incl. scp-like git@host:path), and a literal-IP host may not be
// loopback/link-local/metadata. Credentials must never be embedded in the URL.
func ValidateRepoURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("repo URL is required")
	}
	host, scheme, hasUserinfoPassword, err := repoHost(raw)
	if err != nil {
		return err
	}
	if scheme != "https" && scheme != "ssh" {
		return errors.New("repo URL must be https:// or ssh:// (or git@host:path)")
	}
	if hasUserinfoPassword {
		return errors.New("do not embed credentials in the repo URL; use the PAT/deploy-key field")
	}
	if host == "" {
		return errors.New("repo URL must include a host")
	}
	if strings.EqualFold(host, "localhost") {
		return errors.New("repo URL must not be loopback")
	}
	if ip, perr := netip.ParseAddr(host); perr == nil && opsclient.IsBlockedAddr(ip.Unmap()) {
		return errors.New("repo URL host must not be a loopback/link-local/metadata address")
	}
	return nil
}

// RepoScheme returns a repo URL's transport ("https" or "ssh"), or "" if it can't be determined.
// Callers use it to match a credential type to the URL (an SSH key can't auth an https:// URL).
func RepoScheme(raw string) string {
	_, scheme, _, err := repoHost(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return scheme
}

// RepoHostName returns a repo URL's host (e.g. "github.com"), or "" if it can't be determined.
func RepoHostName(raw string) string {
	host, _, _, err := repoHost(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return host
}

// repoHost extracts (host, scheme, hasPassword) from an https or ssh/scp URL.
func repoHost(raw string) (host, scheme string, hasPassword bool, err error) {
	// scp-like syntax: [user@]host:path (no scheme, no slashes before the colon)
	if !strings.Contains(raw, "://") {
		at := strings.IndexByte(raw, '@')
		colon := strings.IndexByte(raw, ':')
		if colon < 0 || (strings.IndexByte(raw, '/') >= 0 && strings.IndexByte(raw, '/') < colon) {
			return "", "", false, fmt.Errorf("unrecognized repo URL %q", raw)
		}
		h := raw[:colon]
		if at >= 0 && at < colon {
			h = raw[at+1 : colon]
		}
		return h, "ssh", false, nil
	}
	u, perr := url.Parse(raw)
	if perr != nil {
		return "", "", false, fmt.Errorf("invalid repo URL")
	}
	pw := false
	if u.User != nil {
		_, pw = u.User.Password()
	}
	return u.Hostname(), u.Scheme, pw, nil
}
