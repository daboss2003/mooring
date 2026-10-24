package edge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The Mooring-owned Caddy. The service runs sandboxed (ProtectSystem=strict), so a packaged caddy
// such as /usr/bin/caddy is read-only to it: a Caddy with a DNS plugin compiled in can only be
// installed where the service may write. That is <data_dir>/bin/caddy. The edge runs it when it
// exists and falls back to the system caddy otherwise.
const ownedCaddyRel = "bin/caddy"

// DefaultBuildServer is Caddy's official build server. It compiles standard Caddy plus the
// requested plugin packages and serves the binary — the same artifact `caddy add-package` fetches.
const DefaultBuildServer = "https://caddyserver.com/api/download"

// MinCaddyVersion is the oldest Caddy that accepts everything the edge renders: edge.trusted_proxies
// refuses QUIC 0-RTT through `allow_0rtt`, which Caddy added in 2.11.
var MinCaddyVersion = Version{Major: 2, Minor: 11}

// supportedCaddyMajor is the Caddy major version the rendered config is written for. The build server
// serves the latest release, so a downloaded build of a future major (which may reject the boot
// config and crash-loop every app's edge) is refused and the current binary kept.
const supportedCaddyMajor = 2

// maxCaddyDownload caps a build-server download: a plugin build is ~50 MB, and anything far larger is
// not a Caddy binary. A variable only so a test can lower it.
var maxCaddyDownload int64 = 256 << 20

const (
	downloadTimeout = 10 * time.Minute // the build server compiles on demand before it answers
	caddyCmdTimeout = 30 * time.Second
	errTailLines    = 20
)

// OwnedCaddyPath is where Mooring installs its own Caddy build: <dataDir>/bin/caddy.
func OwnedCaddyPath(dataDir string) string { return filepath.Join(dataDir, ownedCaddyRel) }

// ResolveCaddy returns the Caddy binary the edge runs: the Mooring-owned build when it exists and is
// executable, else the system caddy on PATH (absolute path), else "".
func ResolveCaddy(dataDir string) string {
	if dataDir != "" {
		p := OwnedCaddyPath(dataDir)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p
		}
	}
	if p, err := exec.LookPath("caddy"); err == nil {
		return p
	}
	return ""
}

// Version is a Caddy release number.
type Version struct{ Major, Minor, Patch int }

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// AtLeast reports whether v >= min.
func (v Version) AtLeast(min Version) bool {
	if v.Major != min.Major {
		return v.Major > min.Major
	}
	if v.Minor != min.Minor {
		return v.Minor > min.Minor
	}
	return v.Patch >= min.Patch
}

// ParseCaddyVersion reads `caddy version` output. Official builds print "v2.11.2 h1:…", distro
// builds a bare "2.6.2"; a pre-release suffix ("-beta.1") is ignored. ok=false when the first word
// isn't a version (e.g. a "(devel)" build).
func ParseCaddyVersion(out string) (Version, bool) {
	f := strings.Fields(out)
	if len(f) == 0 {
		return Version{}, false
	}
	s := strings.TrimPrefix(f[0], "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return Version{}, false
	}
	var n [3]int
	for i, p := range parts {
		x, err := strconv.Atoi(p)
		if err != nil || x < 0 {
			return Version{}, false
		}
		n[i] = x
	}
	return Version{n[0], n[1], n[2]}, true
}

// CaddyVersion runs `<bin> version` and parses it.
func CaddyVersion(ctx context.Context, bin string) (Version, error) {
	out, err := runCaddy(ctx, bin, "version")
	if err != nil {
		return Version{}, err
	}
	v, ok := ParseCaddyVersion(string(out))
	if !ok {
		return Version{}, fmt.Errorf("unrecognized `caddy version` output: %s", tailLines(out, 3))
	}
	return v, nil
}

// CaddyModules returns the module IDs compiled into bin (`caddy list-modules`).
func CaddyModules(ctx context.Context, bin string) (map[string]bool, error) {
	out, err := runCaddy(ctx, bin, "list-modules")
	if err != nil {
		return nil, err
	}
	mods := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		// A module line is the bare ID; the summaries ("Standard modules: 106") contain spaces.
		if t := strings.TrimSpace(line); t != "" && !strings.ContainsAny(t, " \t") {
			mods[t] = true
		}
	}
	return mods, nil
}

// CaddyExtraPackages returns the Go module paths of bin's NON-standard modules (plugins someone built
// in), so a replacement build can keep them. It needs `list-modules --packages --skip-standard`; on a
// Caddy without those flags it returns an error and the caller builds only what it needs.
func CaddyExtraPackages(ctx context.Context, bin string) ([]string, error) {
	out, err := runCaddy(ctx, bin, "list-modules", "--packages", "--skip-standard")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var pkgs []string
	for _, line := range strings.Split(string(out), "\n") {
		// "<module-id> <module-path>"; the summaries ("Non-standard modules: 1") have three words and
		// an unknown module (no build info) has one — neither can be carried over.
		f := strings.Fields(line)
		if len(f) != 2 || !ValidPackagePath(f[1]) || seen[f[1]] {
			continue
		}
		seen[f[1]] = true
		pkgs = append(pkgs, f[1])
	}
	sort.Strings(pkgs)
	return pkgs, nil
}

// packagePathRe is a Go module path the build server accepts: a lowercase host with a dot, then at
// least one path segment. Anything else (spaces, query characters, `..`) is refused before it can
// reach the download URL.
var packagePathRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)+(/[A-Za-z0-9._~-]+)+$`)

// ValidPackagePath reports whether p is a plausible Go module path for the build server.
func ValidPackagePath(p string) bool {
	if len(p) > 200 || !packagePathRe.MatchString(p) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

var osArchRe = regexp.MustCompile(`^[a-z0-9]{2,16}$`)

// BuildServerURL is the download URL for a Caddy built for goos/goarch with packages compiled in.
// base "" is DefaultBuildServer and must be https; every package path is validated.
func BuildServerURL(base, goos, goarch string, packages []string) (string, error) {
	if base == "" {
		base = DefaultBuildServer
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("edge: Caddy build server %q must be an https URL", base)
	}
	if !osArchRe.MatchString(goos) || !osArchRe.MatchString(goarch) {
		return "", fmt.Errorf("edge: invalid os/arch %q/%q for a Caddy build", goos, goarch)
	}
	q := url.Values{}
	q.Set("os", goos)
	q.Set("arch", goarch)
	for _, p := range packages {
		if !ValidPackagePath(p) {
			return "", fmt.Errorf("edge: refusing Caddy plugin package path %q", p)
		}
		q.Add("p", p)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// InstallOptions configures InstallPluginBuild.
type InstallOptions struct {
	DataDir     string   // the Mooring-owned binary goes to <DataDir>/bin/caddy
	Packages    []string // Go module paths to compile in (the DNS providers needed + any plugins carried over)
	WantModules []string // module IDs the new binary must have (e.g. dns.providers.cloudflare)
	BuildServer string   // "" = DefaultBuildServer
	GOOS        string   // "" = this host
	GOARCH      string   // "" = this host
	Client      *http.Client
	// Owner, when set, receives the bin dir and the new binary (lchown) before the check runs: `mooring
	// setup` runs as root and hands them to the service user; the service itself leaves it nil.
	Owner *Owner
}

// Owner is a file owner for InstallOptions.Owner.
type Owner struct{ Uid, Gid int }

// staleDownloadAge is how old an abandoned `caddy.new.*` download must be before an install removes it
// (well past downloadTimeout, so a concurrent install's download is never taken).
const staleDownloadAge = time.Hour

// InstallPluginBuild downloads a Caddy with opt.Packages compiled in from the build server and makes
// it the Mooring-owned binary. The swap is safe: the download goes to a uniquely named
// bin/caddy.new.<random> (size-capped, https only, redirects included), is verified (its `version`
// runs and is >= MinCaddyVersion, and `list-modules` has every WantModule), the current owned binary
// (if any) is kept as bin/caddy.bak, and the new one is renamed into place, so there is never a moment
// with no binary at bin/caddy. On any failure the current binary is left untouched. No file
// capabilities are needed: the edge child gets CAP_NET_BIND_SERVICE as an ambient capability from the
// mooring unit.
//
// Every file operation goes through an os.Root on data_dir: data_dir belongs to the service user, and a
// root caller (setup) must never follow a symlink planted there (a `bin` pointing at /usr/local/bin,
// say) out of data_dir. The unique temp name keeps two concurrent installs (setup while the service
// installs) from renaming each other's half-written file into place.
func InstallPluginBuild(ctx context.Context, opt InstallOptions) (string, error) {
	if opt.DataDir == "" {
		return "", errors.New("edge: no data_dir for the Mooring-owned caddy")
	}
	// No Packages is a plain, current standard build (setup replacing a Caddy older than
	// MinCaddyVersion when no DNS plugin is needed).
	goos, goarch := opt.GOOS, opt.GOARCH
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	src, err := BuildServerURL(opt.BuildServer, goos, goarch, opt.Packages)
	if err != nil {
		return "", err
	}
	root, err := os.OpenRoot(opt.DataDir)
	if err != nil {
		return "", fmt.Errorf("edge: open %s: %w", opt.DataDir, err)
	}
	defer root.Close()
	const binDir, dst, bak = "bin", "bin/caddy", "bin/caddy.bak"
	if err := root.MkdirAll(binDir, 0o700); err != nil {
		return "", fmt.Errorf("edge: create %s/bin: %w", opt.DataDir, err)
	}
	if fi, err := root.Lstat(binDir); err != nil || !fi.IsDir() {
		return "", fmt.Errorf("edge: %s/bin is not a directory (a symlink is refused)", opt.DataDir)
	}
	if opt.Owner != nil {
		if err := root.Lchown(binDir, opt.Owner.Uid, opt.Owner.Gid); err != nil {
			return "", fmt.Errorf("edge: chown %s/bin: %w", opt.DataDir, err)
		}
	}
	removeStaleDownloads(root, binDir)
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", err
	}
	tmp := binDir + "/caddy.new." + hex.EncodeToString(rnd[:])
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return "", fmt.Errorf("edge: write the Caddy download: %w", err)
	}
	derr := download(ctx, opt.Client, src, f)
	if cerr := f.Close(); derr == nil && cerr != nil {
		derr = fmt.Errorf("edge: write the Caddy download: %w", cerr)
	}
	if derr != nil {
		_ = root.Remove(tmp)
		return "", derr
	}
	// Hand it to the service user BEFORE checking it: a root caller runs the check unprivileged
	// (runCaddy), so the account it drops to must be able to execute the 0700 file.
	if opt.Owner != nil {
		if err := root.Lchown(tmp, opt.Owner.Uid, opt.Owner.Gid); err != nil {
			_ = root.Remove(tmp)
			return "", fmt.Errorf("edge: chown the Caddy download: %w", err)
		}
	}
	if err := verifyCaddy(ctx, filepath.Join(opt.DataDir, tmp), opt.WantModules); err != nil {
		_ = root.Remove(tmp)
		return "", err
	}
	if fi, err := root.Lstat(dst); err == nil && fi.Mode().IsRegular() {
		// Keep the previous build. A hard link leaves dst in place, so the rename below replaces it
		// atomically; refuse the swap rather than lose the only known-good binary.
		_ = root.Remove(bak)
		if err := root.Link(dst, bak); err != nil {
			_ = root.Remove(tmp)
			return "", fmt.Errorf("edge: keep the previous caddy as %s/%s: %w", opt.DataDir, bak, err)
		}
	}
	if err := root.Rename(tmp, dst); err != nil {
		_ = root.Remove(tmp)
		return "", fmt.Errorf("edge: install %s: %w", OwnedCaddyPath(opt.DataDir), err)
	}
	return OwnedCaddyPath(opt.DataDir), nil
}

// removeStaleDownloads deletes `caddy.new*` files in dir older than staleDownloadAge — what an
// interrupted install leaves behind.
func removeStaleDownloads(root *os.Root, dir string) {
	d, err := root.Open(dir)
	if err != nil {
		return
	}
	entries, _ := d.ReadDir(-1)
	d.Close()
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "caddy.new") {
			continue
		}
		if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) > staleDownloadAge {
			_ = root.Remove(dir + "/" + e.Name())
		}
	}
}

// download streams src into w, refusing a non-200 answer, an empty body, a body over
// maxCaddyDownload, and any redirect off https.
func download(ctx context.Context, c *http.Client, src string, w io.Writer) error {
	if c == nil {
		c = &http.Client{Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 5 * time.Minute, // a fresh plugin combination is compiled before the reply
			ForceAttemptHTTP2:     true,
			DisableKeepAlives:     true, // one download per attempt: leave no idle connection behind
		}}
	}
	cc := *c // never mutate the caller's client
	cc.CheckRedirect = httpsOnlyRedirects
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "mooring")
	resp, err := cc.Do(req)
	if err != nil {
		return fmt.Errorf("edge: download a Caddy plugin build: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return fmt.Errorf("edge: Caddy build server answered %s: %s", resp.Status, tailLines(body, errTailLines))
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, maxCaddyDownload+1))
	if err != nil {
		return fmt.Errorf("edge: write the Caddy download: %w", err)
	}
	if n > maxCaddyDownload {
		return fmt.Errorf("edge: the Caddy download is over %d MiB — refusing it", maxCaddyDownload>>20)
	}
	if n == 0 {
		return errors.New("edge: the Caddy build server sent an empty file")
	}
	return nil
}

func httpsOnlyRedirects(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing a redirect off https (to %s)", req.URL.Redacted())
	}
	return nil
}

// verifyCaddy checks a downloaded binary before it can go live: it runs, its version is at least
// MinCaddyVersion, and it has every wanted module.
func verifyCaddy(ctx context.Context, bin string, want []string) error {
	v, err := CaddyVersion(ctx, bin)
	if err != nil {
		return fmt.Errorf("edge: the downloaded Caddy does not run: %w", err)
	}
	if !v.AtLeast(MinCaddyVersion) {
		return fmt.Errorf("edge: the downloaded Caddy is %s, older than %s", v, MinCaddyVersion)
	}
	if v.Major != supportedCaddyMajor {
		return fmt.Errorf("edge: the downloaded Caddy is %s; this Mooring supports Caddy %d.x — keeping the current binary", v, supportedCaddyMajor)
	}
	mods, err := CaddyModules(ctx, bin)
	if err != nil {
		return fmt.Errorf("edge: the downloaded Caddy can't list its modules: %w", err)
	}
	var missing []string
	for _, m := range want {
		if !mods[m] {
			missing = append(missing, m)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("edge: the downloaded Caddy lacks %s", strings.Join(missing, ", "))
	}
	return nil
}

// runCaddy runs a short, daemon-less caddy command (version, list-modules) with a timeout and an
// empty environment, returning its output; a failure carries the bounded tail of that output.
func runCaddy(ctx context.Context, bin string, args ...string) ([]byte, error) {
	if bin == "" {
		return nil, errors.New("no caddy binary")
	}
	cctx, cancel := context.WithTimeout(ctx, caddyCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Env = []string{"HOME=" + os.TempDir()}
	cmd.Dir = "/" // traversable by the dropped-to account, whatever the caller's cwd
	// Never as root, no controlling terminal, the whole group killed on timeout (hardenCaddyCmd).
	if err := hardenCaddyCmd(cmd); err != nil {
		return nil, err
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("`%s %s` failed (%v): %s", filepath.Base(bin), strings.Join(args, " "), err, tailLines(out, errTailLines))
	}
	return out, nil
}

// tailLines returns the last n non-empty lines of b joined with " | " (bounded to 4 KiB), so a failed
// command's error carries its real cause rather than only its final line.
func tailLines(b []byte, n int) string {
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	s := strings.Join(lines, " | ")
	if len(s) > 4096 {
		s = s[len(s)-4096:]
	}
	return s
}
