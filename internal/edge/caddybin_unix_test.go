//go:build unix

package edge

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A new owned build is 0755 even under the service's 0077 umask (the host vulnerability scan reads it
// without CAP_DAC_OVERRIDE); the bin dir stays 0700.
func TestInstallPluginBuildMakesTheBinaryReadable(t *testing.T) {
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })
	dataDir := t.TempDir()
	srv, _ := buildServer(t, http.StatusOK, fakeCaddy("v2.11.2 h1:x", []string{"dns.providers.cloudflare"}, nil))
	path, err := InstallPluginBuild(context.Background(), InstallOptions{DataDir: dataDir, Packages: []string{"github.com/caddy-dns/cloudflare"},
		WantModules: []string{"dns.providers.cloudflare"}, BuildServer: srv.URL, Client: srv.Client(), GOOS: "linux", GOARCH: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o755 {
		t.Errorf("the owned build is %o; want 0755", got)
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("the bin dir is %o; want 0700", got)
	}
}
