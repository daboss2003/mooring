// Package docker is a thin, READ-ONLY Docker Engine API client that talks to the
// loopback docker-socket-proxy (plan §3) — never the raw socket. It deliberately
// implements only the handful of read endpoints the proxy's verb allowlist
// permits (CONTAINERS/INFO/VERSION), instead of pulling in the full Docker Go
// SDK: that keeps the binary near the ~12–18 MB footprint target (plan §2) and
// the dependency/supply-chain surface minimal (plan §15). Container-supplied
// fields (names, labels, image) are untrusted input and must be output-encoded
// by callers (html/template does this).
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Compose label keys Mooring groups containers by (an app = one project) and
// targets `docker compose` with (the project dir + config files).
const (
	LabelProject     = "com.docker.compose.project"
	LabelService     = "com.docker.compose.service"
	LabelWorkingDir  = "com.docker.compose.project.working_dir"
	LabelConfigFiles = "com.docker.compose.project.config_files"
	// LabelOneOff marks a `docker compose run` container ("True"). These are transient one-shot
	// containers (cron scheduled_tasks, backup/restore sidecars) — NOT supervised services — so
	// the monitor/self-heal must exclude them from the app snapshot.
	LabelOneOff = "com.docker.compose.oneoff"
)

const maxResponseBytes = 16 << 20 // cap untrusted API responses

// Client is a read-only Engine API client over the loopback socket-proxy.
type Client struct {
	base string
	hc   *http.Client
}

// New returns a client targeting a loopback proxy address (host:port). The
// caller (config validation) guarantees the address is loopback.
func New(proxyAddr string) *Client {
	return &Client{
		base: "http://" + proxyAddr,
		hc: &http.Client{
			Timeout: 15 * time.Second,
			// Never follow redirects (review #4): a 3xx from a compromised/
			// misconfigured proxy (e.g. Location: http://169.254.169.254/...) must
			// not move Mooring's request off the loopback proxy. ErrUseLastResponse
			// returns the 3xx verbatim, which get()'s non-200 check then rejects.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
				MaxIdleConns:          4,
				IdleConnTimeout:       60 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
			},
		},
	}
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body := io.LimitReader(resp.Body, maxResponseBytes)
	if resp.StatusCode != http.StatusOK {
		// Drain a little for connection reuse; don't echo raw daemon errors.
		_, _ = io.Copy(io.Discard, io.LimitReader(body, 4096))
		return fmt.Errorf("docker: GET %s: status %d", path, resp.StatusCode)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, body)
		return nil
	}
	return json.NewDecoder(body).Decode(out)
}

// Version reports the daemon version (also a liveness probe).
func (c *Client) Version(ctx context.Context) (Version, error) {
	var v Version
	err := c.get(ctx, "/version", &v)
	return v, err
}

// Info returns daemon-level info (container counts, ncpu, mem).
func (c *Client) Info(ctx context.Context) (Info, error) {
	var i Info
	err := c.get(ctx, "/info", &i)
	return i, err
}

// ListContainers lists containers. all=true includes stopped ones.
func (c *Client) ListContainers(ctx context.Context, all bool) ([]Container, error) {
	q := url.Values{}
	if all {
		q.Set("all", "1")
	}
	var cs []Container
	err := c.get(ctx, "/containers/json?"+q.Encode(), &cs)
	return cs, err
}

// InspectContainer returns the detailed state of one container.
func (c *Client) InspectContainer(ctx context.Context, id string) (ContainerInspect, error) {
	var ci ContainerInspect
	err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/json", &ci)
	return ci, err
}

// StatsOneShot returns a single, immediate stats sample (no daemon-side double
// read). CPU% is derived by the caller from deltas between successive samples.
func (c *Client) StatsOneShot(ctx context.Context, id string) (Stats, error) {
	var s Stats
	err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/stats?stream=false&one-shot=true", &s)
	return s, err
}
