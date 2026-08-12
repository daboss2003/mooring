package edgemetrics

import (
	"encoding/json"
	"net"
	"strings"
)

// accessEntry is the slice of a Caddy JSON access-log line we use. Caddy logs each handled request
// as {"logger":"http.log.access...","request":{"host":...,"uri":...},"duration":<seconds float>,"status":n}.
type accessEntry struct {
	Logger   string  `json:"logger"`
	Duration float64 `json:"duration"` // seconds
	Status   int     `json:"status"`
	Request  struct {
		Host string `json:"host"`
		URI  string `json:"uri"` // path + optional ?query
	} `json:"request"`
}

// ParseAccess extracts (host, path, latency-ms, status) from one Caddy JSON access-log line. The
// path is the request URI with any query string stripped (so it can be prefix-matched to a route).
// ok=false for any non-access line (Caddy's own logs, errors, malformed JSON) or an entry missing a
// host — callers simply skip those, so a hostile/garbage line can never crash or mis-record.
func ParseAccess(line []byte) (host, path string, durMs float64, status int, ok bool) {
	var e accessEntry
	if err := json.Unmarshal(line, &e); err != nil {
		return "", "", 0, 0, false
	}
	if e.Request.Host == "" {
		return "", "", 0, 0, false // not an access entry (or no host to attribute to)
	}
	host = e.Request.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h // a client that sent "Host: name:443" still attributes to the bare hostname
	}
	path = e.Request.URI
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return host, path, e.Duration * 1000.0, e.Status, true
}
