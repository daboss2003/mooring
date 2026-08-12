package edgemetrics

import "testing"

func TestParseAccess(t *testing.T) {
	// A real Caddy access line (the shape from the operator's own edge logs).
	line := []byte(`{"level":"info","ts":1786489778.46,"logger":"http.log.access.log0","msg":"handled request","request":{"remote_ip":"1.2.3.4","host":"api.anchor-api.credlockng.com","method":"GET","uri":"/api/v2/agent/x/config?trace=1"},"duration":0.1262139,"status":200}`)
	host, path, durMs, status, ok := ParseAccess(line)
	if !ok {
		t.Fatal("a valid access line should parse")
	}
	if host != "api.anchor-api.credlockng.com" {
		t.Errorf("host = %q", host)
	}
	if path != "/api/v2/agent/x/config" { // query stripped
		t.Errorf("path = %q, want the query stripped", path)
	}
	if durMs < 126.2 || durMs > 126.3 { // 0.1262139s → ~126.2ms
		t.Errorf("durMs = %v, want ~126.2", durMs)
	}
	if status != 200 {
		t.Errorf("status = %d", status)
	}

	// A client that sends "Host: name:443" still attributes to the bare hostname.
	if host, _, _, _, ok := ParseAccess([]byte(`{"logger":"http.log.access.x","request":{"host":"api.example.com:443","uri":"/"},"duration":0.01,"status":200}`)); !ok || host != "api.example.com" {
		t.Errorf("host with port: got host=%q ok=%v, want api.example.com", host, ok)
	}

	// Non-access / garbage lines must be skipped (ok=false), never crash.
	for _, bad := range [][]byte{
		[]byte(`{"level":"error","logger":"http.log.error","msg":"dial tcp: refused"}`), // error line, no host
		[]byte(`not json at all`),
		[]byte(`{"request":{"method":"GET"},"duration":0.5}`), // no host
		[]byte(``),
		[]byte(`{}`),
	} {
		if _, _, _, _, ok := ParseAccess(bad); ok {
			t.Errorf("a non-access/garbage line must not parse as access: %s", bad)
		}
	}
}
