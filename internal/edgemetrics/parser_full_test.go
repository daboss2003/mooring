package edgemetrics

import "testing"

func TestParseAccessFull(t *testing.T) {
	line := []byte(`{"logger":"http.log.access.x","duration":0.34,"status":502,"request":{"host":"api.example.com:443","uri":"/v1/orders?x=1","method":"POST","remote_ip":"1.2.3.4"}}`)
	r, ok := ParseAccessFull(line)
	if !ok {
		t.Fatal("should parse a well-formed access line")
	}
	if r.Host != "api.example.com" || r.Path != "/v1/orders" || r.Method != "POST" || r.Status != 502 || r.RemoteIP != "1.2.3.4" || r.DurMs != 340 {
		t.Errorf("parsed wrong: %+v", r)
	}
	// remote_addr fallback (older Caddy: "ip:port").
	if r2, ok := ParseAccessFull([]byte(`{"status":500,"request":{"host":"a.com","uri":"/","remote_addr":"9.9.9.9:5555"}}`)); !ok || r2.RemoteIP != "9.9.9.9" {
		t.Errorf("remote_addr fallback: %+v ok=%v", r2, ok)
	}
	// junk / no host → not an access entry.
	if _, ok := ParseAccessFull([]byte(`not json`)); ok {
		t.Error("junk must not parse")
	}
	if _, ok := ParseAccessFull([]byte(`{"status":200,"request":{}}`)); ok {
		t.Error("a host-less entry must not parse")
	}
}

func TestLookupRoutePrefix(t *testing.T) {
	idx := NewHostIndex()
	idx.Set([]Route{
		{Host: "h.com", PathPrefix: "/api", Key: Key{App: "shop", Service: "api"}},
		{Host: "h.com", PathPrefix: "", Key: Key{App: "shop", Service: "web"}},
	})
	if k, p, ok := idx.LookupRoute("h.com", "/api/orders"); !ok || p != "/api" || k.Service != "api" {
		t.Errorf("longest-prefix route: key=%+v prefix=%q ok=%v", k, p, ok)
	}
	if k, p, ok := idx.LookupRoute("h.com", "/other"); !ok || p != "" || k.Service != "web" {
		t.Errorf("whole-host route: key=%+v prefix=%q ok=%v", k, p, ok)
	}
	if _, _, ok := idx.LookupRoute("nope.com", "/"); ok {
		t.Error("unknown host must not resolve")
	}
}
