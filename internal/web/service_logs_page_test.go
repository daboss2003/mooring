package web

import "testing"

// the exact 200-response line the user reported being colored red (responseTime 574 was misread as 5xx).
const userStatus200Line = `{"statusCode":200,"headers":{"content-security-policy":"default-src 'self';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests","cross-origin-opener-policy":"same-origin","cross-origin-resource-policy":"same-origin","origin-agent-cluster":"?1","referrer-policy":"no-referrer","strict-transport-security":"max-age=31536000; includeSubDomains; preload","x-content-type-options":"nosniff","x-dns-prefetch-control":"off","x-download-options":"noopen","x-frame-options":"SAMEORIGIN","x-permitted-cross-domain-policies":"none","x-xss-protection":"0","vary":"Origin","access-control-allow-credentials":"true","access-control-expose-headers":"X-Access-Token","content-type":"application/json; charset=utf-8","content-length":"494"}},"responseTime":574,"msg":"request completed"}`

func TestLogLevel(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{userStatus200Line, ""}, // statusCode is 200; the bare 574/494 must NOT count as a status

		// status only counts as a status FIELD's value.
		{`{"statusCode":502,"msg":"x"}`, "error"},
		{`{"statusCode":404}`, "warn"},
		{`{"statusCode":200}`, ""},
		{`status=500`, "error"},
		{`status_code=404`, "warn"},
		{`http_status=500`, "error"},
		{`{"responseStatus":502}`, "error"}, // camelCase compound status key still works
		{`"status": 503`, "error"},
		{`{"statusCode":  500}`, "error"},                        // pretty-printed: two spaces after the colon
		{`"status" : 502`, "error"},                              // spaces around the colon
		{`"status":"502"`, "error"},                              // quoted string value
		{`{"responseTime":574,"latencyMs":500,"bytes":418}`, ""}, // bare 4xx/5xx numbers, no status field
		{`{"statusTime":574,"code":200}`, ""},                    // a field that BEGINS with status is not a status field
		{`{"statusCount":503}`, ""},                              // ditto — 503 here is a count, not a status

		// level keywords still classify (and outrank / combine with status).
		{`[WARN] retrying`, "warn"},
		{`level=debug connecting`, "debug"},
		{`trace: entering handler`, "debug"},
		{`{"level":"error","statusCode":200}`, "error"}, // keyword error even though status is 2xx
		{`panic: runtime error`, "error"},
		{`a warning and an error`, "error"}, // error outranks warn
		{`stderr stream opened`, ""},        // substring inside a token must NOT match
		{`processed request in 12ms`, ""},
		{`GET /api 502 12ms`, ""}, // a bare access-log status (no status field) is not colored anymore
	}
	for _, c := range cases {
		if got := logLevel(c.in); got != c.want {
			t.Errorf("logLevel(%q) = %q, want %q", short(c.in), got, c.want)
		}
	}
}

func shortLine(s string) string {
	if len(s) > 60 {
		return s[:60] + "…"
	}
	return s
}
