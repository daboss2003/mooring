package web

import "testing"

func TestLogLevel(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`{"level":"error","statusCode":502,"msg":"x"}`, "error"}, // keyword AND status both say error
		{`GET /api 502 12ms`, "error"},                            // bare 5xx status
		{`[WARN] retrying`, "warn"},
		{`GET /missing 404`, "warn"}, // 4xx status
		{`level=debug connecting`, "debug"},
		{`trace: entering handler`, "debug"},
		{`{"level":"info","statusCode":200}`, ""}, // info/2xx → no color
		{`processed request in 12ms`, ""},         // nothing severity-ish
		{`panic: runtime error`, "error"},
		{`stderr stream opened`, ""},        // a substring inside a token must NOT match (stderr != err)
		{`a warning and an error`, "error"}, // error outranks warn
	}
	for _, c := range cases {
		if got := logLevel(c.in); got != c.want {
			t.Errorf("logLevel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
