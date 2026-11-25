package parse

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/siem"
)

// caddyAccess is the part of a Caddy access-log entry the SIEM keeps. Intentional: of the request
// headers only User-Agent and Sec-Fetch-Site are decoded; Caddy logs them all (Cookie/Authorization
// as REDACTED), and none of the others is stored.
type caddyAccess struct {
	Logger  string  `json:"logger"`
	TS      float64 `json:"ts"` // epoch seconds
	Request struct {
		RemoteIP string `json:"remote_ip"`
		ClientIP string `json:"client_ip"`
		Proto    string `json:"proto"`
		Method   string `json:"method"`
		Host     string `json:"host"`
		URI      string `json:"uri"`
		Headers  struct {
			UA        []string `json:"User-Agent"`
			FetchSite []string `json:"Sec-Fetch-Site"`
		} `json:"headers"`
		TLS struct {
			ServerName string `json:"server_name"`
		} `json:"tls"`
	} `json:"request"`
	BytesRead float64 `json:"bytes_read"`
	UserID    string  `json:"user_id"`
	Duration  float64 `json:"duration"` // seconds
	Size      float64 `json:"size"`
	Status    float64 `json:"status"`
}

// EdgeAccess parses one Caddy access-log JSON line (logger http.log.access.*) into a
// KindHTTPRequest event; IP is request.client_ip (the real client behind trusted proxies), else
// remote_ip. ok is false for a line that isn't an access log entry.
func EdgeAccess(raw []byte, now time.Time) (siem.Event, bool) {
	if !bytes.Contains(raw, []byte(`"http.log.access`)) {
		return siem.Event{}, false // Caddy's other loggers (tls, admin, …) share the pipe
	}
	var a caddyAccess
	if err := json.Unmarshal(raw, &a); err != nil {
		// A field of an unexpected type is skipped and the rest kept; anything else isn't JSON.
		var te *json.UnmarshalTypeError
		if !errors.As(err, &te) {
			return siem.Event{}, false
		}
	}
	if a.Logger != "http.log.access" && !strings.HasPrefix(a.Logger, "http.log.access.") {
		return siem.Event{}, false
	}
	e := siem.Event{Src: siem.SrcEdge, Kind: siem.KindHTTPRequest, Lvl: siem.LvlInfo,
		TS: within(epoch(a.TS), now)}
	r := &a.Request
	if e.IP = parseIP(r.ClientIP); e.IP == "" {
		e.IP = parseIP(r.RemoteIP)
	}
	path, query, _ := strings.Cut(r.URI, "?")
	f := make(map[string]any, 12)
	setStr(f, "method", r.Method)
	setStr(f, "host", r.Host)
	setStr(f, "path", path)
	setStr(f, "query", query)
	setStr(f, "proto", r.Proto)
	setStr(f, "sni", r.TLS.ServerName)
	setStr(f, "user_id", a.UserID)
	if len(r.Headers.UA) > 0 {
		setStr(f, "ua", r.Headers.UA[0])
	}
	if len(r.Headers.FetchSite) > 0 {
		setStr(f, "fetch_site", fetchSite(r.Headers.FetchSite[0]))
	}
	setNum(f, "status", a.Status)
	setNum(f, "dur_ms", a.Duration*1000)
	setNum(f, "size", a.Size)
	setNum(f, "bytes_read", a.BytesRead)
	e.F = f
	switch {
	case a.Status >= 500:
		e.Lvl = siem.LvlError
	case a.Status >= 400:
		e.Lvl = siem.LvlWarn
	}
	e.Msg = r.Method + " " + r.Host + path + " " + strconv.FormatFloat(a.Status, 'f', -1, 64)
	return e, true
}

func setStr(f map[string]any, k, v string) {
	if v != "" {
		f[k] = v
	}
}

func setNum(f map[string]any, k string, v float64) {
	if !math.IsInf(v, 0) && !math.IsNaN(v) {
		f[k] = v
	}
}

// Audit converts one Mooring audit event recorded at ts (Kind siem.KindMooringPrefix+Action).
func Audit(ts time.Time, ev audit.Event) siem.Event {
	e := siem.Event{TS: ts, Src: siem.SrcMooring, Kind: siem.KindMooringPrefix + ev.Action, Lvl: siem.LvlInfo,
		Actor: ev.Actor, IP: ev.IP, Msg: ev.Detail, Out: siem.OutFailure}
	// Intentional: an unset outcome is ok, the default audit.Log records.
	ok := ev.Outcome == audit.OK || ev.Outcome == ""
	if ok {
		e.Out = siem.OutSuccess
	}
	switch {
	case ev.Outcome == audit.Error:
		e.Lvl = siem.LvlError
	case ev.Level == audit.Security && !ok:
		e.Lvl = siem.LvlWarn
	}
	if ev.Target != "" || ev.UA != "" {
		e.F = map[string]any{}
		if ev.Target != "" {
			e.F["target"] = ev.Target
		}
		if ev.UA != "" {
			e.F["ua"] = ev.UA
		}
	}
	return e
}

// fetchSite is a Sec-Fetch-Site value as stored in f.fetch_site: one of the four values browsers
// send (trimmed, lower-cased), or "" for anything else.
// Intentional: a value no browser sends stores nothing. Any client can set the header, so a
// made-up value is not evidence of a browser (the request is then judged by its User-Agent like
// any other), and no free text from a client reaches the field.
func fetchSite(v string) string {
	switch v = strings.ToLower(strings.TrimSpace(v)); v {
	case "cross-site", "same-origin", "same-site", "none":
		return v
	}
	return ""
}
