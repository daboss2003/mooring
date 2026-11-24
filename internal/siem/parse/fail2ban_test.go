package parse

import (
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

func TestFail2Ban(t *testing.T) {
	cases := []struct {
		line          string
		kind, lvl, ip string
		f             map[string]any
		msg           string
	}{
		{"2026-11-23 13:14:41,123 fail2ban.actions        [123]: NOTICE  [sshd] Ban 198.51.100.7",
			siem.KindFail2BanBan, siem.LvlWarn, "198.51.100.7",
			map[string]any{"jail": "sshd", "logger": "fail2ban.actions", "pid": 123.0}, "[sshd] Ban 198.51.100.7"},
		{"2026-11-23 13:24:41,001 fail2ban.actions        [123]: NOTICE  [sshd] Unban 198.51.100.7",
			siem.KindFail2BanUnban, siem.LvlInfo, "198.51.100.7", map[string]any{"jail": "sshd"}, ""},
		{"2026-11-23 13:00:00,500 fail2ban.actions        [123]: NOTICE  [nginx-http-auth] Restore Ban 2001:db8::9",
			siem.KindFail2BanBan, siem.LvlInfo, "2001:db8::9", map[string]any{"jail": "nginx-http-auth", "restore": true}, ""},
		{"2026-11-23 13:14:40,999 fail2ban.filter         [123]: INFO    [sshd] Found 198.51.100.7 - 2026-11-23 13:14:40",
			siem.KindLog, siem.LvlInfo, "198.51.100.7", map[string]any{"jail": "sshd", "logger": "fail2ban.filter"}, ""},
		{"2026-11-23 13:14:42,000 fail2ban.actions        [123]: NOTICE  [sshd] 198.51.100.7 already banned",
			siem.KindLog, siem.LvlInfo, "198.51.100.7", map[string]any{"jail": "sshd"}, ""},
		{"2026-11-23 13:14:42,000 fail2ban.server         [99]: INFO    Starting Fail2ban v1.0.2",
			siem.KindLog, siem.LvlInfo, "", map[string]any{"logger": "fail2ban.server"}, "Starting Fail2ban v1.0.2"},
		{"2026-11-23 13:14:42,000 fail2ban.jail           [99]: WARNING Jail 'x' has no actions",
			siem.KindLog, siem.LvlWarn, "", nil, ""},
		{"2026-11-23 13:14:42,000 fail2ban.transmitter    [99]: ERROR   Command failed",
			siem.KindLog, siem.LvlError, "", nil, ""},
		// Older format without a pid, and a ban of something that isn't an address.
		{"2026-11-23 13:14:42,000 fail2ban.actions: WARNING [sshd] Ban 198.51.100.8",
			siem.KindFail2BanBan, siem.LvlWarn, "198.51.100.8", map[string]any{"jail": "sshd"}, ""},
		{"2026-11-23 13:14:42,000 fail2ban.actions        [1]: NOTICE  [sshd] Ban not-an-ip",
			siem.KindFail2BanBan, siem.LvlWarn, "", map[string]any{"jail": "sshd"}, ""},
	}
	for _, c := range cases {
		e, ok := Fail2Ban(c.line, hostNow, wat)
		if !ok {
			t.Errorf("%s: not ok", c.line)
			continue
		}
		checkEvent(t, e)
		if e.Src != siem.SrcHost || e.Kind != c.kind || e.Lvl != c.lvl || e.IP != c.ip {
			t.Errorf("%s:\n kind %q lvl %q ip %q", c.line, e.Kind, e.Lvl, e.IP)
		}
		for k, v := range c.f {
			if e.F[k] != v {
				t.Errorf("%s: F[%s] = %#v want %#v", c.line, k, e.F[k], v)
			}
		}
		if c.msg != "" && e.Msg != c.msg {
			t.Errorf("%s: msg %q", c.line, e.Msg)
		}
	}
	e, _ := Fail2Ban(cases[0].line, hostNow, wat)
	if want := time.Date(2026, 11, 23, 12, 14, 41, 123000000, time.UTC); !e.TS.Equal(want) {
		t.Errorf("TS in loc: %v want %v", e.TS, want)
	}
	// A timestamp more than a day ahead of now is not trusted.
	e, _ = Fail2Ban("2026-12-23 13:14:41,123 fail2ban.actions [1]: NOTICE [sshd] Ban 198.51.100.7", hostNow, wat)
	if !e.TS.Equal(hostNow) {
		t.Errorf("future TS: %v", e.TS)
	}
	if _, ok := Fail2Ban("2026-11-23 13:14:41,123 fail2ban.actions [1]: NOTICE [sshd] Ban 198.51.100.7", hostNow, nil); !ok {
		t.Error("nil loc")
	}
	for _, line := range []string{"", "  ", "garbage", "Traceback (most recent call last):",
		"  File \"/usr/lib/python3/dist-packages/fail2ban/server/action.py\", line 1",
		"2026-13-23 13:14:41,123 fail2ban.actions [1]: NOTICE x", "2026-11-23 13:14:41,123",
		"2026-11-23 13:14:41,123 notfail2ban [1]: NOTICE x", "\x00\xff"} {
		if _, ok := Fail2Ban(line, hostNow, wat); ok {
			t.Errorf("%q must not parse", line)
		}
	}
	e, ok := Fail2Ban("2026-11-23 13:14:41,123 fail2ban.actions [1]: NOTICE ["+strings.Repeat("j", 8<<10)+"] Ban \xff", hostNow, wat)
	if !ok {
		t.Error("long jail")
	}
	checkEvent(t, e)
}
