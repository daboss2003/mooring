package respond

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/daboss2003/mooring/internal/siem"
)

// clean makes text safe for a one-line alert that goes to chat channels: control and format
// characters are removed, and so are '<', '>', '@' and '`'. The value is then cut to n bytes.
// Intentional: without those four, a name like "<!channel>" or "@everyone" would notify a Slack
// or Discord channel (the rule engine's summaries follow the same rule).
func clean(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t' || r == '\r':
			b.WriteByte(' ')
		case r == utf8.RuneError, unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == '<', r == '>', r == '@', r == '`':
		default:
			b.WriteRune(r)
		}
		if b.Len() > n+4 {
			break
		}
	}
	return siem.Cut(strings.TrimSpace(b.String()), n)
}

// plain is s with control and format characters removed, on one line, cut to n bytes.
func plain(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t' || r == '\r':
			b.WriteByte(' ')
		case r == utf8.RuneError, unicode.IsControl(r), unicode.Is(unicode.Cf, r):
		default:
			b.WriteRune(r)
		}
		if b.Len() > n+4 {
			break
		}
	}
	return siem.Cut(strings.TrimSpace(b.String()), n)
}

// word is a value as one token of an audit record's detail: spaces become '_'.
func word(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return '_'
		}
		return r
	}, plain(s, 128))
}

// fmtDur writes a duration as "45s", "10m", "1h30m", "7d".
func fmtDur(d time.Duration) string {
	d = d.Round(time.Second)
	if d <= 0 {
		return "0s"
	}
	if d >= 24*time.Hour && d%(24*time.Hour) == 0 {
		return strconv.FormatInt(int64(d/(24*time.Hour)), 10) + "d"
	}
	h, m, s := d/time.Hour, (d%time.Hour)/time.Minute, (d%time.Minute)/time.Second
	var b strings.Builder
	if h > 0 {
		b.WriteString(strconv.FormatInt(int64(h), 10) + "h")
	}
	if m > 0 {
		b.WriteString(strconv.FormatInt(int64(m), 10) + "m")
	}
	if s > 0 && h == 0 {
		b.WriteString(strconv.FormatInt(int64(s), 10) + "s")
	}
	return b.String()
}

func invalidIn(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{siem.ErrInvalidInput}, a...)...)
}

// checkActor checks the acting owner's name: plain text on one line.
func checkActor(actor string) error {
	if actor == "" || plain(actor, siem.MaxShort) != actor {
		return invalidIn("the actor must be a user name of at most %d bytes on one line", siem.MaxShort)
	}
	return nil
}
