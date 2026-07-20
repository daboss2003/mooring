package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/url"
	"strings"

	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/ops"
)

// All operator-facing assets are embedded in the binary (plan §2): no asset
// pipeline, no node_modules. All rendering uses html/template (never
// text/template / template.HTML on external content — plan §15 lint).

//go:embed templates/*.html static/*
var embeddedAssets embed.FS

var templateFuncs = template.FuncMap{
	"humanBytes": humanBytes,
	"pct1":       func(f float64) string { return fmt.Sprintf("%.1f", f) },
	// pathEscape encodes an untrusted compose project name into a single safe
	// URL path segment (review #3/#10): '/' '?' '#' etc. become %-encoded so the
	// {project} route matches and r.PathValue decodes back to the exact value.
	"pathEscape": url.PathEscape,
	// shortSha abbreviates a git commit sha for display (numeric-hex only, always safe).
	"shortSha": shortSha,
	// unixTS renders a unix timestamp's UTC display text; the "ts" template wraps it
	// in a <time data-ts> element app.js localises to the viewer's timezone.
	"unixTS": unixTS,
	// sparkPoints builds an SVG polyline "points" string from Mooring-computed
	// health scores (0..1). The values are numeric (never app strings), so the
	// output is safe to embed in an html/template-escaped attribute.
	"sparkPoints": sparkPoints,
	// ratioPct returns used/total as a 0..100 float (0 when total==0). Used for
	// the dashboard meter widths, which are SVG rect attributes (NOT CSS) — the CSP
	// is style-src 'self', so inline style="" is forbidden.
	"ratioPct": func(used, total uint64) float64 {
		if total == 0 {
			return 0
		}
		return float64(used) / float64(total) * 100
	},
	// meterClass buckets a 0..100 value into a severity class for the meter fill.
	"meterClass": func(p float64) string {
		switch {
		case p >= 90:
			return "is-down"
		case p >= 75:
			return "is-warn"
		default:
			return ""
		}
	},
	// appsUp counts apps with every service running (for the overview stat card).
	"appsUp": func(apps []monitor.App) int {
		n := 0
		for _, a := range apps {
			if !a.Degraded() {
				n++
			}
		}
		return n
	},
	// assetVer is a content hash of the embedded JS/CSS, appended as ?v= to their
	// URLs so a new build busts the browser cache (the assets are served with a
	// 1-hour max-age; without this, an upgrade's UI fixes wouldn't reach the browser
	// until the cache expired or the operator hard-refreshed).
	"assetVer": func() string { return staticAssetVer },
}

// staticAssetVer is the cache-bust token for /static/app.js + app.css, computed once
// from their embedded bytes at package init.
var staticAssetVer = computeStaticVer()

func computeStaticVer() string {
	h := sha256.New()
	for _, name := range []string{"static/app.js", "static/app.css", "static/favicon.svg"} {
		if b, err := embeddedAssets.ReadFile(name); err == nil {
			h.Write(b)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

const sparkW, sparkH = 220.0, 32.0

func sparkPoints(pts []ops.SnapshotPoint) string {
	if len(pts) < 2 {
		return ""
	}
	var b strings.Builder
	last := float64(len(pts) - 1)
	for i, p := range pts {
		x := float64(i) / last * sparkW
		v := p.Value
		if v < 0 {
			v = 0
		} else if v > 1 {
			v = 1
		}
		y := (1 - v) * sparkH
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%.1f,%.1f", x, y)
	}
	return b.String()
}

func parseTemplates() (*template.Template, error) {
	return template.New("").Funcs(templateFuncs).ParseFS(embeddedAssets, "templates/*.html")
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
