#!/usr/bin/env bash
# Build/refresh the signed APT repo from a release's .deb packages.
#
#   deploy/apt/publish.sh v1.2.3
#
# Requires: aptly, gh (GitHub CLI, authenticated), gpg with the signing key present.
# Env: GPG_KEY_ID (the signing key id/fingerprint); REPO defaults to daboss2003/mooring.
set -euo pipefail

VERSION="${1:?usage: publish.sh <vX.Y.Z>}"
REPO="${REPO:-daboss2003/mooring}"
DIST="${DIST:-stable}"
COMPONENT="${COMPONENT:-main}"
GPG_KEY_ID="${GPG_KEY_ID:?set GPG_KEY_ID to the signing key fingerprint}"
OUT="${OUT:-public}"
ARCHES="${ARCHES:-amd64 arm64}"   # the linux arches goreleaser builds .debs for

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# Download the release's .deb assets with curl rather than `gh release download`:
# gh can finish the transfer but fail to exit (hangs), and these assets are public.
# For a private repo, export GH_AUTH=1 to send a token.
echo ">> downloading ${VERSION} .deb assets from ${REPO}"
ver="${VERSION#v}"
# Optional auth header for a private repo (no bash arrays — macOS bash 3.2 trips
# over an empty array under `set -u`).
hdr=""
if [ "${GH_AUTH:-}" = "1" ]; then hdr="Authorization: Bearer $(gh auth token)"; fi
for arch in $ARCHES; do
    f="mooring_${ver}_linux_${arch}.deb"
    echo "   $f"
    url="https://github.com/${REPO}/releases/download/${VERSION}/${f}"
    if [ -n "$hdr" ]; then
        curl -fSL --retry 3 --retry-delay 2 -H "$hdr" -o "$workdir/$f" "$url"
    else
        curl -fSL --retry 3 --retry-delay 2 -o "$workdir/$f" "$url"
    fi
done

# Create the aptly repo on first run; ignore if it already exists.
aptly repo create -distribution="$DIST" -component="$COMPONENT" mooring 2>/dev/null || true

echo ">> adding packages"
aptly repo add mooring "$workdir"/*.deb

echo ">> publishing (signed)"
# sign always has >=1 element, so "${sign[@]}" is safe even on bash 3.2. In CI set
# GPG_PASSPHRASE to sign non-interactively (-batch + a 0600 passphrase-file under the
# workdir, removed with it); locally, omit it and gpg-agent/pinentry prompts.
sign=(-gpg-key="$GPG_KEY_ID")
if [ -n "${GPG_PASSPHRASE:-}" ]; then
    pf="$workdir/passphrase"
    (umask 077; printf '%s' "$GPG_PASSPHRASE" > "$pf")
    sign+=(-batch "-passphrase-file=$pf")
fi
if aptly publish list | grep -q "$DIST"; then
    aptly publish update "${sign[@]}" "$DIST"
else
    aptly publish repo "${sign[@]}" -distribution="$DIST" mooring
fi

# Export the rendered repo + the public signing key for static hosting.
mkdir -p "$OUT"
rootdir="$(aptly config show | sed -n 's/.*"rootDir": *"\(.*\)".*/\1/p')"
rootdir="${rootdir/#\~/$HOME}"            # aptly prints "~/.aptly" — expand the leading ~
[ -d "$rootdir/public" ] || rootdir="$HOME/.aptly"   # fallback to the default location
rsync -a --delete "$rootdir/public/" "$OUT/"
gpg --armor --export "$GPG_KEY_ID" > "$OUT/gpg.key"
touch "$OUT/.nojekyll" # serve dists/ + pool/ raw (no GitHub Pages Jekyll processing)

# SEO landing page: this is Mooring's one real, indexable website (the GitHub repo
# aside), so it carries a proper title, meta description, keywords, Open Graph /
# Twitter cards, and JSON-LD so search engines understand what Mooring is. Keep the
# copy keyword-rich for the QUALIFIED terms people actually search ("self-hosted
# paas", "caprover/coolify/dokploy alternative", "docker deploy"), since the bare
# word "mooring" is dominated by boating results.
cat > "$OUT/index.html" <<'HTML'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="google-site-verification" content="PkuSMId0UAbJlQ-wI8AB1HFFVsSbJrXy2oOtxfDBClk">
<title>Mooring — self-hosted PaaS for Docker | CapRover, Coolify &amp; Dokploy alternative</title>
<meta name="description" content="Mooring is a lightweight, security-first self-hosted PaaS and control plane for Docker. Deploy multi-service apps from one typed YAML with automatic HTTPS, monitoring, alerts, backups, Git deploys and self-healing — no Docker Swarm or Kubernetes. A self-hosted Heroku/Railway and CapRover/Coolify/Dokploy alternative.">
<meta name="keywords" content="self-hosted PaaS, self hosted paas, Docker PaaS, control plane for Docker, CapRover alternative, Coolify alternative, Dokploy alternative, Dokku alternative, Heroku alternative self-hosted, Railway alternative, Docker deployment platform, docker compose dashboard, deploy docker apps, self-hosted platform as a service, Mooring">
<link rel="canonical" href="https://daboss2003.github.io/mooring/">
<meta property="og:type" content="website">
<meta property="og:site_name" content="Mooring">
<meta property="og:title" content="Mooring — self-hosted PaaS for Docker (CapRover / Coolify / Dokploy alternative)">
<meta property="og:description" content="Deploy multi-service Docker apps from one typed YAML: automatic HTTPS, monitoring, alerts, backups, Git deploys, self-healing — no Swarm or Kubernetes.">
<meta property="og:url" content="https://daboss2003.github.io/mooring/">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="Mooring — self-hosted PaaS for Docker">
<meta name="twitter:description" content="A lightweight, security-first self-hosted PaaS / control plane for Docker. A CapRover / Coolify / Dokploy alternative — no Swarm or Kubernetes.">
<script type="application/ld+json">
{"@context":"https://schema.org","@type":"SoftwareApplication","name":"Mooring","applicationCategory":"DeveloperApplication","operatingSystem":"Linux","description":"A lightweight, security-first self-hosted PaaS and control plane for Docker. Deploy multi-service apps from one typed YAML with automatic HTTPS, monitoring, alerts, backups, Git deploys and self-healing — no Docker Swarm or Kubernetes.","offers":{"@type":"Offer","price":"0","priceCurrency":"USD"},"url":"https://github.com/daboss2003/mooring","codeRepository":"https://github.com/daboss2003/mooring","license":"https://github.com/daboss2003/mooring/blob/main/LICENSE","keywords":"self-hosted PaaS, Docker, CapRover alternative, Coolify alternative, Dokploy alternative, Heroku alternative"}
</script>
<style>
body{font:16px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:52rem;margin:0 auto;padding:2.5rem 1.2rem;color:#1a1a1a}
h1{font-size:2rem;margin:0 0 .3rem} .tag{font-size:1.15rem;color:#444;margin:.2rem 0 1.4rem}
h2{margin-top:2rem} code,pre{background:#f4f4f5;border-radius:6px} code{padding:.1em .35em}
pre{padding:1rem;overflow:auto} ul{padding-left:1.2rem} a{color:#0b62d6}
table{border-collapse:collapse;width:100%;margin:1rem 0} th,td{border:1px solid #e2e2e2;padding:.4rem .6rem;text-align:left}
</style>
</head>
<body>
<h1>Mooring</h1>
<p class="tag">A lightweight, security-first <strong>self-hosted PaaS</strong> and <strong>control plane for Docker</strong> — deploy multi-service apps from one typed YAML, with no Docker Swarm or Kubernetes.</p>

<p>Mooring is a self-hosted alternative to Heroku and Railway, and to <strong>CapRover</strong>, <strong>Coolify</strong>, and <strong>Dokploy</strong>. You describe a multi-service app in a single <code>mooring.yaml</code>; Mooring generates and owns the Compose file and Dockerfile, provisions HTTPS at the edge, and deploys, monitors, scales, and self-heals it. Most tools put a UI on top of Docker or layer a PaaS on Swarm/Kubernetes — Mooring is a <em>control plane</em>: <code>typed YAML → Mooring → Docker Engine</code>.</p>

<h2>What you get</h2>
<ul>
<li><strong>Automatic HTTPS</strong> — give an app a domain; Mooring issues and renews the certificate. No proxy to run, no certbot.</li>
<li><strong>Deploy from Git</strong> — connect a repo and deploy on click; fetch-only, never pushes.</li>
<li><strong>Multi-service apps from one file</strong> — services, domains, config, secrets, scaling.</li>
<li><strong>Monitoring &amp; alerts</strong> — live health for every app and the host, with email / webhook / Slack / Discord / Telegram alerts.</li>
<li><strong>Backups, self-healing, and auto-scaling</strong> — conservative, opt-in automation.</li>
<li><strong>Single static binary</strong> — no external database or services; runs as a systemd unit. Security model documented.</li>
</ul>

<h2>Why Mooring vs CapRover / Coolify / Dokploy</h2>
<table>
<tr><th>&nbsp;</th><th>Mooring</th><th>CapRover</th><th>Coolify</th><th>Dokploy</th></tr>
<tr><td>No Docker Swarm required</td><td>Yes</td><td>No</td><td>Yes</td><td>Yes</td></tr>
<tr><td>No Kubernetes</td><td>Yes</td><td>Yes</td><td>Yes</td><td>Yes</td></tr>
<tr><td>Generates &amp; owns Compose + Dockerfile</td><td>Yes</td><td>No</td><td>No</td><td>No</td></tr>
<tr><td>Single static binary (no extra DB)</td><td>Yes</td><td>No</td><td>No</td><td>No</td></tr>
</table>

<h2>Install (Debian / Ubuntu)</h2>
<pre>curl -fsSL https://daboss2003.github.io/mooring/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/mooring.gpg
echo "deb [signed-by=/usr/share/keyrings/mooring.gpg] https://daboss2003.github.io/mooring stable main" | sudo tee /etc/apt/sources.list.d/mooring.list
sudo apt update &amp;&amp; sudo apt install mooring</pre>
<p>Or grab a <code>.deb</code> / <code>.rpm</code> / static binary from the <a href="https://github.com/daboss2003/mooring/releases/latest">latest release</a>.</p>

<h2>Links</h2>
<p><a href="https://github.com/daboss2003/mooring">Source on GitHub</a> · <a href="https://github.com/daboss2003/mooring/tree/main/docs">Documentation</a> · <a href="https://github.com/daboss2003/mooring/releases">Releases</a></p>
</body>
</html>
HTML

# robots.txt + sitemap.xml so crawlers index the site (and can find the sitemap).
cat > "$OUT/robots.txt" <<'ROBOTS'
User-agent: *
Allow: /
Sitemap: https://daboss2003.github.io/mooring/sitemap.xml
ROBOTS
cat > "$OUT/sitemap.xml" <<'SITEMAP'
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://daboss2003.github.io/mooring/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>
</urlset>
SITEMAP

# Search-engine site-verification files (kept so they survive each re-publish).
# Google Search Console (HTML-file method); add the Bing BingSiteAuth.xml here too.
printf 'google-site-verification: googlebd8c74b732cfc831.html\n' > "$OUT/googlebd8c74b732cfc831.html"

echo ">> done. Serve ./$OUT/ at your apt domain (e.g. https://daboss2003.github.io/mooring)."
