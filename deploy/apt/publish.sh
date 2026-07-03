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
touch "$OUT/.nojekyll" # serve dists/ + pool/ + _sidebar.md raw (no GitHub Pages Jekyll processing)

# The marketing site + docs live as real files under site/ in the repo (landing page,
# assets, robots.txt, sitemap.xml, search-verification files, and the Docsify docs
# shell). Copy them over the apt repo, then drop the markdown docs into /docs so the
# Docsify site can render them. REPO is the repo root (this script is deploy/apt/).
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cp -a "$REPO/site/." "$OUT/"
mkdir -p "$OUT/docs"
cp "$REPO/docs/"*.md "$OUT/docs/"
[ -d "$REPO/docs/assets" ] && cp -a "$REPO/docs/assets" "$OUT/docs/"

echo ">> done. Serve ./$OUT/ at your apt domain (e.g. https://daboss2003.github.io/mooring)."
