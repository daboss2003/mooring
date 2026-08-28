package imageupdate

import (
	"context"
	"regexp"
	"strings"
)

// digestExec is the write-plane capture surface (satisfied by *dockerexec.Runner; faked in tests).
// It runs a static-argv `docker` child capturing stdout, WITHOUT queuing (skip-don't-queue): a slow
// registry round-trip must never stall a deploy waiting on the one-docker-child slot.
type digestExec interface {
	CaptureTry(ctx context.Context, argv []string) (string, error)
}

// sha256Re matches a docker content digest. Both `docker image inspect`'s RepoDigests
// ("repo@sha256:<64hex>") and `docker buildx imagetools inspect`'s .Manifest.Digest
// ("sha256:<64hex>") contain exactly this token; we extract it and ignore everything else, so CLI
// stdout is treated as untrusted (we never store or compare a raw, unvalidated line).
var sha256Re = regexp.MustCompile(`sha256:[0-9a-f]{64}`)

// normalizeDigest extracts the sha256:<64hex> token from CLI output, or "" if none is present.
func normalizeDigest(s string) string { return sha256Re.FindString(strings.TrimSpace(s)) }

// deployedDigest reads the LOCALLY-PULLED image's content digest for ref (no network). Compose
// pulled the image at deploy, so `docker image inspect` finds it and RepoDigests[0] carries the
// digest the local image was pulled at. An empty result (RepoDigests empty, or the image is not
// present) means we can't establish a "currently running" digest → the caller flags no update.
func deployedDigest(ctx context.Context, x digestExec, ref string) (string, error) {
	out, err := x.CaptureTry(ctx, []string{
		"image", "inspect", ref, "--format", "{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}",
	})
	if err != nil {
		return "", err
	}
	return normalizeDigest(out), nil
}

// latestDigest reads the registry's CURRENT manifest digest for ref's tag (network; using docker's
// own configured registry auth, so private registries the host is logged in to work). It is a
// metadata-only call — buildx imagetools inspect fetches the manifest, never the layers. For a
// multi-arch tag it returns the manifest-LIST digest, which is exactly what RepoDigests[0] also
// records, so the two compare cleanly.
func latestDigest(ctx context.Context, x digestExec, ref string) (string, error) {
	out, err := x.CaptureTry(ctx, []string{
		"buildx", "imagetools", "inspect", ref, "--format", "{{.Manifest.Digest}}",
	})
	if err != nil {
		return "", err
	}
	return normalizeDigest(out), nil
}

// isDigestPinned reports whether ref is pinned to an immutable digest (name@sha256:…). A
// digest-pinned service can never have a "newer image for the same reference", so it is skipped.
func isDigestPinned(ref string) bool { return strings.Contains(ref, "@sha256:") }
