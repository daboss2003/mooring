package imageupdate

import (
	"strings"
	"testing"
)

func TestNormalizeDigest(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	cases := []struct {
		in, want string
	}{
		{"postgres@" + d, d},                          // image inspect RepoDigests form
		{"docker.io/library/postgres@" + d + "\n", d}, // fully-qualified + trailing newline
		{d, d},                  // buildx .Manifest.Digest form
		{"  " + d + "  ", d},    // whitespace
		{"", ""},                // empty
		{"no digest here", ""},  // garbage → empty (untrusted stdout ignored)
		{"sha256:tooshort", ""}, // wrong length rejected
		{"sha256:" + strings.Repeat("A", 64), ""}, // uppercase hex is not docker's form → rejected
	}
	for _, c := range cases {
		if got := normalizeDigest(c.in); got != c.want {
			t.Errorf("normalizeDigest(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsDigestPinned(t *testing.T) {
	if !isDigestPinned("postgres@sha256:" + strings.Repeat("a", 64)) {
		t.Error("a name@sha256:… ref must be treated as digest-pinned")
	}
	if isDigestPinned("postgres:16") {
		t.Error("a tag ref must not be treated as digest-pinned")
	}
}
