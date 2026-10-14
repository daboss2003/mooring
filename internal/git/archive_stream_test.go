package git

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// A commit whose files add up to more than any git output buffer extracts completely, and a single file
// larger than 16 MiB is written whole: nothing is cut short (the checkout used to keep only the first
// 8 MiB of the archive and fail with "unexpected EOF", and to cut each file at 16 MiB without a word).
func TestArchiveExtractsLargeCommitsWhole(t *testing.T) {
	small, big := randomBytes(t, 9<<20), randomBytes(t, 20<<20)
	r, sha := gitFixture(t, func(dir string) {
		os.WriteFile(filepath.Join(dir, "assets.bin"), small, 0o644)
		os.MkdirAll(filepath.Join(dir, "media"), 0o755)
		os.WriteFile(filepath.Join(dir, "media", "video.bin"), big, 0o644)
		os.WriteFile(filepath.Join(dir, "zz.txt"), []byte("last\n"), 0o644)
	})
	dest := t.TempDir()
	if err := r.ArchiveTo(context.Background(), sha, dest, nil); err != nil {
		t.Fatalf("archive: %v", err)
	}
	for name, want := range map[string][]byte{"assets.bin": small, "media/video.bin": big, "zz.txt": []byte("last\n")} {
		got, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(name)))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: %d bytes, err %v; want %d bytes, identical", name, len(got), err, len(want))
		}
	}
}

// Past the checkout limit the error says so, naming the limit, instead of a tar error.
func TestArchiveOverTheLimitSaysSo(t *testing.T) {
	old := archiveLimit
	archiveLimit = 1 << 20
	t.Cleanup(func() { archiveLimit = old })
	r, sha := gitFixture(t, func(dir string) {
		os.WriteFile(filepath.Join(dir, "big.bin"), randomBytes(t, 2<<20), 0o644)
	})
	err := r.ArchiveTo(context.Background(), sha, t.TempDir(), nil)
	if err == nil || !strings.Contains(err.Error(), "larger than 1 MiB") {
		t.Fatalf("want the size-limit error, got %v", err)
	}
}

// A git failure is reported as git's error, not as a truncated tar stream.
func TestArchiveReportsGitErrors(t *testing.T) {
	r, _ := gitFixture(t, func(dir string) {
		os.WriteFile(filepath.Join(dir, "f"), []byte("x\n"), 0o644)
	})
	err := r.ArchiveTo(context.Background(), strings.Repeat("ab", 20), t.TempDir(), nil)
	if err == nil || strings.Contains(err.Error(), "EOF") {
		t.Fatalf("want git's error for a missing commit, got %v", err)
	}
}

// An entry rejected mid-stream stops git instead of leaving it blocked on a full pipe.
func TestArchiveRejectionStopsGit(t *testing.T) {
	r, sha := gitFixture(t, func(dir string) {
		os.WriteFile(filepath.Join(dir, "a-link-target"), []byte("x\n"), 0o644)
		os.Symlink("/etc/passwd", filepath.Join(dir, "b-link"))
		os.WriteFile(filepath.Join(dir, "c-big.bin"), randomBytes(t, 8<<20), 0o644)
	})
	done := make(chan error, 1)
	go func() { done <- r.ArchiveTo(context.Background(), sha, t.TempDir(), nil) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "symlinks rejected") {
			t.Fatalf("want the symlink rejection, got %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("ArchiveTo hung after rejecting an entry")
	}
}
