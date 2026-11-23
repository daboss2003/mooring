package serverinfo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRebootRequiredMissingFlag(t *testing.T) {
	dir := t.TempDir()
	// A package list without the flag file means no reboot is pending.
	if err := os.WriteFile(filepath.Join(dir, "reboot-required.pkgs"), []byte("libc6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if req, pkgs := rebootRequired(filepath.Join(dir, "reboot-required"), filepath.Join(dir, "reboot-required.pkgs")); req || pkgs != nil {
		t.Errorf("no flag → (false, nil), got (%v, %v)", req, pkgs)
	}
}

func TestRebootRequiredNoPackageList(t *testing.T) {
	dir := t.TempDir()
	flag := filepath.Join(dir, "reboot-required")
	if err := os.WriteFile(flag, []byte("*** System restart required ***\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if req, pkgs := rebootRequired(flag, filepath.Join(dir, "missing.pkgs")); !req || len(pkgs) != 0 {
		t.Errorf("flag without a list → (true, none), got (%v, %v)", req, pkgs)
	}
}

func TestRebootRequiredParsesList(t *testing.T) {
	dir := t.TempDir()
	flag, list := filepath.Join(dir, "reboot-required"), filepath.Join(dir, "reboot-required.pkgs")
	if err := os.WriteFile(flag, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("linux-image-6.8.0-49-generic\nlibc6\n\n  libc6  \ndbus\nbad name\n<script>\n" + strings.Repeat("x", 200) + "\nlibssl3t64:amd64\n")
	if err := os.WriteFile(list, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	req, pkgs := rebootRequired(flag, list)
	if !req {
		t.Fatal("flag present → required")
	}
	if got := strings.Join(pkgs, ","); got != "dbus,libc6,libssl3t64:amd64,linux-image-6.8.0-49-generic" {
		t.Errorf("pkgs = %q, want deduped, sorted, junk dropped", got)
	}

	// Capped at rebootPkgsMax.
	b.Reset()
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&b, "pkg%02d\n", 49-i)
	}
	if err := os.WriteFile(list, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	_, pkgs = rebootRequired(flag, list)
	if len(pkgs) != rebootPkgsMax || pkgs[0] != "pkg00" || pkgs[len(pkgs)-1] != fmt.Sprintf("pkg%02d", rebootPkgsMax-1) {
		t.Errorf("want the first %d sorted names, got %v", rebootPkgsMax, pkgs)
	}
}
