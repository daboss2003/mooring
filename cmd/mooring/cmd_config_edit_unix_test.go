//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/config"
)

// The edit tests run without root or a terminal: the uid gate and the terminal check are injected,
// and "this user" stands in for root as the owner of the directory and of what is created.

const (
	editOld = "setting: old\n"
	editNew = "setting: new\n"
)

// fakeParse refuses content that says INVALID; everything else loads.
func fakeParse(raw []byte, file string) (*config.Config, error) {
	if bytes.Contains(raw, []byte("INVALID")) {
		return nil, errors.New(file + ":1:1: INVALID is not a setting")
	}
	return &config.Config{}, nil
}

// writeEditor is an editor that saves content in place.
func writeEditor(content string) func(string) error {
	return func(file string) error { return os.WriteFile(file, []byte(content), 0o600) }
}

type editFixture struct {
	dir, path string
	out       *bytes.Buffer
	e         *configEdit
	ran       int // editor runs
}

func newEditFixture(t *testing.T, mode os.FileMode, editor func(file string) error, answers string) *editFixture {
	t.Helper()
	dir := t.TempDir()
	fx := &editFixture{dir: dir, path: filepath.Join(dir, "config.yaml"), out: &bytes.Buffer{}}
	if mode != 0 {
		if err := os.WriteFile(fx.path, []byte(editOld), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fx.path, mode); err != nil {
			t.Fatal(err)
		}
	}
	fx.e = &configEdit{
		path:        fx.path,
		examples:    []string{filepath.Join(dir, "no-example.yaml")},
		in:          bufio.NewReader(strings.NewReader(answers)),
		out:         fx.out,
		euid:        func() int { return 0 },
		interactive: func() bool { return true },
		runEditor: func(_ context.Context, file string) error {
			fx.ran++
			return editor(file)
		},
		parse:   fakeParse,
		groupID: func(string) (int, bool) { return 0, false },
	}
	return fx
}

func (fx *editFixture) run() (int, string) {
	var w bytes.Buffer
	code := exitStatus("config", fx.e.run(context.Background()), &w)
	return code, fx.out.String() + w.String()
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// leftovers are the editable and install copies still in dir (there must be none after any run).
func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if strings.Contains(e.Name(), ".edit-") || strings.Contains(e.Name(), ".new-") {
			out = append(out, e.Name())
		}
	}
	return out
}

func statT(t *testing.T, path string) *syscall.Stat_t {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t)
}

// lockFree reports whether the editing lock in dir can be taken.
func lockFree(t *testing.T, dir string) bool {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, configLockName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil
}

// otherGroup is a group of this user that a new file in dir would NOT get by default, so a test
// can tell a preserved group from the default one.
func otherGroup(t *testing.T, dir string) (int, bool) {
	t.Helper()
	probe := filepath.Join(dir, "probe")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	natural := int(statT(t, probe).Gid)
	os.Remove(probe)
	groups, _ := os.Getgroups()
	for _, g := range groups {
		if g == natural {
			continue
		}
		// Usable only if this user may give a file to it.
		f := filepath.Join(dir, "probe2")
		ok := os.WriteFile(f, nil, 0o600) == nil && os.Chown(f, -1, g) == nil
		os.Remove(f)
		if ok {
			return g, true
		}
	}
	return 0, false
}

func TestConfigEditNeedsRootAndTerminal(t *testing.T) {
	for name, tweak := range map[string]func(*configEdit){
		"not root":       func(e *configEdit) { e.euid = func() int { return 1000 } },
		"not a terminal": func(e *configEdit) { e.interactive = func() bool { return false } },
	} {
		fx := newEditFixture(t, 0o640, writeEditor(editNew), "")
		tweak(fx.e)
		code, out := fx.run()
		if code != 2 || !strings.Contains(out, "sudo mooring config check") {
			t.Errorf("%s: exit %d, %q (want 2 and a pointer at config check)", name, code, out)
		}
		if fx.ran != 0 || mustRead(t, fx.path) != editOld {
			t.Errorf("%s: nothing may be edited", name)
		}
		if ents, _ := os.ReadDir(fx.dir); len(ents) != 1 {
			t.Errorf("%s: nothing may be created (no lock, no copy)", name)
		}
	}
}

func TestConfigEditUnchanged(t *testing.T) {
	fx := newEditFixture(t, 0o640, func(string) error { return nil }, "")
	before := statT(t, fx.path).Ino
	code, out := fx.run()
	if code != 0 || !strings.Contains(out, "unchanged") {
		t.Errorf("exit %d, %q", code, out)
	}
	if statT(t, fx.path).Ino != before || mustRead(t, fx.path) != editOld {
		t.Error("an unchanged edit must not touch the file")
	}
	if l := leftovers(t, fx.dir); len(l) != 0 {
		t.Errorf("copies left behind: %v", l)
	}
	if _, err := os.Stat(lastGoodPath(fx.path)); err == nil {
		t.Error("no .last-good for an unchanged edit")
	}
}

// A valid edit is installed with the file's own mode and group: 0640 stays 0640 (the service's
// group keeps reading it), 0600 stays 0600. The previous content is kept, root-only.
func TestConfigEditInstallPreservesOwnerAndMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o600} {
		fx := newEditFixture(t, mode, writeEditor(editNew), "")
		gid, haveGroup := otherGroup(t, fx.dir)
		if haveGroup {
			if err := os.Chown(fx.path, -1, gid); err != nil {
				t.Fatal(err)
			}
		}
		wantUID := statT(t, fx.path).Uid
		wantGID := statT(t, fx.path).Gid
		// The editor's copy is private whatever the target's mode is.
		edit := fx.e.runEditor
		fx.e.runEditor = func(ctx context.Context, file string) error {
			if fi, err := os.Lstat(file); err != nil || fi.Mode().Perm() != 0o600 || filepath.Dir(file) != fx.dir {
				t.Errorf("the editable copy must be 0600 in the config's directory: %v %v", fi, err)
			}
			return edit(ctx, file)
		}
		code, out := fx.run()
		if code != 0 {
			t.Fatalf("mode %#o: exit %d, %s", mode, code, out)
		}
		if got := mustRead(t, fx.path); got != editNew {
			t.Errorf("mode %#o: installed content %q", mode, got)
		}
		fi, _ := os.Lstat(fx.path)
		st := statT(t, fx.path)
		if fi.Mode().Perm() != mode || !fi.Mode().IsRegular() {
			t.Errorf("mode %#o: installed mode %#o", mode, fi.Mode().Perm())
		}
		if st.Uid != wantUID || st.Gid != wantGID {
			t.Errorf("mode %#o: installed owner %d:%d, want %d:%d", mode, st.Uid, st.Gid, wantUID, wantGID)
		}
		if !haveGroup {
			t.Log("this user has no second group: the group assertion can't discriminate here")
		}
		lg, err := os.Lstat(lastGoodPath(fx.path))
		if err != nil || lg.Mode().Perm() != 0o600 || mustRead(t, lastGoodPath(fx.path)) != editOld {
			t.Errorf("mode %#o: .last-good must hold the previous content, 0600: %v %v", mode, lg, err)
		}
		if l := leftovers(t, fx.dir); len(l) != 0 {
			t.Errorf("copies left behind: %v", l)
		}
		for _, s := range []string{"installed; the previous file is kept as " + lastGoodPath(fx.path), "nothing was reloaded or restarted"} {
			if !strings.Contains(out, s) {
				t.Errorf("output must contain %q:\n%s", s, out)
			}
		}
		if !lockFree(t, fx.dir) {
			t.Error("the lock must be released when the edit ends")
		}
	}
}

// With the real parser, the keys that changed are listed with the command that applies them.
func TestConfigEditPrintsApplyCommands(t *testing.T) {
	src, _ := cliHost(t)
	raw := mustRead(t, src)
	next := strings.Replace(raw, `"127.0.0.1/32"`, `"203.0.113.9/32"`, 1)
	fx := newEditFixture(t, 0o640, writeEditor(next), "")
	if err := os.WriteFile(fx.path, []byte(raw), 0o640); err != nil {
		t.Fatal(err)
	}
	fx.e.parse = config.ParseNamed
	code, out := fx.run()
	if code != 0 || mustRead(t, fx.path) != next {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	a, _ := config.Parse([]byte(raw))
	b, _ := config.Parse([]byte(next))
	if rl, rs := config.DiffApply(a, b); len(rl)+len(rs) == 0 {
		t.Log("config.DiffApply is still the contract stub: key assertions skipped")
		return
	}
	if !strings.Contains(out, "  reload  (sudo systemctl reload mooring): ip_allowlist\n") {
		t.Errorf("the changed key and its command:\n%s", out)
	}
}

// A refused edit is never installed: edit again or discard, nothing else.
func TestConfigEditInvalid(t *testing.T) {
	// Discard.
	fx := newEditFixture(t, 0o640, writeEditor("INVALID\n"), "x\n")
	code, out := fx.run()
	if code != 1 || mustRead(t, fx.path) != editOld || !strings.Contains(out, "INVALID is not a setting") || !strings.Contains(out, "(e)dit again / (x) discard: ") {
		t.Errorf("discard: exit %d\n%s", code, out)
	}
	if l := leftovers(t, fx.dir); len(l) != 0 {
		t.Errorf("discard left copies: %v", l)
	}

	// There is no "install anyway": other answers are asked again, and the end of input discards.
	fx = newEditFixture(t, 0o640, writeEditor("INVALID\n"), "i\ny\ninstall\n")
	code, out = fx.run()
	if code != 1 || mustRead(t, fx.path) != editOld || fx.ran != 1 {
		t.Errorf("no install-anyway: exit %d, editor ran %d times\n%s", code, fx.ran, out)
	}
	if strings.Count(out, "(e)dit again / (x) discard: ") != 4 {
		t.Errorf("every other answer is asked again:\n%s", out)
	}

	// Edit again: the second round continues from the refused text and installs once it is valid.
	round := 0
	fx = newEditFixture(t, 0o640, nil, "e\n")
	fx.e.runEditor = func(_ context.Context, file string) error {
		round++
		if round == 1 {
			return os.WriteFile(file, []byte("INVALID\n"), 0o600)
		}
		if got := mustRead(t, file); got != "INVALID\n" {
			t.Errorf("the second round must open the refused text, got %q", got)
		}
		return os.WriteFile(file, []byte(editNew), 0o600)
	}
	code, out = fx.run()
	if code != 0 || round != 2 || mustRead(t, fx.path) != editNew {
		t.Errorf("edit again: exit %d rounds %d\n%s", code, round, out)
	}
}

func TestConfigEditEditorFails(t *testing.T) {
	fx := newEditFixture(t, 0o640, func(file string) error {
		_ = os.WriteFile(file, []byte(editNew), 0o600)
		return errors.New("exit status 1")
	}, "")
	code, out := fx.run()
	if code != 1 || mustRead(t, fx.path) != editOld || len(leftovers(t, fx.dir)) != 0 {
		t.Errorf("a failed editor installs nothing: exit %d\n%s", code, out)
	}
}

// --- abuse ---

// A symlink at the config path is not followed: nothing is read through it, nothing written.
func TestConfigEditRefusesSymlinkTarget(t *testing.T) {
	fx := newEditFixture(t, 0, writeEditor(editNew), "")
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte(editOld), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, fx.path); err != nil {
		t.Fatal(err)
	}
	code, out := fx.run()
	if code != 1 || !strings.Contains(out, "symlink") {
		t.Errorf("exit %d, %q", code, out)
	}
	if fx.ran != 0 {
		t.Error("the editor must not run on a symlinked config")
	}
	if fi, _ := os.Lstat(fx.path); fi.Mode()&os.ModeSymlink == 0 || mustRead(t, victim) != editOld {
		t.Error("the symlink and its target must be left alone")
	}
}

func TestConfigEditRefusesHardLinkedTarget(t *testing.T) {
	fx := newEditFixture(t, 0o640, writeEditor(editNew), "")
	other := filepath.Join(fx.dir, "other-name")
	if err := os.Link(fx.path, other); err != nil {
		t.Skip("no hard links here:", err)
	}
	code, out := fx.run()
	if code != 1 || !strings.Contains(out, "hard links") || fx.ran != 0 {
		t.Errorf("exit %d ran %d, %q", code, fx.ran, out)
	}
	if mustRead(t, fx.path) != editOld || mustRead(t, other) != editOld {
		t.Error("a hard-linked config must be left alone")
	}
}

func TestConfigEditRefusesNonRegularTarget(t *testing.T) {
	fx := newEditFixture(t, 0, writeEditor(editNew), "")
	if err := syscall.Mkfifo(fx.path, 0o600); err != nil {
		t.Skip("no fifo here:", err)
	}
	done := make(chan struct{})
	var code int
	var out string
	go func() { code, out = fx.run(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("opening a FIFO at the config path must not block")
	}
	if code != 1 || !strings.Contains(out, "not a regular file") || fx.ran != 0 {
		t.Errorf("exit %d, %q", code, out)
	}
}

// The file is swapped for a symlink while the editor is open: nothing is installed, the symlink's
// target is untouched and the operator's edit is kept.
func TestConfigEditTargetSwappedDuringEdit(t *testing.T) {
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("victim\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var fx *editFixture
	fx = newEditFixture(t, 0o640, func(file string) error {
		if err := os.Remove(fx.path); err != nil {
			return err
		}
		if err := os.Symlink(victim, fx.path); err != nil {
			return err
		}
		return os.WriteFile(file, []byte(editNew), 0o600)
	}, "")
	code, out := fx.run()
	if code != 1 || !strings.Contains(out, "changed while it was being edited") {
		t.Errorf("exit %d, %q", code, out)
	}
	if mustRead(t, victim) != "victim\n" {
		t.Error("the symlink's target was written")
	}
	if fi, _ := os.Lstat(fx.path); fi.Mode()&os.ModeSymlink == 0 {
		t.Error("nothing may be installed over a path that changed")
	}
	kept := rejectedEditPath(fx.path)
	if mustRead(t, kept) != editNew || !strings.Contains(out, "Your edit is kept at "+kept) {
		t.Errorf("the edit must be kept and named:\n%s", out)
	}
	if fi, _ := os.Lstat(kept); fi.Mode() != 0o600 {
		t.Errorf("the kept edit is %v, want a regular 0600 file", fi.Mode())
	}
	if l := leftovers(t, fx.dir); len(l) != 0 {
		t.Errorf("the working copies are removed: %v", l)
	}

	// The same for a file rewritten in place by another tool (same inode, new content).
	fx = newEditFixture(t, 0o640, nil, "")
	fx.e.runEditor = func(_ context.Context, file string) error {
		if err := os.WriteFile(fx.path, []byte("setting: other tool, longer\n"), 0o640); err != nil {
			return err
		}
		return os.WriteFile(file, []byte(editNew), 0o600)
	}
	code, out = fx.run()
	if code != 1 || mustRead(t, fx.path) != "setting: other tool, longer\n" {
		t.Errorf("a concurrent write must not be overwritten: exit %d\n%s", code, out)
	}
}

// The swap lands in the last window, after the final check and before the rename: the rename
// replaces the symlink itself and never writes through it.
func TestConfigEditRenameDoesNotFollowSymlink(t *testing.T) {
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("victim\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fx := newEditFixture(t, 0o640, writeEditor(editNew), "")
	fx.e.hook = func(stage string) {
		if stage != "before-rename" {
			return
		}
		if err := os.Remove(fx.path); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(victim, fx.path); err != nil {
			t.Error(err)
		}
	}
	code, out := fx.run()
	if code != 0 {
		t.Fatalf("exit %d, %s", code, out)
	}
	if mustRead(t, victim) != "victim\n" {
		t.Error("the rename wrote through the symlink")
	}
	fi, _ := os.Lstat(fx.path)
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o640 || mustRead(t, fx.path) != editNew {
		t.Errorf("the path must hold the new regular file: %v", fi.Mode())
	}
}

// An editor that saves by REPLACING its file (rename-on-save): the copy is opened again by name and
// checked from scratch.
func TestConfigEditEditorReplacesCopy(t *testing.T) {
	// A regular replacement, with the loose mode an editor might give it: accepted, and what is
	// installed still has the config's own mode (it is a new file, not the editor's).
	fx := newEditFixture(t, 0o640, func(file string) error {
		repl := file + ".swp"
		if err := os.WriteFile(repl, []byte(editNew), 0o644); err != nil {
			return err
		}
		if err := os.Chmod(repl, 0o644); err != nil {
			return err
		}
		return os.Rename(repl, file)
	}, "")
	code, out := fx.run()
	fi, _ := os.Lstat(fx.path)
	if code != 0 || mustRead(t, fx.path) != editNew || fi.Mode().Perm() != 0o640 {
		t.Errorf("rename-on-save: exit %d mode %#o\n%s", code, fi.Mode().Perm(), out)
	}
	if l := leftovers(t, fx.dir); len(l) != 0 {
		t.Errorf("copies left behind: %v", l)
	}

	// Replaced by a symlink to another (valid) file: refused, and that file is not read into place.
	elsewhere := filepath.Join(t.TempDir(), "elsewhere.yaml")
	if err := os.WriteFile(elsewhere, []byte("setting: from elsewhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fx = newEditFixture(t, 0o640, func(file string) error {
		if err := os.Remove(file); err != nil {
			return err
		}
		return os.Symlink(elsewhere, file)
	}, "")
	code, out = fx.run()
	if code != 1 || mustRead(t, fx.path) != editOld || !strings.Contains(out, "was not changed") {
		t.Errorf("symlinked copy: exit %d\n%s", code, out)
	}
	if mustRead(t, elsewhere) != "setting: from elsewhere\n" {
		t.Error("the symlink's target must not be touched")
	}
	if l := leftovers(t, fx.dir); len(l) != 0 {
		t.Errorf("the symlink must be removed (not its target): %v", l)
	}

	// Replaced by a hard link to another file.
	fx = newEditFixture(t, 0o640, func(file string) error {
		if err := os.Remove(file); err != nil {
			return err
		}
		return os.Link(elsewhere, file)
	}, "")
	code, out = fx.run()
	if code != 1 || mustRead(t, fx.path) != editOld || !strings.Contains(out, "hard link") {
		t.Errorf("hard-linked copy: exit %d\n%s", code, out)
	}

	// Replaced by a FIFO: refused without blocking.
	fx = newEditFixture(t, 0o640, func(file string) error {
		if err := os.Remove(file); err != nil {
			return err
		}
		return syscall.Mkfifo(file, 0o600)
	}, "")
	done := make(chan struct{})
	go func() { code, out = fx.run(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a FIFO in place of the copy must not block")
	}
	if code != 1 || mustRead(t, fx.path) != editOld || !strings.Contains(out, "no longer a regular file") {
		t.Errorf("fifo copy: exit %d\n%s", code, out)
	}
}

// One editor at a time.
func TestConfigEditLock(t *testing.T) {
	var fx *editFixture
	inner := ""
	innerCode := -1
	fx = newEditFixture(t, 0o640, func(file string) error {
		// While the first editor is open, a second `config edit` is turned away.
		second := newEditFixture(t, 0, writeEditor("setting: second\n"), "")
		second.e.path = fx.path
		innerCode, inner = second.run()
		if second.ran != 0 {
			t.Error("the second editor must not open")
		}
		return os.WriteFile(file, []byte(editNew), 0o600)
	}, "")
	code, out := fx.run()
	if innerCode != 1 || !strings.Contains(inner, "already being edited") {
		t.Errorf("second editor: exit %d, %q", innerCode, inner)
	}
	if code != 0 || mustRead(t, fx.path) != editNew {
		t.Errorf("the first edit must still install: exit %d\n%s", code, out)
	}
	if fi, err := os.Lstat(filepath.Join(fx.dir, configLockName)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("the lock file is .config.lock, 0600: %v %v", fi, err)
	}
	if !lockFree(t, fx.dir) {
		t.Error("the lock must be free after the edit")
	}
}

// A directory someone else can write to is refused: names in it could be swapped at any time.
func TestConfigEditRefusesWritableDir(t *testing.T) {
	fx := newEditFixture(t, 0o640, writeEditor(editNew), "")
	if err := os.Chmod(fx.dir, 0o775); err != nil {
		t.Fatal(err)
	}
	code, out := fx.run()
	if code != 1 || fx.ran != 0 || !strings.Contains(out, "writable by root only") || mustRead(t, fx.path) != editOld {
		t.Errorf("exit %d, %q", code, out)
	}
}

// Copies a killed run left behind are removed by the next one.
func TestConfigEditRemovesStaleCopies(t *testing.T) {
	fx := newEditFixture(t, 0o640, func(string) error { return nil }, "")
	stale := []string{".config.yaml.edit-0011223344556677.yaml", ".config.yaml.new-8899aabbccddeeff"}
	for _, n := range stale {
		if err := os.WriteFile(filepath.Join(fx.dir, n), []byte("encryption_key: old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keep := filepath.Join(fx.dir, "config.yaml.bak")
	if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := fx.run(); code != 0 {
		t.Fatalf("exit %d, %s", code, out)
	}
	if l := leftovers(t, fx.dir); len(l) != 0 {
		t.Errorf("stale copies not removed: %v", l)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Error("only this command's own copies are removed")
	}
}

func TestConfigEditMissingFile(t *testing.T) {
	const example = "setting: example\n"
	setup := func(answers string, withExample bool) *editFixture {
		fx := newEditFixture(t, 0, writeEditor(editNew), answers)
		if withExample {
			// The packaged template is absent, the manual install's is there (docs/installation.md).
			fx.e.examples = []string{filepath.Join(fx.dir, "usr-share-config.example.yaml"), filepath.Join(fx.dir, "config.example.yaml")}
			if err := os.WriteFile(fx.e.examples[1], []byte(example), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return fx
	}

	// No example: an error, nothing created.
	fx := setup("", false)
	if code, out := fx.run(); code != 1 || !strings.Contains(out, "does not exist") || fx.ran != 0 {
		t.Errorf("no example: exit %d, %q", code, out)
	}

	// Declined.
	fx = setup("n\n", true)
	if code, out := fx.run(); code != 1 || fx.ran != 0 || !strings.Contains(out, "Start from "+fx.e.examples[1]+"? (y)es / (n)o: ") {
		t.Errorf("declined: exit %d, %q", code, out)
	}
	if _, err := os.Lstat(fx.path); err == nil {
		t.Error("declined: nothing may be created")
	}

	// Accepted, the service group exists: its group, 0640. The editor starts from the example.
	fx = setup("y\n", true)
	gid, haveGroup := otherGroup(t, fx.dir)
	if !haveGroup {
		gid = os.Getegid()
	}
	fx.e.groupID = func(name string) (int, bool) {
		if name != "mooring" {
			t.Errorf("group looked up: %q", name)
		}
		return gid, true
	}
	edit := fx.e.runEditor
	fx.e.runEditor = func(ctx context.Context, file string) error {
		if got := mustRead(t, file); got != example {
			t.Errorf("the editor must start from the example, got %q", got)
		}
		return edit(ctx, file)
	}
	code, out := fx.run()
	fi, err := os.Lstat(fx.path)
	if code != 0 || err != nil || fi.Mode().Perm() != 0o640 || int(statT(t, fx.path).Gid) != gid || mustRead(t, fx.path) != editNew {
		t.Fatalf("created with the service group: exit %d %v %v\n%s", code, fi, err, out)
	}
	if _, err := os.Lstat(lastGoodPath(fx.path)); err == nil {
		t.Error("a new file has no previous version to keep")
	}
	if strings.Contains(out, "note:") {
		t.Errorf("no note when the group exists:\n%s", out)
	}

	// Accepted, no service group yet: this user only, 0600, and a note.
	fx = setup("y\n", true)
	code, out = fx.run()
	fi, err = os.Lstat(fx.path)
	if code != 0 || err != nil || fi.Mode().Perm() != 0o600 || !strings.Contains(out, `note: this host has no "mooring" group`) {
		t.Errorf("created without the group: exit %d %v %v\n%s", code, fi, err, out)
	}

	// Saved without a change: nothing is created.
	fx = setup("y\n", true)
	fx.e.runEditor = func(context.Context, string) error { return nil }
	if code, out := fx.run(); code != 0 || !strings.Contains(out, "was not created") {
		t.Errorf("unchanged example: exit %d, %q", code, out)
	}
	if _, err := os.Lstat(fx.path); err == nil {
		t.Error("an unchanged example must not be installed")
	}
}

func TestResolveEditor(t *testing.T) {
	onPath := map[string]string{"vim": "/usr/bin/vim", "nano": "/bin/nano", "vi": "/usr/bin/vi", "code": "/usr/local/bin/code", "sensible-editor": "/usr/bin/sensible-editor"}
	look := func(name string) (string, error) {
		if p, ok := onPath[name]; ok {
			return p, nil
		}
		return "", exec.ErrNotFound
	}
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"SUDO_EDITOR first", map[string]string{"SUDO_EDITOR": "vim", "VISUAL": "code", "EDITOR": "nano"}, "/usr/bin/vim"},
		{"then VISUAL", map[string]string{"VISUAL": "code --wait", "EDITOR": "nano"}, "/usr/local/bin/code --wait"},
		{"then EDITOR, split on spaces", map[string]string{"EDITOR": "  vim  -u NONE "}, "/usr/bin/vim -u NONE"},
		{"nothing set: sensible-editor", nil, "/usr/bin/sensible-editor"},
		{"a missing program is skipped", map[string]string{"EDITOR": "emacs"}, "/usr/bin/sensible-editor"},
		// Never a shell: the whole first word is the program name, so shell syntax names nothing.
		{"shell syntax is not run", map[string]string{"EDITOR": "vi; rm -rf /"}, "/usr/bin/sensible-editor"},
		{"a command substitution is not run", map[string]string{"VISUAL": "$(reboot)", "EDITOR": "nano"}, "/bin/nano"},
	}
	for _, c := range cases {
		got, err := resolveEditor(env(c.env), look)
		if err != nil || strings.Join(got, " ") != c.want {
			t.Errorf("%s: %v %v, want %q", c.name, got, err, c.want)
		}
	}
	delete(onPath, "sensible-editor")
	if got, _ := resolveEditor(env(nil), look); strings.Join(got, " ") != "/bin/nano" {
		t.Errorf("fallback order: sensible-editor, nano, vi; got %v", got)
	}
	if _, err := resolveEditor(env(nil), func(string) (string, error) { return "", exec.ErrNotFound }); err == nil {
		t.Error("no editor at all is an error")
	}
}

// --- a process that dies or is signalled ---

const editHelperEnv = "MOORING_TEST_CONFIG_EDIT"

// TestConfigEditHelper is not a test: the two tests below run it in a child process, which is then
// killed mid-install or signalled while its editor is open.
func TestConfigEditHelper(t *testing.T) {
	mode := os.Getenv(editHelperEnv)
	if mode == "" {
		return
	}
	path := os.Getenv(editHelperEnv + "_PATH")
	e := &configEdit{
		path: path, examples: []string{path + ".none"},
		in: bufio.NewReader(strings.NewReader("")), out: os.Stdout,
		euid: func() int { return 0 }, interactive: func() bool { return true },
		parse: fakeParse, groupID: func(string) (int, bool) { return 0, false },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	switch {
	case strings.HasPrefix(mode, "kill:"):
		e.runEditor = func(_ context.Context, file string) error { return os.WriteFile(file, []byte(editNew), 0o600) }
		e.hook = func(stage string) {
			if stage == strings.TrimPrefix(mode, "kill:") {
				_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
				select {}
			}
		}
	case mode == "signal":
		e.runEditor = func(ctx context.Context, file string) error {
			if err := os.WriteFile(file, []byte(editNew), 0o600); err != nil {
				return err
			}
			// What an editor leaves beside the file it edits.
			for _, n := range editorSiblings(file) {
				if err := os.WriteFile(n, []byte(editOld), 0o600); err != nil {
					return err
				}
			}
			if err := os.WriteFile(path+".ready", nil, 0o600); err != nil {
				return err
			}
			<-ctx.Done() // the editor stays open until the signal stops it
			return ctx.Err()
		}
		e.saveTerm = func() func() {
			return func() { _ = os.WriteFile(path+".term-restored", nil, 0o600) }
		}
		defer e.watchSignals(cancel, os.Exit)()
	}
	err := e.run(ctx)
	if mode == "signal" {
		time.Sleep(10 * time.Second) // the signal handler exits first
	}
	t.Fatalf("the helper should have died: %v", err)
}

func startEditHelper(t *testing.T, mode, path string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestConfigEditHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), editHelperEnv+"="+mode, editHelperEnv+"_PATH="+path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd
}

// Killed (SIGKILL) just before or just after the rename: the file at the path is the complete old
// one or the complete new one, never a part of either. The next edit cleans up and works.
func TestConfigEditKilledMidInstall(t *testing.T) {
	for stage, want := range map[string]string{"before-rename": editOld, "after-rename": editNew} {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte(editOld), 0o640); err != nil {
			t.Fatal(err)
		}
		cmd := startEditHelper(t, "kill:"+stage, path)
		err := cmd.Wait()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
			t.Fatalf("%s: the helper must die of SIGKILL: %v", stage, err)
		}
		if got := mustRead(t, path); got != want {
			t.Errorf("killed %s: the file is %q, want the complete %q", stage, got, want)
		}
		if fi, _ := os.Lstat(path); !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o640 {
			t.Errorf("killed %s: mode %v", stage, fi.Mode())
		}
		// The kernel released the dead process's lock; the next run removes what it left.
		fx := newEditFixture(t, 0, func(string) error { return nil }, "")
		fx.dir, fx.path, fx.e.path = dir, path, path
		if code, out := fx.run(); code != 0 {
			t.Errorf("after a kill %s the next edit must work: exit %d, %s", stage, code, out)
		}
		if l := leftovers(t, dir); len(l) != 0 {
			t.Errorf("after a kill %s: copies left behind: %v", stage, l)
		}
	}
}

// SIGINT, SIGTERM, SIGHUP and SIGQUIT while the editor is open: the copy and the editor's own files
// beside it are removed, the terminal is put back, the lock released, the file untouched, and the
// exit status is 1 (SIGQUIT's default would be a stack dump and exit 2, with everything left behind).
func TestConfigEditSignalCleansUp(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT} {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte(editOld), 0o640); err != nil {
			t.Fatal(err)
		}
		cmd := startEditHelper(t, "signal", path)
		deadline := time.Now().Add(30 * time.Second)
		for {
			if _, err := os.Stat(path + ".ready"); err == nil {
				break
			}
			if time.Now().After(deadline) {
				_ = cmd.Process.Kill()
				t.Fatal("the helper's editor never opened")
			}
			time.Sleep(20 * time.Millisecond)
		}
		if lockFree(t, dir) || len(editFiles(t, dir)) != 1+len(editorSiblings("x")) {
			t.Fatalf("%v: while editing the lock is held and the copy and the editor's files exist: %v", sig, editFiles(t, dir))
		}
		if err := cmd.Process.Signal(sig); err != nil {
			t.Fatal(err)
		}
		err := cmd.Wait()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 1 {
			t.Errorf("%v: exit must be 1: %v", sig, err)
		}
		if l := editFiles(t, dir); len(l) != 0 {
			t.Errorf("%v: copies left behind: %v", sig, l)
		}
		if _, err := os.Stat(path + ".term-restored"); err != nil {
			t.Errorf("%v: the terminal must be put back", sig)
		}
		if !lockFree(t, dir) {
			t.Errorf("%v: the lock must be released", sig)
		}
		if mustRead(t, path) != editOld {
			t.Errorf("%v: the file must be untouched", sig)
		}
	}
}

// editFiles are the files in dir that hold a copy's content under any name: the copies themselves
// and what an editor leaves beside them.
func editFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if strings.Contains(e.Name(), ".edit-") || strings.Contains(e.Name(), ".new-") {
			out = append(out, e.Name())
		}
	}
	return out
}

// A signal that lands after the edited copy was read back and before install takes its lock: the
// handler removes the copies, releases the lock and says the file was not changed. Nothing may be
// installed after that.
func TestConfigEditSignalBeforeInstall(t *testing.T) {
	fx := newEditFixture(t, 0o640, writeEditor(editNew), "")
	exitCode := make(chan int, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := fx.e.watchSignals(cancel, func(c int) { exitCode <- c })
	defer stop()
	fx.e.parse = func(raw []byte, file string) (*config.Config, error) {
		if string(raw) == editNew {
			_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
			for i := 0; i < 2500; i++ { // until the handler has cleaned up
				fx.e.mu.Lock()
				done := fx.e.lock == nil
				fx.e.mu.Unlock()
				if done {
					break
				}
				time.Sleep(2 * time.Millisecond)
			}
		}
		return &config.Config{}, nil
	}
	renamed := false
	fx.e.hook = func(string) { renamed = true }
	err := fx.e.run(ctx)
	select {
	case code := <-exitCode:
		if code != 1 {
			t.Errorf("the handler exits %d, want 1", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the signal handler never finished")
	}
	if got := mustRead(t, fx.path); got != editOld || renamed {
		t.Errorf("installed after the handler said the file was not changed: %q (run: %v)\n%s", got, err, fx.out.String())
	}
	if err == nil || !strings.Contains(err.Error(), "interrupted") || strings.Contains(fx.out.String(), "installed") {
		t.Errorf("run must report the interruption: %v\n%s", err, fx.out.String())
	}
	if _, serr := os.Lstat(lastGoodPath(fx.path)); serr == nil {
		t.Error("no .last-good may be written by a run that installed nothing")
	}
	if l := editFiles(t, fx.dir); len(l) != 0 {
		t.Errorf("copies left behind: %v", l)
	}
}

// A file serve refuses for its mode is installed with the mode it had, and then the operator is
// told serve will refuse it, with the command that fixes it. The check is serve's own (config.Load).
func TestConfigEditWarnsWhenServeRefusesTheFile(t *testing.T) {
	fx := newEditFixture(t, 0o644, writeEditor(editNew), "")
	fx.e.serveRefusal = servePermsRefusal
	code, out := fx.run()
	fi, _ := os.Lstat(fx.path)
	if code != 0 || fi.Mode().Perm() != 0o644 || mustRead(t, fx.path) != editNew {
		t.Fatalf("the edit is installed with the mode the file had: exit %d mode %v\n%s", code, fi.Mode(), out)
	}
	fix := "sudo chown root:mooring " + fx.path + " && sudo chmod 0640 " + fx.path
	if !strings.Contains(out, "warning: mooring serve will not start with "+fx.path) || !strings.Contains(out, "world-accessible") || !strings.Contains(out, fix) {
		t.Errorf("no warning with the fix command:\n%s", out)
	}
	if strings.Index(out, "warning:") < strings.Index(out, "installed;") {
		t.Errorf("the warning comes after the install:\n%s", out)
	}

	// A file serve accepts: no warning. (The content is not the check's business: it was parsed.)
	fx = newEditFixture(t, 0o640, writeEditor(editNew), "")
	fx.e.serveRefusal = func(string) error { return nil }
	if code, out := fx.run(); code != 0 || strings.Contains(out, "warning:") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

// servePermsRefusal reports the file's owner and mode only: a parse problem is not its answer.
func TestServePermsRefusal(t *testing.T) {
	t.Setenv(config.DevInsecurePermsEnv, "1") // the owner half needs root; the mode half doesn't
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("not: a config\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := servePermsRefusal(p); err != nil {
		t.Errorf("a 0640 file's content is not a permission refusal: %v", err)
	}
	for _, mode := range []os.FileMode{0o644, 0o660, 0o604} {
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if err := servePermsRefusal(p); err == nil {
			t.Errorf("mode %#o must be reported", mode)
		}
	}
}

// A chmod (or chown) from another terminal while the editor is open is not silently put back.
func TestConfigEditModeChangedDuringEdit(t *testing.T) {
	var fx *editFixture
	fx = newEditFixture(t, 0o644, func(file string) error {
		if err := os.Chmod(fx.path, 0o640); err != nil { // the operator fixes the mode meanwhile
			return err
		}
		return os.WriteFile(file, []byte(editNew), 0o600)
	}, "")
	code, out := fx.run()
	fi, _ := os.Lstat(fx.path)
	if code != 1 || fi.Mode().Perm() != 0o640 || mustRead(t, fx.path) != editOld || !strings.Contains(out, "owner or mode") {
		t.Errorf("exit %d mode %v\n%s", code, fi.Mode(), out)
	}
	if mustRead(t, rejectedEditPath(fx.path)) != editNew {
		t.Error("the edit is kept")
	}

	if gid, ok := otherGroup(t, fx.dir); ok {
		fx = newEditFixture(t, 0o640, nil, "")
		fx.e.runEditor = func(_ context.Context, file string) error {
			if err := os.Chown(fx.path, -1, gid); err != nil {
				return err
			}
			return os.WriteFile(file, []byte(editNew), 0o600)
		}
		code, out = fx.run()
		if code != 1 || int(statT(t, fx.path).Gid) != gid || mustRead(t, fx.path) != editOld {
			t.Errorf("a chgrp during the edit: exit %d\n%s", code, out)
		}
	}
}

// The edit kept after a changed-underneath refusal survives the next run (the message says to
// compare it and run config edit again), replaces an older one, and is root-only.
func TestConfigEditKeptEditSurvivesNextRun(t *testing.T) {
	fx := newEditFixture(t, 0o640, nil, "")
	kept := rejectedEditPath(fx.path)
	// An older kept edit, readable by others, is replaced, not written into.
	if err := os.WriteFile(kept, []byte("older\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fx.e.runEditor = func(_ context.Context, file string) error {
		if err := os.WriteFile(fx.path, []byte("setting: other tool, longer\n"), 0o640); err != nil {
			return err
		}
		return os.WriteFile(file, []byte(editNew), 0o600)
	}
	code, out := fx.run()
	if code != 1 || !strings.Contains(out, kept) {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if fi, _ := os.Lstat(kept); fi.Mode() != 0o600 || mustRead(t, kept) != editNew {
		t.Fatalf("the kept edit: %v %q", fi.Mode(), mustRead(t, kept))
	}
	// The next run, as the message tells the operator.
	fx2 := newEditFixture(t, 0, func(string) error { return nil }, "")
	fx2.dir, fx2.path, fx2.e.path = fx.dir, fx.path, fx.path
	if code, out := fx2.run(); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if got, err := os.ReadFile(kept); err != nil || string(got) != editNew {
		t.Errorf("the kept edit was removed by the next run: %v", err)
	}

	// A symlink planted at the kept name is replaced, never written through.
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("victim\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Remove(kept)
	if err := os.Symlink(victim, kept); err != nil {
		t.Fatal(err)
	}
	fx3 := newEditFixture(t, 0, nil, "")
	fx3.dir, fx3.path, fx3.e.path = fx.dir, fx.path, fx.path
	fx3.e.runEditor = func(_ context.Context, file string) error {
		if err := os.WriteFile(fx.path, []byte("setting: a third tool wrote this\n"), 0o640); err != nil {
			return err
		}
		return os.WriteFile(file, []byte(editNew), 0o600)
	}
	if code, _ := fx3.run(); code != 1 || mustRead(t, victim) != "victim\n" {
		t.Errorf("exit %d; the symlink's target: %q", code, mustRead(t, victim))
	}
	if fi, _ := os.Lstat(kept); !fi.Mode().IsRegular() {
		t.Errorf("the kept edit must be a regular file: %v", fi.Mode())
	}
}

// An editor's backup, swap and lock files beside the copy hold the file's secrets: they go with
// the copy on a normal run. Files that only look similar stay.
func TestConfigEditRemovesEditorBackups(t *testing.T) {
	var made []string
	fx := newEditFixture(t, 0o640, func(file string) error {
		old, _ := os.ReadFile(file)
		for _, n := range editorSiblings(file) {
			if err := os.WriteFile(n, old, 0o600); err != nil {
				return err
			}
			made = append(made, n)
		}
		return os.WriteFile(file, []byte(editNew), 0o600)
	}, "")
	bystanders := []string{"config.yaml~", ".config.yaml.swp", "#config.yaml#", "config.yaml.bak"}
	for _, n := range bystanders {
		if err := os.WriteFile(filepath.Join(fx.dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if code, out := fx.run(); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if len(made) < 5 {
		t.Fatalf("the editor made %d files", len(made))
	}
	for _, n := range made {
		if _, err := os.Lstat(n); err == nil {
			t.Errorf("left behind: %s", filepath.Base(n))
		}
	}
	for _, n := range append(bystanders, "config.yaml", "config.yaml.last-good") {
		if _, err := os.Lstat(filepath.Join(fx.dir, n)); err != nil {
			t.Errorf("%s is not this run's and must stay", n)
		}
	}
	// None of the names can be the config file's or .last-good's.
	for _, n := range editorSiblings(filepath.Join(fx.dir, ".config.yaml.edit-0011223344556677.yaml")) {
		if !strings.Contains(filepath.Base(n), ".edit-0011223344556677") {
			t.Errorf("%s is not derived from the copy's name", n)
		}
	}
}

// What a killed run's editor left beside its copy is removed by the next run.
func TestConfigEditRemovesStaleEditorBackups(t *testing.T) {
	fx := newEditFixture(t, 0o640, func(string) error { return nil }, "")
	for _, n := range editorSiblings(filepath.Join(fx.dir, ".config.yaml.edit-0011223344556677.yaml")) {
		if err := os.WriteFile(n, []byte("encryption_key: old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if code, out := fx.run(); code != 0 {
		t.Fatalf("exit %d, %s", code, out)
	}
	if l := editFiles(t, fx.dir); len(l) != 0 {
		t.Errorf("stale editor files not removed: %v", l)
	}
}

// The terminal's settings are put back after every editor run, and at the end of the run.
func TestConfigEditRestoresTerminal(t *testing.T) {
	fx := newEditFixture(t, 0o640, nil, "e\n")
	restored := 0
	fx.e.saveTerm = func() func() { return func() { restored++ } }
	var seen []int
	fx.e.runEditor = func(_ context.Context, file string) error {
		seen = append(seen, restored)
		if len(seen) == 1 {
			return os.WriteFile(file, []byte("INVALID\n"), 0o600)
		}
		return os.WriteFile(file, []byte(editNew), 0o600)
	}
	if code, out := fx.run(); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if len(seen) != 2 || seen[0] != 0 || seen[1] != 1 || restored < 2 {
		t.Errorf("restores seen by each editor run: %v, total %d", seen, restored)
	}
}

// The editor is asked to stop (SIGTERM) before it is killed, so it can leave the terminal as it
// found it.
func TestRunConfigEditorStopsWithSIGTERM(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "editor.sh")
	const body = "#!/bin/sh\ntrap 'echo stopped > \"$1.term\"; exit 0' TERM\necho ready > \"$1.ready\"\nwhile :; do sleep 0.05; done\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUDO_EDITOR", script)
	file := filepath.Join(dir, "copy.yaml")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runConfigEditor(ctx, file) }()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(file + ".ready"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the editor never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the editor was not stopped")
	}
	if _, err := os.Stat(file + ".term"); err != nil {
		t.Error("the editor was killed without being asked to stop first (no SIGTERM)")
	}
}

// serviceViewOf: what root's own check can't see. Only the two mistakes that are fine for root and
// not for the service are reported; every other file is Load's to judge.
func TestServiceViewOf(t *testing.T) {
	const p, svc = "/etc/mooring/config.yaml", 990
	for _, c := range []struct {
		name          string
		perm          fs.FileMode
		uid, gid      int
		want, notWant string
	}{
		{name: "root:mooring 0640", perm: 0o640, gid: svc},
		{name: "root:mooring 0440", perm: 0o440, gid: svc},
		{name: "root:root 0600", perm: 0o600, want: "readable by root only (mode 0600): the service (user mooring) can't read it"},
		{name: "root:mooring 0600", perm: 0o600, gid: svc, want: "readable by root only"},
		{name: "root:root 0400", perm: 0o400, want: "readable by root only (mode 0400)"},
		{name: "root:root 0640", perm: 0o640, want: "belongs to group id 0, not to the service's group mooring (id 990)", notWant: "root only"},
		{name: "root:staff 0640", perm: 0o640, gid: 20, want: "belongs to group id 20, not to the service's group mooring (id 990)"},
		// Refused by Load for everybody: not this rule's business.
		{name: "world-readable", perm: 0o644, gid: 20},
		{name: "group-writable", perm: 0o660, gid: 20},
		{name: "not root's", perm: 0o600, uid: 1000},
	} {
		err := serviceViewOf(p, c.perm, c.uid, c.gid, svc)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want) || !strings.HasPrefix(err.Error(), p+" ")):
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		case c.notWant != "" && strings.Contains(err.Error(), c.notWant):
			t.Errorf("%s: %v must not say %q", c.name, err, c.notWant)
		}
	}
	// Anyone but root: Load applied the rule already, or this user can't tell.
	if os.Geteuid() != 0 {
		f := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := serviceView(f); err != nil {
			t.Errorf("not root: %v", err)
		}
	}
}

// After an install, a file only the service can't use (root-only, or another group) is warned
// about with the command that fixes it.
func TestConfigEditWarnsWhenTheServiceCantReadTheFile(t *testing.T) {
	fx := newEditFixture(t, 0o600, writeEditor(editNew), "")
	fx.e.serveRefusal = func(p string) error {
		return serviceViewOf(p, 0o600, 0, 0, 990)
	}
	code, out := fx.run()
	if code != 0 || mustRead(t, fx.path) != editNew {
		t.Fatalf("exit %d\n%s", code, out)
	}
	fix := "sudo chown root:mooring " + fx.path + " && sudo chmod 0640 " + fx.path
	if !strings.Contains(out, "warning: mooring serve will not start with "+fx.path+" as it is now") || !strings.Contains(out, "the service (user mooring) can't read it") || !strings.Contains(out, fix) {
		t.Errorf("no warning with the fix command:\n%s", out)
	}
}

// A glob character in a custom --config path is a plain character: only this file's copies, in
// this directory, are removed.
func TestConfigEditStaleCleanupTakesNamesLiterally(t *testing.T) {
	root := t.TempDir()
	own, other := filepath.Join(root, "m[1]"), filepath.Join(root, "m1")
	for _, d := range []string{own, other} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, ".config.yaml.edit-live.yaml"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	e := &configEdit{}
	e.removeStale(own, "config.yaml")
	if _, err := os.Lstat(filepath.Join(own, ".config.yaml.edit-live.yaml")); err == nil {
		t.Error("the stale copy in the file's own directory (m[1]) must be removed")
	}
	if _, err := os.Lstat(filepath.Join(other, ".config.yaml.edit-live.yaml")); err != nil {
		t.Error("a copy in ANOTHER directory (m1) was removed")
	}

	// A base name with glob characters: other files' copies stay, its own go.
	c := filepath.Join(root, "c")
	if err := os.Mkdir(c, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{".prod.yaml.edit-live", ".*.yaml.edit-mine", "#.x.yaml.edit-1#", "#.*.yaml.edit-1#"} {
		if err := os.WriteFile(filepath.Join(c, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	e.removeStale(c, "*.yaml")
	for n, wantGone := range map[string]bool{".prod.yaml.edit-live": false, "#.x.yaml.edit-1#": false, ".*.yaml.edit-mine": true, "#.*.yaml.edit-1#": true} {
		_, err := os.Lstat(filepath.Join(c, n))
		if gone := err != nil; gone != wantGone {
			t.Errorf("%s: removed = %v, want %v", n, gone, wantGone)
		}
	}
}

// What the cleanup removes and what it never touches, by name.
func TestStaleCopyName(t *testing.T) {
	keep := []string{"config.yaml", "config.yaml.last-good", "config.yaml.rejected-edit", ".config.lock",
		".adm-group-added", "config.example.yaml", ".config.yaml.swp", "config.yaml~", "#config.yaml#",
		".#config.yaml", "config.yaml.bak", ".config.yaml", ".config.yaml.edit", ".config.yaml.new",
		"config.yaml.edit-1", "config.yaml.new-1", "other.yaml", ".other.yaml.edit-1", "..config.yaml.new-1",
		"x.config.yaml.edit-1", "config.yaml.dpkg-old", "config.yaml.rpmnew", "#.config.yaml.edit-abc"}
	gone := []string{".config.yaml.edit-abc.yaml", ".config.yaml.new-abc", ".config.yaml.new-abc.last-good",
		".config.yaml.edit-abc.yaml~", "..config.yaml.edit-abc.yaml.swp", "#.config.yaml.edit-abc.yaml#",
		".#.config.yaml.edit-abc.yaml", ".config.yaml.edit-abc.yaml.save", "..config.yaml.edit-abc.yaml.un~"}
	for _, n := range keep {
		if staleCopyName(n, "config.yaml") {
			t.Errorf("%s must stay", n)
		}
	}
	for _, n := range gone {
		if !staleCopyName(n, "config.yaml") {
			t.Errorf("%s must be removed", n)
		}
	}
	// Every file an editor leaves beside a copy is one the next run removes.
	for _, n := range editorSiblings("/etc/mooring/.config.yaml.edit-0011223344556677.yaml") {
		if !staleCopyName(filepath.Base(n), "config.yaml") {
			t.Errorf("an editor's %s would be left behind by the next run", filepath.Base(n))
		}
	}
	var names []string
	for _, n := range editorSiblings("/d/copy") {
		names = append(names, filepath.Base(n))
	}
	for _, want := range []string{"copy.save", ".copy.un~"} { // nano's emergency save, vim's undo file
		if !slices.Contains(names, want) {
			t.Errorf("editorSiblings lacks %s: %v", want, names)
		}
	}
}

// A signal that lands after install kept the edit (and returned that) and before the command saw
// the interruption: the handler ends the process, so it must say where the edit is.
func TestConfigEditSignalAfterEditWasKept(t *testing.T) {
	var fx *editFixture
	fx = newEditFixture(t, 0o640, func(file string) error {
		if err := os.WriteFile(fx.path, []byte("setting: theirs\n"), 0o640); err != nil { // changed underneath
			return err
		}
		return os.WriteFile(file, []byte(editNew), 0o600)
	}, "")
	var handlerOut bytes.Buffer
	fx.e.errOut = &handlerOut
	exitCode := make(chan int, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := fx.e.watchSignals(cancel, func(c int) { exitCode <- c })
	err := fx.e.run(ctx)
	kept := rejectedEditPath(fx.path)
	if err == nil || !strings.Contains(err.Error(), "Your edit is kept at "+kept) {
		t.Fatalf("the edit must be kept: %v", err)
	}
	// cmdConfigEdit has not looked at the interruption yet: the signal arrives now.
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-exitCode:
		if code != 1 {
			t.Errorf("exit %d, want 1", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the signal handler never finished")
	}
	got := handlerOut.String()
	if !strings.Contains(got, "interrupted; "+fx.path+" was not changed") || !strings.Contains(got, "Your edit is kept at "+kept) {
		t.Errorf("the handler must say where the edit is kept:\n%s", got)
	}
	if mustRead(t, kept) != editNew {
		t.Error("the kept edit must survive the handler's cleanup")
	}

	// Nothing kept: only the one line.
	stop()
	fx2 := newEditFixture(t, 0o640, writeEditor(editNew), "")
	handlerOut.Reset()
	fx2.e.errOut = &handlerOut
	exit2 := make(chan int, 1)
	defer fx2.e.watchSignals(func() {}, func(c int) { exit2 <- c })()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exit2:
	case <-time.After(10 * time.Second):
		t.Fatal("the signal handler never finished")
	}
	if got := handlerOut.String(); strings.Count(got, "mooring config:") != 1 || strings.Contains(got, "kept") {
		t.Errorf("nothing was kept:\n%s", got)
	}
}
