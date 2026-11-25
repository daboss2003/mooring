//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/yamldiag"
)

// cmd_config_edit_unix.go is `mooring config edit`: visudo for config.yaml. Root edits a private
// copy; the copy replaces the file only when it loads, by a rename, with the file's own owner,
// group and mode. It writes a root-owned file the service trusts, so every step fails closed:
//
//   - the directory must be root's and writable by nobody else (then only root can swap a name in it);
//   - the file is opened without following a symlink and must be a regular file with one name;
//   - one editor at a time (flock on .config.lock beside the file);
//   - the editor works on a 0600 copy in the same directory; after it exits the copy is opened
//     again by name and must still be a regular, single-name file of this user, because an editor
//     may save by replacing the file;
//   - what is installed is a NEW file holding exactly the bytes that were checked, never the
//     editor's own file;
//   - nothing is installed when the file (its content, owner or mode) changed underneath the edit,
//     or after a signal said to stop.

const (
	configGroup    = serviceGroup
	configLockName = ".config.lock"
	// maxConfigBytes bounds what is read back from the editor's copy.
	maxConfigBytes = 4 << 20
	// editorStopDelay is how long an editor told to stop (SIGTERM) has before it is killed.
	editorStopDelay = 3 * time.Second
)

// configExamplePaths are where a missing config file can be started from: the packages' template,
// then the manual (raw binary) install's (docs/installation.md).
var configExamplePaths = []string{"/usr/share/mooring/config.example.yaml", "/etc/mooring/config.example.yaml"}

func cmdConfigEdit(args []string) error {
	fs := flag.NewFlagSet("config edit", flag.ContinueOnError)
	path := fs.String("config", config.DefaultPath, "path to config.yaml")
	if err := fs.Parse(args); err != nil {
		return &exitError{code: 2, err: err, printed: true}
	}
	if fs.NArg() > 0 {
		return usageError("config edit takes no arguments (got %q)", fs.Arg(0))
	}
	e := &configEdit{
		path:     *path,
		examples: configExamplePaths,
		in:       bufio.NewReader(os.Stdin),
		out:      os.Stdout,
		euid:     os.Geteuid,
		interactive: func() bool {
			return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
		},
		runEditor:    runConfigEditor,
		parse:        config.ParseNamed,
		groupID:      lookupGroupID,
		serveRefusal: servePermsRefusal,
		saveTerm:     saveTerminal,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := e.watchSignals(cancel, os.Exit)
	defer stop()
	err := e.run(ctx)
	if e.wasInterrupted() {
		// Intentional: the signal handler ends the process (after the editor stopped and the
		// terminal is back), with the one message that is true; returning here would race it.
		select {}
	}
	return err
}

// servePermsRefusal is why `mooring serve` will not start with the file at path for its owner,
// group or mode (nil: it will). It runs serve's own check, through config.Load, so the rules live
// in one place. config edit runs as root, for which Load skips the group rule and reads any file,
// so the two mistakes only the service sees (a root-only file, another group) are judged by
// serviceView.
func servePermsRefusal(path string) error {
	_, err := config.Load(path)
	var d *yamldiag.Diagnostics
	if err == nil || errors.As(err, &d) || errors.Is(err, config.ErrOtherGroup) {
		// The content was checked before the install; only the file itself is asked about.
		return serviceView(path)
	}
	return err
}

// saveTerminal remembers the terminal's settings; the returned func puts them back (an editor
// that was stopped or killed leaves the terminal in raw mode).
func saveTerminal() (restore func()) {
	fd := int(os.Stdin.Fd())
	st, err := term.GetState(fd)
	if err != nil {
		return func() {}
	}
	return func() { _ = term.Restore(fd, st) }
}

// configEdit is one `config edit` run. The terminal, the uid gate, the editor and the group lookup
// are injected so the file handling is tested without root or a terminal.
type configEdit struct {
	path     string   // the config file
	examples []string // what a missing file can be started from: the first that exists
	in       *bufio.Reader
	out      io.Writer

	euid        func() int
	interactive func() bool
	runEditor   func(ctx context.Context, file string) error
	parse       func(raw []byte, file string) (*config.Config, error)
	groupID     func(name string) (gid int, ok bool)
	// serveRefusal: why serve refuses the installed file for its owner or mode (nil func: not asked).
	serveRefusal func(path string) error
	// saveTerm remembers the terminal's settings and returns what puts them back (nil: nothing to do).
	saveTerm func() (restore func())
	hook     func(stage string) // tests: "before-rename", "after-rename"

	mu          sync.Mutex
	temps       map[string]struct{} // files to remove on the way out
	editCopy    string              // the editor's copy: its backup and swap files are removed with it
	lock        *os.File
	installed   bool
	interrupted bool // a signal said to stop: nothing is created or installed from then on
	// keptNote says where an edit that was not installed is kept. The signal handler prints it
	// too: a signal that lands after install returned it would otherwise end the process before
	// anyone printed where the operator's work is.
	keptNote    string
	errOut      io.Writer     // the signal handler's messages (nil: os.Stderr)
	editing     chan struct{} // open while the editor runs
	restoreTerm func()
}

// editTarget is the file as it was when the edit started.
type editTarget struct {
	exists  bool
	info    fs.FileInfo // identity, for the changed-underneath check
	content []byte
	uid     int
	gid     int
	mode    fs.FileMode
	note    string // how a new file's owner was chosen
}

// errEditInterrupted is run's error after a signal; the signal handler prints the message.
func (e *configEdit) errEditInterrupted() error {
	return &exitError{code: 1, err: fmt.Errorf("interrupted; %s was not changed", e.path)}
}

func (e *configEdit) wasInterrupted() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.interrupted
}

// editOnce runs the editor on file and puts the terminal back as it was, whatever the editor did
// and however it ended.
func (e *configEdit) editOnce(ctx context.Context, file string) error {
	done := make(chan struct{})
	e.mu.Lock()
	if e.interrupted {
		e.mu.Unlock()
		return e.errEditInterrupted()
	}
	e.editing = done
	restore := e.restoreTerm
	e.mu.Unlock()
	err := e.runEditor(ctx, file)
	if restore != nil {
		restore()
	}
	e.mu.Lock()
	e.editing = nil
	e.mu.Unlock()
	close(done)
	return err
}

func (e *configEdit) run(ctx context.Context) error {
	if e.euid() != 0 || !e.interactive() {
		return usageError("config edit needs root and a terminal (run: sudo mooring config edit). To check the file without editing it: %s", checkCommand)
	}
	path, err := filepath.Abs(e.path)
	if err != nil {
		return err
	}
	e.path = path
	dir, base := filepath.Dir(path), filepath.Base(path)
	if err := checkEditDir(dir); err != nil {
		return err
	}
	if err := e.acquireLock(dir); err != nil {
		return err
	}
	defer e.cleanup()
	e.removeStale(dir, base)
	if e.saveTerm != nil {
		restore := e.saveTerm()
		e.mu.Lock()
		e.restoreTerm = restore
		e.mu.Unlock()
		defer restore()
	}

	target, err := e.openTarget()
	if err != nil {
		return err
	}
	if !target.exists {
		if err := e.startFromExample(target); err != nil {
			return err
		}
	}

	tmp, f, err := e.createPrivate(dir, "."+base+".edit-", ".yaml", target.content)
	if err != nil {
		return fmt.Errorf("make an editable copy: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("make an editable copy: %w", err)
	}
	e.mu.Lock()
	e.editCopy = tmp
	e.mu.Unlock()

	for {
		if err := e.editOnce(ctx, tmp); err != nil {
			if ctx.Err() != nil || e.wasInterrupted() {
				return e.errEditInterrupted()
			}
			return fmt.Errorf("the editor failed (%v); %s was not changed", err, e.path)
		}
		edited, err := readEditedCopy(tmp)
		if err != nil {
			return fmt.Errorf("%w; %s was not changed", err, e.path)
		}
		if bytes.Equal(edited, target.content) {
			if target.exists {
				fmt.Fprintf(e.out, "%s unchanged\n", e.path)
			} else {
				fmt.Fprintf(e.out, "unchanged; %s was not created\n", e.path)
			}
			return nil
		}
		newCfg, perr := e.parse(edited, e.path)
		if perr == nil {
			return e.install(dir, base, tmp, target, edited, newCfg)
		}
		fmt.Fprintln(e.out, strings.TrimRight(refusalText(perr), "\n"))
		fmt.Fprintf(e.out, "\nThe edited file is refused; %s was not changed.\n", e.path)
		// Intentional: no "install anyway". A file serve refuses must never reach the service's path.
		if e.ask("(e)dit again / (x) discard: ", "ex") != 'e' {
			return &exitError{code: 1, err: fmt.Errorf("edit discarded; %s was not changed", e.path)}
		}
	}
}

// checkEditDir refuses a directory in which someone other than this user could swap names.
func checkEditDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("config directory: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if int(st.Uid) != os.Geteuid() || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s must be owned by root and writable by root only (it is uid %d, mode %#o): a file can't be edited safely there", dir, st.Uid, fi.Mode().Perm())
	}
	return nil
}

// acquireLock takes the editing lock without waiting. The lock file stays behind on purpose:
// removing it would let two editors each lock a different file of the same name.
func (e *configEdit) acquireLock(dir string) error {
	name := filepath.Join(dir, configLockName)
	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return fmt.Errorf("lock %s: %w", name, err)
	}
	if fi, serr := f.Stat(); serr != nil || !fi.Mode().IsRegular() {
		f.Close()
		return fmt.Errorf("lock %s: not a regular file", name)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("%s is already being edited (another `mooring config edit` holds %s)", e.path, name)
		}
		return fmt.Errorf("lock %s: %w", name, err)
	}
	e.mu.Lock()
	e.lock = f
	e.mu.Unlock()
	return nil
}

// removeStale deletes copies a killed run left behind (they hold the file's secrets). Only called
// with the lock held, so no live editor owns one.
func (e *configEdit) removeStale(dir, base string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, ent := range ents {
		if !staleCopyName(ent.Name(), base) {
			continue
		}
		n := filepath.Join(dir, ent.Name())
		if fi, err := os.Lstat(n); err == nil && fi.Mode().IsRegular() {
			_ = os.Remove(n)
		}
	}
}

// staleCopyName reports that name (a file beside the config file base) is a copy of an earlier run
// or a file an editor left beside one. The first two prefixes are the copies themselves and what
// editors append to them ("<copy>~", "<copy>.swp", "<copy>.save"); the others are the names editors
// derive by a prefix (vim ".<copy>.swp" and ".<copy>.un~", emacs "#<copy>#" and ".#<copy>"). None can
// be the config file, .last-good or .rejected-edit: every one needs ".edit-" or ".new-" after the
// file's name.
// Intentional: plain prefix and suffix comparisons on the directory's entries, no glob pattern. A
// pattern built from the path let glob characters in a custom --config path ("m[1]/config.yaml",
// "*.yaml") match, and delete, copies that belong to another file.
func staleCopyName(name, base string) bool {
	for _, prefix := range []string{"." + base + ".edit-", "." + base + ".new-", ".." + base + ".edit-", ".#." + base + ".edit-"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return strings.HasPrefix(name, "#."+base+".edit-") && strings.HasSuffix(name, "#")
}

// openTarget reads the file to edit. A symlink is not followed; anything but a regular file with
// a single name is refused.
func (e *configEdit) openTarget() (*editTarget, error) {
	f, err := os.OpenFile(e.path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return &editTarget{}, nil
	}
	if err != nil {
		if li, lerr := os.Lstat(e.path); lerr == nil && li.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s is a symlink; refusing to edit through it (name the real file with --config)", e.path)
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || !ok {
		return nil, fmt.Errorf("%s is not a regular file; refusing to edit it", e.path)
	}
	if st.Nlink != 1 {
		return nil, fmt.Errorf("%s has %d hard links; refusing to edit it (the other names would keep the old file)", e.path, st.Nlink)
	}
	raw, err := readCapped(f)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", e.path, err)
	}
	return &editTarget{exists: true, info: fi, content: raw, uid: int(st.Uid), gid: int(st.Gid), mode: fi.Mode().Perm()}, nil
}

// startFromExample offers the packaged example for a config file that doesn't exist yet and picks
// the new file's owner: root:mooring 0640 (what the service reads), or root only when the host
// has no mooring group yet.
func (e *configEdit) startFromExample(t *editTarget) error {
	var (
		raw     []byte
		example string
	)
	for _, cand := range e.examples {
		b, err := os.ReadFile(cand)
		if err != nil {
			continue
		}
		raw, example = b, cand
		break
	}
	if example == "" {
		return fmt.Errorf("%s does not exist, and there is no example at %s to start from", e.path, strings.Join(e.examples, " or "))
	}
	if len(raw) > maxConfigBytes {
		return fmt.Errorf("%s is too large to start from", example)
	}
	fmt.Fprintf(e.out, "%s does not exist.\n", e.path)
	if e.ask(fmt.Sprintf("Start from %s? (y)es / (n)o: ", example), "yn") != 'y' {
		return &exitError{code: 1, err: fmt.Errorf("%s was not created", e.path)}
	}
	t.content = raw
	t.uid = os.Geteuid()
	if gid, ok := e.groupID(configGroup); ok {
		t.gid, t.mode = gid, 0o640
		return nil
	}
	t.gid, t.mode = os.Getegid(), 0o600
	t.note = fmt.Sprintf("note: this host has no %q group, so the file is readable by root only. The service runs as %s: after creating that user, run  sudo chgrp %s %s && sudo chmod 0640 %s",
		configGroup, configGroup, configGroup, e.path, e.path)
	return nil
}

// createPrivate makes a new 0600 file of this user in dir (it never opens an existing name) with
// content written and flushed, and registers it for removal on the way out.
func (e *configEdit) createPrivate(dir, prefix, suffix string, content []byte) (string, *os.File, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.createPrivateLocked(dir, prefix, suffix, content)
}

// createPrivateLocked is createPrivate for a caller that holds e.mu (install).
func (e *configEdit) createPrivateLocked(dir, prefix, suffix string, content []byte) (string, *os.File, error) {
	if e.interrupted {
		return "", nil, errors.New("interrupted")
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", nil, err
	}
	name := filepath.Join(dir, prefix+hex.EncodeToString(rnd[:])+suffix)
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", nil, err
	}
	if e.temps == nil {
		e.temps = map[string]struct{}{}
	}
	e.temps[name] = struct{}{}
	err = f.Chmod(0o600) // the umask may have cleared more; never less than private
	if err == nil {
		_, err = f.Write(content)
	}
	if err == nil {
		err = f.Sync()
	}
	if err != nil {
		f.Close()
		return "", nil, err
	}
	return name, f, nil
}

// readEditedCopy opens the editor's copy again BY NAME. An editor may have saved by replacing the
// file, so what is at the name now is checked from scratch: not a symlink, a regular file, one
// name, owned by this user.
func readEditedCopy(name string) ([]byte, error) {
	f, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("the edited copy can't be read back (%v)", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("the edited copy can't be read back (%v)", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || !ok {
		return nil, errors.New("the edited copy is no longer a regular file")
	}
	if st.Nlink != 1 {
		return nil, errors.New("the edited copy is now a hard link to another file")
	}
	if int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("the edited copy is now owned by uid %d", st.Uid)
	}
	raw, err := readCapped(f)
	if err != nil {
		return nil, fmt.Errorf("the edited copy can't be read back (%v)", err)
	}
	return raw, nil
}

func readCapped(f *os.File) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxConfigBytes {
		return nil, fmt.Errorf("larger than %d bytes", maxConfigBytes)
	}
	return raw, nil
}

// install puts the checked bytes in place. The file at the path is always complete: the old one
// until the rename, the new one after it.
func (e *configEdit) install(dir, base, editCopy string, t *editTarget, edited []byte, newCfg *config.Config) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	// A signal's handler has removed the copies, released the lock and said the file was not
	// changed (or is about to): that must stay true, so nothing is installed after it.
	if e.interrupted {
		return e.errEditInterrupted()
	}

	// The file must still be the one that was read: another tool may have written it meanwhile, or
	// changed its owner or mode (installing would silently put the old ones back).
	cur, lerr := os.Lstat(e.path)
	changed := false
	switch {
	case t.exists:
		changed = lerr != nil || !os.SameFile(cur, t.info) || !cur.ModTime().Equal(t.info.ModTime()) || cur.Size() != t.info.Size()
		if !changed {
			st, ok := cur.Sys().(*syscall.Stat_t)
			changed = !ok || cur.Mode() != t.info.Mode() || int(st.Uid) != t.uid || int(st.Gid) != t.gid
		}
	default:
		changed = !errors.Is(lerr, fs.ErrNotExist)
	}
	if changed {
		const what = "%s changed while it was being edited (its content, owner or mode); nothing was installed. "
		// Kept as a new root-only file under a name the next run's cleanup leaves alone.
		kept := rejectedEditPath(e.path)
		name, f, err := e.createPrivateLocked(dir, "."+base+".new-", "", edited)
		if err == nil {
			err = f.Close()
		}
		if err == nil {
			// rename(2) replaces an older kept edit, and a symlink at the name itself.
			err = os.Rename(name, kept)
		}
		if err != nil {
			delete(e.temps, editCopy) // keep the operator's work where it is
			e.keptNote = fmt.Sprintf(what+"Your edit is still at %s (root only; it could not be kept as %s: %v). Copy it elsewhere now: the next config edit removes it", e.path, editCopy, kept, err)
			return errors.New(e.keptNote)
		}
		delete(e.temps, name)
		e.keptNote = fmt.Sprintf(what+"Your edit is kept at %s (root only, mode 0600; it replaces an older kept edit): compare it with the file, run config edit again, and remove it when done", e.path, kept)
		return errors.New(e.keptNote)
	}

	// The previous content first: were this run killed between the two renames, .last-good would
	// equal the file that is still in place.
	if t.exists {
		name, f, err := e.createPrivateLocked(dir, "."+base+".new-", ".last-good", t.content)
		if err != nil {
			return fmt.Errorf("keep the previous file: %w; %s was not changed", err, e.path)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("keep the previous file: %w; %s was not changed", err, e.path)
		}
		if err := os.Rename(name, lastGoodPath(e.path)); err != nil {
			return fmt.Errorf("keep the previous file: %w; %s was not changed", err, e.path)
		}
		delete(e.temps, name)
	}

	name, f, err := e.createPrivateLocked(dir, "."+base+".new-", "", edited)
	if err != nil {
		return fmt.Errorf("write the new file: %w; %s was not changed", err, e.path)
	}
	// Owner and group before the mode, so the file is never readable by a group it doesn't have yet.
	// Intentional: the ORIGINAL owner, group and mode, not 0600 root:root. The supported install is
	// root:mooring 0640; a root-only file is one the service can't read.
	err = f.Chown(t.uid, t.gid)
	if err == nil {
		err = f.Chmod(t.mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("write the new file: %w; %s was not changed", err, e.path)
	}
	if e.hook != nil {
		e.hook("before-rename")
	}
	// rename(2) replaces the name itself: were a symlink put at the path after the check above, it
	// would be replaced, not written through.
	if err := os.Rename(name, e.path); err != nil {
		return fmt.Errorf("install the new file: %w; %s was not changed", err, e.path)
	}
	delete(e.temps, name)
	e.installed = true
	if e.hook != nil {
		e.hook("after-rename")
	}
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		d.Close()
	}

	// Intentional (owner decision): a file serve refuses for its owner or mode is still installed
	// with the owner and mode it had, and the operator is told afterwards. Changing them here
	// would be a second, unasked-for change; the content they edited is in place either way.
	defer e.warnServeRefusal()
	if !t.exists {
		fmt.Fprintf(e.out, "%s created (uid %d, gid %d, mode %#o)\n", e.path, t.uid, t.gid, t.mode)
		if t.note != "" {
			fmt.Fprintln(e.out, t.note)
		}
		fmt.Fprintf(e.out, "Start the service with it:\n  sudo systemctl enable --now mooring\n")
		return nil
	}
	fmt.Fprintf(e.out, "%s installed; the previous file is kept as %s\n", e.path, lastGoodPath(e.path))
	oldCfg, oerr := e.parse(t.content, e.path)
	if oerr != nil {
		fmt.Fprintf(e.out, "The previous file did not load, so what changed is not known. To apply:\n  restart (%s)\n", restartCommand)
		return nil
	}
	reload, restart := config.DiffApply(oldCfg, newCfg)
	fmt.Fprintln(e.out, "To apply (nothing was reloaded or restarted):")
	writeApplyLines(e.out, reload, restart)
	return nil
}

// warnServeRefusal says, after an install, that serve will not start with the file for its owner,
// group or mode (or because the service can't reach it), with the command that fixes that.
func (e *configEdit) warnServeRefusal() {
	if e.serveRefusal == nil {
		return
	}
	err := e.serveRefusal(e.path)
	if err == nil {
		return
	}
	fmt.Fprintf(e.out, "warning: mooring serve will not start with %s as it is now, whatever is in it: %v\n", e.path, err)
	var cant *serviceCantUseError
	if errors.As(err, &cant) && cant.advice != "" {
		text, _ := serviceViewFix(e.path, err)
		fmt.Fprintf(e.out, "  %s\n", text)
		return
	}
	fmt.Fprintf(e.out, "  Its owner and mode were kept as they were. To fix them:\n  %s\n", permsFixCommand(e.path))
}

// ask prompts until one of choices is answered; the end of input is the last (the safe) choice.
func (e *configEdit) ask(prompt, choices string) rune {
	for {
		fmt.Fprint(e.out, prompt)
		line, err := e.in.ReadString('\n')
		if ans := strings.ToLower(strings.TrimSpace(line)); ans != "" && strings.ContainsRune(choices, rune(ans[0])) {
			return rune(ans[0])
		}
		if err != nil {
			fmt.Fprintln(e.out)
			return rune(choices[len(choices)-1])
		}
	}
}

// cleanup removes the copies and releases the lock. Safe to call more than once and from the
// signal handler; it waits for an install in progress.
func (e *configEdit) cleanup() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cleanupLocked()
}

// editorSiblings are the backup, swap, undo and lock files editors leave beside a file they edit
// (nano and emacs "name~", vim ".name.swp" or "name.swp" for a dot file, emacs "#name#" and
// ".#name", nano's emergency "name.save", vim's persistent undo ".name.un~"). They hold the file's
// content. Every name is built from the copy's own name, which
// carries this run's random part, so none can be the config file or .last-good.
func editorSiblings(copyPath string) []string {
	dir, name := filepath.Dir(copyPath), filepath.Base(copyPath)
	out := []string{name + "~", "#" + name + "#", ".#" + name, name + ".save", "." + name + ".un~"}
	for _, ext := range []string{".swp", ".swo", ".swn"} {
		out = append(out, name+ext, "."+name+ext)
	}
	for i := range out {
		out[i] = filepath.Join(dir, out[i])
	}
	return out
}

func (e *configEdit) cleanupLocked() {
	for name := range e.temps {
		_ = os.Remove(name)
	}
	e.temps = nil
	if e.editCopy != "" {
		for _, name := range editorSiblings(e.editCopy) {
			_ = os.Remove(name) // unlink only: a symlink (emacs's lock) is removed, not followed
		}
	}
	if e.lock != nil {
		_ = e.lock.Close() // closing the descriptor releases the flock
		e.lock = nil
	}
}

// watchSignals makes SIGINT, SIGTERM, SIGHUP and SIGQUIT stop the editor (SIGTERM, then a kill),
// put the terminal back, remove the copies, release the lock and exit. From the moment the signal
// is taken nothing is installed, so "was not changed" is true whenever it is printed. The returned
// func stops watching.
func (e *configEdit) watchSignals(cancel context.CancelFunc, exit func(int)) (stop func()) {
	sig := make(chan os.Signal, 1)
	done := make(chan struct{})
	// Intentional: SIGQUIT too. Go's default for it is a stack dump and an exit that would leave
	// the copy (the file's secrets) and a raw terminal behind.
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	go func() {
		select {
		case <-done:
			return
		case <-sig:
		}
		// Under the lock an install holds: either it finished (installed) or it will refuse.
		e.mu.Lock()
		e.interrupted = true
		editing, restore := e.editing, e.restoreTerm
		e.mu.Unlock()
		cancel() // stops the editor
		if editing != nil {
			select {
			case <-editing:
			case <-time.After(editorStopDelay + 2*time.Second):
			}
		}
		if restore != nil {
			restore()
		}
		e.mu.Lock()
		e.cleanupLocked()
		installed, keptNote, errOut := e.installed, e.keptNote, e.errOut
		e.mu.Unlock()
		if installed {
			exit(0)
			return
		}
		if errOut == nil {
			errOut = os.Stderr
		}
		fmt.Fprintf(errOut, "\nmooring config: interrupted; %s was not changed\n", e.path)
		if keptNote != "" {
			fmt.Fprintf(errOut, "mooring config: %s\n", keptNote)
		}
		exit(1)
	}()
	return func() { signal.Stop(sig); close(done) }
}

// resolveEditor picks the editor: $SUDO_EDITOR, $VISUAL, $EDITOR, then sensible-editor, nano, vi.
// A variable is split on spaces into a program and its arguments.
// Intentional: no shell. A variable holding shell syntax names a program that doesn't exist and
// is skipped.
func resolveEditor(getenv func(string) string, lookPath func(string) (string, error)) ([]string, error) {
	var candidates [][]string
	for _, v := range []string{"SUDO_EDITOR", "VISUAL", "EDITOR"} {
		if f := strings.Fields(getenv(v)); len(f) > 0 {
			candidates = append(candidates, f)
		}
	}
	candidates = append(candidates, []string{"sensible-editor"}, []string{"nano"}, []string{"vi"})
	for _, c := range candidates {
		if p, err := lookPath(c[0]); err == nil {
			return append([]string{p}, c[1:]...), nil
		}
	}
	return nil, errors.New("no editor found: set EDITOR, or install nano or vi")
}

func lookupGroupID(name string) (int, bool) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, false
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, false
	}
	return gid, true
}
