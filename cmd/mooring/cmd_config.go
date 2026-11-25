package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/yamldiag"
)

// cmd_config.go is `mooring config`: the host config file's own tools.
//
//	mooring config check   — the checks serve runs at start, without starting anything (any user
//	                         who can read the file; the unit's ExecReload runs it as the service).
//	mooring config edit    — edit a copy, install it only when it is valid (cmd_config_edit_unix.go).
//
// Neither prints a value from the file: what is wrong comes from the diagnostics, which mask them,
// and what is right is reported by key name and hostname only.

const (
	reloadCommand  = "sudo systemctl reload mooring"
	restartCommand = "sudo systemctl restart mooring"
	checkCommand   = "sudo mooring config check"
	// serviceGroup is the group config.yaml belongs to (root:mooring 0640).
	serviceGroup = "mooring"
	// serviceProbeCommand is the hidden `mooring config` subcommand root's check re-executes this
	// binary with, as the service's user (cmd_config_perms_unix.go). It is in no usage text.
	serviceProbeCommand = "probe-as-service"
)

// permsFixCommand is the command that gives the config file the owner, group and mode the service
// reads it with.
func permsFixCommand(path string) string {
	return fmt.Sprintf("sudo chown root:%s %s && sudo chmod 0640 %s", serviceGroup, path, path)
}

func cmdConfig(args []string) error {
	const use = "usage: mooring config <check|edit> [--config PATH]"
	if len(args) == 0 {
		return usageError(use)
	}
	switch args[0] {
	case "check":
		return runConfigCheck(args[1:], configCheckEnv{stdout: os.Stdout, stderr: os.Stderr, load: config.Load})
	case "edit":
		return cmdConfigEdit(args[1:])
	case serviceProbeCommand:
		return runConfigProbe(args[1:], os.Stdout, config.Load)
	default:
		return usageError("unknown config subcommand %q\n%s", args[0], use)
	}
}

// runConfigProbe is `mooring config probe-as-service -- /absolute/path`: serve's own read of the
// file (config.Load), answered by the exit status. 0: this user can use the file. config.ExitInvalid
// (78): it can't, and stdout has why on one line. 2: no answer (the file is not there, an I/O
// error, a wrong invocation). It reads nothing but the file and prints nothing from it: the line is
// the diagnostics' one-line form, or the error about the file's path, owner, group or mode.
// Intentional: no flag parsing. The one argument after "--" is the path, whatever it looks like.
func runConfigProbe(args []string, stdout io.Writer, load func(path string) (*config.Config, error)) error {
	if len(args) != 2 || args[0] != "--" || !filepath.IsAbs(args[1]) {
		return &exitError{code: 2, err: errors.New("usage: mooring config " + serviceProbeCommand + " -- /absolute/path"), printed: true}
	}
	_, err := load(args[1])
	if err == nil {
		return nil
	}
	if configUnreadable(err) && !errors.Is(err, fs.ErrPermission) {
		return &exitError{code: 2, err: err, printed: true}
	}
	fmt.Fprintln(stdout, probeReason(err))
	return &exitError{code: config.ExitInvalid, err: err, printed: true}
}

// probeReason is err on one line: the failed call alone for a file that can't be reached
// ("stat /etc/mooring/config.yaml: permission denied"), else the error's own text.
func probeReason(err error) string {
	msg := err.Error()
	var d *yamldiag.Diagnostics
	var pe *fs.PathError
	if !errors.As(err, &d) && errors.As(err, &pe) {
		msg = pe.Error()
	}
	return strings.Join(strings.Fields(msg), " ")
}

// maxProbeLine bounds the one line root's check reads from the child.
const maxProbeLine = 1024

// probeLine is the child's output as the one line it must be: valid UTF-8 of at most maxProbeLine
// bytes, printable characters only, with or without the final newline. ok=false for anything else.
// Intentional: nothing is cleaned up. The child runs as the service's user, which can interfere
// with it, and the line is printed on root's terminal: output that is not exactly a plain line
// (an escape sequence, a second line, a carriage return) is not shown at all.
func probeLine(out []byte) (string, bool) {
	line := strings.TrimSuffix(string(out), "\n")
	if len(line) > maxProbeLine || !utf8.ValidString(line) || strings.TrimSpace(line) == "" {
		return "", false
	}
	for _, r := range line {
		if !unicode.IsPrint(r) {
			return "", false
		}
	}
	return line, true
}

// serviceCantUseError is a config file that is fine for root and that the service can't use: it
// can't read it, or refuses it for its group. Root's own check can't see either (root reads every
// file and is exempt from the group rule).
type serviceCantUseError struct {
	msg string
	// advice and command say what to do when the file's own owner and mode are not the cause:
	// a sentence without its full stop, and the command that does it ("" when there is none).
	// Both empty: the fix is permsFixCommand.
	advice, command string
}

func (e *serviceCantUseError) Error() string { return e.msg }

// serviceViewFix is what to do about a file the service can't use (verr, from serviceView), for a
// terminal (text, which follows "What is in the file is valid. " or stands alone) and on one line
// (hint: --json, doctor).
func serviceViewFix(path string, verr error) (text, hint string) {
	var e *serviceCantUseError
	if !errors.As(verr, &e) || e.advice == "" {
		fix := permsFixCommand(path)
		return "To fix its owner and mode:\n  " + fix, "run: " + fix
	}
	sentence := strings.ToUpper(e.advice[:1]) + e.advice[1:]
	if e.command == "" {
		return sentence + ".", e.advice
	}
	return sentence + ":\n  " + e.command, e.advice + ": " + e.command
}

// lastGoodPath is where `config edit` keeps the file it replaced.
func lastGoodPath(path string) string { return path + ".last-good" }

// rejectedEditPath is where `config edit` keeps an edit it could not install because the file
// changed underneath it. Intentional: no leading dot and no ".edit-"/".new-" in the name, so the
// next run's stale-copy cleanup never matches it.
func rejectedEditPath(path string) string { return path + ".rejected-edit" }

// configCheckEnv is what `config check` writes to and loads with (tests inject both).
type configCheckEnv struct {
	stdout, stderr io.Writer
	load           func(path string) (*config.Config, error)
	// serviceUser reports that the caller is the service's own user (nil: looked up by name).
	serviceUser func() bool
	// serviceView judges the file as the service would, for a caller whose own check can't
	// (root). nil: serviceView.
	serviceView func(path string) error
}

// isServiceUser reports that this process runs as the service's user ("mooring"): the unit's
// ExecReload check and the package script's do.
func isServiceUser() bool {
	u, err := user.Current()
	return err == nil && u.Username == serviceGroup
}

// configCheckReport is the --json form of a valid file. A refused file prints the diagnostics'
// own JSON instead; the exit status tells the two apart.
type configCheckReport struct {
	OK            bool               `json:"ok"`
	File          string             `json:"file"`
	Warnings      []string           `json:"warnings"`
	CertHostnames []configCheckCert  `json:"cert_hostnames"`
	RepeatedLabel string             `json:"repeated_label,omitempty"`
	Changed       *configCheckChange `json:"changed,omitempty"`
	// RejectedEdit is the edit `config edit` kept instead of installing, when there is one.
	RejectedEdit string `json:"rejected_edit,omitempty"`
}

type configCheckCert struct {
	Host string `json:"host"`
	Why  string `json:"why"`
}

type configCheckChange struct {
	Since   string   `json:"since"`
	Reload  []string `json:"reload"`
	Restart []string `json:"restart"`
}

// configCheckUnjudged is the --json form of a file that could not be judged (exit 2): it is
// missing, can't be read, or belongs to a group this user can't judge it by. The same object
// `validate --json` prints for a definition it can't read.
type configCheckUnjudged struct {
	OK    bool   `json:"ok"`
	File  string `json:"file"`
	Error string `json:"error"`
}

// otherGroupAdvice is what a caller who can't judge the file (config.ErrOtherGroup) is told.
func otherGroupAdvice(path string) string {
	return fmt.Sprintf("can't judge %s as this user (the file belongs to another group): run %s", path, checkCommand)
}

// runConfigCheck is `mooring config check`. Exit status: 0 valid, config.ExitInvalid (78) refused,
// 2 for a file that can't be read or judged by this user, or a wrong invocation.
func runConfigCheck(args []string, env configCheckEnv) error {
	fs := flag.NewFlagSet("config check", flag.ContinueOnError)
	fs.SetOutput(env.stderr)
	path := fs.String("config", config.DefaultPath, "path to config.yaml")
	quiet := fs.Bool("quiet", false, "print nothing; the exit status is the answer")
	errorsOnly := fs.Bool("errors-only", false, "print nothing when the file is valid; print what is wrong when it isn't")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if err := fs.Parse(args); err != nil {
		return &exitError{code: 2, err: err, printed: true} // flag already printed it
	}
	if fs.NArg() > 0 {
		return usageError("config check takes no arguments (got %q)", fs.Arg(0))
	}
	if *quiet && (*asJSON || *errorsOnly) {
		return usageError("config check: --quiet can't be combined with --json or --errors-only")
	}
	// unjudged: the file was not judged (exit 2).
	unjudged := func(err error) error {
		switch {
		case *quiet:
			return &exitError{code: 2, err: err, printed: true}
		case *asJSON:
			b, jerr := json.Marshal(configCheckUnjudged{File: *path, Error: err.Error()})
			if jerr != nil {
				return jerr
			}
			fmt.Fprintf(env.stdout, "%s\n", b)
			return &exitError{code: 2, err: err, printed: true}
		}
		return &exitError{code: 2, err: err}
	}
	const refusedLine = "\n%s is refused: mooring will not start or reload with it.\n"

	cfg, err := env.load(*path)
	if err != nil {
		// Intentional: not a refusal. The group rule compares the file's group with THIS caller's
		// primary group; for anyone but the service user (and root, who is exempt) a healthy
		// root:mooring 0640 file fails it. Exit 2, like a file that can't be read.
		// The service user is the one caller the rule is for: for it the file IS refused (below).
		asService := env.serviceUser
		if asService == nil {
			asService = isServiceUser
		}
		if errors.Is(err, config.ErrOtherGroup) && !asService() {
			return unjudged(errors.New(otherGroupAdvice(*path)))
		}
		if configUnreadable(err) {
			return unjudged(err)
		}
		switch {
		case *quiet:
		case *asJSON:
			fmt.Fprintf(env.stdout, "%s\n", refusalJSON(*path, err, ""))
		default:
			fmt.Fprintln(env.stderr, strings.TrimRight(refusalText(err), "\n"))
			fmt.Fprintf(env.stderr, refusedLine, *path)
		}
		return &exitError{code: config.ExitInvalid, err: err, printed: true}
	}

	// Root reads every file and is exempt from the group rule, so the load above can't see a file
	// the service can't reach, can't read or refuses for its group. Intentional: that is a refusal (78), not a
	// warning under "OK". The service will not start or reload with the file, whatever is in it.
	view := env.serviceView
	if view == nil {
		view = serviceView
	}
	if verr := view(*path); verr != nil {
		text, hint := serviceViewFix(*path, verr)
		switch {
		case *quiet:
		case *asJSON:
			fmt.Fprintf(env.stdout, "%s\n", refusalJSON(*path, verr, hint))
		default:
			fmt.Fprintf(env.stderr, "%s\nWhat is in the file is valid. %s\n", verr, text)
			fmt.Fprintf(env.stderr, refusedLine, *path)
		}
		return &exitError{code: config.ExitInvalid, err: verr, printed: true}
	}
	if *quiet || *errorsOnly {
		return nil
	}

	rep := configCheckReport{OK: true, File: *path, Warnings: append([]string{}, cfg.LoadWarnings...), CertHostnames: []configCheckCert{}}
	for _, n := range cfg.CertHostnames() {
		rep.CertHostnames = append(rep.CertHostnames, configCheckCert{Host: n.Host, Why: n.Why})
	}
	if host, ok := cfg.RepeatedLabel(); ok {
		rep.RepeatedLabel = host
	}
	// lstat only: the kept edit is root's (0600) and is never read here.
	if _, serr := os.Lstat(rejectedEditPath(*path)); serr == nil {
		rep.RejectedEdit = rejectedEditPath(*path)
	}
	prevNote := ""
	// Intentional: an unreadable .last-good is skipped without a word. It is root's (0600), and
	// this command also runs as the service user (the unit's ExecReload), which can't read it.
	if raw, rerr := os.ReadFile(lastGoodPath(*path)); rerr == nil {
		if prev, perr := config.ParseNamed(raw, lastGoodPath(*path)); perr == nil {
			reload, restart := config.DiffApply(prev, cfg)
			rep.Changed = &configCheckChange{Since: lastGoodPath(*path), Reload: nonNil(reload), Restart: nonNil(restart)}
		} else {
			prevNote = fmt.Sprintf("%s does not load, so what changed since it is not known; %s applies everything", lastGoodPath(*path), restartCommand)
		}
	}

	if *asJSON {
		b, jerr := json.Marshal(rep)
		if jerr != nil {
			return jerr
		}
		fmt.Fprintf(env.stdout, "%s\n", b)
		return nil
	}
	w := env.stdout
	fmt.Fprintf(w, "OK: %s is valid\n", *path)
	for _, x := range rep.Warnings {
		fmt.Fprintf(w, "warning: %s\n", x)
	}
	if rep.RepeatedLabel != "" {
		fmt.Fprintf(w, "warning: the dashboard hostname is %s: admin.subdomain repeats the first label of edge.base_domain (if that is not meant, set edge.base_domain to the domain without it)\n", rep.RepeatedLabel)
	}
	if len(rep.CertHostnames) > 0 {
		fmt.Fprintln(w, "Certificates are requested for (plus one per app route with its own hostname):")
		width := 0
		for _, c := range rep.CertHostnames {
			width = max(width, len(c.Host))
		}
		for _, c := range rep.CertHostnames {
			fmt.Fprintf(w, "  %-*s  %s\n", width, c.Host, c.Why)
		}
	}
	if rep.Changed != nil {
		fmt.Fprintf(w, "Changed since %s:\n", rep.Changed.Since)
		writeApplyLines(w, rep.Changed.Reload, rep.Changed.Restart)
	}
	if prevNote != "" {
		fmt.Fprintf(w, "note: %s\n", prevNote)
	}
	if rep.RejectedEdit != "" {
		fmt.Fprintf(w, "note: an edit that was not installed is kept at %s (root only): compare it with the file, then remove it\n", rep.RejectedEdit)
	}
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// writeApplyLines says which changed keys a reload applies and which need a restart, each with
// the exact command. It never runs either.
func writeApplyLines(w io.Writer, reload, restart []string) {
	if len(reload) == 0 && len(restart) == 0 {
		fmt.Fprintln(w, "  no setting changed; nothing to apply")
		return
	}
	if len(reload) > 0 {
		fmt.Fprintf(w, "  reload  (%s): %s\n", reloadCommand, strings.Join(reload, ", "))
	}
	if len(restart) > 0 {
		fmt.Fprintf(w, "  restart (%s): %s\n", restartCommand, strings.Join(restart, ", "))
	}
	if len(reload) > 0 && len(restart) > 0 {
		fmt.Fprintln(w, "  a restart applies both")
	}
}

// configUnreadable reports that err is about reaching the file (missing, no permission to read
// it, an I/O error), not about what is in it or who owns it.
func configUnreadable(err error) bool {
	var d *yamldiag.Diagnostics
	if errors.As(err, &d) {
		return false
	}
	var pe *fs.PathError
	return errors.As(err, &pe)
}

// refusalText is a refused file's error for a terminal: the diagnostics' multi-line form when the
// error is one, else its message.
func refusalText(err error) string {
	var d *yamldiag.Diagnostics
	if errors.As(err, &d) {
		if t := d.Terminal(); strings.TrimSpace(t) != "" {
			return t
		}
	}
	return err.Error()
}

// refusalJSON is a refused file's error as the diagnostics' JSON. An error that isn't a
// Diagnostics (the file's owner or mode) becomes one problem without a position, with hint.
func refusalJSON(file string, err error, hint string) []byte {
	var d *yamldiag.Diagnostics
	if errors.As(err, &d) {
		if b := d.JSON(); len(b) > 0 {
			return b
		}
	}
	plain := &yamldiag.Diagnostics{File: file, Problems: []yamldiag.Problem{{Kind: yamldiag.KindSemantic, Msg: err.Error(), Hint: hint}}}
	if b := plain.JSON(); len(b) > 0 {
		return b
	}
	b, _ := json.Marshal(plain)
	return b
}

// unitRetryNote is what serve's line says when it exits for a cause that can end by itself.
const unitRetryNote = "the unit starts the service again every 2s, so a volume that attaches late is picked up without a restart"

// configStartExit is serve's exit status for a config.yaml it did not load.
// Intentional (owner decision): a file that is not there, or that can't be reached for a reason
// other than its permissions, exits 1, which the unit restarts on: /etc/mooring may be on a volume
// that attaches after the service starts. A file that is there and refused, or that the service
// may not read, exits config.ExitInvalid (78, never restarted): a restart can't fix either.
func configStartExit(err error) int {
	if configUnreadable(err) && !errors.Is(err, fs.ErrPermission) {
		return 1
	}
	return config.ExitInvalid
}

// logConfigRefused writes serve's single line for a config.yaml it will not start with, in the
// same slog text format as the rest of its log. The message says which it is: no file, a file the
// service can't read, a file of another group, or a file that is refused.
func logConfigRefused(log *slog.Logger, path string, err error) {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		log.Error("config.yaml not found; not starting", "file", path, "detail", err.Error(),
			"hint", "create it: sudo mooring config edit (or pass --config); "+unitRetryNote)
		return
	case configUnreadable(err) && !errors.Is(err, fs.ErrPermission):
		log.Error("config.yaml can't be read; not starting", "file", path, "detail", err.Error(), "hint", unitRetryNote)
		return
	case configUnreadable(err):
		log.Error("config.yaml can't be read; not starting", "file", path, "detail", err.Error(),
			"hint", "the service user must be able to read it: "+permsFixCommand(path))
		return
	case errors.Is(err, config.ErrOtherGroup):
		log.Error("config.yaml belongs to another group than the service's; not starting", "file", path, "detail", err.Error(),
			"hint", "give it to the service's group: "+permsFixCommand(path))
		return
	}
	attrs := []any{"file", path}
	problems := 1
	var d *yamldiag.Diagnostics
	if errors.As(err, &d) {
		if n := len(d.Problems) + d.More; n > 0 {
			problems = n
		}
		if len(d.Problems) > 0 && d.Problems[0].Line > 0 {
			attrs = append(attrs, "line", d.Problems[0].Line)
		}
	}
	attrs = append(attrs, "problems", problems, "detail", err.Error(), "hint", "run: "+checkCommand)
	log.Error("config.yaml is not valid; not starting", attrs...)
}
