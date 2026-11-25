package main

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	needrestartConfSrc = "deploy/needrestart/mooring.conf"
	needrestartConfDst = "/etc/needrestart/conf.d/mooring.conf"
)

// needrestartOverride is the one statement the file may hold: the unit's entry in override_rc, set to 0.
var needrestartOverride = regexp.MustCompile(`^\$nrconf\{override_rc\}\{qr\((.+)\)\} = 0;$`)

// needrestartUnits are unit names against the override's pattern: only mooring.service may match.
var needrestartUnits = map[string]bool{
	"mooring.service":      true,
	"mooring-foo.service":  false,
	"mooring@x.service":    false,
	"xmooring.service":     false,
	"mooring.service.d":    false,
	"mooringXservice":      false,
	"mooring.socket":       false,
	"mooring.service\nfoo": false,
	"docker.service":       false,
}

// needrestartStatements returns the file's lines that are not blank or comments.
func needrestartStatements(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(needrestartConfSrc)))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if s := strings.TrimSpace(line); s != "" && !strings.HasPrefix(s, "#") {
			out = append(out, line)
		}
	}
	return out
}

// The package installs the needrestart override as a conffile at the path needrestart reads.
// needrestart restarts a service that runs a replaced binary after every apt run; postinstall leaves
// mooring.service on the old version when the new one refuses config.yaml, and without the override
// needrestart restarts it onto the version that exits 78.
func TestPackageShipsNeedrestartOverride(t *testing.T) {
	b, err := os.ReadFile("../../.goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	type content struct {
		Src      string `yaml:"src"`
		Dst      string `yaml:"dst"`
		Type     string `yaml:"type"`
		FileInfo struct {
			Mode  int    `yaml:"mode"`
			Owner string `yaml:"owner"`
			Group string `yaml:"group"`
		} `yaml:"file_info"`
	}
	var cfg struct {
		Nfpms []struct {
			ID       string    `yaml:"id"`
			Contents []content `yaml:"contents"`
		} `yaml:"nfpms"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Nfpms) == 0 {
		t.Fatal("no nfpms in .goreleaser.yaml")
	}
	// needrestart.conf reads /etc/needrestart/conf.d/*.conf and nothing else.
	if path.Dir(needrestartConfDst) != "/etc/needrestart/conf.d" || path.Ext(needrestartConfDst) != ".conf" {
		t.Fatalf("%s is not a *.conf file in /etc/needrestart/conf.d", needrestartConfDst)
	}
	for _, p := range cfg.Nfpms {
		var found []content
		for _, c := range p.Contents {
			if c.Dst == needrestartConfDst {
				found = append(found, c)
			} else if strings.HasPrefix(c.Dst, "/etc/needrestart/") {
				t.Errorf("%s: %s is installed under /etc/needrestart; only %s is expected", p.ID, c.Dst, needrestartConfDst)
			}
		}
		if len(found) != 1 {
			t.Errorf("%s: %d contents entries install %s, want 1", p.ID, len(found), needrestartConfDst)
			continue
		}
		c := found[0]
		if c.Src != needrestartConfSrc {
			t.Errorf("%s: src = %q, want %q", p.ID, c.Src, needrestartConfSrc)
		}
		if c.Type != "config|noreplace" {
			t.Errorf("%s: type = %q, want config|noreplace (a conffile: an operator's edit survives upgrades)", p.ID, c.Type)
		}
		if c.FileInfo.Mode != 0o644 || c.FileInfo.Owner != "root" || c.FileInfo.Group != "root" {
			t.Errorf("%s: file_info = %o %s:%s, want 644 root:root", p.ID, c.FileInfo.Mode, c.FileInfo.Owner, c.FileInfo.Group)
		}
	}
}

// The file holds one statement, the override for mooring.service, and its pattern matches that unit
// name only.
func TestNeedrestartOverrideMatchesOnlyMooringService(t *testing.T) {
	stmts := needrestartStatements(t)
	if len(stmts) != 1 {
		t.Fatalf("%s has %d statements, want 1 (the override): %q", needrestartConfSrc, len(stmts), stmts)
	}
	m := needrestartOverride.FindStringSubmatch(stmts[0])
	if m == nil {
		t.Fatalf("statement %q is not `$nrconf{override_rc}{qr(<pattern>)} = 0;`", stmts[0])
	}
	if m[1] != `^mooring\.service$` {
		t.Errorf("pattern = %q, want %q", m[1], `^mooring\.service$`)
	}
	re, err := regexp.Compile(m[1])
	if err != nil {
		t.Fatal(err)
	}
	for unit, want := range needrestartUnits {
		// Perl's $ also matches before a final newline; a unit name never ends in one.
		if got := re.MatchString(unit); got != want {
			t.Errorf("pattern %q matches %q = %v, want %v", m[1], unit, got, want)
		}
	}
}

// The file is Perl that needrestart.conf evals. Evaluated the same way, it leaves override_rc with a
// value of 0 for mooring.service and no entry for any other unit name.
func TestNeedrestartOverrideEvaluatesInPerl(t *testing.T) {
	perl, err := exec.LookPath("perl")
	if err != nil {
		t.Skip("perl not installed")
	}
	abs, err := filepath.Abs(filepath.Join("..", "..", filepath.FromSlash(needrestartConfSrc)))
	if err != nil {
		t.Fatal(err)
	}
	// The eval line is needrestart.conf's own; the lookup loop is needrestart's (the last matching
	// key's value is the unit's default selection, "none" stands for no matching key).
	const script = `use strict; use warnings;
our %nrconf = (override_rc => { qr(^docker) => 0 });
my $fn = shift @ARGV;
eval do { local(@ARGV, $/) = $fn; <>};
die "Error parsing $fn: $@" if($@);
foreach my $rc (@ARGV) {
    my $restart = "none";
    foreach my $re (keys %{$nrconf{override_rc}}) {
        next unless($rc =~ /$re/);
        $restart = $nrconf{override_rc}->{$re};
        last;
    }
    print "$rc=$restart\n";
}
`
	args := []string{"-e", script, abs}
	var want strings.Builder
	for _, unit := range []string{"mooring.service", "mooring-foo.service", "mooring@x.service", "xmooring.service", "mooring.service.d", "mooringXservice", "mooring.socket"} {
		args = append(args, unit)
		if needrestartUnits[unit] {
			want.WriteString(unit + "=0\n")
		} else {
			want.WriteString(unit + "=none\n")
		}
	}
	out, err := exec.Command(perl, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("perl: %v\n%s", err, out)
	}
	if string(out) != want.String() {
		t.Errorf("perl evaluated the file to:\n%swant:\n%s", out, want.String())
	}
}
