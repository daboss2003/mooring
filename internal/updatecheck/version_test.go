package updatecheck

import "testing"

func TestParseSemverAndNewer(t *testing.T) {
	if _, ok := parseSemver("dev"); ok {
		t.Error("`dev` must not parse")
	}
	if _, ok := parseSemver("v1.2"); ok {
		t.Error("`v1.2` (2 parts) must not parse")
	}
	v, ok := parseSemver("v0.4.3-rc1+abc")
	if !ok || v != (semver{0, 4, 3}) {
		t.Errorf("parseSemver strip pre/build: %+v ok=%v", v, ok)
	}
	if !newer("0.4.3", "v0.4.5") {
		t.Error("0.4.5 should be newer than 0.4.3")
	}
	if newer("0.4.5", "v0.4.5") {
		t.Error("equal is not newer")
	}
	if newer("0.4.5", "0.4.3") {
		t.Error("older latest is not newer")
	}
	if newer("dev", "0.4.5") {
		t.Error("unparseable running must suppress (not newer)")
	}
}

func TestAffectedByRange(t *testing.T) {
	v := semver{0, 4, 3}
	cases := []struct {
		rng          string
		want, wantOK bool
	}{
		{"< 0.4.4", true, true},
		{"< 0.4.3", false, true},
		{"<= 0.4.3", true, true},
		{">= 0.4.0, < 0.4.4", true, true},
		{">= 0.5.0", false, true},
		{"= 0.4.3", true, true},
		{"= 0.4.2", false, true},
		{"0.4.3", true, true},             // bare version == "="
		{"~> 0.4.0", false, false},        // unknown operator → unparseable → fail-safe
		{"< not-a-version", false, false}, // unparseable version → fail-safe
		{"", false, false},                // empty
	}
	for _, c := range cases {
		got, ok := affectedByRange(v, c.rng)
		if got != c.want || ok != c.wantOK {
			t.Errorf("affectedByRange(%q) = (%v,%v), want (%v,%v)", c.rng, got, ok, c.want, c.wantOK)
		}
	}
}
