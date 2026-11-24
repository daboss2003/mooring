package enrich

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/enrich/mmdbtest"
)

// A valid file of the right kind opens; its metadata is readable and lookups work.
func TestOpenDBValid(t *testing.T) {
	d := openTestDB(t, testCity("Lagos"), KindCity)
	defer d.Close()
	if md := d.Metadata(); md.DatabaseType != "DBIP-City-Lite" || md.NodeCount == 0 || md.IPVersion != 6 {
		t.Errorf("metadata %+v", md)
	}
	a := openTestDB(t, testASN(), KindASN)
	defer a.Close()
	if !strings.Contains(a.Metadata().DatabaseType, "ASN") {
		t.Errorf("ASN metadata %+v", a.Metadata())
	}
}

// A file of the wrong kind, a corrupt or truncated file, an empty, oversized or non-regular file is
// refused.
func TestOpenDBRefuses(t *testing.T) {
	city := testCity("Lagos")
	asn := testASN()
	cases := []struct {
		name string
		b    []byte
		kind string
		want string
	}{
		{"ASN as City", asn, KindCity, "database type"},
		{"City as ASN", city, KindASN, "database type"},
		{"unknown kind", city, "Country", "kind"},
		{"empty", nil, KindCity, "empty"},
		{"garbage", []byte(strings.Repeat("not a database ", 100)), KindCity, ""},
		{"truncated tree", city[:40], KindCity, ""},
		{"tree cut out", append(append([]byte{}, city[:10]...), city[len(city)-300:]...), KindCity, ""},
		{"node count past the file", mmdbtest.Write(mmdbtest.Options{DatabaseType: "DBIP-City-Lite", NodeCountDelta: 1 << 20},
			[]mmdbtest.Network{{Prefix: "8.8.8.0/24", Data: map[string]any{"city": "x"}}}), KindCity, ""},
		{"node count off by one", mmdbtest.Write(mmdbtest.Options{DatabaseType: "DBIP-City-Lite", NodeCountDelta: -1},
			[]mmdbtest.Network{{Prefix: "8.8.8.0/24", Data: map[string]any{"city": "x"}}}), KindCity, ""},
		{"no networks", mmdbtest.Write(mmdbtest.Options{DatabaseType: "DBIP-City-Lite"}, nil), KindCity, ""},
		{"invalid UTF-8 in a record", mmdbtest.City(mmdbtest.CityEntry{Prefix: "8.8.8.0/24", City: "\xff\xfe", Country: "US"}), KindCity, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := openBytes(t, c.b, c.kind)
			if err == nil {
				d.Close()
				t.Fatal("opened")
			}
			if c.want != "" && !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q doesn't mention %q", err, c.want)
			}
		})
	}

	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.WriteFile(filepath.Join(dir, "big.mmdb"), city, 0o600); err != nil {
		t.Fatal(err)
	}
	if d, err := OpenDB(root, "big.mmdb", KindCity, int64(len(city)-1)); err == nil || !strings.Contains(err.Error(), "larger") {
		if d != nil {
			d.Close()
		}
		t.Errorf("a file over the size limit: %v", err)
	}
	// A symlink is refused even when it stays inside the root (os.Root itself refuses one that leaves
	// it, or an absolute one).
	for link, target := range map[string]string{"link.mmdb": "big.mmdb", "abs.mmdb": filepath.Join(dir, "big.mmdb")} {
		if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
		if d, err := OpenDB(root, link, KindCity, 64<<20); err == nil {
			d.Close()
			t.Errorf("symlink %s → %s was opened", link, target)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub.mmdb"), 0o700); err != nil {
		t.Fatal(err)
	}
	if d, err := OpenDB(root, "sub.mmdb", KindCity, 64<<20); err == nil {
		d.Close()
		t.Error("a directory was opened")
	}
	if d, err := OpenDB(root, "../big.mmdb", KindCity, 64<<20); err == nil {
		d.Close()
		t.Error("a path out of the root was opened")
	}
	if d, err := OpenDB(root, "missing.mmdb", KindCity, 64<<20); err == nil || !os.IsNotExist(err) {
		if d != nil {
			d.Close()
		}
		t.Errorf("a missing file: %v, want a not-exist error", err)
	}
}

// cleanText strips control and format characters, replaces invalid UTF-8 and cuts on a rune
// boundary.
func TestCleanText(t *testing.T) {
	for in, want := range map[string]string{
		"Lagos":                        "Lagos",
		"\xff\xfeSydney":               "Sydney",
		"a\x00b\x1bc\x7fd\u0085e":      "abcde",
		"‮evil​":                       "evil",
		"  São Paulo ":                 "São Paulo",
		strings.Repeat("é", 40):        strings.Repeat("é", 32),
		"Ab" + strings.Repeat("x", 70): "Ab" + strings.Repeat("x", 62),
	} {
		if got := cleanText(in, 64); got != want {
			t.Errorf("cleanText(%q) = %q, want %q", in, got, want)
		}
	}
}

// OpenDB and lookups never panic or hang on a hostile file.
func FuzzOpenDB(f *testing.F) {
	f.Add(testCity("Lagos"), true)
	f.Add(testASN(), false)
	f.Add(mmdbtest.Write(mmdbtest.Options{DatabaseType: "DBIP-City-Lite", NodeCountDelta: -1},
		[]mmdbtest.Network{{Prefix: "8.8.8.0/24", Data: map[string]any{"city": "x"}}}), true)
	dir := f.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { root.Close() })
	f.Fuzz(func(t *testing.T, b []byte, city bool) {
		if err := os.WriteFile(filepath.Join(dir, "db.mmdb"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		kind := KindASN
		if city {
			kind = KindCity
		}
		d, err := OpenDB(root, "db.mmdb", kind, 1<<20)
		if err != nil {
			return
		}
		x := New()
		if city {
			x.SetCity(d)
		} else {
			x.SetASN(d)
		}
		for _, ip := range []string{"8.8.8.8", "41.58.1.1", "1.1.1.1", "2001:4860::1", "185.220.101.7"} {
			e := siem.Event{IP: ip}
			x.Enrich(&e)
		}
		x.Close()
	})
}
