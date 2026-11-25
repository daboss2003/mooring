package imagescan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// repeatReader yields prefix, then n times the byte b, and counts what was read from it.
type repeatReader struct {
	prefix []byte
	b      byte
	n      int64
	read   int64
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if len(r.prefix) > 0 {
		k := copy(p, r.prefix)
		r.prefix = r.prefix[k:]
		r.read += int64(k)
		return k, nil
	}
	if r.n <= 0 {
		return 0, io.EOF
	}
	k := min(int64(len(p)), r.n)
	for i := range p[:k] {
		p[i] = r.b
	}
	r.n -= k
	r.read += k
	return int(k), nil
}

const tooDeepReason = "the scan report is nested deeper than 512 levels"

// A run of opening brackets is refused at the depth limit wherever it is in the report, after
// reading little of it and without allocating for it. Before the limit, 64 MiB of "[" under a key
// Mooring skips grew the heap by 1650 MiB and failed only at the end of the input.
func TestScanReportDepthLimitBoundsMemory(t *testing.T) {
	for name, prefix := range map[string]string{
		"skipped top-level key":    `{"X":`,
		"skipped Metadata key":     `{"Metadata":{"ImageConfig":`,
		"skipped result key":       `{"Results":[{"Target":"t","Packages":`,
		"inside one finding":       `{"Results":[{"Vulnerabilities":[{"Severity":"HIGH","Z":`,
		"inside Metadata.OS":       `{"Metadata":{"OS":{"Family":"ubuntu","Z":`,
		"skipped, objects":         `{"X":{"a":{"a":`,
		"skipped, after the walk":  `{"Results":[],"Metadata":null,"X":`,
		"skipped, with whitespace": "{\n  \"X\": ",
	} {
		for _, b := range []byte{'[', '{'} {
			src := &repeatReader{prefix: []byte(prefix), b: b, n: 8 << 20}
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			_, err := readHostReport(src, defaultLimits, nil, nil, true)
			runtime.ReadMemStats(&after)
			if b == '{' && !strings.Contains(prefix, `"X"`) {
				// "{{" is not JSON, which the decoder may notice before 512 of them are read.
				var oe *outputError
				if !errors.As(err, &oe) {
					t.Errorf("%s (%c): err = %v; want a report error", name, b, err)
				}
			} else if b == '[' {
				wantReason(t, name, err, tooDeepReason)
			}
			var oe *outputError
			if errors.As(err, &oe) && oe.reason == tooDeepReason && !oe.limit {
				t.Errorf("%s: the depth limit must stop the scanner", name)
			}
			if src.read > 64<<10 {
				t.Errorf("%s (%c): read %d bytes of the run before refusing it; want it refused at the limit", name, b, src.read)
			}
			// TotalAlloc only grows, so this is everything allocated while decoding.
			if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
				t.Errorf("%s (%c): allocated %d bytes for a run of brackets; want under 1 MiB", name, b, grew)
			}
		}
	}
}

func TestScanReportDepthLimitIsExact(t *testing.T) {
	nest := func(prefix, suffix string, open, close string, n int) string {
		return prefix + strings.Repeat(open, n) + strings.Repeat(close, n) + suffix
	}
	// The report object is level 1, the result array 2, the result 3, so a skipped value there may
	// add 509 levels.
	for name, c := range map[string]struct {
		in string
		ok bool
	}{
		"skipped, 511 below the report":     {nest(`{"X":`, `,"Results":[]}`, "[", "]", 511), true},
		"skipped, 512 below the report":     {nest(`{"X":`, `,"Results":[]}`, "[", "]", 512), false},
		"skipped objects, 511":              {nest(`{"X":`, `1`+strings.Repeat("}", 511)+`}`, `{"a":`, "", 511), true},
		"skipped objects, 512":              {nest(`{"X":`, `1`+strings.Repeat("}", 512)+`}`, `{"a":`, "", 512), false},
		"in a result, 509":                  {nest(`{"Results":[{"Target":"t","P":`, `}]}`, "[", "]", 509), true},
		"in a result, 510":                  {nest(`{"Results":[{"Target":"t","P":`, `}]}`, "[", "]", 510), false},
		"in a finding, 507":                 {nest(`{"Results":[{"Vulnerabilities":[{"Severity":"LOW","Z":`, `}]}]}`, "[", "]", 507), true},
		"in a finding, 508":                 {nest(`{"Results":[{"Vulnerabilities":[{"Severity":"LOW","Z":`, `}]}]}`, "[", "]", 508), false},
		"closed brackets don't add up":      {`{"X":[` + strings.TrimSuffix(strings.Repeat(`[[{"a":[]}]],`, 5000), ",") + `],"Results":[]}`, true},
		"brackets in a string":              {`{"X":"` + strings.Repeat("[{", 5000) + `","Results":[]}`, true},
		"brackets after an escaped quote":   {`{"X":"\"` + strings.Repeat("[", 5000) + `\\","Y":"\\\"` + strings.Repeat("{", 5000) + `","Results":[]}`, true},
		"brackets in a key":                 {`{"` + strings.Repeat("[", 5000) + `":1,"Results":[]}`, true},
		"brackets after a string's end":     {`{"X":"\\",` + `"Y":` + strings.Repeat("[", 600) + strings.Repeat("]", 600) + `}`, false},
		"a finding's text with brackets":    {`{"Results":[{"Vulnerabilities":[{"Severity":"LOW","Title":"` + strings.Repeat("[", 5000) + `"}]}]}`, true},
		"deep, split over many small reads": {nest(`{"X":`, `}`, "[ ", "] ", 512), false},
	} {
		// One byte per read: the count must not depend on where a read ends.
		for _, r := range []io.Reader{strings.NewReader(c.in), iotestOneByte{strings.NewReader(c.in)}} {
			rep, err := readReport("t", r, defaultLimits)
			if c.ok && err != nil {
				t.Errorf("%s: %v; want it read", name, err)
			}
			if !c.ok {
				wantReason(t, name, err, tooDeepReason)
			}
			if name == "a finding's text with brackets" && rep.Low != 1 {
				t.Errorf("%s: %+v", name, rep)
			}
		}
	}
	if r := errTooDeep().Error(); r != tooDeepReason {
		t.Errorf("depth limit text = %q", r)
	}
}

type iotestOneByte struct{ r io.Reader }

func (o iotestOneByte) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.r.Read(p[:1])
}

// The scanner is stopped at the depth limit, like at the other limits.
func TestScanReportTooDeepStopsTheScanner(t *testing.T) {
	start := time.Now()
	for name, err := range scanAll(t, `printf '{"X":'; exec yes '[[[[[[[[[[[[[[[['`, limits{}) {
		wantReason(t, name, err, tooDeepReason)
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Errorf("three endless scans took %v; the scanner must be stopped at the limit", d)
	}
}

// A number Mooring doesn't read can't fail the report, whatever its size (json.Unmarshal skipped it).
func TestScanSkippedNumbersOfAnySize(t *testing.T) {
	in := `{"X":1e400,"Y":[-1e999,` + strings.Repeat("9", 5000) + `,0.1e-400],"Metadata":{"Size":1e400,"OS":{"Family":"ubuntu","Name":"24.04","Z":1e400}},
	 "Results":[{"Target":"t","Class":"os-pkgs","N":123456789012345678901234567890,
	  "Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"a","Severity":"HIGH","FixedVersion":"2","CVSS":{"nvd":{"V3Score":1e400}}}]}]}`
	h, err := readHostReport(strings.NewReader(in), defaultLimits, nil, nil, true)
	if err != nil {
		t.Fatalf("a report with numbers outside float64: %v", err)
	}
	if h.OS != "ubuntu 24.04" || h.High != 1 || h.FixableHigh != 1 {
		t.Errorf("host = %+v", h)
	}
	if rep, err := parseReport("t", []byte(`{"X":1e400,"Results":[]}`)); err != nil || rep.Total() != 0 {
		t.Errorf(`{"X":1e400,"Results":[]}: %+v, %v`, rep, err)
	}
	// A number is still not a string, and a malformed number is still not JSON.
	_, err = parseReport("t", []byte(`{"Results":[{"Target":1e400}]}`))
	wantReason(t, "number as Target", err, "the scan report is not in the format Mooring reads")
	_, err = parseReport("t", []byte(`{"X":1e,"Results":[]}`))
	wantReason(t, "malformed number", err, "the scan report is not valid JSON")
}

// After a report that can't be used for another reason than a limit, the rest of the scanner's output
// is read and dropped only up to the report limit; then the scanner is stopped instead of being left
// to write until the scan timeout.
func TestScanDiscardIsBoundedByTheReportLimit(t *testing.T) {
	sc := New(fakeDocker(t, `exec yes '{"a":1},'`), "", 5*time.Minute)
	sc.lim = limits{report: 1 << 20, entry: 64 << 10, kept: 1 << 20}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	start := time.Now()
	_, err := sc.ScanImage(ctx, "nginx:1")
	wantReason(t, "endless output after a syntax error", err, "the scan report is not valid JSON")
	if d := time.Since(start); d > 6*time.Second {
		t.Errorf("took %v; the scanner must be stopped once the report limit is used up", d)
	}

	// Output that ends exactly on the limit is not a stop: the scanner's own failure is reported.
	const size = 256 << 10
	sc = New(fakeDocker(t, fmt.Sprintf(`head -c %d /dev/zero | tr '\0' x; echo "FATAL db download failed" >&2; exit 3`, size)), "", 5*time.Minute)
	sc.lim = limits{report: size, entry: 64 << 10, kept: 1 << 20}
	_, err = sc.ScanImage(context.Background(), "nginx:1")
	if err == nil || !strings.Contains(err.Error(), "trivy scan failed: exit status 3: FATAL db download failed") {
		t.Errorf("output of exactly the limit, then exit 3: err = %v; want the exit status and stderr", err)
	}
	// One byte more is.
	sc.lim.report = size - 1
	_, err = sc.ScanImage(context.Background(), "nginx:1")
	wantReason(t, "one byte over", err, "the scan report is not valid JSON")
}

// A stopped scanner gets SIGTERM, which `docker run` passes on to the container (a killed docker CLI
// passes nothing on); the limit path and the timeout path stop it the same way. A CLI that ignores
// SIGTERM is killed after the grace.
func TestScanStopIsSIGTERMThenKill(t *testing.T) {
	small := limits{report: 1 << 20, entry: 64 << 10, kept: 1 << 20}
	marker := func() string { return filepath.Join(t.TempDir(), "got-term") }
	gotTERM := func(name, m string) {
		t.Helper()
		if b, err := os.ReadFile(m); err != nil || strings.TrimSpace(string(b)) != "term" {
			t.Errorf("%s: the scanner was not stopped with SIGTERM (marker: %q, %v)", name, b, err)
		}
	}

	m := marker()
	sc := New(fakeDocker(t, `trap 'echo term > "`+m+`"; kill $!; exit 0' TERM
printf '{"X":['
yes '1,' &
wait`), "", 5*time.Minute)
	sc.lim = small
	start := time.Now()
	_, err := sc.ScanImage(context.Background(), "nginx:1")
	wantReason(t, "limit", err, "the scan report is larger than 1 MiB")
	gotTERM("limit", m)
	if d := time.Since(start); d > 8*time.Second {
		t.Errorf("limit: took %v; a scanner that exits on SIGTERM is not waited for longer", d)
	}

	// The timeout and shutdown path: the context ends while the scanner is running (once its trap is
	// set, which a new executable can take a while to reach).
	m = marker()
	ready := filepath.Join(t.TempDir(), "ready")
	sc = New(fakeDocker(t, `trap 'echo term > "`+m+`"; kill $!; exit 0' TERM
sleep 60 &
: > "`+ready+`"
wait`), "", 5*time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if _, err := os.Stat(ready); err == nil {
				break
			}
		}
		cancel()
	}()
	if _, err := sc.ScanImage(ctx, "nginx:1"); err == nil {
		t.Error("context ended: want an error")
	}
	gotTERM("context ended", m)

	// SIGTERM ignored (and inherited by yes): killed after the grace, and Wait returns.
	sc = New(fakeDocker(t, `trap '' TERM
printf '{"X":['
exec yes '1,'`), "", 5*time.Minute)
	sc.lim = small
	sc.grace = 400 * time.Millisecond
	start = time.Now()
	_, err = sc.ScanImage(context.Background(), "nginx:1")
	wantReason(t, "ignores SIGTERM", err, "the scan report is larger than 1 MiB")
	if d := time.Since(start); d < 400*time.Millisecond || d > 8*time.Second {
		t.Errorf("ignores SIGTERM: took %v; want the kill after the 400ms grace", d)
	}
	if New("docker", "", time.Minute).grace != 0 || stopGrace != 10*time.Second {
		t.Error("the default grace is 10s")
	}
}

// Decided behaviour that differs from the json.Unmarshal the decoder replaced. Not bugs: see the
// Intentional comments in trivyDecoder.report.
func TestDecodeTrivyDecidedBehaviour(t *testing.T) {
	finding := func(id, sev string) string {
		return `{"VulnerabilityID":"` + id + `","PkgName":"p","Severity":"` + sev + `","FixedVersion":"1"}`
	}
	// The keys of the walk match in exact case; another case is an unknown key.
	lower := `{"metadata":{"OS":{"Family":"ubuntu","Name":"1"}},"Metadata":{"os":{"Family":"debian","Name":"2"}},
	 "results":[{"Target":"a","Class":"os-pkgs","Vulnerabilities":[` + finding("CVE-1", "HIGH") + `]}],
	 "Results":[{"target":"usr/bin/caddy","class":"lang-pkgs","vulnerabilities":[` + finding("CVE-2", "CRITICAL") + `],
	             "Target":"b","Class":"os-pkgs","Vulnerabilities":[` + finding("CVE-3", "LOW") + `]}]}`
	h, err := readHostReport(strings.NewReader(lower), defaultLimits, nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if h.OS != "" || h.Total() != 1 || h.Low != 1 || len(h.Reports) != 1 {
		t.Errorf("keys in another case must be skipped: %+v", h)
	}
	// Inside one finding the fields still match as encoding/json matches them.
	rep, err := parseReport("t", []byte(`{"Results":[{"Vulnerabilities":[{"vulnerabilityid":"CVE-1","SEVERITY":"HIGH"}]}]}`))
	if err != nil || rep.High != 1 || rep.Top[0].ID != "CVE-1" {
		t.Errorf("a finding's fields: %+v, %v", rep, err)
	}

	// A top-level null is refused, not read as an empty (clean) report.
	for _, in := range []string{`null`, " null\n"} {
		_, err := readHostReport(strings.NewReader(in), defaultLimits, nil, nil, true)
		wantReason(t, "host "+in, err, "the scan report is not in the format Mooring reads")
		_, err = parseReport("t", []byte(in))
		wantReason(t, "image "+in, err, "the scan report is not in the format Mooring reads")
	}

	// A repeated Results key, and a repeated Vulnerabilities key in one result, add up.
	for name, in := range map[string]string{
		"Results": `{"Results":[{"Target":"a","Class":"os-pkgs","Vulnerabilities":[` + finding("CVE-1", "HIGH") + `]}],
		            "Results":[{"Target":"b","Class":"os-pkgs","Vulnerabilities":[` + finding("CVE-9", "LOW") + `]}]}`,
		"Vulnerabilities": `{"Results":[{"Target":"a","Class":"os-pkgs","Vulnerabilities":[` + finding("CVE-1", "HIGH") + `],
		                    "Vulnerabilities":[` + finding("CVE-9", "LOW") + `]}]}`,
	} {
		rep, err := parseReport("t", []byte(in))
		if err != nil || rep.High != 1 || rep.Low != 1 || len(rep.Top) != 2 || rep.Top[0].ID != "CVE-1" || rep.Top[1].ID != "CVE-9" {
			t.Errorf("repeated %s: %+v, %v; want both counted", name, rep, err)
		}
		if _, ok := rep.fixableHC["CVE-1|p"]; !ok {
			t.Errorf("repeated %s: the first one's fixable High must still alert: %v", name, rep.fixableHC)
		}
	}
}

// An app target whose report can't be used shows why next to the app, as the host scan does, and
// logs it at Warn; a scanner that failed keeps the text without a reason.
func TestRunnerAppScanFailureNamesTheReason(t *testing.T) {
	_, tooDeep := parseReport("t", []byte(`{"X":`+strings.Repeat("[", 600)))
	_, noOutput := parseReport("t", nil)
	scanner := errors.New("trivy scan failed: exit status 1: FATAL secret stderr text")
	for name, c := range map[string]struct {
		errs    map[string]error
		want    string
		logged  string
		quietly string
	}{
		"a report over a limit":         {map[string]error{"a:1": tooDeep}, "one or more targets could not be scanned: " + tooDeepReason, tooDeepReason, ""},
		"no output":                     {map[string]error{"b:1": noOutput}, "one or more targets could not be scanned: the scanner returned no output", "the scanner returned no output", ""},
		"the scanner failed":            {map[string]error{"a:1": scanner}, "one or more targets could not be scanned", "", "FATAL"},
		"a reason replaces no reason":   {map[string]error{"a:1": scanner, "b:1": tooDeep}, "one or more targets could not be scanned: " + tooDeepReason, tooDeepReason, "FATAL"},
		"the first reason wins":         {map[string]error{"a:1": noOutput, "b:1": tooDeep}, "one or more targets could not be scanned: the scanner returned no output", tooDeepReason, ""},
		"a wrapped report error counts": {map[string]error{"a:1": fmt.Errorf("scan: %w", tooDeep)}, "one or more targets could not be scanned: " + tooDeepReason, tooDeepReason, ""},
		"no failure":                    {nil, "", "", ""},
	} {
		sc := &fakeScanner{img: map[string]Report{"c:1": {Target: "c:1", High: 2}}, imgErr: c.errs}
		st := NewStore(testDB(t))
		var log bytes.Buffer
		targets := func(context.Context) []Target {
			return []Target{
				{Project: "shop", Kind: KindImage, Ref: "a:1", Label: "a:1"},
				{Project: "shop", Kind: KindImage, Ref: "b:1", Label: "b:1"},
				{Project: "shop", Kind: KindImage, Ref: "c:1", Label: "c:1"},
			}
		}
		NewRunner(sc, st, nil, targets, 0, slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelWarn}))).ScanAll(context.Background())
		got, ok, err := st.Get(context.Background(), "shop")
		if err != nil || !ok {
			t.Fatalf("%s: get: %v ok=%v", name, err, ok)
		}
		if got.Error != c.want {
			t.Errorf("%s: stored error = %q; want %q", name, got.Error, c.want)
		}
		if got.High != 2 {
			t.Errorf("%s: the targets that were scanned still count: %+v", name, got)
		}
		if c.logged != "" && !(strings.Contains(log.String(), "level=WARN") && strings.Contains(log.String(), c.logged) && strings.Contains(log.String(), "project=shop")) {
			t.Errorf("%s: the reason must be logged at Warn: %q", name, log.String())
		}
		if c.logged == "" && log.Len() != 0 {
			t.Errorf("%s: nothing to log at Warn: %q", name, log.String())
		}
		if c.quietly != "" && strings.Contains(log.String(), c.quietly) {
			t.Errorf("%s: a failed scanner stays at Debug: %q", name, log.String())
		}
		if strings.Contains(got.Error, "FATAL") || strings.Contains(got.Error, "stderr") {
			t.Errorf("%s: the scanner's stderr must not reach the page: %q", name, got.Error)
		}
	}
}
