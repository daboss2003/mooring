package imagescan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// limits bound one scan report. Trivy's output is hostile input (package names and versions come from
// the scanned image) and can be very large on an honest host too: every installed kernel package
// carries each open kernel CVE with its description and reference list. The report is therefore
// decoded as a stream and never held whole; these are the three things that stay bounded.
type limits struct {
	report int64 // bytes of JSON read from the scanner
	entry  int64 // bytes of one JSON value held at once (one finding, one string)
	kept   int64 // bytes of findings and identities kept while aggregating
}

// defaultLimits: the report cap only bounds the time spent reading (the decode holds one entry at a
// time); memory is bounded by entry (the decoder's buffer, which can reach twice that) plus kept,
// plus the decoder's state per open bracket, which maxDepth bounds.
var defaultLimits = limits{report: 1 << 30, entry: 4 << 20, kept: 32 << 20}

// maxDepth is how many objects and arrays may be open at once anywhere in a report (the report
// object itself is level 1). json.Decoder.Token keeps state for every open bracket and has no limit
// of its own, and an opening bracket is a complete token, so the entry limit never sees a run of
// them. Trivy's reports nest about ten levels.
const maxDepth = 512

// outputError is a scan that ran but whose report can't be used. reason is fixed text that is safe to
// show on the Server tab (it never quotes the scanner's output); cause is for the log only.
type outputError struct {
	reason string
	cause  error
	limit  bool // a limit was passed: the scanner is still writing and must be stopped
}

func (e *outputError) Error() string {
	if e.cause != nil {
		return e.reason + ": " + e.cause.Error()
	}
	return e.reason
}

func (e *outputError) Unwrap() error { return e.cause }

func mib(n int64) int64 { return n >> 20 }

var errNoOutput = &outputError{reason: "the scanner returned no output"}

func errReportTooLarge(lim limits) error {
	return &outputError{reason: fmt.Sprintf("the scan report is larger than %d MiB", mib(lim.report)), limit: true}
}

func errEntryTooLarge(lim limits) error {
	return &outputError{reason: fmt.Sprintf("one entry of the scan report is larger than %d MiB", mib(lim.entry)), limit: true}
}

func errTooDeep() error {
	return &outputError{reason: fmt.Sprintf("the scan report is nested deeper than %d levels", maxDepth), limit: true}
}

func errTooManyFindings(limit int64) error {
	return &outputError{reason: fmt.Sprintf("the scan report has more findings than Mooring keeps (%d MiB)", mib(limit)), limit: true}
}

// budget is the kept-bytes allowance of one scan, shared by its reportBuilders. A nil budget is unlimited.
type budget struct{ left, limit int64 }

func newBudget(lim limits) *budget { return &budget{left: lim.kept, limit: lim.kept} }

func (b *budget) take(n int64) error {
	if b == nil {
		return nil
	}
	b.left -= n
	if b.left < 0 {
		return errTooManyFindings(b.limit)
	}
	return nil
}

func (b *budget) give(n int64) {
	if b != nil {
		b.left += n
	}
}

// reportReader enforces the report, entry and depth limits on the bytes the JSON decoder reads, so a
// limit holds however the decoder goes on to read them (the structured walk, a skipped value, a
// finding decoded whole).
type reportReader struct {
	r        io.Reader
	lim      limits
	n        int64        // bytes handed to the decoder
	consumed func() int64 // the decoder's InputOffset: bytes of complete values it is done with
	err      error        // the limit that was passed (sticky)
	readErr  error        // the source's own read error, other than io.EOF

	depth    int  // objects and arrays open in the bytes read so far
	inString bool // the bytes read so far end inside a JSON string
	escaped  bool // ... right after a backslash
}

func (g *reportReader) Read(p []byte) (int, error) {
	if g.err != nil {
		return 0, g.err
	}
	// The decoder only reads more when the value it is scanning is not complete, so every byte it
	// has not consumed belongs to that one value.
	if g.n-g.consumed() > g.lim.entry {
		g.err = errEntryTooLarge(g.lim)
		return 0, g.err
	}
	if room := g.lim.report + 1 - g.n; int64(len(p)) > room {
		p = p[:room]
	}
	k, err := g.r.Read(p)
	g.n += int64(k)
	if g.n > g.lim.report {
		g.err = errReportTooLarge(g.lim)
		return 0, g.err
	}
	if g.tooDeep(p[:k]) {
		// The decoder never sees these bytes, so it allocates nothing for the brackets in them.
		g.err = errTooDeep()
		return 0, g.err
	}
	if err != nil && err != io.EOF {
		g.readErr = err
	}
	return k, err
}

// tooDeep counts the brackets in p that are outside JSON strings and reports whether more than
// maxDepth are open at once. The count is exact for valid JSON; in anything else it only decides
// which of two refusals the report gets.
func (g *reportReader) tooDeep(p []byte) bool {
	for _, c := range p {
		switch {
		case g.escaped:
			g.escaped = false
		case g.inString:
			switch c {
			case '\\':
				g.escaped = true
			case '"':
				g.inString = false
			}
		case c == '"':
			g.inString = true
		case c == '{', c == '[':
			if g.depth++; g.depth > maxDepth {
				return true
			}
		case c == '}', c == ']':
			if g.depth > 0 {
				g.depth--
			}
		}
	}
	return false
}

// errShape is a report that is JSON but not laid out as a Trivy report.
var errShape = errors.New("a value has an unexpected JSON type")

// trivyDecoder walks one Trivy JSON report token by token, decoding only the values Mooring reads and
// skipping the rest without holding them.
type trivyDecoder struct {
	dec  *json.Decoder
	kept *budget
}

// decodeTrivy reads one Trivy JSON report from r and calls result for each entry of Results once its
// findings are aggregated. It returns Metadata.OS (nil when absent). Every failure to get a usable
// report is an *outputError, except a read error of r itself.
func decodeTrivy(r io.Reader, lim limits, kept *budget, result func(trivyResult) error) (*trivyOS, error) {
	in := &reportReader{r: r, lim: lim}
	dec := json.NewDecoder(in)
	// Token would otherwise convert every number to a float64 and fail the report on one outside its
	// range (1e400), also in a value Mooring skips. No number of a report is read.
	dec.UseNumber()
	in.consumed = dec.InputOffset
	d := &trivyDecoder{dec: dec, kept: kept}

	first, err := dec.Token()
	if err == io.EOF && in.err == nil && in.readErr == nil {
		return nil, errNoOutput
	}
	var osInfo *trivyOS
	if err == nil {
		err = d.report(first, &osInfo, result)
	}
	if err == nil {
		// Like json.Unmarshal: nothing but white space may follow the report.
		if _, terr := dec.Token(); terr == nil {
			err = &json.SyntaxError{Offset: dec.InputOffset()}
		} else if terr != io.EOF {
			err = terr
		}
	}
	if err == nil {
		return osInfo, nil
	}
	var oe *outputError
	var syn *json.SyntaxError
	switch {
	case in.err != nil:
		return nil, in.err
	case errors.As(err, &oe):
		return nil, err
	case in.readErr != nil:
		return nil, fmt.Errorf("reading the scan report: %w", in.readErr)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return nil, &outputError{reason: "the scan report is incomplete", cause: fmt.Errorf("it ends after %d bytes", in.n)}
	case errors.As(err, &syn):
		return nil, &outputError{reason: "the scan report is not valid JSON", cause: fmt.Errorf("at byte %d", syn.Offset)}
	default:
		return nil, &outputError{reason: "the scan report is not in the format Mooring reads", cause: fmt.Errorf("near byte %d: %w", dec.InputOffset(), err)}
	}
}

func (d *trivyDecoder) report(first json.Token, osInfo **trivyOS, result func(trivyResult) error) error {
	// Intentional: a top-level null is refused (json.Unmarshal took it for an empty report). A scan
	// that printed "null" found nothing out, and an empty report would show the target as clean.
	if first != json.Delim('{') {
		return errShape
	}
	// Intentional: the keys the walk reads (Metadata, OS, Results, Target, Class, Vulnerabilities)
	// match in exact case, as Trivy writes them; json.Unmarshal also took "results". A key in
	// another case is skipped like any unknown key.
	return d.fields(func(key string) error {
		switch key {
		case "Metadata":
			return d.object(func(key string) error {
				if key != "OS" {
					return d.skip()
				}
				return d.dec.Decode(osInfo)
			})
		case "Results":
			// Intentional: a repeated Results key (and a repeated Vulnerabilities key in one
			// result) adds its entries to the earlier ones; json.Unmarshal kept only the last.
			// Trivy writes each key once, and counting everything can't hide a finding.
			return d.array(func() error {
				res, err := d.result()
				if err != nil {
					return err
				}
				return result(res)
			})
		}
		return d.skip()
	})
}

func (d *trivyDecoder) result() (trivyResult, error) {
	res := trivyResult{vulns: newReportBuilder(d.kept)}
	err := d.object(func(key string) error {
		switch key {
		case "Target":
			return d.dec.Decode(&res.Target)
		case "Class":
			return d.dec.Decode(&res.Class)
		case "Vulnerabilities":
			return d.array(func() error {
				var v trivyVuln
				if err := d.dec.Decode(&v); err != nil {
					return err
				}
				return res.vulns.add(v)
			})
		}
		return d.skip()
	})
	if err != nil {
		return res, err
	}
	// A result with no findings still costs its entry in the caller's aggregation.
	return res, d.kept.take(keyCost(res.Target) + keyCost(res.Class) + 256)
}

// open reads the start of an object or array value; false for a JSON null.
func (d *trivyDecoder) open(delim json.Delim) (bool, error) {
	t, err := d.dec.Token()
	if err != nil {
		return false, err
	}
	switch t {
	case nil:
		return false, nil
	case delim:
		return true, nil
	}
	return false, errShape
}

// object calls field for each key of the next value, an object or null; field reads the key's value.
func (d *trivyDecoder) object(field func(key string) error) error {
	if ok, err := d.open('{'); err != nil || !ok {
		return err
	}
	return d.fields(field)
}

// fields is object after the opening brace.
func (d *trivyDecoder) fields(field func(key string) error) error {
	for d.dec.More() {
		t, err := d.dec.Token()
		if err != nil {
			return err
		}
		key, ok := t.(string)
		if !ok {
			return errShape
		}
		if err := field(key); err != nil {
			return err
		}
	}
	_, err := d.dec.Token()
	return err
}

// array calls elem for each element of the next value, an array or null; elem reads the element.
func (d *trivyDecoder) array(elem func() error) error {
	if ok, err := d.open('['); err != nil || !ok {
		return err
	}
	for d.dec.More() {
		if err := elem(); err != nil {
			return err
		}
	}
	_, err := d.dec.Token()
	return err
}

// skip reads past the next value one token at a time, so a large value Mooring doesn't read (a
// package list, an image config) is never held.
func (d *trivyDecoder) skip() error {
	for depth := 0; ; {
		t, err := d.dec.Token()
		if err != nil {
			return err
		}
		if delim, ok := t.(json.Delim); ok {
			if delim == '{' || delim == '[' {
				depth++
			} else {
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}
