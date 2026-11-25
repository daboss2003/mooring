// Package yamldiag explains why a YAML file (config.yaml, mooring.yaml) was refused: the real line
// and column, the line itself with a caret, a plain message and a hint. It runs ONLY after the
// file's own strict decode or validation has already failed, and only adds detail: it can never
// turn a refusal into an acceptance, and a file it finds nothing wrong with is still refused with
// the decoder's own message. Standard library and yaml.v3 only.
//
// The exported names, types and signatures are a frozen contract (internal/config and
// internal/definition are written against them).
//
// Three passes, each only when the one before found nothing: a line scanner (scan.go) for the
// mistakes the parser reports on the wrong line, the parser's own message in plain words
// (explain.go), and for a file that parses a walk of its nodes against the target type's yaml tags
// (walk.go).
package yamldiag

import (
	"reflect"

	"gopkg.in/yaml.v3"
)

// Problem kinds.
const (
	KindSyntax     = "syntax"      // the file is not valid YAML (indentation, a tab, a missing space after ':', an unclosed quote …)
	KindUnknownKey = "unknown_key" // a key the file's schema doesn't have
	KindDuplicate  = "duplicate"   // a key written twice in one mapping
	KindType       = "type"        // a value of the wrong type (a quoted boolean, a list where a mapping belongs …)
	KindSemantic   = "semantic"    // a value the file's validation refuses
)

// Limits.
const (
	MaxProblems = 20      // problems kept per file (the rest are counted in Diagnostics.More)
	MaxExcerpt  = 200     // bytes of a line shown
	MaxInput    = 1 << 20 // bytes examined (a longer file gets the decoder's own message only)
)

// Pos is a position in the file: 1-based line and column (0, 0: unknown).
type Pos struct {
	Line int `json:"line,omitempty"`
	Col  int `json:"col,omitempty"`
}

// Problem is one thing wrong with the file.
type Problem struct {
	Pos
	Kind string `json:"kind"`
	// Path is the key path the problem is about ("edge.base_domains[0].domain"), "" when it has none
	// (a syntax error).
	Path string `json:"path,omitempty"`
	Msg  string `json:"msg"`            // one sentence, no trailing period, no Go type names
	Hint string `json:"hint,omitempty"` // what to change ("remove the quotes", "did you mean edge?")
	// Excerpt is the offending line as shown (control characters removed, cut to MaxExcerpt, with
	// Options.RedactValues the value replaced by "…"); "" when the position is unknown.
	Excerpt string `json:"excerpt,omitempty"`

	prev  string // the line before, as shown by Terminal
	shown bool   // Excerpt comes from the file (it may be an empty line)
	caret int    // the caret's column under Excerpt as displayed (0: none)
	merge bool   // about a merge (<<): Path is the block that merges, not a key of it
}

// Diagnostics is what is wrong with one file. It is an error: Error() is ONE line, so existing
// wrappers, logs and HTTP error bodies stay single-line.
type Diagnostics struct {
	File     string    `json:"file"` // the path or name shown ("/etc/mooring/config.yaml", "mooring.yaml")
	Problems []Problem `json:"problems"`
	More     int       `json:"more,omitempty"` // problems beyond MaxProblems
	// Cause is the error the file was refused with (the strict decode's or the validation's); Unwrap
	// returns it, so errors.Is / errors.As against it keep working.
	Cause error `json:"-"`

	redact bool // Options.RedactValues: Cause's message is shown without the values yaml quotes in it
}

// Error is the one-line form: "<file>:<line>:<col>: <msg> (hint: <hint>); N more problems". With no
// problems it is Cause's own message prefixed by the file.
func (d *Diagnostics) Error() string { return d.errorLine() }

func (d *Diagnostics) Unwrap() error {
	if d == nil {
		return nil
	}
	return d.Cause
}

// Terminal is the multi-line form for a terminal: each problem as "<file>:<line>:<col>: <msg>", the
// line before, the line with a caret under the column, and "hint: …". No colour codes.
func (d *Diagnostics) Terminal() string { return d.terminal() }

// JSON is Diagnostics as JSON (the fields tagged above).
func (d *Diagnostics) JSON() []byte { return d.json() }

// Options says how a file is explained.
type Options struct {
	File string // shown in messages
	// RedactValues: nothing the file holds as a value is printed (config.yaml holds the encryption
	// key, password hashes and tokens, and its errors reach the journal). There is no exception: an
	// excerpt shows the indentation, the key and "…"; a message never quotes a value it found; a key
	// is named only when it is a key of the schema, spelled as the schema spells it (any other may be
	// a secret typed where a key belongs; one close to a schema key gets that key as its hint); the
	// decoder's own text is shown without what it copied from the file.
	// The messages a caller passes to Semantic are printed as given: they must be value-free too.
	RedactValues bool
	// Schema is the type the file decodes into, for Semantic (Explain is given it as target). Under
	// RedactValues, Semantic names the schema's keys in its excerpts; without it, only the keys of
	// the problem's own path.
	Schema reflect.Type
}

// Explain examines raw after it was refused with cause (the strict decode's error, or nil when only
// validation refused it) and returns what it found. target is the type the file decodes into (its
// yaml struct tags name the keys). It never returns nil: with nothing found, the result has no
// problems and its Error() is cause's message. Bounded work; never panics on hostile input.
func Explain(raw []byte, target reflect.Type, cause error, o Options) *Diagnostics {
	return explain(raw, target, cause, o)
}

// Index finds the position of a key path in a file that parses as YAML.
type Index struct{ root *yaml.Node }

// NewIndex parses raw; an error means the file isn't valid YAML (positions are then unknown).
func NewIndex(raw []byte) (*Index, error) { return newIndex(raw) }

// Pos is the position of the VALUE at path ("edge.acme_email", "users[1].role"), or of the key when
// the value is a mapping or a list; false when the path isn't in the file (the position of its
// nearest existing parent is returned then).
func (ix *Index) Pos(path string) (Pos, bool) { return ix.pos(path) }

// Has reports whether path is written in the file (also with an empty or zero value).
func (ix *Index) Has(path string) bool {
	_, _, ok := ix.lookup(path)
	return ok
}

// Semantic adds validation problems (each with a Path and a Msg, Kind KindSemantic) to d, filling
// their positions and excerpts from raw; a path that isn't in the file gets its nearest parent's
// position. cause becomes d.Cause when d has none.
func (d *Diagnostics) Semantic(raw []byte, problems []Problem, cause error, o Options) {
	d.semantic(raw, problems, cause, o)
}

// Suggest is the candidate closest to key when it is close enough to be a likely typo ("" when none
// is).
func Suggest(key string, candidates []string) string { return suggest(key, candidates) }
