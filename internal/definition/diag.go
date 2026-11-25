package definition

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/daboss2003/mooring/internal/yamldiag"
	"gopkg.in/yaml.v3"
)

// Readable definition errors (v0.34.0).
//
// What Parse, ParseNamed, ParseHost and ParseStored accept and refuse is decided by hardenAndDecode
// and the validate methods alone, exactly as before. This file only runs after one of them has
// refused the file, and turns that refusal into a *yamldiag.Diagnostics (file, line, column, the
// line itself, a hint). The refusal's own text is kept: Error() stays one line and still carries it.

// decodeError is a refusal by the YAML parser or the strict decode. Its text is the same as the
// fmt.Errorf(prefix+"%w") it replaces.
type decodeError struct {
	prefix string // "invalid YAML: ", "definition rejected (unknown or mistyped field): "
	err    error
}

func (e *decodeError) Error() string { return e.prefix + e.err.Error() }
func (e *decodeError) Unwrap() error { return e.err }

// hardenError is a refusal by harden(), with the position of the node it is about.
type hardenError struct {
	msg       string
	kind      string
	line, col int
}

func (e *hardenError) Error() string { return e.msg }

func refusedAt(n *yaml.Node, kind, format string, a ...any) error {
	return &hardenError{msg: fmt.Sprintf(format, a...), kind: kind, line: n.Line, col: n.Column}
}

// fieldError is a validation error that knows which key it is about ("spec.edge.routes[0].lb").
// Its text is the wrapped error's.
type fieldError struct {
	path string
	err  error
}

func (e *fieldError) Error() string { return e.err.Error() }
func (e *fieldError) Unwrap() error { return e.err }

// at says which key err is about. An error that already names a key keeps it (the inner one is the
// more exact), and nil stays nil.
func at(path string, err error) error {
	if err == nil || path == "" {
		return err
	}
	var fe *fieldError
	if errors.As(err, &fe) {
		return err
	}
	return &fieldError{path: path, err: err}
}

// atf is fmt.Errorf for a validation error about the key at path.
func atf(path, format string, a ...any) error {
	return &fieldError{path: path, err: fmt.Errorf(format, a...)}
}

// servicePath is the key path of a service in the file.
func servicePath(name string) string { return "spec.compose.services." + name }

// explainRefusal turns the refusal err of the file raw into the error the parser returns. The
// verdict is already made: this only adds the position and the offending line.
func explainRefusal(raw []byte, file string, target reflect.Type, err error) (out error) {
	// Intentional: a panic while explaining is swallowed and the plain refusal returned — the file
	// is refused either way, and a bug in the explanation must not hide why.
	defer func() {
		if recover() != nil {
			out = err
		}
	}()
	// Intentional: values are shown (RedactValues off) — a definition holds secret NAMES only, and
	// the operator needs to see the line they wrote.
	o := yamldiag.Options{File: file}
	var de *decodeError
	if errors.As(err, &de) {
		d := yamldiag.Explain(raw, target, de.err, o)
		if d == nil {
			return err
		}
		return fmt.Errorf("%s%w", de.prefix, d)
	}
	p := yamldiag.Problem{Kind: yamldiag.KindSemantic, Msg: err.Error()}
	var he *hardenError
	var fe *fieldError
	switch {
	case errors.As(err, &he):
		p.Kind, p.Pos = he.kind, yamldiag.Pos{Line: he.line, Col: he.col}
	case errors.As(err, &fe):
		p.Path = fe.path
	}
	if p.Line == 0 && p.Path == "" {
		// Nothing to look up, so the file is not parsed again: the size cap in hardenAndDecode
		// refuses a file BEFORE it is parsed, and explaining that must not parse it either.
		raw = nil
	}
	d := &yamldiag.Diagnostics{File: file}
	d.Semantic(raw, []yamldiag.Problem{p}, err, o)
	return d
}

// storedRefusal is the refusal of a stored canonical: the same text, with no position.
func storedRefusal(err error) error {
	return &yamldiag.Diagnostics{File: "stored definition", Cause: err}
}
