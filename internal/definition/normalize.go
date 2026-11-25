package definition

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/daboss2003/mooring/internal/yamldiag"
	"gopkg.in/yaml.v3"
)

// maxDefBytes caps a definition file (a decode-bomb defence; a real def is small).
const maxDefBytes = 512 << 10

// Parse turns mooring.yaml bytes into a validated, typed App Definition. It is the
// parser-differential-resistant chokepoint (plan §7.7):
//   - reject YAML anchors, aliases, and merge keys (<<) — they let one parser see a
//     different document than another, smuggling a key past validation;
//   - reject duplicate keys (last-wins ambiguity);
//   - reject a SECOND YAML document;
//   - reject unknown keys (KnownFields — additionalProperties:false everywhere);
//   - reject any Tier-1 security field (the 3-tier boundary, §7.8);
//   - exact apiVersion + kind + immutable-slug shape, fail-closed.
//
// A refusal is returned as (or wrapping) a *yamldiag.Diagnostics that says where in the file it is
// (diag.go); the checks above alone decide what is accepted.
func Parse(raw []byte) (*Definition, error) { return ParseNamed(raw, "mooring.yaml") }

// ParseNamed is Parse with the file's name for its messages ("mooring.yaml",
// "mooring.staging.yaml").
func ParseNamed(raw []byte, file string) (*Definition, error) {
	var d Definition
	if err := hardenAndDecode(raw, &d); err != nil {
		return nil, explainRefusal(raw, file, reflect.TypeOf(d), err)
	}
	if err := d.validateEnvelope(); err != nil {
		return nil, explainRefusal(raw, file, reflect.TypeOf(d), err)
	}
	return &d, nil
}

// ParseStored is Parse for a canonical Mooring rendered and stored itself. A refusal names no line
// and shows no excerpt: the operator never wrote that text, so its positions would point nowhere.
func ParseStored(raw []byte) (*Definition, error) {
	var d Definition
	if err := hardenAndDecode(raw, &d); err != nil {
		return nil, storedRefusal(err)
	}
	if err := d.validateEnvelope(); err != nil {
		return nil, storedRefusal(err)
	}
	return &d, nil
}

// Kind peeks the `kind` field for dispatch (App vs Host). It is a loose read used
// ONLY to choose the typed parser — the real Parse/ParseHost then re-does the full
// hardened, parser-differential-resistant validation, so a mis-peek can't bypass it.
func Kind(raw []byte) (string, error) {
	var env struct {
		Kind string `yaml:"kind"`
	}
	if err := yaml.Unmarshal(raw, &env); err != nil {
		// Intentional: no target type — this read looks at one key only, so the file's other keys
		// are not this refusal's to judge.
		return "", explainRefusal(raw, "", nil, &decodeError{prefix: "invalid YAML: ", err: err})
	}
	return env.Kind, nil
}

// PeekMetadata leniently reads metadata.slug + metadata.name from a mooring file —
// just enough to label a multi-file repo's chooser (which file → which app). It does
// NOT validate the document; the slug it returns is re-checked by gitstore.Save (the
// real gate) before any app is created, and the full hardened Parse runs at deploy.
func PeekMetadata(raw []byte) (slug, name string) {
	var m struct {
		Metadata struct {
			Slug string `yaml:"slug"`
			Name string `yaml:"name"`
		} `yaml:"metadata"`
	}
	_ = yaml.Unmarshal(raw, &m)
	return strings.TrimSpace(m.Metadata.Slug), strings.TrimSpace(m.Metadata.Name)
}

// hardenAndDecode is the shared, type-agnostic parse pipeline for App + Host docs.
func hardenAndDecode(raw []byte, target any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return errors.New("empty definition")
	}
	if len(raw) > maxDefBytes {
		return fmt.Errorf("definition too large (%d bytes, max %d)", len(raw), maxDefBytes)
	}

	// Pass 1: parse to a Node (which PRESERVES anchors/aliases) and harden it. This
	// must run BEFORE the typed decode, which would silently resolve aliases.
	var node yaml.Node
	if err := yaml.Unmarshal(raw, &node); err != nil {
		return &decodeError{prefix: "invalid YAML: ", err: err}
	}
	if err := harden(&node); err != nil {
		return err
	}

	// Pass 2: typed decode with unknown-field rejection.
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(target); err != nil {
		return &decodeError{prefix: "definition rejected (unknown or mistyped field): ", err: err}
	}
	// A second document is not allowed (a parser-differential / smuggle vector).
	if err := dec.Decode(new(yaml.Node)); err != io.EOF {
		return errors.New("a definition must contain exactly one document")
	}
	return nil
}

// tier1Keys are the security/identity fields that live ONLY in the SSH-edited
// /etc/mooring/config.yaml (Tier 1, §7.8). They must never appear in a Tier-2 host
// or Tier-3 app definition; seeing one is a hard reject with a pointer to SSH — no
// web/CLI definition route ever touches the key/allowlist/bind (principle 4).
var tier1Keys = map[string]bool{
	"encryption_key": true, "encryption_key_previous": true,
	"ip_allowlist": true, "trusted_proxies": true, "trust_proxy": true,
	"bind_addr": true, "bind": true,
	"auth": true, "password_hash": true, "totp_secret": true, "username": true,
	"acme_email": true,
}

// harden recursively rejects the YAML constructs that enable parser-differential
// attacks (anchors, aliases, merge keys, duplicate keys) AND any Tier-1 field.
func harden(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode {
		return refusedAt(n, yamldiag.KindSyntax, "YAML aliases (*ref) are not allowed in a definition")
	}
	if n.Anchor != "" {
		return refusedAt(n, yamldiag.KindSyntax, "YAML anchors (&ref) are not allowed in a definition")
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Tag == "!!merge" || key.Value == "<<" {
				return refusedAt(key, yamldiag.KindSyntax, "YAML merge keys (<<) are not allowed in a definition")
			}
			if seen[key.Value] {
				return refusedAt(key, yamldiag.KindDuplicate, "duplicate key %q in a definition", key.Value)
			}
			seen[key.Value] = true
			if tier1Keys[key.Value] {
				return refusedAt(key, yamldiag.KindSemantic, "%q is a Tier-1 security field — it lives only in /etc/mooring/config.yaml (SSH-edit), never a host/app definition", key.Value)
			}
		}
	}
	for _, c := range n.Content {
		if err := harden(c); err != nil {
			return err
		}
	}
	return nil
}

// Canonical re-marshals a definition to canonical YAML (stable field order from the
// struct) — what is written back to canonical.yaml on every successful apply, so the
// stored form is always Mooring's typed render, never the operator's raw bytes.
func Canonical(d *Definition) ([]byte, error) { return marshalYAML(d) }

func marshalYAML(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
