package yamldiag

import (
	"errors"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// parseRoot parses the first document (the one the decoders read) and returns its top node, nil for
// an empty file.
func parseRoot(raw []byte) (root *yaml.Node, err error) {
	defer func() {
		if recover() != nil {
			root, err = nil, errors.New("yaml: the file could not be parsed")
		}
	}()
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0], nil
	}
	return nil, nil
}

func newIndex(raw []byte) (*Index, error) {
	if len(raw) > MaxInput {
		return nil, errors.New("yaml: the file is too large to examine")
	}
	root, err := parseRoot(raw)
	if err != nil {
		return nil, err
	}
	return &Index{root: root}, nil
}

func deref(n *yaml.Node) *yaml.Node {
	for i := 0; n != nil && n.Kind == yaml.AliasNode && i < 8; i++ {
		n = n.Alias
	}
	return n
}

func child(m *yaml.Node, rest string) (k, v *yaml.Node) {
	// Intentional: the longest key that is a prefix of the path wins, so a key that itself contains
	// dots ("example.com") is found.
	for i := 0; i+1 < len(m.Content); i += 2 {
		name := m.Content[i].Value
		if name == "" || !strings.HasPrefix(rest, name) || (k != nil && len(name) <= len(k.Value)) {
			continue
		}
		if len(rest) == len(name) || rest[len(name)] == '.' || rest[len(name)] == '[' {
			k, v = m.Content[i], m.Content[i+1]
		}
	}
	return k, v
}

// lookup follows path; ok is false when it stops early, and key/val are then the nearest parent.
func (ix *Index) lookup(path string) (key, val *yaml.Node, ok bool) {
	if ix == nil || ix.root == nil {
		return nil, nil, false
	}
	val = ix.root
	rest := path
	for depth := 0; rest != ""; depth++ {
		cur := deref(val)
		if cur == nil || depth > maxDepth {
			return key, val, false
		}
		if rest[0] == '[' {
			end := strings.IndexByte(rest, ']')
			if end < 0 || cur.Kind != yaml.SequenceNode {
				return key, val, false
			}
			i, err := strconv.Atoi(rest[1:end])
			if err != nil || i < 0 || i >= len(cur.Content) {
				return key, val, false
			}
			key, val, rest = nil, cur.Content[i], rest[end+1:]
		} else {
			if cur.Kind != yaml.MappingNode {
				return key, val, false
			}
			k, v := child(cur, rest)
			if k == nil { // a key that comes from a merge (<<: *anchor)
				for i := 0; i+1 < len(cur.Content) && k == nil; i += 2 {
					if m := deref(cur.Content[i+1]); cur.Content[i].Value == "<<" && m != nil && m.Kind == yaml.MappingNode {
						k, v = child(m, rest)
					}
				}
			}
			if k == nil {
				return key, val, false
			}
			key, val, rest = k, v, rest[len(k.Value):]
		}
		rest = strings.TrimPrefix(rest, ".")
	}
	return key, val, true
}

func (ix *Index) pos(path string) (Pos, bool) {
	key, val, ok := ix.lookup(path)
	return posOf(key, val), ok
}
