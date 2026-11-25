package yamldiag

import (
	"encoding"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	maxDepth     = 100     // nesting followed by the walk and the index
	maxNodes     = 200_000 // nodes visited per file (aliases can repeat a subtree)
	maxCollected = 10 * MaxProblems
	maxTypes     = 2000 // struct visits of the search for "belongs under"
)

type obsoleteUnmarshaler interface {
	UnmarshalYAML(unmarshal func(interface{}) error) error
}

var (
	unmarshalerType     = reflect.TypeOf((*yaml.Unmarshaler)(nil)).Elem()
	obsoleteType        = reflect.TypeOf((*obsoleteUnmarshaler)(nil)).Elem()
	textUnmarshalerType = reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()
	durationType        = reflect.TypeOf(time.Duration(0))
	timeType            = reflect.TypeOf(time.Time{})
)

// opaque: the type decodes itself, so its keys and value types cannot be read from struct tags.
func opaque(t reflect.Type) bool {
	if t.Implements(unmarshalerType) || t.Implements(obsoleteType) {
		return true
	}
	if t.Kind() != reflect.Ptr {
		p := reflect.PointerTo(t)
		return p.Implements(unmarshalerType) || p.Implements(obsoleteType)
	}
	return false
}

func textual(t reflect.Type) bool {
	return t.Implements(textUnmarshalerType) || reflect.PointerTo(t).Implements(textUnmarshalerType)
}

type structInfo struct {
	fields    map[string]reflect.Type
	names     []string     // in declaration order
	inlineMap reflect.Type // element type of an inline map, nil without one
	anyKey    bool         // an inline part decodes itself: unknown keys cannot be judged
}

type walker struct {
	root   reflect.Type
	o      Options
	infos  map[reflect.Type]*structInfo
	nodes  int
	probs  []Problem
	more   int
	own    int                 // problems found by the walk itself (the rest come from the cause)
	owners map[string][]string // key → parent paths that have it, built on first use
	names  []string            // the keys of owners
	visits int                 // structs visited building owners

	// What the walk met through an alias (the decoder reports those at the ANCHOR's line, the walk at
	// the alias): fromCause uses it so a complaint is never pinned on the key the anchor is written
	// under.
	via         int                 // > 0 while walking the value of an alias
	viaPos      Pos                 // where that alias is written (the outermost one)
	viaReported map[*yaml.Node]bool // nodes the walk reported a problem about through an alias
	viaOpaque   map[*yaml.Node]site // nodes a self-decoding type reads through an alias, and where
	direct      map[*yaml.Node]bool // nodes a self-decoding type reads where they are written
}

// site is a place in the file a decoder complaint may be about.
type site struct {
	path string
	pos  Pos
}

// report adds a problem about node n.
func (w *walker) report(n *yaml.Node, p Problem) {
	if w.via > 0 {
		if w.viaReported == nil {
			w.viaReported = map[*yaml.Node]bool{}
		}
		w.viaReported[n] = true
	}
	w.add(p)
}

// through marks the walk as below an alias (or a merge of one) written at pos, until the function
// it returns is called. Every problem found meanwhile is placed at pos: the lines of the anchor are
// another key's, and may be right where they are written.
func (w *walker) through(pos Pos) func() {
	if w.via == 0 {
		w.viaPos = pos
	}
	w.via++
	return func() { w.via-- }
}

// keyPos is where a problem about key k is placed: the key, or the alias the walk reached it through.
func (w *walker) keyPos(k *yaml.Node) Pos {
	if w.via > 0 {
		return w.viaPos
	}
	return Pos{k.Line, k.Column}
}

// selfDecoding notes that the type at path decodes n itself: the walk says nothing about it, and
// the decoder's complaint (if any) carries n's own line.
func (w *walker) selfDecoding(n *yaml.Node, path string, pos Pos) {
	if w.via == 0 {
		if w.direct == nil {
			w.direct = map[*yaml.Node]bool{}
		}
		w.direct[n] = true
		return
	}
	if w.viaOpaque == nil {
		w.viaOpaque = map[*yaml.Node]site{}
	}
	if _, seen := w.viaOpaque[n]; !seen {
		w.viaOpaque[n] = site{path, pos}
	}
}

// keyName is a key written in the file as a message, a path or a hint may name it; ok is false when
// it may not be printed (RedactValues, and named refuses it: it may be a secret typed as a key).
func (w *walker) keyName(key string) (name string, ok bool) {
	if w.o.RedactValues && !w.named(key) {
		return "…", false
	}
	return key, true
}

// named reports whether a key written in the file may be printed under RedactValues: only a key of
// the schema, spelled as the schema spells it. Intentional: a key that is close to a schema key
// ("Bind_Addr", "bind_adr") or written like one ("hunter2") is not named. A short lowercase secret
// typed where a key belongs has the shape of a key and may be a letter away from one; a typo gets
// the schema's key as its hint instead (keyHint), which prints nothing from the file (owner decision
// 2026-11-25).
func (w *walker) named(key string) bool {
	if w.root == nil || key == "" {
		return false
	}
	w.schemaKeys()
	_, ok := w.owners[key]
	return ok
}

// schemaKeys fills owners and names from the target type, once.
func (w *walker) schemaKeys() {
	if w.owners != nil {
		return
	}
	w.owners = map[string][]string{}
	if w.root == nil {
		return
	}
	w.index(w.root, "", 0, map[reflect.Type]bool{})
	for k := range w.owners {
		w.names = append(w.names, k)
	}
	slices.Sort(w.names)
}

func (w *walker) add(p Problem) {
	if len(w.probs) >= maxCollected {
		w.more++
		return
	}
	p.Msg, p.Hint, p.Path = cleanText(p.Msg, maxMsg), cleanText(p.Hint, maxMsg), cleanText(p.Path, maxMsg)
	w.probs = append(w.probs, p)
}

func (w *walker) info(t reflect.Type) *structInfo {
	if si, ok := w.infos[t]; ok {
		return si
	}
	si := &structInfo{fields: map[string]reflect.Type{}}
	w.infos[t] = si
	w.collect(si, t, 0)
	return si
}

func (w *walker) collect(si *structInfo, t reflect.Type, depth int) {
	if depth > 8 {
		si.anyKey = true
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" && !f.Anonymous {
			continue
		}
		tag := f.Tag.Get("yaml")
		if tag == "" && !strings.Contains(string(f.Tag), ":") {
			tag = string(f.Tag)
		}
		if tag == "-" {
			continue
		}
		parts := strings.Split(tag, ",")
		inline := false
		for _, flag := range parts[1:] {
			inline = inline || flag == "inline"
		}
		if inline {
			ft := f.Type
			for ft.Kind() == reflect.Ptr {
				ft = ft.Elem()
			}
			switch {
			case ft.Kind() == reflect.Map:
				si.inlineMap = ft.Elem()
			case ft.Kind() == reflect.Struct && !opaque(ft):
				w.collect(si, ft, depth+1)
			default:
				si.anyKey = true
			}
			continue
		}
		name := parts[0]
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		if _, dup := si.fields[name]; !dup {
			si.names = append(si.names, name)
		}
		si.fields[name] = f.Type
	}
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func nameOf(path string) string {
	if path == "" {
		return "the file"
	}
	return path
}

func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null"
}

func found(n *yaml.Node) string {
	switch n.Kind {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a list"
	}
	switch n.ShortTag() {
	case "!!int", "!!float":
		return "a number"
	case "!!bool":
		return "true or false"
	}
	return "text"
}

// posOf is where a value is shown: the value itself, or its key when the value is a mapping or a
// list (those start on a later line).
func posOf(key, val *yaml.Node) Pos {
	if val != nil && val.Line > 0 && (key == nil || val.Kind == yaml.ScalarNode || val.Kind == yaml.AliasNode) {
		return Pos{val.Line, val.Column}
	}
	if key != nil && key.Line > 0 {
		return Pos{key.Line, key.Column}
	}
	if val != nil {
		return Pos{val.Line, val.Column}
	}
	return Pos{}
}

func (w *walker) spend() bool {
	w.nodes++
	return w.nodes <= maxNodes
}

func (w *walker) walk(key, n *yaml.Node, t reflect.Type, path string, depth int) {
	if n == nil || t == nil || depth > maxDepth || !w.spend() {
		return
	}
	pos := posOf(key, n)
	if w.via > 0 {
		pos = w.viaPos
	}
	if n.Kind == yaml.AliasNode {
		if n = n.Alias; n == nil {
			return
		}
		defer w.through(pos)()
	}
	for {
		if opaque(t) {
			w.selfDecoding(n, path, pos)
			return
		}
		if t.Kind() != reflect.Ptr {
			break
		}
		t = t.Elem()
	}
	if isNull(n) || n.Kind == yaml.AliasNode || n.Kind == yaml.DocumentNode {
		return
	}
	mismatch := func(want, hint string) {
		w.report(n, Problem{Pos: pos, Kind: KindType, Path: path, Hint: hint,
			Msg: fmt.Sprintf("%s must be %s, found %s", nameOf(path), want, found(n))})
	}
	switch t.Kind() {
	case reflect.Interface:
	case reflect.Struct:
		switch {
		case n.Kind == yaml.MappingNode:
			w.structMap(n, t, path, depth)
		case n.Kind == yaml.ScalarNode && (t == timeType || textual(t)):
		case n.Kind == yaml.ScalarNode:
			mismatch(`a mapping (indented "key: value" lines)`, gluedHint(n))
		default:
			mismatch(`a mapping (indented "key: value" lines)`, `remove the "- " and write the keys directly under it`)
		}
	case reflect.Map:
		switch n.Kind {
		case yaml.MappingNode:
			w.pairs(n, path, depth, func(k, v *yaml.Node, _ bool) {
				name, _ := w.keyName(k.Value)
				w.walk(k, v, t.Elem(), joinPath(path, name), depth+1)
			})
		case yaml.ScalarNode:
			mismatch(`a mapping (indented "key: value" lines)`, gluedHint(n))
		default:
			mismatch(`a mapping (indented "key: value" lines)`, `remove the "- " and write the keys directly under it`)
		}
	case reflect.Slice, reflect.Array:
		switch {
		case n.Kind == yaml.SequenceNode:
			for i, c := range n.Content {
				w.walk(nil, c, t.Elem(), path+"["+strconv.Itoa(i)+"]", depth+1)
			}
		case n.Kind == yaml.ScalarNode && (t.Elem().Kind() == reflect.Uint8 || textual(t)):
		case n.Kind == yaml.ScalarNode:
			mismatch(`a list (lines starting with "- ")`, `write the value as "- value" on its own line below the key, or as [value]`)
		default:
			mismatch(`a list (lines starting with "- ")`, `start each entry with "- "`)
		}
	default:
		if n.Kind != yaml.ScalarNode {
			mismatch(wantScalar(t), "")
			return
		}
		if textual(t) {
			return
		}
		w.scalar(n, t, path, pos)
	}
}

func gluedHint(n *yaml.Node) string {
	if n.Style == 0 && gluedColon(n.Value) >= 0 && !strings.ContainsAny(n.Value, " \t\n") {
		return "add a space after the ':'"
	}
	return ""
}

func wantScalar(t reflect.Type) string {
	switch {
	case t == durationType:
		return "a duration like 30s or 5m"
	case t.Kind() == reflect.Bool:
		return "true or false"
	case t.Kind() == reflect.String:
		return "a single value"
	}
	return "a number"
}

// decodes asks the decoder itself whether it takes this scalar for t, so the walk never reports a
// value the decoder accepts.
func decodes(n *yaml.Node, t reflect.Type) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = true // unsure: say nothing
		}
	}()
	plain := *n
	plain.Anchor, plain.Content, plain.Alias = "", nil, nil
	return plain.Decode(reflect.New(t).Interface()) == nil
}

func (w *walker) scalar(n *yaml.Node, t reflect.Type, path string, pos Pos) {
	if decodes(n, t) {
		return
	}
	quoted := n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0
	tag := n.ShortTag()
	name := nameOf(path)
	shown := ""
	// Intentional: with RedactValues the value found is never quoted (it may be a secret pasted on
	// the wrong line).
	if !w.o.RedactValues {
		if tag == "!!str" {
			shown = fmt.Sprintf(" (found %q)", cleanText(n.Value, 40))
		} else {
			shown = fmt.Sprintf(" (found %s)", cleanText(n.Value, 40))
		}
	}
	p := Problem{Pos: pos, Kind: KindType, Path: path}
	switch {
	case t.Kind() == reflect.Bool:
		switch strings.ToLower(n.Value) {
		case "true", "false", "yes", "no", "on", "off":
			if quoted {
				p.Msg = name + " must be true or false without quotes" + shown
				p.Hint = "remove the quotes"
				break
			}
			fallthrough
		default:
			p.Msg = name + " must be true or false" + shown
		}
	case t == durationType:
		p.Msg = name + " must be a duration like 30s or 5m" + shown
	case t.Kind() == reflect.String:
		p.Msg = name + " must be text" + shown
	default:
		_, numErr := strconv.ParseFloat(strings.TrimSpace(n.Value), 64)
		unsigned := t.Kind() >= reflect.Uint && t.Kind() <= reflect.Uintptr
		switch {
		case tag == "!!str" && quoted && numErr == nil:
			p.Msg = name + " must be a number without quotes" + shown
			p.Hint = "remove the quotes"
		case tag == "!!int" && unsigned && strings.HasPrefix(n.Value, "-"):
			p.Msg = name + " must not be negative" + shown
		case tag == "!!int" || tag == "!!float":
			p.Msg = name + " is out of range" + shown
		default:
			p.Msg = name + " must be a number" + shown
		}
	}
	w.report(n, p)
}

// isMerge is yaml's own test for a merge key.
func isMerge(k *yaml.Node) bool {
	return k.Kind == yaml.ScalarNode && k.Value == "<<" && (k.Tag == "" || k.Tag == "!" || k.ShortTag() == "!!merge")
}

// pairs visits a mapping's entries once each, reporting a key written twice, then the entries a
// merge (<<) brings in. merged tells each that the entry is not written in the block: it comes from
// an anchor merged into it.
func (w *walker) pairs(n *yaml.Node, path string, depth int, each func(k, v *yaml.Node, merged bool)) {
	w.entries(n, path, depth, nil, false, each)
}

// entries is pairs for one mapping: the block itself (taken nil) or a mapping merged into it. taken
// are the keys the block already has, as the decoder keeps them: the block's own keys win over a
// merged one, an earlier merge over a later one.
func (w *walker) entries(n *yaml.Node, path string, depth int, taken map[string]bool, merged bool, each func(k, v *yaml.Node, merged bool)) {
	if depth > maxDepth {
		return
	}
	seen := map[string]int{}
	var mergeKey, mergeVal *yaml.Node
	merges := 0
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if !w.spend() {
			return
		}
		if k.Kind != yaml.ScalarNode || isNull(k) { // the decoder skips a null key
			continue
		}
		if isMerge(k) {
			mergeKey, mergeVal = k, v
			merges++
			continue
		}
		if first, dup := seen[k.Value]; dup {
			// Intentional: a key written twice in an anchored block is not reported through the alias.
			// The two lines are the anchor's, and the decoder's own complaint (fromCause) carries them.
			if w.via == 0 {
				name, ok := w.keyName(k.Value)
				msg := fmt.Sprintf("key %q is written twice in this block (first on line %d)", cleanText(k.Value, 60), first)
				if !ok {
					msg = fmt.Sprintf("a key is written twice in this block (first on line %d)", first)
				}
				w.report(k, Problem{Pos: Pos{k.Line, k.Column}, Kind: KindDuplicate, Path: joinPath(path, name), Msg: msg, Hint: "keep one of the two"})
			}
			continue
		}
		seen[k.Value] = k.Line
		if taken != nil {
			if taken[k.Value] {
				continue
			}
			taken[k.Value] = true
		}
		each(k, v, merged)
	}
	// Intentional: with two "<<" the decoder refuses the mapping as a key written twice and merges
	// nothing; that complaint is the decoder's (fromCause).
	if merges != 1 {
		return
	}
	if taken == nil {
		taken = make(map[string]bool, len(seen))
		for k := range seen {
			taken[k] = true
		}
	}
	w.merge(mergeKey, mergeVal, path, depth, taken, merged, each)
}

// merge visits what "<<: v" brings into the block at path: a mapping, an alias of one, or a list of
// those. A mapping written in place is reported where it is written; one reached through an alias
// is reported at the "<<" (through), because its lines belong to the anchor's own key.
func (w *walker) merge(mk, mv *yaml.Node, path string, depth int, taken map[string]bool, merged bool, each func(k, v *yaml.Node, merged bool)) {
	one := func(m *yaml.Node) bool {
		if m == nil || !w.spend() {
			return false
		}
		alias := m.Kind == yaml.AliasNode
		if alias {
			if m = m.Alias; m == nil {
				return false
			}
		}
		if m.Kind != yaml.MappingNode {
			w.add(Problem{Pos: w.keyPos(mk), Kind: KindType, Path: path, merge: true,
				Msg:  "a merge (<<) takes a mapping or a list of mappings",
				Hint: `refer to the anchor of a mapping, or remove the "<<" line`})
			return false
		}
		if alias {
			defer w.through(Pos{mk.Line, mk.Column})()
		}
		w.entries(m, path, depth+1, taken, merged || alias, each)
		return true
	}
	if mv.Kind != yaml.SequenceNode {
		one(mv)
		return
	}
	for _, m := range mv.Content {
		if !one(m) {
			return
		}
	}
}

func (w *walker) structMap(n *yaml.Node, t reflect.Type, path string, depth int) {
	si := w.info(t)
	w.pairs(n, path, depth, func(k, v *yaml.Node, merged bool) {
		if ft, ok := si.fields[k.Value]; ok {
			w.walk(k, v, ft, joinPath(path, k.Value), depth+1)
			return
		}
		name, shown := w.keyName(k.Value)
		if si.inlineMap != nil {
			w.walk(k, v, si.inlineMap, joinPath(path, name), depth+1)
			return
		}
		if si.anyKey {
			return
		}
		if merged {
			// The key is right where it is written (the anchor's block); the mistake is the merge.
			msg := "unknown key "
			if shown {
				msg += fmt.Sprintf("%q ", cleanText(k.Value, 60))
			}
			into := "the top level of the file"
			if path != "" {
				into = path
			}
			w.report(k, Problem{Pos: w.keyPos(k), Kind: KindUnknownKey, Path: path, Msg: msg + "merged into " + into, merge: true,
				Hint: "the merge copies every key of the block it refers to; write the keys this block needs instead"})
			return
		}
		msg := fmt.Sprintf("unknown key %q", cleanText(k.Value, 60))
		if !shown {
			msg = "unknown key on this line"
			if w.via > 0 {
				msg = "unknown key"
			}
		}
		if path != "" {
			msg += " in " + path
		}
		if !shown && w.via > 0 { // the line shown is the alias's, not the key's
			if path != "" {
				msg += ","
			}
			msg += " in the block this line refers to"
		}
		w.report(k, Problem{Pos: w.keyPos(k), Kind: KindUnknownKey, Path: joinPath(path, name), Msg: msg, Hint: w.keyHint(k.Value, path, si)})
	})
}

func (w *walker) keyHint(key, parent string, si *structInfo) string {
	if s := Suggest(key, si.names); s != "" {
		return "did you mean " + s + "?"
	}
	if hint := w.belongs(key, parent); hint != "" {
		return hint
	}
	// The key is not named in the message (named): a key of another block written with a typo or in
	// capitals is pointed at by the schema's own spelling of it.
	if w.o.RedactValues && len(w.owners[key]) == 0 {
		if s := suggest(key, w.names); s != "" {
			hint := "did you mean " + s + "?"
			if at := w.belongs(s, parent); at != "" {
				hint += " " + at
			}
			return hint
		}
	}
	if len(si.names) > 0 && len(si.names) <= 8 {
		return "keys allowed here: " + strings.Join(si.names, ", ")
	}
	return ""
}

// belongs says where else in the schema key (a key of it) is written, "" when it has no other place
// or more than one could be meant.
func (w *walker) belongs(key, parent string) string {
	w.schemaKeys()
	// Only when one place is meant: with several, naming one would be a guess. A block that exists
	// in several places (an S3 block, a DNS block) is every one of them here.
	here := stripIndexes(parent)
	var others, below []string
	for _, at := range w.owners[key] {
		if at == here || slices.Contains(others, at) {
			continue
		}
		others = append(others, at)
		if here != "" && strings.HasPrefix(at, here+".") {
			below = append(below, at)
		}
	}
	at, ok := "", false
	switch {
	case len(others) == 1:
		at, ok = others[0], true
	case len(below) == 1: // several, but one of them is inside the block the key was written in
		at, ok = below[0], true
	}
	if ok {
		if at == "" {
			return key + " belongs at the top level of the file"
		}
		return key + " belongs under " + at + ":"
	}
	return ""
}

// index records, for every key of the target type, the parent paths (without list indexes) it may
// be written under. Intentional: onPath guards only against a type that contains itself — a type
// used in two places is recorded at both, or its keys would look as if they had one owner.
func (w *walker) index(t reflect.Type, path string, depth int, onPath map[reflect.Type]bool) {
	for t.Kind() == reflect.Ptr || t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || depth > 12 || onPath[t] || w.visits >= maxTypes || opaque(t) {
		return
	}
	w.visits++
	onPath[t] = true
	defer delete(onPath, t)
	si := w.info(t)
	for _, name := range si.names {
		w.owners[name] = append(w.owners[name], path)
		w.index(si.fields[name], joinPath(path, name), depth+1, onPath)
	}
}

// stripIndexes is a key path without its list indexes ("users[1].role" → "users.role"). Intentional:
// only "[digits]" is an index; a key that itself has brackets ("idle_time[x]out") keeps them, or it
// would be taken for another key.
func stripIndexes(path string) string {
	if !strings.Contains(path, "[") {
		return path
	}
	var b strings.Builder
	for i := 0; i < len(path); i++ {
		if path[i] == '[' {
			j := i + 1
			for j < len(path) && path[j] >= '0' && path[j] <= '9' {
				j++
			}
			if j > i+1 && j < len(path) && path[j] == ']' {
				i = j
				continue
			}
		}
		b.WriteByte(path[i])
	}
	return b.String()
}

var (
	// causeLineRE is "line N: text" or "line N, column M: text" (what a type that decodes itself
	// writes when it knows the column: two values on one line need it to be told apart).
	causeLineRE = regexp.MustCompile(`(?:^|[\s:(])line (\d+)(?:, column (\d+))?: (.+)$`)
	fieldRE     = regexp.MustCompile(`^field (.+) not found in type \S+$`)
	unmarshalRE = regexp.MustCompile(`^cannot unmarshal (!\S*)`)
	decodeRE    = regexp.MustCompile(`^cannot decode `)
	dupRE       = regexp.MustCompile(`^mapping key "(.*)" already defined at line (\d+)$`)
	typeErrRE   = regexp.MustCompile(`^line (\d+): (field |cannot unmarshal |cannot decode |mapping key )`)
	dupTailRE   = regexp.MustCompile(` already defined at line (\d+)$`)
)

// causeLine is one "line N: …" complaint of the decoder.
type causeLine struct {
	line, col int
	msg       string
}

// causeLines are the decoder's complaints that carry a line. With RedactValues nothing the decoder
// copied from the file is in them: yaml's own list of type errors is read entry by entry and each
// entry reduced to its kind (an entry's first words are the decoder's; the key, tag or value after
// them may hold anything, a line break and "line 3: …" included), any other text is scrubbed first.
func (w *walker) causeLines(cause error) []causeLine {
	const maxLines = 200
	var out []causeLine
	var te *yaml.TypeError
	if w.o.RedactValues && errors.As(cause, &te) {
		for n, e := range te.Errors {
			if n >= maxLines {
				break
			}
			m := typeErrRE.FindStringSubmatch(e)
			if m == nil {
				continue
			}
			line, err := strconv.Atoi(m[1])
			if err != nil {
				continue
			}
			msg := ""
			switch m[2] {
			case "field ":
				msg = "field … not found in type …"
			case "cannot unmarshal ":
				msg = "cannot unmarshal " + scrubbedTag(e[len(m[0]):])
			case "cannot decode ":
				msg = "cannot decode …"
			default:
				// Intentional: the key is Go-quoted, so the last " already defined at line N" is the
				// decoder's own.
				d := dupTailRE.FindStringSubmatch(e)
				if d == nil {
					continue
				}
				msg = `mapping key "…" already defined at line ` + d[1]
			}
			out = append(out, causeLine{line: line, msg: msg})
		}
		return out
	}
	text := cause.Error()
	if len(text) > maxScrub {
		return nil
	}
	if w.o.RedactValues {
		text = scrub(text)
	}
	for n, seg := range strings.Split(text, "\n") {
		if n >= maxLines {
			break
		}
		m := causeLineRE.FindStringSubmatch(strings.TrimSpace(seg))
		if m == nil {
			continue
		}
		line, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		col, _ := strconv.Atoi(m[2])
		out = append(out, causeLine{line: line, col: col, msg: m[3]})
	}
	return out
}

// fromCause keeps the decoder's own "line N: …" complaints the walk did not explain itself (a type
// that decodes itself reports this way), in plain words where the wording is yaml's.
func (w *walker) fromCause(root *yaml.Node, cause error, lines int) {
	if cause == nil || root == nil {
		return
	}
	taken := map[int]bool{}
	w.own = len(w.probs)
	for _, p := range w.probs {
		taken[p.Line] = true
	}
	for _, c := range w.causeLines(cause) {
		if c.line < 1 || c.line > lines || taken[c.line] {
			continue
		}
		taken[c.line] = true
		path, pos, at := locate(root, c.line, c.col, w.keyName)
		// The decoder names the line of the value it read. For an alias that is the anchor's line,
		// under another key: what the walk reported through the alias is already said, and what a
		// self-decoding type read through the alias belongs to the alias's key.
		if w.throughAlias(at, &path, &pos) || w.covered(path) {
			continue
		}
		p := Problem{Pos: pos, Kind: KindSemantic, Path: path, Msg: c.msg}
		switch {
		case fieldRE.MatchString(c.msg):
			p.Kind = KindUnknownKey
			p.Msg = fmt.Sprintf("unknown key %q", cleanText(fieldRE.FindStringSubmatch(c.msg)[1], 60))
			if w.o.RedactValues {
				p.Msg = "unknown key on this line"
			}
		case unmarshalRE.MatchString(c.msg):
			p.Kind = KindType
			what := map[string]string{"!!str": "text", "!!int": "a number", "!!float": "a number", "!!bool": "true or false",
				"!!seq": "a list", "!!map": "a mapping"}[unmarshalRE.FindStringSubmatch(c.msg)[1]]
			if what == "" {
				what = "another kind of value"
			}
			p.Msg = fmt.Sprintf("%s has the wrong type (found %s)", nameOf(path), what)
		case decodeRE.MatchString(c.msg):
			p.Kind = KindType
			p.Msg = nameOf(path) + " has a tag its value does not match"
			p.Hint = "remove the tag"
		case dupRE.MatchString(c.msg):
			d := dupRE.FindStringSubmatch(c.msg)
			p.Kind = KindDuplicate
			p.Msg = fmt.Sprintf("key %q is written twice in this block (first on line %s)", cleanText(d[1], 60), d[2])
			if w.o.RedactValues {
				p.Msg = fmt.Sprintf("a key is written twice in this block (first on line %s)", d[2])
			}
		}
		w.add(p)
	}
}

// throughAlias looks at the nodes a decoder complaint may be about (at). done: the walk already
// reported one of them through an alias. Otherwise, when a self-decoding type read one of them
// through an alias and not where it is written, path and pos become the alias's.
func (w *walker) throughAlias(at []*yaml.Node, path *string, pos *Pos) (done bool) {
	for _, n := range at {
		if w.viaReported[n] {
			return true
		}
	}
	for _, n := range at {
		if s, ok := w.viaOpaque[n]; ok && !w.direct[n] {
			*path, *pos = s.path, s.pos
			return false
		}
	}
	return false
}

// covered: the walk already reported path or a parent of it (yaml names the value's line, the walk
// the key's).
func (w *walker) covered(path string) bool {
	for _, p := range w.probs[:w.own] {
		// A merge's problem has the path of the block that merges: it says nothing about the block's
		// other keys.
		if p.merge {
			continue
		}
		if p.Path == "" || p.Path == path || (strings.HasPrefix(path, p.Path) && (path[len(p.Path)] == '.' || path[len(p.Path)] == '[')) {
			return true
		}
	}
	return false
}

// locate is the path and position of the key or value a decoder complaint at line (and col, when
// the complaint has one) is about: the node written exactly there, or without a column (or with
// none at it) the first key or value on the line. at are the nodes the complaint may be about: that
// one node, or every node on the line.
func locate(root *yaml.Node, line, col int, keyName func(string) (string, bool)) (path string, pos Pos, at []*yaml.Node) {
	if col > 0 {
		if path, pos, at = locateIn(root, line, col, keyName); len(at) > 0 {
			return path, pos, at[:1]
		}
	}
	return locateIn(root, line, 0, keyName)
}

func locateIn(root *yaml.Node, line, col int, keyName func(string) (string, bool)) (path string, pos Pos, at []*yaml.Node) {
	budget := maxNodes
	pos = Pos{Line: line}
	found := false
	// primary: the node may be the one the complaint is placed at (without a column a mapping or a
	// list never is: its line is its first entry's, and that entry is the better place).
	hit := func(n *yaml.Node, p string, primary bool) {
		if n.Line != line || (col > 0 && n.Column != col) {
			return
		}
		if len(at) < 64 {
			at = append(at, n)
		}
		if primary && !found {
			found, path, pos = true, p, Pos{n.Line, n.Column}
		}
	}
	var visit func(n *yaml.Node, p string, depth int)
	visit = func(n *yaml.Node, p string, depth int) {
		budget--
		if n == nil || depth > maxDepth || budget < 0 || (found && col > 0) {
			return
		}
		switch n.Kind {
		case yaml.ScalarNode, yaml.AliasNode:
			hit(n, p, true)
		case yaml.MappingNode:
			hit(n, p, col > 0)
			for i := 0; i+1 < len(n.Content); i += 2 {
				name, _ := keyName(n.Content[i].Value)
				child := joinPath(p, name)
				hit(n.Content[i], child, true)
				visit(n.Content[i+1], child, depth+1)
			}
		case yaml.SequenceNode:
			hit(n, p, col > 0)
			for i, c := range n.Content {
				visit(c, p+"["+strconv.Itoa(i)+"]", depth+1)
			}
		}
	}
	visit(root, "", 0)
	return path, pos, at
}
