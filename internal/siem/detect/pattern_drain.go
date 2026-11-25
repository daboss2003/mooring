package detect

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/daboss2003/mooring/internal/siem"
)

// The template tree of a scope (Drain: He et al., "Drain: An Online Log Parsing Approach with
// Fixed Depth Tree", ICWS 2017). A line goes down by its token count, then its first two tokens (a
// token with a digit, or one past a node's maxKids children, goes to the <*> child), to a leaf of
// templates of that shape; it joins the most similar one (the share of positions where the
// template has the line's token), which keeps the tokens they share and has <*> elsewhere, or
// starts a template of its own.

const (
	patDepth = 2   // tokens a line goes down by after its token count
	patSim   = 0.5 // a line joins a template it shares at least this share of tokens with
)

// pnode is a node of a scope's tree: a token count's root (parent nil), a path token's node, or a
// leaf (depth patDepth, or the line's token count when that is less) holding templates.
type pnode struct {
	parent   *pnode
	key      string // the path token, or the root's token count
	n        int    // the root's token count
	kids     map[string]*pnode
	clusters []*ptmpl
}

// pscope is one scope's learned templates: an app service's ("app:<slug>/<service>") or the
// host's.
type pscope struct {
	name     string
	app, svc string
	host     bool
	first    int64 // unix ns: its first line was mined (the learning period runs from here)
	relearn  int64 // unix ns: it learns until then too (the tokenizer changed)
	last     int64 // unix ns (the engine's clock): a line of it was last mined
	lastSave int64 // last as it was when the scope was last marked to be saved (to the day)
	tokVer   int
	roots    map[int]*pnode
	cache    map[uint64]*ptmpl // fingerprint → template
	n, nodes int
	lru      list.List // its templates, most recently used first (unprotected)
	wlru     list.List // unprotected, with a new report waiting: forgotten for room after lru's
	plru     list.List // protected
	olru     list.List // the ones the owner marked (expected, ignored)
	// The new-template cap: templates made in the minute and the hour (unix minute and hour).
	newMin, newHour int
	minAt, hourAt   int64
	overflow        int64 // lines not sorted into a template since its last churn firing
	capHits         int64 // of them: held back by the new-template cap
	roomHits        int64 // of them: no room (a full leaf with nothing alike, the node caps, no free ID)
	churnAt         int64 // unix ns of its last churn firing
	dirty, saved    bool
}

// label names a scope in a detection's summary: "shop/web", "shop", "host logs".
func (s *pscope) label() string {
	if s.host {
		return "host logs"
	}
	if s.svc == "" {
		return clean(s.app, siem.MaxShort)
	}
	return clean(s.app, siem.MaxShort) + "/" + clean(s.svc, siem.MaxShort)
}

// scopeName is the stored name of a scope: "host" or "app:<slug>/<service>".
func scopeName(host bool, app, svc string) string {
	if host {
		return siem.SrcHost
	}
	return "app:" + app + "/" + svc
}

// appPatPrefix is the start of the scope names of an app's services.
func appPatPrefix(slug string) string { return "app:" + slug + "/" }

// parseScope is scopeName's inverse; false for a name that is none.
func parseScope(name string) (host bool, app, svc string, ok bool) {
	if name == siem.SrcHost {
		return true, "", "", true
	}
	rest, found := strings.CutPrefix(name, "app:")
	if !found {
		return false, "", "", false
	}
	app, svc, found = strings.Cut(rest, "/")
	if !found || app == "" || len(app) > siem.MaxShort || len(svc) > siem.MaxShort || !plainText(app) || !plainText(svc) {
		return false, "", "", false
	}
	return false, app, svc, true
}

// ptmpl is one template.
type ptmpl struct {
	id    string
	sc    *pscope
	leaf  *pnode
	toks  []string
	path  [patDepth]string // the keys of the path it took down the tree (<*> where it went to that child)
	npath int
	text  string // the tokens joined, cut to siem.MaxPatternText

	lvl         uint8 // the highest level seen (siem.LevelRank)
	state       string
	first, last int64 // unix ns of its first and newest line
	count       int64
	seen        uint32 // hours it had a line in
	seenAt      int64  // the newest of them (unix hours)
	reported    bool   // pattern.new or pattern.new_error reported it
	fresh       bool   // made new, and its report neither sent nor cancelled (expected, learned) yet
	pending     bool   // in the miner's reports waiting

	hours    [patHours]uint32 // lines per unix hour, the hour h at h mod patHours
	hourAt   int64            // the newest hour counted (unix hours)
	mins     [patMins]uint32  // lines per unix minute
	minAt    int64
	sample   string
	sampleAt int64 // unix ns the sample was taken

	spikeUntil int64 // unix ns: no spike firing before
	usualKey   int64 // the hour and window usual was worked out for
	usual      float64
	usualOK    bool

	el, gel *list.Element // in its scope's list and the miner's
	prot    bool          // in the protected lists
	own     bool          // in the owner-marked lists
	dead    bool
	saved   bool // a row exists
	dirty   bool // to be saved with the next tick
	cdirty  bool // only its counts changed: saved with the next full save or hour's end
}

const (
	patHours = 192 // 8 days
	patMins  = 60
)

// patternID is the ID of a template made in scope from tokens: "p" + 16 hex of SHA-256 over both,
// so the same template of the same scope gets the same ID on any box and after a restart; n > 0
// tries again after a clash with another template.
func patternID(scope, text string, n int) string {
	h := sha256.New()
	h.Write([]byte(scope))
	h.Write([]byte{0})
	h.Write([]byte(text))
	if n > 0 {
		h.Write([]byte{0})
		h.Write([]byte(strconv.Itoa(n)))
	}
	var b [sha256.Size]byte
	return "p" + hex.EncodeToString(h.Sum(b[:0])[:8])
}

func validPatternID(id string) bool { return len(id) == 17 && id[0] == 'p' && isLowerHex(id[1:]) }

// render joins tokens as a template's text, cut to siem.MaxPatternText.
func render(toks []string) string { return siem.Cut(strings.Join(toks, " "), siem.MaxPatternText) }

// sim is how many of the template's positions hold the line's token, as a share of them, and how
// many are <*>.
func (t *ptmpl) sim(msg string, toks []tok) (float64, int) {
	eq, params := 0, 0
	for i, s := range t.toks {
		switch {
		case s == wildcard:
			params++
		case tokMatches(msg, toks[i], s):
			eq++
		}
	}
	return float64(eq) / float64(len(t.toks)), params
}

// fits reports whether a line fits the template as it is (its fingerprint cache entry).
func (t *ptmpl) fits(msg string, toks []tok) bool {
	if t.dead || len(t.toks) != len(toks) {
		return false
	}
	for i, s := range t.toks {
		if s != wildcard && !tokMatches(msg, toks[i], s) {
			return false
		}
	}
	return true
}

// merge makes the template fit a line: positions holding another token become <*> ("key=<*>"
// when both are key=value of the same key). It reports whether the template changed.
func (t *ptmpl) merge(msg string, toks []tok) bool {
	changed := false
	for i, s := range t.toks {
		if s == wildcard || tokMatches(msg, toks[i], s) {
			continue
		}
		w := wildcard
		if k := kvKeyOf(s); k != "" && toks[i].kv > 0 && msg[toks[i].ps:toks[i].ps+toks[i].kv] == k {
			w = k + wildcard
		}
		t.toks[i], changed = w, true
	}
	if changed {
		t.text = render(t.toks)
	}
	return changed
}

// pathKey is a line's token as the tree's key, in buf: "key=<*>" for a key=value token (its
// values don't split the tree), <*> for a token with a digit.
func pathKey(buf []byte, msg string, t tok) []byte {
	if t.kv > 0 {
		buf = append(append(buf[:0], msg[t.ps:t.ps+t.kv]...), wildcard...)
	} else {
		buf = appendTok(buf[:0], msg, t)
	}
	for _, c := range buf {
		if isDigit(c) {
			return append(buf[:0], wildcard...)
		}
	}
	return buf
}

// maxLeaves is how many leaves a line's templates can be in: at each step down, its token's child
// and the <*> child.
const maxLeaves = 1 << patDepth

// leaves finds the leaves a line's templates can be in, into out, and returns how many: at each
// step its token's child and the <*> child. Both, because which of the two a template went to
// depended on the node's children when it was made (past maxKids: the <*> child), and they change:
// a line must find its template after a restart, or once its token has a child of its own. The
// path of the line's own tokens comes first.
func (m *miner) leaves(sc *pscope, msg string, toks []tok, out *[maxLeaves]*pnode) int {
	root := sc.roots[len(toks)]
	if root == nil {
		return 0
	}
	out[0] = root
	n := 1
	for d := 0; d < min(len(toks), patDepth) && n > 0; d++ {
		m.pbuf = pathKey(m.pbuf, msg, toks[d])
		var next [maxLeaves]*pnode
		k := 0
		for _, node := range out[:n] {
			own := node.kids[string(m.pbuf)]
			if own != nil {
				next[k] = own
				k++
			}
			if w := node.kids[wildcard]; w != nil && w != own {
				next[k] = w
				k++
			}
		}
		*out, n = next, k
	}
	return n
}

// bestOf is the template most similar to a line in the leaves it can be in (ties: the earlier
// leaf's), and its share.
func (m *miner) bestOf(sc *pscope, msg string, toks []tok) (*ptmpl, float64) {
	var (
		ls     [maxLeaves]*pnode
		top    *ptmpl
		topSim = -1.0
	)
	for _, leaf := range ls[:m.leaves(sc, msg, toks, &ls)] {
		if t, s := best(leaf, msg, toks); t != nil && s > topSim {
			top, topSim = t, s
		}
	}
	return top, topSim
}

// best is the leaf's template most similar to a line (ties: the one with more <*>), and its share.
func best(leaf *pnode, msg string, toks []tok) (*ptmpl, float64) {
	var (
		top    *ptmpl
		topSim = -1.0
		topPar = -1
	)
	for _, t := range leaf.clusters {
		s, p := t.sim(msg, toks)
		if s > topSim || s == topSim && p > topPar {
			top, topSim, topPar = t, s, p
		}
	}
	return top, topSim
}

// newNode adds a child (or a root, parent nil) within the scope's and the miner's node caps.
func (m *miner) newNode(sc *pscope, parent *pnode, key string, n int) *pnode {
	if sc.nodes >= m.lim.scopeNodes() || m.nodes >= m.lim.nodes() {
		return nil
	}
	x := &pnode{parent: parent, key: key, n: n}
	if parent == nil {
		if sc.roots == nil {
			sc.roots = map[int]*pnode{}
		}
		sc.roots[n] = x
	} else {
		if parent.kids == nil {
			parent.kids = map[string]*pnode{}
		}
		parent.kids[key] = x
	}
	sc.nodes++
	m.nodes++
	return x
}

// childKey is the key of the child of node a new template with path key goes to: key's own while
// node has it or room for it, else <*> (past maxKids children; the last place is the <*> child's).
func (m *miner) childKey(node *pnode, key string) string {
	if key == wildcard || node.kids[key] != nil {
		return key
	}
	if _, wild := node.kids[wildcard]; wild && len(node.kids) >= m.lim.kids || !wild && len(node.kids)+1 >= m.lim.kids {
		return wildcard
	}
	return key
}

// routeLeaf is the leaf insertLeaf would return for keys when it exists already, else nil; it
// makes nothing.
func (m *miner) routeLeaf(sc *pscope, n int, keys []string) *pnode {
	node := sc.roots[n]
	for i := 0; node != nil && i < len(keys); i++ {
		node = node.kids[m.childKey(node, keys[i])]
	}
	return node
}

// insertLeaf finds or makes the leaf a new template goes in, following keys (a line's path
// tokens, or a template's stored path when it is read back), within maxKids children per node; nil
// past the node caps (any node made on the way is pruned again). keys is changed to the path
// taken: <*> where the template went to that child.
func (m *miner) insertLeaf(sc *pscope, n int, keys []string) *pnode {
	node := sc.roots[n]
	if node == nil {
		if node = m.newNode(sc, nil, strconv.Itoa(n), n); node == nil {
			return nil
		}
	}
	for i := range keys {
		key := m.childKey(node, keys[i])
		keys[i] = key
		next := node.kids[key]
		if next == nil {
			if next = m.newNode(sc, node, key, 0); next == nil {
				m.prune(sc, node)
				return nil
			}
		}
		node = next
	}
	return node
}

// lineKeys are a line's path keys (allocated: a new template's).
func lineKeys(msg string, toks []tok) []string {
	keys := make([]string, 0, patDepth)
	var buf []byte
	for d := 0; d < min(len(toks), patDepth); d++ {
		buf = pathKey(buf, msg, toks[d])
		keys = append(keys, string(buf))
	}
	return keys
}

// prune removes node and its parents while they hold nothing.
func (m *miner) prune(sc *pscope, node *pnode) {
	for node != nil && len(node.clusters) == 0 && len(node.kids) == 0 {
		if node.parent == nil {
			if sc.roots[node.n] == node {
				delete(sc.roots, node.n)
			}
		} else {
			delete(node.parent.kids, node.key)
		}
		sc.nodes--
		m.nodes--
		node = node.parent
	}
}

// unlink takes a template out of its leaf (and prunes the leaf when that was its last).
func (m *miner) unlink(t *ptmpl) {
	leaf := t.leaf
	if leaf == nil {
		return
	}
	for i, x := range leaf.clusters {
		if x == t {
			last := len(leaf.clusters) - 1
			leaf.clusters[i] = leaf.clusters[last]
			leaf.clusters[last] = nil
			leaf.clusters = leaf.clusters[:last]
			break
		}
	}
	t.leaf = nil
	m.prune(t.sc, leaf)
}
