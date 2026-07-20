package web

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// §15 Phase-3 authz matrix, REGENERATED FROM THE ROUTE TABLE so a new route can't
// slip past untested. Two complementary gates:
//
//   - TestRoutePostureFromTable (static): parse Handler()'s mux registrations and
//     assert every route is either in the auth-exempt allowlist or wrapped in
//     requireAuth, and every mutating-verb route is wrapped in requireCSRF (except
//     the HMAC-gated webhook). A route added without its guards fails the build.
//   - TestAnonymousDeniedMatrix (dynamic): drive an anonymous request (allowlisted
//     peer, no session, no CSRF) at every protected route and assert it never
//     returns 2xx — "any unexpected allow fails the gate."

// authExempt are the deliberately public (no requireAuth) routes.
var authExempt = map[string]bool{
	"GET /healthz":          true,
	"POST /webhook/{token}": true, // HMAC + replay + rate-limit gated instead
	"GET /login":            true,
	"POST /login":           true,
	"POST /logout":          true,
	"GET /session/status":   true, // non-refreshing liveness probe; returns 204/401 itself, no session data
	"GET /static/theme.css": true,
	"GET /static/":          true, // embedded asset FileServer (behind the allowlist)
	// OAuth callback: a cross-site navigation back from github.com, so the Strict
	// session cookie isn't sent. Authenticated instead by the single-use Lax OAuth
	// state cookie that only an authenticated+CSRF'd /github/connect could have set.
	"GET /github/callback": true,
}

// csrfExempt are the mutating routes that intentionally do NOT use requireCSRF.
var csrfExempt = map[string]bool{
	"POST /webhook/{token}": true, // authenticated by HMAC signature, not a session/CSRF
}

var mutatingVerb = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}

type routeReg struct {
	key      string // "VERB /pattern"
	verb     string
	pattern  string
	hasAuth  bool
	hasCSRF  bool
	hasToken bool // wrapped in requireToken (the bearer-API auth gate)
	isHandle bool // mux.Handle (raw handler) vs mux.HandleFunc
}

// extractRoutes parses server.go and returns every mux route registration in
// Handler(), with whether its middleware chain contains requireAuth / requireCSRF.
func extractRoutes(t *testing.T) []routeReg {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "server.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse server.go: %v", err)
	}
	routes := extractRoutesFromFile(f, fset)
	if len(routes) == 0 {
		t.Fatal("extractRoutes found no mux registrations — parser drift?")
	}
	return routes
}

// extractRoutesFromFile is the pure core of extractRoutes (testable on snippets). It
// is FAIL-CLOSED: a mux.HandleFunc/Handle whose pattern is NOT a string literal
// cannot be statically analysed, so instead of being silently skipped (which would
// let an unauthenticated route exist while the gate passes), it is recorded as an
// unanalysable route with hasAuth=false — guaranteeing TestRoutePostureFromTable
// fails until the route is registered with a literal pattern.
func extractRoutesFromFile(f *ast.File, fset *token.FileSet) []routeReg {
	var routes []routeReg
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Name != "mux" {
			return true
		}
		if (sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle") || len(call.Args) < 2 {
			return true
		}
		ln := fset.Position(call.Pos()).Line
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			// Fail-closed: an un-analysable route registration is recorded as
			// unauthenticated so the posture gate fails loudly.
			routes = append(routes, routeReg{
				key:     "<non-literal pattern at server.go:" + strconv.Itoa(ln) + ">",
				verb:    "POST", // force BOTH the auth and CSRF checks to apply
				pattern: "",
				hasAuth: false,
				hasCSRF: false,
			})
			return true
		}
		key := strings.Trim(lit.Value, "`\"")
		parts := strings.SplitN(key, " ", 2)
		if len(parts) != 2 {
			return true
		}
		r := routeReg{key: key, verb: parts[0], pattern: parts[1], isHandle: sel.Sel.Name == "Handle"}
		ast.Inspect(call.Args[1], func(m ast.Node) bool {
			if s, ok := m.(*ast.SelectorExpr); ok {
				switch s.Sel.Name {
				case "requireAuth", "requirePerm":
					// requirePerm wraps requireAuth (session gate) and additionally enforces
					// the acting user's role — so it satisfies the authentication requirement.
					r.hasAuth = true
				case "requireCSRF":
					r.hasCSRF = true
				case "requireToken":
					r.hasToken = true
				}
			}
			return true
		})
		routes = append(routes, r)
		return true
	})
	return routes
}

func TestRoutePostureFromTable(t *testing.T) {
	for _, r := range extractRoutes(t) {
		// A route is authenticated by either the session gate (requireAuth) or the
		// bearer gate (requireToken). The bearer API is CSRF-EXEMPT by construction:
		// it carries no ambient credential, so there is nothing a cross-site request
		// can abuse.
		authed := r.hasAuth || r.hasToken
		if !authExempt[r.key] && !authed {
			t.Errorf("AUTHZ: %q is not auth-exempt and is missing requireAuth/requireToken (add it, or allowlist if truly public)", r.key)
		}
		if mutatingVerb[r.verb] && !csrfExempt[r.key] && !r.hasToken && !r.hasCSRF {
			t.Errorf("AUTHZ: mutating route %q is missing requireCSRF (add it, or allowlist if HMAC-authenticated)", r.key)
		}
		// An auth-exempt route must be a DELIBERATE entry — flag a route that claims
		// to be public but still wires an auth gate (contradiction / stale allowlist).
		if authExempt[r.key] && authed {
			t.Errorf("AUTHZ: %q is in the auth-exempt allowlist but wires an auth gate (remove one)", r.key)
		}
	}
}

// TestAuthExemptListHasNoStaleEntries ensures the allowlist tracks the real table —
// a removed route must not linger as a phantom "public" entry.
func TestAuthExemptListHasNoStaleEntries(t *testing.T) {
	live := map[string]bool{}
	for _, r := range extractRoutes(t) {
		live[r.key] = true
	}
	for k := range authExempt {
		if !live[k] {
			t.Errorf("AUTHZ: auth-exempt allowlist entry %q no longer exists in the route table (remove it)", k)
		}
	}
	for k := range csrfExempt {
		if !live[k] {
			t.Errorf("AUTHZ: csrf-exempt allowlist entry %q no longer exists in the route table (remove it)", k)
		}
	}
}

// fillParams substitutes wildcard segments so a pattern becomes a concrete path.
func fillParams(pattern string) string {
	if pattern == "/{$}" {
		return "/"
	}
	segs := strings.Split(pattern, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, "{") {
			segs[i] = "x"
		}
	}
	return strings.Join(segs, "/")
}

func TestAnonymousDeniedMatrix(t *testing.T) {
	e := buildServer(t, []string{"203.0.113.7/32"}, false, nil, "")
	const peer = "203.0.113.7:1234" // allowlisted, so we test AUTH not the allowlist
	for _, r := range extractRoutes(t) {
		if authExempt[r.key] || r.isHandle || strings.HasSuffix(r.pattern, "/") {
			continue // public, or a prefix/static handler
		}
		path := fillParams(r.pattern)
		var form map[string][]string
		if mutatingVerb[r.verb] {
			form = map[string][]string{} // ensure the body is form-parsed
		}
		resp := e.req(t, r.verb, path, peer, nil, nil, form)
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			t.Errorf("AUTHZ: anonymous %s %s returned %d (a 2xx) — protected routes must deny no-session access",
				r.verb, path, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

// Self-test: the real extractor + posture rule must FIRE on a route missing
// requireAuth, a mutating route missing requireCSRF, AND a non-literal pattern
// (fail-closed) — guarding against the gate rotting into a no-op or fail-open.
func TestPostureDetectorFires(t *testing.T) {
	src := `package web
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /secret", s.handleSecret)
	mux.HandleFunc("POST /danger", s.requireAuth(s.handleDanger))
	dyn := "GET /sneaky"
	mux.HandleFunc(dyn, s.handleSneaky)
	return mux
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "snippet.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	got := extractRoutesFromFile(f, fset)
	if len(got) != 3 {
		t.Fatalf("expected 3 routes (incl. the non-literal one recorded fail-closed), got %d: %+v", len(got), got)
	}
	var missingAuth, missingCSRF, nonLiteral int
	for _, r := range got {
		if !r.hasAuth {
			missingAuth++ // /secret AND the non-literal route
		}
		if mutatingVerb[r.verb] && !r.hasCSRF {
			missingCSRF++ // /danger has auth but no CSRF; the non-literal is verb=POST too
		}
		if strings.HasPrefix(r.key, "<non-literal pattern") {
			nonLiteral++
		}
	}
	if missingAuth == 0 {
		t.Error("posture detector failed to flag a route missing requireAuth")
	}
	if missingCSRF == 0 {
		t.Error("posture detector failed to flag a mutating route missing requireCSRF")
	}
	if nonLiteral != 1 {
		t.Error("FAIL-OPEN: a non-literal route pattern was not recorded fail-closed (it would silently escape the gate)")
	}
}
