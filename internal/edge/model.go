package edge

// The typed subset of the Caddy v2 admin-API config Mooring emits. The config is
// ALWAYS marshalled from these structs (never string concat / loose maps for the
// security-relevant parts) so what Caddy runs is exactly Mooring's typed render
// (SBD-7). Only the fields Mooring uses are modelled; everything else is omitted.

type caddyConfig struct {
	Admin *caddyAdmin `json:"admin"`
	Apps  caddyApps   `json:"apps"`
}

type caddyAdmin struct {
	Listen        string            `json:"listen"`
	EnforceOrigin bool              `json:"enforce_origin"`
	Origins       []string          `json:"origins,omitempty"`
	Config        *caddyAdminConfig `json:"config,omitempty"`
}

// caddyAdminConfig disables Caddy's config autosave. Mooring re-feeds the whole document on
// every boot (Supervisor.InitialCfg) and re-renders it on every change, so autosave is never
// needed — and turning it off keeps a secret-bearing config (e.g. a DNS-01 api_token) from
// being written at rest to /var/lib/caddy/.../autosave.json beyond the 0600 root config.yaml.
type caddyAdminConfig struct {
	Persist *bool `json:"persist,omitempty"`
}

type caddyApps struct {
	HTTP caddyHTTP `json:"http"`
	TLS  *caddyTLS `json:"tls,omitempty"`
}

type caddyHTTP struct {
	Servers map[string]caddyServer `json:"servers"`
}

type caddyServer struct {
	Listen []string     `json:"listen"`
	Routes []caddyRoute `json:"routes"`
}

type caddyRoute struct {
	Match    []caddyMatch   `json:"match,omitempty"`
	Handle   []caddyHandler `json:"handle"`
	Terminal bool           `json:"terminal,omitempty"`
}

type caddyMatch struct {
	Host     []string       `json:"host,omitempty"`
	Path     []string       `json:"path,omitempty"`
	RemoteIP *caddyRemoteIP `json:"remote_ip,omitempty"`
}

type caddyRemoteIP struct {
	Ranges []string `json:"ranges"`
}

type caddyHandler struct {
	Handler string `json:"handler"`
	// reverse_proxy
	Upstreams     []caddyUpstream     `json:"upstreams,omitempty"`
	Transport     map[string]any      `json:"transport,omitempty"`
	Headers       *caddyProxyHeaders  `json:"headers,omitempty"`
	LoadBalancing *caddyLoadBalancing `json:"load_balancing,omitempty"`
	HealthChecks  *caddyHealthChecks  `json:"health_checks,omitempty"`
	// headers handler
	Response *caddyHeaderOps `json:"response,omitempty"`
	// static_response
	StatusCode int `json:"status_code,omitempty"`
}

// caddyLoadBalancing selects across a replica pool (least_conn for M14 edge pools).
type caddyLoadBalancing struct {
	SelectionPolicy map[string]any `json:"selection_policy,omitempty"`
}

// caddyHealthChecks holds the passive health policy applied to a pool — a replica
// that fails repeatedly is taken out until it recovers.
type caddyHealthChecks struct {
	Passive *caddyPassiveHealth `json:"passive,omitempty"`
}

type caddyPassiveHealth struct {
	FailDuration string `json:"fail_duration,omitempty"`
	MaxFails     int    `json:"max_fails,omitempty"`
}

type caddyUpstream struct {
	Dial string `json:"dial"`
}

type caddyProxyHeaders struct {
	Request  *caddyHeaderOps `json:"request,omitempty"`
	Response *caddyHeaderOps `json:"response,omitempty"`
}

type caddyHeaderOps struct {
	Set map[string][]string `json:"set,omitempty"`
}

type caddyTLS struct {
	// Certificates.automate is what makes Caddy PROACTIVELY obtain a cert for a name.
	// automation.policies only scopes the issuer; a cert-only subject (one no server
	// route references) is never obtained unless it's listed here (on-demand is off).
	Certificates *caddyCertificates `json:"certificates,omitempty"`
	Automation   caddyAutomation    `json:"automation"`
}

type caddyCertificates struct {
	Automate []string `json:"automate,omitempty"`
}

type caddyAutomation struct {
	Policies []caddyTLSPolicy `json:"policies,omitempty"`
}

type caddyTLSPolicy struct {
	Subjects []string      `json:"subjects,omitempty"`
	Issuers  []caddyIssuer `json:"issuers,omitempty"`
}

type caddyIssuer struct {
	Module       string           `json:"module"`
	CA           string           `json:"ca,omitempty"`
	Email        string           `json:"email,omitempty"`
	TrustedRoots []string         `json:"trusted_roots_pem_files,omitempty"` // for a private CA's own https
	Challenges   *caddyChallenges `json:"challenges,omitempty"`              // set → DNS-01 (for a wildcard subject)
}

// caddyChallenges scopes an ACME issuer to a specific challenge. Mooring only ever sets DNS
// (for the optional *.base_domain wildcard); leaving it nil keeps Caddy's default HTTP-01 +
// TLS-ALPN-01 on :80/:443 for every ordinary subject.
type caddyChallenges struct {
	DNS *caddyDNSChallenge `json:"dns,omitempty"`
}

// caddyDNSChallenge carries the DNS provider module + its (secret-bearing) config, e.g.
// {"provider":{"name":"cloudflare","api_token":"…"}}. The provider module must be COMPILED
// INTO the caddy binary (vanilla Caddy has none — build one with xcaddy).
type caddyDNSChallenge struct {
	Provider map[string]any `json:"provider,omitempty"`
}
