package web

import (
	"sync"
	"time"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/servicelog"
)

// logPolicyTTL is how long an app's per-service log retention is cached.
const logPolicyTTL = 30 * time.Second

// maxLogPolicyApps bounds the cache: the log page asks about whatever app its URL names.
const maxLogPolicyApps = 1024

// logPolicyEntry is one app's requested log retention per service (nil = no definition / none set).
type logPolicyEntry struct {
	at  time.Time
	svc map[string]servicelog.Policy
}

// logPolicyCache serves servicelog's policy source from the deployed definitions.
type logPolicyCache struct {
	read func(app string) (*definition.Definition, error)
	now  func() time.Time

	mu      sync.Mutex
	entries map[string]logPolicyEntry
}

func newLogPolicyCache(read func(string) (*definition.Definition, error), now func() time.Time) *logPolicyCache {
	return &logPolicyCache{read: read, now: now, entries: map[string]logPolicyEntry{}}
}

// ServiceLogPolicySource returns the log store's policy source: each service's `logs:` from its
// app's canonical (HMAC-verified, re-parsed) definition, cached for logPolicyTTL. A failed read keeps
// the last good value, or reports unknown (the store then keeps the service's last known policy, or
// applies the default). An app with no definition gets the default.
func (s *Server) ServiceLogPolicySource() servicelog.PolicySource {
	if s.defStore == nil {
		return func(string, string) (servicelog.Policy, bool) { return servicelog.Policy{}, true }
	}
	return newLogPolicyCache(s.defStore.Current, time.Now).lookup
}

func (c *logPolicyCache) lookup(app, svc string) (servicelog.Policy, bool) {
	c.mu.Lock()
	e, cached := c.entries[app]
	c.mu.Unlock()
	if cached && c.now().Sub(e.at) < logPolicyTTL {
		return e.svc[svc], true
	}
	def, err := c.read(app)
	if err != nil {
		if cached {
			return e.svc[svc], true
		}
		return servicelog.Policy{}, false
	}
	e = logPolicyEntry{at: c.now(), svc: logPoliciesFrom(def)}
	c.mu.Lock()
	if _, ok := c.entries[app]; !ok && len(c.entries) >= maxLogPolicyApps {
		clear(c.entries)
	}
	c.entries[app] = e
	c.mu.Unlock()
	return e.svc[svc], true
}

// logPoliciesFrom extracts each service's requested log retention from a definition (nil for none).
func logPoliciesFrom(def *definition.Definition) map[string]servicelog.Policy {
	if def == nil {
		return nil
	}
	var out map[string]servicelog.Policy
	for name, svc := range def.Spec.Compose.Services {
		if svc.Logs == nil {
			continue
		}
		var p servicelog.Policy
		if d, err := config.ParseDuration(svc.Logs.Retain); err == nil && d > 0 {
			p.Retain = d
		}
		if svc.Logs.MaxLines > 0 {
			p.MaxLines = svc.Logs.MaxLines
		}
		if out == nil {
			out = map[string]servicelog.Policy{}
		}
		out[name] = p
	}
	return out
}
