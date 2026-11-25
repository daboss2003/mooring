package definition

import (
	"fmt"
	"reflect"
	"sort"
)

// host.go is the kind:Host definition (plan §7.8): the singleton Tier-2 server-wide
// config — the app registry, global defaults projected beneath each app, server-wide
// alerting, and cross-app deploy/setup ordering. A THIRD front-end onto the same
// reconciler; structurally incapable of expressing a Tier-1 field (those are
// rejected in harden()), so it is dashboard/CLI-writable without touching identity.

// Host is the whole host.yaml document.
type Host struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Spec       HostSpec `yaml:"spec"`
}

// HostSpec is the server-wide surface.
type HostSpec struct {
	Apps          []AppRegistration `yaml:"apps,omitempty"`
	Defaults      *Defaults         `yaml:"defaults,omitempty"`
	Orchestration *Orchestration    `yaml:"orchestration,omitempty"`
}

// AppRegistration is one entry in the registry — the ONLY place the set of apps on
// the box is enumerated. Registering does NOT deploy.
type AppRegistration struct {
	Slug    string    `yaml:"slug"`
	Source  AppSource `yaml:"source"`
	Enabled bool      `yaml:"enabled"`
}

// AppSource is a oneOf: a repo (+ref), a local path, or managed-in-place.
type AppSource struct {
	Repo    string `yaml:"repo,omitempty"`
	Ref     string `yaml:"ref,omitempty"`
	Path    string `yaml:"path,omitempty"`
	Managed bool   `yaml:"managed,omitempty"`
}

// Defaults is the global base layer projected BENEATH each app's spec (resolved
// before §5.6). It carries ONLY the Tier-3 subset of knobs — never edge.routes or
// git.ref (which don't exist here by construction) and never a Tier-1 field. A
// default may TIGHTEN a posture but never silently WIDEN one (see posture.go).
//
// POSTURE-SENSITIVE: every field here must be handled by PostureWidenings() in
// posture.go. TestDefaultsFieldsAllPostureChecked enforces this — adding a field
// without a widening check fails that test, so the predicate stays closed.
type Defaults struct {
	Scaling     *DefaultScaling `yaml:"scaling,omitempty"`
	SelfHealing *bool           `yaml:"self_healing,omitempty"` // enable/disable the supervisor
	AutoDeploy  *bool           `yaml:"auto_deploy,omitempty"`  // default git auto-deploy (widening → ack)
}

// DefaultScaling is the host-default scaling envelope (a ceiling, projectable).
type DefaultScaling struct {
	Max int `yaml:"max,omitempty"`
	Min int `yaml:"min,omitempty"`
}

// Orchestration sequences multi-app deploys/setup under one operator-initiated run.
type Orchestration struct {
	DeployOrder []OrderEdge `yaml:"deploy_order,omitempty"`
	SetupOrder  []string    `yaml:"setup_order,omitempty"`
}

// OrderEdge means: the deploy of Deploy waits until After is healthy.
type OrderEdge struct {
	Deploy string `yaml:"deploy"`
	After  string `yaml:"after"`
}

// ParseHost parses + validates a kind:Host document through the same hardened,
// parser-differential-resistant, Tier-1-rejecting pipeline as an App.
func ParseHost(raw []byte) (*Host, error) { return ParseHostNamed(raw, "host.yaml") }

// ParseHostNamed is ParseHost with the file's name for its messages.
func ParseHostNamed(raw []byte, file string) (*Host, error) {
	var h Host
	if err := hardenAndDecode(raw, &h); err != nil {
		return nil, explainRefusal(raw, file, reflect.TypeOf(h), err)
	}
	if err := h.validateEnvelope(); err != nil {
		return nil, explainRefusal(raw, file, reflect.TypeOf(h), err)
	}
	return &h, nil
}

func (h *Host) validateEnvelope() error {
	if h.APIVersion != APIVersion {
		return atf("apiVersion", "apiVersion must be exactly %q (got %q)", APIVersion, h.APIVersion)
	}
	if h.Kind != "Host" {
		return atf("kind", "kind must be \"Host\" (got %q)", h.Kind)
	}
	return h.Spec.validate()
}

func (s *HostSpec) validate() error {
	known := map[string]bool{}
	for i, a := range s.Apps {
		entry := fmt.Sprintf("spec.apps[%d]", i)
		if !slugRe.MatchString(a.Slug) {
			return atf(entry+".slug", "registry app slug %q is invalid", a.Slug)
		}
		if known[a.Slug] {
			return atf(entry+".slug", "duplicate app %q in the registry", a.Slug)
		}
		known[a.Slug] = true
		if err := a.Source.validate(a.Slug); err != nil {
			return at(entry+".source", err)
		}
	}
	if s.Defaults != nil {
		if err := s.Defaults.validate(); err != nil {
			return at("spec.defaults.scaling", err)
		}
	}
	if s.Orchestration != nil {
		if err := s.Orchestration.validate(known); err != nil {
			return at("spec.orchestration", err)
		}
	}
	return nil
}

// validate enforces the semantic rules on the host defaults (every other section is
// validated, so a nonsensical default — negative or inverted replica bounds — must
// be rejected at parse, not discovered at apply).
func (d *Defaults) validate() error {
	if d.Scaling != nil {
		if d.Scaling.Max < 0 || d.Scaling.Min < 0 {
			return fmt.Errorf("defaults.scaling: min/max replicas must be >= 0")
		}
		if d.Scaling.Max > 0 && d.Scaling.Min > d.Scaling.Max {
			return fmt.Errorf("defaults.scaling.min (%d) cannot exceed max (%d)", d.Scaling.Min, d.Scaling.Max)
		}
	}
	return nil
}

// validate enforces the source oneOf: managed, OR a repo (+optional ref), OR a path —
// exactly one.
func (src AppSource) validate(slug string) error {
	n := 0
	if src.Managed {
		n++
	}
	if src.Repo != "" {
		n++
	}
	if src.Path != "" {
		n++
	}
	if n != 1 {
		return fmt.Errorf("app %q source must be exactly one of {managed:true} | {repo[,ref]} | {path}", slug)
	}
	if src.Ref != "" && src.Repo == "" {
		return fmt.Errorf("app %q source.ref requires source.repo", slug)
	}
	return nil
}

func (o *Orchestration) validate(known map[string]bool) error {
	for i, e := range o.DeployOrder {
		entry := fmt.Sprintf("spec.orchestration.deploy_order[%d]", i)
		if !known[e.Deploy] || !known[e.After] {
			return atf(entry, "deploy_order references an unregistered app (%q after %q)", e.Deploy, e.After)
		}
		if e.Deploy == e.After {
			return atf(entry, "deploy_order: %q cannot depend on itself", e.Deploy)
		}
	}
	for i, s := range o.SetupOrder {
		if !known[s] {
			return atf(fmt.Sprintf("spec.orchestration.setup_order[%d]", i), "setup_order references an unregistered app %q", s)
		}
	}
	if _, err := o.DeploySequence(); err != nil {
		return at("spec.orchestration.deploy_order", err) // cycle
	}
	return nil
}

// DeploySequence returns a valid deploy order (a topological sort of the partial
// order: an app appears only after every app it waits on). A cycle is an error.
func (o *Orchestration) DeploySequence() ([]string, error) {
	// Build adjacency: After → Deploy (an edge means Deploy waits for After).
	deps := map[string][]string{} // node → things that must come before it
	nodes := map[string]bool{}
	for _, e := range o.DeployOrder {
		deps[e.Deploy] = append(deps[e.Deploy], e.After)
		nodes[e.Deploy] = true
		nodes[e.After] = true
	}
	var order []string
	state := map[string]int{} // 0=unseen,1=visiting,2=done
	var visit func(n string) error
	visit = func(n string) error {
		switch state[n] {
		case 1:
			return fmt.Errorf("deploy_order has a cycle through %q", n)
		case 2:
			return nil
		}
		state[n] = 1
		befores := append([]string{}, deps[n]...)
		sort.Strings(befores) // deterministic order
		for _, b := range befores {
			if err := visit(b); err != nil {
				return err
			}
		}
		state[n] = 2
		order = append(order, n)
		return nil
	}
	all := make([]string, 0, len(nodes))
	for n := range nodes {
		all = append(all, n)
	}
	sort.Strings(all)
	for _, n := range all {
		if err := visit(n); err != nil {
			return nil, err
		}
	}
	return order, nil
}

// Canonical re-marshals a host definition to canonical YAML.
func CanonicalHost(h *Host) ([]byte, error) {
	return marshalYAML(h)
}
