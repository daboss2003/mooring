package provision

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// composeFile is the ENTIRE shape the generator can emit. There is deliberately
// no field for privileged / cap_add / devices / network_mode / pid / ipc / uts /
// security_opt / host binds / :80:443 — they cannot be expressed, so no input can
// produce them. yaml.Marshal (never string concatenation) renders it.
type composeFile struct {
	Name     string                    `yaml:"name"`
	Services map[string]composeService `yaml:"services"`
	Volumes  map[string]nullYAML       `yaml:"volumes,omitempty"`
}

type composeService struct {
	Image           string          `yaml:"image,omitempty"`
	Build           *composeBuild   `yaml:"build,omitempty"`
	Restart         string          `yaml:"restart,omitempty"`
	Ports           []string        `yaml:"ports,omitempty"`
	Volumes         []string        `yaml:"volumes,omitempty"`
	Environment     []string        `yaml:"environment,omitempty"`
	Command         []string        `yaml:"command,omitempty"`
	Healthcheck     *composeHealth  `yaml:"healthcheck,omitempty"`
	DependsOn       []string        `yaml:"depends_on,omitempty"`
	MemLimit        string          `yaml:"mem_limit,omitempty"`
	MemReservation  string          `yaml:"mem_reservation,omitempty"`
	StopGracePeriod string          `yaml:"stop_grace_period,omitempty"`
	Ulimits         *composeUlimits `yaml:"ulimits,omitempty"`
	// Profiles gates a service out of the default `up` (compose only starts a profiled service
	// when its profile is enabled or via `compose run`). Mooring uses it for scheduled-only
	// (cron) services so they exist in the compose but never run as long-lived containers.
	Profiles []string `yaml:"profiles,omitempty"`
}

// composeUlimits / composeNofile render docker-compose's
// `ulimits: { nofile: { soft, hard } }` (the map form Docker always accepts).
type composeUlimits struct {
	Nofile *composeNofile `yaml:"nofile,omitempty"`
}

type composeNofile struct {
	Soft int `yaml:"soft"`
	Hard int `yaml:"hard"`
}

// composeBuild is the generated `build:` directive — Mooring builds the service's
// image from a Mooring-generated Dockerfile (the operator never writes one).
type composeBuild struct {
	Context    string `yaml:"context"`
	Dockerfile string `yaml:"dockerfile,omitempty"`
}

type composeHealth struct {
	Test []string `yaml:"test"`
}

// scheduledProfile is the compose profile Mooring puts on scheduled-only (cron) services so
// `up` never starts them; `compose run <service>` still runs one on demand (run enables the
// service's profile automatically).
const scheduledProfile = "mooring-scheduled"

// nullYAML marshals to an empty mapping value (the `volname:` named-volume form).
type nullYAML struct{}

func (nullYAML) MarshalYAML() (any, error) { return nil, nil }

// Generate validates the spec and renders a deterministic, safe compose document.
// The result is STILL meant to be run through §5.6 by the caller (defense in
// depth) — Generate guarantees safety by construction, §5.6 guarantees it again.
func Generate(spec Spec) ([]byte, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	cf := composeFile{Name: spec.Slug, Services: map[string]composeService{}}
	namedVols := map[string]nullYAML{}

	for _, svc := range spec.Services {
		cs := composeService{Restart: svc.Restart, DependsOn: svc.DependsOn, MemLimit: svc.MemLimit, MemReservation: svc.MemReservation, StopGracePeriod: svc.StopGracePeriod}
		if svc.Scheduled {
			cs.Profiles = []string{scheduledProfile} // present in compose, NOT started by `up`
		}
		if svc.Ulimits != nil && svc.Ulimits.Nofile != nil {
			cs.Ulimits = &composeUlimits{Nofile: &composeNofile{Soft: svc.Ulimits.Nofile.Soft, Hard: svc.Ulimits.Nofile.Hard}}
		}
		if svc.Build != nil {
			cs.Build = &composeBuild{Context: svc.Build.Context, Dockerfile: svc.Build.Dockerfile}
		} else {
			cs.Image = svc.Image
		}
		for _, p := range svc.Ports {
			if !p.Publish {
				continue // internal-only: reachable on the compose network, no host map
			}
			host := "127.0.0.1:"
			if p.Public {
				host = "" // bind all interfaces (operator-acked; §5.6 still judges it)
			}
			// The host port defaults to the container port (host==container, the
			// historical behavior); a distinct `published` maps host→container so a
			// non-root container can bind a privileged host port (Docker's root
			// daemon does the privileged bind, not the app).
			hostPort := p.Internal
			if p.Published != 0 {
				hostPort = p.Published
			}
			// Append the protocol only when set, so a plain TCP mapping stays
			// byte-identical to before (no churn for existing apps).
			proto := ""
			if p.Protocol != "" {
				proto = "/" + p.Protocol
			}
			cs.Ports = append(cs.Ports, fmt.Sprintf("%s%d:%d%s", host, hostPort, p.Internal, proto))
		}
		for _, v := range svc.Volumes {
			src := v.Name
			if src == "" {
				src = "./" + v.Source // explicit run_dir-relative bind
			} else {
				namedVols[v.Name] = nullYAML{}
			}
			entry := src + ":" + v.Target
			if v.ReadOnly {
				entry += ":ro"
			}
			cs.Volumes = append(cs.Volumes, entry)
		}
		for _, e := range svc.Env {
			if e.Secret != "" {
				// Secret reference: ${NAME} resolved from the 0600 --env-file at deploy
				// (the encrypted store), never baked into the YAML.
				cs.Environment = append(cs.Environment, e.Key+"=${"+e.Secret+"}")
			} else {
				// Non-secret literal — safe inline (validated: no ${...}, no control chars).
				cs.Environment = append(cs.Environment, e.Key+"="+e.Value)
			}
		}
		if len(svc.Command) > 0 {
			cs.Command = svc.Command
		}
		if len(svc.Healthcheck) > 0 {
			cs.Healthcheck = &composeHealth{Test: append([]string{"CMD"}, svc.Healthcheck...)}
		}
		cf.Services[svc.Name] = cs
	}
	if len(namedVols) > 0 {
		cf.Volumes = namedVols
	}

	out, err := yaml.Marshal(cf)
	if err != nil {
		return nil, fmt.Errorf("generate: marshal compose: %w", err)
	}
	return out, nil
}
