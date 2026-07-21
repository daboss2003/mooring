package docker

import (
	"sort"
	"strings"
)

// Version is the subset of GET /version we use.
type Version struct {
	Version    string `json:"Version"`
	APIVersion string `json:"ApiVersion"`
}

// Info is the subset of GET /info we use.
type Info struct {
	Containers        int    `json:"Containers"`
	ContainersRunning int    `json:"ContainersRunning"`
	ContainersStopped int    `json:"ContainersStopped"`
	Images            int    `json:"Images"`
	NCPU              int    `json:"NCPU"`
	MemTotal          int64  `json:"MemTotal"`
	ServerVersion     string `json:"ServerVersion"`
}

// Container is the subset of a GET /containers/json entry we use.
type Container struct {
	ID              string                  `json:"Id"`
	Names           []string                `json:"Names"`
	Image           string                  `json:"Image"`
	State           string                  `json:"State"`  // running|exited|created|paused|...
	Status          string                  `json:"Status"` // human string, e.g. "Up 3 hours (healthy)"
	Labels          map[string]string       `json:"Labels"`
	NetworkSettings containerNetworkSummary `json:"NetworkSettings"`
}

// containerNetworkSummary is the slice of /containers/json's NetworkSettings we
// read: each attached network's in-container IP. The edge dials these directly
// (it reaches them over the docker bridge), so the host need not resolve the
// compose service name.
type containerNetworkSummary struct {
	Networks map[string]struct {
		IPAddress string `json:"IPAddress"`
	} `json:"Networks"`
}

// IPs returns the container's non-empty per-network IPv4 addresses, sorted by
// network name for a deterministic order (so a re-render of the same replica set
// produces byte-identical config and skips a needless Caddy reload).
func (c Container) IPs() []string {
	names := make([]string, 0, len(c.NetworkSettings.Networks))
	for n := range c.NetworkSettings.Networks {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []string
	for _, n := range names {
		if ip := strings.TrimSpace(c.NetworkSettings.Networks[n].IPAddress); ip != "" {
			out = append(out, ip)
		}
	}
	return out
}

// Project returns the compose project label (the app key), or "" if unlabeled.
func (c Container) Project() string { return c.Labels[LabelProject] }

// OneOff reports whether this is a transient `compose run` one-shot container (cron task or
// backup/restore sidecar) rather than a supervised long-running service.
func (c Container) OneOff() bool { return c.Labels[LabelOneOff] == "True" }

// Service returns the compose service label, or "" if unlabeled.
func (c Container) Service() string { return c.Labels[LabelService] }

// WorkingDir returns the compose project working directory (the app run_dir).
func (c Container) WorkingDir() string { return c.Labels[LabelWorkingDir] }

// ConfigFiles returns the compose config file paths for the project, dropping
// empty/whitespace entries (a stray "" would become `docker compose -f ""`).
func (c Container) ConfigFiles() []string {
	v := c.Labels[LabelConfigFiles]
	if v == "" {
		return nil
	}
	var out []string
	for _, f := range strings.Split(v, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// Name returns the primary container name without the leading slash.
func (c Container) Name() string {
	if len(c.Names) == 0 {
		return ""
	}
	return strings.TrimPrefix(c.Names[0], "/")
}

// ContainerInspect is the subset of GET /containers/{id}/json we use.
type ContainerInspect struct {
	ID           string `json:"Id"`
	Name         string `json:"Name"`
	RestartCount int    `json:"RestartCount"`
	State        struct {
		Status     string `json:"Status"`
		Running    bool   `json:"Running"`
		ExitCode   int    `json:"ExitCode"`
		OOMKilled  bool   `json:"OOMKilled"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
		Health     *struct {
			Status        string `json:"Status"` // healthy|unhealthy|starting
			FailingStreak int    `json:"FailingStreak"`
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	Mounts []struct {
		Type string `json:"Type"` // bind | volume | tmpfs
		Name string `json:"Name"` // volume name ("" for binds; a 64-hex hash for anonymous volumes)
		RW   bool   `json:"RW"`
	} `json:"Mounts"`
}

// HasSharedRWVolume reports whether the container has a read-write mount that would
// be SHARED across replicas (a host bind or a named volume) — the auto-scaling C3
// disqualifier. Anonymous volumes (a 64-hex name) are per-replica scratch and don't
// count; tmpfs never counts.
func (ci ContainerInspect) HasSharedRWVolume() bool {
	for _, m := range ci.Mounts {
		if !m.RW {
			continue
		}
		switch m.Type {
		case "bind":
			return true
		case "volume":
			if m.Name != "" && !isAnonymousVolume(m.Name) {
				return true
			}
		}
	}
	return false
}

// isAnonymousVolume reports whether a volume name is Docker's anonymous-volume hash
// (64 lowercase hex chars) — per-replica scratch, safe to scale.
func isAnonymousVolume(name string) bool {
	if len(name) != 64 {
		return false
	}
	for _, c := range name {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// HealthStatus returns the container's healthcheck status, or "none" if it has
// no healthcheck.
func (ci ContainerInspect) HealthStatus() string {
	if ci.State.Health == nil || ci.State.Health.Status == "" {
		return "none"
	}
	return ci.State.Health.Status
}

// Stats is the subset of GET /containers/{id}/stats we use (raw counters; CPU%
// is computed from deltas between successive one-shot samples).
type Stats struct {
	CPUStats    cpuStats `json:"cpu_stats"`
	PreCPUStats cpuStats `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
}

type cpuStats struct {
	CPUUsage struct {
		TotalUsage  uint64   `json:"total_usage"`
		PercpuUsage []uint64 `json:"percpu_usage"`
	} `json:"cpu_usage"`
	SystemUsage uint64 `json:"system_cpu_usage"`
	OnlineCPUs  uint32 `json:"online_cpus"`
}

// MemUsed returns memory usage minus reclaimable page cache (cgroup v2
// inactive_file, or v1 cache), matching `docker stats`' notion of used memory.
func (s Stats) MemUsed() uint64 {
	used := s.MemoryStats.Usage
	cache := s.MemoryStats.Stats["inactive_file"]
	if cache == 0 {
		cache = s.MemoryStats.Stats["cache"]
	}
	if cache <= used {
		return used - cache
	}
	return used
}

// MemLimit returns the container memory limit.
func (s Stats) MemLimit() uint64 { return s.MemoryStats.Limit }

// CPUPercentBetween computes instantaneous CPU% from this sample's counters
// versus a previous sample's counters (Docker's formula). prevTotal/prevSystem
// are the previous one-shot's cpu_usage.total_usage / system_cpu_usage. Returns
// 0 when no meaningful delta exists yet (first sample).
func (s Stats) CPUPercentBetween(prevTotal, prevSystem uint64) float64 {
	cpuDelta := float64(s.CPUStats.CPUUsage.TotalUsage) - float64(prevTotal)
	sysDelta := float64(s.CPUStats.SystemUsage) - float64(prevSystem)
	if cpuDelta <= 0 || sysDelta <= 0 {
		return 0
	}
	// Mirror Docker's reference fallback chain: online_cpus, else
	// len(percpu_usage) (older daemons), else 1 (review #7).
	cpus := float64(s.CPUStats.OnlineCPUs)
	if cpus == 0 {
		cpus = float64(len(s.CPUStats.CPUUsage.PercpuUsage))
	}
	if cpus == 0 {
		cpus = 1
	}
	return (cpuDelta / sysDelta) * cpus * 100.0
}

// RawCPU returns the raw counters used as the "previous" sample next tick.
func (s Stats) RawCPU() (total, system uint64) {
	return s.CPUStats.CPUUsage.TotalUsage, s.CPUStats.SystemUsage
}
