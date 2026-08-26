package web

import (
	"reflect"
	"testing"

	"github.com/daboss2003/mooring/internal/definition"
)

// eligibleReconcileVolumes must reconcile a named writable volume ONLY when every service mounting it
// runs as the pinned non-root UID — never a volume shared with a service on a different UID (the
// data-safety fix), and never a read-only-only volume or a run-dir bind.
func TestEligibleReconcileVolumes(t *testing.T) {
	mk := func(svcs map[string]definition.Service) *definition.Definition {
		return &definition.Definition{Spec: definition.Spec{Compose: definition.Compose{Services: svcs}}}
	}
	cases := []struct {
		name     string
		def      *definition.Definition
		nonroot  map[string]bool
		expected []string
	}{
		{
			name:     "solo pinned writable named volume is eligible",
			def:      mk(map[string]definition.Service{"web": {Volumes: []definition.Volume{{Name: "data", Target: "/data"}}}}),
			nonroot:  map[string]bool{"web": true},
			expected: []string{"data"},
		},
		{
			name: "volume shared with a NON-pinned service is excluded",
			def: mk(map[string]definition.Service{
				"web": {Volumes: []definition.Volume{{Name: "media", Target: "/m"}}},
				"db":  {Volumes: []definition.Volume{{Name: "media", Target: "/m"}}}, // db not pinned
			}),
			nonroot:  map[string]bool{"web": true},
			expected: nil,
		},
		{
			name:     "read-only-only volume is excluded (nothing writes it)",
			def:      mk(map[string]definition.Service{"web": {Volumes: []definition.Volume{{Name: "ro", Target: "/ro", ReadOnly: true}}}}),
			nonroot:  map[string]bool{"web": true},
			expected: nil,
		},
		{
			name:     "run-dir bind (no Name) is skipped",
			def:      mk(map[string]definition.Service{"web": {Volumes: []definition.Volume{{Source: "./x", Target: "/x"}}}}),
			nonroot:  map[string]bool{"web": true},
			expected: nil,
		},
		{
			name: "volume shared by two pinned services is eligible once",
			def: mk(map[string]definition.Service{
				"web":    {Volumes: []definition.Volume{{Name: "shared", Target: "/s"}}},
				"worker": {Volumes: []definition.Volume{{Name: "shared", Target: "/s"}}},
			}),
			nonroot:  map[string]bool{"web": true, "worker": true},
			expected: []string{"shared"},
		},
		{
			name: "writable if ANY mount is writable, even when another mounts it :ro",
			def: mk(map[string]definition.Service{
				"web":    {Volumes: []definition.Volume{{Name: "d", Target: "/d", ReadOnly: true}}},
				"worker": {Volumes: []definition.Volume{{Name: "d", Target: "/d"}}},
			}),
			nonroot:  map[string]bool{"web": true, "worker": true},
			expected: []string{"d"},
		},
	}
	for _, c := range cases {
		got := eligibleReconcileVolumes(c.def, c.nonroot)
		if len(got) == 0 && len(c.expected) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, c.expected) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.expected)
		}
	}
}
