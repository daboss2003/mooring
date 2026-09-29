package docker

import (
	"encoding/json"
	"reflect"
	"testing"
)

// Info decodes the daemon identity fields (ID, Name, DockerRootDir) next to the
// counters from a real-shaped /info body; fields Mooring doesn't use are ignored.
func TestInfoDecode(t *testing.T) {
	const body = `{
		"ID": "4f2b8d0e-3c1a-4e8b-9d6f-0a7c5e2b1d93",
		"Containers": 14, "ContainersRunning": 11, "ContainersPaused": 0, "ContainersStopped": 3,
		"Images": 22, "Driver": "overlay2", "DriverStatus": [["Backing Filesystem", "extfs"]],
		"NCPU": 4, "MemTotal": 8323051520,
		"DockerRootDir": "/var/snap/docker/common/var-lib-docker",
		"Name": "vps-1", "ServerVersion": "27.3.1",
		"Swarm": {"LocalNodeState": "inactive"},
		"SecurityOptions": ["name=apparmor", "name=seccomp,profile=builtin"]
	}`
	var got Info
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	want := Info{
		Containers: 14, ContainersRunning: 11, ContainersStopped: 3, Images: 22,
		NCPU: 4, MemTotal: 8323051520, ServerVersion: "27.3.1",
		ID: "4f2b8d0e-3c1a-4e8b-9d6f-0a7c5e2b1d93", Name: "vps-1",
		DockerRootDir: "/var/snap/docker/common/var-lib-docker",
	}
	if got != want {
		t.Errorf("Info decode:\n got %+v\nwant %+v", got, want)
	}
}

// IPs() unmarshals /containers/json's NetworkSettings, returns non-empty IPs sorted
// by network name (deterministic), and copes with empty IPs / no networks.
func TestContainerIPs(t *testing.T) {
	cases := []struct {
		name string
		json string
		want []string
	}{
		{
			name: "sorted by network name, empties dropped",
			// zeta_net sorts after alpha_net, so alpha's IP comes first; mid_net has no IP.
			json: `{"NetworkSettings":{"Networks":{
				"zeta_net":{"IPAddress":"172.18.0.9"},
				"alpha_net":{"IPAddress":"172.19.0.3"},
				"mid_net":{"IPAddress":""}}}}`,
			want: []string{"172.19.0.3", "172.18.0.9"},
		},
		{name: "no networks", json: `{"NetworkSettings":{"Networks":{}}}`, want: nil},
		{name: "absent NetworkSettings", json: `{"Id":"x"}`, want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c Container
			if err := json.Unmarshal([]byte(tc.json), &c); err != nil {
				t.Fatal(err)
			}
			if got := c.IPs(); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("IPs() = %v, want %v", got, tc.want)
			}
		})
	}
}
