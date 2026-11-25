package web

import (
	"testing"

	"github.com/daboss2003/mooring/internal/siem"
)

// Every account scope the detection engine gives an entity (internal/siem/detect incScope: the
// event source, "app:<slug>" for an app event, "app" when the app is unknown) opens its entity page;
// anything else is refused.
func TestEntityScopesTheEngineProduces(t *testing.T) {
	for _, scope := range []string{"", "mooring", "host", "edge", "app", "app:shop", "app:my-app-2"} {
		if _, ok := parseEntity(siem.EntityAccount, "alice", scope); !ok {
			t.Errorf("scope %q refused", scope)
		}
	}
	for _, scope := range []string{"siem", "app:", "app:Shop", "App", "mooring ", "x:y"} {
		if _, ok := parseEntity(siem.EntityAccount, "alice", scope); ok {
			t.Errorf("scope %q accepted", scope)
		}
	}
}
