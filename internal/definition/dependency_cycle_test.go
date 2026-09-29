package definition

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/compose"
)

// cyclicDef declares api → worker → api. It passes Parse: the cycle check is submit-time only.
const cyclicDef = `apiVersion: mooring/v1
kind: App
metadata:
  slug: shop
spec:
  compose:
    services:
      api:
        image: ghcr.io/acme/api:1
        depends_on: [worker]
      worker:
        image: ghcr.io/acme/api:1
        depends_on: [db, api]
      db:
        image: postgres:16
`

func TestDependencyCycle(t *testing.T) {
	spec := func(deps map[string][]string) *Spec {
		s := &Spec{Compose: Compose{Services: map[string]Service{}}}
		for name, d := range deps {
			s.Compose.Services[name] = Service{Image: "nginx:1", DependsOn: d}
		}
		return s
	}
	for name, c := range map[string]struct {
		deps map[string][]string
		want []string
	}{
		"none":             {map[string][]string{"a": nil, "b": {"a"}}, nil},
		"diamond":          {map[string][]string{"a": {"b", "c"}, "b": {"d"}, "c": {"d"}, "d": nil}, nil},
		"two":              {map[string][]string{"a": {"b"}, "b": {"a"}}, []string{"a", "b", "a"}},
		"three":            {map[string][]string{"a": {"b"}, "b": {"c"}, "c": {"a"}}, []string{"a", "b", "c", "a"}},
		"behind a prefix":  {map[string][]string{"a": {"b"}, "b": {"c"}, "c": {"b"}}, []string{"b", "c", "b"}},
		"self":             {map[string][]string{"a": {"a"}}, []string{"a", "a"}},
		"unknown skipped":  {map[string][]string{"a": {"ghost"}, "b": {"a"}}, nil},
		"declared order":   {map[string][]string{"a": {"c", "b"}, "b": {"a"}, "c": {"a"}}, []string{"a", "c", "a"}},
		"disjoint + cycle": {map[string][]string{"a": nil, "x": {"y"}, "y": {"x"}}, []string{"x", "y", "x"}},
	} {
		if got := spec(c.deps).DependencyCycle(); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: DependencyCycle() = %v, want %v", name, got, c.want)
		}
	}
}

// A cyclic definition still PARSES (a stored canonical must stay readable), but the
// submit-time check and the reconcile gate reject it.
func TestValidateForSubmitRejectsCycle(t *testing.T) {
	d, err := Parse([]byte(cyclicDef))
	if err != nil {
		t.Fatalf("a cyclic definition must still parse (stored canonicals are re-parsed on read): %v", err)
	}
	err = ValidateForSubmit(d)
	if err == nil || !strings.Contains(err.Error(), "api → worker → api") {
		t.Fatalf("ValidateForSubmit = %v, want the api → worker → api cycle", err)
	}
	if err := Validate(d, "/run/app", compose.Env{}, nil); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Errorf("Validate must reject a depends_on cycle, got %v", err)
	}
	if err := ValidateForSubmit(base()); err != nil {
		t.Errorf("an acyclic definition must pass the submit check: %v", err)
	}
}

// The stored-definition read path (HMAC verify + re-Parse) still loads a cyclic canonical.
func TestCyclicCanonicalStillReadableFromStore(t *testing.T) {
	s, _ := testStore(t)
	d, err := Parse([]byte(cyclicDef))
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.SaveCanonical(context.Background(), d, "legacy", "")
	if err != nil {
		t.Fatal(err)
	}
	cur, err := s.Current("shop")
	if err != nil || cur == nil {
		t.Fatalf("Current must load a stored cyclic canonical, got %v %v", cur, err)
	}
	if _, err := s.Version("shop", id); err != nil {
		t.Fatalf("Version must load a stored cyclic canonical: %v", err)
	}
	if ValidateForSubmit(cur) == nil {
		t.Error("resubmitting the cyclic definition must still be rejected")
	}
}
