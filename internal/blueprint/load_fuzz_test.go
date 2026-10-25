package blueprint_test

import (
	"bytes"
	"io"
	"reflect"
	"testing"

	"github.com/ml0renz0/secretwright/internal/blueprint"
)

// FuzzLoad exercises both untrusted files. A successful parse must remain valid
// when passed to plan/apply, and arbitrary failures must not echo file contents.
func FuzzLoad(f *testing.F) {
	policy := []byte(`{"api_version":"secretwright/v1","name":"app","resources":[{"id":"read","kind":"policy","name":"app-read","spec":{"policy":"path \"secret/*\" { capabilities = [\"read\"] }"}}]}`)
	template := []byte(`api_version: secretwright/v1
name: app
variables:
  disabled: {type: boolean, default: false}
resources:
  - {id: team, kind: group, name: app-team, spec: {member_entities: [owner]}}
  - {id: owner, kind: entity, name: app-owner, spec: {disabled: "${var.disabled}"}}
`)
	for _, seed := range []struct {
		input     []byte
		overrides []byte
	}{
		{policy, nil},
		{policy, []byte("{}")},
		{template, []byte("disabled: true\n")},
		{template, []byte("disabled: false\ndisabled: true\n")},
		{template, []byte("disabled: private-fuzz-value\n")},
		{append(append([]byte(nil), policy...), []byte("\n---\n{}")...), nil},
		{[]byte("name: &private-fuzz-anchor app\nresources: []\n"), nil},
		{[]byte("\xff\x00"), []byte("invalid: 1e99999999999999999999")},
	} {
		f.Add(seed.input, seed.overrides)
	}
	f.Fuzz(func(t *testing.T, input, overrides []byte) {
		load := func() (blueprint.Document, error) {
			var values io.Reader
			if len(overrides) != 0 {
				values = bytes.NewReader(overrides)
			}
			return blueprint.Load(bytes.NewReader(input), values)
		}
		first, firstErr := load()
		second, secondErr := load()
		if (firstErr == nil) != (secondErr == nil) || !reflect.DeepEqual(first, second) {
			t.Fatal("identical blueprint inputs produced different validation results")
		}
		if firstErr != nil {
			if firstErr != blueprint.ErrInvalidBlueprint || secondErr != blueprint.ErrInvalidBlueprint {
				t.Fatal("validation returned a non-static error that may expose input")
			}
			if !reflect.DeepEqual(first, blueprint.Document{}) {
				t.Fatal("failed validation exposed a partially resolved document")
			}
			return
		}
		again, err := blueprint.ValidateDocument(first)
		if err != nil || !reflect.DeepEqual(first, again) {
			t.Fatal("accepted blueprint was not stable when revalidated for execution")
		}
		resources := make(map[string]blueprint.Resource, len(first.Resources))
		for _, resource := range first.Resources {
			resources[resource.ID] = resource
		}
		if len(resources) != len(first.Resources) || len(first.Order) != len(first.Resources) {
			t.Fatal("accepted blueprint lost or duplicated a graph resource")
		}
		seen := make(map[string]bool, len(first.Order))
		for _, id := range first.Order {
			resource, exists := resources[id]
			if !exists || seen[id] {
				t.Fatal("execution order contains an unknown or repeated resource")
			}
			for _, dependency := range resource.DependsOn {
				if !seen[dependency] {
					t.Fatal("execution order placed a resource before its dependency")
				}
			}
			seen[id] = true
		}
	})
}
