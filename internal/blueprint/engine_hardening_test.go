package blueprint_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ml0renz0/secretwright/internal/blueprint"
)

func TestApplyKeepsValidatedIntentAndIdentityReferencesDetachedFromBackend(t *testing.T) {
	document := f07LoadDocument(t,
		map[string]any{"id": "owner", "kind": "entity", "name": "app-owner", "spec": map[string]any{"policies": []string{"app-read"}}},
		map[string]any{"id": "team", "kind": "group", "name": "app-team", "spec": map[string]any{"policies": []string{"app-read"}, "member_entities": []string{"owner"}}},
	)
	want, err := blueprint.ValidateDocument(document)
	if err != nil {
		t.Fatal("could not detach valid test fixture")
	}
	backend := f07NewBackend()
	poison := func(resource blueprint.Resource, ids map[string]string) {
		resource.Spec["policies"].([]any)[0] = "private-f07-replaced-policy"
		resource.Spec["injected"] = "private-f07-injected-field"
		if len(resource.DependsOn) != 0 {
			resource.DependsOn[0] = "private-f07-replaced-dependency"
		}
		if members, ok := resource.Spec["member_entities"].([]any); ok && len(members) != 0 {
			members[0] = "private-f07-replaced-member"
		}
		ids["owner"] = "private-f07-replaced-id"
		ids["injected"] = "private-f07-injected-id"
	}
	check := func(resource blueprint.Resource, ids map[string]string) {
		t.Helper()
		if !reflect.DeepEqual(resource.Spec["policies"], []any{"app-read"}) || resource.Spec["injected"] != nil || ids["injected"] != "" {
			t.Error("a previous backend call changed the validated specification or shared IDs")
		}
		if resource.ID == "team" && (!reflect.DeepEqual(resource.DependsOn, []string{"owner"}) || !reflect.DeepEqual(resource.Spec["member_entities"], []any{"owner"})) {
			t.Error("a previous backend call changed a dependency or member reference")
		}
	}
	backend.inspect = func(ctx context.Context, resource blueprint.Resource, ids map[string]string, count int) (blueprint.Observation, error) {
		check(resource, ids)
		if resource.ID == "team" && count == 2 && ids["owner"] != f07EntityID {
			t.Error("backend mutation corrupted an ID needed by a dependent creation")
		}
		observation := backend.current(resource)
		poison(resource, ids)
		return observation, nil
	}
	backend.create = func(ctx context.Context, resource blueprint.Resource, ids map[string]string) (blueprint.Observation, error) {
		check(resource, ids)
		id := f07EntityID
		if resource.ID == "team" {
			id = f07GroupID
			if ids["owner"] != f07EntityID {
				t.Error("dependent creation received a modified identity ID")
			}
		}
		poison(resource, ids)
		return blueprint.Observation{Exists: true, Equal: true, ID: id, Fingerprint: "created"}, nil
	}
	report, err := blueprint.Apply(context.Background(), document, backend)
	if err != nil || backend.writes != 2 || !reflect.DeepEqual(f07Statuses(report), []string{"created", "created"}) {
		t.Fatal("backend argument mutation interrupted an otherwise valid apply")
	}
	if !reflect.DeepEqual(document, want) {
		t.Error("backend argument mutation escaped into the caller's document")
	}
	f07RequirePrivate(t, report, err)
}

func TestApplyCancellationBetweenInspectionAndWriteAndAfterConfirmedWrite(t *testing.T) {
	document := f07LoadDocument(t, f07PolicyResource("a"), f07PolicyResource("b"), f07PolicyResource("c"))
	for _, afterWrite := range []bool{false, true} {
		name := "after_inspection_before_write"
		if afterWrite {
			name = "after_confirmed_write"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			backend := f07NewBackend()
			backend.inspect = func(ctx context.Context, resource blueprint.Resource, ids map[string]string, count int) (blueprint.Observation, error) {
				if resource.ID == "a" && count == 2 && !afterWrite {
					cancel()
				}
				return backend.current(resource), nil
			}
			backend.create = func(context.Context, blueprint.Resource, map[string]string) (blueprint.Observation, error) {
				cancel()
				return blueprint.Observation{Exists: true, Equal: true, Fingerprint: "created"}, nil
			}
			report, err := blueprint.Apply(ctx, document, backend)
			want, writes := []string{"failed", "not_started", "not_started"}, 0
			if afterWrite {
				want, writes = []string{"created", "failed", "not_started"}, 1
			}
			if !errors.Is(err, context.Canceled) || errors.Is(err, blueprint.ErrPartial) != afterWrite || backend.writes != writes || !reflect.DeepEqual(f07Statuses(report), want) {
				t.Error("cancellation allowed a new mutation or lost the confirmed partial result")
			}
			wantEvents := []string{"inspect:a", "inspect:b", "inspect:c", "inspect:a"}
			if afterWrite {
				wantEvents = append(wantEvents, "create:a")
			}
			if !reflect.DeepEqual(backend.events, wantEvents) {
				t.Error("canceled apply continued backend work after its stopping point")
			}
		})
	}
}

func TestApplyStopsWithPartialConflictWhenAnEqualResourceChangesAfterPreflight(t *testing.T) {
	document := f07LoadDocument(t,
		f07PolicyResource("a"),
		map[string]any{"id": "b", "kind": "entity", "name": "app-b", "spec": map[string]any{}},
		f07PolicyResource("c"),
	)
	for _, identityChanged := range []bool{false, true} {
		name := "managed_fingerprint"
		if identityChanged {
			name = "replacement_identity"
		}
		t.Run(name, func(t *testing.T) {
			backend := f07NewBackend()
			backend.states["b"] = blueprint.Observation{Exists: true, Equal: true, ID: f07EntityID, Fingerprint: "before"}
			backend.inspect = func(ctx context.Context, resource blueprint.Resource, ids map[string]string, count int) (blueprint.Observation, error) {
				observation := backend.current(resource)
				if resource.ID == "b" && count == 2 {
					if identityChanged {
						observation.ID = f07GroupID
					} else {
						observation.Fingerprint = "after"
					}
				}
				return observation, nil
			}
			report, err := blueprint.Apply(context.Background(), document, backend)
			if !errors.Is(err, blueprint.ErrConflict) || !errors.Is(err, blueprint.ErrPartial) || backend.writes != 1 || !reflect.DeepEqual(f07Statuses(report), []string{"created", "conflict", "not_started"}) {
				t.Error("an equal replacement or changed prerequisite was silently adopted after a creation")
			}
			if report.Items[1].Reason != "stale_state" || backend.inspections["c"] != 1 {
				t.Error("stale-state conflict lost its reason or continued execution")
			}
			f07RequirePrivate(t, report, err)
		})
	}
}
