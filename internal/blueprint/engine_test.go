package blueprint_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/blueprint"
	"github.com/ml0renz0/secretwright/internal/vault"
)

const (
	f07EntityID = "11111111-1111-4111-8111-111111111111"
	f07GroupID  = "22222222-2222-4222-8222-222222222222"
)

type f07Backend struct {
	states      map[string]blueprint.Observation
	inspections map[string]int
	events      []string
	writes      int
	inspect     func(context.Context, blueprint.Resource, map[string]string, int) (blueprint.Observation, error)
	create      func(context.Context, blueprint.Resource, map[string]string) (blueprint.Observation, error)
}

func f07NewBackend() *f07Backend {
	return &f07Backend{states: make(map[string]blueprint.Observation), inspections: make(map[string]int)}
}

func (backend *f07Backend) Inspect(ctx context.Context, resource blueprint.Resource, ids map[string]string) (blueprint.Observation, error) {
	backend.inspections[resource.ID]++
	backend.events = append(backend.events, "inspect:"+resource.ID)
	if backend.inspect != nil {
		return backend.inspect(ctx, resource, ids, backend.inspections[resource.ID])
	}
	return backend.current(resource), nil
}

func (backend *f07Backend) current(resource blueprint.Resource) blueprint.Observation {
	if state, present := backend.states[resource.ID]; present {
		return state
	}
	return blueprint.Observation{Fingerprint: "absent-" + resource.ID}
}

func (backend *f07Backend) Create(ctx context.Context, resource blueprint.Resource, ids map[string]string) (blueprint.Observation, error) {
	backend.writes++
	backend.events = append(backend.events, "create:"+resource.ID)
	if backend.create != nil {
		return backend.create(ctx, resource, ids)
	}
	state := blueprint.Observation{Exists: true, Equal: true, Fingerprint: "current-" + resource.ID}
	if resource.Kind == "entity" {
		state.ID = f07EntityID
	} else if resource.Kind == "group" {
		state.ID = f07GroupID
	}
	backend.states[resource.ID] = state
	return state, nil
}

func f07Statuses(report blueprint.ApplyReport) []string {
	values := make([]string, 0, len(report.Items))
	for _, item := range report.Items {
		values = append(values, item.Status)
	}
	return values
}

func TestPlanInspectsEverythingAndApplyDoesNotWriteOnAnyConflict(t *testing.T) {
	document := f07LoadDocument(t, f07PolicyResource("c"), f07PolicyResource("b"), f07PolicyResource("a"))
	backend := f07NewBackend()
	backend.states["b"] = blueprint.Observation{Exists: true, Fingerprint: "private-f07-observed-policy"}
	backend.states["c"] = blueprint.Observation{Exists: true, Equal: true, Fingerprint: "same"}
	plan, err := blueprint.BuildPlan(context.Background(), document, backend)
	if !errors.Is(err, blueprint.ErrConflict) || len(plan.Resources) != 3 || len(plan.Changes) != 2 || backend.writes != 0 {
		t.Fatal("plan omitted a conflict or performed a mutation")
	}
	if !reflect.DeepEqual(backend.events, []string{"inspect:a", "inspect:b", "inspect:c"}) || plan.Resources[0].Action != "create" || plan.Resources[1].Action != "conflict" || plan.Resources[2].Action != "noop" {
		t.Error("plan did not finish inspection in deterministic dependency order")
	}
	report, err := blueprint.Apply(context.Background(), document, backend)
	if !errors.Is(err, blueprint.ErrConflict) || backend.writes != 0 || !reflect.DeepEqual(f07Statuses(report), []string{"not_started", "conflict", "unchanged"}) {
		t.Error("apply started a creation despite a complete preflight conflict")
	}
	f07RequirePrivate(t, plan, report, err)
}

func TestApplyResolvesCreatedEntityReferencesAndBecomesAnEmptyPlan(t *testing.T) {
	document := f07LoadDocument(t,
		map[string]any{"id": "team", "kind": "group", "name": "app-team", "spec": map[string]any{"member_entities": []string{"owner"}}},
		map[string]any{"id": "owner", "kind": "entity", "name": "app-owner", "spec": map[string]any{}},
	)
	backend := f07NewBackend()
	sawResolvedID := false
	backend.inspect = func(ctx context.Context, resource blueprint.Resource, ids map[string]string, count int) (blueprint.Observation, error) {
		if resource.ID == "team" && count == 1 && ids["owner"] != "" {
			t.Error("preflight guessed an ID for an entity that does not exist")
		}
		if resource.ID == "team" && count == 2 {
			sawResolvedID = ids["owner"] == f07EntityID
		}
		return backend.current(resource), nil
	}
	report, err := blueprint.Apply(context.Background(), document, backend)
	if err != nil || backend.writes != 2 || !sawResolvedID || !reflect.DeepEqual(f07Statuses(report), []string{"created", "created"}) {
		t.Fatal("apply failed to resolve newly created IDs in dependency order")
	}
	if report.Items[0].RemoteID != f07EntityID || report.Items[1].RemoteID != f07GroupID {
		t.Error("apply omitted the confirmed remote identity metadata")
	}
	backend.inspect = nil
	plan, err := blueprint.BuildPlan(context.Background(), document, backend)
	if err != nil || plan.Changes == nil || len(plan.Changes) != 0 || len(plan.Resources) != 2 || backend.writes != 2 {
		t.Error("a successfully applied blueprint did not produce an empty changes array")
	}
	if _, err := blueprint.Apply(context.Background(), document, backend); err != nil || backend.writes != 2 {
		t.Error("an idempotent apply created or updated an existing equivalent resource")
	}
	f07RequirePrivate(t, report, plan)
}

func TestApplyRejectsStaleAbsentAndNoopObservationsBeforeWriting(t *testing.T) {
	document := f07LoadDocument(t, f07PolicyResource("read"))
	for _, existing := range []bool{false, true} {
		backend := f07NewBackend()
		backend.inspect = func(ctx context.Context, resource blueprint.Resource, ids map[string]string, count int) (blueprint.Observation, error) {
			state := blueprint.Observation{Exists: existing, Equal: existing, Fingerprint: "same"}
			if count == 2 {
				if existing {
					state.Equal = false
				} else {
					state.Exists, state.Equal, state.Fingerprint = true, true, "changed"
				}
			}
			return state, nil
		}
		report, err := blueprint.Apply(context.Background(), document, backend)
		if !errors.Is(err, blueprint.ErrConflict) || errors.Is(err, blueprint.ErrPartial) || backend.writes != 0 || !reflect.DeepEqual(f07Statuses(report), []string{"conflict"}) {
			t.Error("apply adopted a concurrently created target or trusted a stale noop")
		}
	}
}

func TestApplyStopsAfterConfirmedOrUnconfirmedPartialOutcomes(t *testing.T) {
	document := f07LoadDocument(t, f07PolicyResource("a"), f07PolicyResource("b"), f07PolicyResource("c"))
	for _, unknown := range []bool{false, true} {
		backend := f07NewBackend()
		backend.create = func(ctx context.Context, resource blueprint.Resource, ids map[string]string) (blueprint.Observation, error) {
			if resource.ID == "a" && !unknown {
				return blueprint.Observation{Exists: true, Equal: true, Fingerprint: "created-a"}, nil
			}
			if unknown {
				return blueprint.Observation{}, fmt.Errorf("%w: private-f07-upstream", blueprint.ErrUnconfirmed)
			}
			return blueprint.Observation{}, fmt.Errorf("%w: private-f07-upstream", vault.ErrPermissionDenied)
		}
		report, err := blueprint.Apply(context.Background(), document, backend)
		want, writes := []string{"created", "failed", "not_started"}, 2
		if unknown {
			want, writes = []string{"unconfirmed", "not_started", "not_started"}, 1
		}
		if !errors.Is(err, blueprint.ErrPartial) || backend.writes != writes || !reflect.DeepEqual(f07Statuses(report), want) {
			t.Error("apply retried an uncertain write, rolled back, or continued after failure")
		}
		f07RequirePrivate(t, report, err)
	}
	backend := f07NewBackend()
	backend.create = func(context.Context, blueprint.Resource, map[string]string) (blueprint.Observation, error) {
		return blueprint.Observation{Exists: true, Equal: false}, nil
	}
	if report, err := blueprint.Apply(context.Background(), document, backend); !errors.Is(err, blueprint.ErrPartial) || backend.writes != 1 || report.Items[0].Status != "unconfirmed" {
		t.Error("apply treated an unverified post-write observation as success")
	}
}

func TestPlanningFailureAndInvalidConstructedDocumentNeverMutate(t *testing.T) {
	document := f07LoadDocument(t, f07PolicyResource("a"), f07PolicyResource("b"))
	backend := f07NewBackend()
	backend.inspect = func(ctx context.Context, resource blueprint.Resource, ids map[string]string, count int) (blueprint.Observation, error) {
		if resource.ID == "b" {
			return blueprint.Observation{}, fmt.Errorf("%w: private-f07-server", vault.ErrPermissionDenied)
		}
		return backend.current(resource), nil
	}
	plan, err := blueprint.BuildPlan(context.Background(), document, backend)
	if !errors.Is(err, vault.ErrPermissionDenied) || len(plan.Resources) != 0 || backend.writes != 0 {
		t.Error("a denied inspection was omitted or exposed as a complete plan")
	}
	report, err := blueprint.Apply(context.Background(), document, backend)
	if !errors.Is(err, vault.ErrPermissionDenied) || len(report.Items) != 0 || backend.writes != 0 {
		t.Error("a failed preflight already started a mutation")
	}
	f07RequirePrivate(t, plan, report, err)
	document.Resources[0].Spec["credential"] = "private-f07-untrusted-constructed-spec"
	backend = f07NewBackend()
	if _, err := blueprint.Apply(context.Background(), document, backend); !errors.Is(err, blueprint.ErrInvalidBlueprint) || len(backend.events) != 0 {
		t.Error("a constructed document bypassed schema validation before backend calls")
	}
}

func TestBlueprintReportsExcludeTransientObservationsAndBackendDiagnostics(t *testing.T) {
	document := f07LoadDocument(t, f07PolicyResource("read"))
	backend := f07NewBackend()
	backend.states["read"] = blueprint.Observation{Exists: true, Fingerprint: "private-f07-observation", Conflict: "private-f07-diagnostic"}
	plan, err := blueprint.BuildPlan(context.Background(), document, backend)
	if !errors.Is(err, blueprint.ErrConflict) {
		t.Fatal("conflicting backend fixture was not rejected")
	}
	f07RequirePrivate(t, plan, err, backend.states["read"])
	if encoded, _ := json.Marshal(backend.states["read"]); string(encoded) != "{}" {
		t.Error("transient observations can be serialized into state")
	}
	backend.inspect = func(context.Context, blueprint.Resource, map[string]string, int) (blueprint.Observation, error) {
		return blueprint.Observation{}, errors.New("private-f07-untrusted-backend-body")
	}
	if _, err := blueprint.BuildPlan(context.Background(), document, backend); err == nil {
		t.Error("backend transport failure was ignored")
	} else {
		f07RequirePrivate(t, err)
	}
}

func TestBlueprintHonorsTheProvidedWholeOperationDeadlineAndCancellation(t *testing.T) {
	document := f07LoadDocument(t, f07PolicyResource("read"))
	backend := f07NewBackend()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := blueprint.Apply(ctx, document, backend); !errors.Is(err, context.Canceled) || len(backend.events) != 0 {
		t.Error("canceled blueprint operation contacted its backend")
	}
	backend.inspect = func(ctx context.Context, resource blueprint.Resource, ids map[string]string, count int) (blueprint.Observation, error) {
		<-ctx.Done()
		return blueprint.Observation{}, ctx.Err()
	}
	ctx, cancel = context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := blueprint.BuildPlan(ctx, document, backend); !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 2*time.Second || backend.writes != 0 {
		t.Error("blueprint inspection did not honor its overall deadline")
	}
}
