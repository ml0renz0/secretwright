package blueprint_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ml0renz0/secretwright/internal/blueprint"
	"github.com/ml0renz0/secretwright/internal/managedstate"
	"github.com/ml0renz0/secretwright/internal/vault"
)

func f09Hash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func f09Target() managedstate.Target {
	return managedstate.Target{AddressSHA256: f09Hash("fixture-address"), ClusterID: "99999999-9999-4999-8999-999999999999", Namespace: "team"}
}

func f09Clone(state managedstate.State) managedstate.State {
	state.Resources = append([]managedstate.Record{}, state.Resources...)
	return state
}

type f09Sink struct {
	t       *testing.T
	state   managedstate.State
	saved   []managedstate.State
	events  *[]string
	fail    func(int, managedstate.State) error
}

func (sink *f09Sink) Snapshot() managedstate.State { return f09Clone(sink.state) }

func (sink *f09Sink) Save(state managedstate.State) error {
	sink.t.Helper()
	if managedstate.Validate(state) != nil || state.Revision != sink.state.Revision+1 || state.Blueprint != sink.state.Blueprint || state.Target != sink.state.Target {
		sink.t.Fatal("managed engine attempted an invalid or unbound checkpoint")
	}
	if sink.events != nil {
		*sink.events = append(*sink.events, "save")
	}
	if sink.fail != nil {
		if err := sink.fail(len(sink.saved)+1, f09Clone(state)); err != nil {
			return err
		}
	}
	sink.saved = append(sink.saved, f09Clone(state))
	sink.state = f09Clone(state)
	return nil
}

type f09Backend struct {
	states      map[string]blueprint.Observation
	inspections map[string]int
	events      []string
	writes      int
	inspect     func(context.Context, blueprint.Resource, map[string]string, int) (blueprint.Observation, error)
	mutate      func(context.Context, blueprint.Resource, map[string]string, string, blueprint.Observation) (blueprint.Observation, error)
}

func f09NewBackend() *f09Backend {
	return &f09Backend{states: make(map[string]blueprint.Observation), inspections: make(map[string]int)}
}

func f09Observed(id, kind, fingerprint string, equal bool) blueprint.Observation {
	result := blueprint.Observation{Exists: true, Equal: equal, Fingerprint: f09Hash(fingerprint), Guard: f09Hash(fingerprint)}
	switch kind {
	case "entity":
		result.ID = f07EntityID
	case "group":
		result.ID = f07GroupID
	case "kv_mount":
		result.ID = "kv_fixture_accessor"
	}
	if kind != "policy" {
		result.Identity = f09Hash("identity:" + id)
	}
	return result
}

func (backend *f09Backend) current(resource blueprint.Resource) blueprint.Observation {
	if current, ok := backend.states[resource.ID]; ok {
		return current
	}
	return blueprint.Observation{Fingerprint: f09Hash("absent:" + resource.ID), Guard: f09Hash("absent:" + resource.ID)}
}

func (backend *f09Backend) Inspect(ctx context.Context, resource blueprint.Resource, ids map[string]string) (blueprint.Observation, error) {
	backend.inspections[resource.ID]++
	backend.events = append(backend.events, "inspect:"+resource.ID)
	if backend.inspect != nil {
		return backend.inspect(ctx, resource, ids, backend.inspections[resource.ID])
	}
	return backend.current(resource), nil
}

func (backend *f09Backend) Create(ctx context.Context, resource blueprint.Resource, ids map[string]string) (blueprint.Observation, error) {
	return backend.write(ctx, resource, ids, "create", blueprint.Observation{})
}

func (backend *f09Backend) Update(ctx context.Context, resource blueprint.Resource, ids map[string]string, expected blueprint.Observation) (blueprint.Observation, error) {
	return backend.write(ctx, resource, ids, "update", expected)
}

func (backend *f09Backend) write(ctx context.Context, resource blueprint.Resource, ids map[string]string, operation string, expected blueprint.Observation) (blueprint.Observation, error) {
	backend.writes++
	backend.events = append(backend.events, operation+":"+resource.ID)
	if backend.mutate != nil {
		return backend.mutate(ctx, resource, ids, operation, expected)
	}
	current := f09Observed(resource.ID, resource.Kind, "desired:"+resource.ID, true)
	backend.states[resource.ID] = current
	return current, nil
}

func f09Record(resource blueprint.Resource, observation blueprint.Observation) managedstate.Record {
	auth, _ := resource.Spec["auth_mount"].(string)
	return managedstate.Record{ID: resource.ID, Kind: resource.Kind, Name: resource.Name, AuthMount: auth, RemoteID: observation.ID, IdentitySHA256: observation.Identity, Fingerprint: observation.Fingerprint}
}

func f09State(t *testing.T, document blueprint.Document, backend *f09Backend) managedstate.State {
	t.Helper()
	state := managedstate.State{APIVersion: managedstate.APIVersion, Blueprint: document.Name, Target: f09Target(), Revision: 1, Resources: []managedstate.Record{}}
	for _, resource := range document.Resources {
		observation := backend.current(resource)
		if observation.Exists {
			state.Resources = append(state.Resources, f09Record(resource, observation))
		}
	}
	if managedstate.Validate(state) != nil {
		t.Fatal("could not prepare the managed state fixture")
	}
	return state
}

func f09Actions(plan blueprint.ManagedPlan) map[string]string {
	result := make(map[string]string)
	for _, resource := range plan.Resources {
		result[resource.ID] = resource.Action
	}
	return result
}

func f09Statuses(report blueprint.ManagedReport) map[string]string {
	result := make(map[string]string)
	for _, resource := range report.Items {
		result[resource.ID] = resource.Status
	}
	return result
}

func f09Safe(t *testing.T, values ...any) {
	t.Helper()
	for _, value := range values {
		var body []byte
		if err, ok := value.(error); ok {
			if err == nil {
				continue
			}
			body = []byte(err.Error())
		} else {
			var err error
			body, err = json.Marshal(value)
			if err != nil {
				t.Fatal("could not encode reconciliation metadata")
			}
		}
		for _, private := range []string{"private-f09-", "capabilities =", `"spec"`, `"observations"`, `"baseline_sha256"`, `"identity_sha256"`} {
			if strings.Contains(string(body), private) {
				t.Fatal("reconciliation report or error exposed transient input or fingerprints")
			}
		}
	}
}

func TestManagedAdoptionIsExplicitReadOnlyAndSkipsAbsentResources(t *testing.T) {
	document := f07LoadDocument(t, f07PolicyResource("a"), f07PolicyResource("b"))
	backend := f09NewBackend()
	backend.states["a"] = f09Observed("a", "policy", "baseline:a", true)
	state, report, err := blueprint.Adopt(context.Background(), document, backend, f09Target())
	if err != nil || backend.writes != 0 || len(state.Resources) != 1 || state.Resources[0].ID != "a" || state.Revision != 1 || state.Target != f09Target() {
		t.Fatal("explicit adoption mutated Vault or claimed an absent resource")
	}
	if managedstate.Validate(state) != nil {
		t.Fatal("adoption did not produce a valid bounded state")
	}
	f09Safe(t, report, err)
	backend.states["a"] = f09Observed("a", "policy", "different", false)
	state, report, err = blueprint.Adopt(context.Background(), document, backend, f09Target())
	if !errors.Is(err, blueprint.ErrConflict) || len(state.Resources) != 0 || backend.writes != 0 {
		t.Fatal("adoption accepted a differing existing resource or returned a partial ownership ledger")
	}
	backend = f09NewBackend()
	state, _, err = blueprint.Adopt(context.Background(), document, backend, f09Target())
	if err != nil || state.Resources == nil || len(state.Resources) != 0 || managedstate.Validate(state) != nil {
		t.Error("clean-server adoption could not initialize an empty inventory")
	}
}

func TestManagedPlanSeparatesIntentDriftRefreshAndExternalResources(t *testing.T) {
	for _, mode := range []string{"unchanged", "desired", "drift", "already-desired", "external"} {
		t.Run(mode, func(t *testing.T) {
			document := f07LoadDocument(t, f07PolicyResource("a"))
			backend := f09NewBackend()
			backend.states["a"] = f09Observed("a", "policy", "baseline", true)
			state := f09State(t, document, backend)
			observation := backend.states["a"]
			switch mode {
			case "desired":
				observation.Equal = false
			case "drift", "already-desired":
				observation.Fingerprint, observation.Guard = f09Hash("external-change"), f09Hash("external-change")
				observation.Equal = mode == "already-desired"
			case "external":
				state.Resources = []managedstate.Record{}
			}
			backend.states["a"] = observation
			plan, err := blueprint.BuildManagedPlan(context.Background(), document, backend, state, f09Target(), false)
			want := "noop"
			if mode == "desired" {
				want = "update"
			} else if mode == "drift" || mode == "already-desired" {
				want = "drift"
				if !errors.Is(err, blueprint.ErrConflict) || !plan.Resources[0].Drift {
					t.Error("external drift did not require explicit repair")
				}
			} else if err != nil {
				t.Fatal("unchanged or external equivalent resource was rejected")
			}
			if f09Actions(plan)["a"] != want || backend.writes != 0 {
				t.Error("managed planning misclassified intent, drift or an external resource")
			}
			if mode == "external" && plan.Resources[0].Managed {
				t.Error("an equivalent external resource was silently adopted")
			}
			if mode == "drift" || mode == "already-desired" {
				repaired, repairErr := blueprint.BuildManagedPlan(context.Background(), document, backend, state, f09Target(), true)
				want = "update"
				if mode == "already-desired" {
					want = "refresh"
				}
				if repairErr != nil || f09Actions(repaired)["a"] != want || !repaired.Resources[0].Drift {
					t.Error("explicit repair did not distinguish resource updates from state-only refresh")
				}
				f09Safe(t, repaired, repairErr)
			}
			f09Safe(t, plan, err)
		})
	}
}

func TestManagedConflictsNeverCheckpointAndOmittedResourcesAreRetained(t *testing.T) {
	document := f07LoadDocument(t, f07PolicyResource("a"), f07PolicyResource("b"))
	backend := f09NewBackend()
	for _, resource := range document.Resources {
		backend.states[resource.ID] = f09Observed(resource.ID, resource.Kind, "baseline:"+resource.ID, true)
	}
	state := f09State(t, document, backend)
	onlyA := f07LoadDocument(t, f07PolicyResource("a"))
	plan, err := blueprint.BuildManagedPlan(context.Background(), onlyA, backend, state, f09Target(), false)
	if err != nil || f09Actions(plan)["b"] != "retain" || len(plan.Changes) != 0 || backend.inspections["b"] != 0 {
		t.Fatal("omitted owned resource was deleted, inspected as desired or treated as a mutation")
	}
	sink := &f09Sink{t: t, state: state}
	report, err := blueprint.ApplyManaged(context.Background(), onlyA, backend, sink, f09Target(), false)
	if err != nil || len(sink.saved) != 0 || backend.writes != 0 || f09Statuses(report)["b"] != "retained" || !reflect.DeepEqual(sink.state, state) {
		t.Error("unchanged/retained apply changed the inventory or Vault")
	}
	for _, mismatch := range []string{"target", "pending", "missing", "locator"} {
		t.Run(mismatch, func(t *testing.T) {
			changed := f09Clone(state)
			target := f09Target()
			candidate := f09NewBackend()
			candidate.states["a"], candidate.states["b"] = backend.states["a"], backend.states["b"]
			switch mismatch {
			case "target":
				target.Namespace = "other-team"
			case "pending":
				changed.Resources[1].Pending = "update"
			case "missing":
				delete(candidate.states, "a")
			case "locator":
				changed.Resources[0].Name = "app-previous-name"
			}
			sink := &f09Sink{t: t, state: changed}
			_, err := blueprint.ApplyManaged(context.Background(), document, candidate, sink, target, true)
			if !errors.Is(err, blueprint.ErrConflict) || candidate.writes != 0 || len(sink.saved) != 0 {
				t.Error("unsafe managed preflight performed a mutation or checkpoint")
			}
		})
	}
}

func TestManagedMutationIsBracketedByDurablePendingAndConfirmedCheckpoints(t *testing.T) {
	for _, operation := range []string{"create", "update"} {
		t.Run(operation, func(t *testing.T) {
			document := f07LoadDocument(t, f07PolicyResource("a"))
			backend := f09NewBackend()
			if operation == "update" {
				backend.states["a"] = f09Observed("a", "policy", "baseline", false)
			}
			sink := &f09Sink{t: t, state: f09State(t, document, backend), events: &backend.events}
			backend.mutate = func(ctx context.Context, resource blueprint.Resource, ids map[string]string, actual string, expected blueprint.Observation) (blueprint.Observation, error) {
				if actual != operation || len(sink.saved) != 1 || len(sink.state.Resources) != 1 || sink.state.Resources[0].Pending != operation {
					t.Fatal("Vault mutation started before its durable pending checkpoint")
				}
				if operation == "update" && expected.Fingerprint != f09Hash("baseline") {
					t.Error("update did not receive the latest checked server observation")
				}
				result := f09Observed(resource.ID, resource.Kind, "confirmed", true)
				backend.states[resource.ID] = result
				return result, nil
			}
			report, err := blueprint.ApplyManaged(context.Background(), document, backend, sink, f09Target(), false)
			want := "created"
			if operation == "update" {
				want = "updated"
			}
			if err != nil || backend.writes != 1 || len(sink.saved) != 2 || sink.state.Resources[0].Pending != "" || sink.state.Resources[0].Fingerprint != f09Hash("confirmed") || f09Statuses(report)["a"] != want {
				t.Fatal("confirmed mutation did not advance and clear its pending inventory record")
			}
			plan, err := blueprint.BuildManagedPlan(context.Background(), document, backend, sink.Snapshot(), f09Target(), false)
			if err != nil || len(plan.Changes) != 0 {
				t.Error("a confirmed managed application did not become an empty plan")
			}
			f09Safe(t, plan, report, err)
		})
	}
}

func TestManagedCheckpointAndDefinitiveMutationFailuresStopWithoutFurtherWrites(t *testing.T) {
	for _, failure := range []string{"before-write", "after-write", "permission", "permission-restore-fails"} {
		t.Run(failure, func(t *testing.T) {
			document := f07LoadDocument(t, f07PolicyResource("a"), f07PolicyResource("b"))
			backend := f09NewBackend()
			sink := &f09Sink{t: t, state: f09State(t, document, backend)}
			sink.fail = func(call int, state managedstate.State) error {
				if (failure == "before-write" && call == 1) || ((failure == "after-write" || failure == "permission-restore-fails") && call == 2) {
					return managedstate.ErrStateIO
				}
				return nil
			}
			if strings.HasPrefix(failure, "permission") {
				backend.mutate = func(context.Context, blueprint.Resource, map[string]string, string, blueprint.Observation) (blueprint.Observation, error) {
					return blueprint.Observation{}, vault.ErrPermissionDenied
				}
			}
			report, err := blueprint.ApplyManaged(context.Background(), document, backend, sink, f09Target(), false)
			wantWrites := 1
			if failure == "before-write" {
				wantWrites = 0
			}
			if err == nil || backend.writes != wantWrites || f09Statuses(report)["b"] != "not_started" {
				t.Fatal("checkpoint or mutation failure allowed a later resource to start")
			}
			if failure == "permission" {
				if !errors.Is(err, vault.ErrPermissionDenied) || errors.Is(err, blueprint.ErrPartial) || len(sink.state.Resources) != 0 || len(sink.saved) != 2 {
					t.Error("definitive denial did not restore the previous inventory and preserve its typed error")
				}
			} else if failure != "before-write" {
				if !errors.Is(err, blueprint.ErrPartial) || len(sink.state.Resources) != 1 || sink.state.Resources[0].Pending != "create" {
					t.Error("failed confirmation discarded an uncertain or durable pending write")
				}
			}
			f09Safe(t, report, err)
		})
	}
}

func TestManagedUncertainCreationRequiresExplicitRecoveryAdoptionWithoutReplay(t *testing.T) {
	document := f07LoadDocument(t, f07PolicyResource("a"), f07PolicyResource("b"))
	backend := f09NewBackend()
	sink := &f09Sink{t: t, state: f09State(t, document, backend)}
	backend.mutate = func(ctx context.Context, resource blueprint.Resource, ids map[string]string, operation string, expected blueprint.Observation) (blueprint.Observation, error) {
		backend.states[resource.ID] = f09Observed(resource.ID, resource.Kind, "applied-with-lost-response", true)
		return blueprint.Observation{}, fmt.Errorf("private-f09-upstream-body: %w", blueprint.ErrUnconfirmed)
	}
	report, err := blueprint.ApplyManaged(context.Background(), document, backend, sink, f09Target(), false)
	if !errors.Is(err, blueprint.ErrPartial) || backend.writes != 1 || len(sink.state.Resources) != 1 || sink.state.Resources[0].Pending != "create" || f09Statuses(report)["b"] != "not_started" {
		t.Fatal("uncertain creation lost its pending record or retried a mutation")
	}
	f09Safe(t, report, err)
	if _, err := blueprint.ApplyManaged(context.Background(), document, backend, sink, f09Target(), true); !errors.Is(err, blueprint.ErrConflict) || backend.writes != 1 {
		t.Error("ordinary repair bypassed pending uncertainty")
	}
	before := sink.Snapshot()
	if _, err := blueprint.RecoverManaged(context.Background(), document, backend, sink, f09Target(), false); !errors.Is(err, blueprint.ErrConflict) || !reflect.DeepEqual(sink.state, before) {
		t.Error("recovery silently claimed a current resource after uncertain creation")
	}
	recovered, err := blueprint.RecoverManaged(context.Background(), document, backend, sink, f09Target(), true)
	if err != nil || backend.writes != 1 || sink.state.Resources[0].Pending != "" || sink.state.Resources[0].Fingerprint != f09Hash("applied-with-lost-response") || f09Statuses(recovered)["a"] != "recovered" {
		t.Fatal("explicit recovery replayed a creation or failed to checkpoint its current result")
	}
	f09Safe(t, recovered, err)
}

func TestManagedRecoveryDistinguishesAppliedAndUnappliedUpdates(t *testing.T) {
	for _, current := range []string{"baseline", "desired", "third-party"} {
		t.Run(current, func(t *testing.T) {
			document := f07LoadDocument(t, f07PolicyResource("a"))
			backend := f09NewBackend()
			backend.states["a"] = f09Observed("a", "policy", "baseline", false)
			state := f09State(t, document, backend)
			state.Resources[0].Pending = "update"
			backend.states["a"] = f09Observed("a", "policy", current, current == "desired")
			sink := &f09Sink{t: t, state: state}
			report, err := blueprint.RecoverManaged(context.Background(), document, backend, sink, f09Target(), false)
			if current == "third-party" {
				if !errors.Is(err, blueprint.ErrConflict) || len(sink.saved) != 0 || sink.state.Resources[0].Pending != "update" {
					t.Error("recovery overwrote evidence of an unrelated current state")
				}
			} else if err != nil || len(sink.saved) != 1 || sink.state.Resources[0].Pending != "" || sink.state.Resources[0].Fingerprint != f09Hash(current) {
				t.Error("recovery did not distinguish an unapplied update from its confirmed desired result")
			}
			if backend.writes != 0 {
				t.Error("read-only recovery replayed a Vault mutation")
			}
			f09Safe(t, report, err)
		})
	}
}

func TestManagedApplyRejectsStaleIdentityAndGuardBeforeWriting(t *testing.T) {
	for _, change := range []string{"identity", "guard", "fingerprint"} {
		t.Run(change, func(t *testing.T) {
			document := f07LoadDocument(t, map[string]any{"id": "a", "kind": "entity", "name": "app-a", "spec": map[string]any{}})
			backend := f09NewBackend()
			backend.states["a"] = f09Observed("a", "entity", "baseline", false)
			sink := &f09Sink{t: t, state: f09State(t, document, backend)}
			backend.inspect = func(ctx context.Context, resource blueprint.Resource, ids map[string]string, count int) (blueprint.Observation, error) {
				observation := backend.current(resource)
				if count == 2 {
					switch change {
					case "identity":
						observation.ID, observation.Identity = f07GroupID, f09Hash("replacement")
					case "guard":
						observation.Guard = f09Hash("new-private-preserved-data")
					case "fingerprint":
						observation.Fingerprint = f09Hash("new-concurrent-managed-fields")
					}
				}
				return observation, nil
			}
			_, err := blueprint.ApplyManaged(context.Background(), document, backend, sink, f09Target(), false)
			if !errors.Is(err, blueprint.ErrConflict) || backend.writes != 0 || len(sink.saved) != 0 {
				t.Error("a stale server identity or preserved field was overwritten after preflight")
			}
		})
	}
}

func TestManagedGroupUpdateResolvesNewlyCreatedIdentityWithoutFalseDrift(t *testing.T) {
	document := f07LoadDocument(t,
		map[string]any{"id": "owner", "kind": "entity", "name": "app-owner", "spec": map[string]any{}},
		map[string]any{"id": "team", "kind": "group", "name": "app-team", "spec": map[string]any{"member_entities": []string{"owner"}}},
	)
	backend := f09NewBackend()
	backend.states["team"] = f09Observed("team", "group", "baseline-team", false)
	sink := &f09Sink{t: t, state: f09State(t, document, backend)}
	backend.inspect = func(ctx context.Context, resource blueprint.Resource, ids map[string]string, count int) (blueprint.Observation, error) {
		observation := backend.current(resource)
		if resource.ID == "team" && ids["owner"] == "" {
			observation.Conflict = "unresolved_reference"
		}
		return observation, nil
	}
	backend.mutate = func(ctx context.Context, resource blueprint.Resource, ids map[string]string, operation string, expected blueprint.Observation) (blueprint.Observation, error) {
		if resource.ID == "team" && (operation != "update" || ids["owner"] != f07EntityID) {
			t.Fatal("managed group update did not resolve the preceding newly created entity UUID")
		}
		observation := f09Observed(resource.ID, resource.Kind, "desired:"+resource.ID, true)
		backend.states[resource.ID] = observation
		return observation, nil
	}
	report, err := blueprint.ApplyManaged(context.Background(), document, backend, sink, f09Target(), false)
	if err != nil || backend.writes != 2 || !reflect.DeepEqual(f09Statuses(report), map[string]string{"owner": "created", "team": "updated"}) || len(sink.saved) != 4 {
		t.Fatal("an owned group could not add a new identity in one safely checkpointed application")
	}
}

func TestManagedCancellationAfterAConfirmedWriteRetainsItsCheckpoint(t *testing.T) {
	document := f07LoadDocument(t, f07PolicyResource("a"), f07PolicyResource("b"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend := f09NewBackend()
	sink := &f09Sink{t: t, state: f09State(t, document, backend)}
	backend.mutate = func(context.Context, blueprint.Resource, map[string]string, string, blueprint.Observation) (blueprint.Observation, error) {
		cancel()
		return f09Observed("a", "policy", "confirmed", true), nil
	}
	report, err := blueprint.ApplyManaged(ctx, document, backend, sink, f09Target(), false)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, blueprint.ErrPartial) || backend.writes != 1 || len(sink.saved) != 2 || sink.state.Resources[0].Pending != "" || f09Statuses(report)["b"] != "not_started" {
		t.Fatal("cancellation lost a confirmed checkpoint or allowed another write")
	}
}

func TestManagedGroupCannotTrustAnUnownedIdentityOrReuseARetainedLocator(t *testing.T) {
	document := f07LoadDocument(t,
		map[string]any{"id": "owner", "kind": "entity", "name": "app-owner", "spec": map[string]any{}},
		map[string]any{"id": "team", "kind": "group", "name": "app-team", "spec": map[string]any{"member_entities": []string{"owner"}}},
	)
	backend := f09NewBackend()
	backend.states["owner"] = f09Observed("owner", "entity", "owner", true)
	backend.states["team"] = f09Observed("team", "group", "team", true)
	state := f09State(t, document, backend)
	for _, record := range state.Resources {
		if record.ID == "team" {
			state.Resources = []managedstate.Record{record}
			break
		}
	}
	sink := &f09Sink{t: t, state: state}
	if _, err := blueprint.ApplyManaged(context.Background(), document, backend, sink, f09Target(), true); !errors.Is(err, blueprint.ErrConflict) || backend.writes != 0 || len(sink.saved) != 0 {
		t.Error("owned group trusted an equivalent external identity without managed identity proof")
	}
	oldDocument := f07LoadDocument(t, f07PolicyResource("old"))
	backend = f09NewBackend()
	backend.states["old"] = f09Observed("old", "policy", "baseline", true)
	state = f09State(t, oldDocument, backend)
	replacement := f07PolicyResource("new")
	replacement["name"] = "app-old"
	document = f07LoadDocument(t, replacement)
	backend.states["new"] = backend.states["old"]
	sink = &f09Sink{t: t, state: state}
	if _, err := blueprint.ApplyManaged(context.Background(), document, backend, sink, f09Target(), true); !errors.Is(err, blueprint.ErrConflict) || backend.writes != 0 || len(sink.saved) != 0 {
		t.Error("a new logical ID silently reused a locator retained by an older owned resource")
	}
}

func TestManagedRepairNeverConvertsAnOwnedKVMount(t *testing.T) {
	document := f07LoadDocument(t, map[string]any{"id": "storage", "kind": "kv_mount", "name": "application", "spec": map[string]any{"version": 1}})
	backend := f09NewBackend()
	backend.states["storage"] = f09Observed("storage", "kv_mount", "existing-version-two", false)
	sink := &f09Sink{t: t, state: f09State(t, document, backend)}
	if _, err := blueprint.ApplyManaged(context.Background(), document, backend, sink, f09Target(), true); !errors.Is(err, blueprint.ErrConflict) || backend.writes != 0 || len(sink.saved) != 0 {
		t.Fatal("managed repair converted or rewrote an existing KV engine")
	}
}
