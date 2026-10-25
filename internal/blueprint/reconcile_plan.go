package blueprint

import (
	"context"
	"math"
	"sort"

	"github.com/ml0renz0/secretwright/internal/managedstate"
)

// Adopt explicitly records matching current resources without mutating Vault.
// Missing resources remain unowned and may be created by a subsequent managed
// application. A conflict never returns a partially usable inventory.
func Adopt(ctx context.Context, document Document, backend ManagedBackend, target managedstate.Target) (managedstate.State, ManagedReport, error) {
	if err := managedContext(ctx); err != nil {
		return managedstate.State{}, ManagedReport{}, err
	}
	document, err := ValidateDocument(document)
	if err != nil {
		return managedstate.State{}, ManagedReport{}, ErrInvalidBlueprint
	}
	state := managedstate.State{APIVersion: managedstate.APIVersion, Blueprint: document.Name, Target: target, Revision: 1, Resources: []managedstate.Record{}}
	if managedstate.Validate(state) != nil || backend == nil {
		return managedstate.State{}, ManagedReport{}, managedstate.ErrInvalidState
	}
	ordered, err := orderedResources(document)
	if err != nil {
		return managedstate.State{}, ManagedReport{}, err
	}
	report := ManagedReport{Blueprint: document.Name, Items: make([]ManagedItem, 0, len(ordered))}
	knownIDs := make(map[string]string)
	conflict := false
	for _, resource := range ordered {
		if err := ctx.Err(); err != nil {
			return managedstate.State{}, ManagedReport{}, err
		}
		observation, err := backend.Inspect(ctx, copyResource(resource), copyRemoteIDs(knownIDs))
		if err != nil {
			return managedstate.State{}, ManagedReport{}, safeManagedError(err)
		}
		if !validManagedObservation(resource, observation) {
			return managedstate.State{}, ManagedReport{}, errOperationFailed
		}
		item := ManagedItem{ID: resource.ID, Kind: resource.Kind, Name: resource.Name, Status: "absent", RemoteID: observation.ID}
		if observation.Conflict != "" || observation.Exists && !observation.Equal {
			item.Status, item.Reason = "conflict", "different_configuration"
			if observation.Conflict != "" {
				item.Reason = safeConflictReason(observation.Conflict)
			}
			conflict = true
		} else if observation.Exists {
			item.Status = "adopted"
			state.Resources = append(state.Resources, managedRecord(resource, observation))
		}
		report.Items = append(report.Items, item)
		rememberRemoteID(knownIDs, resource, observation)
	}
	if err := ctx.Err(); err != nil {
		return managedstate.State{}, ManagedReport{}, err
	}
	if conflict {
		return managedstate.State{}, report, ErrConflict
	}
	sort.Slice(state.Resources, func(i, j int) bool { return state.Resources[i].ID < state.Resources[j].ID })
	if managedstate.Validate(state) != nil {
		return managedstate.State{}, ManagedReport{}, managedstate.ErrInvalidState
	}
	return state, report, nil
}

// BuildManagedPlan compares the desired configuration, current observations and
// the last confirmed local baseline. It never checkpoints or mutates Vault.
func BuildManagedPlan(ctx context.Context, document Document, backend ManagedBackend, state managedstate.State, target managedstate.Target, repair bool) (ManagedPlan, error) {
	if err := managedContext(ctx); err != nil {
		return ManagedPlan{}, err
	}
	document, err := ValidateDocument(document)
	if err != nil {
		return ManagedPlan{}, ErrInvalidBlueprint
	}
	state = copyManagedState(state)
	if err := validateManagedBinding(document, state, target, false); err != nil {
		return ManagedPlan{}, err
	}
	if backend == nil {
		return ManagedPlan{}, errOperationFailed
	}
	return buildManagedPlan(ctx, document, backend, state, repair)
}

func buildManagedPlan(ctx context.Context, document Document, backend ManagedBackend, state managedstate.State, repair bool) (ManagedPlan, error) {
	ordered, err := orderedResources(document)
	if err != nil {
		return ManagedPlan{}, err
	}
	plan := ManagedPlan{Blueprint: document.Name, Resources: make([]ManagedResourcePlan, 0, len(ordered)+len(state.Resources)), Changes: []ManagedResourcePlan{}, observations: make(map[string]Observation, len(ordered))}
	tracked := recordMap(state)
	knownIDs := make(map[string]string)
	created := make(map[string]bool)
	declared := make(map[string]bool, len(ordered))
	positions := make(map[string]int, len(ordered))
	additionalRecords := 0
	for _, resource := range ordered {
		if err := ctx.Err(); err != nil {
			return ManagedPlan{}, err
		}
		observation, err := backend.Inspect(ctx, copyResource(resource), copyRemoteIDs(knownIDs))
		if err != nil {
			return ManagedPlan{}, safeManagedError(err)
		}
		if !validManagedObservation(resource, observation) {
			return ManagedPlan{}, errOperationFailed
		}
		record, owned := tracked[resource.ID]
		item := ManagedResourcePlan{ID: resource.ID, Kind: resource.Kind, Name: resource.Name, RemoteID: observation.ID, Managed: owned}
		compatible := observation.Conflict == "" || owned && unresolvedManagedGroup(resource, observation, knownIDs, created)
		switch {
		case owned && !observation.Exists:
			item.Action, item.Reason = "conflict", "owned_missing"
		case owned && !sameManagedIdentity(record, observation):
			item.Action, item.Reason = "conflict", "identity_changed"
		case !compatible:
			item.Action, item.Reason = "conflict", safeConflictReason(observation.Conflict)
		case !owned && !observation.Exists:
			item.Action = "create"
			created[resource.ID] = true
			additionalRecords++
		case !owned && observation.Equal:
			item.Action = "noop"
		case !owned:
			item.Action, item.Reason = "conflict", "unmanaged_resource"
		default:
			item.Drift = record.Fingerprint != observation.Fingerprint
			switch {
			case resource.Kind == "kv_mount" && !observation.Equal:
				item.Action, item.Reason = "conflict", "incompatible_mount"
			case item.Drift && !repair:
				item.Action, item.Reason = "drift", "external_drift"
			case item.Drift && observation.Equal:
				item.Action, item.Reason = "refresh", "external_drift"
			case item.Drift:
				item.Action, item.Reason = "update", "external_drift"
			case observation.Equal:
				item.Action = "noop"
			default:
				item.Action, item.Reason = "update", "desired_change"
			}
		}
		plan.observations[resource.ID] = observation
		positions[resource.ID] = len(plan.Resources)
		declared[resource.ID] = true
		plan.Resources = append(plan.Resources, item)
		rememberRemoteID(knownIDs, resource, observation)
	}
	if len(state.Resources)+additionalRecords > managedstate.MaxResources {
		return ManagedPlan{}, managedstate.ErrInvalidState
	}
	// A managed membership must not follow an untracked same-name identity whose
	// UUID could later be replaced without a corresponding declaration change.
	for _, resource := range ordered {
		index := positions[resource.ID]
		item := &plan.Resources[index]
		if resource.Kind != "group" || !item.Managed && item.Action != "create" {
			continue
		}
		for _, field := range []string{"member_entities", "member_groups"} {
			references, _ := stringValues(resource.Spec[field])
			for _, reference := range references {
				target, exists := positions[reference]
				if !exists || !safeManagedReference(plan.Resources[target]) {
					item.Action, item.Reason = "conflict", "unmanaged_reference"
				}
			}
		}
	}
	retained := make([]managedstate.Record, 0, len(state.Resources))
	for _, record := range state.Resources {
		if !declared[record.ID] {
			retained = append(retained, record)
		}
	}
	sort.Slice(retained, func(i, j int) bool { return retained[i].ID < retained[j].ID })
	for _, record := range retained {
		plan.Resources = append(plan.Resources, ManagedResourcePlan{ID: record.ID, Kind: record.Kind, Name: record.Name, RemoteID: record.RemoteID, Action: "retain", Managed: true})
	}
	conflict := false
	checkpoints := uint64(0)
	for _, item := range plan.Resources {
		if item.Action != "noop" && item.Action != "retain" {
			plan.Changes = append(plan.Changes, item)
		}
		switch item.Action {
		case "create", "update":
			checkpoints += 2
		case "refresh":
			checkpoints++
		case "conflict", "drift":
			conflict = true
		}
	}
	if err := ctx.Err(); err != nil {
		return ManagedPlan{}, err
	}
	if conflict {
		return plan, ErrConflict
	}
	if state.Revision > uint64(math.MaxInt64)-checkpoints {
		return ManagedPlan{}, managedstate.ErrInvalidState
	}
	return plan, nil
}

func safeManagedReference(item ManagedResourcePlan) bool {
	return item.Action == "create" || item.Managed && item.Action != "conflict"
}

func unresolvedManagedGroup(resource Resource, observation Observation, knownIDs map[string]string, created map[string]bool) bool {
	if resource.Kind != "group" || observation.Conflict != "unresolved_reference" {
		return false
	}
	missing := false
	for _, field := range []string{"member_entities", "member_groups"} {
		references, _ := stringValues(resource.Spec[field])
		for _, reference := range references {
			if knownIDs[reference] == "" {
				missing = true
				if !created[reference] {
					return false
				}
			}
		}
	}
	return missing
}
