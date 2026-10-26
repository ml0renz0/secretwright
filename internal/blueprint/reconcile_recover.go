package blueprint

import (
	"context"
	"errors"
	"sort"

	"github.com/ml0renz0/secretwright/internal/managedstate"
)

// RecoverManaged only acknowledges inspected outcomes in the local inventory.
// It never replays a create or update. Claiming an uncertain creation requires
// the additional explicit adoptPending acknowledgement.
func RecoverManaged(ctx context.Context, document Document, backend ManagedBackend, sink StateSink, target managedstate.Target, adoptPending bool) (ManagedReport, error) {
	if err := managedContext(ctx); err != nil {
		return ManagedReport{}, err
	}
	document, err := ValidateDocument(document)
	if err != nil {
		return ManagedReport{}, ErrInvalidBlueprint
	}
	if sink == nil || backend == nil {
		return ManagedReport{}, errOperationFailed
	}
	state := copyManagedState(sink.Snapshot())
	if err := validateManagedBinding(document, state, target, true); err != nil {
		return ManagedReport{}, err
	}
	tracked := recordMap(state)
	declared := make(map[string]Resource, len(document.Resources))
	for _, resource := range document.Resources {
		declared[resource.ID] = resource
	}
	pending := 0
	for _, record := range state.Resources {
		if record.Pending == "" {
			continue
		}
		pending++
		if _, exists := declared[record.ID]; !exists {
			return ManagedReport{}, ErrStateConflict
		}
	}
	if pending == 0 {
		// This report describes recovery work only; it does not attest to the
		// current server configuration or refresh any nonpending baseline.
		report := ManagedReport{Blueprint: document.Name, Items: make([]ManagedItem, 0, len(state.Resources))}
		for _, record := range state.Resources {
			status := "unchanged"
			if _, exists := declared[record.ID]; !exists {
				status = "retained"
			}
			report.Items = append(report.Items, ManagedItem{ID: record.ID, Kind: record.Kind, Name: record.Name, RemoteID: record.RemoteID, Status: status})
		}
		return report, nil
	}
	ordered, err := orderedResources(document)
	if err != nil {
		return ManagedReport{}, err
	}
	observed := make(map[string]Observation, len(ordered))
	knownIDs := make(map[string]string)
	for _, resource := range ordered {
		if err := ctx.Err(); err != nil {
			return ManagedReport{}, err
		}
		observation, err := backend.Inspect(ctx, copyResource(resource), copyRemoteIDs(knownIDs))
		if err != nil {
			return ManagedReport{}, safeManagedError(err)
		}
		if !validManagedObservation(resource, observation) {
			return ManagedReport{}, errOperationFailed
		}
		observed[resource.ID] = observation
		rememberRemoteID(knownIDs, resource, observation)
	}
	report := ManagedReport{Blueprint: document.Name, Items: make([]ManagedItem, 0, len(ordered)+len(state.Resources))}
	next := copyManagedState(state)
	recovered := make([]int, 0, pending)
	conflict := false
	for _, resource := range ordered {
		observation := observed[resource.ID]
		record, owned := tracked[resource.ID]
		item := ManagedItem{ID: resource.ID, Kind: resource.Kind, Name: resource.Name, RemoteID: observation.ID, Status: "unchanged"}
		reason := ""
		if observation.Conflict != "" {
			reason = safeConflictReason(observation.Conflict)
		} else if owned && record.Pending != "create" && (!observation.Exists || !sameManagedIdentity(record, observation)) {
			reason = "identity_changed"
		} else if owned && resource.Kind == "group" && observation.Exists && !safeRecoveryGroupReferences(resource, tracked, observed, adoptPending) {
			reason = "unmanaged_reference"
		}
		if owned && record.Pending != "" && reason == "" {
			item.Status = "not_started"
			switch record.Pending {
			case "create":
				if !observation.Exists {
					next = withManagedRecord(next, record, true)
				} else if observation.Equal && adoptPending {
					next = withManagedRecord(next, managedRecord(resource, observation), false)
				} else {
					reason = "pending_adoption_required"
				}
			case "update":
				if observation.Fingerprint == record.Fingerprint {
					record.Pending = ""
					next = withManagedRecord(next, record, false)
				} else if observation.Equal {
					next = withManagedRecord(next, managedRecord(resource, observation), false)
				} else {
					reason = "unresolved_pending_state"
				}
			}
			if reason == "" {
				recovered = append(recovered, len(report.Items))
			}
		}
		if reason != "" {
			item.Status, item.Reason = "conflict", reason
			conflict = true
		}
		report.Items = append(report.Items, item)
	}
	retained := make([]managedstate.Record, 0, len(state.Resources))
	for _, record := range state.Resources {
		if _, exists := declared[record.ID]; !exists {
			retained = append(retained, record)
		}
	}
	sort.Slice(retained, func(i, j int) bool { return retained[i].ID < retained[j].ID })
	for _, record := range retained {
		report.Items = append(report.Items, ManagedItem{ID: record.ID, Kind: record.Kind, Name: record.Name, RemoteID: record.RemoteID, Status: "retained"})
	}
	if err := ctx.Err(); err != nil {
		return ManagedReport{}, err
	}
	if conflict {
		return report, ErrStateConflict
	}
	if _, err := saveManagedCheckpoint(sink, state, next); err != nil {
		status := "failed"
		if errors.Is(err, managedstate.ErrStateUnconfirmed) {
			status = "unconfirmed"
		} else if errors.Is(err, ErrConflict) {
			status = "conflict"
		}
		for _, index := range recovered {
			report.Items[index].Status, report.Items[index].Reason = status, managedErrorReason(err)
		}
		return managedOutcome(report, err, false)
	}
	for _, index := range recovered {
		report.Items[index].Status = "recovered"
	}
	return report, nil
}

func safeRecoveryGroupReferences(resource Resource, tracked map[string]managedstate.Record, observed map[string]Observation, adoptPending bool) bool {
	for _, field := range []string{"member_entities", "member_groups"} {
		references, _ := stringValues(resource.Spec[field])
		for _, reference := range references {
			record, owned := tracked[reference]
			current := observed[reference]
			if !owned || !current.Exists || current.Conflict != "" {
				return false
			}
			if record.Pending == "create" {
				if !adoptPending || !current.Equal {
					return false
				}
			} else if !sameManagedIdentity(record, current) {
				return false
			}
		}
	}
	return true
}
