package blueprint

import (
	"context"
	"errors"

	"github.com/ml0renz0/secretwright/internal/managedstate"
)

// ApplyManaged reconciles only resources authorized by the bound inventory. It
// persists a pending checkpoint before each mutation and a verified checkpoint
// afterwards; neither uncertain writes nor saved plans are replayed.
func ApplyManaged(ctx context.Context, document Document, backend ManagedBackend, sink StateSink, target managedstate.Target, repair bool) (ManagedReport, error) {
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
	if err := validateManagedBinding(document, state, target, false); err != nil {
		return ManagedReport{}, err
	}
	plan, err := buildManagedPlan(ctx, document, backend, state, repair)
	if err != nil {
		if !errors.Is(err, ErrConflict) || plan.observations == nil {
			return ManagedReport{}, err
		}
		return managedReport(plan, true), err
	}
	ordered, err := orderedResources(document)
	if err != nil {
		return ManagedReport{}, err
	}
	report := managedReport(plan, false)
	knownIDs := make(map[string]string)
	changed := false
	for index, resource := range ordered {
		if err := ctx.Err(); err != nil {
			return managedOutcome(report, err, changed)
		}
		current, err := backend.Inspect(ctx, copyResource(resource), copyRemoteIDs(knownIDs))
		if err != nil {
			return failedManagedApply(report, index, "failed", safeManagedError(err), changed)
		}
		if err := ctx.Err(); err != nil {
			return failedManagedApply(report, index, "failed", err, changed)
		}
		if !validManagedObservation(resource, current) {
			return failedManagedApply(report, index, "failed", errOperationFailed, changed)
		}
		item := plan.Resources[index]
		if staleManagedObservation(plan.observations[resource.ID], current) || current.Conflict != "" ||
			(item.Action == "noop" || item.Action == "refresh") && !current.Equal {
			report.Items[index].Status, report.Items[index].Reason = "conflict", "stale_state"
			return managedOutcome(report, ErrConflict, changed)
		}
		switch item.Action {
		case "noop":
			report.Items[index].Status = "unchanged"
			report.Items[index].RemoteID = current.ID
			rememberRemoteID(knownIDs, resource, current)
			continue
		case "refresh":
			next := withManagedRecord(state, managedRecord(resource, current), false)
			state, err = saveManagedCheckpoint(sink, state, next)
			if err != nil {
				return failedManagedApply(report, index, "failed", err, changed)
			}
			report.Items[index].Status = "refreshed"
			report.Items[index].RemoteID = current.ID
			changed = true
			rememberRemoteID(knownIDs, resource, current)
			continue
		case "create", "update":
			// The complete preflight guarantees these are the only remaining
			// actions for declared resources.
		default:
			return failedManagedApply(report, index, "conflict", ErrStateConflict, changed)
		}
		if err := ctx.Err(); err != nil {
			return failedManagedApply(report, index, "failed", err, changed)
		}
		before := copyManagedState(state)
		pending := managedRecord(resource, Observation{})
		if item.Action == "update" {
			pending = recordMap(state)[resource.ID]
		}
		pending.Pending = item.Action
		state, err = saveManagedCheckpoint(sink, state, withManagedRecord(state, pending, false))
		if err != nil {
			return failedManagedApply(report, index, "failed", err, changed)
		}
		// A local fsync may have outlived the operation budget. Clear the
		// checkpoint rather than dispatching a newly canceled mutation.
		if err := ctx.Err(); err != nil {
			var restoreErr error
			state, restoreErr = restoreManagedCheckpoint(sink, state, before)
			if restoreErr != nil {
				return unconfirmedManagedApply(report, index, restoreErr)
			}
			return failedManagedApply(report, index, "failed", err, changed)
		}
		var verified Observation
		if item.Action == "create" {
			verified, err = backend.Create(ctx, copyResource(resource), copyRemoteIDs(knownIDs))
		} else {
			verified, err = backend.Update(ctx, copyResource(resource), copyRemoteIDs(knownIDs), current)
		}
		if err != nil {
			err = safeManagedError(err)
			if errors.Is(err, ErrUnconfirmed) || errors.Is(err, managedstate.ErrStateUnconfirmed) {
				return unconfirmedManagedApply(report, index, err)
			}
			// Definitive failure did not apply the requested mutation. Restore
			// its old metadata instead of requiring recovery for a known denial.
			var restoreErr error
			state, restoreErr = restoreManagedCheckpoint(sink, state, before)
			if restoreErr != nil {
				return unconfirmedManagedApply(report, index, restoreErr)
			}
			status := "failed"
			if errors.Is(err, ErrConflict) {
				status = "conflict"
			}
			return failedManagedApply(report, index, status, err, changed)
		}
		if !validManagedObservation(resource, verified) || !verified.Exists || !verified.Equal || verified.Conflict != "" ||
			item.Action == "update" && (verified.ID != current.ID || verified.Identity != current.Identity) {
			return unconfirmedManagedApply(report, index, ErrUnconfirmed)
		}
		next := withManagedRecord(state, managedRecord(resource, verified), false)
		state, err = saveManagedCheckpoint(sink, state, next)
		if err != nil {
			return unconfirmedManagedApply(report, index, err)
		}
		report.Items[index].Status = "created"
		if item.Action == "update" {
			report.Items[index].Status = "updated"
		}
		report.Items[index].RemoteID = verified.ID
		changed = true
		rememberRemoteID(knownIDs, resource, verified)
	}
	if err := ctx.Err(); err != nil {
		return managedOutcome(report, err, changed)
	}
	return report, nil
}

func restoreManagedCheckpoint(sink StateSink, current, previous managedstate.State) (managedstate.State, error) {
	next := copyManagedState(current)
	next.Resources = append([]managedstate.Record{}, previous.Resources...)
	return saveManagedCheckpoint(sink, current, next)
}
