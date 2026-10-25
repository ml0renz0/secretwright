package blueprint

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"

	"github.com/ml0renz0/secretwright/internal/managedstate"
)

var managedHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

func copyManagedState(state managedstate.State) managedstate.State {
	state.Resources = append([]managedstate.Record{}, state.Resources...)
	return state
}

func managedRecord(resource Resource, observation Observation) managedstate.Record {
	auth, _ := resource.Spec["auth_mount"].(string)
	return managedstate.Record{
		ID: resource.ID, Kind: resource.Kind, Name: resource.Name, AuthMount: auth,
		RemoteID: observation.ID, IdentitySHA256: observation.Identity, Fingerprint: observation.Fingerprint,
	}
}

func managedLocator(kind, name, auth string) string {
	return kind + "\x00" + auth + "\x00" + name
}

func resourceLocator(resource Resource) string {
	auth, _ := resource.Spec["auth_mount"].(string)
	return managedLocator(resource.Kind, resource.Name, auth)
}

func recordLocator(record managedstate.Record) string {
	return managedLocator(record.Kind, record.Name, record.AuthMount)
}

func recordMap(state managedstate.State) map[string]managedstate.Record {
	result := make(map[string]managedstate.Record, len(state.Resources))
	for _, record := range state.Resources {
		result[record.ID] = record
	}
	return result
}

func validateManagedBinding(document Document, state managedstate.State, target managedstate.Target, allowPending bool) error {
	if managedstate.Validate(state) != nil {
		return managedstate.ErrInvalidState
	}
	if state.Blueprint != document.Name || state.Target != target {
		return ErrStateConflict
	}
	locators := make(map[string]string, len(state.Resources))
	byID := recordMap(state)
	for _, record := range state.Resources {
		if !allowPending && record.Pending != "" {
			return ErrStateConflict
		}
		locators[recordLocator(record)] = record.ID
	}
	for _, resource := range document.Resources {
		locator := resourceLocator(resource)
		if record, owned := byID[resource.ID]; owned && recordLocator(record) != locator {
			return ErrStateConflict
		}
		if previousID, tracked := locators[locator]; tracked && previousID != resource.ID {
			// A new logical ID cannot claim a locator whose old ID is retained.
			return ErrStateConflict
		}
	}
	return nil
}

func sameManagedIdentity(record managedstate.Record, observation Observation) bool {
	return record.RemoteID == observation.ID && record.IdentitySHA256 == observation.Identity
}

func staleManagedObservation(previous, current Observation) bool {
	return staleObservation(previous, current) || previous.Identity != current.Identity || previous.Guard != current.Guard
}

func validManagedObservation(resource Resource, observation Observation) bool {
	if !managedHash.MatchString(observation.Fingerprint) || observation.Guard != "" && !managedHash.MatchString(observation.Guard) {
		return false
	}
	if !observation.Exists {
		return observation.ID == "" && observation.Identity == ""
	}
	if resource.Kind == "policy" {
		return observation.ID == "" && observation.Identity == ""
	}
	if !managedHash.MatchString(observation.Identity) {
		return false
	}
	return !needsRemoteID(resource) || observation.ID != ""
}

func withManagedRecord(state managedstate.State, record managedstate.Record, remove bool) managedstate.State {
	copy := state
	copy.Resources = make([]managedstate.Record, 0, len(state.Resources)+1)
	for _, existing := range state.Resources {
		if existing.ID != record.ID {
			copy.Resources = append(copy.Resources, existing)
		}
	}
	if !remove {
		copy.Resources = append(copy.Resources, record)
	}
	sort.Slice(copy.Resources, func(i, j int) bool { return copy.Resources[i].ID < copy.Resources[j].ID })
	return copy
}

func saveManagedCheckpoint(sink StateSink, current, next managedstate.State) (managedstate.State, error) {
	if current.Revision >= math.MaxInt64 {
		return current, managedstate.ErrInvalidState
	}
	next = copyManagedState(next)
	next.Revision = current.Revision + 1
	if managedstate.Validate(next) != nil {
		return current, managedstate.ErrInvalidState
	}
	if err := sink.Save(copyManagedState(next)); err != nil {
		return current, safeManagedError(err)
	}
	return next, nil
}

func safeManagedError(err error) error {
	switch {
	case errors.Is(err, managedstate.ErrStateUnconfirmed):
		return managedstate.ErrStateUnconfirmed
	case errors.Is(err, managedstate.ErrStateLocked), errors.Is(err, managedstate.ErrStateChanged), errors.Is(err, ErrStateConflict):
		return ErrStateConflict
	case errors.Is(err, managedstate.ErrInvalidState):
		return managedstate.ErrInvalidState
	case errors.Is(err, managedstate.ErrStateIO):
		return managedstate.ErrStateIO
	default:
		return safeEngineError(err)
	}
}

func managedErrorReason(err error) string {
	switch {
	case errors.Is(err, managedstate.ErrStateUnconfirmed), errors.Is(err, managedstate.ErrStateIO), errors.Is(err, managedstate.ErrInvalidState):
		return "state_persistence"
	case errors.Is(err, ErrStateConflict):
		return "state_conflict"
	default:
		return engineErrorReason(err)
	}
}

func managedOutcome(report ManagedReport, err error, changed bool) (ManagedReport, error) {
	err = safeManagedError(err)
	if changed || errors.Is(err, ErrUnconfirmed) || errors.Is(err, managedstate.ErrStateUnconfirmed) {
		return report, fmt.Errorf("%w: %w", ErrPartial, err)
	}
	return report, err
}

func failedManagedApply(report ManagedReport, index int, status string, err error, changed bool) (ManagedReport, error) {
	if errors.Is(err, ErrUnconfirmed) || errors.Is(err, managedstate.ErrStateUnconfirmed) {
		status = "unconfirmed"
	}
	report.Items[index].Status = status
	report.Items[index].Reason = managedErrorReason(err)
	return managedOutcome(report, err, changed)
}

func unconfirmedManagedApply(report ManagedReport, index int, err error) (ManagedReport, error) {
	report.Items[index].Status = "unconfirmed"
	report.Items[index].Reason = managedErrorReason(err)
	return report, fmt.Errorf("%w: %w", ErrPartial, safeManagedError(err))
}

func managedReport(plan ManagedPlan, conflicts bool) ManagedReport {
	report := ManagedReport{Blueprint: plan.Blueprint, Items: make([]ManagedItem, len(plan.Resources))}
	for i, resource := range plan.Resources {
		status := "not_started"
		switch resource.Action {
		case "retain":
			status = "retained"
		case "noop":
			if conflicts {
				status = "unchanged"
			}
		case "conflict", "drift":
			if conflicts {
				status = "conflict"
			}
		}
		report.Items[i] = ManagedItem{ID: resource.ID, Kind: resource.Kind, Name: resource.Name, Status: status, RemoteID: resource.RemoteID}
		if status == "conflict" {
			report.Items[i].Reason = resource.Reason
		}
	}
	return report
}

func managedContext(ctx context.Context) error {
	if ctx == nil {
		return errOperationFailed
	}
	return ctx.Err()
}
