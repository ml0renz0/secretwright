package blueprint

import (
	"context"
	"errors"
	"fmt"

	"github.com/ml0renz0/secretwright/internal/vault"
)

// BuildPlan inspects the entire dependency graph before returning a plan. It
// never creates resources and never omits a denied or invalid observation.
func BuildPlan(ctx context.Context, document Document, backend Backend) (Plan, error) {
	if err := ctx.Err(); err != nil {
		return Plan{}, err
	}
	document, err := ValidateDocument(document)
	if err != nil {
		return Plan{}, ErrInvalidBlueprint
	}
	if backend == nil {
		return Plan{}, errOperationFailed
	}
	return buildPlan(ctx, document, backend)
}

func orderedResources(document Document) ([]Resource, error) {
	byID := make(map[string]Resource, len(document.Resources))
	for _, resource := range document.Resources {
		byID[resource.ID] = resource
	}
	ordered := make([]Resource, 0, len(document.Order))
	for _, id := range document.Order {
		resource, present := byID[id]
		if !present {
			return nil, ErrInvalidBlueprint
		}
		ordered = append(ordered, resource)
	}
	if len(ordered) != len(document.Resources) {
		return nil, ErrInvalidBlueprint
	}
	return ordered, nil
}

func buildPlan(ctx context.Context, document Document, backend Backend) (Plan, error) {
	ordered, err := orderedResources(document)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{
		Blueprint:    document.Name,
		Resources:    make([]ResourcePlan, 0, len(ordered)),
		Changes:      make([]ResourcePlan, 0),
		observations: make(map[string]Observation, len(ordered)),
	}
	knownIDs := make(map[string]string)
	conflict := false
	for _, resource := range ordered {
		if err := ctx.Err(); err != nil {
			return Plan{}, err
		}
		observation, err := backend.Inspect(ctx, copyResource(resource), copyRemoteIDs(knownIDs))
		if err != nil {
			return Plan{}, safeEngineError(err)
		}
		plan.observations[resource.ID] = observation
		item := ResourcePlan{
			ID:       resource.ID,
			Kind:     resource.Kind,
			Name:     resource.Name,
			RemoteID: observation.ID,
		}
		switch {
		case observation.Conflict != "":
			item.Action, item.Reason = "conflict", safeConflictReason(observation.Conflict)
		case !observation.Exists:
			item.Action = "create"
		case observation.Equal:
			item.Action = "noop"
		default:
			item.Action, item.Reason = "conflict", "different_configuration"
		}
		plan.Resources = append(plan.Resources, item)
		if item.Action != "noop" {
			plan.Changes = append(plan.Changes, item)
		}
		conflict = conflict || item.Action == "conflict"
		rememberRemoteID(knownIDs, resource, observation)
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, err
	}
	if conflict {
		return plan, ErrConflict
	}
	return plan, nil
}

// Apply recomputes all observations and refuses the entire plan if any target
// conflicts. It then rechecks every resource immediately before acting on it.
// These checks narrow races; administrative Vault APIs do not offer atomic CAS.
func Apply(ctx context.Context, document Document, backend Backend) (ApplyReport, error) {
	if err := ctx.Err(); err != nil {
		return ApplyReport{}, err
	}
	document, err := ValidateDocument(document)
	if err != nil {
		return ApplyReport{}, ErrInvalidBlueprint
	}
	if backend == nil {
		return ApplyReport{}, errOperationFailed
	}
	plan, err := buildPlan(ctx, document, backend)
	if err != nil {
		if !errors.Is(err, ErrConflict) || plan.observations == nil {
			return ApplyReport{}, err
		}
		return conflictReport(plan), ErrConflict
	}
	ordered, err := orderedResources(document)
	if err != nil {
		return ApplyReport{}, err
	}
	report := pendingReport(plan)
	knownIDs := make(map[string]string)
	created := false
	for index, resource := range ordered {
		if err := ctx.Err(); err != nil {
			return failedApply(report, index, "failed", err, created)
		}
		current, err := backend.Inspect(ctx, copyResource(resource), copyRemoteIDs(knownIDs))
		if err != nil {
			return failedApply(report, index, "failed", safeEngineError(err), created)
		}
		previous := plan.observations[resource.ID]
		if staleObservation(previous, current) || current.Conflict != "" ||
			(plan.Resources[index].Action == "noop" && !current.Equal) {
			report.Items[index].Status, report.Items[index].Reason = "conflict", "stale_state"
			return applyOutcome(report, ErrConflict, created)
		}
		if plan.Resources[index].Action == "noop" {
			report.Items[index].Status = "unchanged"
			report.Items[index].RemoteID = current.ID
			rememberRemoteID(knownIDs, resource, current)
			continue
		}
		if err := ctx.Err(); err != nil {
			return failedApply(report, index, "failed", err, created)
		}
		observed, err := backend.Create(ctx, copyResource(resource), copyRemoteIDs(knownIDs))
		if err != nil {
			err = safeEngineError(err)
			status := "failed"
			if errors.Is(err, ErrUnconfirmed) {
				status = "unconfirmed"
			} else if errors.Is(err, ErrConflict) {
				status = "conflict"
			}
			return failedApply(report, index, status, err, created)
		}
		if !observed.Exists || !observed.Equal || observed.Conflict != "" ||
			(needsRemoteID(resource) && observed.ID == "") {
			return failedApply(report, index, "unconfirmed", ErrUnconfirmed, created)
		}
		report.Items[index].Status = "created"
		report.Items[index].RemoteID = observed.ID
		created = true
		rememberRemoteID(knownIDs, resource, observed)
	}
	return report, nil
}

func staleObservation(previous, current Observation) bool {
	return previous.Exists != current.Exists || previous.ID != current.ID || previous.Fingerprint != current.Fingerprint
}

func pendingReport(plan Plan) ApplyReport {
	report := ApplyReport{Blueprint: plan.Blueprint, Items: make([]ApplyItem, len(plan.Resources))}
	for index, resource := range plan.Resources {
		report.Items[index] = ApplyItem{
			ID:       resource.ID,
			Kind:     resource.Kind,
			Name:     resource.Name,
			Status:   "not_started",
			RemoteID: resource.RemoteID,
		}
	}
	return report
}

func conflictReport(plan Plan) ApplyReport {
	report := pendingReport(plan)
	for index, resource := range plan.Resources {
		switch resource.Action {
		case "noop":
			report.Items[index].Status = "unchanged"
		case "conflict":
			report.Items[index].Status = "conflict"
			report.Items[index].Reason = resource.Reason
		}
	}
	return report
}

func failedApply(report ApplyReport, index int, status string, err error, created bool) (ApplyReport, error) {
	report.Items[index].Status = status
	report.Items[index].Reason = engineErrorReason(err)
	return applyOutcome(report, err, created)
}

func applyOutcome(report ApplyReport, err error, created bool) (ApplyReport, error) {
	if created || errors.Is(err, ErrUnconfirmed) {
		return report, fmt.Errorf("%w: %w", ErrPartial, err)
	}
	return report, err
}

func needsRemoteID(resource Resource) bool {
	return resource.Kind == "entity" || resource.Kind == "group"
}

func rememberRemoteID(known map[string]string, resource Resource, observation Observation) {
	if needsRemoteID(resource) && observation.Exists && observation.ID != "" {
		known[resource.ID] = observation.ID
	}
}

func copyRemoteIDs(values map[string]string) map[string]string {
	copy := make(map[string]string, len(values))
	for key, value := range values {
		copy[key] = value
	}
	return copy
}

// Backend normalization must not change the validated desired document between
// preflight and creation. The same applies to slices of dependency identifiers.
func copyResource(resource Resource) Resource {
	resource.DependsOn = append([]string(nil), resource.DependsOn...)
	resource.Spec = copySpecValue(resource.Spec).(map[string]any)
	return resource
}

func copySpecValue(value any) any {
	switch value := value.(type) {
	case map[string]any:
		copy := make(map[string]any, len(value))
		for key, child := range value {
			copy[key] = copySpecValue(child)
		}
		return copy
	case []any:
		copy := make([]any, len(value))
		for index, child := range value {
			copy[index] = copySpecValue(child)
		}
		return copy
	case []string:
		return append([]string(nil), value...)
	default:
		return value
	}
}

func safeConflictReason(reason string) string {
	switch reason {
	case "different_configuration", "incompatible_mount", "mount_overlap", "unresolved_reference", "external_group":
		return reason
	default:
		return "resource_conflict"
	}
}

// Interface implementations must not inject server diagnostics or values into
// reports. Keep only known error identities, stripping any surrounding text.
func safeEngineError(err error) error {
	switch {
	case errors.Is(err, ErrUnconfirmed), errors.Is(err, ErrPartial), errors.Is(err, vault.ErrAccessUnconfirmed), errors.Is(err, vault.ErrAccessPartial):
		return ErrUnconfirmed
	case errors.Is(err, ErrConflict), errors.Is(err, vault.ErrConflict):
		return ErrConflict
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, vault.ErrPermissionDenied):
		return vault.ErrPermissionDenied
	case errors.Is(err, vault.ErrUnauthenticated):
		return vault.ErrUnauthenticated
	case errors.Is(err, vault.ErrNotFound):
		return vault.ErrNotFound
	case errors.Is(err, ErrInvalidBlueprint):
		return ErrInvalidBlueprint
	default:
		return errOperationFailed
	}
}

func engineErrorReason(err error) string {
	switch {
	case errors.Is(err, ErrUnconfirmed):
		return "unconfirmed"
	case errors.Is(err, ErrConflict):
		return "conflict"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, vault.ErrPermissionDenied), errors.Is(err, vault.ErrUnauthenticated):
		return "permission_denied"
	case errors.Is(err, vault.ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrInvalidBlueprint):
		return "invalid_blueprint"
	default:
		return "operation_failed"
	}
}
