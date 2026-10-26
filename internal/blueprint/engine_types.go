package blueprint

import (
	"context"
	"errors"
)

var (
	ErrConflict    = errors.New("blueprint conflicts with existing or changed Vault resources")
	ErrPartial     = errors.New("blueprint application is incomplete; some resources may have been created; verify the reported resources before retrying")
	ErrUnconfirmed = errors.New("blueprint resource creation could not be confirmed; verify the resource before retrying")

	errOperationFailed = errors.New("blueprint resource inspection or creation failed")
)

// Observation is transient backend state, never a serializable state file or
// execution plan. Fingerprint describes current managed fields and prerequisites.
type Observation struct {
	Exists      bool   `json:"-"`
	Equal       bool   `json:"-"`
	ID          string `json:"-"`
	Fingerprint string `json:"-"`
	Identity    string `json:"-"`
	Guard       string `json:"-"`
	Conflict    string `json:"-"`
}

// Backend implements only inspection and creation of the fixed resource kinds.
// Create returns an observation verified after its mutation. An unknown write
// or failed post-write verification must return ErrUnconfirmed.
type Backend interface {
	Inspect(context.Context, Resource, map[string]string) (Observation, error)
	Create(context.Context, Resource, map[string]string) (Observation, error)
}

type ResourcePlan struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Action   string `json:"action"`
	Reason   string `json:"reason,omitempty"`
	RemoteID string `json:"remote_id,omitempty"`
}

// Plan exposes resource metadata only. Its observations cannot be serialized
// and are never accepted as authority by Apply, which rebuilds its own plan.
type Plan struct {
	Blueprint    string         `json:"blueprint"`
	Resources    []ResourcePlan `json:"resources"`
	Changes      []ResourcePlan `json:"changes"`
	observations map[string]Observation
}

type ApplyItem struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	RemoteID string `json:"remote_id,omitempty"`
}

type ApplyReport struct {
	Blueprint string      `json:"blueprint"`
	Items     []ApplyItem `json:"items"`
}
