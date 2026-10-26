package blueprint

import (
	"fmt"

	"github.com/ml0renz0/secretwright/internal/managedstate"
)

// ErrStateConflict identifies a binding, ownership or pending-checkpoint conflict
// while retaining the ordinary blueprint conflict exit classification.
var ErrStateConflict = fmt.Errorf("%w: managed inventory does not authorize this operation", ErrConflict)

// StateSink persists detached metadata checkpoints. Callers hold its exclusive
// lock throughout a managed application or explicit recovery.
type StateSink interface {
	Snapshot() managedstate.State
	Save(managedstate.State) error
}

type ManagedResourcePlan struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Action   string `json:"action"`
	Reason   string `json:"reason,omitempty"`
	RemoteID string `json:"remote_id,omitempty"`
	Managed  bool   `json:"managed"`
	Drift    bool   `json:"drift,omitempty"`
}

// Observations contain only transient server state and are never accepted as a
// saved execution plan. ApplyManaged rebuilds every observation under the lock.
type ManagedPlan struct {
	Blueprint    string                `json:"blueprint"`
	Resources    []ManagedResourcePlan `json:"resources"`
	Changes      []ManagedResourcePlan `json:"changes"`
	observations map[string]Observation
}

type ManagedItem struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	RemoteID string `json:"remote_id,omitempty"`
}

type ManagedReport struct {
	Blueprint string        `json:"blueprint"`
	Items     []ManagedItem `json:"items"`
}
