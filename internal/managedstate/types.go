// Package managedstate stores private, non-secret reconciliation checkpoints.
// It is a local declaration of ownership, not a lock on the remote server.
package managedstate

import "errors"

const (
	APIVersion    = "secretwright/state/v1"
	MaxResources  = 256
	MaxInputBytes = 1 << 20
)

var (
	ErrInvalidState     = errors.New("invalid or oversized Secretwright ownership state")
	ErrStateLocked      = errors.New("ownership state is locked; verify the active writer before removing a stale lock")
	ErrStateChanged     = errors.New("ownership state or its lock changed; reload and inspect before retrying")
	ErrStateIO          = errors.New("could not read or persist the private ownership state")
	ErrStateUnconfirmed = errors.New("ownership state persistence could not be confirmed; inspect before retrying")
)

type Target struct {
	AddressSHA256 string `json:"address_sha256"`
	ClusterID     string `json:"cluster_id"`
	Namespace     string `json:"namespace"`
}

type Record struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	AuthMount      string `json:"auth_mount,omitempty"`
	RemoteID       string `json:"remote_id,omitempty"`
	IdentitySHA256 string `json:"identity_sha256,omitempty"`
	Fingerprint    string `json:"baseline_sha256,omitempty"`
	Pending        string `json:"pending,omitempty"`
}

type State struct {
	APIVersion string   `json:"api_version"`
	Blueprint  string   `json:"blueprint"`
	Target     Target   `json:"target"`
	Revision   uint64   `json:"revision"`
	Resources  []Record `json:"resources"`
}

func clone(state State) State {
	if state.Resources != nil {
		state.Resources = append([]Record{}, state.Resources...)
	}
	return state
}
