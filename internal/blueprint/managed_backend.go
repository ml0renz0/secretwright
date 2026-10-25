package blueprint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"time"

	"github.com/ml0renz0/secretwright/internal/vault"
)

// ManagedBackend adds guarded updates without changing F07's create-only
// interface or its permission requirements.
type ManagedBackend interface {
	Backend
	Update(context.Context, Resource, map[string]string, Observation) (Observation, error)
}

type ManagedVaultBackend struct {
	*VaultBackend
}

func NewManagedVaultBackend(client *vault.Client, token string) *ManagedVaultBackend {
	return &ManagedVaultBackend{VaultBackend: NewVaultBackend(client, token)}
}

func managedIdentity(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func (b *ManagedVaultBackend) Inspect(ctx context.Context, resource Resource, remoteIDs map[string]string) (Observation, error) {
	if b == nil || b.VaultBackend == nil || b.client == nil {
		return Observation{}, ErrInvalidBlueprint
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	if resource.Kind == "approle" {
		return b.inspectManagedRole(ctx, resource)
	}
	if resource.Kind == "kv_mount" {
		return b.inspectManagedMount(ctx, resource)
	}
	current, err := b.VaultBackend.Inspect(ctx, resource, remoteIDs)
	if err != nil {
		return Observation{}, err
	}
	current.Guard = current.Fingerprint
	if current.Exists && (resource.Kind == "entity" || resource.Kind == "group") {
		current.Identity = managedIdentity(current.ID)
	}
	return current, nil
}

func (b *ManagedVaultBackend) inspectManagedMount(ctx context.Context, resource Resource) (Observation, error) {
	version, err := blueprintMountVersion(resource)
	if err != nil {
		return Observation{}, err
	}
	state, err := b.client.ReadBlueprintKVMount(ctx, b.token, resource.Name)
	if err != nil {
		return Observation{}, err
	}
	current, err := observedState(state.Exists, state.Accessor, state)
	if err != nil {
		return Observation{}, err
	}
	current.Guard = current.Fingerprint
	if state.Exists {
		current.Identity = managedIdentity(state.Accessor)
	}
	if len(state.Overlaps) != 0 {
		current.Conflict = "mount_overlap"
	} else if state.Exists && (state.Type != "kv" || state.Version != version) {
		current.Conflict = "incompatible_mount"
	} else {
		current.Equal = state.Exists
	}
	return current, nil
}

func (b *ManagedVaultBackend) inspectManagedRole(ctx context.Context, resource Resource) (Observation, error) {
	desired, opts, err := blueprintRole(resource)
	if err != nil {
		return Observation{}, err
	}
	state, err := b.client.ReadReconciliationAppRole(ctx, b.token, resource.Name, opts)
	if err != nil {
		return Observation{}, err
	}
	current := Observation{Exists: state.State.Exists, Fingerprint: state.Fingerprint, Identity: state.Identity, Guard: state.Guard}
	if !current.Exists {
		return current, nil
	}
	ttl, _ := time.ParseDuration(desired.TokenTTL)
	maximum, _ := time.ParseDuration(desired.TokenMaxTTL)
	secretTTL, _ := time.ParseDuration(desired.SecretIDTTL)
	role := state.State.Role
	current.Equal = reflect.DeepEqual(role.TokenPolicies, desired.TokenPolicies) &&
		role.TokenTTLSeconds == int64(ttl/time.Second) && role.TokenMaxTTLSeconds == int64(maximum/time.Second) &&
		role.SecretIDTTLSeconds == int64(secretTTL/time.Second) && role.SecretIDNumUses == desired.SecretIDNumUses &&
		role.TokenNumUses == desired.TokenNumUses && role.BindSecretID && role.TokenNoDefaultPolicy &&
		state.State.TokenType == "service" && state.State.TokenPeriodSeconds == 0
	return current, nil
}

func (b *ManagedVaultBackend) Create(ctx context.Context, resource Resource, remoteIDs map[string]string) (Observation, error) {
	if b == nil || b.VaultBackend == nil || b.client == nil {
		return Observation{}, ErrInvalidBlueprint
	}
	created, err := b.VaultBackend.Create(ctx, resource, remoteIDs)
	if err != nil {
		return Observation{}, safeEngineError(err)
	}
	verified, err := b.Inspect(ctx, resource, remoteIDs)
	if err != nil || !verified.Exists || !verified.Equal || verified.Conflict != "" ||
		created.ID != "" && verified.ID != created.ID || created.Fingerprint != verified.Fingerprint {
		return Observation{}, ErrUnconfirmed
	}
	return verified, nil
}

func sameManagedObservation(first, second Observation) bool {
	return first.Exists == second.Exists && first.ID == second.ID && first.Identity == second.Identity &&
		first.Fingerprint == second.Fingerprint && first.Guard == second.Guard
}

func (b *ManagedVaultBackend) Update(ctx context.Context, resource Resource, remoteIDs map[string]string, expected Observation) (Observation, error) {
	if resource.Kind == "kv_mount" {
		return Observation{}, ErrConflict
	}
	current, err := b.Inspect(ctx, resource, remoteIDs)
	if err != nil {
		return Observation{}, safeEngineError(err)
	}
	if !current.Exists || current.Conflict != "" || !sameManagedObservation(current, expected) {
		return Observation{}, ErrConflict
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	switch resource.Kind {
	case "policy":
		policy, parseErr := blueprintPolicy(resource)
		if parseErr != nil {
			return Observation{}, parseErr
		}
		_, err = b.client.WritePolicy(ctx, b.token, resource.Name, policy)
	case "approle":
		spec, opts, parseErr := blueprintRole(resource)
		if parseErr != nil {
			return Observation{}, parseErr
		}
		_, err = b.client.UpdateReconciliationAppRole(ctx, b.token, resource.Name, spec, opts, vault.ReconciliationRoleState{
			Identity: current.Identity, Fingerprint: current.Fingerprint, Guard: current.Guard,
		})
	case "entity":
		spec, parseErr := blueprintEntity(resource)
		if parseErr != nil {
			return Observation{}, parseErr
		}
		_, err = b.client.UpdateReconciliationEntity(ctx, b.token, current.ID, spec, current.Fingerprint)
	case "group":
		spec, unresolved, parseErr := blueprintGroup(resource, remoteIDs)
		if parseErr != nil || unresolved {
			return Observation{}, ErrInvalidBlueprint
		}
		_, err = b.client.UpdateReconciliationGroup(ctx, b.token, current.ID, spec, current.Fingerprint)
	default:
		return Observation{}, ErrInvalidBlueprint
	}
	if err != nil {
		if errors.Is(err, vault.ErrAccessUnconfirmed) {
			return Observation{}, ErrUnconfirmed
		}
		if errors.Is(err, vault.ErrNotFound) {
			return Observation{}, ErrConflict
		}
		return Observation{}, safeEngineError(err)
	}
	verified, err := b.Inspect(ctx, resource, remoteIDs)
	if err != nil || !verified.Exists || !verified.Equal || verified.Conflict != "" || verified.ID != current.ID || verified.Identity != current.Identity {
		return Observation{}, ErrUnconfirmed
	}
	return verified, nil
}
