package blueprint

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/ml0renz0/secretwright/internal/vault"
)

// VaultBackend inspects only supported, named configuration resources. The
// selected credential never appears in an observation or a public plan.
type VaultBackend struct {
	client *vault.Client
	token  string
}

func NewVaultBackend(client *vault.Client, token string) *VaultBackend {
	return &VaultBackend{client: client, token: token}
}

func (b *VaultBackend) Inspect(ctx context.Context, resource Resource, remoteIDs map[string]string) (Observation, error) {
	if b == nil || b.client == nil {
		return Observation{}, ErrInvalidBlueprint
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	switch resource.Kind {
	case "kv_mount":
		return b.inspectMount(ctx, resource)
	case "policy":
		return b.inspectPolicy(ctx, resource)
	case "approle":
		return b.inspectRole(ctx, resource)
	case "entity":
		return b.inspectEntity(ctx, resource)
	case "group":
		return b.inspectGroup(ctx, resource, remoteIDs)
	default:
		return Observation{}, ErrInvalidBlueprint
	}
}

func (b *VaultBackend) inspectMount(ctx context.Context, resource Resource) (Observation, error) {
	version, err := blueprintMountVersion(resource)
	if err != nil {
		return Observation{}, err
	}
	state, err := b.client.ReadBlueprintKVMount(ctx, b.token, resource.Name)
	if err != nil {
		return Observation{}, err
	}
	observation, err := observedState(state.Exists, "", state)
	if err != nil {
		return Observation{}, err
	}
	if len(state.Overlaps) != 0 {
		observation.Conflict = "mount_overlap"
	} else if state.Exists && (state.Type != "kv" || state.Version != version) {
		observation.Conflict = "incompatible_mount"
	} else {
		observation.Equal = state.Exists
	}
	return observation, nil
}

func (b *VaultBackend) inspectPolicy(ctx context.Context, resource Resource) (Observation, error) {
	desired, err := blueprintPolicy(resource)
	if err != nil {
		return Observation{}, err
	}
	policy, err := b.client.ReadPolicy(ctx, b.token, resource.Name)
	if errors.Is(err, vault.ErrNotFound) {
		return observedState(false, "", map[string]any{"exists": false})
	}
	if err != nil {
		return Observation{}, err
	}
	current, err := NormalizePolicy(policy.Policy)
	if err != nil {
		// An unsupported or oversized existing policy cannot be considered
		// equivalent. Its bounded F06 projection is sufficient to fingerprint
		// the conflict, without publishing or rewriting the policy text.
		observation, fingerprintErr := observedState(true, "", policy)
		observation.Conflict = "different_configuration"
		return observation, fingerprintErr
	}
	observation, err := observedState(true, "", map[string]any{"name": policy.Name, "policy": current})
	observation.Equal = current == desired
	return observation, err
}

func (b *VaultBackend) inspectRole(ctx context.Context, resource Resource) (Observation, error) {
	desired, opts, err := blueprintRole(resource)
	if err != nil {
		return Observation{}, err
	}
	state, err := b.client.ReadBlueprintAppRole(ctx, b.token, resource.Name, opts)
	if err != nil {
		return Observation{}, err
	}
	observation, err := observedState(state.Exists, "", state)
	if err != nil || !state.Exists {
		return observation, err
	}
	ttl, _ := time.ParseDuration(desired.TokenTTL)
	maximum, _ := time.ParseDuration(desired.TokenMaxTTL)
	secretTTL, _ := time.ParseDuration(desired.SecretIDTTL)
	role := state.Role
	observation.Equal = reflect.DeepEqual(role.TokenPolicies, desired.TokenPolicies) &&
		role.TokenTTLSeconds == int64(ttl/time.Second) && role.TokenMaxTTLSeconds == int64(maximum/time.Second) &&
		role.SecretIDTTLSeconds == int64(secretTTL/time.Second) && role.SecretIDNumUses == desired.SecretIDNumUses &&
		role.TokenNumUses == desired.TokenNumUses && role.BindSecretID && role.TokenNoDefaultPolicy &&
		state.TokenType == "service" && state.TokenPeriodSeconds == 0
	return observation, nil
}

func (b *VaultBackend) inspectEntity(ctx context.Context, resource Resource) (Observation, error) {
	desired, err := blueprintEntity(resource)
	if err != nil {
		return Observation{}, err
	}
	entity, err := b.client.ReadEntityByName(ctx, b.token, resource.Name)
	if errors.Is(err, vault.ErrNotFound) {
		return observedState(false, "", map[string]any{"exists": false})
	}
	if err != nil {
		return Observation{}, err
	}
	observation, err := observedState(true, entity.ID, entity)
	observation.Equal = entity.Name == desired.Name && reflect.DeepEqual(entity.Policies, desired.Policies) && entity.Disabled == desired.Disabled
	return observation, err
}

func (b *VaultBackend) inspectGroup(ctx context.Context, resource Resource, remoteIDs map[string]string) (Observation, error) {
	desired, unresolved, err := blueprintGroup(resource, remoteIDs)
	if err != nil {
		return Observation{}, err
	}
	group, err := b.client.ReadGroupByName(ctx, b.token, resource.Name)
	if errors.Is(err, vault.ErrNotFound) {
		return observedState(false, "", map[string]any{"exists": false})
	}
	if err != nil {
		return Observation{}, err
	}
	observation, err := observedState(true, group.ID, group)
	if err != nil {
		return Observation{}, err
	}
	if group.Type != "internal" {
		observation.Conflict = "external_group"
	} else if unresolved {
		observation.Conflict = "unresolved_reference"
	} else {
		observation.Equal = group.Name == desired.Name && reflect.DeepEqual(group.Policies, desired.Policies) &&
			reflect.DeepEqual(group.MemberEntityIDs, desired.MemberEntityIDs) && reflect.DeepEqual(group.MemberGroupIDs, desired.MemberGroupIDs)
	}
	return observation, nil
}

// Create performs an additional read-only existence check, then uses only the
// fixed F06 write methods or create-only KV mount API. Administrative APIs have
// no compare-and-set: a concurrent creation can still race the final request.
func (b *VaultBackend) Create(ctx context.Context, resource Resource, remoteIDs map[string]string) (Observation, error) {
	current, err := b.Inspect(ctx, resource, remoteIDs)
	if err != nil {
		return Observation{}, err
	}
	if current.Exists || current.Conflict != "" {
		return Observation{}, ErrConflict
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	createdID := ""
	switch resource.Kind {
	case "kv_mount":
		version, inputErr := blueprintMountVersion(resource)
		if inputErr != nil {
			return Observation{}, inputErr
		}
		_, err = b.client.CreateBlueprintKVMount(ctx, b.token, resource.Name, version)
	case "policy":
		policy, inputErr := blueprintPolicy(resource)
		if inputErr != nil {
			return Observation{}, inputErr
		}
		_, err = b.client.WritePolicy(ctx, b.token, resource.Name, policy)
	case "approle":
		spec, opts, inputErr := blueprintRole(resource)
		if inputErr != nil {
			return Observation{}, inputErr
		}
		_, err = b.client.WriteAppRole(ctx, b.token, resource.Name, spec, opts)
	case "entity":
		spec, inputErr := blueprintEntity(resource)
		if inputErr != nil {
			return Observation{}, inputErr
		}
		var created vault.AccessResult
		created, err = b.client.WriteEntity(ctx, b.token, "", spec)
		createdID = created.ID
	case "group":
		spec, unresolved, inputErr := blueprintGroup(resource, remoteIDs)
		if inputErr != nil || unresolved {
			return Observation{}, ErrInvalidBlueprint
		}
		var created vault.AccessResult
		created, err = b.client.CreateBlueprintGroup(ctx, b.token, spec)
		createdID = created.ID
	default:
		return Observation{}, ErrInvalidBlueprint
	}
	if err != nil {
		if errors.Is(err, vault.ErrAccessUnconfirmed) {
			return Observation{}, ErrUnconfirmed
		}
		if errors.Is(err, vault.ErrConflict) {
			return Observation{}, ErrConflict
		}
		return Observation{}, err
	}
	verified, err := b.Inspect(ctx, resource, remoteIDs)
	if err != nil || !verified.Exists || !verified.Equal || verified.Conflict != "" ||
		(resource.Kind == "entity" || resource.Kind == "group") && (verified.ID == "" || verified.ID != createdID) {
		return Observation{}, ErrUnconfirmed
	}
	return verified, nil
}

func observedState(exists bool, id string, state any) (Observation, error) {
	encoded, err := json.Marshal(state)
	if err != nil {
		return Observation{}, vault.ErrAccessResponse
	}
	digest := sha256.Sum256(encoded)
	return Observation{Exists: exists, ID: id, Fingerprint: hex.EncodeToString(digest[:])}, nil
}

func blueprintMountVersion(resource Resource) (int, error) {
	if len(resource.Spec) != 1 {
		return 0, ErrInvalidBlueprint
	}
	encoded, err := json.Marshal(resource.Spec)
	if err != nil {
		return 0, ErrInvalidBlueprint
	}
	var spec struct {
		Version int `json:"version"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&spec) != nil || spec.Version != 1 && spec.Version != 2 {
		return 0, ErrInvalidBlueprint
	}
	return spec.Version, nil
}

func blueprintPolicy(resource Resource) (string, error) {
	policy, ok := resource.Spec["policy"].(string)
	if !ok || len(resource.Spec) != 1 {
		return "", ErrInvalidBlueprint
	}
	return NormalizePolicy(policy)
}

func blueprintRole(resource Resource) (vault.RoleSpec, vault.AppRoleOptions, error) {
	values := copyBlueprintSpec(resource.Spec)
	mount := "approle"
	if value, present := values["auth_mount"]; present {
		var ok bool
		mount, ok = value.(string)
		if !ok || mount == "" {
			return vault.RoleSpec{}, vault.AppRoleOptions{}, ErrInvalidBlueprint
		}
		delete(values, "auth_mount")
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return vault.RoleSpec{}, vault.AppRoleOptions{}, ErrInvalidBlueprint
	}
	spec, err := vault.DecodeRoleSpec(bytes.NewReader(encoded))
	if err != nil {
		return vault.RoleSpec{}, vault.AppRoleOptions{}, ErrInvalidBlueprint
	}
	return spec, vault.AppRoleOptions{Mount: mount}, nil
}

func blueprintEntity(resource Resource) (vault.EntitySpec, error) {
	values := copyBlueprintSpec(resource.Spec)
	if _, supplied := values["name"]; supplied {
		return vault.EntitySpec{}, ErrInvalidBlueprint
	}
	values["name"] = resource.Name
	encoded, err := json.Marshal(values)
	if err != nil {
		return vault.EntitySpec{}, ErrInvalidBlueprint
	}
	spec, err := vault.DecodeEntitySpec(bytes.NewReader(encoded))
	if err != nil {
		return vault.EntitySpec{}, ErrInvalidBlueprint
	}
	return spec, nil
}

func blueprintGroup(resource Resource, remoteIDs map[string]string) (vault.GroupSpec, bool, error) {
	values := copyBlueprintSpec(resource.Spec)
	if _, supplied := values["name"]; supplied {
		return vault.GroupSpec{}, false, ErrInvalidBlueprint
	}
	values["name"] = resource.Name
	unresolved := false
	for source, destination := range map[string]string{"member_entities": "member_entity_ids", "member_groups": "member_group_ids"} {
		if references, supplied := values[source]; supplied {
			ids, err := blueprintStringList(references)
			if err != nil {
				return vault.GroupSpec{}, false, err
			}
			members := []string{}
			if direct, supplied := values[destination]; supplied {
				members, err = blueprintStringList(direct)
				if err != nil {
					return vault.GroupSpec{}, false, err
				}
			}
			for _, id := range ids {
				remoteID := remoteIDs[id]
				if remoteID == "" {
					unresolved = true
					continue
				}
				members = append(members, remoteID)
			}
			values[destination] = members
			delete(values, source)
		}
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return vault.GroupSpec{}, false, ErrInvalidBlueprint
	}
	spec, err := vault.DecodeGroupSpec(bytes.NewReader(encoded))
	if err != nil {
		return vault.GroupSpec{}, false, ErrInvalidBlueprint
	}
	return spec, unresolved, nil
}

func blueprintStringList(value any) ([]string, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > MaxExpandedBytes || bytes.Equal(bytes.TrimSpace(encoded), []byte("null")) {
		return nil, ErrInvalidBlueprint
	}
	var values []string
	if json.Unmarshal(encoded, &values) != nil {
		return nil, ErrInvalidBlueprint
	}
	return values, nil
}

func copyBlueprintSpec(source map[string]any) map[string]any {
	copy := make(map[string]any, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}
