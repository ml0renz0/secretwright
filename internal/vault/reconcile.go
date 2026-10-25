package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/hashicorp/vault/api"
)

// TargetBinding identifies the selected server without retaining its URL or a
// credential. A state inventory must also match the namespace and cluster.
type TargetBinding struct {
	AddressSHA256 string `json:"address_sha256"`
	ClusterID     string `json:"cluster_id"`
	Namespace     string `json:"namespace"`
}

func (c *Client) ReconciliationTarget(ctx context.Context) (TargetBinding, error) {
	if c == nil || c.api == nil {
		return TargetBinding{}, ErrAccessResponse
	}
	status, err := c.Status(ctx)
	if err != nil {
		return TargetBinding{}, err
	}
	if !status.Initialized || status.Sealed || !validateIdentityID(status.ClusterID) {
		return TargetBinding{}, ErrAccessResponse
	}
	return TargetBinding{AddressSHA256: reconciliationDigest([]byte(c.api.Address())), ClusterID: status.ClusterID, Namespace: c.namespace}, nil
}

// ReconciliationRoleState contains hashes only for the private role identifier
// and preserved alias metadata. The latter must never enter inventory files.
type ReconciliationRoleState struct {
	State       BlueprintAppRoleState
	Identity    string
	Fingerprint string
	Guard       string
}

func reconciliationDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func reconciliationFingerprint(value any) (string, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return "", ErrAccessResponse
	}
	return reconciliationDigest(body), nil
}

func (c *Client) ReadReconciliationAppRole(ctx context.Context, token, name string, opts AppRoleOptions) (ReconciliationRoleState, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return ReconciliationRoleState{}, err
	}
	defer client.SetToken("")
	state, _, err := readReconciliationAppRole(ctx, client, name, opts)
	return state, err
}

// All configuration and the preservation data come from the same role read.
// RoleID is obtained separately because the ordinary role projection omits it.
func readReconciliationAppRole(ctx context.Context, client *api.Client, name string, opts AppRoleOptions) (ReconciliationRoleState, map[string]string, error) {
	path, mount, err := appRolePath(name, opts)
	if err != nil {
		return ReconciliationRoleState{}, nil, err
	}
	catalog, err := accessRead(ctx, client, "sys/auth", false)
	if err != nil {
		return ReconciliationRoleState{}, nil, err
	}
	if len(catalog.Data) > MaxAccessList {
		return ReconciliationRoleState{}, nil, ErrAccessResponse
	}
	raw, found := catalog.Data[mount+"/"]
	if !found {
		return ReconciliationRoleState{}, nil, ErrNotFound
	}
	configuration, ok := raw.(map[string]any)
	if !ok {
		return ReconciliationRoleState{}, nil, ErrAccessResponse
	}
	kind, kindOK := configuration["type"].(string)
	accessor, accessorOK := configuration["accessor"].(string)
	if !kindOK || !accessorOK || !validAccessCredential(accessor) {
		return ReconciliationRoleState{}, nil, ErrAccessResponse
	}
	if kind != "approle" {
		return ReconciliationRoleState{}, nil, ErrInvalidAccessInput
	}
	state := ReconciliationRoleState{State: BlueprintAppRoleState{AuthMountAccessor: accessor}}
	metadata := map[string]string{}
	secret, err := accessRead(ctx, client, path, false)
	if !errors.Is(err, ErrNotFound) {
		if err != nil {
			return ReconciliationRoleState{}, nil, err
		}
		role, err := parseRoleReport(secret, name, mount)
		if err != nil {
			return ReconciliationRoleState{}, nil, err
		}
		tokenType, typeOK := secret.Data["token_type"].(string)
		period, periodErr := accessNumber(secret.Data["token_period"])
		if !typeOK || !validateAccessName(tokenType) || periodErr != nil || period < 0 {
			return ReconciliationRoleState{}, nil, ErrAccessResponse
		}
		metadata, err = reconciliationAliasMetadata(secret.Data["alias_metadata"])
		if err != nil {
			return ReconciliationRoleState{}, nil, err
		}
		roleID, err := readAppRoleID(ctx, client, path)
		if err != nil {
			return ReconciliationRoleState{}, nil, err
		}
		state.State.Exists, state.State.Role, state.State.TokenType, state.State.TokenPeriodSeconds = true, role, tokenType, period
		state.Identity, err = reconciliationFingerprint([]string{roleID, accessor})
		if err != nil {
			return ReconciliationRoleState{}, nil, err
		}
	}
	state.Fingerprint, err = reconciliationFingerprint(state.State)
	if err != nil {
		return ReconciliationRoleState{}, nil, err
	}
	state.Guard, err = reconciliationFingerprint([]any{state.Fingerprint, metadata})
	if err != nil {
		return ReconciliationRoleState{}, nil, err
	}
	return state, metadata, nil
}

func reconciliationAliasMetadata(value any) (map[string]string, error) {
	metadata := map[string]string{}
	if value == nil {
		return metadata, nil
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) > 1000 {
		return nil, ErrAccessResponse
	}
	for key, raw := range object {
		text, ok := raw.(string)
		if !ok || len(key) > 256 || len(text) > 4096 || !utf8.ValidString(key) || !utf8.ValidString(text) || strings.ContainsRune(key, 0) || strings.ContainsRune(text, 0) {
			return nil, ErrAccessResponse
		}
		metadata[key] = text
	}
	body, err := json.Marshal(metadata)
	if err != nil || len(body) > MaxAccessSpecBytes {
		return nil, ErrAccessResponse
	}
	return metadata, nil
}

// UpdateReconciliationAppRole preserves alias_metadata explicitly: Vault clears
// it when omitted. Other unowned restrictions remain omitted, never replayed.
// In particular, local_secret_ids is a create-only option.
func (c *Client) UpdateReconciliationAppRole(ctx context.Context, token, name string, spec RoleSpec, opts AppRoleOptions, expected ReconciliationRoleState) (AccessResult, error) {
	path, _, err := appRolePath(name, opts)
	if err != nil {
		return AccessResult{}, err
	}
	_, body, err := prepareRoleSpec(spec)
	if err != nil {
		return AccessResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return AccessResult{}, err
	}
	defer client.SetToken("")
	current, metadata, err := readReconciliationAppRole(ctx, client, name, opts)
	if err != nil {
		return AccessResult{}, err
	}
	if !current.State.Exists || current.Identity != expected.Identity || current.Fingerprint != expected.Fingerprint || current.Guard != expected.Guard {
		return AccessResult{}, ErrConflict
	}
	body["alias_metadata"] = metadata
	if _, err := accessWrite(ctx, client, http.MethodPost, path, body); err != nil {
		return AccessResult{}, err
	}
	verified, preserved, err := readReconciliationAppRole(ctx, client, name, opts)
	if err != nil || !verified.State.Exists || verified.Identity != current.Identity || !reflect.DeepEqual(metadata, preserved) {
		return AccessResult{}, ErrAccessUnconfirmed
	}
	return AccessResult{Resource: "approle", Name: name}, nil
}

func (c *Client) UpdateReconciliationEntity(ctx context.Context, token, id string, spec EntitySpec, expectedFingerprint string) (AccessResult, error) {
	if !validateIdentityID(id) {
		return AccessResult{}, ErrInvalidAccessInput
	}
	spec, err := normalizeEntitySpec(spec)
	if err != nil {
		return AccessResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return AccessResult{}, err
	}
	defer client.SetToken("")
	current, err := readEntityIdentity(ctx, client, id)
	if err != nil {
		return AccessResult{}, err
	}
	fingerprint, err := reconciliationFingerprint(current)
	if err != nil {
		return AccessResult{}, err
	}
	if current.Name != spec.Name || fingerprint != expectedFingerprint {
		return AccessResult{}, ErrConflict
	}
	secret, err := accessWrite(ctx, client, http.MethodPost, "identity/entity/id/"+id, map[string]any{
		"name": spec.Name, "policies": spec.Policies, "disabled": spec.Disabled,
	})
	if err != nil {
		return AccessResult{}, err
	}
	return identityWriteResult(secret, "entity", spec.Name, id)
}

func (c *Client) UpdateReconciliationGroup(ctx context.Context, token, id string, spec GroupSpec, expectedFingerprint string) (AccessResult, error) {
	if !validateIdentityID(id) {
		return AccessResult{}, ErrInvalidAccessInput
	}
	spec, err := normalizeGroupSpec(spec)
	if err != nil {
		return AccessResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return AccessResult{}, err
	}
	defer client.SetToken("")
	current, err := readGroupIdentity(ctx, client, "id/"+id, id)
	if err != nil {
		return AccessResult{}, err
	}
	fingerprint, err := reconciliationFingerprint(current)
	if err != nil {
		return AccessResult{}, err
	}
	if current.Name != spec.Name || current.Type != "internal" || fingerprint != expectedFingerprint {
		return AccessResult{}, ErrConflict
	}
	secret, err := accessWrite(ctx, client, http.MethodPost, "identity/group/id/"+id, map[string]any{
		"name": spec.Name, "policies": spec.Policies, "type": "internal",
		"member_entity_ids": spec.MemberEntityIDs, "member_group_ids": spec.MemberGroupIDs,
	})
	if err != nil {
		return AccessResult{}, err
	}
	return identityWriteResult(secret, "group", spec.Name, id)
}
