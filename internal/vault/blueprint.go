package vault

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// OperationTimeout lets an orchestrator bound the complete operation rather
// than resetting its budget for each public resource method it invokes.
func (c *Client) OperationTimeout() time.Duration {
	if c == nil {
		return 0
	}
	return c.timeout
}

// BlueprintAppRoleState includes the fixed invariants written by F06 and the
// identity of the existing authentication mount. It contains no role credential.
type BlueprintAppRoleState struct {
	Exists             bool
	Role               RoleReport
	TokenType          string
	TokenPeriodSeconds int64
	AuthMountAccessor  string
}

// BlueprintKVMountState describes only a declared storage mount and prefixes
// that would prevent its creation. It never contains any stored secret values.
type BlueprintKVMountState struct {
	Exists   bool
	Type     string
	Version  int
	Accessor string
	Overlaps []string
}

func (c *Client) ReadEntityByName(ctx context.Context, token, name string) (EntityReport, error) {
	if !validateAccessName(name) {
		return EntityReport{}, ErrInvalidAccessInput
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return EntityReport{}, err
	}
	defer client.SetToken("")
	secret, err := accessRead(ctx, client, "identity/entity/name/"+name, false)
	if err != nil {
		return EntityReport{}, err
	}
	return parseEntityIdentity(secret, "", name)
}

func (c *Client) ReadGroupByName(ctx context.Context, token, name string) (GroupReport, error) {
	if !validateAccessName(name) {
		return GroupReport{}, ErrInvalidAccessInput
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return GroupReport{}, err
	}
	defer client.SetToken("")
	group, err := readGroupIdentity(ctx, client, "name/"+name, "")
	if err != nil {
		return GroupReport{}, err
	}
	if group.Name != name {
		return GroupReport{}, ErrAccessResponse
	}
	return group, nil
}

// CreateBlueprintGroup differs from the interactive F06 upsert: an existing
// group observed by its final read must never have its membership replaced.
func (c *Client) CreateBlueprintGroup(ctx context.Context, token string, spec GroupSpec) (AccessResult, error) {
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
	_, err = readGroupIdentity(ctx, client, "name/"+spec.Name, "")
	if err == nil {
		return AccessResult{}, ErrConflict
	}
	if !errors.Is(err, ErrNotFound) {
		return AccessResult{}, err
	}
	secret, err := accessWrite(ctx, client, http.MethodPost, "identity/group", map[string]any{
		"name": spec.Name, "policies": spec.Policies, "type": "internal",
		"member_entity_ids": spec.MemberEntityIDs, "member_group_ids": spec.MemberGroupIDs,
	})
	if err != nil {
		return AccessResult{}, err
	}
	return identityWriteResult(secret, "group", spec.Name, "")
}

func (c *Client) ReadBlueprintAppRole(ctx context.Context, token, name string, opts AppRoleOptions) (BlueprintAppRoleState, error) {
	path, mount, err := appRolePath(name, opts)
	if err != nil {
		return BlueprintAppRoleState{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return BlueprintAppRoleState{}, err
	}
	defer client.SetToken("")
	catalog, err := accessRead(ctx, client, "sys/auth", false)
	if err != nil {
		return BlueprintAppRoleState{}, err
	}
	if len(catalog.Data) > MaxAccessList {
		return BlueprintAppRoleState{}, ErrAccessResponse
	}
	raw, present := catalog.Data[mount+"/"]
	if !present {
		return BlueprintAppRoleState{}, ErrNotFound
	}
	configuration, ok := raw.(map[string]any)
	if !ok {
		return BlueprintAppRoleState{}, ErrAccessResponse
	}
	kind, kindOK := configuration["type"].(string)
	accessor, accessorOK := configuration["accessor"].(string)
	if !kindOK || !accessorOK || !validAccessCredential(accessor) {
		return BlueprintAppRoleState{}, ErrAccessResponse
	}
	if kind != "approle" {
		return BlueprintAppRoleState{}, ErrInvalidAccessInput
	}
	state := BlueprintAppRoleState{AuthMountAccessor: accessor}
	secret, err := accessRead(ctx, client, path, false)
	if errors.Is(err, ErrNotFound) {
		return state, nil
	}
	if err != nil {
		return BlueprintAppRoleState{}, err
	}
	role, err := parseRoleReport(secret, name, mount)
	if err != nil {
		return BlueprintAppRoleState{}, err
	}
	tokenType, typeOK := secret.Data["token_type"].(string)
	period, periodErr := accessNumber(secret.Data["token_period"])
	if !typeOK || !validateAccessName(tokenType) || periodErr != nil || period < 0 {
		return BlueprintAppRoleState{}, ErrAccessResponse
	}
	state.Exists, state.Role, state.TokenType, state.TokenPeriodSeconds = true, role, tokenType, period
	return state, nil
}

func blueprintMountPath(name string) (string, error) {
	if len(name) == 0 || len(name) > 1024 || strings.ToLower(name) != name {
		return "", ErrInvalidAccessInput
	}
	segments := strings.Split(name, "/")
	for _, segment := range segments {
		if !validateAccessName(segment) {
			return "", ErrInvalidAccessInput
		}
	}
	switch segments[0] {
	case "auth", "sys", "identity", "cubbyhole":
		return "", ErrInvalidAccessInput
	}
	return name + "/", nil
}

func (c *Client) ReadBlueprintKVMount(ctx context.Context, token, name string) (BlueprintKVMountState, error) {
	prefix, err := blueprintMountPath(name)
	if err != nil {
		return BlueprintKVMountState{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return BlueprintKVMountState{}, err
	}
	defer client.SetToken("")
	secret, err := accessRead(ctx, client, "sys/mounts", false)
	if err != nil {
		return BlueprintKVMountState{}, err
	}
	if len(secret.Data) > MaxAccessList {
		return BlueprintKVMountState{}, ErrAccessResponse
	}
	state := BlueprintKVMountState{Overlaps: []string{}}
	for current, raw := range secret.Data {
		canonical, err := canonicalMount(current)
		if err != nil || canonical != current {
			return BlueprintKVMountState{}, ErrAccessResponse
		}
		if canonical != prefix {
			if strings.HasPrefix(canonical, prefix) || strings.HasPrefix(prefix, canonical) {
				state.Overlaps = append(state.Overlaps, canonical)
			}
			continue
		}
		configuration, ok := raw.(map[string]any)
		if !ok {
			return BlueprintKVMountState{}, ErrAccessResponse
		}
		kind, kindOK := configuration["type"].(string)
		accessor, accessorOK := configuration["accessor"].(string)
		if !kindOK || !validateAccessName(kind) || !accessorOK || !validAccessCredential(accessor) {
			return BlueprintKVMountState{}, ErrAccessResponse
		}
		state.Exists, state.Type, state.Accessor = true, kind, accessor
		if kind != "kv" {
			continue
		}
		state.Version = 1
		if rawOptions := configuration["options"]; rawOptions != nil {
			options, ok := rawOptions.(map[string]any)
			if !ok {
				return BlueprintKVMountState{}, ErrAccessResponse
			}
			if rawVersion, present := options["version"]; present {
				version, ok := rawVersion.(string)
				if !ok {
					return BlueprintKVMountState{}, ErrAccessResponse
				}
				switch version {
				case "", "1":
					state.Version = 1
				case "2":
					state.Version = 2
				default:
					state.Version = 0
				}
			}
		}
	}
	sort.Strings(state.Overlaps)
	return state, nil
}

// CreateBlueprintKVMount never tunes, converts or removes an existing engine.
// The administrative mount API itself rejects an already occupied prefix.
func (c *Client) CreateBlueprintKVMount(ctx context.Context, token, name string, version int) (AccessResult, error) {
	prefix, err := blueprintMountPath(name)
	if err != nil || version != 1 && version != 2 {
		return AccessResult{}, ErrInvalidAccessInput
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return AccessResult{}, err
	}
	defer client.SetToken("")
	if _, err := accessWrite(ctx, client, http.MethodPost, "sys/mounts/"+strings.TrimSuffix(prefix, "/"), map[string]any{
		"type": "kv", "options": map[string]any{"version": strconv.Itoa(version)},
	}); err != nil {
		return AccessResult{}, err
	}
	return AccessResult{Resource: "kv_mount", Name: name}, nil
}
