package vault

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/hashicorp/vault/api"
)

const maxIdentityMembers = 1000

type EntitySpec struct {
	Name     string   `json:"name"`
	Policies []string `json:"policies"`
	Disabled bool     `json:"disabled"`
}

type EntityReport struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Policies []string `json:"policies"`
	Disabled bool     `json:"disabled"`
}

type GroupSpec struct {
	Name            string   `json:"name"`
	Policies        []string `json:"policies"`
	MemberEntityIDs []string `json:"member_entity_ids"`
	MemberGroupIDs  []string `json:"member_group_ids"`
}

type GroupReport struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	Policies        []string `json:"policies"`
	MemberEntityIDs []string `json:"member_entity_ids"`
	MemberGroupIDs  []string `json:"member_group_ids"`
}

func DecodeEntitySpec(input io.Reader) (EntitySpec, error) {
	object, err := readAccessSpec(input)
	if err != nil {
		return EntitySpec{}, err
	}
	for key := range object {
		if key != "name" && key != "policies" && key != "disabled" {
			return EntitySpec{}, ErrInvalidAccessInput
		}
	}
	name, ok := object["name"].(string)
	if !ok {
		return EntitySpec{}, ErrInvalidAccessInput
	}
	spec := EntitySpec{Name: name, Policies: []string{}}
	if value, present := object["policies"]; present {
		spec.Policies, err = identitySpecStrings(value)
		if err != nil {
			return EntitySpec{}, err
		}
	}
	if value, present := object["disabled"]; present {
		spec.Disabled, ok = value.(bool)
		if !ok {
			return EntitySpec{}, ErrInvalidAccessInput
		}
	}
	return normalizeEntitySpec(spec)
}

func DecodeGroupSpec(input io.Reader) (GroupSpec, error) {
	object, err := readAccessSpec(input)
	if err != nil {
		return GroupSpec{}, err
	}
	for key := range object {
		if key != "name" && key != "policies" && key != "member_entity_ids" && key != "member_group_ids" {
			return GroupSpec{}, ErrInvalidAccessInput
		}
	}
	name, ok := object["name"].(string)
	if !ok {
		return GroupSpec{}, ErrInvalidAccessInput
	}
	spec := GroupSpec{Name: name, Policies: []string{}, MemberEntityIDs: []string{}, MemberGroupIDs: []string{}}
	for key, destination := range map[string]*[]string{
		"policies":          &spec.Policies,
		"member_entity_ids": &spec.MemberEntityIDs,
		"member_group_ids":  &spec.MemberGroupIDs,
	} {
		if value, present := object[key]; present {
			*destination, err = identitySpecStrings(value)
			if err != nil {
				return GroupSpec{}, err
			}
		}
	}
	return normalizeGroupSpec(spec)
}

func identitySpecStrings(value any) ([]string, error) {
	if _, ok := value.([]any); !ok {
		return nil, ErrInvalidAccessInput
	}
	values, err := accessStringList(value)
	if err != nil {
		return nil, ErrInvalidAccessInput
	}
	return values, nil
}

func normalizeEntitySpec(spec EntitySpec) (EntitySpec, error) {
	if !validateAccessName(spec.Name) {
		return EntitySpec{}, ErrInvalidAccessInput
	}
	policies, err := normalizeAccessPolicies(spec.Policies, false)
	if err != nil {
		return EntitySpec{}, ErrInvalidAccessInput
	}
	spec.Policies = policies
	return spec, nil
}

func normalizeGroupSpec(spec GroupSpec) (GroupSpec, error) {
	if !validateAccessName(spec.Name) {
		return GroupSpec{}, ErrInvalidAccessInput
	}
	var err error
	spec.Policies, err = normalizeAccessPolicies(spec.Policies, false)
	if err != nil {
		return GroupSpec{}, ErrInvalidAccessInput
	}
	spec.MemberEntityIDs, err = normalizeIdentityMembers(spec.MemberEntityIDs, maxIdentityMembers)
	if err != nil {
		return GroupSpec{}, ErrInvalidAccessInput
	}
	spec.MemberGroupIDs, err = normalizeIdentityMembers(spec.MemberGroupIDs, maxIdentityMembers)
	if err != nil {
		return GroupSpec{}, ErrInvalidAccessInput
	}
	return spec, nil
}

func normalizeIdentityMembers(values []string, limit int) ([]string, error) {
	if len(values) > limit {
		return nil, ErrInvalidAccessInput
	}
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validateIdentityID(value) {
			return nil, ErrInvalidAccessInput
		}
		unique[strings.ToLower(value)] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func (c *Client) ListEntities(ctx context.Context, token string) ([]string, error) {
	return c.listIdentities(ctx, token, "entity")
}

func (c *Client) ListGroups(ctx context.Context, token string) ([]string, error) {
	return c.listIdentities(ctx, token, "group")
}

func (c *Client) listIdentities(ctx context.Context, token, resource string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return nil, err
	}
	defer client.SetToken("")
	secret, err := accessRead(ctx, client, "identity/"+resource+"/id", true)
	if err != nil {
		return nil, err
	}
	return accessNames(secret, true)
}

func (c *Client) ReadEntity(ctx context.Context, token, id string) (EntityReport, error) {
	if !validateIdentityID(id) {
		return EntityReport{}, ErrInvalidAccessInput
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return EntityReport{}, err
	}
	defer client.SetToken("")
	return readEntityIdentity(ctx, client, id)
}

func readEntityIdentity(ctx context.Context, client *api.Client, id string) (EntityReport, error) {
	secret, err := accessRead(ctx, client, "identity/entity/id/"+id, false)
	if err != nil {
		return EntityReport{}, err
	}
	return parseEntityIdentity(secret, id, "")
}

func parseEntityIdentity(secret *api.Secret, expectedID, expectedName string) (EntityReport, error) {
	if secret == nil || secret.Data == nil {
		return EntityReport{}, ErrAccessResponse
	}
	actualID, idOK := secret.Data["id"].(string)
	name, nameOK := secret.Data["name"].(string)
	disabled, disabledOK := secret.Data["disabled"].(bool)
	if !idOK || !validateIdentityID(actualID) || expectedID != "" && !strings.EqualFold(actualID, expectedID) ||
		!nameOK || !validateAccessName(name) || expectedName != "" && name != expectedName || !disabledOK {
		return EntityReport{}, ErrAccessResponse
	}
	policies, err := accessStringList(secret.Data["policies"])
	if err != nil {
		return EntityReport{}, ErrAccessResponse
	}
	policies, err = normalizeAccessPolicies(policies, false)
	if err != nil {
		return EntityReport{}, ErrAccessResponse
	}
	return EntityReport{ID: strings.ToLower(actualID), Name: name, Policies: policies, Disabled: disabled}, nil
}

func (c *Client) ReadGroup(ctx context.Context, token, id string) (GroupReport, error) {
	if !validateIdentityID(id) {
		return GroupReport{}, ErrInvalidAccessInput
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return GroupReport{}, err
	}
	defer client.SetToken("")
	return readGroupIdentity(ctx, client, "id/"+id, id)
}

func readGroupIdentity(ctx context.Context, client *api.Client, suffix, expectedID string) (GroupReport, error) {
	secret, err := accessRead(ctx, client, "identity/group/"+suffix, false)
	if err != nil {
		return GroupReport{}, err
	}
	id, idOK := secret.Data["id"].(string)
	name, nameOK := secret.Data["name"].(string)
	kind, typeOK := secret.Data["type"].(string)
	if !idOK || !validateIdentityID(id) || expectedID != "" && !strings.EqualFold(id, expectedID) ||
		!nameOK || !validateAccessName(name) || !typeOK || kind != "internal" && kind != "external" {
		return GroupReport{}, ErrAccessResponse
	}
	policies, err := accessStringList(secret.Data["policies"])
	if err != nil {
		return GroupReport{}, ErrAccessResponse
	}
	policies, err = normalizeAccessPolicies(policies, false)
	if err != nil {
		return GroupReport{}, ErrAccessResponse
	}
	entityIDs, err := accessStringList(secret.Data["member_entity_ids"])
	if err != nil {
		return GroupReport{}, ErrAccessResponse
	}
	entityIDs, err = normalizeIdentityMembers(entityIDs, MaxAccessList)
	if err != nil {
		return GroupReport{}, ErrAccessResponse
	}
	groupIDs, err := accessStringList(secret.Data["member_group_ids"])
	if err != nil {
		return GroupReport{}, ErrAccessResponse
	}
	groupIDs, err = normalizeIdentityMembers(groupIDs, MaxAccessList)
	if err != nil {
		return GroupReport{}, ErrAccessResponse
	}
	return GroupReport{ID: strings.ToLower(id), Name: name, Type: kind, Policies: policies, MemberEntityIDs: entityIDs, MemberGroupIDs: groupIDs}, nil
}

func (c *Client) WriteEntity(ctx context.Context, token, id string, spec EntitySpec) (AccessResult, error) {
	if id != "" && !validateIdentityID(id) {
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
	path := "identity/entity"
	if id != "" {
		if _, err := readEntityIdentity(ctx, client, id); err != nil {
			return AccessResult{}, err
		}
		path += "/id/" + id
	}
	secret, err := accessWrite(ctx, client, http.MethodPost, path, map[string]any{
		"name": spec.Name, "policies": spec.Policies, "disabled": spec.Disabled,
	})
	if err != nil {
		return AccessResult{}, err
	}
	return identityWriteResult(secret, "entity", spec.Name, id)
}

func (c *Client) WriteGroup(ctx context.Context, token, id string, spec GroupSpec) (AccessResult, error) {
	if id != "" && !validateIdentityID(id) {
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
	path, suffix := "identity/group", "name/"+spec.Name
	if id != "" {
		path, suffix = path+"/id/"+id, "id/"+id
	}
	existing, err := readGroupIdentity(ctx, client, suffix, id)
	if err != nil && (id != "" || !errors.Is(err, ErrNotFound)) {
		return AccessResult{}, err
	}
	if err == nil && existing.Type != "internal" {
		return AccessResult{}, ErrInvalidAccessInput
	}
	secret, err := accessWrite(ctx, client, http.MethodPost, path, map[string]any{
		"name": spec.Name, "policies": spec.Policies, "type": "internal",
		"member_entity_ids": spec.MemberEntityIDs, "member_group_ids": spec.MemberGroupIDs,
	})
	if err != nil {
		return AccessResult{}, err
	}
	knownID := id
	if knownID == "" && existing.ID != "" {
		knownID = existing.ID
	}
	return identityWriteResult(secret, "group", spec.Name, knownID)
}

func identityWriteResult(secret *api.Secret, resource, name, knownID string) (AccessResult, error) {
	id := knownID
	if secret != nil && secret.Data != nil {
		if raw, present := secret.Data["id"]; present {
			actualID, ok := raw.(string)
			if !ok || !validateIdentityID(actualID) || knownID != "" && !strings.EqualFold(actualID, knownID) {
				return AccessResult{}, ErrAccessUnconfirmed
			}
			id = actualID
		}
	}
	if !validateIdentityID(id) {
		return AccessResult{}, ErrAccessUnconfirmed
	}
	return AccessResult{Resource: resource, Name: name, ID: strings.ToLower(id)}, nil
}

func (c *Client) DeleteEntity(ctx context.Context, token, id string) (AccessResult, error) {
	if !validateIdentityID(id) {
		return AccessResult{}, ErrInvalidAccessInput
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return AccessResult{}, err
	}
	defer client.SetToken("")
	if _, err := accessWrite(ctx, client, http.MethodDelete, "identity/entity/id/"+id, nil); err != nil {
		return AccessResult{}, err
	}
	return AccessResult{Resource: "entity", ID: strings.ToLower(id), Deleted: true}, nil
}

func (c *Client) DeleteGroup(ctx context.Context, token, id string) (AccessResult, error) {
	if !validateIdentityID(id) {
		return AccessResult{}, ErrInvalidAccessInput
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return AccessResult{}, err
	}
	defer client.SetToken("")
	group, err := readGroupIdentity(ctx, client, "id/"+id, id)
	if err != nil {
		return AccessResult{}, err
	}
	if group.Type != "internal" {
		return AccessResult{}, ErrInvalidAccessInput
	}
	if _, err := accessWrite(ctx, client, http.MethodDelete, "identity/group/id/"+id, nil); err != nil {
		return AccessResult{}, err
	}
	return AccessResult{Resource: "group", ID: strings.ToLower(id), Deleted: true}, nil
}
