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

// Lookup proofs are deliberately excluded from ordinary report encoding.
type TokenLifecycleInfo struct {
	Exists bool `json:"exists"`
	TTLSeconds int64 `json:"ttl_seconds"`
	Renewable bool `json:"renewable"`
	Type string `json:"-"`
	NumUses int `json:"-"`
	Policies []string `json:"-"`
	IdentityPolicies []string `json:"-"`
	Path string `json:"-"`
	RoleName string `json:"-"`
	EntityID string `json:"-"`
}

type LeaseLifecycleInfo struct {
	Exists bool `json:"exists"`
	TTLSeconds int64 `json:"ttl_seconds"`
	Renewable bool `json:"renewable"`
}

// These body-based lookups are reads, despite requiring POST/PUT. In
// particular they must not be classified as uncertain writes on a lost reply.
func lifecycleLookup(ctx context.Context, client *api.Client, method, path string, body map[string]any, missing string) (*api.Secret, error) {
	if err := ctx.Err(); err != nil { return nil, err }
	request := client.NewRequest(method, "/v1/"+path)
	if request.SetJSONBody(body) != nil { return nil, ErrInvalidAccessInput }
	response, err := client.RawRequestWithContext(ctx, request)
	if response != nil { defer response.Body.Close() }
	if err != nil {
		var rejected *api.ResponseError
		if errors.As(err, &rejected) && len(rejected.Errors) == 1 && rejected.Errors[0] == missing && (rejected.StatusCode == 400 || missing == "bad token" && rejected.StatusCode == 403) { return nil, nil }
		return nil, accessRequestError(err)
	}
	if response == nil || response.StatusCode < 200 || response.StatusCode >= 300 { return nil, ErrAccessResponse }
	secret, err := api.ParseSecret(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || secret == nil || secret.Data == nil { return nil, ErrAccessResponse }
	return secret, nil
}

func lifecyclePolicies(value any) ([]string, error) {
	list, err := accessStringList(value)
	if err != nil || len(list) > 128 { return nil, ErrAccessResponse }
	for _, policy := range list { if !validateAccessName(policy) { return nil, ErrAccessResponse } }
	sort.Strings(list)
	return list, nil
}

func (c *Client) InspectLifecycleToken(ctx context.Context, operator, target string) (TokenLifecycleInfo, error) {
	operator, target = strings.TrimSpace(operator), strings.TrimSpace(target)
	if !validAccessCredential(operator) || !validAccessCredential(target) || operator == target { return TokenLifecycleInfo{}, ErrInvalidAccessInput }
	ctx, cancel := context.WithTimeout(ctx, c.timeout); defer cancel()
	client, err := c.accessClient(operator, false)
	if err != nil { return TokenLifecycleInfo{}, err }; defer client.SetToken("")
	secret, err := lifecycleLookup(ctx, client, http.MethodPost, "auth/token/lookup", map[string]any{"token": target}, "bad token")
	if err != nil || secret == nil { return TokenLifecycleInfo{}, err }
	data := secret.Data
	ttl, ttlErr := accessNumber(data["ttl"])
	uses, usesErr := accessNumber(data["num_uses"])
	renewable, renewableOK := data["renewable"].(bool)
	kind, kindOK := data["type"].(string)
	if ttlErr != nil || usesErr != nil || ttl < 0 || uses < 0 || uses > 1000 || !renewableOK || !kindOK || kind != "service" && kind != "batch" { return TokenLifecycleInfo{}, ErrAccessResponse }
	policies, err := lifecyclePolicies(data["policies"])
	if err != nil { return TokenLifecycleInfo{}, err }
	identityPolicies, err := lifecyclePolicies(data["identity_policies"])
	if err != nil { return TokenLifecycleInfo{}, err }
	info := TokenLifecycleInfo{Exists: true, TTLSeconds: ttl, Renewable: renewable, Type: kind, NumUses: int(uses), Policies: policies, IdentityPolicies: identityPolicies}
	for key, destination := range map[string]*string{"path": &info.Path, "entity_id": &info.EntityID} {
		if value, exists := data[key]; exists {
			text, ok := value.(string); if !ok || len(text) > 4096 { return TokenLifecycleInfo{}, ErrAccessResponse }; *destination = text
		}
	}
	if raw := data["meta"]; raw != nil {
		meta, ok := raw.(map[string]any); if !ok { return TokenLifecycleInfo{}, ErrAccessResponse }
		if rawRole, found := meta["role_name"]; found { role, ok := rawRole.(string); if !ok || !validateAccessName(role) { return TokenLifecycleInfo{}, ErrAccessResponse }; info.RoleName = role }
	}
	return info, nil
}

func lifecycleRenewableToken(info TokenLifecycleInfo) bool {
	if !info.Exists || !info.Renewable || info.Type != "service" || info.TTLSeconds <= 0 || info.NumUses != 0 { return false }
	for _, policies := range [][]string{info.Policies, info.IdentityPolicies} { for _, policy := range policies { if strings.EqualFold(policy, "root") { return false } } }
	return true
}

func (c *Client) RenewLifecycleToken(ctx context.Context, operator, target string, increment int64) (TokenLifecycleInfo, error) {
	if increment < 1 || increment > 86400 { return TokenLifecycleInfo{}, ErrInvalidAccessInput }
	ctx, cancel := context.WithTimeout(ctx, c.timeout); defer cancel()
	info, err := c.InspectLifecycleToken(ctx, operator, target)
	if err != nil { return TokenLifecycleInfo{}, err }
	if !info.Exists { return info, nil }
	if !lifecycleRenewableToken(info) { return TokenLifecycleInfo{}, ErrInvalidAccessInput }
	client, err := c.accessClient(operator, false)
	if err != nil { return TokenLifecycleInfo{}, err }; defer client.SetToken("")
	secret, err := accessWrite(ctx, client, http.MethodPut, "auth/token/renew", map[string]any{"token": strings.TrimSpace(target), "increment": increment})
	if err != nil { return TokenLifecycleInfo{}, err }
	if secret == nil || secret.Auth == nil || secret.Auth.LeaseDuration <= 0 || secret.Auth.ClientToken != strings.TrimSpace(target) { return TokenLifecycleInfo{}, ErrAccessUnconfirmed }
	info.TTLSeconds, info.Renewable = int64(secret.Auth.LeaseDuration), secret.Auth.Renewable
	return info, nil
}

func ValidateLifecycleLeaseID(id string) error {
	if len(id) == 0 || len(id) > 4096 { return ErrInvalidAccessInput }
	for _, segment := range strings.Split(id, "/") {
		if segment == "" || segment == "." || segment == ".." { return ErrInvalidAccessInput }
		for _, c := range segment { if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') { return ErrInvalidAccessInput } }
	}
	return nil
}

func (c *Client) InspectLifecycleLease(ctx context.Context, operator, id string) (LeaseLifecycleInfo, error) {
	if ValidateLifecycleLeaseID(id) != nil { return LeaseLifecycleInfo{}, ErrInvalidAccessInput }
	ctx, cancel := context.WithTimeout(ctx, c.timeout); defer cancel()
	client, err := c.accessClient(operator, false)
	if err != nil { return LeaseLifecycleInfo{}, err }; defer client.SetToken("")
	secret, err := lifecycleLookup(ctx, client, http.MethodPut, "sys/leases/lookup", map[string]any{"lease_id": id}, "invalid lease")
	if err != nil || secret == nil { return LeaseLifecycleInfo{}, err }
	ttl, err := accessNumber(secret.Data["ttl"])
	renewable, ok := secret.Data["renewable"].(bool)
	if err != nil || ttl < 0 || !ok { return LeaseLifecycleInfo{}, ErrAccessResponse }
	return LeaseLifecycleInfo{Exists: true, TTLSeconds: ttl, Renewable: renewable}, nil
}

func (c *Client) RenewLifecycleLease(ctx context.Context, operator, id string, increment int64) (LeaseLifecycleInfo, error) {
	if ValidateLifecycleLeaseID(id) != nil || increment < 1 || increment > 86400 { return LeaseLifecycleInfo{}, ErrInvalidAccessInput }
	ctx, cancel := context.WithTimeout(ctx, c.timeout); defer cancel()
	info, err := c.InspectLifecycleLease(ctx, operator, id)
	if err != nil || !info.Exists { return info, err }
	if !info.Renewable || info.TTLSeconds <= 0 { return LeaseLifecycleInfo{}, ErrInvalidAccessInput }
	client, err := c.accessClient(operator, false)
	if err != nil { return LeaseLifecycleInfo{}, err }; defer client.SetToken("")
	secret, err := accessWrite(ctx, client, http.MethodPut, "sys/leases/renew", map[string]any{"lease_id": id, "increment": increment})
	if err != nil { return LeaseLifecycleInfo{}, err }
	if secret == nil || secret.LeaseID != id || secret.LeaseDuration <= 0 { return LeaseLifecycleInfo{}, ErrAccessUnconfirmed }
	return LeaseLifecycleInfo{Exists: true, TTLSeconds: int64(secret.LeaseDuration), Renewable: secret.Renewable}, nil
}

func (c *Client) RevokeLifecycleLease(ctx context.Context, operator, id string) (LeaseLifecycleInfo, error) {
	if ValidateLifecycleLeaseID(id) != nil { return LeaseLifecycleInfo{}, ErrInvalidAccessInput }
	ctx, cancel := context.WithTimeout(ctx, c.timeout); defer cancel()
	info, err := c.InspectLifecycleLease(ctx, operator, id)
	if err != nil || !info.Exists { return info, err }
	client, err := c.accessClient(operator, false)
	if err != nil { return LeaseLifecycleInfo{}, err }; defer client.SetToken("")
	_, err = accessWrite(ctx, client, http.MethodPut, "sys/leases/revoke", map[string]any{"lease_id": id, "sync": true})
	if err != nil { return LeaseLifecycleInfo{}, err }
	confirmed, err := c.InspectLifecycleLease(ctx, operator, id)
	if err != nil || confirmed.Exists { return LeaseLifecycleInfo{}, ErrAccessUnconfirmed }
	return confirmed, nil
}
