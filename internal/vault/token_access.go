package vault

import (
	"context"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/hashicorp/vault/api"
)

// TokenSpec deliberately excludes policy inheritance, root policies, custom
// token IDs, orphan tokens, token roles, periods, and arbitrary metadata.
type TokenSpec struct {
	Policies       []string `json:"policies"`
	TTL            string   `json:"ttl"`
	ExplicitMaxTTL string   `json:"explicit_max_ttl"`
	Renewable      bool     `json:"renewable"`
	NumUses        int      `json:"num_uses"`
}

type CapabilityReport struct {
	Path         string   `json:"path"`
	Capabilities []string `json:"capabilities"`
}

// DecodeTokenSpec validates the entire configuration before any credential is
// selected or a request can be sent. Unknown and duplicate fields are rejected.
func DecodeTokenSpec(input io.Reader) (TokenSpec, error) {
	object, err := readAccessSpec(input)
	if err != nil {
		return TokenSpec{}, err
	}
	for name := range object {
		switch name {
		case "policies", "ttl", "explicit_max_ttl", "renewable", "num_uses":
		default:
			return TokenSpec{}, ErrInvalidAccessInput
		}
	}
	policies, err := accessStringList(object["policies"])
	if err != nil {
		return TokenSpec{}, ErrInvalidAccessInput
	}
	ttl, ttlOK := object["ttl"].(string)
	maximum, maximumOK := object["explicit_max_ttl"].(string)
	if !ttlOK || !maximumOK {
		return TokenSpec{}, ErrInvalidAccessInput
	}
	spec := TokenSpec{Policies: policies, TTL: ttl, ExplicitMaxTTL: maximum}
	if value, supplied := object["renewable"]; supplied {
		var ok bool
		spec.Renewable, ok = value.(bool)
		if !ok {
			return TokenSpec{}, ErrInvalidAccessInput
		}
	}
	if value, supplied := object["num_uses"]; supplied {
		uses, err := accessNumber(value)
		if err != nil || uses < 0 || uses > 1000 {
			return TokenSpec{}, ErrInvalidAccessInput
		}
		spec.NumUses = int(uses)
	}
	normalized, _, _, err := normalizeTokenSpec(spec)
	return normalized, err
}

func normalizeTokenSpec(spec TokenSpec) (TokenSpec, int64, int64, error) {
	policies, err := normalizeAccessPolicies(spec.Policies, true)
	if err != nil {
		return TokenSpec{}, 0, 0, err
	}
	ttl, err := accessDurationSeconds(spec.TTL)
	if err != nil {
		return TokenSpec{}, 0, 0, err
	}
	maximum, err := accessDurationSeconds(spec.ExplicitMaxTTL)
	if err != nil || maximum < ttl || spec.NumUses < 0 || spec.NumUses > 1000 {
		return TokenSpec{}, 0, 0, ErrInvalidAccessInput
	}
	spec.Policies = policies
	return spec, ttl, maximum, nil
}

// CreateToken always sends explicit, nonempty policies. Omitting policies, or
// sending an empty slice, would otherwise inherit the operator's privileges.
func (c *Client) CreateToken(ctx context.Context, token string, spec TokenSpec) (IssuedToken, error) {
	spec, ttl, maximum, err := normalizeTokenSpec(spec)
	if err != nil {
		return IssuedToken{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return IssuedToken{}, err
	}
	defer client.SetToken("")
	secret, err := accessWrite(ctx, client, http.MethodPost, "auth/token/create", map[string]any{
		"policies":          spec.Policies,
		"ttl":               ttl,
		"explicit_max_ttl":  maximum,
		"renewable":         spec.Renewable,
		"num_uses":          spec.NumUses,
		"no_default_policy": true,
		"no_parent":         false,
		"type":              "service",
	})
	if err != nil {
		return IssuedToken{}, err
	}
	return parseIssuedToken(secret, "token")
}

// parseIssuedToken is shared by token creation and unauthenticated AppRole
// login. Malformed successful responses can conceal a committed issuance.
func parseIssuedToken(secret *api.Secret, kind string) (IssuedToken, error) {
	if secret == nil || secret.Auth == nil {
		return IssuedToken{}, ErrAccessUnconfirmed
	}
	auth := secret.Auth
	if !validAccessCredential(auth.ClientToken) || !validAccessCredential(auth.Accessor) || auth.LeaseDuration <= 0 {
		return IssuedToken{}, ErrAccessUnconfirmed
	}
	policies, err := normalizeAccessPolicies(auth.Policies, true)
	if err != nil || auth.EntityID != "" && !validateIdentityID(auth.EntityID) {
		return IssuedToken{}, ErrAccessUnconfirmed
	}
	return IssuedToken{
		Token:    auth.ClientToken,
		Accessor: auth.Accessor,
		Report: CredentialReport{
			Kind:       kind,
			Policies:   policies,
			TTLSeconds: int64(auth.LeaseDuration),
			Renewable:  auth.Renewable,
			EntityID:   auth.EntityID,
		},
	}, nil
}

// RevokeToken revokes the selected token and its descendants. The target is a
// request-body credential and is never interpolated into the request path.
func (c *Client) RevokeToken(ctx context.Context, operator, target string) (AccessResult, error) {
	if !validAccessCredential(target) {
		return AccessResult{}, ErrInvalidAccessInput
	}
	return c.revokeAccessToken(ctx, operator, "auth/token/revoke", map[string]any{"token": target})
}

// RevokeSelf authenticates solely with the selected target token. This also
// permits best-effort cleanup after an AppRole login artifact cannot be saved.
func (c *Client) RevokeSelf(ctx context.Context, target string) (AccessResult, error) {
	if !validAccessCredential(target) {
		return AccessResult{}, ErrInvalidAccessInput
	}
	return c.revokeAccessToken(ctx, target, "auth/token/revoke-self", nil)
}

// RevokeTokenAccessor is used for compensating cleanup of a known token
// issuance. Accessors remain credentials supplied only through request bodies.
func (c *Client) RevokeTokenAccessor(ctx context.Context, operator, accessor string) (AccessResult, error) {
	if !validAccessCredential(accessor) {
		return AccessResult{}, ErrInvalidAccessInput
	}
	return c.revokeAccessToken(ctx, operator, "auth/token/revoke-accessor", map[string]any{"accessor": accessor})
}

func (c *Client) revokeAccessToken(ctx context.Context, token, path string, body map[string]any) (AccessResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return AccessResult{}, err
	}
	defer client.SetToken("")
	if _, err := accessWrite(ctx, client, http.MethodPost, path, body); err != nil {
		return AccessResult{}, err
	}
	return AccessResult{Resource: "token", Deleted: true}, nil
}

// ValidateCapabilityPaths validates physical API paths before credential
// selection. It deliberately performs no KV logical-to-physical translation.
func ValidateCapabilityPaths(paths []string) ([]string, error) {
	if len(paths) == 0 || len(paths) > 100 {
		return nil, ErrInvalidAccessInput
	}
	unique := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if path == "" || len(path) > MaxAccessSpecBytes || strings.HasPrefix(path, "/") || strings.HasPrefix(path, "v1/") || !validLogicalText(path) {
			return nil, ErrInvalidAccessInput
		}
		for _, segment := range strings.Split(strings.TrimSuffix(path, "/"), "/") {
			if segment == "" || segment == "." || segment == ".." {
				return nil, ErrInvalidAccessInput
			}
		}
		unique[path] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for path := range unique {
		result = append(result, path)
	}
	sort.Strings(result)
	return result, nil
}

// Capabilities queries only the supplied operator token. Although Vault uses
// POST, this endpoint is read-only and transport failures are not mutations.
func (c *Client) Capabilities(ctx context.Context, token string, paths []string) ([]CapabilityReport, error) {
	paths, err := ValidateCapabilityPaths(paths)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return nil, err
	}
	defer client.SetToken("")
	secret, err := readTokenCapabilities(ctx, client, paths)
	if err != nil {
		return nil, err
	}
	result := make([]CapabilityReport, 0, len(paths))
	for _, path := range paths {
		value, present := secret.Data[path]
		if !present && len(paths) == 1 {
			value = secret.Data["capabilities"]
		}
		capabilities, err := accessStringList(value)
		if err != nil || len(capabilities) == 0 {
			return nil, ErrAccessResponse
		}
		unique := make(map[string]struct{}, len(capabilities))
		for _, capability := range capabilities {
			switch capability {
			case "create", "read", "update", "delete", "list", "sudo", "patch", "subscribe", "deny", "root":
			default:
				return nil, ErrAccessResponse
			}
			unique[capability] = struct{}{}
		}
		projected := make([]string, 0, len(unique))
		for capability := range unique {
			projected = append(projected, capability)
		}
		sort.Strings(projected)
		result = append(result, CapabilityReport{Path: path, Capabilities: projected})
	}
	return result, nil
}

func readTokenCapabilities(ctx context.Context, client *api.Client, paths []string) (*api.Secret, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	request := client.NewRequest(http.MethodPost, "/v1/sys/capabilities-self")
	if err := request.SetJSONBody(map[string]any{"paths": paths}); err != nil {
		return nil, ErrInvalidAccessInput
	}
	response, err := client.RawRequestWithContext(ctx, request)
	if response != nil {
		defer response.Body.Close()
		if response.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
	}
	if err != nil {
		return nil, accessRequestError(err)
	}
	if response == nil || response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, ErrAccessResponse
	}
	secret, err := api.ParseSecret(response.Body)
	if err != nil || secret == nil || secret.Data == nil {
		return nil, ErrAccessResponse
	}
	return secret, nil
}
