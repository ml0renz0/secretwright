package vault

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hashicorp/vault/api"
)

// ErrUnauthenticated means that lookup-self could not confirm authentication.
// A 403 may also mean a valid token lacks permission to inspect itself.
var ErrUnauthenticated = errors.New("Vault authentication could not be confirmed; provide a token with lookup-self permission")

// AuthStatus exposes only the explicitly supported, nonsensitive token metadata.
type AuthStatus struct {
	Authenticated bool     `json:"authenticated"`
	Namespace     string   `json:"namespace"`
	Policies      []string `json:"policies"`
	TTL           int64    `json:"ttl_seconds"`
	Renewable     bool     `json:"renewable"`
}

// CheckToken performs one read-only self-lookup. A separate SDK client isolates
// this token from concurrent health requests and other authentication checks.
func (c *Client) CheckToken(ctx context.Context, token string) (AuthStatus, error) {
	token, err := normalizeToken(token)
	if err != nil {
		return AuthStatus{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := api.NewClient(c.newConfig())
	if err != nil {
		return AuthStatus{}, errors.New("could not initialize the authentication client")
	}
	client.SetHeaders(requestHeaders())
	client.SetNamespace(c.namespace)
	client.SetToken(token)
	defer client.SetToken("")
	secret, err := client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return AuthStatus{}, safeRequestError(err, true)
	}
	invalid := errors.New("Vault returned invalid authentication metadata")
	if secret == nil || secret.Data == nil {
		return AuthStatus{}, invalid
	}
	rawPolicies, ok := secret.Data["policies"].([]interface{})
	if !ok {
		return AuthStatus{}, invalid
	}
	policies := make([]string, 0, len(rawPolicies))
	for _, value := range rawPolicies {
		policy, ok := value.(string)
		if !ok {
			return AuthStatus{}, invalid
		}
		policies = append(policies, policy)
	}
	ttlNumber, ok := secret.Data["ttl"].(json.Number)
	if !ok {
		return AuthStatus{}, invalid
	}
	ttl, err := ttlNumber.Int64()
	if err != nil || ttl < 0 {
		return AuthStatus{}, invalid
	}
	renewable, ok := secret.Data["renewable"].(bool)
	if !ok {
		return AuthStatus{}, invalid
	}
	return AuthStatus{
		Authenticated: true,
		Namespace:     c.namespace,
		Policies:      policies,
		TTL:           ttl,
		Renewable:     renewable,
	}, nil
}
