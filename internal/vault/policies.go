package vault

import (
	"context"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"
)

const maxPolicyInputBytes = 1 << 20

type PolicyReport struct {
	Name   string `json:"name"`
	Policy string `json:"policy"`
}

// ReadPolicyInput preserves the requested HCL without interpreting it locally.
// Vault validates its syntax, and any rejection is reported without its body.
func ReadPolicyInput(input io.Reader) (string, error) {
	body, err := readBoundedJSON(input, maxPolicyInputBytes)
	if err != nil || len(strings.TrimSpace(string(body))) == 0 || strings.ContainsRune(string(body), 0) {
		return "", ErrInvalidAccessInput
	}
	return string(body), nil
}

func (c *Client) ListPolicies(ctx context.Context, token string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return nil, err
	}
	defer client.SetToken("")
	secret, err := accessRead(ctx, client, "sys/policies/acl", true)
	if err != nil {
		return nil, err
	}
	return accessNames(secret, false)
}

func (c *Client) ReadPolicy(ctx context.Context, token, name string) (PolicyReport, error) {
	if !validateAccessName(name) {
		return PolicyReport{}, ErrInvalidAccessInput
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return PolicyReport{}, err
	}
	defer client.SetToken("")
	secret, err := accessRead(ctx, client, "sys/policies/acl/"+name, false)
	if err != nil {
		return PolicyReport{}, err
	}
	policy, ok := secret.Data["policy"].(string)
	if !ok || len(policy) > maxPolicyInputBytes || !utf8.ValidString(policy) || strings.ContainsRune(policy, 0) {
		return PolicyReport{}, ErrAccessResponse
	}
	return PolicyReport{Name: name, Policy: policy}, nil
}

func (c *Client) WritePolicy(ctx context.Context, token, name, policy string) (AccessResult, error) {
	if !validateAccessName(name) || strings.EqualFold(name, "root") {
		return AccessResult{}, ErrInvalidAccessInput
	}
	if _, err := ReadPolicyInput(strings.NewReader(policy)); err != nil {
		return AccessResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return AccessResult{}, err
	}
	defer client.SetToken("")
	if _, err := accessWrite(ctx, client, http.MethodPost, "sys/policies/acl/"+name, map[string]any{"policy": policy}); err != nil {
		return AccessResult{}, err
	}
	return AccessResult{Resource: "policy", Name: name}, nil
}

func (c *Client) DeletePolicy(ctx context.Context, token, name string) (AccessResult, error) {
	if !validateAccessName(name) || strings.EqualFold(name, "root") || strings.EqualFold(name, "default") {
		return AccessResult{}, ErrInvalidAccessInput
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return AccessResult{}, err
	}
	defer client.SetToken("")
	if _, err := accessWrite(ctx, client, http.MethodDelete, "sys/policies/acl/"+name, nil); err != nil {
		return AccessResult{}, err
	}
	return AccessResult{Resource: "policy", Name: name, Deleted: true}, nil
}
