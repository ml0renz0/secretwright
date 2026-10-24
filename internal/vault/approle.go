package vault

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/api"
)

type AppRoleOptions struct {
	Mount string
}

type RoleSpec struct {
	TokenPolicies   []string `json:"token_policies"`
	TokenTTL        string   `json:"token_ttl"`
	TokenMaxTTL     string   `json:"token_max_ttl"`
	SecretIDTTL     string   `json:"secret_id_ttl"`
	SecretIDNumUses int      `json:"secret_id_num_uses"`
	TokenNumUses    int      `json:"token_num_uses"`
}

type RoleReport struct {
	Name                 string   `json:"name"`
	AuthMount            string   `json:"auth_mount"`
	TokenPolicies        []string `json:"token_policies"`
	TokenTTLSeconds      int64    `json:"token_ttl_seconds"`
	TokenMaxTTLSeconds   int64    `json:"token_max_ttl_seconds"`
	SecretIDTTLSeconds   int64    `json:"secret_id_ttl_seconds"`
	SecretIDNumUses      int      `json:"secret_id_num_uses"`
	TokenNumUses         int      `json:"token_num_uses"`
	BindSecretID         bool     `json:"bind_secret_id"`
	TokenNoDefaultPolicy bool     `json:"token_no_default_policy"`
}

// Ordinary JSON encoding exposes only the safe report. The dedicated private
// codec is the only JSON output that includes the AppRole credentials.
type AppRoleCredentials struct {
	RoleID           string           `json:"-"`
	SecretID         string           `json:"-"`
	SecretIDAccessor string           `json:"-"`
	Report           CredentialReport `json:"report"`
}

func DecodeRoleSpec(input io.Reader) (RoleSpec, error) {
	object, err := readAccessSpec(input)
	if err != nil {
		return RoleSpec{}, err
	}
	for field := range object {
		switch field {
		case "token_policies", "token_ttl", "token_max_ttl", "secret_id_ttl", "secret_id_num_uses", "token_num_uses":
		default:
			return RoleSpec{}, ErrInvalidAccessInput
		}
	}
	policies, err := accessStringList(object["token_policies"])
	if err != nil {
		return RoleSpec{}, ErrInvalidAccessInput
	}
	ttl, ttlOK := object["token_ttl"].(string)
	maximumTTL, maximumOK := object["token_max_ttl"].(string)
	secretTTL, secretOK := object["secret_id_ttl"].(string)
	uses, err := accessNumber(object["secret_id_num_uses"])
	if err != nil || uses < 1 || uses > 1000 || !ttlOK || !maximumOK || !secretOK {
		return RoleSpec{}, ErrInvalidAccessInput
	}
	tokenUses := int64(0)
	if value, present := object["token_num_uses"]; present {
		tokenUses, err = accessNumber(value)
		if err != nil || tokenUses < 0 || tokenUses > 1000 {
			return RoleSpec{}, ErrInvalidAccessInput
		}
	}
	spec := RoleSpec{
		TokenPolicies:   policies,
		TokenTTL:        ttl,
		TokenMaxTTL:     maximumTTL,
		SecretIDTTL:     secretTTL,
		SecretIDNumUses: int(uses),
		TokenNumUses:    int(tokenUses),
	}
	normalized, _, err := prepareRoleSpec(spec)
	return normalized, err
}

func prepareRoleSpec(spec RoleSpec) (RoleSpec, map[string]any, error) {
	policies, err := normalizeAccessPolicies(spec.TokenPolicies, true)
	if err != nil {
		return RoleSpec{}, nil, err
	}
	ttl, err := accessDurationSeconds(spec.TokenTTL)
	if err != nil {
		return RoleSpec{}, nil, err
	}
	maximumTTL, err := accessDurationSeconds(spec.TokenMaxTTL)
	if err != nil || maximumTTL < ttl {
		return RoleSpec{}, nil, ErrInvalidAccessInput
	}
	secretTTL, err := accessDurationSeconds(spec.SecretIDTTL)
	if err != nil || spec.SecretIDNumUses < 1 || spec.SecretIDNumUses > 1000 || spec.TokenNumUses < 0 || spec.TokenNumUses > 1000 {
		return RoleSpec{}, nil, ErrInvalidAccessInput
	}
	spec.TokenPolicies = policies
	body := map[string]any{
		"token_policies":          policies,
		"token_ttl":               ttl,
		"token_max_ttl":           maximumTTL,
		"secret_id_ttl":           secretTTL,
		"secret_id_num_uses":      spec.SecretIDNumUses,
		"token_num_uses":          spec.TokenNumUses,
		"bind_secret_id":          true,
		"token_no_default_policy": true,
		"token_type":              "service",
		"token_period":            0,
	}
	return spec, body, nil
}

func DecodeAppRoleCredentials(input io.Reader) (AppRoleCredentials, error) {
	object, err := readAccessSpec(input)
	if err != nil {
		return AppRoleCredentials{}, err
	}
	for field := range object {
		if field != "role_id" && field != "secret_id" && field != "secret_id_accessor" {
			return AppRoleCredentials{}, ErrInvalidAccessInput
		}
	}
	roleID, roleOK := object["role_id"].(string)
	secretID, secretOK := object["secret_id"].(string)
	if !roleOK || !secretOK || !validAccessCredential(roleID) || !validAccessCredential(secretID) {
		return AppRoleCredentials{}, ErrInvalidAccessInput
	}
	accessor := ""
	if value, present := object["secret_id_accessor"]; present {
		var ok bool
		accessor, ok = value.(string)
		if !ok || !validAccessCredential(accessor) {
			return AppRoleCredentials{}, ErrInvalidAccessInput
		}
	}
	return AppRoleCredentials{RoleID: roleID, SecretID: secretID, SecretIDAccessor: accessor}, nil
}

func EncodeAppRoleCredentials(output io.Writer, credentials AppRoleCredentials) error {
	if output == nil || !validAccessCredential(credentials.RoleID) || !validAccessCredential(credentials.SecretID) || !validAccessCredential(credentials.SecretIDAccessor) {
		return ErrInvalidAccessInput
	}
	private := struct {
		RoleID           string `json:"role_id"`
		SecretID         string `json:"secret_id"`
		SecretIDAccessor string `json:"secret_id_accessor"`
	}{credentials.RoleID, credentials.SecretID, credentials.SecretIDAccessor}
	body, err := json.Marshal(private)
	if err != nil || len(body) >= MaxAccessSpecBytes {
		return ErrInvalidAccessInput
	}
	body = append(body, '\n')
	written, err := output.Write(body)
	if err != nil || written != len(body) {
		return ErrInvalidAccessInput
	}
	return nil
}

func normalizedAppRoleMount(opts AppRoleOptions) (string, error) {
	mount := opts.Mount
	if mount == "" {
		mount = "approle"
	}
	for _, segment := range strings.Split(mount, "/") {
		if !validateAccessName(segment) {
			return "", ErrInvalidAccessInput
		}
	}
	return mount, nil
}

func appRolePath(name string, opts AppRoleOptions) (string, string, error) {
	if !validateAccessName(name) {
		return "", "", ErrInvalidAccessInput
	}
	mount, err := normalizedAppRoleMount(opts)
	if err != nil {
		return "", "", err
	}
	return "auth/" + mount + "/role/" + name, mount, nil
}

func (c *Client) ListAppRoles(ctx context.Context, token string, opts AppRoleOptions) ([]string, error) {
	mount, err := normalizedAppRoleMount(opts)
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
	secret, err := accessRead(ctx, client, "auth/"+mount+"/role", true)
	if err != nil {
		return nil, err
	}
	return accessNames(secret, false)
}

func (c *Client) ReadAppRole(ctx context.Context, token, name string, opts AppRoleOptions) (RoleReport, error) {
	path, mount, err := appRolePath(name, opts)
	if err != nil {
		return RoleReport{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return RoleReport{}, err
	}
	defer client.SetToken("")
	secret, err := accessRead(ctx, client, path, false)
	if err != nil {
		return RoleReport{}, err
	}
	return parseRoleReport(secret, name, mount)
}

func parseRoleReport(secret *api.Secret, name, mount string) (RoleReport, error) {
	if secret == nil || secret.Data == nil {
		return RoleReport{}, ErrAccessResponse
	}
	data := secret.Data
	policies, err := accessStringList(data["token_policies"])
	if err != nil {
		return RoleReport{}, ErrAccessResponse
	}
	policies, err = normalizeAccessPolicies(policies, false)
	if err != nil {
		return RoleReport{}, ErrAccessResponse
	}
	ttl, err := accessNumber(data["token_ttl"])
	if err != nil || ttl < 0 {
		return RoleReport{}, ErrAccessResponse
	}
	maximumTTL, err := accessNumber(data["token_max_ttl"])
	if err != nil || maximumTTL < 0 {
		return RoleReport{}, ErrAccessResponse
	}
	secretTTL, err := accessNumber(data["secret_id_ttl"])
	if err != nil || secretTTL < 0 {
		return RoleReport{}, ErrAccessResponse
	}
	uses, err := accessNumber(data["secret_id_num_uses"])
	if err != nil || uses < 0 || int64(int(uses)) != uses {
		return RoleReport{}, ErrAccessResponse
	}
	tokenUses, err := accessNumber(data["token_num_uses"])
	if err != nil || tokenUses < 0 || int64(int(tokenUses)) != tokenUses {
		return RoleReport{}, ErrAccessResponse
	}
	bound, boundOK := data["bind_secret_id"].(bool)
	noDefault, noDefaultOK := data["token_no_default_policy"].(bool)
	if !boundOK || !noDefaultOK {
		return RoleReport{}, ErrAccessResponse
	}
	return RoleReport{
		Name:                 name,
		AuthMount:            mount,
		TokenPolicies:        policies,
		TokenTTLSeconds:      ttl,
		TokenMaxTTLSeconds:   maximumTTL,
		SecretIDTTLSeconds:   secretTTL,
		SecretIDNumUses:      int(uses),
		TokenNumUses:         int(tokenUses),
		BindSecretID:         bound,
		TokenNoDefaultPolicy: noDefault,
	}, nil
}

func (c *Client) WriteAppRole(ctx context.Context, token, name string, spec RoleSpec, opts AppRoleOptions) (AccessResult, error) {
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
	if _, err := accessWrite(ctx, client, http.MethodPost, path, body); err != nil {
		return AccessResult{}, err
	}
	return AccessResult{Resource: "approle", Name: name}, nil
}

func (c *Client) DeleteAppRole(ctx context.Context, token, name string, opts AppRoleOptions) (AccessResult, error) {
	path, _, err := appRolePath(name, opts)
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
	if _, err := accessWrite(ctx, client, http.MethodDelete, path, nil); err != nil {
		return AccessResult{}, err
	}
	return AccessResult{Resource: "approle", Name: name, Deleted: true}, nil
}

func readAppRoleID(ctx context.Context, client *api.Client, path string) (string, error) {
	secret, err := accessRead(ctx, client, path+"/role-id", false)
	if err != nil {
		return "", err
	}
	roleID, ok := secret.Data["role_id"].(string)
	if !ok || !validAccessCredential(roleID) {
		return "", ErrAccessResponse
	}
	return roleID, nil
}

func (c *Client) ReadAppRoleID(ctx context.Context, token, name string, opts AppRoleOptions) (string, error) {
	path, _, err := appRolePath(name, opts)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return "", err
	}
	defer client.SetToken("")
	return readAppRoleID(ctx, client, path)
}

func validateIssuableRole(secret *api.Secret, role RoleReport) error {
	if !role.BindSecretID || !role.TokenNoDefaultPolicy || role.TokenTTLSeconds <= 0 || role.TokenTTLSeconds > 86400 ||
		role.TokenMaxTTLSeconds < role.TokenTTLSeconds || role.TokenMaxTTLSeconds > 86400 ||
		role.SecretIDTTLSeconds <= 0 || role.SecretIDTTLSeconds > 86400 ||
		role.SecretIDNumUses < 1 || role.SecretIDNumUses > 1000 || role.TokenNumUses < 0 || role.TokenNumUses > 1000 {
		return ErrInvalidAccessInput
	}
	if _, err := normalizeAccessPolicies(role.TokenPolicies, true); err != nil {
		return err
	}
	kind, kindOK := secret.Data["token_type"].(string)
	if !kindOK || kind != "service" && kind != "default-service" {
		return ErrInvalidAccessInput
	}
	period, err := accessNumber(secret.Data["token_period"])
	if err != nil || period != 0 {
		return ErrInvalidAccessInput
	}
	return nil
}

func (c *Client) IssueAppRoleCredentials(ctx context.Context, token, name string, opts AppRoleOptions) (AppRoleCredentials, error) {
	path, mount, err := appRolePath(name, opts)
	if err != nil {
		return AppRoleCredentials{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return AppRoleCredentials{}, err
	}
	defer client.SetToken("")
	secret, err := accessRead(ctx, client, path, false)
	if err != nil {
		return AppRoleCredentials{}, err
	}
	role, err := parseRoleReport(secret, name, mount)
	if err != nil {
		return AppRoleCredentials{}, err
	}
	if err := validateIssuableRole(secret, role); err != nil {
		return AppRoleCredentials{}, err
	}
	roleID, err := readAppRoleID(ctx, client, path)
	if err != nil {
		return AppRoleCredentials{}, err
	}
	secret, err = accessWrite(ctx, client, http.MethodPost, path+"/secret-id", map[string]any{})
	if err != nil {
		return AppRoleCredentials{}, err
	}
	if secret == nil || secret.Data == nil {
		return AppRoleCredentials{}, ErrAccessUnconfirmed
	}
	secretID, secretOK := secret.Data["secret_id"].(string)
	accessor, accessorOK := secret.Data["secret_id_accessor"].(string)
	ttl, ttlErr := accessNumber(secret.Data["secret_id_ttl"])
	uses, usesErr := accessNumber(secret.Data["secret_id_num_uses"])
	if !secretOK || !accessorOK || !validAccessCredential(secretID) || !validAccessCredential(accessor) ||
		ttlErr != nil || ttl <= 0 || ttl > 86400 || usesErr != nil || uses < 1 || uses > 1000 {
		return AppRoleCredentials{}, ErrAccessUnconfirmed
	}
	return AppRoleCredentials{
		RoleID:           roleID,
		SecretID:         secretID,
		SecretIDAccessor: accessor,
		Report: CredentialReport{
			Kind:       "approle_credentials",
			Name:       name,
			AuthMount:  mount,
			Policies:   role.TokenPolicies,
			TTLSeconds: ttl,
			Uses:       int(uses),
		},
	}, nil
}

func (c *Client) RevokeAppRoleSecretID(ctx context.Context, token, name, accessor string, opts AppRoleOptions) (AccessResult, error) {
	path, _, err := appRolePath(name, opts)
	if err != nil {
		return AccessResult{}, err
	}
	if !validAccessCredential(accessor) {
		return AccessResult{}, ErrInvalidAccessInput
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return AccessResult{}, err
	}
	defer client.SetToken("")
	if _, err := accessWrite(ctx, client, http.MethodPost, path+"/secret-id-accessor/destroy", map[string]any{"secret_id_accessor": accessor}); err != nil {
		return AccessResult{}, err
	}
	return AccessResult{Resource: "approle_secret_id", Name: name, Deleted: true}, nil
}

func (c *Client) LoginAppRole(ctx context.Context, credentials AppRoleCredentials, opts AppRoleOptions) (IssuedToken, error) {
	mount, err := normalizedAppRoleMount(opts)
	if err != nil {
		return IssuedToken{}, err
	}
	if !validAccessCredential(credentials.RoleID) || !validAccessCredential(credentials.SecretID) {
		return IssuedToken{}, ErrInvalidAccessInput
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient("", true)
	if err != nil {
		return IssuedToken{}, err
	}
	defer client.SetToken("")
	secret, err := accessWrite(ctx, client, http.MethodPost, "auth/"+mount+"/login", map[string]any{
		"role_id": credentials.RoleID, "secret_id": credentials.SecretID,
	})
	if err != nil {
		return IssuedToken{}, err
	}
	token, err := parseIssuedToken(secret, "approle_login")
	if err != nil {
		return IssuedToken{}, err
	}
	token.Report.AuthMount = mount
	return token, nil
}
