package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hashicorp/vault/api"
)

const (
	MaxAccessList      = 10000
	MaxAccessSpecBytes = 64 << 10
)

var (
	ErrInvalidAccessInput = errors.New("invalid access or identity input")
	ErrAccessResponse     = errors.New("Vault access request or response could not be validated")
	ErrAccessUnconfirmed  = errors.New("Vault access mutation outcome is not confirmed; verify the state before retrying")
	ErrAccessPartial      = errors.New("issued credential could not be saved and revocation was not confirmed; it may remain active")
)

// AccessResult projects only the resource selected by the caller and its ID.
type AccessResult struct {
	Resource string `json:"resource"`
	Name     string `json:"name,omitempty"`
	ID       string `json:"id,omitempty"`
	Deleted  bool   `json:"deleted,omitempty"`
}

// CredentialReport contains no bearer credential or revocation accessor.
type CredentialReport struct {
	Kind       string   `json:"kind"`
	Name       string   `json:"name,omitempty"`
	AuthMount  string   `json:"auth_mount,omitempty"`
	Policies   []string `json:"policies,omitempty"`
	TTLSeconds int64    `json:"ttl_seconds"`
	Renewable  bool     `json:"renewable"`
	EntityID   string   `json:"entity_id,omitempty"`
	Uses       int      `json:"uses,omitempty"`
}

// IssuedToken is deliberately safe to JSON-encode as an ordinary report. Only
// the credential-file writer may access Token and Accessor directly.
type IssuedToken struct {
	Token    string           `json:"-"`
	Accessor string           `json:"-"`
	Report   CredentialReport `json:"report"`
}

func (c *Client) accessClient(token string, anonymous bool) (*api.Client, error) {
	if !anonymous {
		return c.kvClient(token)
	}
	client, err := api.NewClient(c.newConfig())
	if err != nil {
		return nil, ErrAccessResponse
	}
	configureRequestClient(client, c.namespace, "")
	return client, nil
}

// accessRead retains denied and missing statuses without exposing an upstream
// URL, response body, warning or custom metadata in an error.
func accessRead(ctx context.Context, client *api.Client, path string, list bool) (*api.Secret, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	request := client.NewRequest(http.MethodGet, "/v1/"+path)
	if list {
		request.Params.Set("list", "true")
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

func accessRequestError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var responseError *api.ResponseError
	if errors.As(err, &responseError) {
		switch responseError.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return ErrPermissionDenied
		case http.StatusNotFound:
			return ErrNotFound
		}
	}
	return ErrAccessResponse
}

// A lost or malformed mutation response differs from a rejected request: the
// server may have committed it, so callers must never retry automatically.
func accessWrite(ctx context.Context, client *api.Client, method, path string, body map[string]any) (*api.Secret, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	secret, err := performMutation(ctx, client, method, path, body)
	if errors.Is(err, errMutationUnconfirmed) {
		if errors.Is(err, context.Canceled) {
			return nil, fmt.Errorf("%w: %w", ErrAccessUnconfirmed, context.Canceled)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: %w", ErrAccessUnconfirmed, context.DeadlineExceeded)
		}
		return nil, ErrAccessUnconfirmed
	}
	return secret, err
}

func validateAccessName(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		alphaNumeric := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
		if !alphaNumeric && (index == 0 || character != '_' && character != '-' && character != '.') {
			return false
		}
	}
	return true
}

func validateIdentityID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if value[index] != '-' {
				return false
			}
			continue
		}
		character := value[index]
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f' || character >= 'A' && character <= 'F') {
			return false
		}
	}
	return true
}

func normalizeAccessPolicies(values []string, requireIssued bool) ([]string, error) {
	if len(values) > 128 || requireIssued && len(values) == 0 {
		return nil, ErrInvalidAccessInput
	}
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validateAccessName(value) || requireIssued && strings.EqualFold(value, "root") {
			return nil, ErrInvalidAccessInput
		}
		unique[value] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func accessDurationSeconds(value string) (int64, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 || duration > 24*time.Hour || duration%time.Second != 0 {
		return 0, ErrInvalidAccessInput
	}
	return int64(duration / time.Second), nil
}

func readAccessSpec(input io.Reader) (map[string]any, error) {
	body, err := readBoundedJSON(input, MaxAccessSpecBytes)
	if err != nil {
		return nil, ErrInvalidAccessInput
	}
	value, err := decodeStrictJSON(body)
	if err != nil {
		return nil, ErrInvalidAccessInput
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) == 0 {
		return nil, ErrInvalidAccessInput
	}
	return object, nil
}

func accessStringList(value any) ([]string, error) {
	if value == nil {
		return []string{}, nil
	}
	if values, ok := value.([]string); ok {
		if len(values) > MaxAccessList {
			return nil, ErrAccessResponse
		}
		return append([]string{}, values...), nil
	}
	values, ok := value.([]any)
	if !ok || len(values) > MaxAccessList {
		return nil, ErrAccessResponse
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil, ErrAccessResponse
		}
		result = append(result, text)
	}
	return result, nil
}

func accessNumber(value any) (int64, error) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, ErrAccessResponse
	}
	parsed, err := number.Int64()
	if err != nil {
		return 0, ErrAccessResponse
	}
	return parsed, nil
}

func accessNames(secret *api.Secret, ids bool) ([]string, error) {
	if secret == nil || secret.Data == nil || secret.Data["keys"] == nil {
		return nil, ErrAccessResponse
	}
	values, err := accessStringList(secret.Data["keys"])
	if err != nil {
		return nil, err
	}
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		valid := validateAccessName(value)
		if ids {
			valid = validateIdentityID(value)
		}
		if !valid {
			return nil, ErrAccessResponse
		}
		unique[value] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func validAccessCredential(value string) bool {
	return value != "" && len(value) <= maximumTokenBytes && utf8.ValidString(value) &&
		strings.IndexFunc(value, func(character rune) bool { return unicode.IsSpace(character) || unicode.IsControl(character) }) < 0
}
