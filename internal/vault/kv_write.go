package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
)

var (
	ErrConflict             = errors.New("Vault check-and-set conflict; read the current version before retrying")
	ErrPartial              = errors.New("destination written; source deletion not confirmed; verify both before retrying")
	ErrInvalidData          = errors.New("secret data must be a nonempty JSON object with serializable values")
	ErrUnsupportedOperation = errors.New("operation or option is not supported for this KV engine")
	errMutationUnconfirmed  = errors.New("Vault mutation outcome is not confirmed; it may have applied; verify the state before retrying")
)

// WriteOptions retains whether CAS was supplied, including an explicit zero.
type WriteOptions struct {
	KVOptions
	CAS   *int
	Force bool
}

// WriteResult deliberately omits the values supplied to a mutation.
type WriteResult struct {
	Path      string `json:"path"`
	KVVersion int    `json:"kv_version"`
	Version   int    `json:"version,omitempty"`
}

type MutationResult struct {
	Path      string `json:"path"`
	KVVersion int    `json:"kv_version"`
	Versions  []int  `json:"versions,omitempty"`
}

type CopyResult struct {
	Source        string `json:"source"`
	Destination   string `json:"destination"`
	KVVersion     int    `json:"kv_version"`
	Version       int    `json:"version,omitempty"`
	SourceVersion int    `json:"source_version,omitempty"`
	SourceDeleted bool   `json:"source_deleted"`
}

type kvTarget struct {
	logical string
	mount   Mount
	key     string
}

// Put replaces one value. A KV v2 destination is create-only unless its caller
// supplies the exact revision to replace; KV v1 has no conditional write API.
func (c *Client) Put(ctx context.Context, token, target string, data map[string]any, opts WriteOptions) (WriteResult, error) {
	if err := validateWriteOptions(opts); err != nil {
		return WriteResult{}, err
	}
	if opts.Force {
		return WriteResult{}, ErrUnsupportedOperation
	}
	if err := validateSecretData(data); err != nil {
		return WriteResult{}, err
	}
	_, explicit, err := validateKVTarget(target, opts.KVOptions)
	if err != nil {
		return WriteResult{}, err
	}
	if explicit != nil && explicit.Version == 1 && opts.CAS != nil {
		return WriteResult{}, ErrUnsupportedOperation
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.kvClient(token)
	if err != nil {
		return WriteResult{}, err
	}
	defer client.SetToken("")
	selected, err := resolveKVTarget(ctx, client, target, opts.KVOptions)
	if err != nil {
		return WriteResult{}, err
	}
	return writeSnapshot(ctx, client, selected, data, opts.CAS)
}

// Remove never deletes an engine, a directory recursively, or KV v2 metadata.
func (c *Client) Remove(ctx context.Context, token, target string, versions []int, opts WriteOptions) (MutationResult, error) {
	if err := validateWriteOptions(opts); err != nil {
		return MutationResult{}, err
	}
	if opts.CAS != nil {
		return MutationResult{}, ErrUnsupportedOperation
	}
	versions, err := canonicalVersions(versions, false)
	if err != nil {
		return MutationResult{}, err
	}
	_, explicit, err := validateKVTarget(target, opts.KVOptions)
	if err != nil {
		return MutationResult{}, err
	}
	if explicit != nil && explicit.Version == 1 && (!opts.Force || len(versions) != 0) {
		return MutationResult{}, ErrUnsupportedOperation
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.kvClient(token)
	if err != nil {
		return MutationResult{}, err
	}
	defer client.SetToken("")
	selected, err := resolveKVTarget(ctx, client, target, opts.KVOptions)
	if err != nil {
		return MutationResult{}, err
	}
	method, physical := http.MethodDelete, selected.mount.Path+selected.key
	var body map[string]any
	if selected.mount.Version == 1 {
		if !opts.Force || len(versions) != 0 {
			return MutationResult{}, ErrUnsupportedOperation
		}
	} else if len(versions) == 0 {
		physical = selected.mount.Path + "data/" + selected.key
	} else {
		method, physical = http.MethodPost, selected.mount.Path+"delete/"+selected.key
		body = map[string]any{"versions": versions}
	}
	if _, err := performMutation(ctx, client, method, physical, body); err != nil {
		return MutationResult{}, err
	}
	return MutationResult{Path: selected.logical, KVVersion: selected.mount.Version, Versions: versions}, nil
}

// Copy transfers the latest values without copying history or deleting source.
func (c *Client) Copy(ctx context.Context, token, source, destination string, opts WriteOptions) (CopyResult, error) {
	return c.copyOrMove(ctx, token, source, destination, opts, false)
}

// Move is intentionally not atomic. Once destination creation is confirmed, a
// deletion failure retains that destination and reports the partial outcome.
func (c *Client) Move(ctx context.Context, token, source, destination string, opts WriteOptions) (CopyResult, error) {
	return c.copyOrMove(ctx, token, source, destination, opts, true)
}

func (c *Client) copyOrMove(ctx context.Context, token, source, destination string, opts WriteOptions, move bool) (CopyResult, error) {
	if err := validateWriteOptions(opts); err != nil {
		return CopyResult{}, err
	}
	sourcePath, _, err := validateKVTarget(source, opts.KVOptions)
	if err != nil {
		return CopyResult{}, err
	}
	destinationPath, explicit, err := validateKVTarget(destination, opts.KVOptions)
	if err != nil {
		return CopyResult{}, err
	}
	if sourcePath == destinationPath {
		return CopyResult{}, ErrInvalidPath
	}
	if explicit != nil && explicit.Version == 1 && (!opts.Force || opts.CAS != nil) {
		return CopyResult{}, ErrUnsupportedOperation
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.kvClient(token)
	if err != nil {
		return CopyResult{}, err
	}
	defer client.SetToken("")
	src, err := resolveKVTarget(ctx, client, source, opts.KVOptions)
	if err != nil {
		return CopyResult{}, err
	}
	if move && src.mount.Version == 1 && !opts.Force {
		return CopyResult{}, ErrUnsupportedOperation
	}
	dst, err := resolveKVTarget(ctx, client, destination, opts.KVOptions)
	if err != nil {
		return CopyResult{}, err
	}
	if dst.mount.Version == 1 && (!opts.Force || opts.CAS != nil) {
		return CopyResult{}, ErrUnsupportedOperation
	}
	data, sourceVersion, err := readSnapshot(ctx, client, src, 0, move)
	if err != nil {
		return CopyResult{}, err
	}
	written, err := writeSnapshot(ctx, client, dst, data, opts.CAS)
	if err != nil {
		// An unconfirmed destination mutation must never trigger source deletion.
		return CopyResult{}, err
	}
	result := CopyResult{
		Source: src.logical, Destination: dst.logical, KVVersion: dst.mount.Version,
		Version: written.Version, SourceVersion: sourceVersion,
	}
	if !move {
		return result, nil
	}
	method, physical := http.MethodDelete, src.mount.Path+src.key
	var body map[string]any
	if src.mount.Version == 2 {
		method, physical = http.MethodPost, src.mount.Path+"delete/"+src.key
		body = map[string]any{"versions": []int{sourceVersion}}
	}
	if _, err := performMutation(ctx, client, method, physical, body); err != nil {
		return result, fmt.Errorf("%w: %w", ErrPartial, err)
	}
	result.SourceDeleted = true
	return result, nil
}

func validateWriteOptions(opts WriteOptions) error {
	if opts.CAS != nil && *opts.CAS < 0 {
		return ErrInvalidPath
	}
	return nil
}

func validateSecretData(data map[string]any) error {
	if len(data) == 0 {
		return ErrInvalidData
	}
	_, err := json.Marshal(data)
	if err != nil {
		return ErrInvalidData
	}
	return nil
}

func validateKVTarget(target string, opts KVOptions) (string, *Mount, error) {
	logical, explicit, err := prepareKVPath(target, opts)
	if err != nil {
		return "", nil, err
	}
	if logical == "/" || (explicit != nil && logical == "/"+strings.TrimSuffix(explicit.Path, "/")) {
		return "", nil, ErrInvalidPath
	}
	return logical, explicit, nil
}

func resolveKVTarget(ctx context.Context, client *api.Client, target string, opts KVOptions) (kvTarget, error) {
	logical, explicit, err := validateKVTarget(target, opts)
	if err != nil {
		return kvTarget{}, err
	}
	mount, err := selectMount(ctx, client, logical, explicit)
	if err != nil {
		return kvTarget{}, err
	}
	key := strings.TrimPrefix(strings.TrimPrefix(logical, "/"+strings.TrimSuffix(mount.Path, "/")), "/")
	if key == "" {
		return kvTarget{}, ErrInvalidPath
	}
	return kvTarget{logical: logical, mount: mount, key: key}, nil
}

func writeSnapshot(ctx context.Context, client *api.Client, target kvTarget, data map[string]any, cas *int) (WriteResult, error) {
	if err := validateSecretData(data); err != nil {
		return WriteResult{}, err
	}
	if cas != nil && *cas < 0 {
		return WriteResult{}, ErrInvalidPath
	}
	physical, body := target.mount.Path+target.key, data
	if target.mount.Version == 1 {
		if cas != nil {
			return WriteResult{}, ErrUnsupportedOperation
		}
	} else {
		normalized, err := validateKV2Numbers(data)
		if err != nil {
			return WriteResult{}, err
		}
		comparison := 0
		if cas != nil {
			comparison = *cas
		}
		physical = target.mount.Path + "data/" + target.key
		body = map[string]any{"data": normalized, "options": map[string]any{"cas": comparison}}
	}
	secret, err := performMutation(ctx, client, http.MethodPost, physical, body)
	if err != nil {
		return WriteResult{}, err
	}
	result := WriteResult{Path: target.logical, KVVersion: target.mount.Version}
	if target.mount.Version == 2 {
		if secret == nil || secret.Data == nil {
			return WriteResult{}, mutationUnconfirmed(nil)
		}
		version, err := metadataInteger(secret.Data["version"], false)
		if err != nil {
			return WriteResult{}, mutationUnconfirmed(nil)
		}
		result.Version = version
	}
	return result, nil
}

func readSnapshot(ctx context.Context, client *api.Client, target kvTarget, version int, requireVersion bool) (map[string]any, int, error) {
	if version < 0 {
		return nil, 0, ErrInvalidPath
	}
	if target.mount.Version == 1 && version != 0 {
		return nil, 0, ErrUnsupportedOperation
	}
	physical := target.mount.Path + target.key
	if target.mount.Version == 2 {
		physical = target.mount.Path + "data/" + target.key
	}
	var secret *api.Secret
	var err error
	if version == 0 {
		secret, err = readLogical(ctx, client, physical, false)
	} else {
		secret, err = readVersionLogical(ctx, client, physical, version)
	}
	if err != nil {
		return nil, 0, err
	}
	if secret == nil || secret.Data == nil {
		return nil, 0, ErrNotFound
	}
	if target.mount.Version == 1 {
		return secret.Data, 0, nil
	}
	rawData, present := secret.Data["data"]
	if !present {
		return nil, 0, errKVResponse
	}
	if rawData == nil {
		return nil, 0, ErrNotFound
	}
	data, ok := rawData.(map[string]interface{})
	if !ok {
		return nil, 0, errKVResponse
	}
	capturedVersion := 0
	if rawMetadata, present := secret.Data["metadata"]; present {
		metadata, ok := rawMetadata.(map[string]interface{})
		if !ok {
			return nil, 0, errKVResponse
		}
		if rawVersion, present := metadata["version"]; present {
			capturedVersion, err = metadataInteger(rawVersion, false)
			if err != nil || (version > 0 && capturedVersion != version) {
				return nil, 0, errKVResponse
			}
		}
	}
	if requireVersion && capturedVersion == 0 {
		return nil, 0, errKVResponse
	}
	return data, capturedVersion, nil
}

// Raw reads retain HTTP 404 even when Vault includes tombstone data or warnings.
func readVersionLogical(ctx context.Context, client *api.Client, physical string, version int) (*api.Secret, error) {
	response, err := client.Logical().ReadRawWithDataWithContext(ctx, physical, map[string][]string{"version": {strconv.Itoa(version)}})
	if response != nil {
		defer response.Body.Close()
		if response.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
	}
	if err != nil {
		var upstream *api.ResponseError
		if errors.As(err, &upstream) && (upstream.StatusCode == http.StatusUnauthorized || upstream.StatusCode == http.StatusForbidden) {
			return nil, ErrPermissionDenied
		}
		return nil, safeRequestError(err, false)
	}
	if response == nil || response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errKVResponse
	}
	secret, err := api.ParseSecret(response.Body)
	if errors.Is(err, io.EOF) || (err == nil && secret == nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, errKVResponse
	}
	return secret, nil
}

func performMutation(ctx context.Context, client *api.Client, method, physical string, body map[string]any) (*api.Secret, error) {
	request := client.NewRequest(method, "/v1/"+physical)
	if body != nil {
		if err := request.SetJSONBody(body); err != nil {
			return nil, ErrInvalidData
		}
	}
	response, err := client.RawRequestWithContext(ctx, request)
	if response != nil {
		defer response.Body.Close()
		if response.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
	}
	if err != nil {
		var upstream *api.ResponseError
		if errors.As(err, &upstream) {
			switch upstream.StatusCode {
			case http.StatusUnauthorized, http.StatusForbidden:
				return nil, ErrPermissionDenied
			case http.StatusConflict, http.StatusPreconditionFailed:
				return nil, ErrConflict
			case http.StatusBadRequest:
				for _, message := range upstream.Errors {
					if strings.TrimSpace(message) == "check-and-set parameter did not match the current version" {
						return nil, ErrConflict
					}
				}
				return nil, errors.New("Vault rejected the mutation")
			}
		}
		return nil, mutationUnconfirmed(err)
	}
	if response == nil || response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, mutationUnconfirmed(nil)
	}
	if response.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	secret, err := api.ParseSecret(response.Body)
	if err != nil || secret == nil {
		return nil, mutationUnconfirmed(err)
	}
	return secret, nil
}

func mutationUnconfirmed(cause error) error {
	if errors.Is(cause, context.Canceled) {
		return fmt.Errorf("%w: %w", errMutationUnconfirmed, context.Canceled)
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", errMutationUnconfirmed, context.DeadlineExceeded)
	}
	return errMutationUnconfirmed
}

func metadataInteger(value any, allowZero bool) (int, error) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, errKVResponse
	}
	parsed, err := number.Int64()
	if err != nil || parsed < 0 || (!allowZero && parsed == 0) || int64(int(parsed)) != parsed {
		return 0, errKVResponse
	}
	return int(parsed), nil
}

func canonicalVersions(versions []int, required bool) ([]int, error) {
	if len(versions) == 0 {
		if required || versions != nil {
			return nil, ErrInvalidPath
		}
		return nil, nil
	}
	unique := make(map[int]struct{}, len(versions))
	for _, version := range versions {
		if version <= 0 {
			return nil, ErrInvalidPath
		}
		unique[version] = struct{}{}
	}
	canonical := make([]int, 0, len(unique))
	for version := range unique {
		canonical = append(canonical, version)
	}
	sort.Ints(canonical)
	return canonical, nil
}
