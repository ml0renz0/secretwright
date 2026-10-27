package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/ml0renz0/secretwright/internal/keytab"
)

const maxKeytabResponseBytes = 2 << 20

// StoredKeytab separates private bytes from metadata in both supported report
// encodings. Only an explicitly reserved private output may receive Data.
type StoredKeytab struct {
	Data    []byte        `json:"-" yaml:"-"`
	Report  keytab.Report `json:"report"`
	Path    string        `json:"path"`
	Version int           `json:"version"`
}

// ValidateKeytabTarget requires a single, explicit KV v2 key. It never discovers
// an engine or normalizes traversal into an otherwise acceptable destination.
func ValidateKeytabTarget(target string, opts KVOptions) error {
	if opts.Version != 2 || opts.Mount == "" || opts.CWD != "" && opts.CWD != "/" || !strings.HasPrefix(target, "/") {
		return ErrInvalidPath
	}
	logical, err := ResolvePath("/", target)
	if err != nil || logical != target {
		return ErrInvalidPath
	}
	mount, err := canonicalMount(opts.Mount)
	if err != nil || !strings.HasPrefix(logical, "/"+mount) {
		return ErrInvalidPath
	}
	return nil
}

// StoreKeytab saves a validated binary without rewriting records, holes or
// padding. Omitted CAS remains create-only, as in Put; no unknown mutation is
// retried or compensated by this wrapper.
func (c *Client) StoreKeytab(ctx context.Context, token, target string, raw []byte, cas *int, opts KVOptions) (WriteResult, error) {
	if err := ctx.Err(); err != nil {
		return WriteResult{}, err
	}
	if err := ValidateKeytabTarget(target, opts); err != nil {
		return WriteResult{}, err
	}
	if cas != nil && *cas < 0 {
		return WriteResult{}, ErrInvalidPath
	}
	if _, err := keytab.Inspect(bytes.NewReader(raw)); err != nil {
		return WriteResult{}, keytab.ErrInvalidInput
	}
	envelope := map[string]any{
		"api_version": keytab.APIVersion,
		"encoding":    "base64",
		"data":        base64.StdEncoding.EncodeToString(raw),
	}
	written, err := c.Put(ctx, token, target, envelope, WriteOptions{KVOptions: opts, CAS: cas})
	if errors.Is(err, errMutationUnconfirmed) {
		if errors.Is(err, context.Canceled) {
			return WriteResult{}, errors.Join(ErrAccessUnconfirmed, context.Canceled)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return WriteResult{}, errors.Join(ErrAccessUnconfirmed, context.DeadlineExceeded)
		}
		return WriteResult{}, ErrAccessUnconfirmed
	}
	return written, err
}

func decodeStoredKeytab(envelope map[string]any) ([]byte, keytab.Report, error) {
	if len(envelope) != 3 || envelope["api_version"] != keytab.APIVersion || envelope["encoding"] != "base64" {
		return nil, keytab.Report{}, errKVResponse
	}
	encoded, ok := envelope["data"].(string)
	if !ok || len(encoded) == 0 || len(encoded) > base64.StdEncoding.EncodedLen(keytab.MaxInputBytes) {
		return nil, keytab.Report{}, errKVResponse
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) > keytab.MaxInputBytes || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return nil, keytab.Report{}, errKVResponse
	}
	report, err := keytab.Inspect(bytes.NewReader(decoded))
	if err != nil {
		return nil, keytab.Report{}, errKVResponse
	}
	return decoded, report, nil
}

// ReadKeytab reads one bounded KV v2 response. Revision and private bytes come
// from that same snapshot, including for a latest-version read. A missing or
// deleted revision never causes another lookup or fallback.
func (c *Client) ReadKeytab(ctx context.Context, token, target string, revision int, opts KVOptions) (StoredKeytab, error) {
	if err := ctx.Err(); err != nil {
		return StoredKeytab{}, err
	}
	if err := ValidateKeytabTarget(target, opts); err != nil {
		return StoredKeytab{}, err
	}
	if revision < 0 {
		return StoredKeytab{}, ErrInvalidPath
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.kvClient(token)
	if err != nil {
		return StoredKeytab{}, err
	}
	defer client.SetToken("")
	mount, _ := canonicalMount(opts.Mount)
	key := strings.TrimPrefix(target, "/"+mount)
	request := client.NewRequest(http.MethodGet, "/v1/"+mount+"data/"+key)
	if revision > 0 {
		request.Params.Set("version", strconv.Itoa(revision))
	}
	response, err := client.RawRequestWithContext(ctx, request)
	if response != nil {
		defer response.Body.Close()
		if response.StatusCode == http.StatusNotFound {
			return StoredKeytab{}, ErrNotFound
		}
	}
	if err != nil {
		return StoredKeytab{}, accessRequestError(err)
	}
	if response == nil || response.StatusCode < 200 || response.StatusCode >= 300 {
		return StoredKeytab{}, errKVResponse
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxKeytabResponseBytes+1))
	if err != nil && ctx.Err() != nil {
		return StoredKeytab{}, ctx.Err()
	}
	if err != nil || len(body) > maxKeytabResponseBytes || !json.Valid(body) {
		return StoredKeytab{}, errKVResponse
	}
	secret, err := api.ParseSecret(bytes.NewReader(body))
	if err != nil || secret == nil || secret.Data == nil {
		return StoredKeytab{}, errKVResponse
	}
	rawData, present := secret.Data["data"]
	if !present {
		return StoredKeytab{}, errKVResponse
	}
	if rawData == nil {
		return StoredKeytab{}, ErrNotFound
	}
	metadata, ok := secret.Data["metadata"].(map[string]any)
	if !ok {
		return StoredKeytab{}, errKVResponse
	}
	version, err := metadataInteger(metadata["version"], false)
	if err != nil || revision > 0 && version != revision {
		return StoredKeytab{}, errKVResponse
	}
	if raw, present := metadata["destroyed"]; present {
		destroyed, ok := raw.(bool)
		if !ok {
			return StoredKeytab{}, errKVResponse
		}
		if destroyed {
			return StoredKeytab{}, ErrNotFound
		}
	}
	if raw, present := metadata["deletion_time"]; present {
		deleted, ok := raw.(string)
		if !ok {
			return StoredKeytab{}, errKVResponse
		}
		if deleted != "" {
			return StoredKeytab{}, ErrNotFound
		}
	}
	envelope, ok := rawData.(map[string]any)
	if !ok {
		return StoredKeytab{}, errKVResponse
	}
	data, report, err := decodeStoredKeytab(envelope)
	if err != nil {
		return StoredKeytab{}, err
	}
	return StoredKeytab{Data: append([]byte(nil), data...), Report: report, Path: target, Version: version}, nil
}
