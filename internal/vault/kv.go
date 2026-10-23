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

var (
	ErrPermissionDenied = errors.New("Vault denied the operation; verify the token and its permissions")
	ErrNotFound         = errors.New("Vault path was not found")
	ErrInvalidPath      = errors.New("invalid logical Vault path or mount selection")
	ErrNotKV            = errors.New("requested mount is not a supported KV engine")
	errKVResponse       = errors.New("Vault returned invalid KV metadata or data")
)

// Mount identifies an engine using its complete logical prefix, including the
// trailing slash. Version describes the API mapping, not a secret's revision.
type Mount struct {
	Path    string `json:"path"`
	Version int    `json:"version"`
}

// KVOptions selects the logical working directory and an optional explicit
// engine. Mount and Version must be supplied together to bypass discovery.
type KVOptions struct {
	CWD     string
	Mount   string
	Version int
}

// Mounts returns only KV engines visible to this token. It does not require the
// administrative sys/mounts API or permission to perform token lookup-self.
func (c *Client) Mounts(ctx context.Context, token string) ([]Mount, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.kvClient(token)
	if err != nil {
		return nil, err
	}
	defer client.SetToken("")
	return readMountCatalog(ctx, client)
}

// List returns immediate logical child names. Only directory names end in '/'.
func (c *Client) List(ctx context.Context, token, target string, opts KVOptions) ([]string, error) {
	logical, explicit, err := prepareKVPath(target, opts)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.kvClient(token)
	if err != nil {
		return nil, err
	}
	defer client.SetToken("")
	return listKVChildren(ctx, client, logical, explicit)
}

// listKVChildren shares the exact single-directory behavior with recursive
// traversal while keeping the operation-owned client and token stable.
func listKVChildren(ctx context.Context, client *api.Client, logical string, explicit *Mount) ([]string, error) {
	if logical == "/" {
		mounts, err := readMountCatalog(ctx, client)
		if err != nil {
			return nil, err
		}
		children, _ := virtualChildren(mounts, logical)
		return children, nil
	}
	mount, err := selectMount(ctx, client, logical, explicit)
	if err != nil {
		// Vault deliberately returns 403 for a nonexistent mount. A separate,
		// ACL-filtered catalog can prove a virtual ancestor exists. This never
		// guesses a backend version or reads data after failed discovery.
		if explicit == nil && (errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrNotFound)) {
			mounts, catalogErr := readMountCatalog(ctx, client)
			if catalogErr == nil {
				if children, virtual := virtualChildren(mounts, logical); virtual {
					return children, nil
				}
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		return nil, err
	}
	key := strings.TrimPrefix(strings.TrimPrefix(logical, "/"+strings.TrimSuffix(mount.Path, "/")), "/")
	physical := mount.Path + key
	if mount.Version == 2 {
		physical = mount.Path + "metadata/" + key
	}
	secret, err := readLogical(ctx, client, physical, true)
	if err != nil {
		return nil, err
	}
	if secret.Data == nil {
		return nil, ErrNotFound
	}
	values, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, errKVResponse
	}
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		name, ok := value.(string)
		if !ok {
			return nil, errKVResponse
		}
		segment := strings.TrimSuffix(name, "/")
		if segment == "" || segment == "." || segment == ".." || strings.Contains(segment, "/") || !validLogicalText(name) {
			return nil, errKVResponse
		}
		unique[name] = struct{}{}
	}
	return sortedNames(unique), nil
}

// Read returns the latest secret's values. KV v2 metadata is never mixed into
// the values, and a deleted latest version never falls back to an older one.
func (c *Client) Read(ctx context.Context, token, target string, opts KVOptions) (map[string]any, error) {
	logical, explicit, err := prepareKVPath(target, opts)
	if err != nil {
		return nil, err
	}
	if logical == "/" {
		return nil, ErrInvalidPath
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.kvClient(token)
	if err != nil {
		return nil, err
	}
	defer client.SetToken("")
	mount, err := selectMount(ctx, client, logical, explicit)
	if err != nil {
		return nil, err
	}
	key := strings.TrimPrefix(strings.TrimPrefix(logical, "/"+strings.TrimSuffix(mount.Path, "/")), "/")
	if key == "" {
		return nil, ErrInvalidPath
	}
	physical := mount.Path + key
	if mount.Version == 2 {
		physical = mount.Path + "data/" + key
	}
	secret, err := readLogical(ctx, client, physical, false)
	if err != nil {
		return nil, err
	}
	if secret.Data == nil {
		return nil, ErrNotFound
	}
	if mount.Version == 1 {
		return secret.Data, nil
	}
	values, present := secret.Data["data"]
	if !present {
		return nil, errKVResponse
	}
	if values == nil {
		return nil, ErrNotFound
	}
	data, ok := values.(map[string]interface{})
	if !ok {
		return nil, errKVResponse
	}
	return data, nil
}

// ChangeDir validates a listable directory and returns its canonical path. The
// eventual interactive shell can retain this path as its own session state.
func (c *Client) ChangeDir(ctx context.Context, token, target string, opts KVOptions) (string, error) {
	logical, err := ResolvePath(opts.CWD, target)
	if err != nil {
		return "", err
	}
	if _, err := c.List(ctx, token, logical, opts); err != nil {
		return "", err
	}
	return logical, nil
}

func (c *Client) kvClient(token string) (*api.Client, error) {
	token, err := normalizeToken(token)
	if err != nil {
		return nil, err
	}
	client, err := api.NewClient(c.newConfig())
	if err != nil {
		return nil, errors.New("could not initialize the KV client")
	}
	configureRequestClient(client, c.namespace, token)
	return client, nil
}

func prepareKVPath(target string, opts KVOptions) (string, *Mount, error) {
	logical, err := ResolvePath(opts.CWD, target)
	if err != nil {
		return "", nil, err
	}
	if opts.Mount == "" && opts.Version == 0 {
		return logical, nil, nil
	}
	if opts.Mount == "" || (opts.Version != 1 && opts.Version != 2) {
		return "", nil, ErrInvalidPath
	}
	prefix, err := canonicalMount(opts.Mount)
	if err != nil {
		return "", nil, err
	}
	mount := &Mount{Path: prefix, Version: opts.Version}
	if !pathInMount(logical, *mount) {
		return "", nil, ErrInvalidPath
	}
	return logical, mount, nil
}

func selectMount(ctx context.Context, client *api.Client, logical string, explicit *Mount) (Mount, error) {
	if explicit != nil {
		return *explicit, nil
	}
	secret, err := readLogical(ctx, client, "sys/internal/ui/mounts/"+strings.TrimPrefix(logical, "/"), false)
	if err != nil {
		return Mount{}, err
	}
	if secret.Data == nil {
		return Mount{}, errKVResponse
	}
	prefix, ok := secret.Data["path"].(string)
	if !ok {
		return Mount{}, errKVResponse
	}
	mount, err := parseMount(prefix, secret.Data)
	if err != nil {
		return Mount{}, err
	}
	if !pathInMount(logical, mount) {
		return Mount{}, errKVResponse
	}
	return mount, nil
}

func parseMount(prefix string, data map[string]interface{}) (Mount, error) {
	typeName, ok := data["type"].(string)
	if !ok {
		return Mount{}, errKVResponse
	}
	if typeName != "kv" {
		return Mount{}, ErrNotKV
	}
	prefix, err := canonicalMount(prefix)
	if err != nil {
		return Mount{}, errKVResponse
	}
	version := 1
	if raw := data["options"]; raw != nil {
		options, ok := raw.(map[string]interface{})
		if !ok {
			return Mount{}, errKVResponse
		}
		if rawVersion, present := options["version"]; present {
			value, ok := rawVersion.(string)
			if !ok {
				return Mount{}, errKVResponse
			}
			switch value {
			case "", "1":
			case "2":
				version = 2
			default:
				return Mount{}, ErrNotKV
			}
		}
	}
	return Mount{Path: prefix, Version: version}, nil
}

func readMountCatalog(ctx context.Context, client *api.Client) ([]Mount, error) {
	secret, err := readLogical(ctx, client, "sys/internal/ui/mounts", false)
	if err != nil {
		return nil, err
	}
	if secret.Data == nil {
		return nil, errKVResponse
	}
	entries, ok := secret.Data["secret"].(map[string]interface{})
	if !ok {
		return nil, errKVResponse
	}
	mounts := make([]Mount, 0, len(entries))
	for prefix, raw := range entries {
		data, ok := raw.(map[string]interface{})
		if !ok {
			return nil, errKVResponse
		}
		typeName, ok := data["type"].(string)
		if !ok {
			return nil, errKVResponse
		}
		if typeName != "kv" {
			continue
		}
		mount, err := parseMount(prefix, data)
		if err != nil {
			return nil, err
		}
		mounts = append(mounts, mount)
	}
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].Path < mounts[j].Path })
	return mounts, nil
}

func virtualChildren(mounts []Mount, logical string) ([]string, bool) {
	for _, mount := range mounts {
		if pathInMount(logical, mount) {
			return nil, false
		}
	}
	prefix := strings.TrimPrefix(logical, "/")
	if prefix != "" {
		prefix += "/"
	}
	children := make(map[string]struct{})
	for _, mount := range mounts {
		if strings.HasPrefix(mount.Path, prefix) {
			rest := strings.TrimPrefix(mount.Path, prefix)
			if name, _, _ := strings.Cut(rest, "/"); name != "" {
				children[name+"/"] = struct{}{}
			}
		}
	}
	return sortedNames(children), len(children) > 0 || logical == "/"
}

func sortedNames(unique map[string]struct{}) []string {
	names := make([]string, 0, len(unique))
	for name := range unique {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Keep HTTP status information: the SDK's high-level Read can hide a 404 that
// includes KV v2 tombstone metadata. Both GET and semantic LIST use this helper;
// the caller's context bounds the complete discovery-and-read operation.
func readLogical(ctx context.Context, client *api.Client, physical string, list bool) (*api.Secret, error) {
	var parameters map[string][]string
	if list {
		parameters = map[string][]string{"list": {"true"}}
	}
	response, err := client.Logical().ReadRawWithDataWithContext(ctx, physical, parameters)
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
