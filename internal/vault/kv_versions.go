package vault

import (
	"context"
	"net/http"
	"sort"
	"strconv"

	"github.com/hashicorp/vault/api"
)

// VersionInfo is a whitelist of lifecycle metadata, never a secret's values.
type VersionInfo struct {
	Version      int    `json:"version"`
	CreatedTime  string `json:"created_time"`
	DeletionTime string `json:"deletion_time"`
	Destroyed    bool   `json:"destroyed"`
}

type VersionHistory struct {
	Path           string        `json:"path"`
	CurrentVersion int           `json:"current_version"`
	OldestVersion  int           `json:"oldest_version"`
	Versions       []VersionInfo `json:"versions"`
}

// ReadVersion reads exactly one positive KV v2 revision. A missing or deleted
// revision never falls back to the latest or to an older available revision.
func (c *Client) ReadVersion(ctx context.Context, token, target string, version int, opts KVOptions) (map[string]any, error) {
	if version <= 0 {
		return nil, ErrInvalidPath
	}
	if _, _, err := validateVersionTarget(target, opts); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.kvClient(token)
	if err != nil {
		return nil, err
	}
	defer client.SetToken("")
	selected, err := resolveVersionTarget(ctx, client, target, opts)
	if err != nil {
		return nil, err
	}
	data, _, err := readSnapshot(ctx, client, selected, version, false)
	return data, err
}

// Versions returns a sorted projection of metadata without custom metadata,
// tokens, values, or arbitrary upstream response fields.
func (c *Client) Versions(ctx context.Context, token, target string, opts KVOptions) (VersionHistory, error) {
	if _, _, err := validateVersionTarget(target, opts); err != nil {
		return VersionHistory{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.kvClient(token)
	if err != nil {
		return VersionHistory{}, err
	}
	defer client.SetToken("")
	selected, err := resolveVersionTarget(ctx, client, target, opts)
	if err != nil {
		return VersionHistory{}, err
	}
	secret, err := readLogical(ctx, client, selected.mount.Path+"metadata/"+selected.key, false)
	if err != nil {
		return VersionHistory{}, err
	}
	if secret == nil || secret.Data == nil {
		return VersionHistory{}, ErrNotFound
	}
	current, err := metadataInteger(secret.Data["current_version"], true)
	if err != nil {
		return VersionHistory{}, err
	}
	oldest, err := metadataInteger(secret.Data["oldest_version"], true)
	if err != nil || oldest > current {
		return VersionHistory{}, errKVResponse
	}
	rawVersions, ok := secret.Data["versions"].(map[string]interface{})
	if !ok {
		return VersionHistory{}, errKVResponse
	}
	versions := make([]VersionInfo, 0, len(rawVersions))
	for rawVersion, value := range rawVersions {
		version, err := strconv.Atoi(rawVersion)
		if err != nil || version <= 0 || strconv.Itoa(version) != rawVersion || version > current {
			return VersionHistory{}, errKVResponse
		}
		metadata, ok := value.(map[string]interface{})
		if !ok {
			return VersionHistory{}, errKVResponse
		}
		created, createdOK := metadata["created_time"].(string)
		deleted, deletedOK := metadata["deletion_time"].(string)
		destroyed, destroyedOK := metadata["destroyed"].(bool)
		if !createdOK || !deletedOK || !destroyedOK {
			return VersionHistory{}, errKVResponse
		}
		versions = append(versions, VersionInfo{Version: version, CreatedTime: created, DeletionTime: deleted, Destroyed: destroyed})
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i].Version < versions[j].Version })
	return VersionHistory{
		Path: selected.logical, CurrentVersion: current, OldestVersion: oldest, Versions: versions,
	}, nil
}

// Undelete restores the selected KV v2 versions without changing history.
func (c *Client) Undelete(ctx context.Context, token, target string, versions []int, opts KVOptions) (MutationResult, error) {
	return c.mutateVersions(ctx, token, target, versions, opts, "undelete")
}

// Destroy permanently removes only explicitly selected KV v2 revisions. It
// never deletes metadata and is available only after an explicit force option.
func (c *Client) Destroy(ctx context.Context, token, target string, versions []int, opts WriteOptions) (MutationResult, error) {
	if err := validateWriteOptions(opts); err != nil {
		return MutationResult{}, err
	}
	if !opts.Force || opts.CAS != nil {
		return MutationResult{}, ErrUnsupportedOperation
	}
	return c.mutateVersions(ctx, token, target, versions, opts.KVOptions, "destroy")
}

func (c *Client) mutateVersions(ctx context.Context, token, target string, versions []int, opts KVOptions, action string) (MutationResult, error) {
	versions, err := canonicalVersions(versions, true)
	if err != nil {
		return MutationResult{}, err
	}
	if _, _, err := validateVersionTarget(target, opts); err != nil {
		return MutationResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.kvClient(token)
	if err != nil {
		return MutationResult{}, err
	}
	defer client.SetToken("")
	selected, err := resolveVersionTarget(ctx, client, target, opts)
	if err != nil {
		return MutationResult{}, err
	}
	if _, err := performMutation(ctx, client, http.MethodPost, selected.mount.Path+action+"/"+selected.key, map[string]any{"versions": versions}); err != nil {
		return MutationResult{}, err
	}
	return MutationResult{Path: selected.logical, KVVersion: 2, Versions: versions}, nil
}

// Rollback reads the current revision first, then the requested historical data,
// and creates a new revision guarded by that captured CAS. History is retained.
func (c *Client) Rollback(ctx context.Context, token, target string, version int, opts KVOptions) (WriteResult, error) {
	if version <= 0 {
		return WriteResult{}, ErrInvalidPath
	}
	if _, _, err := validateVersionTarget(target, opts); err != nil {
		return WriteResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.kvClient(token)
	if err != nil {
		return WriteResult{}, err
	}
	defer client.SetToken("")
	selected, err := resolveVersionTarget(ctx, client, target, opts)
	if err != nil {
		return WriteResult{}, err
	}
	metadata, err := readLogical(ctx, client, selected.mount.Path+"metadata/"+selected.key, false)
	if err != nil {
		return WriteResult{}, err
	}
	if metadata == nil || metadata.Data == nil {
		return WriteResult{}, ErrNotFound
	}
	current, err := metadataInteger(metadata.Data["current_version"], false)
	if err != nil {
		return WriteResult{}, err
	}
	data, _, err := readSnapshot(ctx, client, selected, version, false)
	if err != nil {
		return WriteResult{}, err
	}
	return writeSnapshot(ctx, client, selected, data, &current)
}

func validateVersionTarget(target string, opts KVOptions) (string, *Mount, error) {
	logical, explicit, err := validateKVTarget(target, opts)
	if err != nil {
		return "", nil, err
	}
	if explicit != nil && explicit.Version != 2 {
		return "", nil, ErrUnsupportedOperation
	}
	return logical, explicit, nil
}

func resolveVersionTarget(ctx context.Context, client *api.Client, target string, opts KVOptions) (kvTarget, error) {
	selected, err := resolveKVTarget(ctx, client, target, opts)
	if err != nil {
		return kvTarget{}, err
	}
	if selected.mount.Version != 2 {
		return kvTarget{}, ErrUnsupportedOperation
	}
	return selected, nil
}
