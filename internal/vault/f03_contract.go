package vault

import (
	"context"
	"errors"
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

func (c *Client) Put(ctx context.Context, token, target string, data map[string]any, opts WriteOptions) (WriteResult, error) {
	return WriteResult{}, ErrUnsupportedOperation
}

func (c *Client) Remove(ctx context.Context, token, target string, versions []int, opts WriteOptions) (MutationResult, error) {
	return MutationResult{}, ErrUnsupportedOperation
}

func (c *Client) Copy(ctx context.Context, token, source, destination string, opts WriteOptions) (CopyResult, error) {
	return CopyResult{}, ErrUnsupportedOperation
}

func (c *Client) Move(ctx context.Context, token, source, destination string, opts WriteOptions) (CopyResult, error) {
	return CopyResult{}, ErrUnsupportedOperation
}

func (c *Client) ReadVersion(ctx context.Context, token, target string, version int, opts KVOptions) (map[string]any, error) {
	return nil, ErrUnsupportedOperation
}

func (c *Client) Versions(ctx context.Context, token, target string, opts KVOptions) (VersionHistory, error) {
	return VersionHistory{}, ErrUnsupportedOperation
}

func (c *Client) Undelete(ctx context.Context, token, target string, versions []int, opts KVOptions) (MutationResult, error) {
	return MutationResult{}, ErrUnsupportedOperation
}

func (c *Client) Destroy(ctx context.Context, token, target string, versions []int, opts WriteOptions) (MutationResult, error) {
	return MutationResult{}, ErrUnsupportedOperation
}

func (c *Client) Rollback(ctx context.Context, token, target string, version int, opts KVOptions) (WriteResult, error) {
	return WriteResult{}, ErrUnsupportedOperation
}
