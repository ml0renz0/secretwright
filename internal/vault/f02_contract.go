package vault

import (
	"context"
	"errors"
)

type Mount struct {
	Path    string `json:"path"`
	Version int    `json:"version"`
}

type KVOptions struct {
	CWD     string
	Mount   string
	Version int
}

var (
	ErrPermissionDenied = errors.New("Vault denied the operation")
	ErrNotFound = errors.New("Vault path was not found")
	ErrInvalidPath = errors.New("invalid logical Vault path")
	ErrNotKV = errors.New("requested mount is not a supported KV engine")
)

func ResolvePath(cwd, target string) (string, error) { return "", ErrInvalidPath }
func (c *Client) Mounts(ctx context.Context, token string) ([]Mount, error) {
	return nil, errors.New("F02 mount discovery is not implemented yet")
}
func (c *Client) List(ctx context.Context, token, target string, opts KVOptions) ([]string, error) {
	return nil, errors.New("F02 listing is not implemented yet")
}
func (c *Client) Read(ctx context.Context, token, target string, opts KVOptions) (map[string]any, error) {
	return nil, errors.New("F02 reading is not implemented yet")
}
func (c *Client) ChangeDir(ctx context.Context, token, target string, opts KVOptions) (string, error) {
	return "", errors.New("F02 navigation is not implemented yet")
}
