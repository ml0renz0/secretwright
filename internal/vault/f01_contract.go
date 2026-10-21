package vault

import (
	"context"
	"errors"
	"time"
)

const DefaultTimeout = 10 * time.Second

var ErrUnauthenticated = errors.New("Vault authentication could not be confirmed")

type Options struct {
	Address   *string
	Namespace *string
	Timeout   *time.Duration
}

type AuthStatus struct {
	Authenticated bool     `json:"authenticated"`
	Namespace     string   `json:"namespace"`
	Policies      []string `json:"policies"`
	TTL           int64    `json:"ttl_seconds"`
	Renewable     bool     `json:"renewable"`
}

func New(options Options) (*Client, error) {
	return nil, errors.New("F01 connection options are not implemented yet")
}

func (c *Client) CheckToken(ctx context.Context, token string) (AuthStatus, error) {
	return AuthStatus{}, ErrUnauthenticated
}

func LoadToken(path string) (string, error) {
	return "", ErrUnauthenticated
}
