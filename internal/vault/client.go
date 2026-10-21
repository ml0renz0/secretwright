// Package vault implements Vault operations independently of the command interface.
package vault

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/hashicorp/vault/api"
)

// Client wraps the official Vault API client. Domain operations belong here,
// independently of their eventual interactive or batch interface.
type Client struct {
	api       *api.Client
	namespace string
	timeout   time.Duration
	newConfig func() *api.Config
}

// Status is the deliberately small, stable public health report.
type Status struct {
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	Standby     bool   `json:"standby"`
	Version     string `json:"version"`
	ClusterName string `json:"cluster_name,omitempty"`
	ClusterID   string `json:"cluster_id,omitempty"`
}

// NewFromEnvironment reads supported environment settings without selecting a
// token. Health requires no authentication, so inherited tokens are never sent.
func NewFromEnvironment() (*Client, error) {
	return New(Options{})
}

func requestHeaders() http.Header {
	headers := make(http.Header)
	headers.Set("X-Vault-Request", "true")
	return headers
}

// Status retrieves Vault health without reading or changing secrets. The
// official SDK decodes sealed and uninitialized responses as health reports.
func (c *Client) Status(ctx context.Context) (Status, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	health, err := c.api.Sys().HealthWithContext(ctx)
	if err != nil {
		return Status{}, safeRequestError(err, false)
	}
	return Status{
		Initialized: health.Initialized,
		Sealed:      health.Sealed,
		Standby:     health.Standby,
		Version:     health.Version,
		ClusterName: health.ClusterName,
		ClusterID:   health.ClusterID,
	}, nil
}

// Never propagate upstream error bodies, URLs or headers into public errors.
func safeRequestError(err error, authentication bool) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var responseError *api.ResponseError
	if authentication && errors.As(err, &responseError) && (responseError.StatusCode == http.StatusUnauthorized || responseError.StatusCode == http.StatusForbidden) {
		return ErrUnauthenticated
	}
	return errors.New("Vault request failed; check the address, connectivity, and TLS configuration")
}
