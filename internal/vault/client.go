// Package vault implements read-only Vault operations for the F00 bootstrap.
package vault

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"

	"github.com/hashicorp/vault/api"
)

// Client wraps the official Vault API client. Domain operations belong here,
// independently of their eventual interactive or batch interface.
type Client struct {
	api *api.Client
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

// NewFromEnvironment reads the official client's standard environment settings.
// Health requires no authentication, so inherited tokens are never sent. TLS
// certificate verification cannot be disabled by VAULT_SKIP_VERIFY.
func NewFromEnvironment() (*Client, error) {
	config := api.DefaultConfig()
	if config.Error != nil {
		return nil, errors.New("invalid Vault client configuration; check the VAULT_* environment variables")
	}
	effectiveAddress := config.Address
	if config.AgentAddress != "" {
		effectiveAddress = config.AgentAddress
	}
	address, err := url.Parse(effectiveAddress)
	if err != nil || (address.Scheme != "http" && address.Scheme != "https") || address.Host == "" {
		return nil, errors.New("Vault address must be an absolute http or https URL")
	}
	if address.User != nil || address.RawQuery != "" || address.Fragment != "" {
		return nil, errors.New("Vault address must not contain credentials, a query, or a fragment")
	}
	transport, ok := config.HttpClient.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify {
		return nil, errors.New("TLS verification is required; unset VAULT_SKIP_VERIFY and configure a trusted CA")
	}
	// A status probe is bounded by its caller's context and needs no retries or
	// redirects. In particular, never forward client credentials to a redirect.
	config.MaxRetries = 0
	config.DisableRedirects = true
	client, err := api.NewClient(config)
	if err != nil {
		return nil, errors.New("could not initialize the Vault client")
	}
	headers := make(http.Header)
	headers.Set("X-Vault-Request", "true")
	client.SetHeaders(headers)
	client.SetToken("")
	client.SetNamespace(os.Getenv("VAULT_NAMESPACE"))
	return &Client{api: client}, nil
}

// Status retrieves Vault health without reading or changing secrets. The
// official SDK decodes sealed and uninitialized responses as health reports.
func (c *Client) Status(ctx context.Context) (Status, error) {
	health, err := c.api.Sys().HealthWithContext(ctx)
	if err != nil {
		// Server responses and URLs can contain sensitive data. Keep diagnostics
		// bounded instead of returning arbitrary upstream error bodies.
		if errors.Is(err, context.Canceled) {
			return Status{}, context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return Status{}, context.DeadlineExceeded
		}
		return Status{}, errors.New("could not read Vault health; check the address, connectivity, and TLS configuration")
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
