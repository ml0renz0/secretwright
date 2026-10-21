package vault

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/hashicorp/vault/api"
)

// DefaultTimeout bounds a request unless explicitly overridden.
const DefaultTimeout = 10 * time.Second

// Options override their corresponding environment settings. Pointers distinguish
// an omitted option from an explicit empty namespace or invalid zero timeout.
type Options struct {
	Address   *string
	Namespace *string
	Timeout   *time.Duration
}

// New builds a credential-free client. Authentication selects a token for one
// operation, while the shared client always remains safe for public health reads.
func New(options Options) (*Client, error) {
	address := os.Getenv("VAULT_AGENT_ADDR")
	if address == "" {
		address = os.Getenv("VAULT_ADDR")
	}
	if address == "" {
		address = api.DefaultAddress
	}
	if options.Address != nil {
		address = *options.Address
	}
	parsed, err := url.Parse(address)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.Opaque != "" {
		return nil, errors.New("Vault address must be an absolute http or https URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return nil, errors.New("Vault address must not contain credentials, a query, or a fragment")
	}

	namespace := os.Getenv("VAULT_NAMESPACE")
	if options.Namespace != nil {
		namespace = *options.Namespace
	}
	namespace = strings.Trim(namespace, "/")
	if strings.ContainsAny(namespace, "\\?#") || strings.IndexFunc(namespace, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return nil, errors.New("invalid Vault namespace")
	}
	if namespace != "" {
		for _, segment := range strings.Split(namespace, "/") {
			if segment == "" || segment == "." || segment == ".." {
				return nil, errors.New("invalid Vault namespace")
			}
		}
	}

	timeout := DefaultTimeout
	if options.Timeout != nil {
		timeout = *options.Timeout
	} else if raw := os.Getenv("VAULT_CLIENT_TIMEOUT"); raw != "" {
		timeout, err = time.ParseDuration(raw)
		if err != nil {
			return nil, errors.New("Vault timeout must be a positive duration, for example 5s")
		}
	}
	if timeout <= 0 {
		return nil, errors.New("Vault timeout must be a positive duration, for example 5s")
	}
	if raw := os.Getenv("VAULT_SKIP_VERIFY"); raw != "" {
		insecure, err := strconv.ParseBool(raw)
		if err != nil || insecure {
			return nil, errors.New("TLS verification is required; unset VAULT_SKIP_VERIFY and configure a trusted CA")
		}
	}

	// Resolve supported settings explicitly so an overridden invalid environment
	// value cannot veto a valid option. Keep standard HTTP proxy and CA handling.
	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("unsupported Vault HTTP transport")
	}
	transport := baseTransport.Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	config := &api.Config{
		Address: address,
		Timeout: timeout,
		HttpClient: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		MaxRetries:       0,
		DisableRedirects: true,
	}
	if err := config.ConfigureTLS(&api.TLSConfig{
		CACert:        os.Getenv("VAULT_CACERT"),
		CACertBytes:   []byte(os.Getenv("VAULT_CACERT_BYTES")),
		CAPath:        os.Getenv("VAULT_CAPATH"),
		ClientCert:    os.Getenv("VAULT_CLIENT_CERT"),
		ClientKey:     os.Getenv("VAULT_CLIENT_KEY"),
		TLSServerName: os.Getenv("VAULT_TLS_SERVER_NAME"),
	}); err != nil {
		return nil, errors.New("invalid Vault TLS configuration; check CA and client certificate settings")
	}
	client, err := api.NewClient(config)
	if err != nil {
		return nil, errors.New("could not initialize the Vault client")
	}
	configureRequestClient(client, namespace, "")
	// The SDK's Clone omits DisableRedirects. Use a fresh configuration for
	// authenticated operations; only the immutable, concurrent-safe HTTP client
	// and transport are shared. No mutex-bearing Config value is copied.
	newConfig := func() *api.Config {
		return &api.Config{
			Address:          address,
			Timeout:          timeout,
			HttpClient:       config.HttpClient,
			MaxRetries:       0,
			DisableRedirects: true,
		}
	}
	return &Client{api: client, namespace: namespace, timeout: timeout, newConfig: newConfig}, nil
}
