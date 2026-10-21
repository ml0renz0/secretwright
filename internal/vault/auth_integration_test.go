//go:build integration

package vault_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/ml0renz0/secretwright/internal/cli"
	"github.com/ml0renz0/secretwright/internal/vault"
)

// Integration credentials are provisioned only by the disposable test fixture.
// Explicitly require its file instead of falling back to an operator's token.
func integrationTokenAdmin(t *testing.T) *api.Client {
	t.Helper()
	if os.Getenv("VAULT_ADDR") == "" {
		t.Fatal("VAULT_ADDR is required; run make integration-local")
	}
	path := os.Getenv("VAULT_TEST_ROOT_TOKEN_FILE")
	if path == "" {
		t.Fatal("VAULT_TEST_ROOT_TOKEN_FILE is required; run make integration-local")
	}
	credential, err := os.ReadFile(path)
	if err != nil || len(credential) == 0 {
		t.Fatal("could not read the disposable fixture credential")
	}
	config := api.DefaultConfig()
	if config.Error != nil {
		t.Fatal("invalid disposable fixture configuration")
	}
	config.MaxRetries = 0
	config.Timeout = 5 * time.Second
	config.DisableRedirects = true
	admin, err := api.NewClient(config)
	if err != nil {
		t.Fatal("could not initialize the disposable fixture administrator")
	}
	admin.SetToken(strings.TrimSpace(string(credential)))
	return admin
}

func createIntegrationToken(t *testing.T, admin *api.Client, request *api.TokenCreateRequest) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	secret, err := admin.Auth().Token().CreateWithContext(ctx, request)
	if err != nil || secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		t.Fatal("could not provision a disposable integration token")
	}
	token := secret.Auth.ClientToken
	t.Cleanup(func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Revoked and expired tokens may already be absent. The enclosing lab
		// destroys the whole server even when this best-effort revocation fails.
		_ = admin.Auth().Token().RevokeTreeWithContext(cleanupContext, token)
	})
	return token
}

func defaultIntegrationToken(t *testing.T, admin *api.Client) string {
	t.Helper()
	renewable := true
	return createIntegrationToken(t, admin, &api.TokenCreateRequest{
		Policies:    []string{"default"},
		TTL:         "1m",
		DisplayName: "secretwright-f01-integration",
		Renewable:   &renewable,
	})
}

func TestIntegrationTokenAuthentication(t *testing.T) {
	admin := integrationTokenAdmin(t)
	token := defaultIntegrationToken(t, admin)
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatal("could not create the Secretwright client")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	report, err := client.CheckToken(ctx, token)
	if err != nil {
		t.Fatal("Secretwright could not authenticate the valid fixture token")
	}
	if !report.Authenticated || report.Namespace != "" || !report.Renewable {
		t.Fatal("valid fixture token returned an unexpected authentication report")
	}
	if !slices.Contains(report.Policies, "default") || report.TTL <= 0 || report.TTL > 60 {
		t.Fatal("authentication report omitted the token's policy or bounded lifetime")
	}

	t.Setenv("VAULT_TOKEN", token)
	var stdout, stderr bytes.Buffer
	if code := cli.Run(ctx, []string{"auth", "check"}, &stdout, &stderr, "integration"); code != 0 {
		t.Fatal("auth check CLI did not accept the valid fixture token")
	}
	if stderr.Len() != 0 || strings.Contains(stdout.String(), token) || strings.Contains(stderr.String(), token) {
		t.Fatal("auth check CLI emitted unexpected output or a credential")
	}
	var actual vault.AuthStatus
	if err := json.Unmarshal(stdout.Bytes(), &actual); err != nil || !actual.Authenticated {
		t.Fatal("auth check CLI did not produce an authenticated JSON report")
	}
	for _, forbidden := range []string{`"id"`, `"accessor"`, `"meta"`, `"metadata"`, `"client_token"`} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatal("auth check CLI exposed an unapproved token field")
		}
	}
	// Authentication must not leave credentials on the shared health client.
	if health, err := client.Status(ctx); err != nil || !health.Initialized || health.Sealed {
		t.Fatal("health regressed after checking a token on the same client")
	}
}

func TestIntegrationInvalidTokenIsRejected(t *testing.T) {
	// Require the same controlled fixture even though no administrative call is
	// needed: this test must not silently use an operator's configured server.
	_ = integrationTokenAdmin(t)
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatal("could not create the Secretwright client")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	invalid := "f01-deliberately-invalid-integration-token"
	if _, err := client.CheckToken(ctx, invalid); !errors.Is(err, vault.ErrUnauthenticated) {
		t.Fatal("invalid token was not reported as unauthenticated")
	}
	t.Setenv("VAULT_TOKEN", invalid)
	var stdout, stderr bytes.Buffer
	if code := cli.Run(ctx, []string{"auth", "check"}, &stdout, &stderr, "integration"); code != 2 {
		t.Fatal("auth check CLI did not return the rejected-credential exit code")
	}
	if stdout.Len() != 0 || stderr.Len() == 0 || strings.Contains(stderr.String(), invalid) {
		t.Fatal("rejected authentication emitted unexpected output or a credential")
	}
}

func TestIntegrationRevokedTokenIsRejected(t *testing.T) {
	admin := integrationTokenAdmin(t)
	token := defaultIntegrationToken(t, admin)
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatal("could not create the Secretwright client")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := client.CheckToken(ctx, token); err != nil {
		t.Fatal("fresh fixture token was not initially valid")
	}
	if err := admin.Auth().Token().RevokeTreeWithContext(ctx, token); err != nil {
		t.Fatal("could not revoke the disposable fixture token")
	}
	if _, err := client.CheckToken(ctx, token); !errors.Is(err, vault.ErrUnauthenticated) {
		t.Fatal("revoked token was not reported as unauthenticated")
	}
}

func TestIntegrationTokenWithoutLookupPermissionIsUnconfirmed(t *testing.T) {
	admin := integrationTokenAdmin(t)
	policyName := fmt.Sprintf("secretwright-f01-deny-self-%d", time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	policy := `path "auth/token/lookup-self" { capabilities = ["deny"] }`
	if err := admin.Sys().PutPolicyWithContext(ctx, policyName, policy); err != nil {
		t.Fatal("could not provision the disposable deny policy")
	}
	t.Cleanup(func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = admin.Sys().DeletePolicyWithContext(cleanupContext, policyName)
	})
	token := createIntegrationToken(t, admin, &api.TokenCreateRequest{
		Policies:        []string{policyName},
		NoDefaultPolicy: true,
		TTL:             "1m",
		DisplayName:     "secretwright-f01-denied-integration",
	})
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatal("could not create the Secretwright client")
	}
	if _, err := client.CheckToken(ctx, token); !errors.Is(err, vault.ErrUnauthenticated) {
		t.Fatal("a token without lookup-self permission was incorrectly confirmed")
	}
}

func TestIntegrationExpiredTokenIsRejected(t *testing.T) {
	admin := integrationTokenAdmin(t)
	renewable := false
	token := createIntegrationToken(t, admin, &api.TokenCreateRequest{
		Policies:       []string{"default"},
		TTL:            "1s",
		ExplicitMaxTTL: "1s",
		DisplayName:    "secretwright-f01-expiring-integration",
		Renewable:      &renewable,
	})
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatal("could not create the Secretwright client")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		_, err := client.CheckToken(ctx, token)
		if errors.Is(err, vault.ErrUnauthenticated) {
			return
		}
		if err != nil {
			t.Fatal("authentication failed unexpectedly while awaiting token expiry")
		}
		select {
		case <-ctx.Done():
			t.Fatal("the short-lived fixture token was not rejected within five seconds")
		case <-ticker.C:
		}
	}
}
