//go:build integration

package vault_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/cli"
	"github.com/ml0renz0/secretwright/internal/vault"
)

// This acceptance test intentionally requires a real, initialized and unsealed
// Vault. It never silently skips a missing fixture and never mutates secrets.
func TestIntegrationVaultHealth(t *testing.T) {
	if os.Getenv("VAULT_ADDR") == "" {
		t.Fatal("VAULT_ADDR is required; run make integration-local for an ephemeral Vault")
	}
	// The health endpoint is public. An inherited operator token must not be
	// necessary for this first vertical slice.
	t.Setenv("VAULT_TOKEN", "f00-health-does-not-require-authentication")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatalf("create real Vault client: %v", err)
	}
	status, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("read real Vault health: %v", err)
	}
	if !status.Initialized || status.Sealed || status.Standby {
		t.Fatalf("expected initialized, unsealed, active development Vault; got %+v", status)
	}
	if status.Version == "" || status.ClusterName == "" || status.ClusterID == "" {
		t.Fatalf("real Vault health omitted server identity: %+v", status)
	}
	var stdout, stderr bytes.Buffer
	if code := cli.Run(ctx, []string{"status"}, &stdout, &stderr, "integration"); code != 0 {
		t.Fatalf("status CLI exit = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("successful status wrote stderr: %q", stderr.String())
	}
	var actual vault.Status
	if err := json.Unmarshal(stdout.Bytes(), &actual); err != nil {
		t.Fatalf("status CLI did not produce valid JSON: %v", err)
	}
	if actual != status {
		t.Errorf("CLI report = %+v, API report = %+v", actual, status)
	}
}
