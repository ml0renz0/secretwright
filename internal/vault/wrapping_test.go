package vault_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ml0renz0/secretwright/internal/vault"
)

func TestInheritedWrappingDoesNotAlterReadOnlyOperations(t *testing.T) {
	clearVaultEnvironment(t)
	mount := map[string]any{
		"path": "secret/", "type": "kv", "options": map[string]any{"version": "2"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Wrap-TTL") != "" {
			t.Error("a read-only operation inherited response wrapping")
		}
		var body any
		switch r.URL.Path {
		case "/v1/sys/health":
			body = map[string]any{"initialized": true, "sealed": false, "version": "2.2.0"}
		case "/v1/auth/token/lookup-self":
			body = map[string]any{"data": map[string]any{"policies": []string{"default"}, "ttl": 60, "renewable": false}}
		case "/v1/sys/internal/ui/mounts":
			body = map[string]any{"data": map[string]any{"secret": map[string]any{"secret/": mount}}}
		case "/v1/sys/internal/ui/mounts/secret", "/v1/sys/internal/ui/mounts/secret/item":
			body = map[string]any{"data": mount}
		case "/v1/secret/metadata":
			body = map[string]any{"data": map[string]any{"keys": []string{"item"}}}
		case "/v1/secret/data/item":
			body = map[string]any{"data": map[string]any{"data": map[string]any{"value": "fixture-value"}}}
		default:
			t.Error("read-only wrapping regression used an unexpected endpoint")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Error("could not encode the wrapping regression fixture")
		}
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_WRAP_TTL", "5m")
	t.Setenv("VAULT_HEADERS", `{"x-vault-wrap-ttl":"1m"}`)
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatalf("create client with inherited wrapping: %v", err)
	}
	ctx := context.Background()
	const token = "wrapping-isolation-token"
	t.Run("public health", func(t *testing.T) {
		health, err := client.Status(ctx)
		if err != nil || !health.Initialized || health.Sealed {
			t.Fatal("inherited wrapping changed the health operation")
		}
	})
	t.Run("authentication", func(t *testing.T) {
		report, err := client.CheckToken(ctx, token)
		if err != nil || !report.Authenticated {
			t.Fatal("inherited wrapping changed the authentication operation")
		}
	})
	t.Run("mount catalog", func(t *testing.T) {
		mounts, err := client.Mounts(ctx, token)
		if err != nil || len(mounts) != 1 || mounts[0].Path != "secret/" {
			t.Fatal("inherited wrapping changed the mount catalog operation")
		}
	})
	t.Run("KV list", func(t *testing.T) {
		children, err := client.List(ctx, token, "/secret", vault.KVOptions{})
		if err != nil || len(children) != 1 || children[0] != "item" {
			t.Fatal("inherited wrapping changed the KV list operation")
		}
	})
	t.Run("KV read", func(t *testing.T) {
		data, err := client.Read(ctx, token, "/secret/item", vault.KVOptions{})
		if err != nil || data["value"] != "fixture-value" {
			t.Fatal("inherited wrapping changed the KV read operation")
		}
	})
}
