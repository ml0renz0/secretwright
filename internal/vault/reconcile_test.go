package vault_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ml0renz0/secretwright/internal/vault"
)

func TestReconciliationTargetBindsClusterAddressAndNamespaceWithoutCredentials(t *testing.T) {
	for _, scenario := range []string{"ready", "sealed", "uninitialized", "missing_cluster"} {
		t.Run(scenario, func(t *testing.T) {
			clearVaultEnvironment(t)
			cluster := "11111111-1111-4111-8111-111111111111"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/v1/sys/health" || r.Header.Get("X-Vault-Token") != "" || r.Header.Get("X-Vault-Namespace") != "team/dev" {
					t.Error("target binding consulted credentials or changed the selected namespace")
				}
				state := map[string]any{"initialized": true, "sealed": false, "cluster_id": cluster}
				if scenario == "sealed" {
					state["sealed"] = true
				} else if scenario == "uninitialized" {
					state["initialized"] = false
				} else if scenario == "missing_cluster" {
					state["cluster_id"] = ""
				}
				_ = json.NewEncoder(w).Encode(state)
			}))
			defer server.Close()
			t.Setenv("VAULT_TOKEN", "private-f09-inherited-token")
			namespace := "team/dev"
			client, err := vault.New(vault.Options{Address: &server.URL, Namespace: &namespace})
			if err != nil {
				t.Fatal("could not create target-binding fixture client")
			}
			target, err := client.ReconciliationTarget(context.Background())
			if scenario != "ready" {
				if err == nil || target != (vault.TargetBinding{}) || strings.Contains(err.Error(), server.URL) {
					t.Error("unusable target returned an ownership binding or an input-bearing error")
				}
				return
			}
			digest := sha256.Sum256([]byte(server.URL))
			if err != nil || target.AddressSHA256 != hex.EncodeToString(digest[:]) || target.ClusterID != cluster || target.Namespace != namespace {
				t.Error("target binding omitted or mixed the configured address, cluster or namespace")
			}
			body, _ := json.Marshal(target)
			if strings.Contains(string(body), server.URL) || strings.Contains(string(body), "private-f09") {
				t.Error("target binding exposed its server URL or credential")
			}
		})
	}
}
