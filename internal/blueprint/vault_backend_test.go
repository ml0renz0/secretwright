package blueprint_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ml0renz0/secretwright/internal/blueprint"
	"github.com/ml0renz0/secretwright/internal/vault"
)

func f07Reply(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": value})
}

func f07VaultBackend(t *testing.T, handler http.HandlerFunc) (*blueprint.VaultBackend, *httptest.Server) {
	t.Helper()
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "VAULT_") {
			t.Setenv(name, "")
		}
	}
	t.Setenv("VAULT_TOKEN", "private-f07-inherited-token")
	t.Setenv("VAULT_WRAP_TTL", "1h")
	t.Setenv("VAULT_HEADERS", `{"X-Private":"private-f07-inherited-header"}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "selected-f07-token" || r.Header.Get("X-Vault-Namespace") != "team/dev" || r.Header.Get("X-Vault-Wrap-TTL") != "" || r.Header.Get("X-Private") != "" {
			t.Error("blueprint request inherited authentication, wrapping or headers")
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	namespace := "team/dev"
	client, err := vault.New(vault.Options{Address: &server.URL, Namespace: &namespace})
	if err != nil {
		t.Fatal("could not initialize blueprint fixture client")
	}
	return blueprint.NewVaultBackend(client, "selected-f07-token"), server
}

func f07MountCatalog() map[string]any {
	return map[string]any{
		"secret/":   map[string]any{"type": "kv", "options": map[string]any{"version": "2"}, "accessor": "kv_secret"},
		"database/": map[string]any{"type": "database", "options": map[string]any{}, "accessor": "database_app"},
	}
}

func f07RoleState() map[string]any {
	return map[string]any{
		"token_policies": []string{"app-read"}, "token_ttl": 300, "token_max_ttl": 3600,
		"secret_id_ttl": 600, "secret_id_num_uses": 1, "token_num_uses": 0,
		"bind_secret_id": true, "token_no_default_policy": true, "token_type": "service", "token_period": 0,
	}
}

func f07RoleResource() blueprint.Resource {
	return blueprint.Resource{ID: "role", Kind: "approle", Name: "app", Spec: map[string]any{
		"auth_mount": "team/approle", "token_policies": []any{"app-read"}, "token_ttl": "5m", "token_max_ttl": "1h",
		"secret_id_ttl": "10m", "secret_id_num_uses": json.Number("1"), "token_num_uses": json.Number("0"),
	}}
}

func TestVaultBlueprintMountInspectionRejectsConversionsAndOverlappingPrefixes(t *testing.T) {
	var mutations atomic.Int32
	backend, _ := f07VaultBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/sys/mounts" {
			mutations.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f07Reply(w, f07MountCatalog())
	})
	for _, test := range []struct {
		name     string
		version  int
		conflict bool
	}{
		{name: "secret", version: 2},
		{name: "secret", version: 1, conflict: true},
		{name: "secret/nested", version: 2, conflict: true},
		{name: "database", version: 2, conflict: true},
	} {
		resource := blueprint.Resource{ID: "storage", Kind: "kv_mount", Name: test.name, Spec: map[string]any{"version": test.version}}
		observed, err := backend.Inspect(context.Background(), resource, nil)
		if err != nil || test.conflict && observed.Conflict == "" || !test.conflict && (!observed.Exists || !observed.Equal) {
			t.Error("KV inspection silently adopted an incompatible version, backend or overlapping mount")
		}
	}
	if mutations.Load() != 0 {
		t.Error("KV mount planning sent a mutation or read a secret")
	}
}

func TestVaultBlueprintCreationVerifiesItsResultAndNeverRetries(t *testing.T) {
	for _, failVerification := range []bool{false, true} {
		t.Run(map[bool]string{false: "verified", true: "unconfirmed"}[failVerification], func(t *testing.T) {
			var created atomic.Bool
			var writes atomic.Int32
			backend, _ := f07VaultBackend(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/mounts":
					catalog := map[string]any{}
					if created.Load() {
						if failVerification {
							w.WriteHeader(http.StatusForbidden)
							_, _ = w.Write([]byte(`{"errors":["private-f07-verification-body"]}`))
							return
						}
						catalog["app/"] = map[string]any{"type": "kv", "options": map[string]any{"version": "2"}, "accessor": "kv_app"}
					}
					f07Reply(w, catalog)
				case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/mounts/app":
					writes.Add(1)
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["type"] != "kv" || !reflect.DeepEqual(body["options"], map[string]any{"version": "2"}) {
						t.Error("blueprint mount creation did not use its fixed KV version")
					}
					created.Store(true)
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Error("blueprint mount creation used an unexpected endpoint")
					w.WriteHeader(http.StatusNotFound)
				}
			})
			resource := blueprint.Resource{ID: "storage", Kind: "kv_mount", Name: "app", Spec: map[string]any{"version": 2}}
			observed, err := backend.Create(context.Background(), resource, nil)
			if failVerification {
				if !errors.Is(err, blueprint.ErrUnconfirmed) {
					t.Error("a write followed by failed verification was reported as a safe retry")
				}
				f07RequirePrivate(t, err)
			} else if err != nil || !observed.Exists || !observed.Equal {
				t.Error("confirmed blueprint creation did not return a verified observation")
			}
			if writes.Load() != 1 {
				t.Error("blueprint creation retried or performed an extra mutation")
			}
		})
	}
}

func TestVaultBlueprintAppRolePreflightRequiresTheExistingBackendAndFixedInvariants(t *testing.T) {
	for _, test := range []struct {
		name       string
		missing    bool
		periodic   bool
		batch      bool
	}{
		{name: "equivalent"}, {name: "missing auth mount", missing: true}, {name: "periodic", periodic: true}, {name: "batch", batch: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var writes, roleReads atomic.Int32
			backend, _ := f07VaultBackend(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					writes.Add(1)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				switch r.URL.Path {
				case "/v1/sys/auth":
					catalog := map[string]any{}
					if !test.missing {
						catalog["team/approle/"] = map[string]any{"type": "approle", "accessor": "auth_approle_app"}
					}
					f07Reply(w, catalog)
				case "/v1/auth/team/approle/role/app":
					roleReads.Add(1)
					data := f07RoleState()
					if test.periodic {
						data["token_period"] = 60
					}
					if test.batch {
						data["token_type"] = "batch"
					}
					f07Reply(w, data)
				default:
					t.Error("AppRole planning read an unexpected endpoint")
					w.WriteHeader(http.StatusNotFound)
				}
			})
			observed, err := backend.Inspect(context.Background(), f07RoleResource(), nil)
			switch {
			case test.missing:
				if !errors.Is(err, vault.ErrNotFound) || roleReads.Load() != 0 {
					t.Error("a missing authentication mount was mistaken for a missing role")
				}
			case test.periodic || test.batch:
				if err != nil || !observed.Exists || observed.Equal {
					t.Error("blueprint planning accepted an existing periodic or batch role as equivalent")
				}
			default:
				if err != nil || !observed.Exists || !observed.Equal {
					t.Error("the desired AppRole did not match its existing bounded configuration")
				}
			}
			if writes.Load() != 0 {
				t.Error("AppRole planning modified authentication configuration")
			}
		})
	}
}

func TestVaultBlueprintReferencesUseObservedUUIDsWithoutChangingFingerprints(t *testing.T) {
	backend, _ := f07VaultBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/identity/group/name/app-team" {
			t.Error("group reference planning enumerated or mutated unrelated resources")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		f07Reply(w, map[string]any{
			"id": f07GroupID, "name": "app-team", "type": "internal", "policies": []string{},
			"member_entity_ids": []string{f07EntityID}, "member_group_ids": []string{},
			"metadata": map[string]any{"private": "private-f07-group-metadata"},
		})
	})
	resource := blueprint.Resource{ID: "team", Kind: "group", Name: "app-team", Spec: map[string]any{"member_entities": []any{"owner"}}}
	unresolved, err := backend.Inspect(context.Background(), resource, nil)
	if err != nil || !unresolved.Exists || unresolved.Equal || unresolved.Conflict == "" {
		t.Fatal("an existing group with unresolved member references was silently adopted")
	}
	resolved, err := backend.Inspect(context.Background(), resource, map[string]string{"owner": f07EntityID})
	if err != nil || !resolved.Exists || !resolved.Equal || resolved.ID != f07GroupID || unresolved.Fingerprint != resolved.Fingerprint {
		t.Error("resolving desired member IDs changed the fingerprint of an unchanged observed group")
	}
	f07RequirePrivate(t, resolved, unresolved)
}

func TestVaultBlueprintPolicyComparisonCanonicalizesSyntaxWithoutReturningBodies(t *testing.T) {
	backend, _ := f07VaultBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/sys/policies/acl/app-read" {
			t.Error("policy inspection used an unrelated route")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		f07Reply(w, map[string]any{"name": "app-read", "policy": "path   \"secret/data/app/*\" { capabilities=[ \"read\" ] }"})
	})
	resource := blueprint.Resource{ID: "read", Kind: "policy", Name: "app-read", Spec: map[string]any{"policy": f07Policy}}
	observed, err := backend.Inspect(context.Background(), resource, nil)
	if err != nil || !observed.Exists || !observed.Equal {
		t.Error("policy formatting alone was treated as a configuration conflict")
	}
	f07RequirePrivate(t, observed)
}
