package blueprint_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ml0renz0/secretwright/internal/blueprint"
	"github.com/ml0renz0/secretwright/internal/vault"
)

func f09ManagedBackend(t *testing.T, handler http.HandlerFunc) (*blueprint.ManagedVaultBackend, *blueprint.VaultBackend) {
	t.Helper()
	legacy, server := f07VaultBackend(t, handler)
	namespace := "team/dev"
	client, err := vault.New(vault.Options{Address: &server.URL, Namespace: &namespace})
	if err != nil {
		t.Fatal("could not initialize managed backend fixture")
	}
	return blueprint.NewManagedVaultBackend(client, "selected-f07-token"), legacy
}

func f09AuthCatalog(w http.ResponseWriter) {
	f07Reply(w, map[string]any{"team/approle/": map[string]any{"type": "approle", "accessor": "auth_approle_app"}})
}

func f09PrivateObservation(t *testing.T, observation blueprint.Observation) {
	t.Helper()
	body, err := json.Marshal(observation)
	if err != nil || string(body) != "{}" {
		t.Error("managed observation exposed identity proofs or private configuration")
	}
}

func TestManagedAppRoleIdentityAndPreservationGuardDoNotChangeLegacyPermissions(t *testing.T) {
	var roleReads atomic.Int32
	var roleID, alias atomic.Value
	roleID.Store("private-f09-role-id")
	alias.Store("private-f09-alias-one")
	managed, legacy := f09ManagedBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("managed observation sent a mutation")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/v1/sys/auth":
			f09AuthCatalog(w)
		case "/v1/auth/team/approle/role/app":
			state := f07RoleState()
			state["alias_metadata"] = map[string]string{"external": alias.Load().(string)}
			f07Reply(w, state)
		case "/v1/auth/team/approle/role/app/role-id":
			roleReads.Add(1)
			f07Reply(w, map[string]any{"role_id": roleID.Load().(string)})
		default:
			t.Error("managed observation used an unrelated endpoint")
			w.WriteHeader(http.StatusNotFound)
		}
	})
	if observed, err := legacy.Inspect(context.Background(), f07RoleResource(), nil); err != nil || !observed.Equal || roleReads.Load() != 0 {
		t.Fatal("legacy F07 inspection acquired a new credential-read permission requirement")
	}
	first, err := managed.Inspect(context.Background(), f07RoleResource(), nil)
	if err != nil || !first.Equal || first.ID != "" || len(first.Identity) != 64 || len(first.Guard) != 64 || roleReads.Load() == 0 {
		t.Fatal("managed role observation omitted its hashed stable identity or preservation guard")
	}
	alias.Store("private-f09-alias-two")
	second, err := managed.Inspect(context.Background(), f07RoleResource(), nil)
	if err != nil || first.Identity != second.Identity || first.Fingerprint != second.Fingerprint || first.Guard == second.Guard {
		t.Error("an unmanaged alias change changed the managed baseline or escaped its write guard")
	}
	roleID.Store("private-f09-replaced-role-id")
	replaced, err := managed.Inspect(context.Background(), f07RoleResource(), nil)
	if err != nil || replaced.Identity == second.Identity || replaced.Fingerprint != second.Fingerprint {
		t.Error("a recreated role with equivalent configuration retained its old identity proof")
	}
	f09PrivateObservation(t, first)
	f09PrivateObservation(t, second)
	f09PrivateObservation(t, replaced)
}

func TestManagedAppRoleUpdatePreservesUnmanagedConfigurationAndRefusesStaleProofs(t *testing.T) {
	for _, change := range []string{"none", "alias", "identity"} {
		t.Run(change, func(t *testing.T) {
			var writes atomic.Int32
			var updated atomic.Bool
			var roleID, alias atomic.Value
			roleID.Store("private-f09-role-id")
			alias.Store("private-f09-external-alias")
			backend, _ := f09ManagedBackend(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/auth":
					f09AuthCatalog(w)
				case r.Method == http.MethodGet && r.URL.Path == "/v1/auth/team/approle/role/app/role-id":
					f07Reply(w, map[string]any{"role_id": roleID.Load().(string)})
				case r.Method == http.MethodGet && r.URL.Path == "/v1/auth/team/approle/role/app":
					state := f07RoleState()
					state["alias_metadata"] = map[string]string{"external": alias.Load().(string)}
					state["secret_id_bound_cidrs"], state["token_bound_cidrs"] = []string{"127.0.0.0/8"}, []string{"127.0.0.0/8"}
					state["token_explicit_max_ttl"], state["local_secret_ids"] = 7200, true
					if updated.Load() {
						state["token_ttl"] = 600
					}
					f07Reply(w, state)
				case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/team/approle/role/app":
					writes.Add(1)
					var body map[string]any
					if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 11 || body["token_ttl"] != float64(600) || !reflect.DeepEqual(body["alias_metadata"], map[string]any{"external": "private-f09-external-alias"}) {
						t.Error("role update omitted preserved alias metadata or changed its managed whitelist")
					}
					for _, forbidden := range []string{"role_id", "secret_id_bound_cidrs", "token_bound_cidrs", "token_explicit_max_ttl", "local_secret_ids"} {
						if _, present := body[forbidden]; present {
							t.Error("role update replayed a credential, restriction or create-only field")
						}
					}
					updated.Store(true)
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Error("managed role update used an unrelated endpoint")
					w.WriteHeader(http.StatusNotFound)
				}
			})
			resource := f07RoleResource()
			resource.Spec["token_ttl"] = "10m"
			before, err := backend.Inspect(context.Background(), resource, nil)
			if err != nil || !before.Exists || before.Equal {
				t.Fatal("could not observe the role's intentional configuration change")
			}
			if change == "alias" {
				alias.Store("private-f09-concurrent-alias")
			} else if change == "identity" {
				roleID.Store("private-f09-concurrent-role-id")
			}
			after, err := backend.Update(context.Background(), resource, nil, before)
			if change != "none" {
				if !errors.Is(err, blueprint.ErrConflict) || writes.Load() != 0 {
					t.Error("a stale role identity or preserved field was overwritten")
				}
			} else if err != nil || writes.Load() != 1 || !after.Equal || after.Identity != before.Identity {
				t.Error("managed role update was not one verified mutation preserving its stable identity")
			}
			if err != nil && strings.Contains(err.Error(), "private-") {
				t.Error("managed role error exposed a credential or private preservation value")
			}
			f09PrivateObservation(t, after)
		})
	}
}

func TestManagedIdentityUpdateUsesRegisteredUUIDAndOnlyManagedFields(t *testing.T) {
	for _, kind := range []string{"entity", "group"} {
		t.Run(kind, func(t *testing.T) {
			id := f07EntityID
			if kind == "group" {
				id = f07GroupID
			}
			var writes atomic.Int32
			var updated atomic.Bool
			name := "app-" + kind
			backend, _ := f09ManagedBackend(t, func(w http.ResponseWriter, r *http.Request) {
				prefix := "/v1/identity/" + kind
				if r.Method == http.MethodGet && (r.URL.Path == prefix+"/name/"+name || r.URL.Path == prefix+"/id/"+id) {
					state := map[string]any{"id": id, "name": name, "policies": []string{}, "metadata": map[string]string{"external": "private-f09-metadata"}}
					if kind == "entity" {
						state["disabled"], state["aliases"] = false, []any{map[string]string{"name": "private-f09-alias"}}
					} else {
						state["type"], state["member_entity_ids"], state["member_group_ids"] = "internal", []string{}, []string{}
					}
					if updated.Load() {
						state["policies"] = []string{"app-read"}
					}
					f07Reply(w, state)
					return
				}
				if r.Method != http.MethodPost || r.URL.Path != prefix+"/id/"+id {
					t.Error("identity update used a name-based upsert or unrelated route")
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writes.Add(1)
				var body map[string]any
				if json.NewDecoder(r.Body).Decode(&body) != nil || body["name"] != name || !reflect.DeepEqual(body["policies"], []any{"app-read"}) {
					t.Error("identity update omitted its declared managed configuration")
				}
				wantFields := 3
				if kind == "group" {
					wantFields = 5
				}
				if len(body) != wantFields || body["metadata"] != nil || body["aliases"] != nil {
					t.Error("identity update replayed or cleared unrelated metadata and aliases")
				}
				updated.Store(true)
				w.WriteHeader(http.StatusNoContent)
			})
			resource := blueprint.Resource{ID: "identity", Kind: kind, Name: name, Spec: map[string]any{"policies": []any{"app-read"}}}
			before, err := backend.Inspect(context.Background(), resource, nil)
			if err != nil || before.ID != id || before.Equal || len(before.Identity) != 64 {
				t.Fatal("could not inspect the managed identity change")
			}
			after, err := backend.Update(context.Background(), resource, nil, before)
			if err != nil || writes.Load() != 1 || !after.Equal || after.ID != id || after.Identity != before.Identity {
				t.Error("identity update changed UUID or failed to verify its managed fields")
			}
			f09PrivateObservation(t, after)
		})
	}
}

func TestManagedUpdateDoesNotRetryLostAcknowledgementsOrFailedVerification(t *testing.T) {
	for _, lostAck := range []bool{false, true} {
		t.Run(map[bool]string{false: "verification_denied", true: "lost_acknowledgement"}[lostAck], func(t *testing.T) {
			var writes atomic.Int32
			var updated atomic.Bool
			backend, _ := f09ManagedBackend(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/sys/policies/acl/app-read" {
					t.Error("policy update used an unrelated route")
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if r.Method == http.MethodGet {
					if updated.Load() {
						w.WriteHeader(http.StatusForbidden)
						_, _ = w.Write([]byte(`{"errors":["private-f09-denied-body"]}`))
						return
					}
					f07Reply(w, map[string]any{"policy": f07Policy})
					return
				}
				if r.Method != http.MethodPost {
					t.Error("policy update changed its operation")
				}
				writes.Add(1)
				updated.Store(true)
				if lostAck {
					hijacker, ok := w.(http.Hijacker)
					if !ok {
						t.Error("fixture cannot discard its mutation acknowledgement")
						return
					}
					connection, _, err := hijacker.Hijack()
					if err == nil {
						_ = connection.Close()
					}
					return
				}
				w.WriteHeader(http.StatusNoContent)
			})
			resource := blueprint.Resource{ID: "policy", Kind: "policy", Name: "app-read", Spec: map[string]any{"policy": `path "secret/data/app/*" { capabilities = ["read", "list"] }`}}
			before, err := backend.Inspect(context.Background(), resource, nil)
			if err != nil || !before.Exists || before.Equal {
				t.Fatal("could not inspect the pending policy change")
			}
			if _, err := backend.Update(context.Background(), resource, nil, before); !errors.Is(err, blueprint.ErrUnconfirmed) || strings.Contains(err.Error(), "private-") || writes.Load() != 1 {
				t.Error("uncertain managed update was retried or misreported as safely rejected")
			}
		})
	}
}

func TestManagedBackendNeverUpdatesOrConvertsStorageMounts(t *testing.T) {
	var writes atomic.Int32
	backend, _ := f09ManagedBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/sys/mounts" {
			writes.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f07Reply(w, f07MountCatalog())
	})
	resource := blueprint.Resource{ID: "storage", Kind: "kv_mount", Name: "secret", Spec: map[string]any{"version": 2}}
	before, err := backend.Inspect(context.Background(), resource, nil)
	if err != nil || !before.Equal || before.ID == "" || len(before.Identity) != 64 {
		t.Fatal("managed storage observation omitted the mount accessor identity")
	}
	if _, err := backend.Update(context.Background(), resource, nil, before); !errors.Is(err, blueprint.ErrConflict) || writes.Load() != 0 {
		t.Error("managed storage update tuned, converted, or removed an existing mount")
	}
}

var _ blueprint.ManagedBackend = (*blueprint.ManagedVaultBackend)(nil)
