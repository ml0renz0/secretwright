//go:build integration

package blueprint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/blueprint"
	"github.com/ml0renz0/secretwright/internal/managedstate"
	"github.com/ml0renz0/secretwright/internal/vault"
)

func f09IntegrationTarget(t *testing.T, ctx context.Context, client *vault.Client) managedstate.Target {
	t.Helper()
	binding, err := client.ReconciliationTarget(ctx)
	if err != nil {
		t.Fatal("could not bind the disposable reconciliation target")
	}
	return managedstate.Target{AddressSHA256: binding.AddressSHA256, ClusterID: binding.ClusterID, Namespace: binding.Namespace}
}

func f09IntegrationStore(t *testing.T, state managedstate.State) (*managedstate.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "managed-state.json")
	if err := managedstate.Create(path, state); err != nil {
		t.Fatal("could not create the private reconciliation inventory")
	}
	store, err := managedstate.Lock(path)
	if err != nil {
		t.Fatal("could not lock the disposable reconciliation inventory")
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, path
}

func f09FindRecord(t *testing.T, state managedstate.State, id string) managedstate.Record {
	t.Helper()
	for _, record := range state.Resources {
		if record.ID == id {
			return record
		}
	}
	t.Fatal("managed inventory omitted the expected resource")
	return managedstate.Record{}
}

func f09Raw(t *testing.T, ctx context.Context, fixture *blueprintIntegrationFixture, path string) map[string]any {
	t.Helper()
	secret, err := fixture.admin.Logical().ReadWithContext(ctx, path)
	if err != nil || secret == nil || secret.Data == nil {
		t.Fatal("could not inspect the private reconciliation preservation fixture")
	}
	return secret.Data
}

func f09RequireInventoryPrivate(t *testing.T, path string, forbidden ...string) {
	t.Helper()
	body, err := os.ReadFile(path)
	info, statErr := os.Lstat(path)
	if err != nil || statErr != nil || info.Mode().Perm() != 0o600 || !json.Valid(body) {
		t.Fatal("reconciliation inventory was not valid private JSON")
	}
	for _, value := range append([]string{"capabilities", "token_policies", "private-f07-", "private-f09-", `"spec"`, `"alias_metadata"`}, forbidden...) {
		if value != "" && bytes.Contains(body, []byte(value)) {
			t.Fatal("reconciliation inventory persisted configuration, credentials or private preserved fields")
		}
	}
}

func TestIntegrationManagedUpdatesPreserveUnmanagedFieldsAndEffectiveAccess(t *testing.T) {
	fixture := prepareBlueprintIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	document := loadIntegrationBlueprint(t, blueprintIntegrationSource(fixture))
	if _, err := blueprint.Apply(ctx, document, blueprint.NewVaultBackend(fixture.client, fixture.issuer)); err != nil {
		t.Fatal("could not prepare the pre-F09 declarative installation")
	}
	backend := blueprint.NewManagedVaultBackend(fixture.client, fixture.issuer)
	target := f09IntegrationTarget(t, ctx, fixture.client)
	state, _, err := blueprint.Adopt(ctx, document, backend, target)
	if err != nil || len(state.Resources) != len(document.Resources) {
		t.Fatal("explicit adoption could not capture the existing F07 installation")
	}
	entityID := f09FindRecord(t, state, "entity").RemoteID
	groupID := f09FindRecord(t, state, "base-group").RemoteID
	policyName, roleName := fixture.prefix+"-read", fixture.prefix+"-role"
	rolePath := "auth/" + fixture.auth + "/role/" + roleName
	for path, body := range map[string]map[string]any{
		"identity/entity/id/" + entityID: {"name": fixture.prefix + "-entity", "policies": []string{}, "disabled": false, "metadata": map[string]string{"fixture": "private-f09-entity-metadata"}},
		"identity/group/id/" + groupID: {"name": fixture.prefix + "-base", "type": "internal", "policies": []string{policyName}, "member_entity_ids": []string{entityID}, "metadata": map[string]string{"fixture": "private-f09-group-metadata"}},
		rolePath: {
			"token_policies": []string{policyName}, "token_ttl": 120, "token_max_ttl": 300,
			"secret_id_ttl": 120, "secret_id_num_uses": 5, "token_num_uses": 0,
			"bind_secret_id": true, "token_no_default_policy": true, "token_type": "service", "token_period": 0,
			"alias_metadata": map[string]string{"fixture": "private-f09-role-alias"},
			// Preserve a non-empty CIDR independently of whether the fixture is
			// reached through loopback or a Docker bridge address.
			"secret_id_bound_cidrs": []string{"0.0.0.0/0"}, "token_bound_cidrs": []string{"0.0.0.0/0"}, "token_explicit_max_ttl": 600,
		},
	} {
		if _, err := fixture.admin.Logical().WriteWithContext(ctx, path, body); err != nil {
			t.Fatal("could not prepare private fields outside the managed projection")
		}
	}
	credentials, err := fixture.control.IssueAppRoleCredentials(ctx, fixture.issuer, roleName, vault.AppRoleOptions{Mount: fixture.auth})
	if err != nil {
		t.Fatal("could not issue the pre-update SecretID preservation fixture")
	}
	auth, err := fixture.admin.Sys().ListAuthWithContext(ctx)
	if err != nil || auth[fixture.auth+"/"] == nil {
		t.Fatal("could not inspect the existing authentication binding")
	}
	alias, err := fixture.admin.Logical().WriteWithContext(ctx, "identity/entity-alias", map[string]any{"name": credentials.RoleID, "canonical_id": entityID, "mount_accessor": auth[fixture.auth+"/"].Accessor})
	if err != nil || alias == nil || alias.Data["id"] == nil {
		t.Fatal("could not prepare an external identity alias")
	}
	aliasID, _ := alias.Data["id"].(string)
	opts := vault.KVOptions{Mount: fixture.mount, Version: 2}
	for _, key := range []string{"allowed/item", "denied/item"} {
		if _, err := fixture.control.Put(ctx, fixture.issuer, "/"+fixture.mount+"/"+key, map[string]any{"value": "private-f09-kv-value"}, vault.WriteOptions{KVOptions: opts}); err != nil {
			t.Fatal("could not seed disposable access verification data")
		}
	}
	issued, err := fixture.control.LoginAppRole(ctx, credentials, vault.AppRoleOptions{Mount: fixture.auth})
	if err != nil || issued.Token == "" || issued.Report.EntityID != entityID {
		t.Fatal("pre-update credentials did not resolve the external identity alias")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = fixture.admin.Auth().Token().RevokeTreeWithContext(cleanup, issued.Token)
	})
	read := func(key string, permitted bool) {
		t.Helper()
		value, readErr := fixture.control.Read(ctx, issued.Token, "/"+fixture.mount+"/"+key, opts)
		if permitted {
			if readErr != nil || value["value"] != "private-f09-kv-value" {
				t.Fatal("managed policy did not grant its current effective permission")
			}
		} else if !errors.Is(readErr, vault.ErrPermissionDenied) {
			t.Fatal("managed policy granted a permission removed from its current ACL")
		}
	}
	read("allowed/item", true)
	read("denied/item", false)
	beforeRole := f09Raw(t, ctx, fixture, rolePath)
	beforeAlias := f09Raw(t, ctx, fixture, "identity/entity-alias/id/"+aliasID)
	// Adopt again into a new inventory after preparing external metadata; none
	// of those unmanaged fields should be treated as managed drift.
	writes := fixture.writes.Load()
	state, _, err = blueprint.Adopt(ctx, document, backend, target)
	if err != nil || fixture.writes.Load() != writes {
		t.Fatal("read-only adoption changed Vault or confused external metadata with managed fields")
	}
	store, statePath := f09IntegrationStore(t, state)
	desired, err := blueprint.ValidateDocument(document)
	if err != nil {
		t.Fatal("could not detach the desired update fixture")
	}
	for index := range desired.Resources {
		resource := &desired.Resources[index]
		switch resource.ID {
		case "read":
			resource.Spec["policy"] = fmt.Sprintf(`path %q { capabilities = ["read"] }`, fixture.mount+"/data/denied/item")
		case "role":
			resource.Spec["token_ttl"] = "1m"
		case "entity":
			resource.Spec["policies"] = []string{policyName}
		case "base-group":
			resource.Spec["policies"] = []string{}
		case "group":
			resource.Spec["policies"] = []string{policyName}
		}
	}
	desired, err = blueprint.ValidateDocument(desired)
	if err != nil {
		t.Fatal("desired managed changes failed blueprint validation")
	}
	plan, err := blueprint.BuildManagedPlan(ctx, desired, backend, store.Snapshot(), target, false)
	if err != nil || len(plan.Changes) != 5 || fixture.writes.Load() != writes {
		t.Fatal("managed plan did not identify only its five intentional updates")
	}
	report, err := blueprint.ApplyManaged(ctx, desired, backend, store, target, false)
	if err != nil || fixture.writes.Load() != writes+5 {
		t.Fatal("managed updates did not execute each declared mutation exactly once")
	}
	read("allowed/item", false)
	read("denied/item", true)
	afterRole := f09Raw(t, ctx, fixture, rolePath)
	for _, key := range []string{"alias_metadata", "secret_id_bound_cidrs", "token_bound_cidrs", "token_explicit_max_ttl", "local_secret_ids"} {
		if !reflect.DeepEqual(beforeRole[key], afterRole[key]) {
			t.Fatal("AppRole update changed private fields outside the managed projection")
		}
	}
	for path, marker := range map[string]string{"identity/entity/id/" + entityID: "private-f09-entity-metadata", "identity/group/id/" + groupID: "private-f09-group-metadata"} {
		metadata, _ := f09Raw(t, ctx, fixture, path)["metadata"].(map[string]any)
		if metadata["fixture"] != marker {
			t.Fatal("identity update removed private metadata outside the blueprint")
		}
	}
	if !reflect.DeepEqual(beforeAlias, f09Raw(t, ctx, fixture, "identity/entity-alias/id/"+aliasID)) {
		t.Fatal("managed identity update changed its external authentication alias")
	}
	currentCredentials, err := fixture.control.IssueAppRoleCredentials(ctx, fixture.issuer, roleName, vault.AppRoleOptions{Mount: fixture.auth})
	if err != nil || currentCredentials.RoleID != credentials.RoleID {
		t.Fatal("AppRole update regenerated its existing RoleID")
	}
	afterLogin, err := fixture.control.LoginAppRole(ctx, credentials, vault.AppRoleOptions{Mount: fixture.auth})
	if err != nil || afterLogin.Token == "" {
		t.Fatal("AppRole update invalidated a previously issued SecretID")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = fixture.admin.Auth().Token().RevokeTreeWithContext(cleanup, afterLogin.Token)
	})
	confirmed, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal("could not inspect the confirmed inventory")
	}
	writes = fixture.writes.Load()
	if _, err := blueprint.ApplyManaged(ctx, desired, backend, store, target, false); err != nil || fixture.writes.Load() != writes {
		t.Fatal("second managed application was not free of Vault writes")
	}
	if next, err := os.ReadFile(statePath); err != nil || !bytes.Equal(confirmed, next) {
		t.Fatal("idempotent managed application rewrote an unchanged inventory")
	}
	// An external ACL edit changes permissions for the same already-issued
	// token. Ordinary apply must stop; explicit repair restores the intended ACL.
	if _, err := fixture.control.WritePolicy(ctx, fixture.issuer, policyName, fmt.Sprintf(`path %q { capabilities = ["read"] }`, fixture.mount+"/data/allowed/item")); err != nil {
		t.Fatal("could not inject deterministic external policy drift")
	}
	read("allowed/item", true)
	read("denied/item", false)
	if _, err := blueprint.ApplyManaged(ctx, desired, backend, store, target, false); !errors.Is(err, blueprint.ErrConflict) || fixture.writes.Load() != writes {
		t.Fatal("ordinary managed apply overwrote external drift without explicit repair")
	}
	if next, err := os.ReadFile(statePath); err != nil || !bytes.Equal(confirmed, next) {
		t.Fatal("conflicting preflight changed its inventory baseline")
	}
	if _, err := blueprint.ApplyManaged(ctx, desired, backend, store, target, true); err != nil || fixture.writes.Load() != writes+1 {
		t.Fatal("explicit repair did not reconcile only the drifted policy")
	}
	read("allowed/item", false)
	read("denied/item", true)
	for _, badTarget := range []managedstate.Target{
		{AddressSHA256: target.AddressSHA256, ClusterID: target.ClusterID, Namespace: "other-team"},
		{AddressSHA256: f09Hash("another-url"), ClusterID: target.ClusterID, Namespace: target.Namespace},
		{AddressSHA256: target.AddressSHA256, ClusterID: "00000000-0000-4000-8000-000000000000", Namespace: target.Namespace},
	} {
		before := fixture.writes.Load()
		if _, err := blueprint.ApplyManaged(ctx, desired, backend, store, badTarget, true); !errors.Is(err, blueprint.ErrConflict) || fixture.writes.Load() != before {
			t.Fatal("managed inventory allowed mutation of a different target binding")
		}
	}
	f09RequireInventoryPrivate(t, statePath, fixture.issuer, credentials.RoleID, credentials.SecretID, credentials.SecretIDAccessor, issued.Token, issued.Accessor)
	f09Safe(t, plan, report)
	// The role identity proof must also reject an otherwise identical role
	// whose credential identifier has been replaced outside this inventory.
	if _, err := fixture.admin.Logical().WriteWithContext(ctx, rolePath+"/role-id", map[string]any{"role_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}); err != nil {
		t.Fatal("could not inject deterministic AppRole identity replacement")
	}
	before := fixture.writes.Load()
	if _, err := blueprint.ApplyManaged(ctx, desired, backend, store, target, true); !errors.Is(err, blueprint.ErrConflict) || fixture.writes.Load() != before {
		t.Fatal("repair silently adopted a replaced AppRole credential identity")
	}
}

func TestIntegrationManagedLostAcknowledgementPersistsPendingAndRecoversWithoutReplay(t *testing.T) {
	fixture := prepareBlueprintIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	policy := fixture.prefix + "-uncertain"
	resource := f07PolicyResource("a")
	resource["name"] = policy
	document := f07LoadDocument(t, resource)
	upstream, err := url.Parse(os.Getenv("VAULT_ADDR"))
	if err != nil {
		t.Fatal("invalid disposable reconciliation address")
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	var writes atomic.Int32
	var applied atomic.Bool
	physical := "/v1/sys/policies/acl/" + policy
	proxy.ModifyResponse = func(response *http.Response) error {
		if response.Request.URL.Path == physical && response.Request.Method != http.MethodGet && response.StatusCode >= 200 && response.StatusCode < 300 {
			applied.Store(true)
			return errors.New("discard the mutation acknowledgement")
		}
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, _ error) {
		if r.URL.Path == physical && applied.Load() {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error("could not inject the acknowledgement loss")
				return
			}
			_ = connection.Close()
			return
		}
		w.WriteHeader(http.StatusBadGateway)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != "LIST" {
			writes.Add(1)
		}
		proxy.ServeHTTP(w, r)
	}))
	defer server.Close()
	address := server.URL
	client, err := vault.New(vault.Options{Address: &address})
	if err != nil {
		t.Fatal("could not initialize the acknowledgement-loss client")
	}
	backend := blueprint.NewManagedVaultBackend(client, fixture.issuer)
	target := f09IntegrationTarget(t, ctx, client)
	state, _, err := blueprint.Adopt(ctx, document, backend, target)
	if err != nil || len(state.Resources) != 0 || writes.Load() != 0 {
		t.Fatal("clean-server adoption wrote Vault or claimed an absent resource")
	}
	store, statePath := f09IntegrationStore(t, state)
	report, err := blueprint.ApplyManaged(ctx, document, backend, store, target, false)
	if !errors.Is(err, blueprint.ErrPartial) || !applied.Load() || writes.Load() != 1 || len(store.Snapshot().Resources) != 1 || store.Snapshot().Resources[0].Pending != "create" {
		t.Fatal("lost acknowledgement was retried or lost its durable pending evidence")
	}
	if _, err := fixture.control.ReadPolicy(ctx, fixture.issuer, policy); err != nil {
		t.Fatal("the injected uncertain mutation did not actually reach Vault")
	}
	if _, err := blueprint.RecoverManaged(ctx, document, backend, store, target, false); !errors.Is(err, blueprint.ErrConflict) || writes.Load() != 1 {
		t.Fatal("recovery implicitly claimed an uncertain creation or replayed it")
	}
	if _, err := blueprint.RecoverManaged(ctx, document, backend, store, target, true); err != nil || writes.Load() != 1 || store.Snapshot().Resources[0].Pending != "" {
		t.Fatal("explicit recovery failed to confirm the existing creation without replay")
	}
	plan, err := blueprint.BuildManagedPlan(ctx, document, backend, store.Snapshot(), target, false)
	if err != nil || len(plan.Changes) != 0 || writes.Load() != 1 {
		t.Fatal("recovered result did not produce an empty managed plan")
	}
	f09Safe(t, report, plan, err)
	f09RequireInventoryPrivate(t, statePath, fixture.issuer)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = fixture.admin.Sys().DeletePolicyWithContext(cleanup, policy)
	})
}
