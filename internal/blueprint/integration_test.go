//go:build integration

package blueprint_test

import (
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
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/ml0renz0/secretwright/internal/blueprint"
	"github.com/ml0renz0/secretwright/internal/vault"
)

type blueprintIntegrationFixture struct {
	admin   *api.Client
	client  *vault.Client
	control *vault.Client
	issuer  string
	prefix  string
	mount   string
	auth    string
	writes  atomic.Int32
}

func prepareBlueprintIntegrationFixture(t *testing.T) *blueprintIntegrationFixture {
	t.Helper()
	address, tokenFile := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TEST_ROOT_TOKEN_FILE")
	if address == "" || tokenFile == "" {
		t.Fatal("run make integration-local with the disposable Vault fixture")
	}
	credential, err := os.ReadFile(tokenFile)
	if err != nil || len(credential) == 0 {
		t.Fatal("could not read the disposable blueprint fixture credential")
	}
	config := api.DefaultConfig()
	config.Address, config.MaxRetries, config.Timeout, config.DisableRedirects = address, 0, 5*time.Second, true
	admin, err := api.NewClient(config)
	if err != nil {
		t.Fatal("could not initialize the disposable blueprint administrator")
	}
	admin.SetToken(strings.TrimSpace(string(credential)))
	control, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatal("could not initialize the disposable blueprint control client")
	}
	prefix := fmt.Sprintf("f07-blueprint-%d", time.Now().UnixNano())
	fixture := &blueprintIntegrationFixture{admin: admin, control: control, issuer: admin.Token(), prefix: prefix, mount: prefix + "-kv", auth: prefix + "-approle"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := admin.Sys().EnableAuthWithOptionsWithContext(ctx, fixture.auth, &api.EnableAuthOptions{Type: "approle"}); err != nil {
		t.Fatal("could not enable the disposable prerequisite AppRole mount")
	}
	upstream, err := url.Parse(address)
	if err != nil {
		t.Fatal("invalid disposable Vault address")
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != "LIST" {
			fixture.writes.Add(1)
		}
		proxy.ServeHTTP(w, r)
	}))
	proxyAddress := server.URL
	fixture.client, err = vault.New(vault.Options{Address: &proxyAddress})
	if err != nil {
		server.Close()
		t.Fatal("could not initialize the observed blueprint client")
	}
	t.Cleanup(func() {
		server.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = admin.Sys().DisableAuthWithContext(cleanup, fixture.auth)
		_ = admin.Sys().UnmountWithContext(cleanup, fixture.mount)
		_ = admin.Sys().DeletePolicyWithContext(cleanup, fixture.prefix+"-read")
	})
	return fixture
}

func blueprintIntegrationSource(fixture *blueprintIntegrationFixture) string {
	return fmt.Sprintf(`api_version: secretwright/v1
name: %s
variables:
  storage: {type: string, default: %s}
  prefix: {type: string, default: %s}
  uses: {type: integer, default: 5}
  disabled: {type: boolean, default: false}
  note: {type: string, default: private-f07-variable-note}
resources:
  - id: storage
    kind: kv_mount
    name: ${var.storage}
    spec: {version: 2}
  - id: read
    kind: policy
    name: ${var.prefix}-read
    depends_on: [storage]
    spec:
      policy: |
        # private-f07-policy-body ${var.note}
        path "${var.storage}/data/allowed/item" { capabilities = ["read"] }
  - id: role
    kind: approle
    name: ${var.prefix}-role
    depends_on: [read]
    spec:
      auth_mount: %s
      token_policies: ["${var.prefix}-read"]
      token_ttl: 2m
      token_max_ttl: 5m
      secret_id_ttl: 2m
      secret_id_num_uses: "${var.uses}"
  - id: entity
    kind: entity
    name: ${var.prefix}-entity
    depends_on: [read]
    spec: {policies: [], disabled: "${var.disabled}"}
  - id: base-group
    kind: group
    name: ${var.prefix}-base
    depends_on: [read]
    spec:
      policies: ["${var.prefix}-read"]
      member_entities: [entity]
  - id: group
    kind: group
    name: ${var.prefix}-group
    spec: {member_groups: [base-group]}
`, fixture.prefix, fixture.mount, fixture.prefix, fixture.auth)
}

func loadIntegrationBlueprint(t *testing.T, source string) blueprint.Document {
	t.Helper()
	document, err := blueprint.Load(strings.NewReader(source), nil)
	if err != nil {
		t.Fatal("could not validate the bounded disposable blueprint")
	}
	return document
}

func requireBlueprintMetadata(t *testing.T, report any, forbidden ...string) {
	t.Helper()
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal("could not encode blueprint metadata")
	}
	for _, marker := range append([]string{"private-f07-policy-body", "private-f07-variable-note", "private-f07-secret-value"}, forbidden...) {
		if marker != "" && strings.Contains(string(body), marker) {
			t.Fatal("blueprint metadata exposed configuration contents or credentials")
		}
	}
}

func TestIntegrationBlueprintApplyCreatesResourcesAndThenPlansNoChanges(t *testing.T) {
	fixture := prepareBlueprintIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	document := loadIntegrationBlueprint(t, blueprintIntegrationSource(fixture))
	backend := blueprint.NewVaultBackend(fixture.client, fixture.issuer)
	plan, err := blueprint.BuildPlan(ctx, document, backend)
	if err != nil || len(plan.Changes) != 6 || fixture.writes.Load() != 0 {
		t.Fatal("blueprint planning did not inspect all new resources without mutations")
	}
	for _, change := range plan.Changes {
		if change.Action != "create" {
			t.Fatal("new blueprint resource did not plan creation")
		}
	}
	requireBlueprintMetadata(t, document, fixture.issuer)
	requireBlueprintMetadata(t, plan, fixture.issuer)
	report, err := blueprint.Apply(ctx, document, backend)
	if err != nil || len(report.Items) != 6 || fixture.writes.Load() != 6 {
		t.Fatal("blueprint apply did not create exactly its six declared resources")
	}
	ids := make(map[string]string)
	for _, item := range report.Items {
		if item.Status != "created" {
			t.Fatal("blueprint apply did not confirm all declared creations")
		}
		ids[item.ID] = item.RemoteID
	}
	requireBlueprintMetadata(t, report, fixture.issuer)
	if ids["entity"] == "" || ids["base-group"] == "" || ids["group"] == "" {
		t.Fatal("blueprint apply did not retain identity IDs for dependent resources")
	}
	base, err := fixture.control.ReadGroup(ctx, fixture.issuer, ids["base-group"])
	if err != nil || !reflect.DeepEqual(base.MemberEntityIDs, []string{ids["entity"]}) || !reflect.DeepEqual(base.Policies, []string{fixture.prefix + "-read"}) {
		t.Fatal("blueprint did not resolve the entity reference to its actual Vault ID")
	}
	group, err := fixture.control.ReadGroup(ctx, fixture.issuer, ids["group"])
	if err != nil || !reflect.DeepEqual(group.MemberGroupIDs, []string{ids["base-group"]}) {
		t.Fatal("blueprint did not resolve the group reference to its actual Vault ID")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = fixture.control.DeleteGroup(cleanup, fixture.issuer, ids["group"])
		_, _ = fixture.control.DeleteGroup(cleanup, fixture.issuer, ids["base-group"])
		_, _ = fixture.control.DeleteEntity(cleanup, fixture.issuer, ids["entity"])
	})
	plan, err = blueprint.BuildPlan(ctx, document, backend)
	if err != nil || len(plan.Changes) != 0 || len(plan.Resources) != 6 || fixture.writes.Load() != 6 {
		t.Fatal("an applied blueprint did not produce an empty plan")
	}
	again, err := blueprint.Apply(ctx, document, backend)
	if err != nil || len(again.Items) != 6 || fixture.writes.Load() != 6 {
		t.Fatal("idempotent blueprint apply repeated a mutation")
	}
	for _, item := range again.Items {
		if item.Status != "unchanged" {
			t.Fatal("idempotent blueprint apply did not report unchanged resources")
		}
	}
	for _, key := range []string{"allowed/item", "denied/item"} {
		if _, err := fixture.control.Put(ctx, fixture.issuer, "/"+fixture.mount+"/"+key, map[string]any{"value": "private-f07-secret-value"}, vault.WriteOptions{KVOptions: vault.KVOptions{Mount: fixture.mount, Version: 2}}); err != nil {
			t.Fatal("could not seed disposable data outside the declarative blueprint")
		}
	}
	credentials, err := fixture.control.IssueAppRoleCredentials(ctx, fixture.issuer, fixture.prefix+"-role", vault.AppRoleOptions{Mount: fixture.auth})
	if err != nil {
		t.Fatal("the blueprint AppRole could not issue bounded credentials")
	}
	issued, err := fixture.control.LoginAppRole(ctx, credentials, vault.AppRoleOptions{Mount: fixture.auth})
	if err != nil || issued.Token == "" {
		t.Fatal("the blueprint AppRole could not authenticate its application")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = fixture.admin.Auth().Token().RevokeTreeWithContext(cleanup, issued.Token)
	})
	data, err := fixture.control.Read(ctx, issued.Token, "/"+fixture.mount+"/allowed/item", vault.KVOptions{Mount: fixture.mount, Version: 2})
	if err != nil || data["value"] != "private-f07-secret-value" {
		t.Fatal("the blueprint did not grant the declared application read permission")
	}
	if _, err := fixture.control.Read(ctx, issued.Token, "/"+fixture.mount+"/denied/item", vault.KVOptions{Mount: fixture.mount, Version: 2}); !errors.Is(err, vault.ErrPermissionDenied) {
		t.Fatal("the blueprint application token gained an undeclared permission")
	}
	requireBlueprintMetadata(t, plan, fixture.issuer, credentials.RoleID, credentials.SecretID, credentials.SecretIDAccessor, issued.Token, issued.Accessor)
}

func TestIntegrationBlueprintConflictPreflightPreservesExistingResources(t *testing.T) {
	for _, mismatch := range []string{"policy", "mount version"} {
		t.Run(mismatch, func(t *testing.T) {
			fixture := prepareBlueprintIntegrationFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			oldPolicy := fmt.Sprintf(`path %q { capabilities = ["read"] }`, fixture.mount+"/data/denied/item")
			if mismatch == "policy" {
				if _, err := fixture.control.WritePolicy(ctx, fixture.issuer, fixture.prefix+"-read", oldPolicy); err != nil {
					t.Fatal("could not seed the existing policy conflict")
				}
			} else if err := fixture.admin.Sys().MountWithContext(ctx, fixture.mount, &api.MountInput{Type: "kv", Options: map[string]string{"version": "1"}}); err != nil {
				t.Fatal("could not seed the incompatible existing KV engine")
			}
			document := loadIntegrationBlueprint(t, blueprintIntegrationSource(fixture))
			backend := blueprint.NewVaultBackend(fixture.client, fixture.issuer)
			plan, err := blueprint.BuildPlan(ctx, document, backend)
			if !errors.Is(err, blueprint.ErrConflict) || len(plan.Resources) != 6 || fixture.writes.Load() != 0 {
				t.Fatal("existing incompatible resource did not block the complete plan")
			}
			report, err := blueprint.Apply(ctx, document, backend)
			if !errors.Is(err, blueprint.ErrConflict) || len(report.Items) != 6 || fixture.writes.Load() != 0 {
				t.Fatal("blueprint conflict allowed another resource to mutate")
			}
			mounts, err := fixture.admin.Sys().ListMountsWithContext(ctx)
			if err != nil {
				t.Fatal("could not verify the disposable mount catalog")
			}
			if mismatch == "policy" {
				if _, exists := mounts[fixture.mount+"/"]; exists {
					t.Fatal("policy conflict still created the planned KV engine")
				}
				policy, err := fixture.control.ReadPolicy(ctx, fixture.issuer, fixture.prefix+"-read")
				if err != nil || policy.Policy != oldPolicy {
					t.Fatal("blueprint replaced a conflicting policy")
				}
			} else {
				mount := mounts[fixture.mount+"/"]
				if mount == nil || mount.Type != "kv" || mount.Options["version"] != "1" {
					t.Fatal("blueprint migrated or replaced the existing KV engine")
				}
				if _, err := fixture.control.ReadPolicy(ctx, fixture.issuer, fixture.prefix+"-read"); !errors.Is(err, vault.ErrNotFound) {
					t.Fatal("mount conflict still created another planned policy")
				}
			}
			requireBlueprintMetadata(t, plan, fixture.issuer)
			requireBlueprintMetadata(t, report, fixture.issuer)
		})
	}
}

func TestIntegrationBlueprintDeniedReadPreflightMakesNoMutations(t *testing.T) {
	fixture := prepareBlueprintIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fresh, denied, permission := fixture.prefix+"-fresh", fixture.prefix+"-denied", fixture.prefix+"-preflight"
	policy := fmt.Sprintf(`path %q { capabilities = ["create", "read", "update"] }
path %q { capabilities = ["deny"] }`, "sys/policies/acl/"+fresh, "sys/policies/acl/"+denied)
	if err := fixture.admin.Sys().PutPolicyWithContext(ctx, permission, policy); err != nil {
		t.Fatal("could not prepare the denied blueprint preflight policy")
	}
	secret, err := fixture.admin.Auth().Token().CreateWithContext(ctx, &api.TokenCreateRequest{Policies: []string{permission}, NoDefaultPolicy: true, TTL: "1m"})
	if err != nil || secret == nil || secret.Auth == nil {
		t.Fatal("could not prepare the restricted blueprint operator")
	}
	operator := secret.Auth.ClientToken
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = fixture.admin.Auth().Token().RevokeTreeWithContext(cleanup, operator)
		_ = fixture.admin.Sys().DeletePolicyWithContext(cleanup, permission)
		_ = fixture.admin.Sys().DeletePolicyWithContext(cleanup, fresh)
	})
	source := fmt.Sprintf(`api_version: secretwright/v1
name: %s
resources:
  - id: a-create
    kind: policy
    name: %s
    spec: {policy: 'path "application/data/item" { capabilities = ["read"] }'}
  - id: z-denied
    kind: policy
    name: %s
    spec: {policy: 'path "application/data/item" { capabilities = ["read"] }'}
`, fixture.prefix, fresh, denied)
	document := loadIntegrationBlueprint(t, source)
	backend := blueprint.NewVaultBackend(fixture.client, operator)
	plan, err := blueprint.BuildPlan(ctx, document, backend)
	if !errors.Is(err, vault.ErrPermissionDenied) || len(plan.Resources) != 0 || fixture.writes.Load() != 0 {
		t.Fatal("denied read did not fail the entire blueprint preflight")
	}
	report, err := blueprint.Apply(ctx, document, backend)
	if !errors.Is(err, vault.ErrPermissionDenied) || len(report.Items) != 0 || fixture.writes.Load() != 0 {
		t.Fatal("denied blueprint preflight already changed another resource")
	}
	if _, err := fixture.control.ReadPolicy(ctx, fixture.issuer, fresh); !errors.Is(err, vault.ErrNotFound) {
		t.Fatal("denied blueprint preflight published the preceding planned policy")
	}
}
