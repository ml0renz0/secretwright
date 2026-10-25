//go:build integration

package architecture_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"path"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/ml0renz0/secretwright/internal/architecture"
	"github.com/ml0renz0/secretwright/internal/blueprint"
	"github.com/ml0renz0/secretwright/internal/vault"
)

type architectureFixture struct {
	admin                               *api.Client
	control, observed                   *vault.Client
	issuer, name, mount, auth, accessor string
	writes                              atomic.Int32
}

func newArchitectureFixture(t *testing.T) *architectureFixture {
	t.Helper()
	address, file := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TEST_ROOT_TOKEN_FILE")
	if address == "" || file == "" {
		t.Fatal("run make integration-local with its disposable Vault fixture")
	}
	credential, err := os.ReadFile(file)
	if err != nil || len(credential) == 0 {
		t.Fatal("could not read the disposable architecture administrator")
	}
	config := api.DefaultConfig()
	config.Address, config.MaxRetries, config.Timeout, config.DisableRedirects = address, 0, 5*time.Second, true
	admin, err := api.NewClient(config)
	if err != nil {
		t.Fatal("could not initialize the architecture fixture administrator")
	}
	admin.SetToken(strings.TrimSpace(string(credential)))
	control, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatal("could not initialize the architecture fixture control client")
	}
	name := fmt.Sprintf("f08-%d", time.Now().UnixNano())
	fixture := &architectureFixture{admin: admin, control: control, issuer: admin.Token(), name: name, mount: name + "-kv", auth: name + "-auth"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := admin.Sys().EnableAuthWithOptionsWithContext(ctx, fixture.auth, &api.EnableAuthOptions{Type: "approle"}); err != nil {
		t.Fatal("could not enable the prerequisite disposable authentication mount")
	}
	auth, err := admin.Sys().ListAuthWithContext(ctx)
	if err != nil || auth[fixture.auth+"/"] == nil || auth[fixture.auth+"/"].Accessor == "" {
		t.Fatal("could not inspect the disposable authentication mount accessor")
	}
	fixture.accessor = auth[fixture.auth+"/"].Accessor
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
	fixture.observed, err = vault.New(vault.Options{Address: &proxyAddress})
	if err != nil {
		server.Close()
		t.Fatal("could not create the architecture mutation counter")
	}
	t.Cleanup(func() {
		server.Close()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = admin.Sys().DisableAuthWithContext(cleanup, fixture.auth)
		_ = admin.Sys().UnmountWithContext(cleanup, fixture.mount)
	})
	return fixture
}

type architectureScope struct {
	path, access string
	user         bool
}

func architectureDigest(scope string) string {
	digest := sha256.Sum256([]byte(scope))
	return hex.EncodeToString(digest[:8])
}

func requireArchitectureSafe(t *testing.T, value any, forbidden ...string) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("could not encode architecture execution metadata")
	}
	for _, marker := range append([]string{"private-f08-secret"}, forbidden...) {
		if marker != "" && strings.Contains(string(body), marker) {
			t.Fatal("architecture execution metadata exposed a credential or secret value")
		}
	}
}

func renderArchitectureFixture(t *testing.T, fixture *architectureFixture, instances []map[string]any) (blueprint.Document, []byte) {
	t.Helper()
	for _, instance := range instances {
		instance["mount"] = fixture.mount
		if instance["template"] != "single-user" && instance["template"] != "multi-user" {
			instance["auth_mount"] = fixture.auth
		}
	}
	input, err := json.Marshal(map[string]any{"api_version": "secretwright/architecture/v1", "name": fixture.name, "instances": instances})
	if err != nil {
		t.Fatal("could not prepare the architecture fixture manifest")
	}
	output, err := architecture.Render(bytes.NewReader(input))
	if err != nil {
		t.Fatal("could not render a supported architecture fixture")
	}
	document, err := blueprint.Load(bytes.NewReader(output), nil)
	if err != nil {
		t.Fatal("architecture output was not an executable F07 blueprint")
	}
	return document, output
}

func applyArchitectureTwice(t *testing.T, ctx context.Context, fixture *architectureFixture, document blueprint.Document) map[string]string {
	t.Helper()
	backend := blueprint.NewVaultBackend(fixture.observed, fixture.issuer)
	plan, err := blueprint.BuildPlan(ctx, document, backend)
	if err != nil || len(plan.Changes) != len(document.Resources) || fixture.writes.Load() != 0 {
		t.Fatal("architecture planning failed or mutated the disposable Vault")
	}
	for _, item := range plan.Changes {
		if item.Action != "create" {
			t.Fatal("a fresh architecture planned an action other than creation")
		}
	}
	report, err := blueprint.Apply(ctx, document, backend)
	if err != nil || len(report.Items) != len(document.Resources) || fixture.writes.Load() != int32(len(document.Resources)) {
		t.Fatal("architecture application did not create exactly its declared resources")
	}
	ids := make(map[string]string)
	for _, item := range report.Items {
		if item.Status != "created" {
			t.Fatal("architecture application did not confirm every creation")
		}
		ids[item.ID] = item.RemoteID
	}
	plan, err = blueprint.BuildPlan(ctx, document, backend)
	if err != nil || len(plan.Changes) != 0 || fixture.writes.Load() != int32(len(document.Resources)) {
		t.Fatal("an applied architecture did not produce an empty plan without writes")
	}
	again, err := blueprint.Apply(ctx, document, backend)
	if err != nil || len(again.Items) != len(document.Resources) || fixture.writes.Load() != int32(len(document.Resources)) {
		t.Fatal("a second architecture application repeated a mutation")
	}
	for _, item := range again.Items {
		if item.Status != "unchanged" || item.RemoteID != ids[item.ID] {
			t.Fatal("repeated architecture application changed resource identity or status")
		}
	}
	requireArchitectureSafe(t, plan, fixture.issuer)
	requireArchitectureSafe(t, report, fixture.issuer)
	requireArchitectureSafe(t, again, fixture.issuer)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		for index := len(document.Order) - 1; index >= 0; index-- {
			id := document.Order[index]
			for _, resource := range document.Resources {
				if resource.ID != id {
					continue
				}
				switch resource.Kind {
				case "entity":
					_, _ = fixture.control.DeleteEntity(cleanup, fixture.issuer, ids[id])
				case "group":
					_, _ = fixture.control.DeleteGroup(cleanup, fixture.issuer, ids[id])
				case "policy":
					_ = fixture.admin.Sys().DeletePolicyWithContext(cleanup, resource.Name)
				}
			}
		}
	})
	return ids
}

func architectureToken(t *testing.T, ctx context.Context, fixture *architectureFixture, document blueprint.Document, ids map[string]string, scope architectureScope) string {
	t.Helper()
	digest := architectureDigest(scope.path)
	role := ""
	for _, resource := range document.Resources {
		if resource.ID == "role_"+digest {
			role = resource.Name
		}
	}
	if scope.user {
		// Human authentication bindings are explicitly outside F08. The fixture
		// connects an otherwise unprivileged AppRole to the generated identity so
		// the following reads exercise its generated group's effective policies.
		baseline := fixture.name + "-login"
		if _, err := fixture.control.WritePolicy(ctx, fixture.issuer, baseline, `path "auth/token/lookup-self" { capabilities = ["read"] }`); err != nil {
			t.Fatal("could not prepare the fixture-only login policy")
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			_ = fixture.admin.Sys().DeletePolicyWithContext(cleanup, baseline)
		})
		role = fixture.name + "-user-" + digest
		if _, err := fixture.control.WriteAppRole(ctx, fixture.issuer, role, vault.RoleSpec{
			TokenPolicies: []string{baseline}, TokenTTL: "1m", TokenMaxTTL: "5m", SecretIDTTL: "1m", SecretIDNumUses: 1,
		}, vault.AppRoleOptions{Mount: fixture.auth}); err != nil {
			t.Fatal("could not prepare the fixture-only identity login")
		}
	}
	if role == "" {
		t.Fatal("architecture omitted its declared application role")
	}
	credentials, err := fixture.control.IssueAppRoleCredentials(ctx, fixture.issuer, role, vault.AppRoleOptions{Mount: fixture.auth})
	if err != nil {
		t.Fatal("could not issue credentials for the rendered architecture")
	}
	if scope.user {
		entity := ids["entity_"+digest]
		if entity == "" {
			t.Fatal("architecture omitted the declared user identity")
		}
		if _, err := fixture.admin.Logical().WriteWithContext(ctx, "identity/entity-alias", map[string]any{
			"name": credentials.RoleID, "canonical_id": entity, "mount_accessor": fixture.accessor,
		}); err != nil {
			t.Fatal("could not prepare the external fixture-only identity binding")
		}
		group, err := fixture.control.ReadGroup(ctx, fixture.issuer, ids["group_"+digest])
		if err != nil || !slices.Equal(group.MemberEntityIDs, []string{entity}) || len(group.Policies) != 1 {
			t.Fatal("generated user group did not reference its actual identity UUID")
		}
	}
	issued, err := fixture.control.LoginAppRole(ctx, credentials, vault.AppRoleOptions{Mount: fixture.auth})
	if err != nil || issued.Token == "" || (scope.user && issued.Report.EntityID != ids["entity_"+digest]) {
		t.Fatal("architecture login failed or resolved a different user identity")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = fixture.admin.Auth().Token().RevokeTreeWithContext(cleanup, issued.Token)
	})
	requireArchitectureSafe(t, issued, fixture.issuer, credentials.RoleID, credentials.SecretID, credentials.SecretIDAccessor, issued.Token, issued.Accessor)
	return issued.Token
}

func requireArchitecturePermissions(t *testing.T, ctx context.Context, fixture *architectureFixture, document blueprint.Document, ids map[string]string, scopes []architectureScope) {
	t.Helper()
	opts := vault.KVOptions{Mount: fixture.mount, Version: 2}
	for _, scope := range scopes {
		for _, key := range []string{scope.path, scope.path + "/item", scope.path + "-extra/item"} {
			if _, err := fixture.control.Put(ctx, fixture.issuer, "/"+fixture.mount+"/"+key, map[string]any{"value": "private-f08-secret"}, vault.WriteOptions{KVOptions: opts}); err != nil {
				t.Fatal("could not seed data outside the rendered blueprint")
			}
		}
	}
	for _, scope := range scopes {
		token := architectureToken(t, ctx, fixture, document, ids, scope)
		for _, key := range []string{scope.path, scope.path + "/item"} {
			value, err := fixture.control.Read(ctx, token, "/"+fixture.mount+"/"+key, opts)
			if err != nil || value["value"] != "private-f08-secret" {
				t.Fatal("generated scope did not grant its own declared read permission")
			}
		}
		children, err := fixture.control.List(ctx, token, "/"+fixture.mount+"/"+scope.path, opts)
		if err != nil || !slices.Contains(children, "item") {
			t.Fatal("generated scope did not grant listing within its own boundary")
		}
		if _, err := fixture.control.List(ctx, token, "/"+fixture.mount+"/"+path.Dir(scope.path), opts); !errors.Is(err, vault.ErrPermissionDenied) {
			t.Fatal("generated scope leaked ancestor listings")
		}
		for _, other := range append(append([]architectureScope(nil), scopes...), architectureScope{path: scope.path + "-extra"}) {
			if other.path == scope.path {
				continue
			}
			if _, err := fixture.control.Read(ctx, token, "/"+fixture.mount+"/"+other.path+"/item", opts); !errors.Is(err, vault.ErrPermissionDenied) {
				t.Fatal("generated scope gained access across a user, app, environment or tenant boundary")
			}
		}
		created := "/" + fixture.mount + "/" + scope.path + "/created"
		_, err = fixture.control.Put(ctx, token, created, map[string]any{"value": "private-f08-secret"}, vault.WriteOptions{KVOptions: opts})
		if scope.access == "read" {
			if !errors.Is(err, vault.ErrPermissionDenied) {
				t.Fatal("read-only architecture unexpectedly granted a write")
			}
		} else {
			if err != nil {
				t.Fatal("read-write architecture denied creation in its own scope")
			}
			cas := 1
			if _, err := fixture.control.Put(ctx, token, created, map[string]any{"value": "private-f08-secret-updated"}, vault.WriteOptions{KVOptions: opts, CAS: &cas}); err != nil {
				t.Fatal("read-write architecture denied a CAS update in its own scope")
			}
			if _, err := fixture.control.Remove(ctx, token, created, nil, vault.WriteOptions{KVOptions: opts}); err != nil {
				t.Fatal("read-write architecture denied soft deletion in its own scope")
			}
		}
		if _, err := fixture.control.Destroy(ctx, token, "/"+fixture.mount+"/"+scope.path+"/item", []int{1}, vault.WriteOptions{KVOptions: opts, Force: true}); !errors.Is(err, vault.ErrPermissionDenied) {
			t.Fatal("architecture granted destructive history administration")
		}
	}
}

func TestIntegrationArchitectureCatalogPatternsPreserveScopedAccessAndIdempotence(t *testing.T) {
	for _, pattern := range []string{"single-user", "multi-user", "single-app", "multi-app", "multi-env", "saas", "composition"} {
		t.Run(pattern, func(t *testing.T) {
			fixture := newArchitectureFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			instance := map[string]any{"id": "main", "template": pattern, "access": "read"}
			instances := []map[string]any{instance}
			var scopes []architectureScope
			add := func(id, suffix, access string, user bool) {
				scopes = append(scopes, architectureScope{path: fixture.name + "/" + id + "/" + suffix, access: access, user: user})
			}
			switch pattern {
			case "single-user", "multi-user":
				users := []string{"alice"}
				if pattern == "multi-user" {
					users = append(users, "bob")
					instance["access"] = "read-write"
				}
				instance["users"] = users
				for _, user := range users {
					add("main", "users/"+user, instance["access"].(string), true)
				}
			case "single-app", "multi-app":
				apps := []string{"api"}
				if pattern == "multi-app" {
					apps = append(apps, "worker")
					instance["access"] = "read-write"
				}
				instance["applications"] = apps
				for _, app := range apps {
					add("main", "apps/"+app, instance["access"].(string), false)
				}
			case "multi-env":
				instance["applications"], instance["environments"] = []string{"api", "worker"}, []string{"dev", "prod"}
				for _, env := range []string{"dev", "prod"} {
					for _, app := range []string{"api", "worker"} {
						add("main", "envs/"+env+"/apps/"+app, "read", false)
					}
				}
			case "saas":
				instance["tenants"], instance["environments"], instance["applications"], instance["access"] = []string{"acme", "acme-extra"}, []string{"dev", "prod"}, []string{"api", "worker"}, "read-write"
				for _, tenant := range []string{"acme", "acme-extra"} {
					for _, env := range []string{"dev", "prod"} {
						for _, app := range []string{"api", "worker"} {
							add("main", "tenants/"+tenant+"/envs/"+env+"/apps/"+app, "read-write", false)
						}
					}
				}
			case "composition":
				instances = []map[string]any{
					{"id": "people", "template": "multi-user", "users": []string{"alice", "bob"}, "access": "read"},
					{"id": "services", "template": "multi-app", "applications": []string{"api", "worker"}, "access": "read-write"},
				}
				for _, user := range []string{"alice", "bob"} {
					add("people", "users/"+user, "read", true)
				}
				for _, app := range []string{"api", "worker"} {
					add("services", "apps/"+app, "read-write", false)
				}
			}
			document, output := renderArchitectureFixture(t, fixture, instances)
			mounts := 0
			for _, resource := range document.Resources {
				if resource.Kind == "kv_mount" {
					mounts++
				}
			}
			if mounts != 1 || strings.Contains(string(output), fixture.issuer) {
				t.Fatal("composed architecture duplicated its shared mount or included a credential")
			}
			ids := applyArchitectureTwice(t, ctx, fixture, document)
			requireArchitecturePermissions(t, ctx, fixture, document, ids, scopes)
		})
	}
}
