//go:build integration

package vault_test

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
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/ml0renz0/secretwright/internal/vault"
)

type accessIntegrationFixture struct {
	kv     kvIntegrationFixture
	client *vault.Client
	issuer string
	mount  string
	policy string
	role   string
}

func prepareAccessIntegrationFixture(t *testing.T) accessIntegrationFixture {
	t.Helper()
	kv := prepareKVIntegrationFixture(t)
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatal("could not initialize the disposable access client")
	}
	prefix := fmt.Sprintf("secretwright-f06-%d", time.Now().UnixNano())
	fixture := accessIntegrationFixture{kv: kv, client: client, issuer: kv.admin.Token(), mount: prefix, policy: prefix + "-app", role: "application"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := kv.admin.Sys().EnableAuthWithOptionsWithContext(ctx, fixture.mount, &api.EnableAuthOptions{Type: "approle"}); err != nil {
		t.Fatal("could not enable the disposable AppRole auth mount")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = kv.admin.Sys().DisableAuthWithContext(cleanup, fixture.mount)
		_ = kv.admin.Sys().DeletePolicyWithContext(cleanup, fixture.policy)
	})
	policy := fmt.Sprintf(`path %q { capabilities = ["read"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/create" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "sys/capabilities-self" { capabilities = ["update"] }
`, kv.v2+"data/allowed/item")
	if _, err := client.WritePolicy(ctx, fixture.issuer, fixture.policy, policy); err != nil {
		t.Fatal("could not create the disposable application ACL policy")
	}
	_, err = client.WriteAppRole(ctx, fixture.issuer, fixture.role, vault.RoleSpec{
		TokenPolicies: []string{fixture.policy}, TokenTTL: "2m", TokenMaxTTL: "5m",
		SecretIDTTL: "2m", SecretIDNumUses: 5,
	}, vault.AppRoleOptions{Mount: fixture.mount})
	if err != nil {
		t.Fatal("could not create the bounded disposable AppRole")
	}
	return fixture
}

func requireAccessReportSafe(t *testing.T, report any, forbidden ...string) {
	t.Helper()
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal("could not encode access metadata")
	}
	for _, value := range forbidden {
		if value != "" && strings.Contains(string(encoded), value) {
			t.Fatal("access metadata exposed a credential")
		}
	}
}

func requireAccessRead(t *testing.T, ctx context.Context, fixture accessIntegrationFixture, token, key string, permitted bool) {
	t.Helper()
	data, err := fixture.client.Read(ctx, token, "/"+fixture.kv.v2+key, vault.KVOptions{Mount: fixture.kv.v2, Version: 2})
	if permitted {
		if err != nil || data["value"] != "private-kv-value-"+key {
			t.Fatal("issued credential could not read its permitted disposable value")
		}
	} else if !errors.Is(err, vault.ErrPermissionDenied) {
		t.Fatal("issued credential was not denied access outside its policy")
	}
}

func TestIntegrationAccessAppRolePermissionsAndSeparateRevocation(t *testing.T) {
	fixture := prepareAccessIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	opts := vault.AppRoleOptions{Mount: fixture.mount}
	policies, err := fixture.client.ListPolicies(ctx, fixture.issuer)
	if err != nil || !slices.Contains(policies, fixture.policy) || !slices.IsSorted(policies) {
		t.Fatal("modern ACL policy listing did not include the configured application")
	}
	policy, err := fixture.client.ReadPolicy(ctx, fixture.issuer, fixture.policy)
	if err != nil || policy.Name != fixture.policy || !strings.Contains(policy.Policy, fixture.kv.v2+"data/allowed/item") {
		t.Fatal("modern ACL policy read did not preserve the requested configuration")
	}
	roles, err := fixture.client.ListAppRoles(ctx, fixture.issuer, opts)
	if err != nil || !slices.Contains(roles, fixture.role) {
		t.Fatal("AppRole listing lost its explicit auth mount")
	}
	role, err := fixture.client.ReadAppRole(ctx, fixture.issuer, fixture.role, opts)
	if err != nil || !role.BindSecretID || !role.TokenNoDefaultPolicy || role.TokenTTLSeconds != 120 || role.SecretIDNumUses != 5 || !slices.Equal(role.TokenPolicies, []string{fixture.policy}) {
		t.Fatal("AppRole read did not retain bounded, explicit credential settings")
	}
	credentials, err := fixture.client.IssueAppRoleCredentials(ctx, fixture.issuer, fixture.role, opts)
	if err != nil || credentials.RoleID == "" || credentials.SecretID == "" || credentials.SecretIDAccessor == "" {
		t.Fatal("AppRole did not issue the private credential bundle")
	}
	roleID, err := fixture.client.ReadAppRoleID(ctx, fixture.issuer, fixture.role, opts)
	if err != nil || roleID != credentials.RoleID {
		t.Fatal("AppRole role ID export disagreed with the issued bundle")
	}
	requireAccessReportSafe(t, credentials, fixture.issuer, credentials.RoleID, credentials.SecretID, credentials.SecretIDAccessor)
	requireAccessReportSafe(t, role, fixture.issuer, credentials.RoleID, credentials.SecretID, credentials.SecretIDAccessor)

	upstream, err := url.Parse(os.Getenv("VAULT_ADDR"))
	if err != nil {
		t.Fatal("invalid disposable Vault address")
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	var sentOperator atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/"+fixture.mount+"/login" && r.Header.Get("X-Vault-Token") != "" {
			sentOperator.Store(true)
		}
		proxy.ServeHTTP(w, r)
	}))
	defer server.Close()
	address := server.URL
	loginClient, err := vault.New(vault.Options{Address: &address})
	if err != nil {
		t.Fatal("could not initialize the isolated login client")
	}
	t.Setenv("VAULT_TOKEN", "f06-deliberately-invalid-inherited-token")
	issued, err := loginClient.LoginAppRole(ctx, credentials, opts)
	if err != nil || issued.Token == "" || issued.Accessor == "" || issued.Report.TTLSeconds <= 0 || issued.Report.TTLSeconds > 120 || issued.Report.EntityID == "" {
		t.Fatal("AppRole login did not return its bounded private token")
	}
	if sentOperator.Load() || slices.Contains(issued.Report.Policies, "root") || slices.Contains(issued.Report.Policies, "default") || !slices.Contains(issued.Report.Policies, fixture.policy) {
		t.Fatal("AppRole login sent or inherited operator credentials or policies")
	}
	requireAccessReportSafe(t, issued, fixture.issuer, credentials.RoleID, credentials.SecretID, credentials.SecretIDAccessor, issued.Token, issued.Accessor)
	requireAccessRead(t, ctx, fixture, issued.Token, "allowed/item", true)
	requireAccessRead(t, ctx, fixture, issued.Token, "denied/item", false)
	paths := []string{fixture.kv.v2 + "data/allowed/item", fixture.kv.v2 + "data/denied/item"}
	capabilities, err := fixture.client.Capabilities(ctx, issued.Token, paths)
	if err != nil || len(capabilities) != 2 {
		t.Fatal("self capability query did not report both physical API paths")
	}
	for _, report := range capabilities {
		if report.Path == paths[0] && !slices.Contains(report.Capabilities, "read") {
			t.Fatal("self capabilities omitted an explicitly granted permission")
		}
		if report.Path == paths[1] && !slices.Equal(report.Capabilities, []string{"deny"}) {
			t.Fatal("self capabilities granted an unrelated physical path")
		}
	}
	if _, err := fixture.client.WritePolicy(ctx, issued.Token, "must-not-escalate", `path "*" { capabilities = ["sudo"] }`); !errors.Is(err, vault.ErrPermissionDenied) {
		t.Fatal("application credential was able to administer ACL policies")
	}
	if _, err := fixture.client.RevokeAppRoleSecretID(ctx, fixture.issuer, fixture.role, credentials.SecretIDAccessor, opts); err != nil {
		t.Fatal("could not revoke the issued SecretID by its private accessor")
	}
	if _, err := loginClient.LoginAppRole(ctx, credentials, opts); err == nil {
		t.Fatal("a destroyed SecretID still permitted a new AppRole login")
	}
	// Destroying a SecretID affects future login, not already issued tokens.
	requireAccessRead(t, ctx, fixture, issued.Token, "allowed/item", true)
	if _, err := fixture.client.RevokeToken(ctx, fixture.issuer, issued.Token); err != nil {
		t.Fatal("could not revoke the already issued application token")
	}
	requireAccessRead(t, ctx, fixture, issued.Token, "allowed/item", false)
	if _, err := fixture.client.DeleteAppRole(ctx, fixture.issuer, fixture.role, opts); err != nil {
		t.Fatal("could not delete the disposable AppRole")
	}
	if _, err := fixture.client.ReadAppRole(ctx, fixture.issuer, fixture.role, opts); !errors.Is(err, vault.ErrNotFound) {
		t.Fatal("deleted AppRole remained readable")
	}
	if _, err := fixture.client.DeletePolicy(ctx, fixture.issuer, fixture.policy); err != nil {
		t.Fatal("could not delete the disposable ACL policy")
	}
	if _, err := fixture.client.ReadPolicy(ctx, fixture.issuer, fixture.policy); !errors.Is(err, vault.ErrNotFound) {
		t.Fatal("deleted ACL policy remained readable")
	}
}

func TestIntegrationAccessTokenIssuanceAndInternalGroupPermissions(t *testing.T) {
	fixture := prepareAccessIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	minted, err := fixture.client.CreateToken(ctx, fixture.issuer, vault.TokenSpec{Policies: []string{fixture.policy}, TTL: "1m", ExplicitMaxTTL: "2m"})
	if err != nil || minted.Report.TTLSeconds <= 0 || minted.Report.TTLSeconds > 60 || !slices.Equal(minted.Report.Policies, []string{fixture.policy}) {
		t.Fatal("explicit token creation inherited issuer policies or lost its lifetime limit")
	}
	requireAccessReportSafe(t, minted, fixture.issuer, minted.Token, minted.Accessor)
	requireAccessRead(t, ctx, fixture, minted.Token, "allowed/item", true)
	requireAccessRead(t, ctx, fixture, minted.Token, "denied/item", false)
	if _, err := fixture.client.RevokeSelf(ctx, minted.Token); err != nil {
		t.Fatal("issued token could not revoke itself using its explicitly granted permission")
	}
	requireAccessRead(t, ctx, fixture, minted.Token, "allowed/item", false)

	opts := vault.AppRoleOptions{Mount: fixture.mount}
	credentials, err := fixture.client.IssueAppRoleCredentials(ctx, fixture.issuer, fixture.role, opts)
	if err != nil {
		t.Fatal("could not provision credentials for the disposable identity")
	}
	issued, err := fixture.client.LoginAppRole(ctx, credentials, opts)
	if err != nil || issued.Report.EntityID == "" {
		t.Fatal("AppRole login did not identify its automatically created entity")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = fixture.kv.admin.Auth().Token().RevokeTreeWithContext(cleanup, issued.Token)
	})
	entity, err := fixture.client.ReadEntity(ctx, fixture.issuer, issued.Report.EntityID)
	if err != nil || entity.ID != issued.Report.EntityID {
		t.Fatal("AppRole-created identity could not be inspected by entity ID")
	}
	independent, err := fixture.client.WriteEntity(ctx, fixture.issuer, "", vault.EntitySpec{Name: fixture.policy + "-entity", Policies: []string{fixture.policy}})
	if err != nil || independent.ID == "" {
		t.Fatal("could not create the explicitly configured independent entity")
	}
	entities, err := fixture.client.ListEntities(ctx, fixture.issuer)
	if err != nil || !slices.Contains(entities, independent.ID) {
		t.Fatal("entity listing omitted an explicitly created identity")
	}
	if _, err := fixture.client.WriteEntity(ctx, fixture.issuer, independent.ID, vault.EntitySpec{Name: fixture.policy + "-entity", Policies: []string{fixture.policy}, Disabled: true}); err != nil {
		t.Fatal("could not update the explicit entity ID")
	}
	updated, err := fixture.client.ReadEntity(ctx, fixture.issuer, independent.ID)
	if err != nil || !updated.Disabled || !slices.Equal(updated.Policies, []string{fixture.policy}) {
		t.Fatal("entity read lost its permitted policy or disabled projection")
	}
	if _, err := fixture.client.DeleteEntity(ctx, fixture.issuer, independent.ID); err != nil {
		t.Fatal("could not delete the explicitly selected entity")
	}
	if _, err := fixture.client.ReadEntity(ctx, fixture.issuer, independent.ID); !errors.Is(err, vault.ErrNotFound) {
		t.Fatal("deleted entity remained readable")
	}
	extraPolicy := fixture.policy + "-group"
	if _, err := fixture.client.WritePolicy(ctx, fixture.issuer, extraPolicy, fmt.Sprintf(`path %q { capabilities = ["read"] }`, fixture.kv.v2+"data/denied/item")); err != nil {
		t.Fatal("could not provision the internal group's additional ACL policy")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = fixture.kv.admin.Sys().DeletePolicyWithContext(cleanup, extraPolicy)
	})
	requireAccessRead(t, ctx, fixture, issued.Token, "denied/item", false)
	group, err := fixture.client.WriteGroup(ctx, fixture.issuer, "", vault.GroupSpec{Name: fixture.policy + "-group", Policies: []string{extraPolicy}, MemberEntityIDs: []string{issued.Report.EntityID}})
	if err != nil || group.ID == "" {
		t.Fatal("could not attach the login-created entity to an internal group")
	}
	groups, err := fixture.client.ListGroups(ctx, fixture.issuer)
	if err != nil || !slices.Contains(groups, group.ID) {
		t.Fatal("internal group listing omitted the configured membership")
	}
	readGroup, err := fixture.client.ReadGroup(ctx, fixture.issuer, group.ID)
	if err != nil || readGroup.Type != "internal" || !slices.Equal(readGroup.MemberEntityIDs, []string{issued.Report.EntityID}) || !slices.Equal(readGroup.Policies, []string{extraPolicy}) {
		t.Fatal("internal group read did not preserve its explicit members and policies")
	}
	requireAccessReportSafe(t, readGroup, fixture.issuer, credentials.RoleID, credentials.SecretID, credentials.SecretIDAccessor, issued.Token, issued.Accessor)
	// Identity policies are evaluated dynamically for an existing entity token.
	requireAccessRead(t, ctx, fixture, issued.Token, "denied/item", true)
	child, err := fixture.client.CreateToken(ctx, issued.Token, vault.TokenSpec{Policies: []string{fixture.policy}, TTL: "1m", ExplicitMaxTTL: "2m"})
	if err != nil || child.Report.EntityID != issued.Report.EntityID || !slices.Contains(child.Report.Policies, fixture.policy) || slices.Contains(child.Report.Policies, "root") {
		t.Fatal("child token did not preserve its parent entity alongside explicit token policies")
	}
	requireAccessReportSafe(t, child, fixture.issuer, credentials.RoleID, credentials.SecretID, credentials.SecretIDAccessor, issued.Token, issued.Accessor, child.Token, child.Accessor)
	// Explicit token policies do not remove inherited entity/group permissions.
	requireAccessRead(t, ctx, fixture, child.Token, "denied/item", true)
	if _, err := fixture.client.DeleteGroup(ctx, fixture.issuer, group.ID); err != nil {
		t.Fatal("could not delete the explicitly selected internal group")
	}
	requireAccessRead(t, ctx, fixture, issued.Token, "denied/item", false)
	requireAccessRead(t, ctx, fixture, child.Token, "denied/item", false)
	requireAccessRead(t, ctx, fixture, issued.Token, "allowed/item", true)
}

func cleanupAccessIntegrationToken(t *testing.T, fixture accessIntegrationFixture, token string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = fixture.client.RevokeToken(ctx, fixture.issuer, token)
	})
}

func TestIntegrationAccessSecretIDUseLimitDoesNotRevokeItsIssuedToken(t *testing.T) {
	fixture := prepareAccessIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	opts := vault.AppRoleOptions{Mount: fixture.mount}
	_, err := fixture.client.WriteAppRole(ctx, fixture.issuer, fixture.role, vault.RoleSpec{
		TokenPolicies: []string{fixture.policy}, TokenTTL: "1m", TokenMaxTTL: "2m",
		SecretIDTTL: "1m", SecretIDNumUses: 1,
	}, opts)
	if err != nil {
		t.Fatal("could not configure the disposable single-use SecretID")
	}
	credentials, err := fixture.client.IssueAppRoleCredentials(ctx, fixture.issuer, fixture.role, opts)
	if err != nil {
		t.Fatal("could not issue the disposable single-use SecretID")
	}
	issued, err := fixture.client.LoginAppRole(ctx, credentials, opts)
	if err != nil || issued.Token == "" {
		t.Fatal("single-use SecretID did not permit its first login")
	}
	cleanupAccessIntegrationToken(t, fixture, issued.Token)
	second, err := fixture.client.LoginAppRole(ctx, credentials, opts)
	if err == nil || second.Token != "" {
		t.Fatal("exhausted SecretID permitted another login")
	}
	requireAccessReportSafe(t, err.Error(), fixture.issuer, credentials.RoleID, credentials.SecretID, credentials.SecretIDAccessor, issued.Token)
	requireAccessReportSafe(t, second, fixture.issuer, credentials.RoleID, credentials.SecretID, credentials.SecretIDAccessor, issued.Token)
	// Consuming the final login use is independent of the issued token's lifetime.
	requireAccessRead(t, ctx, fixture, issued.Token, "allowed/item", true)
}

func TestIntegrationAccessTokenUseLimitIsNotConsumedByClientBookkeeping(t *testing.T) {
	fixture := prepareAccessIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	issued, err := fixture.client.CreateToken(ctx, fixture.issuer, vault.TokenSpec{
		Policies: []string{fixture.policy}, TTL: "1m", ExplicitMaxTTL: "2m", NumUses: 1,
	})
	if err != nil || issued.Token == "" {
		t.Fatal("could not create the disposable single-use token")
	}
	cleanupAccessIntegrationToken(t, fixture, issued.Token)
	// An implicit lookup-self or mount discovery would spend this sole use before
	// the caller's explicit read. The mount and version are supplied by the helper.
	requireAccessRead(t, ctx, fixture, issued.Token, "allowed/item", true)
	requireAccessRead(t, ctx, fixture, issued.Token, "allowed/item", false)
	requireAccessReportSafe(t, issued, fixture.issuer, issued.Token, issued.Accessor)
}

func TestIntegrationAccessRevokingParentRevokesDescendantsButNotSiblingTokens(t *testing.T) {
	fixture := prepareAccessIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	spec := vault.TokenSpec{Policies: []string{fixture.policy}, TTL: "1m", ExplicitMaxTTL: "2m"}
	parent, err := fixture.client.CreateToken(ctx, fixture.issuer, spec)
	if err != nil || parent.Token == "" {
		t.Fatal("could not create the disposable parent token")
	}
	cleanupAccessIntegrationToken(t, fixture, parent.Token)
	child, err := fixture.client.CreateToken(ctx, parent.Token, spec)
	if err != nil || child.Token == "" {
		t.Fatal("could not create the disposable child token")
	}
	cleanupAccessIntegrationToken(t, fixture, child.Token)
	sibling, err := fixture.client.CreateToken(ctx, fixture.issuer, spec)
	if err != nil || sibling.Token == "" {
		t.Fatal("could not create the independent disposable token")
	}
	cleanupAccessIntegrationToken(t, fixture, sibling.Token)
	for _, token := range []string{parent.Token, child.Token, sibling.Token} {
		requireAccessRead(t, ctx, fixture, token, "allowed/item", true)
	}
	if _, err := fixture.client.RevokeToken(ctx, fixture.issuer, parent.Token); err != nil {
		t.Fatal("could not revoke the disposable parent token")
	}
	requireAccessRead(t, ctx, fixture, parent.Token, "allowed/item", false)
	requireAccessRead(t, ctx, fixture, child.Token, "allowed/item", false)
	requireAccessRead(t, ctx, fixture, sibling.Token, "allowed/item", true)
}

func TestIntegrationAccessPolicyChangesAffectAlreadyIssuedTokens(t *testing.T) {
	fixture := prepareAccessIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	issued, err := fixture.client.CreateToken(ctx, fixture.issuer, vault.TokenSpec{
		Policies: []string{fixture.policy}, TTL: "1m", ExplicitMaxTTL: "2m",
	})
	if err != nil || issued.Token == "" {
		t.Fatal("could not create the disposable policy-bound token")
	}
	cleanupAccessIntegrationToken(t, fixture, issued.Token)
	requireAccessRead(t, ctx, fixture, issued.Token, "allowed/item", true)
	requireAccessRead(t, ctx, fixture, issued.Token, "denied/item", false)
	updated := fmt.Sprintf(`path %q { capabilities = ["read"] }`, fixture.kv.v2+"data/denied/item")
	if _, err := fixture.client.WritePolicy(ctx, fixture.issuer, fixture.policy, updated); err != nil {
		t.Fatal("could not replace the disposable token's ACL policy")
	}
	// ACL bodies are evaluated for each request, rather than captured when the
	// token is minted. Removing a grant must take effect without another login.
	requireAccessRead(t, ctx, fixture, issued.Token, "allowed/item", false)
	requireAccessRead(t, ctx, fixture, issued.Token, "denied/item", true)
	if _, err := fixture.client.DeletePolicy(ctx, fixture.issuer, fixture.policy); err != nil {
		t.Fatal("could not remove the disposable token's ACL policy")
	}
	requireAccessRead(t, ctx, fixture, issued.Token, "allowed/item", false)
	requireAccessRead(t, ctx, fixture, issued.Token, "denied/item", false)
}
