//go:build integration

package lifecycle_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/ml0renz0/secretwright/internal/lifecycle"
	"github.com/ml0renz0/secretwright/internal/vault"
)

type lifecycleIntegrationFixture struct {
	admin    *api.Client
	client   *vault.Client
	operator string
	auth     string
	mount    string
	policy   string
	role     string
	consumer string
	old      string
	spec     lifecycle.Spec
}

func lifecycleIntegrationClients(t *testing.T) (*api.Client, *vault.Client, string) {
	t.Helper()
	if os.Getenv("VAULT_ADDR") == "" || os.Getenv("VAULT_TEST_ROOT_TOKEN_FILE") == "" {
		t.Skip("disposable Vault fixture is required; run make integration-local")
	}
	body, err := os.ReadFile(os.Getenv("VAULT_TEST_ROOT_TOKEN_FILE"))
	if err != nil {
		t.Fatal("could not read the private disposable operator credential")
	}
	config := api.DefaultConfig()
	config.Address = os.Getenv("VAULT_ADDR")
	config.MaxRetries = 0
	admin, err := api.NewClient(config)
	if err != nil {
		t.Fatal("could not create the disposable administrative client")
	}
	operator := strings.TrimSpace(string(body))
	admin.SetToken(operator)
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatal("could not create the disposable lifecycle client")
	}
	return admin, client, operator
}

func prepareLifecycleIntegrationFixture(t *testing.T) lifecycleIntegrationFixture {
	t.Helper()
	admin, client, operator := lifecycleIntegrationClients(t)
	prefix := fmt.Sprintf("secretwright-f10-%d", time.Now().UnixNano())
	f := lifecycleIntegrationFixture{admin: admin, client: client, operator: operator, auth: prefix + "-auth", mount: prefix + "-kv", policy: prefix + "-read", role: "application", consumer: filepath.Join(t.TempDir(), "consumer.token")}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := admin.Sys().EnableAuthWithOptionsWithContext(ctx, f.auth, &api.EnableAuthOptions{Type: "approle"}); err != nil {
		t.Fatal("could not mount the disposable lifecycle AppRole provider")
	}
	if err := admin.Sys().MountWithContext(ctx, f.mount, &api.MountInput{Type: "kv", Options: map[string]string{"version": "2"}}); err != nil {
		t.Fatal("could not mount the disposable lifecycle probe engine")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = admin.Sys().DisableAuthWithContext(cleanup, f.auth)
		_ = admin.Sys().UnmountWithContext(cleanup, f.mount)
		_ = admin.Sys().DeletePolicyWithContext(cleanup, f.policy)
	})
	policy := fmt.Sprintf(`path %q { capabilities = ["read"] }`, f.mount+"/data/health")
	if err := admin.Sys().PutPolicyWithContext(ctx, f.policy, policy); err != nil {
		t.Fatal("could not install the disposable lifecycle probe policy")
	}
	if _, err := admin.Logical().WriteWithContext(ctx, f.mount+"/data/health", map[string]any{"data": map[string]any{"value": "private-f10-probe-value"}}); err != nil {
		t.Fatal("could not seed the disposable lifecycle probe")
	}
	role := vault.RoleSpec{TokenPolicies: []string{f.policy}, TokenTTL: "1m", TokenMaxTTL: "5m", SecretIDTTL: "2m", SecretIDNumUses: 5}
	if _, err := client.WriteAppRole(ctx, operator, f.role, role, vault.AppRoleOptions{Mount: f.auth}); err != nil {
		t.Fatal("could not create the disposable short-lived AppRole")
	}
	credentials, err := client.IssueAppRoleCredentials(ctx, operator, f.role, vault.AppRoleOptions{Mount: f.auth})
	if err != nil {
		t.Fatal("could not issue the bootstrap lifecycle credentials")
	}
	issued, err := client.LoginAppRole(ctx, credentials, vault.AppRoleOptions{Mount: f.auth})
	if err != nil || issued.Token == "" {
		t.Fatal("could not authenticate the bootstrap lifecycle consumer")
	}
	f.old = issued.Token
	if err := os.WriteFile(f.consumer, []byte(f.old+"\n"), 0o600); err != nil {
		t.Fatal("could not prepare the private lifecycle consumer file")
	}
	// The old token remains below the threshold while newly issued tokens meet
	// the minimum. This tests the decision without sleeps or clock manipulation.
	role.TokenTTL = "2m"
	if _, err := client.WriteAppRole(ctx, operator, f.role, role, vault.AppRoleOptions{Mount: f.auth}); err != nil {
		t.Fatal("could not extend the disposable role's future token TTL")
	}
	f.spec = lifecycle.Spec{APIVersion: "secretwright/lifecycle/v1", Name: "application", Provider: lifecycle.ProviderSpec{Kind: "approle", AuthMount: f.auth, Role: f.role}, Consumer: lifecycle.ConsumerSpec{Kind: "token-file", Path: f.consumer}, Verify: lifecycle.VerifySpec{Kind: "kv-read", Mount: f.mount, KVVersion: 2, Path: "/" + f.mount + "/health"}, Policy: lifecycle.PolicySpec{RotateBelow: "90s", MinimumNewTTL: "90s"}}
	return f
}

func lifecycleRequireRead(t *testing.T, ctx context.Context, f lifecycleIntegrationFixture, token string, permitted bool) {
	t.Helper()
	data, err := f.client.Read(ctx, token, "/"+f.mount+"/health", vault.KVOptions{Mount: f.mount, Version: 2})
	if permitted && (err != nil || data["value"] != "private-f10-probe-value") {
		t.Fatal("the live lifecycle credential could not read its configured probe")
	}
	if !permitted && !errors.Is(err, vault.ErrPermissionDenied) {
		t.Fatal("the retired lifecycle credential retained effective probe access")
	}
}

func lifecycleRequireMetadataPrivate(t *testing.T, value any, forbidden ...string) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("could not inspect lifecycle metadata")
	}
	for _, secret := range append(forbidden, "private-f10-probe-value") {
		if secret != "" && bytes.Contains(body, []byte(secret)) {
			t.Fatal("lifecycle metadata exposed private credentials or probe contents")
		}
	}
}

func TestIntegrationLifecyclePublishesVerifiedTokenAndRetiresOnlyAfterAck(t *testing.T) {
	f := prepareLifecycleIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	receipt := filepath.Join(t.TempDir(), "rotation.yaml")
	backend := lifecycle.NewVaultBackend(f.client, f.operator)
	readonly, err := lifecycle.Open(f.spec, receipt, "", false)
	if err != nil {
		t.Fatal("could not inspect an unstarted private rotation")
	}
	dry, err := lifecycle.Rotate(ctx, f.spec, readonly, backend, true)
	_ = readonly.Close()
	if err != nil || dry.Status != "would_rotate" || !dry.Due {
		t.Fatal("the real short-lived consumer did not produce a due dry run")
	}
	for _, path := range []string{receipt, receipt + ".lock", receipt + ".d"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("read-only rotation created a receipt, lock or credential artifacts")
		}
	}
	store, err := lifecycle.Open(f.spec, receipt, "", true)
	if err != nil {
		t.Fatal("could not open the private lifecycle receipt")
	}
	defer store.Close()
	report, err := lifecycle.Rotate(ctx, f.spec, store, backend, false)
	if err != nil || report.Phase != "published" || report.Status != "awaiting_consumer_ack" {
		t.Fatal("rotation did not publish a verified real AppRole token")
	}
	consumer, err := lifecycle.ReadPrivate(f.consumer)
	if err != nil || consumer.Token == f.old || consumer.Token == "" {
		t.Fatal("rotation did not replace the private consumer credential")
	}
	lifecycleRequireRead(t, ctx, f, consumer.Token, true)
	lifecycleRequireRead(t, ctx, f, f.old, true)
	lifecycleRequireMetadataPrivate(t, report, f.operator, f.old, consumer.Token)
	lifecycleRequireMetadataPrivate(t, store.Snapshot(), f.operator, f.old, consumer.Token)
	before := store.Snapshot()
	repeated, err := lifecycle.Rotate(ctx, f.spec, store, backend, false)
	if err != nil || repeated.Status != "awaiting_consumer_ack" || store.Snapshot().Revision != before.Revision {
		t.Fatal("a published rotation replayed issuance or changed its durable checkpoint")
	}
	if _, err := lifecycle.Retire(ctx, f.spec, store, backend, false); err == nil || store.Snapshot().Revision != before.Revision {
		t.Fatal("retirement without consumer acknowledgement changed the rotation")
	}
	lifecycleRequireRead(t, ctx, f, f.old, true)
	retired, err := lifecycle.Retire(ctx, f.spec, store, backend, true)
	if err != nil || retired.Phase != "retired" || store.Snapshot().Phase != "retired" {
		t.Fatal("acknowledged rotation did not confirm old-token retirement")
	}
	lifecycleRequireRead(t, ctx, f, consumer.Token, true)
	lifecycleRequireRead(t, ctx, f, f.old, false)
	old, err := f.client.InspectLifecycleToken(ctx, f.operator, f.old)
	if err != nil || old.Exists {
		t.Fatal("the acknowledged old token was not actually revoked in Vault")
	}
	info, err := os.Stat(f.consumer)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("rotation weakened consumer file permissions")
	}
}

func TestIntegrationLifecycleFailedNewProbeLeavesOldConsumerUsable(t *testing.T) {
	f := prepareLifecycleIntegrationFixture(t)
	f.spec.Verify.Path = "/" + f.mount + "/denied"
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	before, err := os.ReadFile(f.consumer)
	if err != nil {
		t.Fatal("could not snapshot the private consumer")
	}
	receipt := filepath.Join(t.TempDir(), "failed-probe.yaml")
	store, err := lifecycle.Open(f.spec, receipt, "", true)
	if err != nil {
		t.Fatal("could not open the failed-probe rotation")
	}
	defer store.Close()
	if _, err := lifecycle.Rotate(ctx, f.spec, store, lifecycle.NewVaultBackend(f.client, f.operator), false); err == nil {
		t.Fatal("a denied new-token probe permitted publication")
	}
	after, err := os.ReadFile(f.consumer)
	if err != nil || !bytes.Equal(before, after) || store.Snapshot().Phase == "published" || store.Snapshot().Phase == "retired" {
		t.Fatal("failed new-token verification changed or retired the old consumer")
	}
	lifecycleRequireRead(t, ctx, f, f.old, true)
	lifecycleRequireMetadataPrivate(t, store.Snapshot(), f.old, f.operator)
}

func TestIntegrationLifecycleRenewReportsActualServiceTokenTTL(t *testing.T) {
	f := prepareLifecycleIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	before, err := f.client.InspectLifecycleToken(ctx, f.operator, f.old)
	if err != nil || !before.Exists || !before.Renewable || before.TTLSeconds <= 0 || before.TTLSeconds > 60 {
		t.Fatal("real lifecycle token lookup returned incorrect bounded metadata")
	}
	renewed, err := f.client.RenewLifecycleToken(ctx, f.operator, f.old, 240)
	if err != nil || !renewed.Exists || renewed.TTLSeconds <= 0 || renewed.TTLSeconds > 240 {
		t.Fatal("real lifecycle token renewal did not report its actual finite TTL")
	}
	lifecycleRequireMetadataPrivate(t, renewed, f.operator, f.old)
	lifecycleRequireRead(t, ctx, f, f.old, true)
}

func lifecycleRequireDatabaseLogin(t *testing.T, ctx context.Context, username, password string, permitted bool) {
	t.Helper()
	// Credentials travel only in environment variables. Neither psql arguments
	// nor a failed subprocess diagnostic can publish a generated credential.
	command := exec.CommandContext(ctx, "docker", "exec", "--env", "PGUSER", "--env", "PGPASSWORD", "--env", "PGDATABASE", "--env", "PGHOST", "--env", "PGCONNECT_TIMEOUT", os.Getenv("VAULT_TEST_DATABASE_CONTAINER"), "psql", "--no-psqlrc", "--no-password", "--tuples-only", "--no-align", "--command", "SELECT 1")
	command.Env = append(os.Environ(), "PGUSER="+username, "PGPASSWORD="+password, "PGDATABASE=secretwright", "PGHOST=127.0.0.1", "PGCONNECT_TIMEOUT=3")
	body, err := command.Output()
	if permitted && (err != nil || strings.TrimSpace(string(body)) != "1") {
		t.Fatal("the live disposable database credential could not authenticate")
	}
	if !permitted && err == nil {
		t.Fatal("the revoked disposable database credential could still authenticate")
	}
}

func TestIntegrationLifecyclePostgresLeaseRenewalAndExactRevocation(t *testing.T) {
	admin, client, operator := lifecycleIntegrationClients(t)
	if os.Getenv("VAULT_TEST_DATABASE_CONTAINER") == "" {
		if os.Getenv("VAULT_TEST_REQUIRE_DATABASE") == "1" {
			t.Fatal("required disposable PostgreSQL fixture is missing")
		}
		t.Skip("Docker PostgreSQL fixture unavailable; database lease coverage requires Docker")
	}
	password, err := os.ReadFile(os.Getenv("VAULT_TEST_DATABASE_PASSWORD_FILE"))
	if err != nil || len(password) == 0 || os.Getenv("VAULT_TEST_DATABASE_ADDRESS") == "" {
		t.Fatal("the private disposable PostgreSQL fixture is incomplete")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	mount := fmt.Sprintf("secretwright-f10-db-%d", time.Now().UnixNano())
	if err := admin.Sys().MountWithContext(ctx, mount, &api.MountInput{Type: "database"}); err != nil {
		t.Fatal("could not mount the disposable database engine")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = admin.Sys().UnmountWithContext(cleanup, mount)
	})
	connection := "postgresql://{{username}}:{{password}}@" + os.Getenv("VAULT_TEST_DATABASE_ADDRESS") + "/secretwright?sslmode=disable"
	if _, err := admin.Logical().WriteWithContext(ctx, mount+"/config/fixture", map[string]any{"plugin_name": "postgresql-database-plugin", "allowed_roles": []string{"application"}, "connection_url": connection, "username": "secretwright_fixture", "password": strings.TrimSpace(string(password))}); err != nil {
		t.Fatal("could not configure the disposable PostgreSQL plugin connection")
	}
	statement := `CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT CONNECT ON DATABASE secretwright TO "{{name}}";`
	if _, err := admin.Logical().WriteWithContext(ctx, mount+"/roles/application", map[string]any{"db_name": "fixture", "creation_statements": []string{statement}, "default_ttl": "2m", "max_ttl": "10m"}); err != nil {
		t.Fatal("could not configure the disposable renewable database role")
	}
	issued, err := admin.Logical().ReadWithContext(ctx, mount+"/creds/application")
	if err != nil || issued == nil || issued.LeaseID == "" || !issued.Renewable {
		t.Fatal("the disposable database plugin did not issue a renewable lease")
	}
	username, userOK := issued.Data["username"].(string)
	credential, passwordOK := issued.Data["password"].(string)
	if !userOK || !passwordOK || username == "" || credential == "" {
		t.Fatal("the disposable database plugin omitted its private credentials")
	}
	lifecycleRequireDatabaseLogin(t, ctx, username, credential, true)
	before, err := client.InspectLifecycleLease(ctx, operator, issued.LeaseID)
	if err != nil || !before.Exists || !before.Renewable || before.TTLSeconds <= 0 {
		t.Fatal("real database lease lookup did not retain its renewable TTL")
	}
	renewed, err := client.RenewLifecycleLease(ctx, operator, issued.LeaseID, 240)
	if err != nil || !renewed.Exists || !renewed.Renewable || renewed.TTLSeconds <= 0 || renewed.TTLSeconds > 240 {
		t.Fatal("real database lease renewal did not report its actual finite TTL")
	}
	lifecycleRequireMetadataPrivate(t, renewed, operator, issued.LeaseID, username, credential, strings.TrimSpace(string(password)))
	lifecycleRequireDatabaseLogin(t, ctx, username, credential, true)
	if _, err := client.RevokeLifecycleLease(ctx, operator, issued.LeaseID); err != nil {
		t.Fatal("exact synchronous database lease revocation failed")
	}
	after, err := client.InspectLifecycleLease(ctx, operator, issued.LeaseID)
	if err != nil || after.Exists {
		t.Fatal("the synchronously revoked database lease still exists in Vault")
	}
	// A failed connection proves revocation only while the same server still
	// accepts an independent valid credential.
	lifecycleRequireDatabaseLogin(t, ctx, "secretwright_fixture", strings.TrimSpace(string(password)), true)
	lifecycleRequireDatabaseLogin(t, ctx, username, credential, false)
}
