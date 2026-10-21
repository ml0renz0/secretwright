//go:build integration

package vault_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/ml0renz0/secretwright/internal/cli"
	"github.com/ml0renz0/secretwright/internal/vault"
)

type kvIntegrationFixture struct {
	admin        *api.Client
	v1           string
	v2           string
	nested       string
	parent       string
	scopedToken  string
	readToken    string
	listToken    string
}

func prepareKVIntegrationFixture(t *testing.T) kvIntegrationFixture {
	t.Helper()
	admin := integrationTokenAdmin(t)
	prefix := fmt.Sprintf("secretwright-f02-%d", time.Now().UnixNano())
	fixture := kvIntegrationFixture{
		admin:  admin,
		v1:     prefix + "-v1/",
		v2:     prefix + "-v2/",
		nested: prefix + "-parent/kv/",
		parent: prefix + "-parent",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, mount := range []struct {
		path    string
		version int
	}{{fixture.v1, 1}, {fixture.v2, 2}, {fixture.nested, 2}} {
		if err := admin.Sys().MountWithContext(ctx, mount.path, &api.MountInput{
			Type:    "kv",
			Options: map[string]string{"version": fmt.Sprint(mount.version)},
		}); err != nil {
			t.Fatal("could not provision a disposable KV mount")
		}
		t.Cleanup(func() {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = admin.Sys().UnmountWithContext(cleanupContext, mount.path)
		})
		for _, key := range []string{"allowed/item", "allowed/data/item", "allowed/nested/leaf", "denied/item"} {
			values := map[string]any{
				"value": "private-kv-value-" + key,
				"data":  map[string]any{"nested": "private-nested-kv-value"},
			}
			path := mount.path + key
			var request map[string]any = values
			if mount.version == 2 {
				path = mount.path + "data/" + key
				request = map[string]any{"data": values}
			}
			if _, err := admin.Logical().WriteWithContext(ctx, path, request); err != nil {
				t.Fatal("could not seed a disposable KV record")
			}
		}
	}
	if _, err := admin.Logical().WriteWithContext(ctx, fixture.v2+"data/allowed/deleted", map[string]any{
		"data": map[string]any{"value": "private-deleted-kv-value"},
	}); err != nil {
		t.Fatal("could not seed the disposable deleted record")
	}
	if _, err := admin.Logical().DeleteWithContext(ctx, fixture.v2+"data/allowed/deleted"); err != nil {
		t.Fatal("could not soft-delete the disposable KV v2 record")
	}

	var fullPolicy, readPolicy, listPolicy strings.Builder
	for _, mount := range []struct {
		path    string
		version int
	}{{fixture.v1, 1}, {fixture.v2, 2}, {fixture.nested, 2}} {
		readPath, listPath := mount.path+"allowed/", mount.path+"allowed"
		if mount.version == 2 {
			readPath, listPath = mount.path+"data/allowed/", mount.path+"metadata/allowed"
		}
		fmt.Fprintf(&readPolicy, "path %q { capabilities = [\"read\"] }\n", readPath+"*")
		fmt.Fprintf(&listPolicy, "path %q { capabilities = [\"list\"] }\n", listPath)
		fmt.Fprintf(&listPolicy, "path %q { capabilities = [\"list\"] }\n", listPath+"/*")
	}
	fullPolicy.WriteString(readPolicy.String())
	fullPolicy.WriteString(listPolicy.String())
	fixture.scopedToken = createKVIntegrationPolicyToken(t, admin, prefix+"-read-list", fullPolicy.String())
	fixture.readToken = createKVIntegrationPolicyToken(t, admin, prefix+"-read", readPolicy.String())
	fixture.listToken = createKVIntegrationPolicyToken(t, admin, prefix+"-list", listPolicy.String())
	return fixture
}

func createKVIntegrationPolicyToken(t *testing.T, admin *api.Client, policyName, policy string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := admin.Sys().PutPolicyWithContext(ctx, policyName, policy); err != nil {
		t.Fatal("could not provision the disposable KV policy")
	}
	t.Cleanup(func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = admin.Sys().DeletePolicyWithContext(cleanupContext, policyName)
	})
	return createIntegrationToken(t, admin, &api.TokenCreateRequest{
		Policies:        []string{policyName},
		NoDefaultPolicy: true,
		TTL:             "2m",
		DisplayName:     "secretwright-f02-integration",
	})
}

func TestIntegrationKVReadNavigationAndPermissions(t *testing.T) {
	fixture := prepareKVIntegrationFixture(t)
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatal("could not create the Secretwright KV client")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, mount := range []struct {
		name    string
		path    string
		version int
	}{{"KV v1", fixture.v1, 1}, {"KV v2", fixture.v2, 2}, {"nested mount", fixture.nested, 2}} {
		t.Run(mount.name, func(t *testing.T) {
			for _, key := range []string{"allowed/item", "allowed/data/item"} {
				report, err := client.Read(ctx, fixture.scopedToken, "/"+mount.path+key, vault.KVOptions{})
				if err != nil {
					t.Fatal("scoped token could not read its allowed record using automatic mount discovery")
				}
				if len(report) != 2 || report["value"] != "private-kv-value-"+key {
					t.Fatal("KV reader returned an incorrect value or a wire-level wrapper")
				}
				inner, ok := report["data"].(map[string]any)
				if !ok || inner["nested"] != "private-nested-kv-value" {
					t.Fatal("KV reader lost a user field named data")
				}
			}
			entries, err := client.List(ctx, fixture.scopedToken, "/"+mount.path+"allowed", vault.KVOptions{})
			if err != nil || !slices.IsSorted(entries) || !slices.Contains(entries, "item") || !slices.Contains(entries, "nested/") || !slices.Contains(entries, "data/") {
				t.Fatal("scoped token could not list its allowed directory correctly")
			}
			directory, err := client.ChangeDir(ctx, fixture.scopedToken, "..", vault.KVOptions{CWD: "/" + mount.path + "allowed/nested"})
			if err != nil || directory != "/"+mount.path+"allowed" {
				t.Fatal("directory navigation did not resolve or validate its logical parent")
			}
			if values, err := client.Read(ctx, fixture.scopedToken, "../item", vault.KVOptions{CWD: "/" + mount.path + "allowed/nested"}); err != nil || values["value"] != "private-kv-value-allowed/item" {
				t.Fatal("relative record navigation failed")
			}
			if _, err := client.Read(ctx, fixture.scopedToken, "/"+mount.path+"denied/item", vault.KVOptions{}); !errors.Is(err, vault.ErrPermissionDenied) {
				t.Fatal("scoped token was not denied access to another subtree")
			}
			if _, err := client.List(ctx, fixture.scopedToken, "/"+mount.path+"denied", vault.KVOptions{Mount: mount.path, Version: mount.version}); !errors.Is(err, vault.ErrPermissionDenied) {
				t.Fatal("scoped token was not denied listing another subtree")
			}
			if _, err := client.Read(ctx, fixture.scopedToken, "/"+mount.path+"allowed/missing", vault.KVOptions{}); !errors.Is(err, vault.ErrNotFound) {
				t.Fatal("missing allowed record was not reported as absent")
			}
			explicit := vault.KVOptions{Mount: mount.path, Version: mount.version}
			if _, err := client.Read(ctx, fixture.readToken, "/"+mount.path+"allowed/item", explicit); err != nil {
				t.Fatal("read-only token could not read with an explicit KV mount")
			}
			if _, err := client.List(ctx, fixture.readToken, "/"+mount.path+"allowed", explicit); !errors.Is(err, vault.ErrPermissionDenied) {
				t.Fatal("read permission incorrectly granted list permission")
			}
			if _, err := client.List(ctx, fixture.listToken, "/"+mount.path+"allowed", explicit); err != nil {
				t.Fatal("list-only token could not list with an explicit KV mount")
			}
			if _, err := client.Read(ctx, fixture.listToken, "/"+mount.path+"allowed/item", explicit); !errors.Is(err, vault.ErrPermissionDenied) {
				t.Fatal("list permission incorrectly granted read permission")
			}
		})
	}
	if _, err := client.CheckToken(ctx, fixture.scopedToken); !errors.Is(err, vault.ErrUnauthenticated) {
		t.Fatal("the scoped fixture unexpectedly has lookup-self permission")
	}
	if _, err := client.Read(ctx, fixture.scopedToken, "/"+fixture.v2+"allowed/deleted", vault.KVOptions{}); !errors.Is(err, vault.ErrNotFound) {
		t.Fatal("latest soft-deleted KV v2 record was not reported as absent")
	}

	mounts, err := client.Mounts(ctx, fixture.admin.Token())
	if err != nil {
		t.Fatal("could not enumerate the disposable KV mounts")
	}
	for path, version := range map[string]int{fixture.v1: 1, fixture.v2: 2, fixture.nested: 2} {
		if !slices.ContainsFunc(mounts, func(mount vault.Mount) bool { return mount.Path == path && mount.Version == version }) {
			t.Fatal("visible KV mount catalog omitted a mount or its engine version")
		}
	}
	rootEntries, err := client.List(ctx, fixture.admin.Token(), "/", vault.KVOptions{})
	if err != nil || !slices.Contains(rootEntries, fixture.parent+"/") {
		t.Fatal("logical root did not expose the nested mount's virtual parent")
	}
	parentEntries, err := client.List(ctx, fixture.admin.Token(), "/"+fixture.parent, vault.KVOptions{})
	if err != nil || !slices.Equal(parentEntries, []string{"kv/"}) {
		t.Fatal("nested mount's virtual parent could not be listed")
	}
	if directory, err := client.ChangeDir(ctx, fixture.admin.Token(), "/"+fixture.parent, vault.KVOptions{}); err != nil || directory != "/"+fixture.parent {
		t.Fatal("nested mount's virtual parent could not be selected")
	}
	assertKVIntegrationCLI(t, fixture)
}

func assertKVIntegrationCLI(t *testing.T, fixture kvIntegrationFixture) {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "kv-token")
	if err := os.WriteFile(tokenPath, []byte(fixture.scopedToken), 0600); err != nil {
		t.Fatal("could not prepare the disposable mounted CLI credential")
	}
	t.Setenv("VAULT_TOKEN", "invalid-inherited-kv-token")
	for _, test := range []struct {
		name string
		args []string
		code int
	}{
		{name: "read KV v1", args: []string{"cat", "--token-file", tokenPath, "/" + fixture.v1 + "allowed/item"}},
		{name: "read KV v2 relative", args: []string{"cat", "--token-file", tokenPath, "--cwd", "/" + fixture.v2 + "allowed", "item"}},
		{name: "denied", args: []string{"cat", "--token-file", tokenPath, "/" + fixture.v2 + "denied/item"}, code: 2},
		{name: "missing", args: []string{"cat", "--token-file", tokenPath, "/" + fixture.v1 + "allowed/missing"}, code: 3},
		{name: "soft deleted", args: []string{"cat", "--token-file", tokenPath, "/" + fixture.v2 + "allowed/deleted"}, code: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var stdout, stderr bytes.Buffer
			if code := cli.Run(ctx, test.args, &stdout, &stderr, "integration"); code != test.code {
				t.Fatal("KV CLI returned an unexpected exit code")
			}
			if strings.Contains(stdout.String()+stderr.String(), fixture.scopedToken) || strings.Contains(stdout.String()+stderr.String(), "invalid-inherited-kv-token") {
				t.Fatal("KV CLI exposed a credential")
			}
			if test.code == 0 {
				var report map[string]any
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil || report["value"] != "private-kv-value-allowed/item" || stderr.Len() != 0 {
					t.Fatal("KV CLI did not return the selected secret as JSON")
				}
			} else if stdout.Len() != 0 || stderr.Len() == 0 || strings.Contains(stderr.String(), "private-kv-value") {
				t.Fatal("KV failure returned secret data or unexpected output")
			}
		})
	}
}
