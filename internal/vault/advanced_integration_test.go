//go:build integration

package vault_test

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
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/vault"
)

func advancedIntegrationValues(label string) map[string]any {
	return map[string]any{
		"value":      "private-f05-" + label,
		"number":     json.Number("1"),
		"identifier": "9007199254740993",
		"nested":     map[string]any{"value": "private-f05-nested"},
	}
}

func requireAdvancedSafeReport(t *testing.T, report any, token string) {
	t.Helper()
	encoded, err := json.Marshal(report)
	if err != nil || strings.Contains(string(encoded), token) || strings.Contains(string(encoded), "private-f05-") || strings.Contains(string(encoded), "9007199254740993") {
		t.Fatal("advanced operation report exposed a credential or secret value")
	}
}

func seedAdvancedIntegration(t *testing.T, ctx context.Context, client *vault.Client, token, root string, values map[string]map[string]any) {
	t.Helper()
	for key, data := range values {
		if _, err := client.Put(ctx, token, root+"/"+key, data, vault.WriteOptions{}); err != nil {
			t.Fatal("could not provision the private recursive-operation fixture")
		}
	}
}

func TestIntegrationAdvancedTreeSearchCopyAndRestore(t *testing.T) {
	fixture := prepareKVIntegrationFixture(t)
	writer := createKVIntegrationPolicyToken(t, fixture.admin, fmt.Sprintf("secretwright-f05-%d", time.Now().UnixNano()), integrationWritePolicy(fixture))
	client := newWriteIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root := "/" + fixture.v2 + "allowed/f05-source"
	old, replacement := advancedIntegrationValues("before"), advancedIntegrationValues("after")
	other := advancedIntegrationValues("other")
	values := map[string]map[string]any{"item": old, "foo": other, "foo/bar": old, "nested/秘密": other}
	seedAdvancedIntegration(t, ctx, client, writer, root, values)
	options := vault.RecursiveOptions{Concurrency: 2}

	tree, err := client.Walk(ctx, fixture.listToken, root, options)
	if err != nil || tree.Root != root || len(tree.Entries) != 6 {
		t.Fatal("LIST-only recursive traversal did not retain every directory and key")
	}
	leaf, directory := false, false
	for _, entry := range tree.Entries {
		if entry.Path == root+"/foo" {
			leaf = leaf || !entry.Directory
			directory = directory || entry.Directory
		}
	}
	if !leaf || !directory {
		t.Fatal("recursive traversal confused a key with its same-named directory")
	}
	requireAdvancedSafeReport(t, tree, fixture.listToken)
	if _, err := client.Read(ctx, fixture.listToken, root+"/item", vault.KVOptions{}); !errors.Is(err, vault.ErrPermissionDenied) {
		t.Fatal("LIST-only traversal credential unexpectedly gained permission to read values")
	}
	match := advancedIntegrationValues("before")
	match["number"] = json.Number("1.00")
	found, err := client.Find(ctx, writer, root, match, options)
	wantMatches := []string{root + "/foo/bar", root + "/item"}
	if err != nil || !reflect.DeepEqual(found, wantMatches) {
		t.Fatal("recursive find did not compare whole JSON objects with exact numeric semantics")
	}
	requireAdvancedSafeReport(t, found, writer)
	if found, err := client.Find(ctx, writer, root, map[string]any{"value": old["value"]}, options); err != nil || len(found) != 0 {
		t.Fatal("recursive find treated a partial JSON object as a whole-object match")
	}

	dry, err := client.Replace(ctx, writer, root, match, replacement, vault.BulkOptions{RecursiveOptions: options, DryRun: true})
	if err != nil || !dry.DryRun || len(dry.Items) != 2 {
		t.Fatal("replacement dry-run did not plan only matching secrets")
	}
	for _, path := range wantMatches {
		requireIntegrationValues(t, ctx, client, writer, path, old)
	}
	requireAdvancedSafeReport(t, dry, writer)
	changed, err := client.Replace(ctx, writer, root, match, replacement, vault.BulkOptions{RecursiveOptions: options})
	if err != nil || len(changed.Items) != 2 {
		t.Fatal("recursive whole-object replacement did not update its matching snapshots")
	}
	requireAdvancedSafeReport(t, changed, writer)
	for _, key := range []string{"foo/bar", "item"} {
		values[key] = replacement
		requireIntegrationValues(t, ctx, client, writer, root+"/"+key, replacement)
	}
	unchanged, err := client.Replace(ctx, writer, root, replacement, replacement, vault.BulkOptions{RecursiveOptions: options})
	if err != nil || len(unchanged.Items) != 2 {
		t.Fatal("equal replacement failed instead of preserving the current revisions")
	}
	for _, item := range unchanged.Items {
		if item.Status != "unchanged" {
			t.Fatal("equal replacement created an unnecessary revision")
		}
	}
	for _, path := range wantMatches {
		history, err := client.Versions(ctx, writer, path, vault.KVOptions{})
		if err != nil || history.CurrentVersion != 2 {
			t.Fatal("replacement dry-run or equal replacement changed revision history")
		}
	}
	if found, err := client.Find(ctx, writer, root, match, options); err != nil || len(found) != 0 {
		t.Fatal("replacement left a stale matching current value")
	}

	destination := "/" + fixture.nested + "allowed/f05-copy"
	copied, err := client.CopyTree(ctx, writer, root, destination, vault.BulkOptions{RecursiveOptions: options})
	if err != nil || len(copied.Items) != len(values) {
		t.Fatal("recursive copy across mounts did not preserve all relative keys")
	}
	requireAdvancedSafeReport(t, copied, writer)
	for key, data := range values {
		requireIntegrationValues(t, ctx, client, writer, destination+"/"+key, data)
		requireIntegrationValues(t, ctx, client, writer, root+"/"+key, data)
	}
	conflict, err := client.CopyTree(ctx, writer, root, destination, vault.BulkOptions{RecursiveOptions: vault.RecursiveOptions{Concurrency: 1}})
	if !errors.Is(err, vault.ErrConflict) || errors.Is(err, vault.ErrBulkPartial) {
		t.Fatal("create-only recursive copy overwrote existing destination keys")
	}
	requireAdvancedSafeReport(t, conflict, writer)

	archive, err := client.Backup(ctx, writer, root, options)
	if err != nil || archive.Format != "secretwright-kv" || archive.Version != 1 || archive.Root != root || len(archive.Entries) != len(values) {
		t.Fatal("current-value backup did not produce its versioned relative-key archive")
	}
	var encoded bytes.Buffer
	if err := vault.EncodeArchive(&encoded, archive); err != nil {
		t.Fatal("current-value backup could not encode its bounded archive")
	}
	decoded, err := vault.DecodeArchive(&encoded)
	if err != nil || len(decoded.Entries) != len(values) {
		t.Fatal("current-value backup archive could not be validated for restore")
	}
	restoredRoot := "/" + fixture.v2 + "allowed/f05-restored"
	restored, err := client.Restore(ctx, writer, restoredRoot, decoded, vault.BulkOptions{RecursiveOptions: options})
	if err != nil || len(restored.Items) != len(values) {
		t.Fatal("validated archive did not restore its current values")
	}
	requireAdvancedSafeReport(t, restored, writer)
	for key, data := range values {
		requireIntegrationValues(t, ctx, client, writer, restoredRoot+"/"+key, data)
	}
	if _, err := client.Restore(ctx, writer, restoredRoot, decoded, vault.BulkOptions{RecursiveOptions: vault.RecursiveOptions{Concurrency: 1}}); !errors.Is(err, vault.ErrConflict) {
		t.Fatal("restore silently overwrote an existing KV v2 destination")
	}
	legacyRoot := "/" + fixture.v1 + "allowed/f05-restored"
	if _, err := client.Restore(ctx, writer, legacyRoot, decoded, vault.BulkOptions{RecursiveOptions: options}); !errors.Is(err, vault.ErrUnsupportedOperation) {
		t.Fatal("restore into KV v1 did not require force")
	}
	if _, err := client.Restore(ctx, writer, legacyRoot, decoded, vault.BulkOptions{RecursiveOptions: options, Force: true}); err != nil {
		t.Fatal("forced restore into KV v1 failed")
	}
	for key, data := range values {
		requireIntegrationValues(t, ctx, client, writer, legacyRoot+"/"+key, data)
	}
}

func TestIntegrationAdvancedPreflightRejectsDeniedAndDeletedValues(t *testing.T) {
	fixture := prepareKVIntegrationFixture(t)
	policy := integrationWritePolicy(fixture)
	writer := createKVIntegrationPolicyToken(t, fixture.admin, fmt.Sprintf("secretwright-f05-preflight-%d", time.Now().UnixNano()), policy)
	client := newWriteIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root := "/" + fixture.v2 + "allowed/f05-denied"
	values := advancedIntegrationValues("preflight")
	seedAdvancedIntegration(t, ctx, client, writer, root, map[string]map[string]any{"a": values, "z": values})
	deniedPolicy := policy + fmt.Sprintf("path %q { capabilities = [\"deny\"] }\n", fixture.v2+"data/allowed/f05-denied/z")
	denied := createKVIntegrationPolicyToken(t, fixture.admin, fmt.Sprintf("secretwright-f05-denied-%d", time.Now().UnixNano()), deniedPolicy)
	options := vault.RecursiveOptions{Concurrency: 2}
	if tree, err := client.Walk(ctx, denied, root, options); err != nil || len(tree.Entries) != 2 {
		t.Fatal("recursive metadata-only listing required read permission for secret values")
	}
	if _, err := client.Backup(ctx, denied, root, options); !errors.Is(err, vault.ErrPermissionDenied) {
		t.Fatal("backup silently omitted an unreadable secret")
	}
	destination := "/" + fixture.v2 + "allowed/f05-denied-copy"
	if _, err := client.CopyTree(ctx, denied, root, destination, vault.BulkOptions{RecursiveOptions: options}); !errors.Is(err, vault.ErrPermissionDenied) {
		t.Fatal("recursive copy did not stop at a denied preflight snapshot")
	}
	if _, err := client.Read(ctx, writer, destination+"/a", vault.KVOptions{}); !errors.Is(err, vault.ErrNotFound) {
		t.Fatal("denied recursive-copy preflight already wrote a destination")
	}
	if _, err := client.Replace(ctx, denied, root, values, advancedIntegrationValues("must-not-apply"), vault.BulkOptions{RecursiveOptions: options}); !errors.Is(err, vault.ErrPermissionDenied) {
		t.Fatal("replacement did not reject an incomplete preflight")
	}
	requireIntegrationValues(t, ctx, client, writer, root+"/a", values)

	tombstones := "/" + fixture.v2 + "allowed/f05-tombstones"
	seedAdvancedIntegration(t, ctx, client, writer, tombstones, map[string]map[string]any{"a": values, "b": values})
	if _, err := client.Remove(ctx, writer, tombstones+"/b", nil, vault.WriteOptions{}); err != nil {
		t.Fatal("could not prepare the current-value tombstone fixture")
	}
	if tree, err := client.Walk(ctx, writer, tombstones, options); err != nil || len(tree.Entries) != 2 {
		t.Fatal("LIST-only tree did not retain the tombstone's name")
	}
	if _, err := client.Backup(ctx, writer, tombstones, options); !errors.Is(err, vault.ErrNotFound) {
		t.Fatal("backup presented an incomplete tombstone snapshot as successful")
	}
	if _, err := client.Find(ctx, writer, tombstones, values, options); !errors.Is(err, vault.ErrNotFound) {
		t.Fatal("find silently skipped a missing current snapshot")
	}
	if _, err := client.CopyTree(ctx, writer, tombstones, destination, vault.BulkOptions{RecursiveOptions: options}); !errors.Is(err, vault.ErrNotFound) {
		t.Fatal("copy did not reject an incomplete tombstone preflight")
	}
	if _, err := client.Read(ctx, writer, destination+"/a", vault.KVOptions{}); !errors.Is(err, vault.ErrNotFound) {
		t.Fatal("tombstone copy preflight already wrote a destination")
	}
}

func TestIntegrationRecursiveRemovePreservesANewerConcurrentRevision(t *testing.T) {
	fixture := prepareKVIntegrationFixture(t)
	writer := createKVIntegrationPolicyToken(t, fixture.admin, fmt.Sprintf("secretwright-f05-remove-%d", time.Now().UnixNano()), integrationWritePolicy(fixture))
	client := newWriteIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	root := "/" + fixture.v2 + "allowed/f05-concurrent-remove"
	old, newer := advancedIntegrationValues("captured"), advancedIntegrationValues("newer")
	seedAdvancedIntegration(t, ctx, client, writer, root, map[string]map[string]any{"item": old})
	upstream, err := url.Parse(os.Getenv("VAULT_ADDR"))
	if err != nil {
		t.Fatal("invalid disposable fixture address")
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	var injected atomic.Bool
	var badRequest atomic.Bool
	hookErrors := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/"+fixture.v2+"delete/allowed/f05-concurrent-remove/item" && r.Method == http.MethodPost {
			body, readErr := io.ReadAll(r.Body)
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))
			var request struct {
				Versions []int `json:"versions"`
			}
			if readErr != nil || json.Unmarshal(body, &request) != nil || !slices.Equal(request.Versions, []int{1}) || !injected.CompareAndSwap(false, true) {
				badRequest.Store(true)
			} else {
				hookContext, stop := context.WithTimeout(context.Background(), 5*time.Second)
				_, hookErr := fixture.admin.Logical().WriteWithContext(hookContext, fixture.v2+"data/allowed/f05-concurrent-remove/item", map[string]any{
					"data": newer, "options": map[string]any{"cas": 1},
				})
				stop()
				if hookErr != nil {
					hookErrors <- errors.New("could not interleave the private concurrent revision")
				}
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	defer server.Close()
	address := server.URL
	proxied, err := vault.New(vault.Options{Address: &address})
	if err != nil {
		t.Fatal("could not create the private concurrent-removal proxy client")
	}
	report, err := proxied.RemoveTree(ctx, writer, root, vault.BulkOptions{RecursiveOptions: vault.RecursiveOptions{Concurrency: 1}})
	if err != nil || !injected.Load() || badRequest.Load() || len(report.Items) != 1 || report.Items[0].Status != "deleted" {
		t.Fatal("recursive removal did not delete exactly its captured snapshot")
	}
	select {
	case <-hookErrors:
		t.Fatal("could not interleave the private concurrent revision")
	default:
	}
	requireAdvancedSafeReport(t, report, writer)
	requireIntegrationValues(t, ctx, client, writer, root+"/item", newer)
	history, err := client.Versions(ctx, writer, root+"/item", vault.KVOptions{})
	if err != nil || history.CurrentVersion != 2 || len(history.Versions) != 2 || history.Versions[0].DeletionTime == "" || history.Versions[1].DeletionTime != "" {
		t.Fatal("recursive removal changed a newer concurrent revision or destroyed history")
	}
}
