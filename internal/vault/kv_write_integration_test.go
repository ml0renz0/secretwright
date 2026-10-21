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
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/vault"
)

func integrationWritePolicy(fixture kvIntegrationFixture) string {
	var policy strings.Builder
	for _, mount := range []struct {
		path    string
		version int
	}{{fixture.v1, 1}, {fixture.v2, 2}, {fixture.nested, 2}} {
		if mount.version == 1 {
			fmt.Fprintf(&policy, "path %q { capabilities = [\"create\",\"read\",\"update\",\"delete\",\"list\"] }\n", mount.path+"allowed/*")
			continue
		}
		fmt.Fprintf(&policy, "path %q { capabilities = [\"create\",\"read\",\"update\",\"delete\"] }\n", mount.path+"data/allowed/*")
		fmt.Fprintf(&policy, "path %q { capabilities = [\"read\",\"list\"] }\n", mount.path+"metadata/allowed/*")
		for _, operation := range []string{"delete", "undelete", "destroy"} {
			fmt.Fprintf(&policy, "path %q { capabilities = [\"update\"] }\n", mount.path+operation+"/allowed/*")
		}
	}
	return policy.String()
}

func newWriteIntegrationClient(t *testing.T) *vault.Client {
	t.Helper()
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatal("could not create the Secretwright mutation client")
	}
	return client
}

func integrationValues(revision string) map[string]any {
	return map[string]any{
		"value": "private-f03-value-" + revision,
		"large": json.Number("9007199254740993"),
		"data":  map[string]any{"nested": "private-f03-nested-" + revision},
	}
}

func requireIntegrationValues(t *testing.T, ctx context.Context, client *vault.Client, token, path string, want map[string]any) {
	t.Helper()
	got, err := client.Read(ctx, token, path, vault.KVOptions{})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("KV mutation did not preserve the expected values and numeric precision")
	}
}

func requireSafeMutationReport(t *testing.T, report any, token string) {
	t.Helper()
	encoded, err := json.Marshal(report)
	if err != nil || strings.Contains(string(encoded), token) || strings.Contains(string(encoded), "private-f03-") || strings.Contains(string(encoded), "9007199254740993") {
		t.Fatal("mutation report exposed a credential or secret value")
	}
}

func TestIntegrationKVWritesCASAndVersionLifecycle(t *testing.T) {
	fixture := prepareKVIntegrationFixture(t)
	writer := createKVIntegrationPolicyToken(t, fixture.admin, fmt.Sprintf("secretwright-f03-write-%d", time.Now().UnixNano()), integrationWritePolicy(fixture))
	client := newWriteIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("KV v1 replacement and forced deletion", func(t *testing.T) {
		target := "/" + fixture.v1 + "allowed/f03-value"
		first, second := integrationValues("v1-first"), integrationValues("v1-second")
		report, err := client.Put(ctx, writer, target, first, vault.WriteOptions{})
		if err != nil || report.KVVersion != 1 || report.Version != 0 || report.Path != target {
			t.Fatal("KV v1 put did not confirm its logical destination")
		}
		requireSafeMutationReport(t, report, writer)
		requireIntegrationValues(t, ctx, client, writer, target, first)
		if _, err := client.Put(ctx, writer, target, second, vault.WriteOptions{}); err != nil {
			t.Fatal("KV v1 replacement failed")
		}
		requireIntegrationValues(t, ctx, client, writer, target, second)
		if _, err := client.Remove(ctx, writer, target, nil, vault.WriteOptions{}); !errors.Is(err, vault.ErrUnsupportedOperation) {
			t.Fatal("KV v1 deletion did not require an explicit force option")
		}
		requireIntegrationValues(t, ctx, client, writer, target, second)
		if _, err := client.ReadVersion(ctx, writer, target, 1, vault.KVOptions{}); !errors.Is(err, vault.ErrUnsupportedOperation) {
			t.Fatal("KV v1 incorrectly accepted historical version reads")
		}
		removed, err := client.Remove(ctx, writer, target, nil, vault.WriteOptions{Force: true})
		if err != nil || removed.KVVersion != 1 {
			t.Fatal("forced KV v1 deletion failed")
		}
		requireSafeMutationReport(t, removed, writer)
		if _, err := client.Read(ctx, writer, target, vault.KVOptions{}); !errors.Is(err, vault.ErrNotFound) {
			t.Fatal("forced KV v1 deletion left the record readable")
		}
	})

	t.Run("KV v2 CAS and reversible history", func(t *testing.T) {
		target := "/" + fixture.v2 + "allowed/f03-history"
		first, second := integrationValues("v2-first"), integrationValues("v2-second")
		created, err := client.Put(ctx, writer, target, first, vault.WriteOptions{})
		if err != nil || created.KVVersion != 2 || created.Version != 1 {
			t.Fatal("KV v2 create-only put did not create its first revision")
		}
		requireSafeMutationReport(t, created, writer)
		if _, err := client.Put(ctx, writer, target, second, vault.WriteOptions{}); !errors.Is(err, vault.ErrConflict) {
			t.Fatal("create-only KV v2 put silently overwrote an existing record")
		}
		requireIntegrationValues(t, ctx, client, writer, target, first)
		cas := 1
		updated, err := client.Put(ctx, writer, target, second, vault.WriteOptions{CAS: &cas})
		if err != nil || updated.Version != 2 {
			t.Fatal("matching KV v2 CAS did not create the next revision")
		}
		if _, err := client.Put(ctx, writer, target, integrationValues("stale-write"), vault.WriteOptions{CAS: &cas}); !errors.Is(err, vault.ErrConflict) {
			t.Fatal("stale KV v2 CAS was not rejected")
		}
		requireIntegrationValues(t, ctx, client, writer, target, second)
		historical, err := client.ReadVersion(ctx, writer, target, 1, vault.KVOptions{})
		if err != nil || !reflect.DeepEqual(historical, first) {
			t.Fatal("historical KV v2 read returned the wrong revision")
		}
		history, err := client.Versions(ctx, writer, target, vault.KVOptions{})
		if err != nil || history.CurrentVersion != 2 || len(history.Versions) != 2 || history.Versions[0].Version != 1 || history.Versions[1].Version != 2 || history.Versions[0].CreatedTime == "" {
			t.Fatal("KV v2 version history was not sorted or complete")
		}
		requireSafeMutationReport(t, history, writer)
		if _, err := client.Remove(ctx, writer, target, []int{2}, vault.WriteOptions{}); err != nil {
			t.Fatal("explicit KV v2 revision deletion failed")
		}
		if _, err := client.Read(ctx, writer, target, vault.KVOptions{}); !errors.Is(err, vault.ErrNotFound) {
			t.Fatal("soft-deleted latest KV v2 revision remained readable")
		}
		if _, err := client.Undelete(ctx, writer, target, []int{2}, vault.KVOptions{}); err != nil {
			t.Fatal("KV v2 undelete failed")
		}
		requireIntegrationValues(t, ctx, client, writer, target, second)
		if _, err := client.Remove(ctx, writer, target, nil, vault.WriteOptions{}); err != nil {
			t.Fatal("KV v2 latest-revision soft deletion failed")
		}
		if _, err := client.Undelete(ctx, writer, target, []int{2}, vault.KVOptions{}); err != nil {
			t.Fatal("KV v2 latest revision could not be restored")
		}
		rolledBack, err := client.Rollback(ctx, writer, target, 1, vault.KVOptions{})
		if err != nil || rolledBack.Version != 3 {
			t.Fatal("rollback did not create a new KV v2 revision")
		}
		requireIntegrationValues(t, ctx, client, writer, target, first)
		if _, err := client.Destroy(ctx, writer, target, []int{1}, vault.WriteOptions{}); !errors.Is(err, vault.ErrUnsupportedOperation) {
			t.Fatal("permanent revision destruction did not require force")
		}
		destroyed, err := client.Destroy(ctx, writer, target, []int{1}, vault.WriteOptions{Force: true})
		if err != nil || len(destroyed.Versions) != 1 || destroyed.Versions[0] != 1 {
			t.Fatal("forced KV v2 revision destruction failed")
		}
		requireSafeMutationReport(t, destroyed, writer)
		if _, err := client.ReadVersion(ctx, writer, target, 1, vault.KVOptions{}); !errors.Is(err, vault.ErrNotFound) {
			t.Fatal("destroyed historical KV v2 revision remained readable")
		}
		if _, err := client.Rollback(ctx, writer, target, 1, vault.KVOptions{}); !errors.Is(err, vault.ErrNotFound) {
			t.Fatal("rollback recreated a destroyed KV v2 revision")
		}
		history, err = client.Versions(ctx, writer, target, vault.KVOptions{})
		if err != nil || history.CurrentVersion != 3 || len(history.Versions) != 3 || !history.Versions[0].Destroyed {
			t.Fatal("KV v2 lifecycle changed unrelated history or lost destruction metadata")
		}
		requireIntegrationValues(t, ctx, client, writer, target, first)
	})

	t.Run("copy and move across mounts", func(t *testing.T) {
		values := integrationValues("cross-mount")
		source := "/" + fixture.v1 + "allowed/f03-copy-source"
		destination := "/" + fixture.v2 + "allowed/f03-copy-destination"
		if _, err := client.Put(ctx, writer, source, values, vault.WriteOptions{}); err != nil {
			t.Fatal("could not create the cross-mount source")
		}
		copied, err := client.Copy(ctx, writer, source, destination, vault.WriteOptions{})
		if err != nil || copied.KVVersion != 2 || copied.Version != 1 || copied.SourceDeleted {
			t.Fatal("KV v1 to KV v2 copy failed")
		}
		requireSafeMutationReport(t, copied, writer)
		requireIntegrationValues(t, ctx, client, writer, source, values)
		requireIntegrationValues(t, ctx, client, writer, destination, values)
		if _, err := client.Copy(ctx, writer, source, destination, vault.WriteOptions{}); !errors.Is(err, vault.ErrConflict) {
			t.Fatal("copy overwrote an existing KV v2 destination without CAS")
		}
		legacyDestination := "/" + fixture.v1 + "allowed/f03-copy-back"
		if _, err := client.Copy(ctx, writer, destination, legacyDestination, vault.WriteOptions{}); !errors.Is(err, vault.ErrUnsupportedOperation) {
			t.Fatal("copy into KV v1 did not require force")
		}
		if _, err := client.Copy(ctx, writer, destination, legacyDestination, vault.WriteOptions{Force: true}); err != nil {
			t.Fatal("forced copy into KV v1 failed")
		}
		requireIntegrationValues(t, ctx, client, writer, legacyDestination, values)
		movedDestination := "/" + fixture.nested + "allowed/f03-moved"
		moved, err := client.Move(ctx, writer, destination, movedDestination, vault.WriteOptions{})
		if err != nil || moved.SourceVersion != 1 || !moved.SourceDeleted || moved.KVVersion != 2 {
			t.Fatal("KV v2 move did not delete the captured source revision")
		}
		requireSafeMutationReport(t, moved, writer)
		requireIntegrationValues(t, ctx, client, writer, movedDestination, values)
		if _, err := client.Read(ctx, writer, destination, vault.KVOptions{}); !errors.Is(err, vault.ErrNotFound) {
			t.Fatal("moved KV v2 source revision remained readable")
		}
		legacyMove := "/" + fixture.v2 + "allowed/f03-legacy-moved"
		if _, err := client.Move(ctx, writer, source, legacyMove, vault.WriteOptions{}); !errors.Is(err, vault.ErrUnsupportedOperation) {
			t.Fatal("move from KV v1 did not require force")
		}
		requireIntegrationValues(t, ctx, client, writer, source, values)
		if _, err := client.Move(ctx, writer, source, legacyMove, vault.WriteOptions{Force: true}); err != nil {
			t.Fatal("forced move from KV v1 into KV v2 failed")
		}
		requireIntegrationValues(t, ctx, client, writer, legacyMove, values)
		if _, err := client.Read(ctx, writer, source, vault.KVOptions{}); !errors.Is(err, vault.ErrNotFound) {
			t.Fatal("forced KV v1 move did not delete its source")
		}
	})
}

func TestIntegrationKVWritePermissionsAndPartialMove(t *testing.T) {
	fixture := prepareKVIntegrationFixture(t)
	fullPolicy := integrationWritePolicy(fixture)
	writer := createKVIntegrationPolicyToken(t, fixture.admin, fmt.Sprintf("secretwright-f03-full-%d", time.Now().UnixNano()), fullPolicy)
	client := newWriteIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var writeOnlyPolicy strings.Builder
	for _, mount := range []struct {
		path    string
		version int
	}{{fixture.v1, 1}, {fixture.v2, 2}} {
		prefix := mount.path
		if mount.version == 2 {
			prefix += "data/"
		}
		fmt.Fprintf(&writeOnlyPolicy, "path %q { capabilities = [\"create\",\"update\"] }\n", prefix+"allowed/*")
	}
	writeOnly := createKVIntegrationPolicyToken(t, fixture.admin, fmt.Sprintf("secretwright-f03-write-only-%d", time.Now().UnixNano()), writeOnlyPolicy.String())
	for _, mount := range []string{fixture.v1, fixture.v2} {
		target := "/" + mount + "allowed/f03-write-only"
		if _, err := client.Put(ctx, writeOnly, target, integrationValues("write-only"), vault.WriteOptions{}); err != nil {
			t.Fatal("write-only token could not create its allowed record")
		}
		if _, err := client.Read(ctx, writeOnly, target, vault.KVOptions{}); !errors.Is(err, vault.ErrPermissionDenied) {
			t.Fatal("write permission incorrectly granted secret read permission")
		}
		if _, err := client.Put(ctx, fixture.readToken, target, integrationValues("read-only-rejected"), vault.WriteOptions{}); !errors.Is(err, vault.ErrPermissionDenied) {
			t.Fatal("read permission incorrectly granted secret write permission")
		}
		requireIntegrationValues(t, ctx, client, writer, target, integrationValues("write-only"))
		if _, err := client.Put(ctx, writer, "/"+mount+"denied/f03-new", integrationValues("cross-subtree-rejected"), vault.WriteOptions{}); !errors.Is(err, vault.ErrPermissionDenied) {
			t.Fatal("scoped writer could mutate another subtree")
		}
	}
	source := "/" + fixture.v2 + "allowed/f03-partial-source"
	destination := "/" + fixture.nested + "allowed/f03-partial-destination"
	values := integrationValues("partial-move")
	if _, err := client.Put(ctx, writer, source, values, vault.WriteOptions{}); err != nil {
		t.Fatal("could not provision the partial-move source")
	}
	deniedDelete := fullPolicy + fmt.Sprintf("path %q { capabilities = [\"deny\"] }\n", fixture.v2+"delete/allowed/f03-partial-source")
	partialToken := createKVIntegrationPolicyToken(t, fixture.admin, fmt.Sprintf("secretwright-f03-partial-%d", time.Now().UnixNano()), deniedDelete)
	if _, err := client.Move(ctx, partialToken, source, destination, vault.WriteOptions{}); !errors.Is(err, vault.ErrPartial) {
		t.Fatal("move with an unconfirmed source deletion did not report a partial result")
	} else if strings.Contains(err.Error(), partialToken) || strings.Contains(err.Error(), "private-f03-") {
		t.Fatal("partial-move diagnostic exposed a credential or value")
	}
	requireIntegrationValues(t, ctx, client, writer, source, values)
	requireIntegrationValues(t, ctx, client, writer, destination, values)
	failedDestination := "/" + fixture.nested + "denied/f03-failed-destination"
	if _, err := client.Move(ctx, writer, source, failedDestination, vault.WriteOptions{}); !errors.Is(err, vault.ErrPermissionDenied) {
		t.Fatal("move with a denied destination did not preserve the source")
	}
	requireIntegrationValues(t, ctx, client, writer, source, values)
}

func TestIntegrationKVMovePreservesConcurrentSourceRevision(t *testing.T) {
	fixture := prepareKVIntegrationFixture(t)
	writer := createKVIntegrationPolicyToken(t, fixture.admin, fmt.Sprintf("secretwright-f03-race-%d", time.Now().UnixNano()), integrationWritePolicy(fixture))
	client := newWriteIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	source := "/" + fixture.v2 + "allowed/f03-race-source"
	destination := "/" + fixture.nested + "allowed/f03-race-destination"
	oldValues, newValues := integrationValues("snapshot-old"), integrationValues("snapshot-new")
	if _, err := client.Put(ctx, writer, source, oldValues, vault.WriteOptions{}); err != nil {
		t.Fatal("could not provision the concurrent-move source")
	}
	upstream, err := url.Parse(os.Getenv("VAULT_ADDR"))
	if err != nil {
		t.Fatal("invalid disposable fixture address")
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	var interleaved atomic.Int32
	hookErrors := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/"+fixture.nested+"data/allowed/f03-race-destination" || (r.Method != http.MethodPost && r.Method != http.MethodPut) {
			proxy.ServeHTTP(w, r)
			return
		}
		// Buffer only the destination acknowledgement. Once Vault has written the
		// destination, introduce a newer source revision before returning that
		// acknowledgement to Move. The backend and every mutation remain real.
		recorder := httptest.NewRecorder()
		proxy.ServeHTTP(recorder, r)
		if recorder.Code >= 200 && recorder.Code < 300 {
			interleaved.Add(1)
			hookContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, hookErr := fixture.admin.Logical().WriteWithContext(hookContext, fixture.v2+"data/allowed/f03-race-source", map[string]any{
				"data": newValues, "options": map[string]any{"cas": 1},
			})
			cancel()
			if hookErr != nil {
				select {
				case hookErrors <- errors.New("could not interleave the concurrent source revision"):
				default:
				}
			}
		}
		for name, values := range recorder.Header() {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(recorder.Body.Bytes())
	}))
	defer server.Close()
	proxyAddress := server.URL
	proxied, err := vault.New(vault.Options{Address: &proxyAddress})
	if err != nil {
		t.Fatal("could not create the interleaving test client")
	}
	moved, err := proxied.Move(ctx, writer, source, destination, vault.WriteOptions{})
	if err != nil || moved.SourceVersion != 1 || !moved.SourceDeleted || interleaved.Load() != 1 {
		t.Fatal("move did not remove exactly the captured source revision")
	}
	select {
	case <-hookErrors:
		t.Fatal("could not interleave the concurrent source revision")
	default:
	}
	requireIntegrationValues(t, ctx, client, writer, destination, oldValues)
	requireIntegrationValues(t, ctx, client, writer, source, newValues)
	history, err := client.Versions(ctx, writer, source, vault.KVOptions{})
	if err != nil || history.CurrentVersion != 2 || len(history.Versions) != 2 || history.Versions[0].DeletionTime == "" || history.Versions[1].DeletionTime != "" {
		t.Fatal("move changed the newer concurrent source revision")
	}
}
