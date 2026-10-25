//go:build integration

package vault_test

import (
	"context"
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

func hardeningIntegrationProxy(t *testing.T, wrap func(*httputil.ReverseProxy) http.Handler) *vault.Client {
	t.Helper()
	upstream, err := url.Parse(os.Getenv("VAULT_ADDR"))
	if err != nil {
		t.Fatal("invalid disposable fixture address")
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	server := httptest.NewServer(wrap(proxy))
	t.Cleanup(server.Close)
	address := server.URL
	client, err := vault.New(vault.Options{Address: &address})
	if err != nil {
		t.Fatal("could not create the private mutation fault proxy client")
	}
	return client
}

func TestIntegrationReplaceProtectsConcurrentRevisionsAndStopsAfterConflict(t *testing.T) {
	fixture := prepareKVIntegrationFixture(t)
	writer := createKVIntegrationPolicyToken(t, fixture.admin, fmt.Sprintf("secretwright-hardening-replace-%d", time.Now().UnixNano()), integrationWritePolicy(fixture))
	client := newWriteIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	old := advancedIntegrationValues("race-original")
	newer := advancedIntegrationValues("race-concurrent")
	replacement := advancedIntegrationValues("race-replacement")

	for conflictIndex, conflictKey := range []string{"a", "b"} {
		t.Run("conflict-at-"+conflictKey, func(t *testing.T) {
			root := "/" + fixture.v2 + "allowed/hardening-replace-" + conflictKey
			seedAdvancedIntegration(t, ctx, client, writer, root, map[string]map[string]any{"a": old, "b": old, "c": old})
			physicalRoot := "/v1/" + fixture.v2 + "data/allowed/hardening-replace-" + conflictKey + "/"
			var writes atomic.Int32
			var injected, hookFailed atomic.Bool
			proxied := hardeningIntegrationProxy(t, func(proxy *httputil.ReverseProxy) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasPrefix(r.URL.Path, physicalRoot) && (r.Method == http.MethodPost || r.Method == http.MethodPut) {
						writes.Add(1)
						if r.URL.Path == physicalRoot+conflictKey && injected.CompareAndSwap(false, true) {
							hookContext, stop := context.WithTimeout(context.Background(), 5*time.Second)
							_, hookErr := fixture.admin.Logical().WriteWithContext(hookContext, strings.TrimPrefix(r.URL.Path, "/v1/"), map[string]any{
								"data": newer, "options": map[string]any{"cas": 1},
							})
							stop()
							hookFailed.Store(hookErr != nil)
						}
					}
					proxy.ServeHTTP(w, r)
				})
			})
			report, err := proxied.Replace(ctx, writer, root, old, replacement, vault.BulkOptions{RecursiveOptions: vault.RecursiveOptions{Concurrency: 1}})
			if !errors.Is(err, vault.ErrConflict) || errors.Is(err, vault.ErrBulkPartial) != (conflictIndex > 0) {
				t.Fatal("replacement lost its CAS conflict or confirmed partial-change classification")
			}
			if !injected.Load() || hookFailed.Load() || writes.Load() != int32(conflictIndex+1) || len(report.Items) != 3 {
				t.Fatal("replacement retried a stale snapshot or continued after its first conflict")
			}
			requireAdvancedSafeReport(t, report, writer)
			for index, key := range []string{"a", "b", "c"} {
				want, status, version := old, "not_started", 1
				switch {
				case index < conflictIndex:
					want, status, version = replacement, "written", 2
				case index == conflictIndex:
					want, status, version = newer, "failed", 2
					if report.Items[index].Error != "conflict" {
						t.Fatal("replacement conflict report lost its safe failure category")
					}
				}
				if report.Items[index].Path != root+"/"+key || report.Items[index].Status != status {
					t.Fatal("replacement did not retain deterministic status for every planned key")
				}
				requireIntegrationValues(t, ctx, client, writer, root+"/"+key, want)
				history, historyErr := client.Versions(ctx, writer, root+"/"+key, vault.KVOptions{})
				if historyErr != nil || history.CurrentVersion != version || len(history.Versions) != version {
					t.Fatal("replacement retried, overwrote concurrent data, or rolled back a confirmed change")
				}
			}
		})
	}
}

func TestIntegrationRestoreDoesNotResurrectDeletedOrDestroyedDestinations(t *testing.T) {
	fixture := prepareKVIntegrationFixture(t)
	writer := createKVIntegrationPolicyToken(t, fixture.admin, fmt.Sprintf("secretwright-hardening-restore-%d", time.Now().UnixNano()), integrationWritePolicy(fixture))
	client := newWriteIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, destroyed := range []bool{false, true} {
		name := "soft-deleted"
		if destroyed {
			name = "destroyed"
		}
		t.Run(name, func(t *testing.T) {
			root := "/" + fixture.v2 + "allowed/hardening-restore-" + name
			target := root + "/a"
			if _, err := client.Put(ctx, writer, target, advancedIntegrationValues("restore-old"), vault.WriteOptions{}); err != nil {
				t.Fatal("could not seed the tombstoned restore destination")
			}
			if destroyed {
				if _, err := client.Destroy(ctx, writer, target, []int{1}, vault.WriteOptions{Force: true}); err != nil {
					t.Fatal("could not destroy the restore destination revision")
				}
			} else if _, err := client.Remove(ctx, writer, target, nil, vault.WriteOptions{}); err != nil {
				t.Fatal("could not soft-delete the restore destination revision")
			}
			before, err := client.Versions(ctx, writer, target, vault.KVOptions{})
			if err != nil || before.CurrentVersion != 1 || len(before.Versions) != 1 || before.Versions[0].Destroyed != destroyed || (!destroyed && before.Versions[0].DeletionTime == "") {
				t.Fatal("could not observe the tombstone before restore")
			}
			archive := vault.Archive{Format: "secretwright-kv", Version: 1, Root: "/unrelated-source", Entries: []vault.ArchiveEntry{
				{Path: "a", Data: advancedIntegrationValues("restore-new")},
				{Path: "b", Data: advancedIntegrationValues("must-not-start")},
			}}
			report, err := client.Restore(ctx, writer, root, archive, vault.BulkOptions{RecursiveOptions: vault.RecursiveOptions{Concurrency: 1}})
			if !errors.Is(err, vault.ErrConflict) || errors.Is(err, vault.ErrBulkPartial) || len(report.Items) != 2 || report.Items[0].Status != "failed" || report.Items[0].Error != "conflict" || report.Items[1].Status != "not_started" {
				t.Fatal("restore treated a tombstoned destination as an unused create-only key")
			}
			requireAdvancedSafeReport(t, report, writer)
			after, err := client.Versions(ctx, writer, target, vault.KVOptions{})
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("restore changed or erased an existing tombstone's revision history")
			}
			for _, path := range []string{target, root + "/b"} {
				if _, err := client.Read(ctx, writer, path, vault.KVOptions{}); !errors.Is(err, vault.ErrNotFound) {
					t.Fatal("restore resurrected a tombstone or dispatched a later key after conflict")
				}
			}
		})
	}
}

func TestIntegrationMoveWithAppliedButLostCopyAcknowledgementKeepsItsSource(t *testing.T) {
	fixture := prepareKVIntegrationFixture(t)
	writer := createKVIntegrationPolicyToken(t, fixture.admin, fmt.Sprintf("secretwright-hardening-move-%d", time.Now().UnixNano()), integrationWritePolicy(fixture))
	client := newWriteIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	source := "/" + fixture.v2 + "allowed/hardening-uncertain-source"
	destination := "/" + fixture.nested + "allowed/hardening-uncertain-destination"
	values := integrationValues("uncertain-real-write")
	if _, err := client.Put(ctx, writer, source, values, vault.WriteOptions{}); err != nil {
		t.Fatal("could not seed the uncertain-move source")
	}
	physicalDestination := "/v1/" + fixture.nested + "data/allowed/hardening-uncertain-destination"
	var writes, otherMutations atomic.Int32
	var applied atomic.Bool
	proxied := hardeningIntegrationProxy(t, func(proxy *httputil.ReverseProxy) http.Handler {
		proxy.ModifyResponse = func(response *http.Response) error {
			if response.Request.URL.Path == physicalDestination && (response.Request.Method == http.MethodPost || response.Request.Method == http.MethodPut) && response.StatusCode >= 200 && response.StatusCode < 300 {
				applied.Store(true)
				return errors.New("discard the private mutation acknowledgement")
			}
			return nil
		}
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, _ error) {
			if r.URL.Path == physicalDestination && applied.Load() {
				loseKVMutationResponse(t, w)
				return
			}
			w.WriteHeader(http.StatusBadGateway)
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
				if r.URL.Path == physicalDestination {
					writes.Add(1)
				} else {
					otherMutations.Add(1)
				}
			}
			proxy.ServeHTTP(w, r)
		})
	})
	report, err := proxied.Move(ctx, writer, source, destination, vault.WriteOptions{})
	if err == nil || !strings.Contains(err.Error(), "not confirmed") || errors.Is(err, vault.ErrPartial) || report != (vault.CopyResult{}) {
		t.Fatal("move claimed a confirmed destination after losing its actual write acknowledgement")
	}
	if !applied.Load() || writes.Load() != 1 || otherMutations.Load() != 0 {
		t.Fatal("uncertain move retried, deleted its source, or rolled back its destination")
	}
	requireSafeMutationReport(t, report, writer)
	for _, path := range []string{source, destination} {
		requireIntegrationValues(t, ctx, client, writer, path, values)
		history, historyErr := client.Versions(ctx, writer, path, vault.KVOptions{})
		if historyErr != nil || history.CurrentVersion != 1 || len(history.Versions) != 1 || history.Versions[0].DeletionTime != "" || history.Versions[0].Destroyed {
			t.Fatal("uncertain move changed either path after its one applied destination write")
		}
	}
}
