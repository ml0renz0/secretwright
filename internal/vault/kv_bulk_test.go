package vault_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/vault"
)

func assertBulkMetadata(t *testing.T, result vault.BulkResult) {
	t.Helper()
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("encode bulk metadata: %v", err)
	}
	for _, forbidden := range []string{"fixture-secret-value", "private-replacement-value", "selected-token", "upstream-private-value", "\"data\"", "\"match\"", "\"replacement\""} {
		if strings.Contains(string(encoded), forbidden) {
			t.Error("bulk report exposed secret inputs, values or server content")
		}
	}
}

func TestReplaceUsesTheCapturedRevisionAndAvoidsUnchangedWrites(t *testing.T) {
	for _, unchanged := range []bool{false, true} {
		name := "replace matching full object"
		if unchanged {
			name = "identical replacement is unchanged"
		}
		t.Run(name, func(t *testing.T) {
			lists := map[string][]string{"/v1/secret/metadata/app": {"a", "b"}}
			original := map[string]any{"n": json.Number("1.00"), "value": "fixture-secret-value"}
			secrets := map[string]advancedSecret{
				"/v1/secret/data/app/a": {data: original, version: 7},
				"/v1/secret/data/app/b": {data: map[string]any{"n": json.Number("1"), "value": "fixture-secret-value", "extra": true}, version: 9},
			}
			var writes atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if replyAdvancedRead(t, w, r, lists, secrets) {
					return
				}
				if r.URL.Path != "/v1/secret/data/app/a" || (r.Method != http.MethodPost && r.Method != http.MethodPut) {
					t.Error("replace modified an unmatched object or used an unexpected endpoint")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				writes.Add(1)
				body := kvWriteBody(t, r)
				options, _ := body["options"].(map[string]any)
				if options["cas"] != json.Number("7") || !reflect.DeepEqual(body["data"], map[string]any{"new": "private-replacement-value"}) {
					t.Error("replace did not write the full replacement with captured revision CAS")
				}
				kvReply(w, map[string]any{"version": 8})
			})
			match := map[string]any{"value": "fixture-secret-value", "n": json.Number("1")}
			replacement := map[string]any{"new": "private-replacement-value"}
			if unchanged {
				replacement = map[string]any{"value": "fixture-secret-value", "n": json.Number("1e0")}
			}
			result, err := client.Replace(context.Background(), "selected-token", "/secret/app", match, replacement, vault.BulkOptions{RecursiveOptions: explicitRecursive("secret", 2, 1)})
			if err != nil || len(result.Items) != 1 {
				t.Fatalf("replace full object: result=%#v error=%v", result, err)
			}
			if unchanged {
				if writes.Load() != 0 || result.Items[0].Status != "unchanged" {
					t.Error("an identical semantic replacement created a new revision")
				}
			} else if writes.Load() != 1 || result.Items[0].Status != "written" || result.Items[0].Version != 8 {
				t.Error("replace did not confirm its one changed matching object")
			}
			assertBulkMetadata(t, result)
		})
	}
}

func TestCopyTreePlansAllReadsBeforeCreateOnlyWrites(t *testing.T) {
	lists := map[string][]string{
		"/v1/secret/metadata/source":     {"foo/", "foo", "z"},
		"/v1/secret/metadata/source/foo": {"bar"},
	}
	secrets := map[string]advancedSecret{
		"/v1/secret/data/source/foo":     {data: map[string]any{"value": "fixture-secret-value"}},
		"/v1/secret/data/source/foo/bar": {data: map[string]any{"value": "fixture-secret-value"}},
		"/v1/secret/data/source/z":       {data: map[string]any{"value": "fixture-secret-value"}},
	}
	var reads atomic.Int32
	var pathsMu sync.Mutex
	var written []string
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/secret/data/source/") {
			reads.Add(1)
		}
		if replyAdvancedRead(t, w, r, lists, secrets) {
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/v1/secret/data/destination/") || (r.Method != http.MethodPost && r.Method != http.MethodPut) {
			t.Error("copy tree deleted a source or accessed a path outside the destination")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if reads.Load() != int32(len(secrets)) {
			t.Error("copy tree started mutating before completing every source read")
		}
		body := kvWriteBody(t, r)
		if !reflect.DeepEqual(body, map[string]any{"data": map[string]any{"value": "fixture-secret-value"}, "options": map[string]any{"cas": json.Number("0")}}) {
			t.Error("copy tree bypassed create-only CAS or changed the copied object")
		}
		pathsMu.Lock()
		written = append(written, r.URL.Path)
		pathsMu.Unlock()
		kvReply(w, map[string]any{"version": 1})
	})
	result, err := client.CopyTree(context.Background(), "selected-token", "/secret/source", "/secret/destination", vault.BulkOptions{RecursiveOptions: explicitRecursive("secret", 2, 1)})
	if err != nil {
		t.Fatalf("copy directory contents: %v", err)
	}
	want := []string{"/v1/secret/data/destination/foo", "/v1/secret/data/destination/foo/bar", "/v1/secret/data/destination/z"}
	if !reflect.DeepEqual(written, want) || len(result.Items) != len(want) {
		t.Error("copy tree changed relative key mapping or collapsed a leaf/subtree pair")
	}
	for _, item := range result.Items {
		if item.Status != "written" || !strings.HasPrefix(item.Destination, "/secret/destination/") {
			t.Error("copy tree report did not describe its confirmed destination")
		}
	}
	assertBulkMetadata(t, result)
}

func TestCopyTreeRejectsOverlappingRootsAndPreflightsNumericLoss(t *testing.T) {
	for _, destination := range []string{"/", "/secret/source", "/secret/source/child", "/secret"} {
		t.Run(destination, func(t *testing.T) {
			var requests atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			})
			_, err := client.CopyTree(context.Background(), "selected-token", "/secret/source", destination, vault.BulkOptions{RecursiveOptions: explicitRecursive("secret", 2, 1)})
			if !errors.Is(err, vault.ErrInvalidPath) || requests.Load() != 0 {
				t.Error("overlapping recursive roots contacted Vault")
			}
		})
	}
	t.Run("complete numeric preflight", func(t *testing.T) {
		var writes atomic.Int32
		client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			lists := map[string][]string{"/v1/legacy/source": {"a", "b"}}
			secrets := map[string]advancedSecret{
				"/v1/legacy/source/a": {data: map[string]any{"value": "fixture-secret-value"}},
				"/v1/legacy/source/b": {data: map[string]any{"n": json.Number("9007199254740993")}},
			}
			if replyAdvancedRead(t, w, r, lists, secrets) {
				return
			}
			writes.Add(1)
			kvReply(w, map[string]any{"version": 1})
		})
		_, err := client.CopyTree(context.Background(), "selected-token", "/legacy/source", "/secret/destination", vault.BulkOptions{RecursiveOptions: vault.RecursiveOptions{Concurrency: 1}})
		if !errors.Is(err, vault.ErrInvalidData) || writes.Load() != 0 {
			t.Error("a later inexact number was discovered only after an earlier key had been written")
		}
	})
}

func TestRemoveTreeDeletesCapturedVersionsWithoutDestroyingMetadata(t *testing.T) {
	var deletes atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		lists := map[string][]string{"/v1/secret/metadata/app": {"a"}}
		secrets := map[string]advancedSecret{"/v1/secret/data/app/a": {data: map[string]any{"value": "fixture-secret-value"}, version: 7}}
		if replyAdvancedRead(t, w, r, lists, secrets) {
			return
		}
		if r.URL.Path != "/v1/secret/delete/app/a" || r.Method != http.MethodPost {
			t.Error("recursive removal deleted current data, destroyed revisions, or removed metadata")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		deletes.Add(1)
		if !reflect.DeepEqual(kvWriteBody(t, r), map[string]any{"versions": []any{json.Number("7")}}) {
			t.Error("recursive removal did not target only the revision captured before a concurrent newer write")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	result, err := client.RemoveTree(context.Background(), "selected-token", "/secret/app", vault.BulkOptions{RecursiveOptions: explicitRecursive("secret", 2, 1)})
	if err != nil || deletes.Load() != 1 || len(result.Items) != 1 || result.Items[0].Status != "deleted" {
		t.Error("recursive deletion failed to report its one confirmed captured-version removal")
	}
	assertBulkMetadata(t, result)
}

func TestRecursiveMutationsRejectDeniedPreflightWithoutAnyWrite(t *testing.T) {
	for _, operation := range []string{"replace", "copy", "remove"} {
		t.Run(operation, func(t *testing.T) {
			var mutations atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if kvOperation(r) == "LIST" && r.URL.Path == "/v1/secret/metadata/source" {
					kvReply(w, map[string]any{"keys": []string{"a", "denied"}})
				} else if r.Method == http.MethodGet && r.URL.Path == "/v1/secret/data/source/a" {
					kvReply(w, map[string]any{"data": map[string]any{"value": "fixture-secret-value"}, "metadata": map[string]any{"version": 7}})
				} else if r.Method == http.MethodGet && r.URL.Path == "/v1/secret/data/source/denied" {
					http.Error(w, "upstream-private-value", http.StatusForbidden)
				} else {
					mutations.Add(1)
					w.WriteHeader(http.StatusInternalServerError)
				}
			})
			options := vault.BulkOptions{RecursiveOptions: explicitRecursive("secret", 2, 1)}
			var result vault.BulkResult
			var err error
			switch operation {
			case "replace":
				result, err = client.Replace(context.Background(), "selected-token", "/secret/source", map[string]any{"value": "fixture-secret-value"}, map[string]any{"new": true}, options)
			case "copy":
				result, err = client.CopyTree(context.Background(), "selected-token", "/secret/source", "/secret/destination", options)
			case "remove":
				result, err = client.RemoveTree(context.Background(), "selected-token", "/secret/source", options)
			}
			if !errors.Is(err, vault.ErrPermissionDenied) || mutations.Load() != 0 || len(result.Items) != 0 {
				t.Error("recursive mutation changed a readable key before discovering a denied source")
			}
			assertKVSafeError(t, err)
		})
	}
}

func testArchive(entries ...vault.ArchiveEntry) vault.Archive {
	return vault.Archive{Format: "secretwright-kv", Version: 1, Root: "/legacy/backup", Entries: entries}
}

func TestRestoreValidatesEveryArchiveEntryBeforeContactingVault(t *testing.T) {
	for _, archive := range []vault.Archive{
		testArchive(vault.ArchiveEntry{Path: "a", Data: map[string]any{"value": true}}, vault.ArchiveEntry{Path: "../escape", Data: map[string]any{"value": true}}),
		testArchive(vault.ArchiveEntry{Path: "a", Data: map[string]any{"value": true}}, vault.ArchiveEntry{Path: "a", Data: map[string]any{"value": false}}),
		testArchive(vault.ArchiveEntry{Path: "a", Data: map[string]any{}}),
	} {
		var requests atomic.Int32
		client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
		})
		_, err := client.Restore(context.Background(), "selected-token", "/secret/restored", archive, vault.BulkOptions{RecursiveOptions: explicitRecursive("secret", 2, 1)})
		if !errors.Is(err, vault.ErrInvalidArchive) || requests.Load() != 0 {
			t.Error("restore contacted Vault before rejecting the complete malformed archive")
		}
	}
}

func TestRestoreCreatesOnlyWithCASZeroAndNeverCreatesMounts(t *testing.T) {
	archive := testArchive(
		vault.ArchiveEntry{Path: "foo/bar", Data: map[string]any{"value": "fixture-secret-value"}},
		vault.ArchiveEntry{Path: "foo", Data: map[string]any{"value": "fixture-secret-value"}},
	)
	var written []string
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if replyAdvancedRead(t, w, r, nil, nil) {
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/v1/secret/data/restored/") || (r.Method != http.MethodPost && r.Method != http.MethodPut) {
			t.Error("restore created a mount, trusted archive routing, or used an unexpected endpoint")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		body := kvWriteBody(t, r)
		options, _ := body["options"].(map[string]any)
		if options["cas"] != json.Number("0") {
			t.Error("restore can overwrite an existing KV v2 revision")
		}
		written = append(written, r.URL.Path)
		kvReply(w, map[string]any{"version": 1})
	})
	result, err := client.Restore(context.Background(), "selected-token", "/secret/restored", archive, vault.BulkOptions{RecursiveOptions: explicitRecursive("secret", 2, 1)})
	if err != nil || !reflect.DeepEqual(written, []string{"/v1/secret/data/restored/foo", "/v1/secret/data/restored/foo/bar"}) {
		t.Error("restore changed relative paths, sorted ordering, or leaf/subtree coexistence")
	}
	assertBulkMetadata(t, result)
}

func TestBulkKV1WritesAndDeletesRequireForceAndPreserveExactData(t *testing.T) {
	for _, operation := range []string{"restore", "replace", "remove"} {
		for _, force := range []bool{false, true} {
			name := operation + " guarded"
			if force {
				name = operation + " forced"
			}
			t.Run(name, func(t *testing.T) {
				var mutations atomic.Int32
				value := map[string]any{"n": json.Number("9007199254740993123456789")}
				client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
					lists := map[string][]string{"/v1/legacy/app": {"a"}}
					secrets := map[string]advancedSecret{"/v1/legacy/app/a": {data: value}}
					if replyAdvancedRead(t, w, r, lists, secrets) {
						return
					}
					mutations.Add(1)
					if r.URL.Path != "/v1/legacy/app/a" {
						t.Error("KV v1 bulk operation used a versioned API route")
					}
					if operation == "remove" {
						if r.Method != http.MethodDelete {
							t.Error("forced KV v1 removal did not permanently delete its selected key")
						}
					} else {
						body := kvWriteBody(t, r)
						want := value
						if operation == "replace" {
							want = map[string]any{"n": json.Number("9007199254740993123456789"), "changed": true}
						}
						if !reflect.DeepEqual(body, want) {
							t.Error("KV v1 bulk write lost an exact number or sent a KV v2 envelope")
						}
					}
					w.WriteHeader(http.StatusNoContent)
				})
				options := vault.BulkOptions{RecursiveOptions: explicitRecursive("legacy", 1, 1), Force: force}
				var err error
				switch operation {
				case "restore":
					_, err = client.Restore(context.Background(), "selected-token", "/legacy/app", testArchive(vault.ArchiveEntry{Path: "a", Data: value}), options)
				case "replace":
					_, err = client.Replace(context.Background(), "selected-token", "/legacy/app", value, map[string]any{"n": json.Number("9007199254740993123456789"), "changed": true}, options)
				case "remove":
					_, err = client.RemoveTree(context.Background(), "selected-token", "/legacy/app", options)
				}
				if !force {
					if !errors.Is(err, vault.ErrUnsupportedOperation) || mutations.Load() != 0 {
						t.Error("KV v1 bulk mutation ran without explicit force")
					}
				} else if err != nil || mutations.Load() != 1 {
					t.Error("an explicitly forced KV v1 operation did not complete exactly once")
				}
			})
		}
	}
}

func TestBulkStopsAfterAnExecutionFailureAndReportsConfirmedChanges(t *testing.T) {
	var writes atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if replyAdvancedRead(t, w, r, nil, nil) {
			return
		}
		writes.Add(1)
		switch r.URL.Path {
		case "/v1/secret/data/restored/a":
			kvReply(w, map[string]any{"version": 1})
		case "/v1/secret/data/restored/b":
			http.Error(w, "upstream-private-value", http.StatusForbidden)
		default:
			t.Error("bulk execution dispatched a later item after a failed mutation")
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	archive := testArchive(
		vault.ArchiveEntry{Path: "c", Data: map[string]any{"value": "fixture-secret-value"}},
		vault.ArchiveEntry{Path: "b", Data: map[string]any{"value": "fixture-secret-value"}},
		vault.ArchiveEntry{Path: "a", Data: map[string]any{"value": "fixture-secret-value"}},
	)
	result, err := client.Restore(context.Background(), "selected-token", "/secret/restored", archive, vault.BulkOptions{RecursiveOptions: explicitRecursive("secret", 2, 1)})
	if !errors.Is(err, vault.ErrBulkPartial) || !errors.Is(err, vault.ErrPermissionDenied) || writes.Load() != 2 {
		t.Error("bulk partial outcome lost its confirmed change or underlying denial")
	}
	if len(result.Items) != 3 || result.Items[0].Status != "written" || result.Items[1].Status != "failed" || result.Items[2].Status != "not_started" {
		t.Error("bulk partial report did not cover all planned items deterministically")
	}
	assertBulkMetadata(t, result)
	assertKVSafeError(t, err)
}

func TestBulkTreatsAnUnconfirmedMutationAsPartialWithoutRetry(t *testing.T) {
	var writes atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if replyAdvancedRead(t, w, r, nil, nil) {
			return
		}
		writes.Add(1)
		http.Error(w, "upstream-private-value", http.StatusInternalServerError)
	})
	result, err := client.Restore(context.Background(), "selected-token", "/secret/restored", testArchive(vault.ArchiveEntry{Path: "a", Data: map[string]any{"value": true}}), vault.BulkOptions{RecursiveOptions: explicitRecursive("secret", 2, 1)})
	if !errors.Is(err, vault.ErrBulkPartial) || writes.Load() != 1 || len(result.Items) != 1 || result.Items[0].Status != "unconfirmed" {
		t.Error("unconfirmed mutation was retried or falsely reported as unchanged")
	}
	assertBulkMetadata(t, result)
}

func TestBulkDryRunPerformsNoMutation(t *testing.T) {
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if replyAdvancedRead(t, w, r, nil, nil) {
			return
		}
		t.Error("dry-run sent a mutation")
		w.WriteHeader(http.StatusInternalServerError)
	})
	archive := testArchive(vault.ArchiveEntry{Path: "a", Data: map[string]any{"value": "fixture-secret-value"}})
	result, err := client.Restore(context.Background(), "selected-token", "/secret/restored", archive, vault.BulkOptions{RecursiveOptions: explicitRecursive("secret", 2, 1), DryRun: true})
	if err != nil || !result.DryRun || len(result.Items) != 1 || result.Items[0].Status != "planned" {
		t.Error("dry-run failed to return a metadata-only complete plan")
	}
	assertBulkMetadata(t, result)
}

func TestBulkWorkersAreBoundedAndJoinedBeforeReturning(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	var active, maximum, completed atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if replyAdvancedRead(t, w, r, nil, nil) {
			return
		}
		now := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); now > old && !maximum.CompareAndSwap(old, now); old = maximum.Load() {
		}
		if now == 2 {
			once.Do(func() { close(release) })
		}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		kvReply(w, map[string]any{"version": 1})
		completed.Add(1)
	}, vault.Options{Timeout: durationPointer(time.Second)})
	archive := testArchive(
		vault.ArchiveEntry{Path: "a", Data: map[string]any{"value": true}},
		vault.ArchiveEntry{Path: "b", Data: map[string]any{"value": true}},
		vault.ArchiveEntry{Path: "c", Data: map[string]any{"value": true}},
		vault.ArchiveEntry{Path: "d", Data: map[string]any{"value": true}},
	)
	result, err := client.Restore(context.Background(), "selected-token", "/secret/restored", archive, vault.BulkOptions{RecursiveOptions: explicitRecursive("secret", 2, 2)})
	if err != nil || maximum.Load() != 2 || active.Load() != 0 || completed.Load() != 4 || len(result.Items) != 4 {
		t.Error("bulk executor escaped its worker bound or returned before joining active requests")
	}
	assertBulkMetadata(t, result)
}
