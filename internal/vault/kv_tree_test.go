package vault_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/vault"
)

type advancedSecret struct {
	data    map[string]any
	version int
}

// replyAdvancedRead handles only discovery, LIST and current data reads. A
// caller must explicitly handle every mutation after this returns false.
func replyAdvancedRead(t *testing.T, w http.ResponseWriter, r *http.Request, lists map[string][]string, secrets map[string]advancedSecret) bool {
	t.Helper()
	assertKVWriteCredentials(t, r, "selected-token")
	if strings.HasPrefix(r.URL.Path, "/v1/sys/internal/ui/mounts/") && r.Method == http.MethodGet {
		logical := strings.TrimPrefix(r.URL.Path, "/v1/sys/internal/ui/mounts")
		switch {
		case logical == "/legacy" || strings.HasPrefix(logical, "/legacy/"):
			kvReply(w, kvMountMetadata("legacy/", "1"))
		case logical == "/teams/dev/kv" || strings.HasPrefix(logical, "/teams/dev/kv/"):
			kvReply(w, kvMountMetadata("teams/dev/kv/", "2"))
		case logical == "/secret" || strings.HasPrefix(logical, "/secret/"):
			kvReply(w, kvMountMetadata("secret/", "2"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
		return true
	}
	if kvOperation(r) == "LIST" {
		names, ok := lists[r.URL.Path]
		if !ok {
			return false
		}
		kvReply(w, map[string]any{"keys": names})
		return true
	}
	if r.Method != http.MethodGet {
		return false
	}
	secret, ok := secrets[r.URL.Path]
	if !ok {
		return false
	}
	if strings.HasPrefix(r.URL.Path, "/v1/legacy/") {
		kvReply(w, secret.data)
	} else {
		revision := secret.version
		if revision == 0 {
			revision = 7
		}
		kvReply(w, map[string]any{"data": secret.data, "metadata": map[string]any{"version": revision}})
	}
	return true
}

func explicitRecursive(mount string, version, concurrency int) vault.RecursiveOptions {
	return vault.RecursiveOptions{KVOptions: vault.KVOptions{Mount: mount, Version: version}, Concurrency: concurrency}
}

func TestWalkUsesOnlyLISTAndPreservesAKeyBesideItsSubtree(t *testing.T) {
	lists := map[string][]string{
		"/v1/teams/dev/kv/metadata/app":     {"z", "foo/", "a/", "foo", "foo/"},
		"/v1/teams/dev/kv/metadata/app/a":   {"item"},
		"/v1/teams/dev/kv/metadata/app/foo": {"bar"},
	}
	var dataReads atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assertKVReadOnlyRequest(t, r, "selected-token")
		if strings.Contains(r.URL.Path, "/data/") {
			dataReads.Add(1)
		}
		if !replyAdvancedRead(t, w, r, lists, nil) {
			t.Errorf("tree accessed an unexpected endpoint: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	options := explicitRecursive("teams/dev/kv", 2, 3)
	options.CWD = "/teams/dev/kv"
	result, err := client.Walk(context.Background(), "selected-token", "./app", options)
	if err != nil {
		t.Fatalf("walk nested mount: %v", err)
	}
	if result.Root != "/teams/dev/kv/app" || dataReads.Load() != 0 {
		t.Error("tree lost its canonical root or read secret values")
	}
	got := make(map[string]bool)
	paths := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		if strings.HasSuffix(entry.Path, "/") {
			t.Error("tree encoded type in the path instead of the directory field")
		}
		got[fmt.Sprintf("%s:%t", entry.Path, entry.Directory)] = true
		paths = append(paths, entry.Path)
	}
	want := map[string]bool{
		"/teams/dev/kv/app/a:true":        true,
		"/teams/dev/kv/app/a/item:false":  true,
		"/teams/dev/kv/app/foo:false":     true,
		"/teams/dev/kv/app/foo:true":      true,
		"/teams/dev/kv/app/foo/bar:false": true,
		"/teams/dev/kv/app/z:false":       true,
	}
	if !reflect.DeepEqual(got, want) || len(result.Entries) != len(want) || !sort.StringsAreSorted(paths) {
		t.Error("tree collapsed a key/subtree pair, duplicated names, or changed deterministic order")
	}
}

func TestWalkRejectsADeniedSubtreeAndMalformedNames(t *testing.T) {
	for _, test := range []struct {
		name      string
		names     []string
		denyChild bool
	}{
		{name: "denied directory", names: []string{"allowed", "denied/"}, denyChild: true},
		{name: "traversal response", names: []string{"../private"}},
		{name: "nested response segment", names: []string{"child/item"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				assertKVReadOnlyRequest(t, r, "selected-token")
				if r.URL.Path == "/v1/secret/metadata/app" {
					kvReply(w, map[string]any{"keys": test.names})
				} else if test.denyChild && r.URL.Path == "/v1/secret/metadata/app/denied" {
					http.Error(w, "upstream-private-value", http.StatusForbidden)
				} else {
					t.Error("tree requested a path not returned as an immediate directory")
					w.WriteHeader(http.StatusNotFound)
				}
			})
			_, err := client.Walk(context.Background(), "selected-token", "/secret/app", explicitRecursive("secret", 2, 2))
			assertKVSafeError(t, err)
			if test.denyChild && !errors.Is(err, vault.ErrPermissionDenied) {
				t.Error("denied recursive LIST was presented as an empty successful tree")
			}
		})
	}
}

func TestWalkBoundsEntriesDepthAndRejectsInvalidOptionsBeforeRequests(t *testing.T) {
	t.Run("entry bound", func(t *testing.T) {
		names := make([]string, vault.MaxTreeEntries+1)
		for i := range names {
			names[i] = fmt.Sprintf("key-%05d", i)
		}
		client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if kvOperation(r) != "LIST" {
				t.Error("entry limit required reading values")
			}
			kvReply(w, map[string]any{"keys": names})
		})
		_, err := client.Walk(context.Background(), "selected-token", "/secret/app", explicitRecursive("secret", 2, 1))
		if !errors.Is(err, vault.ErrTraversalLimit) {
			t.Errorf("oversized tree error = %v, want traversal limit", err)
		}
	})
	t.Run("depth bound", func(t *testing.T) {
		var requests atomic.Int32
		client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			kvReply(w, map[string]any{"keys": []string{"next/"}})
		})
		_, err := client.Walk(context.Background(), "selected-token", "/secret/app", explicitRecursive("secret", 2, 1))
		if !errors.Is(err, vault.ErrTraversalLimit) || requests.Load() > int32(vault.MaxTreeDepth+2) {
			t.Error("recursive tree escaped its depth bound")
		}
	})
	for _, concurrency := range []int{-1, vault.MaxConcurrency + 1} {
		t.Run(fmt.Sprintf("concurrency %d", concurrency), func(t *testing.T) {
			var requests atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			})
			_, err := client.Walk(context.Background(), "selected-token", "/secret/app", explicitRecursive("secret", 2, concurrency))
			if err == nil || requests.Load() != 0 {
				t.Error("invalid worker count contacted Vault")
			}
		})
	}
}

func TestFindReadsInABoundedPoolAndComparesCompleteJSONObjects(t *testing.T) {
	lists := map[string][]string{"/v1/secret/metadata/app": {"d", "b", "a", "c"}}
	secrets := map[string]advancedSecret{
		"/v1/secret/data/app/a": {data: map[string]any{"number": json.Number("1.00"), "nested": []any{true, "fixture-secret-value"}}},
		"/v1/secret/data/app/b": {data: map[string]any{"number": json.Number("1e0"), "nested": []any{true, "fixture-secret-value"}}},
		"/v1/secret/data/app/c": {data: map[string]any{"number": json.Number("1"), "nested": []any{true, "fixture-secret-value"}, "extra": true}},
		"/v1/secret/data/app/d": {data: map[string]any{"number": json.Number("2"), "nested": []any{true, "fixture-secret-value"}}},
	}
	release := make(chan struct{})
	var once sync.Once
	var active, maximum atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/data/") {
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
		}
		if !replyAdvancedRead(t, w, r, lists, secrets) {
			t.Error("find used an unexpected endpoint")
			w.WriteHeader(http.StatusNotFound)
		}
	}, vault.Options{Timeout: durationPointer(time.Second)})
	match := map[string]any{"nested": []any{true, "fixture-secret-value"}, "number": json.Number("1")}
	result, err := client.Find(context.Background(), "selected-token", "/secret/app", match, explicitRecursive("secret", 2, 2))
	if err != nil {
		t.Fatalf("find structurally equal complete objects: %v", err)
	}
	if maximum.Load() != 2 || !reflect.DeepEqual(result, []string{"/secret/app/a", "/secret/app/b"}) {
		t.Error("find lost bounded concurrency, numeric equality, exact object matching, or sorted paths")
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "fixture-secret-value") {
		t.Error("find returned secret values")
	}
}

func TestFindComparesHugeExponentsWithoutFloatOrExponentExpansion(t *testing.T) {
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		lists := map[string][]string{"/v1/legacy/app": {"a", "b"}}
		secrets := map[string]advancedSecret{
			"/v1/legacy/app/a": {data: map[string]any{"n": json.Number("10e999999")}},
			"/v1/legacy/app/b": {data: map[string]any{"n": json.Number("2e1000000")}},
		}
		if !replyAdvancedRead(t, w, r, lists, secrets) {
			t.Error("unexpected huge-number comparison request")
			w.WriteHeader(http.StatusNotFound)
		}
	})
	start := time.Now()
	result, err := client.Find(context.Background(), "selected-token", "/legacy/app", map[string]any{"n": json.Number("1e1000000")}, explicitRecursive("legacy", 1, 1))
	if err != nil || !reflect.DeepEqual(result, []string{"/legacy/app/a"}) || time.Since(start) > time.Second {
		t.Error("find lost exact large-number semantics or expanded an exponent")
	}
}

func TestDataTraversalFailsOnMissingOrDeniedCurrentSecrets(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden} {
		t.Run(fmt.Sprintf("HTTP %d", status), func(t *testing.T) {
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/secret/metadata/app" && kvOperation(r) == "LIST" {
					kvReply(w, map[string]any{"keys": []string{"current", "deleted"}})
				} else if r.URL.Path == "/v1/secret/data/app/current" && r.Method == http.MethodGet {
					kvReply(w, map[string]any{"data": map[string]any{"value": "fixture-secret-value"}, "metadata": map[string]any{"version": 4}})
				} else if r.URL.Path == "/v1/secret/data/app/deleted" && r.Method == http.MethodGet {
					http.Error(w, "upstream-private-value", status)
				} else {
					t.Error("data traversal mutated state or fell back to an older version")
					w.WriteHeader(http.StatusInternalServerError)
				}
			})
			options := explicitRecursive("secret", 2, 2)
			_, err := client.Backup(context.Background(), "selected-token", "/secret/app", options)
			assertKVSafeError(t, err)
			want := vault.ErrNotFound
			if status == http.StatusForbidden {
				want = vault.ErrPermissionDenied
			}
			if !errors.Is(err, want) {
				t.Error("backup silently omitted an unreadable current secret")
			}
		})
	}
}

func TestBackupPreservesBothLeafAndNestedRelativeKeys(t *testing.T) {
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		lists := map[string][]string{
			"/v1/legacy/app":     {"foo/", "foo"},
			"/v1/legacy/app/foo": {"bar"},
		}
		secrets := map[string]advancedSecret{
			"/v1/legacy/app/foo":     {data: map[string]any{"n": json.Number("9007199254740993123456789")}},
			"/v1/legacy/app/foo/bar": {data: map[string]any{"value": "fixture-secret-value"}},
		}
		if !replyAdvancedRead(t, w, r, lists, secrets) {
			t.Error("backup requested metadata history or an unexpected endpoint")
			w.WriteHeader(http.StatusNotFound)
		}
	})
	archive, err := client.Backup(context.Background(), "selected-token", "/legacy/app", explicitRecursive("legacy", 1, 2))
	if err != nil {
		t.Fatalf("backup current snapshots: %v", err)
	}
	if archive.Format != "secretwright-kv" || archive.Version != 1 || archive.Root != "/legacy/app" || len(archive.Entries) != 2 {
		t.Fatal("backup did not identify a complete current-value archive")
	}
	if archive.Entries[0].Path != "foo" || archive.Entries[1].Path != "foo/bar" || archive.Entries[0].Data["n"] != json.Number("9007199254740993123456789") {
		t.Error("backup collapsed a leaf/subtree pair or lost KV v1 numeric precision")
	}
}

func TestRecursiveDeadlineBoundsTheWholeTraversalAndHonorsCancellation(t *testing.T) {
	t.Run("whole operation deadline", func(t *testing.T) {
		client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(40 * time.Millisecond):
				kvReply(w, map[string]any{"keys": []string{"next/"}})
			case <-r.Context().Done():
			}
		}, vault.Options{Timeout: durationPointer(70 * time.Millisecond)})
		start := time.Now()
		_, err := client.Walk(context.Background(), "selected-token", "/secret/app", explicitRecursive("secret", 2, 1))
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 500*time.Millisecond {
			t.Error("recursive operation reset its deadline for each directory")
		}
	})
	t.Run("already canceled", func(t *testing.T) {
		var requests atomic.Int32
		client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
		})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := client.Walk(ctx, "selected-token", "/secret/app", explicitRecursive("secret", 2, 2))
		if !errors.Is(err, context.Canceled) || requests.Load() != 0 {
			t.Error("canceled traversal contacted Vault or ignored cancellation")
		}
	})
}

func TestWalkOnlyTreatsAProvenEmptyMountAsAnEmptyDirectory(t *testing.T) {
	for _, test := range []struct {
		name    string
		target  string
		options vault.RecursiveOptions
		status  int
		empty   bool
	}{
		{name: "discovered mount", target: "/secret", status: http.StatusNotFound, empty: true},
		{name: "explicit selection is not proof", target: "/secret", options: explicitRecursive("secret", 2, 1), status: http.StatusNotFound},
		{name: "missing child directory", target: "/secret/missing", status: http.StatusNotFound},
		{name: "denied mount", target: "/secret", status: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/v1/sys/internal/ui/mounts/") {
					kvReply(w, kvMountMetadata("secret/", "2"))
				} else if kvOperation(r) == "LIST" {
					w.WriteHeader(test.status)
				} else {
					t.Error("empty tree read values or mutated state")
					w.WriteHeader(http.StatusInternalServerError)
				}
			})
			result, err := client.Walk(context.Background(), "selected-token", test.target, test.options)
			if test.empty {
				if err != nil || result.Root != "/secret" || result.Entries == nil || len(result.Entries) != 0 {
					t.Error("a discovered empty real mount was not represented as a complete empty tree")
				}
			} else if err == nil {
				t.Error("an unproven missing or denied directory became a successful empty tree")
			}
		})
	}
}
