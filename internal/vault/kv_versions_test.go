package vault_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/ml0renz0/secretwright/internal/vault"
)

func TestReadVersionUsesExactPositiveRevisionWithoutMetadataProjection(t *testing.T) {
	var requests atomic.Int32
	values := map[string]any{"value": "fixture-secret-value", "large": json.Number("9007199254740994")}
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assertKVReadOnlyRequest(t, r, "selected-token")
		if r.URL.Path != "/v1/teams/dev/kv/data/data/app" || r.URL.Query().Get("version") != "3" || len(r.URL.Query()) != 1 {
			t.Error("historical read did not request exactly the selected revision on the correct KV v2 route")
		}
		kvReply(w, map[string]any{"data": values, "metadata": map[string]any{"version": 3, "custom_metadata": map[string]any{"private": "upstream-private-value"}}})
	})
	got, err := client.ReadVersion(context.Background(), "selected-token", "/teams/dev/kv/data/app", 3, vault.KVOptions{Mount: "/teams/dev/kv", Version: 2})
	if err != nil {
		t.Fatalf("read exact historical revision: %v", err)
	}
	if !reflect.DeepEqual(got, values) {
		t.Error("historical read changed numeric precision or mixed metadata into values")
	}
	if requests.Load() != 1 {
		t.Error("explicit version and mount performed an unnecessary preflight")
	}
}

func TestVersionsProjectsOnlySortedPublicHistoryFields(t *testing.T) {
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assertKVReadOnlyRequest(t, r, "selected-token")
		if r.URL.Path != "/v1/secret/metadata/app" || r.URL.RawQuery != "" {
			t.Error("versions did not use the KV v2 metadata endpoint")
		}
		kvReply(w, map[string]any{
			"current_version": 9,
			"oldest_version":  2,
			"custom_metadata": map[string]any{"password": "fixture-secret-value"},
			"data":            map[string]any{"private": "fixture-secret-value"},
			"versions": map[string]any{
				"9": map[string]any{"created_time": "created-nine", "deletion_time": "", "destroyed": false, "private": "fixture-secret-value"},
				"2": map[string]any{"created_time": "created-two", "deletion_time": "deleted-two", "destroyed": false},
				"5": map[string]any{"created_time": "created-five", "deletion_time": "", "destroyed": true},
			},
		})
	})
	got, err := client.Versions(context.Background(), "selected-token", "/secret/app", vault.KVOptions{Mount: "/secret", Version: 2})
	if err != nil {
		t.Fatalf("read version history: %v", err)
	}
	want := vault.VersionHistory{
		Path:           "/secret/app",
		CurrentVersion: 9,
		OldestVersion:  2,
		Versions: []vault.VersionInfo{
			{Version: 2, CreatedTime: "created-two", DeletionTime: "deleted-two", Destroyed: false},
			{Version: 5, CreatedTime: "created-five", DeletionTime: "", Destroyed: true},
			{Version: 9, CreatedTime: "created-nine", DeletionTime: "", Destroyed: false},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("version history = %#v, want %#v", got, want)
	}
	assertKVResultFields(t, got, "path", "current_version", "oldest_version", "versions")
	for _, version := range got.Versions {
		assertKVResultFields(t, version, "version", "created_time", "deletion_time", "destroyed")
	}
}

func TestVersionRestorationAndDestructionUseOnlyExplicitRevisions(t *testing.T) {
	for _, destroy := range []bool{false, true} {
		name, route := "undelete", "/v1/secret/undelete/app"
		if destroy {
			name, route = "destroy", "/v1/secret/destroy/app"
		}
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				assertKVWriteCredentials(t, r, "selected-token")
				if r.URL.Path != route {
					t.Error("version operation used a data, latest, or metadata deletion endpoint")
				}
				if !reflect.DeepEqual(kvWriteBody(t, r), map[string]any{"versions": []any{json.Number("2"), json.Number("5")}}) {
					t.Error("version mutation did not send exactly the sorted unique requested revisions")
				}
				w.WriteHeader(http.StatusNoContent)
			})
			versions := []int{5, 2, 5}
			var result vault.MutationResult
			var err error
			if destroy {
				result, err = client.Destroy(context.Background(), "selected-token", "/secret/app", versions, vault.WriteOptions{KVOptions: vault.KVOptions{Mount: "/secret", Version: 2}, Force: true})
			} else {
				result, err = client.Undelete(context.Background(), "selected-token", "/secret/app", versions, vault.KVOptions{Mount: "/secret", Version: 2})
			}
			if err != nil {
				t.Fatalf("mutate selected historical revisions: %v", err)
			}
			if result.Path != "/secret/app" || result.KVVersion != 2 || !reflect.DeepEqual(result.Versions, []int{2, 5}) {
				t.Errorf("version mutation result = %#v", result)
			}
			if !reflect.DeepEqual(versions, []int{5, 2, 5}) {
				t.Error("version mutation modified the caller's revision slice")
			}
			if requests.Load() != 1 {
				t.Error("explicit revision mutation performed extra requests")
			}
			assertKVResultFields(t, result, "path", "kv_version", "versions")
		})
	}
}

func TestRollbackReadsCurrentMetadataBeforeOldDataAndCreatesNewVersionWithCAS(t *testing.T) {
	var stage atomic.Int32
	values := map[string]any{"value": "fixture-secret-value", "large": json.Number("9007199254740994")}
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assertKVWriteCredentials(t, r, "selected-token")
		switch stage.Add(1) {
		case 1:
			if r.Method != http.MethodGet || r.URL.Path != "/v1/secret/metadata/app" || r.URL.RawQuery != "" {
				t.Error("rollback did not capture current metadata before historical data")
			}
			kvReply(w, map[string]any{"current_version": 11, "oldest_version": 1, "versions": map[string]any{}})
		case 2:
			if r.Method != http.MethodGet || r.URL.Path != "/v1/secret/data/app" || r.URL.Query().Get("version") != "3" {
				t.Error("rollback did not read the exact requested old revision")
			}
			kvReply(w, map[string]any{"data": values, "metadata": map[string]any{"version": 3, "destroyed": false, "deletion_time": ""}})
		case 3:
			if r.URL.Path != "/v1/secret/data/app" || r.URL.RawQuery != "" {
				t.Error("rollback attempted to rewrite old history")
			}
			want := map[string]any{"data": values, "options": map[string]any{"cas": json.Number("11")}}
			if !reflect.DeepEqual(kvWriteBody(t, r), want) {
				t.Error("rollback omitted captured current CAS, leaked metadata, or changed exact values")
			}
			kvReply(w, map[string]any{"version": 12})
		default:
			t.Error("rollback performed an extra write or cleanup")
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	result, err := client.Rollback(context.Background(), "selected-token", "/secret/app", 3, vault.KVOptions{Mount: "/secret", Version: 2})
	if err != nil {
		t.Fatalf("restore values into a new revision: %v", err)
	}
	if result.Path != "/secret/app" || result.KVVersion != 2 || result.Version != 12 || stage.Load() != 3 {
		t.Errorf("rollback result or request count = %#v, %d", result, stage.Load())
	}
	assertKVResultFields(t, result, "path", "kv_version", "version")
}

func TestRollbackConcurrentChangeReturnsConflictWithoutRetry(t *testing.T) {
	var writes atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/secret/metadata/app":
			kvReply(w, map[string]any{"current_version": 4, "oldest_version": 1, "versions": map[string]any{}})
		case r.Method == http.MethodGet && r.URL.Query().Get("version") == "2":
			kvReply(w, map[string]any{"data": map[string]any{"value": "fixture-secret-value"}, "metadata": map[string]any{"version": 2}})
		default:
			writes.Add(1)
			body := kvWriteBody(t, r)
			if !reflect.DeepEqual(body["options"], map[string]any{"cas": json.Number("4")}) {
				t.Error("rollback did not retain the original current revision after concurrent change")
			}
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"errors":["check-and-set parameter did not match the current version","upstream-private-value"]}`)
		}
	})
	_, err := client.Rollback(context.Background(), "selected-token", "/secret/app", 2, vault.KVOptions{Mount: "/secret", Version: 2})
	if !errors.Is(err, vault.ErrConflict) {
		t.Errorf("rollback concurrent write = %v, want conflict", err)
	}
	assertKVSafeError(t, err)
	if writes.Load() != 1 {
		t.Error("rollback retried with a newer CAS and overwrote a concurrent change")
	}
}

func TestMissingHistoricalResponsesDoNotBecomeSuccessfulDataOrWrites(t *testing.T) {
	for _, operation := range []string{"read", "versions", "rollback"} {
		t.Run(operation, func(t *testing.T) {
			var writes atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					writes.Add(1)
				}
				if operation == "rollback" && r.URL.Path == "/v1/secret/metadata/app" {
					kvReply(w, map[string]any{"current_version": 3, "oldest_version": 1, "versions": map[string]any{}})
					return
				}
				w.WriteHeader(http.StatusNotFound)
				io.WriteString(w, `{"data":{"data":{"value":"fixture-secret-value"},"current_version":3},"warnings":["upstream-private-value"]}`)
			})
			var err error
			opts := vault.KVOptions{Mount: "/secret", Version: 2}
			switch operation {
			case "read":
				_, err = client.ReadVersion(context.Background(), "selected-token", "/secret/app", 2, opts)
			case "versions":
				_, err = client.Versions(context.Background(), "selected-token", "/secret/app", opts)
			case "rollback":
				_, err = client.Rollback(context.Background(), "selected-token", "/secret/app", 2, opts)
			}
			if !errors.Is(err, vault.ErrNotFound) {
				t.Errorf("HTTP 404 with decorative data = %v, want not found", err)
			}
			assertKVSafeError(t, err)
			if writes.Load() != 0 {
				t.Error("missing historical revision triggered a write")
			}
		})
	}
}

func TestRollbackDoesNotWriteDeletedDestroyedOrMalformedOldValues(t *testing.T) {
	for _, historical := range []any{
		map[string]any{"data": nil, "metadata": map[string]any{"version": 2, "destroyed": true}},
		map[string]any{"data": nil, "metadata": map[string]any{"version": 2, "deletion_time": "deleted"}},
		map[string]any{"data": "upstream-private-value"},
		nil,
	} {
		t.Run("unavailable old values", func(t *testing.T) {
			var writes atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					writes.Add(1)
				}
				if r.URL.Path == "/v1/secret/metadata/app" {
					kvReply(w, map[string]any{"current_version": 3, "oldest_version": 1, "versions": map[string]any{}})
				} else {
					kvReply(w, historical)
				}
			})
			_, err := client.Rollback(context.Background(), "selected-token", "/secret/app", 2, vault.KVOptions{Mount: "/secret", Version: 2})
			assertKVSafeError(t, err)
			if writes.Load() != 0 {
				t.Error("unavailable historical values triggered a new revision")
			}
		})
	}
}

func TestVersionsRejectsMalformedHistory(t *testing.T) {
	for _, data := range []any{
		nil,
		map[string]any{"current_version": -1, "oldest_version": 0, "versions": map[string]any{}},
		map[string]any{"current_version": 1, "oldest_version": -1, "versions": map[string]any{}},
		map[string]any{"current_version": "upstream-private-value", "oldest_version": 0, "versions": map[string]any{}},
		map[string]any{"current_version": 1, "oldest_version": 0, "versions": []any{}},
		map[string]any{"current_version": 1, "oldest_version": 0, "versions": map[string]any{"0": map[string]any{"created_time": "", "deletion_time": "", "destroyed": false}}},
		map[string]any{"current_version": 1, "oldest_version": 0, "versions": map[string]any{"1": map[string]any{"created_time": "", "deletion_time": "", "destroyed": "false"}}},
	} {
		t.Run("malformed metadata", func(t *testing.T) {
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				kvReply(w, data)
			})
			_, err := client.Versions(context.Background(), "selected-token", "/secret/app", vault.KVOptions{Mount: "/secret", Version: 2})
			assertKVSafeError(t, err)
		})
	}
}

func TestVersionOperationsValidateRevisionsAndV1SafetyBeforeNetworking(t *testing.T) {
	v1 := vault.KVOptions{Mount: "/legacy", Version: 1}
	v2 := vault.KVOptions{Mount: "/secret", Version: 2}
	zero := 0
	operations := map[string]struct {
		run  func(*vault.Client) error
		want error
	}{
		"historical zero": {run: func(c *vault.Client) error {
			_, err := c.ReadVersion(context.Background(), "selected-token", "/secret/app", 0, v2)
			return err
		}, want: vault.ErrInvalidPath},
		"rollback negative": {run: func(c *vault.Client) error {
			_, err := c.Rollback(context.Background(), "selected-token", "/secret/app", -1, v2)
			return err
		}, want: vault.ErrInvalidPath},
		"remove explicit empty": {run: func(c *vault.Client) error {
			_, err := c.Remove(context.Background(), "selected-token", "/secret/app", []int{}, vault.WriteOptions{KVOptions: v2})
			return err
		}, want: vault.ErrInvalidPath},
		"remove zero revision": {run: func(c *vault.Client) error {
			_, err := c.Remove(context.Background(), "selected-token", "/secret/app", []int{1, 0}, vault.WriteOptions{KVOptions: v2})
			return err
		}, want: vault.ErrInvalidPath},
		"undelete empty": {run: func(c *vault.Client) error {
			_, err := c.Undelete(context.Background(), "selected-token", "/secret/app", nil, v2)
			return err
		}, want: vault.ErrInvalidPath},
		"undelete negative": {run: func(c *vault.Client) error {
			_, err := c.Undelete(context.Background(), "selected-token", "/secret/app", []int{2, -1}, v2)
			return err
		}, want: vault.ErrInvalidPath},
		"destroy empty": {run: func(c *vault.Client) error {
			_, err := c.Destroy(context.Background(), "selected-token", "/secret/app", nil, vault.WriteOptions{KVOptions: v2, Force: true})
			return err
		}, want: vault.ErrInvalidPath},
		"destroy missing force": {run: func(c *vault.Client) error {
			_, err := c.Destroy(context.Background(), "selected-token", "/secret/app", []int{1}, vault.WriteOptions{KVOptions: v2})
			return err
		}, want: vault.ErrUnsupportedOperation},
		"remove CAS forbidden": {run: func(c *vault.Client) error {
			_, err := c.Remove(context.Background(), "selected-token", "/secret/app", nil, vault.WriteOptions{KVOptions: v2, CAS: &zero})
			return err
		}, want: vault.ErrUnsupportedOperation},
		"destroy CAS forbidden": {run: func(c *vault.Client) error {
			_, err := c.Destroy(context.Background(), "selected-token", "/secret/app", []int{1}, vault.WriteOptions{KVOptions: v2, CAS: &zero, Force: true})
			return err
		}, want: vault.ErrUnsupportedOperation},
		"v1 remove requires force": {run: func(c *vault.Client) error {
			_, err := c.Remove(context.Background(), "selected-token", "/legacy/app", nil, vault.WriteOptions{KVOptions: v1})
			return err
		}, want: vault.ErrUnsupportedOperation},
		"v1 version removal unsupported": {run: func(c *vault.Client) error {
			_, err := c.Remove(context.Background(), "selected-token", "/legacy/app", []int{1}, vault.WriteOptions{KVOptions: v1, Force: true})
			return err
		}, want: vault.ErrUnsupportedOperation},
		"v1 historical unsupported": {run: func(c *vault.Client) error {
			_, err := c.ReadVersion(context.Background(), "selected-token", "/legacy/app", 1, v1)
			return err
		}, want: vault.ErrUnsupportedOperation},
		"v1 history unsupported": {run: func(c *vault.Client) error {
			_, err := c.Versions(context.Background(), "selected-token", "/legacy/app", v1)
			return err
		}, want: vault.ErrUnsupportedOperation},
		"v1 undelete unsupported": {run: func(c *vault.Client) error {
			_, err := c.Undelete(context.Background(), "selected-token", "/legacy/app", []int{1}, v1)
			return err
		}, want: vault.ErrUnsupportedOperation},
		"v1 destroy unsupported": {run: func(c *vault.Client) error {
			_, err := c.Destroy(context.Background(), "selected-token", "/legacy/app", []int{1}, vault.WriteOptions{KVOptions: v1, Force: true})
			return err
		}, want: vault.ErrUnsupportedOperation},
		"v1 rollback unsupported": {run: func(c *vault.Client) error {
			_, err := c.Rollback(context.Background(), "selected-token", "/legacy/app", 1, v1)
			return err
		}, want: vault.ErrUnsupportedOperation},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			})
			err := operation.run(client)
			if !errors.Is(err, operation.want) {
				t.Errorf("invalid version operation = %v, want %v", err, operation.want)
			}
			if requests.Load() != 0 {
				t.Error("invalid or unsupported version operation contacted Vault")
			}
		})
	}
}
