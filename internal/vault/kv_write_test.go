package vault_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/vault"
)

func assertKVWriteCredentials(t *testing.T, r *http.Request, token string) {
	t.Helper()
	if r.Header.Get("X-Vault-Token") != token {
		t.Error("mutation did not use its explicitly selected token")
	}
	if r.Header.Get("X-Vault-Namespace") != "team" || r.Header.Get("X-Vault-Request") != "true" {
		t.Error("mutation lost namespace or the Vault Agent protection header")
	}
	if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Vault-Wrap-TTL") != "" {
		t.Error("mutation forwarded an unrelated inherited credential or wrapping preference")
	}
}

func kvWriteBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		t.Errorf("semantic write method = %s, want POST or SDK PUT", r.Method)
	}
	decoder := json.NewDecoder(r.Body)
	decoder.UseNumber()
	var body map[string]any
	if err := decoder.Decode(&body); err != nil {
		t.Errorf("decode mutation payload: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Error("mutation sent trailing JSON")
	}
	return body
}

func assertKVSafeError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("operation unexpectedly succeeded")
	}
	for _, private := range []string{"selected-token", "fixture-secret-value", "upstream-private-value", "private/path", "inherited-private-value"} {
		if strings.Contains(err.Error(), private) {
			t.Error("operation error exposed private request or response content")
		}
	}
}

func assertKVResultFields(t *testing.T, value any, allowed ...string) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode operation result: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("decode operation result: %v", err)
	}
	for field := range fields {
		found := false
		for _, permitted := range allowed {
			if field == permitted {
				found = true
			}
		}
		if !found {
			t.Errorf("operation result exposed an unexpected field: %s", field)
		}
	}
	if strings.Contains(string(encoded), "fixture-secret-value") || strings.Contains(string(encoded), "selected-token") {
		t.Error("operation result exposed secret data or a token")
	}
}

func TestPutUsesVersionSpecificFullReplacementAndCAS(t *testing.T) {
	seven := 7
	for _, test := range []struct {
		name     string
		target   string
		mount    string
		version  string
		physical string
		cas      *int
		wantCAS  json.Number
	}{
		{name: "v1 raw values", target: "/legacy/app", mount: "legacy/", version: "1", physical: "/v1/legacy/app"},
		{name: "v2 create only by default", target: "/secret/app", mount: "secret/", version: "2", physical: "/v1/secret/data/app", wantCAS: "0"},
		{name: "v2 exact revision", target: "/teams/dev/kv/data/app", mount: "teams/dev/kv/", version: "2", physical: "/v1/teams/dev/kv/data/data/app", cas: &seven, wantCAS: "7"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var writes atomic.Int32
			large := json.Number("9007199254740994")
			if test.version == "1" {
				large = json.Number("9007199254740993123456789")
			}
			values := map[string]any{"password": "fixture-secret-value", "large": large, "data": map[string]any{"enabled": true}}
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				assertKVWriteCredentials(t, r, "selected-token")
				switch r.URL.Path {
				case "/v1/sys/internal/ui/mounts" + test.target:
					if r.Method != http.MethodGet {
						t.Error("mount discovery mutated state")
					}
					kvReply(w, kvMountMetadata(test.mount, test.version))
				case test.physical:
					writes.Add(1)
					body := kvWriteBody(t, r)
					want := values
					if test.version == "2" {
						want = map[string]any{"data": values, "options": map[string]any{"cas": test.wantCAS}}
					}
					if !reflect.DeepEqual(body, want) {
						t.Error("write did not send only the full values and required CAS envelope")
					}
					if test.version == "1" {
						w.WriteHeader(http.StatusNoContent)
					} else {
						kvReply(w, map[string]any{"version": 8, "custom_metadata": map[string]any{"password": "fixture-secret-value"}})
					}
				default:
					t.Errorf("unexpected write endpoint: %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			})
			result, err := client.Put(context.Background(), "selected-token", test.target, values, vault.WriteOptions{CAS: test.cas})
			if err != nil {
				t.Fatalf("put full values: %v", err)
			}
			if result.Path != test.target || result.KVVersion < 1 || result.KVVersion > 2 || (test.version == "2" && result.Version != 8) {
				t.Errorf("unexpected write result: %#v", result)
			}
			if writes.Load() != 1 {
				t.Errorf("write requests = %d, want exactly one", writes.Load())
			}
			assertKVResultFields(t, result, "path", "kv_version", "version")
		})
	}
}

func TestPutRejectsInvalidInputsBeforeAnyRequest(t *testing.T) {
	negative, zero := -1, 0
	for _, test := range []struct {
		name    string
		target  string
		data    map[string]any
		options vault.WriteOptions
		want    error
	}{
		{name: "nil values", target: "/secret/app", options: vault.WriteOptions{KVOptions: vault.KVOptions{Mount: "/secret", Version: 2}}, want: vault.ErrInvalidData},
		{name: "empty values", target: "/secret/app", data: map[string]any{}, options: vault.WriteOptions{KVOptions: vault.KVOptions{Mount: "/secret", Version: 2}}, want: vault.ErrInvalidData},
		{name: "negative CAS", target: "/secret/app", data: map[string]any{"value": "fixture-secret-value"}, options: vault.WriteOptions{CAS: &negative}, want: vault.ErrInvalidPath},
		{name: "force forbidden", target: "/secret/app", data: map[string]any{"value": true}, options: vault.WriteOptions{Force: true}, want: vault.ErrUnsupportedOperation},
		{name: "root is not a key", target: "/", data: map[string]any{"value": true}, want: vault.ErrInvalidPath},
		{name: "invalid logical path", target: "/private/path?query=value", data: map[string]any{"value": true}, want: vault.ErrInvalidPath},
		{name: "incomplete override", target: "/secret/app", data: map[string]any{"value": true}, options: vault.WriteOptions{KVOptions: vault.KVOptions{Mount: "/secret"}}, want: vault.ErrInvalidPath},
		{name: "v1 explicit zero CAS", target: "/legacy/app", data: map[string]any{"value": true}, options: vault.WriteOptions{KVOptions: vault.KVOptions{Mount: "/legacy", Version: 1}, CAS: &zero}, want: vault.ErrUnsupportedOperation},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			})
			_, err := client.Put(context.Background(), "selected-token", test.target, test.data, test.options)
			if !errors.Is(err, test.want) {
				t.Errorf("invalid put error = %v, want %v", err, test.want)
			}
			if requests.Load() != 0 {
				t.Error("invalid put contacted Vault")
			}
		})
	}
}

func TestRemoveMapsLatestAndExplicitVersionsWithoutMetadataDeletion(t *testing.T) {
	for _, test := range []struct {
		name     string
		target   string
		version  int
		versions []int
		force    bool
		physical string
		method   string
	}{
		{name: "v1 forced permanent key deletion", target: "/legacy/app", version: 1, force: true, physical: "/v1/legacy/app", method: http.MethodDelete},
		{name: "v2 latest soft deletion", target: "/secret/app", version: 2, physical: "/v1/secret/data/app", method: http.MethodDelete},
		{name: "v2 exact sorted unique revisions", target: "/secret/app", version: 2, versions: []int{3, 1, 3}, physical: "/v1/secret/delete/app", method: http.MethodPost},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			mount := "/secret"
			if test.version == 1 {
				mount = "/legacy"
			}
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				assertKVWriteCredentials(t, r, "selected-token")
				if r.URL.Path != test.physical {
					t.Errorf("remove route = %s, want exact data/delete route", r.URL.Path)
				}
				if test.method == http.MethodDelete {
					if r.Method != http.MethodDelete {
						t.Errorf("remove method = %s, want DELETE", r.Method)
					}
					body, err := io.ReadAll(r.Body)
					if err != nil || len(body) != 0 {
						t.Error("single key deletion sent a payload")
					}
				} else if !reflect.DeepEqual(kvWriteBody(t, r), map[string]any{"versions": []any{json.Number("1"), json.Number("3")}}) {
					t.Error("version deletion did not canonicalize exact revisions")
				}
				w.WriteHeader(http.StatusNoContent)
			})
			result, err := client.Remove(context.Background(), "selected-token", test.target, test.versions, vault.WriteOptions{KVOptions: vault.KVOptions{Mount: mount, Version: test.version}, Force: test.force})
			if err != nil {
				t.Fatalf("remove key revisions: %v", err)
			}
			if result.Path != test.target || result.KVVersion != test.version || requests.Load() != 1 {
				t.Errorf("unexpected removal result or request count: %#v, %d", result, requests.Load())
			}
			if test.versions != nil && !reflect.DeepEqual(result.Versions, []int{1, 3}) {
				t.Errorf("removed revisions = %v, want sorted unique [1 3]", result.Versions)
			}
			assertKVResultFields(t, result, "path", "kv_version", "versions")
		})
	}
}

func TestCopyCrossMountPreservesExactValuesAndDestinationPolicy(t *testing.T) {
	for _, test := range []struct {
		name        string
		sourceMount string
		sourceKV    string
		destMount   string
		destKV      string
		force       bool
	}{
		{name: "v2 to v2", sourceMount: "source/", sourceKV: "2", destMount: "destination/", destKV: "2"},
		{name: "v1 to v2", sourceMount: "legacy/", sourceKV: "1", destMount: "destination/", destKV: "2"},
		{name: "v2 to forced v1", sourceMount: "source/", sourceKV: "2", destMount: "legacy/", destKV: "1", force: true},
		{name: "v1 to forced v1", sourceMount: "legacy/", sourceKV: "1", destMount: "other/", destKV: "1", force: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var writes atomic.Int32
			large := json.Number("9007199254740994")
			if test.destKV == "1" {
				large = json.Number("9007199254740993123456789")
			}
			values := map[string]any{"value": "fixture-secret-value", "large": large}
			source := "/" + test.sourceMount + "data/app"
			destination := "/" + test.destMount + "data/copied"
			sourcePhysical := "/v1/" + test.sourceMount + "data/app"
			if test.sourceKV == "2" {
				sourcePhysical = "/v1/" + test.sourceMount + "data/data/app"
			}
			destPhysical := "/v1/" + test.destMount + "data/copied"
			if test.destKV == "2" {
				destPhysical = "/v1/" + test.destMount + "data/data/copied"
			}
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				assertKVWriteCredentials(t, r, "selected-token")
				switch r.URL.Path {
				case "/v1/sys/internal/ui/mounts" + source:
					kvReply(w, kvMountMetadata(test.sourceMount, test.sourceKV))
				case "/v1/sys/internal/ui/mounts" + destination:
					kvReply(w, kvMountMetadata(test.destMount, test.destKV))
				case sourcePhysical:
					if r.Method != http.MethodGet || r.URL.RawQuery != "" {
						t.Error("copy mutated its source or requested history")
					}
					if test.sourceKV == "2" {
						kvReply(w, map[string]any{"data": values, "metadata": map[string]any{"version": 7, "custom_metadata": map[string]any{"private": "fixture-secret-value"}}})
					} else {
						kvReply(w, values)
					}
				case destPhysical:
					writes.Add(1)
					want := values
					if test.destKV == "2" {
						want = map[string]any{"data": values, "options": map[string]any{"cas": json.Number("0")}}
					}
					if !reflect.DeepEqual(kvWriteBody(t, r), want) {
						t.Error("copy changed numeric precision, included metadata, or omitted destination CAS")
					}
					if test.destKV == "2" {
						kvReply(w, map[string]any{"version": 1})
					} else {
						w.WriteHeader(http.StatusNoContent)
					}
				default:
					t.Errorf("unexpected copy endpoint: %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			})
			result, err := client.Copy(context.Background(), "selected-token", source, destination, vault.WriteOptions{Force: test.force})
			if err != nil {
				t.Fatalf("copy current values: %v", err)
			}
			if result.Source != source || result.Destination != destination || result.SourceDeleted || writes.Load() != 1 {
				t.Errorf("unexpected copy result or write count: %#v, %d", result, writes.Load())
			}
			assertKVResultFields(t, result, "source", "destination", "kv_version", "version", "source_version", "source_deleted")
		})
	}
}

func TestMoveDeletesOnlyCapturedSourceRevisionAfterDestinationWrite(t *testing.T) {
	for _, partial := range []bool{false, true} {
		name := "success"
		if partial {
			name = "source deletion not confirmed"
		}
		t.Run(name, func(t *testing.T) {
			var destinationWrites, sourceDeletes atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				assertKVWriteCredentials(t, r, "selected-token")
				switch r.URL.Path {
				case "/v1/secret/data/source":
					if r.Method != http.MethodGet {
						t.Error("move deleted the latest source instead of the captured revision")
					}
					kvReply(w, map[string]any{"data": map[string]any{"value": "fixture-secret-value"}, "metadata": map[string]any{"version": 7}})
				case "/v1/secret/data/destination":
					destinationWrites.Add(1)
					if sourceDeletes.Load() != 0 {
						t.Error("move deleted its source before copying")
					}
					kvWriteBody(t, r)
					kvReply(w, map[string]any{"version": 1})
				case "/v1/secret/delete/source":
					sourceDeletes.Add(1)
					if destinationWrites.Load() != 1 {
						t.Error("move deleted its source before the successful destination write")
					}
					want := map[string]any{"versions": []any{json.Number("7")}}
					if !reflect.DeepEqual(kvWriteBody(t, r), want) {
						t.Error("move did not delete only revision captured before a newer concurrent source write")
					}
					if partial {
						w.WriteHeader(http.StatusServiceUnavailable)
						io.WriteString(w, `{"errors":["upstream-private-value"]}`)
					} else {
						w.WriteHeader(http.StatusNoContent)
					}
				default:
					t.Errorf("move attempted unexpected cleanup or route: %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			})
			result, err := client.Move(context.Background(), "selected-token", "/secret/source", "/secret/destination", vault.WriteOptions{KVOptions: vault.KVOptions{Mount: "/secret", Version: 2}})
			if partial {
				if !errors.Is(err, vault.ErrPartial) {
					t.Errorf("move after destination success = %v, want partial outcome", err)
				}
				assertKVSafeError(t, err)
			} else if err != nil || !result.SourceDeleted || result.SourceVersion != 7 {
				t.Errorf("successful move result = %#v, error %v", result, err)
			}
			if destinationWrites.Load() != 1 || sourceDeletes.Load() != 1 {
				t.Errorf("move retried or rolled back: writes=%d deletes=%d", destinationWrites.Load(), sourceDeletes.Load())
			}
		})
	}
}

func TestFailedCopyLeavesSourceUntouched(t *testing.T) {
	var writes atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secret/data/source":
			if r.Method != http.MethodGet {
				t.Error("failed copy mutated its source")
			}
			kvReply(w, map[string]any{"data": map[string]any{"value": "fixture-secret-value"}, "metadata": map[string]any{"version": 4}})
		case "/v1/secret/data/destination":
			writes.Add(1)
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"errors":["selected-token upstream-private-value private/path"]}`)
		default:
			t.Errorf("failed copy performed an unexpected operation: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	_, err := client.Move(context.Background(), "selected-token", "/secret/source", "/secret/destination", vault.WriteOptions{KVOptions: vault.KVOptions{Mount: "/secret", Version: 2}})
	if !errors.Is(err, vault.ErrPermissionDenied) || errors.Is(err, vault.ErrPartial) {
		t.Errorf("destination refusal error = %v, want permission denied before partial move", err)
	}
	assertKVSafeError(t, err)
	if writes.Load() != 1 {
		t.Error("failed destination write was retried")
	}
}

func TestWriteCASConflictsAreClassifiedWithoutUpstreamContent(t *testing.T) {
	for _, test := range []struct {
		name     string
		status   int
		message  string
		conflict bool
	}{
		{name: "known CAS mismatch", status: 400, message: "check-and-set parameter did not match the current version", conflict: true},
		{name: "HTTP conflict", status: 409, message: "upstream-private-value", conflict: true},
		{name: "HTTP precondition", status: 412, message: "upstream-private-value", conflict: true},
		{name: "other bad request", status: 400, message: "upstream-private-value"},
		{name: "unauthorized", status: 401, message: "upstream-private-value"},
		{name: "forbidden", status: 403, message: "upstream-private-value"},
		{name: "server failure", status: 503, message: "upstream-private-value"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(test.status)
				json.NewEncoder(w).Encode(map[string]any{"errors": []string{test.message, "selected-token fixture-secret-value private/path"}})
			})
			_, err := client.Put(context.Background(), "selected-token", "/secret/app", map[string]any{"value": "fixture-secret-value"}, vault.WriteOptions{KVOptions: vault.KVOptions{Mount: "/secret", Version: 2}})
			assertKVSafeError(t, err)
			if errors.Is(err, vault.ErrConflict) != test.conflict {
				t.Errorf("CAS conflict classification = %v, want %v", errors.Is(err, vault.ErrConflict), test.conflict)
			}
			if (test.status == 401 || test.status == 403) && !errors.Is(err, vault.ErrPermissionDenied) {
				t.Errorf("write authentication status = %v, want permission denied", err)
			}
			if requests.Load() != 1 {
				t.Errorf("mutation requests = %d, want no automatic retry", requests.Load())
			}
		})
	}
}

func TestMutationDoesNotFollowRedirects(t *testing.T) {
	var redirected, writes atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		kvReply(w, map[string]any{"version": 1})
	}))
	defer destination.Close()
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writes.Add(1)
		w.Header().Set("Location", destination.URL+"/v1/private/path")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	_, err := client.Put(context.Background(), "selected-token", "/secret/app", map[string]any{"value": "fixture-secret-value"}, vault.WriteOptions{KVOptions: vault.KVOptions{Mount: "/secret", Version: 2}})
	assertKVSafeError(t, err)
	if redirected.Load() != 0 || writes.Load() != 1 {
		t.Error("mutation followed a redirect or retried it")
	}
}

func TestMalformedMutationResponseIsNotRetried(t *testing.T) {
	for _, body := range []string{`{"data":{"version":"private/path"}}`, `{"data":null}`, `{"data":{"version":0}}`, `{"data":`} {
		t.Run(body, func(t *testing.T) {
			var requests atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, body)
			})
			_, err := client.Put(context.Background(), "selected-token", "/secret/app", map[string]any{"value": true}, vault.WriteOptions{KVOptions: vault.KVOptions{Mount: "/secret", Version: 2}})
			assertKVSafeError(t, err)
			if requests.Load() != 1 {
				t.Error("ambiguous mutation response was retried")
			}
		})
	}
}

func TestWriteTimeoutBoundsDiscoveryAndMutationTogether(t *testing.T) {
	timeout := 100 * time.Millisecond
	var writes atomic.Int32
	releaseHandler := make(chan struct{})
	defer close(releaseHandler)
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/internal/ui/mounts/secret/app" {
			select {
			case <-time.After(70 * time.Millisecond):
				kvReply(w, kvMountMetadata("secret/", "2"))
			case <-r.Context().Done():
			}
			return
		}
		writes.Add(1)
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error("timed mutation request body could not be consumed")
			return
		}
		select {
		case <-r.Context().Done():
		case <-releaseHandler:
		}
	}, vault.Options{Timeout: &timeout})
	started := time.Now()
	_, err := client.Put(context.Background(), "selected-token", "/secret/app", map[string]any{"value": "fixture-secret-value"}, vault.WriteOptions{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("mutation timeout = %v, want deadline exceeded", err)
	}
	assertKVSafeError(t, err)
	if elapsed := time.Since(started); elapsed > 155*time.Millisecond {
		t.Errorf("whole operation timeout restarted between discovery and mutation: %v", elapsed)
	}
	if writes.Load() != 1 {
		t.Errorf("timed mutation attempts = %d, want exactly one", writes.Load())
	}
}

func TestWriteOperationsRequireAnExplicitTokenAndNeverLookupSelf(t *testing.T) {
	opts := vault.KVOptions{Mount: "/secret", Version: 2}
	operations := map[string]func(*vault.Client, string) error{
		"put": func(c *vault.Client, token string) error {
			_, err := c.Put(context.Background(), token, "/secret/app", map[string]any{"value": true}, vault.WriteOptions{KVOptions: opts})
			return err
		},
		"remove": func(c *vault.Client, token string) error {
			_, err := c.Remove(context.Background(), token, "/secret/app", nil, vault.WriteOptions{KVOptions: opts})
			return err
		},
		"copy": func(c *vault.Client, token string) error {
			_, err := c.Copy(context.Background(), token, "/secret/app", "/secret/copied", vault.WriteOptions{KVOptions: opts})
			return err
		},
		"move": func(c *vault.Client, token string) error {
			_, err := c.Move(context.Background(), token, "/secret/app", "/secret/moved", vault.WriteOptions{KVOptions: opts})
			return err
		},
		"historical read": func(c *vault.Client, token string) error {
			_, err := c.ReadVersion(context.Background(), token, "/secret/app", 1, opts)
			return err
		},
		"versions": func(c *vault.Client, token string) error {
			_, err := c.Versions(context.Background(), token, "/secret/app", opts)
			return err
		},
		"undelete": func(c *vault.Client, token string) error {
			_, err := c.Undelete(context.Background(), token, "/secret/app", []int{1}, opts)
			return err
		},
		"destroy": func(c *vault.Client, token string) error {
			_, err := c.Destroy(context.Background(), token, "/secret/app", []int{1}, vault.WriteOptions{KVOptions: opts, Force: true})
			return err
		},
		"rollback": func(c *vault.Client, token string) error {
			_, err := c.Rollback(context.Background(), token, "/secret/app", 1, opts)
			return err
		},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusForbidden)
			})
			err := operation(client, "")
			if !errors.Is(err, vault.ErrUnauthenticated) {
				t.Errorf("operation without selected token = %v, want unauthenticated", err)
			}
			if requests.Load() != 0 {
				t.Error("operation selected an inherited token or called lookup-self")
			}
		})
	}
}

func TestWriteOperationsDoNotBypassDeniedMountDiscovery(t *testing.T) {
	operations := map[string]func(*vault.Client) error{
		"put": func(c *vault.Client) error {
			_, err := c.Put(context.Background(), "selected-token", "/secret/app", map[string]any{"value": true}, vault.WriteOptions{})
			return err
		},
		"remove": func(c *vault.Client) error {
			_, err := c.Remove(context.Background(), "selected-token", "/secret/app", nil, vault.WriteOptions{})
			return err
		},
		"copy": func(c *vault.Client) error {
			_, err := c.Copy(context.Background(), "selected-token", "/secret/app", "/secret/copied", vault.WriteOptions{})
			return err
		},
		"move": func(c *vault.Client) error {
			_, err := c.Move(context.Background(), "selected-token", "/secret/app", "/secret/moved", vault.WriteOptions{})
			return err
		},
		"historical read": func(c *vault.Client) error {
			_, err := c.ReadVersion(context.Background(), "selected-token", "/secret/app", 1, vault.KVOptions{})
			return err
		},
		"versions": func(c *vault.Client) error {
			_, err := c.Versions(context.Background(), "selected-token", "/secret/app", vault.KVOptions{})
			return err
		},
		"undelete": func(c *vault.Client) error {
			_, err := c.Undelete(context.Background(), "selected-token", "/secret/app", []int{1}, vault.KVOptions{})
			return err
		},
		"destroy": func(c *vault.Client) error {
			_, err := c.Destroy(context.Background(), "selected-token", "/secret/app", []int{1}, vault.WriteOptions{Force: true})
			return err
		},
		"rollback": func(c *vault.Client) error {
			_, err := c.Rollback(context.Background(), "selected-token", "/secret/app", 1, vault.KVOptions{})
			return err
		},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				assertKVReadOnlyRequest(t, r, "selected-token")
				if !strings.HasPrefix(r.URL.Path, "/v1/sys/internal/ui/mounts/") {
					t.Error("operation guessed an API route after denied mount discovery")
				}
				w.WriteHeader(http.StatusForbidden)
				io.WriteString(w, `{"errors":["upstream-private-value selected-token private/path"]}`)
			})
			err := operation(client)
			if !errors.Is(err, vault.ErrPermissionDenied) {
				t.Errorf("denied discovery = %v, want permission denied", err)
			}
			assertKVSafeError(t, err)
			if requests.Load() != 1 {
				t.Errorf("denied discovery requests = %d, want one without guessing or catalog fallback", requests.Load())
			}
		})
	}
}

func TestCopyAndMoveRejectUnsafeInputsBeforeAnyRequest(t *testing.T) {
	zero, negative := 0, -1
	for _, test := range []struct {
		name        string
		source      string
		destination string
		options     vault.WriteOptions
		move        bool
		want        error
	}{
		{name: "same canonical copy", source: "/secret/apps/../app", destination: "/secret/app", want: vault.ErrInvalidPath},
		{name: "same canonical move from cwd", source: "./app", destination: "/secret/app", options: vault.WriteOptions{KVOptions: vault.KVOptions{CWD: "/secret"}}, move: true, want: vault.ErrInvalidPath},
		{name: "negative destination CAS", source: "/secret/app", destination: "/secret/copied", options: vault.WriteOptions{CAS: &negative}, want: vault.ErrInvalidPath},
		{name: "unforced v1 destination", source: "/legacy/app", destination: "/legacy/copied", options: vault.WriteOptions{KVOptions: vault.KVOptions{Mount: "/legacy", Version: 1}}, want: vault.ErrUnsupportedOperation},
		{name: "v1 CAS forbidden even with force", source: "/legacy/app", destination: "/legacy/copied", options: vault.WriteOptions{KVOptions: vault.KVOptions{Mount: "/legacy", Version: 1}, CAS: &zero, Force: true}, want: vault.ErrUnsupportedOperation},
		{name: "unforced v1 move", source: "/legacy/app", destination: "/legacy/moved", options: vault.WriteOptions{KVOptions: vault.KVOptions{Mount: "/legacy", Version: 1}}, move: true, want: vault.ErrUnsupportedOperation},
		{name: "override does not cover destination", source: "/secret/app", destination: "/secret-other/copied", options: vault.WriteOptions{KVOptions: vault.KVOptions{Mount: "/secret", Version: 2}}, want: vault.ErrInvalidPath},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			})
			var err error
			if test.move {
				_, err = client.Move(context.Background(), "selected-token", test.source, test.destination, test.options)
			} else {
				_, err = client.Copy(context.Background(), "selected-token", test.source, test.destination, test.options)
			}
			if !errors.Is(err, test.want) {
				t.Errorf("unsafe copy or move = %v, want %v", err, test.want)
			}
			if requests.Load() != 0 {
				t.Error("invalid copy or move contacted Vault")
			}
		})
	}
}

func TestMoveRequiresCapturedPositiveSourceVersionBeforeWriting(t *testing.T) {
	for _, metadata := range []any{nil, map[string]any{}, map[string]any{"version": 0}, map[string]any{"version": -1}, map[string]any{"version": "upstream-private-value"}} {
		t.Run("invalid captured revision", func(t *testing.T) {
			var writes atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					writes.Add(1)
				}
				kvReply(w, map[string]any{"data": map[string]any{"value": true}, "metadata": metadata})
			})
			_, err := client.Move(context.Background(), "selected-token", "/secret/source", "/secret/destination", vault.WriteOptions{KVOptions: vault.KVOptions{Mount: "/secret", Version: 2}})
			assertKVSafeError(t, err)
			if writes.Load() != 0 {
				t.Error("move wrote a destination without a deletable captured source revision")
			}
		})
	}
}
