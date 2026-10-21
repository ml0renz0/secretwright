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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/vault"
)

func kvReply(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func kvMountMetadata(path, version string) map[string]any {
	return map[string]any{"path": path, "type": "kv", "options": map[string]any{"version": version}}
}

// The official SDK encodes LIST as GET with list=true on the wire.
func kvOperation(r *http.Request) string {
	if r.Method == "LIST" || (r.Method == http.MethodGet && r.URL.Query().Get("list") == "true") {
		return "LIST"
	}
	return r.Method
}

func kvTestClient(t *testing.T, handler http.HandlerFunc, options ...vault.Options) *vault.Client {
	t.Helper()
	clearVaultEnvironment(t)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_NAMESPACE", "team")
	t.Setenv("VAULT_TOKEN", "inherited-token-must-not-be-selected")
	t.Setenv("VAULT_HEADERS", `{"Authorization":"Bearer inherited-private-value","Cookie":"inherited-cookie","x-vault-token":"inherited-header-token"}`)
	var client *vault.Client
	var err error
	if len(options) == 0 {
		client, err = vault.NewFromEnvironment()
	} else {
		client, err = vault.New(options[0])
	}
	if err != nil {
		t.Fatalf("create KV test client: %v", err)
	}
	return client
}

func assertKVReadOnlyRequest(t *testing.T, r *http.Request, token string) {
	t.Helper()
	if r.Method != http.MethodGet && r.Method != "LIST" {
		t.Errorf("product made a mutating request: %s", r.Method)
	}
	if r.Header.Get("X-Vault-Token") != token {
		t.Error("KV operation did not use its explicitly selected token")
	}
	if r.Header.Get("X-Vault-Namespace") != "team" || r.Header.Get("X-Vault-Request") != "true" {
		t.Error("KV operation lost namespace or the Vault Agent protection header")
	}
	if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		t.Error("KV operation forwarded an unrelated inherited credential")
	}
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) != 0 {
		t.Error("read-only KV operation unexpectedly sent a request body")
	}
}

func TestMountsReturnsSortedVisibleKVEngines(t *testing.T) {
	var requests atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assertKVReadOnlyRequest(t, r, "selected-token")
		if kvOperation(r) != http.MethodGet || r.URL.Path != "/v1/sys/internal/ui/mounts" {
			t.Errorf("catalog used an unexpected endpoint: %s %s", r.Method, r.URL.Path)
		}
		kvReply(w, map[string]any{
			"secret": map[string]any{
				"teams/dev/kv/": kvMountMetadata("teams/dev/kv/", "2"),
				"legacy/":       map[string]any{"type": "kv", "options": nil},
				"secret/":       kvMountMetadata("secret/", "2"),
				"explicit-v1/":  kvMountMetadata("explicit-v1/", "1"),
				"pki/":          map[string]any{"type": "pki"},
				"sys/":          map[string]any{"type": "system"},
			},
			"auth": map[string]any{"token/": map[string]any{"type": "token"}},
		})
	})
	got, err := client.Mounts(context.Background(), "selected-token")
	if err != nil {
		t.Fatalf("list visible engines: %v", err)
	}
	want := []vault.Mount{{Path: "explicit-v1/", Version: 1}, {Path: "legacy/", Version: 1}, {Path: "secret/", Version: 2}, {Path: "teams/dev/kv/", Version: 2}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mount catalog = %#v, want %#v", got, want)
	}
	if requests.Load() != 1 {
		t.Errorf("catalog requests = %d, want one nonadministrative lookup", requests.Load())
	}
}

func TestReadMapsLogicalPathsToTheDetectedKVVersion(t *testing.T) {
	for _, test := range []struct {
		name       string
		target     string
		options    vault.KVOptions
		logical    string
		mount      string
		version    string
		physical   string
		secretData map[string]any
	}{
		{name: "KV v1 preserves a data-named field", target: "/legacy/app", logical: "legacy/app", mount: "legacy/", version: "1", physical: "/v1/legacy/app", secretData: map[string]any{"username": "reader", "data": map[string]any{"nested": "preserved"}}},
		{name: "KV v2 unwraps only the data envelope", target: "/secret/app", logical: "secret/app", mount: "secret/", version: "2", physical: "/v1/secret/data/app", secretData: map[string]any{"password": "fixture-value", "enabled": true}},
		{name: "nested mount and data-named key", target: "/teams/dev/kv/data/client", logical: "teams/dev/kv/data/client", mount: "teams/dev/kv/", version: "2", physical: "/v1/teams/dev/kv/data/data/client", secretData: map[string]any{"value": "nested-fixture"}},
		{name: "relative path from explicit cwd", target: "../shared", options: vault.KVOptions{CWD: "/secret/apps/billing"}, logical: "secret/apps/shared", mount: "secret/", version: "2", physical: "/v1/secret/data/apps/shared", secretData: map[string]any{"value": "shared-fixture"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls []string
			var callLock sync.Mutex
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				assertKVReadOnlyRequest(t, r, "selected-token")
				callLock.Lock()
				calls = append(calls, kvOperation(r)+" "+r.URL.Path)
				callLock.Unlock()
				switch r.URL.Path {
				case "/v1/sys/internal/ui/mounts/" + test.logical:
					kvReply(w, kvMountMetadata(test.mount, test.version))
				case test.physical:
					if test.version == "2" {
						kvReply(w, map[string]any{"data": test.secretData, "metadata": map[string]any{"version": 7, "custom_metadata": map[string]any{"private": "not-the-secret"}}})
					} else {
						kvReply(w, test.secretData)
					}
				default:
					t.Errorf("unexpected endpoint: %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			})
			got, err := client.Read(context.Background(), "selected-token", test.target, test.options)
			if err != nil {
				t.Fatalf("read logical secret: %v", err)
			}
			if !reflect.DeepEqual(got, test.secretData) {
				t.Errorf("secret data = %#v, want %#v", got, test.secretData)
			}
			wantCalls := []string{"GET /v1/sys/internal/ui/mounts/" + test.logical, "GET " + test.physical}
			callLock.Lock()
			defer callLock.Unlock()
			if !reflect.DeepEqual(calls, wantCalls) {
				t.Errorf("operations = %v, want %v", calls, wantCalls)
			}
		})
	}
}

func TestListUsesKVMetadataOnlyForVersionTwo(t *testing.T) {
	for _, test := range []struct {
		name     string
		target   string
		mount    string
		version  string
		physical string
	}{
		{name: "KV v1", target: "/legacy/app", mount: "legacy/", version: "1", physical: "/v1/legacy/app"},
		{name: "KV v2", target: "/secret/app", mount: "secret/", version: "2", physical: "/v1/secret/metadata/app"},
		{name: "nested KV v2 root", target: "/teams/dev/kv", mount: "teams/dev/kv/", version: "2", physical: "/v1/teams/dev/kv/metadata"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls []string
			var callLock sync.Mutex
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				assertKVReadOnlyRequest(t, r, "selected-token")
				operation := kvOperation(r)
				callLock.Lock()
				calls = append(calls, operation+" "+strings.TrimSuffix(r.URL.Path, "/"))
				callLock.Unlock()
				if r.URL.Path == "/v1/sys/internal/ui/mounts"+test.target {
					kvReply(w, kvMountMetadata(test.mount, test.version))
				} else if operation == "LIST" && strings.TrimSuffix(r.URL.Path, "/") == test.physical {
					kvReply(w, map[string]any{"keys": []string{"z", "a/", "a", "z"}})
				} else {
					t.Errorf("unexpected list endpoint: %s %s", operation, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			})
			got, err := client.List(context.Background(), "selected-token", test.target, vault.KVOptions{})
			if err != nil {
				t.Fatalf("list logical directory: %v", err)
			}
			if want := []string{"a", "a/", "z"}; !reflect.DeepEqual(got, want) {
				t.Errorf("directory entries = %v, want %v", got, want)
			}
			callLock.Lock()
			defer callLock.Unlock()
			if len(calls) != 2 || !strings.HasPrefix(calls[1], "LIST ") {
				t.Errorf("expected discovery followed by one LIST, got %v", calls)
			}
		})
	}
}

func TestVirtualDirectoriesExposeOnlyImmediateVisibleMountChildren(t *testing.T) {
	for _, test := range []struct {
		target string
		want   []string
	}{
		{target: "/", want: []string{"legacy/", "secret/", "teams/"}},
		{target: "/teams", want: []string{"dev/", "prod/"}},
		{target: "/teams/dev", want: []string{"kv/"}},
	} {
		t.Run(test.target, func(t *testing.T) {
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				assertKVReadOnlyRequest(t, r, "selected-token")
				if r.URL.Path != "/v1/sys/internal/ui/mounts" {
					if r.URL.Path != "/v1/sys/internal/ui/mounts"+test.target {
						t.Errorf("unexpected virtual directory request: %s", r.URL.Path)
					}
					w.WriteHeader(http.StatusNotFound)
					return
				}
				kvReply(w, map[string]any{"secret": map[string]any{
					"legacy/":        kvMountMetadata("legacy/", "1"),
					"secret/":        kvMountMetadata("secret/", "2"),
					"teams/dev/kv/":  kvMountMetadata("teams/dev/kv/", "2"),
					"teams/prod/kv/": kvMountMetadata("teams/prod/kv/", "2"),
				}})
			})
			got, err := client.List(context.Background(), "selected-token", test.target, vault.KVOptions{})
			if err != nil {
				t.Fatalf("list virtual directory: %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("virtual directory entries = %v, want %v", got, test.want)
			}
			if test.target != "/" {
				gotDirectory, err := client.ChangeDir(context.Background(), "selected-token", test.target, vault.KVOptions{})
				if err != nil || gotDirectory != test.target {
					t.Errorf("validated directory = %q, error %v", gotDirectory, err)
				}
			}
		})
	}
}

func TestExplicitMountVersionBypassesDiscovery(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			var requests atomic.Int32
			physical := "/v1/secret/apps/item"
			if version == 2 {
				physical = "/v1/secret/data/apps/item"
			}
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				assertKVReadOnlyRequest(t, r, "selected-token")
				if r.URL.Path != physical {
					t.Errorf("explicit mount unexpectedly performed discovery or used another path: %s", r.URL.Path)
					w.WriteHeader(http.StatusForbidden)
					return
				}
				data := map[string]any{"value": "explicit-fixture"}
				if version == 2 {
					kvReply(w, map[string]any{"data": data})
				} else {
					kvReply(w, data)
				}
			})
			got, err := client.Read(context.Background(), "selected-token", "item", vault.KVOptions{CWD: "/secret/apps", Mount: "secret/", Version: version})
			if err != nil || got["value"] != "explicit-fixture" {
				t.Fatalf("explicit mount read failed: %v", err)
			}
			if requests.Load() != 1 {
				t.Errorf("explicit read requests = %d, want no preflight", requests.Load())
			}
		})
	}
}

func TestInvalidKVPathsAndMountOverridesNeverContactVault(t *testing.T) {
	for _, test := range []struct {
		name    string
		target  string
		options vault.KVOptions
	}{
		{name: "mount without version", target: "/secret/item", options: vault.KVOptions{Mount: "secret/"}},
		{name: "version without mount", target: "/secret/item", options: vault.KVOptions{Version: 2}},
		{name: "unsupported explicit version", target: "/secret/item", options: vault.KVOptions{Mount: "secret/", Version: 3}},
		{name: "mount boundary", target: "/secretary/item", options: vault.KVOptions{Mount: "secret/", Version: 2}},
		{name: "mount root is not a secret", target: "/secret", options: vault.KVOptions{Mount: "secret/", Version: 2}},
		{name: "encoded separator", target: "/secret/private-path-marker%2fitem"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			})
			got, err := client.Read(context.Background(), "selected-token", test.target, test.options)
			if err == nil || got != nil {
				t.Fatal("invalid KV request was accepted")
			}
			if requests.Load() != 0 {
				t.Error("invalid logical request contacted Vault")
			}
			if strings.Contains(err.Error(), "private-path-marker") {
				t.Error("logical path diagnostic exposed its input")
			}
		})
	}
}

func TestKVPermissionFailuresNeverGuessTheBackendVersion(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var requests atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path != "/v1/sys/internal/ui/mounts/secret/private-path-marker" {
					t.Error("permission failure triggered another backend lookup")
				}
				w.WriteHeader(code)
				io.WriteString(w, `{"errors":["private-upstream-marker private-token-marker"]}`)
			})
			got, err := client.Read(context.Background(), "private-token-marker", "/secret/private-path-marker", vault.KVOptions{})
			if got != nil || !errors.Is(err, vault.ErrPermissionDenied) {
				t.Errorf("permission failure classification = %v", err)
			}
			if requests.Load() != 1 {
				t.Errorf("permission failure made %d requests, want no guessing or fallback", requests.Load())
			}
			if err != nil {
				for _, marker := range []string{"private-upstream-marker", "private-token-marker", "private-path-marker"} {
					if strings.Contains(err.Error(), marker) {
						t.Error("permission error exposed private input or upstream content")
					}
				}
			}
		})
	}
}

func TestKVReadRejectsMissingDeletedAndMalformedData(t *testing.T) {
	for _, test := range []struct {
		name     string
		code     int
		body     string
		notFound bool
	}{
		{name: "missing secret", code: http.StatusNotFound, body: `{"errors":[]}`, notFound: true},
		{name: "deleted latest version", code: http.StatusOK, body: `{"data":{"data":null,"metadata":{"deletion_time":"2026-10-21T00:00:00Z"}}}`, notFound: true},
		{name: "invalid JSON", code: http.StatusOK, body: "private-upstream-marker"},
		{name: "data has wrong type", code: http.StatusOK, body: `{"data":{"data":"private-upstream-marker"}}`},
		{name: "backend denied", code: http.StatusForbidden, body: `{"errors":["private-upstream-marker"]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/v1/sys/internal/ui/mounts/") {
					kvReply(w, kvMountMetadata("secret/", "2"))
					return
				}
				w.WriteHeader(test.code)
				io.WriteString(w, test.body)
			})
			got, err := client.Read(context.Background(), "selected-token", "/secret/item", vault.KVOptions{})
			if got != nil || err == nil {
				t.Fatal("missing, deleted, or invalid secret response was accepted")
			}
			if test.notFound && !errors.Is(err, vault.ErrNotFound) {
				t.Errorf("missing/deleted classification = %v", err)
			}
			if test.code == http.StatusForbidden && !errors.Is(err, vault.ErrPermissionDenied) {
				t.Errorf("backend permission classification = %v", err)
			}
			if strings.Contains(err.Error(), "private-upstream-marker") {
				t.Error("secret response error exposed the upstream body")
			}
		})
	}
}

func TestMountDiscoveryRejectsUnsupportedAndUnrelatedMounts(t *testing.T) {
	for _, test := range []struct {
		name  string
		data  any
		notKV bool
	}{
		{name: "non KV engine", data: map[string]any{"path": "secret/", "type": "pki"}, notKV: true},
		{name: "unsupported version", data: kvMountMetadata("secret/", "3")},
		{name: "unrelated mount prefix", data: kvMountMetadata("secretary/", "2")},
		{name: "missing path", data: map[string]any{"type": "kv", "options": map[string]any{"version": "2"}}},
		{name: "invalid options", data: map[string]any{"path": "secret/", "type": "kv", "options": "private-upstream-marker"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				kvReply(w, test.data)
			})
			got, err := client.Read(context.Background(), "selected-token", "/secret/item", vault.KVOptions{})
			if got != nil || err == nil {
				t.Fatal("unsupported or malformed mount metadata was accepted")
			}
			if test.notKV && !errors.Is(err, vault.ErrNotKV) {
				t.Errorf("non-KV engine classification = %v", err)
			}
			if requests.Load() != 1 {
				t.Error("invalid mount metadata caused a secret read or guessed API version")
			}
			if strings.Contains(err.Error(), "private-upstream-marker") {
				t.Error("mount error exposed upstream content")
			}
		})
	}
}

func TestKVListRejectsUnsafeChildrenAndAcceptsEmptyArrays(t *testing.T) {
	for _, test := range []struct {
		name string
		keys any
		ok   bool
	}{
		{name: "empty directory", keys: []string{}, ok: true},
		{name: "wrong type", keys: "private-upstream-marker"},
		{name: "nonstring entry", keys: []any{1}},
		{name: "parent entry", keys: []string{"../"}},
		{name: "absolute entry", keys: []string{"/other/"}},
		{name: "nested entry", keys: []string{"other/child"}},
		{name: "encoded entry", keys: []string{"other%2fchild"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				kvReply(w, map[string]any{"keys": test.keys})
			})
			got, err := client.List(context.Background(), "selected-token", "/secret/app", vault.KVOptions{Mount: "secret/", Version: 2})
			if test.ok {
				if err != nil || got == nil || len(got) != 0 {
					t.Fatalf("empty keys array should be a successful empty directory: %v", err)
				}
			} else if err == nil || got != nil {
				t.Fatal("unsafe or malformed directory entries were accepted")
			}
		})
	}
}

func TestVirtualDirectoryCatalogCanResolveAnInventoryHiding403(t *testing.T) {
	for _, test := range []struct {
		name   string
		target string
		want   []string
		denied bool
	}{
		{name: "visible ancestor", target: "/teams", want: []string{"dev/"}},
		{name: "unknown path remains denied", target: "/missing", denied: true},
		{name: "denied path inside an engine remains denied", target: "/secret/blocked", denied: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var backendCalls atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/internal/ui/mounts" {
					kvReply(w, map[string]any{"secret": map[string]any{
						"teams/dev/kv/":          kvMountMetadata("teams/dev/kv/", "2"),
						"secret/":                kvMountMetadata("secret/", "2"),
						"secret/blocked/nested/": kvMountMetadata("secret/blocked/nested/", "2"),
					}})
					return
				}
				if r.URL.Path == "/v1/sys/internal/ui/mounts"+test.target {
					w.WriteHeader(http.StatusForbidden)
					io.WriteString(w, `{"errors":["permission denied"]}`)
					return
				}
				backendCalls.Add(1)
				w.WriteHeader(http.StatusForbidden)
			})
			got, err := client.List(context.Background(), "selected-token", test.target, vault.KVOptions{})
			if test.denied {
				if !errors.Is(err, vault.ErrPermissionDenied) || got != nil {
					t.Errorf("inventory-hiding permission failure changed classification: %v", err)
				}
			} else if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Errorf("visible ancestor result = %v, error %v", got, err)
			}
			if backendCalls.Load() != 0 {
				t.Error("metadata denial caused an unauthorized backend probe")
			}
		})
	}
}

func TestKVReadAndListPermissionsAreIndependent(t *testing.T) {
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assertKVReadOnlyRequest(t, r, "selected-token")
		if kvOperation(r) == "LIST" {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"errors":["private-permission-marker"]}`)
			return
		}
		if r.URL.Path != "/v1/secret/data/allowed" {
			t.Errorf("unexpected read endpoint: %s", r.URL.Path)
		}
		kvReply(w, map[string]any{"data": map[string]any{"value": "permitted-read"}})
	})
	options := vault.KVOptions{Mount: "secret/", Version: 2}
	got, err := client.Read(context.Background(), "selected-token", "/secret/allowed", options)
	if err != nil || got["value"] != "permitted-read" {
		t.Fatalf("read permission was incorrectly tied to list permission: %v", err)
	}
	if _, err := client.List(context.Background(), "selected-token", "/secret", options); !errors.Is(err, vault.ErrPermissionDenied) {
		t.Errorf("list permission failure = %v", err)
	}
	if _, err := client.ChangeDir(context.Background(), "selected-token", "/secret", options); !errors.Is(err, vault.ErrPermissionDenied) {
		t.Errorf("change-directory did not validate directory access: %v", err)
	}
}

func TestKVOperationsWithoutATokenDoNotContactVault(t *testing.T) {
	var requests atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	operations := []func() error{
		func() error { _, err := client.Mounts(context.Background(), ""); return err },
		func() error {
			_, err := client.List(context.Background(), "", "/secret/app", vault.KVOptions{})
			return err
		},
		func() error {
			_, err := client.Read(context.Background(), "", "/secret/app", vault.KVOptions{})
			return err
		},
		func() error {
			_, err := client.ChangeDir(context.Background(), "", "/secret/app", vault.KVOptions{})
			return err
		},
	}
	for _, operation := range operations {
		if err := operation(); !errors.Is(err, vault.ErrUnauthenticated) {
			t.Errorf("missing-token operation error = %v, want ErrUnauthenticated", err)
		}
	}
	if requests.Load() != 0 {
		t.Error("missing-token operations contacted Vault")
	}
}

func TestKVReadsAndPublicHealthKeepConcurrentTokensIsolated(t *testing.T) {
	var reads, health atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			health.Add(1)
			if r.Header.Get("X-Vault-Token") != "" {
				t.Error("a public health request acquired a KV token")
			}
			io.WriteString(w, `{"initialized":true,"sealed":false,"version":"2.2.0"}`)
			return
		}
		reads.Add(1)
		owner := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")
		if (owner != "alpha" && owner != "beta") || r.Header.Get("X-Vault-Token") != owner+"-token" {
			t.Error("a KV read acquired another operation's credential")
		}
		kvReply(w, map[string]any{"data": map[string]any{"owner": owner}})
	})
	start := make(chan struct{})
	failures := make(chan error, 18)
	var workers sync.WaitGroup
	for index := range 18 {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			<-start
			if index%3 == 0 {
				_, err := client.Status(context.Background())
				failures <- err
				return
			}
			owner := "alpha"
			if index%3 == 2 {
				owner = "beta"
			}
			got, err := client.Read(context.Background(), owner+"-token", "/secret/"+owner, vault.KVOptions{Mount: "secret/", Version: 2})
			if err == nil && got["owner"] != owner {
				err = errors.New("concurrent read returned another caller's data")
			}
			failures <- err
		}(index)
	}
	close(start)
	workers.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Errorf("concurrent operation failed: %v", err)
		}
	}
	if health.Load() != 6 || reads.Load() != 12 {
		t.Errorf("health/KV request counts = %d/%d, want 6/12", health.Load(), reads.Load())
	}
}

func TestKVReadRespectsCancellationAndConfiguredTimeout(t *testing.T) {
	timeout := 40 * time.Millisecond
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}, vault.Options{Timeout: &timeout})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	options := vault.KVOptions{Mount: "secret/", Version: 2}
	if _, err := client.Read(ctx, "selected-token", "/secret/app", options); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled KV operation = %v, want context.Canceled", err)
	}
	started := time.Now()
	if _, err := client.Read(context.Background(), "selected-token", "/secret/app", options); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("bounded KV operation = %v, want deadline exceeded", err)
	}
	if time.Since(started) > 2*time.Second {
		t.Error("configured timeout failed to bound the KV request")
	}
}

func TestKVReadNeverForwardsATokenToRedirects(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit engine", true: "discovery"}[automatic], func(t *testing.T) {
			var forwarded atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded.Add(1)
				kvReply(w, map[string]any{"data": map[string]any{"value": "must-not-be-reached"}})
			}))
			defer target.Close()
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL+"/v1/secret/data/app", http.StatusTemporaryRedirect)
			})
			options := vault.KVOptions{Mount: "secret/", Version: 2}
			if automatic {
				options = vault.KVOptions{}
			}
			if _, err := client.Read(context.Background(), "private-token-not-forwarded", "/secret/app", options); err == nil {
				t.Error("redirected KV read unexpectedly succeeded")
			}
			if forwarded.Load() != 0 {
				t.Error("KV request forwarded its token to a redirect target")
			}
		})
	}
}

func TestKVReadNeverTreatsHTTP404WithDataOrWarningsAsSuccess(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			for _, body := range []string{
				`{"data":{"value":"private-missing-value"}}`,
				`{"warnings":["private-missing-warning"]}`,
			} {
				client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)
					io.WriteString(w, body)
				})
				got, err := client.Read(context.Background(), "selected-token", "/secret/missing", vault.KVOptions{Mount: "secret/", Version: version})
				if got != nil || !errors.Is(err, vault.ErrNotFound) {
					t.Errorf("HTTP 404 with a body was not classified as missing: %v", err)
				}
				if err != nil && (strings.Contains(err.Error(), "private-missing-value") || strings.Contains(err.Error(), "private-missing-warning")) {
					t.Error("missing-secret error exposed upstream data")
				}
			}
		})
	}
}

func TestMountCatalogDoesNotHideUnsupportedKVVersions(t *testing.T) {
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		kvReply(w, map[string]any{"secret": map[string]any{
			"known/":  kvMountMetadata("known/", "1"),
			"future/": kvMountMetadata("future/", "3"),
		}})
	})
	got, err := client.Mounts(context.Background(), "selected-token")
	if got != nil || !errors.Is(err, vault.ErrNotKV) {
		t.Errorf("an unsupported KV version was silently omitted from the catalog: %v", err)
	}
}

func TestMountCatalogIgnoresNonKVVersionOptions(t *testing.T) {
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		kvReply(w, map[string]any{"secret": map[string]any{
			"known/": kvMountMetadata("known/", "1"),
			"pki/":   map[string]any{"type": "pki", "options": map[string]any{"version": "unsupported-for-KV"}},
		}})
	})
	got, err := client.Mounts(context.Background(), "selected-token")
	want := []vault.Mount{{Path: "known/", Version: 1}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("non-KV options affected the visible KV catalog: %v", err)
	}
}
