package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/cli"
)

func TestKVHelpDoesNotReadConfigurationOrCredentials(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "://invalid")
	t.Setenv("VAULT_CLIENT_TIMEOUT", "invalid-duration")
	t.Setenv("VAULT_CACERT", "/does-not-exist/private-ca-marker")
	for _, command := range []string{"mounts", "ls", "cat", "cd"} {
		code, stdout, stderr := runNetworkCommand(context.Background(), command, "--help")
		if code != 0 || !strings.Contains(stdout, "Usage:") || stderr != "" {
			t.Errorf("%s help failed offline: exit=%d, stdout=%q, stderr=%q", command, code, stdout, stderr)
		}
	}
}

func TestKVInvalidOptionsFailWithoutEchoOrNetwork(t *testing.T) {
	cleanEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "private-credential-marker")
	const marker = "private-argument-marker"
	for _, args := range [][]string{
		{"cat"},
		{"mounts", marker},
		{"mounts", "--cwd", "/"},
		{"ls", "first", marker},
		{"cd", "first", marker},
		{"cat", "--" + marker, "/secret/item"},
		{"ls", "--timeout", marker},
		{"cat", "--kv-version", marker, "/secret/item"},
		{"cat", "--mount", "secret", "/secret/item"},
		{"cat", "--kv-version", "2", "/secret/item"},
		{"cat", "--mount", "", "--kv-version", "2", "/secret/item"},
		{"cat", "--mount", "secret", "--kv-version", "0", "/secret/item"},
		{"cat", "--mount", "secret", "--kv-version", "3", "/secret/item"},
		{"cat", "/secret/item", "--mount", "secret", "--kv-version", "2"},
		{"cat", "--token-file", "", "/secret/item"},
		{"cat", "--token-file", "/does-not-exist/" + marker, "/secret/item"},
		{"cat", "--mount", "secret", "--kv-version", "2", "/secretary/" + marker},
		{"cat", "--mount", "secret", "--kv-version", "2", "/secret/" + marker + "%2fitem"},
		{"ls", "--cwd", marker},
	} {
		code, stdout, stderr := runNetworkCommand(context.Background(), args...)
		if code != 1 || stdout != "" || stderr == "" {
			t.Errorf("invalid KV options returned exit=%d, stdout=%q, stderr=%q", code, stdout, stderr)
		}
		if strings.Contains(stdout+stderr, marker) || strings.Contains(stdout+stderr, "private-credential-marker") {
			t.Error("KV diagnostic echoed a rejected argument or credential")
		}
	}
	if requests.Load() != 0 {
		t.Errorf("invalid KV options made %d requests", requests.Load())
	}
}

func TestKVMissingTokenNeverContactsVault(t *testing.T) {
	cleanEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	for _, args := range [][]string{{"mounts"}, {"ls"}, {"cat", "/secret/item"}, {"cd"}} {
		code, stdout, stderr := runNetworkCommand(context.Background(), args...)
		if code != 2 || stdout != "" || stderr == "" {
			t.Errorf("missing token returned exit=%d, stdout=%q, stderr=%q", code, stdout, stderr)
		}
	}
	if requests.Load() != 0 {
		t.Error("a KV command without a token contacted Vault")
	}
}

func TestKVCommandsNavigateAndReadLogicalPaths(t *testing.T) {
	cleanEnvironment(t)
	server := kvCLIFixture(t)
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "kv-cli-fixture-token")
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "visible KV mounts", args: []string{"mounts"}, want: `[{"path":"legacy/","version":1},{"path":"secret/","version":2},{"path":"team/nested/","version":2}]`},
		{name: "logical root", args: []string{"ls"}, want: `["legacy/","secret/","team/"]`},
		{name: "relative directory", args: []string{"ls", "--cwd", "/secret/app", "."}, want: `["item","nested/"]`},
		{name: "v1 data field remains data", args: []string{"cat", "/legacy/app/item"}, want: `{"value":"v1-fixture-value","data":{"value":"ordinary-data-field"}}`},
		{name: "v2 read unwraps metadata", args: []string{"cat", "--cwd", "/secret/app", "item"}, want: `{"value":"v2-fixture-value"}`},
		{name: "nested mount", args: []string{"cat", "/team/nested/item"}, want: `{"value":"nested-fixture-value"}`},
		{name: "validated directory", args: []string{"cd", "--cwd", "/secret", "app/./nested/.."}, want: `{"path":"/secret/app"}`},
		{name: "default directory is root", args: []string{"cd"}, want: `{"path":"/"}`},
		{name: "cd does not persist across invocations", args: []string{"ls"}, want: `["legacy/","secret/","team/"]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runNetworkCommand(context.Background(), test.args...)
			if code != 0 || stderr != "" {
				t.Fatalf("KV command failed: exit=%d, stderr=%q", code, stderr)
			}
			kvAssertJSON(t, stdout, test.want)
			if strings.Contains(stdout, "kv-cli-fixture-token") {
				t.Error("KV output exposed the request credential")
			}
		})
	}
}

func TestKVExplicitMountAndTokenFileOverrideDiscoveryAndEnvironment(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run("KV version "+strconv.Itoa(version), func(t *testing.T) {
			cleanEnvironment(t)
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Header.Get("X-Vault-Token") != "kv-cli-file-token" || r.Header.Get("X-Vault-Namespace") != "" {
					t.Error("KV request did not apply token-file and root namespace overrides")
				}
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Vault-Request") != "true" {
					t.Error("KV request sent inherited credentials or omitted its protection header")
				}
				readPath, listPath := "/v1/team/nested/app/item", "/v1/team/nested/app"
				if version == 2 {
					readPath, listPath = "/v1/team/nested/data/app/item", "/v1/team/nested/metadata/app"
				}
				switch {
				case r.Method == http.MethodGet && r.URL.Path == readPath:
					if version == 1 {
						kvWriteData(t, w, map[string]any{"value": "file-source-fixture"})
					} else {
						kvWriteData(t, w, map[string]any{"data": map[string]any{"value": "file-source-fixture"}, "metadata": map[string]any{"version": 1}})
					}
				case r.Method == "LIST" && strings.TrimSuffix(r.URL.Path, "/") == listPath:
					kvWriteData(t, w, map[string]any{"keys": []string{"item"}})
				default:
					t.Errorf("explicit mount used an unexpected operation: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusInternalServerError)
				}
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", "://ignored-address")
			t.Setenv("VAULT_AGENT_ADDR", "://ignored-agent")
			t.Setenv("VAULT_NAMESPACE", "inherited-namespace")
			t.Setenv("VAULT_TOKEN", "inherited-token-must-not-be-used")
			t.Setenv("VAULT_HEADERS", `{"Authorization":"private-inherited-header","Cookie":"private-cookie"}`)
			file := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(file, []byte("kv-cli-file-token\n"), 0600); err != nil {
				t.Fatal(err)
			}
			options := []string{"--address", server.URL, "--namespace", "", "--token-file", file, "--mount", "team/nested", "--kv-version", strconv.Itoa(version)}
			for _, command := range []struct {
				name string
				path string
				want string
			}{
				{name: "cat", path: "/team/nested/app/item", want: `{"value":"file-source-fixture"}`},
				{name: "ls", path: "/team/nested/app", want: `["item"]`},
				{name: "cd", path: "/team/nested/app", want: `{"path":"/team/nested/app"}`},
			} {
				args := append([]string{command.name}, options...)
				args = append(args, command.path)
				code, stdout, stderr := runNetworkCommand(context.Background(), args...)
				if code != 0 || stderr != "" {
					t.Fatalf("explicit KV options failed: exit=%d, stderr=%q", code, stderr)
				}
				kvAssertJSON(t, stdout, command.want)
			}
			if requests.Load() != 3 {
				t.Errorf("explicit mount made %d requests; want one operation per command without discovery", requests.Load())
			}
		})
	}
}

func TestKVErrorsUseContractExitCodesAndSafeDiagnostics(t *testing.T) {
	for _, test := range []struct {
		name string
		code int
		body string
		want int
	}{
		{name: "unauthorized", code: http.StatusUnauthorized, body: `{"errors":["private-upstream-body"]}`, want: 2},
		{name: "forbidden", code: http.StatusForbidden, body: `{"errors":["private-upstream-body"]}`, want: 2},
		{name: "not found", code: http.StatusNotFound, body: `{"errors":["private-upstream-body"]}`, want: 3},
		{name: "server error", code: http.StatusServiceUnavailable, body: `{"errors":["private-upstream-body"]}`, want: 1},
		{name: "malformed JSON", code: http.StatusOK, body: "private-upstream-body", want: 1},
		{name: "deleted v2 value", code: http.StatusOK, body: `{"data":{"data":null,"metadata":{"deletion_time":"2026-10-21T00:00:00Z"}}}`, want: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanEnvironment(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.code)
				io.WriteString(w, test.body)
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", server.URL)
			t.Setenv("VAULT_TOKEN", "private-request-token")
			code, stdout, stderr := runNetworkCommand(context.Background(), "cat", "--mount", "secret", "--kv-version", "2", "/secret/private-path-marker")
			if code != test.want || stdout != "" || stderr == "" {
				t.Errorf("KV failure returned exit=%d, stdout=%q, stderr=%q; want %d", code, stdout, stderr, test.want)
			}
			for _, marker := range []string{"private-upstream-body", "private-request-token", "private-path-marker"} {
				if strings.Contains(stdout+stderr, marker) {
					t.Error("KV failure diagnostic exposed a credential, path, or upstream body")
				}
			}
		})
	}
}

func TestKVOutputFailuresReturnError(t *testing.T) {
	cleanEnvironment(t)
	server := kvCLIFixture(t)
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "kv-cli-fixture-token")
	for _, args := range [][]string{{"mounts"}, {"ls", "/secret/app"}, {"cat", "/secret/app/item"}, {"cd", "/secret/app"}} {
		var stderr bytes.Buffer
		if code := cli.Run(context.Background(), args, failedWriter{}, &stderr, "test"); code != 1 {
			t.Errorf("KV output failure returned %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "could not write output") || strings.Contains(stderr.String(), "fixture-value") {
			t.Errorf("missing or unsafe KV output error: %q", stderr.String())
		}
	}
}

func TestKVTimeoutOptionBoundsTheRead(t *testing.T) {
	cleanEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		<-r.Context().Done()
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "private-timeout-token")
	t.Setenv("VAULT_CLIENT_TIMEOUT", "1m")
	started := time.Now()
	code, stdout, stderr := runNetworkCommand(context.Background(), "cat", "--timeout", "20ms", "--mount", "secret", "--kv-version", "2", "/secret/item")
	if code != 1 || stdout != "" || stderr == "" || time.Since(started) > 2*time.Second {
		t.Errorf("KV read did not apply its timeout: exit=%d, stdout=%q, stderr=%q", code, stdout, stderr)
	}
	if requests.Load() != 1 {
		t.Errorf("timed-out KV read made %d requests, want one", requests.Load())
	}
}

func kvCLIFixture(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "kv-cli-fixture-token" {
			t.Error("KV fixture did not receive the selected token")
		}
		if r.Method != http.MethodGet && r.Method != "LIST" {
			t.Errorf("KV CLI attempted a write operation: %s", r.Method)
		}
		requestPath := strings.TrimSuffix(r.URL.Path, "/")
		if r.Method == http.MethodGet && requestPath == "/v1/sys/internal/ui/mounts" {
			kvWriteData(t, w, map[string]any{"secret": map[string]any{
				"legacy/": map[string]any{"type": "kv", "options": map[string]string{}},
				"secret/": map[string]any{"type": "kv", "options": map[string]string{"version": "2"}},
				"team/nested/": map[string]any{"type": "kv", "options": map[string]string{"version": "2"}},
				"transit/": map[string]any{"type": "transit"},
			}})
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(requestPath, "/v1/sys/internal/ui/mounts/") {
			logical := strings.TrimPrefix(requestPath, "/v1/sys/internal/ui/mounts/")
			mount, version := "secret/", "2"
			if strings.HasPrefix(logical, "legacy/") {
				mount, version = "legacy/", "1"
			} else if strings.HasPrefix(logical, "team/nested/") {
				mount = "team/nested/"
			}
			kvWriteData(t, w, map[string]any{"path": mount, "type": "kv", "options": map[string]string{"version": version}})
			return
		}
		if r.Method == "LIST" && (requestPath == "/v1/secret/metadata/app" || requestPath == "/v1/legacy/app") {
			kvWriteData(t, w, map[string]any{"keys": []string{"nested/", "item"}})
			return
		}
		if r.Method == http.MethodGet {
			switch requestPath {
			case "/v1/legacy/app/item":
				kvWriteData(t, w, map[string]any{"value": "v1-fixture-value", "data": map[string]any{"value": "ordinary-data-field"}})
				return
			case "/v1/secret/data/app/item":
				kvWriteData(t, w, map[string]any{"data": map[string]any{"value": "v2-fixture-value"}, "metadata": map[string]any{"version": 2, "created_time": "unused-metadata"}})
				return
			case "/v1/team/nested/data/item":
				kvWriteData(t, w, map[string]any{"data": map[string]any{"value": "nested-fixture-value"}})
				return
			}
		}
		t.Errorf("unexpected KV CLI operation: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
}

func kvWriteData(t *testing.T, writer http.ResponseWriter, data map[string]any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(map[string]any{"data": data}); err != nil {
		t.Errorf("encode KV CLI fixture: %v", err)
	}
}

func kvAssertJSON(t *testing.T, actual, expected string) {
	t.Helper()
	var got, want any
	if err := json.Unmarshal([]byte(actual), &got); err != nil {
		t.Fatalf("KV output is not JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(expected), &want); err != nil {
		t.Fatalf("invalid expected JSON fixture: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("JSON output = %s, want %s", actual, expected)
	}
}
