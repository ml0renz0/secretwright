package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ml0renz0/secretwright/internal/cli"
)

func runWriteCLI(input io.Reader, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := cli.RunWithInput(context.Background(), args, input, &stdout, &stderr, "test")
	return code, stdout.String(), stderr.String()
}

func TestKVPutUsesCreateOnlyAndExplicitCAS(t *testing.T) {
	for _, test := range []struct {
		name string
		cas  string
		want string
	}{
		{name: "default create only", want: "0"},
		{name: "explicit create only", cas: "0", want: "0"},
		{name: "conditional replacement", cas: "7", want: "7"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanEnvironment(t)
			var writes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writes.Add(1)
				if r.URL.Path != "/v1/secret/data/item" || (r.Method != http.MethodPost && r.Method != http.MethodPut) {
					t.Errorf("unexpected put operation: %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("X-Vault-Token") != "private-write-token" {
					t.Error("put did not send the selected credential")
				}
				var request struct {
					Data    map[string]any `json:"data"`
					Options struct {
						CAS json.Number `json:"cas"`
					} `json:"options"`
				}
				decoder := json.NewDecoder(r.Body)
				decoder.UseNumber()
				if err := decoder.Decode(&request); err != nil {
					t.Errorf("invalid put JSON: %v", err)
				}
				if request.Options.CAS.String() != test.want || request.Data["value"] != "private-input-value" {
					t.Error("put lost its explicit/default CAS or submitted values")
				}
				kvWriteData(t, w, map[string]any{"version": 8, "private": "private-upstream-value"})
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", server.URL)
			t.Setenv("VAULT_TOKEN", "private-write-token")
			args := []string{"put", "--mount", "secret", "--kv-version", "2"}
			if test.cas != "" {
				args = append(args, "--cas", test.cas)
			}
			args = append(args, "/secret/item")
			code, stdout, stderr := runWriteCLI(strings.NewReader(`{"value":"private-input-value"}`), args...)
			if code != 0 || stderr != "" {
				t.Fatalf("put failed: exit=%d, stderr=%q", code, stderr)
			}
			kvAssertJSON(t, stdout, `{"path":"/secret/item","kv_version":2,"version":8}`)
			for _, private := range []string{"private-input-value", "private-upstream-value", "private-write-token"} {
				if strings.Contains(stdout+stderr, private) {
					t.Error("put success report exposed values or credentials")
				}
			}
			if writes.Load() != 1 {
				t.Errorf("put made %d requests, want one explicit write", writes.Load())
			}
		})
	}
}

func TestKVRemoveAndVersionMutationsUseExactVersions(t *testing.T) {
	for _, test := range []struct {
		name   string
		args   []string
		path   string
		delete bool
		want   string
	}{
		{name: "soft delete latest", args: []string{"rm"}, path: "/v1/secret/data/item", delete: true, want: `{"path":"/secret/item","kv_version":2}`},
		{name: "soft delete selected versions", args: []string{"rm", "--versions", "4,2,4"}, path: "/v1/secret/delete/item", want: `{"path":"/secret/item","kv_version":2,"versions":[2,4]}`},
		{name: "undelete selected versions", args: []string{"undelete", "--versions", "4,2,4"}, path: "/v1/secret/undelete/item", want: `{"path":"/secret/item","kv_version":2,"versions":[2,4]}`},
		{name: "destroy selected versions", args: []string{"destroy", "--versions", "4,2,4", "--force"}, path: "/v1/secret/destroy/item", want: `{"path":"/secret/item","kv_version":2,"versions":[2,4]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanEnvironment(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != test.path {
					t.Errorf("unexpected version mutation path: %s", r.URL.Path)
				}
				if test.delete {
					if r.Method != http.MethodDelete {
						t.Error("latest soft deletion did not use DELETE")
					}
				} else {
					if r.Method != http.MethodPost && r.Method != http.MethodPut {
						t.Error("version mutation did not write its version selection")
					}
					var payload struct {
						Versions []int `json:"versions"`
					}
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || !reflect.DeepEqual(payload.Versions, []int{2, 4}) {
						t.Error("version selection was not sorted and deduplicated")
					}
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", server.URL)
			t.Setenv("VAULT_TOKEN", "mutation-token")
			args := append(append([]string{}, test.args...), "--mount", "secret", "--kv-version", "2", "/secret/item")
			code, stdout, stderr := runWriteCLI(strings.NewReader(""), args...)
			if code != 0 || stderr != "" {
				t.Fatalf("version mutation failed: exit=%d, stderr=%q", code, stderr)
			}
			kvAssertJSON(t, stdout, test.want)
		})
	}
}

func TestKVHistoricalReadAndHistoryAreProjected(t *testing.T) {
	cleanEnvironment(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("history operation attempted a mutation")
		}
		if r.URL.Path == "/v1/secret/data/item" && r.URL.Query().Get("version") == "2" {
			kvWriteData(t, w, map[string]any{"data": map[string]any{"value": "historical-fixture"}, "metadata": map[string]any{"version": 2, "custom_metadata": map[string]any{"private": "private-metadata-marker"}}})
			return
		}
		if r.URL.Path == "/v1/secret/metadata/item" {
			io.WriteString(w, `{"data":{"current_version":3,"oldest_version":1,"custom_metadata":{"private":"private-metadata-marker"},"versions":{"3":{"created_time":"2026-10-21T03:00:00Z","deletion_time":"","destroyed":false},"1":{"created_time":"2026-10-21T01:00:00Z","deletion_time":"2026-10-21T02:00:00Z","destroyed":true}}}}`)
			return
		}
		t.Errorf("unexpected history request: %s", r.URL.String())
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "history-token")
	code, stdout, stderr := runWriteCLI(strings.NewReader(""), "cat", "--mount", "secret", "--kv-version", "2", "--version", "2", "/secret/item")
	if code != 0 || stderr != "" {
		t.Fatalf("historical read failed: exit=%d, stderr=%q", code, stderr)
	}
	kvAssertJSON(t, stdout, `{"value":"historical-fixture"}`)
	code, stdout, stderr = runWriteCLI(strings.NewReader(""), "versions", "--mount", "secret", "--kv-version", "2", "/secret/item")
	if code != 0 || stderr != "" {
		t.Fatalf("version history failed: exit=%d, stderr=%q", code, stderr)
	}
	kvAssertJSON(t, stdout, `{"path":"/secret/item","current_version":3,"oldest_version":1,"versions":[{"version":1,"created_time":"2026-10-21T01:00:00Z","deletion_time":"2026-10-21T02:00:00Z","destroyed":true},{"version":3,"created_time":"2026-10-21T03:00:00Z","deletion_time":"","destroyed":false}]}`)
	if strings.Contains(stdout+stderr, "private-metadata-marker") {
		t.Error("version history exposed custom metadata")
	}
}

func TestKVRollbackReadsMetadataBeforeOldValuesAndCreatesNewRevision(t *testing.T) {
	cleanEnvironment(t)
	var sequence atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch sequence.Add(1) {
		case 1:
			if r.Method != http.MethodGet || r.URL.Path != "/v1/secret/metadata/item" {
				t.Error("rollback did not capture current metadata before reading old values")
			}
			kvWriteData(t, w, map[string]any{"current_version": 3, "oldest_version": 1, "versions": map[string]any{}})
		case 2:
			if r.Method != http.MethodGet || r.URL.Path != "/v1/secret/data/item" || r.URL.Query().Get("version") != "1" {
				t.Error("rollback did not read the requested historical revision")
			}
			kvWriteData(t, w, map[string]any{"data": map[string]any{"value": "private-restored-value"}, "metadata": map[string]any{"version": 1}})
		case 3:
			var payload struct {
				Data    map[string]any `json:"data"`
				Options struct {
					CAS int `json:"cas"`
				} `json:"options"`
			}
			if r.URL.Path != "/v1/secret/data/item" || (r.Method != http.MethodPost && r.Method != http.MethodPut) {
				t.Error("rollback did not create a new data revision")
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.Options.CAS != 3 || payload.Data["value"] != "private-restored-value" {
				t.Error("rollback lost its current-revision CAS or historical data")
			}
			kvWriteData(t, w, map[string]any{"version": 4})
		default:
			t.Error("rollback attempted extra operations")
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "rollback-token")
	code, stdout, stderr := runWriteCLI(strings.NewReader(""), "rollback", "--mount", "secret", "--kv-version", "2", "/secret/item", "1")
	if code != 0 || stderr != "" {
		t.Fatalf("rollback failed: exit=%d, stderr=%q", code, stderr)
	}
	kvAssertJSON(t, stdout, `{"path":"/secret/item","kv_version":2,"version":4}`)
	if sequence.Load() != 3 || strings.Contains(stdout+stderr, "private-restored-value") {
		t.Error("rollback used unexpected operations or exposed restored values")
	}
}

func TestKVMoveKeepsSourceOnConflictAndReportsPartialDeletion(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "destination CAS conflict", true: "source deletion unconfirmed"}[partial], func(t *testing.T) {
			cleanEnvironment(t)
			var reads, writes, deletions atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/secret/data/source":
					reads.Add(1)
					kvWriteData(t, w, map[string]any{"data": map[string]any{"value": "private-source-value"}, "metadata": map[string]any{"version": 7}})
				case "/v1/secret/data/destination":
					writes.Add(1)
					if partial {
						kvWriteData(t, w, map[string]any{"version": 1})
					} else {
						w.WriteHeader(http.StatusBadRequest)
						io.WriteString(w, `{"errors":["check-and-set parameter did not match the current version","private-upstream-marker"]}`)
					}
				case "/v1/secret/delete/source":
					deletions.Add(1)
					var payload struct {
						Versions []int `json:"versions"`
					}
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || !reflect.DeepEqual(payload.Versions, []int{7}) {
						t.Error("move did not select only the source revision captured by its read")
					}
					w.WriteHeader(http.StatusForbidden)
					io.WriteString(w, `{"errors":["private-upstream-marker"]}`)
				default:
					t.Errorf("move attempted an unexpected operation: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusInternalServerError)
				}
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", server.URL)
			t.Setenv("VAULT_TOKEN", "private-move-token")
			code, stdout, stderr := runWriteCLI(strings.NewReader(""), "mv", "--mount", "secret", "--kv-version", "2", "/secret/source", "/secret/destination")
			wantCode, wantDeletions := 4, int32(0)
			if partial {
				wantCode, wantDeletions = 5, 1
			}
			if code != wantCode || stdout != "" || stderr == "" {
				t.Errorf("move failure returned exit=%d, stdout=%q, stderr=%q; want %d", code, stdout, stderr, wantCode)
			}
			if reads.Load() != 1 || writes.Load() != 1 || deletions.Load() != wantDeletions {
				t.Error("move retried or deleted its source before a successful destination write")
			}
			for _, marker := range []string{"private-source-value", "private-upstream-marker", "private-move-token"} {
				if strings.Contains(stdout+stderr, marker) {
					t.Error("move failure exposed values, upstream text, or credentials")
				}
			}
		})
	}
}

func TestKVInvalidWriteFlagsAndSelectionsDoNotContactVault(t *testing.T) {
	cleanEnvironment(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "private-write-token")
	for _, args := range [][]string{
		{"put", "--cas", "-1", "/secret/item"},
		{"put", "--force", "/secret/item"},
		{"put", "/secret/item", "private-value=argument-marker"},
		{"cp", "/secret/item", "/secret/./item"},
		{"mv", "/secret/item", "/secret/./item"},
		{"rm", "--versions", "1,,2", "/secret/item"},
		{"rm", "--versions", "0", "/secret/item"},
		{"undelete", "/secret/item"},
		{"undelete", "--versions", "1, 2", "/secret/item"},
		{"destroy", "--versions", "1", "/secret/item"},
		{"destroy", "--force", "--versions", "-1", "/secret/item"},
		{"destroy", "--force", "--versions", "999999999999999999999999", "/secret/item"},
		{"versions", "--force", "/secret/item"},
		{"rollback", "/secret/item", "0"},
		{"rollback", "/secret/item", "private-version-marker"},
		{"cat", "--version", "0", "/secret/item"},
	} {
		code, stdout, stderr := runWriteCLI(strings.NewReader(`{"value":"private-input-marker"}`), args...)
		if code != 1 || stdout != "" || stderr == "" {
			t.Errorf("invalid write options returned exit=%d, stdout=%q, stderr=%q", code, stdout, stderr)
		}
		for _, marker := range []string{"argument-marker", "private-version-marker", "private-write-token", "private-input-marker"} {
			if strings.Contains(stdout+stderr, marker) {
				t.Error("invalid write options diagnostic echoed private input")
			}
		}
	}
	if calls.Load() != 0 {
		t.Errorf("invalid write options made %d requests", calls.Load())
	}
}

func TestKVCopyAndMoveReportOnlyConfirmedOutcomes(t *testing.T) {
	for _, backend := range []struct {
		name    string
		version string
		prefix  string
	}{
		{name: "legacy", version: "1", prefix: "/v1/secret/"},
		{name: "versioned", version: "2", prefix: "/v1/secret/data/"},
	} {
		for _, command := range []string{"cp", "mv"} {
			t.Run(command+" "+backend.name, func(t *testing.T) {
				cleanEnvironment(t)
				var sequence atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch sequence.Add(1) {
					case 1:
						if r.Method != http.MethodGet || r.URL.Path != backend.prefix+"source" {
							t.Error("copy did not first read its current source")
						}
						data := map[string]any{"value": "private-copy-value"}
						if backend.version == "2" {
							data = map[string]any{"data": data, "metadata": map[string]any{"version": 7}}
						}
						kvWriteData(t, w, data)
					case 2:
						if r.URL.Path != backend.prefix+"destination" || (r.Method != http.MethodPost && r.Method != http.MethodPut) {
							t.Error("copy did not write its destination after reading the source")
						}
						var payload map[string]any
						if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
							t.Error("copy submitted invalid destination JSON")
						}
						data := payload
						if backend.version == "2" {
							var ok bool
							data, ok = payload["data"].(map[string]any)
							options, optionsOK := payload["options"].(map[string]any)
							if !ok || !optionsOK || options["cas"] != float64(0) {
								t.Error("copy did not create its versioned destination with CAS zero")
							}
						} else if _, hasOptions := payload["options"]; hasOptions {
							t.Error("legacy copy submitted unsupported CAS options")
						}
						if data["value"] != "private-copy-value" {
							t.Error("copy lost its source values")
						}
						if backend.version == "2" {
							kvWriteData(t, w, map[string]any{"version": 3})
						} else {
							w.WriteHeader(http.StatusNoContent)
						}
					case 3:
						if command != "mv" {
							t.Error("copy unexpectedly deleted its source")
						}
						if backend.version == "2" {
							var payload struct {
								Versions []int `json:"versions"`
							}
							if r.URL.Path != "/v1/secret/delete/source" || (r.Method != http.MethodPost && r.Method != http.MethodPut) {
								t.Error("move used an incorrect versioned source deletion")
							}
							if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || !reflect.DeepEqual(payload.Versions, []int{7}) {
								t.Error("move failed to preserve a newer concurrent source revision")
							}
						} else if r.Method != http.MethodDelete || r.URL.Path != "/v1/secret/source" {
							t.Error("forced legacy move did not delete its source key")
						}
						w.WriteHeader(http.StatusNoContent)
					default:
						t.Error("copy or move repeated its operations")
						w.WriteHeader(http.StatusInternalServerError)
					}
				}))
				defer server.Close()
				t.Setenv("VAULT_ADDR", server.URL)
				t.Setenv("VAULT_TOKEN", "private-copy-token")
				args := []string{command, "--mount", "secret", "--kv-version", backend.version}
				if backend.version == "1" {
					args = append(args, "--force")
				}
				args = append(args, "/secret/source", "/secret/destination")
				code, stdout, stderr := runWriteCLI(strings.NewReader(""), args...)
				if code != 0 || stderr != "" {
					t.Fatalf("copy or move failed: exit=%d, stderr=%q", code, stderr)
				}
				want := `{"source":"/secret/source","destination":"/secret/destination","kv_version":1,"source_deleted":false}`
				if backend.version == "2" {
					want = `{"source":"/secret/source","destination":"/secret/destination","kv_version":2,"version":3,"source_version":7,"source_deleted":false}`
				}
				wantRequests := int32(2)
				if command == "mv" {
					want = strings.Replace(want, `"source_deleted":false`, `"source_deleted":true`, 1)
					wantRequests = 3
				}
				kvAssertJSON(t, stdout, want)
				if sequence.Load() != wantRequests || strings.Contains(stdout+stderr, "private-") {
					t.Error("copy or move used unexpected operations or exposed data or credentials")
				}
			})
		}
	}
}

func TestKVLegacyWritesRejectMissingForceAndExplicitCASBeforeNetworking(t *testing.T) {
	cleanEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "legacy-token")
	for _, selection := range []struct {
		command string
		args    []string
	}{
		{command: "put", args: []string{"--cas", "0", "/secret/item"}},
		{command: "rm", args: []string{"/secret/item"}},
		{command: "rm", args: []string{"--versions", "1", "--force", "/secret/item"}},
		{command: "cp", args: []string{"/secret/source", "/secret/destination"}},
		{command: "mv", args: []string{"/secret/source", "/secret/destination"}},
		{command: "cp", args: []string{"--force", "--cas", "0", "/secret/source", "/secret/destination"}},
		{command: "mv", args: []string{"--force", "--cas", "0", "/secret/source", "/secret/destination"}},
	} {
		args := append([]string{selection.command, "--mount", "secret", "--kv-version", "1"}, selection.args...)
		code, stdout, stderr := runWriteCLI(strings.NewReader(`{"value":"private-legacy-value"}`), args...)
		if code != 1 || stdout != "" || stderr == "" {
			t.Errorf("invalid legacy operation returned exit=%d, stdout=%q, stderr=%q", code, stdout, stderr)
		}
		if strings.Contains(stdout+stderr, "private-legacy-value") {
			t.Error("legacy rejection exposed input values")
		}
	}
	if requests.Load() != 0 {
		t.Errorf("invalid legacy operations made %d requests", requests.Load())
	}
}
