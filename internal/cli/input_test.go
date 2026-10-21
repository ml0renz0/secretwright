package cli_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type f03PanicReader struct{}

func (f03PanicReader) Read([]byte) (int, error) {
	panic("input must not be consumed")
}

type f03ErrorReader struct{}

func (f03ErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("private-reader-error-marker")
}

func TestKVPutInputSourcesPreserveExactNumbers(t *testing.T) {
	for _, source := range []string{"stdin", "explicit stdin", "file"} {
		t.Run(source, func(t *testing.T) {
			cleanEnvironment(t)
			const number = "9007199254740993123456789"
			const input = `{"number":9007199254740993123456789,"nested":{"enabled":true},"value":"private-file-value"}`
			var writes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writes.Add(1)
				if r.URL.Path != "/v1/secret/data/item" || (r.Method != http.MethodPost && r.Method != http.MethodPut) {
					t.Error("input put used an unexpected operation")
				}
				var payload struct {
					Data map[string]any `json:"data"`
				}
				decoder := json.NewDecoder(r.Body)
				decoder.UseNumber()
				if err := decoder.Decode(&payload); err != nil {
					t.Errorf("put submitted invalid JSON: %v", err)
				}
				got, ok := payload.Data["number"].(json.Number)
				if !ok || got.String() != number || payload.Data["value"] != "private-file-value" {
					t.Error("put did not preserve the selected input and exact large integer")
				}
				nested, ok := payload.Data["nested"].(map[string]any)
				if !ok || nested["enabled"] != true {
					t.Error("put did not preserve nested JSON data")
				}
				kvWriteData(t, w, map[string]any{"version": 1})
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", server.URL)
			t.Setenv("VAULT_TOKEN", "private-input-token")
			args := []string{"put", "--mount", "secret", "--kv-version", "2"}
			var reader io.Reader = strings.NewReader(input)
			switch source {
			case "explicit stdin":
				args = append(args, "--file", "-")
			case "file":
				path := filepath.Join(t.TempDir(), "input.json")
				if err := os.WriteFile(path, []byte(input), 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--file", path)
				reader = f03PanicReader{}
			}
			args = append(args, "/secret/item")
			code, stdout, stderr := runWriteCLI(reader, args...)
			if code != 0 || stderr != "" {
				t.Fatalf("put selected input failed: exit=%d, stderr=%q", code, stderr)
			}
			kvAssertJSON(t, stdout, `{"path":"/secret/item","kv_version":2,"version":1}`)
			if writes.Load() != 1 || strings.Contains(stdout+stderr, "private-") || strings.Contains(stdout+stderr, number) {
				t.Error("put retried or exposed its input or credential")
			}
		})
	}
}

func TestKVPutRejectsInvalidJSONBeforeNetworking(t *testing.T) {
	cleanEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "private-input-token")
	for _, test := range []struct {
		name  string
		input string
	}{
		{name: "empty"},
		{name: "whitespace", input: " \n\t"},
		{name: "null", input: "null"},
		{name: "array", input: `[{"value":"private-input-marker"}]`},
		{name: "scalar", input: `"private-input-marker"`},
		{name: "empty object", input: `{}`},
		{name: "malformed", input: `{"value":"private-input-marker"`},
		{name: "second value", input: `{"value":"private-input-marker"} {}`},
		{name: "trailing garbage", input: `{"value":"private-input-marker"} private-trailing-marker`},
		{name: "over limit", input: `{"value":"` + strings.Repeat("x", 1<<20) + `private-input-marker"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runWriteCLI(strings.NewReader(test.input), "put", "--mount", "secret", "--kv-version", "2", "/secret/item")
			if code != 1 || stdout != "" || stderr == "" {
				t.Errorf("invalid input returned exit=%d, stdout=%q, stderr=%q", code, stdout, stderr)
			}
			if strings.Contains(stderr, "private-") {
				t.Error("invalid JSON diagnostic exposed input or credential")
			}
		})
	}
	if requests.Load() != 0 {
		t.Errorf("invalid JSON made %d requests", requests.Load())
	}
}

func TestKVPutInputFailuresAreSafeAndDoNotContactVault(t *testing.T) {
	cleanEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "private-input-token")
	for _, test := range []struct {
		name   string
		reader io.Reader
		flags  []string
	}{
		{name: "reader failure", reader: f03ErrorReader{}},
		{name: "missing file", reader: f03PanicReader{}, flags: []string{"--file", filepath.Join(t.TempDir(), "private-file-path-marker.json")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string{"put", "--mount", "secret", "--kv-version", "2"}, test.flags...)
			args = append(args, "/secret/item")
			code, stdout, stderr := runWriteCLI(test.reader, args...)
			if code != 1 || stdout != "" || stderr == "" {
				t.Errorf("input failure returned exit=%d, stdout=%q, stderr=%q", code, stdout, stderr)
			}
			if strings.Contains(stderr, "private-") {
				t.Error("input failure diagnostic exposed an error, file path, or credential")
			}
		})
	}
	if requests.Load() != 0 {
		t.Errorf("failed input made %d requests", requests.Load())
	}
}

func TestKVWriteHelpIsOfflineAndDoesNotReadInput(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "private-invalid-address-marker")
	t.Setenv("VAULT_TOKEN", "private-help-token")
	for _, command := range []string{"put", "rm", "cp", "mv", "versions", "undelete", "destroy", "rollback", "cat"} {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := runWriteCLI(f03PanicReader{}, command, "--help")
			if code != 0 || stdout == "" || stderr != "" {
				t.Errorf("help failed: exit=%d, stdout=%q, stderr=%q", code, stdout, stderr)
			}
			if strings.Contains(stdout+stderr, "private-") {
				t.Error("help loaded private runtime configuration")
			}
		})
	}
}
