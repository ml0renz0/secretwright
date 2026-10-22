package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ml0renz0/secretwright/internal/cli"
)

func runShellCLI(input io.Reader, args ...string) (int, string, string) {
	var output, diagnostics bytes.Buffer
	code := cli.RunWithInput(context.Background(), args, input, &output, &diagnostics, "test")
	return code, output.String(), diagnostics.String()
}

func decodeShellOutputs(t *testing.T, output string) []any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(output))
	decoder.UseNumber()
	var values []any
	for {
		var value any
		err := decoder.Decode(&value)
		if err == io.EOF {
			return values
		}
		if err != nil {
			t.Fatal("session stdout contained a prompt, echo, or invalid JSON")
		}
		values = append(values, value)
	}
}

func TestShellSessionPreservesDirectoryAndUsesFixedConnection(t *testing.T) {
	cleanEnvironment(t)
	var lookups, reads, lists atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "session-selected-token" || r.Header.Get("X-Vault-Namespace") != "team" {
			t.Error("session lost its fixed namespace or explicitly selected credential")
		}
		if r.Method != http.MethodGet {
			t.Error("read-only session attempted a mutation")
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/sys/internal/ui/mounts/secret"):
			lookups.Add(1)
			kvWriteData(t, w, map[string]any{"path": "secret/", "type": "kv", "options": map[string]string{"version": "2"}})
		case r.URL.Path == "/v1/secret/metadata/app" && r.URL.Query().Get("list") == "true":
			lists.Add(1)
			kvWriteData(t, w, map[string]any{"keys": []string{"item", "nested/"}})
		case r.URL.Path == "/v1/secret/data/app/item":
			reads.Add(1)
			kvWriteData(t, w, map[string]any{"data": map[string]any{"value": "session-requested-secret"}})
		default:
			t.Error("session used a wrong logical directory or inspected the token")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("session-selected-token"), 0o600); err != nil {
		t.Fatal("could not prepare the private token file")
	}
	t.Setenv("VAULT_ADDR", "https://invalid.example")
	t.Setenv("VAULT_TOKEN", "inherited-token-not-selected")
	t.Setenv("VAULT_NAMESPACE", "inherited-namespace")
	input := "cd /secret/app\npwd\ncat item\nls\nhistory\n"
	code, output, diagnostics := runShellCLI(strings.NewReader(input), "shell", "--no-prompt", "--address", server.URL, "--namespace", "team", "--token-file", tokenFile)
	if code != 0 || diagnostics != "" {
		t.Fatalf("fixed-connection session failed: exit=%d, diagnostics=%q", code, diagnostics)
	}
	values := decodeShellOutputs(t, output)
	want := []any{
		map[string]any{"path": "/secret/app"},
		map[string]any{"path": "/secret/app"},
		map[string]any{"value": "session-requested-secret"},
		[]any{"item", "nested/"},
		[]any{"cd /secret/app", "pwd", "ls"},
	}
	if !reflect.DeepEqual(values, want) {
		t.Error("session did not preserve cwd, command JSON, or the safe history allowlist")
	}
	if reads.Load() != 1 || lists.Load() != 2 || lookups.Load() != 3 {
		t.Error("session repeated a command or performed an unrequested token lookup")
	}
	for _, token := range []string{"session-selected-token", "inherited-token-not-selected"} {
		if strings.Contains(output+diagnostics, token) {
			t.Error("session output exposed a credential")
		}
	}
}

func TestShellOfflineBuiltinsDoNotLoadCredentialsOrVault(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "private-invalid-address")
	t.Setenv("VAULT_CLIENT_TIMEOUT", "private-invalid-timeout")
	code, output, diagnostics := runShellCLI(strings.NewReader("pwd\nhistory\nexit\n"), "shell", "--cwd", "/secret/../apps", "--token-file", "/private/nonexistent-token")
	if code != 0 || diagnostics != "" {
		t.Error("offline session builtins consulted a token or network configuration")
	}
	want := []any{map[string]any{"path": "/apps"}, []any{"pwd"}}
	if !reflect.DeepEqual(decodeShellOutputs(t, output), want) {
		t.Error("offline builtins did not return canonical cwd and bounded session history")
	}
}

func TestShellBatchStopsAtFirstFailureWithoutPromptOrEcho(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
		code  int
	}{
		{name: "invalid command", input: "private-unknown-command private-token-marker\npwd\n", code: 1},
		{name: "malformed quote", input: "cat 'private-input-marker\npwd\n", code: 1},
		{name: "operator", input: "pwd; private-token-marker\npwd\n", code: 1},
		{name: "missing token", input: "cat /secret/item\npwd\n", code: 2},
		{name: "stdin put", input: "put /secret/item\n{\"private-value\":true}\npwd\n", code: 1},
		{name: "explicit stdin put", input: "put --file - /secret/item\npwd\n", code: 1},
		{name: "nested shell", input: "shell\npwd\n", code: 1},
		{name: "connection override", input: "cat --address https://private-host-marker /secret/item\npwd\n", code: 1},
		{name: "credential override", input: "cat --token-file private-token-marker /secret/item\npwd\n", code: 1},
		{name: "cwd override", input: "ls --cwd /private-path-marker /secret\npwd\n", code: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanEnvironment(t)
			code, output, diagnostics := runShellCLI(strings.NewReader(test.input), "shell", "--no-prompt")
			if code != test.code || output != "" || diagnostics == "" {
				t.Errorf("failed batch returned exit=%d or continued after the first failure", code)
			}
			for _, marker := range []string{"private-", "secretwright:/", "[0]"} {
				if strings.Contains(output+diagnostics, marker) {
					t.Error("batch diagnostics echoed input, credentials, a path, or a prompt")
				}
			}
		})
	}
}

func TestShellScriptAndNoPromptAliasesUseTheSameSession(t *testing.T) {
	cleanEnvironment(t)
	input := "# private-comment-marker\r\n\r\npwd\r\nexit\r\nprivate-unreached-command\r\n"
	for _, args := range [][]string{{"shell", "--no-prompt"}, {"--no-prompt"}} {
		code, output, diagnostics := runShellCLI(strings.NewReader(input), args...)
		if code != 0 || diagnostics != "" || !reflect.DeepEqual(decodeShellOutputs(t, output), []any{map[string]any{"path": "/"}}) {
			t.Error("stdin session alias added prompts or changed script semantics")
		}
	}
	filename := filepath.Join(t.TempDir(), "operations with spaces.sw")
	if err := os.WriteFile(filename, []byte(input), 0o600); err != nil {
		t.Fatal("could not prepare the private command file")
	}
	for _, args := range [][]string{{"shell", "--script", filename}, {"--script", filename}} {
		code, output, diagnostics := runShellCLI(f03PanicReader{}, args...)
		if code != 0 || diagnostics != "" || !reflect.DeepEqual(decodeShellOutputs(t, output), []any{map[string]any{"path": "/"}}) {
			t.Error("script-file session consumed stdin or changed the common command engine")
		}
	}
	for _, args := range [][]string{{"shell", "--script", "-"}, {"shell", "--script", "/private-missing-file"}, {"shell", "--cwd", "relative"}} {
		code, output, diagnostics := runShellCLI(f03PanicReader{}, args...)
		if code != 1 || output != "" || diagnostics == "" || strings.Contains(diagnostics, "private-") {
			t.Error("invalid shell startup exposed a filename or consumed stdin")
		}
	}
}

func TestShellPutUsesExplicitFileWithoutConsumingFollowingCommands(t *testing.T) {
	cleanEnvironment(t)
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/secret/data/app/item" || (r.Method != http.MethodPost && r.Method != http.MethodPut) {
			t.Error("session file write used an unexpected operation")
		}
		var request struct {
			Data    map[string]any `json:"data"`
			Options struct {
				CAS int `json:"cas"`
			} `json:"options"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Options.CAS != 0 || request.Data["value"] != "private-file-only-value" {
			t.Error("session altered file data or omitted create-only CAS")
		}
		writes.Add(1)
		kvWriteData(t, w, map[string]any{"version": 1})
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "private-file-token")
	filename := filepath.Join(t.TempDir(), "values with spaces.json")
	if err := os.WriteFile(filename, []byte(`{"value":"private-file-only-value"}`), 0o600); err != nil {
		t.Fatal("could not prepare the private data file")
	}
	input := fmt.Sprintf("put --mount secret --kv-version 2 --file %q item\npwd\nhistory\n", filename)
	code, output, diagnostics := runShellCLI(strings.NewReader(input), "shell", "--cwd", "/secret/app")
	if code != 0 || diagnostics != "" || writes.Load() != 1 {
		t.Error("file-only put consumed session commands or failed to preserve its cwd")
	}
	want := []any{map[string]any{"path": "/secret/app/item", "kv_version": json.Number("2"), "version": json.Number("1")}, map[string]any{"path": "/secret/app"}, []any{"pwd"}}
	if !reflect.DeepEqual(decodeShellOutputs(t, output), want) {
		t.Error("session write result or history included data or file arguments")
	}
	if strings.Contains(output+diagnostics, "private-file-") || strings.Contains(output+diagnostics, filename) {
		t.Error("session exposed a data filename, token, or secret value")
	}
}
