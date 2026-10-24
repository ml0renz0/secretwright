package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/cli"
)

const blueprintCLIPolicy = `path "private-blueprint-configuration/app/*" { capabilities = ["read"] }`

func blueprintCLIInput(t *testing.T, body string) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "private-blueprint-input.yaml")
	if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
		t.Fatal("could not prepare blueprint input")
	}
	return name
}

func blueprintCLIDocument(t *testing.T, names ...string) string {
	t.Helper()
	resources := make([]any, 0, len(names))
	for _, name := range names {
		resources = append(resources, map[string]any{
			"id": name, "kind": "policy", "name": name,
			"spec": map[string]any{"policy": blueprintCLIPolicy},
		})
	}
	body, err := json.Marshal(map[string]any{
		"api_version": "secretwright/v1", "name": "test-blueprint", "resources": resources,
	})
	if err != nil {
		t.Fatal("could not encode blueprint input")
	}
	return blueprintCLIInput(t, string(body))
}

func blueprintCLIReport(t *testing.T, output string) map[string]any {
	t.Helper()
	var report map[string]any
	if json.Unmarshal([]byte(output), &report) != nil {
		t.Fatal("blueprint command did not produce JSON metadata")
	}
	return report
}

func TestBlueprintOfflineCommandsIgnoreCredentialsAndNetworkConfiguration(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "private-invalid-address")
	t.Setenv("VAULT_CACERT", filepath.Join(t.TempDir(), "private-missing-ca"))
	for _, args := range [][]string{
		{"blueprint"}, {"blueprint", "--help"}, {"blueprint", "schema", "--help"},
		{"blueprint", "validate", "--help"}, {"blueprint", "plan", "--help"}, {"blueprint", "apply", "--help"},
	} {
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		if code != 0 || !strings.Contains(output, "Usage:") || diagnostics != "" {
			t.Error("blueprint help was not offline")
		}
	}
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, "blueprint", "schema")
	if code != 0 || diagnostics != "" || blueprintCLIReport(t, output)["$id"] != "urn:secretwright:blueprint:v1" {
		t.Fatal("blueprint schema was not exported offline")
	}
	name := blueprintCLIDocument(t, "app")
	code, output, diagnostics = runWriteCLI(f03PanicReader{}, "blueprint", "validate", "--file", name)
	report := blueprintCLIReport(t, output)
	if code != 0 || diagnostics != "" || report["name"] != "test-blueprint" || report["resources"] != float64(1) || strings.Contains(output, "private-") {
		t.Error("blueprint validation consulted configuration or exposed its spec")
	}
}

func TestBlueprintRejectsOptionsAndInvalidFilesBeforeCredentialsOrHTTP(t *testing.T) {
	cleanEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "private-blueprint-operator")
	invalid := blueprintCLIInput(t, "api_version: secretwright/v1\nname: private-invalid-marker\nresources: [untrusted-private-spec]\n")
	missingToken := filepath.Join(t.TempDir(), "private-missing-token")
	for _, args := range [][]string{
		{"blueprint", "delete"}, {"blueprint", "schema", "--file", invalid},
		{"blueprint", "validate", "--address", server.URL, "--file", invalid},
		{"blueprint", "validate", "--file", "-"}, {"blueprint", "plan", "--file", "-"},
		{"blueprint", "apply", "--file", invalid, "--vars", "-"},
		{"blueprint", "plan", "--file", invalid, "--token-file", missingToken},
		{"blueprint", "apply", "--file", invalid, "--token-file", missingToken},
		{"blueprint", "apply", "--file", invalid, "unexpected"},
	} {
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		if code != 1 || output != "" || diagnostics == "" || strings.Contains(diagnostics, "private-") || strings.Contains(diagnostics, "token file") {
			t.Error("invalid blueprint options or document were not rejected safely before credentials")
		}
	}
	if requests.Load() != 0 {
		t.Error("invalid blueprint input contacted Vault")
	}
}

func TestBlueprintValidateUsesExplicitVariableFileWithoutPrintingValues(t *testing.T) {
	cleanEnvironment(t)
	name := blueprintCLIInput(t, `api_version: secretwright/v1
name: app
variables:
  target: {type: string}
resources:
  - id: app
    kind: policy
    name: app
    spec:
      policy: 'path "${var.target}/*" { capabilities = ["read"] }'
`)
	variables := blueprintCLIInput(t, "target: private-variable-value\n")
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, "blueprint", "validate", "--file", name, "--vars", variables)
	if code != 0 || diagnostics != "" || blueprintCLIReport(t, output)["name"] != "app" || strings.Contains(output, "private-") {
		t.Error("blueprint variables were not loaded privately from the selected file")
	}
}

func TestBlueprintPlanAndApplyAreIdempotentAndReportsContainOnlyMetadata(t *testing.T) {
	cleanEnvironment(t)
	var mu sync.Mutex
	policies := make(map[string]string)
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/sys/policies/acl/") || r.Header.Get("X-Vault-Token") != "private-blueprint-operator" {
			t.Error("blueprint used a different endpoint or credential")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/v1/sys/policies/acl/")
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodGet {
			policy, exists := policies[name]
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			accessReply(t, w, map[string]any{"data": map[string]any{"policy": policy}})
			return
		}
		if r.Method != http.MethodPost {
			t.Error("blueprint performed an unsupported mutation")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var input struct {
			Policy string `json:"policy"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil || input.Policy == "" {
			t.Error("blueprint lost the desired policy")
		}
		policies[name] = input.Policy
		writes.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "private-blueprint-operator")
	name := blueprintCLIDocument(t, "app")
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, "blueprint", "plan", "--file", name)
	if code != 0 || diagnostics != "" || writes.Load() != 0 || len(blueprintCLIReport(t, output)["changes"].([]any)) != 1 {
		t.Fatal("blueprint plan wrote resources or omitted its create action")
	}
	code, output, diagnostics = runWriteCLI(f03PanicReader{}, "blueprint", "apply", "--file", name)
	if code != 0 || diagnostics != "" || writes.Load() != 1 || len(blueprintCLIReport(t, output)["items"].([]any)) != 1 {
		t.Fatal("blueprint apply did not confirm the planned creation")
	}
	for _, action := range []string{"plan", "apply"} {
		code, output, diagnostics = runWriteCLI(f03PanicReader{}, "blueprint", action, "--file", name)
		report := blueprintCLIReport(t, output)
		if code != 0 || diagnostics != "" || writes.Load() != 1 || strings.Contains(output, "private-") {
			t.Error("blueprint repeated a mutation or leaked configuration")
		}
		if action == "plan" && !reflect.DeepEqual(report["changes"], []any{}) {
			t.Error("blueprint did not produce an empty plan after apply")
		}
	}
}

func TestBlueprintConflictsAndDeniedReadsBlockAllWrites(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(map[bool]string{false: "conflict", true: "denied"}[denied], func(t *testing.T) {
			cleanEnvironment(t)
			var writes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					writes.Add(1)
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/a") {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if denied {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				accessReply(t, w, map[string]any{"data": map[string]any{"policy": `path "private-existing-configuration" { capabilities = ["deny"] }`}})
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", server.URL)
			t.Setenv("VAULT_TOKEN", "private-blueprint-operator")
			name := blueprintCLIDocument(t, "a", "z")
			for _, action := range []string{"plan", "apply"} {
				code, output, diagnostics := runWriteCLI(f03PanicReader{}, "blueprint", action, "--file", name)
				want := 4
				if denied {
					want = 2
				}
				if code != want || diagnostics == "" || writes.Load() != 0 || strings.Contains(output+diagnostics, "private-") {
					t.Error("blueprint conflict or denied preflight changed a resource or exposed configuration")
				}
				if denied && output != "" {
					t.Error("blueprint presented an incomplete denied plan as complete")
				}
				if !denied && output == "" {
					t.Error("blueprint omitted the complete conflict report")
				}
			}
		})
	}
}

func TestBlueprintApplyReportsPartialChangesAndDoesNotDispatchTheRemainder(t *testing.T) {
	cleanEnvironment(t)
	var created atomic.Bool
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if strings.HasSuffix(r.URL.Path, "/a") && created.Load() {
				accessReply(t, w, map[string]any{"data": map[string]any{"policy": blueprintCLIPolicy}})
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writes.Add(1)
		if strings.HasSuffix(r.URL.Path, "/a") {
			created.Store(true)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/b") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		t.Error("blueprint dispatched a mutation after its first failure")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "private-blueprint-operator")
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, "blueprint", "apply", "--file", blueprintCLIDocument(t, "a", "b", "c"))
	if code != 5 || diagnostics == "" || writes.Load() != 2 {
		t.Fatal("blueprint did not preserve the partial mutation exit code")
	}
	items := blueprintCLIReport(t, output)["items"].([]any)
	statuses := make([]string, 0, len(items))
	for _, value := range items {
		statuses = append(statuses, value.(map[string]any)["status"].(string))
	}
	if !reflect.DeepEqual(statuses, []string{"created", "failed", "not_started"}) || strings.Contains(output+diagnostics, "private-") {
		t.Error("blueprint partial report lost ordered statuses or exposed configuration")
	}
}

func TestBlueprintTimeoutBoundsTheWholePlan(t *testing.T) {
	cleanEnvironment(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(40 * time.Millisecond):
			w.WriteHeader(http.StatusNotFound)
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "private-blueprint-operator")
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, "blueprint", "plan", "--timeout", "60ms", "--file", blueprintCLIDocument(t, "a", "b"))
	if code != 1 || output != "" || diagnostics == "" {
		t.Error("blueprint reset the timeout for each individual request")
	}
}

func TestShellBlueprintOfflineCommandsKeepHistoryEmptyAndRejectNestedOverrides(t *testing.T) {
	cleanEnvironment(t)
	name := blueprintCLIDocument(t, "app")
	commands := "blueprint validate --file " + name + "\nhistory\n"
	code, output, diagnostics := runShellCLI(strings.NewReader(commands), "shell", "--no-prompt", "--address", "private-invalid-address", "--token-file", filepath.Join(t.TempDir(), "private-missing-token"))
	values := decodeShellOutputs(t, output)
	if code != 0 || diagnostics != "" || len(values) != 2 || !reflect.DeepEqual(values[1], []any{}) {
		t.Error("shell offline validation inherited connection arguments or entered history")
	}
	for _, line := range []string{
		"blueprint plan --address https://private-override-marker --file " + name,
		"blueprint apply --file " + name + " --namespace private-override-marker",
		"blueprint validate --file -", "blueprint apply --file " + name + " --vars -",
	} {
		code, output, diagnostics = runShellCLI(strings.NewReader(line+"\npwd\n"), "shell", "--no-prompt")
		if code != 1 || output != "" || diagnostics == "" || strings.Contains(diagnostics, "private-") {
			t.Error("shell accepted nested blueprint overrides or consumed its command stream")
		}
	}
}

func TestShellBlueprintPlanKeepsStartupConnectionAndTokenWithoutKVCWD(t *testing.T) {
	cleanEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/v1/sys/policies/acl/app" ||
			r.Header.Get("X-Vault-Token") != "private-blueprint-file-token" || r.Header.Get("X-Vault-Namespace") != "team" {
			t.Error("shell blueprint plan lost its fixed startup connection or credentials")
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", "private-invalid-inherited-address")
	t.Setenv("VAULT_TOKEN", "private-invalid-inherited-token")
	name := blueprintCLIDocument(t, "app")
	token := blueprintCLIInput(t, "private-blueprint-file-token")
	commands := "blueprint plan --file " + name + "\nhistory\n"
	code, output, diagnostics := runShellCLI(strings.NewReader(commands), "shell", "--no-prompt", "--address", server.URL, "--namespace", "team", "--token-file", token, "--cwd", "/unused-kv-directory")
	values := decodeShellOutputs(t, output)
	if code != 0 || diagnostics != "" || requests.Load() == 0 || len(values) != 2 || !reflect.DeepEqual(values[1], []any{}) || strings.Contains(output, "private-") {
		t.Error("shell blueprint plan inherited KV cwd, exposed credentials or entered history")
	}
}

type blueprintShortWriter struct{}

func (blueprintShortWriter) Write(value []byte) (int, error) { return len(value) - 1, nil }

func TestBlueprintSchemaReportsShortWrites(t *testing.T) {
	var diagnostics bytes.Buffer
	code := cli.RunWithInput(context.Background(), []string{"blueprint", "schema"}, f03PanicReader{}, blueprintShortWriter{}, &diagnostics, "test")
	if code != 1 || diagnostics.Len() == 0 {
		t.Error("blueprint schema silently accepted a truncated output")
	}
}

