package cli_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func accessInputFile(t *testing.T, body string) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "private-access-input.json")
	if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
		t.Fatal("could not prepare private access input")
	}
	return name
}

func accessJSON(t *testing.T, output string) map[string]any {
	t.Helper()
	var result map[string]any
	if json.Unmarshal([]byte(output), &result) != nil {
		t.Fatal("access command did not return valid JSON metadata")
	}
	return result
}

func accessReply(t *testing.T, w http.ResponseWriter, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if json.NewEncoder(w).Encode(body) != nil {
		t.Error("could not prepare access response")
	}
}

func issuedAccessToken() map[string]any {
	return map[string]any{"auth": map[string]any{
		"client_token": "private-issued-token", "accessor": "private-issued-accessor",
		"policies": []string{"app"}, "token_policies": []string{"app"},
		"lease_duration": 60, "renewable": false,
	}}
}

func TestAccessHelpAndInvalidCommandsAreOffline(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "private-invalid-address")
	for _, args := range [][]string{
		{"policy"}, {"policy", "list"}, {"policy", "read"}, {"policy", "write"}, {"policy", "delete"},
		{"approle"}, {"approle", "list"}, {"approle", "read"}, {"approle", "write"}, {"approle", "delete"},
		{"approle", "role-id"}, {"approle", "credentials"}, {"approle", "revoke-secret-id"}, {"approle", "login"},
		{"token"}, {"token", "create"}, {"token", "revoke"}, {"token", "revoke-self"}, {"token", "capabilities"},
		{"identity"}, {"identity", "entity"}, {"identity", "entity", "list"}, {"identity", "entity", "read"},
		{"identity", "entity", "write"}, {"identity", "entity", "delete"},
		{"identity", "group"}, {"identity", "group", "list"}, {"identity", "group", "read"},
		{"identity", "group", "write"}, {"identity", "group", "delete"},
	} {
		command := append(append([]string(nil), args...), "--help")
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, command...)
		if code != 0 || !strings.Contains(output, "Usage:") || diagnostics != "" {
			t.Errorf("access help failed for %s", strings.Join(args, " "))
		}
	}
	for _, args := range [][]string{
		{"policy", "read", "private/bad"}, {"policy", "delete", "app"},
		{"policy", "delete", "--force", "root"}, {"policy", "delete", "--force", "default"},
		{"approle", "read", "--auth-mount", "private/../approle", "app"},
		{"approle", "login", "--token-file", "private-token", "--file", "-", "--out", "private-out"},
		{"token", "revoke-self"}, {"token", "capabilities", "/v1/secret/data/item"},
		{"identity", "entity", "read", "private-not-uuid"},
		{"identity", "group", "delete", "--force", "private/bad"},
	} {
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		if code != 1 || output != "" || diagnostics == "" || strings.Contains(diagnostics, "private-") || strings.Contains(diagnostics, "private/") {
			t.Errorf("access invalid options were not rejected safely: %s", args[0])
		}
	}
}

func TestAccessInputAndExistingCredentialOutputsFailBeforeRequests(t *testing.T) {
	cleanEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "private-operator-token")
	for _, test := range []struct {
		prefix []string
		body   string
	}{
		{prefix: []string{"approle", "write"}, body: `{"token_policies":["root"]}`},
		{prefix: []string{"token", "create"}, body: `{"policies":["app"],"ttl":"1m","ttl":"2m","explicit_max_ttl":"3m"}`},
		{prefix: []string{"approle", "login"}, body: `{"role_id":"private-role","secret_id":"private-secret","unexpected":true}`},
		{prefix: []string{"identity", "entity", "write"}, body: `{"name":"app","metadata":{"value":"private-value"}}`},
	} {
		args := append(append([]string(nil), test.prefix...), "--file", accessInputFile(t, test.body))
		if test.prefix[0] == "token" || test.prefix[1] == "login" {
			args = append(args, "--out", filepath.Join(t.TempDir(), "credential"))
		}
		if test.prefix[0] == "approle" && test.prefix[1] == "write" {
			args = append(args, "app")
		}
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		if code != 1 || output != "" || diagnostics == "" || strings.Contains(diagnostics, "private-") {
			t.Error("invalid access file was not rejected without exposing input")
		}
	}
	directory := t.TempDir()
	existing := filepath.Join(directory, "existing")
	if os.WriteFile(existing, []byte("private-existing"), 0o600) != nil {
		t.Fatal("could not prepare existing credential output")
	}
	link := filepath.Join(directory, "existing-link")
	if os.Symlink(existing, link) != nil {
		t.Fatal("could not prepare credential output symlink")
	}
	for _, name := range []string{existing, link} {
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, "approle", "role-id", "--out", name, "app")
		if code != 1 || output != "" || diagnostics == "" || strings.Contains(diagnostics, name) {
			t.Error("existing credential output did not fail safely before issuance")
		}
	}
	if requests.Load() != 0 {
		t.Error("invalid input or existing credential output contacted Vault")
	}
	if contents, _ := os.ReadFile(existing); string(contents) != "private-existing" {
		t.Error("credential output overwrote an existing file")
	}
}

func TestCreatedTokenIsPrivateAndNeverPrinted(t *testing.T) {
	cleanEnvironment(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/create" || r.Method != http.MethodPost || r.Header.Get("X-Vault-Token") != "private-operator-token" {
			t.Error("token creation did not use the selected operator and endpoint")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		accessReply(t, w, issuedAccessToken())
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "private-operator-token")
	spec := accessInputFile(t, `{"policies":["app"],"ttl":"1m","explicit_max_ttl":"2m"}`)
	outputFile := filepath.Join(t.TempDir(), "token")
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, "token", "create", "--file", spec, "--out", outputFile)
	if code != 0 || diagnostics != "" || strings.Contains(output, "private-") {
		t.Fatal("token creation did not return safe metadata")
	}
	if accessJSON(t, output)["kind"] != "token" {
		t.Error("token creation report omitted its credential kind")
	}
	contents, err := os.ReadFile(outputFile)
	info, statErr := os.Stat(outputFile)
	if err != nil || statErr != nil || string(contents) != "private-issued-token\n" || info.Mode().Perm() != 0o600 {
		t.Error("created token was not committed to its private compatible token file")
	}
}

func TestAppRoleLoginIgnoresTheOperatorAndDoesNotChangeTheSession(t *testing.T) {
	cleanEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/v1/auth/custom/approle/login" || r.Header.Get("X-Vault-Token") != "" || r.Header.Get("X-Vault-Namespace") != "team" {
			t.Error("AppRole login inherited operator credentials or lost its namespace")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		accessReply(t, w, issuedAccessToken())
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "private-inherited-operator")
	input := accessInputFile(t, `{"role_id":"private-role-id","secret_id":"private-secret-id"}`)
	out := filepath.Join(t.TempDir(), "login-token")
	source := "approle login --auth-mount custom/approle --file '" + input + "' --out '" + out + "'\nhistory\n"
	code, output, diagnostics := runWriteCLI(strings.NewReader(source), "shell", "--namespace", "team", "--token-file", filepath.Join(t.TempDir(), "missing-operator"), "--no-prompt")
	if code != 0 || diagnostics != "" || strings.Contains(output, "private-") || requests.Load() != 1 {
		t.Fatal("AppRole login did not remain anonymous inside a configured shell")
	}
	var report map[string]any
	decoder := json.NewDecoder(strings.NewReader(output))
	if decoder.Decode(&report) != nil {
		t.Fatal("login did not produce a metadata report")
	}
	var history []string
	if decoder.Decode(&history) != nil || len(history) != 0 {
		t.Error("access command entered the session history")
	}
}

func TestAccessShellRejectsNestedConnectionOverrides(t *testing.T) {
	cleanEnvironment(t)
	for _, source := range []string{
		"policy list --address private-override\n",
		"approle delete --force --namespace private-override app\n",
		"identity entity read --timeout 1s 11111111-1111-1111-1111-111111111111\n",
		"identity group delete --force --token-file private-override 11111111-1111-1111-1111-111111111111\n",
		"token revoke-self --force --address private-override\n",
	} {
		code, output, diagnostics := runWriteCLI(strings.NewReader(source), "shell", "--no-prompt")
		if code != 1 || output != "" || !strings.Contains(diagnostics, "shell startup") || strings.Contains(diagnostics, "private-") {
			t.Error("nested access command bypassed the fixed session connection")
		}
	}
}

func TestCredentialPublicationFailureCompensatesWithoutDeletingAnotherFile(t *testing.T) {
	cleanEnvironment(t)
	destination := filepath.Join(t.TempDir(), "token")
	var revoked atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/token/create":
			if os.Remove(destination) != nil || os.WriteFile(destination, []byte("replacement-file"), 0o600) != nil {
				t.Error("could not simulate loss of the reserved output")
			}
			accessReply(t, w, issuedAccessToken())
		case "/v1/auth/token/revoke-accessor":
			revoked.Add(1)
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["accessor"] != "private-issued-accessor" {
				t.Error("compensation did not revoke the issued token by accessor")
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Error("credential publication retried or made an unexpected request")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "private-operator-token")
	spec := accessInputFile(t, `{"policies":["app"],"ttl":"1m","explicit_max_ttl":"2m"}`)
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, "token", "create", "--file", spec, "--out", destination)
	if code != 1 || output != "" || diagnostics == "" || strings.Contains(diagnostics, "private-") || revoked.Load() != 1 {
		t.Error("failed credential publication did not perform safe compensation")
	}
	if contents, _ := os.ReadFile(destination); !reflect.DeepEqual(contents, []byte("replacement-file")) {
		t.Error("credential cleanup removed or changed a file it no longer owned")
	}
}
