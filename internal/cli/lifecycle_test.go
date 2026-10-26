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

	"github.com/ml0renz0/secretwright/internal/blueprint"
	"github.com/ml0renz0/secretwright/internal/cli"
)

func lifecycleCLIFile(t *testing.T, body string) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "private-lifecycle-input")
	if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
		t.Fatal("could not prepare private lifecycle input")
	}
	return name
}

func lifecycleCLIPolicy(t *testing.T) string {
	t.Helper()
	consumer := lifecycleCLIFile(t, "private-old-consumer-token\n")
	return lifecycleCLIFile(t, fmt.Sprintf(`api_version: secretwright/lifecycle/v1
name: payments-api
provider: {kind: approle, auth_mount: approle, role: payments-api}
consumer: {kind: token-file, path: %q}
verify: {kind: kv-read, mount: secret, kv_version: 2, path: /secret/payments/health}
policy: {rotate_below: 5m, minimum_new_ttl: 10m}
`, consumer))
}

func TestLifecycleOfflineExampleSchemaAndValidation(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "private-invalid-address")
	t.Setenv("VAULT_CACERT", "/private-missing-ca")
	t.Setenv("VAULT_TOKEN", "private-offline-operator")
	for _, format := range []string{"", "yaml", "json"} {
		args := []string{"lifecycle", "example"}
		if format != "" {
			args = append(args, "--format", format)
		}
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		document, err := blueprint.DecodeConfiguration(strings.NewReader(output))
		if code != 0 || diagnostics != "" || err != nil || document["api_version"] != "secretwright/lifecycle/v1" {
			t.Fatal("offline lifecycle example was not a complete configuration")
		}
		if format == "json" && !json.Valid([]byte(output)) || format != "json" && json.Valid([]byte(output)) {
			t.Error("lifecycle example lost YAML default or explicit JSON selection")
		}
		code, report, diagnostics := runWriteCLI(f03PanicReader{}, "lifecycle", "validate", "--file", lifecycleCLIFile(t, output))
		var metadata map[string]any
		if code != 0 || diagnostics != "" || json.Unmarshal([]byte(report), &metadata) != nil || metadata["name"] != document["name"] {
			t.Error("offline example did not pass lifecycle validation with JSON metadata")
		}
		for _, disallowed := range []string{"consumer", "provider", "verify", "policy", "path"} {
			if _, present := metadata[disallowed]; present {
				t.Error("lifecycle validation report exposed configuration")
			}
		}
	}
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, "lifecycle", "schema")
	var schema map[string]any
	if code != 0 || diagnostics != "" || json.Unmarshal([]byte(output), &schema) != nil || schema["$id"] != "urn:secretwright:lifecycle:v1" {
		t.Error("lifecycle schema was not available offline as JSON")
	}
}

func TestLifecycleHelpIsOfflineAtEveryCommandDepth(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "private-invalid-address")
	t.Setenv("VAULT_CACERT", "/private-missing-ca")
	for _, prefix := range [][]string{
		{"lifecycle"}, {"lifecycle", "schema"}, {"lifecycle", "example"},
		{"lifecycle", "validate"}, {"lifecycle", "inspect"}, {"lifecycle", "rotate"},
		{"lifecycle", "retire"}, {"lifecycle", "recover"},
		{"lifecycle", "token"}, {"lifecycle", "token", "inspect"}, {"lifecycle", "token", "renew"},
		{"lifecycle", "lease"}, {"lifecycle", "lease", "inspect"},
		{"lifecycle", "lease", "renew"}, {"lifecycle", "lease", "revoke"},
	} {
		args := append(append([]string(nil), prefix...), "--help")
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		if code != 0 || diagnostics != "" || !strings.Contains(output, "Usage:") {
			t.Error("lifecycle help read files, credentials or network configuration")
		}
	}
}

func TestLifecycleRejectsInvalidOptionsAndPrivateInputsBeforeNetwork(t *testing.T) {
	cleanEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "")
	policy := lifecycleCLIPolicy(t)
	target := lifecycleCLIFile(t, "private-target-token\n")
	lease := lifecycleCLIFile(t, "lease_id: database/creds/private-role/private-lease\n")
	badLease := lifecycleCLIFile(t, "lease_id: database/creds/private-role/private-lease\nextra: private-value\n")
	receipt := lifecycleCLIFile(t, "private-malformed-receipt")
	public := lifecycleCLIFile(t, "private-public-token")
	if err := os.Chmod(public, 0o644); err != nil {
		t.Fatal("could not prepare unprotected input")
	}
	link := filepath.Join(t.TempDir(), "private-token-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal("could not prepare input symlink")
	}
	for _, args := range [][]string{
		{"lifecycle", "private-unknown"}, {"lifecycle", "schema", "--format", "yaml"},
		{"lifecycle", "example", "--format", "private-unknown"}, {"lifecycle", "example", "--address", server.URL},
		{"lifecycle", "validate", "--file", "-"}, {"lifecycle", "validate", "--file", policy, "private-extra"},
		{"lifecycle", "validate", "--file", policy, "--token-file", target},
		{"lifecycle", "inspect", "--file", policy},
		{"lifecycle", "inspect", "--file", policy, "--receipt", receipt},
		{"lifecycle", "rotate", "--file", policy, "--receipt", "-"},
		{"lifecycle", "retire", "--file", policy, "--receipt", receipt},
		{"lifecycle", "recover", "--file", policy, "--receipt", receipt, "--format", "json"},
		{"lifecycle", "inspect", "--file", policy, "--receipt", receipt, "--cwd", "/private-cwd"},
		{"lifecycle", "token", "inspect", "private-target-token"},
		{"lifecycle", "token", "inspect", "--file", "-"},
		{"lifecycle", "token", "inspect", "--file", public},
		{"lifecycle", "token", "inspect", "--file", link},
		{"lifecycle", "token", "inspect", "--file", target, "--dry-run"},
		{"lifecycle", "token", "inspect", "--file", target, "--increment", "1m"},
		{"lifecycle", "token", "renew", "--file", target},
		{"lifecycle", "lease", "inspect", "--file", badLease},
		{"lifecycle", "lease", "revoke", "--file", lease},
		{"lifecycle", "lease", "inspect", "database/creds/private-role/private-lease"},
		{"lifecycle", "lease", "revoke", "--file", lease, "--force", "--prefix", "private-prefix"},
	} {
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		if code != 1 || output != "" || diagnostics == "" || strings.Contains(diagnostics, "private-") {
			t.Error("invalid lifecycle invocation was accepted or exposed private input")
		}
	}
	for _, duration := range []string{"0", "-1s", "1ms", "1.5s", "24h1s", "private-duration"} {
		for _, kind := range []string{"token", "lease"} {
			file := target
			if kind == "lease" {
				file = lease
			}
			for _, args := range [][]string{
				{"lifecycle", kind, "renew", "--file", file, "--increment", duration},
				{"lifecycle", kind, "renew", "--file", file, "--increment", "1m", "--if-ttl-below", duration},
			} {
				code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
				if code != 1 || output != "" || diagnostics == "" || strings.Contains(diagnostics, "private-") {
					t.Error("invalid lifecycle duration reached credential or network selection")
				}
			}
		}
	}
	if requests.Load() != 0 {
		t.Error("invalid lifecycle invocation contacted Vault")
	}
}

func lifecycleTokenLookup(ttl int64) map[string]any {
	return map[string]any{"data": map[string]any{
		"id": "private-target-token", "accessor": "private-target-accessor", "ttl": ttl,
		"renewable": true, "type": "service", "num_uses": 0, "policies": []string{"app"},
		"path": "auth/approle/login", "meta": map[string]any{"role_name": "app"},
		"entity_id": "11111111-1111-4111-8111-111111111111",
	}}
}

func TestLifecycleTokenRenewUsesPrivateTargetAndReportsActualTTL(t *testing.T) {
	cleanEnvironment(t)
	target := lifecycleCLIFile(t, "private-target-token\n")
	operator := lifecycleCLIFile(t, "private-selected-operator\n")
	var renewals atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "private-selected-operator" || r.Header.Get("X-Vault-Namespace") != "team" || strings.Contains(r.URL.String(), "private-") {
			t.Error("target credential was used as operator, URL or namespace")
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil || body["token"] != "private-target-token" {
			t.Error("token lifecycle request omitted its private body target")
		}
		switch r.URL.Path {
		case "/v1/auth/token/lookup":
			if r.Method != http.MethodPost {
				t.Error("token inspection did not use operator lookup")
			}
			ttl := int64(125)
			if renewals.Load() != 0 {
				ttl = 93
			}
			accessReply(t, w, lifecycleTokenLookup(ttl))
		case "/v1/auth/token/renew":
			renewals.Add(1)
			if r.Method != http.MethodPut || body["increment"] != float64(60) {
				t.Error("token renewal changed its explicit bounded increment")
			}
			accessReply(t, w, map[string]any{"auth": map[string]any{"client_token": "private-target-token", "lease_duration": 93, "renewable": true, "policies": []string{"app"}}})
		default:
			t.Error("token lifecycle used an unexpected endpoint")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	for _, test := range []struct {
		action string
		flags []string
		ttl int64
		mutations int32
	}{
		{"inspect", nil, 125, 0},
		{"renew", []string{"--increment", "1m", "--dry-run"}, 125, 0},
		{"renew", []string{"--increment", "1m", "--if-ttl-below", "100s"}, 125, 0},
		{"renew", []string{"--increment", "1m", "--if-ttl-below", "3m"}, 93, 1},
	} {
		args := []string{"lifecycle", "token", test.action, "--address", server.URL, "--namespace", "team", "--token-file", operator, "--file", target}
		args = append(args, test.flags...)
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		var report struct { TTL int64 `json:"ttl_seconds"` }
		if code != 0 || diagnostics != "" || json.Unmarshal([]byte(output), &report) != nil || report.TTL != test.ttl || renewals.Load() != test.mutations || strings.Contains(output, "private-") {
			t.Error("token lifecycle did not report actual TTL without exposing its private target")
		}
	}
	for _, writer := range []io.Writer{failedWriter{}, blueprintShortWriter{}} {
		var diagnostics bytes.Buffer
		code := cli.RunWithInput(context.Background(), []string{"lifecycle", "token", "inspect", "--address", server.URL, "--namespace", "team", "--token-file", operator, "--file", target}, f03PanicReader{}, writer, &diagnostics, "test")
		if code != 1 || diagnostics.Len() == 0 || strings.Contains(diagnostics.String(), "private-") {
			t.Error("lifecycle inspection ignored failed or short output writes")
		}
	}
}

func TestLifecycleLeaseCommandsUseExactPrivateIDAndFixedShellConnection(t *testing.T) {
	cleanEnvironment(t)
	leaseID := "database/creds/private-role/private-lease"
	lease := lifecycleCLIFile(t, "lease_id: "+leaseID+"\n")
	operator := lifecycleCLIFile(t, "private-selected-operator\n")
	t.Setenv("VAULT_TOKEN", "private-unselected-operator")
	var renewals, revocations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "private-selected-operator" || r.Header.Get("X-Vault-Namespace") != "team" || strings.Contains(r.URL.String(), "private-") {
			t.Error("lease lifecycle did not preserve its fixed operator, namespace or private ID")
		}
		var body map[string]any
		if r.Method != http.MethodPut || json.NewDecoder(r.Body).Decode(&body) != nil || body["lease_id"] != leaseID {
			t.Error("lease lifecycle did not send the exact ID in its request body")
		}
		switch r.URL.Path {
		case "/v1/sys/leases/lookup":
			if revocations.Load() != 0 {
				w.WriteHeader(http.StatusBadRequest)
				accessReply(t, w, map[string]any{"errors": []string{"invalid lease"}})
				return
			}
			ttl := 125
			if renewals.Load() != 0 {
				ttl = 90
			}
			accessReply(t, w, map[string]any{"data": map[string]any{"id": leaseID, "ttl": ttl, "renewable": true}})
		case "/v1/sys/leases/renew":
			renewals.Add(1)
			if body["increment"] != float64(60) {
				t.Error("lease lifecycle did not send its bounded increment in seconds")
			}
			accessReply(t, w, map[string]any{"lease_id": leaseID, "lease_duration": 90, "renewable": true})
		case "/v1/sys/leases/revoke":
			revocations.Add(1)
			if body["sync"] != true || body["force"] != nil || body["prefix"] != nil {
				t.Error("lease acknowledgment invoked a force or prefix endpoint")
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Error("lease lifecycle used an unexpected endpoint")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	source := strings.Join([]string{
		"lifecycle lease inspect --file " + lease,
		"lifecycle lease renew --file " + lease + " --increment 1m --dry-run",
		"lifecycle lease renew --file " + lease + " --increment 1m --if-ttl-below 100s",
		"lifecycle lease renew --file " + lease + " --increment 1m --if-ttl-below 3m",
		"lifecycle lease revoke --file " + lease + " --dry-run",
		"lifecycle lease revoke --file " + lease + " --force",
		"lifecycle lease inspect --file " + lease,
		"history", "",
	}, "\n")
	code, output, diagnostics := runShellCLI(strings.NewReader(source), "shell", "--no-prompt", "--address", server.URL, "--namespace", "team", "--token-file", operator, "--cwd", "/unused-kv-cwd")
	values := decodeShellOutputs(t, output)
	if code != 0 || diagnostics != "" || len(values) != 8 || renewals.Load() != 1 || revocations.Load() != 1 || strings.Contains(output, "private-") {
		t.Fatal("lease lifecycle failed exact renewal/revocation or leaked its private identifier")
	}
	if values[3].(map[string]any)["ttl_seconds"] != json.Number("90") || values[6].(map[string]any)["exists"] != false || !reflect.DeepEqual(values[7], []any{}) {
		t.Error("lease lifecycle lost actual TTL, absence confirmation or shell history exclusion")
	}
}

func TestLifecycleOfflineOutputFailuresAndShellIsolation(t *testing.T) {
	cleanEnvironment(t)
	policy := lifecycleCLIPolicy(t)
	for _, args := range [][]string{
		{"lifecycle", "schema"}, {"lifecycle", "example"},
		{"lifecycle", "validate", "--file", policy},
	} {
		for _, writer := range []io.Writer{failedWriter{}, blueprintShortWriter{}} {
			var diagnostics bytes.Buffer
			code := cli.RunWithInput(context.Background(), args, f03PanicReader{}, writer, &diagnostics, "test")
			if code != 1 || diagnostics.Len() == 0 || strings.Contains(diagnostics.String(), "private-") {
				t.Error("offline lifecycle output ignored failed or short writes")
			}
		}
	}
	t.Setenv("VAULT_ADDR", "private-invalid-address")
	t.Setenv("VAULT_CACERT", "/private-missing-ca")
	source := "lifecycle schema\nlifecycle example --format json\nlifecycle validate --file " + policy + "\nhistory\n"
	code, output, diagnostics := runShellCLI(strings.NewReader(source), "shell", "--no-prompt", "--address", "private-invalid-startup", "--token-file", "/private-unreadable-token", "--cwd", "/unused-kv-cwd")
	values := decodeShellOutputs(t, output)
	if code != 0 || diagnostics != "" || len(values) != 4 || !reflect.DeepEqual(values[3], []any{}) {
		t.Error("offline lifecycle shell actions inherited network options, KV cwd or history")
	}
	for _, line := range []string{
		"lifecycle rotate --dry-run --address https://private-override",
		"lifecycle retire --ack-consumer --namespace private-team",
		"lifecycle recover --abandon --token-file /private-token",
		"lifecycle token renew --dry-run --timeout 1s",
		"lifecycle lease revoke --force --address https://private-override",
		"lifecycle lease revoke --dry-run --token-file /private-token",
	} {
		code, output, diagnostics = runShellCLI(strings.NewReader(line+"\npwd\n"), "shell", "--no-prompt")
		if code != 1 || output != "" || diagnostics == "" || strings.Contains(diagnostics, "private-") {
			t.Error("nested lifecycle boolean option bypassed fixed shell connection guards")
		}
	}
}
