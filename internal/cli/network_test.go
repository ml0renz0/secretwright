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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/cli"
)

func runNetworkCommand(ctx context.Context, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := cli.Run(ctx, args, &stdout, &stderr, "test")
	return code, stdout.String(), stderr.String()
}

func TestNetworkHelpDoesNotReadConfigurationOrCredentials(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "://invalid")
	t.Setenv("VAULT_CLIENT_TIMEOUT", "invalid-timeout")
	t.Setenv("VAULT_CACERT", "/does-not-exist/ca.pem")
	for _, args := range [][]string{{"status", "--help"}, {"auth", "check", "--help"}} {
		code, stdout, stderr := runNetworkCommand(context.Background(), args...)
		if code != 0 || stdout == "" || stderr != "" {
			t.Errorf("help must succeed offline: exit=%d, stdout=%q, stderr=%q", code, stdout, stderr)
		}
	}
}

func TestNetworkFlagErrorsDoNotEchoSuppliedValues(t *testing.T) {
	cleanEnvironment(t)
	const marker = "sensitive-input-marker"
	for _, args := range [][]string{
		{"status", "--timeout", marker},
		{"status", "--" + marker},
		{"status", "--address", "http://localhost:8200", marker},
		{"auth", marker},
		{"auth", "check", "--timeout", marker},
		{"auth", "check", "--" + marker},
		{"auth", "check", "--token", marker},
		{"auth", "check", "--token-file", "/does-not-exist/" + marker},
	} {
		code, stdout, stderr := runNetworkCommand(context.Background(), args...)
		if code != 1 || stdout != "" || stderr == "" {
			t.Errorf("expected usage/configuration error: exit=%d, stdout=%q, stderr=%q", code, stdout, stderr)
		}
		if strings.Contains(stdout+stderr, marker) {
			t.Error("diagnostic echoed an argument, token value, or file path")
		}
	}
}

func TestAuthCheckUsesExplicitCredentialsAndSanitizesReport(t *testing.T) {
	for _, tc := range []struct {
		name      string
		file      bool
		namespace string
	}{
		{name: "environment token", namespace: "ops"},
		{name: "file overrides environment and empty namespace", file: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnvironment(t)
			const envToken = "f01-environment-token"
			const fileToken = "f01-file-token"
			wantToken := envToken
			if tc.file {
				wantToken = fileToken
			}
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/v1/auth/token/lookup-self" {
					t.Errorf("unexpected operation: %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("X-Vault-Token") != wantToken {
					t.Error("authentication request used the wrong token source")
				}
				if r.Header.Get("X-Vault-Namespace") != tc.namespace {
					t.Errorf("namespace = %q, want %q", r.Header.Get("X-Vault-Namespace"), tc.namespace)
				}
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("authentication request sent unrelated inherited credentials")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"data":{"id":"f01-environment-token","accessor":"sensitive-accessor","policies":["default","read-only"],"ttl":3600,"renewable":true,"metadata":{"private":"sensitive-metadata"}}}`)
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", "://ignored-address")
			t.Setenv("VAULT_AGENT_ADDR", "://ignored-agent")
			t.Setenv("VAULT_NAMESPACE", "ignored-namespace")
			t.Setenv("VAULT_TOKEN", envToken)
			t.Setenv("VAULT_HEADERS", `{"Authorization":"inherited-private","Cookie":"inherited-cookie"}`)
			args := []string{"auth", "check", "--address", server.URL, "--namespace", tc.namespace}
			if tc.file {
				path := filepath.Join(t.TempDir(), "token")
				if err := os.WriteFile(path, []byte(fileToken+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--token-file", path)
			}
			code, stdout, stderr := runNetworkCommand(context.Background(), args...)
			if code != 0 || stderr != "" {
				t.Fatalf("auth check failed: exit=%d, stderr=%q", code, stderr)
			}
			var report struct {
				Authenticated bool     `json:"authenticated"`
				Namespace     string   `json:"namespace"`
				Policies      []string `json:"policies"`
				TTL           int64    `json:"ttl_seconds"`
				Renewable     bool     `json:"renewable"`
			}
			if err := json.Unmarshal([]byte(stdout), &report); err != nil {
				t.Fatalf("invalid auth JSON: %v", err)
			}
			if !report.Authenticated || report.Namespace != tc.namespace || report.TTL != 3600 || !report.Renewable || strings.Join(report.Policies, ",") != "default,read-only" {
				t.Errorf("unexpected safe authentication report: %+v", report)
			}
			for _, sensitive := range []string{envToken, fileToken, "sensitive-accessor", "sensitive-metadata", "inherited-private", "inherited-cookie"} {
				if strings.Contains(stdout+stderr, sensitive) {
					t.Error("auth output exposed a sensitive response field or credential")
				}
			}
			if requests.Load() != 1 {
				t.Errorf("requests = %d, want one authenticated lookup", requests.Load())
			}
		})
	}
}

func TestAuthCheckMissingAndRejectedCredentials(t *testing.T) {
	for _, status := range []int{0, http.StatusUnauthorized, http.StatusForbidden} {
		name := http.StatusText(status)
		if status == 0 {
			name = "missing token"
		}
		t.Run(name, func(t *testing.T) {
			cleanEnvironment(t)
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if status == 0 {
					w.WriteHeader(http.StatusTeapot)
					return
				}
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"errors":["rejected-token-private-body"]}`)
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", server.URL)
			if status != 0 {
				t.Setenv("VAULT_TOKEN", "rejected-private-token")
			}
			code, stdout, stderr := runNetworkCommand(context.Background(), "auth", "check")
			if code != 2 || stdout != "" || stderr == "" {
				t.Errorf("expected unconfirmed authentication: exit=%d, stdout=%q, stderr=%q", code, stdout, stderr)
			}
			if strings.Contains(stderr, "rejected-token-private-body") || strings.Contains(stderr, "rejected-private-token") {
				t.Error("authentication diagnostic exposed credentials or an upstream body")
			}
			if status == 0 && requests.Load() != 0 {
				t.Error("missing credentials caused a network request")
			}
		})
	}
}

func TestStatusFlagsOverrideEnvironmentWithoutSendingTokens(t *testing.T) {
	cleanEnvironment(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/health" || r.Method != http.MethodGet {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-Vault-Token") != "" || r.Header.Get("X-Vault-Namespace") != "ops" {
			t.Error("health did not isolate credentials or apply the namespace override")
		}
		_, _ = io.WriteString(w, `{"initialized":true,"sealed":false,"version":"2.2.0"}`)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", "://ignored-address")
	t.Setenv("VAULT_AGENT_ADDR", "://ignored-agent")
	t.Setenv("VAULT_NAMESPACE", "ignored-namespace")
	t.Setenv("VAULT_TOKEN", "never-send-this-token")
	code, stdout, stderr := runNetworkCommand(context.Background(), "status", "--address", server.URL, "--namespace", "ops")
	if code != 0 || stderr != "" || !strings.Contains(stdout, `"initialized": true`) {
		t.Errorf("status override failed: exit=%d, stdout=%q, stderr=%q", code, stdout, stderr)
	}
}

func TestNetworkTimeoutFlagBoundsRequests(t *testing.T) {
	for _, command := range [][]string{{"status"}, {"auth", "check"}} {
		t.Run(strings.Join(command, " "), func(t *testing.T) {
			cleanEnvironment(t)
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				<-r.Context().Done()
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", server.URL)
			t.Setenv("VAULT_TOKEN", "timeout-test-token")
			t.Setenv("VAULT_CLIENT_TIMEOUT", "1m")
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			started := time.Now()
			args := append(append([]string{}, command...), "--timeout", "20ms")
			code, stdout, stderr := runNetworkCommand(ctx, args...)
			if code != 1 || stdout != "" || stderr == "" || time.Since(started) >= 750*time.Millisecond {
				t.Errorf("configured timeout was not applied: exit=%d, stdout=%q, stderr=%q", code, stdout, stderr)
			}
			if requests.Load() != 1 {
				t.Errorf("requests = %d, want exactly one timed-out request", requests.Load())
			}
		})
	}
}

func TestAuthCheckResponseAndOutputFailures(t *testing.T) {
	for _, malformed := range []bool{true, false} {
		t.Run(map[bool]string{true: "malformed response", false: "output failure"}[malformed], func(t *testing.T) {
			cleanEnvironment(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if malformed {
					_, _ = io.WriteString(w, "sensitive-malformed-body")
					return
				}
				_, _ = io.WriteString(w, `{"data":{"policies":["default"],"ttl":60,"renewable":false}}`)
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", server.URL)
			t.Setenv("VAULT_TOKEN", "private-output-failure-token")
			var stderr bytes.Buffer
			if code := cli.Run(context.Background(), []string{"auth", "check"}, failedWriter{}, &stderr, "test"); code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if stderr.Len() == 0 || strings.Contains(stderr.String(), "sensitive-malformed-body") || strings.Contains(stderr.String(), "private-output-failure-token") {
				t.Error("missing or unsafe failure diagnostic")
			}
		})
	}
}
