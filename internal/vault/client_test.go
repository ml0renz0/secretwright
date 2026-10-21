package vault_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/vault"
)

func clearVaultEnvironment(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "VAULT_") {
			t.Setenv(name, "")
		}
	}
}

func TestStatusHealthStatesAreReadOnly(t *testing.T) {
	tests := []struct {
		name   string
		status vault.Status
		code   int
	}{
		{
			name: "active",
			status: vault.Status{
				Initialized: true,
				Version:     "2.2.0",
				ClusterName: "test-cluster",
				ClusterID:   "test-cluster-id",
			},
			code: http.StatusOK,
		},
		{
			name:   "standby",
			status: vault.Status{Initialized: true, Standby: true, Version: "2.2.0"},
			code:   299,
		},
		{
			name:   "sealed",
			status: vault.Status{Initialized: true, Sealed: true, Version: "2.2.0"},
			code:   299,
		},
		{
			name:   "uninitialized",
			status: vault.Status{Sealed: true, Version: "2.2.0"},
			code:   299,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearVaultEnvironment(t)
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/v1/sys/health" {
					t.Errorf("unexpected operation: %s %s", r.Method, r.URL.Path)
				}
				if token := r.Header.Get("X-Vault-Token"); token != "" {
					t.Error("health request sent an inherited Vault token")
				}
				if r.Header.Get("X-Vault-Namespace") != "team" {
					t.Errorf("namespace = %q, want team", r.Header.Get("X-Vault-Namespace"))
				}
				for _, parameter := range []string{"sealedcode", "uninitcode", "standbycode"} {
					if r.URL.Query().Get(parameter) != "299" {
						t.Errorf("%s = %q, want 299", parameter, r.URL.Query().Get(parameter))
					}
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || len(body) != 0 {
					t.Error("health request must not have a body")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.code)
				if err := json.NewEncoder(w).Encode(test.status); err != nil {
					t.Errorf("encode health fixture: %v", err)
				}
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", server.URL)
			t.Setenv("VAULT_TOKEN", "inherited-token-must-not-be-sent")
			t.Setenv("VAULT_NAMESPACE", "team")
			client, err := vault.NewFromEnvironment()
			if err != nil {
				t.Fatalf("create client: %v", err)
			}
			got, err := client.Status(context.Background())
			if err != nil {
				t.Fatalf("read health: %v", err)
			}
			if got != test.status {
				t.Errorf("status = %+v, want %+v", got, test.status)
			}
			if requests.Load() != 1 {
				t.Errorf("requests = %d, want exactly one read", requests.Load())
			}
		})
	}
}

func TestNewFromEnvironmentRejectsUnsafeConfiguration(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "relative address", key: "VAULT_ADDR", value: "vault.internal:8200"},
		{name: "unsupported scheme", key: "VAULT_ADDR", value: "ftp://vault.internal:8200"},
		{name: "missing host", key: "VAULT_ADDR", value: "https:///vault"},
		{name: "malformed address", key: "VAULT_ADDR", value: "https://[::1"},
		{name: "userinfo", key: "VAULT_ADDR", value: "https://username:private-password@vault.internal:8200"},
		{name: "query", key: "VAULT_ADDR", value: "https://vault.internal:8200?token=private-token"},
		{name: "fragment", key: "VAULT_ADDR", value: "https://vault.internal:8200#private-token"},
		{name: "disabled verification", key: "VAULT_SKIP_VERIFY", value: "true"},
		{name: "invalid timeout", key: "VAULT_CLIENT_TIMEOUT", value: "not-a-duration"},
		{name: "missing CA", key: "VAULT_CACERT", value: "/does/not/exist/private-ca.pem"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearVaultEnvironment(t)
			t.Setenv(test.key, test.value)
			client, err := vault.NewFromEnvironment()
			if err == nil || client != nil {
				t.Fatal("unsafe or invalid configuration was accepted")
			}
			if strings.Contains(err.Error(), test.value) {
				t.Error("configuration error echoed the supplied value")
			}
		})
	}
}

func TestStatusRequiresTrustedTLS(t *testing.T) {
	clearVaultEnvironment(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"initialized":true,"sealed":false,"version":"2.2.0"}`)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if _, err := client.Status(context.Background()); err == nil {
		t.Fatal("untrusted TLS certificate was accepted")
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caPath, caPEM, 0600); err != nil {
		t.Fatalf("write public test certificate: %v", err)
	}
	t.Setenv("VAULT_CACERT", caPath)
	client, err = vault.NewFromEnvironment()
	if err != nil {
		t.Fatalf("create client with trusted CA: %v", err)
	}
	status, err := client.Status(context.Background())
	if err != nil {
		t.Fatalf("read health using trusted CA: %v", err)
	}
	if !status.Initialized || status.Sealed {
		t.Errorf("unexpected health report: %+v", status)
	}
}

func TestStatusDoesNotExposeUpstreamErrors(t *testing.T) {
	for _, test := range []struct {
		name string
		code int
		body string
	}{
		{name: "server error", code: http.StatusServiceUnavailable, body: `{"errors":["sensitive-upstream-marker"]}`},
		{name: "invalid JSON", code: http.StatusOK, body: `sensitive-upstream-marker`},
	} {
		t.Run(test.name, func(t *testing.T) {
			clearVaultEnvironment(t)
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(test.code)
				io.WriteString(w, test.body)
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", server.URL)
			client, err := vault.NewFromEnvironment()
			if err != nil {
				t.Fatalf("create client: %v", err)
			}
			if _, err := client.Status(context.Background()); err == nil {
				t.Fatal("upstream error was ignored")
			} else if strings.Contains(err.Error(), "sensitive-upstream-marker") {
				t.Error("upstream response body appeared in error")
			}
			if requests.Load() != 1 {
				t.Errorf("requests = %d; status must not retry", requests.Load())
			}
		})
	}
}

func TestStatusDoesNotFollowRedirects(t *testing.T) {
	clearVaultEnvironment(t)
	var followed atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		followed.Add(1)
		io.WriteString(w, `{"initialized":true,"version":"2.2.0"}`)
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/v1/sys/health", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if _, err := client.Status(context.Background()); err == nil {
		t.Error("unexpected successful redirected health response")
	}
	if followed.Load() != 0 {
		t.Error("status followed a redirect")
	}
}

func TestStatusRespectsContext(t *testing.T) {
	clearVaultEnvironment(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := client.Status(ctx); !errors.Is(err, context.Canceled) {
			t.Errorf("error = %v, want context.Canceled", err)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		if _, err := client.Status(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("error = %v, want context.DeadlineExceeded", err)
		}
	})
}
