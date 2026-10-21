package vault_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/vault"
)

func TestConnectionOptionsOverrideEnvironment(t *testing.T) {
	for _, test := range []struct {
		name      string
		namespace string
	}{
		{name: "explicit namespace", namespace: "selected/team"},
		{name: "explicit root namespace", namespace: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			clearVaultEnvironment(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/sys/health" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				if r.Header.Get("X-Vault-Namespace") != test.namespace {
					t.Errorf("namespace = %q, want %q", r.Header.Get("X-Vault-Namespace"), test.namespace)
				}
				io.WriteString(w, `{"initialized":true,"sealed":false,"version":"2.2.0"}`)
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", "not-a-valid-address")
			t.Setenv("VAULT_AGENT_ADDR", "not-a-valid-agent-address")
			t.Setenv("VAULT_NAMESPACE", "inherited/team")
			t.Setenv("VAULT_CLIENT_TIMEOUT", "not-a-valid-duration")
			address := server.URL
			timeout := time.Second
			client, err := vault.New(vault.Options{Address: &address, Namespace: &test.namespace, Timeout: &timeout})
			if err != nil {
				t.Fatalf("explicit options must override corresponding environment settings: %v", err)
			}
			if _, err := client.Status(context.Background()); err != nil {
				t.Fatalf("read selected server: %v", err)
			}
		})
	}
}

func TestAgentAddressTakesPrecedenceOverVaultAddress(t *testing.T) {
	clearVaultEnvironment(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Request") != "true" {
			t.Error("request to Vault Agent lacks its protection header")
		}
		io.WriteString(w, `{"initialized":true,"sealed":false,"version":"2.2.0"}`)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", "unused-invalid-address")
	t.Setenv("VAULT_AGENT_ADDR", server.URL)
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatalf("create agent connection: %v", err)
	}
	if _, err := client.Status(context.Background()); err != nil {
		t.Fatalf("read health through agent address: %v", err)
	}
}

func TestConnectionOptionsRejectInvalidValues(t *testing.T) {
	for _, test := range []struct {
		name      string
		address   *string
		namespace *string
		timeout   *time.Duration
	}{
		{name: "empty explicit address", address: stringPointer("")},
		{name: "empty query", address: stringPointer("https://vault.test:8200?")},
		{name: "unsupported scheme", address: stringPointer("ftp://vault.test:8200")},
		{name: "namespace newline", namespace: stringPointer("team\r\nAuthorization: private-marker")},
		{name: "zero timeout", timeout: durationPointer(0)},
		{name: "negative timeout", timeout: durationPointer(-time.Second)},
	} {
		t.Run(test.name, func(t *testing.T) {
			clearVaultEnvironment(t)
			client, err := vault.New(vault.Options{Address: test.address, Namespace: test.namespace, Timeout: test.timeout})
			if err == nil || client != nil {
				t.Fatal("invalid explicit connection configuration was accepted")
			}
			if strings.Contains(err.Error(), "private-marker") {
				t.Error("configuration diagnostic exposed an input value")
			}
		})
	}
	for _, value := range []string{"0s", "-1s", "invalid-private-duration-marker"} {
		t.Run("environment timeout "+value, func(t *testing.T) {
			clearVaultEnvironment(t)
			t.Setenv("VAULT_CLIENT_TIMEOUT", value)
			if _, err := vault.NewFromEnvironment(); err == nil {
				t.Error("invalid environment timeout was accepted")
			} else if strings.Contains(err.Error(), value) {
				t.Error("timeout diagnostic echoed its input")
			}
		})
	}
}

func TestConfiguredTimeoutBoundsStatusRequest(t *testing.T) {
	for _, source := range []string{"environment", "options"} {
		t.Run(source, func(t *testing.T) {
			clearVaultEnvironment(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				<-r.Context().Done()
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", server.URL)
			var options vault.Options
			if source == "environment" {
				t.Setenv("VAULT_CLIENT_TIMEOUT", "40ms")
			} else {
				t.Setenv("VAULT_CLIENT_TIMEOUT", "5s")
				options.Timeout = durationPointer(40 * time.Millisecond)
			}
			client, err := vault.New(options)
			if err != nil {
				t.Fatalf("create bounded client: %v", err)
			}
			started := time.Now()
			if _, err := client.Status(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("status error = %v, want deadline exceeded", err)
			}
			if time.Since(started) > 2*time.Second {
				t.Error("configured timeout failed to bound the request")
			}
		})
	}
}

func TestNamespacesAreNormalizedWithoutChangingTheirScope(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "", want: ""},
		{input: "/", want: ""},
		{input: "team/dev", want: "team/dev"},
		{input: "/team/dev/", want: "team/dev"},
	} {
		t.Run(test.input, func(t *testing.T) {
			clearVaultEnvironment(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Vault-Namespace") != test.want {
					t.Errorf("namespace = %q, want %q", r.Header.Get("X-Vault-Namespace"), test.want)
				}
				io.WriteString(w, `{"initialized":true,"sealed":false,"version":"2.2.0"}`)
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", server.URL)
			t.Setenv("VAULT_NAMESPACE", test.input)
			client, err := vault.NewFromEnvironment()
			if err != nil {
				t.Fatalf("create namespaced client: %v", err)
			}
			if _, err := client.Status(context.Background()); err != nil {
				t.Fatalf("read namespaced health: %v", err)
			}
		})
	}
	for _, namespace := range []string{"team//app", ".", "..", "team/../app", "team\\app", "team?app", "team#app", "team app", "team\tapp", "team\x7fapp"} {
		t.Run("invalid namespace", func(t *testing.T) {
			clearVaultEnvironment(t)
			t.Setenv("VAULT_NAMESPACE", namespace)
			if _, err := vault.NewFromEnvironment(); err == nil {
				t.Error("invalid namespace was accepted")
			}
		})
	}
}

func stringPointer(value string) *string { return &value }

func durationPointer(value time.Duration) *time.Duration { return &value }
