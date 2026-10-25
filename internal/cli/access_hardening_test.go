package cli_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAppRoleLoginPublicationFailureRevokesOnlyItsIssuedToken(t *testing.T) {
	for _, rejectedCleanup := range []bool{false, true} {
		name := "confirmed compensation"
		if rejectedCleanup {
			name = "denied compensation"
		}
		t.Run(name, func(t *testing.T) {
			cleanEnvironment(t)
			directory := t.TempDir()
			destination := filepath.Join(directory, "login-token")
			protected := filepath.Join(directory, "replacement-target")
			if err := os.WriteFile(protected, []byte("private-existing-target"), 0o600); err != nil {
				t.Fatal("could not prepare the replacement target")
			}
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodPost || r.Header.Get("X-Vault-Namespace") != "team" {
					t.Error("login or compensation changed the operation or namespace")
				}
				switch r.URL.Path {
				case "/v1/auth/custom/approle/login":
					if r.Header.Get("X-Vault-Token") != "" {
						t.Error("anonymous login sent the operator credential")
					}
					if os.Remove(destination) != nil || os.Symlink(protected, destination) != nil {
						t.Error("could not replace the reserved output with a symlink")
					}
					accessReply(t, w, issuedAccessToken())
				case "/v1/auth/token/revoke-self":
					if r.Header.Get("X-Vault-Token") != "private-issued-token" {
						t.Error("login compensation revoked a credential other than the issued token")
					}
					if rejectedCleanup {
						w.WriteHeader(http.StatusForbidden)
					} else {
						w.WriteHeader(http.StatusNoContent)
					}
				default:
					t.Error("login compensation retried issuance or used an administrative endpoint")
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", server.URL)
			t.Setenv("VAULT_TOKEN", "private-operator-token")
			input := accessInputFile(t, `{"role_id":"private-role-id","secret_id":"private-secret-id"}`)
			code, output, diagnostics := runWriteCLI(f03PanicReader{}, "approle", "login", "--auth-mount", "custom/approle", "--namespace", "team", "--file", input, "--out", destination)
			wantCode := 1
			if rejectedCleanup {
				wantCode = 5
			}
			if code != wantCode || output != "" || diagnostics == "" || requests.Load() != 2 || strings.Contains(diagnostics, "private-") {
				t.Error("failed login publication lost its compensation outcome or exposed credentials")
			}
			if target, err := os.Readlink(destination); err != nil || target != protected {
				t.Error("credential cleanup removed or changed a replacement symlink")
			}
			if body, err := os.ReadFile(protected); err != nil || string(body) != "private-existing-target" {
				t.Error("credential publication followed the replacement symlink")
			}
		})
	}
}

func TestAppRoleBundlePublicationFailureRevokesOnlyItsSecretIDAccessor(t *testing.T) {
	cleanEnvironment(t)
	destination := filepath.Join(t.TempDir(), "approle-bundle")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("X-Vault-Token") != "private-operator-token" || r.Header.Get("X-Vault-Namespace") != "team" {
			t.Error("bundle issuance or compensation lost the selected operator scope")
		}
		switch r.URL.Path {
		case "/v1/auth/custom/approle/role/app":
			if r.Method != http.MethodGet {
				t.Error("credential issuance changed its AppRole configuration")
			}
			_, _ = io.WriteString(w, `{"data":{"token_policies":["app"],"token_ttl":60,"token_max_ttl":120,"secret_id_ttl":60,"secret_id_num_uses":1,"token_num_uses":0,"bind_secret_id":true,"token_no_default_policy":true,"token_type":"service","token_period":0}}`)
		case "/v1/auth/custom/approle/role/app/role-id":
			if r.Method != http.MethodGet {
				t.Error("credential issuance changed the AppRole ID")
			}
			_, _ = io.WriteString(w, `{"data":{"role_id":"private-role-id"}}`)
		case "/v1/auth/custom/approle/role/app/secret-id":
			if r.Method != http.MethodPost {
				t.Error("credential issuance used the wrong operation")
			}
			if os.Remove(destination) != nil {
				t.Error("could not remove the credential reservation")
			}
			_, _ = io.WriteString(w, `{"data":{"secret_id":"private-secret-id","secret_id_accessor":"private-secret-accessor","secret_id_ttl":60,"secret_id_num_uses":1}}`)
		case "/v1/auth/custom/approle/role/app/secret-id-accessor/destroy":
			var body map[string]any
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 || body["secret_id_accessor"] != "private-secret-accessor" {
				t.Error("bundle compensation did not revoke only the newly issued SecretID by accessor")
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Error("bundle compensation retried issuance or revoked an unrelated credential")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "private-operator-token")
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, "approle", "credentials", "--auth-mount", "custom/approle", "--namespace", "team", "--out", destination, "app")
	if code != 1 || output != "" || diagnostics == "" || requests.Load() != 4 || strings.Contains(diagnostics, "private-") {
		t.Error("failed bundle publication did not safely compensate its own SecretID exactly once")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Error("failed bundle publication retained an incomplete credential output")
	}
}
