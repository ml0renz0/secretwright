package vault_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ml0renz0/secretwright/internal/vault"
)

func TestAppRoleCRUDUsesTheSelectedAuthMountAndSafeConfiguration(t *testing.T) {
	var writes, deletes atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		accessRequest(t, r, "selected-token")
		switch {
		case r.URL.Path == "/v1/auth/team/approle/role" && kvOperation(r) == "LIST":
			kvReply(w, map[string]any{"keys": []string{"z-worker", "app", "app"}})
		case r.URL.Path == "/v1/auth/team/approle/role/app" && r.Method == http.MethodGet:
			kvReply(w, accessRoleData())
		case r.URL.Path == "/v1/auth/team/approle/role/app" && r.Method == http.MethodPost:
			writes.Add(1)
			body := kvWriteBody(t, r)
			want := map[string]any{
				"token_policies": []any{"app-read"}, "token_ttl": json.Number("300"), "token_max_ttl": json.Number("600"),
				"secret_id_ttl": json.Number("300"), "secret_id_num_uses": json.Number("2"), "token_num_uses": json.Number("0"),
				"bind_secret_id": true, "token_no_default_policy": true, "token_type": "service", "token_period": json.Number("0"),
			}
			if !reflect.DeepEqual(body, want) {
				t.Error("AppRole write did not use explicit finite credentials and policy bounds")
			}
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/auth/team/approle/role/app" && r.Method == http.MethodDelete:
			deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Error("AppRole command used an unexpected endpoint")
			w.WriteHeader(http.StatusNotFound)
		}
	})
	opts := vault.AppRoleOptions{Mount: "team/approle"}
	ctx := context.Background()
	names, err := client.ListAppRoles(ctx, "selected-token", opts)
	if err != nil || !reflect.DeepEqual(names, []string{"app", "z-worker"}) {
		t.Fatal("AppRole listing did not preserve the selected auth mount")
	}
	role, err := client.ReadAppRole(ctx, "selected-token", "app", opts)
	if err != nil || role.Name != "app" || role.AuthMount != "team/approle" || role.TokenTTLSeconds != 300 || role.SecretIDNumUses != 2 || !role.BindSecretID || !role.TokenNoDefaultPolicy {
		t.Fatal("AppRole read did not project supported configuration fields")
	}
	accessAssertSafe(t, role)
	result, err := client.WriteAppRole(ctx, "selected-token", "app", accessRoleSpec(), opts)
	if err != nil || result.Name != "app" {
		t.Fatal("AppRole write did not confirm its selected role")
	}
	accessAssertSafe(t, result)
	result, err = client.DeleteAppRole(ctx, "selected-token", "app", opts)
	if err != nil || !result.Deleted || writes.Load() != 1 || deletes.Load() != 1 {
		t.Fatal("AppRole mutation confirmation was incorrect")
	}
}

func TestAppRoleIssuanceCapturesRoleIDAndRevokesOnlyTheSecretIDAccessor(t *testing.T) {
	var calls []string
	var mu sync.Mutex
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		accessRequest(t, r, "selected-token")
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/v1/auth/approle/role/app":
			kvReply(w, accessRoleData())
		case "/v1/auth/approle/role/app/role-id":
			if r.Method != http.MethodGet {
				t.Error("RoleID read changed server state")
			}
			kvReply(w, map[string]any{"role_id": f06RoleID, "metadata": "private-f06-role-id-metadata"})
		case "/v1/auth/approle/role/app/secret-id":
			if r.Method != http.MethodPost {
				t.Error("SecretID issue did not use the explicit generation endpoint")
			}
			kvReply(w, map[string]any{"secret_id": f06SecretID, "secret_id_accessor": f06Accessor, "secret_id_ttl": 300, "secret_id_num_uses": 2, "metadata": "private-f06-secret-metadata"})
		case "/v1/auth/approle/role/app/secret-id-accessor/destroy":
			if !reflect.DeepEqual(kvWriteBody(t, r), map[string]any{"secret_id_accessor": f06Accessor}) {
				t.Error("SecretID revocation sent the secret rather than only its accessor")
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Error("SecretID workflow used an unexpected endpoint")
			w.WriteHeader(http.StatusNotFound)
		}
	})
	credentials, err := client.IssueAppRoleCredentials(context.Background(), "selected-token", "app", vault.AppRoleOptions{})
	if err != nil || credentials.RoleID != f06RoleID || credentials.SecretID != f06SecretID || credentials.SecretIDAccessor != f06Accessor || credentials.Report.TTLSeconds != 300 {
		t.Fatal("SecretID issue did not preserve its private credentials and bounded lifetime")
	}
	accessAssertSafe(t, credentials)
	want := []string{"GET /v1/auth/approle/role/app", "GET /v1/auth/approle/role/app/role-id", "POST /v1/auth/approle/role/app/secret-id"}
	mu.Lock()
	if !reflect.DeepEqual(calls, want) {
		t.Error("SecretID generation did not finish safe role and RoleID reads before issuing")
	}
	mu.Unlock()
	var private bytes.Buffer
	if err := vault.EncodeAppRoleCredentials(&private, credentials); err != nil {
		t.Fatal("credential bundle could not be encoded to its explicitly private writer")
	}
	decoded, err := vault.DecodeAppRoleCredentials(&private)
	if err != nil || decoded.RoleID != f06RoleID || decoded.SecretID != f06SecretID || decoded.SecretIDAccessor != f06Accessor {
		t.Fatal("private credential bundle did not round-trip")
	}
	result, err := client.RevokeAppRoleSecretID(context.Background(), "selected-token", "app", decoded.SecretIDAccessor, vault.AppRoleOptions{})
	if err != nil || !result.Deleted {
		t.Fatal("SecretID revocation was not confirmed")
	}
	accessAssertSafe(t, result)
}

func TestAppRoleLoginNeverSendsAnInheritedOperatorToken(t *testing.T) {
	var requests atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		accessRequest(t, r, "")
		if r.Method != http.MethodPost || r.URL.Path != "/v1/auth/custom/approle/login" {
			t.Error("AppRole login used an unexpected auth mount or endpoint")
		}
		want := map[string]any{"role_id": f06RoleID, "secret_id": f06SecretID}
		if !reflect.DeepEqual(kvWriteBody(t, r), want) {
			t.Error("AppRole login sent extra data or lost its supplied credentials")
		}
		accessAuth(w)
	})
	credentials := vault.AppRoleCredentials{RoleID: f06RoleID, SecretID: f06SecretID, SecretIDAccessor: f06Accessor}
	issued, err := client.LoginAppRole(context.Background(), credentials, vault.AppRoleOptions{Mount: "custom/approle"})
	if err != nil || issued.Token != "private-f06-issued-token" || issued.Accessor != f06Accessor || issued.Report.EntityID != f06EntityID || issued.Report.TTLSeconds != 300 {
		t.Fatal("AppRole login did not preserve its private token and safe metadata")
	}
	accessAssertSafe(t, issued)
	if requests.Load() != 1 {
		t.Error("AppRole login performed an operator token lookup or retried issuance")
	}
}

func TestAppRoleRejectsUnboundedRoleOrMalformedIssueWithoutRetry(t *testing.T) {
	for _, mode := range []string{"unbounded role", "periodic role", "batch role", "missing token type", "missing token period", "inherited default policy", "malformed secret", "server failure"} {
		t.Run(mode, func(t *testing.T) {
			var issues atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/auth/approle/role/app":
					data := accessRoleData()
					if mode == "unbounded role" {
						data["secret_id_ttl"] = 0
					}
					if mode == "periodic role" {
						data["token_period"] = 300
					}
					if mode == "batch role" {
						data["token_type"] = "batch"
					}
					if mode == "missing token type" {
						delete(data, "token_type")
					}
					if mode == "missing token period" {
						delete(data, "token_period")
					}
					if mode == "inherited default policy" {
						data["token_no_default_policy"] = false
					}
					kvReply(w, data)
				case "/v1/auth/approle/role/app/role-id":
					kvReply(w, map[string]any{"role_id": f06RoleID})
				case "/v1/auth/approle/role/app/secret-id":
					issues.Add(1)
					if mode == "server failure" {
						w.WriteHeader(http.StatusServiceUnavailable)
						_, _ = io.WriteString(w, `{"errors":["private-f06-issue-error"]}`)
					} else {
						kvReply(w, map[string]any{"secret_id": f06SecretID, "secret_id_ttl": 300, "secret_id_num_uses": 2})
					}
				default:
					t.Error("credential issue made an unexpected request")
					w.WriteHeader(http.StatusNotFound)
				}
			})
			_, err := client.IssueAppRoleCredentials(context.Background(), "selected-token", "app", vault.AppRoleOptions{})
			if err == nil {
				t.Fatal("unsafe or unconfirmed credential issue was accepted")
			}
			accessAssertSafe(t, err)
			if mode != "malformed secret" && mode != "server failure" {
				if issues.Load() != 0 {
					t.Error("unbounded credential configuration was detected after issuing")
				}
			} else if issues.Load() != 1 || !errors.Is(err, vault.ErrAccessUnconfirmed) {
				t.Error("unconfirmed SecretID issuance was retried or lost its outcome category")
			}
		})
	}
}

func TestAppRoleInputsAreStrictAndDoNotPermitUnboundedCredentials(t *testing.T) {
	for _, body := range []string{
		`{"token_policies":[],"token_ttl":"5m","token_max_ttl":"1h","secret_id_ttl":"5m","secret_id_num_uses":1}`,
		`{"token_policies":["root"],"token_ttl":"5m","token_max_ttl":"1h","secret_id_ttl":"5m","secret_id_num_uses":1}`,
		`{"token_policies":["app-read"],"token_ttl":"0s","token_max_ttl":"1h","secret_id_ttl":"5m","secret_id_num_uses":1}`,
		`{"token_policies":["app-read"],"token_ttl":"5m","token_max_ttl":"1m","secret_id_ttl":"5m","secret_id_num_uses":1}`,
		`{"token_policies":["app-read"],"token_ttl":"5m","token_max_ttl":"1h","secret_id_ttl":"25h","secret_id_num_uses":1}`,
		`{"token_policies":["app-read"],"token_ttl":"5m","token_max_ttl":"1h","secret_id_ttl":"5m","secret_id_num_uses":0}`,
	} {
		if _, err := vault.DecodeRoleSpec(strings.NewReader(body)); err == nil {
			t.Error("role configuration accepted inherited policies or unbounded credentials")
		}
	}
	for _, body := range []string{
		`{"role_id":"x","secret_id":"y","secret_id":"z"}`,
		`{"role_id":"x"}`,
		`{"role_id":"x","secret_id":"y","token":"private-f06-extra"}`,
		`{"role_id":"x","secret_id":"private-f06-secret\nline"}`,
	} {
		if _, err := vault.DecodeAppRoleCredentials(strings.NewReader(body)); err == nil {
			t.Error("private credential decoder accepted ambiguous or invalid data")
		}
	}
	var requests atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	for _, mount := range []string{"/approle", "approle/", "../approle", "team//approle", "team/private?mount"} {
		if _, err := client.ListAppRoles(context.Background(), "selected-token", vault.AppRoleOptions{Mount: mount}); err == nil {
			t.Error("AppRole accepted a noncanonical auth mount")
		}
	}
	if requests.Load() != 0 {
		t.Error("invalid AppRole mount selection contacted Vault")
	}
}
