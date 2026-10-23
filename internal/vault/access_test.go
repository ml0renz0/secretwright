package vault_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/vault"
)

const (
	f06RoleID   = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	f06SecretID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	f06Accessor = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	f06EntityID = "11111111-1111-4111-8111-111111111111"
	f06GroupID  = "22222222-2222-4222-8222-222222222222"
	f06MemberID = "33333333-3333-4333-8333-333333333333"
)

func accessAssertSafe(t *testing.T, value any) {
	t.Helper()
	var encoded string
	if err, ok := value.(error); ok {
		if err == nil {
			t.Fatal("expected a safe operation error")
		}
		encoded = err.Error()
	} else {
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal("could not encode the public access report")
		}
		encoded = string(body)
	}
	for _, private := range []string{"private-f06-", "selected-token", f06RoleID, f06SecretID, f06Accessor} {
		if strings.Contains(encoded, private) {
			t.Error("access report exposed a credential or unapproved upstream field")
		}
	}
}

func accessRequest(t *testing.T, r *http.Request, token string) {
	t.Helper()
	assertKVWriteCredentials(t, r, token)
}

func accessAuth(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{
		"client_token": "private-f06-issued-token", "accessor": f06Accessor,
		"lease_duration": 300, "renewable": false, "policies": []string{"app-read"},
		"token_policies": []string{"app-read"}, "entity_id": f06EntityID,
		"metadata": map[string]any{"private": "private-f06-auth-metadata"},
	}})
}

func accessRoleData() map[string]any {
	return map[string]any{
		"token_policies": []string{"app-read"}, "token_ttl": 300, "token_max_ttl": 600,
		"secret_id_ttl": 300, "secret_id_num_uses": 2, "token_num_uses": 0,
		"bind_secret_id": true, "token_no_default_policy": true, "token_type": "service", "token_period": 0,
		"metadata": map[string]any{"private": "private-f06-role-metadata"},
	}
}

func accessRoleSpec() vault.RoleSpec {
	return vault.RoleSpec{TokenPolicies: []string{"app-read"}, TokenTTL: "5m", TokenMaxTTL: "10m", SecretIDTTL: "5m", SecretIDNumUses: 2}
}

func accessTokenSpec() vault.TokenSpec {
	return vault.TokenSpec{Policies: []string{"app-read"}, TTL: "5m", ExplicitMaxTTL: "10m"}
}

func TestPoliciesUseModernEndpointsAndProjectOnlyRequestedConfiguration(t *testing.T) {
	const policy = `path "secret/data/app/*" { capabilities = ["read"] }`
	var lists, reads, writes, deletes atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		accessRequest(t, r, "selected-token")
		switch {
		case r.URL.Path == "/v1/sys/policies/acl" && kvOperation(r) == "LIST":
			lists.Add(1)
			kvReply(w, map[string]any{"keys": []string{"z-reader", "app-read", "app-read"}, "private": "private-f06-catalog"})
		case r.URL.Path == "/v1/sys/policies/acl/app-read" && r.Method == http.MethodGet:
			reads.Add(1)
			kvReply(w, map[string]any{"policy": policy, "name": "untrusted-response-name", "metadata": "private-f06-policy-metadata"})
		case r.URL.Path == "/v1/sys/policies/acl/app-read" && r.Method == http.MethodPost:
			writes.Add(1)
			body := kvWriteBody(t, r)
			if !reflect.DeepEqual(body, map[string]any{"policy": policy}) {
				t.Error("policy write forwarded fields beyond the selected ACL document")
			}
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/sys/policies/acl/app-read" && r.Method == http.MethodDelete:
			deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Error("policy command used an unexpected or legacy endpoint")
			w.WriteHeader(http.StatusNotFound)
		}
	})
	names, err := client.ListPolicies(context.Background(), "selected-token")
	if err != nil || !reflect.DeepEqual(names, []string{"app-read", "z-reader"}) {
		t.Fatal("policy listing did not return a sorted distinct catalog")
	}
	got, err := client.ReadPolicy(context.Background(), "selected-token", "app-read")
	if err != nil || got.Name != "app-read" || got.Policy != policy {
		t.Fatal("policy read did not return the requested ACL configuration")
	}
	accessAssertSafe(t, got)
	result, err := client.WritePolicy(context.Background(), "selected-token", "app-read", policy)
	if err != nil || result.Name != "app-read" {
		t.Fatal("policy write did not confirm the selected policy")
	}
	accessAssertSafe(t, result)
	result, err = client.DeletePolicy(context.Background(), "selected-token", "app-read")
	if err != nil || !result.Deleted {
		t.Fatal("policy delete did not confirm the explicit deletion")
	}
	if lists.Load() != 1 || reads.Load() != 1 || writes.Load() != 1 || deletes.Load() != 1 {
		t.Error("policy commands made unexpected extra requests")
	}
}

func TestAccessRejectsInvalidIdentifiersAndReservedPolicyMutationsOffline(t *testing.T) {
	var requests atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	ctx := context.Background()
	for _, name := range []string{"", "../private-f06-path", "a/b", "a?query", "a%2fb", "with space", strings.Repeat("a", 129)} {
		if _, err := client.ReadPolicy(ctx, "selected-token", name); err == nil {
			t.Error("policy accepted an invalid name")
		}
		if _, err := client.WriteAppRole(ctx, "selected-token", name, accessRoleSpec(), vault.AppRoleOptions{}); err == nil {
			t.Error("AppRole accepted an invalid name")
		}
	}
	if _, err := client.WritePolicy(ctx, "selected-token", "root", `path "*" { capabilities = ["read"] }`); err == nil {
		t.Error("root policy write was accepted")
	}
	for _, name := range []string{"root", "default"} {
		if _, err := client.DeletePolicy(ctx, "selected-token", name); err == nil {
			t.Error("reserved policy deletion was accepted")
		}
	}
	for _, id := range []string{"", "name-only", "../private-f06-id", f06EntityID + "/x"} {
		if _, err := client.ReadEntity(ctx, "selected-token", id); err == nil {
			t.Error("entity read accepted an invalid UUID")
		}
	}
	if requests.Load() != 0 {
		t.Error("invalid access input contacted Vault")
	}
}

func TestAccessReadsPreserveTypedErrorsAndNeverReturnServerBodies(t *testing.T) {
	for _, test := range []struct {
		status int
		want   error
	}{
		{status: 401, want: vault.ErrPermissionDenied},
		{status: 403, want: vault.ErrPermissionDenied},
		{status: 404, want: vault.ErrNotFound},
		{status: 503},
	} {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			var requests atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, `{"errors":["private-f06-server-body"]}`)
			})
			_, err := client.ReadPolicy(context.Background(), "selected-token", "app-read")
			if err == nil || (test.want != nil && !errors.Is(err, test.want)) {
				t.Fatal("access read lost its safe error category")
			}
			accessAssertSafe(t, err)
			if requests.Load() != 1 {
				t.Error("access request was retried or performed an authentication lookup")
			}
		})
	}
}

func TestAccessCatalogRejectsMalformedAndOversizedLists(t *testing.T) {
	oversized := make([]string, vault.MaxAccessList+1)
	for index := range oversized {
		oversized[index] = fmt.Sprintf("policy-%05d", index)
	}
	for _, values := range []any{[]any{"app-read", 4}, []string{"../private-f06-path"}, oversized} {
		client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			kvReply(w, map[string]any{"keys": values})
		})
		if _, err := client.ListPolicies(context.Background(), "selected-token"); err == nil {
			t.Error("malformed or oversized policy catalog was silently accepted")
		}
	}
}

func TestAccessDeadlineAndCancellationStopReadRequests(t *testing.T) {
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}, vault.Options{Timeout: durationPointer(40 * time.Millisecond)})
	if _, err := client.ListPolicies(context.Background(), "selected-token"); !errors.Is(err, context.DeadlineExceeded) {
		t.Error("access read did not respect its request deadline")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.ListPolicies(ctx, "selected-token"); !errors.Is(err, context.Canceled) {
		t.Error("access read ignored parent cancellation")
	}
}

func TestAccessFileDecodersRejectAmbiguousOrUnboundedSpecifications(t *testing.T) {
	decoders := map[string]func(io.Reader) error{
		"role": func(r io.Reader) error { _, err := vault.DecodeRoleSpec(r); return err },
		"token": func(r io.Reader) error { _, err := vault.DecodeTokenSpec(r); return err },
		"entity": func(r io.Reader) error { _, err := vault.DecodeEntitySpec(r); return err },
		"group": func(r io.Reader) error { _, err := vault.DecodeGroupSpec(r); return err },
	}
	for name, decode := range decoders {
		t.Run(name, func(t *testing.T) {
			for _, body := range []string{`{}`, `{"name":"app","name":"other"}`, `{"name":"app","unknown":"private-f06-spec"}`, `{"name":"app"} {}`, strings.Repeat(" ", vault.MaxAccessSpecBytes+1)} {
				if err := decode(strings.NewReader(body)); err == nil {
					t.Error("strict access decoder accepted missing, duplicate, unknown or oversized input")
				} else {
					accessAssertSafe(t, err)
				}
			}
		})
	}
	for _, body := range []string{"", " \n", "private-f06-policy\x00body", strings.Repeat("x", (1<<20)+1), string([]byte{0xff})} {
		if _, err := vault.ReadPolicyInput(strings.NewReader(body)); err == nil {
			t.Error("ACL input decoder accepted an invalid or oversized document")
		}
	}
}
