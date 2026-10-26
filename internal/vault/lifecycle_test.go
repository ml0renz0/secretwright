package vault_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ml0renz0/secretwright/internal/vault"
)

const lifecycleTargetToken = "private-f10-target-token"
const lifecycleLeaseID = "database/creds/private-f10-role/private-f10-lease"

func lifecycleTokenData() map[string]any {
	return map[string]any{
		"id": lifecycleTargetToken, "accessor": "private-f10-accessor",
		"ttl": 300, "renewable": true, "type": "service", "num_uses": 0,
		"policies": []string{"app-read"}, "identity_policies": []string{"team-read"},
		"path": "auth/custom/approle/login", "entity_id": f06EntityID,
		"meta": map[string]any{"role_name": "private-f10-role", "private": "private-f10-metadata"},
	}
}

func lifecycleAssertSafe(t *testing.T, value any) {
	t.Helper()
	var body string
	if err, ok := value.(error); ok {
		if err == nil {
			t.Fatal("expected a safe operation error")
		}
		body = err.Error()
	} else {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal("could not encode lifecycle metadata")
		}
		body = string(encoded)
	}
	for _, private := range []string{"private-f10-", "selected-token", lifecycleLeaseID, f06EntityID, "auth/custom/approle/login"} {
		if strings.Contains(body, private) {
			t.Error("lifecycle output exposed a credential or unapproved lookup field")
		}
	}
}

func lifecycleRenewAuth(w http.ResponseWriter, ttl int) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{
		"client_token": lifecycleTargetToken, "accessor": "private-f10-accessor",
		"lease_duration": ttl, "renewable": true, "policies": []string{"app-read"},
		"token_policies": []string{"app-read"}, "entity_id": f06EntityID,
		"metadata": map[string]any{"private": "private-f10-metadata"},
	}})
}

func TestLifecycleTokenInspectionUsesTheOperatorAndKeepsLookupMetadataPrivate(t *testing.T) {
	var requests atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		accessRequest(t, r, "selected-token")
		if r.Method != http.MethodPost || r.URL.Path != "/v1/auth/token/lookup" || r.URL.RawQuery != "" ||
			!reflect.DeepEqual(kvWriteBody(t, r), map[string]any{"token": lifecycleTargetToken}) {
			t.Error("token inspection consumed the target token or interpolated its credential into a URL")
		}
		kvReply(w, lifecycleTokenData())
	})
	info, err := client.InspectLifecycleToken(context.Background(), "selected-token", lifecycleTargetToken)
	if err != nil || !info.Exists || info.TTLSeconds != 300 || !info.Renewable || info.Type != "service" || info.NumUses != 0 ||
		info.Path != "auth/custom/approle/login" || info.RoleName != "private-f10-role" || info.EntityID != f06EntityID ||
		!reflect.DeepEqual(info.Policies, []string{"app-read"}) || !reflect.DeepEqual(info.IdentityPolicies, []string{"team-read"}) {
		t.Fatal("token inspection omitted required bounded lifecycle metadata")
	}
	lifecycleAssertSafe(t, info)
	if _, err := client.InspectLifecycleToken(context.Background(), "selected-token", "selected-token"); err == nil || requests.Load() != 1 {
		t.Error("operator-token self-management was not rejected before HTTP")
	}
}

func TestLifecycleLookupDistinguishesMissingTargetsFromDeniedOperators(t *testing.T) {
	for _, test := range []struct {
		name    string
		status  int
		body    string
		missing bool
		denied  bool
	}{
		{"absent real Vault token", 403, `{"errors":["bad token"]}`, true, false},
		{"absent compatible token", 400, `{"errors":["bad token"]}`, true, false},
		{"operator denied", 403, `{"errors":["permission denied"]}`, false, true},
		{"unrelated request failure", 400, `{"errors":["private-f10-request-error"]}`, false, false},
		{"malformed metadata", 200, `{"data":{"ttl":"private-f10-value"}}`, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				accessRequest(t, r, "selected-token")
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			})
			info, err := client.InspectLifecycleToken(context.Background(), "selected-token", lifecycleTargetToken)
			if test.missing {
				if err != nil || info.Exists {
					t.Error("missing target was confused with operator permission failure")
				}
			} else {
				if err == nil || info.Exists || test.denied && !errors.Is(err, vault.ErrPermissionDenied) {
					t.Error("lookup denial or invalid metadata appeared successful")
				} else {
					lifecycleAssertSafe(t, err)
				}
			}
			lifecycleAssertSafe(t, info)
			if requests.Load() != 1 {
				t.Error("read-only token lookup retried or dispatched another endpoint")
			}
		})
	}
}

func TestLifecycleTokenRenewalReturnsActualTTLWithoutUsingTheTargetAsOperator(t *testing.T) {
	var reads, writes atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		accessRequest(t, r, "selected-token")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/token/lookup":
			reads.Add(1)
			if !reflect.DeepEqual(kvWriteBody(t, r), map[string]any{"token": lifecycleTargetToken}) {
				t.Error("renewal lookup changed the target")
			}
			kvReply(w, lifecycleTokenData())
		case r.Method == http.MethodPut && r.URL.Path == "/v1/auth/token/renew":
			writes.Add(1)
			if !reflect.DeepEqual(kvWriteBody(t, r), map[string]any{"token": lifecycleTargetToken, "increment": json.Number("600")}) {
				t.Error("token renewal changed its explicit bounded increment or target")
			}
			lifecycleRenewAuth(w, 123)
		default:
			t.Error("renewal used lookup-self, renew-self, or an unrelated endpoint")
			w.WriteHeader(http.StatusNotFound)
		}
	})
	info, err := client.RenewLifecycleToken(context.Background(), "selected-token", lifecycleTargetToken, 600)
	if err != nil || !info.Exists || info.TTLSeconds != 123 || !info.Renewable || writes.Load() != 1 || reads.Load() < 1 {
		t.Fatal("renewal guessed the requested TTL instead of projecting the actual server result")
	}
	lifecycleAssertSafe(t, info)
}

func TestLifecycleTokenRenewalRejectsUnboundedPrivilegedOrLimitedTargetsBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"not renewable", func(v map[string]any) { v["renewable"] = false }},
		{"root policy", func(v map[string]any) { v["policies"] = []string{"root"} }},
		{"root identity policy", func(v map[string]any) { v["identity_policies"] = []string{"root"} }},
		{"unlimited TTL", func(v map[string]any) { v["ttl"] = 0 }},
		{"batch token", func(v map[string]any) { v["type"] = "batch" }},
		{"limited uses", func(v map[string]any) { v["num_uses"] = 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var writes atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/auth/token/lookup" {
					writes.Add(1)
					w.WriteHeader(http.StatusNoContent)
					return
				}
				value := lifecycleTokenData()
				test.edit(value)
				kvReply(w, value)
			})
			if _, err := client.RenewLifecycleToken(context.Background(), "selected-token", lifecycleTargetToken, 60); err == nil || writes.Load() != 0 {
				t.Error("unsafe lifecycle token received a renewal mutation")
			} else {
				lifecycleAssertSafe(t, err)
			}
		})
	}
	var requests atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	for _, increment := range []int64{-1, 0, 86401} {
		if _, err := client.RenewLifecycleToken(context.Background(), "selected-token", lifecycleTargetToken, increment); err == nil {
			t.Error("invalid renewal increment was accepted")
		}
	}
	if requests.Load() != 0 {
		t.Error("invalid renewal options selected a credential or contacted Vault")
	}
}

func TestLifecycleTokenRenewalNeverRetriesUnknownMutationOutcomes(t *testing.T) {
	for _, outcome := range []string{"missing auth", "zero lifetime", "server error", "lost acknowledgement"} {
		t.Run(outcome, func(t *testing.T) {
			var writes atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/auth/token/lookup" {
					kvReply(w, lifecycleTokenData())
					return
				}
				writes.Add(1)
				switch outcome {
				case "missing auth":
					_, _ = io.WriteString(w, `{}`)
				case "zero lifetime":
					lifecycleRenewAuth(w, 0)
				case "server error":
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = io.WriteString(w, `{"errors":["private-f10-renew-error"]}`)
				default:
					loseKVMutationResponse(t, w)
				}
			})
			info, err := client.RenewLifecycleToken(context.Background(), "selected-token", lifecycleTargetToken, 60)
			if !errors.Is(err, vault.ErrAccessUnconfirmed) || writes.Load() != 1 {
				t.Error("unknown token renewal was retried or classified as a definite failure")
			}
			lifecycleAssertSafe(t, info)
			if err != nil {
				lifecycleAssertSafe(t, err)
			}
		})
	}
}

func TestLifecycleLeaseLookupUsesExactBodyAndDistinguishesMissingFromFailure(t *testing.T) {
	var requests atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		accessRequest(t, r, "selected-token")
		if r.Method != http.MethodPut || r.URL.Path != "/v1/sys/leases/lookup" || r.URL.RawQuery != "" ||
			!reflect.DeepEqual(kvWriteBody(t, r), map[string]any{"lease_id": lifecycleLeaseID}) {
			t.Error("lease inspection used a prefix, URL credential or unrelated endpoint")
		}
		kvReply(w, map[string]any{"id": lifecycleLeaseID, "ttl": 300, "renewable": true, "private": "private-f10-lease-value"})
	})
	info, err := client.InspectLifecycleLease(context.Background(), "selected-token", lifecycleLeaseID)
	if err != nil || !info.Exists || info.TTLSeconds != 300 || !info.Renewable || requests.Load() != 1 {
		t.Fatal("exact lease inspection omitted actual TTL or required a mutation")
	}
	lifecycleAssertSafe(t, info)
	for _, test := range []struct {
		status  int
		message string
		missing bool
		denied  bool
	}{
		{400, "invalid lease", true, false}, {400, "private-f10-other-error", false, false}, {403, "permission denied", false, true},
	} {
		client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(test.status)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{test.message}})
		})
		actual, err := client.InspectLifecycleLease(context.Background(), "selected-token", lifecycleLeaseID)
		if test.missing {
			if err != nil || actual.Exists {
				t.Error("Vault's exact invalid-lease response did not mean absent")
			}
		} else if err == nil || actual.Exists || test.denied && !errors.Is(err, vault.ErrPermissionDenied) {
			t.Error("lease denial or unrelated failure was silently treated as absence")
		}
		lifecycleAssertSafe(t, actual)
		if err != nil {
			lifecycleAssertSafe(t, err)
		}
	}
}

func TestLifecycleLeaseRenewalAndSynchronousExactRevocationReturnSafeActualMetadata(t *testing.T) {
	var renewed, revoked atomic.Int32
	var absent atomic.Bool
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		accessRequest(t, r, "selected-token")
		body := kvWriteBody(t, r)
		if r.Method != http.MethodPut || r.URL.RawQuery != "" || body["lease_id"] != lifecycleLeaseID {
			t.Error("lifecycle lease operation changed its exact identifier or transport method")
		}
		switch r.URL.Path {
		case "/v1/sys/leases/lookup":
			if absent.Load() {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"errors":["invalid lease"]}`)
				return
			}
			kvReply(w, map[string]any{"id": lifecycleLeaseID, "ttl": 300, "renewable": true})
		case "/v1/sys/leases/renew":
			renewed.Add(1)
			if !reflect.DeepEqual(body, map[string]any{"lease_id": lifecycleLeaseID, "increment": json.Number("600")}) {
				t.Error("lease renewal changed its bounded increment")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"lease_id": lifecycleLeaseID, "lease_duration": 123, "renewable": true, "data": map[string]any{"password": "private-f10-password"}})
		case "/v1/sys/leases/revoke":
			revoked.Add(1)
			if !reflect.DeepEqual(body, map[string]any{"lease_id": lifecycleLeaseID, "sync": true}) {
				t.Error("lease revocation was asynchronous or used unapproved force semantics")
			}
			absent.Store(true)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Error("lifecycle lease operation used a prefix, force or unrelated endpoint")
			w.WriteHeader(http.StatusNotFound)
		}
	})
	renewal, err := client.RenewLifecycleLease(context.Background(), "selected-token", lifecycleLeaseID, 600)
	if err != nil || !renewal.Exists || renewal.TTLSeconds != 123 || !renewal.Renewable || renewed.Load() != 1 {
		t.Fatal("lease renewal did not report the actual server lifetime")
	}
	lifecycleAssertSafe(t, renewal)
	result, err := client.RevokeLifecycleLease(context.Background(), "selected-token", lifecycleLeaseID)
	if err != nil || result.Exists || revoked.Load() != 1 {
		t.Fatal("exact synchronous lease revocation was not confirmed")
	}
	lifecycleAssertSafe(t, result)
	if _, err := client.RevokeLifecycleLease(context.Background(), "selected-token", lifecycleLeaseID); err != nil || revoked.Load() != 1 {
		t.Error("revoking an absent lease dispatched a second mutation")
	}
}

func TestLifecycleLeaseBoundsAndNonrenewablePreflightNeverMutate(t *testing.T) {
	var requests, mutations atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/v1/sys/leases/lookup" {
			mutations.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		kvReply(w, map[string]any{"id": lifecycleLeaseID, "ttl": 300, "renewable": false})
	})
	for _, id := range []string{"", "/database/creds/app/id", "database//app/id", "database/../app/id", "database/creds/*", "https://private-f10.invalid/lease", "database/creds/app/id?private-f10-value", "database/creds/app/\x00id", strings.Repeat("x", 4097)} {
		if vault.ValidateLifecycleLeaseID(id) == nil {
			t.Error("unsafe lease identifier was accepted")
		}
		if _, err := client.InspectLifecycleLease(context.Background(), "selected-token", id); err == nil {
			t.Error("lease inspection bypassed identifier validation")
		}
	}
	for _, increment := range []int64{-1, 0, 86401} {
		if _, err := client.RenewLifecycleLease(context.Background(), "selected-token", lifecycleLeaseID, increment); err == nil {
			t.Error("unsafe lease renewal increment was accepted")
		}
	}
	if requests.Load() != 0 {
		t.Error("invalid lease request contacted Vault")
	}
	if _, err := client.RenewLifecycleLease(context.Background(), "selected-token", lifecycleLeaseID, 60); err == nil || mutations.Load() != 0 || requests.Load() != 1 {
		t.Error("nonrenewable lease was mutated instead of rejected during inspection")
	}
}

func TestLifecycleLeaseMutationsNeverRetryUnknownOutcomes(t *testing.T) {
	for _, operation := range []string{"renew", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			var writes atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/leases/lookup" {
					kvReply(w, map[string]any{"id": lifecycleLeaseID, "ttl": 300, "renewable": true})
					return
				}
				writes.Add(1)
				loseKVMutationResponse(t, w)
			})
			var err error
			if operation == "renew" {
				_, err = client.RenewLifecycleLease(context.Background(), "selected-token", lifecycleLeaseID, 60)
			} else {
				_, err = client.RevokeLifecycleLease(context.Background(), "selected-token", lifecycleLeaseID)
			}
			if !errors.Is(err, vault.ErrAccessUnconfirmed) || writes.Load() != 1 {
				t.Error("unknown lease mutation was retried or its uncertainty was discarded")
			}
			if err != nil {
				lifecycleAssertSafe(t, err)
			}
		})
	}
}
