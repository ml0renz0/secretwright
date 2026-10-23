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

func TestTokenCreationNeverInheritsTheAdministrativePolicies(t *testing.T) {
	var requests atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		accessRequest(t, r, "selected-token")
		if r.URL.Path != "/v1/auth/token/create" || r.Method != http.MethodPost {
			t.Error("token creation used an unexpected endpoint")
		}
		want := map[string]any{
			"policies": []any{"app-read"}, "ttl": json.Number("300"), "explicit_max_ttl": json.Number("600"),
			"renewable": false, "num_uses": json.Number("0"), "no_default_policy": true, "no_parent": false, "type": "service",
		}
		if !reflect.DeepEqual(kvWriteBody(t, r), want) {
			t.Error("token creation inherited policy, lifetime or administrative token defaults")
		}
		accessAuth(w)
	})
	issued, err := client.CreateToken(context.Background(), "selected-token", accessTokenSpec())
	if err != nil || issued.Token != "private-f06-issued-token" || issued.Accessor != f06Accessor || issued.Report.TTLSeconds != 300 || issued.Report.Renewable {
		t.Fatal("token creation did not return its private credential and actual lifetime")
	}
	if !reflect.DeepEqual(issued.Report.Policies, []string{"app-read"}) || issued.Report.EntityID != f06EntityID {
		t.Error("token creation reported policies or identity other than the approved response")
	}
	accessAssertSafe(t, issued)
	if requests.Load() != 1 {
		t.Error("token creation performed extra administrative or retry requests")
	}
}

func TestTokenSpecificationsRejectImplicitPoliciesAndUnboundedLifetimesOffline(t *testing.T) {
	for _, body := range []string{
		`{"ttl":"5m","explicit_max_ttl":"1h"}`,
		`{"policies":[],"ttl":"5m","explicit_max_ttl":"1h"}`,
		`{"policies":["ROOT"],"ttl":"5m","explicit_max_ttl":"1h"}`,
		`{"policies":["app-read"],"ttl":"0s","explicit_max_ttl":"1h"}`,
		`{"policies":["app-read"],"ttl":"1.5s","explicit_max_ttl":"1h"}`,
		`{"policies":["app-read"],"ttl":"5m","explicit_max_ttl":"1m"}`,
		`{"policies":["app-read"],"ttl":"25h","explicit_max_ttl":"25h"}`,
		`{"policies":["app-read"],"ttl":"5m","explicit_max_ttl":"1h","no_parent":true}`,
		`{"policies":["app-read"],"ttl":"5m","explicit_max_ttl":"1h","num_uses":-1}`,
	} {
		if _, err := vault.DecodeTokenSpec(strings.NewReader(body)); err == nil {
			t.Error("token decoder accepted implicit privileges, unsupported fields or an unbounded lifetime")
		}
	}
	var requests atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	for _, spec := range []vault.TokenSpec{
		{TTL: "5m", ExplicitMaxTTL: "1h"},
		{Policies: []string{"root"}, TTL: "5m", ExplicitMaxTTL: "1h"},
		{Policies: []string{"app-read"}, TTL: "0s", ExplicitMaxTTL: "1h"},
	} {
		if _, err := client.CreateToken(context.Background(), "selected-token", spec); err == nil {
			t.Error("direct domain token creation bypassed input validation")
		}
	}
	if requests.Load() != 0 {
		t.Error("invalid token creation contacted Vault")
	}
}

func TestTokenIssuanceReportsMalformedOrLostResponsesWithoutRetrying(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "missing auth", status: 200, body: `{}`},
		{name: "missing accessor", status: 200, body: `{"auth":{"client_token":"private-f06-issued-token","lease_duration":300,"renewable":false,"policies":["app-read"]}}`},
		{name: "unbounded auth", status: 200, body: `{"auth":{"client_token":"private-f06-issued-token","accessor":"private-f06-accessor","lease_duration":0,"renewable":false,"policies":["app-read"]}}`},
		{name: "root auth", status: 200, body: `{"auth":{"client_token":"private-f06-issued-token","accessor":"private-f06-accessor","lease_duration":300,"renewable":false,"policies":["root"]}}`},
		{name: "malformed JSON", status: 200, body: `private-f06-invalid-json`},
		{name: "server failure", status: 503, body: `{"errors":["private-f06-server-token-error"]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			})
			issued, err := client.CreateToken(context.Background(), "selected-token", accessTokenSpec())
			if !errors.Is(err, vault.ErrAccessUnconfirmed) {
				t.Fatal("malformed or lost token issue was not classified as an uncertain mutation")
			}
			accessAssertSafe(t, err)
			accessAssertSafe(t, issued)
			if requests.Load() != 1 {
				t.Error("uncertain token issuance was retried")
			}
		})
	}
}

func TestTokenRevocationKeepsCredentialsInTheRequiredBodyOrHeader(t *testing.T) {
	var target, self, accessor atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/token/revoke":
			target.Add(1)
			accessRequest(t, r, "selected-token")
			if !reflect.DeepEqual(kvWriteBody(t, r), map[string]any{"token": "private-f06-target-token"}) {
				t.Error("target token revocation did not send only the target token in the body")
			}
		case "/v1/auth/token/revoke-self":
			self.Add(1)
			accessRequest(t, r, "private-f06-target-token")
			body, err := io.ReadAll(r.Body)
			if r.Method != http.MethodPost || err != nil || strings.Contains(string(body), "private-f06-target-token") {
				t.Error("self revocation duplicated its credential outside the selected header")
			}
		case "/v1/auth/token/revoke-accessor":
			accessor.Add(1)
			accessRequest(t, r, "selected-token")
			if !reflect.DeepEqual(kvWriteBody(t, r), map[string]any{"accessor": f06Accessor}) {
				t.Error("compensating revocation did not use only the issued accessor")
			}
		default:
			t.Error("token revocation used an unexpected or orphaning endpoint")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	ctx := context.Background()
	result, err := client.RevokeToken(ctx, "selected-token", "private-f06-target-token")
	if err != nil || !result.Deleted {
		t.Fatal("target token revocation was not confirmed")
	}
	accessAssertSafe(t, result)
	result, err = client.RevokeSelf(ctx, "private-f06-target-token")
	if err != nil || !result.Deleted {
		t.Fatal("self token revocation was not confirmed")
	}
	accessAssertSafe(t, result)
	result, err = client.RevokeTokenAccessor(ctx, "selected-token", f06Accessor)
	if err != nil || !result.Deleted || target.Load() != 1 || self.Load() != 1 || accessor.Load() != 1 {
		t.Fatal("token revocation made unexpected requests")
	}
	accessAssertSafe(t, result)
}

func TestCapabilitiesQueryPhysicalPathsForTheSelectedTokenOnly(t *testing.T) {
	var requests atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		accessRequest(t, r, "selected-token")
		if r.Method != http.MethodPost || r.URL.Path != "/v1/sys/capabilities-self" {
			t.Error("capability query used an administrative target-token endpoint")
		}
		want := map[string]any{"paths": []any{"secret/data/app/item", "secret/metadata/app/"}}
		if !reflect.DeepEqual(kvWriteBody(t, r), want) {
			t.Error("capabilities remapped physical paths or sent a target token in the body")
		}
		kvReply(w, map[string]any{
			"secret/data/app/item": []string{"read", "read"},
			"secret/metadata/app/": []string{"read", "list"},
			"metadata":             "private-f06-capability-metadata",
		})
	})
	got, err := client.Capabilities(context.Background(), "selected-token", []string{"secret/metadata/app/", "secret/data/app/item", "secret/data/app/item"})
	want := []vault.CapabilityReport{
		{Path: "secret/data/app/item", Capabilities: []string{"read"}},
		{Path: "secret/metadata/app/", Capabilities: []string{"list", "read"}},
	}
	if err != nil || !reflect.DeepEqual(got, want) || requests.Load() != 1 {
		t.Fatal("capabilities did not report sorted approved verbs for each physical path")
	}
	accessAssertSafe(t, got)
}

func TestCapabilitiesRejectInvalidPathsAndUnapprovedResponseVerbs(t *testing.T) {
	var requests atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		kvReply(w, map[string]any{"secret/data/app": []string{"read", "private-f06-verb"}})
	})
	for _, paths := range [][]string{nil, {"/secret/data/app"}, {"v1/secret/data/app"}, {"secret/../private-f06-path"}, {"secret/data/app?query"}} {
		if _, err := client.Capabilities(context.Background(), "selected-token", paths); err == nil {
			t.Error("capability query accepted a noncanonical physical API path")
		}
	}
	if requests.Load() != 0 {
		t.Error("invalid capabilities query contacted Vault")
	}
	if _, err := client.Capabilities(context.Background(), "selected-token", []string{"secret/data/app"}); !errors.Is(err, vault.ErrAccessResponse) {
		t.Error("capability query accepted an unapproved server verb")
	} else {
		accessAssertSafe(t, err)
	}
}
