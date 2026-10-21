package vault_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/vault"
)

func TestCheckTokenReturnsOnlySafeAuthenticationMetadata(t *testing.T) {
	for _, test := range []struct {
		name      string
		ttl       int64
		renewable bool
		policies  []string
	}{
		{name: "service token", ttl: 3600, renewable: true, policies: []string{"default", "application-reader"}},
		{name: "root token", ttl: 0, renewable: false, policies: []string{"root"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			clearVaultEnvironment(t)
			const token = "caller-token-private-marker"
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/v1/auth/token/lookup-self" {
					t.Errorf("unexpected authentication operation: %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("X-Vault-Token") != token {
					t.Error("self-lookup did not use the explicitly supplied token")
				}
				if r.Header.Get("X-Vault-Namespace") != "organization/team" {
					t.Error("self-lookup lost the configured namespace")
				}
				if r.Header.Get("X-Vault-Request") != "true" {
					t.Error("self-lookup omitted the Vault Agent protection header")
				}
				for _, header := range []string{"Authorization", "Cookie", "X-Operator-Private"} {
					if r.Header.Get(header) != "" {
						t.Errorf("self-lookup sent an inherited %s header", header)
					}
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || len(body) != 0 {
					t.Error("self-lookup must not write a request body")
				}
				writeTokenData(w, map[string]any{
					"id": token, "accessor": "private-accessor-marker", "policies": test.policies,
					"ttl": test.ttl, "renewable": test.renewable, "meta": map[string]string{"private": "private-metadata-marker"},
					"display_name": "private-display-name-marker", "namespace": "untrusted-response-namespace",
				})
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", server.URL)
			t.Setenv("VAULT_NAMESPACE", "organization/team")
			t.Setenv("VAULT_TOKEN", "different-inherited-token")
			t.Setenv("VAULT_HEADERS", `{"Authorization":"Bearer inherited-authorization","Cookie":"inherited-cookie","x-vault-token":"inherited-header-token","X-Operator-Private":"inherited-private-header"}`)
			client, err := vault.NewFromEnvironment()
			if err != nil {
				t.Fatalf("create client: %v", err)
			}
			result, err := client.CheckToken(context.Background(), token)
			if err != nil {
				t.Fatalf("check token: %v", err)
			}
			if !result.Authenticated || result.Namespace != "organization/team" || result.TTL != test.ttl || result.Renewable != test.renewable {
				t.Errorf("unexpected authentication report: %+v", result)
			}
			if strings.Join(result.Policies, ",") != strings.Join(test.policies, ",") {
				t.Errorf("policies = %v, want %v", result.Policies, test.policies)
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatalf("encode public authentication report: %v", err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatalf("read public authentication fields: %v", err)
			}
			for _, field := range []string{"authenticated", "namespace", "policies", "ttl_seconds", "renewable"} {
				if _, ok := fields[field]; !ok {
					t.Errorf("public report is missing %s", field)
				}
			}
			if len(fields) != 5 {
				t.Errorf("public report contains %d fields, want exactly five", len(fields))
			}
			for _, secret := range []string{token, "private-accessor-marker", "private-metadata-marker", "private-display-name-marker", "untrusted-response-namespace"} {
				if strings.Contains(string(encoded), secret) {
					t.Error("public authentication report exposed private upstream fields")
				}
			}
			if requests.Load() != 1 {
				t.Errorf("authentication requests = %d, want one self-lookup", requests.Load())
			}
		})
	}
}

func TestCheckTokenRejectsErrorsAndMalformedResponses(t *testing.T) {
	for _, test := range []struct {
		name            string
		code            int
		body            string
		unauthenticated bool
	}{
		{name: "invalid token", code: http.StatusForbidden, body: `{"errors":["private-upstream-token-marker"]}`, unauthenticated: true},
		{name: "unauthorized", code: http.StatusUnauthorized, body: `{"errors":["private-upstream-token-marker"]}`, unauthenticated: true},
		{name: "upstream failure", code: http.StatusServiceUnavailable, body: `{"errors":["private-upstream-token-marker"]}`},
		{name: "invalid JSON", code: http.StatusOK, body: "private-upstream-token-marker"},
		{name: "missing data", code: http.StatusOK, body: `{}`},
		{name: "null data", code: http.StatusOK, body: `{"data":null}`},
		{name: "empty data", code: http.StatusOK, body: `{"data":{}}`},
		{name: "invalid policies", code: http.StatusOK, body: `{"data":{"policies":"private-upstream-token-marker","ttl":3600,"renewable":true}}`},
		{name: "invalid policy entry", code: http.StatusOK, body: `{"data":{"policies":[1],"ttl":3600,"renewable":true}}`},
		{name: "invalid TTL", code: http.StatusOK, body: `{"data":{"policies":["default"],"ttl":"private-upstream-token-marker","renewable":true}}`},
		{name: "negative TTL", code: http.StatusOK, body: `{"data":{"policies":["default"],"ttl":-1,"renewable":true}}`},
		{name: "fractional TTL", code: http.StatusOK, body: `{"data":{"policies":["default"],"ttl":1.5,"renewable":true}}`},
		{name: "invalid renewable", code: http.StatusOK, body: `{"data":{"policies":["default"],"ttl":3600,"renewable":"private-upstream-token-marker"}}`},
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
			result, err := client.CheckToken(context.Background(), "private-upstream-token-marker")
			if err == nil || result.Authenticated {
				t.Fatal("invalid authentication response was accepted")
			}
			if errors.Is(err, vault.ErrUnauthenticated) != test.unauthenticated {
				t.Errorf("unauthenticated classification = %v, want %v", errors.Is(err, vault.ErrUnauthenticated), test.unauthenticated)
			}
			if strings.Contains(err.Error(), "private-upstream-token-marker") {
				t.Error("authentication error exposed private upstream content")
			}
			if requests.Load() != 1 {
				t.Errorf("authentication requests = %d, want one attempt", requests.Load())
			}
		})
	}
}

func TestCheckTokenMissingTokenDoesNotContactVault(t *testing.T) {
	clearVaultEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if _, err := client.CheckToken(context.Background(), ""); !errors.Is(err, vault.ErrUnauthenticated) {
		t.Errorf("missing-token error = %v, want ErrUnauthenticated", err)
	}
	if requests.Load() != 0 {
		t.Error("missing-token check contacted Vault")
	}
}

func TestAuthenticationNeverContaminatesConcurrentHealthRequests(t *testing.T) {
	clearVaultEnvironment(t)
	var healthCalls, authCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sys/health":
			healthCalls.Add(1)
			if r.Header.Get("X-Vault-Token") != "" {
				t.Error("health request inherited a token from a concurrent authentication check")
			}
			io.WriteString(w, `{"initialized":true,"sealed":false,"version":"2.2.0"}`)
		case "/v1/auth/token/lookup-self":
			authCalls.Add(1)
			token := r.Header.Get("X-Vault-Token")
			if token != "first-caller-token" && token != "second-caller-token" {
				t.Error("authentication request used an unrelated inherited token")
				w.WriteHeader(http.StatusForbidden)
				return
			}
			writeTokenData(w, map[string]any{"id": token, "policies": []string{token[:5]}, "ttl": 60, "renewable": true})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "inherited-token-must-stay-isolated")
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	start := make(chan struct{})
	failures := make(chan error, 30)
	var workers sync.WaitGroup
	for index := range 30 {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			<-start
			if index%3 == 0 {
				_, err := client.Status(context.Background())
				failures <- err
				return
			}
			token := "first-caller-token"
			if index%3 == 2 {
				token = "second-caller-token"
			}
			report, err := client.CheckToken(context.Background(), token)
			if err == nil && (!report.Authenticated || len(report.Policies) != 1 || report.Policies[0] != token[:5]) {
				err = errors.New("authentication report came from a different concurrent token")
			}
			failures <- err
		}(index)
	}
	close(start)
	workers.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Errorf("concurrent request: %v", err)
		}
	}
	if _, err := client.Status(context.Background()); err != nil {
		t.Fatalf("read health after authentication: %v", err)
	}
	if healthCalls.Load() != 11 || authCalls.Load() != 20 {
		t.Errorf("health/auth requests = %d/%d, want 11/20", healthCalls.Load(), authCalls.Load())
	}
}

func TestCheckTokenHonorsCancellationAndConfiguredTimeout(t *testing.T) {
	clearVaultEnvironment(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_CLIENT_TIMEOUT", "40ms")
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.CheckToken(ctx, "caller-token"); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled authentication error = %v, want context.Canceled", err)
	}
	if _, err := client.CheckToken(context.Background(), "caller-token"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("bounded authentication error = %v, want context.DeadlineExceeded", err)
	}
}

func TestCheckTokenDoesNotFollowRedirects(t *testing.T) {
	clearVaultEnvironment(t)
	var forwarded atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		writeTokenData(w, map[string]any{"policies": []string{"default"}, "ttl": 60, "renewable": true})
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/v1/auth/token/lookup-self", http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	t.Setenv("VAULT_ADDR", source.URL)
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if _, err := client.CheckToken(context.Background(), "private-token-not-forwarded"); err == nil {
		t.Error("redirected token check unexpectedly succeeded")
	}
	if forwarded.Load() != 0 {
		t.Error("authentication forwarded its token to a redirect target")
	}
}

func TestCheckTokenVerifiesTLSAndSupportsClientCertificates(t *testing.T) {
	clearVaultEnvironment(t)
	caPEM, serverCertificate, clientCertificatePEM, clientKeyPEM := mutualTLSMaterial(t)
	clientRoots := x509.NewCertPool()
	clientRoots.AppendCertsFromPEM(caPEM)
	var authenticated atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticated.Add(1)
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			t.Error("authentication request did not use a verified client certificate")
		}
		writeTokenData(w, map[string]any{"policies": []string{"default"}, "ttl": 60, "renewable": true})
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCertificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatalf("create untrusted TLS client: %v", err)
	}
	if _, err := client.CheckToken(context.Background(), "caller-token"); err == nil {
		t.Error("authentication accepted an untrusted server certificate")
	}
	t.Setenv("VAULT_CACERT_BYTES", string(caPEM))
	client, err = vault.NewFromEnvironment()
	if err != nil {
		t.Fatalf("create trusted client: %v", err)
	}
	if _, err := client.CheckToken(context.Background(), "caller-token"); err == nil {
		t.Error("mutual TLS authentication succeeded without a client certificate")
	}
	if authenticated.Load() != 0 {
		t.Error("an unverified TLS connection reached the authenticated endpoint")
	}
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "client.pem")
	keyPath := filepath.Join(directory, "client-key.pem")
	if err := os.WriteFile(certificatePath, clientCertificatePEM, 0600); err != nil {
		t.Fatalf("write client certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, clientKeyPEM, 0600); err != nil {
		t.Fatalf("write client key: %v", err)
	}
	t.Setenv("VAULT_CLIENT_CERT", certificatePath)
	t.Setenv("VAULT_CLIENT_KEY", keyPath)
	client, err = vault.NewFromEnvironment()
	if err != nil {
		t.Fatalf("create mutual TLS client: %v", err)
	}
	if report, err := client.CheckToken(context.Background(), "caller-token"); err != nil || !report.Authenticated {
		t.Fatalf("mutual TLS authentication failed: %v", err)
	}
	if authenticated.Load() != 1 {
		t.Errorf("verified authenticated calls = %d, want one", authenticated.Load())
	}
}

func writeTokenData(writer http.ResponseWriter, data map[string]any) {
	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(map[string]any{"data": data})
}

func mutualTLSMaterial(t *testing.T) ([]byte, tls.Certificate, []byte, []byte) {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate test key: %v", err)
		}
		return key
	}
	caKey, serverKey, clientKey := newKey(), newKey(), newKey()
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "F01 test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create test CA: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	issue := func(serial int64, key *ecdsa.PrivateKey, client bool) ([]byte, []byte) {
		certificate := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: fmt.Sprintf("F01 test %d", serial)}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if client {
			certificate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		} else {
			certificate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			certificate.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(rand.Reader, certificate, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatalf("issue test certificate: %v", err)
		}
		privateDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("encode test private key: %v", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	}
	serverPEM, serverKeyPEM := issue(2, serverKey, false)
	serverPair, err := tls.X509KeyPair(serverPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("load test server key pair: %v", err)
	}
	clientPEM, clientKeyPEM := issue(3, clientKey, true)
	return caPEM, serverPair, clientPEM, clientKeyPEM
}
