//go:build integration

package vault_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/ml0renz0/secretwright/internal/pki"
	"github.com/ml0renz0/secretwright/internal/vault"
)

type pkiIntegrationFixture struct {
	admin *api.Client
	client *vault.Client
	mount string
	token string
	denied string
	roots []byte
}

func preparePKIIntegration(t *testing.T) pkiIntegrationFixture {
	t.Helper()
	admin := integrationTokenAdmin(t)
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatal("could not initialize the disposable PKI client")
	}
	f := pkiIntegrationFixture{admin: admin, client: client, mount: fmt.Sprintf("secretwright-f11-%d", time.Now().UnixNano())}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := admin.Sys().MountWithContext(ctx, f.mount, &api.MountInput{Type: "pki", Config: api.MountConfigInput{MaxLeaseTTL: "1h", DefaultLeaseTTL: "5m"}}); err != nil {
		t.Fatal("could not mount the disposable PKI engine")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = admin.Sys().UnmountWithContext(cleanup, f.mount)
	})
	root, err := admin.Logical().WriteWithContext(ctx, f.mount+"/root/generate/internal", map[string]any{"common_name": "Secretwright F11 fixture root", "ttl": "1h", "key_type": "ec", "key_bits": 256, "format": "pem"})
	if err != nil || root == nil {
		t.Fatal("could not create the disposable non-exportable root")
	}
	ca, ok := root.Data["certificate"].(string)
	if !ok || ca == "" {
		t.Fatal("disposable PKI root omitted its public certificate")
	}
	f.roots = []byte(ca)
	_, err = admin.Logical().WriteWithContext(ctx, f.mount+"/roles/application", map[string]any{
		"allowed_domains": []string{"fixture.test"}, "allow_subdomains": true, "allow_bare_domains": false,
		"allow_ip_sans": true, "max_ttl": "5m", "ttl": "2m", "key_type": "ec", "key_bits": 256,
		"server_flag": true, "client_flag": false, "code_signing_flag": false,
		"use_csr_common_name": true, "use_csr_sans": true, "require_cn": false,
	})
	if err != nil {
		t.Fatal("could not create the bounded disposable PKI role")
	}
	policy := fmt.Sprintf(`path %q { capabilities = ["read"] }
path %q { capabilities = ["update"] }
path %q { capabilities = ["update"] }
path %q { capabilities = ["update"] }
`, f.mount+"/cert/*", f.mount+"/issue/application", f.mount+"/sign/application", f.mount+"/revoke")
	f.token = createKVIntegrationPolicyToken(t, admin, f.mount+"-issuer", policy)
	f.denied = createKVIntegrationPolicyToken(t, admin, f.mount+"-denied", `path "secretwright-f11-unrelated/*" { capabilities = ["read"] }`)
	return f
}

func pkiIntegrationSpec() pki.Spec {
	return pki.Spec{APIVersion: "secretwright/pki/v1", Name: "application", CommonName: "app.fixture.test", DNSNames: []string{"app.fixture.test"}, IPAddresses: []string{"127.0.0.1"}, TTL: "2m", Usage: "server-auth", Key: pki.KeySpec{Type: "ecdsa", Bits: 256}}
}

func pkiIntegrationPrivateReport(t *testing.T, value any, forbidden ...string) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("could not encode PKI metadata")
	}
	for _, marker := range append(forbidden, "-----BEGIN PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----") {
		if marker != "" && strings.Contains(string(body), marker) {
			t.Error("PKI report exposed private material or a Vault credential")
		}
	}
}

func pkiIntegrationTLS(t *testing.T, identity, roots []byte) {
	t.Helper()
	pair, err := tls.X509KeyPair(identity, identity)
	if err != nil {
		t.Fatal("issued identity is not a usable TLS certificate and matching private key")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(roots) {
		t.Fatal("could not load the explicit disposable TLS root")
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "fixture-pki-ready")
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "app.fixture.test", MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5*time.Second}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal("a native TLS handshake could not trust the issued certificate with its explicit root and SAN")
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(body) != "fixture-pki-ready" {
		t.Fatal("the native TLS consumer did not receive its authenticated response")
	}
	wrongTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "wrong.fixture.test", MinVersion: tls.VersionTLS12}}
	defer wrongTransport.CloseIdleConnections()
	wrong := &http.Client{Transport: wrongTransport, Timeout: 5*time.Second}
	if response, err := wrong.Get(server.URL); err == nil {
		_ = response.Body.Close()
		t.Error("native TLS accepted a hostname outside the issued SAN")
	}
}

func TestIntegrationPKIIssueIsUsableByANativeTLSConsumerAndCanBeRevoked(t *testing.T) {
	f := preparePKIIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	opts := vault.PKIOptions{Mount: f.mount}
	ca, err := f.client.ReadPKICA(ctx, f.token, opts)
	if err != nil || !ca.Report.IsCA || pki.ValidateRoots(ca.PEM) != nil {
		t.Fatal("PKI CA read did not return the explicit public trust anchor")
	}
	issued, err := f.client.IssuePKICertificate(ctx, f.token, "application", pkiIntegrationSpec(), f.roots, opts)
	if err != nil || issued.Report.IsCA || issued.Report.TTLSeconds <= 0 || issued.Report.TTLSeconds > 120 || issued.Report.Serial == "" {
		t.Fatal("bounded PKI issue did not return the actual leaf validity")
	}
	pkiIntegrationPrivateReport(t, issued, f.token, f.denied, string(issued.PEM))
	pkiIntegrationTLS(t, issued.PEM, f.roots)
	verified, err := pki.VerifyCertificate(bytes.NewReader(issued.PEM), bytes.NewReader(f.roots), nil, pki.VerifyOptions{Name: "app.fixture.test", Usage: "server-auth"})
	if err != nil || !verified.Valid || verified.RevocationChecked {
		t.Fatal("explicit chain verification failed or falsely claimed to check revocation")
	}
	read, err := f.client.ReadPKICertificate(ctx, f.token, issued.Report.Serial, opts)
	if err != nil || read.Report.SHA256 != issued.Report.SHA256 || bytes.Contains(read.PEM, []byte("PRIVATE KEY")) {
		t.Fatal("PKI certificate read changed its bound leaf or returned a private key")
	}
	revoked, err := f.client.RevokePKICertificate(ctx, f.token, issued.PEM, opts)
	if err != nil || !revoked.Revoked || revoked.RevocationTime <= 0 || revoked.Serial != issued.Report.Serial {
		t.Fatal("exact PKI revocation did not return a confirmed revocation record")
	}
	pkiIntegrationPrivateReport(t, revoked, f.token)
	crl, err := f.admin.Logical().ReadWithContext(ctx, f.mount+"/cert/crl")
	if err != nil || crl == nil {
		t.Fatal("could not read the disposable signed CRL after revocation")
	}
	text, ok := crl.Data["certificate"].(string)
	block, _ := pem.Decode([]byte(text))
	rootBlock, _ := pem.Decode(f.roots)
	if !ok || block == nil || rootBlock == nil {
		t.Fatal("PKI revocation omitted the public signed CRL")
	}
	list, err := x509.ParseRevocationList(block.Bytes)
	root, rootErr := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil || rootErr != nil || list.CheckSignatureFrom(root) != nil {
		t.Fatal("the PKI revocation list was not signed by the explicit fixture root")
	}
	leaf, _ := pem.Decode(read.PEM)
	if leaf == nil {
		t.Fatal("PKI certificate read omitted its public PEM leaf")
	}
	certificate, err := x509.ParseCertificate(leaf.Bytes)
	if err != nil {
		t.Fatal("could not parse the public issued leaf for CRL comparison")
	}
	found := false
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
			found = true
		}
	}
	if !found {
		t.Error("the exact revoked certificate serial is absent from its CA-signed CRL")
	}
}

func TestIntegrationPKISignsLocalCSRWithoutSendingItsPrivateKey(t *testing.T) {
	f := preparePKIIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	spec := pkiIntegrationSpec()
	generated, err := pki.GenerateCSR(ctx, spec)
	if err != nil {
		t.Fatal("could not generate the native local key and signed CSR")
	}
	upstream, err := url.Parse(os.Getenv("VAULT_ADDR"))
	if err != nil {
		t.Fatal("invalid disposable Vault address")
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	var writes atomic.Int32
	var leaked atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/"+f.mount+"/sign/application" {
			writes.Add(1)
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil || bytes.Contains(body, []byte("PRIVATE KEY")) || bytes.Contains(body, generated.PrivateKeyPEM) {
				leaked.Store(true)
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		proxy.ServeHTTP(w, r)
	}))
	defer server.Close()
	address := server.URL
	client, err := vault.New(vault.Options{Address: &address})
	if err != nil {
		t.Fatal("could not create the isolated signing client")
	}
	signed, err := client.SignPKICertificate(ctx, f.token, "application", spec, generated.CSRPEM, f.roots, vault.PKIOptions{Mount: f.mount})
	if err != nil || writes.Load() != 1 || leaked.Load() || bytes.Contains(signed.PEM, []byte("PRIVATE KEY")) {
		t.Fatal("PKI signing failed or sent/returned a local private key")
	}
	matched, err := pki.MatchPrivateKey(bytes.NewReader(signed.PEM), bytes.NewReader(generated.PrivateKeyPEM))
	if err != nil || !matched.Match || signed.Report.PublicKeySHA256 != generated.Report.PublicKeySHA256 {
		t.Fatal("the signed certificate does not belong to the retained local private key")
	}
	pkiIntegrationTLS(t, append(append([]byte(nil), generated.PrivateKeyPEM...), signed.PEM...), f.roots)
	pkiIntegrationPrivateReport(t, signed, f.token, string(generated.PrivateKeyPEM))
}

func TestIntegrationPKIRoleAndTokenPermissionsRemainEffective(t *testing.T) {
	f := preparePKIIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	opts := vault.PKIOptions{Mount: f.mount}
	if _, err := f.client.IssuePKICertificate(ctx, f.denied, "application", pkiIntegrationSpec(), f.roots, opts); !errors.Is(err, vault.ErrPermissionDenied) {
		t.Error("a token without PKI issue permission acquired a certificate")
	}
	spec := pkiIntegrationSpec()
	spec.CommonName, spec.DNSNames = "outside.invalid", []string{"outside.invalid"}
	if _, err := f.client.IssuePKICertificate(ctx, f.token, "application", spec, f.roots, opts); err == nil {
		t.Error("the PKI role issued an identity outside its allowed domain")
	}
}

func TestIntegrationPKILostIssueAcknowledgementDoesNotRepeatIssuance(t *testing.T) {
	f := preparePKIIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	upstream, err := url.Parse(os.Getenv("VAULT_ADDR"))
	if err != nil {
		t.Fatal("invalid disposable Vault address")
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	var writes atomic.Int32
	proxy.ModifyResponse = func(response *http.Response) error {
		if response.Request.URL.Path == "/v1/"+f.mount+"/issue/application" && response.StatusCode == 200 {
			_ = response.Body.Close()
			response.Body = io.NopCloser(strings.NewReader(`{"data":`))
			response.ContentLength = -1
			response.Header.Del("Content-Length")
		}
		return nil
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/"+f.mount+"/issue/application" {
			writes.Add(1)
		}
		proxy.ServeHTTP(w, r)
	}))
	defer server.Close()
	address := server.URL
	client, err := vault.New(vault.Options{Address: &address})
	if err != nil {
		t.Fatal("could not create the uncertain-issuance test client")
	}
	if _, err := client.IssuePKICertificate(ctx, f.token, "application", pkiIntegrationSpec(), f.roots, vault.PKIOptions{Mount: f.mount}); !errors.Is(err, vault.ErrAccessUnconfirmed) || writes.Load() != 1 {
		t.Error("an applied issuance with lost acknowledgement was retried or its uncertainty was hidden")
	}
}
