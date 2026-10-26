package cli_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/blueprint"
	"github.com/ml0renz0/secretwright/internal/cli"
)

const pkiCLIRequest = `api_version: secretwright/pki/v1
name: application
common_name: api.example.test
dns_names: [api.example.test]
ip_addresses: []
ttl: 1h
usage: server-auth
key: {type: ecdsa, bits: 256}
`

func pkiCLIFile(t *testing.T, body []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pki-input")
	if os.WriteFile(path, body, mode) != nil || os.Chmod(path, mode) != nil {
		t.Fatal("could not prepare PKI input fixture")
	}
	return path
}

type pkiCLIFixture struct {
	root, cert, key, csr []byte
}

func pkiCLICertificates(t *testing.T, expired bool) pkiCLIFixture {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("could not prepare native root key")
	}
	now := time.Now().UTC().Truncate(time.Second)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fixture Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal("could not prepare native root certificate")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("could not prepare native leaf key")
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1001), Subject: pkix.Name{CommonName: "api.example.test"}, DNSNames: []string{"api.example.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	if expired {
		leaf.NotBefore, leaf.NotAfter = now.Add(-time.Hour), now.Add(-time.Minute)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal("could not prepare native leaf certificate")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal("could not encode native private key")
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: leaf.Subject, DNSNames: leaf.DNSNames}, leafKey)
	if err != nil {
		t.Fatal("could not prepare native CSR")
	}
	return pkiCLIFixture{root: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), csr: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})}
}

func pkiCLISafe(t *testing.T, output, diagnostics string, private ...string) {
	t.Helper()
	for _, marker := range append(private, "-----BEGIN", "private-f11-upstream", "private-f11-operator") {
		if marker != "" && strings.Contains(output+diagnostics, marker) {
			t.Error("PKI metadata or diagnostics exposed private material")
		}
	}
}

func TestPKIOfflineExamplesSchemaAndHelpIgnoreVaultConfiguration(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "private-invalid-address")
	t.Setenv("VAULT_CACERT", "/private-missing-ca")
	t.Setenv("VAULT_TOKEN", "private-f11-operator")
	for _, format := range []string{"", "yaml", "json"} {
		args := []string{"pki", "example"}
		if format != "" {
			args = append(args, "--format", format)
		}
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		document, err := blueprint.DecodeConfiguration(strings.NewReader(output))
		if code != 0 || diagnostics != "" || err != nil || document["api_version"] != "secretwright/pki/v1" || json.Valid([]byte(output)) != (format == "json") {
			t.Fatal("offline PKI example lost YAML defaults or explicit JSON")
		}
		file := pkiCLIFile(t, []byte(output), 0o644)
		code, output, diagnostics = runWriteCLI(f03PanicReader{}, "pki", "validate", "--file", file)
		var report map[string]any
		if code != 0 || diagnostics != "" || json.Unmarshal([]byte(output), &report) != nil || report["name"] != document["name"] {
			t.Error("PKI example was not validated offline as metadata")
		}
		for _, key := range []string{"common_name", "dns_names", "ip_addresses", "key"} {
			if _, present := report[key]; present {
				t.Error("PKI validation returned request configuration")
			}
		}
	}
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, "pki", "schema")
	var schema map[string]any
	if code != 0 || diagnostics != "" || json.Unmarshal([]byte(output), &schema) != nil || schema["$id"] != "urn:secretwright:pki:v1" {
		t.Error("PKI schema was not available offline")
	}
	for _, prefix := range [][]string{
		{"pki"}, {"pki", "schema"}, {"pki", "example"}, {"pki", "validate"},
		{"pki", "cert"}, {"pki", "cert", "inspect"}, {"pki", "cert", "verify"}, {"pki", "cert", "match"},
		{"pki", "key"}, {"pki", "key", "inspect"}, {"pki", "csr"}, {"pki", "csr", "inspect"}, {"pki", "csr", "create"},
		{"pki", "ca"}, {"pki", "read"}, {"pki", "issue"}, {"pki", "sign"}, {"pki", "revoke"},
	} {
		args := append(append([]string{}, prefix...), "--help")
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		if code != 0 || diagnostics != "" || !strings.Contains(output, "Usage:") {
			t.Error("PKI help selected credentials or network at a command depth")
		}
	}
}

func TestPKINativeInspectionVerificationAndKeyMatchingStayOffline(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "private-invalid-address")
	t.Setenv("VAULT_CLIENT_TIMEOUT", "private-invalid-timeout")
	f := pkiCLICertificates(t, false)
	cert, root, key, csr := pkiCLIFile(t, f.cert, 0o644), pkiCLIFile(t, f.root, 0o644), pkiCLIFile(t, f.key, 0o600), pkiCLIFile(t, f.csr, 0o644)
	for _, args := range [][]string{
		{"pki", "cert", "inspect", "--file", cert}, {"pki", "key", "inspect", "--file", key}, {"pki", "csr", "inspect", "--file", csr},
		{"pki", "cert", "verify", "--file", cert, "--ca-file", root, "--hostname", "api.example.test"},
		{"pki", "cert", "match", "--file", cert, "--key", key},
	} {
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		if code != 0 || diagnostics != "" || !json.Valid([]byte(output)) {
			t.Error("native PKI operation did not return offline JSON metadata")
		}
		pkiCLISafe(t, output, diagnostics, string(f.key), string(f.cert), string(f.csr))
		if args[2] == "verify" {
			var report struct {
				Valid             bool `json:"valid"`
				RevocationChecked bool `json:"revocation_checked"`
			}
			if json.Unmarshal([]byte(output), &report) != nil || !report.Valid || report.RevocationChecked {
				t.Error("X509 verification falsely claimed a revocation check")
			}
		}
	}
	wrong := pkiCLICertificates(t, false)
	wrongRoot, wrongKey := pkiCLIFile(t, wrong.root, 0o644), pkiCLIFile(t, wrong.key, 0o600)
	expired := pkiCLICertificates(t, true)
	for _, args := range [][]string{
		{"pki", "cert", "verify", "--file", cert, "--ca-file", root, "--hostname", "foreign.example.test"},
		{"pki", "cert", "verify", "--file", cert, "--ca-file", wrongRoot},
		{"pki", "cert", "verify", "--file", cert, "--ca-file", root, "--usage", "client-auth"},
		{"pki", "cert", "verify", "--file", pkiCLIFile(t, expired.cert, 0o644), "--ca-file", pkiCLIFile(t, expired.root, 0o644)},
		{"pki", "cert", "match", "--file", cert, "--key", wrongKey},
	} {
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		if code != 4 || diagnostics == "" || !json.Valid([]byte(output)) {
			t.Error("negative PKI verification or mismatch lacked its safe report and exit code")
		}
		pkiCLISafe(t, output, diagnostics, string(f.key), string(wrong.key))
	}
}

func TestPKICSRCreatePublishesPrivateMatchingKeyAndCSR(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "private-invalid-address")
	request := pkiCLIFile(t, []byte(pkiCLIRequest), 0o644)
	directory := t.TempDir()
	keyPath, csrPath := filepath.Join(directory, "key.pem"), filepath.Join(directory, "request.pem")
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, "pki", "csr", "create", "--file", request, "--key-out", keyPath, "--out", csrPath)
	if code != 0 || diagnostics != "" || !json.Valid([]byte(output)) {
		t.Fatal("offline CSR generation did not publish its metadata")
	}
	keyBody, keyErr := os.ReadFile(keyPath)
	csrBody, csrErr := os.ReadFile(csrPath)
	keyBlock, _ := pem.Decode(keyBody)
	csrBlock, _ := pem.Decode(csrBody)
	if keyErr != nil || csrErr != nil || keyBlock == nil || csrBlock == nil {
		t.Fatal("CSR generation did not save standard PEM artifacts")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal("generated private key was not PKCS8")
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		t.Fatal("generated key cannot sign")
	}
	parsedCSR, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil || parsedCSR.CheckSignature() != nil || parsedCSR.Subject.CommonName != "api.example.test" || len(parsedCSR.DNSNames) != 1 || parsedCSR.DNSNames[0] != "api.example.test" {
		t.Fatal("generated CSR did not contain a verified requested identity")
	}
	publicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(publicKey, parsedCSR.RawSubjectPublicKeyInfo) {
		t.Error("generated CSR and private key do not correspond")
	}
	for _, path := range []string{keyPath, csrPath} {
		info, err := os.Stat(path)
		if err != nil || info.Mode() != 0o600 {
			t.Error("generated PKI artifact was not private")
		}
	}
	pkiCLISafe(t, output, diagnostics, string(keyBody), string(csrBody))
	code, _, diagnostics = runWriteCLI(f03PanicReader{}, "pki", "csr", "create", "--file", request, "--key-out", keyPath, "--out", filepath.Join(directory, "second.pem"))
	if code != 4 || diagnostics == "" {
		t.Error("CSR creation overwrote an existing private key")
	}
}

func TestPKIRejectsUnsafeOptionsAndReservesOutputsBeforeSelectingOperator(t *testing.T) {
	cleanEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	f := pkiCLICertificates(t, false)
	cert, root := pkiCLIFile(t, f.cert, 0o644), pkiCLIFile(t, f.root, 0o644)
	request := pkiCLIFile(t, []byte(pkiCLIRequest), 0o644)
	publicKey := pkiCLIFile(t, f.key, 0o644)
	for _, args := range [][]string{
		{"pki", "example", "--format", "toml"}, {"pki", "schema", "--format", "yaml"},
		{"pki", "validate", "--file", "-"}, {"pki", "cert", "inspect", "--file", cert, "--address", server.URL},
		{"pki", "cert", "verify", "--file", cert, "--ca-file", root, "--usage", "any"},
		{"pki", "key", "inspect", "--file", publicKey},
		{"pki", "cert", "inspect", "--file", pkiCLIFile(t, append(append([]byte{}, f.key...), f.cert...), 0o644)},
		{"pki", "revoke", "--mount", "pki", "--file", cert},
		{"pki", "ca", "--mount", "../pki", "--out", filepath.Join(t.TempDir(), "out")},
		{"pki", "read", "--mount", "pki", "--serial", "private?serial", "--out", filepath.Join(t.TempDir(), "out")},
		{"pki", "issue", "--mount", "pki", "--role", "app", "--file", request, "--ca-file", cert, "--out", filepath.Join(t.TempDir(), "out")},
		{"pki", "sign", "--mount", "pki", "--role", "app", "--file", request, "--csr", publicKey, "--ca-file", root, "--out", filepath.Join(t.TempDir(), "out")},
		{"pki", "ca", "--mount", "pki", "--out", "-"}, {"pki", "ca", "--mount", "pki", "--out", "out", "--dry-run"},
	} {
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		if code != 1 || diagnostics == "" {
			t.Error("invalid PKI options or local inputs were accepted")
		}
		pkiCLISafe(t, output, diagnostics, string(f.key))
	}
	existing := pkiCLIFile(t, []byte("private-existing-output"), 0o600)
	missingOperator := filepath.Join(t.TempDir(), "missing-operator")
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, "pki", "issue", "--mount", "pki", "--role", "app", "--file", request, "--ca-file", root, "--out", existing, "--token-file", missingOperator)
	if code != 4 || diagnostics == "" {
		t.Error("an existing output was not rejected before selecting the absent operator")
	}
	if body, err := os.ReadFile(existing); err != nil || string(body) != "private-existing-output" {
		t.Error("PKI preflight changed an existing output")
	}
	pkiCLISafe(t, output, diagnostics, missingOperator)
	if requests.Load() != 0 {
		t.Error("invalid PKI options, private files or output conflicts contacted Vault")
	}
}

func TestPKICAReadUsesSelectedConnectionAndPrivatePEMOutput(t *testing.T) {
	cleanEnvironment(t)
	f := pkiCLICertificates(t, false)
	operator := pkiCLIFile(t, []byte("private-f11-operator\n"), 0o600)
	var reads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/v1/pki/cert/ca" || r.Header.Get("X-Vault-Token") != "private-f11-operator" || r.Header.Get("X-Vault-Namespace") != "team" {
			t.Error("CA read lost its selected connection or endpoint")
		}
		accessReply(t, w, map[string]any{"data": map[string]any{"certificate": string(f.root)}})
	}))
	defer server.Close()
	out := filepath.Join(t.TempDir(), "ca.pem")
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, "pki", "ca", "--mount", "pki", "--address", server.URL, "--namespace", "team", "--token-file", operator, "--out", out)
	if code != 0 || diagnostics != "" || !json.Valid([]byte(output)) || reads.Load() != 1 {
		t.Fatal("CA read did not produce public metadata and one private output")
	}
	body, err := os.ReadFile(out)
	if err != nil || !bytes.Contains(body, []byte("BEGIN CERTIFICATE")) {
		t.Error("CA read did not export a standard PEM file")
	}
	info, err := os.Stat(out)
	if err != nil || info.Mode() != 0o600 {
		t.Error("CA output was not private")
	}
	pkiCLISafe(t, output, diagnostics, string(f.root))
	var failed bytes.Buffer
	code = cli.RunWithInput(context.Background(), []string{"pki", "cert", "inspect", "--file", out}, f03PanicReader{}, blueprintShortWriter{}, &failed, "test")
	if code != 1 || failed.Len() == 0 {
		t.Error("PKI metadata ignored a short stdout write")
	}
}

func TestPKIOfflineCommandsDetectEveryFailedOrShortOutput(t *testing.T) {
	cleanEnvironment(t)
	f := pkiCLICertificates(t, false)
	cert, root, key, csr := pkiCLIFile(t, f.cert, 0o644), pkiCLIFile(t, f.root, 0o644), pkiCLIFile(t, f.key, 0o600), pkiCLIFile(t, f.csr, 0o644)
	request := pkiCLIFile(t, []byte(pkiCLIRequest), 0o644)
	for _, args := range [][]string{
		{"pki", "schema"}, {"pki", "example"}, {"pki", "validate", "--file", request},
		{"pki", "cert", "inspect", "--file", cert}, {"pki", "key", "inspect", "--file", key}, {"pki", "csr", "inspect", "--file", csr},
		{"pki", "cert", "verify", "--file", cert, "--ca-file", root}, {"pki", "cert", "match", "--file", cert, "--key", key},
	} {
		for _, output := range []io.Writer{failedWriter{}, blueprintShortWriter{}} {
			var diagnostics bytes.Buffer
			code := cli.RunWithInput(context.Background(), args, f03PanicReader{}, output, &diagnostics, "test")
			if code != 1 || diagnostics.Len() == 0 {
				t.Error("PKI offline command ignored a failed or short output write")
			}
			pkiCLISafe(t, "", diagnostics.String(), string(f.key))
		}
	}
}

func TestPKICanceledCSRGenerationDoesNotLeavePrivateArtifacts(t *testing.T) {
	cleanEnvironment(t)
	request := pkiCLIFile(t, []byte(pkiCLIRequest), 0o644)
	directory := t.TempDir()
	keyPath, csrPath := filepath.Join(directory, "key.pem"), filepath.Join(directory, "request.pem")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output, diagnostics bytes.Buffer
	code := cli.RunWithInput(ctx, []string{"pki", "csr", "create", "--file", request, "--key-out", keyPath, "--out", csrPath}, f03PanicReader{}, &output, &diagnostics, "test")
	if code != 130 || diagnostics.Len() == 0 {
		t.Error("canceled CSR generation did not report cancellation before effects")
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Error("canceled CSR generation left a reserved output or private key")
	}
	pkiCLISafe(t, output.String(), diagnostics.String())
}
