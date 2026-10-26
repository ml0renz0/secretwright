package vault_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/pki"
	"github.com/ml0renz0/secretwright/internal/vault"
)

const f11Operator = "private-f11-selected-operator"
const f11Mount = "team/pki"
const f11Serial = "01:23:45"

type f11PKIFixture struct {
	root       *x509.Certificate
	rootKey    *ecdsa.PrivateKey
	leaf       *x509.Certificate
	leafKey    *ecdsa.PrivateKey
	rootPEM    []byte
	leafPEM    []byte
	keyPEM     []byte
	csrPEM     []byte
	spec       pki.Spec
}

func f11NewKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("could not generate the private PKI fixture key")
	}
	return key
}

func f11Leaf(t *testing.T, root *x509.Certificate, rootKey, key *ecdsa.PrivateKey, edit func(*x509.Certificate)) (*x509.Certificate, []byte) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(0x12345), Subject: pkix.Name{CommonName: "app.fixture.test"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(15 * time.Minute),
		DNSNames: []string{"api.fixture.test", "app.fixture.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if edit != nil {
		edit(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal("could not sign the disposable PKI fixture leaf")
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("could not parse the disposable PKI fixture leaf")
	}
	return certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func f11Fixture(t *testing.T) f11PKIFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootKey, leafKey := f11NewKey(t), f11NewKey(t)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0x45678), Subject: pkix.Name{CommonName: "Secretwright Disposable Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal("could not generate the disposable PKI root")
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal("could not parse the disposable PKI root")
	}
	leaf, leafPEM := f11Leaf(t, root, rootKey, leafKey, nil)
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal("could not encode the private PKI fixture key")
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "app.fixture.test"}, DNSNames: []string{"api.fixture.test", "app.fixture.test"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}, leafKey)
	if err != nil {
		t.Fatal("could not generate the disposable PKI CSR")
	}
	return f11PKIFixture{
		root: root, rootKey: rootKey, leaf: leaf, leafKey: leafKey,
		rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), leafPEM: leafPEM,
		keyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		csrPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		spec: pki.Spec{APIVersion: "secretwright/pki/v1", Name: "application", CommonName: "app.fixture.test",
			DNSNames: []string{"api.fixture.test", "app.fixture.test"}, IPAddresses: []string{"127.0.0.1"}, TTL: "15m", Usage: "server-auth", Key: pki.KeySpec{Type: "ecdsa", Bits: 256}},
	}
}

func (f f11PKIFixture) response(includeKey bool) map[string]any {
	data := map[string]any{
		"certificate": string(f.leafPEM), "issuing_ca": string(f.rootPEM),
		"ca_chain": []string{string(f.rootPEM)}, "serial_number": f11Serial,
		"expiration": f.leaf.NotAfter.Unix(), "private": "private-f11-unapproved-response",
	}
	if includeKey {
		data["private_key"], data["private_key_type"] = string(f.keyPEM), "ec"
	}
	return data
}

func f11AssertSafe(t *testing.T, value any) {
	t.Helper()
	var body string
	if err, ok := value.(error); ok {
		if err == nil {
			t.Fatal("expected a safe PKI error")
		}
		body = err.Error()
	} else {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal("could not encode approved PKI metadata")
		}
		body = string(encoded)
	}
	for _, forbidden := range []string{"-----BEGIN", "private-f11-", "selected-token", "inherited-private-value"} {
		if strings.Contains(body, forbidden) {
			t.Error("PKI metadata or error exposed a credential or unapproved response field")
		}
	}
}

func TestPKIReadProjectsPublicCertificateMetadataWithoutLeakingPEM(t *testing.T) {
	f := f11Fixture(t)
	var requests atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		accessRequest(t, r, f11Operator)
		if r.Method != http.MethodGet || r.URL.RawQuery != "" {
			t.Error("PKI public read used a mutation or query")
		}
		switch r.URL.Path {
		case "/v1/" + f11Mount + "/cert/ca":
			kvReply(w, map[string]any{"certificate": string(f.rootPEM)})
		case "/v1/" + f11Mount + "/cert/" + f11Serial:
			kvReply(w, map[string]any{"certificate": string(f.leafPEM), "revocation_time": 0})
		default:
			t.Error("PKI read used an unrelated endpoint")
			w.WriteHeader(http.StatusNotFound)
		}
	})
	ca, err := client.ReadPKICA(context.Background(), f11Operator, vault.PKIOptions{Mount: f11Mount})
	if err != nil || !ca.Report.IsCA || !bytes.Equal(ca.PEM, f.rootPEM) {
		t.Fatal("PKI CA read omitted its public certificate or approved metadata")
	}
	f11AssertSafe(t, ca)
	certificate, err := client.ReadPKICertificate(context.Background(), f11Operator, f11Serial, vault.PKIOptions{Mount: f11Mount})
	digest := sha256.Sum256(f.leaf.Raw)
	if err != nil || certificate.Report.Serial != f11Serial || certificate.Report.SHA256 != hex.EncodeToString(digest[:]) || !bytes.Equal(certificate.PEM, f.leafPEM) || certificate.Report.TTLSeconds <= 0 || requests.Load() != 2 {
		t.Fatal("PKI certificate read omitted its validated fingerprint, serial or lifetime")
	}
	f11AssertSafe(t, certificate)
}

func TestPKIMountSerialAndLocalEmissionPreflightRejectBeforeHTTP(t *testing.T) {
	f := f11Fixture(t)
	var requests atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	for _, mount := range []string{"", "/pki", "pki/", "pki//team", "pki/../team", "pki?private-f11-value", "pki%20", strings.Repeat("x", 1025)} {
		if vault.ValidatePKIMount(mount) == nil {
			t.Error("unsafe PKI mount was accepted")
		}
		if _, err := client.ReadPKICA(context.Background(), "", vault.PKIOptions{Mount: mount}); err == nil {
			t.Error("PKI read contacted a mount that failed local validation")
		}
	}
	for _, serial := range []string{"", "00", "00:00", "../01", "01/23", "01?private-f11-value", "01%23", "01::23", "gg", strings.Repeat("ab", 33), "01\x00"} {
		if _, err := vault.ValidatePKISerial(serial); err == nil {
			t.Error("unsafe or unbounded PKI serial was accepted")
		}
		if _, err := client.ReadPKICertificate(context.Background(), "", serial, vault.PKIOptions{Mount: f11Mount}); err == nil {
			t.Error("PKI serial validation was bypassed by a read")
		}
	}
	if serial, err := vault.ValidatePKISerial("AB:CD"); err != nil || serial != "ab:cd" {
		t.Error("valid public serial did not acquire a deterministic canonical spelling")
	}
	for _, input := range []struct {
		role  string
		spec  pki.Spec
		roots []byte
	}{{"../private-role", f.spec, f.rootPEM}, {"application", pki.Spec{}, f.rootPEM}, {"application", f.spec, f.leafPEM}, {"application", f.spec, []byte("private-f11-invalid-roots")}} {
		if _, err := client.IssuePKICertificate(context.Background(), "", input.role, input.spec, input.roots, vault.PKIOptions{Mount: f11Mount}); err == nil {
			t.Error("invalid role, request or roots passed PKI issuance preflight")
		} else {
			f11AssertSafe(t, err)
		}
	}
	badCSR := append(append([]byte(nil), f.csrPEM...), f.keyPEM...)
	if _, err := client.SignPKICertificate(context.Background(), "", "application", f.spec, badCSR, f.rootPEM, vault.PKIOptions{Mount: f11Mount}); err == nil {
		t.Error("sign accepted a CSR input containing a private key")
	}
	if requests.Load() != 0 {
		t.Error("invalid local PKI inputs selected credentials or contacted Vault")
	}
}

func TestPKIIssueUsesExplicitBodyAndReturnsOneValidatedPrivateIdentity(t *testing.T) {
	f := f11Fixture(t)
	var writes atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writes.Add(1)
		accessRequest(t, r, f11Operator)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/"+f11Mount+"/issue/application" || r.URL.RawQuery != "" {
			t.Error("PKI issue used a different mount, role or transport method")
		}
		body := kvWriteBody(t, r)
		for key, expected := range map[string]any{"common_name": "app.fixture.test", "alt_names": "api.fixture.test,app.fixture.test", "ip_sans": "127.0.0.1", "ttl": json.Number("900"), "exclude_cn_from_sans": true, "format": "pem", "private_key_format": "pkcs8", "key_type": "ec", "key_bits": json.Number("256")} {
			if !reflect.DeepEqual(body[key], expected) {
				t.Error("PKI issue changed the explicit bounded request")
			}
		}
		kvReply(w, f.response(true))
	})
	issued, err := client.IssuePKICertificate(context.Background(), f11Operator, "application", f.spec, f.rootPEM, vault.PKIOptions{Mount: f11Mount})
	if err != nil || writes.Load() != 1 || issued.Report.Serial != f11Serial || issued.Report.IsCA || issued.Report.NotAfter.Unix() != f.leaf.NotAfter.Unix() || issued.Report.TTLSeconds <= 0 || issued.Report.TTLSeconds > 900 {
		t.Fatal("PKI issuance omitted its validated actual certificate lifetime")
	}
	inspected, err := pki.InspectCertificates(bytes.NewReader(issued.PEM), time.Now())
	if err != nil || !inspected.ContainsPrivateKey || len(inspected.Certificates) != 2 {
		t.Fatal("PKI issuance did not form one bounded identity bundle with a deduplicated chain")
	}
	matched, err := pki.MatchPrivateKey(bytes.NewReader(issued.PEM), bytes.NewReader(issued.PEM))
	if err != nil || !matched.Match {
		t.Error("the issued private key does not match the public leaf")
	}
	f11AssertSafe(t, issued)
}

func TestPKISignSendsOnlyTheValidatedCSRAndNeverItsPrivateKey(t *testing.T) {
	f := f11Fixture(t)
	var writes atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writes.Add(1)
		accessRequest(t, r, f11Operator)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/"+f11Mount+"/sign/application" {
			t.Error("PKI signing changed the selected mount, role or method")
		}
		body := kvWriteBody(t, r)
		if body["csr"] != string(f.csrPEM) || body["private_key"] != nil || body["ttl"] != json.Number("900") || body["format"] != "pem" {
			t.Error("PKI signing omitted its bounded CSR request or supplied a private key")
		}
		encoded, _ := json.Marshal(body)
		if bytes.Contains(encoded, []byte("PRIVATE KEY")) || bytes.Contains(encoded, bytes.TrimSpace(f.keyPEM)) {
			t.Error("PKI signing transmitted the local private key")
		}
		kvReply(w, f.response(false))
	})
	signed, err := client.SignPKICertificate(context.Background(), f11Operator, "application", f.spec, f.csrPEM, f.rootPEM, vault.PKIOptions{Mount: f11Mount})
	if err != nil || writes.Load() != 1 || signed.Report.PublicKeySHA256 == "" || signed.Report.NotAfter.Unix() != f.leaf.NotAfter.Unix() {
		t.Fatal("PKI signing did not validate the actual certificate and requested public key")
	}
	inspected, err := pki.InspectCertificates(bytes.NewReader(signed.PEM), time.Now())
	if err != nil || inspected.ContainsPrivateKey || len(inspected.Certificates) != 2 {
		t.Error("a signed public chain unexpectedly retained private key material")
	}
	f11AssertSafe(t, signed)
}

func TestPKIEmissionRejectsWrongSuccessfulResponsesAsUnconfirmedWithoutCompensation(t *testing.T) {
	f := f11Fixture(t)
	wrongKey := f11NewKey(t)
	wrongKeyDER, err := x509.MarshalPKCS8PrivateKey(wrongKey)
	if err != nil {
		t.Fatal("could not encode invalid response fixture")
	}
	_, wrongSAN := f11Leaf(t, f.root, f.rootKey, f.leafKey, func(c *x509.Certificate) {
		c.DNSNames = []string{"foreign.fixture.test"}
	})
	_, wrongSPKI := f11Leaf(t, f.root, f.rootKey, wrongKey, nil)
	otherRoot := f11Fixture(t)
	for _, test := range []struct {
		name string
		sign bool
		edit func(map[string]any)
	}{
		{"missing key", false, func(data map[string]any) { delete(data, "private_key") }},
		{"wrong key", false, func(data map[string]any) { data["private_key"] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: wrongKeyDER})) }},
		{"wrong expiration", false, func(data map[string]any) { data["expiration"] = f.leaf.NotAfter.Add(time.Hour).Unix() }},
		{"wrong serial", false, func(data map[string]any) { data["serial_number"] = "01:02:03" }},
		{"wrong SAN", false, func(data map[string]any) { data["certificate"] = string(wrongSAN) }},
		{"untrusted chain", false, func(data map[string]any) { data["certificate"], data["issuing_ca"], data["ca_chain"] = string(otherRoot.leafPEM), string(otherRoot.rootPEM), []string{string(otherRoot.rootPEM)} }},
		{"CA instead of leaf", false, func(data map[string]any) { data["certificate"] = string(f.rootPEM) }},
		{"malformed certificate", false, func(data map[string]any) { data["certificate"] = "private-f11-invalid-certificate" }},
		{"key returned by signing", true, func(data map[string]any) { data["private_key"] = string(f.keyPEM) }},
		{"wrong signed public key", true, func(data map[string]any) { data["certificate"] = string(wrongSPKI) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var writes atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				writes.Add(1)
				if strings.Contains(r.URL.Path, "/revoke") {
					t.Error("invalid emission triggered an unrequested revocation")
				}
				data := f.response(!test.sign)
				test.edit(data)
				kvReply(w, data)
			})
			var issued vault.PKICertificate
			var err error
			if test.sign {
				issued, err = client.SignPKICertificate(context.Background(), f11Operator, "application", f.spec, f.csrPEM, f.rootPEM, vault.PKIOptions{Mount: f11Mount})
			} else {
				issued, err = client.IssuePKICertificate(context.Background(), f11Operator, "application", f.spec, f.rootPEM, vault.PKIOptions{Mount: f11Mount})
			}
			if !errors.Is(err, vault.ErrAccessUnconfirmed) || len(issued.PEM) != 0 || writes.Load() != 1 {
				t.Error("invalid successful PKI response was retried, exposed or classified as a definite non-emission")
			}
			f11AssertSafe(t, issued)
			if err != nil {
				f11AssertSafe(t, err)
			}
		})
	}
}

func TestPKIRevocationBindsTheExactStoredFingerprintBeforeItsSingleMutation(t *testing.T) {
	f := f11Fixture(t)
	var reads, writes atomic.Int32
	revokedAt := time.Now().Unix()
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		accessRequest(t, r, f11Operator)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/"+f11Mount+"/cert/"+f11Serial:
			reads.Add(1)
			kvReply(w, map[string]any{"certificate": string(f.leafPEM), "revocation_time": 0})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/"+f11Mount+"/revoke":
			writes.Add(1)
			if !reflect.DeepEqual(kvWriteBody(t, r), map[string]any{"serial_number": f11Serial}) {
				t.Error("revocation changed its exact certificate serial or added force/prefix semantics")
			}
			kvReply(w, map[string]any{"revocation_time": revokedAt, "revocation_time_rfc3339": time.Unix(revokedAt, 0).UTC().Format(time.RFC3339)})
		default:
			t.Error("revocation used an unrelated endpoint")
			w.WriteHeader(http.StatusNotFound)
		}
	})
	report, err := client.RevokePKICertificate(context.Background(), f11Operator, f.leafPEM, vault.PKIOptions{Mount: f11Mount})
	if err != nil || !report.Revoked || report.Serial != f11Serial || report.RevocationTime != revokedAt || reads.Load() < 1 || writes.Load() != 1 {
		t.Fatal("exact certificate revocation was not bound and confirmed")
	}
	f11AssertSafe(t, report)
	if _, err := client.RevokePKICertificate(context.Background(), f11Operator, f.rootPEM, vault.PKIOptions{Mount: f11Mount}); err == nil || writes.Load() != 1 {
		t.Error("CA revocation was not rejected before HTTP mutation")
	}
	_, otherPEM := f11Leaf(t, f.root, f.rootKey, f11NewKey(t), nil)
	if _, err := client.RevokePKICertificate(context.Background(), f11Operator, otherPEM, vault.PKIOptions{Mount: f11Mount}); err == nil || writes.Load() != 1 {
		t.Error("a different certificate sharing the serial bypassed fingerprint binding")
	} else {
		f11AssertSafe(t, err)
	}
}

func TestPKIMutationsNeverRetryLostOrMalformedAcknowledgements(t *testing.T) {
	f := f11Fixture(t)
	for _, operation := range []string{"issue", "sign", "revoke"} {
		for _, outcome := range []string{"lost acknowledgement", "server error", "missing data"} {
			t.Run(operation+"/"+outcome, func(t *testing.T) {
				var writes atomic.Int32
				client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet {
						kvReply(w, map[string]any{"certificate": string(f.leafPEM), "revocation_time": 0})
						return
					}
					writes.Add(1)
					switch outcome {
					case "lost acknowledgement":
						loseKVMutationResponse(t, w)
					case "server error":
						w.WriteHeader(http.StatusServiceUnavailable)
						_, _ = io.WriteString(w, `{"errors":["private-f11-upstream-error"]}`)
					default:
						_, _ = io.WriteString(w, `{}`)
					}
				})
				var err error
				switch operation {
				case "issue":
					_, err = client.IssuePKICertificate(context.Background(), f11Operator, "application", f.spec, f.rootPEM, vault.PKIOptions{Mount: f11Mount})
				case "sign":
					_, err = client.SignPKICertificate(context.Background(), f11Operator, "application", f.spec, f.csrPEM, f.rootPEM, vault.PKIOptions{Mount: f11Mount})
				case "revoke":
					_, err = client.RevokePKICertificate(context.Background(), f11Operator, f.leafPEM, vault.PKIOptions{Mount: f11Mount})
				}
				if !errors.Is(err, vault.ErrAccessUnconfirmed) || writes.Load() != 1 {
					t.Error("uncertain PKI mutation was replayed or lost its uncertain outcome")
				}
				if err != nil {
					f11AssertSafe(t, err)
				}
			})
		}
	}
}

func TestPKIReadRejectsPrivateOrMalformedResponsesAndPreservesDeniedStatus(t *testing.T) {
	f := f11Fixture(t)
	for _, test := range []struct {
		status int
		body   string
		denied bool
	}{
		{http.StatusForbidden, `{"errors":["private-f11-denied"]}`, true},
		{http.StatusNotFound, `{"errors":[]}`, false},
		{http.StatusOK, `{"data":{"certificate":"private-f11-invalid"}}`, false},
		{http.StatusOK, "{}", false},
	} {
		client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(test.status)
			_, _ = io.WriteString(w, test.body)
		})
		value, err := client.ReadPKICertificate(context.Background(), f11Operator, f11Serial, vault.PKIOptions{Mount: f11Mount})
		if err == nil || len(value.PEM) != 0 || test.denied && !errors.Is(err, vault.ErrPermissionDenied) || test.status == http.StatusNotFound && !errors.Is(err, vault.ErrNotFound) {
			t.Error("invalid PKI read appeared successful or lost its denied/missing status")
		}
		f11AssertSafe(t, value)
		if err != nil {
			f11AssertSafe(t, err)
		}
	}
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		kvReply(w, map[string]any{"certificate": string(f.leafPEM), "private_key": string(f.keyPEM)})
	})
	if value, err := client.ReadPKICertificate(context.Background(), f11Operator, f11Serial, vault.PKIOptions{Mount: f11Mount}); err == nil || len(value.PEM) != 0 {
		t.Error("public certificate read accepted an unexpected private key")
	}
}
