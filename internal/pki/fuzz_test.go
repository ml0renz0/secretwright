package pki_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/pki"
)

type fuzzPKIInputs struct {
	root, leaf, key, csr []byte
	privateEncodings     [][]byte
}

// Ed25519 keeps the seed corpus inexpensive: no prime generation or repeated
// large RSA parsing is required to explore the valid paths of each parser.
func newFuzzPKIInputs(f *testing.F, now time.Time) fuzzPKIInputs {
	f.Helper()
	rootKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	leafKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	root := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PEM fuzz test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	if err != nil {
		f.Fatal("could not create the native PEM fuzz root")
	}
	leaf := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "app.fixture.test"},
		DNSNames:              []string{"app.fixture.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, leafKey.Public(), rootKey)
	if err != nil {
		f.Fatal("could not create the native PEM fuzz leaf")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		f.Fatal("could not encode the native PEM fuzz key")
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     leaf.Subject,
		DNSNames:    leaf.DNSNames,
		IPAddresses: leaf.IPAddresses,
	}, leafKey)
	if err != nil {
		f.Fatal("could not create the native PEM fuzz CSR")
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	escapedKey, err := json.Marshal(string(keyPEM))
	if err != nil {
		f.Fatal("could not prepare the private fuzz output markers")
	}
	return fuzzPKIInputs{
		root: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		leaf: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		key:  keyPEM,
		csr:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		privateEncodings: [][]byte{
			escapedKey[1 : len(escapedKey)-1],
			[]byte(base64.StdEncoding.EncodeToString(keyPEM)),
			[]byte(base64.StdEncoding.EncodeToString(keyDER)),
		},
	}
}

func checkFuzzPKIMetadata(t *testing.T, value any, inputs fuzzPKIInputs) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("PKI metadata was not JSON encodable")
	}
	for _, private := range inputs.privateEncodings {
		if bytes.Contains(body, private) {
			t.Fatal("PKI metadata exposed private key material")
		}
	}
}

func checkFuzzPKIError(t *testing.T, err error) {
	t.Helper()
	if err != nil && err != pki.ErrInvalidInput && err != pki.ErrVerification && err != pki.ErrKeyMismatch {
		t.Fatal("PKI validation returned a non-static diagnostic")
	}
}

func FuzzInspectPEM(f *testing.F) {
	now := time.Date(2030, time.January, 1, 12, 0, 0, 0, time.UTC)
	inputs := newFuzzPKIInputs(f, now)
	identity := append(append([]byte(nil), inputs.key...), inputs.leaf...)
	chain := append(append([]byte(nil), inputs.leaf...), inputs.root...)
	for _, seed := range [][]byte{
		nil,
		inputs.root,
		inputs.leaf,
		inputs.key,
		inputs.csr,
		identity,
		chain,
		[]byte("private-fuzz-marker"),
		[]byte("-----BEGIN CERTIFICATE-----\nprivate-fuzz-marker\n-----END CERTIFICATE-----\n"),
		[]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----\n"),
		[]byte("-----BEGIN CERTIFICATE REQUEST-----\nAA==\n-----END CERTIFICATE REQUEST-----\n"),
		append([]byte("private-fuzz-prefix\n"), inputs.leaf...),
		append(append([]byte(nil), inputs.csr...), []byte("private-fuzz-suffix\n")...),
		{0xff, 0x00},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		// Unit tests exercise the full 1 MiB file limit. A smaller fuzz budget
		// keeps repeated ASN.1 parsing and verification useful within CI time.
		if len(input) > 16*1024 {
			t.Skip()
		}
		original := append([]byte(nil), input...)
		certs, certErr := pki.InspectCertificates(bytes.NewReader(input), now)
		certsAgain, certErrAgain := pki.InspectCertificates(bytes.NewReader(input), now)
		checkFuzzPKIError(t, certErr)
		checkFuzzPKIError(t, certErrAgain)
		if certErr != certErrAgain || !reflect.DeepEqual(certs, certsAgain) {
			t.Fatal("certificate inspection changed for identical bytes and time")
		}
		if certErr != nil && !reflect.DeepEqual(certs, pki.CertificateReport{}) {
			t.Fatal("failed certificate inspection exposed partial metadata")
		}
		checkFuzzPKIMetadata(t, certs, inputs)

		csr, csrErr := pki.InspectCSR(bytes.NewReader(input))
		csrAgain, csrErrAgain := pki.InspectCSR(bytes.NewReader(input))
		checkFuzzPKIError(t, csrErr)
		checkFuzzPKIError(t, csrErrAgain)
		if csrErr != csrErrAgain || !reflect.DeepEqual(csr, csrAgain) {
			t.Fatal("CSR inspection changed for identical bytes")
		}
		if csrErr != nil && !reflect.DeepEqual(csr, pki.CSRReport{}) {
			t.Fatal("failed CSR inspection exposed partial metadata")
		}
		checkFuzzPKIMetadata(t, csr, inputs)

		key, keyErr := pki.InspectPrivateKey(bytes.NewReader(input))
		keyAgain, keyErrAgain := pki.InspectPrivateKey(bytes.NewReader(input))
		checkFuzzPKIError(t, keyErr)
		checkFuzzPKIError(t, keyErrAgain)
		if keyErr != keyErrAgain || !reflect.DeepEqual(key, keyAgain) {
			t.Fatal("key inspection changed for identical bytes")
		}
		if keyErr != nil && !reflect.DeepEqual(key, pki.KeyReport{}) {
			t.Fatal("failed key inspection exposed partial metadata")
		}
		checkFuzzPKIMetadata(t, key, inputs)

		match, matchErr := pki.MatchPrivateKey(bytes.NewReader(input), bytes.NewReader(inputs.key))
		matchAgain, matchErrAgain := pki.MatchPrivateKey(bytes.NewReader(input), bytes.NewReader(inputs.key))
		checkFuzzPKIError(t, matchErr)
		checkFuzzPKIError(t, matchErrAgain)
		if matchErr != matchErrAgain || match != matchAgain || matchErr != nil && match.Match || matchErr == nil && !match.Match {
			t.Fatal("key matching was inconsistent or accepted a failed proof")
		}
		checkFuzzPKIMetadata(t, match, inputs)

		options := pki.VerifyOptions{Time: now, Name: "app.fixture.test", Usage: "server-auth"}
		verified, verifyErr := pki.VerifyCertificate(bytes.NewReader(input), bytes.NewReader(inputs.root), nil, options)
		verifiedAgain, verifyErrAgain := pki.VerifyCertificate(bytes.NewReader(input), bytes.NewReader(inputs.root), nil, options)
		checkFuzzPKIError(t, verifyErr)
		checkFuzzPKIError(t, verifyErrAgain)
		if verifyErr != verifyErrAgain || verified != verifiedAgain || verified.RevocationChecked || verifyErr != nil && verified.Valid || verifyErr == nil && (!verified.Valid || verified.ChainLength < 1) {
			t.Fatal("certificate verification changed or claimed an unperformed check")
		}
		if verifyErr == pki.ErrVerification {
			switch verified.Reason {
			case "expired", "not_yet_valid", "name_mismatch", "unknown_authority", "incompatible_usage", "invalid_chain":
			default:
				t.Fatal("verification returned an unapproved failure reason")
			}
		}
		checkFuzzPKIMetadata(t, verified, inputs)
		if !bytes.Equal(input, original) {
			t.Fatal("PEM inspection modified its input bytes")
		}
	})
}
