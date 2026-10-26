package pki_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/pki"
)

func assertPKIError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("invalid PKI input unexpectedly succeeded")
	}
	if !errors.Is(err, pki.ErrInvalidInput) && !errors.Is(err, pki.ErrVerification) && !errors.Is(err, pki.ErrKeyMismatch) {
		t.Error("PKI operation returned an unapproved diagnostic")
	}
	if strings.Contains(err.Error(), "private-marker") || strings.Contains(err.Error(), "-----BEGIN") {
		t.Error("PKI error disclosed rejected data")
	}
}

func TestCertificateInspectionReportsPublicMetadataAndRealExpiry(t *testing.T) {
	f := newCertificateFixture(t, "ecdsa")
	full := append(append([]byte{}, f.leafPEM...), fixtureChain(f)...)
	report, err := pki.InspectCertificates(bytes.NewReader(full), fixtureTime)
	if err != nil || len(report.Certificates) != 3 || report.ContainsPrivateKey {
		t.Fatal("valid certificate chain could not be inspected")
	}
	leaf := report.Certificates[0]
	fingerprint := sha256.Sum256(f.leaf.Raw)
	if leaf.SHA256 != hex.EncodeToString(fingerprint[:]) || leaf.Serial != "01:ab" || leaf.TTLSeconds != 3600 || leaf.Validity != "valid" || leaf.IsCA || leaf.NotBefore.Location() != time.UTC || leaf.NotAfter.Location() != time.UTC || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "app.example.test" || len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0] != "127.0.0.1" || leaf.PublicKeySHA256 == "" || leaf.Key.PublicKeySHA256 != leaf.PublicKeySHA256 {
		t.Error("certificate inspection lost its native identity or validity metadata")
	}
	for _, check := range []struct{ at time.Time; status string }{{fixtureTime.Add(2*time.Hour), "expired"}, {fixtureTime.Add(-2*time.Minute), "not_yet_valid"}} {
		report, err := pki.InspectCertificates(bytes.NewReader(f.leafPEM), check.at)
		if err != nil || report.Certificates[0].Validity != check.status {
			t.Error("inspection confused temporal validity with chain trust")
		}
	}
	serial, err := pki.CertificateSerial(bytes.NewReader(full))
	if err != nil || serial != "01:ab" {
		t.Error("leaf serial was not canonical lower-case colon hex")
	}
	if _, err := pki.CertificateSerial(bytes.NewReader(f.rootPEM)); err == nil {
		t.Error("a CA certificate was accepted as a revocation target")
	}
}

func TestNativeKeyInspectionMatchingAndIdentityBundles(t *testing.T) {
	for _, kind := range []string{"ecdsa", "rsa", "ed25519"} {
		t.Run(kind, func(t *testing.T) {
			f := newCertificateFixture(t, kind)
			keyReport, err := pki.InspectPrivateKey(bytes.NewReader(f.keyPEM))
			if err != nil || keyReport.PublicKeySHA256 == "" || keyReport.Algorithm == "" {
				t.Fatal("native private key could not be inspected")
			}
			match, err := pki.MatchPrivateKey(bytes.NewReader(f.leafPEM), bytes.NewReader(f.keyPEM))
			if err != nil || !match.Match {
				t.Error("matching public keys were not recognized")
			}
			wrong := fixturePrivateKey(t, fixtureKey(t, kind))
			match, err = pki.MatchPrivateKey(bytes.NewReader(f.leafPEM), bytes.NewReader(wrong))
			if !errors.Is(err, pki.ErrKeyMismatch) || match.Match {
				t.Error("different private key matched the supplied certificate")
			}
			identity := append(append(append([]byte{}, f.keyPEM...), f.leafPEM...), fixtureChain(f)...)
			report, err := pki.InspectCertificates(bytes.NewReader(identity), fixtureTime)
			if err != nil || !report.ContainsPrivateKey || len(report.Certificates) != 3 {
				t.Error("matching private identity bundle was not recognized")
			}
			bundledKey, err := pki.InspectPrivateKey(bytes.NewReader(identity))
			if err != nil || bundledKey.PublicKeySHA256 != keyReport.PublicKeySHA256 {
				t.Error("key inspection could not handle a matching identity bundle")
			}
			encoded, err := json.Marshal(report)
			if err != nil || bytes.Contains(encoded, []byte("-----BEGIN")) || bytes.Contains(encoded, f.keyPEM) || bytes.Contains(encoded, []byte("private_key")) && !bytes.Contains(encoded, []byte("contains_private_key")) {
				t.Error("identity metadata serialized private credential material")
			}
			mismatched := append(append([]byte{}, wrong...), f.leafPEM...)
			if _, err := pki.InspectCertificates(bytes.NewReader(mismatched), fixtureTime); err == nil {
				t.Error("identity bundle with an unrelated private key was accepted")
			}
			var legacy []byte
			switch key := f.leafKey.(type) {
			case *rsa.PrivateKey:
				legacy = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
			case *ecdsa.PrivateKey:
				der, err := x509.MarshalECPrivateKey(key)
				if err != nil {
					t.Fatal("could not encode SEC1 fixture")
				}
				legacy = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
			}
			if legacy != nil {
				legacyReport, err := pki.InspectPrivateKey(bytes.NewReader(legacy))
				if err != nil || legacyReport.PublicKeySHA256 != keyReport.PublicKeySHA256 {
					t.Error("PKCS1 or SEC1 form changed the public identity of a private key")
				}
			}
		})
	}
}

func TestVerificationUsesOnlyExplicitTrustNameUsageAndTime(t *testing.T) {
	f := newCertificateFixture(t, "ecdsa")
	for _, name := range []string{"app.example.test", "127.0.0.1"} {
		report, err := pki.VerifyCertificate(bytes.NewReader(f.leafPEM), bytes.NewReader(f.rootPEM), bytes.NewReader(f.intermediatePEM), pki.VerifyOptions{Time: fixtureTime, Name: name, Usage: "server-auth"})
		if err != nil || !report.Valid || report.ChainLength != 3 || report.RevocationChecked {
			t.Error("explicit root, intermediate and SAN did not verify natively")
		}
	}
	wrongRoot := newCertificateFixture(t, "ecdsa")
	for _, test := range []struct{ name, usage, reason string; at time.Time; roots, intermediates []byte }{
		{"wrong.example.test", "server-auth", "name_mismatch", fixtureTime, f.rootPEM, f.intermediatePEM},
		{"app.example.test", "client-auth", "incompatible_usage", fixtureTime, f.rootPEM, f.intermediatePEM},
		{"app.example.test", "server-auth", "expired", fixtureTime.Add(2*time.Hour), f.rootPEM, f.intermediatePEM},
		{"app.example.test", "server-auth", "not_yet_valid", fixtureTime.Add(-2*time.Minute), f.rootPEM, f.intermediatePEM},
		{"app.example.test", "server-auth", "unknown_authority", fixtureTime, wrongRoot.rootPEM, f.intermediatePEM},
		{"app.example.test", "server-auth", "unknown_authority", fixtureTime, f.rootPEM, nil},
	} {
		report, err := pki.VerifyCertificate(bytes.NewReader(f.leafPEM), bytes.NewReader(test.roots), bytes.NewReader(test.intermediates), pki.VerifyOptions{Time: test.at, Name: test.name, Usage: test.usage})
		if !errors.Is(err, pki.ErrVerification) || report.Valid || report.Reason != test.reason || report.RevocationChecked {
			t.Error("negative verification did not preserve its approved reason without claiming revocation checking")
		}
	}
	// A root sent as part of an untrusted chain must never become a trust anchor.
	full := append(append([]byte{}, f.leafPEM...), fixtureChain(f)...)
	if report, err := pki.VerifyCertificate(bytes.NewReader(full), bytes.NewReader(wrongRoot.rootPEM), nil, pki.VerifyOptions{Time: fixtureTime, Name: "app.example.test"}); err == nil || report.Valid {
		t.Error("a certificate inside the untrusted chain was silently trusted")
	}
	if pki.ValidateRoots(f.rootPEM) != nil {
		t.Error("explicit CA root was rejected")
	}
	for _, roots := range [][]byte{nil, f.leafPEM, append(append([]byte{}, f.rootPEM...), f.keyPEM...)} {
		assertPKIError(t, pki.ValidateRoots(roots))
	}
}

func TestCSRInspectionChecksItsCryptographicSignature(t *testing.T) {
	f := newCertificateFixture(t, "ecdsa")
	report, err := pki.InspectCSR(bytes.NewReader(f.csrPEM))
	if err != nil || !report.SignatureValid || report.CommonName != "app.example.test" || report.PublicKeySHA256 == "" || len(report.DNSNames) != 1 || len(report.IPAddresses) != 1 {
		t.Fatal("valid native CSR could not be inspected")
	}
	block, _ := pem.Decode(f.csrPEM)
	block.Bytes[len(block.Bytes)-1] ^= 1
	if _, err := pki.InspectCSR(bytes.NewReader(pem.EncodeToMemory(block))); err == nil {
		t.Error("a CSR with a forged signature was inspected as valid")
	}
}

type failedPEMReader struct{}

func (failedPEMReader) Read([]byte) (int, error) { return 0, errors.New("private-marker-reader") }

func TestStrictPEMProfilesRejectAmbiguousEncryptedOrOversizedInputs(t *testing.T) {
	f := newCertificateFixture(t, "ecdsa")
	for _, bad := range [][]byte{
		nil, []byte("private-marker"), f.leaf.Raw,
		append([]byte("private-marker\n"), f.leafPEM...),
		append(append([]byte{}, f.leafPEM...), []byte("private-marker\n")...),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Private-Marker": "rejected"}, Bytes: f.leaf.Raw}),
		append(append(append([]byte{}, f.keyPEM...), f.keyPEM...), f.leafPEM...),
		append(append([]byte{}, f.leafPEM...), f.csrPEM...),
		bytes.Repeat(f.leafPEM, 33), bytes.Repeat([]byte("x"), (1<<20)+1),
		pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("private-marker")}),
	} {
		_, err := pki.InspectCertificates(bytes.NewReader(bad), fixtureTime)
		assertPKIError(t, err)
	}
	for _, bad := range [][]byte{nil, f.leafPEM, append(append([]byte{}, f.keyPEM...), f.keyPEM...), bytes.Repeat([]byte("x"), (64<<10)+1), pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("private-marker")})} {
		_, err := pki.InspectPrivateKey(bytes.NewReader(bad))
		assertPKIError(t, err)
	}
	for _, bad := range [][]byte{nil, f.leafPEM, append(append([]byte{}, f.csrPEM...), f.keyPEM...), append(append([]byte{}, f.csrPEM...), f.csrPEM...), bytes.Repeat([]byte("x"), (1<<20)+1)} {
		_, err := pki.InspectCSR(bytes.NewReader(bad))
		assertPKIError(t, err)
	}
	for _, reader := range []io.Reader{nil, failedPEMReader{}} {
		_, err := pki.InspectCertificates(reader, fixtureTime)
		assertPKIError(t, err)
	}
}
