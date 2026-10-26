package pki_test

import (
	"bytes"
	"crypto/x509"
	"testing"

	"github.com/ml0renz0/secretwright/internal/pki"
)

func TestMalformedPEMPrefixCannotBeSkippedToFindAValidBlock(t *testing.T) {
	f := newCertificateFixture(t, "ecdsa")
	for _, prefix := range []string{
		"-----BEGIN CERTIFICATE-----\ninvalid-base64\n",
		"-----BEGIN CERTIFICATE-----\ninvalid-base64\n-----END CERTIFICATE-----\n",
		"-----BEGIN PRIVATE KEY-----\ninvalid-base64\n",
		"-----BEGIN CERTIFICATE-----\n-----END PRIVATE KEY-----\n",
	} {
		body := append([]byte(prefix), f.leafPEM...)
		if _, err := pki.InspectCertificates(bytes.NewReader(body), fixtureTime); err == nil {
			t.Error("parser silently discarded a malformed PEM block before the certificate")
		}
	}
}

func TestIssuedTLSProfileRequiresTheRequestedKeyAndDigitalSignatureUsage(t *testing.T) {
	f := newCertificateFixture(t, "ecdsa")
	spec := fixtureSpec()
	wrongKey := spec
	wrongKey.Key = pki.KeySpec{Type: "ecdsa", Bits: 384}
	if _, err := pki.ValidateIssued(wrongKey, f.leafPEM, fixtureChain(f), f.keyPEM, nil, f.rootPEM, fixtureTime); err == nil {
		t.Error("matching key and certificate bypassed the requested key parameters")
	}
	leaf := fixtureLeafTemplate()
	leaf.KeyUsage = x509.KeyUsageKeyEncipherment
	_, encoded := fixtureCertificate(t, leaf, f.intermediate, f.leafKey.Public(), f.intermediateKey)
	if _, err := pki.ValidateIssued(spec, encoded, fixtureChain(f), f.keyPEM, nil, f.rootPEM, fixtureTime); err == nil {
		t.Error("issued TLS certificate omitted its digital signature key usage")
	}
}
