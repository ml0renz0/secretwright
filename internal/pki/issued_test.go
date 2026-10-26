package pki_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/pki"
)

func TestCSRPreflightRequiresExactRequestAndSafeExtensions(t *testing.T) {
	f := newCertificateFixture(t, "ecdsa")
	spec := fixtureSpec()
	if _, err := pki.ValidateCSR(spec, f.csrPEM); err != nil {
		t.Fatal("matching native CSR failed preflight")
	}
	for _, edit := range []func(*x509.CertificateRequest){
		func(c *x509.CertificateRequest) { c.Subject.CommonName = "foreign.example.test" },
		func(c *x509.CertificateRequest) { c.DNSNames = append(c.DNSNames, "foreign.example.test") },
		func(c *x509.CertificateRequest) { c.IPAddresses = append(c.IPAddresses, net.ParseIP("127.0.0.2")) },
		func(c *x509.CertificateRequest) { c.EmailAddresses = []string{"private-marker@example.test"} },
		func(c *x509.CertificateRequest) {
			c.URIs = []*url.URL{{Scheme: "spiffe", Host: "private-marker.example.test"}}
		},
		func(c *x509.CertificateRequest) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff}}}
		},
	} {
		_, err := pki.ValidateCSR(spec, fixtureCSR(t, f.leafKey, edit))
		assertPKIError(t, err)
	}
	wrongType := fixtureCSR(t, fixtureKey(t, "ed25519"), nil)
	_, err := pki.ValidateCSR(spec, wrongType)
	assertPKIError(t, err)
}

func TestIssuedCertificateMustMatchExplicitTrustRequestAndPossessedKey(t *testing.T) {
	f := newCertificateFixture(t, "ecdsa")
	spec := fixtureSpec()
	for _, mode := range []string{"issue", "sign"} {
		key, csr := f.keyPEM, []byte(nil)
		if mode == "sign" {
			key, csr = nil, f.csrPEM
		}
		leaf, err := pki.ValidateIssued(spec, f.leafPEM, fixtureChain(f), key, csr, f.rootPEM, fixtureTime)
		if err != nil || leaf.Serial != "01:ab" || leaf.TTLSeconds != 3600 || leaf.IsCA || leaf.PublicKeySHA256 == "" {
			t.Error("valid issued or signed certificate failed its native response checks")
		}
	}
	for _, test := range []struct {
		name string
		edit func(*x509.Certificate)
	}{
		{"wrong CN", func(c *x509.Certificate) { c.Subject.CommonName = "foreign.example.test" }},
		{"extra DNS", func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "foreign.example.test") }},
		{"missing DNS", func(c *x509.Certificate) { c.DNSNames = nil }},
		{"extra IP", func(c *x509.Certificate) { c.IPAddresses = append(c.IPAddresses, net.ParseIP("127.0.0.2")) }},
		{"extra email", func(c *x509.Certificate) { c.EmailAddresses = []string{"private-marker@example.test"} }},
		{"extra URI", func(c *x509.Certificate) {
			c.URIs = []*url.URL{{Scheme: "spiffe", Host: "private-marker.example.test"}}
		}},
		{"CA leaf", func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }},
		{"wrong EKU", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{"any EKU", func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageAny}
		}},
		{"longer TTL", func(c *x509.Certificate) { c.NotAfter = fixtureTime.Add(time.Hour + 6*time.Second) }},
		{"expired", func(c *x509.Certificate) {
			c.NotBefore = fixtureTime.Add(-2 * time.Hour)
			c.NotAfter = fixtureTime.Add(-time.Second)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			template := fixtureLeafTemplate()
			test.edit(template)
			_, certificate := fixtureCertificate(t, template, f.intermediate, f.leafKey.Public(), f.intermediateKey)
			_, err := pki.ValidateIssued(spec, certificate, fixtureChain(f), f.keyPEM, nil, f.rootPEM, fixtureTime)
			assertPKIError(t, err)
		})
	}
	wrong := newCertificateFixture(t, "ecdsa")
	for _, args := range []struct{ key, csr, roots []byte }{
		{wrong.keyPEM, nil, f.rootPEM},
		{nil, wrong.csrPEM, f.rootPEM},
		{f.keyPEM, nil, wrong.rootPEM},
		{nil, nil, f.rootPEM},
	} {
		_, err := pki.ValidateIssued(spec, f.leafPEM, fixtureChain(f), args.key, args.csr, args.roots, fixtureTime)
		assertPKIError(t, err)
	}
}
