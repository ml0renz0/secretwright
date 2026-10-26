package pki_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/pki"
)

var fixtureTime = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

type certificateFixture struct {
	root, intermediate, leaf                          *x509.Certificate
	rootKey, intermediateKey, leafKey                 crypto.Signer
	rootPEM, intermediatePEM, leafPEM, keyPEM, csrPEM []byte
}

func fixtureKey(t *testing.T, kind string) crypto.Signer {
	t.Helper()
	switch kind {
	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal("could not generate RSA fixture")
		}
		return key
	case "ed25519":
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal("could not generate Ed25519 fixture")
		}
		return key
	default:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal("could not generate ECDSA fixture")
		}
		return key
	}
}

func fixtureCertificate(t *testing.T, template, parent *x509.Certificate, public crypto.PublicKey, signer crypto.Signer) (*x509.Certificate, []byte) {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	if err != nil {
		t.Fatal("could not sign certificate fixture")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("could not parse certificate fixture")
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func fixturePrivateKey(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("could not encode private fixture")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func fixtureCSR(t *testing.T, key crypto.Signer, edit func(*x509.CertificateRequest)) []byte {
	t.Helper()
	request := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "app.example.test"}, DNSNames: []string{"app.example.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	if edit != nil {
		edit(request)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, request, key)
	if err != nil {
		t.Fatal("could not sign CSR fixture")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func fixtureLeafTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(0x01ab),
		Subject:               pkix.Name{CommonName: "app.example.test"},
		DNSNames:              []string{"app.example.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             fixtureTime.Add(-time.Minute),
		NotAfter:              fixtureTime.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
}

func newCertificateFixture(t *testing.T, kind string) certificateFixture {
	t.Helper()
	f := certificateFixture{rootKey: fixtureKey(t, "ecdsa"), intermediateKey: fixtureKey(t, "ecdsa"), leafKey: fixtureKey(t, kind)}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fixture Root"}, NotBefore: fixtureTime.Add(-time.Hour), NotAfter: fixtureTime.Add(365 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 1}
	f.root, f.rootPEM = fixtureCertificate(t, root, root, f.rootKey.Public(), f.rootKey)
	intermediate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Fixture Intermediate"}, NotBefore: fixtureTime.Add(-time.Hour), NotAfter: fixtureTime.Add(30 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 0, MaxPathLenZero: true}
	f.intermediate, f.intermediatePEM = fixtureCertificate(t, intermediate, f.root, f.intermediateKey.Public(), f.rootKey)
	f.leaf, f.leafPEM = fixtureCertificate(t, fixtureLeafTemplate(), f.intermediate, f.leafKey.Public(), f.intermediateKey)
	f.keyPEM = fixturePrivateKey(t, f.leafKey)
	f.csrPEM = fixtureCSR(t, f.leafKey, nil)
	return f
}

func fixtureSpec() pki.Spec {
	return pki.Spec{APIVersion: "secretwright/pki/v1", Name: "application", CommonName: "app.example.test", DNSNames: []string{"app.example.test"}, IPAddresses: []string{"127.0.0.1"}, TTL: "1h", Usage: "server-auth", Key: pki.KeySpec{Type: "ecdsa", Bits: 256}}
}

func fixtureChain(f certificateFixture) []byte {
	return append(append([]byte{}, f.intermediatePEM...), f.rootPEM...)
}
