package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type pkiIOFixture struct {
	certificate []byte
	key         []byte
	csr         []byte
	bundle      []byte
}

func newPKIIOFixture(t *testing.T) pkiIOFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("could not generate native PKI file fixture")
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(29),
		Subject:      pkix.Name{CommonName: "files.fixture.test"},
		DNSNames:     []string{"files.fixture.test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("could not sign native PKI file fixture")
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("could not encode native private key fixture")
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  template.Subject,
		DNSNames: template.DNSNames,
	}, key)
	if err != nil {
		t.Fatal("could not sign native CSR file fixture")
	}
	fixture := pkiIOFixture{
		certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:         pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
		csr:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
	}
	fixture.bundle = append(append([]byte(nil), fixture.key...), fixture.certificate...)
	return fixture
}

func pkiIOFile(t *testing.T, body []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private-pki-file-marker")
	if os.WriteFile(path, body, 0o600) != nil || os.Chmod(path, mode) != nil {
		t.Fatal("could not create PKI file fixture")
	}
	return path
}

func pkiIOError(t *testing.T, err error, forbidden ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("unsafe PKI file operation succeeded")
	}
	for _, marker := range append(forbidden, "private-pki-file-marker", "BEGIN PRIVATE KEY", "BEGIN CERTIFICATE", "private-file-body-marker") {
		if marker != "" && strings.Contains(err.Error(), marker) {
			t.Error("PKI file error exposed a filename or cryptographic material")
		}
	}
}

func TestPKIRawReaderPreservesExactBytesAndAppliesExplicitBounds(t *testing.T) {
	body := []byte("private-file-body-marker\n\x00\xff")
	path := pkiIOFile(t, body, 0o600)
	got, err := readPKIFile(path, true, int64(len(body)))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("bounded PKI reader altered file bytes")
	}
	got[0] = 'x'
	again, err := readPKIFile(path, true, int64(len(body)))
	if err != nil || !bytes.Equal(again, body) {
		t.Error("mutating returned bytes changed the file or a shared read buffer")
	}
	for _, limit := range []int64{-1, 0, int64(len(body) - 1)} {
		got, err := readPKIFile(path, true, limit)
		pkiIOError(t, err, path)
		if len(got) != 0 {
			t.Error("a failed PKI read returned partial private bytes")
		}
	}
	if os.Chmod(path, 0o644) != nil {
		t.Fatal("could not make public file fixture")
	}
	if got, err := readPKIFile(path, false, int64(len(body))); err != nil || !bytes.Equal(got, body) {
		t.Error("public PKI data unexpectedly required private file permissions")
	}
}

func TestPKIPrivateReaderRejectsModesSymlinksAndNonregularInputs(t *testing.T) {
	for _, mode := range []os.FileMode{0o400, 0o640, 0o644, 0o660, 0o700, 0o777, 0o600 | os.ModeSetuid, 0o600 | os.ModeSetgid, 0o600 | os.ModeSticky} {
		path := pkiIOFile(t, []byte("private-file-body-marker"), mode)
		got, err := readPKIFile(path, true, 1024)
		pkiIOError(t, err, path)
		if len(got) != 0 {
			t.Error("unprotected PKI file returned private bytes")
		}
	}
	regular := pkiIOFile(t, []byte("private-file-body-marker"), 0o600)
	link := filepath.Join(t.TempDir(), "private-pki-file-marker-link")
	if os.Symlink(regular, link) != nil {
		t.Fatal("could not create PKI file symlink")
	}
	broken := filepath.Join(t.TempDir(), "private-pki-file-marker-dangling")
	if os.Symlink(regular+".missing", broken) != nil {
		t.Fatal("could not create dangling PKI file symlink")
	}
	for _, path := range []string{"", "-", regular + ".missing", t.TempDir(), link, broken} {
		for _, private := range []bool{false, true} {
			got, err := readPKIFile(path, private, 1024)
			pkiIOError(t, err, path)
			if len(got) != 0 {
				t.Error("nonregular PKI input returned file contents")
			}
		}
	}
}

func TestPKICertificateReaderDistinguishesPublicCertificatesFromPrivateIdentities(t *testing.T) {
	fixture := newPKIIOFixture(t)
	for _, mode := range []os.FileMode{0o600, 0o644} {
		path := pkiIOFile(t, fixture.certificate, mode)
		body, err := readPKICertificates(path)
		if err != nil || !bytes.Equal(body, fixture.certificate) {
			t.Error("valid public certificate could not be read for offline inspection")
		}
	}
	path := pkiIOFile(t, fixture.bundle, 0o600)
	if body, err := readPKICertificates(path); err != nil || !bytes.Equal(body, fixture.bundle) {
		t.Fatal("private matching identity bundle was rejected")
	}
	if os.Chmod(path, 0o644) != nil {
		t.Fatal("could not weaken identity fixture permissions")
	}
	body, err := readPKICertificates(path)
	pkiIOError(t, err, path)
	if len(body) != 0 {
		t.Error("certificate inspection exposed an unprotected identity key")
	}
	other := newPKIIOFixture(t)
	for _, invalid := range [][]byte{
		fixture.key,
		fixture.csr,
		append(append([]byte(nil), other.key...), fixture.certificate...),
		append(append([]byte(nil), fixture.certificate...), []byte("private-file-body-marker")...),
		bytes.Repeat([]byte("x"), (1<<20)+1),
	} {
		path := pkiIOFile(t, invalid, 0o600)
		body, err := readPKICertificates(path)
		pkiIOError(t, err, path)
		if len(body) != 0 {
			t.Error("invalid certificate file returned a partial cryptographic bundle")
		}
	}
}

func TestPKIKeyAndCSRReadersApplyTheirDistinctProfiles(t *testing.T) {
	fixture := newPKIIOFixture(t)
	for _, valid := range [][]byte{fixture.key, fixture.bundle} {
		path := pkiIOFile(t, valid, 0o600)
		if body, err := readPKIKey(path); err != nil || !bytes.Equal(body, valid) {
			t.Error("private key or matching identity bundle was rejected")
		}
		if os.Chmod(path, 0o644) != nil {
			t.Fatal("could not weaken key fixture permissions")
		}
		body, err := readPKIKey(path)
		pkiIOError(t, err, path)
		if len(body) != 0 {
			t.Error("key inspection returned unprotected private material")
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o644} {
		path := pkiIOFile(t, fixture.csr, mode)
		if body, err := readPKICSR(path); err != nil || !bytes.Equal(body, fixture.csr) {
			t.Error("public signed CSR was rejected")
		}
	}
	for _, body := range [][]byte{fixture.key, fixture.certificate, append(append([]byte(nil), fixture.key...), fixture.csr...)} {
		path := pkiIOFile(t, body, 0o600)
		got, err := readPKICSR(path)
		pkiIOError(t, err, path)
		if len(got) != 0 {
			t.Error("CSR reader could allow a private key to reach the signing request")
		}
	}
}

func TestPKIIdentityOutputReusesExclusivePrivateCredentialPublication(t *testing.T) {
	fixture := newPKIIOFixture(t)
	path := filepath.Join(t.TempDir(), "private-pki-file-marker-identity.pem")
	output, err := reserveCredentialOutput(path)
	if err != nil {
		t.Fatal("could not reserve private identity output")
	}
	defer output.abort()
	if _, err := reserveCredentialOutput(path); err == nil {
		t.Error("a private identity reservation could be overwritten")
	}
	if err := output.commit(func(writer io.Writer) error {
		n, err := writer.Write(fixture.bundle)
		if err != nil {
			return err
		}
		if n != len(fixture.bundle) {
			return io.ErrShortWrite
		}
		return nil
	}); err != nil {
		t.Fatal("could not publish private identity fixture")
	}
	output.abort()
	body, err := os.ReadFile(path)
	info, statErr := os.Lstat(path)
	if err != nil || statErr != nil || info.Mode().Perm() != 0o600 || !bytes.Equal(body, fixture.bundle) {
		t.Error("identity publication changed bytes, permissions or retained output")
	}
}
