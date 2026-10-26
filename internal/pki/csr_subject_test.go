package pki_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/ml0renz0/secretwright/internal/pki"
)

func csrRawCommonNames(t *testing.T, names ...string) []byte {
	t.Helper()
	sequence := make(pkix.RDNSequence, 0, len(names))
	for _, name := range names {
		sequence = append(sequence, pkix.RelativeDistinguishedNameSET{{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
			Value: name,
		}})
	}
	body, err := asn1.Marshal(sequence)
	if err != nil {
		t.Fatal("could not encode the native CSR subject fixture")
	}
	return body
}

func TestCSRSubjectRequiresExactlyTheRequestedCommonName(t *testing.T) {
	key := fixtureKey(t, "ecdsa")
	for _, test := range []struct {
		name   string
		common string
		edit   func(*x509.CertificateRequest)
	}{
		{
			name:   "different CN before the matching CN",
			common: "app.example.test",
			edit: func(request *x509.CertificateRequest) {
				request.RawSubject = csrRawCommonNames(t, "foreign.example.test", "app.example.test")
			},
		},
		{
			name:   "matching CN repeated twice",
			common: "app.example.test",
			edit: func(request *x509.CertificateRequest) {
				request.RawSubject = csrRawCommonNames(t, "app.example.test", "app.example.test")
			},
		},
		{
			name:   "unrequested organizational unit",
			common: "app.example.test",
			edit: func(request *x509.CertificateRequest) {
				request.Subject.OrganizationalUnit = []string{"private-marker-unrequested-unit"}
			},
		},
		{
			name:   "explicit empty CN instead of absent CN",
			common: "",
			edit: func(request *x509.CertificateRequest) {
				request.RawSubject = csrRawCommonNames(t, "")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := fixtureSpec()
			spec.CommonName = test.common
			csr := fixtureCSR(t, key, test.edit)
			block, _ := pem.Decode(csr)
			if block == nil {
				t.Fatal("could not decode the signed CSR subject fixture")
			}
			parsed, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil || parsed.CheckSignature() != nil || parsed.Subject.CommonName != spec.CommonName {
				t.Fatal("the native CSR fixture did not have a valid signature and matching projected CN")
			}
			report, err := pki.ValidateCSR(spec, csr)
			if !errors.Is(err, pki.ErrInvalidInput) || report.SignatureValid {
				t.Error("CSR preflight accepted additional or ambiguous subject attributes")
			}
			assertPKIError(t, err)
		})
	}
	for _, common := range []string{"app.example.test", ""} {
		spec := fixtureSpec()
		spec.CommonName = common
		csr := fixtureCSR(t, key, func(request *x509.CertificateRequest) {
			request.Subject = pkix.Name{CommonName: common}
		})
		if _, err := pki.ValidateCSR(spec, csr); err != nil {
			t.Error("unambiguous requested CSR subject was rejected")
		}
	}
}
