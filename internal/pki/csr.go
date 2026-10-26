package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"reflect"
)

func matchesKey(spec KeySpec, report KeyReport) bool {
	if spec.Type != report.Algorithm {
		return false
	}
	if spec.Type == "ed25519" {
		return report.Bits == 256
	}
	return spec.Bits == report.Bits
}

func sameIdentity(spec Spec, common string, dns []string, ips []net.IP) bool {
	if common != spec.CommonName {
		return false
	}
	canonical := make([]string, 0, len(dns))
	for _, name := range dns {
		value, ok := canonicalDNS(name)
		if !ok {
			return false
		}
		canonical = append(canonical, value)
	}
	addresses, err := ipStrings(ips)
	return err == nil && reflect.DeepEqual(stringSet(canonical), spec.DNSNames) && reflect.DeepEqual(stringSet(addresses), spec.IPAddresses)
}

func ValidateCSR(spec Spec, body []byte) (CSRReport, error) {
	spec, err := ValidateSpec(spec)
	if err != nil {
		return CSRReport{}, err
	}
	request, err := parseRequest(body)
	if err != nil || !sameIdentity(spec, request.Subject.CommonName, request.DNSNames, request.IPAddresses) || len(request.EmailAddresses) != 0 || len(request.URIs) != 0 {
		return CSRReport{}, ErrInvalidInput
	}
	commonNameOID := asn1.ObjectIdentifier{2, 5, 4, 3}
	commonNames := 0
	for _, name := range request.Subject.Names {
		if !name.Type.Equal(commonNameOID) {
			return CSRReport{}, ErrInvalidInput
		}
		value, ok := name.Value.(string)
		if !ok || value != spec.CommonName || value == "" {
			return CSRReport{}, ErrInvalidInput
		}
		commonNames++
	}
	if commonNames > 1 || spec.CommonName != "" && commonNames != 1 {
		return CSRReport{}, ErrInvalidInput
	}
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	for _, extension := range request.Extensions {
		if !extension.Id.Equal(sanOID) {
			return CSRReport{}, ErrInvalidInput
		}
	}
	extensionRequestOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	for _, attribute := range request.Attributes {
		if !attribute.Type.Equal(extensionRequestOID) {
			return CSRReport{}, ErrInvalidInput
		}
	}
	report, err := InspectCSR(bytes.NewReader(body))
	if err != nil || !matchesKey(spec.Key, report.Key) {
		return CSRReport{}, ErrInvalidInput
	}
	return report, nil
}

func GenerateCSR(ctx context.Context, spec Spec) (GeneratedCSR, error) {
	if err := ctx.Err(); err != nil {
		return GeneratedCSR{}, err
	}
	spec, err := ValidateSpec(spec)
	if err != nil {
		return GeneratedCSR{}, err
	}
	var key crypto.Signer
	switch spec.Key.Type {
	case "ecdsa":
		curve := elliptic.P256()
		if spec.Key.Bits == 384 {
			curve = elliptic.P384()
		}
		key, err = ecdsa.GenerateKey(curve, rand.Reader)
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, spec.Key.Bits)
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		return GeneratedCSR{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return GeneratedCSR{}, err
	}
	request := &x509.CertificateRequest{Subject: pkix.Name{CommonName: spec.CommonName}, DNSNames: append([]string(nil), spec.DNSNames...)}
	for _, value := range spec.IPAddresses {
		request.IPAddresses = append(request.IPAddresses, net.ParseIP(value))
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, request, key)
	if err != nil {
		return GeneratedCSR{}, ErrInvalidInput
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return GeneratedCSR{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return GeneratedCSR{}, err
	}
	result := GeneratedCSR{CSRPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})}
	result.Report, err = ValidateCSR(spec, result.CSRPEM)
	if err != nil {
		return GeneratedCSR{}, err
	}
	return result, nil
}
