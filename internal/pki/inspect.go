package pki

import (
	"crypto/x509"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"time"
)

func serialNumber(certificate *x509.Certificate) (string, error) {
	if certificate.SerialNumber == nil || certificate.SerialNumber.Sign() <= 0 || len(certificate.SerialNumber.Bytes()) > 32 {
		return "", ErrInvalidInput
	}
	raw := certificate.SerialNumber.Bytes()
	parts := make([]string, len(raw))
	for index, value := range raw {
		parts[index] = hex.EncodeToString([]byte{value})
	}
	return strings.Join(parts, ":"), nil
}

func ipStrings(addresses []net.IP) ([]string, error) {
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if address.To16() == nil {
			return nil, ErrInvalidInput
		}
		result = append(result, address.String())
	}
	return result, nil
}

func copyMetadata(values []string, limit int) ([]string, error) {
	if len(values) > 256 {
		return nil, ErrInvalidInput
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !validMetadata(value, limit) {
			return nil, ErrInvalidInput
		}
		result = append(result, value)
	}
	return result, nil
}

func certificateInfo(certificate *x509.Certificate, now time.Time) (CertificateInfo, error) {
	if now.IsZero() {
		now = time.Now()
	}
	key, err := publicKeyReport(certificate.PublicKey)
	if err != nil {
		return CertificateInfo{}, err
	}
	serial, err := serialNumber(certificate)
	if err != nil || !validMetadata(certificate.Subject.String(), 4096) || !validMetadata(certificate.Issuer.String(), 4096) || len(certificate.DNSNames)+len(certificate.IPAddresses)+len(certificate.EmailAddresses)+len(certificate.URIs) > 256 {
		return CertificateInfo{}, ErrInvalidInput
	}
	dns, err := copyMetadata(certificate.DNSNames, 253)
	if err != nil {
		return CertificateInfo{}, err
	}
	ips, err := ipStrings(certificate.IPAddresses)
	if err != nil {
		return CertificateInfo{}, err
	}
	emails, err := copyMetadata(certificate.EmailAddresses, 320)
	if err != nil {
		return CertificateInfo{}, err
	}
	uris := make([]string, 0, len(certificate.URIs))
	for _, uri := range certificate.URIs {
		if uri == nil || !validMetadata(uri.String(), 2048) {
			return CertificateInfo{}, ErrInvalidInput
		}
		uris = append(uris, uri.String())
	}
	validity := "valid"
	if now.Before(certificate.NotBefore) {
		validity = "not_yet_valid"
	} else if now.After(certificate.NotAfter) {
		validity = "expired"
	}
	usages := make([]string, 0)
	for _, usage := range []struct {
		bit  x509.KeyUsage
		name string
	}{{x509.KeyUsageDigitalSignature, "digital-signature"}, {x509.KeyUsageKeyEncipherment, "key-encipherment"}, {x509.KeyUsageKeyAgreement, "key-agreement"}, {x509.KeyUsageCertSign, "cert-sign"}, {x509.KeyUsageCRLSign, "crl-sign"}} {
		if certificate.KeyUsage&usage.bit != 0 {
			usages = append(usages, usage.name)
		}
	}
	for _, usage := range certificate.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "server-auth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "client-auth")
		case x509.ExtKeyUsageAny:
			usages = append(usages, "any")
		}
	}
	return CertificateInfo{Subject: certificate.Subject.String(), Issuer: certificate.Issuer.String(), Serial: serial, SHA256: fingerprint(certificate.Raw), PublicKeySHA256: key.PublicKeySHA256, DNSNames: dns, IPAddresses: ips, EmailAddresses: emails, URIs: uris, NotBefore: certificate.NotBefore.UTC(), NotAfter: certificate.NotAfter.UTC(), TTLSeconds: certificate.NotAfter.Unix() - now.Unix(), Validity: validity, IsCA: certificate.IsCA, Key: key, Usages: usages}, nil
}

func InspectCertificates(input io.Reader, now time.Time) (CertificateReport, error) {
	body, err := boundedInput(input)
	if err != nil {
		return CertificateReport{}, err
	}
	document, err := parseCertificates(body, true)
	if err != nil {
		return CertificateReport{}, err
	}
	report := CertificateReport{Certificates: make([]CertificateInfo, 0, len(document.certificates)), ContainsPrivateKey: document.key != nil}
	for _, certificate := range document.certificates {
		info, err := certificateInfo(certificate, now)
		if err != nil {
			return CertificateReport{}, err
		}
		report.Certificates = append(report.Certificates, info)
	}
	return report, nil
}

func InspectPrivateKey(input io.Reader) (KeyReport, error) {
	body, err := boundedInput(input)
	if err != nil {
		return KeyReport{}, err
	}
	document, err := decodePEM(body)
	if err != nil || document.key == nil || document.request != nil {
		return KeyReport{}, ErrInvalidInput
	}
	return publicKeyReport(document.key.Public())
}

func InspectCSR(input io.Reader) (CSRReport, error) {
	body, err := boundedInput(input)
	if err != nil {
		return CSRReport{}, err
	}
	request, err := parseRequest(body)
	if err != nil {
		return CSRReport{}, err
	}
	key, err := publicKeyReport(request.PublicKey)
	if err != nil || !validMetadata(request.Subject.String(), 4096) || !validMetadata(request.Subject.CommonName, 253) || len(request.DNSNames)+len(request.IPAddresses)+len(request.EmailAddresses)+len(request.URIs) > 256 {
		return CSRReport{}, ErrInvalidInput
	}
	dns, err := copyMetadata(request.DNSNames, 253)
	if err != nil {
		return CSRReport{}, err
	}
	ips, err := ipStrings(request.IPAddresses)
	if err != nil {
		return CSRReport{}, err
	}
	return CSRReport{Subject: request.Subject.String(), CommonName: request.Subject.CommonName, PublicKeySHA256: key.PublicKeySHA256, DNSNames: dns, IPAddresses: ips, SignatureValid: true, Key: key}, nil
}

func CertificateSerial(input io.Reader) (string, error) {
	body, err := boundedInput(input)
	if err != nil {
		return "", err
	}
	document, err := parseCertificates(body, true)
	if err != nil || document.certificates[0].IsCA {
		return "", ErrInvalidInput
	}
	for _, certificate := range document.certificates[1:] {
		if !certificate.IsCA {
			return "", ErrInvalidInput
		}
	}
	return serialNumber(document.certificates[0])
}
