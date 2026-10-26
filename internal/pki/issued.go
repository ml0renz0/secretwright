package pki

import (
	"bytes"
	"crypto/x509"
	"time"
)

// ValidateIssued applies the requested issuance profile before any credential
// can be published. Returned issuer certificates never become trusted roots.
func ValidateIssued(spec Spec, certificate, chain, key, csr, roots []byte, now time.Time) (CertificateInfo, error) {
	spec, err := ValidateSpec(spec)
	if err != nil || ValidateRoots(roots) != nil {
		return CertificateInfo{}, ErrInvalidInput
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	document, err := parseCertificates(certificate, false)
	if err != nil || len(document.certificates) != 1 {
		return CertificateInfo{}, ErrInvalidInput
	}
	leaf := document.certificates[0]
	if leaf.IsCA || !sameIdentity(spec, leaf.Subject.CommonName, leaf.DNSNames, leaf.IPAddresses) || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || leaf.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return CertificateInfo{}, ErrInvalidInput
	}
	usage := x509.ExtKeyUsageServerAuth
	if spec.Usage == "client-auth" {
		usage = x509.ExtKeyUsageClientAuth
	}
	found := false
	for _, value := range leaf.ExtKeyUsage {
		if value == x509.ExtKeyUsageAny {
			return CertificateInfo{}, ErrInvalidInput
		}
		found = found || value == usage
	}
	if !found {
		return CertificateInfo{}, ErrInvalidInput
	}
	info, err := certificateInfo(leaf, now)
	ttl, ttlErr := requestTTL(spec.TTL)
	if err != nil || ttlErr != nil || !matchesKey(spec.Key, info.Key) || info.TTLSeconds <= 0 || leaf.NotAfter.After(now.Add(ttl+5*time.Second)) {
		return CertificateInfo{}, ErrInvalidInput
	}
	if len(key) != 0 && len(csr) == 0 {
		match, err := MatchPrivateKey(bytes.NewReader(certificate), bytes.NewReader(key))
		if err != nil || !match.Match {
			return CertificateInfo{}, ErrKeyMismatch
		}
	} else if len(csr) != 0 && len(key) == 0 {
		request, err := ValidateCSR(spec, csr)
		if err != nil || request.PublicKeySHA256 != info.PublicKeySHA256 {
			return CertificateInfo{}, ErrKeyMismatch
		}
	} else {
		return CertificateInfo{}, ErrInvalidInput
	}
	if len(bytes.TrimSpace(chain)) != 0 {
		issuers, err := parseCertificates(chain, false)
		if err != nil {
			return CertificateInfo{}, ErrInvalidInput
		}
		for _, issuer := range issuers.certificates {
			if !issuer.IsCA {
				return CertificateInfo{}, ErrInvalidInput
			}
		}
	}
	verified, err := VerifyCertificate(bytes.NewReader(certificate), bytes.NewReader(roots), bytes.NewReader(chain), VerifyOptions{Time: now, Usage: spec.Usage})
	if err != nil || !verified.Valid {
		return CertificateInfo{}, ErrVerification
	}
	return info, nil
}
