package pki

import (
	"bytes"
	"crypto/x509"
	"errors"
	"io"
	"net/netip"
	"time"
)

func ValidateRoots(body []byte) error {
	document, err := parseCertificates(body, false)
	if err != nil {
		return ErrInvalidInput
	}
	for _, root := range document.certificates {
		if !root.IsCA || !root.BasicConstraintsValid || root.KeyUsage != 0 && root.KeyUsage&x509.KeyUsageCertSign == 0 {
			return ErrInvalidInput
		}
	}
	return nil
}

func VerifyCertificate(cert, roots, intermediates io.Reader, options VerifyOptions) (VerifyReport, error) {
	certificate, err := boundedInput(cert)
	if err != nil {
		return VerifyReport{}, err
	}
	rootPEM, err := boundedInput(roots)
	if err != nil || ValidateRoots(rootPEM) != nil {
		return VerifyReport{}, ErrInvalidInput
	}
	document, err := parseCertificates(certificate, true)
	if err != nil {
		return VerifyReport{}, err
	}
	rootDocument, _ := parseCertificates(rootPEM, false)
	pool, chain := x509.NewCertPool(), x509.NewCertPool()
	for _, root := range rootDocument.certificates {
		pool.AddCert(root)
	}
	for _, intermediate := range document.certificates[1:] {
		chain.AddCert(intermediate)
	}
	if intermediates != nil {
		body, err := io.ReadAll(io.LimitReader(intermediates, maxPEMBytes+1))
		if err != nil || len(body) > maxPEMBytes {
			return VerifyReport{}, ErrInvalidInput
		}
		if len(bytes.TrimSpace(body)) != 0 {
			additional, err := parseCertificates(body, false)
			if err != nil {
				return VerifyReport{}, err
			}
			for _, intermediate := range additional.certificates {
				chain.AddCert(intermediate)
			}
		}
	}
	if options.Time.IsZero() {
		options.Time = time.Now()
	}
	if options.Usage == "" {
		options.Usage = "server-auth"
	}
	usage := x509.ExtKeyUsageServerAuth
	if options.Usage == "client-auth" {
		usage = x509.ExtKeyUsageClientAuth
	} else if options.Usage != "server-auth" {
		return VerifyReport{}, ErrInvalidInput
	}
	if options.Name != "" {
		if address, err := netip.ParseAddr(options.Name); err == nil && address.Zone() == "" {
			options.Name = address.Unmap().String()
		} else if canonical, valid := canonicalDNS(options.Name); valid {
			options.Name = canonical
		} else {
			return VerifyReport{}, ErrInvalidInput
		}
	}
	chains, err := document.certificates[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: chain, CurrentTime: options.Time, DNSName: options.Name, KeyUsages: []x509.ExtKeyUsage{usage}})
	if err != nil {
		reason := "invalid_chain"
		var hostname x509.HostnameError
		var authority x509.UnknownAuthorityError
		var invalid x509.CertificateInvalidError
		switch {
		case errors.As(err, &hostname):
			reason = "name_mismatch"
		case errors.As(err, &invalid):
			switch invalid.Reason {
			case x509.Expired:
				reason = "expired"
				if options.Time.Before(invalid.Cert.NotBefore) {
					reason = "not_yet_valid"
				}
			case x509.IncompatibleUsage:
				reason = "incompatible_usage"
			}
		case errors.As(err, &authority):
			reason = "unknown_authority"
		}
		return VerifyReport{Reason: reason}, ErrVerification
	}
	return VerifyReport{Valid: true, ChainLength: len(chains[0]), RevocationChecked: false}, nil
}

func MatchPrivateKey(cert, key io.Reader) (MatchReport, error) {
	certificate, err := boundedInput(cert)
	if err != nil {
		return MatchReport{}, err
	}
	private, err := boundedInput(key)
	if err != nil {
		return MatchReport{}, err
	}
	document, err := parseCertificates(certificate, true)
	if err != nil {
		return MatchReport{}, err
	}
	keyDocument, err := decodePEM(private)
	if err != nil || keyDocument.key == nil || keyDocument.request != nil {
		return MatchReport{}, ErrInvalidInput
	}
	if !samePublicKey(document.certificates[0].PublicKey, keyDocument.key.Public()) {
		return MatchReport{}, ErrKeyMismatch
	}
	return MatchReport{Match: true}, nil
}
