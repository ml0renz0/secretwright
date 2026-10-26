package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxPEMBytes = 1 << 20
const maxKeyPEMBytes = 64 << 10
const maxCertificates = 32

type pemDocument struct {
	certificates []*x509.Certificate
	key          crypto.Signer
	request      *x509.CertificateRequest
}

// Decode only the first complete block. pem.Decode otherwise searches past an
// invalid block and can silently discard a malformed PEM prefix.
func firstPEMBlock(body []byte) (*pem.Block, []byte) {
	newline := bytes.IndexByte(body, '\n')
	if newline < 0 {
		return nil, nil
	}
	header := strings.TrimSuffix(string(body[:newline]), "\r")
	if !strings.HasPrefix(header, "-----BEGIN ") || !strings.HasSuffix(header, "-----") {
		return nil, nil
	}
	kind := strings.TrimSuffix(strings.TrimPrefix(header, "-----BEGIN "), "-----")
	endMarker := []byte("-----END " + kind + "-----")
	end := bytes.Index(body, endMarker)
	if end < newline {
		return nil, nil
	}
	end += len(endMarker)
	if bytes.Contains(body[newline:end], []byte("-----BEGIN ")) {
		return nil, nil
	}
	block, rest := pem.Decode(body[:end])
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil
	}
	return block, body[end:]
}

func boundedInput(input io.Reader) ([]byte, error) {
	if input == nil {
		return nil, ErrInvalidInput
	}
	body, err := io.ReadAll(io.LimitReader(input, maxPEMBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxPEMBytes {
		return nil, ErrInvalidInput
	}
	return body, nil
}

func parsePrivate(block *pem.Block) (crypto.Signer, error) {
	if len(pem.EncodeToMemory(block)) > maxKeyPEMBytes {
		return nil, ErrInvalidInput
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, ErrInvalidInput
	}
	if err != nil {
		return nil, ErrInvalidInput
	}
	var signer crypto.Signer
	switch parsed := key.(type) {
	case *rsa.PrivateKey:
		signer = parsed
	case *ecdsa.PrivateKey:
		signer = parsed
	case ed25519.PrivateKey:
		signer = parsed
	default:
		return nil, ErrInvalidInput
	}
	if _, err := publicKeyReport(signer.Public()); err != nil {
		return nil, ErrInvalidInput
	}
	return signer, nil
}

// Decode enforces a complete PEM document; pem.Decode alone would silently
// search past a garbage prefix. Profiles are checked by each public operation.
func decodePEM(body []byte) (pemDocument, error) {
	var result pemDocument
	if len(body) == 0 || len(body) > maxPEMBytes {
		return result, ErrInvalidInput
	}
	rest := bytes.TrimSpace(body)
	blocks := 0
	for len(rest) != 0 {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return pemDocument{}, ErrInvalidInput
		}
		block, remaining := firstPEMBlock(rest)
		if block == nil || len(block.Headers) != 0 {
			return pemDocument{}, ErrInvalidInput
		}
		blocks++
		if blocks > maxCertificates+1 {
			return pemDocument{}, ErrInvalidInput
		}
		switch block.Type {
		case "CERTIFICATE":
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil || len(result.certificates) >= maxCertificates {
				return pemDocument{}, ErrInvalidInput
			}
			result.certificates = append(result.certificates, certificate)
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			if result.key != nil {
				return pemDocument{}, ErrInvalidInput
			}
			key, err := parsePrivate(block)
			if err != nil {
				return pemDocument{}, ErrInvalidInput
			}
			result.key = key
		case "CERTIFICATE REQUEST":
			if result.request != nil {
				return pemDocument{}, ErrInvalidInput
			}
			request, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil || request.CheckSignature() != nil {
				return pemDocument{}, ErrInvalidInput
			}
			result.request = request
		default:
			return pemDocument{}, ErrInvalidInput
		}
		rest = bytes.TrimSpace(remaining)
	}
	if blocks == 0 || result.request != nil && (result.key != nil || len(result.certificates) != 0) {
		return pemDocument{}, ErrInvalidInput
	}
	if result.key != nil && len(result.certificates) == 0 && len(body) > maxKeyPEMBytes {
		return pemDocument{}, ErrInvalidInput
	}
	if result.key != nil && len(result.certificates) != 0 && !samePublicKey(result.certificates[0].PublicKey, result.key.Public()) {
		return pemDocument{}, ErrKeyMismatch
	}
	return result, nil
}

func parseCertificates(body []byte, allowIdentity bool) (pemDocument, error) {
	document, err := decodePEM(body)
	if err != nil {
		return pemDocument{}, err
	}
	if len(document.certificates) == 0 || document.request != nil || !allowIdentity && document.key != nil {
		return pemDocument{}, ErrInvalidInput
	}
	return document, nil
}

func parseRequest(body []byte) (*x509.CertificateRequest, error) {
	document, err := decodePEM(body)
	if err != nil || document.request == nil || document.key != nil || len(document.certificates) != 0 {
		return nil, ErrInvalidInput
	}
	return document.request, nil
}

func publicKeyReport(public any) (KeyReport, error) {
	var result KeyReport
	switch key := public.(type) {
	case *rsa.PublicKey:
		if key == nil || key.N == nil || key.N.Sign() <= 0 || key.N.BitLen() > 8192 || key.E < 3 {
			return KeyReport{}, ErrInvalidInput
		}
		result.Algorithm, result.Bits = "rsa", key.N.BitLen()
	case *ecdsa.PublicKey:
		if key == nil || key.Curve == nil || key.X == nil || key.Y == nil || !key.Curve.IsOnCurve(key.X, key.Y) {
			return KeyReport{}, ErrInvalidInput
		}
		result.Algorithm, result.Bits, result.Curve = "ecdsa", key.Curve.Params().BitSize, key.Curve.Params().Name
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return KeyReport{}, ErrInvalidInput
		}
		result.Algorithm, result.Bits = "ed25519", 256
	default:
		return KeyReport{}, ErrInvalidInput
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return KeyReport{}, ErrInvalidInput
	}
	result.PublicKeySHA256 = fingerprint(der)
	return result, nil
}

func fingerprint(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func samePublicKey(left, right any) bool {
	first, firstErr := x509.MarshalPKIXPublicKey(left)
	second, secondErr := x509.MarshalPKIXPublicKey(right)
	return firstErr == nil && secondErr == nil && subtle.ConstantTimeCompare(first, second) == 1
}

func validMetadata(value string, limit int) bool {
	if len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
