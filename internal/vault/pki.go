package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/ml0renz0/secretwright/internal/pki"
)

const maxPKIResponseBytes = 1 << 20
const maxPKIChainCertificates = 32

type PKIOptions struct {
	Mount string
}

// PKICertificate deliberately excludes both public PEM and private material
// from metadata reports. Only an explicitly reserved output receives PEM.
type PKICertificate struct {
	PEM    []byte              `json:"-"`
	Report pki.CertificateInfo `json:"report"`
}

type PKIRevocationReport struct {
	Serial         string `json:"serial"`
	Revoked        bool   `json:"revoked"`
	RevocationTime int64  `json:"revocation_time"`
}

func ValidatePKIMount(mount string) error {
	if mount == "" || len(mount) > 1024 {
		return ErrInvalidAccessInput
	}
	for _, segment := range strings.Split(mount, "/") {
		if !validateAccessName(segment) {
			return ErrInvalidAccessInput
		}
	}
	return nil
}

// ValidatePKISerial canonicalizes a positive, bounded hexadecimal serial. Only
// hexadecimal bytes and their explicit separator may enter a certificate URL.
func ValidatePKISerial(serial string) (string, error) {
	if serial == "" || len(serial) > 95 {
		return "", ErrInvalidAccessInput
	}
	raw := serial
	if strings.ContainsAny(serial, ":-") {
		separator := ":"
		if strings.Contains(serial, "-") {
			separator = "-"
		}
		parts := strings.Split(serial, separator)
		if len(parts) > 32 {
			return "", ErrInvalidAccessInput
		}
		for _, part := range parts {
			if len(part) != 2 {
				return "", ErrInvalidAccessInput
			}
		}
		raw = strings.Join(parts, "")
	} else if len(raw)%2 != 0 {
		raw = "0" + raw
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) == 0 || len(decoded) > 32 {
		return "", ErrInvalidAccessInput
	}
	for len(decoded) > 0 && decoded[0] == 0 {
		decoded = decoded[1:]
	}
	if len(decoded) == 0 {
		return "", ErrInvalidAccessInput
	}
	parts := make([]string, len(decoded))
	for index, value := range decoded {
		parts[index] = hex.EncodeToString([]byte{value})
	}
	return strings.Join(parts, ":"), nil
}

// pkiRequest bounds successful response parsing and keeps rejected reads
// distinct from mutations whose acknowledgement may have been lost.
func pkiRequest(ctx context.Context, client *api.Client, method, path string, body map[string]any, mutation bool) (*api.Secret, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	request := client.NewRequest(method, "/v1/"+path)
	if body != nil {
		if request.SetJSONBody(body) != nil {
			return nil, ErrInvalidAccessInput
		}
	}
	response, err := client.RawRequestWithContext(ctx, request)
	if response != nil {
		defer response.Body.Close()
	}
	if err != nil {
		if mutation {
			return nil, pkiMutationError(err)
		}
		return nil, accessRequestError(err)
	}
	invalid := ErrAccessResponse
	if mutation {
		invalid = ErrAccessUnconfirmed
	}
	if response == nil || response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, invalid
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxPKIResponseBytes+1))
	if err != nil || len(raw) > maxPKIResponseBytes || !json.Valid(raw) {
		return nil, invalid
	}
	secret, err := api.ParseSecret(bytes.NewReader(raw))
	if err != nil || secret == nil || secret.Data == nil {
		return nil, invalid
	}
	return secret, nil
}

func pkiMutationError(err error) error {
	var upstream *api.ResponseError
	if errors.As(err, &upstream) {
		switch upstream.StatusCode {
		case http.StatusBadRequest:
			return ErrInvalidAccessInput
		case http.StatusUnauthorized, http.StatusForbidden:
			return ErrPermissionDenied
		case http.StatusNotFound:
			return ErrNotFound
		case http.StatusConflict, http.StatusPreconditionFailed:
			return ErrConflict
		}
	}
	if errors.Is(err, context.Canceled) {
		return errors.Join(ErrAccessUnconfirmed, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrAccessUnconfirmed, context.DeadlineExceeded)
	}
	return ErrAccessUnconfirmed
}

func pkiHasPrivateKey(data map[string]any) bool {
	_, present := data["private_key"]
	return present
}

// pkiCertificatePEM accepts certificate-only blocks and emits a detached,
// canonical, deduplicated chain whose first certificate remains the leaf.
func pkiCertificatePEM(data map[string]any) ([]byte, []byte, error) {
	certificate, ok := data["certificate"].(string)
	if !ok || certificate == "" {
		return nil, nil, ErrAccessResponse
	}
	sources := []string{certificate}
	if raw, supplied := data["ca_chain"]; supplied && raw != nil {
		chain, err := accessStringList(raw)
		if err != nil || len(chain) > maxPKIChainCertificates {
			return nil, nil, ErrAccessResponse
		}
		sources = append(sources, chain...)
	}
	if raw, supplied := data["issuing_ca"]; supplied {
		issuer, ok := raw.(string)
		if !ok {
			return nil, nil, ErrAccessResponse
		}
		if issuer != "" {
			sources = append(sources, issuer)
		}
	}
	var output, leaf []byte
	seen := make(map[[32]byte]bool)
	for _, source := range sources {
		if source == "" || len(source) > maxPKIResponseBytes {
			return nil, nil, ErrAccessResponse
		}
		inspected, err := pki.InspectCertificates(bytes.NewReader([]byte(source)), time.Now())
		if err != nil || inspected.ContainsPrivateKey {
			return nil, nil, ErrAccessResponse
		}
		remaining := bytes.TrimSpace([]byte(source))
		for len(remaining) != 0 {
			if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
				return nil, nil, ErrAccessResponse
			}
			block, rest := pem.Decode(remaining)
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return nil, nil, ErrAccessResponse
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return nil, nil, ErrAccessResponse
			}
			digest := sha256.Sum256(block.Bytes)
			if !seen[digest] {
				if len(seen) >= maxPKIChainCertificates {
					return nil, nil, ErrAccessResponse
				}
				seen[digest] = true
				encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
				if leaf == nil {
					leaf = append([]byte(nil), encoded...)
				}
				output = append(output, encoded...)
				if len(output) > maxPKIResponseBytes {
					return nil, nil, ErrAccessResponse
				}
			}
			remaining = bytes.TrimSpace(rest)
		}
	}
	if leaf == nil {
		return nil, nil, ErrAccessResponse
	}
	return leaf, output, nil
}

func pkiReadCertificate(ctx context.Context, client *api.Client, path, serial string, ca bool) (PKICertificate, error) {
	secret, err := pkiRequest(ctx, client, http.MethodGet, path, nil, false)
	if err != nil {
		return PKICertificate{}, err
	}
	if pkiHasPrivateKey(secret.Data) {
		return PKICertificate{}, ErrAccessResponse
	}
	_, chain, err := pkiCertificatePEM(secret.Data)
	if err != nil {
		return PKICertificate{}, err
	}
	inspected, err := pki.InspectCertificates(bytes.NewReader(chain), time.Now())
	if err != nil || inspected.ContainsPrivateKey || len(inspected.Certificates) == 0 {
		return PKICertificate{}, ErrAccessResponse
	}
	first := inspected.Certificates[0]
	if ca {
		for _, certificate := range inspected.Certificates {
			if !certificate.IsCA {
				return PKICertificate{}, ErrAccessResponse
			}
		}
	} else if first.Serial != serial {
		return PKICertificate{}, ErrAccessResponse
	}
	return PKICertificate{PEM: chain, Report: first}, nil
}

func (c *Client) ReadPKICA(ctx context.Context, token string, opts PKIOptions) (PKICertificate, error) {
	if ValidatePKIMount(opts.Mount) != nil {
		return PKICertificate{}, ErrInvalidAccessInput
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return PKICertificate{}, err
	}
	defer client.SetToken("")
	return pkiReadCertificate(ctx, client, opts.Mount+"/cert/ca", "", true)
}

func (c *Client) ReadPKICertificate(ctx context.Context, token, serial string, opts PKIOptions) (PKICertificate, error) {
	if ValidatePKIMount(opts.Mount) != nil {
		return PKICertificate{}, ErrInvalidAccessInput
	}
	serial, err := ValidatePKISerial(serial)
	if err != nil {
		return PKICertificate{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return PKICertificate{}, err
	}
	defer client.SetToken("")
	return pkiReadCertificate(ctx, client, opts.Mount+"/cert/"+serial, serial, false)
}

func pkiIssueBody(spec pki.Spec, sign bool, csr []byte) map[string]any {
	ttl, _ := time.ParseDuration(spec.TTL)
	body := map[string]any{
		"common_name": spec.CommonName, "alt_names": strings.Join(spec.DNSNames, ","),
		"ip_sans": strings.Join(spec.IPAddresses, ","), "ttl": int64(ttl / time.Second),
		"exclude_cn_from_sans": true, "format": "pem", "private_key_format": "pkcs8",
	}
	if sign {
		body["csr"] = string(csr)
	} else {
		keyType := spec.Key.Type
		if keyType == "ecdsa" {
			keyType = "ec"
		}
		body["key_type"], body["key_bits"] = keyType, spec.Key.Bits
	}
	return body
}

func pkiParseIssued(spec pki.Spec, secret *api.Secret, csr, roots []byte, sign bool) (PKICertificate, error) {
	if secret == nil || secret.Data == nil || sign && pkiHasPrivateKey(secret.Data) {
		return PKICertificate{}, ErrAccessUnconfirmed
	}
	leaf, chain, err := pkiCertificatePEM(secret.Data)
	if err != nil {
		return PKICertificate{}, ErrAccessUnconfirmed
	}
	var key []byte
	if !sign {
		encoded, ok := secret.Data["private_key"].(string)
		if !ok || encoded == "" || len(encoded) > 64<<10 {
			return PKICertificate{}, ErrAccessUnconfirmed
		}
		key = []byte(encoded)
		if _, err := pki.InspectPrivateKey(bytes.NewReader(key)); err != nil {
			return PKICertificate{}, ErrAccessUnconfirmed
		}
	}
	info, err := pki.ValidateIssued(spec, leaf, bytes.TrimPrefix(chain, leaf), key, csr, roots, time.Now())
	if err != nil {
		return PKICertificate{}, ErrAccessUnconfirmed
	}
	expiration, err := accessNumber(secret.Data["expiration"])
	serial, serialOK := secret.Data["serial_number"].(string)
	canonical, serialErr := ValidatePKISerial(serial)
	if err != nil || expiration != info.NotAfter.Unix() || !serialOK || serialErr != nil || canonical != info.Serial {
		return PKICertificate{}, ErrAccessUnconfirmed
	}
	output := append([]byte(nil), chain...)
	if !sign {
		block, rest := pem.Decode(bytes.TrimSpace(key))
		if block == nil || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
			return PKICertificate{}, ErrAccessUnconfirmed
		}
		output = append(pem.EncodeToMemory(block), chain...)
	}
	if len(output) > maxPKIResponseBytes {
		return PKICertificate{}, ErrAccessUnconfirmed
	}
	return PKICertificate{PEM: output, Report: info}, nil
}

func (c *Client) IssuePKICertificate(ctx context.Context, token, role string, spec pki.Spec, roots []byte, opts PKIOptions) (PKICertificate, error) {
	return c.pkiEmitCertificate(ctx, token, role, spec, nil, roots, opts, false)
}

func (c *Client) SignPKICertificate(ctx context.Context, token, role string, spec pki.Spec, csr, roots []byte, opts PKIOptions) (PKICertificate, error) {
	return c.pkiEmitCertificate(ctx, token, role, spec, csr, roots, opts, true)
}

func (c *Client) pkiEmitCertificate(ctx context.Context, token, role string, spec pki.Spec, csr, roots []byte, opts PKIOptions, sign bool) (PKICertificate, error) {
	if ValidatePKIMount(opts.Mount) != nil || !validateAccessName(role) {
		return PKICertificate{}, ErrInvalidAccessInput
	}
	normalized, err := pki.ValidateSpec(spec)
	if err != nil {
		return PKICertificate{}, err
	}
	if err := pki.ValidateRoots(roots); err != nil {
		return PKICertificate{}, err
	}
	if sign {
		if _, err := pki.ValidateCSR(normalized, csr); err != nil {
			return PKICertificate{}, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.accessClient(token, false)
	if err != nil {
		return PKICertificate{}, err
	}
	defer client.SetToken("")
	action := "issue/"
	if sign {
		action = "sign/"
	}
	secret, err := pkiRequest(ctx, client, http.MethodPost, opts.Mount+"/"+action+role, pkiIssueBody(normalized, sign, csr), true)
	if err != nil {
		return PKICertificate{}, err
	}
	return pkiParseIssued(normalized, secret, csr, roots, sign)
}

func (c *Client) RevokePKICertificate(ctx context.Context, token string, certificate []byte, opts PKIOptions) (PKIRevocationReport, error) {
	if ValidatePKIMount(opts.Mount) != nil {
		return PKIRevocationReport{}, ErrInvalidAccessInput
	}
	serial, err := pki.CertificateSerial(bytes.NewReader(certificate))
	if err != nil {
		return PKIRevocationReport{}, err
	}
	inspected, err := pki.InspectCertificates(bytes.NewReader(certificate), time.Now())
	if err != nil || len(inspected.Certificates) == 0 || inspected.Certificates[0].IsCA {
		return PKIRevocationReport{}, ErrInvalidAccessInput
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	stored, err := c.ReadPKICertificate(ctx, token, serial, opts)
	if err != nil {
		return PKIRevocationReport{}, err
	}
	if stored.Report.SHA256 != inspected.Certificates[0].SHA256 {
		return PKIRevocationReport{}, ErrConflict
	}
	client, err := c.accessClient(token, false)
	if err != nil {
		return PKIRevocationReport{}, err
	}
	defer client.SetToken("")
	secret, err := pkiRequest(ctx, client, http.MethodPost, opts.Mount+"/revoke", map[string]any{"serial_number": serial}, true)
	if err != nil {
		return PKIRevocationReport{}, err
	}
	revokedAt, err := accessNumber(secret.Data["revocation_time"])
	if err != nil || revokedAt <= 0 {
		return PKIRevocationReport{}, ErrAccessUnconfirmed
	}
	return PKIRevocationReport{Serial: serial, Revoked: true, RevocationTime: revokedAt}, nil
}
