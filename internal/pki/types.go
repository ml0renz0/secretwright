// Package pki provides bounded native X.509 operations without file, network,
// environment, or external-program access.
package pki

import (
	"errors"
	"time"
)

const APIVersion = "secretwright/pki/v1"

var (
	ErrInvalidInput = errors.New("invalid or oversized PKI input")
	ErrVerification = errors.New("PKI certificate verification failed")
	ErrKeyMismatch  = errors.New("PKI certificate and private key do not match")
	ErrPartial      = errors.New("PKI output was only partially saved")
)

type KeySpec struct {
	Type string `json:"type"`
	Bits int    `json:"bits"`
}

type Spec struct {
	APIVersion  string   `json:"api_version"`
	Name        string   `json:"name"`
	CommonName  string   `json:"common_name,omitempty"`
	DNSNames    []string `json:"dns_names"`
	IPAddresses []string `json:"ip_addresses"`
	TTL         string   `json:"ttl"`
	Usage       string   `json:"usage"`
	Key         KeySpec  `json:"key"`
}

type KeyReport struct {
	Algorithm       string `json:"algorithm"`
	Bits            int    `json:"bits"`
	Curve           string `json:"curve,omitempty"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

type CertificateInfo struct {
	Subject         string    `json:"subject"`
	Issuer          string    `json:"issuer"`
	Serial          string    `json:"serial"`
	SHA256          string    `json:"sha256"`
	PublicKeySHA256 string    `json:"public_key_sha256"`
	DNSNames        []string  `json:"dns_names"`
	IPAddresses     []string  `json:"ip_addresses"`
	EmailAddresses  []string  `json:"email_addresses"`
	URIs            []string  `json:"uris"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	TTLSeconds      int64     `json:"ttl_seconds"`
	Validity        string    `json:"validity"`
	IsCA            bool      `json:"is_ca"`
	Key             KeyReport `json:"key"`
	Usages          []string  `json:"usages"`
}

type CertificateReport struct {
	Certificates       []CertificateInfo `json:"certificates"`
	ContainsPrivateKey bool              `json:"contains_private_key"`
}

type CSRReport struct {
	Subject         string    `json:"subject"`
	CommonName      string    `json:"common_name"`
	PublicKeySHA256 string    `json:"public_key_sha256"`
	DNSNames        []string  `json:"dns_names"`
	IPAddresses     []string  `json:"ip_addresses"`
	SignatureValid  bool      `json:"signature_valid"`
	Key             KeyReport `json:"key"`
}

type VerifyOptions struct {
	Time  time.Time
	Name  string
	Usage string
}

type VerifyReport struct {
	Valid             bool   `json:"valid"`
	Reason            string `json:"reason,omitempty"`
	ChainLength       int    `json:"chain_length"`
	RevocationChecked bool   `json:"revocation_checked"`
}

type MatchReport struct {
	Match bool `json:"match"`
}

type GeneratedCSR struct {
	CSRPEM        []byte    `json:"-"`
	PrivateKeyPEM []byte    `json:"-"`
	Report        CSRReport `json:"report"`
}
