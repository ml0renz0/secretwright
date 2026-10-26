package pki_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/ml0renz0/secretwright/internal/fileformat"
	"github.com/ml0renz0/secretwright/internal/pki"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const pkiManifest = `api_version: secretwright/pki/v1
name: application
common_name: app.example.test
dns_names: [app.example.test]
ip_addresses: [127.0.0.1]
ttl: 1h
usage: server-auth
key: {type: ecdsa, bits: 256}
`

type denyPKISchemaLoader struct{}

func (denyPKISchemaLoader) Load(string) (any, error) {
	return nil, errors.New("private-marker-external-schema")
}

func TestPKISchemaAndExamplesAreOfflineStrictAndFormatIndependent(t *testing.T) {
	t.Setenv("VAULT_ADDR", "private-marker-invalid-address")
	t.Setenv("VAULT_CLIENT_TIMEOUT", "private-marker-invalid-timeout")
	t.Setenv("VAULT_TOKEN", "private-marker-operator")
	artifact, err := os.ReadFile("../../schemas/pki-v1.schema.json")
	if err != nil || !bytes.Equal(artifact, pki.Schema()) {
		t.Fatal("runtime PKI schema differs from its published artifact")
	}
	var header map[string]any
	if json.Unmarshal(artifact, &header) != nil || header["$id"] != "urn:secretwright:pki:v1" || header["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatal("PKI schema lost its version or dialect")
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(artifact))
	if err != nil {
		t.Fatal("published PKI schema is not JSON")
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.UseLoader(denyPKISchemaLoader{})
	if compiler.AddResource("urn:secretwright:pki:v1", document) != nil {
		t.Fatal("could not register PKI schema")
	}
	compiled, err := compiler.Compile("urn:secretwright:pki:v1")
	if err != nil {
		t.Fatal("PKI schema depended on an external resource")
	}
	var example any
	if json.Unmarshal(pki.Example(), &example) != nil || compiled.Validate(example) != nil {
		t.Fatal("offline PKI example fails its schema")
	}
	for _, format := range []fileformat.Format{fileformat.YAML, fileformat.JSON} {
		body, err := fileformat.EncodeJSON(pki.Example(), format)
		if err != nil {
			t.Fatal("PKI example could not be rendered")
		}
		if _, err := pki.Load(bytes.NewReader(body)); err != nil {
			t.Error("PKI example could not round-trip through YAML or JSON")
		}
	}
	copy := pki.Schema()
	copy[0] = 'x'
	if !json.Valid(pki.Schema()) {
		t.Error("caller mutation changed shared PKI schema")
	}
}

func TestPKISpecDefaultsNormalizeAndDetachInput(t *testing.T) {
	spec := fixtureSpec()
	spec.Key = pki.KeySpec{}
	spec.Usage = ""
	spec.DNSNames = []string{"z.example.test", "app.example.test", "app.example.test"}
	before := append([]string{}, spec.DNSNames...)
	normalized, err := pki.ValidateSpec(spec)
	if err != nil || normalized.Key.Type != "ecdsa" || normalized.Key.Bits != 256 || normalized.Usage != "server-auth" || !reflect.DeepEqual(normalized.DNSNames, []string{"app.example.test", "z.example.test"}) {
		t.Fatal("PKI spec did not apply its bounded defaults or canonical SAN set")
	}
	if !reflect.DeepEqual(spec.DNSNames, before) {
		t.Error("validating a spec mutated its caller-owned SAN list")
	}
	normalized.DNSNames[0] = "changed.example.test"
	if !reflect.DeepEqual(spec.DNSNames, before) {
		t.Error("validated SAN slice still aliases its input")
	}
	for _, key := range []pki.KeySpec{{Type: "ecdsa", Bits: 256}, {Type: "ecdsa", Bits: 384}, {Type: "rsa", Bits: 2048}, {Type: "rsa", Bits: 3072}, {Type: "rsa", Bits: 4096}, {Type: "ed25519"}} {
		spec := fixtureSpec()
		spec.Key = key
		if _, err := pki.ValidateSpec(spec); err != nil {
			t.Error("supported key parameters were rejected")
		}
	}
}

func TestPKIRejectsAmbiguousOrUnsupportedRequestConfiguration(t *testing.T) {
	for _, source := range []string{
		strings.Replace(pkiManifest, "name: application", "name: application\nname: private-marker", 1),
		strings.Replace(pkiManifest, "type: ecdsa", "type: &private-marker ecdsa", 1),
		strings.Replace(pkiManifest, "type: ecdsa", "type: !private-marker ecdsa", 1),
		strings.Replace(pkiManifest, "bits: 256", "bits: 256.0", 1),
		strings.Replace(pkiManifest, "bits: 256", "bits: 0x100", 1),
		pkiManifest + "include: private-marker.yaml\n",
		pkiManifest + "---\nprivate-marker: second-document\n",
		pkiManifest + strings.Repeat(" ", 1<<20), "", "null", "[]", "{}", string([]byte{0xff}),
	} {
		_, err := pki.Load(strings.NewReader(source))
		if err != pki.ErrInvalidInput {
			t.Error("strict PKI loader accepted ambiguous data or returned a dynamic diagnostic")
		}
	}
	for _, edit := range []func(*pki.Spec){
		func(s *pki.Spec) { s.APIVersion = "private-marker/v2" },
		func(s *pki.Spec) { s.Name = "private-marker/name" },
		func(s *pki.Spec) { s.CommonName = "foreign.example.test" },
		func(s *pki.Spec) { s.DNSNames = nil; s.IPAddresses = nil },
		func(s *pki.Spec) { s.DNSNames = []string{"*.example.test"} },
		func(s *pki.Spec) { s.DNSNames = []string{"https://app.example.test"} },
		func(s *pki.Spec) { s.DNSNames = []string{"private_marker.example.test"} },
		func(s *pki.Spec) { s.DNSNames = []string{"private-marker\n.example.test"} },
		func(s *pki.Spec) { s.IPAddresses = []string{"127.000.0.1"} },
		func(s *pki.Spec) { s.IPAddresses = []string{"fe80::1%private-marker"} },
		func(s *pki.Spec) { s.TTL = "0s" },
		func(s *pki.Spec) { s.TTL = "1ms" },
		func(s *pki.Spec) { s.TTL = "25h" },
		func(s *pki.Spec) { s.Usage = "any" },
		func(s *pki.Spec) { s.Key = pki.KeySpec{Type: "rsa", Bits: 1024} },
		func(s *pki.Spec) { s.Key = pki.KeySpec{Type: "ecdsa", Bits: 521} },
		func(s *pki.Spec) { s.Key = pki.KeySpec{Type: "ed25519", Bits: 256} },
	} {
		invalid := fixtureSpec()
		edit(&invalid)
		_, err := pki.ValidateSpec(invalid)
		if err != pki.ErrInvalidInput {
			t.Error("unsupported PKI request parameters were accepted")
		}
	}
	if _, err := pki.Load(nil); err != pki.ErrInvalidInput {
		t.Error("missing PKI reader was accepted")
	}
}

func TestGeneratedCSRMatchesItsLocalPKCS8PrivateKey(t *testing.T) {
	for _, key := range []pki.KeySpec{{Type: "ecdsa", Bits: 256}, {Type: "ecdsa", Bits: 384}, {Type: "rsa", Bits: 2048}, {Type: "ed25519"}} {
		spec := fixtureSpec()
		spec.Key = key
		generated, err := pki.GenerateCSR(context.Background(), spec)
		if err != nil || len(generated.CSRPEM) == 0 || len(generated.PrivateKeyPEM) == 0 || !generated.Report.SignatureValid {
			t.Fatal("supported local key and CSR generation failed")
		}
		block, rest := pem.Decode(generated.PrivateKeyPEM)
		if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
			t.Fatal("generated private key is not one PKCS8 PEM block")
		}
		if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			t.Error("generated PKCS8 key cannot be parsed by native Go crypto")
		}
		privateReport, err := pki.InspectPrivateKey(bytes.NewReader(generated.PrivateKeyPEM))
		if err != nil || privateReport.PublicKeySHA256 != generated.Report.PublicKeySHA256 {
			t.Error("CSR was not signed by the generated local private key")
		}
		if _, err := pki.ValidateCSR(spec, generated.CSRPEM); err != nil {
			t.Error("generated CSR differs from the requested key, CN or SANs")
		}
		output, err := json.Marshal(generated)
		if err != nil || bytes.Contains(output, []byte("-----BEGIN")) || bytes.Contains(output, []byte("private_key_pem")) || bytes.Contains(output, []byte("csr_pem")) {
			t.Error("generated CSR result serialized its private credential bytes")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	generated, err := pki.GenerateCSR(ctx, fixtureSpec())
	if !errors.Is(err, context.Canceled) || len(generated.CSRPEM) != 0 || len(generated.PrivateKeyPEM) != 0 {
		t.Error("canceled generation returned private artifacts")
	}
}
