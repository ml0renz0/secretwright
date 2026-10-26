package lifecycle_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/fileformat"
	"github.com/ml0renz0/secretwright/internal/lifecycle"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const lifecycleYAML = `api_version: secretwright/lifecycle/v1
name: payments-api
provider: {kind: approle, auth_mount: approle, role: payments-api}
consumer: {kind: token-file, path: /run/payments/vault-token}
verify: {kind: kv-read, mount: secret, kv_version: 2, path: /secret/payments/health}
policy: {rotate_below: 5m, minimum_new_ttl: 10m}
`

func lifecycleSpec(t *testing.T) lifecycle.Spec {
	t.Helper()
	spec, err := lifecycle.Load(strings.NewReader(lifecycleYAML))
	if err != nil {
		t.Fatal("valid lifecycle configuration was rejected")
	}
	return spec
}

type lifecycleDenyLoader struct{}

func (lifecycleDenyLoader) Load(string) (any, error) { return nil, errors.New("external schema denied") }

func TestLifecycleSchemaExampleAndCanonicalSpecRemainOffline(t *testing.T) {
	t.Setenv("VAULT_ADDR", "private-invalid-address")
	t.Setenv("VAULT_TOKEN", "private-operator-token")
	t.Setenv("VAULT_CLIENT_TIMEOUT", "private-invalid-timeout")
	artifact, err := os.ReadFile("../../schemas/lifecycle-v1.schema.json")
	if err != nil || !bytes.Equal(artifact, lifecycle.Schema()) {
		t.Fatal("lifecycle runtime schema differs from the published artifact")
	}
	var header map[string]any
	if json.Unmarshal(artifact, &header) != nil || header["$id"] != "urn:secretwright:lifecycle:v1" || header["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatal("lifecycle schema lost its version or dialect")
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(artifact))
	if err != nil {
		t.Fatal("published lifecycle schema is not JSON")
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.UseLoader(lifecycleDenyLoader{})
	if compiler.AddResource("urn:secretwright:lifecycle:v1", value) != nil {
		t.Fatal("could not register lifecycle schema")
	}
	compiled, err := compiler.Compile("urn:secretwright:lifecycle:v1")
	if err != nil {
		t.Fatal("lifecycle schema required an external resource")
	}
	example := lifecycle.Example()
	var manifest any
	if json.Unmarshal(example, &manifest) != nil || compiled.Validate(manifest) != nil {
		t.Fatal("offline lifecycle example fails the published schema")
	}
	if _, err := lifecycle.Load(bytes.NewReader(example)); err != nil {
		t.Fatal("offline lifecycle example cannot be loaded")
	}
	spec := lifecycleSpec(t)
	alias := spec
	alias.Policy.RotateBelow, alias.Policy.MinimumNewTTL = "300s", "600s"
	if lifecycle.SpecHash(spec) == "" || lifecycle.SpecHash(alias) != lifecycle.SpecHash(spec) {
		t.Error("equivalent duration spellings changed lifecycle identity")
	}
	validated, err := lifecycle.ValidateSpec(spec)
	if err != nil || !reflect.DeepEqual(validated, spec) {
		t.Error("loaded lifecycle configuration changed when revalidated")
	}
	example[0] = 'x'
	if !json.Valid(lifecycle.Example()) {
		t.Error("caller mutation changed the shared lifecycle example")
	}
}

func TestLifecycleRejectsAmbiguousOrExecutableConfigurationWithoutEcho(t *testing.T) {
	for _, source := range []string{
		strings.Replace(lifecycleYAML, "name: payments-api", "name: payments-api\nname: private-duplicate", 1),
		strings.Replace(lifecycleYAML, "kind: approle", "kind: !private-executable approle", 1),
		strings.Replace(lifecycleYAML, "kind: approle", "kind: &private-anchor approle", 1),
		strings.Replace(lifecycleYAML, "path: /run/payments/vault-token", "path: ${env.PRIVATE_TOKEN_FILE}", 1),
		strings.Replace(lifecycleYAML, "kv_version: 2", "kv_version: 1", 1),
		strings.Replace(lifecycleYAML, "kv_version: 2", "kv_version: 2.0", 1),
		strings.Replace(lifecycleYAML, "kv_version: 2", "kv_version: 0x2", 1),
		strings.Replace(lifecycleYAML, "path: /secret/payments/health", "path: /secret-other/payments/health", 1),
		strings.Replace(lifecycleYAML, "path: /secret/payments/health", "path: /secret", 1),
		strings.Replace(lifecycleYAML, "path: /secret/payments/health", "path: /secret/../foreign/key", 1),
		strings.Replace(lifecycleYAML, "path: /run/payments/vault-token", "path: relative/private-token", 1),
		strings.Replace(lifecycleYAML, "path: /run/payments/vault-token", "path: /run/../private-token", 1),
		strings.Replace(lifecycleYAML, "path: /run/payments/vault-token", "path: /", 1),
		strings.Replace(lifecycleYAML, "role: payments-api", "role: private*role", 1),
		strings.Replace(lifecycleYAML, "rotate_below: 5m", "rotate_below: 0s", 1),
		strings.Replace(lifecycleYAML, "rotate_below: 5m", "rotate_below: 1ms", 1),
		strings.Replace(lifecycleYAML, "minimum_new_ttl: 10m", "minimum_new_ttl: 1m", 1),
		strings.Replace(lifecycleYAML, "minimum_new_ttl: 10m", "minimum_new_ttl: 25h", 1),
		lifecycleYAML + "include: private-file.yaml\n",
		lifecycleYAML + "---\nprivate: document\n",
		"{}", "[]", "null", "", string([]byte{0xff, 0}),
		lifecycleYAML + strings.Repeat(" ", 1<<20),
	} {
		spec, err := lifecycle.Load(strings.NewReader(source))
		if err != lifecycle.ErrInvalidLifecycle || !reflect.DeepEqual(spec, lifecycle.Spec{}) {
			t.Error("invalid lifecycle input returned partial configuration or a non-static error")
		}
	}
	if _, err := lifecycle.Load(nil); err != lifecycle.ErrInvalidLifecycle {
		t.Error("missing lifecycle reader was accepted")
	}
	if _, err := lifecycle.Load(failingLifecycleReader{}); err != lifecycle.ErrInvalidLifecycle {
		t.Error("failed lifecycle reader leaked its error")
	}
}

type failingLifecycleReader struct{}

func (failingLifecycleReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestRotationReceiptContainsOnlyStrictBoundMetadata(t *testing.T) {
	receipt := rotationReceipt(lifecycleSpec(t), "prepared")
	if lifecycle.ValidateReceipt(receipt) != nil {
		t.Fatal("valid prepared rotation receipt was rejected")
	}
	for _, format := range []fileformat.Format{fileformat.YAML, fileformat.JSON} {
		receipt.Format = format
		body, err := json.Marshal(receipt)
		if err != nil {
			t.Fatal("could not encode receipt fixture")
		}
		encoded, err := fileformat.EncodeJSON(body, format)
		if err != nil {
			t.Fatal("could not encode receipt format")
		}
		decoded, err := lifecycle.DecodeReceipt(bytes.NewReader(encoded))
		if err != nil || !reflect.DeepEqual(decoded, receipt) {
			t.Error("private receipt did not preserve its metadata in YAML/JSON")
		}
	}
	for _, edit := range []func(*lifecycle.Receipt){
		func(r *lifecycle.Receipt) { r.Revision = 0 },
		func(r *lifecycle.Receipt) { r.ConfigSHA256 = "private-config" },
		func(r *lifecycle.Receipt) { r.Generation = "../private-generation" },
		func(r *lifecycle.Receipt) { r.Phase = "execute-private-script" },
		func(r *lifecycle.Receipt) { r.OldDigest = "private-token" },
		func(r *lifecycle.Receipt) { r.RoleIdentity = "" },
		func(r *lifecycle.Receipt) { r.EntityID = "private-entity" },
		func(r *lifecycle.Receipt) { r.Phase = "published" },
		func(r *lifecycle.Receipt) { r.Format = "private-format" },
	} {
		invalid := receipt
		edit(&invalid)
		if lifecycle.ValidateReceipt(invalid) != lifecycle.ErrInvalidLifecycle {
			t.Error("rotation receipt admitted invalid binding or phase proofs")
		}
	}
	valid, _ := json.Marshal(receipt)
	for _, body := range [][]byte{
		[]byte(strings.Replace(string(valid), `"revision":1`, `"revision":1,"revision":2`, 1)),
		[]byte(strings.Replace(string(valid), `"revision":1`, `"revision":1,"token":"private-token"`, 1)),
		append(append([]byte(nil), valid...), []byte("\n{}")...),
		[]byte("null"), []byte("[]"), []byte("{}"), []byte{0xff},
	} {
		if _, err := lifecycle.DecodeReceipt(bytes.NewReader(body)); err != lifecycle.ErrInvalidLifecycle {
			t.Error("unsafe rotation receipt was accepted")
		}
	}
	if duration, err := time.ParseDuration(lifecycleSpec(t).Policy.MinimumNewTTL); err != nil || duration != 10*time.Minute {
		t.Error("lifecycle duration normalization changed meaning")
	}
}
