package keytab_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/ml0renz0/secretwright/internal/fileformat"
	"github.com/ml0renz0/secretwright/internal/keytab"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const ktPolicyYAML = `api_version: secretwright/keytab/v1
name: web
principal:
  realm: EXAMPLE.TEST
  components: [HTTP, app.example.test]
minimum_kvno: 3
allowed_enctypes: [17, 18, 19, 20]
required_enctypes: [18]
allow_other_principals: false
`

type ktDenyLoader struct{}

func (ktDenyLoader) Load(string) (any, error) {
	return nil, errors.New("external schema access must not occur")
}

func TestKeytabPolicySchemaAndExamplesStayOfflineAndFormatIndependent(t *testing.T) {
	t.Setenv("VAULT_ADDR", "private-invalid-vault-address")
	t.Setenv("VAULT_TOKEN", "private-invalid-vault-token")
	t.Setenv("VAULT_CLIENT_TIMEOUT", "private-invalid-vault-timeout")
	published, err := os.ReadFile("../../schemas/keytab-v1.schema.json")
	if err != nil || !bytes.Equal(published, keytab.Schema()) {
		t.Fatal("runtime keytab schema differs from its published version")
	}
	var header map[string]any
	if json.Unmarshal(published, &header) != nil || header["$id"] != "urn:secretwright:keytab:v1" || header["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatal("keytab schema lost its version or dialect")
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(published))
	if err != nil {
		t.Fatal("published keytab schema is not JSON")
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.UseLoader(ktDenyLoader{})
	if compiler.AddResource("urn:secretwright:keytab:v1", document) != nil {
		t.Fatal("could not register keytab policy schema")
	}
	compiled, err := compiler.Compile("urn:secretwright:keytab:v1")
	if err != nil {
		t.Fatal("keytab policy schema required external resources")
	}
	var example any
	if json.Unmarshal(keytab.Example(), &example) != nil || compiled.Validate(example) != nil {
		t.Fatal("generated keytab policy fails its own schema")
	}
	var first keytab.Policy
	for _, format := range []fileformat.Format{fileformat.YAML, fileformat.JSON} {
		body, err := fileformat.EncodeJSON(keytab.Example(), format)
		if err != nil {
			t.Fatal("could not render keytab policy example")
		}
		policy, err := keytab.LoadPolicy(bytes.NewReader(body))
		if err != nil {
			t.Fatal("generated keytab policy cannot be read")
		}
		if first.APIVersion == "" {
			first = policy
		} else if !reflect.DeepEqual(first, policy) {
			t.Error("YAML and JSON generated different policy meanings")
		}
	}
	copy := keytab.Schema()
	copy[0] = 'x'
	if !json.Valid(keytab.Schema()) {
		t.Error("caller mutation corrupted the shared keytab schema")
	}
	copy = keytab.Example()
	copy[0] = 'x'
	if !json.Valid(keytab.Example()) {
		t.Error("caller mutation corrupted the shared keytab example")
	}
}

func TestKeytabPolicyNormalizationDetachesStructuredIdentityAndLists(t *testing.T) {
	policy := ktPolicy()
	policy.AllowedEnctypes = []uint16{20, 18, 17, 18}
	policy.RequiredEnctypes = []uint16{18, 18}
	normalized, err := keytab.ValidatePolicy(policy)
	if err != nil || !reflect.DeepEqual(normalized.AllowedEnctypes, []uint16{17, 18, 20}) || !reflect.DeepEqual(normalized.RequiredEnctypes, []uint16{18}) {
		t.Fatal("valid policy did not receive deterministic set normalization")
	}
	normalized.Principal.Components[0] = "changed"
	normalized.AllowedEnctypes[0] = 23
	normalized.RequiredEnctypes[0] = 23
	if policy.Principal.Components[0] != "HTTP" || policy.AllowedEnctypes[0] != 20 || policy.RequiredEnctypes[0] != 18 {
		t.Error("normalized policy aliases the caller's identity or encryption lists")
	}
	maximum := ktPolicy()
	maximum.MinimumKVNO = math.MaxUint32
	if _, err := keytab.ValidatePolicy(maximum); err != nil {
		t.Error("maximum unsigned key version cannot be represented in a policy")
	}
	legacy := ktPolicy()
	legacy.AllowedEnctypes, legacy.RequiredEnctypes = []uint16{23}, []uint16{23}
	if _, err := keytab.ValidatePolicy(legacy); err != nil {
		t.Error("an explicit operator choice of a recognized legacy enctype was rejected")
	}
}

func TestKeytabPolicyRejectsAmbiguousMalformedOrUnsupportedConfiguration(t *testing.T) {
	for _, source := range []string{
		"", "null", "[]", "{}", ktPolicyYAML + "---\nname: private-marker\n",
		strings.Replace(ktPolicyYAML, "name: web", "name: web\nname: private-marker", 1),
		strings.Replace(ktPolicyYAML, "name: web", "name: !private-tag web", 1),
		strings.Replace(ktPolicyYAML, "name: web", "name: &private-anchor web", 1),
		strings.Replace(ktPolicyYAML, "minimum_kvno: 3", "minimum_kvno: 3.0", 1),
		strings.Replace(ktPolicyYAML, "minimum_kvno: 3", "minimum_kvno: 0x3", 1),
		strings.Replace(ktPolicyYAML, "minimum_kvno: 3", "minimum_kvno: 4294967296", 1),
		strings.Replace(ktPolicyYAML, "components: [HTTP, app.example.test]", "components: HTTP/app.example.test", 1),
		strings.Replace(ktPolicyYAML, "realm: EXAMPLE.TEST", "realm: EXAMPLE.TEST\n  password: private-marker", 1),
		ktPolicyYAML + "key: private-marker\n",
		ktPolicyYAML + strings.Repeat(" ", keytab.MaxInputBytes),
		string([]byte{0xff, 0}),
	} {
		policy, err := keytab.LoadPolicy(strings.NewReader(source))
		if err != keytab.ErrInvalidPolicy || !reflect.DeepEqual(policy, keytab.Policy{}) {
			t.Error("invalid policy returned partial configuration or a non-static diagnostic")
		}
	}
	for _, edit := range []func(*keytab.Policy){
		func(p *keytab.Policy) { p.APIVersion = "private-marker/v2" },
		func(p *keytab.Policy) { p.Name = "Uppercase" },
		func(p *keytab.Policy) { p.Principal.Realm = "" },
		func(p *keytab.Policy) { p.Principal.Components = nil },
		func(p *keytab.Policy) { p.MinimumKVNO = 0 },
		func(p *keytab.Policy) { p.AllowedEnctypes = nil },
		func(p *keytab.Policy) { p.AllowedEnctypes = []uint16{0} },
		func(p *keytab.Policy) { p.AllowedEnctypes = []uint16{65535} },
		func(p *keytab.Policy) { p.RequiredEnctypes = []uint16{23} },
		func(p *keytab.Policy) { p.AllowedEnctypes = make([]uint16, 65) },
		func(p *keytab.Policy) { p.RequiredEnctypes = make([]uint16, 65) },
	} {
		policy := ktPolicy()
		edit(&policy)
		if _, err := keytab.ValidatePolicy(policy); err != keytab.ErrInvalidPolicy {
			t.Error("invalid policy bounds or identity were accepted")
		}
		if _, err := keytab.Validate(bytes.NewReader(ktFile(ktFixtureRecord())), policy); err != keytab.ErrInvalidPolicy {
			t.Error("invalid explicit policy silently fell back to structural validation")
		}
	}
	for _, reader := range []interface{ Read([]byte) (int, error) }{nil, ktFailingReader{}} {
		if _, err := keytab.LoadPolicy(reader); err != keytab.ErrInvalidPolicy {
			t.Error("missing or failed policy reader escaped its static diagnostic")
		}
	}
}

func TestKeytabValidationChecksTheSelectedPrincipalAndItsCurrentKeyVersion(t *testing.T) {
	older := ktFixtureRecord()
	newer := ktFixtureRecord()
	newer.kvno32 = ktNumber(4)
	otherType := newer
	otherType.enctype, otherType.key = 17, bytes.Repeat([]byte{0}, 16)
	raw := ktFile(older, newer, otherType)
	report, err := keytab.Validate(bytes.NewReader(raw), ktPolicy())
	if err != nil || !report.Valid || !report.PolicyChecked || report.AuthenticationChecked || report.HighestKVNO != 4 || report.EntryCount != 3 || report.Principal != "HTTP/app.example.test@EXAMPLE.TEST" {
		t.Fatal("valid current key version did not satisfy the explicit principal policy")
	}
	ktMetadataPrivate(t, report, raw)
	policy := ktPolicy()
	policy.AllowOtherPrincipals = true
	foreign := ktFixtureRecord()
	foreign.components = []string{"HTTP", "other.example.test"}
	if report, err := keytab.Validate(bytes.NewReader(ktFile(newer, foreign)), policy); err != nil || !report.Valid || !report.PolicyChecked || report.HighestKVNO != 4 || report.AuthenticationChecked {
		t.Error("explicitly allowed other principals changed the selected identity's policy result")
	}
	for _, test := range []struct {
		name    string
		records []ktRecord
		policy  keytab.Policy
		reason  string
	}{
		{"empty", nil, ktPolicy(), "principal_missing"},
		{"old selected entry", []ktRecord{older, newer}, func() keytab.Policy { p := ktPolicy(); p.MinimumKVNO = 4; return p }(), "kvno_too_low"},
		{"foreign principal", []ktRecord{newer, foreign}, ktPolicy(), "unexpected_principal"},
		{"missing selected principal", []ktRecord{foreign}, policy, "principal_missing"},
		{"required only in old version", []ktRecord{older, otherType}, ktPolicy(), "required_enctype_missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			report, err := keytab.Validate(bytes.NewReader(ktFile(test.records...)), test.policy)
			if err != keytab.ErrValidation || report.Valid || !report.PolicyChecked || report.AuthenticationChecked || report.Reason != test.reason {
				t.Error("policy validation ignored a selected principal, old KVNO or highest-version enctype requirement")
			}
			ktMetadataPrivate(t, report, ktFile(test.records...))
		})
	}
}

func TestKeytabValidationKeepsLegacyUnknownAndStructuralModesExplicit(t *testing.T) {
	legacy := ktFixtureRecord()
	legacy.enctype, legacy.key = 23, bytes.Repeat([]byte{0xff}, 16)
	policy := ktPolicy()
	policy.AllowedEnctypes, policy.RequiredEnctypes = []uint16{23}, []uint16{23}
	if report, err := keytab.Validate(bytes.NewReader(ktFile(legacy)), policy); err != nil || !report.Valid || report.AuthenticationChecked {
		t.Error("explicit recognized legacy policy did not remain an operator choice")
	}
	unknown := ktFixtureRecord()
	unknown.enctype = 65535
	for _, record := range []ktRecord{legacy, unknown} {
		if report, err := keytab.Validate(bytes.NewReader(ktFile(record)), ktPolicy()); err != keytab.ErrValidation || report.Reason != "enctype_not_allowed" || report.Valid {
			t.Error("unexpected legacy or unknown enctype passed the requested policy")
		}
		if report, err := keytab.Validate(bytes.NewReader(ktFile(record)), keytab.Policy{}); err != nil || !report.Valid || report.PolicyChecked || report.AuthenticationChecked {
			t.Error("structural validation silently imposed or claimed an authentication policy")
		}
	}
	if report, err := keytab.Validate(bytes.NewReader([]byte{5, 2}), keytab.Policy{}); err != nil || !report.Valid || report.PolicyChecked || report.AuthenticationChecked || report.EntryCount != 0 {
		t.Error("empty keytab structural validation invented an identity requirement")
	}
}

func TestKeytabValidationForeignHigherKVNOCannotChangeSelectedRequirements(t *testing.T) {
	policy := ktPolicy()
	policy.AllowOtherPrincipals = true
	selected := ktFixtureRecord()
	selected.kvno32 = ktNumber(4)
	foreign := ktFixtureRecord()
	foreign.components = []string{"HTTP", "other.example.test"}
	foreign.kvno32 = ktNumber(99)
	if report, err := keytab.Validate(bytes.NewReader(ktFile(selected, foreign)), policy); err != nil || !report.Valid || report.HighestKVNO != 4 || report.AuthenticationChecked {
		t.Fatal("foreign higher KVNO changed the selected principal's current version")
	}
	selected.enctype, selected.key = 17, bytes.Repeat([]byte{0}, 16)
	if report, err := keytab.Validate(bytes.NewReader(ktFile(selected, foreign)), policy); err != keytab.ErrValidation || report.Valid || report.HighestKVNO != 4 || report.Reason != "required_enctype_missing" || report.AuthenticationChecked {
		t.Fatal("foreign higher KVNO supplied an enctype missing from the selected principal")
	}
}

func TestKeytabValidationDetectsDuplicateMetadataWithoutComparingKeys(t *testing.T) {
	first := ktFixtureRecord()
	second := first
	second.nameType = 1
	second.key = bytes.Repeat([]byte{0xff}, 32)
	raw := ktFile(first, second)
	if report, err := keytab.Inspect(bytes.NewReader(raw)); err != nil || len(report.Entries) != 2 {
		t.Fatal("ambiguous duplicate entries cannot be inspected")
	}
	for _, policy := range []keytab.Policy{{}, ktPolicy()} {
		report, err := keytab.Validate(bytes.NewReader(raw), policy)
		if err != keytab.ErrValidation || report.Valid || report.Reason != "duplicate_entry" || report.AuthenticationChecked {
			t.Error("duplicate principal/KVNO/enctype was hidden by key or name-type differences")
		}
		ktMetadataPrivate(t, report, raw)
	}
	for _, changed := range []ktRecord{
		func() ktRecord { r := first; r.realm = "example.test"; return r }(),
		func() ktRecord { r := first; r.components = []string{"http", "app.example.test"}; return r }(),
	} {
		policy := ktPolicy()
		policy.AllowOtherPrincipals = true
		if report, err := keytab.Validate(bytes.NewReader(ktFile(changed)), policy); err != keytab.ErrValidation || report.Reason != "principal_missing" {
			t.Error("case normalization conflated a different Kerberos identity")
		}
	}
}
