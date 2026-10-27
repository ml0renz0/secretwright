package keytab

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"sync"

	"github.com/ml0renz0/secretwright/internal/configuration"
	"github.com/ml0renz0/secretwright/schemas"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const schemaID = "urn:secretwright:keytab:v1"

var resourceName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
var schemaOnce sync.Once
var compiledSchema *jsonschema.Schema
var schemaError error

type denySchemaLoader struct{}

func (denySchemaLoader) Load(string) (any, error) { return nil, ErrInvalidPolicy }

// Schema returns the published policy schema without sharing mutable storage.
func Schema() []byte { return schemas.KeytabV1() }

func validateSchema(value any) error {
	schemaOnce.Do(func() {
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(Schema()))
		if err != nil {
			schemaError = ErrInvalidPolicy
			return
		}
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.UseLoader(denySchemaLoader{})
		if compiler.AddResource(schemaID, document) != nil {
			schemaError = ErrInvalidPolicy
			return
		}
		compiledSchema, err = compiler.Compile(schemaID)
		if err != nil {
			schemaError = ErrInvalidPolicy
		}
	})
	if schemaError != nil || compiledSchema == nil || compiledSchema.Validate(value) != nil {
		return ErrInvalidPolicy
	}
	return nil
}

func enctypeSet(values []uint16) []uint16 {
	unique := make(map[uint16]struct{}, len(values))
	for _, value := range values {
		unique[value] = struct{}{}
	}
	result := make([]uint16, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Slice(result, func(first, second int) bool { return result[first] < result[second] })
	return result
}

// ValidatePolicy detaches and normalizes sets while preserving exact principal
// spelling. A legacy enctype is accepted only through an explicit policy.
func ValidatePolicy(policy Policy) (Policy, error) {
	if policy.APIVersion != APIVersion || !resourceName.MatchString(policy.Name) || policy.MinimumKVNO == 0 || len(policy.AllowedEnctypes) == 0 || len(policy.AllowedEnctypes) > 64 || len(policy.RequiredEnctypes) > 64 {
		return Policy{}, ErrInvalidPolicy
	}
	if _, err := CanonicalPrincipal(policy.Principal.Realm, policy.Principal.Components); err != nil {
		return Policy{}, ErrInvalidPolicy
	}
	allowed := make(map[uint16]bool, len(policy.AllowedEnctypes))
	for _, value := range policy.AllowedEnctypes {
		if _, known := knownEnctype(value); !known {
			return Policy{}, ErrInvalidPolicy
		}
		allowed[value] = true
	}
	for _, value := range policy.RequiredEnctypes {
		if !allowed[value] {
			return Policy{}, ErrInvalidPolicy
		}
	}
	policy.Principal.Components = append([]string(nil), policy.Principal.Components...)
	policy.AllowedEnctypes = enctypeSet(policy.AllowedEnctypes)
	policy.RequiredEnctypes = enctypeSet(policy.RequiredEnctypes)
	return policy, nil
}

// LoadPolicy accepts strict, bounded YAML or JSON and returns static errors.
func LoadPolicy(input io.Reader) (Policy, error) {
	object, err := configuration.DecodeObject(input)
	if err != nil || validateSchema(object) != nil {
		return Policy{}, ErrInvalidPolicy
	}
	body, err := json.Marshal(object)
	var policy Policy
	if err != nil || json.Unmarshal(body, &policy) != nil {
		return Policy{}, ErrInvalidPolicy
	}
	return ValidatePolicy(policy)
}

func noPolicy(policy Policy) bool {
	return policy.APIVersion == "" && policy.Name == "" && policy.Principal.Realm == "" && policy.Principal.Components == nil && policy.MinimumKVNO == 0 && policy.AllowedEnctypes == nil && policy.RequiredEnctypes == nil && !policy.AllowOtherPrincipals
}

type entryIdentity struct {
	principal string
	kvno      uint32
	enctype   uint16
}

// Validate checks structure and metadata only; it never verifies keys with a
// KDC. Required enctypes must belong to the selected principal's highest KVNO.
func Validate(input io.Reader, policy Policy) (ValidationReport, error) {
	checked := !noPolicy(policy)
	if checked {
		var err error
		policy, err = ValidatePolicy(policy)
		if err != nil {
			return ValidationReport{}, ErrInvalidPolicy
		}
	}
	inspected, err := Inspect(input)
	if err != nil {
		return ValidationReport{}, ErrInvalidInput
	}
	report := ValidationReport{PolicyChecked: checked, EntryCount: len(inspected.Entries)}
	if checked {
		report.Principal, _ = CanonicalPrincipal(policy.Principal.Realm, policy.Principal.Components)
	}
	fail := func(reason string) (ValidationReport, error) {
		report.Reason = reason
		return report, ErrValidation
	}
	seen := make(map[entryIdentity]struct{}, len(inspected.Entries))
	selected := make([]EntryReport, 0, len(inspected.Entries))
	foreign := false
	for _, entry := range inspected.Entries {
		identity := entryIdentity{entry.Principal, entry.KVNO, entry.Enctype}
		if _, exists := seen[identity]; exists {
			return fail("duplicate_entry")
		}
		seen[identity] = struct{}{}
		if checked && !samePrincipal(policy.Principal, PrincipalSpec{Realm: entry.Realm, Components: entry.Components}) {
			foreign = true
			continue
		}
		selected = append(selected, entry)
		if entry.KVNO > report.HighestKVNO {
			report.HighestKVNO = entry.KVNO
		}
	}
	if !checked {
		report.Valid = true
		return report, nil
	}
	if len(selected) == 0 {
		return fail("principal_missing")
	}
	if foreign && !policy.AllowOtherPrincipals {
		return fail("unexpected_principal")
	}
	allowed := make(map[uint16]bool, len(policy.AllowedEnctypes))
	for _, value := range policy.AllowedEnctypes {
		allowed[value] = true
	}
	current := make(map[uint16]bool)
	for _, entry := range selected {
		if entry.KVNO < policy.MinimumKVNO {
			return fail("kvno_too_low")
		}
		if !allowed[entry.Enctype] {
			return fail("enctype_not_allowed")
		}
		if entry.KVNO == report.HighestKVNO {
			current[entry.Enctype] = true
		}
	}
	for _, value := range policy.RequiredEnctypes {
		if !current[value] {
			return fail("required_enctype_missing")
		}
	}
	report.Valid = true
	return report, nil
}

// Example returns a fresh JSON policy; the CLI renders YAML by default.
func Example() []byte {
	policy := Policy{
		APIVersion: APIVersion, Name: "web",
		Principal: PrincipalSpec{Realm: "EXAMPLE.TEST", Components: []string{"HTTP", "app.example.test"}},
		MinimumKVNO: 3, AllowedEnctypes: []uint16{17, 18, 19, 20}, RequiredEnctypes: []uint16{18},
	}
	body, _ := json.MarshalIndent(policy, "", "  ")
	return append(body, '\n')
}
