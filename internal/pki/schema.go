package pki

import (
	"bytes"
	"sync"

	"github.com/ml0renz0/secretwright/schemas"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const schemaID = "urn:secretwright:pki:v1"

var schemaOnce sync.Once
var compiledSchema *jsonschema.Schema
var schemaError error

type denySchemaLoader struct{}

func (denySchemaLoader) Load(string) (any, error) { return nil, ErrInvalidInput }

func Schema() []byte { return schemas.PKIV1() }

func validateSchema(value any) error {
	schemaOnce.Do(func() {
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(Schema()))
		if err != nil {
			schemaError = ErrInvalidInput
			return
		}
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.UseLoader(denySchemaLoader{})
		if compiler.AddResource(schemaID, document) != nil {
			schemaError = ErrInvalidInput
			return
		}
		compiledSchema, err = compiler.Compile(schemaID)
		if err != nil {
			schemaError = ErrInvalidInput
		}
	})
	if schemaError != nil || compiledSchema == nil || compiledSchema.Validate(value) != nil {
		return ErrInvalidInput
	}
	return nil
}
