package architecture

import (
	"bytes"
	"sync"

	"github.com/ml0renz0/secretwright/schemas"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const schemaID = "urn:secretwright:architecture:v1"

var (
	schemaOnce  sync.Once
	fullSchema  *jsonschema.Schema
	schemaError error
)

type denySchemaLoader struct{}

func (denySchemaLoader) Load(string) (any, error) {
	return nil, ErrInvalidTemplate
}

// Schema returns the exact versioned artifact embedded in the binary.
func Schema() []byte {
	return schemas.ArchitectureV1()
}

func validateSchema(value any) error {
	schemaOnce.Do(func() {
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(Schema()))
		if err != nil {
			schemaError = ErrInvalidTemplate
			return
		}
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.UseLoader(denySchemaLoader{})
		if compiler.AddResource(schemaID, document) != nil {
			schemaError = ErrInvalidTemplate
			return
		}
		fullSchema, err = compiler.Compile(schemaID)
		if err != nil {
			schemaError = ErrInvalidTemplate
		}
	})
	if schemaError != nil || fullSchema == nil || fullSchema.Validate(value) != nil {
		// Library diagnostics may include input values or rejected fragments.
		return ErrInvalidTemplate
	}
	return nil
}
