package blueprint

import (
	"bytes"
	"sync"

	"github.com/ml0renz0/secretwright/schemas"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const schemaID = "urn:secretwright:blueprint:v1"

var (
	schemaOnce     sync.Once
	fullSchema     *jsonschema.Schema
	envelopeSchema *jsonschema.Schema
	schemaError    error
)

type denySchemaLoader struct{}

func (denySchemaLoader) Load(string) (any, error) {
	return nil, ErrInvalidBlueprint
}

// Schema exposes the exact embedded, versioned artifact without accessing a
// user-selected URL, filesystem schema or remote reference.
func Schema() []byte {
	return schemas.BlueprintV1()
}

func validateSchema(value any, envelope bool) error {
	schemaOnce.Do(func() {
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(Schema()))
		if err != nil {
			schemaError = ErrInvalidBlueprint
			return
		}
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.UseLoader(denySchemaLoader{})
		if err := compiler.AddResource(schemaID, document); err != nil {
			schemaError = ErrInvalidBlueprint
			return
		}
		fullSchema, err = compiler.Compile(schemaID)
		if err != nil {
			schemaError = ErrInvalidBlueprint
			return
		}
		envelopeSchema, err = compiler.Compile(schemaID + "#/$defs/envelope")
		if err != nil {
			schemaError = ErrInvalidBlueprint
		}
	})
	if schemaError != nil {
		return ErrInvalidBlueprint
	}
	selected := fullSchema
	if envelope {
		selected = envelopeSchema
	}
	if selected == nil || selected.Validate(value) != nil {
		// Library errors can contain rejected values and document fragments.
		return ErrInvalidBlueprint
	}
	return nil
}
