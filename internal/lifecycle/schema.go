package lifecycle

import (
	"bytes"
	"sync"

	"github.com/ml0renz0/secretwright/schemas"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const lifecycleSchemaID = "urn:secretwright:lifecycle:v1"

var lifecycleSchemaOnce sync.Once
var lifecycleSchema *jsonschema.Schema
var lifecycleSchemaErr error

type lifecycleSchemaLoader struct{}

func (lifecycleSchemaLoader) Load(string) (any, error) { return nil, ErrInvalidLifecycle }

func Schema() []byte { return schemas.LifecycleV1() }

func validateSchema(value any) error {
	lifecycleSchemaOnce.Do(func() {
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(Schema()))
		if err != nil {
			lifecycleSchemaErr = ErrInvalidLifecycle
			return
		}
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.UseLoader(lifecycleSchemaLoader{})
		if compiler.AddResource(lifecycleSchemaID, document) != nil {
			lifecycleSchemaErr = ErrInvalidLifecycle
			return
		}
		lifecycleSchema, err = compiler.Compile(lifecycleSchemaID)
		if err != nil {
			lifecycleSchemaErr = ErrInvalidLifecycle
		}
	})
	if lifecycleSchemaErr != nil || lifecycleSchema == nil || lifecycleSchema.Validate(value) != nil {
		return ErrInvalidLifecycle
	}
	return nil
}
