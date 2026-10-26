package blueprint

import (
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/ml0renz0/secretwright/internal/configuration"
)

var decimalInteger = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// DecodeConfiguration shares the bounded, JSON-compatible YAML reader with
// offline configuration formats that validate their own versioned schema.
// It does not expand variables, read external references, or access Vault.
func DecodeConfiguration(input io.Reader) (map[string]any, error) {
	value, err := readDocument(input)
	if err != nil {
		return nil, ErrInvalidBlueprint
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, ErrInvalidBlueprint
	}
	return object, nil
}

// Load accepts one bounded YAML or JSON document. It never loads includes,
// environment values, external schemas, functions, or Vault secret data.
func Load(input io.Reader, overrides io.Reader) (Document, error) {
	value, err := readDocument(input)
	if err != nil {
		return Document{}, ErrInvalidBlueprint
	}
	object, ok := value.(map[string]any)
	if !ok || validateSchema(object, true) != nil {
		return Document{}, ErrInvalidBlueprint
	}
	var supplied map[string]any
	if overrides != nil {
		value, err := readDocument(overrides)
		if err != nil {
			return Document{}, ErrInvalidBlueprint
		}
		supplied, ok = value.(map[string]any)
		if !ok {
			return Document{}, ErrInvalidBlueprint
		}
	}
	variables, err := resolveVariables(object["variables"], supplied)
	if err != nil {
		return Document{}, ErrInvalidBlueprint
	}
	if err := expandDocument(object, variables); err != nil {
		return Document{}, ErrInvalidBlueprint
	}
	if err := validateSchema(object, false); err != nil {
		return Document{}, ErrInvalidBlueprint
	}
	document, err := documentFromObject(object)
	if err != nil {
		return Document{}, ErrInvalidBlueprint
	}
	return ValidateDocument(document)
}

func readDocument(input io.Reader) (any, error) {
	value, err := configuration.Decode(input)
	if err != nil {
		return nil, ErrInvalidBlueprint
	}
	return value, nil
}

func validString(value string) bool {
	return len(value) <= MaxStringBytes && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

func documentFromObject(object map[string]any) (Document, error) {
	version, versionOK := object["api_version"].(string)
	name, nameOK := object["name"].(string)
	resources, resourcesOK := object["resources"].([]any)
	if !versionOK || !nameOK || !resourcesOK {
		return Document{}, ErrInvalidBlueprint
	}
	document := Document{APIVersion: version, Name: name, Resources: make([]Resource, 0, len(resources))}
	for _, value := range resources {
		item, ok := value.(map[string]any)
		if !ok {
			return Document{}, ErrInvalidBlueprint
		}
		id, idOK := item["id"].(string)
		kind, kindOK := item["kind"].(string)
		name, nameOK := item["name"].(string)
		spec, specOK := item["spec"].(map[string]any)
		if !idOK || !kindOK || !nameOK || !specOK {
			return Document{}, ErrInvalidBlueprint
		}
		dependencies, err := stringValues(item["depends_on"])
		if err != nil {
			return Document{}, err
		}
		document.Resources = append(document.Resources, Resource{ID: id, Kind: kind, Name: name, DependsOn: dependencies, Spec: spec})
	}
	return document, nil
}

func stringValues(value any) ([]string, error) {
	if value == nil {
		return []string{}, nil
	}
	values, ok := value.([]any)
	if !ok {
		return nil, ErrInvalidBlueprint
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil, ErrInvalidBlueprint
		}
		result = append(result, text)
	}
	return result, nil
}
