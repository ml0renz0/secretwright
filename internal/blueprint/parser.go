package blueprint

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

var decimalInteger = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

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
	if input == nil {
		return nil, ErrInvalidBlueprint
	}
	body, err := io.ReadAll(io.LimitReader(input, MaxInputBytes+1))
	if err != nil || len(body) > MaxInputBytes || !utf8.Valid(body) || bytes.IndexByte(body, 0) >= 0 {
		return nil, ErrInvalidBlueprint
	}
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil || document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return nil, ErrInvalidBlueprint
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidBlueprint
	}
	count := 0
	return yamlJSONValue(document.Content[0], 0, &count)
}

func yamlJSONValue(node *yaml.Node, depth int, count *int) (any, error) {
	*count = *count + 1
	if node == nil || depth > MaxDepth || *count > MaxNodes || node.Anchor != "" || node.Alias != nil || node.Kind == yaml.AliasNode {
		return nil, ErrInvalidBlueprint
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.Tag != "!!map" || len(node.Content)%2 != 0 {
			return nil, ErrInvalidBlueprint
		}
		result := make(map[string]any, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			keyNode := node.Content[index]
			*count = *count + 1
			if *count > MaxNodes || keyNode.Kind != yaml.ScalarNode || keyNode.Tag != "!!str" || keyNode.Anchor != "" || keyNode.Alias != nil || !validString(keyNode.Value) {
				return nil, ErrInvalidBlueprint
			}
			if _, duplicate := result[keyNode.Value]; duplicate {
				return nil, ErrInvalidBlueprint
			}
			value, err := yamlJSONValue(node.Content[index+1], depth+1, count)
			if err != nil {
				return nil, ErrInvalidBlueprint
			}
			result[keyNode.Value] = value
		}
		return result, nil
	case yaml.SequenceNode:
		if node.Tag != "!!seq" {
			return nil, ErrInvalidBlueprint
		}
		result := make([]any, 0, len(node.Content))
		for _, child := range node.Content {
			value, err := yamlJSONValue(child, depth+1, count)
			if err != nil {
				return nil, ErrInvalidBlueprint
			}
			result = append(result, value)
		}
		return result, nil
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!str":
			if !validString(node.Value) {
				return nil, ErrInvalidBlueprint
			}
			return node.Value, nil
		case "!!int":
			if !decimalInteger.MatchString(node.Value) {
				return nil, ErrInvalidBlueprint
			}
			if _, err := strconv.ParseInt(node.Value, 10, 64); err != nil {
				return nil, ErrInvalidBlueprint
			}
			return json.Number(node.Value), nil
		case "!!bool":
			switch node.Value {
			case "true", "True", "TRUE":
				return true, nil
			case "false", "False", "FALSE":
				return false, nil
			}
		case "!!null":
			return nil, nil
		}
	}
	return nil, ErrInvalidBlueprint
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
