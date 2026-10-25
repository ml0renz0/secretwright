package blueprint

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

var variableName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

func resolveVariables(declaration any, supplied map[string]any) (map[string]any, error) {
	declarations := map[string]any{}
	if declaration != nil {
		var ok bool
		declarations, ok = declaration.(map[string]any)
		if !ok || len(declarations) > MaxVariables {
			return nil, ErrInvalidBlueprint
		}
	}
	for key := range supplied {
		if _, exists := declarations[key]; !exists {
			return nil, ErrInvalidBlueprint
		}
	}
	result := make(map[string]any, len(declarations))
	for key, value := range declarations {
		definition, ok := value.(map[string]any)
		if !ok || !variableName.MatchString(key) {
			return nil, ErrInvalidBlueprint
		}
		kind, ok := definition["type"].(string)
		if !ok {
			return nil, ErrInvalidBlueprint
		}
		actual, suppliedValue := supplied[key]
		if !suppliedValue {
			var exists bool
			actual, exists = definition["default"]
			if !exists {
				return nil, ErrInvalidBlueprint
			}
		}
		if !variableTypeMatches(kind, actual) {
			return nil, ErrInvalidBlueprint
		}
		result[key] = actual
	}
	return result, nil
}

func variableTypeMatches(kind string, value any) bool {
	switch kind {
	case "string":
		text, ok := value.(string)
		return ok && len(text) <= MaxVariableBytes && validString(text)
	case "integer":
		number, ok := value.(json.Number)
		if !ok || !decimalInteger.MatchString(number.String()) {
			return false
		}
		_, err := strconv.ParseInt(number.String(), 10, 64)
		return err == nil
	case "boolean":
		_, ok := value.(bool)
		return ok
	}
	return false
}

type expansion struct {
	variables map[string]any
	bytes     int
}

func expandDocument(object map[string]any, variables map[string]any) error {
	expansion := expansion{variables: variables}
	name, ok := object["name"].(string)
	if !ok {
		return ErrInvalidBlueprint
	}
	expanded, err := expansion.text(name)
	if err != nil {
		return err
	}
	object["name"] = expanded
	resources, ok := object["resources"].([]any)
	if !ok {
		return ErrInvalidBlueprint
	}
	for _, value := range resources {
		resource, ok := value.(map[string]any)
		if !ok {
			return ErrInvalidBlueprint
		}
		name, ok := resource["name"].(string)
		if !ok {
			return ErrInvalidBlueprint
		}
		expanded, err := expansion.text(name)
		if err != nil {
			return err
		}
		resource["name"] = expanded
		resource["spec"], err = expansion.value(resource["spec"])
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *expansion) value(value any) (any, error) {
	switch value := value.(type) {
	case string:
		return e.text(value)
	case []any:
		result := make([]any, len(value))
		for index, item := range value {
			expanded, err := e.value(item)
			if err != nil {
				return nil, err
			}
			result[index] = expanded
		}
		return result, nil
	case map[string]any:
		result := make(map[string]any, len(value))
		for key, item := range value {
			expanded, err := e.value(item)
			if err != nil {
				return nil, err
			}
			result[key] = expanded
		}
		return result, nil
	default:
		return value, nil
	}
}

func (e *expansion) text(text string) (any, error) {
	if strings.HasPrefix(text, "${") && strings.HasSuffix(text, "}") && strings.Count(text, "${") == 1 {
		expression := text[2 : len(text)-1]
		if key, ok := strings.CutPrefix(expression, "var."); ok && variableName.MatchString(key) {
			value, exists := e.variables[key]
			if !exists {
				return nil, ErrInvalidBlueprint
			}
			if actual, ok := value.(string); ok {
				if err := e.account(actual); err != nil {
					return nil, err
				}
			}
			// Return the value directly. Its contents are data and must never
			// undergo a second interpolation pass.
			return value, nil
		}
	}
	var output strings.Builder
	remaining := text
	for {
		start := strings.Index(remaining, "${")
		if start < 0 {
			if output.Len() > MaxStringBytes-len(remaining) {
				return nil, ErrInvalidBlueprint
			}
			output.WriteString(remaining)
			break
		}
		end := strings.IndexByte(remaining[start+2:], '}')
		if end < 0 {
			return nil, ErrInvalidBlueprint
		}
		end += start + 2
		expression := remaining[start+2 : end]
		key, ok := strings.CutPrefix(expression, "var.")
		if !ok || !variableName.MatchString(key) {
			return nil, ErrInvalidBlueprint
		}
		value, exists := e.variables[key]
		actual, stringValue := value.(string)
		if !exists || !stringValue || output.Len() > MaxStringBytes-start || output.Len()+start > MaxStringBytes-len(actual) {
			return nil, ErrInvalidBlueprint
		}
		output.WriteString(remaining[:start])
		output.WriteString(actual)
		remaining = remaining[end+1:]
	}
	result := output.String()
	if err := e.account(result); err != nil {
		return nil, err
	}
	return result, nil
}

func (e *expansion) account(value string) error {
	if !validString(value) || len(value) > MaxExpandedBytes-e.bytes {
		return ErrInvalidBlueprint
	}
	e.bytes += len(value)
	return nil
}
