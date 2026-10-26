// Package configuration reads strict, bounded YAML/JSON without domain or network dependencies.
package configuration

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

const MaxInputBytes = 1 << 20
const MaxDepth = 64
const MaxNodes = 10000
const MaxStringBytes = 128 << 10

var ErrInvalidConfiguration = errors.New("invalid or oversized configuration document")
var decimalInteger = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

func DecodeObject(input io.Reader) (map[string]any, error) {
	value, err := Decode(input)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, ErrInvalidConfiguration
	}
	return object, nil
}

func Decode(input io.Reader) (any, error) {
	if input == nil {
		return nil, ErrInvalidConfiguration
	}
	body, err := io.ReadAll(io.LimitReader(input, MaxInputBytes+1))
	if err != nil || len(body) > MaxInputBytes || !utf8.Valid(body) || bytes.IndexByte(body, 0) >= 0 {
		return nil, ErrInvalidConfiguration
	}
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil || document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return nil, ErrInvalidConfiguration
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidConfiguration
	}
	count := 0
	return yamlJSONValue(document.Content[0], 0, &count)
}

func yamlJSONValue(node *yaml.Node, depth int, count *int) (any, error) {
	*count = *count + 1
	if node == nil || depth > MaxDepth || *count > MaxNodes || node.Anchor != "" || node.Alias != nil || node.Kind == yaml.AliasNode {
		return nil, ErrInvalidConfiguration
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.Tag != "!!map" || len(node.Content)%2 != 0 {
			return nil, ErrInvalidConfiguration
		}
		result := make(map[string]any, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			keyNode := node.Content[index]
			*count = *count + 1
			if *count > MaxNodes || keyNode.Kind != yaml.ScalarNode || keyNode.Tag != "!!str" || keyNode.Anchor != "" || keyNode.Alias != nil || !validString(keyNode.Value) {
				return nil, ErrInvalidConfiguration
			}
			if _, duplicate := result[keyNode.Value]; duplicate {
				return nil, ErrInvalidConfiguration
			}
			value, err := yamlJSONValue(node.Content[index+1], depth+1, count)
			if err != nil {
				return nil, ErrInvalidConfiguration
			}
			result[keyNode.Value] = value
		}
		return result, nil
	case yaml.SequenceNode:
		if node.Tag != "!!seq" {
			return nil, ErrInvalidConfiguration
		}
		result := make([]any, 0, len(node.Content))
		for _, child := range node.Content {
			value, err := yamlJSONValue(child, depth+1, count)
			if err != nil {
				return nil, ErrInvalidConfiguration
			}
			result = append(result, value)
		}
		return result, nil
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!str":
			if !validString(node.Value) {
				return nil, ErrInvalidConfiguration
			}
			return node.Value, nil
		case "!!int":
			if !decimalInteger.MatchString(node.Value) {
				return nil, ErrInvalidConfiguration
			}
			if _, err := strconv.ParseInt(node.Value, 10, 64); err != nil {
				return nil, ErrInvalidConfiguration
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
	return nil, ErrInvalidConfiguration
}

func validString(value string) bool {
	return len(value) <= MaxStringBytes && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}
