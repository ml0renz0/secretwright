// Package fileformat encodes generated configuration without expanding data,
// reading references, or changing the JSON APIs used by domain packages.
package fileformat

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Format selects the encoding of a generated configuration file.
type Format string

const (
	YAML Format = "yaml"
	JSON Format = "json"
)

const maxInputBytes = 4 * 1024 * 1024

// ErrInvalidFormat never contains a format name or document contents.
var ErrInvalidFormat = errors.New("invalid file format or configuration document")

// Parse accepts the supported formats and defaults to YAML when unspecified.
func Parse(value string) (Format, error) {
	switch value {
	case "", string(YAML):
		return YAML, nil
	case string(JSON):
		return JSON, nil
	default:
		return "", ErrInvalidFormat
	}
}

// EncodeJSON validates one bounded JSON document and renders it in the selected
// format. JSON numbers remain exact; YAML integers must fit into int64, as
// required by the configuration readers. The input bytes are never modified.
func EncodeJSON(body []byte, format Format) ([]byte, error) {
	selected, err := Parse(string(format))
	if err != nil || len(body) > maxInputBytes || !utf8.Valid(body) || bytes.IndexByte(body, 0) >= 0 {
		return nil, ErrInvalidFormat
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, ErrInvalidFormat
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidFormat
	}
	value, err = configurationValue(value, selected == YAML)
	if err != nil {
		return nil, ErrInvalidFormat
	}
	if selected == JSON {
		encoded, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return nil, ErrInvalidFormat
		}
		return append(encoded, '\n'), nil
	}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(value); err != nil {
		_ = encoder.Close()
		return nil, ErrInvalidFormat
	}
	if err := encoder.Close(); err != nil {
		return nil, ErrInvalidFormat
	}
	return output.Bytes(), nil
}

func configurationValue(value any, yamlOutput bool) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			if !validString(key) {
				return nil, ErrInvalidFormat
			}
			normalized, err := configurationValue(child, yamlOutput)
			if err != nil {
				return nil, ErrInvalidFormat
			}
			result[key] = normalized
		}
		return result, nil
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			normalized, err := configurationValue(child, yamlOutput)
			if err != nil {
				return nil, ErrInvalidFormat
			}
			result[index] = normalized
		}
		return result, nil
	case json.Number:
		if yamlOutput {
			integer, err := typed.Int64()
			if err != nil {
				return nil, ErrInvalidFormat
			}
			return integer, nil
		}
		return typed, nil
	case string:
		if !validString(typed) {
			return nil, ErrInvalidFormat
		}
		return typed, nil
	case bool, nil:
		return typed, nil
	default:
		return nil, ErrInvalidFormat
	}
}

func validString(value string) bool {
	return utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}
