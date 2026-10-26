package fileformat_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ml0renz0/secretwright/internal/fileformat"
	"gopkg.in/yaml.v3"
)

func TestParseSelectsYAMLByDefaultAndOnlyAcceptsKnownFormats(t *testing.T) {
	for _, test := range []struct {
		input string
		want  fileformat.Format
	}{
		{"", fileformat.YAML}, {"yaml", fileformat.YAML}, {"json", fileformat.JSON},
	} {
		got, err := fileformat.Parse(test.input)
		if err != nil || got != test.want {
			t.Error("format parsing did not honor the YAML default or explicit format")
		}
	}
	for _, value := range []string{"YAML", "yml", "JSON", " yaml", "json ", "private-unknown-format"} {
		got, err := fileformat.Parse(value)
		if got != "" || !errors.Is(err, fileformat.ErrInvalidFormat) || err.Error() != fileformat.ErrInvalidFormat.Error() || strings.Contains(err.Error(), value) {
			t.Error("unknown format was accepted or disclosed through its error")
		}
	}
}

func TestEncodeJSONPreservesYAMLTypesIntegerPrecisionAndReadableHCL(t *testing.T) {
	const hcl = "path \"secret/data/payments/*\" {\n  capabilities = [\"read\"]\n}\n"
	input, err := json.Marshal(map[string]any{
		"minimum": json.Number("-9223372036854775808"),
		"maximum": json.Number("9223372036854775807"),
		"nested":  map[string]any{"active": true, "disabled": false, "nothing": nil},
		"strings": []string{"true", "false", "null", "01", "on", "2026-10-26"},
		"policy":  hcl,
	})
	if err != nil {
		t.Fatal("could not prepare JSON fixture")
	}
	original := bytes.Clone(input)
	body, err := fileformat.EncodeJSON(input, fileformat.YAML)
	if err != nil || !bytes.Equal(input, original) || !bytes.HasSuffix(body, []byte("\n")) || bytes.HasSuffix(body, []byte("\n\n")) {
		t.Fatal("YAML conversion failed, mutated input, or omitted its final newline")
	}
	var output struct {
		Minimum int64 `yaml:"minimum"`
		Maximum int64 `yaml:"maximum"`
		Nested  struct {
			Active   bool `yaml:"active"`
			Disabled bool `yaml:"disabled"`
			Nothing  any  `yaml:"nothing"`
		} `yaml:"nested"`
		Strings []string `yaml:"strings"`
		Policy  string   `yaml:"policy"`
	}
	if yaml.Unmarshal(body, &output) != nil || output.Minimum != -9223372036854775808 || output.Maximum != 9223372036854775807 || !output.Nested.Active || output.Nested.Disabled || output.Nested.Nothing != nil || !reflect.DeepEqual(output.Strings, []string{"true", "false", "null", "01", "on", "2026-10-26"}) || output.Policy != hcl {
		t.Fatal("YAML output changed integer precision, scalar types, or policy contents")
	}
	var document yaml.Node
	if yaml.Unmarshal(body, &document) != nil || len(document.Content) != 1 {
		t.Fatal("could not inspect emitted YAML types")
	}
	root := document.Content[0]
	fields := make(map[string]*yaml.Node)
	for index := 0; index < len(root.Content); index += 2 {
		fields[root.Content[index].Value] = root.Content[index+1]
	}
	if fields["minimum"].Tag != "!!int" || fields["maximum"].Tag != "!!int" || fields["policy"].Style != yaml.LiteralStyle {
		t.Error("YAML emitted an integer as text or escaped a multiline policy instead of using a literal block")
	}
	for _, scalar := range fields["strings"].Content {
		if scalar.Tag != "!!str" {
			t.Error("YAML changed an ambiguous string into another scalar type")
		}
	}
	if !bytes.Contains(body, []byte("nested:\n  active: true\n  disabled: false\n  nothing: null\n")) {
		t.Error("YAML nested mappings did not use two-space indentation")
	}
}

func TestEncodeJSONProducesDeterministicFormattedDocumentsWithoutMutatingInput(t *testing.T) {
	first := []byte(`{"z":[9007199254740993,false,null],"a":{"name":"payments"}}`)
	second := []byte(" { \"a\" : {\"name\":\"payments\"}, \"z\": [9007199254740993, false, null] } \n\t")
	for _, format := range []fileformat.Format{fileformat.YAML, fileformat.JSON} {
		original := bytes.Clone(first)
		body, err := fileformat.EncodeJSON(first, format)
		other, otherErr := fileformat.EncodeJSON(second, format)
		if err != nil || otherErr != nil || !bytes.Equal(body, other) || !bytes.Equal(first, original) || !bytes.HasSuffix(body, []byte("\n")) {
			t.Error("equivalent JSON input did not produce stable, complete output without mutation")
		}
		if format == fileformat.JSON {
			want := "{\n  \"a\": {\n    \"name\": \"payments\"\n  },\n  \"z\": [\n    9007199254740993,\n    false,\n    null\n  ]\n}\n"
			if string(body) != want {
				t.Error("JSON output lost integer precision, deterministic key order, or two-space formatting")
			}
		}
	}
}

func TestEncodeJSONRejectsInvalidInputWithOneStaticErrorAndNoPartialOutput(t *testing.T) {
	for _, input := range [][]byte{
		nil, []byte(" "), []byte("private-invalid-json"), []byte(`{"private-input":`),
		[]byte(`{"name":"one"} {"private-input":"two"}`), []byte("{}\n---\n{}"),
		[]byte("{\"name\":\"private-\xff-input\"}"), []byte("{\"name\":\"private-\x00-input\"}"),
		[]byte(`{"name":"private-\u0000-input"}`), []byte(`{"name":"` + strings.Repeat("x", 4*1024*1024) + `"}`),
	} {
		for _, format := range []fileformat.Format{fileformat.YAML, fileformat.JSON} {
			original := bytes.Clone(input)
			body, err := fileformat.EncodeJSON(input, format)
			if len(body) != 0 || !errors.Is(err, fileformat.ErrInvalidFormat) || err.Error() != fileformat.ErrInvalidFormat.Error() || strings.Contains(err.Error(), "private-") || !bytes.Equal(input, original) {
				t.Error("invalid input was accepted, partially emitted, mutated, or disclosed")
			}
		}
	}
	body, err := fileformat.EncodeJSON([]byte(`{"version":2}`), fileformat.Format("private-unknown-format"))
	if len(body) != 0 || !errors.Is(err, fileformat.ErrInvalidFormat) || err.Error() != fileformat.ErrInvalidFormat.Error() {
		t.Error("encoding accepted an unknown format or returned a non-static error")
	}
	body, err = fileformat.EncodeJSON([]byte(`{"version":9223372036854775808}`), fileformat.YAML)
	if len(body) != 0 || !errors.Is(err, fileformat.ErrInvalidFormat) {
		t.Error("YAML conversion accepted an integer outside the supported int64 range")
	}
}

func TestEncodeJSONTreatsReferencesAndFunctionsAsLiteralData(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	t.Setenv("FILEFORMAT_PRIVATE_INPUT", "private-environment-value")
	input := map[string]string{"$ref": server.URL + "/private-ref", "expression": "${env:FILEFORMAT_PRIVATE_INPUT}", "function": "!include private-file", "tag": "!!exec private-command"}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal("could not prepare reference fixture")
	}
	for _, format := range []fileformat.Format{fileformat.YAML, fileformat.JSON} {
		encoded, err := fileformat.EncodeJSON(body, format)
		var output map[string]string
		if err != nil || yaml.Unmarshal(encoded, &output) != nil || !reflect.DeepEqual(output, input) || bytes.Contains(encoded, []byte("private-environment-value")) {
			t.Error("format conversion expanded or changed a literal reference or function string")
		}
	}
	if requests.Load() != 0 {
		t.Error("format conversion attempted to load an external reference")
	}
}
