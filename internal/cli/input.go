package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
)

const maxInputBytes = 1 << 20

var errInvalidInput = errors.New("input must contain one nonempty JSON object of at most 1 MiB")
var errReadInput = errors.New("could not read JSON input")

// readSecretInput bounds input before decoding and preserves integer precision.
// Errors deliberately omit filenames, input fragments, and decoder diagnostics.
func readSecretInput(stdin io.Reader, filename string) (map[string]any, error) {
	input := stdin
	if filename != "" && filename != "-" {
		file, err := os.Open(filename)
		if err != nil {
			return nil, errReadInput
		}
		defer file.Close()
		input = file
	}
	if input == nil {
		return nil, errReadInput
	}
	body, err := io.ReadAll(io.LimitReader(input, maxInputBytes+1))
	if err != nil {
		return nil, errReadInput
	}
	if len(body) > maxInputBytes {
		return nil, errInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var data map[string]any
	if err := decoder.Decode(&data); err != nil || len(data) == 0 {
		return nil, errInvalidInput
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errInvalidInput
	}
	return data, nil
}
